use std::path::Path;

use miette::Result;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, CallExpression, ExportAllDeclaration, ExportNamedDeclaration, Expression,
    ImportDeclaration, ImportExpression, TSExternalModuleReference,
};
use oxc_ast::visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};

use crate::evidence::SourceSpan;
use crate::types::{Import, ImportKind};

use super::extract_package_name;

/// Extracts imports from a single JavaScript/TypeScript file
pub struct ImportExtractor<'a> {
    path: &'a Path,
    source: &'a str,
}

impl<'a> ImportExtractor<'a> {
    pub fn new(path: &'a Path, source: &'a str) -> Self {
        Self { path, source }
    }

    pub fn extract(&self) -> Result<Vec<Import>> {
        let allocator = Allocator::default();

        let source_type = SourceType::from_path(self.path).unwrap_or_default();

        let parser = Parser::new(&allocator, self.source, source_type);
        let parsed = parser.parse();

        if let Some(error) = parsed.errors.first() {
            return Err(miette::miette!(
                "Failed to parse {}: {}",
                self.path.display(),
                error
            ));
        }

        let mut imports = Vec::new();
        ImportVisitor {
            path: self.path,
            imports: &mut imports,
        }
        .visit_program(&parsed.program);

        Ok(imports)
    }
}

struct ImportVisitor<'a> {
    path: &'a Path,
    imports: &'a mut Vec<Import>,
}

impl ImportVisitor<'_> {
    fn record(&mut self, specifier: &str, kind: ImportKind, span: Span) {
        if let Some(package_name) = extract_package_name(specifier) {
            self.imports.push(Import {
                file_path: self.path.to_path_buf(),
                kind,
                resolved_package: Some(package_name),
                specifier: specifier.to_string(),
                span: Some(source_span(span.start, span.end)),
            });
        }
    }
}

impl<'ast> Visit<'ast> for ImportVisitor<'_> {
    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'ast>) {
        self.record(
            declaration.source.value.as_str(),
            ImportKind::EsModule,
            declaration.source.span,
        );
        walk::walk_import_declaration(self, declaration);
    }

    fn visit_export_named_declaration(&mut self, declaration: &ExportNamedDeclaration<'ast>) {
        if let Some(source) = &declaration.source {
            self.record(source.value.as_str(), ImportKind::ReExport, source.span);
        }
        walk::walk_export_named_declaration(self, declaration);
    }

    fn visit_export_all_declaration(&mut self, declaration: &ExportAllDeclaration<'ast>) {
        self.record(
            declaration.source.value.as_str(),
            ImportKind::ReExport,
            declaration.source.span,
        );
        walk::walk_export_all_declaration(self, declaration);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'ast>) {
        if matches!(&call.callee, Expression::Identifier(identifier) if identifier.name == "require")
        {
            if let Some(Argument::StringLiteral(literal)) = call.arguments.first() {
                self.record(literal.value.as_str(), ImportKind::CommonJs, literal.span);
            }
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_import_expression(&mut self, import: &ImportExpression<'ast>) {
        if let Expression::StringLiteral(literal) = &import.source {
            self.record(literal.value.as_str(), ImportKind::Dynamic, literal.span);
        }
        walk::walk_import_expression(self, import);
    }

    fn visit_ts_external_module_reference(&mut self, reference: &TSExternalModuleReference<'ast>) {
        self.record(
            reference.expression.value.as_str(),
            ImportKind::CommonJs,
            reference.expression.span,
        );
        walk::walk_ts_external_module_reference(self, reference);
    }
}

fn source_span(start: u32, end: u32) -> SourceSpan {
    SourceSpan {
        offset: start,
        length: end.saturating_sub(start),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn extract_imports(source: &str) -> Vec<Import> {
        let path = PathBuf::from("test.ts");
        let extractor = ImportExtractor::new(&path, source);
        extractor.extract().unwrap()
    }

    #[test]
    fn test_es_imports() {
        let source = r#"
import lodash from 'lodash';
import { useState } from 'react';
import * as path from 'path';
"#;
        let imports = extract_imports(source);
        assert_eq!(imports.len(), 2); // path is built-in, so only 2
        assert_eq!(imports[0].resolved_package, Some("lodash".to_string()));
        assert_eq!(imports[1].resolved_package, Some("react".to_string()));
    }

    #[test]
    fn test_require() {
        let source = r#"
const lodash = require('lodash');
const { join } = require('path');
"#;
        let imports = extract_imports(source);
        assert_eq!(imports.len(), 1); // path is built-in
        assert_eq!(imports[0].resolved_package, Some("lodash".to_string()));
    }

    #[test]
    fn test_scoped_packages() {
        let source = r#"
import { something } from '@scope/package';
import sub from '@scope/package/subpath';
"#;
        let imports = extract_imports(source);
        assert_eq!(imports.len(), 2);
        assert_eq!(
            imports[0].resolved_package,
            Some("@scope/package".to_string())
        );
        assert_eq!(
            imports[1].resolved_package,
            Some("@scope/package".to_string())
        );
    }

    #[test]
    fn test_relative_imports_ignored() {
        let source = r#"
import local from './local';
import parent from '../parent';
import abs from '/absolute';
"#;
        let imports = extract_imports(source);
        assert_eq!(imports.len(), 0);
    }

    #[test]
    fn test_dynamic_imports() {
        let source = r#"
const mod = await import('lodash');
"#;
        let imports = extract_imports(source);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].kind, ImportKind::Dynamic);
    }

    #[test]
    fn finds_imports_nested_in_functions_classes_and_callbacks() {
        let source = r#"
function load() {
    return require('inside-function');
}

const lazy = async () => import('inside-arrow');

class Loader {
    method() {
        [1].map(() => require('inside-callback'));
    }
}
"#;
        let imports = extract_imports(source);
        let packages: Vec<_> = imports
            .iter()
            .filter_map(|import| import.resolved_package.as_deref())
            .collect();
        assert_eq!(
            packages,
            vec!["inside-function", "inside-arrow", "inside-callback"]
        );
    }

    #[test]
    fn rejects_parse_errors_instead_of_returning_partial_coverage() {
        let path = PathBuf::from("broken.ts");
        let extractor = ImportExtractor::new(&path, "function broken( {");
        assert!(extractor.extract().is_err());
    }
}
