use std::path::Path;

use miette::Result;
use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, Expression, Statement};
use oxc_parser::Parser;
use oxc_span::SourceType;

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

        // We continue even if there are parse errors - partial results are better than none
        if !parsed.errors.is_empty() {
            // Could log warnings here if needed
        }

        let mut imports = Vec::new();

        for stmt in &parsed.program.body {
            self.extract_from_statement(stmt, &mut imports);
        }

        Ok(imports)
    }

    fn extract_from_statement(&self, stmt: &Statement, imports: &mut Vec<Import>) {
        match stmt {
            // ES6 imports: import x from 'package'
            Statement::ImportDeclaration(decl) => {
                let specifier = decl.source.value.as_str();
                let line = self.line_number(decl.span.start);

                if let Some(package_name) = extract_package_name(specifier) {
                    imports.push(Import {
                        file_path: self.path.to_path_buf(),
                        line,
                        specifier: specifier.to_string(),
                        kind: ImportKind::EsModule,
                        resolved_package: Some(package_name),
                    });
                }
            }

            // Re-exports: export { x } from 'package'
            Statement::ExportNamedDeclaration(decl) => {
                if let Some(source) = &decl.source {
                    let specifier = source.value.as_str();
                    let line = self.line_number(decl.span.start);

                    if let Some(package_name) = extract_package_name(specifier) {
                        imports.push(Import {
                            file_path: self.path.to_path_buf(),
                            line,
                            specifier: specifier.to_string(),
                            kind: ImportKind::ReExport,
                            resolved_package: Some(package_name),
                        });
                    }
                }
            }

            // export * from 'package'
            Statement::ExportAllDeclaration(decl) => {
                let specifier = decl.source.value.as_str();
                let line = self.line_number(decl.span.start);

                if let Some(package_name) = extract_package_name(specifier) {
                    imports.push(Import {
                        file_path: self.path.to_path_buf(),
                        line,
                        specifier: specifier.to_string(),
                        kind: ImportKind::ReExport,
                        resolved_package: Some(package_name),
                    });
                }
            }

            // Look for require() calls and dynamic imports in expression statements
            Statement::ExpressionStatement(expr_stmt) => {
                self.extract_from_expression(&expr_stmt.expression, imports);
            }

            // Variable declarations might contain require() or import()
            Statement::VariableDeclaration(var_decl) => {
                for declarator in &var_decl.declarations {
                    if let Some(init) = &declarator.init {
                        self.extract_from_expression(init, imports);
                    }
                }
            }

            _ => {}
        }
    }

    fn extract_from_expression(&self, expr: &Expression, imports: &mut Vec<Import>) {
        match expr {
            // require('package')
            Expression::CallExpression(call) => {
                // Check for require()
                if let Expression::Identifier(ident) = &call.callee {
                    if ident.name == "require" {
                        if let Some(first_arg) = call.arguments.first() {
                            if let Argument::StringLiteral(lit) = first_arg {
                                let specifier = lit.value.as_str();
                                let line = self.line_number(call.span.start);

                                if let Some(package_name) = extract_package_name(specifier) {
                                    imports.push(Import {
                                        file_path: self.path.to_path_buf(),
                                        line,
                                        specifier: specifier.to_string(),
                                        kind: ImportKind::CommonJs,
                                        resolved_package: Some(package_name),
                                    });
                                }
                            }
                        }
                    }
                }

                // Recursively check arguments for nested requires/imports
                for arg in &call.arguments {
                    if let Argument::SpreadElement(spread) = arg {
                        self.extract_from_expression(&spread.argument, imports);
                    } else if let Some(expr) = arg.as_expression() {
                        self.extract_from_expression(expr, imports);
                    }
                }
            }

            // Dynamic import: import('package')
            Expression::ImportExpression(import_expr) => {
                if let Expression::StringLiteral(lit) = &import_expr.source {
                    let specifier = lit.value.as_str();
                    let line = self.line_number(import_expr.span.start);

                    if let Some(package_name) = extract_package_name(specifier) {
                        imports.push(Import {
                            file_path: self.path.to_path_buf(),
                            line,
                            specifier: specifier.to_string(),
                            kind: ImportKind::Dynamic,
                            resolved_package: Some(package_name),
                        });
                    }
                }
            }

            // Recurse into other expressions
            Expression::AwaitExpression(await_expr) => {
                self.extract_from_expression(&await_expr.argument, imports);
            }

            Expression::ConditionalExpression(cond) => {
                self.extract_from_expression(&cond.consequent, imports);
                self.extract_from_expression(&cond.alternate, imports);
            }

            Expression::LogicalExpression(logical) => {
                self.extract_from_expression(&logical.left, imports);
                self.extract_from_expression(&logical.right, imports);
            }

            Expression::AssignmentExpression(assign) => {
                self.extract_from_expression(&assign.right, imports);
            }

            _ => {}
        }
    }

    fn line_number(&self, offset: u32) -> usize {
        self.source[..offset as usize]
            .chars()
            .filter(|c| *c == '\n')
            .count()
            + 1
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
}
