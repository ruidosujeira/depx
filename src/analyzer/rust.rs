use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use miette::{Context, IntoDiagnostic, Result};

use crate::evidence::SourceSpan;

/// One syntactic reference to an external-looking Rust crate identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustReference {
    pub file_path: PathBuf,
    pub identifier: String,
    pub span: SourceSpan,
    pub scope: RustReferenceScope,
}

/// What can be established from source syntax alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustReferenceScope {
    ExplicitExternal,
    ExplicitLocal,
    Unclassified,
}

/// Deterministic result of scanning Rust source files.
#[derive(Debug, Default)]
pub struct RustReferenceMap {
    references: Vec<RustReference>,
    files_analyzed: usize,
}

impl RustReferenceMap {
    pub fn references(&self) -> impl Iterator<Item = &RustReference> {
        self.references.iter()
    }

    pub fn total_references(&self) -> usize {
        self.references.len()
    }

    pub fn files_analyzed(&self) -> usize {
        self.files_analyzed
    }
}

/// Conservatively finds Rust crate references without invoking builds or macro
/// expansion. Comments and string/character literals are masked first so crate
/// names mentioned only in prose do not become usage evidence.
pub struct RustAnalyzer {
    root: PathBuf,
    allowed_project_roots: Vec<PathBuf>,
}

impl RustAnalyzer {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            allowed_project_roots: Vec::new(),
        }
    }

    /// Restrict nested Cargo projects to the supplied workspace roots.
    pub fn with_allowed_project_roots(mut self, mut roots: Vec<PathBuf>) -> Self {
        roots.sort();
        roots.dedup();
        self.allowed_project_roots = roots;
        self
    }

    pub fn analyze(&self) -> Result<RustReferenceMap> {
        let walk_root = self.root.clone();
        let boundary_root = self.root.clone();
        let allowed_project_roots = self.allowed_project_roots.clone();
        let walker = WalkBuilder::new(&walk_root)
            .hidden(true)
            .git_ignore(true)
            .git_global(true)
            .filter_entry(move |entry| {
                if !entry.path().is_dir() {
                    return true;
                }
                if matches!(
                    entry.path().file_name().and_then(|name| name.to_str()),
                    Some("target" | ".git" | "node_modules" | "vendor")
                ) {
                    return false;
                }
                entry.path() == boundary_root
                    || !entry.path().join("Cargo.toml").is_file()
                    || allowed_project_roots
                        .iter()
                        .any(|root| root == entry.path())
            })
            .build();

        let mut map = RustReferenceMap::default();
        for entry in walker {
            let entry = entry
                .into_diagnostic()
                .context("Failed to read Rust project directory entry")?;
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(path)
                .into_diagnostic()
                .with_context(|| format!("Failed to read Rust source: {}", path.display()))?;
            map.references.extend(extract_references(path, &source));
            map.files_analyzed += 1;
        }
        map.references.sort_by(|left, right| {
            left.file_path
                .cmp(&right.file_path)
                .then_with(|| left.span.offset.cmp(&right.span.offset))
                .then_with(|| left.identifier.cmp(&right.identifier))
        });
        Ok(map)
    }
}

fn extract_references(path: &Path, source: &str) -> Vec<RustReference> {
    let masked = mask_non_code(source.as_bytes());
    let local_identifiers = collect_local_identifiers(&masked);
    let mut references = Vec::new();
    let mut index = 0;

    while index < masked.len() {
        if is_identifier_start(masked[index]) {
            let start = index;
            index += 1;
            while index < masked.len() && is_identifier_continue(masked[index]) {
                index += 1;
            }
            let identifier = std::str::from_utf8(&masked[start..index]).unwrap_or_default();
            if identifier == "use" {
                let (mut use_references, end) =
                    extract_use_references(path, &masked, index, &local_identifiers);
                references.append(&mut use_references);
                index = end;
                continue;
            }
            if identifier == "extern" {
                if let Some((reference, end)) = extract_extern_crate(path, &masked, index) {
                    references.push(reference);
                    index = end;
                }
                continue;
            }
            if identifier == "macro_rules" {
                continue;
            }
            let next = next_non_whitespace(&masked, index);
            let path_or_macro = masked.get(next..next.saturating_add(2)) == Some(b"::")
                || masked.get(next) == Some(&b'!');
            let prefix = path_prefix(&masked, start);
            if path_or_macro && prefix != PathPrefix::Nested {
                references.push(RustReference {
                    file_path: path.to_path_buf(),
                    identifier: identifier.to_string(),
                    span: source_span(start, index),
                    scope: if is_known_local_identifier(identifier) {
                        RustReferenceScope::ExplicitLocal
                    } else if prefix == PathPrefix::Absolute {
                        RustReferenceScope::ExplicitExternal
                    } else {
                        identifier_scope(identifier, &local_identifiers)
                    },
                });
            }
            continue;
        }
        index += 1;
    }

    references
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathPrefix {
    None,
    Absolute,
    Nested,
}

fn path_prefix(bytes: &[u8], start: usize) -> PathPrefix {
    let Some(second_colon) = previous_non_whitespace(bytes, start) else {
        return PathPrefix::None;
    };
    if bytes[second_colon] != b':' {
        return PathPrefix::None;
    }
    let Some(first_colon) = previous_non_whitespace(bytes, second_colon) else {
        return PathPrefix::None;
    };
    if bytes[first_colon] != b':' {
        return PathPrefix::None;
    }
    match previous_non_whitespace(bytes, first_colon) {
        Some(previous) if is_identifier_continue(bytes[previous]) => PathPrefix::Nested,
        _ => PathPrefix::Absolute,
    }
}

fn previous_non_whitespace(bytes: &[u8], index: usize) -> Option<usize> {
    let mut cursor = index.checked_sub(1)?;
    while bytes[cursor].is_ascii_whitespace() {
        cursor = cursor.checked_sub(1)?;
    }
    Some(cursor)
}

fn extract_extern_crate(
    path: &Path,
    bytes: &[u8],
    after_extern: usize,
) -> Option<(RustReference, usize)> {
    let (crate_start, crate_end) = next_identifier(bytes, after_extern)?;
    if &bytes[crate_start..crate_end] != b"crate" {
        return None;
    }
    let (start, end) = next_identifier(bytes, crate_end)?;
    let identifier = std::str::from_utf8(&bytes[start..end]).ok()?.to_string();
    let scope = if is_known_local_identifier(&identifier) {
        RustReferenceScope::ExplicitLocal
    } else {
        RustReferenceScope::ExplicitExternal
    };
    Some((
        RustReference {
            file_path: path.to_path_buf(),
            identifier,
            span: source_span(start, end),
            scope,
        },
        end,
    ))
}

fn extract_use_references(
    path: &Path,
    bytes: &[u8],
    after_use: usize,
    local_identifiers: &HashSet<String>,
) -> (Vec<RustReference>, usize) {
    let end = bytes[after_use..]
        .iter()
        .position(|byte| *byte == b';')
        .map_or(bytes.len(), |offset| after_use + offset + 1);
    let mut references = Vec::new();
    let mut cursor = next_non_whitespace(bytes, after_use);
    let leading_group = bytes.get(cursor) == Some(&b'{');
    let leading_absolute = bytes.get(cursor..cursor.saturating_add(2)) == Some(b"::");
    let mut depth = usize::from(leading_group);
    let mut expect_root = true;
    if leading_group {
        cursor += 1;
    }

    while cursor < end {
        match bytes[cursor] {
            b'{' => {
                depth += 1;
                cursor += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                cursor += 1;
            }
            b',' if leading_group && depth == 1 => {
                expect_root = true;
                cursor += 1;
            }
            byte if is_identifier_start(byte) => {
                let start = cursor;
                cursor += 1;
                while cursor < end && is_identifier_continue(bytes[cursor]) {
                    cursor += 1;
                }
                if expect_root {
                    let identifier = std::str::from_utf8(&bytes[start..cursor]).unwrap_or_default();
                    references.push(RustReference {
                        file_path: path.to_path_buf(),
                        identifier: identifier.to_string(),
                        span: source_span(start, cursor),
                        scope: if is_known_local_identifier(identifier) {
                            RustReferenceScope::ExplicitLocal
                        } else if leading_absolute
                            || path_prefix(bytes, start) == PathPrefix::Absolute
                        {
                            RustReferenceScope::ExplicitExternal
                        } else {
                            identifier_scope(identifier, local_identifiers)
                        },
                    });
                    expect_root = false;
                    if !leading_group {
                        break;
                    }
                }
            }
            _ => cursor += 1,
        }
    }
    (references, end)
}

fn collect_local_identifiers(bytes: &[u8]) -> HashSet<String> {
    let mut identifiers = HashSet::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !is_identifier_start(bytes[cursor]) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while cursor < bytes.len() && is_identifier_continue(bytes[cursor]) {
            cursor += 1;
        }
        let end = cursor;
        match &bytes[start..end] {
            b"mod" => {
                if let Some((name_start, name_end)) = next_identifier(bytes, end) {
                    identifiers.insert(
                        std::str::from_utf8(&bytes[name_start..name_end])
                            .unwrap_or_default()
                            .to_string(),
                    );
                }
            }
            b"macro_rules" => {
                let bang = next_non_whitespace(bytes, end);
                if bytes.get(bang) == Some(&b'!') {
                    if let Some((name_start, name_end)) = next_identifier(bytes, bang + 1) {
                        identifiers.insert(
                            std::str::from_utf8(&bytes[name_start..name_end])
                                .unwrap_or_default()
                                .to_string(),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    identifiers
}

fn next_identifier(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    let start = next_non_whitespace(bytes, index);
    if !bytes
        .get(start)
        .is_some_and(|byte| is_identifier_start(*byte))
    {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| is_identifier_continue(*byte))
    {
        end += 1;
    }
    Some((start, end))
}

fn identifier_scope(identifier: &str, local_identifiers: &HashSet<String>) -> RustReferenceScope {
    if local_identifiers.contains(identifier) || is_known_local_identifier(identifier) {
        RustReferenceScope::ExplicitLocal
    } else {
        RustReferenceScope::Unclassified
    }
}

fn is_known_local_identifier(identifier: &str) -> bool {
    matches!(
        identifier,
        "crate"
            | "self"
            | "super"
            | "std"
            | "core"
            | "alloc"
            | "assert"
            | "assert_eq"
            | "assert_ne"
            | "cfg"
            | "column"
            | "compile_error"
            | "concat"
            | "dbg"
            | "debug_assert"
            | "debug_assert_eq"
            | "debug_assert_ne"
            | "eprint"
            | "eprintln"
            | "env"
            | "file"
            | "format"
            | "format_args"
            | "include"
            | "include_bytes"
            | "include_str"
            | "line"
            | "matches"
            | "module_path"
            | "option_env"
            | "panic"
            | "print"
            | "println"
            | "stringify"
            | "thread_local"
            | "todo"
            | "unimplemented"
            | "unreachable"
            | "vec"
            | "write"
            | "writeln"
    )
}

fn source_span(start: usize, end: usize) -> SourceSpan {
    SourceSpan {
        offset: u32::try_from(start).unwrap_or(u32::MAX),
        length: u32::try_from(end - start).unwrap_or(u32::MAX),
    }
}

fn next_non_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit()
}

/// Replace comments and literals with spaces while preserving byte offsets.
fn mask_non_code(source: &[u8]) -> Vec<u8> {
    let mut masked = source.to_vec();
    let mut index = 0;
    while index < source.len() {
        if source.get(index..index + 2) == Some(b"//") {
            let end = source[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(source.len(), |offset| index + offset);
            mask_range(&mut masked, index, end);
            index = end;
            continue;
        }
        if source.get(index..index + 2) == Some(b"/*") {
            let mut cursor = index + 2;
            let mut depth = 1_u32;
            while cursor < source.len() && depth > 0 {
                if source.get(cursor..cursor + 2) == Some(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if source.get(cursor..cursor + 2) == Some(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            mask_range(&mut masked, index, cursor);
            index = cursor;
            continue;
        }
        if let Some(end) = raw_string_end(source, index) {
            mask_range(&mut masked, index, end);
            index = end;
            continue;
        }
        if source[index] == b'"' || source.get(index..index + 2) == Some(b"b\"") {
            let quote = if source[index] == b'"' {
                index
            } else {
                index + 1
            };
            let end = quoted_end(source, quote, b'"');
            mask_range(&mut masked, index, end);
            index = end;
            continue;
        }
        if source[index] == b'\'' {
            if let Some(end) = char_literal_end(source, index) {
                mask_range(&mut masked, index, end);
                index = end;
                continue;
            }
        }
        index += 1;
    }
    masked
}

fn mask_range(bytes: &mut [u8], start: usize, end: usize) {
    let end = end.min(bytes.len());
    for byte in &mut bytes[start..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn quoted_end(source: &[u8], quote: usize, delimiter: u8) -> usize {
    let mut cursor = quote + 1;
    while cursor < source.len() {
        if source[cursor] == b'\\' {
            cursor = (cursor + 2).min(source.len());
        } else if source[cursor] == delimiter {
            return cursor + 1;
        } else {
            cursor += 1;
        }
    }
    source.len()
}

fn char_literal_end(source: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start + 1;
    if source.get(cursor) == Some(&b'\\') {
        cursor += 2;
    } else {
        cursor += 1;
    }
    (source.get(cursor) == Some(&b'\'')).then_some(cursor + 1)
}

fn raw_string_end(source: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    if source.get(cursor) == Some(&b'b') {
        cursor += 1;
    }
    if source.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hashes_start = cursor;
    while source.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if source.get(cursor) != Some(&b'"') {
        return None;
    }
    let hashes = cursor - hashes_start;
    cursor += 1;
    while cursor < source.len() {
        let suffix_start = cursor + 1;
        let suffix_end = suffix_start + hashes;
        if source[cursor] == b'"'
            && suffix_end <= source.len()
            && source[suffix_start..suffix_end]
                .iter()
                .all(|byte| *byte == b'#')
        {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(source.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(source: &str) -> Vec<String> {
        extract_references(Path::new("src/lib.rs"), source)
            .into_iter()
            .map(|reference| reference.identifier)
            .collect()
    }

    #[test]
    fn extracts_paths_macros_use_groups_and_extern_crates() {
        let actual = names(
            r#"
                use serde::{Deserialize, Serialize};
                use {anyhow, tokio as runtime};
                extern crate pretty_assertions;
                tokio::spawn(async {});
                tracing::info!("ready");
            "#,
        );
        for expected in ["serde", "anyhow", "tokio", "pretty_assertions", "tracing"] {
            assert!(actual.contains(&expected.to_string()), "missing {expected}");
        }
        for imported_item in ["Deserialize", "Serialize", "runtime", "spawn", "info"] {
            assert!(!actual.contains(&imported_item.to_string()));
        }
    }

    #[test]
    fn ignores_comments_strings_raw_strings_and_char_literals() {
        let actual = names(
            r##"
                // serde::Serialize
                /* tokio::spawn */
                const NORMAL: &str = "anyhow::Error";
                const RAW: &str = r#"tracing::info"#;
                const CH: char = 'x';
                real_crate::run();
            "##,
        );
        assert_eq!(actual, vec!["real_crate"]);
    }

    #[test]
    fn classifies_explicit_external_local_and_uncertain_references() {
        let references = extract_references(
            Path::new("src/lib.rs"),
            r#"
                mod local;
                use crate::internal;
                use self::sibling;
                use super::parent;
                use local::Thing;
                use declared::Value;
                extern crate std;
                extern crate missing;
            "#,
        );
        let scope = |name: &str| {
            references
                .iter()
                .find(|reference| reference.identifier == name)
                .map(|reference| reference.scope)
        };
        assert_eq!(scope("crate"), Some(RustReferenceScope::ExplicitLocal));
        assert_eq!(scope("self"), Some(RustReferenceScope::ExplicitLocal));
        assert_eq!(scope("super"), Some(RustReferenceScope::ExplicitLocal));
        assert_eq!(scope("std"), Some(RustReferenceScope::ExplicitLocal));
        assert_eq!(scope("local"), Some(RustReferenceScope::ExplicitLocal));
        assert_eq!(scope("declared"), Some(RustReferenceScope::Unclassified));
        assert_eq!(scope("missing"), Some(RustReferenceScope::ExplicitExternal));
    }
}
