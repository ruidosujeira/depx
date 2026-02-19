mod extractor;

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use miette::{Context, IntoDiagnostic, Result};

use crate::types::ImportMap;

pub use extractor::ImportExtractor;

/// Analyzes JavaScript/TypeScript source files to extract imports
pub struct ImportAnalyzer {
    root: PathBuf,
}

impl ImportAnalyzer {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Analyze all JS/TS files in the project and extract imports
    pub fn analyze(&self) -> Result<ImportMap> {
        let mut import_map = ImportMap::new();

        // Walk the directory, respecting .gitignore
        let walker = WalkBuilder::new(&self.root)
            .hidden(true) // Skip hidden files
            .git_ignore(true) // Respect .gitignore
            .git_global(true)
            .filter_entry(|entry| {
                let path = entry.path();

                // Skip node_modules, dist, build directories
                if path.is_dir() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    return !matches!(
                        name,
                        "node_modules" | "dist" | "build" | ".git" | "coverage" | ".next"
                    );
                }

                true
            })
            .build();

        for entry in walker {
            let entry = entry
                .into_diagnostic()
                .context("Failed to read directory entry")?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Check if it's a JS/TS file
            if !is_js_ts_file(path) {
                continue;
            }

            // Skip test files for production analysis
            // (we might want to make this configurable later)
            let is_test = is_test_file(path);

            self.analyze_file(path, is_test, &mut import_map)?;
        }

        Ok(import_map)
    }

    fn analyze_file(&self, path: &Path, _is_test: bool, import_map: &mut ImportMap) -> Result<()> {
        let source = std::fs::read_to_string(path)
            .into_diagnostic()
            .with_context(|| format!("Failed to read file: {}", path.display()))?;

        let extractor = ImportExtractor::new(path, &source);
        let imports = extractor.extract()?;

        for import in imports {
            import_map.add_import(import);
        }

        import_map.mark_file_analyzed();

        Ok(())
    }
}

/// Check if a path is a JavaScript/TypeScript file
fn is_js_ts_file(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };

    matches!(
        ext,
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts"
    )
}

/// Check if a file is likely a test file
fn is_test_file(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Common test file patterns
    path_str.contains(".test.")
        || path_str.contains(".spec.")
        || path_str.contains("__tests__")
        || path_str.contains("__mocks__")
        || path_str.ends_with(".test.ts")
        || path_str.ends_with(".test.js")
        || path_str.ends_with(".spec.ts")
        || path_str.ends_with(".spec.js")
}

/// Extract the package name from an import specifier
///
/// Examples:
/// - "lodash" -> "lodash"
/// - "lodash/fp" -> "lodash"
/// - "@scope/package" -> "@scope/package"
/// - "@scope/package/sub" -> "@scope/package"
/// - "./local" -> None (relative import)
/// - "../utils" -> None (relative import)
pub fn extract_package_name(specifier: &str) -> Option<String> {
    // Skip relative imports
    if specifier.starts_with('.') || specifier.starts_with('/') {
        return None;
    }

    // Skip Node.js built-in modules
    if is_node_builtin(specifier) {
        return None;
    }

    // Handle scoped packages (@scope/package)
    if specifier.starts_with('@') {
        let parts: Vec<&str> = specifier.splitn(3, '/').collect();
        if parts.len() >= 2 {
            return Some(format!("{}/{}", parts[0], parts[1]));
        }
        return None;
    }

    // Regular package - take everything before the first /
    let package_name = specifier.split('/').next()?;
    Some(package_name.to_string())
}

/// Check if a module is a Node.js built-in
fn is_node_builtin(specifier: &str) -> bool {
    // Handle node: prefix
    let module = specifier.strip_prefix("node:").unwrap_or(specifier);

    matches!(
        module,
        "assert"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "dns"
            | "domain"
            | "events"
            | "fs"
            | "http"
            | "http2"
            | "https"
            | "inspector"
            | "module"
            | "net"
            | "os"
            | "path"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "repl"
            | "stream"
            | "string_decoder"
            | "sys"
            | "timers"
            | "tls"
            | "trace_events"
            | "tty"
            | "url"
            | "util"
            | "v8"
            | "vm"
            | "wasi"
            | "worker_threads"
            | "zlib"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_package_name() {
        assert_eq!(extract_package_name("lodash"), Some("lodash".to_string()));
        assert_eq!(
            extract_package_name("lodash/fp"),
            Some("lodash".to_string())
        );
        assert_eq!(
            extract_package_name("@scope/package"),
            Some("@scope/package".to_string())
        );
        assert_eq!(
            extract_package_name("@scope/package/sub/path"),
            Some("@scope/package".to_string())
        );
        assert_eq!(extract_package_name("./local"), None);
        assert_eq!(extract_package_name("../utils"), None);
        assert_eq!(extract_package_name("fs"), None);
        assert_eq!(extract_package_name("node:fs"), None);
    }
}
