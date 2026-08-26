use std::path::Path;

use super::SourceRole;

const CONFIG_FILES: &[&str] = &[
    "vite.config.js",
    "vite.config.ts",
    "vitest.config.js",
    "vitest.config.ts",
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.ts",
    "rollup.config.js",
    "rollup.config.ts",
];

/// Classify a JS/TS file by its conservative project role.
pub fn classify_source_role(path: &Path) -> SourceRole {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if CONFIG_FILES.contains(&file_name) {
        return SourceRole::Configuration;
    }
    if file_name.contains(".test.")
        || file_name.contains(".spec.")
        || path
            .components()
            .any(|component| matches!(component.as_os_str().to_str(), Some("__tests__" | "tests")))
    {
        return SourceRole::Test;
    }
    SourceRole::Runtime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_supported_surfaces() {
        assert_eq!(
            classify_source_role(Path::new("vite.config.ts")),
            SourceRole::Configuration
        );
        assert_eq!(
            classify_source_role(Path::new("src/tool.spec.ts")),
            SourceRole::Test
        );
        assert_eq!(
            classify_source_role(Path::new("tests/integration.ts")),
            SourceRole::Test
        );
        assert_eq!(
            classify_source_role(Path::new("src/index.ts")),
            SourceRole::Runtime
        );
    }
}
