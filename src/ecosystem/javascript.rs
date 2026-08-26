use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use miette::{Context, IntoDiagnostic, Result};
use serde::Deserialize;

use crate::evidence::ManifestSection;

#[derive(Debug)]
pub(super) struct ManifestRecord {
    pub directory: PathBuf,
    pub path: PathBuf,
    pub manifest: PackageJson,
}

#[derive(Debug, Clone)]
pub(super) struct DependencyDeclaration {
    pub name: String,
    pub section: ManifestSection,
    pub dev: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct PackageJson {
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(default)]
    dev_dependencies: HashMap<String, String>,
    #[serde(default)]
    optional_dependencies: HashMap<String, String>,
    #[serde(default)]
    peer_dependencies: HashMap<String, String>,
    workspaces: Option<Workspaces>,
}

impl PackageJson {
    pub fn declarations(&self) -> Vec<DependencyDeclaration> {
        let mut declarations = Vec::new();
        for (table, section, dev) in [
            (&self.dependencies, ManifestSection::Dependencies, false),
            (
                &self.dev_dependencies,
                ManifestSection::DevDependencies,
                true,
            ),
            (
                &self.optional_dependencies,
                ManifestSection::OptionalDependencies,
                false,
            ),
            (
                &self.peer_dependencies,
                ManifestSection::PeerDependencies,
                false,
            ),
        ] {
            declarations.extend(table.keys().map(|name| DependencyDeclaration {
                name: name.clone(),
                section,
                dev,
            }));
        }
        declarations.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.section.cmp(&right.section))
        });
        declarations
    }

    fn workspace_patterns(&self) -> Vec<String> {
        match &self.workspaces {
            Some(Workspaces::Array(patterns)) => patterns.clone(),
            Some(Workspaces::Object { packages }) => packages.clone(),
            None => Vec::new(),
        }
    }

    pub fn version_range(&self, name: &str) -> Option<&str> {
        self.dependencies
            .get(name)
            .or_else(|| self.dev_dependencies.get(name))
            .or_else(|| self.optional_dependencies.get(name))
            .or_else(|| self.peer_dependencies.get(name))
            .map(String::as_str)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Workspaces {
    Array(Vec<String>),
    Object {
        #[serde(default)]
        packages: Vec<String>,
    },
}

pub(super) fn read_manifests(
    root: &Path,
    additional_workspace_patterns: &[String],
) -> Result<Vec<ManifestRecord>> {
    let root_manifest = read_manifest(root, root)?;
    let mut patterns = root_manifest.manifest.workspace_patterns();
    patterns.extend(additional_workspace_patterns.iter().cloned());
    if patterns.is_empty() {
        return Ok(vec![root_manifest]);
    }

    let (includes, excludes) = compile_workspace_patterns(&patterns)?;
    let mut records = vec![root_manifest];
    let walker = WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .filter_entry(|entry| {
            if !entry.path().is_dir() {
                return true;
            }
            !matches!(
                entry.path().file_name().and_then(|name| name.to_str()),
                Some("node_modules" | ".git" | "target")
            )
        })
        .build();
    for entry in walker {
        let entry = entry
            .into_diagnostic()
            .wrap_err("Failed to discover JavaScript workspaces")?;
        let path = entry.path();
        if path == root.join("package.json")
            || path.file_name().and_then(|name| name.to_str()) != Some("package.json")
        {
            continue;
        }
        let Some(directory) = path.parent() else {
            continue;
        };
        let relative = directory.strip_prefix(root).unwrap_or(directory);
        if includes.is_match(relative) && !excludes.is_match(relative) {
            records.push(read_manifest(root, directory)?);
        }
    }
    records.sort_by(|left, right| left.directory.cmp(&right.directory));
    Ok(records)
}

fn read_manifest(root: &Path, directory: &Path) -> Result<ManifestRecord> {
    let absolute_path = directory.join("package.json");
    let content = fs::read_to_string(&absolute_path)
        .into_diagnostic()
        .with_context(|| format!("Failed to read {}", absolute_path.display()))?;
    let manifest = serde_json::from_str(&content)
        .into_diagnostic()
        .with_context(|| format!("Failed to parse {}", absolute_path.display()))?;
    Ok(ManifestRecord {
        directory: directory
            .strip_prefix(root)
            .unwrap_or(directory)
            .to_path_buf(),
        path: absolute_path
            .strip_prefix(root)
            .unwrap_or(&absolute_path)
            .to_path_buf(),
        manifest,
    })
}

fn compile_workspace_patterns(patterns: &[String]) -> Result<(GlobSet, GlobSet)> {
    let mut includes = GlobSetBuilder::new();
    let mut excludes = GlobSetBuilder::new();
    for pattern in patterns {
        let (builder, pattern) = if let Some(pattern) = pattern.strip_prefix('!') {
            (&mut excludes, pattern)
        } else {
            (&mut includes, pattern.as_str())
        };
        builder.add(
            Glob::new(pattern)
                .into_diagnostic()
                .with_context(|| format!("Invalid workspace glob {pattern}"))?,
        );
    }
    Ok((
        includes
            .build()
            .into_diagnostic()
            .wrap_err("Failed to compile workspace globs")?,
        excludes
            .build()
            .into_diagnostic()
            .wrap_err("Failed to compile workspace exclusions")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_json_declarations_preserve_dependency_roles() {
        let manifest: PackageJson = serde_json::from_str(
            r#"{
                "dependencies": {"runtime": "1"},
                "devDependencies": {"tests": "1"},
                "optionalDependencies": {"optional": "1"}
            }"#,
        )
        .unwrap();
        let declarations = manifest.declarations();
        assert!(declarations
            .iter()
            .any(|item| item.name == "runtime" && !item.dev));
        assert!(declarations
            .iter()
            .any(|item| item.name == "tests" && item.dev));
    }
}
