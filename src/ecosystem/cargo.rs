use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use miette::{Context, IntoDiagnostic, Result};
use serde::Deserialize;

use crate::evidence::{manifest_evidence, transitive_evidence, ManifestSection};
use crate::model::{
    Component, ComponentId, DependencyEdge, DependencyKind, Ecosystem, ProjectSnapshot,
};

use super::EcosystemAdapter;

/// Adapter for Rust projects represented by `Cargo.lock`.
pub struct CargoAdapter;

impl EcosystemAdapter for CargoAdapter {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("Cargo.lock").is_file()
    }

    fn build_snapshot(&self, root: &Path) -> Result<ProjectSnapshot> {
        let lockfile = read_lockfile(&root.join("Cargo.lock"))?;
        let manifest = read_manifest(root);
        let ids = component_ids(&lockfile);
        let direct_ids = direct_component_ids(&lockfile, &ids, manifest.as_ref());
        let dev_names = manifest
            .as_ref()
            .map(CargoManifest::dev_names)
            .unwrap_or_default();

        let components: Vec<Component> = lockfile
            .package
            .iter()
            .zip(&ids)
            .map(|(package, id)| Component {
                id: id.clone(),
                direct: direct_ids.contains(id),
                dev: direct_ids.contains(id) && dev_names.contains(&package.name),
                deprecated: None,
            })
            .collect();

        let mut edges = Vec::new();
        for (package, from) in lockfile.package.iter().zip(&ids) {
            for dependency in package.dependencies.as_deref().unwrap_or_default() {
                if let Some(to) = resolve_dependency(dependency, &lockfile, &ids) {
                    edges.push(DependencyEdge {
                        from: from.clone(),
                        to: to.clone(),
                        // Cargo.lock records resolution but not dependency
                        // categories. Manifest evidence will be added later.
                        kind: DependencyKind::Unknown,
                    });
                }
            }
        }

        let mut evidence = Vec::new();
        if let Some(manifest) = &manifest {
            for component in components.iter().filter(|component| component.direct) {
                for section in manifest.sections_for(&component.id.name) {
                    evidence.push(manifest_evidence(
                        component.id.clone(),
                        "Cargo.toml".into(),
                        section,
                    )?);
                }
            }
        }
        evidence.extend(transitive_evidence(&edges, "Cargo.lock".into())?);
        ProjectSnapshot::new(root.to_path_buf(), components, edges).with_evidence(evidence)
    }
}

fn read_lockfile(path: &Path) -> Result<CargoLockfile> {
    let content = fs::read_to_string(path)
        .into_diagnostic()
        .with_context(|| format!("Failed to read {}", path.display()))?;
    toml::from_str(&content)
        .into_diagnostic()
        .wrap_err("Failed to parse Cargo.lock")
}

fn component_ids(lockfile: &CargoLockfile) -> Vec<ComponentId> {
    lockfile
        .package
        .iter()
        .map(|package| ComponentId {
            ecosystem: Ecosystem::Cargo,
            name: package.name.clone(),
            version: package.version.clone(),
            location: package.source.clone(),
        })
        .collect()
}

fn resolve_dependency<'a>(
    dependency: &str,
    lockfile: &CargoLockfile,
    ids: &'a [ComponentId],
) -> Option<&'a ComponentId> {
    let mut parts = dependency.split_whitespace();
    let name = parts.next()?;
    let version = parts.next();
    let source = parts.next().map(|value| value.trim_matches(['(', ')']));

    let mut matches = lockfile.package.iter().zip(ids).filter(|(package, _)| {
        package.name == name
            && version.is_none_or(|expected| package.version == expected)
            && source.is_none_or(|expected| package.source.as_deref() == Some(expected))
    });
    let (_, id) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(id)
}

fn direct_component_ids(
    lockfile: &CargoLockfile,
    ids: &[ComponentId],
    manifest: Option<&CargoManifest>,
) -> HashSet<ComponentId> {
    let Some(manifest) = manifest else {
        return HashSet::new();
    };
    let declared = manifest.direct_names();
    let mut direct = HashSet::new();

    // Root/workspace packages have no registry source. Their resolved lockfile
    // edges identify the exact version selected for a declaration.
    for package in lockfile
        .package
        .iter()
        .filter(|package| package.source.is_none())
    {
        for dependency in package.dependencies.as_deref().unwrap_or_default() {
            if let Some(id) = resolve_dependency(dependency, lockfile, ids) {
                if declared.contains(&id.name) {
                    direct.insert(id.clone());
                }
            }
        }
    }

    // Some generated/minimal locks omit the local package. Only infer by name
    // when that name identifies exactly one resolved component.
    for name in declared {
        if direct.iter().any(|id| id.name == name) {
            continue;
        }
        let matches: Vec<_> = ids.iter().filter(|id| id.name == name).collect();
        if let [id] = matches.as_slice() {
            direct.insert((*id).clone());
        }
    }
    direct
}

fn read_manifest(root: &Path) -> Option<CargoManifest> {
    let content = fs::read_to_string(root.join("Cargo.toml")).ok()?;
    toml::from_str(&content).ok()
}

#[derive(Debug, Deserialize)]
struct CargoLockfile {
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
    dependencies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CargoManifest {
    #[serde(default)]
    dependencies: HashMap<String, ManifestDep>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: HashMap<String, ManifestDep>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: HashMap<String, ManifestDep>,
    workspace: Option<WorkspaceManifest>,
}

impl CargoManifest {
    fn direct_names(&self) -> HashSet<String> {
        let mut names = HashSet::new();
        collect_manifest_names(&self.dependencies, &mut names);
        collect_manifest_names(&self.dev_dependencies, &mut names);
        collect_manifest_names(&self.build_dependencies, &mut names);
        if let Some(workspace) = &self.workspace {
            collect_manifest_names(&workspace.dependencies, &mut names);
        }
        names
    }

    fn dev_names(&self) -> HashSet<String> {
        let mut names = HashSet::new();
        collect_manifest_names(&self.dev_dependencies, &mut names);
        names
    }

    fn sections_for(&self, name: &str) -> Vec<ManifestSection> {
        let mut sections = Vec::new();
        if manifest_contains(&self.dependencies, name) {
            sections.push(ManifestSection::Dependencies);
        }
        if manifest_contains(&self.dev_dependencies, name) {
            sections.push(ManifestSection::DevDependencies);
        }
        if manifest_contains(&self.build_dependencies, name) {
            sections.push(ManifestSection::BuildDependencies);
        }
        if self
            .workspace
            .as_ref()
            .is_some_and(|workspace| manifest_contains(&workspace.dependencies, name))
        {
            sections.push(ManifestSection::WorkspaceDependencies);
        }
        sections
    }
}

fn manifest_contains(table: &HashMap<String, ManifestDep>, name: &str) -> bool {
    table
        .iter()
        .any(|(key, dependency)| dependency.crate_name(key) == name)
}

#[derive(Debug, Deserialize)]
struct WorkspaceManifest {
    #[serde(default)]
    dependencies: HashMap<String, ManifestDep>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ManifestDep {
    Version(#[allow(dead_code)] String),
    Detailed { package: Option<String> },
}

impl ManifestDep {
    fn crate_name(&self, key: &str) -> String {
        match self {
            Self::Detailed {
                package: Some(name),
            } => name.clone(),
            _ => key.to_string(),
        }
    }
}

fn collect_manifest_names(table: &HashMap<String, ManifestDep>, names: &mut HashSet<String>) {
    for (key, dependency) in table {
        names.insert(dependency.crate_name(key));
    }
}
