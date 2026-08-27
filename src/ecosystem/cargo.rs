use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobSetBuilder};
use ignore::WalkBuilder;
use miette::{Context, IntoDiagnostic, Result};
use serde::Deserialize;

use crate::evidence::ManifestSection;
use crate::model::{
    Component, ComponentId, DependencyEdge, DependencyKind, Ecosystem, ProjectSnapshot,
    ProjectUnit, UnitDeclaration,
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
        let manifests = read_manifests(root)?;
        let ids = component_ids(&lockfile);
        let declarations = resolve_manifest_declarations(&lockfile, &ids, &manifests);
        let units = cargo_project_units(&manifests, &declarations);
        let direct_ids: HashSet<_> = declarations
            .iter()
            .map(|declaration| declaration.id.clone())
            .collect();
        let runtime_ids: HashSet<_> = declarations
            .iter()
            .filter(|declaration| declaration.section != ManifestSection::DevDependencies)
            .map(|declaration| declaration.id.clone())
            .collect();

        let components: Vec<Component> = lockfile
            .package
            .iter()
            .zip(&ids)
            // Source-less entries are the project/workspace packages themselves,
            // not installed third-party components.
            .filter(|(package, _)| package.source.is_some())
            .map(|(_, id)| Component {
                id: id.clone(),
                direct: direct_ids.contains(id),
                dev: direct_ids.contains(id) && !runtime_ids.contains(id),
                deprecated: None,
            })
            .collect();
        let component_ids: HashSet<_> = components
            .iter()
            .map(|component| component.id.clone())
            .collect();

        let mut edges = Vec::new();
        for (package, from) in lockfile.package.iter().zip(&ids) {
            for dependency in package.dependencies.as_deref().unwrap_or_default() {
                if let Some(to) = resolve_dependency(dependency, &lockfile, &ids) {
                    if !component_ids.contains(from) || !component_ids.contains(to) {
                        continue;
                    }
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

        ProjectSnapshot::new(root.to_path_buf(), components, edges).with_units(units)
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

fn local_dependency_ids(
    lockfile: &CargoLockfile,
    ids: &[ComponentId],
    local_package_name: Option<&str>,
    dependency_name: &str,
) -> HashSet<ComponentId> {
    let mut resolved = HashSet::new();
    for package in lockfile.package.iter().filter(|package| {
        package.source.is_none() && local_package_name.is_none_or(|name| package.name == name)
    }) {
        for dependency in package.dependencies.as_deref().unwrap_or_default() {
            if let Some(id) = resolve_dependency(dependency, lockfile, ids) {
                if id.name == dependency_name {
                    resolved.insert(id.clone());
                }
            }
        }
    }
    resolved
}

#[derive(Debug)]
struct CargoManifestRecord {
    path: PathBuf,
    manifest: CargoManifest,
}

#[derive(Debug)]
struct ResolvedDeclaration {
    name: String,
    id: ComponentId,
    unit_root: PathBuf,
    section: ManifestSection,
}

fn read_manifests(root: &Path) -> Result<Vec<CargoManifestRecord>> {
    let root_path = root.join("Cargo.toml");
    if !root_path.is_file() {
        return Ok(Vec::new());
    }
    let root_record = read_manifest_record(root, &root_path)?;
    let mut records = vec![root_record];

    if let Some(workspace) = &records[0].manifest.workspace {
        if !workspace.members.is_empty() {
            let includes = compile_manifest_globs(&workspace.members, "member")?;
            let excludes = compile_manifest_globs(&workspace.exclude, "exclude")?;
            let walker = WalkBuilder::new(root)
                .hidden(true)
                .git_ignore(true)
                .filter_entry(|entry| {
                    !entry.path().is_dir()
                        || !matches!(
                            entry.path().file_name().and_then(|name| name.to_str()),
                            Some("target" | ".git")
                        )
                })
                .build();
            for entry in walker {
                let entry = entry
                    .into_diagnostic()
                    .wrap_err("Failed to discover Cargo workspace manifests")?;
                let path = entry.path();
                if path == root_path
                    || path.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml")
                {
                    continue;
                }
                let Some(directory) = path.parent() else {
                    continue;
                };
                let relative = directory.strip_prefix(root).unwrap_or(directory);
                if includes.is_match(relative) && !excludes.is_match(relative) {
                    records.push(read_manifest_record(root, path)?);
                }
            }
        }
    }

    // Cargo treats in-tree path dependencies as workspace participants in many
    // common layouts even when they are not matched by `workspace.members`.
    // Follow only explicit path declarations, so unrelated nested fixtures do
    // not leak into the project boundary.
    let canonical_root = fs::canonicalize(root)
        .into_diagnostic()
        .with_context(|| format!("Failed to resolve Cargo project root {}", root.display()))?;
    let mut index = 0;
    while index < records.len() {
        let manifest_directory = records[index]
            .path
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf();
        let path_dependencies: Vec<_> = records[index]
            .manifest
            .declarations()
            .into_iter()
            .filter_map(|declaration| declaration.path)
            .collect();
        for dependency_path in path_dependencies {
            let candidate = root
                .join(&manifest_directory)
                .join(dependency_path)
                .join("Cargo.toml");
            if !candidate.is_file() {
                continue;
            }
            let canonical = fs::canonicalize(&candidate)
                .into_diagnostic()
                .with_context(|| format!("Failed to resolve {}", candidate.display()))?;
            let Ok(relative) = canonical.strip_prefix(&canonical_root) else {
                continue;
            };
            if records.iter().any(|record| record.path == relative) {
                continue;
            }
            records.push(read_manifest_record(root, &root.join(relative))?);
        }
        index += 1;
    }

    records.sort_by(|left, right| left.path.cmp(&right.path));
    records.dedup_by(|left, right| left.path == right.path);
    Ok(records)
}

fn compile_manifest_globs(patterns: &[String], kind: &str) -> Result<globset::GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern)
                .into_diagnostic()
                .with_context(|| format!("Invalid Cargo workspace {kind} glob {pattern}"))?,
        );
    }
    builder
        .build()
        .into_diagnostic()
        .with_context(|| format!("Failed to compile Cargo workspace {kind} globs"))
}

fn read_manifest_record(root: &Path, path: &Path) -> Result<CargoManifestRecord> {
    let content = fs::read_to_string(path)
        .into_diagnostic()
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let manifest = toml::from_str(&content)
        .into_diagnostic()
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(CargoManifestRecord {
        path: path.strip_prefix(root).unwrap_or(path).to_path_buf(),
        manifest,
    })
}

fn resolve_manifest_declarations(
    lockfile: &CargoLockfile,
    ids: &[ComponentId],
    manifests: &[CargoManifestRecord],
) -> Vec<ResolvedDeclaration> {
    let mut declarations = Vec::new();
    for record in manifests {
        for declaration in record.manifest.declarations() {
            let mut resolved = local_dependency_ids(
                lockfile,
                ids,
                record.manifest.package_name(),
                &declaration.package,
            );
            if resolved.is_empty() && record.manifest.package_name().is_none() {
                resolved = local_dependency_ids(lockfile, ids, None, &declaration.package);
            }
            if resolved.is_empty() {
                let matches: Vec<_> = ids
                    .iter()
                    .filter(|id| id.name == declaration.package && id.location.is_some())
                    .collect();
                if let [id] = matches.as_slice() {
                    resolved.insert((*id).clone());
                }
            }
            resolved.retain(|id| id.location.is_some());
            let unit_root = record.path.parent().unwrap_or(Path::new("")).to_path_buf();
            declarations.extend(resolved.into_iter().map(|id| ResolvedDeclaration {
                name: declaration.alias.clone(),
                id,
                unit_root: unit_root.clone(),
                section: declaration.section,
            }));
        }
    }
    declarations.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.unit_root.cmp(&right.unit_root))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.section.cmp(&right.section))
    });
    declarations.dedup_by(|left, right| {
        left.id == right.id
            && left.name == right.name
            && left.unit_root == right.unit_root
            && left.section == right.section
    });
    declarations
}

fn cargo_project_units(
    manifests: &[CargoManifestRecord],
    declarations: &[ResolvedDeclaration],
) -> Vec<ProjectUnit> {
    manifests
        .iter()
        .map(|record| {
            let unit_root = record.path.parent().unwrap_or(Path::new("")).to_path_buf();
            ProjectUnit::new(
                unit_root.clone(),
                record.path.clone(),
                Ecosystem::Cargo,
                declarations
                    .iter()
                    .filter(|declaration| declaration.unit_root == unit_root)
                    .map(|declaration| UnitDeclaration {
                        name: declaration.alias_identifier(),
                        component: declaration.id.clone(),
                        section: declaration.section,
                    })
                    .collect(),
            )
        })
        .collect()
}

impl ResolvedDeclaration {
    fn alias_identifier(&self) -> String {
        self.name.replace('-', "_")
    }
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
    package: Option<CargoPackageManifest>,
    #[serde(default)]
    dependencies: HashMap<String, ManifestDep>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: HashMap<String, ManifestDep>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: HashMap<String, ManifestDep>,
    #[serde(default)]
    target: HashMap<String, TargetManifest>,
    workspace: Option<WorkspaceManifest>,
}

impl CargoManifest {
    fn package_name(&self) -> Option<&str> {
        self.package.as_ref().map(|package| package.name.as_str())
    }

    fn declarations(&self) -> Vec<CargoDeclaration> {
        let mut declarations = Vec::new();
        collect_manifest_declarations(
            &self.dependencies,
            ManifestSection::Dependencies,
            &mut declarations,
        );
        collect_manifest_declarations(
            &self.dev_dependencies,
            ManifestSection::DevDependencies,
            &mut declarations,
        );
        collect_manifest_declarations(
            &self.build_dependencies,
            ManifestSection::BuildDependencies,
            &mut declarations,
        );
        if let Some(workspace) = &self.workspace {
            collect_manifest_declarations(
                &workspace.dependencies,
                ManifestSection::WorkspaceDependencies,
                &mut declarations,
            );
        }
        for target in self.target.values() {
            collect_manifest_declarations(
                &target.dependencies,
                ManifestSection::Dependencies,
                &mut declarations,
            );
            collect_manifest_declarations(
                &target.dev_dependencies,
                ManifestSection::DevDependencies,
                &mut declarations,
            );
            collect_manifest_declarations(
                &target.build_dependencies,
                ManifestSection::BuildDependencies,
                &mut declarations,
            );
        }
        declarations
    }
}

#[derive(Debug, Deserialize)]
struct CargoPackageManifest {
    name: String,
}

#[derive(Debug, Deserialize)]
struct WorkspaceManifest {
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    dependencies: HashMap<String, ManifestDep>,
}

#[derive(Debug, Default, Deserialize)]
struct TargetManifest {
    #[serde(default)]
    dependencies: HashMap<String, ManifestDep>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: HashMap<String, ManifestDep>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: HashMap<String, ManifestDep>,
}

#[derive(Debug)]
struct CargoDeclaration {
    alias: String,
    package: String,
    path: Option<PathBuf>,
    section: ManifestSection,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ManifestDep {
    Version(#[allow(dead_code)] String),
    Detailed {
        package: Option<String>,
        path: Option<PathBuf>,
    },
}

impl ManifestDep {
    fn crate_name(&self, key: &str) -> String {
        match self {
            Self::Detailed {
                package: Some(name),
                ..
            } => name.clone(),
            _ => key.to_string(),
        }
    }
}

fn collect_manifest_declarations(
    table: &HashMap<String, ManifestDep>,
    section: ManifestSection,
    declarations: &mut Vec<CargoDeclaration>,
) {
    for (key, dependency) in table {
        declarations.push(CargoDeclaration {
            alias: key.clone(),
            package: dependency.crate_name(key),
            path: match dependency {
                ManifestDep::Detailed { path, .. } => path.clone(),
                ManifestDep::Version(_) => None,
            },
            section,
        });
    }
}
