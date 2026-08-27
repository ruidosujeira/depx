use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use miette::{Context, IntoDiagnostic, Result};
use serde::Deserialize;

use crate::model::{
    Component, ComponentId, DependencyEdge, DependencyKind, Ecosystem, ProjectSnapshot,
};

use super::javascript::{
    project_units, read_manifests, ManifestRecord, ResolvedManifestDeclaration,
};
use super::EcosystemAdapter;

/// Adapter for npm `package-lock.json` projects.
pub struct NpmAdapter;

impl EcosystemAdapter for NpmAdapter {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("package-lock.json").is_file()
    }

    fn build_snapshot(&self, root: &Path) -> Result<ProjectSnapshot> {
        let lockfile_path = root.join("package-lock.json");
        let content = std::fs::read_to_string(&lockfile_path)
            .into_diagnostic()
            .with_context(|| format!("Failed to read {}", lockfile_path.display()))?;
        let lockfile: NpmLockfile = serde_json::from_str(&content)
            .into_diagnostic()
            .wrap_err("Failed to parse package-lock.json")?;
        let manifests = read_manifests(root, &[])?;

        if !lockfile.packages.is_empty() {
            build_v2_snapshot(root, lockfile, manifests)
        } else {
            build_v1_snapshot(root, lockfile, manifests)
        }
    }
}

fn build_v2_snapshot(
    root: &Path,
    lockfile: NpmLockfile,
    manifests: Vec<ManifestRecord>,
) -> Result<ProjectSnapshot> {
    let mut ids_by_location = HashMap::new();
    for (location, info) in &lockfile.packages {
        if location.is_empty() || !location.contains("node_modules/") || info.link.unwrap_or(false)
        {
            continue;
        }
        let name = extract_package_name_from_path(location);
        if name.is_empty() {
            continue;
        }
        let id = ComponentId {
            ecosystem: Ecosystem::Npm,
            name: name.clone(),
            version: info.version.clone().unwrap_or_default(),
            location: Some(location.clone()),
        };
        ids_by_location.insert(location.clone(), id);
    }
    let declarations = resolve_manifest_declarations(&manifests, &ids_by_location);
    let units = project_units(&manifests, &declarations);
    let direct_ids: HashSet<_> = declarations.iter().map(|item| item.id.clone()).collect();
    let runtime_ids: HashSet<_> = declarations
        .iter()
        .filter(|item| !item.dev)
        .map(|item| item.id.clone())
        .collect();
    let components: Vec<_> = lockfile
        .packages
        .iter()
        .filter_map(|(location, info)| {
            let id = ids_by_location.get(location)?.clone();
            let direct = direct_ids.contains(&id);
            Some(Component {
                id,
                direct,
                dev: if direct {
                    !runtime_ids.contains(ids_by_location.get(location)?)
                } else {
                    info.dev.unwrap_or(false)
                },
                deprecated: info.deprecated.clone(),
            })
        })
        .collect();

    let mut edges = Vec::new();
    for (location, info) in &lockfile.packages {
        let Some(from) = ids_by_location.get(location) else {
            continue;
        };
        let mut declarations: BTreeMap<&str, DependencyKind> = info
            .dependencies
            .keys()
            .map(|name| (name.as_str(), DependencyKind::Runtime))
            .collect();
        for name in info.optional_dependencies.keys() {
            declarations.insert(name, DependencyKind::Optional);
        }
        for (name, kind) in declarations {
            if let Some(to) = resolve_npm_dependency(location, name, &ids_by_location) {
                edges.push(DependencyEdge {
                    from: from.clone(),
                    to: to.clone(),
                    kind,
                });
            }
        }
    }

    finish_snapshot(root, components, edges, units)
}

fn build_v1_snapshot(
    root: &Path,
    lockfile: NpmLockfile,
    manifests: Vec<ManifestRecord>,
) -> Result<ProjectSnapshot> {
    let mut records = Vec::new();
    collect_v1_records(&lockfile.dependencies, "", &mut records);

    let mut ids_by_location = HashMap::new();
    for record in &records {
        let id = ComponentId {
            ecosystem: Ecosystem::Npm,
            name: record.name.clone(),
            version: record.dependency.version.clone(),
            location: Some(record.location.clone()),
        };
        ids_by_location.insert(record.location.clone(), id);
    }
    let declarations = resolve_manifest_declarations(&manifests, &ids_by_location);
    let units = project_units(&manifests, &declarations);
    let direct_ids: HashSet<_> = declarations.iter().map(|item| item.id.clone()).collect();
    let runtime_ids: HashSet<_> = declarations
        .iter()
        .filter(|item| !item.dev)
        .map(|item| item.id.clone())
        .collect();
    let components: Vec<_> = records
        .iter()
        .filter_map(|record| {
            let id = ids_by_location.get(&record.location)?.clone();
            let direct = direct_ids.contains(&id);
            Some(Component {
                id,
                direct,
                dev: if direct {
                    !runtime_ids.contains(ids_by_location.get(&record.location)?)
                } else {
                    record.dependency.dev.unwrap_or(false)
                },
                deprecated: None,
            })
        })
        .collect();

    let mut edges = Vec::new();
    for record in records {
        let Some(from) = ids_by_location.get(&record.location) else {
            continue;
        };
        for name in record.dependency.requires.keys() {
            if let Some(to) = resolve_npm_dependency(&record.location, name, &ids_by_location) {
                edges.push(DependencyEdge {
                    from: from.clone(),
                    to: to.clone(),
                    kind: DependencyKind::Runtime,
                });
            }
        }
    }

    finish_snapshot(root, components, edges, units)
}

fn resolve_manifest_declarations(
    manifests: &[ManifestRecord],
    ids_by_location: &HashMap<String, ComponentId>,
) -> Vec<ResolvedManifestDeclaration> {
    let mut declarations = Vec::new();
    for record in manifests {
        let from = record.directory.to_string_lossy().replace('\\', "/");
        for declaration in record.manifest.declarations() {
            if let Some(id) = resolve_npm_dependency(&from, &declaration.name, ids_by_location) {
                declarations.push(ResolvedManifestDeclaration {
                    name: declaration.name,
                    id: id.clone(),
                    unit_root: record.directory.clone(),
                    section: declaration.section,
                    dev: declaration.dev,
                });
            }
        }
    }
    declarations.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.unit_root.cmp(&right.unit_root))
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

fn finish_snapshot(
    root: &Path,
    components: Vec<Component>,
    edges: Vec<DependencyEdge>,
    units: Vec<crate::model::ProjectUnit>,
) -> Result<ProjectSnapshot> {
    ProjectSnapshot::new(root.to_path_buf(), components, edges).with_units(units)
}

struct V1Record<'a> {
    name: String,
    location: String,
    dependency: &'a NpmDependency,
}

fn collect_v1_records<'a>(
    dependencies: &'a HashMap<String, NpmDependency>,
    parent: &str,
    records: &mut Vec<V1Record<'a>>,
) {
    for (name, dependency) in dependencies {
        let location = if parent.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{parent}/node_modules/{name}")
        };
        records.push(V1Record {
            name: name.clone(),
            location: location.clone(),
            dependency,
        });
        collect_v1_records(&dependency.dependencies, &location, records);
    }
}

/// Resolve using Node's nearest-`node_modules` lookup order.
fn resolve_npm_dependency<'a>(
    from_location: &str,
    dependency_name: &str,
    ids_by_location: &'a HashMap<String, ComponentId>,
) -> Option<&'a ComponentId> {
    let mut base = Some(from_location);
    while let Some(path) = base {
        let candidate = if path.is_empty() {
            format!("node_modules/{dependency_name}")
        } else {
            format!("{path}/node_modules/{dependency_name}")
        };
        if let Some(id) = ids_by_location.get(&candidate) {
            return Some(id);
        }
        base = path.rfind("node_modules/").map(|index| {
            let prefix = path[..index].trim_end_matches('/');
            prefix
                .trim_end_matches("/node_modules")
                .trim_end_matches('/')
        });
        if base == Some(path) {
            break;
        }
    }
    ids_by_location.get(&format!("node_modules/{dependency_name}"))
}

fn extract_package_name_from_path(path: &str) -> String {
    let name_part = path
        .rsplit_once("node_modules/")
        .map_or(path, |(_, name)| name);
    if name_part.starts_with('@') {
        let mut segments = name_part.split('/');
        if let (Some(scope), Some(package)) = (segments.next(), segments.next()) {
            return format!("{scope}/{package}");
        }
    }
    name_part.split('/').next().unwrap_or_default().to_string()
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NpmLockfile {
    #[serde(default)]
    packages: HashMap<String, NpmPackageInfo>,
    #[serde(default)]
    dependencies: HashMap<String, NpmDependency>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NpmPackageInfo {
    version: Option<String>,
    link: Option<bool>,
    dev: Option<bool>,
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(default)]
    optional_dependencies: HashMap<String, String>,
    deprecated: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct NpmDependency {
    version: String,
    dev: Option<bool>,
    #[serde(default)]
    requires: HashMap<String, String>,
    #[serde(default)]
    dependencies: HashMap<String, NpmDependency>,
}

#[cfg(test)]
mod tests {
    use super::extract_package_name_from_path;

    #[test]
    fn extracts_scoped_and_nested_names() {
        assert_eq!(
            extract_package_name_from_path("node_modules/lodash"),
            "lodash"
        );
        assert_eq!(
            extract_package_name_from_path("node_modules/@types/node"),
            "@types/node"
        );
        assert_eq!(
            extract_package_name_from_path("node_modules/foo/node_modules/bar"),
            "bar"
        );
    }
}
