use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use miette::{Context, IntoDiagnostic, Result};
use serde::Deserialize;

use crate::evidence::{manifest_evidence, transitive_evidence, ManifestSection};
use crate::model::{
    Component, ComponentId, DependencyEdge, DependencyKind, Ecosystem, ProjectSnapshot,
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
        let manifest = read_manifest(root)?;

        if !lockfile.packages.is_empty() {
            build_v2_snapshot(root, lockfile, manifest)
        } else {
            build_v1_snapshot(root, lockfile, manifest)
        }
    }
}

fn read_manifest(root: &Path) -> Result<PackageJson> {
    let path = root.join("package.json");
    if !path.exists() {
        return Ok(PackageJson::default());
    }
    let content = std::fs::read_to_string(&path)
        .into_diagnostic()
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&content)
        .into_diagnostic()
        .wrap_err("Failed to parse package.json")
}

fn build_v2_snapshot(
    root: &Path,
    lockfile: NpmLockfile,
    manifest: PackageJson,
) -> Result<ProjectSnapshot> {
    let direct: HashSet<&str> = manifest
        .dependencies
        .keys()
        .chain(manifest.dev_dependencies.keys())
        .chain(manifest.optional_dependencies.keys())
        .chain(manifest.peer_dependencies.keys())
        .map(String::as_str)
        .collect();
    let dev: HashSet<&str> = manifest
        .dev_dependencies
        .keys()
        .map(String::as_str)
        .collect();

    let mut components = Vec::new();
    let mut ids_by_location = HashMap::new();
    for (location, info) in &lockfile.packages {
        if location.is_empty() {
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
        let is_top_level = location.as_str() == format!("node_modules/{name}");
        components.push(Component {
            id: id.clone(),
            direct: is_top_level && direct.contains(name.as_str()),
            dev: info.dev.unwrap_or(false) || (is_top_level && dev.contains(name.as_str())),
            deprecated: info.deprecated.clone(),
        });
        ids_by_location.insert(location.clone(), id);
    }

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

    build_snapshot_with_evidence(root, components, edges, &manifest)
}

fn build_v1_snapshot(
    root: &Path,
    lockfile: NpmLockfile,
    manifest: PackageJson,
) -> Result<ProjectSnapshot> {
    let direct: HashSet<&str> = manifest
        .dependencies
        .keys()
        .chain(manifest.dev_dependencies.keys())
        .chain(manifest.optional_dependencies.keys())
        .chain(manifest.peer_dependencies.keys())
        .map(String::as_str)
        .collect();
    let dev: HashSet<&str> = manifest
        .dev_dependencies
        .keys()
        .map(String::as_str)
        .collect();
    let mut records = Vec::new();
    collect_v1_records(&lockfile.dependencies, "", &mut records);

    let mut components = Vec::new();
    let mut ids_by_location = HashMap::new();
    for record in &records {
        let is_top_level = record.location == format!("node_modules/{}", record.name);
        let id = ComponentId {
            ecosystem: Ecosystem::Npm,
            name: record.name.clone(),
            version: record.dependency.version.clone(),
            location: Some(record.location.clone()),
        };
        components.push(Component {
            id: id.clone(),
            direct: is_top_level && direct.contains(record.name.as_str()),
            dev: record.dependency.dev.unwrap_or(false)
                || (is_top_level && dev.contains(record.name.as_str())),
            deprecated: None,
        });
        ids_by_location.insert(record.location.clone(), id);
    }

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

    build_snapshot_with_evidence(root, components, edges, &manifest)
}

fn build_snapshot_with_evidence(
    root: &Path,
    components: Vec<Component>,
    edges: Vec<DependencyEdge>,
    manifest: &PackageJson,
) -> Result<ProjectSnapshot> {
    let mut evidence = Vec::new();
    for component in components.iter().filter(|component| component.direct) {
        for section in manifest.sections_for(&component.id.name) {
            evidence.push(manifest_evidence(
                component.id.clone(),
                "package.json".into(),
                section,
            )?);
        }
    }
    evidence.extend(transitive_evidence(&edges, "package-lock.json".into())?);
    ProjectSnapshot::new(root.to_path_buf(), components, edges).with_evidence(evidence)
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
        let candidate = format!("{path}/node_modules/{dependency_name}");
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

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PackageJson {
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(default)]
    dev_dependencies: HashMap<String, String>,
    #[serde(default)]
    optional_dependencies: HashMap<String, String>,
    #[serde(default)]
    peer_dependencies: HashMap<String, String>,
}

impl PackageJson {
    fn sections_for(&self, name: &str) -> Vec<ManifestSection> {
        let tables = [
            (&self.dependencies, ManifestSection::Dependencies),
            (&self.dev_dependencies, ManifestSection::DevDependencies),
            (
                &self.optional_dependencies,
                ManifestSection::OptionalDependencies,
            ),
            (&self.peer_dependencies, ManifestSection::PeerDependencies),
        ];
        tables
            .into_iter()
            .filter_map(|(table, section)| table.contains_key(name).then_some(section))
            .collect()
    }
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
