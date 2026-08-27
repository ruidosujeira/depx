use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use miette::{Context, IntoDiagnostic, Result};
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};

use crate::model::{
    Component, ComponentId, DependencyEdge, DependencyKind, Ecosystem, ProjectSnapshot,
};

use super::javascript::{
    project_units, read_manifests, ManifestRecord, ResolvedManifestDeclaration,
};
use super::EcosystemAdapter;

/// Adapter for pnpm lockfiles (v6 through v9 layouts).
pub struct PnpmAdapter;

impl EcosystemAdapter for PnpmAdapter {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("pnpm-lock.yaml").is_file()
    }

    fn build_snapshot(&self, root: &Path) -> Result<ProjectSnapshot> {
        let lockfile_path = root.join("pnpm-lock.yaml");
        let content = fs::read_to_string(&lockfile_path)
            .into_diagnostic()
            .with_context(|| format!("Failed to read {}", lockfile_path.display()))?;
        let lockfile: Value = serde_yaml_ng::from_str(&content)
            .into_diagnostic()
            .wrap_err("Failed to parse pnpm-lock.yaml")?;
        let workspace_patterns = read_pnpm_workspace_patterns(root)?;
        let manifests = read_manifests(root, &workspace_patterns)?;
        build_snapshot(root, &lockfile, manifests)
    }
}

#[derive(Debug)]
struct PnpmRecord<'a> {
    key: String,
    name: String,
    version: String,
    info: &'a Value,
}

fn build_snapshot(
    root: &Path,
    lockfile: &Value,
    manifests: Vec<ManifestRecord>,
) -> Result<ProjectSnapshot> {
    let root_mapping = lockfile
        .as_mapping()
        .ok_or_else(|| miette::miette!("pnpm-lock.yaml root must be a mapping"))?;
    let packages = mapping_at(root_mapping, "packages");
    let snapshots = mapping_at(root_mapping, "snapshots");
    let records_mapping = snapshots
        .or(packages)
        .ok_or_else(|| miette::miette!("pnpm-lock.yaml does not contain packages or snapshots"))?;
    let mut records = Vec::new();
    for (key, info) in records_mapping {
        let Some(key) = key.as_str() else {
            continue;
        };
        let Some((name, version)) = parse_pnpm_key(key) else {
            continue;
        };
        records.push(PnpmRecord {
            key: key.to_string(),
            name,
            version,
            info,
        });
    }
    records.sort_by(|left, right| left.key.cmp(&right.key));

    let mut ids_by_key = HashMap::new();
    let mut ids_by_name_version: BTreeMap<(String, String), Vec<ComponentId>> = BTreeMap::new();
    for record in &records {
        let id = ComponentId {
            ecosystem: Ecosystem::Npm,
            name: record.name.clone(),
            version: record.version.clone(),
            location: Some(format!("pnpm:{}", record.key)),
        };
        ids_by_key.insert(record.key.clone(), id.clone());
        ids_by_name_version
            .entry((record.name.clone(), record.version.clone()))
            .or_default()
            .push(id);
    }
    let declarations = resolve_declarations(
        &manifests,
        mapping_at(root_mapping, "importers"),
        &ids_by_key,
        &ids_by_name_version,
    );
    let direct_ids: HashSet<_> = declarations.iter().map(|item| item.id.clone()).collect();
    let runtime_ids: HashSet<_> = declarations
        .iter()
        .filter(|item| !item.dev)
        .map(|item| item.id.clone())
        .collect();

    let components: Vec<_> = records
        .iter()
        .filter_map(|record| {
            let id = ids_by_key.get(&record.key)?.clone();
            let direct = direct_ids.contains(&id);
            let metadata = packages
                .and_then(|items| lookup_mapping(items, &record.key))
                .unwrap_or(record.info);
            Some(Component {
                id,
                direct,
                dev: if direct {
                    !runtime_ids.contains(ids_by_key.get(&record.key)?)
                } else {
                    bool_at(metadata, "dev").unwrap_or(false)
                },
                deprecated: string_at(metadata, "deprecated").map(str::to_string),
            })
        })
        .collect();

    let mut edges = Vec::new();
    for record in &records {
        let Some(from) = ids_by_key.get(&record.key) else {
            continue;
        };
        let Some(info) = record.info.as_mapping() else {
            continue;
        };
        let mut dependencies: BTreeMap<String, (String, DependencyKind)> = BTreeMap::new();
        collect_dependency_mapping(
            mapping_at(info, "dependencies"),
            DependencyKind::Runtime,
            &mut dependencies,
        );
        collect_dependency_mapping(
            mapping_at(info, "optionalDependencies"),
            DependencyKind::Optional,
            &mut dependencies,
        );
        for (name, (version, kind)) in dependencies {
            if let Some(to) =
                resolve_pnpm_dependency(&name, &version, &ids_by_key, &ids_by_name_version)
            {
                edges.push(DependencyEdge {
                    from: from.clone(),
                    to,
                    kind,
                });
            }
        }
    }

    let units = project_units(&manifests, &declarations);
    ProjectSnapshot::new(root.to_path_buf(), components, edges).with_units(units)
}

fn resolve_declarations(
    manifests: &[ManifestRecord],
    importers: Option<&Mapping>,
    ids_by_key: &HashMap<String, ComponentId>,
    ids_by_name_version: &BTreeMap<(String, String), Vec<ComponentId>>,
) -> Vec<ResolvedManifestDeclaration> {
    let mut declarations = Vec::new();
    for record in manifests {
        let importer_key = if record.directory.as_os_str().is_empty() {
            ".".to_string()
        } else {
            record.directory.to_string_lossy().replace('\\', "/")
        };
        let importer = importers.and_then(|items| lookup_mapping(items, &importer_key));
        for declaration in record.manifest.declarations() {
            let resolved_version = importer
                .and_then(Value::as_mapping)
                .and_then(|mapping| importer_dependency(mapping, &declaration.name));
            let id = resolved_version
                .as_deref()
                .and_then(|version| {
                    resolve_pnpm_dependency(
                        &declaration.name,
                        version,
                        ids_by_key,
                        ids_by_name_version,
                    )
                })
                .or_else(|| unique_name_match(&declaration.name, ids_by_name_version));
            if let Some(id) = id {
                declarations.push(ResolvedManifestDeclaration {
                    name: declaration.name,
                    id,
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

fn importer_dependency(importer: &Mapping, name: &str) -> Option<String> {
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let item = mapping_at(importer, section).and_then(|items| lookup_mapping(items, name));
        if let Some(item) = item {
            return dependency_version(item);
        }
    }
    None
}

fn collect_dependency_mapping(
    mapping: Option<&Mapping>,
    kind: DependencyKind,
    output: &mut BTreeMap<String, (String, DependencyKind)>,
) {
    let Some(mapping) = mapping else {
        return;
    };
    for (name, value) in mapping {
        if let (Some(name), Some(version)) = (name.as_str(), dependency_version(value)) {
            output.insert(name.to_string(), (version, kind));
        }
    }
}

fn dependency_version(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string).or_else(|| {
        value
            .as_mapping()
            .and_then(|mapping| string_at_mapping(mapping, "version"))
            .map(str::to_string)
    })
}

fn resolve_pnpm_dependency(
    name: &str,
    raw_version: &str,
    ids_by_key: &HashMap<String, ComponentId>,
    ids_by_name_version: &BTreeMap<(String, String), Vec<ComponentId>>,
) -> Option<ComponentId> {
    let raw_version = raw_version.trim_matches('"');
    for key in [
        format!("{name}@{raw_version}"),
        format!("/{name}@{raw_version}"),
        format!("/{name}/{raw_version}"),
    ] {
        if let Some(id) = ids_by_key.get(&key) {
            return Some(id.clone());
        }
    }
    let version = clean_pnpm_version(raw_version)?;
    let matches = ids_by_name_version.get(&(name.to_string(), version))?;
    (matches.len() == 1).then(|| matches[0].clone())
}

fn unique_name_match(
    name: &str,
    ids_by_name_version: &BTreeMap<(String, String), Vec<ComponentId>>,
) -> Option<ComponentId> {
    let matches: Vec<_> = ids_by_name_version
        .iter()
        .filter(|((package, _), _)| package == name)
        .flat_map(|(_, ids)| ids)
        .collect();
    (matches.len() == 1).then(|| matches[0].clone())
}

fn parse_pnpm_key(key: &str) -> Option<(String, String)> {
    let key = key.trim_start_matches('/');
    let key = key.split('(').next().unwrap_or(key);
    let (name, version) = if key.starts_with('@') {
        let index = key.rfind('@')?;
        (&key[..index], &key[index + 1..])
    } else if let Some((name, version)) = key.rsplit_once('@') {
        (name, version)
    } else {
        key.rsplit_once('/')?
    };
    let version = clean_pnpm_version(version)?;
    (!name.is_empty()).then(|| (name.to_string(), version))
}

fn clean_pnpm_version(value: &str) -> Option<String> {
    let value = value.strip_prefix("npm:").unwrap_or(value);
    let value = value.split('(').next().unwrap_or(value);
    if value.is_empty()
        || value.starts_with("link:")
        || value.starts_with("file:")
        || value.starts_with("workspace:")
    {
        return None;
    }
    Some(value.to_string())
}

fn mapping_at<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Mapping> {
    lookup_mapping(mapping, key)?.as_mapping()
}

fn lookup_mapping<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_string()))
}

fn string_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .as_mapping()
        .and_then(|mapping| string_at_mapping(mapping, key))
}

fn string_at_mapping<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a str> {
    lookup_mapping(mapping, key)?.as_str()
}

fn bool_at(value: &Value, key: &str) -> Option<bool> {
    value
        .as_mapping()
        .and_then(|mapping| lookup_mapping(mapping, key))?
        .as_bool()
}

#[derive(Debug, Deserialize, Default)]
struct PnpmWorkspace {
    #[serde(default)]
    packages: Vec<String>,
}

fn read_pnpm_workspace_patterns(root: &Path) -> Result<Vec<String>> {
    let path = root.join("pnpm-workspace.yaml");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path)
        .into_diagnostic()
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let workspace: PnpmWorkspace = serde_yaml_ng::from_str(&content)
        .into_diagnostic()
        .wrap_err("Failed to parse pnpm-workspace.yaml")?;
    Ok(workspace.packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scoped_peer_and_legacy_package_keys() {
        assert_eq!(
            parse_pnpm_key("@scope/pkg@1.2.3(peer@2.0.0)"),
            Some(("@scope/pkg".to_string(), "1.2.3".to_string()))
        );
        assert_eq!(
            parse_pnpm_key("/plain@2.0.0"),
            Some(("plain".to_string(), "2.0.0".to_string()))
        );
        assert_eq!(
            parse_pnpm_key("/legacy/3.0.0"),
            Some(("legacy".to_string(), "3.0.0".to_string()))
        );
    }
}
