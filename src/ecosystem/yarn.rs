use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use miette::{Context, IntoDiagnostic, Result};

use crate::model::{
    Component, ComponentId, DependencyEdge, DependencyKind, Ecosystem, PackageManager,
    ProjectSnapshot,
};

use super::javascript::{
    project_units, read_manifests, ManifestRecord, ResolvedManifestDeclaration,
};
use super::EcosystemAdapter;

/// Adapter for Yarn classic and modern text lockfiles.
pub struct YarnAdapter;

impl EcosystemAdapter for YarnAdapter {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn detect(&self, root: &Path) -> bool {
        root.join("yarn.lock").is_file()
    }

    fn build_snapshot(&self, root: &Path) -> Result<ProjectSnapshot> {
        let path = root.join("yarn.lock");
        let content = fs::read_to_string(&path)
            .into_diagnostic()
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let entries = parse_yarn_lock(&content)?;
        let manifests = read_manifests(root, &[])?;
        build_snapshot(root, entries, manifests)
    }
}

#[derive(Debug, Clone)]
struct YarnEntry {
    descriptors: Vec<Descriptor>,
    /// Yarn Berry locator/resolution, including virtual peer context when present.
    locator: Option<String>,
    version: String,
    dependencies: BTreeMap<String, (String, DependencyKind)>,
}

#[derive(Debug, Clone)]
struct Descriptor {
    name: String,
    range: String,
}

fn build_snapshot(
    root: &Path,
    entries: Vec<YarnEntry>,
    manifests: Vec<ManifestRecord>,
) -> Result<ProjectSnapshot> {
    let mut ids_by_descriptor = HashMap::new();
    let mut ids_by_name: BTreeMap<String, Vec<ComponentId>> = BTreeMap::new();
    let mut entries_by_id = BTreeMap::new();
    for entry in entries {
        let Some(primary) = entry.descriptors.first() else {
            continue;
        };
        let locator = entry.locator.clone().unwrap_or_else(|| {
            let mut descriptors: Vec<_> = entry
                .descriptors
                .iter()
                .map(|descriptor| descriptor_key(&descriptor.name, &descriptor.range))
                .collect();
            descriptors.sort();
            descriptors.join(",")
        });
        let id = ComponentId {
            ecosystem: Ecosystem::Npm,
            name: primary.name.clone(),
            version: entry.version.clone(),
            location: Some(format!("yarn:{locator}")),
        };
        for descriptor in &entry.descriptors {
            ids_by_descriptor.insert(
                descriptor_key(&descriptor.name, &descriptor.range),
                id.clone(),
            );
        }
        let ids = ids_by_name.entry(primary.name.clone()).or_default();
        if !ids.contains(&id) {
            ids.push(id.clone());
        }
        entries_by_id.entry(id).or_insert(entry);
    }
    for ids in ids_by_name.values_mut() {
        ids.sort();
    }

    let declarations = resolve_declarations(&manifests, &ids_by_descriptor, &ids_by_name);
    let direct_ids: HashSet<_> = declarations.iter().map(|item| item.id.clone()).collect();
    let runtime_ids: HashSet<_> = declarations
        .iter()
        .filter(|item| !item.dev)
        .map(|item| item.id.clone())
        .collect();
    let components: Vec<_> = entries_by_id
        .keys()
        .map(|id| Component {
            id: id.clone(),
            direct: direct_ids.contains(id),
            dev: direct_ids.contains(id) && !runtime_ids.contains(id),
            deprecated: None,
        })
        .collect();

    let mut edges = Vec::new();
    for (from, entry) in &entries_by_id {
        for (name, (range, kind)) in &entry.dependencies {
            if let Some(to) = resolve_descriptor(name, range, &ids_by_descriptor, &ids_by_name) {
                edges.push(DependencyEdge {
                    from: from.clone(),
                    to,
                    kind: *kind,
                });
            }
        }
    }
    let units = project_units(&manifests, &declarations);
    ProjectSnapshot::new(root.to_path_buf(), components, edges)
        .with_units(units)?
        .with_package_manager(PackageManager::Yarn)
}

fn resolve_declarations(
    manifests: &[ManifestRecord],
    ids_by_descriptor: &HashMap<String, ComponentId>,
    ids_by_name: &BTreeMap<String, Vec<ComponentId>>,
) -> Vec<ResolvedManifestDeclaration> {
    let mut declarations = Vec::new();
    for record in manifests {
        for declaration in record.manifest.declarations() {
            if let Some(id) = resolve_descriptor(
                &declaration.name,
                manifest_range(record, &declaration.name).unwrap_or_default(),
                ids_by_descriptor,
                ids_by_name,
            ) {
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

// Declarations intentionally expose only names and roles. Re-read the compact
// JSON value here to retain the exact Yarn descriptor without expanding the
// public normalized manifest type.
fn manifest_range<'a>(record: &'a ManifestRecord, name: &str) -> Option<&'a str> {
    record.manifest.version_range(name)
}

fn resolve_descriptor(
    name: &str,
    range: &str,
    ids_by_descriptor: &HashMap<String, ComponentId>,
    ids_by_name: &BTreeMap<String, Vec<ComponentId>>,
) -> Option<ComponentId> {
    let key = descriptor_key(name, range);
    ids_by_descriptor.get(&key).cloned().or_else(|| {
        let matches = ids_by_name.get(name)?;
        (matches.len() == 1).then(|| matches[0].clone())
    })
}

fn descriptor_key(name: &str, range: &str) -> String {
    let range = range
        .trim_matches(['"', '\''])
        .strip_prefix("npm:")
        .unwrap_or(range.trim_matches(['"', '\'']));
    format!("{name}@{range}")
}

fn parse_yarn_lock(content: &str) -> Result<Vec<YarnEntry>> {
    let lines: Vec<_> = content.lines().collect();
    let mut entries = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if line.trim().is_empty()
            || line.trim_start().starts_with('#')
            || line.starts_with(char::is_whitespace)
            || !line.trim_end().ends_with(':')
            || line.trim_start().starts_with("__metadata")
        {
            index += 1;
            continue;
        }
        let key = line.trim().trim_end_matches(':').trim_matches('"');
        let descriptors: Vec<_> = key
            .split(',')
            .filter_map(|item| parse_descriptor(item.trim().trim_matches('"')))
            .collect();
        index += 1;
        let mut version = None;
        let mut locator = None;
        let mut dependencies = BTreeMap::new();
        while index < lines.len() {
            let body = lines[index];
            if !body.trim().is_empty() && !body.starts_with(char::is_whitespace) {
                break;
            }
            let trimmed = body.trim();
            if let Some(value) = field_value(trimmed, "version") {
                version = Some(value.to_string());
                index += 1;
                continue;
            }
            if let Some(value) = field_value(trimmed, "resolution") {
                locator = Some(value.to_string());
                index += 1;
                continue;
            }
            let dependency_kind = if trimmed == "dependencies:" || trimmed == "dependencies" {
                Some(DependencyKind::Runtime)
            } else if trimmed == "optionalDependencies:" || trimmed == "optionalDependencies" {
                Some(DependencyKind::Optional)
            } else {
                None
            };
            if let Some(kind) = dependency_kind {
                let section_indent = indentation(body);
                index += 1;
                while index < lines.len() && indentation(lines[index]) > section_indent {
                    if let Some((name, range)) = dependency_line(lines[index].trim()) {
                        dependencies.insert(name, (range, kind));
                    }
                    index += 1;
                }
                continue;
            }
            index += 1;
        }
        if let Some(version) = version {
            entries.push(YarnEntry {
                descriptors,
                locator,
                version,
                dependencies,
            });
        }
    }
    if entries.is_empty() {
        return Err(miette::miette!(
            "yarn.lock did not contain resolvable entries"
        ));
    }
    Ok(entries)
}

fn parse_descriptor(value: &str) -> Option<Descriptor> {
    let separator = value.rfind('@')?;
    if separator == 0 {
        return None;
    }
    let name = &value[..separator];
    let range = &value[separator + 1..];
    Some(Descriptor {
        name: name.to_string(),
        range: range.strip_prefix("npm:").unwrap_or(range).to_string(),
    })
}

fn field_value<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let rest = line
        .strip_prefix(&format!("{field}:"))
        .or_else(|| line.strip_prefix(&format!("{field} ")))?;
    Some(rest.trim().trim_matches(['"', '\'']))
}

fn dependency_line(line: &str) -> Option<(String, String)> {
    let (name, range) = line
        .split_once(':')
        .or_else(|| line.split_once(char::is_whitespace))?;
    Some((
        name.trim_matches(['"', '\'']).to_string(),
        range.trim().trim_matches(['"', '\'']).to_string(),
    ))
}

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_classic_and_modern_yarn_entries() {
        let entries = parse_yarn_lock(
            r#"# yarn lockfile v1
"@scope/pkg@^1.0.0":
  version "1.2.0"
  dependencies:
    child "^2.0.0"

child@npm:^2.0.0:
  version: 2.1.0
  resolution: "child@npm:2.1.0"
"#,
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].descriptors[0].name, "@scope/pkg");
        assert_eq!(entries[0].version, "1.2.0");
        assert!(entries[0].dependencies.contains_key("child"));
        assert_eq!(entries[1].version, "2.1.0");
        assert_eq!(entries[1].locator.as_deref(), Some("child@npm:2.1.0"));
    }

    #[test]
    fn modern_virtual_peer_contexts_have_distinct_component_ids() {
        let entries = parse_yarn_lock(
            r#"__metadata:
  version: 8

"peerful@virtual:aaa#npm:^1.0.0":
  version: 1.0.0
  resolution: "peerful@virtual:aaa#npm:1.0.0"

"peerful@virtual:bbb#npm:^1.0.0":
  version: 1.0.0
  resolution: "peerful@virtual:bbb#npm:1.0.0"
"#,
        )
        .unwrap();
        let manifests = Vec::new();
        let snapshot = build_snapshot(Path::new("."), entries, manifests).unwrap();
        let peerful: Vec<_> = snapshot
            .components
            .iter()
            .filter(|component| component.id.name == "peerful")
            .collect();
        assert_eq!(peerful.len(), 2);
        assert_ne!(peerful[0].id, peerful[1].id);
        assert!(peerful.iter().any(|component| component
            .id
            .location
            .as_deref()
            .is_some_and(|location| location.contains("virtual:aaa"))));
        assert!(peerful.iter().any(|component| component
            .id
            .location
            .as_deref()
            .is_some_and(|location| location.contains("virtual:bbb"))));
    }
}
