use std::collections::{HashSet, VecDeque};
use std::path::Path;

use miette::{bail, Result};
use semver::Version;

use crate::ecosystem;
use crate::finding::rules::duplicate_findings;
use crate::finding::FindingDetails;
use crate::model::Ecosystem;
use crate::model::{ComponentId, ProjectSnapshot};
use crate::types::{
    DuplicateAnalysis, DuplicateGroup, DuplicateSeverity, DuplicateStats, DuplicateVersion,
};

/// Analyzer for detecting duplicate dependencies
pub struct DuplicateAnalyzer<'a> {
    root: &'a Path,
}

pub const DUPLICATE_SCHEMA_VERSION: u32 = 2;

impl<'a> DuplicateAnalyzer<'a> {
    pub fn new(root: &'a Path) -> Self {
        Self { root }
    }

    /// Analyze the project for duplicate dependencies
    pub fn analyze(&self) -> Result<DuplicateAnalysis> {
        let adapter = ecosystem::detect(self.root)?;
        match adapter.ecosystem() {
            Ecosystem::Cargo => self.analyze_cargo(adapter),
            Ecosystem::Npm => {
                bail!("Duplicate analysis currently only supports Cargo.lock (Rust projects)")
            }
        }
    }

    /// Analyze Cargo.lock for duplicates
    fn analyze_cargo(
        &self,
        adapter: &dyn crate::ecosystem::EcosystemAdapter,
    ) -> Result<DuplicateAnalysis> {
        let snapshot = adapter.build_snapshot(self.root)?;
        let findings = duplicate_findings(&snapshot)?;
        let mut duplicates = Vec::new();
        for finding in findings {
            let FindingDetails::DuplicateVersions { components, .. } = finding.details else {
                continue;
            };
            let mut version_infos: Vec<_> = components
                .iter()
                .map(|component| {
                    let mut dependent_components: Vec<_> = snapshot
                        .dependency_edges
                        .iter()
                        .filter(|edge| edge.to == *component)
                        .map(|edge| edge.from.clone())
                        .collect();
                    dependent_components.sort();
                    dependent_components.dedup();
                    let mut dependents: Vec<_> = dependent_components
                        .iter()
                        .map(|id| id.name.clone())
                        .collect();
                    dependents.sort();
                    dependents.dedup();
                    DuplicateVersion {
                        component: component.clone(),
                        version: component.version.clone(),
                        dependents,
                        dependent_components,
                        direct_roots: direct_roots(&snapshot, component),
                    }
                })
                .collect();
            version_infos.sort_by(|left, right| {
                compare_versions(&left.version, &right.version)
                    .then_with(|| left.dependents.cmp(&right.dependents))
                    .then_with(|| left.component.cmp(&right.component))
            });
            let severity = calculate_severity(&version_infos);
            let major_version_count = distinct_major_versions(&version_infos);
            duplicates.push(DuplicateGroup {
                name: finding.subject.name,
                installation_count: version_infos.len(),
                major_version_count,
                extra_compile_units: version_infos.len().saturating_sub(1),
                versions: version_infos,
                severity,
            });
        }

        // Sort by severity (high first), then by name
        duplicates.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.name.cmp(&b.name))
        });

        // Calculate stats
        let stats = DuplicateStats {
            total_duplicates: duplicates.len(),
            medium_severity: duplicates
                .iter()
                .filter(|d| d.severity == DuplicateSeverity::Medium)
                .count(),
            low_severity: duplicates
                .iter()
                .filter(|d| d.severity == DuplicateSeverity::Low)
                .count(),
            extra_compile_units: duplicates.iter().map(|d| d.versions.len() - 1).sum(),
        };

        Ok(DuplicateAnalysis {
            schema_version: DUPLICATE_SCHEMA_VERSION,
            duplicates,
            stats,
        })
    }
}

/// Compare two version strings, handling semver and non-semver
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    match (Version::parse(a), Version::parse(b)) {
        (Ok(va), Ok(vb)) => va.cmp(&vb),
        _ => a.cmp(b),
    }
}

/// Calculate severity based on version differences
fn calculate_severity(versions: &[DuplicateVersion]) -> DuplicateSeverity {
    if distinct_major_versions(versions) > 1 {
        DuplicateSeverity::Medium
    } else {
        DuplicateSeverity::Low
    }
}

fn distinct_major_versions(versions: &[DuplicateVersion]) -> usize {
    versions
        .iter()
        .filter_map(|v| Version::parse(&v.version).ok())
        .map(|v| v.major)
        .collect::<HashSet<_>>()
        .len()
}

fn direct_roots(snapshot: &ProjectSnapshot, target: &ComponentId) -> Vec<ComponentId> {
    let direct: HashSet<_> = snapshot
        .components
        .iter()
        .filter(|component| component.direct)
        .map(|component| component.id.clone())
        .collect();
    let mut roots = HashSet::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::from([target.clone()]);
    while let Some(current) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        if direct.contains(&current) {
            roots.insert(current);
            continue;
        }
        for edge in snapshot
            .dependency_edges
            .iter()
            .filter(|edge| edge.to == current)
        {
            queue.push_back(edge.from.clone());
        }
    }
    let mut roots: Vec<_> = roots.into_iter().collect();
    roots.sort();
    roots
}

/// Suggest which version to upgrade to
pub fn suggest_resolution(group: &DuplicateGroup) -> Option<String> {
    if group.versions.is_empty() {
        return None;
    }

    // Find the newest version
    let newest = group.versions.last()?;

    // Find dependents that are using older versions
    let outdated_dependents: Vec<&str> = group
        .versions
        .iter()
        .filter(|v| v.version != newest.version)
        .flat_map(|v| v.dependents.iter().map(|s| s.as_str()))
        .collect();

    if outdated_dependents.is_empty() {
        return None;
    }

    Some(format!(
        "Update {} to use {} {}",
        outdated_dependents.join(", "),
        group.name,
        newest.version
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(value: &str) -> DuplicateVersion {
        DuplicateVersion {
            component: ComponentId {
                ecosystem: Ecosystem::Cargo,
                name: "sample".to_string(),
                version: value.to_string(),
                location: Some(format!("registry:{value}")),
            },
            version: value.to_string(),
            dependents: vec![],
            dependent_components: vec![],
            direct_roots: vec![],
        }
    }

    #[test]
    fn test_severity_same_major() {
        let versions = vec![version("1.0.0"), version("1.2.0")];

        assert_eq!(calculate_severity(&versions), DuplicateSeverity::Low);
    }

    #[test]
    fn test_severity_different_major() {
        let versions = vec![version("1.0.0"), version("2.0.0")];

        assert_eq!(calculate_severity(&versions), DuplicateSeverity::Medium);
    }

    #[test]
    fn test_severity_many_versions() {
        let versions = vec![version("1.0.0"), version("1.1.0"), version("1.2.0")];

        assert_eq!(calculate_severity(&versions), DuplicateSeverity::Low);
    }

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("1.0.0", "2.0.0"), std::cmp::Ordering::Less);
        assert_eq!(
            compare_versions("1.2.0", "1.1.0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("1.0.0", "1.0.0"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_versions("2.0.0", "10.0.0"),
            std::cmp::Ordering::Less
        );
    }
}
