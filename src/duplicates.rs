use std::path::Path;

use miette::{bail, Result};
use semver::Version;

use crate::ecosystem;
use crate::finding::rules::duplicate_findings;
use crate::finding::FindingDetails;
use crate::model::Ecosystem;
use crate::types::{
    DuplicateAnalysis, DuplicateGroup, DuplicateSeverity, DuplicateStats, DuplicateVersion,
};

/// Analyzer for detecting duplicate dependencies
pub struct DuplicateAnalyzer<'a> {
    root: &'a Path,
}

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
                    let mut dependents: Vec<_> = snapshot
                        .dependency_edges
                        .iter()
                        .filter(|edge| edge.to == *component)
                        .map(|edge| edge.from.name.clone())
                        .collect();
                    dependents.sort();
                    dependents.dedup();
                    DuplicateVersion {
                        version: component.version.clone(),
                        dependents,
                        transitive_count: 0,
                    }
                })
                .collect();
            version_infos.sort_by(|left, right| {
                compare_versions(&left.version, &right.version)
                    .then_with(|| left.dependents.cmp(&right.dependents))
            });
            let severity = calculate_severity(&version_infos);
            duplicates.push(DuplicateGroup {
                name: finding.subject.name,
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
            high_severity: duplicates
                .iter()
                .filter(|d| d.severity == DuplicateSeverity::High)
                .count(),
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

        Ok(DuplicateAnalysis { duplicates, stats })
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
    if versions.len() >= 3 {
        // 3+ versions is always high severity
        return DuplicateSeverity::High;
    }

    // Parse major versions
    let major_versions: Vec<u64> = versions
        .iter()
        .filter_map(|v| Version::parse(&v.version).ok())
        .map(|v| v.major)
        .collect();

    if major_versions.is_empty() {
        return DuplicateSeverity::Low;
    }

    // Check if all major versions are the same
    let first_major = major_versions[0];
    let all_same_major = major_versions.iter().all(|&m| m == first_major);

    if all_same_major {
        DuplicateSeverity::Low
    } else {
        DuplicateSeverity::Medium
    }
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

    #[test]
    fn test_severity_same_major() {
        let versions = vec![
            DuplicateVersion {
                version: "1.0.0".to_string(),
                dependents: vec![],
                transitive_count: 0,
            },
            DuplicateVersion {
                version: "1.2.0".to_string(),
                dependents: vec![],
                transitive_count: 0,
            },
        ];

        assert_eq!(calculate_severity(&versions), DuplicateSeverity::Low);
    }

    #[test]
    fn test_severity_different_major() {
        let versions = vec![
            DuplicateVersion {
                version: "1.0.0".to_string(),
                dependents: vec![],
                transitive_count: 0,
            },
            DuplicateVersion {
                version: "2.0.0".to_string(),
                dependents: vec![],
                transitive_count: 0,
            },
        ];

        assert_eq!(calculate_severity(&versions), DuplicateSeverity::Medium);
    }

    #[test]
    fn test_severity_many_versions() {
        let versions = vec![
            DuplicateVersion {
                version: "1.0.0".to_string(),
                dependents: vec![],
                transitive_count: 0,
            },
            DuplicateVersion {
                version: "1.1.0".to_string(),
                dependents: vec![],
                transitive_count: 0,
            },
            DuplicateVersion {
                version: "1.2.0".to_string(),
                dependents: vec![],
                transitive_count: 0,
            },
        ];

        assert_eq!(calculate_severity(&versions), DuplicateSeverity::High);
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
