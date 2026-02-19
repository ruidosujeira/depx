use std::path::Path;

use miette::{bail, Result};
use semver::Version;

use crate::lockfile::{CargoLockfileParser, LockfileParser, LockfileType};
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
        let lockfile_parser = LockfileParser::new(self.root)?;

        match lockfile_parser.lockfile_type() {
            LockfileType::Cargo => self.analyze_cargo(lockfile_parser.lockfile_path()),
            LockfileType::Npm => self.analyze_npm(lockfile_parser.lockfile_path()),
            _ => {
                bail!("Duplicate analysis currently only supports Cargo.lock and package-lock.json")
            }
        }
    }

    /// Analyze Cargo.lock for duplicates
    fn analyze_cargo(&self, lockfile_path: &Path) -> Result<DuplicateAnalysis> {
        let parser = CargoLockfileParser::new(lockfile_path);
        let packages_by_name = parser.parse_for_duplicates()?;
        self.analyze_generic(packages_by_name)
    }

    /// Analyze package-lock.json for duplicates
    fn analyze_npm(&self, lockfile_path: &Path) -> Result<DuplicateAnalysis> {
        let parser = crate::lockfile::NpmLockfileParser::new(self.root, lockfile_path);
        let packages_by_name = parser.parse_for_duplicates()?;
        self.analyze_generic(packages_by_name)
    }

    fn analyze_generic(
        &self,
        packages_by_name: std::collections::HashMap<String, Vec<crate::lockfile::CargoPackageInfo>>,
    ) -> Result<DuplicateAnalysis> {
        let mut duplicates = Vec::new();

        for (name, versions) in &packages_by_name {
            // Skip if only one version exists
            if versions.len() <= 1 {
                continue;
            }

            // Build version info
            let mut version_infos: Vec<DuplicateVersion> = versions
                .iter()
                .map(|v| {
                    let full_key = format!("{}@{}", name, v.version);
                    let transitive_count =
                        calculate_transitive_dependents(&full_key, &packages_by_name);

                    DuplicateVersion {
                        version: v.version.clone(),
                        dependents: v.dependents.clone(),
                        transitive_count,
                    }
                })
                .collect();

            // Sort versions for consistent output
            version_infos.sort_by(|a, b| compare_versions(&a.version, &b.version));

            // Calculate severity
            let severity = calculate_severity(&version_infos);

            duplicates.push(DuplicateGroup {
                name: name.clone(),
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

/// Calculate the number of transitive dependents for a package version
fn calculate_transitive_dependents(
    package_key: &str,
    packages_by_name: &std::collections::HashMap<String, Vec<crate::lockfile::CargoPackageInfo>>,
) -> usize {
    use std::collections::{HashSet, VecDeque};

    // First, we need a way to look up a package by its name@version key
    // We can build this map once if we want to optimize, but we'll search
    let mut reverse_graph: std::collections::HashMap<String, &Vec<String>> =
        std::collections::HashMap::new();
    for (name, versions) in packages_by_name {
        for v in versions {
            let key = format!("{}@{}", name, v.version);
            reverse_graph.insert(key, &v.dependents);
        }
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    // Start with the initial dependents
    if let Some(deps) = reverse_graph.get(package_key) {
        for dep in *deps {
            if visited.insert(dep.clone()) {
                queue.push_back(dep.clone());
            }
        }
    }

    let mut count = 0;
    while let Some(current) = queue.pop_front() {
        count += 1;
        if let Some(deps) = reverse_graph.get(&current) {
            for dep in *deps {
                if visited.insert(dep.clone()) {
                    queue.push_back(dep.clone());
                }
            }
        }
    }

    count
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
    fn test_transitive_calculation() {
        use crate::lockfile::CargoPackageInfo;
        use std::collections::HashMap;

        // Setup a mock dependency graph:
        // Root -> A@1.0.0 -> B@1.0.0 -> C@1.0.0
        // Root -> D@1.0.0 -> B@1.0.0

        let mut packages = HashMap::new();

        packages.insert(
            "A".to_string(),
            vec![CargoPackageInfo {
                version: "1.0.0".to_string(),
                dependents: vec!["root".to_string()],
                is_path_dep: false,
            }],
        );

        packages.insert(
            "B".to_string(),
            vec![CargoPackageInfo {
                version: "1.0.0".to_string(),
                dependents: vec!["A@1.0.0".to_string(), "D@1.0.0".to_string()],
                is_path_dep: false,
            }],
        );

        packages.insert(
            "C".to_string(),
            vec![CargoPackageInfo {
                version: "1.0.0".to_string(),
                dependents: vec!["B@1.0.0".to_string()],
                is_path_dep: false,
            }],
        );

        packages.insert(
            "D".to_string(),
            vec![CargoPackageInfo {
                version: "1.0.0".to_string(),
                dependents: vec!["root".to_string()],
                is_path_dep: false,
            }],
        );

        // Transitive dependents of C@1.0.0: B@1.0.0, A@1.0.0, D@1.0.0, root (4 total)
        assert_eq!(calculate_transitive_dependents("C@1.0.0", &packages), 4);

        // Transitive dependents of B@1.0.0: A@1.0.0, D@1.0.0, root (3 total)
        assert_eq!(calculate_transitive_dependents("B@1.0.0", &packages), 3);

        // Transitive dependents of A@1.0.0: root (1 total)
        assert_eq!(calculate_transitive_dependents("A@1.0.0", &packages), 1);
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
    }
}
