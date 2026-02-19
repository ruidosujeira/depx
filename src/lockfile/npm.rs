use std::collections::{HashMap, HashSet};
use std::path::Path;

use miette::{Context, IntoDiagnostic, Result};
use serde::Deserialize;

use crate::types::Package;

/// Parser for npm's package-lock.json
pub struct NpmLockfileParser<'a> {
    root: &'a Path,
    lockfile_path: &'a Path,
}

impl<'a> NpmLockfileParser<'a> {
    pub fn new(root: &'a Path, lockfile_path: &'a Path) -> Self {
        Self {
            root,
            lockfile_path,
        }
    }

    pub fn parse(&self) -> Result<HashMap<String, Package>> {
        let content = std::fs::read_to_string(self.lockfile_path)
            .into_diagnostic()
            .with_context(|| format!("Failed to read {}", self.lockfile_path.display()))?;

        let lockfile: NpmLockfile = serde_json::from_str(&content)
            .into_diagnostic()
            .with_context(|| "Failed to parse package-lock.json")?;

        // Also read package.json to know which are direct dependencies
        let package_json_path = self.root.join("package.json");
        let package_json: PackageJson = if package_json_path.exists() {
            let content = std::fs::read_to_string(&package_json_path)
                .into_diagnostic()
                .with_context(|| "Failed to read package.json")?;
            serde_json::from_str(&content)
                .into_diagnostic()
                .with_context(|| "Failed to parse package.json")?
        } else {
            PackageJson::default()
        };

        let direct_deps: HashSet<String> = package_json
            .dependencies
            .keys()
            .chain(package_json.dev_dependencies.keys())
            .cloned()
            .collect();

        let dev_deps: HashSet<String> = package_json.dev_dependencies.keys().cloned().collect();

        self.parse_lockfile_v3(&lockfile, &direct_deps, &dev_deps)
    }

    /// Parse lockfile format v2/v3 (npm 7+)
    fn parse_lockfile_v3(
        &self,
        lockfile: &NpmLockfile,
        direct_deps: &HashSet<String>,
        dev_deps: &HashSet<String>,
    ) -> Result<HashMap<String, Package>> {
        let mut packages = HashMap::new();

        // In v2/v3, packages are under the "packages" key
        // The keys are paths like "" (root), "node_modules/lodash", etc.
        for (path, pkg_info) in &lockfile.packages {
            // Skip the root package
            if path.is_empty() {
                continue;
            }

            // Extract package name from path
            // "node_modules/lodash" -> "lodash"
            // "node_modules/@scope/pkg" -> "@scope/pkg"
            // "node_modules/foo/node_modules/bar" -> "bar"
            let name = extract_package_name_from_path(path);
            if name.is_empty() {
                continue;
            }

            let version = pkg_info.version.clone().unwrap_or_default();
            let is_direct = direct_deps.contains(&name);
            let is_dev = pkg_info.dev.unwrap_or(false) || dev_deps.contains(&name);

            let dependencies: Vec<String> = pkg_info
                .dependencies
                .keys()
                .chain(pkg_info.optional_dependencies.keys())
                .cloned()
                .collect();

            let package = Package {
                name: name.clone(),
                version,
                is_direct,
                is_dev,
                dependencies,
                deprecated: pkg_info.deprecated.clone(),
            };

            // Use the name as key (this will keep the first occurrence for duplicates)
            packages.entry(name).or_insert(package);
        }

        // Fallback to v1 format if packages map is empty
        if packages.is_empty() && !lockfile.dependencies.is_empty() {
            return self.parse_lockfile_v1(lockfile, direct_deps, dev_deps);
        }

        Ok(packages)
    }

    /// Parse lockfile format v1 (npm 6 and earlier)
    fn parse_lockfile_v1(
        &self,
        lockfile: &NpmLockfile,
        direct_deps: &HashSet<String>,
        dev_deps: &HashSet<String>,
    ) -> Result<HashMap<String, Package>> {
        let mut packages = HashMap::new();

        fn collect_deps(
            deps: &HashMap<String, NpmDependency>,
            packages: &mut HashMap<String, Package>,
            direct_deps: &HashSet<String>,
            dev_deps: &HashSet<String>,
        ) {
            for (name, dep) in deps {
                let is_direct = direct_deps.contains(name);
                let is_dev = dep.dev.unwrap_or(false) || dev_deps.contains(name);

                let dependencies: Vec<String> = dep.requires.keys().cloned().collect();

                let package = Package {
                    name: name.clone(),
                    version: dep.version.clone(),
                    is_direct,
                    is_dev,
                    dependencies,
                    deprecated: None,
                };

                packages.entry(name.clone()).or_insert(package);

                // Recurse into nested dependencies
                collect_deps(&dep.dependencies, packages, direct_deps, dev_deps);
            }
        }

        collect_deps(&lockfile.dependencies, &mut packages, direct_deps, dev_deps);

        Ok(packages)
    }

    pub fn parse_for_duplicates(
        &self,
    ) -> Result<HashMap<String, Vec<crate::lockfile::CargoPackageInfo>>> {
        let content = std::fs::read_to_string(self.lockfile_path)
            .into_diagnostic()
            .with_context(|| format!("Failed to read {}", self.lockfile_path.display()))?;

        let lockfile: NpmLockfile = serde_json::from_str(&content)
            .into_diagnostic()
            .with_context(|| "Failed to parse package-lock.json")?;

        let mut by_name: HashMap<String, Vec<crate::lockfile::CargoPackageInfo>> = HashMap::new();
        let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

        // Build reverse dependency map for npm (v3)
        for (path, pkg_info) in &lockfile.packages {
            let pkg_name = if path.is_empty() {
                // For root, try to get name from pkg_info or use "root"
                pkg_info.name.clone().unwrap_or_else(|| "root".to_string())
            } else {
                extract_package_name_from_path(path)
            };

            let pkg_version = pkg_info.version.clone().unwrap_or_default();
            let pkg_key = format!("{}@{}", pkg_name, pkg_version);

            for dep_name in pkg_info.dependencies.keys() {
                // In npm, we don't always know the exact version of the dependency from the packages map alone
                // without resolving it. For simplicity in duplicate analysis, we'll map to the name for now,
                // or try to find the resolved path if possible.
                // However, the Cargo model uses name@version for keys.
                // For npm, we'll try to find the dependency version in the packages list.

                // Simplified: search for the dependency in node_modules
                let dep_path = if path.is_empty() {
                    format!("node_modules/{}", dep_name)
                } else {
                    format!("{}/node_modules/{}", path, dep_name)
                };

                // If not found nested, it's likely at the root node_modules
                let actual_dep_path = if lockfile.packages.contains_key(&dep_path) {
                    dep_path
                } else {
                    format!("node_modules/{}", dep_name)
                };

                if let Some(target_pkg) = lockfile.packages.get(&actual_dep_path) {
                    let target_version = target_pkg.version.clone().unwrap_or_default();
                    let target_key = format!("{}@{}", dep_name, target_version);

                    dependents
                        .entry(target_key)
                        .or_default()
                        .push(pkg_key.clone());
                } else {
                    // Fallback to just name if can't resolve version
                    dependents
                        .entry(dep_name.clone())
                        .or_default()
                        .push(pkg_key.clone());
                }
            }
        }

        // Group by name
        for (path, pkg_info) in &lockfile.packages {
            if path.is_empty() {
                continue;
            }

            let name = extract_package_name_from_path(path);
            let version = pkg_info.version.clone().unwrap_or_default();
            let key = format!("{}@{}", name, version);
            let pkg_dependents = dependents.get(&key).cloned().unwrap_or_default();

            let versions = by_name.entry(name).or_default();
            if !versions.iter().any(|v| v.version == version) {
                versions.push(crate::lockfile::CargoPackageInfo {
                    version,
                    dependents: pkg_dependents,
                    is_path_dep: false, // npm doesn't have a direct equivalent here easily
                });
            }
        }

        Ok(by_name)
    }
}

fn extract_package_name_from_path(path: &str) -> String {
    // Find the last "node_modules/" in the path
    let parts: Vec<&str> = path.rsplitn(2, "node_modules/").collect();

    if parts.is_empty() {
        return String::new();
    }

    let name_part = parts[0];

    // Handle scoped packages
    if name_part.starts_with('@') {
        // @scope/pkg or @scope/pkg/something
        let segments: Vec<&str> = name_part.splitn(3, '/').collect();
        if segments.len() >= 2 {
            return format!("{}/{}", segments[0], segments[1]);
        }
    }

    // Regular package - take everything before the first /
    name_part.split('/').next().unwrap_or("").to_string()
}

// Serde types for package-lock.json

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NpmLockfile {
    #[serde(default)]
    lockfile_version: u32,

    #[serde(default)]
    packages: HashMap<String, NpmPackageInfo>,

    // v1 format
    #[serde(default)]
    dependencies: HashMap<String, NpmDependency>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NpmPackageInfo {
    name: Option<String>,
    version: Option<String>,

    #[serde(default)]
    dev: Option<bool>,

    #[serde(default)]
    optional: Option<bool>,

    #[serde(default)]
    dependencies: HashMap<String, String>,

    #[serde(default)]
    optional_dependencies: HashMap<String, String>,

    #[serde(default)]
    peer_dependencies: HashMap<String, String>,

    deprecated: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct NpmDependency {
    version: String,

    #[serde(default)]
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
    peer_dependencies: HashMap<String, String>,

    #[serde(default)]
    optional_dependencies: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_package_name() {
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
        assert_eq!(
            extract_package_name_from_path("node_modules/@scope/pkg/node_modules/dep"),
            "dep"
        );
    }
}
