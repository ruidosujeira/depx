use std::collections::HashMap;
use std::fs;
use std::path::Path;

use miette::Result;
use serde::Deserialize;

use crate::types::Package;

/// Parser for Cargo.lock files (Rust projects)
pub struct CargoLockfileParser<'a> {
    lockfile_path: &'a Path,
}

/// Cargo.lock format (TOML)
#[derive(Debug, Deserialize)]
struct CargoLockfile {
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    dependencies: Option<Vec<String>>,
}

impl<'a> CargoLockfileParser<'a> {
    pub fn new(lockfile_path: &'a Path) -> Self {
        Self { lockfile_path }
    }

    pub fn parse(&self) -> Result<HashMap<String, Package>> {
        let content = fs::read_to_string(self.lockfile_path)
            .map_err(|e| miette::miette!("Failed to read Cargo.lock: {}", e))?;

        let lockfile: CargoLockfile = toml::from_str(&content)
            .map_err(|e| miette::miette!("Failed to parse Cargo.lock: {}", e))?;

        self.build_package_map(&lockfile)
    }

    fn build_package_map(&self, lockfile: &CargoLockfile) -> Result<HashMap<String, Package>> {
        let mut packages = HashMap::new();

        // First pass: collect all packages with their versions
        // Use name@version as key since same crate can have multiple versions
        for pkg in &lockfile.package {
            let key = format!("{}@{}", pkg.name, pkg.version);

            // Parse dependencies - they come as "name version" strings
            let deps: Vec<String> = pkg
                .dependencies
                .as_ref()
                .map(|deps| {
                    deps.iter()
                        .map(|d| {
                            // Dependencies are in format "name version" or just "name"
                            let parts: Vec<&str> = d.split_whitespace().collect();
                            if parts.len() >= 2 {
                                format!("{}@{}", parts[0], parts[1])
                            } else {
                                parts[0].to_string()
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let package = Package::new(&pkg.name, &pkg.version).with_dependencies(deps);

            // Mark path dependencies (no source) as "direct" for now
            // In Cargo, the root crate has no source field
            let package = if pkg.source.is_none() {
                package.direct()
            } else {
                package
            };

            packages.insert(key, package);
        }

        Ok(packages)
    }

    /// Parse and return raw package data for duplicate analysis
    /// Returns a map of package name -> list of (version, dependents)
    pub fn parse_for_duplicates(&self) -> Result<HashMap<String, Vec<CargoPackageInfo>>> {
        let content = fs::read_to_string(self.lockfile_path)
            .map_err(|e| miette::miette!("Failed to read Cargo.lock: {}", e))?;

        let lockfile: CargoLockfile = toml::from_str(&content)
            .map_err(|e| miette::miette!("Failed to parse Cargo.lock: {}", e))?;

        let mut by_name: HashMap<String, Vec<CargoPackageInfo>> = HashMap::new();

        // Build a reverse dependency map
        let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

        for pkg in &lockfile.package {
            if let Some(deps) = &pkg.dependencies {
                for dep in deps {
                    let parts: Vec<&str> = dep.split_whitespace().collect();
                    let dep_key = if parts.len() >= 2 {
                        format!("{}@{}", parts[0], parts[1])
                    } else {
                        parts[0].to_string()
                    };

                    let pkg_key = format!("{}@{}", pkg.name, pkg.version);

                    dependents.entry(dep_key).or_default().push(pkg_key);
                }
            }
        }

        // Group packages by name
        for pkg in &lockfile.package {
            let key = format!("{}@{}", pkg.name, pkg.version);
            let pkg_dependents = dependents.get(&key).cloned().unwrap_or_default();

            by_name
                .entry(pkg.name.clone())
                .or_default()
                .push(CargoPackageInfo {
                    version: pkg.version.clone(),
                    dependents: pkg_dependents,
                    is_path_dep: pkg.source.is_none(),
                });
        }

        Ok(by_name)
    }
}

/// Package info for duplicate analysis
#[derive(Debug, Clone)]
pub struct CargoPackageInfo {
    pub version: String,
    pub dependents: Vec<String>,
    pub is_path_dep: bool,
}
