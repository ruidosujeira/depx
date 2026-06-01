use std::collections::{HashMap, HashSet};
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

        // Read the sibling Cargo.toml to learn which crates are actually direct
        // (and which are dev) dependencies. Falls back to a source-based guess
        // when the manifest is absent or declares nothing (e.g. a virtual
        // workspace root).
        let (direct_names, dev_names) = read_manifest_deps(self.lockfile_path);
        let use_manifest = !direct_names.is_empty();

        // Resolve dependency entries to `name@version` keys (Cargo omits the
        // version for unambiguous crates), so graph edges connect to real nodes.
        let versions = versions_by_name(lockfile);

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
                        .filter_map(|d| resolve_dependency_key(d, &versions))
                        .collect()
                })
                .unwrap_or_default();

            let mut package = Package::new(&pkg.name, &pkg.version).with_dependencies(deps);
            let is_direct = if use_manifest {
                direct_names.contains(&pkg.name)
            } else {
                // Without a manifest, a missing `source` marks path/workspace
                // crates, the closest stand-in for "direct".
                pkg.source.is_none()
            };
            if is_direct {
                package = package.direct();
            }
            package.is_dev = dev_names.contains(&pkg.name);

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
        let versions = versions_by_name(&lockfile);

        for pkg in &lockfile.package {
            if let Some(deps) = &pkg.dependencies {
                for dep in deps {
                    let Some(dep_key) = resolve_dependency_key(dep, &versions) else {
                        continue;
                    };

                    dependents
                        .entry(dep_key)
                        .or_default()
                        .push(pkg.name.clone());
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
                });
        }

        Ok(by_name)
    }
}

/// Build a map of crate name -> the versions present in the lockfile.
fn versions_by_name(lockfile: &CargoLockfile) -> HashMap<&str, Vec<&str>> {
    let mut map: HashMap<&str, Vec<&str>> = HashMap::new();
    for pkg in &lockfile.package {
        map.entry(pkg.name.as_str())
            .or_default()
            .push(pkg.version.as_str());
    }
    map
}

/// Resolve a Cargo.lock dependency entry to a `name@version` key.
///
/// Entries look like `"name"`, `"name version"`, or `"name version (source)"`.
/// Cargo only spells out the version when a crate name is ambiguous, so a bare
/// `"name"` is resolved to its unique installed version via `versions` — without
/// this, graph edges to single-version crates never connect. Returns `None` for
/// a blank entry, so callers never index into an empty split.
fn resolve_dependency_key(dep: &str, versions: &HashMap<&str, Vec<&str>>) -> Option<String> {
    let mut parts = dep.split_whitespace();
    let name = parts.next()?;
    if let Some(version) = parts.next() {
        return Some(format!("{}@{}", name, version));
    }
    match versions.get(name) {
        Some(v) if v.len() == 1 => Some(format!("{}@{}", name, v[0])),
        // Ambiguous (Cargo would have spelled out the version) or unknown:
        // keep the bare name as a best effort.
        _ => Some(name.to_string()),
    }
}

/// Read the direct and dev dependency crate names from the `Cargo.toml` next to
/// the lockfile. Returns `(direct, dev)` name sets; `direct` also includes the
/// dev names (a dev dependency is still declared directly). Both sets are empty
/// when the manifest is missing, unparseable, or declares no dependencies.
fn read_manifest_deps(lockfile_path: &Path) -> (HashSet<String>, HashSet<String>) {
    let Some(manifest_path) = lockfile_path.parent().map(|p| p.join("Cargo.toml")) else {
        return (HashSet::new(), HashSet::new());
    };
    let Ok(content) = fs::read_to_string(&manifest_path) else {
        return (HashSet::new(), HashSet::new());
    };
    let Ok(manifest) = toml::from_str::<CargoManifest>(&content) else {
        return (HashSet::new(), HashSet::new());
    };

    let collect = |table: &HashMap<String, ManifestDep>, out: &mut HashSet<String>| {
        for (key, dep) in table {
            out.insert(dep.crate_name(key));
        }
    };

    let mut direct = HashSet::new();
    let mut dev = HashSet::new();
    collect(&manifest.dependencies, &mut direct);
    collect(&manifest.build_dependencies, &mut direct);
    collect(&manifest.dev_dependencies, &mut dev);
    if let Some(workspace) = &manifest.workspace {
        collect(&workspace.dependencies, &mut direct);
    }
    direct.extend(dev.iter().cloned());

    (direct, dev)
}

/// Minimal view of a `Cargo.toml` — just the dependency tables we classify.
#[derive(Debug, Deserialize)]
struct CargoManifest {
    #[serde(default)]
    dependencies: HashMap<String, ManifestDep>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: HashMap<String, ManifestDep>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: HashMap<String, ManifestDep>,
    #[serde(default)]
    workspace: Option<WorkspaceManifest>,
}

#[derive(Debug, Deserialize)]
struct WorkspaceManifest {
    #[serde(default)]
    dependencies: HashMap<String, ManifestDep>,
}

/// A dependency entry: `dep = "1.0"` or `dep = { version = "1", package = "real" }`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ManifestDep {
    // Only the table form carries a `package` rename; the value of the plain
    // `dep = "1.0"` form is irrelevant to dependency classification.
    Version(#[allow(dead_code)] String),
    Detailed { package: Option<String> },
}

impl ManifestDep {
    /// The crate name as it appears in `Cargo.lock`, honouring `package`
    /// renames (`foo = { package = "bar" }` resolves to `bar`).
    fn crate_name(&self, key: &str) -> String {
        match self {
            ManifestDep::Detailed {
                package: Some(name),
            } => name.clone(),
            _ => key.to_string(),
        }
    }
}

/// Package info for duplicate analysis
#[derive(Debug, Clone)]
pub struct CargoPackageInfo {
    pub version: String,
    pub dependents: Vec<String>,
}
