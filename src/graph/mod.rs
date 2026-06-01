use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;

use crate::types::{ImportMap, Package, PackageExplanation, PackageUsage, UsageAnalysis};

/// Dependency graph for analyzing package relationships
pub struct DependencyGraph {
    /// The underlying directed graph
    graph: DiGraph<String, ()>,

    /// Map from package name to node index
    node_indices: HashMap<String, NodeIndex>,

    /// All packages indexed by name
    packages: HashMap<String, Package>,
}

impl DependencyGraph {
    pub fn new(packages: &HashMap<String, Package>) -> Self {
        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();

        // First, create all nodes
        for name in packages.keys() {
            let idx = graph.add_node(name.clone());
            node_indices.insert(name.clone(), idx);
        }

        // Then, add edges (dependency -> dependant direction for "why" queries)
        for (name, pkg) in packages {
            let pkg_idx = node_indices[name];

            for dep_name in &pkg.dependencies {
                if let Some(&dep_idx) = node_indices.get(dep_name) {
                    // Edge from dependant to dependency
                    graph.add_edge(pkg_idx, dep_idx, ());
                }
            }
        }

        Self {
            graph,
            node_indices,
            packages: packages.clone(),
        }
    }

    /// Analyze which packages are used vs unused
    pub fn analyze_usage(&self, imports: &ImportMap, include_dev: bool) -> UsageAnalysis {
        let used_packages = imports.packages_used();

        let mut used = Vec::new();
        let mut unused = Vec::new();
        let mut unused_direct = Vec::new();
        let mut expected_unused_direct = Vec::new();

        // Get all packages that are transitively required by used packages
        let transitively_used = self.get_transitive_dependencies(&used_packages);

        for (name, pkg) in &self.packages {
            // Skip dev dependencies if not included
            if !include_dev && pkg.is_dev {
                continue;
            }

            let is_used = used_packages.contains(name) || transitively_used.contains(name);

            if is_used {
                // Pull the real import sites for directly-imported packages.
                // Transitive-only deps have no import sites (count 0, no files).
                let usages = imports.get_package_usages(name);
                let import_count = usages.map(|v| v.len()).unwrap_or(0);
                let mut files: Vec<PathBuf> = usages
                    .map(|v| v.iter().map(|imp| imp.file_path.clone()).collect())
                    .unwrap_or_default();
                files.sort();
                files.dedup();

                used.push(PackageUsage {
                    package: pkg.clone(),
                    import_count,
                    files,
                });
            } else if is_expected_unused(name) {
                // Not imported, but that's expected (build tool, types, etc.).
                if pkg.is_direct {
                    expected_unused_direct.push(pkg.clone());
                }
            } else {
                // Truly unused: a removable direct dep, or a transitive (incl.
                // dev) dep that nothing in the project imports.
                unused.push(pkg.clone());
                if pkg.is_direct {
                    unused_direct.push(pkg.clone());
                }
            }
        }

        // Sort for consistent output
        unused.sort_by(|a, b| a.name.cmp(&b.name));
        unused_direct.sort_by(|a, b| a.name.cmp(&b.name));
        expected_unused_direct.sort_by(|a, b| a.name.cmp(&b.name));
        used.sort_by(|a, b| a.package.name.cmp(&b.package.name));

        UsageAnalysis {
            used,
            unused,
            unused_direct,
            expected_unused_direct,
        }
    }

    /// Get all packages that are transitive dependencies of the given packages
    fn get_transitive_dependencies(&self, roots: &HashSet<String>) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue: VecDeque<NodeIndex> = VecDeque::new();

        // Start from the root packages
        for name in roots {
            if let Some(&idx) = self.node_indices.get(name) {
                queue.push_back(idx);
            }
        }

        while let Some(idx) = queue.pop_front() {
            let name = &self.graph[idx];
            if visited.contains(name) {
                continue;
            }
            visited.insert(name.clone());

            // Add all dependencies to the queue
            for neighbor in self.graph.neighbors_directed(idx, Direction::Outgoing) {
                queue.push_back(neighbor);
            }
        }

        visited
    }

    /// Resolve a user-supplied query to a node key.
    ///
    /// Prefers an exact match (npm keys are bare names, Cargo keys are
    /// `name@version`), then falls back to a bare crate name, returning the
    /// lowest matching version when several are installed.
    fn resolve_key(&self, query: &str) -> Option<String> {
        if self.packages.contains_key(query) {
            return Some(query.to_string());
        }

        let mut matches: Vec<&String> = self
            .packages
            .keys()
            .filter(|key| key.split_once('@').is_some_and(|(name, _)| name == query))
            .collect();
        matches.sort();
        matches.first().map(|key| (*key).clone())
    }

    /// Explain why a package is in the dependency tree
    pub fn explain_package(&self, package_name: &str) -> Option<PackageExplanation> {
        let key = self.resolve_key(package_name)?;
        let pkg = self.packages.get(&key)?;
        let pkg_idx = self.node_indices.get(&key)?;

        let chains = self.find_dependency_chains(*pkg_idx);

        let is_dev_path = chains.iter().any(|chain| {
            chain
                .first()
                .is_some_and(|root| self.packages.get(root).is_some_and(|p| p.is_dev))
        });

        Some(PackageExplanation {
            package: pkg.clone(),
            dependency_chains: chains,
            is_dev_path,
        })
    }

    /// Find all chains from direct dependencies to the target package
    fn find_dependency_chains(&self, target: NodeIndex) -> Vec<Vec<String>> {
        let mut chains = Vec::new();
        let target_name = &self.graph[target];

        // If it's a direct dependency, return a single-element chain
        if self.packages.get(target_name).is_some_and(|p| p.is_direct) {
            return vec![vec![target_name.clone()]];
        }

        // BFS to find paths from direct dependencies to target
        // We go backwards: from target to roots
        let mut queue: VecDeque<(NodeIndex, Vec<String>)> = VecDeque::new();
        queue.push_back((target, vec![target_name.clone()]));

        let mut visited_paths: HashSet<Vec<String>> = HashSet::new();

        while let Some((current, path)) = queue.pop_front() {
            // Find all packages that depend on current
            for neighbor in self.graph.neighbors_directed(current, Direction::Incoming) {
                let neighbor_name = &self.graph[neighbor];

                // Avoid cycles
                if path.contains(neighbor_name) {
                    continue;
                }

                let mut new_path = vec![neighbor_name.clone()];
                new_path.extend(path.clone());

                // If this is a direct dependency, we found a complete chain
                if self
                    .packages
                    .get(neighbor_name)
                    .is_some_and(|p| p.is_direct)
                {
                    if !visited_paths.contains(&new_path) {
                        visited_paths.insert(new_path.clone());
                        chains.push(new_path);
                    }
                } else {
                    // Continue searching
                    queue.push_back((neighbor, new_path));
                }
            }
        }

        // Limit to most relevant chains (shortest paths first)
        chains.sort_by_key(|c| c.len());
        chains.truncate(5);

        chains
    }
}

/// Check if a package is expected to not be imported directly.
/// These are dev/build tools, type definitions, and similar packages.
fn is_expected_unused(name: &str) -> bool {
    // TypeScript type definitions
    if name.starts_with("@types/") {
        return true;
    }

    // Known build tools and dev utilities that are never imported
    const EXPECTED_UNUSED_EXACT: &[&str] = &[
        // TypeScript
        "typescript",
        "ts-node",
        "tsx",
        "ts-jest",
        // Bundlers & Build tools
        "vite",
        "webpack",
        "webpack-cli",
        "webpack-dev-server",
        "rollup",
        "esbuild",
        "parcel",
        "turbo",
        "nx",
        "tsup",
        "unbuild",
        "pkgroll",
        "microbundle",
        "tsdx",
        "preconstruct",
        "bunchee",
        // Linters & Formatters
        "eslint",
        "prettier",
        "stylelint",
        "biome",
        "oxlint",
        "dprint",
        "xo",
        "standard",
        // Test runners
        "jest",
        "vitest",
        "mocha",
        "ava",
        "tap",
        "c8",
        "nyc",
        "playwright",
        "cypress",
        "@playwright/test",
        "uvu",
        // Dev servers & watchers
        "nodemon",
        "ts-node-dev",
        "tsnd",
        "concurrently",
        "npm-run-all",
        "npm-run-all2",
        "cross-env",
        "wait-on",
        // File utilities
        "rimraf",
        "del-cli",
        "copyfiles",
        "cpy-cli",
        "mkdirp",
        "shx",
        // Git hooks & commits
        "husky",
        "lint-staged",
        "commitlint",
        "simple-git-hooks",
        "lefthook",
        // Versioning & Release
        "semantic-release",
        "release-it",
        "standard-version",
        "bumpp",
        "changelogithub",
        "changelogen",
        "np",
        "lerna",
        "changeset",
        // Patching
        "patch-package",
        "pnpm-patch",
        // Documentation
        "typedoc",
        "jsdoc",
        "documentation",
        "api-extractor",
        // Type checking
        "tsc",
        "attw",
        "publint",
        "arethetypeswrong",
        "knip",
        "depcheck",
    ];

    if EXPECTED_UNUSED_EXACT.contains(&name) {
        return true;
    }

    // Patterns - packages that match these prefixes are expected unused
    const EXPECTED_UNUSED_PREFIXES: &[&str] = &[
        "@typescript-eslint/",
        "@eslint/",
        "eslint-plugin-",
        "eslint-config-",
        "@vitejs/",
        "@rollup/",
        "@babel/",
        "babel-",
        "@swc/",
        "@jest/",
        "@testing-library/",
        "@vitest/",
        "prettier-plugin-",
    ];

    for prefix in EXPECTED_UNUSED_PREFIXES {
        if name.starts_with(prefix) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_packages() -> HashMap<String, Package> {
        let mut packages = HashMap::new();

        packages.insert(
            "express".to_string(),
            Package::new("express", "4.18.0")
                .direct()
                .with_dependencies(vec!["body-parser".to_string()]),
        );

        packages.insert(
            "body-parser".to_string(),
            Package::new("body-parser", "1.20.0").with_dependencies(vec!["raw-body".to_string()]),
        );

        packages.insert("raw-body".to_string(), Package::new("raw-body", "2.5.0"));

        packages.insert(
            "unused-pkg".to_string(),
            Package::new("unused-pkg", "1.0.0").direct(),
        );

        packages
    }

    #[test]
    fn test_transitive_dependencies() {
        let packages = create_test_packages();
        let graph = DependencyGraph::new(&packages);

        let used: HashSet<String> = vec!["express".to_string()].into_iter().collect();
        let transitive = graph.get_transitive_dependencies(&used);

        assert!(transitive.contains("express"));
        assert!(transitive.contains("body-parser"));
        assert!(transitive.contains("raw-body"));
        assert!(!transitive.contains("unused-pkg"));
    }

    #[test]
    fn test_explain_package() {
        let packages = create_test_packages();
        let graph = DependencyGraph::new(&packages);

        let explanation = graph.explain_package("raw-body").unwrap();

        assert_eq!(explanation.package.name, "raw-body");
        assert!(!explanation.dependency_chains.is_empty());

        // The chain should be: express -> body-parser -> raw-body
        let chain = &explanation.dependency_chains[0];
        assert_eq!(chain, &vec!["express", "body-parser", "raw-body"]);
    }

    #[test]
    fn test_analyze_usage_reports_real_import_counts() {
        use crate::types::{Import, ImportKind, ImportMap};
        use std::path::PathBuf;

        fn es_import(file: &str, pkg: &str) -> Import {
            Import {
                file_path: PathBuf::from(file),
                kind: ImportKind::EsModule,
                resolved_package: Some(pkg.to_string()),
            }
        }

        let packages = create_test_packages();
        let graph = DependencyGraph::new(&packages);

        // `express` is imported three times across two distinct files.
        let mut imports = ImportMap::new();
        imports.add_import(es_import("src/a.ts", "express"));
        imports.add_import(es_import("src/a.ts", "express"));
        imports.add_import(es_import("src/b.ts", "express"));

        let analysis = graph.analyze_usage(&imports, true);

        // Directly-imported package: real count + deduped, sorted file list.
        let express = analysis
            .used
            .iter()
            .find(|u| u.package.name == "express")
            .expect("express should be marked used");
        assert_eq!(express.import_count, 3);
        assert_eq!(
            express.files,
            vec![PathBuf::from("src/a.ts"), PathBuf::from("src/b.ts")]
        );

        // Transitive-only dependency: used, but with no import sites of its own.
        let body_parser = analysis
            .used
            .iter()
            .find(|u| u.package.name == "body-parser")
            .expect("body-parser should be transitively used");
        assert_eq!(body_parser.import_count, 0);
        assert!(body_parser.files.is_empty());

        // A direct dependency nobody imports stays flagged as unused.
        assert!(analysis
            .unused_direct
            .iter()
            .any(|p| p.name == "unused-pkg"));
    }
}
