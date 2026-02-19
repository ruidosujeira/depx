use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;

use crate::types::{Package, PackageExplanation, PackageUsage, UsageAnalysis};

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
    pub fn analyze_usage(
        &self,
        used_packages: &HashSet<String>,
        include_dev: bool,
    ) -> UsageAnalysis {
        let mut used = Vec::new();
        let mut unused = Vec::new();
        let mut expected_unused = Vec::new();
        let mut dev_only = Vec::new();
        let mut unused_direct = Vec::new();
        let mut expected_unused_direct = Vec::new();

        // Get all packages that are transitively required by used packages
        let transitively_used = self.get_transitive_dependencies(used_packages);

        for (name, pkg) in &self.packages {
            // Skip dev dependencies if not included
            if !include_dev && pkg.is_dev {
                continue;
            }

            let is_used = used_packages.contains(name) || transitively_used.contains(name);

            if is_used {
                let import_count = if used_packages.contains(name) { 1 } else { 0 };
                used.push(PackageUsage {
                    package: pkg.clone(),
                    import_count,
                    files: Vec::new(),
                });
            } else if is_expected_unused(name) {
                // This package is not imported but that's expected (build tool, types, etc.)
                expected_unused.push(pkg.clone());
                if pkg.is_direct {
                    expected_unused_direct.push(pkg.clone());
                }
            } else if pkg.is_dev && !pkg.is_direct {
                dev_only.push(pkg.clone());
            } else {
                unused.push(pkg.clone());
                if pkg.is_direct {
                    unused_direct.push(pkg.clone());
                }
            }
        }

        // Sort for consistent output
        unused.sort_by(|a, b| a.name.cmp(&b.name));
        unused_direct.sort_by(|a, b| a.name.cmp(&b.name));
        expected_unused.sort_by(|a, b| a.name.cmp(&b.name));
        expected_unused_direct.sort_by(|a, b| a.name.cmp(&b.name));
        used.sort_by(|a, b| a.package.name.cmp(&b.package.name));

        UsageAnalysis {
            used,
            unused,
            expected_unused,
            dev_only,
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

    /// Explain why a package is in the dependency tree
    pub fn explain_package(&self, package_name: &str) -> Option<PackageExplanation> {
        let pkg = self.packages.get(package_name)?;
        let pkg_idx = self.node_indices.get(package_name)?;

        let chains = self.find_dependency_chains(*pkg_idx);

        let is_dev_path = chains.iter().any(|chain| {
            chain.first().is_some_and(|root| {
                self.packages.get(root).is_some_and(|p| p.is_dev)
            })
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
        if self
            .packages
            .get(target_name)
            .is_some_and(|p| p.is_direct)
        {
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

    /// Get a package by name
    pub fn get_package(&self, name: &str) -> Option<&Package> {
        self.packages.get(name)
    }

    /// Get all packages
    pub fn packages(&self) -> &HashMap<String, Package> {
        &self.packages
    }

    /// Get count of all packages
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// Get count of direct dependencies
    pub fn direct_count(&self) -> usize {
        self.packages.values().filter(|p| p.is_direct).count()
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
}
