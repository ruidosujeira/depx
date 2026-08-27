mod cargo;
mod javascript;
mod npm;
mod pnpm;
mod yarn;

use std::path::Path;

use miette::{bail, Result};

use crate::model::{Ecosystem, ProjectSnapshot};

pub use cargo::CargoAdapter;
pub use npm::NpmAdapter;
pub use pnpm::PnpmAdapter;
pub use yarn::YarnAdapter;

/// Adapter from ecosystem-specific project files to depx's normalized model.
pub trait EcosystemAdapter {
    /// Ecosystem represented by this adapter.
    fn ecosystem(&self) -> Ecosystem;
    /// Return whether the adapter recognizes project files at `root`.
    fn detect(&self, root: &Path) -> bool;
    /// Parse ecosystem files into a deterministic normalized snapshot.
    fn build_snapshot(&self, root: &Path) -> Result<ProjectSnapshot>;
}

static CARGO_ADAPTER: CargoAdapter = CargoAdapter;
static NPM_ADAPTER: NpmAdapter = NpmAdapter;
static PNPM_ADAPTER: PnpmAdapter = PnpmAdapter;
static YARN_ADAPTER: YarnAdapter = YarnAdapter;

/// Detect the supported ecosystem at `root` and return its adapter.
pub fn detect(root: &Path) -> Result<&'static dyn EcosystemAdapter> {
    // Preserve the existing Cargo-first behavior for mixed repositories.
    for adapter in [
        &CARGO_ADAPTER as &dyn EcosystemAdapter,
        &NPM_ADAPTER as &dyn EcosystemAdapter,
        &PNPM_ADAPTER as &dyn EcosystemAdapter,
        &YARN_ADAPTER as &dyn EcosystemAdapter,
    ] {
        if adapter.detect(root) {
            return Ok(adapter);
        }
    }

    bail!(
        "No supported lockfile found in {}. Expected Cargo.lock, package-lock.json, pnpm-lock.yaml or yarn.lock",
        root.display()
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::graph::{DependencyGraph, ExplainError};
    use crate::model::DependencyKind;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn npm_preserves_versions_and_locations_and_resolves_nearest_edges() {
        let root = fixture("npm-multiple");
        let snapshot = NpmAdapter.build_snapshot(&root).unwrap();
        let shared: Vec<_> = snapshot
            .components
            .iter()
            .filter(|component| component.id.name == "shared")
            .collect();

        assert_eq!(shared.len(), 3);
        assert!(shared
            .iter()
            .any(|component| component.id.version == "2.0.0"));
        let version_one_locations: Vec<_> = shared
            .iter()
            .filter(|component| component.id.version == "1.0.0")
            .filter_map(|component| component.id.location.as_deref())
            .collect();
        assert_eq!(version_one_locations.len(), 2);
        assert!(version_one_locations.contains(&"node_modules/shared"));
        assert!(version_one_locations.contains(&"node_modules/b/node_modules/shared"));

        let edge = |from: &str, to: &str, version: &str| {
            snapshot.dependency_edges.iter().any(|edge| {
                edge.from.location.as_deref() == Some(from)
                    && edge.to.location.as_deref() == Some(to)
                    && edge.to.version == version
                    && edge.kind == DependencyKind::Runtime
            })
        };
        assert!(edge(
            "node_modules/a",
            "node_modules/a/node_modules/shared",
            "2.0.0"
        ));
        assert!(edge(
            "node_modules/b",
            "node_modules/b/node_modules/shared",
            "1.0.0"
        ));
    }

    #[test]
    fn npm_workspaces_resolve_member_manifests_without_inventorying_local_packages() {
        let root = fixture("npm-workspace");
        let snapshot = NpmAdapter.build_snapshot(&root).unwrap();
        assert!(!snapshot
            .components
            .iter()
            .any(|component| component.id.name == "app"));
        let is_odd = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "is-odd")
            .unwrap();
        assert!(is_odd.direct);
        assert!(snapshot.units.iter().any(|unit| {
            unit.manifest == Path::new("packages/app/package.json")
                && unit
                    .declarations
                    .iter()
                    .any(|declaration| declaration.component == is_odd.id)
        }));
        assert_eq!(snapshot.units.len(), 2);
    }

    #[test]
    fn cargo_uses_normalized_component_ids_and_resolved_edges() {
        let root = fixture("cargo-normalized");
        let snapshot = CargoAdapter.build_snapshot(&root).unwrap();
        let foo_two = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "foo" && component.id.version == "2.0.0")
            .unwrap();

        assert_eq!(foo_two.id.ecosystem, Ecosystem::Cargo);
        assert!(foo_two
            .id
            .location
            .as_deref()
            .unwrap()
            .starts_with("registry+"));
        assert!(foo_two.direct);
        assert!(snapshot.units.iter().any(|unit| {
            unit.declarations
                .iter()
                .any(|declaration| declaration.component == foo_two.id)
        }));
        assert!(snapshot.dependency_edges.iter().any(|edge| {
            edge.from == foo_two.id
                && edge.to.name == "transitive"
                && edge.to.version == "3.0.0"
                && edge.kind == DependencyKind::Unknown
        }));
    }

    #[test]
    fn cargo_workspaces_resolve_members_inherited_dependencies_and_aliases() {
        let root = fixture("cargo-workspace");
        let snapshot = CargoAdapter.build_snapshot(&root).unwrap();
        let serde = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "serde")
            .unwrap();
        let anyhow = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "anyhow")
            .unwrap();
        let pretty_assertions = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "pretty_assertions")
            .unwrap();
        let yansi = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "yansi")
            .unwrap();

        assert!(serde.direct);
        assert!(anyhow.direct);
        assert!(pretty_assertions.direct);
        assert!(pretty_assertions.dev);
        assert!(yansi.direct);
        assert!(!snapshot
            .components
            .iter()
            .any(|component| { matches!(component.id.name.as_str(), "app" | "tool") }));
        assert!(snapshot.units.iter().any(|unit| {
            unit.manifest == Path::new("crates/app/Cargo.toml")
                && unit
                    .declarations
                    .iter()
                    .any(|declaration| declaration.component == anyhow.id)
        }));
        assert!(snapshot.units.iter().any(|unit| {
            unit.manifest == Path::new("internal/shared/Cargo.toml")
                && unit
                    .declarations
                    .iter()
                    .any(|declaration| declaration.component == yansi.id)
        }));
    }

    #[test]
    fn pnpm_workspaces_preserve_direct_declarations_and_edges() {
        let root = fixture("pnpm-workspace");
        let snapshot = PnpmAdapter.build_snapshot(&root).unwrap();
        let minimist = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "minimist")
            .unwrap();
        let is_odd = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "is-odd")
            .unwrap();
        assert!(minimist.direct);
        assert!(is_odd.direct);
        assert!(snapshot.units.iter().any(|unit| {
            unit.manifest == Path::new("packages/app/package.json")
                && unit
                    .declarations
                    .iter()
                    .any(|declaration| declaration.component == is_odd.id)
        }));
        assert_eq!(snapshot.units.len(), 2);
        assert!(snapshot.dependency_edges.iter().any(|edge| {
            edge.from == is_odd.id && edge.to.name == "is-number" && edge.to.version == "6.0.0"
        }));
    }

    #[test]
    fn yarn_workspaces_preserve_direct_declarations_and_edges() {
        let root = fixture("yarn-workspace");
        let snapshot = YarnAdapter.build_snapshot(&root).unwrap();
        let minimist = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "minimist")
            .unwrap();
        let is_odd = snapshot
            .components
            .iter()
            .find(|component| component.id.name == "is-odd")
            .unwrap();
        assert!(minimist.direct);
        assert!(is_odd.direct);
        assert!(snapshot.units.iter().any(|unit| {
            unit.manifest == Path::new("packages/app/package.json")
                && unit
                    .declarations
                    .iter()
                    .any(|declaration| declaration.component == is_odd.id)
        }));
        assert_eq!(snapshot.units.len(), 2);
        assert!(snapshot.dependency_edges.iter().any(|edge| {
            edge.from == is_odd.id && edge.to.name == "is-number" && edge.to.version == "6.0.0"
        }));
    }

    #[test]
    fn why_requires_qualification_for_multiple_versions() {
        let root = fixture("npm-multiple");
        let snapshot = NpmAdapter.build_snapshot(&root).unwrap();
        let graph = DependencyGraph::new(&snapshot).unwrap();

        let error = graph.explain_package("shared").unwrap_err();
        assert!(matches!(
            error,
            ExplainError::Ambiguous { ref matches, .. } if matches.len() == 3
        ));

        let explanation = graph.explain_package("shared@2.0.0").unwrap();
        assert_eq!(explanation.package.id.version, "2.0.0");
        assert_eq!(
            explanation.package.id.location.as_deref(),
            Some("node_modules/a/node_modules/shared")
        );
    }

    #[test]
    fn single_version_project_retains_why_behavior() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/demo-app");
        let snapshot = NpmAdapter.build_snapshot(&root).unwrap();
        let graph = DependencyGraph::new(&snapshot).unwrap();
        let explanation = graph.explain_package("wrappy").unwrap();

        assert_eq!(explanation.package.id.qualified_name(), "wrappy@1.0.2");
        assert!(!explanation.dependency_chains.is_empty());
    }

    #[test]
    fn snapshot_serialization_is_deterministic() {
        let root = fixture("npm-multiple");
        let first = NpmAdapter.build_snapshot(&root).unwrap();
        let second = NpmAdapter.build_snapshot(&root).unwrap();

        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }
}
