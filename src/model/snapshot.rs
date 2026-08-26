use std::path::PathBuf;

use miette::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::evidence::Evidence;
use crate::evidence::EvidenceResolution;

use super::{Component, DependencyEdge};

/// Immutable normalized inventory and dependency evidence for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSnapshot {
    /// Project root from which ecosystem files were read.
    pub root: PathBuf,
    /// Deterministically ordered resolved component inventory.
    pub components: Vec<Component>,
    /// Deterministically ordered resolved dependency relationships.
    pub dependency_edges: Vec<DependencyEdge>,
    /// Deterministically ordered evidence observations.
    pub evidence: Vec<Evidence>,
}

impl ProjectSnapshot {
    /// Construct a snapshot with deterministic component and edge ordering.
    pub fn new(
        root: PathBuf,
        mut components: Vec<Component>,
        mut dependency_edges: Vec<DependencyEdge>,
    ) -> Self {
        components.sort_by(|left, right| left.id.cmp(&right.id));
        dependency_edges.sort();
        dependency_edges.dedup();
        Self {
            root,
            components,
            dependency_edges,
            evidence: Vec::new(),
        }
    }

    /// Return a validated snapshot enriched with additional evidence.
    pub fn with_evidence(mut self, evidence: Vec<Evidence>) -> Result<Self> {
        self.evidence.extend(evidence);
        self.evidence.sort_by(|left, right| left.id.cmp(&right.id));
        self.validate()?;
        Ok(self)
    }

    /// Validate identity uniqueness, references and deterministic ordering.
    pub fn validate(&self) -> Result<()> {
        if !strictly_sorted(self.components.iter().map(|component| &component.id)) {
            bail!("Snapshot components must be uniquely and deterministically ordered");
        }
        if !strictly_sorted(self.dependency_edges.iter()) {
            bail!("Snapshot dependency edges must be unique and deterministically ordered");
        }
        if !strictly_sorted(self.evidence.iter().map(|evidence| &evidence.id)) {
            bail!("Snapshot evidence IDs must be unique and deterministically ordered");
        }

        let component_ids: std::collections::HashSet<_> = self
            .components
            .iter()
            .map(|component| &component.id)
            .collect();
        for edge in &self.dependency_edges {
            if !component_ids.contains(&edge.from) || !component_ids.contains(&edge.to) {
                bail!("Dependency edge references a component outside the snapshot");
            }
        }
        for evidence in &self.evidence {
            if !component_ids.contains(&evidence.subject) {
                bail!(
                    "Evidence {} references a component outside the snapshot",
                    evidence.id.as_str()
                );
            }
            if let EvidenceResolution::Ambiguous { candidates } = &evidence.resolution {
                if candidates.is_empty()
                    || !strictly_sorted(candidates.iter())
                    || candidates.binary_search(&evidence.subject).is_err()
                    || candidates
                        .iter()
                        .any(|candidate| !component_ids.contains(candidate))
                {
                    bail!(
                        "Evidence {} has malformed ambiguity candidates",
                        evidence.id.as_str()
                    );
                }
            }
        }
        Ok(())
    }
}

fn strictly_sorted<'a, T: Ord + 'a>(values: impl Iterator<Item = &'a T>) -> bool {
    let mut previous: Option<&T> = None;
    for value in values {
        if previous.is_some_and(|item| item >= value) {
            return false;
        }
        previous = Some(value);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{
        Confidence, Evidence, EvidenceKind, EvidenceOrigin, EvidenceResolution, SourceRole,
    };
    use crate::model::{ComponentId, Ecosystem};

    fn component(name: &str) -> Component {
        Component {
            id: ComponentId {
                ecosystem: Ecosystem::Npm,
                name: name.to_string(),
                version: "1.0.0".to_string(),
                location: Some(format!("node_modules/{name}")),
            },
            direct: true,
            dev: false,
            deprecated: None,
        }
    }

    #[test]
    fn rejects_evidence_for_unknown_component() {
        let known = component("known");
        let unknown = component("unknown");
        let evidence = Evidence::new(
            unknown.id,
            EvidenceKind::StaticImport,
            EvidenceOrigin {
                path: "src/index.ts".into(),
                span: None,
                description: None,
            },
            SourceRole::Runtime,
            Confidence::High,
            EvidenceResolution::Exact,
        )
        .unwrap();
        let result = ProjectSnapshot::new(PathBuf::from("."), vec![known], Vec::new())
            .with_evidence(vec![evidence]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_duplicate_component_identities_and_evidence_ids() {
        let known = component("known");
        let duplicate = known.clone();
        let snapshot = ProjectSnapshot::new(
            PathBuf::from("."),
            vec![known.clone(), duplicate],
            Vec::new(),
        );
        assert!(snapshot.validate().is_err());

        let evidence = Evidence::new(
            known.id.clone(),
            EvidenceKind::StaticImport,
            EvidenceOrigin {
                path: "src/index.ts".into(),
                span: None,
                description: None,
            },
            SourceRole::Runtime,
            Confidence::High,
            EvidenceResolution::Exact,
        )
        .unwrap();
        let result = ProjectSnapshot::new(PathBuf::from("."), vec![known], Vec::new())
            .with_evidence(vec![evidence.clone(), evidence]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_dependency_edges_to_unknown_components() {
        let known = component("known");
        let unknown = component("unknown");
        let snapshot = ProjectSnapshot {
            root: PathBuf::from("."),
            components: vec![known.clone()],
            dependency_edges: vec![DependencyEdge {
                from: known.id,
                to: unknown.id,
                kind: crate::model::DependencyKind::Runtime,
            }],
            evidence: Vec::new(),
        };
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn normalizes_duplicate_dependency_edges() {
        let parent = component("parent");
        let child = component("child");
        let edge = DependencyEdge {
            from: parent.id.clone(),
            to: child.id.clone(),
            kind: crate::model::DependencyKind::Runtime,
        };
        let snapshot = ProjectSnapshot::new(
            PathBuf::from("."),
            vec![parent, child],
            vec![edge.clone(), edge],
        );
        assert_eq!(snapshot.dependency_edges.len(), 1);
        snapshot.validate().unwrap();
    }
}
