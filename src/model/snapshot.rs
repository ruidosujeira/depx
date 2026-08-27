use std::path::PathBuf;

use miette::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::evidence::Evidence;
use crate::evidence::EvidenceResolution;

use super::{Component, DependencyEdge, ProjectUnit, ProjectUnitId};

/// Immutable normalized inventory and dependency evidence for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSnapshot {
    /// Project root from which ecosystem files were read.
    pub root: PathBuf,
    /// Deterministically ordered resolved component inventory.
    pub components: Vec<Component>,
    /// Deterministically ordered resolved dependency relationships.
    pub dependency_edges: Vec<DependencyEdge>,
    /// Manifest-owned projects participating in this snapshot.
    pub units: Vec<ProjectUnit>,
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
            units: Vec::new(),
            evidence: Vec::new(),
        }
    }

    /// Attach the project/workspace units discovered by the ecosystem adapter.
    pub fn with_units(mut self, mut units: Vec<ProjectUnit>) -> Result<Self> {
        for unit in &mut units {
            unit.declarations.sort();
            unit.declarations.dedup();
        }
        units.sort_by(|left, right| left.id.cmp(&right.id));
        self.units = units;
        self.validate()?;
        Ok(self)
    }

    /// Return the most specific declared unit owning a source path.
    pub fn owner_for_path(&self, path: &std::path::Path) -> Option<&ProjectUnit> {
        self.units
            .iter()
            .filter(|unit| path.starts_with(&unit.root))
            .max_by_key(|unit| unit.root.components().count())
    }

    pub fn unit(&self, id: &ProjectUnitId) -> Option<&ProjectUnit> {
        self.units.iter().find(|unit| &unit.id == id)
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
        if !strictly_sorted(self.units.iter().map(|unit| &unit.id)) {
            bail!("Project units must have unique, deterministically ordered identities");
        }
        if !strictly_sorted(self.evidence.iter().map(|evidence| &evidence.id)) {
            bail!("Snapshot evidence IDs must be unique and deterministically ordered");
        }

        let component_ids: std::collections::HashSet<_> = self
            .components
            .iter()
            .map(|component| &component.id)
            .collect();
        let mut manifests = std::collections::HashSet::new();
        let expected_ecosystem = self
            .components
            .first()
            .map(|component| component.id.ecosystem)
            .or_else(|| self.units.first().map(|unit| unit.ecosystem));
        if self.components.iter().any(|component| {
            expected_ecosystem.is_some_and(|ecosystem| component.id.ecosystem != ecosystem)
        }) {
            bail!("Snapshot components must belong to one ecosystem");
        }
        for unit in &self.units {
            unit.validate_paths()?;
            if !manifests.insert(&unit.manifest) {
                bail!("Project unit manifests must be unique");
            }
            if expected_ecosystem.is_some_and(|ecosystem| unit.ecosystem != ecosystem) {
                bail!("Project units and components must belong to one ecosystem");
            }
            if !strictly_sorted(unit.declarations.iter()) {
                bail!("Project unit declarations must be unique and deterministically ordered");
            }
            if unit.declarations.iter().any(|declaration| {
                declaration.name.trim().is_empty()
                    || !component_ids.contains(&declaration.component)
            }) {
                bail!("Project unit declaration references a component outside the snapshot");
            }
        }
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
            if let Some(owner) = &evidence.owner {
                let unit = self.unit(owner).ok_or_else(|| {
                    miette::miette!(
                        "Evidence {} references an unknown project unit",
                        evidence.id.as_str()
                    )
                })?;
                if !evidence.origin.path.starts_with(&unit.root) {
                    bail!(
                        "Evidence {} origin is outside its owning project unit",
                        evidence.id.as_str()
                    );
                }
                if self
                    .owner_for_path(&evidence.origin.path)
                    .is_some_and(|expected| expected.id != *owner)
                {
                    bail!(
                        "Evidence {} is not assigned to its most specific project unit",
                        evidence.id.as_str()
                    );
                }
                let is_source = matches!(
                    evidence.kind,
                    crate::evidence::EvidenceKind::StaticImport
                        | crate::evidence::EvidenceKind::CommonJsRequire
                        | crate::evidence::EvidenceKind::DynamicImport
                        | crate::evidence::EvidenceKind::ReExport
                        | crate::evidence::EvidenceKind::RustCrateReference
                        | crate::evidence::EvidenceKind::PackageScript { .. }
                        | crate::evidence::EvidenceKind::ConfigurationReference
                );
                if is_source {
                    let declared: std::collections::HashSet<_> = unit
                        .declarations
                        .iter()
                        .map(|declaration| &declaration.component)
                        .collect();
                    if !declared.contains(&evidence.subject)
                        || matches!(&evidence.resolution, EvidenceResolution::Ambiguous { candidates } if candidates.iter().any(|candidate| !declared.contains(candidate)))
                    {
                        bail!("Source evidence is not semantically possible in its owning project unit");
                    }
                }
                if matches!(
                    evidence.kind,
                    crate::evidence::EvidenceKind::ManifestDeclaration { .. }
                ) && (evidence.origin.path != unit.manifest
                    || !unit.declarations.iter().any(|declaration| {
                        declaration.component == evidence.subject
                            && declaration.section
                                == match evidence.kind {
                                    crate::evidence::EvidenceKind::ManifestDeclaration {
                                        section,
                                    } => section,
                                    _ => unreachable!(),
                                }
                    }))
                {
                    bail!("Manifest evidence is not backed by its owner's declarations");
                }
            } else if !self.units.is_empty()
                && matches!(
                    evidence.kind,
                    crate::evidence::EvidenceKind::ManifestDeclaration { .. }
                        | crate::evidence::EvidenceKind::StaticImport
                        | crate::evidence::EvidenceKind::CommonJsRequire
                        | crate::evidence::EvidenceKind::DynamicImport
                        | crate::evidence::EvidenceKind::ReExport
                        | crate::evidence::EvidenceKind::RustCrateReference
                        | crate::evidence::EvidenceKind::PackageScript { .. }
                        | crate::evidence::EvidenceKind::ConfigurationReference
                )
            {
                bail!("Manifest and source evidence must retain its project-unit owner");
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
            if let crate::evidence::EvidenceKind::TransitiveDependency { from, .. } = &evidence.kind
            {
                if !component_ids.contains(from) {
                    bail!("Transitive evidence references a parent outside the snapshot");
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
        Confidence, Evidence, EvidenceKind, EvidenceOrigin, EvidenceResolution, ManifestSection,
        SourceRole,
    };
    use crate::model::{ComponentId, Ecosystem, ProjectUnit, UnitDeclaration};

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
            units: Vec::new(),
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

    #[test]
    fn rejects_source_evidence_owned_by_the_wrong_workspace_unit() {
        let known = component("known");
        let declaration = |root: &str, manifest: &str| {
            ProjectUnit::new(
                root.into(),
                manifest.into(),
                Ecosystem::Npm,
                vec![UnitDeclaration {
                    name: "known".to_string(),
                    component: known.id.clone(),
                    section: ManifestSection::Dependencies,
                }],
            )
        };
        let root_unit = declaration("", "package.json");
        let member_unit = declaration("packages/app", "packages/app/package.json");
        let evidence = Evidence::new_for_unit(
            root_unit.id.clone(),
            known.id.clone(),
            EvidenceKind::StaticImport,
            EvidenceOrigin {
                path: "packages/app/src/index.ts".into(),
                span: None,
                description: None,
            },
            SourceRole::Runtime,
            Confidence::High,
            EvidenceResolution::Exact,
        )
        .unwrap();
        let result = ProjectSnapshot::new(".".into(), vec![known], Vec::new())
            .with_units(vec![root_unit, member_unit])
            .unwrap()
            .with_evidence(vec![evidence]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unit_declarations_outside_the_component_inventory() {
        let known = component("known");
        let unknown = component("unknown");
        let unit = ProjectUnit::new(
            "".into(),
            "package.json".into(),
            Ecosystem::Npm,
            vec![UnitDeclaration {
                name: "unknown".to_string(),
                component: unknown.id,
                section: ManifestSection::Dependencies,
            }],
        );
        assert!(ProjectSnapshot::new(".".into(), vec![known], Vec::new())
            .with_units(vec![unit])
            .is_err());
    }

    #[test]
    fn rejects_non_normalized_or_escaping_unit_roots() {
        let known = component("known");
        let unit = ProjectUnit::new(
            "../outside".into(),
            "../outside/package.json".into(),
            Ecosystem::Npm,
            vec![UnitDeclaration {
                name: "known".to_string(),
                component: known.id.clone(),
                section: ManifestSection::Dependencies,
            }],
        );
        assert!(ProjectSnapshot::new(".".into(), vec![known], Vec::new())
            .with_units(vec![unit])
            .is_err());
    }
}
