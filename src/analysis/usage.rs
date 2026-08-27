use std::collections::{HashMap, HashSet, VecDeque};

use miette::Result;
use serde::{Deserialize, Serialize};

use crate::evidence::{Confidence, EvidenceId, EvidenceKind, EvidenceResolution, SourceRole};
use crate::model::{ComponentId, ProjectSnapshot};

/// Evidence-backed participation state for one component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageState {
    ConfirmedRuntime,
    ConfirmedDevelopment,
    ConfirmedBuild,
    ConfirmedTest,
    ConfigurationOnly,
    TransitivelyRequired,
    Ambiguous,
    NoEvidence,
}

/// Derived assessment retaining references to all supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageAssessment {
    pub component: ComponentId,
    pub state: UsageState,
    pub confidence: Confidence,
    pub evidence: Vec<EvidenceId>,
}

/// Derive deterministic assessments. Evidence remains the source of truth.
pub fn assess_usage(snapshot: &ProjectSnapshot) -> Result<Vec<UsageAssessment>> {
    snapshot.validate()?;
    let mut by_component = HashMap::new();
    for evidence in &snapshot.evidence {
        by_component
            .entry(&evidence.subject)
            .or_insert_with(Vec::new)
            .push(evidence);
    }

    let mut assessments = Vec::new();
    for component in &snapshot.components {
        let evidence = by_component.get(&component.id).cloned().unwrap_or_default();
        let exact: Vec<_> = evidence
            .iter()
            .copied()
            .filter(|item| item.resolution == EvidenceResolution::Exact)
            .collect();
        let ambiguous = evidence
            .iter()
            .any(|item| matches!(item.resolution, EvidenceResolution::Ambiguous { .. }));

        let has_role = |role| {
            exact
                .iter()
                .any(|item| item.role == role && is_usage(&item.kind))
        };
        let state = if has_role(SourceRole::Runtime) {
            UsageState::ConfirmedRuntime
        } else if has_role(SourceRole::Test) {
            UsageState::ConfirmedTest
        } else if has_role(SourceRole::Build) {
            UsageState::ConfirmedBuild
        } else if has_role(SourceRole::Development) {
            UsageState::ConfirmedDevelopment
        } else if has_role(SourceRole::Configuration) {
            UsageState::ConfigurationOnly
        } else if ambiguous {
            UsageState::Ambiguous
        } else if !component.direct
            && exact
                .iter()
                .any(|item| matches!(item.kind, EvidenceKind::TransitiveDependency { .. }))
        {
            UsageState::TransitivelyRequired
        } else {
            UsageState::NoEvidence
        };

        let confidence = match state {
            UsageState::NoEvidence => Confidence::Low,
            UsageState::Ambiguous => Confidence::Low,
            _ => exact
                .iter()
                .filter(|item| supports_state(state, item))
                .map(|item| item.confidence)
                .max()
                .unwrap_or(Confidence::Low),
        };
        let mut ids: Vec<_> = evidence.iter().map(|item| item.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assessments.push(UsageAssessment {
            component: component.id.clone(),
            state,
            confidence,
            evidence: ids,
        });
    }
    assessments.sort_by(|left, right| left.component.cmp(&right.component));
    Ok(assessments)
}

/// Return the exact components that participate in an observed project surface,
/// including every dependency reachable from those components.
///
/// Ambiguous candidates are retained conservatively: excluding them could hide
/// a vulnerability in the component that the runtime ultimately resolves.
pub fn used_component_ids(
    snapshot: &ProjectSnapshot,
    assessments: &[UsageAssessment],
) -> Result<HashSet<ComponentId>> {
    snapshot.validate()?;
    let known: HashSet<_> = snapshot
        .components
        .iter()
        .map(|component| component.id.clone())
        .collect();
    let mut used: HashSet<_> = assessments
        .iter()
        .filter(|assessment| {
            !matches!(
                assessment.state,
                UsageState::NoEvidence | UsageState::TransitivelyRequired
            )
        })
        .filter(|assessment| known.contains(&assessment.component))
        .map(|assessment| assessment.component.clone())
        .collect();
    let mut queue: VecDeque<_> = used.iter().cloned().collect();

    while let Some(component) = queue.pop_front() {
        for dependency in snapshot
            .dependency_edges
            .iter()
            .filter(|edge| edge.from == component)
            .map(|edge| &edge.to)
        {
            if used.insert(dependency.clone()) {
                queue.push_back(dependency.clone());
            }
        }
    }

    Ok(used)
}

fn supports_state(state: UsageState, evidence: &crate::evidence::Evidence) -> bool {
    match state {
        UsageState::ConfirmedRuntime => {
            evidence.role == SourceRole::Runtime && is_usage(&evidence.kind)
        }
        UsageState::ConfirmedDevelopment => {
            evidence.role == SourceRole::Development && is_usage(&evidence.kind)
        }
        UsageState::ConfirmedBuild => {
            evidence.role == SourceRole::Build && is_usage(&evidence.kind)
        }
        UsageState::ConfirmedTest => evidence.role == SourceRole::Test && is_usage(&evidence.kind),
        UsageState::ConfigurationOnly => {
            evidence.role == SourceRole::Configuration && is_usage(&evidence.kind)
        }
        UsageState::TransitivelyRequired => {
            matches!(evidence.kind, EvidenceKind::TransitiveDependency { .. })
        }
        UsageState::Ambiguous | UsageState::NoEvidence => false,
    }
}

fn is_usage(kind: &EvidenceKind) -> bool {
    matches!(
        kind,
        EvidenceKind::StaticImport
            | EvidenceKind::CommonJsRequire
            | EvidenceKind::DynamicImport
            | EvidenceKind::ReExport
            | EvidenceKind::RustCrateReference
            | EvidenceKind::PackageScript { .. }
            | EvidenceKind::ConfigurationReference
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::evidence::{
        Confidence, Evidence, EvidenceKind, EvidenceOrigin, EvidenceResolution, SourceRole,
    };
    use crate::model::{Component, DependencyEdge, DependencyKind, Ecosystem};

    fn component(name: &str, direct: bool) -> Component {
        Component {
            id: ComponentId {
                ecosystem: Ecosystem::Npm,
                name: name.to_string(),
                version: "1.0.0".to_string(),
                location: Some(format!("node_modules/{name}")),
            },
            direct,
            dev: false,
            deprecated: None,
        }
    }

    fn runtime_evidence(subject: &ComponentId) -> Evidence {
        Evidence::new(
            subject.clone(),
            EvidenceKind::StaticImport,
            EvidenceOrigin {
                path: PathBuf::from("src/index.ts"),
                span: None,
                description: None,
            },
            SourceRole::Runtime,
            Confidence::High,
            EvidenceResolution::Exact,
        )
        .unwrap()
    }

    #[test]
    fn used_components_include_only_reachable_transitives() {
        let used_root = component("used-root", true);
        let used_child = component("used-child", false);
        let unused_root = component("unused-root", true);
        let unused_child = component("unused-child", false);
        let snapshot = ProjectSnapshot::new(
            PathBuf::from("."),
            vec![
                used_root.clone(),
                used_child.clone(),
                unused_root.clone(),
                unused_child.clone(),
            ],
            vec![
                DependencyEdge {
                    from: used_root.id.clone(),
                    to: used_child.id.clone(),
                    kind: DependencyKind::Runtime,
                },
                DependencyEdge {
                    from: unused_root.id.clone(),
                    to: unused_child.id.clone(),
                    kind: DependencyKind::Runtime,
                },
            ],
        )
        .with_evidence(vec![runtime_evidence(&used_root.id)])
        .unwrap();
        let assessments = assess_usage(&snapshot).unwrap();

        let used = used_component_ids(&snapshot, &assessments).unwrap();

        assert!(used.contains(&used_root.id));
        assert!(used.contains(&used_child.id));
        assert!(!used.contains(&unused_root.id));
        assert!(!used.contains(&unused_child.id));
    }
}
