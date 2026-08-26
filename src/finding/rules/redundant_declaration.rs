use std::collections::{HashMap, HashSet, VecDeque};

use miette::Result;

use crate::analysis::{AnalysisCoverage, UsageAssessment, UsageState};
use crate::evidence::{Confidence, EvidenceKind};
use crate::model::{ComponentId, ProjectSnapshot};

use super::super::{
    Finding, FindingDetails, FindingRule, FindingSeverity, Recommendation, RecommendationAction,
    RuleCode,
};

pub struct RedundantDeclarationRule;

impl FindingRule for RedundantDeclarationRule {
    fn code(&self) -> &'static str {
        "DX005"
    }

    fn evaluate(
        &self,
        snapshot: &ProjectSnapshot,
        assessments: &[UsageAssessment],
        _coverage: &AnalysisCoverage,
    ) -> Result<Vec<Finding>> {
        let adjacency = adjacency(snapshot);
        let direct: Vec<_> = snapshot
            .components
            .iter()
            .filter(|component| component.direct)
            .map(|component| component.id.clone())
            .collect();
        let mut findings = Vec::new();
        for assessment in assessments {
            if assessment.state != UsageState::NoEvidence || !direct.contains(&assessment.component)
            {
                continue;
            }
            let path = direct
                .iter()
                .filter(|root| **root != assessment.component)
                .filter_map(|root| shortest_path(root, &assessment.component, &adjacency))
                .min_by(|left, right| left.len().cmp(&right.len()).then_with(|| left.cmp(right)));
            let Some(path) = path else {
                continue;
            };
            let mut evidence = Vec::new();
            for item in &snapshot.evidence {
                if item.subject == assessment.component
                    && matches!(item.kind, EvidenceKind::ManifestDeclaration { .. })
                {
                    evidence.push(item.id.clone());
                }
            }
            for edge in path.windows(2) {
                for item in &snapshot.evidence {
                    if item.subject == edge[1]
                        && matches!(
                            &item.kind,
                            EvidenceKind::TransitiveDependency { from, .. } if *from == edge[0]
                        )
                    {
                        evidence.push(item.id.clone());
                    }
                }
            }
            findings.push(Finding::new(
                RuleCode::new(self.code()),
                FindingSeverity::Info,
                Confidence::Medium,
                assessment.component.clone(),
                "Direct declaration may be redundant".to_string(),
                format!(
                    "The component is declared directly without direct usage evidence and is also reachable through {}.",
                    path.iter()
                        .map(ComponentId::qualified_name)
                        .collect::<Vec<_>>()
                        .join(" -> ")
                ),
                evidence,
                Some(Recommendation {
                    action: RecommendationAction::Review,
                    message: "Review whether the direct declaration is intentionally relied upon before removing it."
                        .to_string(),
                }),
                FindingDetails::PotentiallyRedundantDeclaration { path },
            )?);
        }
        Ok(findings)
    }
}

fn adjacency(snapshot: &ProjectSnapshot) -> HashMap<ComponentId, Vec<ComponentId>> {
    let mut adjacency: HashMap<ComponentId, Vec<ComponentId>> = HashMap::new();
    for edge in &snapshot.dependency_edges {
        adjacency
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
    }
    for targets in adjacency.values_mut() {
        targets.sort();
        targets.dedup();
    }
    adjacency
}

fn shortest_path(
    root: &ComponentId,
    target: &ComponentId,
    adjacency: &HashMap<ComponentId, Vec<ComponentId>>,
) -> Option<Vec<ComponentId>> {
    let mut queue = VecDeque::from([(root.clone(), vec![root.clone()])]);
    let mut visited = HashSet::new();
    while let Some((current, path)) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        for next in adjacency.get(&current).into_iter().flatten() {
            let mut next_path = path.clone();
            next_path.push(next.clone());
            if next == target {
                return Some(next_path);
            }
            queue.push_back((next.clone(), next_path));
        }
    }
    None
}
