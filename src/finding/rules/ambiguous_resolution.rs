use std::collections::BTreeMap;

use miette::Result;

use crate::analysis::{AnalysisCoverage, UsageAssessment};
use crate::evidence::{Confidence, EvidenceId, EvidenceKind, EvidenceOrigin, EvidenceResolution};
use crate::model::{ComponentId, ProjectSnapshot};

use super::super::{
    Finding, FindingDetails, FindingRule, FindingSeverity, Recommendation, RecommendationAction,
    RuleCode,
};

pub struct AmbiguousResolutionRule;

type AmbiguityKey = (EvidenceOrigin, EvidenceKind, Vec<ComponentId>);

impl FindingRule for AmbiguousResolutionRule {
    fn code(&self) -> &'static str {
        "DX002"
    }

    fn evaluate(
        &self,
        snapshot: &ProjectSnapshot,
        _assessments: &[UsageAssessment],
        _coverage: &AnalysisCoverage,
    ) -> Result<Vec<Finding>> {
        let mut groups: BTreeMap<AmbiguityKey, Vec<EvidenceId>> = BTreeMap::new();
        for evidence in &snapshot.evidence {
            let EvidenceResolution::Ambiguous { candidates } = &evidence.resolution else {
                continue;
            };
            groups
                .entry((
                    evidence.origin.clone(),
                    evidence.kind.clone(),
                    candidates.clone(),
                ))
                .or_default()
                .push(evidence.id.clone());
        }

        let mut findings = Vec::new();
        for ((origin, _kind, candidates), evidence) in groups {
            let Some(subject) = candidates.first().cloned() else {
                continue;
            };
            let candidate_text = candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(Finding::new(
                RuleCode::new(self.code()),
                FindingSeverity::Warning,
                Confidence::High,
                subject,
                "Reference resolves to multiple installed components".to_string(),
                format!(
                    "{} contains a reference that could resolve to: {candidate_text}.",
                    origin.path.display()
                ),
                evidence,
                Some(Recommendation {
                    action: RecommendationAction::InspectResolution,
                    message: "Inspect the installation topology or qualify the component query."
                        .to_string(),
                }),
                FindingDetails::AmbiguousResolution { candidates },
            )?);
        }
        Ok(findings)
    }
}
