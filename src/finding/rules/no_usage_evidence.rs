use miette::Result;

use crate::analysis::{AnalysisCoverage, UsageAssessment, UsageState};
use crate::evidence::{Confidence, EvidenceKind};
use crate::model::ProjectSnapshot;

use super::super::{
    Finding, FindingDetails, FindingRule, FindingSeverity, Recommendation, RecommendationAction,
    RuleCode,
};

pub struct NoUsageEvidenceRule;

impl FindingRule for NoUsageEvidenceRule {
    fn code(&self) -> &'static str {
        "DX001"
    }

    fn evaluate(
        &self,
        snapshot: &ProjectSnapshot,
        assessments: &[UsageAssessment],
        coverage: &AnalysisCoverage,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for assessment in assessments {
            let Some(component) = snapshot
                .components
                .iter()
                .find(|component| component.id == assessment.component)
            else {
                continue;
            };
            if !component.direct || assessment.state != UsageState::NoEvidence {
                continue;
            }
            let evidence = snapshot
                .evidence
                .iter()
                .filter(|item| {
                    item.subject == component.id
                        && matches!(item.kind, EvidenceKind::ManifestDeclaration { .. })
                })
                .map(|item| item.id.clone())
                .collect();
            findings.push(Finding::new(
                RuleCode::new(self.code()),
                FindingSeverity::Warning,
                Confidence::Low,
                component.id.clone(),
                "Direct dependency without supported usage evidence".to_string(),
                format!(
                    "The component is declared directly, but no supported source, script or configuration references were found. Checked {} surface categories; {} limitations remain.",
                    coverage.checked.len(),
                    coverage.not_checked.len()
                ),
                evidence,
                Some(Recommendation {
                    action: RecommendationAction::Review,
                    message: "Review runtime loading, plugin discovery and unsupported configuration before removing the declaration.".to_string(),
                }),
                FindingDetails::NoUsageEvidence {
                    checked: coverage.checked.clone(),
                    limitations: coverage.not_checked.clone(),
                },
            )?);
        }
        Ok(findings)
    }
}
