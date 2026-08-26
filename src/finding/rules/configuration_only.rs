use miette::Result;

use crate::analysis::{AnalysisCoverage, UsageAssessment, UsageState};
use crate::evidence::{EvidenceKind, EvidenceResolution};
use crate::model::ProjectSnapshot;

use super::super::{
    Finding, FindingDetails, FindingRule, FindingSeverity, Recommendation, RecommendationAction,
    RuleCode,
};

pub struct ConfigurationOnlyRule;

impl FindingRule for ConfigurationOnlyRule {
    fn code(&self) -> &'static str {
        "DX003"
    }

    fn evaluate(
        &self,
        snapshot: &ProjectSnapshot,
        assessments: &[UsageAssessment],
        _coverage: &AnalysisCoverage,
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
            if !component.direct || assessment.state != UsageState::ConfigurationOnly {
                continue;
            }
            let evidence = snapshot
                .evidence
                .iter()
                .filter(|item| {
                    item.subject == component.id
                        && item.kind == EvidenceKind::ConfigurationReference
                        && item.resolution == EvidenceResolution::Exact
                })
                .map(|item| item.id.clone())
                .collect();
            findings.push(Finding::new(
                RuleCode::new(self.code()),
                FindingSeverity::Info,
                assessment.confidence,
                component.id.clone(),
                "Dependency used only through configuration".to_string(),
                "Supported configuration files reference this dependency, with no runtime, test, build or package-script evidence.".to_string(),
                evidence,
                Some(Recommendation {
                    action: RecommendationAction::NoAction,
                    message: "No action is required unless the configuration is being removed."
                        .to_string(),
                }),
                FindingDetails::ConfigurationOnly,
            )?);
        }
        Ok(findings)
    }
}
