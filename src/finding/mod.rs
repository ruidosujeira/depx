mod catalog;
mod engine;
mod model;
pub(crate) mod rules;
mod validation;

pub use catalog::{is_known_code, metadata};
pub use engine::{analyze_project, ProjectAnalysis};
pub use model::{
    DuplicateKind, Finding, FindingDetails, FindingSeverity, Recommendation, RecommendationAction,
    RuleCode, FINDING_SCHEMA_VERSION,
};
pub use validation::validate_analysis;

use miette::Result;

use crate::analysis::{AnalysisCoverage, UsageAssessment};
use crate::model::ProjectSnapshot;

trait FindingRule {
    fn code(&self) -> &'static str;
    fn evaluate(
        &self,
        snapshot: &ProjectSnapshot,
        assessments: &[UsageAssessment],
        coverage: &AnalysisCoverage,
    ) -> Result<Vec<Finding>>;
}
