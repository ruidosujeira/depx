mod coverage;
mod usage;

pub use coverage::{AnalysisCoverage, CoverageArea, CoverageLimitation};
pub use usage::{assess_usage, used_component_ids, UsageAssessment, UsageState};
