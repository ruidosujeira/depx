use miette::{IntoDiagnostic, Result};
use serde::Serialize;

use crate::analysis::{AnalysisCoverage, UsageAssessment};
use crate::evidence::Evidence;
use crate::finding::{Finding, ProjectAnalysis, FINDING_SCHEMA_VERSION};
use crate::model::Component;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonOutput<'a> {
    schema_version: u32,
    project: JsonProject<'a>,
    components: &'a [Component],
    evidence: &'a [Evidence],
    assessments: &'a [UsageAssessment],
    findings: &'a [Finding],
    coverage: &'a AnalysisCoverage,
}

#[derive(Serialize)]
struct JsonProject<'a> {
    root: &'a std::path::Path,
}

pub fn serialize_analysis(analysis: &ProjectAnalysis) -> Result<String> {
    serde_json::to_string_pretty(&JsonOutput {
        schema_version: FINDING_SCHEMA_VERSION,
        project: JsonProject {
            root: &analysis.snapshot.root,
        },
        components: &analysis.snapshot.components,
        evidence: &analysis.snapshot.evidence,
        assessments: &analysis.assessments,
        findings: &analysis.findings,
        coverage: &analysis.coverage,
    })
    .into_diagnostic()
}
