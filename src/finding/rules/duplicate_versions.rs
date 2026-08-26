use std::collections::{BTreeMap, BTreeSet};

use miette::Result;
use semver::Version;

use crate::analysis::{AnalysisCoverage, UsageAssessment};
use crate::evidence::Confidence;
use crate::model::{ComponentId, Ecosystem, ProjectSnapshot};

use super::super::{
    DuplicateKind, Finding, FindingDetails, FindingRule, FindingSeverity, Recommendation,
    RecommendationAction, RuleCode,
};

pub struct DuplicateVersionsRule;

impl FindingRule for DuplicateVersionsRule {
    fn code(&self) -> &'static str {
        "DX004"
    }

    fn evaluate(
        &self,
        snapshot: &ProjectSnapshot,
        _assessments: &[UsageAssessment],
        _coverage: &AnalysisCoverage,
    ) -> Result<Vec<Finding>> {
        duplicate_findings(snapshot)
    }
}

pub fn duplicate_findings(snapshot: &ProjectSnapshot) -> Result<Vec<Finding>> {
    let mut families: BTreeMap<(Ecosystem, String), Vec<ComponentId>> = BTreeMap::new();
    for component in &snapshot.components {
        families
            .entry((component.id.ecosystem, component.id.name.clone()))
            .or_default()
            .push(component.id.clone());
    }
    let mut findings = Vec::new();
    for ((_ecosystem, name), mut components) in families {
        if components.len() < 2 {
            continue;
        }
        components.sort();
        let versions: BTreeSet<_> = components.iter().map(|id| id.version.as_str()).collect();
        let kind = if versions.len() == 1 {
            DuplicateKind::RepeatedInstallation
        } else {
            let majors: BTreeSet<_> = versions
                .iter()
                .filter_map(|version| Version::parse(version).ok().map(|parsed| parsed.major))
                .collect();
            if majors.len() > 1 {
                DuplicateKind::MultipleMajorVersions
            } else {
                DuplicateKind::SameMajorVersions
            }
        };
        let severity = if kind == DuplicateKind::MultipleMajorVersions {
            FindingSeverity::Warning
        } else {
            FindingSeverity::Info
        };
        findings.push(Finding::new(
            RuleCode::new("DX004"),
            severity,
            Confidence::High,
            components[0].clone(),
            "Multiple component versions or installations are present".to_string(),
            format!(
                "Package {name} has {} normalized installations classified as {kind:?}.",
                components.len()
            ),
            Vec::new(),
            Some(Recommendation {
                action: RecommendationAction::ConsolidateVersions,
                message: "Review whether dependency constraints can be aligned; duplicates are not necessarily harmful."
                    .to_string(),
            }),
            FindingDetails::DuplicateVersions { kind, components },
        )?);
    }
    Ok(findings)
}
