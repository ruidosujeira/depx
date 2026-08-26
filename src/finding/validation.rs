use std::collections::HashSet;

use miette::{bail, Result};

use crate::analysis::UsageState;
use crate::evidence::{EvidenceKind, EvidenceResolution};

use super::catalog::metadata;
use super::engine::{sort_findings, ProjectAnalysis};
use super::FindingDetails;

pub fn validate_analysis(analysis: &ProjectAnalysis) -> Result<()> {
    analysis.snapshot.validate()?;
    let component_ids: HashSet<_> = analysis
        .snapshot
        .components
        .iter()
        .map(|component| &component.id)
        .collect();
    let evidence_ids: HashSet<_> = analysis
        .snapshot
        .evidence
        .iter()
        .map(|evidence| &evidence.id)
        .collect();
    let mut finding_ids = HashSet::new();
    let mut expected = analysis.findings.clone();
    sort_findings(&mut expected);
    if expected != analysis.findings {
        bail!("Findings must be deterministically ordered");
    }

    for finding in &analysis.findings {
        if !finding_ids.insert(&finding.id) {
            bail!("Duplicate finding ID {}", finding.id.as_str());
        }
        let Some(rule) = metadata(&finding.rule) else {
            bail!("Unknown finding rule {}", finding.rule.as_str());
        };
        if rule.code != "DX004" && finding.severity != rule.default_severity {
            bail!("Finding severity is incompatible with {}", rule.code);
        }
        if !component_ids.contains(&finding.subject) {
            bail!("Finding references a component outside the snapshot");
        }
        if !strictly_sorted(finding.evidence.iter())
            || finding.evidence.iter().any(|id| !evidence_ids.contains(id))
        {
            bail!("Finding has invalid or unordered evidence references");
        }
        if let Some(recommendation) = &finding.recommendation {
            if !rule.allowed_actions.contains(&recommendation.action) {
                bail!("Recommendation action is incompatible with {}", rule.code);
            }
        }
        validate_rule_invariants(analysis, finding)?;
    }
    Ok(())
}

fn validate_rule_invariants(analysis: &ProjectAnalysis, finding: &super::Finding) -> Result<()> {
    match finding.rule.as_str() {
        "DX001" => {
            let direct = analysis
                .snapshot
                .components
                .iter()
                .any(|component| component.id == finding.subject && component.direct);
            let no_evidence = analysis.assessments.iter().any(|assessment| {
                assessment.component == finding.subject
                    && assessment.state == UsageState::NoEvidence
            });
            if !direct || !no_evidence {
                bail!("DX001 requires a direct component assessed as NoEvidence");
            }
        }
        "DX002" => {
            if finding.evidence.is_empty()
                || !analysis.snapshot.evidence.iter().any(|evidence| {
                    finding.evidence.contains(&evidence.id)
                        && matches!(evidence.resolution, EvidenceResolution::Ambiguous { .. })
                })
            {
                bail!("DX002 requires ambiguous evidence");
            }
        }
        "DX005" => {
            let FindingDetails::PotentiallyRedundantDeclaration { path } = &finding.details else {
                bail!("DX005 requires a transitive path");
            };
            let direct = analysis
                .snapshot
                .components
                .iter()
                .any(|component| component.id == finding.subject && component.direct);
            let declared = analysis.snapshot.evidence.iter().any(|evidence| {
                evidence.subject == finding.subject
                    && matches!(evidence.kind, EvidenceKind::ManifestDeclaration { .. })
            });
            let proven = path.len() >= 2
                && path.last() == Some(&finding.subject)
                && path.windows(2).all(|pair| {
                    analysis
                        .snapshot
                        .dependency_edges
                        .iter()
                        .any(|edge| edge.from == pair[0] && edge.to == pair[1])
                });
            if !direct || !declared || !proven {
                bail!("DX005 requires direct declaration evidence and a proven transitive path");
            }
        }
        _ => {}
    }
    Ok(())
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
