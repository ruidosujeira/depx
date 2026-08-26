use std::collections::BTreeMap;

use miette::{IntoDiagnostic, Result};
use serde_json::json;

use crate::finding::{metadata, FindingSeverity, ProjectAnalysis};

pub fn serialize_sarif(analysis: &ProjectAnalysis) -> Result<String> {
    let mut rules = BTreeMap::new();
    for finding in &analysis.findings {
        let item = metadata(&finding.rule);
        rules.entry(finding.rule.as_str()).or_insert_with(|| {
            json!({
                "id": finding.rule.as_str(),
                "name": item.map_or(finding.summary.as_str(), |value| value.name),
                "shortDescription": {
                    "text": item.map_or(finding.summary.as_str(), |value| value.description)
                }
            })
        });
    }

    let results: Vec<_> = analysis
        .findings
        .iter()
        .map(|finding| {
            let mut result = json!({
                "ruleId": finding.rule.as_str(),
                "level": sarif_level(finding.severity),
                "message": { "text": finding.explanation },
                "fingerprints": { "depx/v1": finding.id.as_str() },
                "properties": {
                    "component": finding.subject,
                    "confidence": finding.confidence,
                    "recommendation": finding.recommendation,
                }
            });
            if let Some(evidence) = analysis
                .snapshot
                .evidence
                .iter()
                .find(|evidence| finding.evidence.binary_search(&evidence.id).is_ok())
            {
                let mut physical_location = json!({
                    "artifactLocation": {
                        "uri": evidence.origin.path.to_string_lossy()
                    }
                });
                if let Some(span) = evidence.origin.span {
                    physical_location["region"] = json!({
                        "byteOffset": span.offset,
                        "byteLength": span.length
                    });
                }
                result["locations"] = json!([{
                    "physicalLocation": physical_location
                }]);
            }
            result
        })
        .collect();

    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "depx",
                    "informationUri": "https://github.com/ruidosujeira/depx",
                    "rules": rules.into_values().collect::<Vec<_>>()
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&document).into_diagnostic()
}

fn sarif_level(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "note",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{AnalysisCoverage, CoverageArea};
    use crate::evidence::{
        Confidence, Evidence, EvidenceKind, EvidenceOrigin, EvidenceResolution, ManifestSection,
        SourceRole,
    };
    use crate::finding::analyze_project;
    use crate::model::{Component, ComponentId, Ecosystem, ProjectSnapshot};
    use serde_json::Value;

    #[test]
    fn emits_sarif_rules_locations_and_stable_fingerprints() {
        let component = Component {
            id: ComponentId {
                ecosystem: Ecosystem::Npm,
                name: "unused".to_string(),
                version: "1.0.0".to_string(),
                location: Some("node_modules/unused".to_string()),
            },
            direct: true,
            dev: false,
            deprecated: None,
        };
        let evidence = Evidence::new(
            component.id.clone(),
            EvidenceKind::ManifestDeclaration {
                section: ManifestSection::Dependencies,
            },
            EvidenceOrigin {
                path: "package.json".into(),
                span: None,
                description: None,
            },
            SourceRole::Unknown,
            Confidence::High,
            EvidenceResolution::Exact,
        )
        .unwrap();
        let snapshot = ProjectSnapshot::new(".".into(), vec![component], Vec::new())
            .with_evidence(vec![evidence])
            .unwrap();
        let analysis = analyze_project(
            snapshot,
            AnalysisCoverage::new(vec![CoverageArea::StaticImports], Vec::new()),
        )
        .unwrap();
        let sarif: Value = serde_json::from_str(&serialize_sarif(&analysis).unwrap()).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "DX001");
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "package.json"
        );
        assert!(sarif["runs"][0]["results"][0]["fingerprints"]["depx/v1"]
            .as_str()
            .unwrap()
            .starts_with("fd-"));
    }
}
