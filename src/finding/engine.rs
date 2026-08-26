use miette::Result;
use serde::{Deserialize, Serialize};

use crate::analysis::{assess_usage, AnalysisCoverage, UsageAssessment};
use crate::model::ProjectSnapshot;

use super::rules::built_in_rules;
use super::{validate_analysis, Finding};

/// Complete derived analysis layered over an observed project snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectAnalysis {
    pub snapshot: ProjectSnapshot,
    pub assessments: Vec<UsageAssessment>,
    pub findings: Vec<Finding>,
    pub coverage: AnalysisCoverage,
}

pub fn analyze_project(
    snapshot: ProjectSnapshot,
    coverage: AnalysisCoverage,
) -> Result<ProjectAnalysis> {
    snapshot.validate()?;
    let assessments = assess_usage(&snapshot)?;
    let mut findings = Vec::new();
    for rule in built_in_rules() {
        findings.extend(rule.evaluate(&snapshot, &assessments, &coverage)?);
    }
    sort_findings(&mut findings);
    findings.dedup_by(|left, right| left.id == right.id);
    let analysis = ProjectAnalysis {
        snapshot,
        assessments,
        findings,
        coverage,
    };
    validate_analysis(&analysis)?;
    Ok(analysis)
}

pub(crate) fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.rule.cmp(&right.rule))
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.id.cmp(&right.id))
    });
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::analysis::{AnalysisCoverage, CoverageArea, CoverageLimitation};
    use crate::evidence::{
        Confidence, Evidence, EvidenceKind, EvidenceOrigin, EvidenceResolution, ManifestSection,
        SourceRole,
    };
    use crate::finding::{
        validate_analysis, DuplicateKind, FindingDetails, FindingSeverity, RuleCode,
    };
    use crate::model::{
        Component, ComponentId, DependencyEdge, DependencyKind, Ecosystem, ProjectSnapshot,
    };

    fn id(ecosystem: Ecosystem, name: &str, version: &str, location: &str) -> ComponentId {
        ComponentId {
            ecosystem,
            name: name.to_string(),
            version: version.to_string(),
            location: Some(location.to_string()),
        }
    }

    fn component(id: ComponentId, direct: bool) -> Component {
        Component {
            id,
            direct,
            dev: false,
            deprecated: None,
        }
    }

    fn origin(path: &str) -> EvidenceOrigin {
        EvidenceOrigin {
            path: PathBuf::from(path),
            span: None,
            description: None,
        }
    }

    fn manifest(subject: &ComponentId) -> Evidence {
        Evidence::new(
            subject.clone(),
            EvidenceKind::ManifestDeclaration {
                section: ManifestSection::Dependencies,
            },
            origin("package.json"),
            SourceRole::Unknown,
            Confidence::High,
            EvidenceResolution::Exact,
        )
        .unwrap()
    }

    fn exact(subject: &ComponentId, kind: EvidenceKind, role: SourceRole) -> Evidence {
        Evidence::new(
            subject.clone(),
            kind,
            origin("src/reference.ts"),
            role,
            Confidence::High,
            EvidenceResolution::Exact,
        )
        .unwrap()
    }

    fn coverage() -> AnalysisCoverage {
        AnalysisCoverage::new(
            vec![CoverageArea::StaticImports, CoverageArea::PackageScripts],
            vec![CoverageLimitation::ComputedModuleNames],
        )
    }

    fn analyze(
        components: Vec<Component>,
        edges: Vec<DependencyEdge>,
        evidence: Vec<Evidence>,
    ) -> ProjectAnalysis {
        let snapshot = ProjectSnapshot::new(PathBuf::from("."), components, edges)
            .with_evidence(evidence)
            .unwrap();
        analyze_project(snapshot, coverage()).unwrap()
    }

    fn findings<'a>(analysis: &'a ProjectAnalysis, code: &str) -> Vec<&'a Finding> {
        analysis
            .findings
            .iter()
            .filter(|finding| finding.rule.as_str() == code)
            .collect()
    }

    #[test]
    fn dx001_only_targets_direct_no_evidence_and_is_cautious() {
        let direct_id = id(Ecosystem::Npm, "old", "1.0.0", "node_modules/old");
        let transitive_id = id(Ecosystem::Npm, "child", "1.0.0", "node_modules/child");
        let analysis = analyze(
            vec![
                component(direct_id.clone(), true),
                component(transitive_id.clone(), false),
            ],
            Vec::new(),
            vec![manifest(&direct_id)],
        );
        let dx001 = findings(&analysis, "DX001");
        assert_eq!(dx001.len(), 1);
        assert_eq!(dx001[0].subject, direct_id);
        assert_eq!(dx001[0].severity, FindingSeverity::Warning);
        let wording = format!(
            "{} {}",
            dx001[0].explanation,
            dx001[0].recommendation.as_ref().unwrap().message
        );
        assert!(!wording.contains("safe to remove"));
        assert!(!dx001.iter().any(|finding| finding.subject == transitive_id));
    }

    #[test]
    fn dx002_groups_ambiguous_evidence_and_preserves_candidates() {
        let first = id(Ecosystem::Npm, "shared", "1.0.0", "node_modules/shared");
        let second = id(
            Ecosystem::Npm,
            "shared",
            "1.0.0",
            "node_modules/a/node_modules/shared",
        );
        let input_candidates = vec![first.clone(), second.clone()];
        let mut candidates = input_candidates.clone();
        candidates.sort();
        let ambiguous = |subject: ComponentId| {
            Evidence::new(
                subject,
                EvidenceKind::StaticImport,
                origin("src/index.ts"),
                SourceRole::Runtime,
                Confidence::Low,
                EvidenceResolution::Ambiguous {
                    candidates: input_candidates.clone(),
                },
            )
            .unwrap()
        };
        let analysis = analyze(
            vec![
                component(first.clone(), true),
                component(second.clone(), true),
            ],
            Vec::new(),
            vec![ambiguous(first), ambiguous(second)],
        );
        let dx002 = findings(&analysis, "DX002");
        assert_eq!(dx002.len(), 1);
        let FindingDetails::AmbiguousResolution { candidates: actual } = &dx002[0].details else {
            panic!("expected ambiguous details");
        };
        assert_eq!(actual, &candidates);
        assert_eq!(dx002[0].evidence.len(), 2);
        assert_eq!(dx002[0].confidence, Confidence::High);
    }

    #[test]
    fn dx003_requires_configuration_only_usage() {
        let config_id = id(Ecosystem::Npm, "plugin", "1.0.0", "node_modules/plugin");
        let config = exact(
            &config_id,
            EvidenceKind::ConfigurationReference,
            SourceRole::Configuration,
        );
        let analysis = analyze(
            vec![component(config_id.clone(), true)],
            Vec::new(),
            vec![manifest(&config_id), config.clone()],
        );
        assert_eq!(findings(&analysis, "DX003").len(), 1);

        let runtime = exact(&config_id, EvidenceKind::StaticImport, SourceRole::Runtime);
        let analysis = analyze(
            vec![component(config_id.clone(), true)],
            Vec::new(),
            vec![manifest(&config_id), config, runtime],
        );
        assert!(findings(&analysis, "DX003").is_empty());

        let script = exact(
            &config_id,
            EvidenceKind::PackageScript {
                script: "lint".to_string(),
            },
            SourceRole::Development,
        );
        let analysis = analyze(
            vec![component(config_id.clone(), true)],
            Vec::new(),
            vec![manifest(&config_id), script],
        );
        assert!(findings(&analysis, "DX003").is_empty());
    }

    #[test]
    fn dx004_classifies_npm_installations_and_version_boundaries() {
        let make = |version: &str, location: &str| {
            component(id(Ecosystem::Npm, "dup", version, location), false)
        };
        for (components, expected) in [
            (
                vec![
                    make("1.0.0", "node_modules/dup"),
                    make("1.0.0", "nested/dup"),
                ],
                DuplicateKind::RepeatedInstallation,
            ),
            (
                vec![make("1.0.0", "a"), make("1.2.0", "b")],
                DuplicateKind::SameMajorVersions,
            ),
            (
                vec![make("1.0.0", "a"), make("2.0.0", "b")],
                DuplicateKind::MultipleMajorVersions,
            ),
        ] {
            let analysis = analyze(components, Vec::new(), Vec::new());
            let dx004 = findings(&analysis, "DX004");
            assert_eq!(dx004.len(), 1);
            assert!(matches!(
                dx004[0].details,
                FindingDetails::DuplicateVersions { kind, .. } if kind == expected
            ));
        }
    }

    #[test]
    fn dx004_uses_normalized_cargo_components() {
        let components = vec![
            component(id(Ecosystem::Cargo, "serde", "1.0.0", "registry+a"), false),
            component(id(Ecosystem::Cargo, "serde", "2.0.0", "registry+a"), false),
        ];
        let analysis = analyze(components, Vec::new(), Vec::new());
        assert_eq!(findings(&analysis, "DX004").len(), 1);
    }

    #[test]
    fn dx005_requires_declaration_and_transitive_path_and_skips_usage_or_ambiguity() {
        let root = id(Ecosystem::Npm, "root", "1.0.0", "node_modules/root");
        let target = id(Ecosystem::Npm, "target", "1.0.0", "node_modules/target");
        let edge = DependencyEdge {
            from: root.clone(),
            to: target.clone(),
            kind: DependencyKind::Runtime,
        };
        let transitive = exact(
            &target,
            EvidenceKind::TransitiveDependency {
                from: root.clone(),
                dependency_kind: DependencyKind::Runtime,
            },
            SourceRole::Unknown,
        );
        let base_components = vec![
            component(root.clone(), true),
            component(target.clone(), true),
        ];
        let base_evidence = vec![manifest(&root), manifest(&target), transitive.clone()];
        let analysis = analyze(
            base_components.clone(),
            vec![edge.clone()],
            base_evidence.clone(),
        );
        assert_eq!(findings(&analysis, "DX005").len(), 1);

        let analysis = analyze(base_components.clone(), Vec::new(), base_evidence.clone());
        assert!(findings(&analysis, "DX005").is_empty());

        let runtime = exact(&target, EvidenceKind::StaticImport, SourceRole::Runtime);
        let mut evidence = base_evidence.clone();
        evidence.push(runtime);
        let analysis = analyze(base_components.clone(), vec![edge.clone()], evidence);
        assert!(findings(&analysis, "DX005").is_empty());

        let ambiguous = Evidence::new(
            target.clone(),
            EvidenceKind::StaticImport,
            origin("src/index.ts"),
            SourceRole::Runtime,
            Confidence::Low,
            EvidenceResolution::Ambiguous {
                candidates: vec![target.clone()],
            },
        )
        .unwrap();
        let mut evidence = base_evidence;
        evidence.push(ambiguous);
        let analysis = analyze(base_components, vec![edge], evidence);
        assert!(findings(&analysis, "DX005").is_empty());
    }

    #[test]
    fn finding_ids_order_and_deduplication_are_deterministic() {
        let subject = id(Ecosystem::Npm, "old", "1.0.0", "node_modules/old");
        let first = analyze(
            vec![component(subject.clone(), true)],
            Vec::new(),
            vec![manifest(&subject)],
        );
        let second = analyze(
            vec![component(subject.clone(), true)],
            Vec::new(),
            vec![manifest(&subject)],
        );
        assert_eq!(first.findings, second.findings);
        assert!(first.findings.windows(2).all(|items| {
            items[0].severity > items[1].severity
                || (items[0].severity == items[1].severity && items[0].rule <= items[1].rule)
        }));

        let mut malformed = first.clone();
        malformed.findings.push(malformed.findings[0].clone());
        assert!(validate_analysis(&malformed).is_err());

        let original_id = first.findings[0].id.as_str().to_string();
        let same = crate::finding::Finding::new(
            RuleCode::new("DX001"),
            FindingSeverity::Warning,
            Confidence::Low,
            subject,
            "changed wording".to_string(),
            "changed explanation".to_string(),
            first.findings[0].evidence.clone(),
            first.findings[0].recommendation.clone(),
            first.findings[0].details.clone(),
        )
        .unwrap();
        assert_eq!(same.id.as_str(), original_id);
    }

    #[test]
    fn validation_rejects_unknown_rules_and_missing_evidence() {
        let subject = id(Ecosystem::Npm, "old", "1.0.0", "node_modules/old");
        let analysis = analyze(
            vec![component(subject.clone(), true)],
            Vec::new(),
            vec![manifest(&subject)],
        );
        let mut unknown = analysis.clone();
        unknown.findings[0].rule = RuleCode::new("DX999");
        assert!(validate_analysis(&unknown).is_err());

        let mut missing = analysis;
        missing.snapshot.evidence.clear();
        assert!(validate_analysis(&missing).is_err());
    }
}
