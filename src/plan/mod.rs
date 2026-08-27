use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, Result};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::analysis::{UsageAssessment, UsageState};
use crate::evidence::Confidence;
use crate::finding::{DuplicateKind, FindingDetails, ProjectAnalysis};
use crate::graph::DependencyGraph;
use crate::model::{Component, ComponentId, Ecosystem};
use crate::types::{DeprecatedPackage, Severity, Vulnerability};

pub const PLAN_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanPriority {
    Low,
    Medium,
    High,
    Urgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanActionKind {
    SecurityUpgrade,
    ReviewRemoval,
    ReplaceDeprecated,
    ConsolidateVersions,
    ReviewDeclaration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRisk {
    Patch,
    Minor,
    Major,
    Manual,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanAction {
    pub id: String,
    pub priority: PlanPriority,
    pub kind: PlanActionKind,
    pub component: ComponentId,
    pub root_component: Option<ComponentId>,
    pub usage: UsageState,
    pub confidence: Confidence,
    pub title: String,
    pub reason: String,
    pub target_version: Option<String>,
    pub change_risk: ChangeRisk,
    pub advisory_ids: Vec<String>,
    pub finding_ids: Vec<String>,
    pub dependency_chains: Vec<Vec<ComponentId>>,
    pub command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSummary {
    pub total_actions: usize,
    pub security_actions: usize,
    pub removal_reviews: usize,
    pub deprecated_replacements: usize,
    pub consolidation_actions: usize,
    pub declaration_reviews: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationPlan {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub project: PathBuf,
    pub summary: PlanSummary,
    pub actions: Vec<PlanAction>,
}

pub fn build_plan(
    analysis: &ProjectAnalysis,
    vulnerabilities: &[Vulnerability],
    deprecated: &[DeprecatedPackage],
) -> Result<RemediationPlan> {
    let graph = DependencyGraph::from_analysis(analysis)?;
    let assessments: HashMap<_, _> = analysis
        .assessments
        .iter()
        .map(|assessment| (&assessment.component, assessment))
        .collect();
    let mut actions = Vec::new();
    let mut represented_findings = HashSet::new();
    let mut vulnerability_groups: BTreeMap<ComponentId, Vec<&Vulnerability>> = BTreeMap::new();
    for vulnerability in vulnerabilities {
        vulnerability_groups
            .entry(vulnerability.component.clone())
            .or_default()
            .push(vulnerability);
    }

    for (component_id, group) in vulnerability_groups {
        let component = analysis
            .snapshot
            .components
            .iter()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                miette::miette!(
                    "Vulnerability references a component outside the analysis snapshot"
                )
            })?;
        let name = &component.id.name;
        let version = &component.id.version;
        let assessment = assessment_for(&assessments, &component.id);
        let explanation = graph.explain_component(&component.id).ok();
        let chains = explanation
            .as_ref()
            .map(|item| item.dependency_chains.clone())
            .unwrap_or_default();
        let root_component = remediation_root(component, &chains);
        let max_severity = group
            .iter()
            .map(|vulnerability| vulnerability.severity)
            .max()
            .unwrap_or(Severity::Unknown);
        let reachable = group
            .iter()
            .any(|vulnerability| vulnerability.affects_used_code);
        let target_version = highest_fixed_version(&group);
        let no_usage_evidence = component.direct && assessment.state == UsageState::NoEvidence;
        let kind = if no_usage_evidence {
            PlanActionKind::ReviewRemoval
        } else {
            PlanActionKind::SecurityUpgrade
        };
        let priority = security_priority(max_severity, reachable);
        let mut advisory_ids: Vec<_> = group
            .iter()
            .map(|vulnerability| vulnerability.id.clone())
            .collect();
        advisory_ids.sort();
        advisory_ids.dedup();
        let related_findings: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.subject == component.id)
            .map(|finding| finding.id.as_str().to_string())
            .collect();
        represented_findings.extend(related_findings.iter().cloned());
        let title = match (&kind, &target_version) {
            (PlanActionKind::ReviewRemoval, _) => {
                format!("Review removal of {}@{}", name, version)
            }
            (_, Some(target)) => format!("Upgrade {name} {version} -> {target}"),
            _ => format!("Remediate vulnerable {name}@{version}"),
        };
        let reason = if no_usage_evidence {
            format!(
                "{} known {}; the direct dependency has no supported usage evidence, so review removal before upgrading",
                advisory_ids.len(),
                vulnerability_label(advisory_ids.len())
            )
        } else {
            format!(
                "{} {} {}{}",
                advisory_ids.len(),
                max_severity,
                vulnerability_label(advisory_ids.len()),
                if reachable {
                    " in reachable code"
                } else {
                    " outside observed reachable code"
                }
            )
        };
        let command = (kind == PlanActionKind::SecurityUpgrade)
            .then(|| {
                direct_update_command(
                    component,
                    target_version.as_deref(),
                    &analysis.snapshot.root,
                )
            })
            .flatten();
        actions.push(new_action(ActionInput {
            priority,
            kind,
            component: component.id.clone(),
            root_component,
            assessment,
            title,
            reason,
            target_version: target_version.clone(),
            change_risk: target_version
                .as_deref()
                .map_or(ChangeRisk::Unknown, |target| change_risk(version, target)),
            advisory_ids,
            finding_ids: related_findings,
            dependency_chains: chains,
            command,
        })?);
    }

    for item in deprecated {
        let assessment = assessment_for(&assessments, &item.package.id);
        let explanation = graph.explain_component(&item.package.id).ok();
        let chains = explanation
            .as_ref()
            .map(|value| value.dependency_chains.clone())
            .unwrap_or_default();
        let root_component = remediation_root(&item.package, &chains);
        actions.push(new_action(ActionInput {
            priority: if item.is_used {
                PlanPriority::High
            } else {
                PlanPriority::Medium
            },
            kind: PlanActionKind::ReplaceDeprecated,
            component: item.package.id.clone(),
            root_component,
            assessment,
            title: format!("Replace deprecated {}", item.package.id.qualified_name()),
            reason: item.message.clone(),
            target_version: None,
            change_risk: ChangeRisk::Manual,
            advisory_ids: Vec::new(),
            finding_ids: Vec::new(),
            dependency_chains: chains,
            command: None,
        })?);
    }

    for finding in &analysis.findings {
        if represented_findings.contains(finding.id.as_str()) {
            continue;
        }
        let (kind, priority, risk, title) = match &finding.details {
            FindingDetails::NoUsageEvidence { .. }
                if component_is_dev(analysis, &finding.subject) =>
            {
                (
                    PlanActionKind::ReviewDeclaration,
                    PlanPriority::Low,
                    ChangeRisk::Manual,
                    format!(
                        "Review development declaration {}",
                        finding.subject.qualified_name()
                    ),
                )
            }
            FindingDetails::NoUsageEvidence { .. } => (
                PlanActionKind::ReviewRemoval,
                PlanPriority::Medium,
                ChangeRisk::Manual,
                format!("Review removal of {}", finding.subject.qualified_name()),
            ),
            FindingDetails::PotentiallyRedundantDeclaration { .. } => (
                PlanActionKind::ReviewDeclaration,
                PlanPriority::Low,
                ChangeRisk::Manual,
                format!("Review declaration of {}", finding.subject.qualified_name()),
            ),
            FindingDetails::DuplicateVersions {
                kind: DuplicateKind::MultipleMajorVersions,
                ..
            } => (
                PlanActionKind::ConsolidateVersions,
                PlanPriority::Low,
                ChangeRisk::Manual,
                format!("Consolidate versions of {}", finding.subject.name),
            ),
            _ => continue,
        };
        let Some(component) = analysis
            .snapshot
            .components
            .iter()
            .find(|component| component.id == finding.subject)
        else {
            continue;
        };
        let assessment = assessment_for(&assessments, &component.id);
        let explanation = graph.explain_component(&component.id).ok();
        let chains = explanation
            .as_ref()
            .map(|value| value.dependency_chains.clone())
            .unwrap_or_default();
        actions.push(new_action(ActionInput {
            priority,
            kind,
            component: component.id.clone(),
            root_component: remediation_root(component, &chains),
            assessment,
            title,
            reason: finding.explanation.clone(),
            target_version: None,
            change_risk: risk,
            advisory_ids: Vec::new(),
            finding_ids: vec![finding.id.as_str().to_string()],
            dependency_chains: chains,
            command: None,
        })?);
    }

    actions.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.component.cmp(&right.component))
            .then_with(|| left.id.cmp(&right.id))
    });
    let summary = summarize(&actions);
    Ok(RemediationPlan {
        schema_version: PLAN_SCHEMA_VERSION,
        project: analysis.snapshot.root.clone(),
        summary,
        actions,
    })
}

fn component_is_dev(analysis: &ProjectAnalysis, id: &ComponentId) -> bool {
    analysis
        .snapshot
        .components
        .iter()
        .find(|component| component.id == *id)
        .is_some_and(|component| component.dev)
}

struct ActionInput {
    priority: PlanPriority,
    kind: PlanActionKind,
    component: ComponentId,
    root_component: Option<ComponentId>,
    assessment: UsageAssessment,
    title: String,
    reason: String,
    target_version: Option<String>,
    change_risk: ChangeRisk,
    advisory_ids: Vec<String>,
    finding_ids: Vec<String>,
    dependency_chains: Vec<Vec<ComponentId>>,
    command: Option<String>,
}

fn new_action(input: ActionInput) -> Result<PlanAction> {
    let identity = serde_json::to_vec(&(
        input.kind,
        &input.component,
        &input.advisory_ids,
        &input.finding_ids,
    ))
    .into_diagnostic()?;
    Ok(PlanAction {
        id: format!("pa-{:016x}", fnv1a(&identity)),
        priority: input.priority,
        kind: input.kind,
        component: input.component,
        root_component: input.root_component,
        usage: input.assessment.state,
        confidence: input.assessment.confidence,
        title: input.title,
        reason: input.reason,
        target_version: input.target_version,
        change_risk: input.change_risk,
        advisory_ids: input.advisory_ids,
        finding_ids: input.finding_ids,
        dependency_chains: input.dependency_chains,
        command: input.command,
    })
}

fn assessment_for(
    assessments: &HashMap<&ComponentId, &UsageAssessment>,
    component: &ComponentId,
) -> UsageAssessment {
    assessments.get(component).map_or_else(
        || UsageAssessment {
            component: component.clone(),
            state: UsageState::NoEvidence,
            confidence: Confidence::Low,
            evidence: Vec::new(),
        },
        |assessment| (*assessment).clone(),
    )
}

fn remediation_root(component: &Component, chains: &[Vec<ComponentId>]) -> Option<ComponentId> {
    if component.direct {
        return Some(component.id.clone());
    }
    chains.first().and_then(|chain| chain.first()).cloned()
}

fn highest_fixed_version(vulnerabilities: &[&Vulnerability]) -> Option<String> {
    let versions: Vec<_> = vulnerabilities
        .iter()
        .filter_map(|vulnerability| vulnerability.patched_version.clone())
        .collect();
    versions
        .iter()
        .filter_map(|value| Version::parse(value).ok())
        .max()
        .map(|version| version.to_string())
        .or_else(|| versions.into_iter().max())
}

fn security_priority(severity: Severity, reachable: bool) -> PlanPriority {
    match (severity, reachable) {
        (Severity::Critical, true) => PlanPriority::Urgent,
        (Severity::Critical | Severity::High, _) => PlanPriority::High,
        (Severity::Medium, true) => PlanPriority::Medium,
        (Severity::Unknown, _) => PlanPriority::Low,
        _ => PlanPriority::Low,
    }
}

fn change_risk(current: &str, target: &str) -> ChangeRisk {
    let (Ok(current), Ok(target)) = (Version::parse(current), Version::parse(target)) else {
        return ChangeRisk::Unknown;
    };
    if target.major != current.major {
        ChangeRisk::Major
    } else if target.minor != current.minor {
        ChangeRisk::Minor
    } else {
        ChangeRisk::Patch
    }
}

fn direct_update_command(
    component: &Component,
    target: Option<&str>,
    project_root: &Path,
) -> Option<String> {
    if !component.direct {
        return None;
    }
    let target = target?;
    Some(match component.id.ecosystem {
        Ecosystem::Npm if project_root.join("pnpm-lock.yaml").is_file() => {
            format!("pnpm update --recursive {}@{}", component.id.name, target)
        }
        Ecosystem::Npm if project_root.join("yarn.lock").is_file() => {
            let modern = std::fs::read_to_string(project_root.join("yarn.lock"))
                .is_ok_and(|lockfile| lockfile.lines().any(|line| line.trim() == "__metadata:"));
            let verb = if modern { "up" } else { "upgrade" };
            format!("yarn {verb} {}@{}", component.id.name, target)
        }
        Ecosystem::Npm => format!("npm install {}@{}", component.id.name, target),
        Ecosystem::Cargo => format!("cargo update -p {} --precise {}", component.id.name, target),
    })
}

fn summarize(actions: &[PlanAction]) -> PlanSummary {
    PlanSummary {
        total_actions: actions.len(),
        security_actions: actions
            .iter()
            .filter(|action| action.kind == PlanActionKind::SecurityUpgrade)
            .count(),
        removal_reviews: actions
            .iter()
            .filter(|action| action.kind == PlanActionKind::ReviewRemoval)
            .count(),
        deprecated_replacements: actions
            .iter()
            .filter(|action| action.kind == PlanActionKind::ReplaceDeprecated)
            .count(),
        consolidation_actions: actions
            .iter()
            .filter(|action| action.kind == PlanActionKind::ConsolidateVersions)
            .count(),
        declaration_reviews: actions
            .iter()
            .filter(|action| action.kind == PlanActionKind::ReviewDeclaration)
            .count(),
    }
}

fn vulnerability_label(count: usize) -> &'static str {
    if count == 1 {
        "vulnerability"
    } else {
        "vulnerabilities"
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
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

    fn component(name: &str, used: bool) -> (Component, Vec<Evidence>) {
        let component = Component {
            id: ComponentId {
                ecosystem: Ecosystem::Npm,
                name: name.to_string(),
                version: "1.2.5".to_string(),
                location: Some(format!("node_modules/{name}")),
            },
            direct: true,
            dev: false,
            deprecated: None,
        };
        let mut evidence = vec![Evidence::new(
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
        .unwrap()];
        if used {
            evidence.push(
                Evidence::new(
                    component.id.clone(),
                    EvidenceKind::StaticImport,
                    EvidenceOrigin {
                        path: "src/index.ts".into(),
                        span: None,
                        description: None,
                    },
                    SourceRole::Runtime,
                    Confidence::High,
                    EvidenceResolution::Exact,
                )
                .unwrap(),
            );
        }
        (component, evidence)
    }

    fn vulnerability_for(component: ComponentId, used: bool) -> Vulnerability {
        Vulnerability {
            component,
            id: "GHSA-test".to_string(),
            title: "Test vulnerability".to_string(),
            severity: Severity::Critical,
            vulnerable_range: "<1.2.6".to_string(),
            patched_version: Some("1.2.6".to_string()),
            url: None,
            affects_used_code: used,
        }
    }

    fn vulnerability(used: bool) -> Vulnerability {
        vulnerability_for(
            ComponentId {
                ecosystem: Ecosystem::Npm,
                name: "minimist".to_string(),
                version: "1.2.5".to_string(),
                location: Some("node_modules/minimist".to_string()),
            },
            used,
        )
    }

    #[test]
    fn reachable_critical_vulnerability_becomes_urgent_patch_action() {
        let (component, evidence) = component("minimist", true);
        let snapshot = ProjectSnapshot::new(".".into(), vec![component], Vec::new())
            .with_evidence(evidence)
            .unwrap();
        let analysis = analyze_project(
            snapshot,
            AnalysisCoverage::new(vec![CoverageArea::StaticImports], Vec::new()),
        )
        .unwrap();
        let plan = build_plan(&analysis, &[vulnerability(true)], &[]).unwrap();
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].priority, PlanPriority::Urgent);
        assert_eq!(plan.actions[0].kind, PlanActionKind::SecurityUpgrade);
        assert_eq!(plan.actions[0].change_risk, ChangeRisk::Patch);
        assert_eq!(
            plan.actions[0].command.as_deref(),
            Some("npm install minimist@1.2.6")
        );
    }

    #[test]
    fn vulnerable_dependency_without_usage_prefers_removal_review() {
        let (component, evidence) = component("minimist", false);
        let snapshot = ProjectSnapshot::new(".".into(), vec![component], Vec::new())
            .with_evidence(evidence)
            .unwrap();
        let analysis = analyze_project(
            snapshot,
            AnalysisCoverage::new(vec![CoverageArea::StaticImports], Vec::new()),
        )
        .unwrap();
        let plan = build_plan(&analysis, &[vulnerability(false)], &[]).unwrap();
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].kind, PlanActionKind::ReviewRemoval);
        assert!(plan.actions[0].reason.contains("review removal"));
        assert!(plan.actions[0].command.is_none());
    }

    #[test]
    fn vulnerability_plan_never_reconstructs_same_version_by_name() {
        let (first, first_evidence) = component("minimist", true);
        let mut second = first.clone();
        second.id.location = Some("node_modules/parent/node_modules/minimist".to_string());
        second.direct = false;
        let snapshot =
            ProjectSnapshot::new(".".into(), vec![first.clone(), second.clone()], Vec::new())
                .with_evidence(first_evidence)
                .unwrap();
        let analysis = analyze_project(
            snapshot,
            AnalysisCoverage::new(vec![CoverageArea::StaticImports], Vec::new()),
        )
        .unwrap();
        let plan = build_plan(
            &analysis,
            &[vulnerability_for(second.id.clone(), false)],
            &[],
        )
        .unwrap();
        let security = plan
            .actions
            .iter()
            .find(|action| action.kind == PlanActionKind::SecurityUpgrade)
            .unwrap();
        assert_eq!(security.component, second.id);
        assert_ne!(security.component, first.id);
    }
}
