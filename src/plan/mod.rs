use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use miette::{IntoDiagnostic, Result};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::analysis::{UsageAssessment, UsageState};
use crate::evidence::Confidence;
use crate::finding::{DuplicateKind, FindingDetails, ProjectAnalysis};
use crate::graph::DependencyGraph;
use crate::model::{
    Component, ComponentId, Ecosystem, PackageManager, ProjectSnapshot, ProjectUnit, ProjectUnitId,
};
use crate::types::{DeprecatedPackage, Severity, Vulnerability};

pub const PLAN_SCHEMA_VERSION: u32 = 3;

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
    /// Project units with declarations resolved to this exact component.
    pub owners: Vec<ProjectUnitId>,
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
        let owners = declaration_owners(&analysis.snapshot, &component.id);
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
                    &analysis.snapshot,
                    &owners,
                )
            })
            .flatten();
        actions.push(new_action(ActionInput {
            priority,
            kind,
            component: component.id.clone(),
            root_component,
            owners,
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
        let owners = declaration_owners(&analysis.snapshot, &item.package.id);
        actions.push(new_action(ActionInput {
            priority: if item.is_used {
                PlanPriority::High
            } else {
                PlanPriority::Medium
            },
            kind: PlanActionKind::ReplaceDeprecated,
            component: item.package.id.clone(),
            root_component,
            owners,
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
        let owners = declaration_owners(&analysis.snapshot, &component.id);
        actions.push(new_action(ActionInput {
            priority,
            kind,
            component: component.id.clone(),
            root_component: remediation_root(component, &chains),
            owners,
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
    owners: Vec<ProjectUnitId>,
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
        &input.owners,
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
        owners: input.owners,
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

fn declaration_owners(snapshot: &ProjectSnapshot, component: &ComponentId) -> Vec<ProjectUnitId> {
    let mut owners: Vec<_> = snapshot
        .units
        .iter()
        .filter(|unit| {
            unit.declarations
                .iter()
                .any(|declaration| declaration.component == *component)
        })
        .map(|unit| unit.id.clone())
        .collect();
    owners.sort();
    owners.dedup();
    owners
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
    snapshot: &ProjectSnapshot,
    owners: &[ProjectUnitId],
) -> Option<String> {
    if !component.direct || owners.len() != 1 {
        return None;
    }
    let target = target?;
    let owner = snapshot.unit(&owners[0])?;
    match snapshot.package_manager? {
        PackageManager::Npm | PackageManager::Pnpm | PackageManager::Yarn => {
            javascript_update_command(snapshot, owner, component, target)
        }
        PackageManager::Cargo => cargo_update_command(snapshot, component, target),
    }
}

fn javascript_update_command(
    snapshot: &ProjectSnapshot,
    owner: &ProjectUnit,
    component: &Component,
    target: &str,
) -> Option<String> {
    if component.id.ecosystem != Ecosystem::Npm
        || !valid_npm_name(&component.id.name)
        || Version::parse(target).is_err()
    {
        return None;
    }
    let package = format!("{}@{target}", component.id.name);
    if owner.root.as_os_str().is_empty() {
        return Some(match snapshot.package_manager? {
            PackageManager::Npm => format!("npm install {package}"),
            PackageManager::Pnpm => format!("pnpm update {package}"),
            PackageManager::Yarn => format!("yarn add {package}"),
            PackageManager::Cargo => return None,
        });
    }

    let workspace = exact_workspace_name(snapshot, owner)?;
    Some(match snapshot.package_manager? {
        PackageManager::Npm => format!("npm install {package} --workspace {workspace}"),
        PackageManager::Pnpm => format!("pnpm --filter {workspace} update {package}"),
        PackageManager::Yarn => format!("yarn workspace {workspace} add {package}"),
        PackageManager::Cargo => return None,
    })
}

fn exact_workspace_name<'a>(
    snapshot: &'a ProjectSnapshot,
    owner: &'a ProjectUnit,
) -> Option<&'a str> {
    let name = owner.name.as_deref().filter(|name| valid_npm_name(name))?;
    (snapshot
        .units
        .iter()
        .filter(|unit| unit.name.as_deref() == Some(name))
        .count()
        == 1)
        .then_some(name)
}

fn cargo_update_command(
    snapshot: &ProjectSnapshot,
    component: &Component,
    target: &str,
) -> Option<String> {
    if component.id.ecosystem != Ecosystem::Cargo
        || component.id.location.is_none()
        || !valid_cargo_name(&component.id.name)
        || Version::parse(&component.id.version).is_err()
        || Version::parse(target).is_err()
    {
        return None;
    }
    let same_package_id = snapshot
        .components
        .iter()
        .filter(|candidate| {
            candidate.id.name == component.id.name && candidate.id.version == component.id.version
        })
        .count();
    if same_package_id != 1 {
        return None;
    }
    Some(format!(
        "cargo update -p {}@{} --precise {target}",
        component.id.name, component.id.version
    ))
}

fn valid_npm_name(value: &str) -> bool {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@/._-".contains(&byte))
    {
        return false;
    }
    if let Some(scoped) = value.strip_prefix('@') {
        return scoped
            .split_once('/')
            .is_some_and(|(scope, package)| !scope.is_empty() && !package.is_empty());
    }
    !value.contains('/') && !value.starts_with(['.', '_'])
}

fn valid_cargo_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
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
    use crate::model::{
        Component, ComponentId, Ecosystem, PackageManager, ProjectSnapshot, ProjectUnit,
        ProjectUnitId, UnitDeclaration,
    };

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
        let owner = ProjectUnitId::from_root(std::path::Path::new(""));
        let mut evidence = vec![Evidence::new_for_unit(
            owner.clone(),
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
                Evidence::new_for_unit(
                    owner,
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

    fn unit(root: &str, name: Option<&str>, declarations: &[(&str, &ComponentId)]) -> ProjectUnit {
        let root = PathBuf::from(root);
        let manifest = root.join(match declarations.first().map(|(_, id)| id.ecosystem) {
            Some(Ecosystem::Cargo) => "Cargo.toml",
            _ => "package.json",
        });
        ProjectUnit::new(
            root,
            manifest,
            declarations
                .first()
                .map_or(Ecosystem::Npm, |(_, id)| id.ecosystem),
            declarations
                .iter()
                .map(|(name, component)| UnitDeclaration {
                    name: (*name).to_string(),
                    component: (*component).clone(),
                    section: ManifestSection::Dependencies,
                })
                .collect(),
        )
        .with_name(name.map(str::to_string))
    }

    fn snapshot(
        package_manager: PackageManager,
        components: Vec<Component>,
        units: Vec<ProjectUnit>,
    ) -> ProjectSnapshot {
        ProjectSnapshot::new(".".into(), components, Vec::new())
            .with_units(units)
            .unwrap()
            .with_package_manager(package_manager)
            .unwrap()
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
        let snapshot = snapshot(
            PackageManager::Npm,
            vec![component.clone()],
            vec![unit("", Some("fixture"), &[("minimist", &component.id)])],
        )
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
        let snapshot = snapshot(
            PackageManager::Npm,
            vec![component.clone()],
            vec![unit("", Some("fixture"), &[("minimist", &component.id)])],
        )
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
        let snapshot = snapshot(
            PackageManager::Npm,
            vec![first.clone(), second.clone()],
            vec![unit("", Some("fixture"), &[("minimist", &first.id)])],
        )
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

    fn installed(
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        location: &str,
        direct: bool,
    ) -> Component {
        Component {
            id: ComponentId {
                ecosystem,
                name: name.to_string(),
                version: version.to_string(),
                location: Some(location.to_string()),
            },
            direct,
            dev: false,
            deprecated: None,
        }
    }

    fn command_for(
        snapshot: &ProjectSnapshot,
        component: &Component,
        target: &str,
    ) -> Option<String> {
        let owners = declaration_owners(snapshot, &component.id);
        direct_update_command(component, Some(target), snapshot, &owners)
    }

    #[test]
    fn npm_root_declaration_gets_a_root_scoped_command() {
        let component = installed(
            Ecosystem::Npm,
            "minimist",
            "1.2.5",
            "node_modules/minimist",
            true,
        );
        let snapshot = snapshot(
            PackageManager::Npm,
            vec![component.clone()],
            vec![unit("", Some("root-app"), &[("minimist", &component.id)])],
        );

        assert_eq!(
            command_for(&snapshot, &component, "1.2.6").as_deref(),
            Some("npm install minimist@1.2.6")
        );
    }

    #[test]
    fn npm_nested_workspace_command_selects_the_exact_owner() {
        let component = installed(
            Ecosystem::Npm,
            "minimist",
            "1.2.5",
            "packages/app/node_modules/minimist",
            true,
        );
        let snapshot = snapshot(
            PackageManager::Npm,
            vec![component.clone()],
            vec![unit(
                "packages/app",
                Some("nested-app"),
                &[("minimist", &component.id)],
            )],
        );

        assert_eq!(
            command_for(&snapshot, &component, "1.2.6").as_deref(),
            Some("npm install minimist@1.2.6 --workspace nested-app")
        );
    }

    #[test]
    fn one_installation_declared_by_multiple_units_has_no_single_command() {
        let component = installed(
            Ecosystem::Npm,
            "shared",
            "1.0.0",
            "node_modules/shared",
            true,
        );
        let snapshot = snapshot(
            PackageManager::Npm,
            vec![component.clone()],
            vec![
                unit("", Some("root-app"), &[("shared", &component.id)]),
                unit(
                    "packages/app",
                    Some("nested-app"),
                    &[("shared", &component.id)],
                ),
            ],
        );

        assert_eq!(declaration_owners(&snapshot, &component.id).len(), 2);
        assert!(command_for(&snapshot, &component, "1.0.1").is_none());
    }

    #[test]
    fn same_name_and_version_installations_remain_workspace_scoped() {
        let first = installed(
            Ecosystem::Npm,
            "shared",
            "1.0.0",
            "packages/a/node_modules/shared",
            true,
        );
        let second = installed(
            Ecosystem::Npm,
            "shared",
            "1.0.0",
            "packages/b/node_modules/shared",
            true,
        );
        let snapshot = snapshot(
            PackageManager::Npm,
            vec![second.clone(), first.clone()],
            vec![
                unit("packages/b", Some("workspace-b"), &[("shared", &second.id)]),
                unit("packages/a", Some("workspace-a"), &[("shared", &first.id)]),
            ],
        );

        assert_eq!(
            command_for(&snapshot, &first, "1.0.1").as_deref(),
            Some("npm install shared@1.0.1 --workspace workspace-a")
        );
        assert_eq!(
            command_for(&snapshot, &second, "1.0.1").as_deref(),
            Some("npm install shared@1.0.1 --workspace workspace-b")
        );
    }

    #[test]
    fn pnpm_update_is_filtered_and_never_recursive() {
        let component = installed(
            Ecosystem::Npm,
            "shared",
            "1.0.0",
            "packages/app/node_modules/shared",
            true,
        );
        let snapshot = snapshot(
            PackageManager::Pnpm,
            vec![component.clone()],
            vec![unit(
                "packages/app",
                Some("pnpm-app"),
                &[("shared", &component.id)],
            )],
        );

        let command = command_for(&snapshot, &component, "1.0.1").unwrap();
        assert_eq!(command, "pnpm --filter pnpm-app update shared@1.0.1");
        assert!(!command
            .split_whitespace()
            .any(|token| token == "--recursive"));
    }

    #[test]
    fn yarn_update_selects_the_exact_workspace() {
        let component = installed(
            Ecosystem::Npm,
            "shared",
            "1.0.0",
            "yarn:shared@npm:1.0.0",
            true,
        );
        let snapshot = snapshot(
            PackageManager::Yarn,
            vec![component.clone()],
            vec![unit(
                "packages/app",
                Some("yarn-app"),
                &[("shared", &component.id)],
            )],
        );

        assert_eq!(
            command_for(&snapshot, &component, "1.0.1").as_deref(),
            Some("yarn workspace yarn-app add shared@1.0.1")
        );
    }

    #[test]
    fn cargo_command_disambiguates_two_installed_versions() {
        let old = installed(
            Ecosystem::Cargo,
            "time",
            "0.3.30",
            "registry+https://github.com/rust-lang/crates.io-index",
            true,
        );
        let newer = installed(
            Ecosystem::Cargo,
            "time",
            "0.3.36",
            "registry+https://github.com/rust-lang/crates.io-index",
            false,
        );
        let snapshot = snapshot(
            PackageManager::Cargo,
            vec![newer, old.clone()],
            vec![unit("", Some("rust-app"), &[("time", &old.id)])],
        );

        assert_eq!(
            command_for(&snapshot, &old, "0.3.31").as_deref(),
            Some("cargo update -p time@0.3.30 --precise 0.3.31")
        );
    }

    #[test]
    fn transitive_or_unprovable_targets_never_get_direct_commands() {
        let transitive = installed(
            Ecosystem::Npm,
            "transitive",
            "1.0.0",
            "node_modules/transitive",
            false,
        );
        let direct = installed(
            Ecosystem::Npm,
            "direct",
            "1.0.0",
            "packages/app/node_modules/direct",
            true,
        );
        let snapshot = snapshot(
            PackageManager::Npm,
            vec![transitive.clone(), direct.clone()],
            vec![unit("packages/app", None, &[("direct", &direct.id)])],
        );

        assert!(command_for(&snapshot, &transitive, "1.0.1").is_none());
        assert!(command_for(&snapshot, &direct, "1.0.1").is_none());
    }

    #[test]
    fn cargo_same_name_version_from_multiple_sources_is_not_guessed() {
        let registry = installed(
            Ecosystem::Cargo,
            "shared",
            "1.0.0",
            "registry+https://example.invalid/index",
            true,
        );
        let git = installed(
            Ecosystem::Cargo,
            "shared",
            "1.0.0",
            "git+https://example.invalid/shared",
            false,
        );
        let snapshot = snapshot(
            PackageManager::Cargo,
            vec![git, registry.clone()],
            vec![unit("", Some("rust-app"), &[("shared", &registry.id)])],
        );

        assert!(command_for(&snapshot, &registry, "1.0.1").is_none());
    }

    #[test]
    fn plan_v3_serializes_owners_and_actions_deterministically() {
        let shared = installed(
            Ecosystem::Npm,
            "shared",
            "1.0.0",
            "node_modules/shared",
            true,
        );
        let alpha = installed(Ecosystem::Npm, "alpha", "1.0.0", "node_modules/alpha", true);
        let make_plan = |components, units, vulnerabilities: Vec<Vulnerability>| {
            let snapshot = snapshot(PackageManager::Npm, components, units);
            let analysis = analyze_project(
                snapshot,
                AnalysisCoverage::new(vec![CoverageArea::StaticImports], Vec::new()),
            )
            .unwrap();
            build_plan(&analysis, &vulnerabilities, &[]).unwrap()
        };
        let root = unit(
            "",
            Some("root-app"),
            &[("shared", &shared.id), ("alpha", &alpha.id)],
        );
        let nested = unit(
            "packages/app",
            Some("nested-app"),
            &[("shared", &shared.id)],
        );
        let first = make_plan(
            vec![shared.clone(), alpha.clone()],
            vec![nested.clone(), root.clone()],
            vec![
                vulnerability_for(shared.id.clone(), false),
                vulnerability_for(alpha.id.clone(), false),
            ],
        );
        let second = make_plan(
            vec![alpha.clone(), shared.clone()],
            vec![root, nested],
            vec![
                vulnerability_for(alpha.id, false),
                vulnerability_for(shared.id, false),
            ],
        );

        assert_eq!(first.schema_version, 3);
        let shared_action = first
            .actions
            .iter()
            .find(|action| action.component.name == "shared")
            .unwrap();
        assert_eq!(
            shared_action
                .owners
                .iter()
                .map(ProjectUnitId::as_str)
                .collect::<Vec<_>>(),
            vec!["unit:.", "unit:packages/app"]
        );
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        assert_ne!(first.schema_version, 2);
    }
}
