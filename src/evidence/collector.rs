use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic, Result};
use serde::Deserialize;

use crate::analysis::{AnalysisCoverage, CoverageArea, CoverageLimitation};
use crate::analyzer::{ImportAnalyzer, RustAnalyzer, RustReference};
use crate::model::{
    Component, ComponentId, DependencyEdge, Ecosystem, ProjectSnapshot, ProjectUnitId,
};
use crate::types::{Import, ImportKind};

use super::classify_source_role;
use super::scripts::extract_script_commands;
use super::{
    Confidence, Evidence, EvidenceKind, EvidenceOrigin, EvidenceResolution, ManifestSection,
    SourceRole,
};

/// Result of enriching a snapshot with locally collected project evidence.
pub struct EvidenceCollection {
    pub snapshot: ProjectSnapshot,
    pub coverage: AnalysisCoverage,
    pub source_references: usize,
    pub files_analyzed: usize,
}

/// Collect supported local source and script evidence.
pub fn collect_project_evidence(snapshot: ProjectSnapshot) -> Result<EvidenceCollection> {
    snapshot.validate()?;
    let ecosystem = snapshot
        .units
        .first()
        .map(|unit| unit.ecosystem)
        .or_else(|| {
            snapshot
                .components
                .first()
                .map(|component| component.id.ecosystem)
        })
        .or_else(|| {
            snapshot
                .root
                .join("package-lock.json")
                .is_file()
                .then_some(Ecosystem::Npm)
        })
        .or_else(|| {
            snapshot
                .root
                .join("Cargo.lock")
                .is_file()
                .then_some(Ecosystem::Cargo)
        });
    let mut evidence = structural_evidence(&snapshot)?;
    let (source_references, files_analyzed, coverage) = if ecosystem == Some(Ecosystem::Npm) {
        let project_roots = snapshot
            .units
            .iter()
            .map(|unit| snapshot.root.join(&unit.root))
            .collect();
        let imports = ImportAnalyzer::new(&snapshot.root)
            .with_allowed_project_roots(project_roots)
            .analyze()?;
        let (source_evidence, unresolved_imports) = collect_source(&snapshot, imports.imports())?;
        evidence.extend(source_evidence);
        evidence.extend(collect_scripts(&snapshot)?);
        let mut limitations = vec![
            CoverageLimitation::ComputedModuleNames,
            CoverageLimitation::FrameworkPluginDiscovery,
            CoverageLimitation::ArbitraryShellEvaluation,
            CoverageLimitation::UnsupportedConfigurationFormats,
            CoverageLimitation::PackageBinaryAliases,
        ];
        if unresolved_imports {
            limitations.push(CoverageLimitation::UnresolvedPackageReferences);
        }
        (
            imports.total_imports(),
            imports.files_analyzed(),
            AnalysisCoverage::new(
                vec![
                    CoverageArea::ManifestDeclarations,
                    CoverageArea::DependencyGraph,
                    CoverageArea::StaticImports,
                    CoverageArea::CommonJsRequires,
                    CoverageArea::DynamicImports,
                    CoverageArea::ReExports,
                    CoverageArea::PackageScripts,
                    CoverageArea::SupportedConfigurationFiles,
                    CoverageArea::TestFiles,
                ],
                limitations,
            ),
        )
    } else if ecosystem == Some(Ecosystem::Cargo) {
        let project_roots = snapshot
            .units
            .iter()
            .map(|unit| snapshot.root.join(&unit.root))
            .collect();
        let references = RustAnalyzer::new(&snapshot.root)
            .with_allowed_project_roots(project_roots)
            .analyze()?;
        let (source_evidence, unresolved_references) =
            collect_rust_source(&snapshot, references.references())?;
        evidence.extend(source_evidence);
        let mut limitations = vec![
            CoverageLimitation::RustConditionalCompilation,
            CoverageLimitation::RustMacroExpansion,
            CoverageLimitation::GeneratedSourceCode,
        ];
        if unresolved_references {
            limitations.push(CoverageLimitation::UnresolvedPackageReferences);
        }
        (
            references.total_references(),
            references.files_analyzed(),
            AnalysisCoverage::new(
                vec![
                    CoverageArea::ManifestDeclarations,
                    CoverageArea::DependencyGraph,
                    CoverageArea::RustCrateReferences,
                    CoverageArea::TestFiles,
                ],
                limitations,
            ),
        )
    } else {
        (0, 0, AnalysisCoverage::new(Vec::new(), Vec::new()))
    };
    let snapshot = snapshot.with_evidence(evidence)?;
    Ok(EvidenceCollection {
        snapshot,
        coverage,
        source_references,
        files_analyzed,
    })
}

fn collect_rust_source<'a>(
    snapshot: &ProjectSnapshot,
    references: impl Iterator<Item = &'a RustReference>,
) -> Result<(Vec<Evidence>, bool)> {
    let mut evidence = Vec::new();
    let unresolved = false;
    for reference in references {
        let relative = relative_path(&snapshot.root, &reference.file_path);
        let owner = snapshot
            .owner_for_path(&relative)
            .map(|unit| unit.id.clone());
        let candidates = resolve_unit_candidates(snapshot, owner.as_ref(), &reference.identifier);
        if candidates.is_empty() {
            // The conservative Rust scanner also sees local modules/workspace
            // crates, which are intentionally absent from the third-party
            // component inventory. Only resolved unit declarations become
            // dependency evidence.
            continue;
        }
        let role = classify_rust_source_role(&relative);
        evidence.extend(evidence_for_candidates(
            owner,
            candidates,
            EvidenceKind::RustCrateReference,
            EvidenceOrigin {
                path: relative,
                span: Some(reference.span),
                description: Some(format!(
                    "references Rust crate identifier {}",
                    reference.identifier
                )),
            },
            role,
            // This collector resolves syntax without executing cfg expansion or
            // macros, so retain medium confidence even for a unique component.
            Confidence::Medium,
        )?);
    }
    Ok((evidence, unresolved))
}

fn classify_rust_source_role(path: &Path) -> SourceRole {
    if path.file_name().and_then(|name| name.to_str()) == Some("build.rs") {
        return SourceRole::Build;
    }
    if path
        .components()
        .any(|component| matches!(component.as_os_str().to_str(), Some("tests" | "benches")))
    {
        return SourceRole::Test;
    }
    if path
        .components()
        .any(|component| component.as_os_str().to_str() == Some("examples"))
    {
        return SourceRole::Development;
    }
    SourceRole::Runtime
}

fn collect_source<'a>(
    snapshot: &ProjectSnapshot,
    imports: impl Iterator<Item = &'a Import>,
) -> Result<(Vec<Evidence>, bool)> {
    let mut evidence = Vec::new();
    let mut unresolved = false;
    for import in imports {
        let Some(name) = &import.resolved_package else {
            continue;
        };
        let relative = relative_path(&snapshot.root, &import.file_path);
        let owner = snapshot
            .owner_for_path(&relative)
            .map(|unit| unit.id.clone());
        let candidates = resolve_unit_candidates(snapshot, owner.as_ref(), name);
        if candidates.is_empty() {
            unresolved = true;
            continue;
        }
        let role = classify_source_role(&relative);
        let kind = if role == SourceRole::Configuration {
            EvidenceKind::ConfigurationReference
        } else {
            match import.kind {
                ImportKind::EsModule => EvidenceKind::StaticImport,
                ImportKind::CommonJs => EvidenceKind::CommonJsRequire,
                ImportKind::Dynamic => EvidenceKind::DynamicImport,
                ImportKind::ReExport => EvidenceKind::ReExport,
            }
        };
        let origin = EvidenceOrigin {
            path: relative,
            span: import.span,
            description: Some(format!("references {}", import.specifier)),
        };
        let confidence = if candidates.len() == 1
            && snapshot
                .components
                .iter()
                .any(|component| component.id == candidates[0] && component.direct)
        {
            Confidence::High
        } else {
            Confidence::Medium
        };
        evidence.extend(evidence_for_candidates(
            owner, candidates, kind, origin, role, confidence,
        )?);
    }
    Ok((evidence, unresolved))
}

fn collect_scripts(snapshot: &ProjectSnapshot) -> Result<Vec<Evidence>> {
    let mut evidence = Vec::new();
    for unit in &snapshot.units {
        let path = snapshot.root.join(&unit.manifest);
        let content = fs::read_to_string(&path)
            .into_diagnostic()
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let manifest: ScriptManifest = serde_json::from_str(&content)
            .into_diagnostic()
            .with_context(|| format!("Failed to parse {} scripts", path.display()))?;
        for (script, command) in manifest.scripts {
            for executable in extract_script_commands(&command) {
                let mut candidates: Vec<_> = unit
                    .declarations
                    .iter()
                    .filter(|declaration| {
                        binary_names(&declaration.component.name).contains(&executable.as_str())
                    })
                    .map(|declaration| declaration.component.clone())
                    .collect();
                candidates.sort();
                candidates.dedup();
                if candidates.is_empty() {
                    continue;
                }
                let kind = EvidenceKind::PackageScript {
                    script: script.clone(),
                };
                let origin = EvidenceOrigin {
                    path: unit.manifest.clone(),
                    span: None,
                    description: Some(format!("scripts.{script} invokes {executable}: {command}")),
                };
                evidence.extend(evidence_for_candidates(
                    Some(unit.id.clone()),
                    candidates,
                    kind,
                    origin,
                    script_role(&script),
                    Confidence::High,
                )?);
            }
        }
    }
    Ok(evidence)
}

fn resolve_unit_candidates(
    snapshot: &ProjectSnapshot,
    owner: Option<&ProjectUnitId>,
    name: &str,
) -> Vec<ComponentId> {
    if let Some(unit) = owner.and_then(|owner| snapshot.unit(owner)) {
        let mut ids: Vec<_> = unit
            .declarations
            .iter()
            .filter(|declaration| declaration.name == name)
            .map(|declaration| declaration.component.clone())
            .collect();
        ids.sort();
        ids.dedup();
        return ids;
    }
    resolve_candidates(&snapshot.components, name)
}

fn resolve_candidates(components: &[Component], name: &str) -> Vec<ComponentId> {
    let matches: Vec<_> = components
        .iter()
        .filter(|component| component.id.name == name)
        .collect();
    let direct: Vec<_> = matches
        .iter()
        .copied()
        .filter(|component| component.direct)
        .collect();
    let selected = if direct.is_empty() { matches } else { direct };
    let mut ids: Vec<_> = selected
        .into_iter()
        .map(|component| component.id.clone())
        .collect();
    ids.sort();
    ids
}

fn evidence_for_candidates(
    owner: Option<ProjectUnitId>,
    candidates: Vec<ComponentId>,
    kind: EvidenceKind,
    origin: EvidenceOrigin,
    role: SourceRole,
    exact_confidence: Confidence,
) -> Result<Vec<Evidence>> {
    if candidates.len() == 1 {
        let evidence = match owner {
            Some(owner) => Evidence::new_for_unit(
                owner,
                candidates[0].clone(),
                kind,
                origin,
                role,
                exact_confidence,
                EvidenceResolution::Exact,
            ),
            None => Evidence::new(
                candidates[0].clone(),
                kind,
                origin,
                role,
                exact_confidence,
                EvidenceResolution::Exact,
            ),
        }?;
        return Ok(vec![evidence]);
    }
    let resolution = EvidenceResolution::Ambiguous {
        candidates: candidates.clone(),
    };
    candidates
        .into_iter()
        .map(|subject| match &owner {
            Some(owner) => Evidence::new_for_unit(
                owner.clone(),
                subject,
                kind.clone(),
                origin.clone(),
                role,
                Confidence::Low,
                resolution.clone(),
            ),
            None => Evidence::new(
                subject,
                kind.clone(),
                origin.clone(),
                role,
                Confidence::Low,
                resolution.clone(),
            ),
        })
        .collect()
}

fn binary_names(package: &str) -> HashSet<&str> {
    let mut names = HashSet::new();
    names.insert(package);
    if let Some((_, unscoped)) = package.rsplit_once('/') {
        names.insert(unscoped);
    }
    match package {
        "typescript" => {
            names.insert("tsc");
        }
        "@biomejs/biome" => {
            names.insert("biome");
        }
        _ => {}
    }
    names
}

fn script_role(script: &str) -> SourceRole {
    let normalized = script.trim_start_matches("pre").trim_start_matches("post");
    if normalized.contains("test") {
        SourceRole::Test
    } else if matches!(normalized, "build" | "prepare" | "pack") || normalized.contains("build") {
        SourceRole::Build
    } else {
        SourceRole::Development
    }
}

fn relative_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn structural_evidence(snapshot: &ProjectSnapshot) -> Result<Vec<Evidence>> {
    let mut evidence = Vec::new();
    for unit in &snapshot.units {
        for declaration in &unit.declarations {
            evidence.push(manifest_evidence(
                unit.id.clone(),
                declaration.component.clone(),
                unit.manifest.clone(),
                declaration.section,
            )?);
        }
    }
    let lockfile = match snapshot.units.first().map(|unit| unit.ecosystem) {
        Some(Ecosystem::Cargo) => PathBuf::from("Cargo.lock"),
        Some(Ecosystem::Npm) if snapshot.root.join("pnpm-lock.yaml").is_file() => {
            PathBuf::from("pnpm-lock.yaml")
        }
        Some(Ecosystem::Npm) if snapshot.root.join("yarn.lock").is_file() => {
            PathBuf::from("yarn.lock")
        }
        _ => PathBuf::from("package-lock.json"),
    };
    evidence.extend(transitive_evidence(&snapshot.dependency_edges, lockfile)?);
    Ok(evidence)
}

#[derive(Deserialize, Default)]
struct ScriptManifest {
    #[serde(default)]
    scripts: HashMap<String, String>,
}

/// Create exact declaration evidence inside an ecosystem adapter.
pub(crate) fn manifest_evidence(
    owner: crate::model::ProjectUnitId,
    subject: ComponentId,
    path: PathBuf,
    section: ManifestSection,
) -> Result<Evidence> {
    let role = match section {
        ManifestSection::DevDependencies => SourceRole::Development,
        ManifestSection::BuildDependencies => SourceRole::Build,
        _ => SourceRole::Unknown,
    };
    Evidence::new_for_unit(
        owner,
        subject,
        EvidenceKind::ManifestDeclaration { section },
        EvidenceOrigin {
            path,
            span: None,
            description: Some(format!("declared in {section:?}")),
        },
        role,
        Confidence::High,
        EvidenceResolution::Exact,
    )
}

/// Create presence evidence for every unique normalized dependency edge.
pub(crate) fn transitive_evidence(
    edges: &[DependencyEdge],
    lockfile: PathBuf,
) -> Result<Vec<Evidence>> {
    edges
        .iter()
        .map(|edge| {
            Evidence::new(
                edge.to.clone(),
                EvidenceKind::TransitiveDependency {
                    from: edge.from.clone(),
                    dependency_kind: edge.kind,
                },
                EvidenceOrigin {
                    path: lockfile.clone(),
                    span: None,
                    description: Some(format!("required by {}", edge.from.qualified_name())),
                },
                SourceRole::Unknown,
                Confidence::High,
                EvidenceResolution::Exact,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{assess_usage, UsageState};
    use crate::ecosystem::{CargoAdapter, EcosystemAdapter, NpmAdapter};
    use crate::model::{Component, Ecosystem};

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/npm-evidence")
    }

    fn cargo_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-normalized")
    }

    fn cargo_workspace_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-workspace")
    }

    fn npm_workspace_context_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/npm-workspace-context")
    }

    fn collected() -> EvidenceCollection {
        let snapshot = NpmAdapter.build_snapshot(&fixture()).unwrap();
        collect_project_evidence(snapshot).unwrap()
    }

    fn has(name: &str, predicate: impl Fn(&Evidence) -> bool) -> bool {
        collected()
            .snapshot
            .evidence
            .iter()
            .any(|evidence| evidence.subject.name == name && predicate(evidence))
    }

    #[test]
    fn source_imports_preserve_kind_role_subpaths_and_spans() {
        assert!(has("lodash", |evidence| {
            evidence.kind == EvidenceKind::StaticImport
                && evidence.role == SourceRole::Runtime
                && evidence.origin.span.is_some()
        }));
        assert!(has("@scope/pkg", |evidence| {
            evidence.kind == EvidenceKind::StaticImport
                && evidence
                    .origin
                    .description
                    .as_deref()
                    .is_some_and(|description| description.contains("@scope/pkg/subpath"))
        }));
        assert!(has("cjs-pkg", |evidence| {
            evidence.kind == EvidenceKind::CommonJsRequire
        }));
        assert!(has("dynamic-pkg", |evidence| {
            evidence.kind == EvidenceKind::DynamicImport
        }));
        assert!(has("export-pkg", |evidence| {
            evidence.kind == EvidenceKind::ReExport
        }));
        assert!(has("vite", |evidence| {
            evidence.kind == EvidenceKind::ConfigurationReference
                && evidence.role == SourceRole::Configuration
        }));
        assert!(has("vitest", |evidence| {
            evidence.kind == EvidenceKind::StaticImport && evidence.role == SourceRole::Test
        }));
    }

    #[test]
    fn workspace_imports_resolve_within_their_exact_unit_context() {
        let snapshot = NpmAdapter
            .build_snapshot(&npm_workspace_context_fixture())
            .unwrap();
        let collection = collect_project_evidence(snapshot).unwrap();
        let shared: Vec<_> = collection
            .snapshot
            .evidence
            .iter()
            .filter(|evidence| {
                evidence.subject.name == "shared" && evidence.kind == EvidenceKind::StaticImport
            })
            .collect();
        assert_eq!(shared.len(), 2);
        assert!(shared
            .iter()
            .all(|evidence| evidence.resolution == EvidenceResolution::Exact));
        for evidence in shared {
            let owner = collection
                .snapshot
                .unit(evidence.owner.as_ref().unwrap())
                .unwrap();
            let expected_location = format!(
                "{}/node_modules/shared",
                owner.root.to_string_lossy().replace('\\', "/")
            );
            assert_eq!(
                evidence.subject.location.as_deref(),
                Some(expected_location.as_str())
            );
        }
    }

    #[test]
    fn unrelated_nested_javascript_projects_are_not_scanned() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/npm-workspace");
        let collection =
            collect_project_evidence(NpmAdapter.build_snapshot(&root).unwrap()).unwrap();
        assert!(collection
            .snapshot
            .evidence
            .iter()
            .all(|evidence| { !evidence.origin.path.starts_with("unrelated") }));
    }

    #[test]
    fn package_scripts_create_role_aware_evidence_for_wrappers_and_chains() {
        let collection = collected();
        for name in ["vite", "vitest", "typescript", "@biomejs/biome"] {
            assert!(collection.snapshot.evidence.iter().any(|evidence| {
                evidence.subject.name == name
                    && matches!(evidence.kind, EvidenceKind::PackageScript { .. })
            }));
        }
        assert!(collection.snapshot.evidence.iter().any(|evidence| {
            evidence.subject.name == "@scope/pkg"
                && matches!(
                    evidence.kind,
                    EvidenceKind::PackageScript { ref script } if script == "scope"
                )
        }));
        assert!(collection.snapshot.evidence.iter().any(|evidence| {
            evidence.subject.name == "vite"
                && matches!(
                    evidence.kind,
                    EvidenceKind::PackageScript { ref script } if script == "build"
                )
                && evidence.role == SourceRole::Build
        }));
    }

    #[test]
    fn manifest_and_transitive_evidence_are_present_but_do_not_imply_direct_usage() {
        let collection = collected();
        assert!(has("no-evidence", |evidence| {
            matches!(evidence.kind, EvidenceKind::ManifestDeclaration { .. })
        }));
        assert!(has("tiny-helper", |evidence| {
            matches!(evidence.kind, EvidenceKind::TransitiveDependency { .. })
        }));
        let assessments = assess_usage(&collection.snapshot).unwrap();
        assert_eq!(
            assessments
                .iter()
                .find(|assessment| assessment.component.name == "no-evidence")
                .unwrap()
                .state,
            UsageState::NoEvidence
        );
        assert_eq!(
            assessments
                .iter()
                .find(|assessment| assessment.component.name == "tiny-helper")
                .unwrap()
                .state,
            UsageState::TransitivelyRequired
        );
    }

    #[test]
    fn ambiguous_imports_never_become_exact_usage() {
        let component = |location: &str| Component {
            id: ComponentId {
                ecosystem: Ecosystem::Npm,
                name: "shared".to_string(),
                version: "1.0.0".to_string(),
                location: Some(location.to_string()),
            },
            direct: true,
            dev: false,
            deprecated: None,
        };
        let snapshot = ProjectSnapshot::new(
            PathBuf::from("."),
            vec![
                component("node_modules/shared"),
                component("vendor/node_modules/shared"),
            ],
            Vec::new(),
        );
        let import = Import {
            file_path: PathBuf::from("src/index.ts"),
            kind: ImportKind::EsModule,
            resolved_package: Some("shared".to_string()),
            specifier: "shared".to_string(),
            span: None,
        };
        let (evidence, unresolved) = collect_source(&snapshot, [&import].into_iter()).unwrap();
        assert!(!unresolved);
        assert_eq!(evidence.len(), 2);
        assert!(evidence.iter().all(|item| matches!(
            item.resolution,
            EvidenceResolution::Ambiguous { ref candidates } if candidates.len() == 2
        )));
        let enriched = snapshot.with_evidence(evidence).unwrap();
        assert!(assess_usage(&enriched)
            .unwrap()
            .iter()
            .all(|assessment| assessment.state == UsageState::Ambiguous));
    }

    #[test]
    fn evidence_and_assessments_are_deterministic() {
        let first = collected();
        let second = collected();
        assert_eq!(
            serde_json::to_string(&first.snapshot.evidence).unwrap(),
            serde_json::to_string(&second.snapshot.evidence).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&assess_usage(&first.snapshot).unwrap()).unwrap(),
            serde_json::to_string(&assess_usage(&second.snapshot).unwrap()).unwrap()
        );
    }

    #[test]
    fn rust_crate_references_are_role_aware_usage_evidence() {
        let snapshot = CargoAdapter.build_snapshot(&cargo_fixture()).unwrap();
        let collection = collect_project_evidence(snapshot).unwrap();
        assert!(collection
            .coverage
            .checked
            .contains(&CoverageArea::RustCrateReferences));
        assert!(collection.snapshot.evidence.iter().any(|evidence| {
            evidence.subject.name == "foo"
                && evidence.kind == EvidenceKind::RustCrateReference
                && evidence.role == SourceRole::Runtime
                && evidence.origin.span.is_some()
        }));
        assert!(collection.snapshot.evidence.iter().any(|evidence| {
            evidence.subject.name == "test-helper"
                && evidence.kind == EvidenceKind::RustCrateReference
                && evidence.role == SourceRole::Test
        }));

        let assessments = assess_usage(&collection.snapshot).unwrap();
        assert_eq!(
            assessments
                .iter()
                .find(|assessment| assessment.component.name == "foo"
                    && assessment.component.version == "2.0.0")
                .unwrap()
                .state,
            UsageState::ConfirmedRuntime
        );
        assert_eq!(
            assessments
                .iter()
                .find(|assessment| assessment.component.name == "test-helper")
                .unwrap()
                .state,
            UsageState::ConfirmedTest
        );
    }

    #[test]
    fn rust_workspace_source_references_resolve_member_aliases() {
        let snapshot = CargoAdapter
            .build_snapshot(&cargo_workspace_fixture())
            .unwrap();
        let collection = collect_project_evidence(snapshot).unwrap();
        assert!(collection.snapshot.evidence.iter().any(|evidence| {
            evidence.subject.name == "anyhow"
                && evidence.kind == EvidenceKind::RustCrateReference
                && evidence.origin.path == Path::new("crates/app/src/lib.rs")
        }));
        assert!(collection.snapshot.evidence.iter().any(|evidence| {
            evidence.subject.name == "pretty_assertions"
                && evidence.kind == EvidenceKind::RustCrateReference
                && evidence.role == SourceRole::Test
        }));
        assert!(collection.snapshot.evidence.iter().any(|evidence| {
            evidence.subject.name == "yansi"
                && evidence.kind == EvidenceKind::RustCrateReference
                && evidence.origin.path == Path::new("internal/shared/src/lib.rs")
        }));
        assert!(!collection.snapshot.evidence.iter().any(|evidence| {
            evidence.kind == EvidenceKind::RustCrateReference
                && evidence.origin.path.starts_with("nested-fixture")
        }));
        assert!(!collection
            .coverage
            .not_checked
            .contains(&CoverageLimitation::UnresolvedPackageReferences));
    }
}
