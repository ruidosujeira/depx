use std::path::PathBuf;

use miette::{bail, IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};

use crate::model::{ComponentId, DependencyKind, ProjectUnitId};

/// Stable, content-derived identity for one evidence item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EvidenceId(String);

impl EvidenceId {
    /// Borrow the stable textual identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Confidence in the resolution and interpretation of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Semantic role of a project surface containing evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRole {
    Runtime,
    Test,
    Build,
    Development,
    Configuration,
    Unknown,
}

/// Manifest table in which a direct dependency was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ManifestSection {
    Dependencies,
    DevDependencies,
    OptionalDependencies,
    PeerDependencies,
    BuildDependencies,
    WorkspaceDependencies,
}

/// Structured reason why a component participates in the project.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceKind {
    ManifestDeclaration {
        section: ManifestSection,
    },
    StaticImport,
    CommonJsRequire,
    DynamicImport,
    ReExport,
    RustCrateReference,
    PackageScript {
        script: String,
    },
    ConfigurationReference,
    TransitiveDependency {
        from: ComponentId,
        dependency_kind: DependencyKind,
    },
}

/// Byte span within an evidence origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceSpan {
    pub offset: u32,
    pub length: u32,
}

/// Location and optional human context for an evidence item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EvidenceOrigin {
    pub path: PathBuf,
    pub span: Option<SourceSpan>,
    pub description: Option<String>,
}

/// Whether evidence resolved to one component or several explicit candidates.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EvidenceResolution {
    Exact,
    Ambiguous { candidates: Vec<ComponentId> },
}

/// One explainable observation about an exact component.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub subject: ComponentId,
    /// Manifest-owned unit that produced this observation, when applicable.
    pub owner: Option<ProjectUnitId>,
    pub kind: EvidenceKind,
    pub origin: EvidenceOrigin,
    pub role: SourceRole,
    pub confidence: Confidence,
    pub resolution: EvidenceResolution,
}

#[derive(Serialize)]
struct EvidencePayload<'a> {
    subject: &'a ComponentId,
    owner: &'a Option<ProjectUnitId>,
    kind: &'a EvidenceKind,
    origin: &'a EvidenceOrigin,
    role: SourceRole,
    confidence: Confidence,
    resolution: &'a EvidenceResolution,
}

impl Evidence {
    /// Construct evidence with an ID derived deterministically from its payload.
    pub fn new(
        subject: ComponentId,
        kind: EvidenceKind,
        origin: EvidenceOrigin,
        role: SourceRole,
        confidence: Confidence,
        resolution: EvidenceResolution,
    ) -> Result<Self> {
        Self::new_owned(None, subject, kind, origin, role, confidence, resolution)
    }

    /// Construct evidence attributed to an exact project/workspace unit.
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_unit(
        owner: ProjectUnitId,
        subject: ComponentId,
        kind: EvidenceKind,
        origin: EvidenceOrigin,
        role: SourceRole,
        confidence: Confidence,
        resolution: EvidenceResolution,
    ) -> Result<Self> {
        Self::new_owned(
            Some(owner),
            subject,
            kind,
            origin,
            role,
            confidence,
            resolution,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_owned(
        owner: Option<ProjectUnitId>,
        subject: ComponentId,
        kind: EvidenceKind,
        origin: EvidenceOrigin,
        role: SourceRole,
        confidence: Confidence,
        mut resolution: EvidenceResolution,
    ) -> Result<Self> {
        if let EvidenceResolution::Ambiguous { candidates } = &mut resolution {
            candidates.sort();
            candidates.dedup();
            if candidates.is_empty() {
                bail!("Ambiguous evidence requires at least one candidate");
            }
            if candidates.binary_search(&subject).is_err() {
                bail!("Ambiguous evidence subject must be one of its candidates");
            }
        }
        let bytes = serde_json::to_vec(&EvidencePayload {
            subject: &subject,
            owner: &owner,
            kind: &kind,
            origin: &origin,
            role,
            confidence,
            resolution: &resolution,
        })
        .into_diagnostic()?;
        let id = EvidenceId(format!("ev-{:016x}", fnv1a(&bytes)));
        Ok(Self {
            id,
            subject,
            owner,
            kind,
            origin,
            role,
            confidence,
            resolution,
        })
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
