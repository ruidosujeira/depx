use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};

use crate::analysis::{CoverageArea, CoverageLimitation};
use crate::evidence::{Confidence, EvidenceId};
use crate::model::ComponentId;

/// Finding schema used when deriving stable IDs.
pub const FINDING_SCHEMA_VERSION: u32 = 1;

/// Stable identity for a derived finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FindingId(String);

impl FindingId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable public code identifying one finding rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RuleCode(String);

impl RuleCode {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// User-facing importance, independent from confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

/// Structured action a user may consider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationAction {
    Review,
    RemoveDeclaration,
    InspectResolution,
    ConsolidateVersions,
    UpdateDependency,
    NoAction,
}

/// Action and its contextual explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    pub action: RecommendationAction,
    pub message: String,
}

/// Classification of an inventory duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateKind {
    RepeatedInstallation,
    SameMajorVersions,
    MultipleMajorVersions,
}

/// Rule-specific structured facts supporting a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingDetails {
    NoUsageEvidence {
        checked: Vec<CoverageArea>,
        limitations: Vec<CoverageLimitation>,
    },
    AmbiguousResolution {
        candidates: Vec<ComponentId>,
    },
    DuplicateVersions {
        kind: DuplicateKind,
        components: Vec<ComponentId>,
    },
    PotentiallyRedundantDeclaration {
        path: Vec<ComponentId>,
    },
    ConfigurationOnly,
}

/// Stable, explainable result produced by one finding rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub rule: RuleCode,
    pub severity: FindingSeverity,
    pub confidence: Confidence,
    pub subject: ComponentId,
    pub summary: String,
    pub explanation: String,
    pub evidence: Vec<EvidenceId>,
    pub recommendation: Option<Recommendation>,
    pub details: FindingDetails,
}

#[derive(Serialize)]
struct FindingIdentity<'a> {
    schema_version: u32,
    rule: &'a RuleCode,
    subject: &'a ComponentId,
    evidence: &'a [EvidenceId],
    details: &'a FindingDetails,
}

impl Finding {
    /// Build an ID stable across identical snapshots for finding schema v1.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule: RuleCode,
        severity: FindingSeverity,
        confidence: Confidence,
        subject: ComponentId,
        summary: String,
        explanation: String,
        mut evidence: Vec<EvidenceId>,
        recommendation: Option<Recommendation>,
        details: FindingDetails,
    ) -> Result<Self> {
        evidence.sort();
        evidence.dedup();
        let bytes = serde_json::to_vec(&FindingIdentity {
            schema_version: FINDING_SCHEMA_VERSION,
            rule: &rule,
            subject: &subject,
            evidence: &evidence,
            details: &details,
        })
        .into_diagnostic()?;
        let id = FindingId(format!("fd-{:016x}", fnv1a(&bytes)));
        Ok(Self {
            id,
            rule,
            severity,
            confidence,
            subject,
            summary,
            explanation,
            evidence,
            recommendation,
            details,
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
