mod classify;
mod collector;
mod model;
mod scripts;

pub use classify::classify_source_role;
pub use collector::collect_project_evidence;
pub use model::{
    Confidence, Evidence, EvidenceId, EvidenceKind, EvidenceOrigin, EvidenceResolution,
    ManifestSection, SourceRole, SourceSpan,
};
