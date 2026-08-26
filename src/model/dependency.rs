use serde::{Deserialize, Serialize};

use super::ComponentId;

/// The role played by a resolved dependency relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyKind {
    /// Required during normal execution.
    Runtime,
    /// Required for development or tests.
    Development,
    /// Activated only when its declaring optional dependency is enabled.
    Optional,
    /// Required while building the component.
    Build,
    /// The ecosystem evidence cannot reliably classify the relationship.
    Unknown,
}

/// A resolved, typed relationship between two components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// Component declaring the dependency.
    pub from: ComponentId,
    /// Exact resolved dependency component.
    pub to: ComponentId,
    /// Evidence-backed dependency category.
    pub kind: DependencyKind,
}
