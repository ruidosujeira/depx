use std::fmt;

use serde::{Deserialize, Serialize};

/// A package registry or package manager ecosystem supported by depx.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    /// The npm ecosystem, represented by `package-lock.json`.
    Npm,
    /// The Rust crate ecosystem, represented by `Cargo.lock`.
    Cargo,
}

/// Stable identity for one resolved component installation.
///
/// `location` distinguishes installations with the same name and version. For
/// npm it is the lockfile package path; for Cargo it is the package source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ComponentId {
    /// Package ecosystem that defines the name and version.
    pub ecosystem: Ecosystem,
    /// Registry package name.
    pub name: String,
    /// Exact resolved version from the lockfile.
    pub version: String,
    /// Installation path or package source when needed to disambiguate.
    pub location: Option<String>,
}

impl ComponentId {
    /// Return the familiar package query form used by the CLI.
    pub fn qualified_name(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.qualified_name())?;
        if let Some(location) = &self.location {
            write!(formatter, " ({location})")?;
        }
        Ok(())
    }
}

/// A resolved software component present in a project snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// Normalized identity of this installation.
    pub id: ComponentId,
    /// Whether the project manifest directly declares this component.
    pub direct: bool,
    /// Whether this component belongs to development dependencies.
    pub dev: bool,
    /// Ecosystem-provided deprecation message, when present.
    pub deprecated: Option<String>,
}
