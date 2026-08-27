use std::path::{Component as PathComponent, Path, PathBuf};

use miette::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::evidence::ManifestSection;

use super::{ComponentId, Ecosystem};

/// Stable identity of one manifest-owned project or workspace member.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProjectUnitId(String);

impl ProjectUnitId {
    pub fn from_root(root: &Path) -> Self {
        let value = if root.as_os_str().is_empty() {
            ".".to_string()
        } else {
            root.to_string_lossy().replace('\\', "/")
        };
        Self(format!("unit:{value}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A declaration resolved by its owning package-manager adapter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UnitDeclaration {
    /// Source-level dependency name (including Cargo aliases).
    pub name: String,
    /// Exact installed component selected in this unit's resolution context.
    pub component: ComponentId,
    pub section: ManifestSection,
}

/// One independently declared project inside the analyzed repository boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProjectUnit {
    pub id: ProjectUnitId,
    /// Directory relative to the snapshot root. The root unit uses an empty path.
    pub root: PathBuf,
    /// Manifest path relative to the snapshot root.
    pub manifest: PathBuf,
    pub ecosystem: Ecosystem,
    pub declarations: Vec<UnitDeclaration>,
}

impl ProjectUnit {
    pub fn new(
        root: PathBuf,
        manifest: PathBuf,
        ecosystem: Ecosystem,
        mut declarations: Vec<UnitDeclaration>,
    ) -> Self {
        declarations.sort();
        declarations.dedup();
        Self {
            id: ProjectUnitId::from_root(&root),
            root,
            manifest,
            ecosystem,
            declarations,
        }
    }

    pub(crate) fn validate_paths(&self) -> Result<()> {
        validate_relative(&self.root, "project unit root")?;
        validate_relative(&self.manifest, "project unit manifest")?;
        if !self.manifest.starts_with(&self.root) {
            bail!(
                "Project unit {} manifest must be inside its root",
                self.id.as_str()
            );
        }
        if self.id != ProjectUnitId::from_root(&self.root) {
            bail!("Project unit identity does not match its normalized root");
        }
        Ok(())
    }
}

fn validate_relative(path: &Path, label: &str) -> Result<()> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                PathComponent::CurDir
                    | PathComponent::ParentDir
                    | PathComponent::RootDir
                    | PathComponent::Prefix(_)
            )
        })
    {
        bail!("{label} must be a normalized relative path");
    }
    Ok(())
}
