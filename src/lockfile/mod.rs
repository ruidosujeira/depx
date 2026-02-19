mod cargo;
mod npm;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use miette::{bail, Result};

use crate::types::Package;

pub use cargo::{CargoLockfileParser, CargoPackageInfo};
pub use npm::NpmLockfileParser;

/// Unified lockfile parser that auto-detects the lockfile type
pub struct LockfileParser {
    root: PathBuf,
    lockfile_path: PathBuf,
    lockfile_type: LockfileType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileType {
    Npm,
    Pnpm,
    Yarn,
    Cargo,
}

impl LockfileParser {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();

        // Auto-detect lockfile
        let (lockfile_path, lockfile_type) = detect_lockfile(&root)?;

        Ok(Self {
            root,
            lockfile_path,
            lockfile_type,
        })
    }

    /// Parse the lockfile and return all packages
    pub fn parse(&self) -> Result<HashMap<String, Package>> {
        match self.lockfile_type {
            LockfileType::Npm => {
                let parser = NpmLockfileParser::new(&self.root, &self.lockfile_path);
                parser.parse()
            }
            LockfileType::Pnpm => {
                bail!("pnpm lockfile support coming soon")
            }
            LockfileType::Yarn => {
                bail!("yarn lockfile support coming soon")
            }
            LockfileType::Cargo => {
                let parser = CargoLockfileParser::new(&self.lockfile_path);
                parser.parse()
            }
        }
    }

    pub fn lockfile_type(&self) -> LockfileType {
        self.lockfile_type
    }

    pub fn lockfile_path(&self) -> &Path {
        &self.lockfile_path
    }
}

fn detect_lockfile(root: &Path) -> Result<(PathBuf, LockfileType)> {
    // Check for Cargo.lock (Rust projects)
    let cargo_lock = root.join("Cargo.lock");
    if cargo_lock.exists() {
        return Ok((cargo_lock, LockfileType::Cargo));
    }

    // Check for npm
    let npm_lock = root.join("package-lock.json");
    if npm_lock.exists() {
        return Ok((npm_lock, LockfileType::Npm));
    }

    // Check for pnpm
    let pnpm_lock = root.join("pnpm-lock.yaml");
    if pnpm_lock.exists() {
        return Ok((pnpm_lock, LockfileType::Pnpm));
    }

    // Check for yarn
    let yarn_lock = root.join("yarn.lock");
    if yarn_lock.exists() {
        return Ok((yarn_lock, LockfileType::Yarn));
    }

    bail!(
        "No lockfile found in {}. Expected one of: Cargo.lock, package-lock.json, pnpm-lock.yaml, yarn.lock",
        root.display()
    )
}
