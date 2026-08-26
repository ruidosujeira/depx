use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::analysis::UsageAssessment;
use crate::evidence::Evidence;
use crate::evidence::SourceSpan;
use crate::finding::Finding;
use crate::model::{Component, ComponentId};

/// Represents an import statement found in source code
#[derive(Debug, Clone)]
pub struct Import {
    /// The source file containing the import
    pub file_path: PathBuf,

    /// The kind of import. Retained for classification and verified by the
    /// extractor tests, though the analyzer itself only keys off the package.
    #[allow(dead_code)]
    pub kind: ImportKind,

    /// Normalized package root name, not yet resolved to a component identity.
    pub resolved_package: Option<String>,

    /// Original module specifier, including any imported subpath.
    pub specifier: String,

    /// Byte span of the module specifier when supplied by the parser.
    pub span: Option<SourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportKind {
    /// ES6 import statement
    EsModule,
    /// CommonJS require()
    CommonJs,
    /// Dynamic import()
    Dynamic,
    /// Re-export (export ... from ...)
    ReExport,
}

/// Collection of all imports found in a project
#[derive(Debug, Default)]
pub struct ImportMap {
    /// All imports indexed by file path
    imports_by_file: HashMap<PathBuf, Vec<Import>>,

    /// Number of files analyzed
    files_count: usize,
}

impl ImportMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_import(&mut self, import: Import) {
        let file_path = import.file_path.clone();

        self.imports_by_file
            .entry(file_path)
            .or_default()
            .push(import);
    }

    pub fn mark_file_analyzed(&mut self) {
        self.files_count += 1;
    }

    pub fn total_imports(&self) -> usize {
        self.imports_by_file.values().map(|v| v.len()).sum()
    }

    pub fn files_analyzed(&self) -> usize {
        self.files_count
    }

    pub fn imports(&self) -> impl Iterator<Item = &Import> {
        self.imports_by_file.values().flatten()
    }
}

/// Explanation of why a package is in the dependency tree
#[derive(Debug)]
pub struct PackageExplanation {
    /// The package being explained
    pub package: Component,

    /// Chain(s) from root to this package
    /// Each chain retains the full resolved component identity.
    pub dependency_chains: Vec<Vec<ComponentId>>,

    /// Evidence directly attached to this exact component.
    pub evidence: Vec<Evidence>,

    /// Evidence-derived usage assessment.
    pub assessment: UsageAssessment,

    /// Structured findings affecting this exact component.
    pub findings: Vec<Finding>,
}

/// A known vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE or GHSA identifier
    pub id: String,

    /// Human-readable title
    pub title: String,

    /// Severity level
    pub severity: Severity,

    /// Affected package name
    pub package_name: String,

    /// Affected version range
    pub vulnerable_range: String,

    /// Fixed version (if available)
    pub patched_version: Option<String>,

    /// Link to advisory
    pub url: Option<String>,

    /// Whether this vulnerability affects code that is actually used
    pub affects_used_code: bool,

    /// The installed version that is vulnerable
    pub installed_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// A deprecated package
#[derive(Debug)]
pub struct DeprecatedPackage {
    pub package: Component,
    pub message: String,
    pub is_used: bool,
}

// ============================================================================
// Duplicate Analysis Types
// ============================================================================

/// Represents a group of duplicate packages (same crate, different versions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    /// The crate name
    pub name: String,

    /// All versions found in the lockfile
    pub versions: Vec<DuplicateVersion>,

    /// Severity level based on version differences
    pub severity: DuplicateSeverity,
}

/// A specific version of a duplicated crate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateVersion {
    /// The version string
    pub version: String,

    /// Packages that depend on this version
    pub dependents: Vec<String>,

    /// Number of transitive dependents
    pub transitive_count: usize,
}

/// Severity of the duplicate based on version differences
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DuplicateSeverity {
    /// Same major version, different minor/patch (usually fine)
    Low,
    /// Different major versions (potential issues)
    Medium,
    /// 3+ different major versions (likely problematic)
    High,
}

impl std::fmt::Display for DuplicateSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DuplicateSeverity::Low => write!(f, "low"),
            DuplicateSeverity::Medium => write!(f, "medium"),
            DuplicateSeverity::High => write!(f, "high"),
        }
    }
}

/// Result of analyzing duplicate dependencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateAnalysis {
    /// All duplicate groups found
    pub duplicates: Vec<DuplicateGroup>,

    /// Summary statistics
    pub stats: DuplicateStats,
}

/// Statistics about duplicates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateStats {
    /// Total number of crates with duplicates
    pub total_duplicates: usize,

    /// Number of high severity duplicates
    pub high_severity: usize,

    /// Number of medium severity duplicates
    pub medium_severity: usize,

    /// Number of low severity duplicates
    pub low_severity: usize,

    /// Estimated additional compile units
    pub extra_compile_units: usize,
}
