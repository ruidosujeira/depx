use serde::{Deserialize, Serialize};

/// Project surface successfully inspected during evidence collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageArea {
    ManifestDeclarations,
    DependencyGraph,
    StaticImports,
    CommonJsRequires,
    DynamicImports,
    ReExports,
    RustCrateReferences,
    PackageScripts,
    SupportedConfigurationFiles,
    TestFiles,
}

/// Important project behavior outside the supported collectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLimitation {
    ComputedModuleNames,
    FrameworkPluginDiscovery,
    ArbitraryShellEvaluation,
    UnsupportedConfigurationFormats,
    PackageBinaryAliases,
    UnresolvedPackageReferences,
    RustConditionalCompilation,
    RustMacroExpansion,
    GeneratedSourceCode,
}

/// Explicit account of inspected and unsupported analysis surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisCoverage {
    pub checked: Vec<CoverageArea>,
    pub not_checked: Vec<CoverageLimitation>,
}

impl AnalysisCoverage {
    pub fn new(mut checked: Vec<CoverageArea>, mut not_checked: Vec<CoverageLimitation>) -> Self {
        checked.sort();
        checked.dedup();
        not_checked.sort();
        not_checked.dedup();
        Self {
            checked,
            not_checked,
        }
    }
}
