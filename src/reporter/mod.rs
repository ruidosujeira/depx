use colored::Colorize;

use crate::analysis::{
    AnalysisCoverage, CoverageArea, CoverageLimitation, UsageAssessment, UsageState,
};
use crate::duplicates::suggest_resolution;
use crate::evidence::{Confidence, Evidence, EvidenceKind, EvidenceResolution, ManifestSection};
use crate::finding::{metadata as finding_metadata, FindingSeverity, ProjectAnalysis};
use crate::model::ProjectSnapshot;
use crate::types::{
    DeprecatedPackage, DuplicateAnalysis, DuplicateSeverity, PackageExplanation, Severity,
    Vulnerability,
};

/// Reporter for formatted terminal output
pub struct Reporter {
    verbose: bool,
}

impl Reporter {
    pub fn new() -> Self {
        Self { verbose: false }
    }

    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Print a status message
    pub fn status(&self, action: &str, message: &str) {
        println!("{:>12} {}", action.green().bold(), message);
    }

    /// Print an info message
    pub fn info(&self, message: &str) {
        println!("{:>12} {}", "Info".cyan().bold(), message);
    }

    /// Render validated structured findings without deriving rule semantics.
    pub fn report_findings(&self, analysis: &ProjectAnalysis, no_evidence_only: bool) {
        println!();
        println!("{}", "Findings".bold().underline());
        println!();
        let findings: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| {
                !no_evidence_only
                    || analysis.assessments.iter().any(|assessment| {
                        assessment.component == finding.subject
                            && assessment.state == UsageState::NoEvidence
                    })
            })
            .collect();
        if findings.is_empty() {
            println!("  {}", "No findings produced by the enabled rules.".green());
            println!();
            return;
        }
        for finding in findings {
            let metadata = finding_metadata(&finding.rule);
            let severity = match finding.severity {
                FindingSeverity::Info => "Info".cyan(),
                FindingSeverity::Warning => "Warning".yellow(),
                FindingSeverity::Error => "Error".red().bold(),
            };
            println!(
                "{} {}  {}",
                severity,
                finding.rule.as_str().bold(),
                finding.subject.qualified_name().cyan()
            );
            println!(
                "  {}",
                metadata.map_or(finding.summary.as_str(), |item| item.name)
            );
            if self.verbose {
                if let Some(metadata) = metadata {
                    println!("  {}", metadata.description.dimmed());
                }
                println!("  {}", finding.explanation.dimmed());
                for evidence in analysis
                    .snapshot
                    .evidence
                    .iter()
                    .filter(|evidence| finding.evidence.binary_search(&evidence.id).is_ok())
                {
                    println!("    evidence: {}", evidence_description(evidence).dimmed());
                }
            }
            if let Some(recommendation) = &finding.recommendation {
                println!("  Recommendation: {}", recommendation.message.dimmed());
            }
            println!();
        }
    }

    /// Render evidence-backed assessments without deriving semantics here.
    pub fn report_analysis(
        &self,
        snapshot: &ProjectSnapshot,
        assessments: &[UsageAssessment],
        coverage: &AnalysisCoverage,
        no_evidence_only: bool,
        include_dev: bool,
    ) {
        println!();
        println!("{}", "Dependency Evidence Report".bold().underline());
        println!();
        let groups = [
            (UsageState::ConfirmedRuntime, "Confirmed runtime usage"),
            (
                UsageState::ConfirmedDevelopment,
                "Confirmed development usage",
            ),
            (UsageState::ConfirmedBuild, "Confirmed build usage"),
            (UsageState::ConfirmedTest, "Confirmed test usage"),
            (UsageState::ConfigurationOnly, "Configuration references"),
            (UsageState::TransitivelyRequired, "Transitive presence"),
            (UsageState::Ambiguous, "Ambiguous evidence"),
            (UsageState::NoEvidence, "No evidence found"),
        ];
        for (state, title) in groups {
            if no_evidence_only && state != UsageState::NoEvidence {
                continue;
            }
            let items: Vec<_> = assessments
                .iter()
                .filter(|assessment| assessment.state == state)
                .filter(|assessment| {
                    include_dev
                        || snapshot
                            .components
                            .iter()
                            .find(|component| component.id == assessment.component)
                            .is_none_or(|component| !component.dev)
                })
                .collect();
            if items.is_empty() {
                continue;
            }
            println!("{}", title.bold());
            for assessment in items {
                println!("  {}", assessment.component.qualified_name().cyan());
                for evidence in evidence_for(snapshot, assessment)
                    .into_iter()
                    .filter(|evidence| evidence_relevant_to_state(evidence, state))
                {
                    println!("    {}", evidence_description(evidence).dimmed());
                }
                if state == UsageState::NoEvidence {
                    println!("    no supported source, script or configuration references found");
                    println!(
                        "    review unsupported runtime loading and configuration before removal"
                    );
                }
            }
            println!();
        }
        report_coverage(coverage);
    }

    /// Report why a package is installed
    pub fn report_why(
        &self,
        _package_name: &str,
        explanation: &PackageExplanation,
        coverage: &AnalysisCoverage,
    ) {
        println!();
        println!("{}", explanation.package.id.qualified_name().cyan().bold());
        println!();
        println!("{}", "Presence".bold());
        for evidence in explanation.evidence.iter().filter(|evidence| {
            matches!(
                evidence.kind,
                EvidenceKind::ManifestDeclaration { .. }
                    | EvidenceKind::TransitiveDependency { .. }
            )
        }) {
            println!("  {}", evidence_description(evidence));
        }
        for chain in &explanation.dependency_chains {
            if chain.len() > 1 {
                println!(
                    "  dependency chain: {}",
                    chain
                        .iter()
                        .map(|id| id.qualified_name())
                        .collect::<Vec<_>>()
                        .join(" -> ")
                );
            }
        }
        println!();
        println!("{}", "Evidence".bold());
        let usage_evidence: Vec<_> = explanation
            .evidence
            .iter()
            .filter(|evidence| {
                !matches!(
                    evidence.kind,
                    EvidenceKind::ManifestDeclaration { .. }
                        | EvidenceKind::TransitiveDependency { .. }
                )
            })
            .collect();
        if usage_evidence.is_empty() {
            println!("  no supported usage evidence found");
        } else {
            for evidence in usage_evidence {
                println!("  {}", evidence_description(evidence));
            }
        }
        println!();
        println!("{}", "Assessment".bold());
        println!("  {}", usage_state_label(explanation.assessment.state));
        println!(
            "  confidence: {}",
            confidence_label(explanation.assessment.confidence)
        );
        println!();
        if !explanation.findings.is_empty() {
            println!("{}", "Findings".bold());
            for finding in &explanation.findings {
                println!("  {}  {}", finding.rule.as_str(), finding.summary);
            }
            println!();
        }
        report_coverage(coverage);
    }

    /// Report vulnerabilities
    #[allow(clippy::type_complexity)]
    pub fn report_vulnerabilities(&self, vulnerabilities: &[Vulnerability], usage_analyzed: bool) {
        println!();

        if vulnerabilities.is_empty() {
            println!("{}", "No known vulnerabilities found!".green().bold());
            return;
        }

        println!(
            "{} {} found",
            vulnerabilities.len().to_string().red().bold(),
            if vulnerabilities.len() == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            }
        );
        println!();

        // Group by severity
        let critical: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .collect();
        let high: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::High)
            .collect();
        let medium: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Medium)
            .collect();
        let low: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Low)
            .collect();

        let severity_groups: Vec<(&str, Vec<_>, fn(&str) -> String)> = vec![
            ("CRITICAL", critical, |s: &str| s.red().bold().to_string()),
            ("HIGH", high, |s: &str| s.red().to_string()),
            ("MEDIUM", medium, |s: &str| s.yellow().to_string()),
            ("LOW", low, |s: &str| s.dimmed().to_string()),
        ];

        for (severity_name, vulns, color_fn) in severity_groups {
            if vulns.is_empty() {
                continue;
            }

            println!("{}", color_fn(severity_name));
            for vuln in vulns {
                // Only annotate usage when an import scan actually ran; without
                // it every vuln would be labelled "[USED]" without checking.
                let used_marker = if !usage_analyzed {
                    String::new()
                } else if vuln.affects_used_code {
                    " [USED]".red().bold().to_string()
                } else {
                    " [unused]".dimmed().to_string()
                };

                println!(
                    "  {} {}@{} - {}{}",
                    vuln.id.white(),
                    vuln.package_name.cyan(),
                    vuln.installed_version.yellow(),
                    vuln.title.dimmed(),
                    used_marker
                );

                if let Some(ref patched) = vuln.patched_version {
                    println!(
                        "       {} {} -> {}",
                        "Fix:".dimmed(),
                        vuln.installed_version.red(),
                        patched.green()
                    );
                }
            }
            println!();
        }
    }

    /// Report deprecated packages
    pub fn report_deprecated(&self, deprecated: &[DeprecatedPackage]) {
        println!();

        if deprecated.is_empty() {
            println!("{}", "No deprecated packages found!".green().bold());
            return;
        }

        println!(
            "{} {} found",
            deprecated.len().to_string().yellow().bold(),
            if deprecated.len() == 1 {
                "deprecated package"
            } else {
                "deprecated packages"
            }
        );
        println!();

        for dep in deprecated {
            let used_marker = if dep.is_used {
                " [USED]".red().bold().to_string()
            } else {
                " [unused]".dimmed().to_string()
            };

            println!(
                "  {} {}@{}{}",
                "-".yellow(),
                dep.package.id.name.white(),
                dep.package.id.version,
                used_marker
            );
            println!("    {}", dep.message.dimmed());
        }

        println!();
    }

    /// Report duplicate dependencies
    pub fn report_duplicates(&self, analysis: &DuplicateAnalysis) {
        println!();

        if analysis.duplicates.is_empty() {
            println!("{}", "No duplicate dependencies found!".green().bold());
            return;
        }

        println!("{}", "Duplicate Dependencies Analysis".bold().underline());
        println!();

        // Summary
        let stats = &analysis.stats;
        println!("{}", "Summary".bold());
        println!(
            "  {} crates with multiple versions",
            stats.total_duplicates.to_string().yellow()
        );
        if stats.high_severity > 0 {
            println!(
                "  {} {}",
                stats.high_severity.to_string().red().bold(),
                "high severity (3+ versions)".red()
            );
        }
        if stats.medium_severity > 0 {
            println!(
                "  {} {}",
                stats.medium_severity.to_string().yellow(),
                "medium severity (different major versions)".yellow()
            );
        }
        if stats.low_severity > 0 {
            println!(
                "  {} {}",
                stats.low_severity.to_string().dimmed(),
                "low severity (same major version)".dimmed()
            );
        }
        println!(
            "  {} extra compile units",
            stats.extra_compile_units.to_string().cyan()
        );
        println!();

        // Group by severity
        let high: Vec<_> = analysis
            .duplicates
            .iter()
            .filter(|d| d.severity == DuplicateSeverity::High)
            .collect();
        let medium: Vec<_> = analysis
            .duplicates
            .iter()
            .filter(|d| d.severity == DuplicateSeverity::Medium)
            .collect();
        let low: Vec<_> = analysis
            .duplicates
            .iter()
            .filter(|d| d.severity == DuplicateSeverity::Low)
            .collect();

        // High severity
        if !high.is_empty() {
            println!("{}", "HIGH SEVERITY".red().bold());
            for group in high {
                self.print_duplicate_group(group);
            }
            println!();
        }

        // Medium severity
        if !medium.is_empty() {
            println!("{}", "MEDIUM SEVERITY".yellow().bold());
            for group in medium {
                self.print_duplicate_group(group);
            }
            println!();
        }

        // Low severity (only in verbose mode)
        if self.verbose && !low.is_empty() {
            println!("{}", "LOW SEVERITY".dimmed());
            for group in low {
                self.print_duplicate_group(group);
            }
            println!();
        } else if !low.is_empty() {
            println!(
                "  {} {} low severity duplicates (use --verbose to show)",
                "+".dimmed(),
                low.len()
            );
            println!();
        }

        // Tip
        println!(
            "  {} {}",
            "Tip:".dimmed(),
            "Use `cargo tree -d` for detailed dependency tree".cyan()
        );
        println!();
    }

    fn print_duplicate_group(&self, group: &crate::types::DuplicateGroup) {
        let severity_marker = match group.severity {
            DuplicateSeverity::High => "!".red().bold(),
            DuplicateSeverity::Medium => "~".yellow(),
            DuplicateSeverity::Low => "-".dimmed(),
        };

        println!(
            "  {} {} ({} versions)",
            severity_marker,
            group.name.cyan().bold(),
            group.versions.len()
        );

        for version in &group.versions {
            let dependents_str = if version.dependents.is_empty() {
                "(root)".to_string()
            } else if version.dependents.len() <= 3 || self.verbose {
                format!("← {}", version.dependents.join(", "))
            } else {
                format!(
                    "← {} +{} more",
                    version.dependents[..2].join(", "),
                    version.dependents.len() - 2
                )
            };

            println!(
                "      {} {}",
                format!("v{}", version.version).white(),
                dependents_str.dimmed()
            );
        }

        // Show suggestion if available
        if self.verbose {
            if let Some(suggestion) = suggest_resolution(group) {
                println!("      {} {}", "→".green(), suggestion.dimmed());
            }
        }
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::new()
    }
}

fn evidence_for<'a>(
    snapshot: &'a ProjectSnapshot,
    assessment: &UsageAssessment,
) -> Vec<&'a Evidence> {
    snapshot
        .evidence
        .iter()
        .filter(|evidence| assessment.evidence.binary_search(&evidence.id).is_ok())
        .collect()
}

fn evidence_relevant_to_state(evidence: &Evidence, state: UsageState) -> bool {
    match state {
        UsageState::NoEvidence => {
            matches!(evidence.kind, EvidenceKind::ManifestDeclaration { .. })
        }
        UsageState::TransitivelyRequired => {
            matches!(evidence.kind, EvidenceKind::TransitiveDependency { .. })
        }
        _ => !matches!(
            evidence.kind,
            EvidenceKind::ManifestDeclaration { .. } | EvidenceKind::TransitiveDependency { .. }
        ),
    }
}

fn evidence_description(evidence: &Evidence) -> String {
    let base = match &evidence.kind {
        EvidenceKind::ManifestDeclaration { section } => {
            format!(
                "declared in {} {}",
                evidence.origin.path.display(),
                manifest_section_label(*section)
            )
        }
        EvidenceKind::TransitiveDependency { from, .. } => {
            format!("required by {}", from.qualified_name())
        }
        EvidenceKind::StaticImport => source_description(evidence, "static import"),
        EvidenceKind::CommonJsRequire => source_description(evidence, "CommonJS require"),
        EvidenceKind::DynamicImport => source_description(evidence, "dynamic import"),
        EvidenceKind::ReExport => source_description(evidence, "re-export"),
        EvidenceKind::ConfigurationReference => {
            source_description(evidence, "configuration reference")
        }
        EvidenceKind::PackageScript { .. } => evidence
            .origin
            .description
            .clone()
            .unwrap_or_else(|| "referenced by package script".to_string()),
    };
    match &evidence.resolution {
        EvidenceResolution::Exact => base,
        EvidenceResolution::Ambiguous { candidates } => format!(
            "{base} (ambiguous: {})",
            candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn manifest_section_label(section: ManifestSection) -> &'static str {
    match section {
        ManifestSection::Dependencies => "dependencies",
        ManifestSection::DevDependencies => "devDependencies",
        ManifestSection::OptionalDependencies => "optionalDependencies",
        ManifestSection::PeerDependencies => "peerDependencies",
        ManifestSection::BuildDependencies => "build-dependencies",
        ManifestSection::WorkspaceDependencies => "workspace.dependencies",
    }
}

fn source_description(evidence: &Evidence, mechanism: &str) -> String {
    format!(
        "{} {} ({mechanism})",
        evidence.origin.path.display(),
        evidence
            .origin
            .description
            .as_deref()
            .unwrap_or("references package")
    )
}

pub(crate) fn usage_state_label(state: UsageState) -> &'static str {
    match state {
        UsageState::ConfirmedRuntime => "confirmed runtime usage",
        UsageState::ConfirmedDevelopment => "confirmed development usage",
        UsageState::ConfirmedBuild => "confirmed build usage",
        UsageState::ConfirmedTest => "confirmed test usage",
        UsageState::ConfigurationOnly => "configuration-only reference",
        UsageState::TransitivelyRequired => "transitively required for presence",
        UsageState::Ambiguous => "ambiguous component resolution",
        UsageState::NoEvidence => "no usage evidence found",
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

fn report_coverage(coverage: &AnalysisCoverage) {
    println!("{}", "Analysis coverage".bold());
    println!("  Checked:");
    for area in &coverage.checked {
        println!("    - {}", coverage_area_label(*area));
    }
    println!("  Not checked:");
    for limitation in &coverage.not_checked {
        println!("    - {}", limitation_label(*limitation));
    }
    println!();
}

fn coverage_area_label(area: CoverageArea) -> &'static str {
    match area {
        CoverageArea::ManifestDeclarations => "manifest declarations",
        CoverageArea::DependencyGraph => "resolved dependency graph",
        CoverageArea::StaticImports => "static imports",
        CoverageArea::CommonJsRequires => "CommonJS require calls with string literals",
        CoverageArea::DynamicImports => "dynamic imports with string literals",
        CoverageArea::ReExports => "re-exports",
        CoverageArea::PackageScripts => "package.json scripts",
        CoverageArea::SupportedConfigurationFiles => "supported JS/TS configuration files",
        CoverageArea::TestFiles => "conservative JS/TS test-file patterns",
    }
}

fn limitation_label(limitation: CoverageLimitation) -> &'static str {
    match limitation {
        CoverageLimitation::ComputedModuleNames => "computed runtime module names",
        CoverageLimitation::FrameworkPluginDiscovery => "framework plugin auto-discovery",
        CoverageLimitation::ArbitraryShellEvaluation => "arbitrary shell evaluation",
        CoverageLimitation::UnsupportedConfigurationFormats => "unsupported configuration formats",
        CoverageLimitation::PackageBinaryAliases => "unknown package-to-binary aliases",
        CoverageLimitation::UnresolvedPackageReferences => {
            "package references that did not resolve to installed components"
        }
        CoverageLimitation::RustSourceUsage => "Rust source usage",
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    #[test]
    fn no_evidence_never_claims_safe_removal() {
        let label = usage_state_label(UsageState::NoEvidence);
        assert!(!label.contains("safe"));
        assert!(!label.contains("remove"));
    }
}
