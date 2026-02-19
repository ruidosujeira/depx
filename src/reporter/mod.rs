use colored::Colorize;

use crate::duplicates::suggest_resolution;
use crate::types::{
    DeprecatedPackage, DuplicateAnalysis, DuplicateSeverity, ImportMap, PackageExplanation,
    Severity, UsageAnalysis, Vulnerability,
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

    /// Print an error message
    pub fn error(&self, message: &str) {
        println!("{:>12} {}", "Error".red().bold(), message);
    }

    /// Print a warning message
    pub fn warn(&self, message: &str) {
        println!("{:>12} {}", "Warning".yellow().bold(), message);
    }

    /// Report full analysis results
    pub fn report_full(&self, analysis: &UsageAnalysis, _imports: &ImportMap) {
        println!();
        println!("{}", "Dependency Analysis Report".bold().underline());
        println!();

        // Summary
        println!("{}", "Summary".bold());
        println!(
            "  {} packages used",
            analysis.used.len().to_string().green()
        );
        if !analysis.unused_direct.is_empty() {
            println!(
                "  {} packages unused {}",
                analysis.unused_direct.len().to_string().red(),
                "(removable)".red()
            );
        }
        if !analysis.expected_unused_direct.is_empty() {
            println!(
                "  {} dev/build tools {}",
                analysis.expected_unused_direct.len().to_string().cyan(),
                "(expected, not imported)".dimmed()
            );
        }
        println!();

        // Unused direct dependencies (truly removable)
        if !analysis.unused_direct.is_empty() {
            println!("{}", "Unused Dependencies (safe to remove):".red().bold());
            for pkg in &analysis.unused_direct {
                let dev_marker = if pkg.is_dev { " (dev)" } else { "" };
                println!(
                    "  {} {}{}",
                    "-".red(),
                    format!("{}@{}", pkg.name, pkg.version).white(),
                    dev_marker.dimmed()
                );
            }
            println!();
            println!("  {} {}", "Tip:".dimmed(), "npm uninstall <package>".cyan());
            println!();
        }

        // Expected unused (dev/build tools) - show only if there are truly unused ones or verbose
        if !analysis.expected_unused_direct.is_empty() {
            println!(
                "{}",
                "Dev/Build Tools (not imported, expected):".cyan().bold()
            );
            for pkg in &analysis.expected_unused_direct {
                println!(
                    "  {} {}",
                    "~".cyan(),
                    format!("{}@{}", pkg.name, pkg.version).dimmed()
                );
            }
            println!();
        }

        // Used packages (verbose only)
        if self.verbose && !analysis.used.is_empty() {
            println!("{}", "Used Packages:".green().bold());
            for usage in &analysis.used {
                let pkg = &usage.package;
                let direct_marker = if pkg.is_direct { " (direct)" } else { "" };
                println!(
                    "  {} {}{}",
                    "+".green(),
                    format!("{}@{}", pkg.name, pkg.version).white(),
                    direct_marker.dimmed()
                );
            }
            println!();
        }

        // Unused transitive dependencies (verbose only)
        if self.verbose {
            let unused_transitive: Vec<_> =
                analysis.unused.iter().filter(|p| !p.is_direct).collect();

            if !unused_transitive.is_empty() {
                println!("{}", "Unused Transitive Dependencies:".yellow().bold());
                for pkg in unused_transitive.iter().take(20) {
                    println!(
                        "  {} {}",
                        "?".yellow(),
                        format!("{}@{}", pkg.name, pkg.version).dimmed()
                    );
                }
                if unused_transitive.len() > 20 {
                    println!(
                        "  {} ... and {} more",
                        "".dimmed(),
                        unused_transitive.len() - 20
                    );
                }
                println!();
            }
        }
    }

    /// Report only unused packages
    pub fn report_unused(&self, analysis: &UsageAnalysis) {
        println!();

        if analysis.unused_direct.is_empty() && analysis.unused.is_empty() {
            println!("{}", "All dependencies appear to be in use!".green().bold());
            return;
        }

        println!(
            "{}",
            "Potentially Unused Dependencies"
                .yellow()
                .bold()
                .underline()
        );
        println!();

        if !analysis.unused_direct.is_empty() {
            println!("{}", "Direct dependencies (in package.json):".bold());
            for pkg in &analysis.unused_direct {
                let dev_marker = if pkg.is_dev { " (dev)" } else { "" };
                println!(
                    "  {} {}{}",
                    "-".red(),
                    pkg.name.white(),
                    dev_marker.dimmed()
                );
            }
            println!();
            println!(
                "{}",
                "Tip: Run `npm uninstall <package>` to remove unused packages".dimmed()
            );
        }

        println!();
    }

    /// Report why a package is installed
    pub fn report_why(&self, _package_name: &str, explanation: &PackageExplanation) {
        println!();
        println!(
            "{} {}@{}",
            "Package:".bold(),
            explanation.package.name.cyan(),
            explanation.package.version
        );
        println!();

        if explanation.package.is_direct {
            println!(
                "  {} This is a {} in package.json",
                "->".green(),
                if explanation.package.is_dev {
                    "dev dependency".yellow()
                } else {
                    "direct dependency".green()
                }
            );
        } else {
            println!("{}", "Dependency chains:".bold());

            for (i, chain) in explanation.dependency_chains.iter().enumerate() {
                let chain_str = chain.join(" -> ");

                let prefix = if i == 0 { "->" } else { "  " };
                println!("  {} {}", prefix.green(), chain_str);
            }

            if explanation.dependency_chains.is_empty() {
                println!(
                    "  {} Could not determine dependency chain (might be orphaned)",
                    "?".yellow()
                );
            }
        }

        if explanation.is_dev_path {
            println!();
            println!(
                "  {} This package is only required for development",
                "Note:".dimmed()
            );
        }

        println!();
    }

    /// Report vulnerabilities
    pub fn report_vulnerabilities(&self, vulnerabilities: &[Vulnerability]) {
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
                let used_marker = if vuln.affects_used_code {
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
                dep.package.name.white(),
                dep.package.version,
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

            let transitive_str = if version.transitive_count > 0 {
                format!("({} transitive)", version.transitive_count)
            } else {
                "".to_string()
            };

            println!(
                "      {} {}{}",
                format!("v{}", version.version).white(),
                transitive_str.yellow(),
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
