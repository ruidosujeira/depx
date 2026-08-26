mod analysis;
mod analyzer;
mod duplicates;
mod ecosystem;
mod evidence;
mod finding;
mod graph;
mod model;
mod output;
mod query;
mod reporter;
mod types;
mod vulnerability;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use miette::Result;

use crate::analysis::{assess_usage, used_component_ids};
use crate::evidence::{collect_project_evidence, EvidenceKind, EvidenceResolution};
use crate::finding::analyze_project;
use crate::graph::DependencyGraph;
use crate::model::{Ecosystem, ProjectSnapshot};
use crate::reporter::Reporter;
use crate::types::Severity;

/// Map a detected lockfile to its OSV ecosystem identifier.
fn osv_ecosystem(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Cargo => "crates.io",
        Ecosystem::Npm => "npm",
    }
}

#[derive(Parser)]
#[command(name = "depx")]
#[command(
    author,
    version,
    about = "Intelligent dependency analyzer for JS/TS projects"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum AuditFailOn {
    /// Never fail because vulnerabilities were found
    Never,
    /// Fail when any vulnerability is found
    Any,
    /// Fail on low, medium, high or critical vulnerabilities
    Low,
    /// Fail on medium, high or critical vulnerabilities
    Medium,
    /// Fail on high or critical vulnerabilities
    High,
    /// Fail only on critical vulnerabilities
    Critical,
}

impl AuditFailOn {
    fn matches(self, severity: Severity) -> bool {
        match self {
            Self::Never => false,
            Self::Any | Self::Low => true,
            Self::Medium => severity >= Severity::Medium,
            Self::High => severity >= Severity::High,
            Self::Critical => severity >= Severity::Critical,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze dependencies in the project
    Analyze {
        /// Path to the project root (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Show only components for which supported collectors found no usage evidence
        #[arg(long)]
        unused: bool,

        /// Exclude dev dependencies from analysis (included by default)
        #[arg(long)]
        no_dev: bool,

        /// Emit deterministic machine-readable JSON
        #[arg(long)]
        json: bool,

        /// Show complete finding evidence in text output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Explain why a package is installed
    Why {
        /// Package name to explain
        package: String,

        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Check for known vulnerabilities
    Audit {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Only show vulnerabilities in actually used packages
        #[arg(long)]
        used_only: bool,

        /// Exit with code 1 when a vulnerability meets this severity threshold
        #[arg(long, value_enum, default_value = "high")]
        fail_on: AuditFailOn,
    },

    /// List deprecated packages
    Deprecated {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Detect duplicate dependencies (multiple versions of same crate)
    Duplicates {
        /// Path to the project root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Show detailed information for each duplicate
        #[arg(short, long)]
        verbose: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("{error:?}");
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Analyze {
            path,
            unused,
            no_dev,
            json,
            verbose,
        } => {
            run_analyze(&path, unused, !no_dev, json, verbose).await?;
            ExitCode::SUCCESS
        }
        Commands::Why { package, path } => {
            run_why(&path, &package).await?;
            ExitCode::SUCCESS
        }
        Commands::Audit {
            path,
            used_only,
            fail_on,
        } => {
            if run_audit(&path, used_only, fail_on).await? {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Deprecated { path } => {
            run_deprecated(&path).await?;
            ExitCode::SUCCESS
        }
        Commands::Duplicates {
            path,
            verbose,
            json,
        } => {
            run_duplicates(&path, verbose, json).await?;
            ExitCode::SUCCESS
        }
    };

    Ok(exit_code)
}

async fn run_analyze(
    path: &Path,
    show_unused_only: bool,
    include_dev: bool,
    json: bool,
    verbose: bool,
) -> Result<()> {
    let reporter = if verbose {
        Reporter::new().verbose()
    } else {
        Reporter::new()
    };
    if !json {
        reporter.status("Analyzing", &format!("project at {}", path.display()));
    }

    // 1. Build the normalized component inventory and resolved edge set.
    let adapter = ecosystem::detect(path)?;

    // This phase's source, script and configuration collectors target JS/TS.
    if adapter.ecosystem() == Ecosystem::Cargo {
        miette::bail!(
            "`analyze` only supports JavaScript/TypeScript projects. \
             For Rust projects, use `depx duplicates` or `depx audit` instead."
        );
    }

    let snapshot = adapter.build_snapshot(path)?;
    let snapshot = if include_dev {
        snapshot
    } else {
        without_dev_components(snapshot)?
    };
    let collection = collect_project_evidence(snapshot)?;

    let source_references = collection.source_references;
    let files_analyzed = collection.files_analyzed;
    let analysis = analyze_project(collection.snapshot, collection.coverage)?;
    if json {
        println!("{}", output::serialize_analysis(&analysis)?);
        return Ok(());
    }
    reporter.info(&format!(
        "Found {} installed packages",
        analysis.snapshot.components.len()
    ));
    reporter.info(&format!(
        "Collected {source_references} source references across {files_analyzed} files"
    ));
    reporter.report_findings(&analysis, show_unused_only);
    reporter.report_analysis(
        &analysis.snapshot,
        &analysis.assessments,
        &analysis.coverage,
        show_unused_only,
        include_dev,
    );

    Ok(())
}

async fn run_why(path: &Path, package: &str) -> Result<()> {
    let reporter = Reporter::new();

    let snapshot = ecosystem::detect(path)?.build_snapshot(path)?;
    let collection = collect_project_evidence(snapshot)?;
    let analysis = analyze_project(collection.snapshot, collection.coverage)?;
    let graph = DependencyGraph::from_analysis(&analysis)?;

    match graph.explain_package(package) {
        Ok(explanation) => reporter.report_why(package, &explanation, &analysis.coverage),
        Err(error) => return Err(miette::miette!(error)),
    }

    Ok(())
}

async fn run_audit(path: &Path, used_only: bool, fail_on: AuditFailOn) -> Result<bool> {
    let reporter = Reporter::new();

    reporter.status("Auditing", &format!("project at {}", path.display()));

    let adapter = ecosystem::detect(path)?;
    if used_only && adapter.ecosystem() == Ecosystem::Cargo {
        miette::bail!(
            "`audit --used-only` is unavailable for Rust projects because Rust source usage is not yet collected"
        );
    }
    let osv_ecosystem = osv_ecosystem(adapter.ecosystem());
    let snapshot = adapter.build_snapshot(path)?;

    let used_components = if used_only {
        let collection = collect_project_evidence(snapshot.clone())?;
        let assessments = assess_usage(&collection.snapshot)?;
        Some(used_component_ids(&collection.snapshot, &assessments)?)
    } else {
        None
    };

    let mut vulnerabilities = vulnerability::check_vulnerabilities(
        &snapshot.components,
        used_components.as_ref(),
        osv_ecosystem,
    )
    .await?;

    // `--used-only` should actually narrow the output, not just relabel it.
    if used_only {
        vulnerabilities.retain(|v| v.affects_used_code);
    }

    reporter.report_vulnerabilities(&vulnerabilities, used_only);

    Ok(vulnerabilities
        .iter()
        .any(|vulnerability| fail_on.matches(vulnerability.severity)))
}

async fn run_deprecated(path: &Path) -> Result<()> {
    let reporter = Reporter::new();

    reporter.status("Checking", "for deprecated packages");

    let snapshot = ecosystem::detect(path)?.build_snapshot(path)?;
    let collection = collect_project_evidence(snapshot)?;

    let assessments = assess_usage(&collection.snapshot)?;
    let used_set = used_component_ids(&collection.snapshot, &assessments)?;

    let deprecated =
        vulnerability::check_deprecated(&collection.snapshot.components, Some(&used_set)).await?;

    reporter.report_deprecated(&deprecated);

    Ok(())
}

async fn run_duplicates(path: &Path, verbose: bool, json: bool) -> Result<()> {
    let reporter = if verbose {
        Reporter::new().verbose()
    } else {
        Reporter::new()
    };

    if !json {
        reporter.status("Analyzing", &format!("duplicates at {}", path.display()));
    }

    let analyzer = duplicates::DuplicateAnalyzer::new(path);
    let analysis = analyzer.analyze()?;

    if json {
        let output = serde_json::to_string_pretty(&analysis)
            .map_err(|e| miette::miette!("Failed to serialize JSON: {}", e))?;
        println!("{}", output);
    } else {
        reporter.report_duplicates(&analysis);
    }

    // Exit non-zero on high-severity duplicates (3+ versions of a crate) so the
    // command can gate a CI step. Lower severities are informational and keep a
    // zero exit. Flush first since `exit` skips stdout's buffer teardown.
    if analysis.stats.high_severity > 0 {
        use std::io::Write;
        std::io::stdout().flush().ok();
        std::process::exit(1);
    }

    Ok(())
}

fn without_dev_components(snapshot: ProjectSnapshot) -> Result<ProjectSnapshot> {
    let retained: HashSet<_> = snapshot
        .components
        .iter()
        .filter(|component| !component.dev)
        .map(|component| component.id.clone())
        .collect();
    let components = snapshot
        .components
        .into_iter()
        .filter(|component| retained.contains(&component.id))
        .collect();
    let dependency_edges = snapshot
        .dependency_edges
        .into_iter()
        .filter(|edge| retained.contains(&edge.from) && retained.contains(&edge.to))
        .collect();
    let evidence = snapshot
        .evidence
        .into_iter()
        .filter(|item| retained.contains(&item.subject))
        .filter(|item| match &item.kind {
            EvidenceKind::TransitiveDependency { from, .. } => retained.contains(from),
            _ => true,
        })
        .filter(|item| match &item.resolution {
            EvidenceResolution::Exact => true,
            EvidenceResolution::Ambiguous { candidates } => candidates
                .iter()
                .all(|candidate| retained.contains(candidate)),
        })
        .collect();
    ProjectSnapshot::new(snapshot.root, components, dependency_edges).with_evidence(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_fail_on(args: &[&str]) -> AuditFailOn {
        let cli = Cli::try_parse_from(args).expect("audit arguments should parse");
        match cli.command {
            Commands::Audit { fail_on, .. } => fail_on,
            _ => panic!("expected audit command"),
        }
    }

    #[test]
    fn audit_defaults_to_high_severity_threshold() {
        assert_eq!(audit_fail_on(&["depx", "audit"]), AuditFailOn::High);
    }

    #[test]
    fn audit_accepts_all_fail_on_values() {
        for value in ["never", "any", "low", "medium", "high", "critical"] {
            let args = ["depx", "audit", "--fail-on", value];
            let _ = audit_fail_on(&args);
        }
    }

    #[test]
    fn audit_fail_on_thresholds_match_expected_severities() {
        assert!(!AuditFailOn::Never.matches(Severity::Critical));
        assert!(AuditFailOn::Any.matches(Severity::Low));
        assert!(AuditFailOn::Low.matches(Severity::Low));
        assert!(!AuditFailOn::Medium.matches(Severity::Low));
        assert!(AuditFailOn::Medium.matches(Severity::Medium));
        assert!(!AuditFailOn::High.matches(Severity::Medium));
        assert!(AuditFailOn::High.matches(Severity::High));
        assert!(AuditFailOn::High.matches(Severity::Critical));
        assert!(!AuditFailOn::Critical.matches(Severity::High));
        assert!(AuditFailOn::Critical.matches(Severity::Critical));
    }
}
