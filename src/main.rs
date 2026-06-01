mod analyzer;
mod duplicates;
mod graph;
mod lockfile;
mod reporter;
mod types;
mod vulnerability;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use miette::Result;

use crate::analyzer::ImportAnalyzer;
use crate::graph::DependencyGraph;
use crate::lockfile::{LockfileParser, LockfileType};
use crate::reporter::Reporter;

/// Map a detected lockfile to its OSV ecosystem identifier.
fn osv_ecosystem(lockfile_type: LockfileType) -> &'static str {
    match lockfile_type {
        LockfileType::Cargo => "crates.io",
        _ => "npm",
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

#[derive(Subcommand)]
enum Commands {
    /// Analyze dependencies in the project
    Analyze {
        /// Path to the project root (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Show only unused dependencies
        #[arg(long)]
        unused: bool,

        /// Exclude dev dependencies from analysis (included by default)
        #[arg(long)]
        no_dev: bool,
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
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            path,
            unused,
            no_dev,
        } => {
            run_analyze(&path, unused, !no_dev).await?;
        }
        Commands::Why { package, path } => {
            run_why(&path, &package).await?;
        }
        Commands::Audit { path, used_only } => {
            run_audit(&path, used_only).await?;
        }
        Commands::Deprecated { path } => {
            run_deprecated(&path).await?;
        }
        Commands::Duplicates {
            path,
            verbose,
            json,
        } => {
            run_duplicates(&path, verbose, json).await?;
        }
    }

    Ok(())
}

async fn run_analyze(path: &Path, show_unused_only: bool, include_dev: bool) -> Result<()> {
    let reporter = Reporter::new();

    reporter.status("Analyzing", &format!("project at {}", path.display()));

    // 1. Parse lockfile to get all installed packages
    let lockfile_parser = LockfileParser::new(path)?;

    // Unused-dependency detection works by scanning JS/TS imports, which is
    // meaningless for Rust crates. Bail early instead of cross-referencing JS
    // imports against Cargo packages (that produces nonsense like flagging the
    // crate itself as removable and suggesting `npm uninstall <crate>`).
    if lockfile_parser.lockfile_type() == LockfileType::Cargo {
        miette::bail!(
            "`analyze` only supports JavaScript/TypeScript projects. \
             For Rust projects, use `depx duplicates` or `depx audit` instead."
        );
    }

    let installed_packages = lockfile_parser.parse()?;

    reporter.info(&format!(
        "Found {} installed packages",
        installed_packages.len()
    ));

    // 2. Analyze source code to find actual imports
    let analyzer = ImportAnalyzer::new(path);
    let imports = analyzer.analyze()?;

    reporter.info(&format!(
        "Found {} import statements across {} files",
        imports.total_imports(),
        imports.files_analyzed()
    ));

    // 3. Build dependency graph
    let graph = DependencyGraph::new(&installed_packages);

    // 4. Cross-reference to find unused packages
    let analysis = graph.analyze_usage(&imports, include_dev);

    // 5. Report results
    if show_unused_only {
        reporter.report_unused(&analysis);
    } else {
        reporter.report_full(&analysis, &imports);
    }

    Ok(())
}

async fn run_why(path: &Path, package: &str) -> Result<()> {
    let reporter = Reporter::new();

    let lockfile_parser = LockfileParser::new(path)?;
    let installed_packages = lockfile_parser.parse()?;

    let graph = DependencyGraph::new(&installed_packages);

    match graph.explain_package(package) {
        Some(explanation) => reporter.report_why(package, &explanation),
        None => reporter.error(&format!("Package '{}' not found in dependencies", package)),
    }

    Ok(())
}

async fn run_audit(path: &Path, used_only: bool) -> Result<()> {
    let reporter = Reporter::new();

    reporter.status("Auditing", &format!("project at {}", path.display()));

    let lockfile_parser = LockfileParser::new(path)?;
    let ecosystem = osv_ecosystem(lockfile_parser.lockfile_type());
    let installed_packages = lockfile_parser.parse()?;

    let used_packages = if used_only {
        let analyzer = ImportAnalyzer::new(path);
        let imports = analyzer.analyze()?;
        Some(imports.packages_used())
    } else {
        None
    };

    let mut vulnerabilities = vulnerability::check_vulnerabilities(
        &installed_packages,
        used_packages.as_ref(),
        ecosystem,
    )
    .await?;

    // `--used-only` should actually narrow the output, not just relabel it.
    if used_only {
        vulnerabilities.retain(|v| v.affects_used_code);
    }

    reporter.report_vulnerabilities(&vulnerabilities, used_only);

    Ok(())
}

async fn run_deprecated(path: &Path) -> Result<()> {
    let reporter = Reporter::new();

    reporter.status("Checking", "for deprecated packages");

    let lockfile_parser = LockfileParser::new(path)?;
    let installed_packages = lockfile_parser.parse()?;

    // Determine which packages are actually reachable from the source code so
    // we can flag deprecated packages that are still in use.
    let analyzer = ImportAnalyzer::new(path);
    let imports = analyzer.analyze()?;
    let graph = DependencyGraph::new(&installed_packages);
    let analysis = graph.analyze_usage(&imports, true);
    let used_set: HashSet<String> = analysis
        .used
        .iter()
        .map(|u| u.package.name.clone())
        .collect();

    let deprecated = vulnerability::check_deprecated(&installed_packages, Some(&used_set)).await?;

    reporter.report_deprecated(&deprecated);

    Ok(())
}

async fn run_duplicates(path: &Path, verbose: bool, json: bool) -> Result<()> {
    let reporter = if verbose {
        Reporter::new().verbose()
    } else {
        Reporter::new()
    };

    reporter.status("Analyzing", &format!("duplicates at {}", path.display()));

    let analyzer = duplicates::DuplicateAnalyzer::new(path);
    let analysis = analyzer.analyze()?;

    if json {
        let output = serde_json::to_string_pretty(&analysis)
            .map_err(|e| miette::miette!("Failed to serialize JSON: {}", e))?;
        println!("{}", output);
    } else {
        reporter.report_duplicates(&analysis);
    }

    Ok(())
}
