mod analyzer;
mod duplicates;
mod graph;
mod lockfile;
mod reporter;
mod types;
mod vulnerability;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use miette::Result;

use crate::analyzer::ImportAnalyzer;
use crate::graph::DependencyGraph;
use crate::lockfile::LockfileParser;
use crate::reporter::Reporter;

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

        /// Include dev dependencies in analysis
        #[arg(long, default_value = "true")]
        include_dev: bool,
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
            include_dev,
        } => {
            run_analyze(&path, unused, include_dev).await?;
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

async fn run_analyze(path: &PathBuf, show_unused_only: bool, include_dev: bool) -> Result<()> {
    let reporter = Reporter::new();

    reporter.status("Analyzing", &format!("project at {}", path.display()));

    // 1. Parse lockfile to get all installed packages
    let lockfile_parser = LockfileParser::new(path)?;
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
    let used_packages = imports.packages_used();
    let analysis = graph.analyze_usage(&used_packages, include_dev);

    // 5. Report results
    if show_unused_only {
        reporter.report_unused(&analysis);
    } else {
        reporter.report_full(&analysis, &imports);
    }

    Ok(())
}

async fn run_why(path: &PathBuf, package: &str) -> Result<()> {
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

async fn run_audit(path: &PathBuf, used_only: bool) -> Result<()> {
    let reporter = Reporter::new();

    reporter.status("Auditing", &format!("project at {}", path.display()));

    let lockfile_parser = LockfileParser::new(path)?;
    let installed_packages = lockfile_parser.parse()?;

    let used_packages = if used_only {
        let analyzer = ImportAnalyzer::new(path);
        let imports = analyzer.analyze()?;
        Some(imports.packages_used())
    } else {
        None
    };

    let vulnerabilities =
        vulnerability::check_vulnerabilities(&installed_packages, used_packages.as_ref()).await?;

    reporter.report_vulnerabilities(&vulnerabilities);

    Ok(())
}

async fn run_deprecated(path: &PathBuf) -> Result<()> {
    let reporter = Reporter::new();

    reporter.status("Checking", "for deprecated packages");

    let lockfile_parser = LockfileParser::new(path)?;
    let installed_packages = lockfile_parser.parse()?;

    let deprecated = vulnerability::check_deprecated(&installed_packages).await?;

    reporter.report_deprecated(&deprecated);

    Ok(())
}

async fn run_duplicates(path: &PathBuf, verbose: bool, json: bool) -> Result<()> {
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
