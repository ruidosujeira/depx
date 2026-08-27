use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use miette::{bail, Context, IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};

use crate::finding::{is_known_code, Finding, FindingSeverity, ProjectAnalysis};

const BASELINE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingFailOn {
    #[default]
    Never,
    Info,
    Warning,
    Error,
}

impl FindingFailOn {
    pub fn matches(self, severity: FindingSeverity) -> bool {
        match self {
            Self::Never => false,
            Self::Info => true,
            Self::Warning => severity >= FindingSeverity::Warning,
            Self::Error => severity >= FindingSeverity::Error,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DepxConfig {
    policy: PolicyConfig,
    ignore: Vec<IgnoreEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyConfig {
    baseline: Option<PathBuf>,
    fail_on: FindingFailOn,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IgnoreEntry {
    package: String,
    rule: Option<String>,
    reason: String,
    expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FindingBaseline {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    findings: Vec<String>,
}

#[derive(Debug, Default)]
pub struct PolicyApplication {
    pub ignored_findings: usize,
    pub baseline_findings: usize,
    pub expired_exceptions: Vec<String>,
}

pub struct Policy {
    root: PathBuf,
    config: DepxConfig,
    baseline: HashSet<String>,
    expired_exceptions: Vec<String>,
}

impl Policy {
    pub fn load(root: &Path, explicit_config: Option<&Path>) -> Result<Self> {
        let config_path = explicit_config
            .map(|path| resolve_path(root, path))
            .or_else(|| {
                root.join("depx.toml")
                    .is_file()
                    .then(|| root.join("depx.toml"))
            });
        let config = if let Some(path) = &config_path {
            let content = fs::read_to_string(path)
                .into_diagnostic()
                .with_context(|| format!("Failed to read depx config {}", path.display()))?;
            toml::from_str(&content)
                .into_diagnostic()
                .with_context(|| format!("Failed to parse depx config {}", path.display()))?
        } else {
            DepxConfig::default()
        };
        validate_config(&config)?;

        let today = utc_date(SystemTime::now())?;
        let expired_exceptions = config
            .ignore
            .iter()
            .filter_map(|entry| {
                entry
                    .expires
                    .as_deref()
                    .and_then(parse_date)
                    .filter(|expires| *expires < today)
                    .map(|_| {
                        format!(
                            "{}{} expired on {}",
                            entry.package,
                            entry
                                .rule
                                .as_ref()
                                .map_or(String::new(), |rule| format!(" ({rule})")),
                            entry.expires.as_deref().unwrap_or_default()
                        )
                    })
            })
            .collect();

        let baseline_path = config
            .policy
            .baseline
            .as_deref()
            .map(|path| resolve_path(root, path))
            .or_else(|| {
                let path = root.join("depx-baseline.json");
                path.is_file().then_some(path)
            });
        let baseline = if let Some(path) = baseline_path {
            read_baseline(&path)?
        } else {
            HashSet::new()
        };

        Ok(Self {
            root: root.to_path_buf(),
            config,
            baseline,
            expired_exceptions,
        })
    }

    pub fn apply(&self, analysis: &mut ProjectAnalysis) -> PolicyApplication {
        let before_ignore = analysis.findings.len();
        analysis
            .findings
            .retain(|finding| !self.is_ignored(finding));
        let ignored_findings = before_ignore - analysis.findings.len();

        let before_baseline = analysis.findings.len();
        analysis
            .findings
            .retain(|finding| !self.baseline.contains(finding.id.as_str()));
        PolicyApplication {
            ignored_findings,
            baseline_findings: before_baseline - analysis.findings.len(),
            expired_exceptions: self.expired_exceptions.clone(),
        }
    }

    pub fn apply_ignores(&self, analysis: &mut ProjectAnalysis) -> usize {
        let before = analysis.findings.len();
        analysis
            .findings
            .retain(|finding| !self.is_ignored(finding));
        before - analysis.findings.len()
    }

    pub fn fail_on(&self, cli_override: Option<FindingFailOn>) -> FindingFailOn {
        cli_override.unwrap_or(self.config.policy.fail_on)
    }

    pub fn should_fail(&self, findings: &[Finding], cli_override: Option<FindingFailOn>) -> bool {
        let threshold = self.fail_on(cli_override);
        findings
            .iter()
            .any(|finding| threshold.matches(finding.severity))
    }

    pub fn write_baseline(&self, analysis: &ProjectAnalysis, output: &Path) -> Result<PathBuf> {
        let output = resolve_path(&self.root, output);
        let mut findings: Vec<_> = analysis
            .findings
            .iter()
            .map(|finding| finding.id.as_str().to_string())
            .collect();
        findings.sort();
        findings.dedup();
        let baseline = FindingBaseline {
            schema_version: BASELINE_SCHEMA_VERSION,
            findings,
        };
        let content = serde_json::to_string_pretty(&baseline)
            .into_diagnostic()
            .wrap_err("Failed to serialize depx baseline")?;
        fs::write(&output, format!("{content}\n"))
            .into_diagnostic()
            .with_context(|| format!("Failed to write baseline {}", output.display()))?;
        Ok(output)
    }

    fn is_ignored(&self, finding: &Finding) -> bool {
        let today = utc_date(SystemTime::now()).ok();
        self.config.ignore.iter().any(|entry| {
            let active = entry
                .expires
                .as_deref()
                .and_then(parse_date)
                .zip(today)
                .is_none_or(|(expires, today)| expires >= today);
            active
                && (entry.package == finding.subject.name
                    || entry.package == finding.subject.qualified_name())
                && entry
                    .rule
                    .as_deref()
                    .is_none_or(|rule| rule == finding.rule.as_str())
        })
    }
}

fn validate_config(config: &DepxConfig) -> Result<()> {
    for entry in &config.ignore {
        if entry.package.trim().is_empty() {
            bail!("depx ignore entries require a non-empty package");
        }
        if entry.reason.trim().is_empty() {
            bail!(
                "depx ignore entry for {} requires a non-empty reason",
                entry.package
            );
        }
        if let Some(rule) = &entry.rule {
            if !is_known_code(rule) {
                bail!(
                    "depx ignore entry for {} references unknown rule {}",
                    entry.package,
                    rule
                );
            }
        }
        if let Some(expires) = &entry.expires {
            if parse_date(expires).is_none() {
                bail!(
                    "depx ignore expiration for {} must use YYYY-MM-DD",
                    entry.package
                );
            }
        }
    }
    Ok(())
}

fn read_baseline(path: &Path) -> Result<HashSet<String>> {
    let content = fs::read_to_string(path)
        .into_diagnostic()
        .with_context(|| format!("Failed to read depx baseline {}", path.display()))?;
    let baseline: FindingBaseline = serde_json::from_str(&content)
        .into_diagnostic()
        .with_context(|| format!("Failed to parse depx baseline {}", path.display()))?;
    if baseline.schema_version != BASELINE_SCHEMA_VERSION {
        bail!(
            "Unsupported depx baseline schema version {} in {}; regenerate it with `depx baseline`",
            baseline.schema_version,
            path.display()
        );
    }
    Ok(baseline.findings.into_iter().collect())
}

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn parse_date(value: &str) -> Option<(i32, u32, u32)> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return None,
    };
    if parts.next().is_some() || day == 0 || day > days_in_month {
        return None;
    }
    Some((year, month, day))
}

fn utc_date(now: SystemTime) -> Result<(i32, u32, u32)> {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .into_diagnostic()
        .wrap_err("System clock is before the Unix epoch")?
        .as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    Ok(civil_from_days(days))
}

// Gregorian civil date conversion adapted from Howard Hinnant's public-domain
// civil calendar algorithms.
fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (
        i32::try_from(year).unwrap_or(i32::MAX),
        u32::try_from(month).unwrap_or(12),
        u32::try_from(day).unwrap_or(31),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_thresholds_are_ordered() {
        assert!(!FindingFailOn::Never.matches(FindingSeverity::Error));
        assert!(FindingFailOn::Info.matches(FindingSeverity::Info));
        assert!(!FindingFailOn::Warning.matches(FindingSeverity::Info));
        assert!(FindingFailOn::Warning.matches(FindingSeverity::Warning));
        assert!(!FindingFailOn::Error.matches(FindingSeverity::Warning));
        assert!(FindingFailOn::Error.matches(FindingSeverity::Error));
    }

    #[test]
    fn civil_dates_match_known_epoch_values() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
    }

    #[test]
    fn config_requires_justified_well_formed_exceptions() {
        let missing_reason: DepxConfig = toml::from_str(
            r#"
                [[ignore]]
                package = "foo"
                reason = ""
            "#,
        )
        .unwrap();
        assert!(validate_config(&missing_reason).is_err());

        let invalid_date: DepxConfig = toml::from_str(
            r#"
                [[ignore]]
                package = "foo"
                reason = "generated code"
                expires = "tomorrow"
            "#,
        )
        .unwrap();
        assert!(validate_config(&invalid_date).is_err());

        let impossible_date: DepxConfig = toml::from_str(
            r#"
                [[ignore]]
                package = "foo"
                rule = "DX999"
                reason = "temporary"
                expires = "2026-02-31"
            "#,
        )
        .unwrap();
        assert!(validate_config(&impossible_date).is_err());
    }
}
