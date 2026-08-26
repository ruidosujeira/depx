# Changelog

All notable changes to depx are documented here. The project follows Semantic Versioning.

## [Unreleased]

## [0.6.0] - 2026-08-26

### Added

- Rust source analysis for `use`, `extern crate`, crate paths and macro references, with role-aware runtime, build and test evidence.
- `depx plan`, which combines usage evidence, dependency paths, vulnerabilities, deprecations and findings into prioritized remediation actions.
- `depx.toml` policies with finding thresholds and justified, optionally expiring exceptions.
- `depx baseline` for adopting depx in an existing codebase without hiding new findings.
- SARIF 2.1.0 output from `depx analyze --sarif` for code-scanning integrations.
- npm, pnpm, Yarn and Cargo workspace manifest discovery.
- `pnpm-lock.yaml` and Yarn classic/modern `yarn.lock` adapters.

### Changed

- Cargo analysis excludes source-less local workspace packages from the third-party inventory.
- Cargo manifest resolution understands renamed crates, workspace dependencies and target-specific dependency tables.
- Remediation plans select npm, pnpm, Yarn or Cargo commands from the detected project files.

### CI and safety

- `depx analyze --fail-on <info|warning|error>` can gate CI using structured findings.
- Policy exceptions require a reason; expired exceptions stop suppressing findings and emit a warning.
- Finding identities, baselines, JSON plans and SARIF fingerprints are deterministic.

[Unreleased]: https://github.com/ruidosujeira/depx/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/ruidosujeira/depx/compare/v0.5.0...v0.6.0
