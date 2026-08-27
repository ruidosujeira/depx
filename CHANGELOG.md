# Changelog

All notable changes to depx are documented here. The project follows Semantic Versioning.

## [Unreleased]

### Added

- Explicit project/workspace units with exact declarations and evidence ownership across npm, pnpm, Yarn and Cargo.
- Bounded OSV retry/backoff with `Retry-After` support and an explicit `unknown` advisory severity.
- Adversarial coverage for workspace isolation, same-name/same-version installation contexts, Yarn virtual locators, cyclic/dense graphs and semantic fingerprints.

### Changed

- Vulnerabilities retain their exact `ComponentId` through audit and remediation planning; plans no longer reconstruct installations from name/version.
- `why` returns up to five deterministic shortest useful chains without pre-enumerating every path.
- Duplicate analysis schema v2 reports exact installations, dependents, direct roots, major counts and compile-unit facts; version count alone no longer creates a high impact or a hard-coded CI failure.
- Analysis/finding, baseline, plan and duplicate schemas are version 2; SARIF fingerprints use `depx/v2` and finding IDs no longer change for source span offsets alone.
- Yarn modern resolution preserves distinct locators and virtual peer contexts; Node built-in subpaths are excluded from package evidence.

### Fixed

- Source and script resolution is scoped to the owning workspace unit, and unrelated nested projects are not scanned.
- Advisories without usable severity data are no longer mislabeled as medium.

### CI and safety

- The validation workflow now runs formatting, Clippy, build and tests on Linux, macOS and Windows.

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
