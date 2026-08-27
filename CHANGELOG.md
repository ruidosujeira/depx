# Changelog

All notable changes to depx are documented here. The project follows Semantic Versioning.

## [Unreleased]

### Added

- Rust source analysis for `use`, `extern crate`, crate paths and macro references, with role-aware runtime, build and test evidence.
- `depx plan`, which combines usage evidence, dependency paths, vulnerabilities, deprecations and findings into prioritized remediation actions.
- `depx.toml` policies with finding thresholds and justified, optionally expiring exceptions.
- `depx baseline` for adopting depx in an existing codebase without hiding new findings.
- SARIF 2.1.0 output from `depx analyze --sarif` for code-scanning integrations.
- npm, pnpm, Yarn and Cargo workspace manifest discovery.
- `pnpm-lock.yaml` and Yarn classic/modern `yarn.lock` adapters.
- Explicit project/workspace units with exact declarations and evidence ownership across npm, pnpm, Yarn and Cargo.
- Bounded OSV retry/backoff with `Retry-After` support and an explicit `unknown` advisory severity.
- Adversarial coverage for workspace isolation, same-name/same-version installation contexts, Yarn virtual locators, cyclic/dense graphs and semantic fingerprints.

### Changed

- Cargo analysis excludes source-less local workspace packages from the third-party inventory.
- Cargo manifest resolution understands renamed crates, workspace dependencies and target-specific dependency tables.
- Remediation plans retain exact declaration owners and emit only package-manager commands that can select one proven project unit and component.
- Cargo remediation package specifications include the installed version; commands are omitted when source identity remains ambiguous.
- Vulnerabilities retain their exact `ComponentId` through audit and remediation planning; plans no longer reconstruct installations from name/version.
- `why` returns up to five deterministic shortest useful chains without pre-enumerating every path.
- Duplicate analysis schema v2 reports exact installations, dependents, direct roots, major counts and compile-unit facts; version count alone no longer creates a high impact or a hard-coded CI failure.
- Analysis and plan schemas are version 3. Finding IDs, baselines and duplicate output remain version 2; SARIF fingerprints use `depx/v2` and finding IDs no longer change for source span offsets alone.
- Yarn modern resolution preserves distinct locators and virtual peer contexts; Node built-in subpaths are excluded from package evidence.

### Fixed

- Rust coverage reports unresolved explicit external references and separately exposes paths that cannot be classified safely from source syntax.
- Source and script resolution is scoped to the owning workspace unit, and unrelated nested projects are not scanned.
- Advisories without usable severity data are no longer mislabeled as medium.

### CI and safety

- `depx analyze --fail-on <info|warning|error>` can gate CI using structured findings.
- Policy exceptions require a reason; expired exceptions stop suppressing findings and emit a warning.
- Finding identities, baselines, JSON plans and SARIF fingerprints are deterministic.
- The validation workflow now runs formatting, Clippy, build and tests on Linux, macOS and Windows.

[Unreleased]: https://github.com/ruidosujeira/depx/compare/v0.4.0...HEAD
