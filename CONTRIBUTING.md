# Contributing to depx

Thank you for improving depx. Keep changes focused on evidence-backed dependency decisions and preserve exact component identity across adapters, evidence, findings, advisories and plans.

Before opening a pull request, run:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo package --allow-dirty
```

Changes to a public JSON shape, baseline identity or SARIF fingerprint must bump the relevant schema version and update `docs/schemas.md` and `CHANGELOG.md`. Parser and graph changes should include adversarial fixtures or tests for ambiguity, cycles, workspace boundaries and deterministic ordering where applicable.

Do not make “unused” synonymous with “safe to remove.” Findings must state their evidence and coverage limitations. Ecosystem-specific resolution belongs in adapters; finding rules consume the normalized model.

Please keep commits reviewable and describe behavioral compatibility, tests run and any remaining limitations in the pull request.
