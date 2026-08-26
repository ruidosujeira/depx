# depx

[![Crates.io](https://img.shields.io/crates/v/depx.svg)](https://crates.io/crates/depx)
[![CI](https://github.com/ruidosujeira/depx/actions/workflows/ci.yml/badge.svg)](https://github.com/ruidosujeira/depx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Understand what's actually in your `node_modules` and `Cargo.lock`.**

<p align="center">
  <img src="assets/demo.gif" alt="depx demo: analyze, why, audit, deprecated and duplicates" width="760">
</p>

A fast dependency analyzer for JavaScript/TypeScript and Rust projects. It cross-references your lockfile against the code you actually import — so it can tell unused packages from expected dev tools, explain *why* a transitive dependency exists, and flag only the vulnerabilities that affect the versions you really have installed. Written in Rust.

## Why depx?

Your `node_modules` has hundreds of packages. Do you know:

- Which ones are actually imported in your code (and which are just dead weight)?
- Why `is-odd` is even installed?
- Whether that vulnerability alert affects a version you actually have?

`npm ls`, `npm audit` and `depcheck` each answer a fragment of this. depx connects the dots in a single tool, for both npm and Cargo projects.

## Installation

```bash
cargo install depx
```

Or build from source:

```bash
git clone https://github.com/ruidosujeira/depx
cd depx
cargo install --path .
```

## Quick start

Run any command from the root of a project (it auto-detects `package-lock.json` or `Cargo.lock`):

```bash
depx analyze        # what's used vs. unused
depx why <package>  # why a package is installed
depx audit          # version-aware vulnerability scan
depx deprecated     # deprecated packages, flagged if still used
depx duplicates     # multiple versions of the same crate (Rust)
```

Want to try it on a real, tiny project first? This repo ships one:

```bash
cd examples/demo-app
npm install         # depx reads the lockfile + source, not node_modules
depx analyze
```

## Commands

### `depx analyze` — find unused dependencies

```text
$ depx analyze

Dependency Analysis Report

Summary
  4 packages used
  1 packages unused (removable)
  2 dev/build tools (expected, not imported)

Unused Dependencies (safe to remove):
  - is-odd@3.0.1

  Tip: npm uninstall <package>

Dev/Build Tools (not imported, expected):
  ~ @types/node@20.14.2
  ~ typescript@5.4.5
```

depx parses your source with [oxc](https://oxc.rs) and matches imports against the lockfile. It separates **truly unused** packages from **dev/build tools that aren't meant to be imported** (`@types/*`, `typescript`, `eslint`, `vitest`, bundlers, etc.), so it won't tell you to uninstall your toolchain.

**Options:**
- `--unused` — show only components without supported usage evidence
- `--no-dev` — exclude development dependencies (included by default)
- `--json` — emit deterministic machine-readable JSON
- `-v` / `--verbose` — show complete finding explanations and evidence

### `depx why <package>` — explain why a package is installed

```text
$ depx why wrappy

Package: wrappy@1.0.2

Dependency chains:
  -> inflight -> wrappy
     inflight -> once -> wrappy
```

Shows every chain from your direct dependencies down to the package you asked about — so you know which dependency to touch to get rid of it.

### `depx audit` — check for *real* vulnerabilities

```text
$ depx audit

1 vulnerability found

CRITICAL
  GHSA-xvch-5gv4-984h minimist@1.2.5 - Prototype Pollution in minimist [USED]
       Fix: 1.2.5 -> 1.2.6
```

depx queries the [OSV](https://osv.dev) database **with your exact installed versions** (npm → `npm`, Cargo → `crates.io`), so you don't drown in old CVEs that don't apply to you. The `[USED]` tag marks advisories that hit code your project actually imports.

**Options:**
- `--used-only` — report only vulnerabilities in packages your code actually uses

### `depx deprecated` — find deprecated packages

```text
$ depx deprecated

1 deprecated package found

  - inflight@1.0.6 [USED]
    This module is not supported, and leaks memory. Do not use it. Check out
    lru-cache if you want a good and tested way to coalesce async requests by a
    key value, which is much more comprehensive and powerful.
```

Each deprecated package is tagged `[USED]` or `[unused]` so you can prioritize the ones that are actually in your code path.

### `depx duplicates` — detect duplicate dependencies (Rust/Cargo)

```text
$ depx duplicates

Duplicate Dependencies Analysis

Summary
  12 crates with multiple versions
  1 high severity (3+ versions)
  11 low severity (same major version)
  14 extra compile units

HIGH SEVERITY
  ! windows-sys (4 versions)
      v0.52.0 ← ring
      v0.59.0 ← colored
      v0.60.2 ← socket2, terminal_size
      v0.61.2 ← anstyle-query, anstyle-wincon +7 more

  + 11 low severity duplicates (use --verbose to show)

  Tip: Use `cargo tree -d` for detailed dependency tree
```

Finds when multiple versions of the same crate end up in your build, ranks them by how disruptive they are (different majors hurt more), estimates the extra compile units, and — in verbose mode — suggests which dependency to bump.

**Options:**
- `-v` / `--verbose` — show all duplicates (including low severity) with upgrade suggestions
- `--json` — emit JSON for programmatic use

## How it works

| Stage | What happens |
|-------|--------------|
| **Lockfile** | Parses `package-lock.json` (v1/v2/v3) or `Cargo.lock` into a package graph, tracking direct/dev/transitive status |
| **Source** | Walks your source and extracts imports with [oxc](https://oxc.rs) — ES modules, CommonJS `require`, dynamic `import()`, and re-exports |
| **Graph** | Builds a dependency graph with [petgraph](https://github.com/petgraph/petgraph) to resolve `why` chains and transitive usage |
| **Advisories** | Batches version-pinned queries to [OSV](https://osv.dev) for vulnerabilities, and reads deprecation metadata from the lockfile |

## Supported lockfiles

- [x] `package-lock.json` (npm) — full analysis
- [x] `Cargo.lock` (Rust) — duplicates + version-aware audit
- [ ] `pnpm-lock.yaml` (planned)
- [ ] `yarn.lock` (planned)

## Built with AI

This project was built in partnership with Claude (Anthropic). I define the architecture, make decisions, review code, and handle the direction. Claude helps write code faster.

I believe AI is a tool, not a replacement. The developer still needs to understand the problem, evaluate solutions, and take responsibility for the result. AI just accelerates execution.

You can see Claude as a contributor in this repo — that's intentional transparency.

## License

MIT
