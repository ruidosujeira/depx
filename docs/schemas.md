# Machine-readable schema compatibility

depx versions every public JSON identity contract. Consumers should inspect the schema version or fingerprint namespace rather than infer compatibility from the CLI version.

| Output | Current version | Version field or namespace |
|---|---:|---|
| `analyze --json` | 3 | `schemaVersion` |
| finding IDs | 2 | `fd-` semantic identity namespace |
| baseline | 2 | `schemaVersion` |
| `plan --json` | 3 | `schemaVersion` |
| `duplicates --json` | 2 | `schemaVersion` |
| SARIF fingerprints | 2 | `depx/v2` |

Version 3 changes:

- analysis project units expose their normalized package/workspace name, and Rust coverage distinguishes unresolved external references from paths that syntax alone cannot classify;
- plan actions expose a deterministically ordered `owners` list containing every project unit that declares the exact `ComponentId`;
- suggested remediation commands use the normalized package manager and exactly one `UnitDeclaration`, including its owner, source-level name and dependency section. Section-preserving flags are emitted only where the manager syntax is supported and tested. Commands are omitted for transitive components, multiple declarations, unsafe identifiers, unsupported alias syntax or package IDs that the manager cannot select unambiguously.

Analysis and plan schema version 2 consumers must migrate explicitly; version 3 adds required identity context and is not silently emitted as version 2.

Version 2 changes retained by the unaffected contracts:

- analysis includes explicit project units; evidence can retain its owning unit;
- finding IDs are semantic (`rule + exact subject + structured details`) and do not include occurrence evidence IDs, so byte-span movement alone does not invalidate a baseline;
- vulnerability-to-plan flow uses the exact component installation/locator;
- duplicate output replaces the unimplemented `transitive_count` field with exact component, immediate-dependent and direct-root facts;
- plan schema version 2 first guaranteed that vulnerability actions target the advisory's exact `ComponentId`; version 3 additionally retains declaration owners through command generation.

Evidence IDs remain occurrence identities and may change when a path, span or diagnostic description changes. Evidence spans and SARIF locations are retained for diagnostics; they are intentionally separate from semantic finding fingerprints.

Version 1 baselines are rejected with a regeneration instruction. Run `depx baseline` and review the resulting version 2 file. Other version 1 JSON consumers should migrate explicitly; depx does not silently reinterpret an older schema.
