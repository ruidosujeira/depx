# Machine-readable schema compatibility

depx versions every public JSON identity contract. Consumers should inspect the schema version or fingerprint namespace rather than infer compatibility from the CLI version.

| Output | Current version | Version field or namespace |
|---|---:|---|
| `analyze --json` and finding IDs | 2 | `schemaVersion` |
| baseline | 2 | `schemaVersion` |
| `plan --json` | 2 | `schemaVersion` |
| `duplicates --json` | 2 | `schemaVersion` |
| SARIF fingerprints | 2 | `depx/v2` |

Version 2 changes:

- analysis includes explicit project units; evidence can retain its owning unit;
- finding IDs are semantic (`rule + exact subject + structured details`) and do not include occurrence evidence IDs, so byte-span movement alone does not invalidate a baseline;
- vulnerability-to-plan flow uses the exact component installation/locator;
- duplicate output replaces the unimplemented `transitive_count` field with exact component, immediate-dependent and direct-root facts;
- plan schema version 2 guarantees that vulnerability actions target the advisory's exact `ComponentId`.

Evidence IDs remain occurrence identities and may change when a path, span or diagnostic description changes. Evidence spans and SARIF locations are retained for diagnostics; they are intentionally separate from semantic finding fingerprints.

Version 1 baselines are rejected with a regeneration instruction. Run `depx baseline` and review the resulting version 2 file. Other version 1 JSON consumers should migrate explicitly; depx does not silently reinterpret an older schema.
