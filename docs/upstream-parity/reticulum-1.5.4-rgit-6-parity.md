# Reticulum 1.5.4 rgit Sixth Advancement Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.4` |
| Previous normative commit | `8a7ad40d649aae1cd755f060fa8f5619f7000b29` |
| Accepted version | `1.5.4` |
| Normative tag or ref | Canonical `rgit/master`, matching `origin/master` |
| Normative commit | `3f95b472820ddfb27f736143fb0b4d0d3aa610f1` |
| Root tree | `a843be443c20aa15b5f63f36663a351230a93168` |
| `RNS` tree | `51f0e922420b47f482df9184b48ade41ac8d6ce3` |
| Version assertion | Target `RNS/_version.py` declares `1.5.4` |
| Audited range | `8a7ad40d649aae1cd755f060fa8f5619f7000b29..3f95b472820ddfb27f736143fb0b4d0d3aa610f1` |
| Acceptance date | `2026-09-27` |
| Detailed audit | [reticulum-1.5.4-rgit-6-audit.md](reticulum-1.5.4-rgit-6-audit.md) |

This accepts a same-version canonical development tip, not a new signed
release. Both upstream remotes were freshly fetched and agree at the accepted
commit. The target `RNS` tree differs from the previously accepted baseline
(`b4c1cf368718971e1dcaf7c1cf2d1459411a360e`) only because `aeccf69f` deletes an
unused `import platform` from `RNS/Interfaces/RNodeInterface.py`; the second
commit leaves that tree unchanged. Historical fixtures and their provenance
remain unchanged.

## Upstream Commit Audit

Both commits have final **Non-runtime** dispositions and separate, non-empty
local mapping commits in upstream ancestry order. The detailed audit records
full hashes, changed paths, review rationale, and the verified unique
`Upstream-Commit` trailers.

| Area | Upstream commits | Final handling |
|---|---|---|
| RNode BLE source hygiene | `aeccf69f` | Deleted unused Python-local import; the native workspace has no RNode BLE implementation, so no Rust counterpart exists. |
| Upstream agent guidance | `3f95b472` | Upstream `AGENTS.md` rewrite only; not loaded by the Reticulum runtime and not vendored. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | The only `RNS` change deletes an unreferenced import; wire and crypto behavior and native fixtures are unchanged. |
| Transport and interfaces | No observable runtime delta; workspace suite and daily live-fabric test passed. |
| Links, channels, and resources | Daily impaired dual-VPS test passed all configured Resource boundaries, concurrency, and forced reconnect recovery. |
| Utilities and APIs | The deleted import is function-local and unused; no native utility or API behavior is affected. |
| Live interop | Exact-target Python/Rust interop was not rerun because the only runtime change is a removed unused import. |

## Acceptance Record

All results below were obtained on 2026-09-27. No planned test is counted as
passed.

| Gate | Result |
|---|---|
| Focused regression suites | Inapplicable: full diff review establishes that the sole runtime edit is a removed unused import. |
| Fixture regeneration/provenance | No regeneration; historical fixtures and provenance unchanged. |
| Exact-target Python/Rust interop | Not rerun for this non-runtime advancement. |
| Workspace and feature suites | `cargo test --workspace` passed. |
| Formatting and lint | `cargo fmt --check` and `bash scripts/lint-host.sh` passed. |
| Release/cross builds | Native-hook `rns-server` and `rns-ctl` release builds passed. No new cross-build claimed. |
| Docker E2E | Not rerun for this non-runtime advancement. |
| Hardware/manual validation | Daily dual-VPS stress passed with four Resource sizes through 1 MiB, concurrent Resources and links, impairment, and forced reconnect recovery. Physical hardware validation remains unclaimed. |

## Caveats and Deferred Validation

This accepts only the reviewed two-commit delta and does not broaden prior
compatibility or hardware claims. Exact-target interop, optional-feature
matrices, Docker, cross-builds, and physical hardware were not rerun. Upstream
editorial and legal opinions are not independently verified or adopted as
native findings.

## Promotion Result

Reticulum 1.5.4 is accepted at `3f95b472820ddfb27f736143fb0b4d0d3aa610f1`.
[UPSTREAM.md](../../UPSTREAM.md) records this normative baseline. Both observed
commits are dispositioned; no runtime port remains outstanding.
