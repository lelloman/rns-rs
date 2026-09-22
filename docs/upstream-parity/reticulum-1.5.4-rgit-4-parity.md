# Reticulum 1.5.4 rgit Fourth Advancement Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.4` |
| Previous normative commit | `99de23c040d507e3fefca19e87b182302902725d` |
| Accepted version | `1.5.4` |
| Normative tag or ref | Canonical `rgit/master`, matching `origin/master` |
| Normative commit | `c7be675739a26bd56fa743678d7dd80ddca39491` |
| Root tree | `8556cdf675d73b2dd0f0e16586c42f2653f41ace` |
| `RNS` tree | `b4c1cf368718971e1dcaf7c1cf2d1459411a360e` |
| Version assertion | Target `RNS/_version.py` declares `1.5.4` |
| Audited range | `99de23c040d507e3fefca19e87b182302902725d..c7be675739a26bd56fa743678d7dd80ddca39491` |
| Acceptance date | `2026-09-22` |
| Detailed audit | [reticulum-1.5.4-rgit-4-audit.md](reticulum-1.5.4-rgit-4-audit.md) |

This accepts a same-version canonical development tip, not a new signed
release. Both upstream remotes were freshly fetched and agree at the accepted
commit. The target `RNS` tree is byte-identical to the preceding accepted
baseline; historical fixtures and their provenance remain unchanged.

## Upstream Commit Audit

All three commits have final **Non-runtime** dispositions and separate,
non-empty local mapping commits in upstream ancestry order. The detailed audit
records full hashes, changed paths, review rationale, and the verified unique
`Upstream-Commit` trailers.

| Area | Upstream commits | Final handling |
|---|---|---|
| Upstream history/manual prose | `21a23650`, `a22de54b`, `c7be6757` | Editorial material and generated manual artifacts only; no native runtime or documentation port. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | The upstream `RNS` tree is unchanged; native sources and fixtures are unchanged. |
| Transport and interfaces | No runtime delta; workspace suite and daily live-fabric test passed. |
| Links, channels, and resources | Daily impaired dual-VPS test passed all configured Resource boundaries, concurrency, and forced reconnect recovery. |
| Utilities and APIs | Changed upstream paths are documentation only; native utility and API behavior is unchanged. |
| Live interop | Exact-target Python/Rust interop was not rerun because the runtime tree is byte-identical. |

## Acceptance Record

All results below were obtained on 2026-09-22. No planned test is counted as
passed.

| Gate | Result |
|---|---|
| Focused regression suites | Inapplicable: full diff review and exact runtime-tree equality establish non-runtime scope. |
| Fixture regeneration/provenance | No regeneration; historical fixtures and provenance unchanged. |
| Exact-target Python/Rust interop | Not rerun for this byte-identical runtime advancement. |
| Workspace and feature suites | `cargo test --workspace` passed. |
| Formatting and lint | `cargo fmt --check` and `bash scripts/lint-host.sh` passed. |
| Release/cross builds | Native-hook `rns-server` and `rns-ctl` release builds passed. No new cross-build claimed. |
| Docker E2E | Not rerun for documentation-only changes. |
| Hardware/manual validation | Daily dual-VPS stress passed with four Resource sizes through 1 MiB, concurrent Resources and links, impairment, and forced reconnect recovery. Physical hardware validation remains unclaimed. |

## Caveats and Deferred Validation

This accepts only the reviewed documentation delta and does not broaden prior
compatibility or hardware claims. Exact-target interop, optional-feature
matrices, Docker, cross-builds, and physical hardware were not rerun. Upstream
editorial and legal opinions are not independently verified or adopted as
native findings.

## Promotion Result

Reticulum 1.5.4 is accepted at `c7be675739a26bd56fa743678d7dd80ddca39491`.
[UPSTREAM.md](../../UPSTREAM.md) records this normative baseline. All three
observed commits are dispositioned; no runtime port remains outstanding.
