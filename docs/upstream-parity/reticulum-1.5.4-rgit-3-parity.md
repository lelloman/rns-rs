# Reticulum 1.5.4 rgit Third Advancement Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.4` |
| Previous normative commit | `e699bb23f1306ed451568d647b497791a44be95a` |
| Accepted version | `1.5.4` |
| Normative tag or ref | Canonical `rgit/master`, matching `origin/master` |
| Normative commit | `99de23c040d507e3fefca19e87b182302902725d` |
| Root tree | `42e27d27afbed126220bec5ae701a745e0568a10` |
| `RNS` tree | `b4c1cf368718971e1dcaf7c1cf2d1459411a360e` |
| Version assertion | Target `RNS/_version.py` declares `1.5.4` |
| Audited range | `e699bb23f1306ed451568d647b497791a44be95a..99de23c040d507e3fefca19e87b182302902725d` |
| Acceptance date | `2026-09-20` |
| Detailed audit | [reticulum-1.5.4-rgit-3-audit.md](reticulum-1.5.4-rgit-3-audit.md) |

This accepts a same-version canonical development tip, not a new signed release.
Both remotes refreshed successfully and agree: GitHub at
`2026-09-20T14:21:11+00:00`, rgit at
`2026-09-20T14:21:15+00:00`. Historical fixture provenance,
the separate GitHub-backed CI interop pin, and earlier acceptance records remain
unchanged.

## Upstream Commit Audit

All 16 commits have final **Non-runtime** dispositions and separate non-empty
local mapping commits in upstream ancestry order. Each has exactly one canonical
`Upstream-Commit` trailer, with no duplicate mapping. Full hashes, changed paths,
dependencies and per-commit rationales are recorded in the detailed audit.

| Area | Upstream commits | Final handling |
|---|---|---|
| History essay | `484cf2d1`, `abf355b4`, `29f6bc86`, `7373f813`, `58881af3`, `9d85931c`, `34b36362` | Archived editorial material and revisions; no native runtime or documentation port. |
| README guidance | `3c479ddb`, `2289a8ef`, `23101e45`, `8743ddcb`, `cb66b3d1`, `ddd55d50` | Upstream links, warnings and presentation; no protocol contract or native endorsement claim. |
| Generated search index | `15e6dd4a` | API search entries and empty-term cleanup; API implementations unchanged. |
| Chapter source and generated copies | `395241b1`, `99de23c0` | Editorial corrections, cross-reference and generated artifacts; no independent runtime change. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Every upstream commit retains the accepted `RNS` tree exactly; native sources and fixtures unchanged. |
| Transport and interfaces | No runtime delta; workspace suite and daily live-fabric test passed. |
| Links, channels and resources | Daily impaired dual-VPS test passed Resource boundaries, concurrency and forced reconnect recovery. |
| Utilities and APIs | Changed paths are only README and docs; generated API search entries do not change API implementations. |
| Live interop | Exact-target Python/Rust interop not rerun; no runtime delta requiring it. |

## Acceptance Record

All results below were obtained on 2026-09-20. No planned test is counted as passed.

| Gate | Result |
|---|---|
| Focused regressions | Inapplicable: full diff review and exact runtime-tree equality establish non-runtime scope. |
| Fixture regeneration/provenance | No regeneration; historical fixtures and provenance unchanged. |
| Exact-target Python/Rust interop | Not rerun for this byte-identical runtime advancement. |
| Workspace and feature suites | `cargo test --workspace`: 2,517 passed, 0 failed, 9 ignored. No separate optional-feature test matrix. |
| Formatting and lint | `cargo fmt --check` and `bash scripts/lint-host.sh` passed; lint covers all workspace targets with native hooks and warnings denied under existing script allowances. |
| Release/cross builds | Daily native-hook `rns-server` and `rns-ctl` release builds passed at `503d1fc`; native source unchanged. No new cross-build claimed. |
| Docker E2E | Not rerun for documentation-only changes. |
| Hardware/manual validation | Daily dual-VPS stress passed: Resource sizes 1,024, 100,000, 1,048,575 and 1,048,576 bytes, concurrent Resources and links, latency/jitter/rate impairment, and one forced disconnect/recovery cycle. Physical hardware validation unclaimed. |

## Caveats and Deferred Validation

This accepts the reviewed documentation delta and does not broaden earlier
compatibility or hardware claims. Upstream editorial opinions, legal
interpretations, benchmark claims, and third-party allegations are not
independently verified or adopted as native findings. Exact-target interop,
optional-feature matrices, Docker, cross-builds and hardware were not rerun;
byte-identical runtime scope and daily operational evidence justify this
non-runtime acceptance, consistent with the preceding acceptance record.
The sandbox blocked the first smoke socket attempt; the unrestricted rerun
passed. Workspace tests also ran with socket access.

## Promotion Result

Reticulum 1.5.4 is accepted at `99de23c040d507e3fefca19e87b182302902725d`.
[UPSTREAM.md](../../UPSTREAM.md) records this normative baseline, and the README
badge links to this acceptance record. All 16 observed commits are dispositioned;
no port remains outstanding for this range.
