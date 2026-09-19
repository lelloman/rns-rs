# Reticulum 1.5.4 rgit Follow-up Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.4` |
| Previous normative commit | `1565126ffd08b9d7bc750ce5df82d5aa3e38183e` |
| Accepted version | `1.5.4` |
| Normative tag or ref | Canonical `rgit/master` |
| Normative commit | `e699bb23f1306ed451568d647b497791a44be95a` |
| Root tree | `654c79a2e4968c9e514f071f1074db548b680cac` |
| `RNS` tree | `b4c1cf368718971e1dcaf7c1cf2d1459411a360e` |
| Version assertion | Target `RNS/_version.py` declares `1.5.4` |
| Audited range | `1565126ffd08b9d7bc750ce5df82d5aa3e38183e..e699bb23f1306ed451568d647b497791a44be95a` |
| Acceptance date | `2026-09-19` |
| Detailed audit | [reticulum-1.5.4-rgit-2-audit.md](reticulum-1.5.4-rgit-2-audit.md) |

This accepts a same-version canonical development tip, not a signed release tag.
The final post-mapping refresh succeeded for both remotes: GitHub at
`2026-09-19T09:39:45Z`, rgit at `2026-09-19T09:39:50Z`. GitHub's tip
`badd850088e25df90d4d08a15a8c0ec68ea5d327` is the target's parent. This mirror
lag does not introduce unreviewed commits. Historical fixtures and the
GitHub-backed CI interop pin retain their existing provenance. The earlier
1.5.4 and 1.5.4 rgit records remain immutable.

## Upstream Commit Audit

All 17 commits have final **Non-runtime** dispositions and distinct non-empty
local mappings, in upstream ancestry order. Each mapping carries exactly one
full `Upstream-Commit` trailer; no upstream hash is mapped twice. The detailed
audit records every full upstream hash, local mapping hash, dependency, and
applicability rationale.

| Area | Upstream commits | Final handling |
|---|---|---|
| Test attribution | `28eba699` | Generation/review comments only; ASTs unchanged in all six Python test files. Upstream attribution is not assigned to native source. |
| README editorial guidance | `0bc132d7`, `b043414a`, `3b0425c8`, `b79f6e0b` | Community-implementation list, warnings, links, and callout formatting; no runtime behavior or native endorsement claim. |
| Chapter and repository documentation | `99bfde84`, `b67872d9`, `1e7432af` | New chapter, generated navigation, and identical upstream AGENTS.md copy; scoped review recorded without importing upstream commentary as native policy or independent findings. |
| Chapter revisions and generated artifacts | `032e1438`, `16ba292b`, `9397114f`, `900b4c60`, `b4c6deee`, `d0231f6e`, `ffad9143`, `badd8500`, `e699bb23` | Reviewed wording, typography, search/index data, and relocation into an addendum. No native runtime port required. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | All 17 commits retain the previous accepted `RNS` tree exactly. No fixture changes. |
| Transport and interfaces | No upstream or native runtime changes; workspace suite passes. |
| Links, channels, and resources | No runtime delta; daily impaired dual-VPS test passed Resource boundaries, concurrency, and forced reconnect recovery. |
| Utilities and APIs | No runtime, packaging-source, or configuration change; native documentation records the precise acceptance scope. |
| Live interop | No new exact-target Python/Rust run; runtime tree identity makes it inapplicable to this documentation/comment-only advancement. |

## Acceptance Record

All checks were performed on `2026-09-19`; no planned check is counted as passed.

| Gate | Result |
|---|---|
| Focused regression suites | No applicable runtime change. Complete diff review, identical runtime trees, and identical ASTs for the six changed Python tests establish non-runtime scope. |
| Fixture regeneration/provenance | No regeneration needed; native fixtures and historical provenance unchanged. |
| Exact-target Python/Rust interop | Not rerun; not applicable to the byte-identical runtime tree. |
| Workspace and feature suites | `cargo test --workspace`: 2,517 passed, 0 failed, 9 ignored. No separate optional-feature test matrix for this non-runtime advancement. |
| Formatting and lint | `cargo fmt --check` and `bash scripts/lint-host.sh` passed. Lint checks all workspace targets with native hooks and warnings denied. |
| Release/cross builds | Daily native-hook `rns-server` and `rns-ctl` release builds passed at `4034ea7`; native sources unchanged by these mappings. No new cross-build claimed. |
| Docker E2E | Not rerun for documentation/comment-only changes. |
| Hardware/manual validation | Full daily dual-VPS smoke passed, including four Resource sizes through 1 MiB, concurrent Resources/links, latency/jitter/rate impairment, and one forced reconnect. Physical hardware validation remains unclaimed. |

## Caveats and Deferred Validation

- This advancement establishes that the reviewed upstream delta requires no
  runtime port. It does not broaden earlier compatibility or hardware claims.
- Upstream editorial opinions, legal interpretations, third-party allegations,
  benchmark figures, and community endorsements are not independently verified
  or adopted as native findings by this audit.
- Existing native benchmark reproducibility requirements remain in force.
- Exact-target interop, optional-feature test matrix, Docker, cross-builds, and
  physical hardware were not rerun; their scope is recorded above.
- The first daily smoke attempt was blocked by sandbox socket restrictions;
  the unrestricted rerun passed. Workspace tests ran with socket access.

## Promotion Result

Reticulum 1.5.4 is accepted at
`e699bb23f1306ed451568d647b497791a44be95a`.
[UPSTREAM.md](../../UPSTREAM.md) records the normative baseline. The README badge
still shows 1.5.4 and links to this acceptance record. All 17 observed commits
are dispositioned; no runtime port remains outstanding for this range.
