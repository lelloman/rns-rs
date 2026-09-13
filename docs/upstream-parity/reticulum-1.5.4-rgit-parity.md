# Reticulum 1.5.4 rgit Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.4` |
| Previous normative commit | `0dbc9e90a33c427befd3873aa29bd6e8463ba192` |
| Accepted version | `1.5.4` |
| Normative tag or ref | Canonical `rgit/master` |
| Normative commit | `1565126ffd08b9d7bc750ce5df82d5aa3e38183e` |
| Root tree | `780e486cf31d518fc84aab5ec5bd9fb823ad6f45` |
| `RNS` tree | `b4c1cf368718971e1dcaf7c1cf2d1459411a360e` |
| Version assertion | Target `RNS/_version.py` declares `1.5.4` |
| Audited range | `0dbc9e90a33c427befd3873aa29bd6e8463ba192..1565126ffd08b9d7bc750ce5df82d5aa3e38183e` |
| Acceptance date | `2026-09-13` |
| Detailed audit | [reticulum-1.5.4-rgit-audit.md](reticulum-1.5.4-rgit-audit.md) |

Both freshly fetched remotes agree on the target. This is a same-version
development-tip advancement, not acceptance of a signed release tag. Historical
fixture provenance is unchanged. The prior 1.5.4 audit and parity record remain
immutable; the qualified records describe this additional commit.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Performance documentation | `1565126ffd08b9d7bc750ce5df82d5aa3e38183e` | Non-runtime. Only `README.md` and `README.mu` changed. Local mapping `9606dd1` adds native performance reporting guidance without adopting Python throughput claims. |

The mapping is non-empty and carries exactly one full `Upstream-Commit` trailer;
no other local commit carries that upstream hash.

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Target and previous baseline have identical `RNS` trees. |
| Transport and interfaces | No runtime changes upstream or locally. |
| Links, channels, and resources | No runtime changes upstream or locally. |
| Utilities and APIs | No behavior changes; native README guidance updated. |
| Live interop | Exact-target rerun not applicable to the README-only diff and identical `RNS` tree. |

## Acceptance Record

| Gate | Result |
|---|---|
| Focused regression suites | Not applicable; documentation-only mapping. |
| Fixture regeneration/provenance | No regeneration needed; fixtures unchanged. |
| Exact-target Python/Rust interop | Not applicable; no wire or externally visible runtime change. |
| Workspace and feature suites | `cargo test --workspace` passed: 2,517 passed, 0 failed, 9 ignored. Native-hook feature coverage compiled by host lint; no separate optional-feature test matrix was run for this documentation-only change. |
| Formatting and lint | `cargo fmt --check` and `bash scripts/lint-host.sh` passed on 2026-09-13. Lint checks all workspace targets with native hooks and warnings denied. |
| Release/cross builds | The retained daily report records a successful native-hook `rns-server` release build. No new release/cross build for this README-only change. |
| Docker E2E | Not rerun for this documentation-only advancement. |
| Hardware/manual validation | The retained daily report records a successful impaired dual-VPS smoke. No new manual run; physical hardware validation remains unclaimed. |

## Caveats and Deferred Validation

- Upstream performance figures are not native benchmark results or guarantees.
- No new live smoke, Docker, cross-build, or physical hardware validation is
  claimed by this mapping. The daily results are retained from the initial audit.
- The GitHub-backed CI interop pin and historical fixtures are unchanged.
- The first workspace test attempt hit sandbox-denied loopback socket creation;
  the unrestricted full rerun passed and supplies the acceptance result.

## Promotion Result

Reticulum 1.5.4 is accepted at
`1565126ffd08b9d7bc750ce5df82d5aa3e38183e`.
[UPSTREAM.md](../../UPSTREAM.md) records this normative baseline. The temporary
`reticulum-next-audit.md` has been replaced by the completed qualified audit.
