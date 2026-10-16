# Reticulum 1.5.7 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.6` |
| Previous normative commit | `49ae71e06cadf5d846849661578a8ad9fcede443` |
| Accepted version | `1.5.7` |
| Normative tag or ref | Canonical `rgit/master` tip (no signed `1.5.7` tag; GitHub mirror still at `e40191b3`) |
| Normative commit | `a29bfb51c468945c96a1ee22cae0114e993e2391` |
| Root tree | `24d4c393de9fd57b933836cea68891fd953ab060` |
| `RNS` tree | `c8cde8d039e59ad1d60ec9ac28ac180b0ab5499c` |
| Version assertion | `RNS.__version__ == "1.5.7"` |
| Audited range | `49ae71e06cadf5d846849661578a8ad9fcede443..a29bfb51c468945c96a1ee22cae0114e993e2391` |
| Acceptance date | `2026-10-16` |
| Detailed audit | [reticulum-1.5.7-audit.md](reticulum-1.5.7-audit.md) |

This accepts a canonical development tip that declares version `1.5.7`, not a
signed release: no signed `1.5.7` tag is published (the nearest tag is `1.5.5`,
and `git describe` reports `1.5.5-11-ga29bfb51`). Both upstream remotes were
freshly fetched; the canonical rgit tip advanced five commits past the accepted
`1.5.6` baseline while the GitHub mirror remained at `e40191b3` (behind the
baseline, which is allowed). The only runtime change is a Python-only Backbone
egress-control fix, structurally covered here; the remaining four commits are
version, changelog, and generated-documentation metadata. Historical fixtures
and their provenance are unchanged.

## Upstream Commit Audit

Every commit has a final disposition and a separate, non-empty local mapping
commit in upstream ancestry order. The detailed audit records full hashes,
changed paths, review rationale, and the verified unique `Upstream-Commit`
trailers.

| Area | Upstream commits | Final handling |
|---|---|---|
| Backbone egress control | `f0875ac4` | Structurally covered: rns-rs builds a fresh writer (`TransmitBuffer` + `EgressController`) per connection and drops the stalled writer on teardown, so upstream's persistent-instance reset is unnecessary; the invariant is documented and a focused regression added. |
| Egress-control test | `cadee01f` | Non-runtime: upstream-only Python test for the persistent-instance reset; native invariants covered by `transmit_buffer.rs` tests. |
| Version metadata | `2578750b` | Non-runtime: `RNS/_version.py` declares `1.5.7`; Rust crate versions are independent. |
| Changelog | `318b78b4` | Non-runtime: upstream `Changelog.md` note, not vendored. |
| Generated manual | `a29bfb51` | Non-runtime: regenerated upstream `docs/manual/` output, not vendored; the `RNS` tree is unchanged from `2578750b`. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No wire or crypto change in range; conformance fixtures and their provenance are unchanged. |
| Transport and interfaces | The only runtime delta is the Python-only Backbone egress-control reset; rns-rs covers it structurally via per-connection writer recreation, with focused regression `fresh_egress_state_does_not_immediately_reescalate_after_teardown`. |
| Links, channels, and resources | Daily impaired dual-VPS test passed four Resource sizes through 1 MiB, concurrent links and channels, and forced reconnect recovery. |
| Utilities and APIs | No utility or API behavior change; exact-target utility interop passed. |
| Live interop | Exact-target Python/Rust interop at `a29bfb51` (RNS `1.5.7`): 2/2 `python_interop`, 6/6 `utility_interop`. |

## Acceptance Record

All results below were obtained on 2026-10-16. No planned test is counted as
passed.

| Gate | Result |
|---|---|
| Focused regression suites | `interface::transmit_buffer` suite passed (13/13), including the new reconnect regression. |
| Fixture regeneration/provenance | No regeneration; historical fixtures and provenance unchanged. |
| Exact-target Python/Rust interop | Passed against a disposable `/tmp` worktree at `a29bfb51`: 2/2 `python_interop`, 6/6 `utility_interop`. |
| Workspace and feature suites | `cargo test --workspace` passed (2,833; 0 failed) and `cargo test --workspace --features rns-hooks` passed (2,892; 0 failed); `cargo test -p rns-ctl --features tls` passed (133). |
| Formatting and lint | `cargo fmt --all --check` and `bash scripts/lint-host.sh` passed. Python tool tests passed (19) and `node --test rns-ctl/assets/app.smoke.test.js` passed (4). |
| Release/cross builds | Native-hook `rns-server`/`rns-ctl` release builds passed (`0.4.1567-3054d35` / `0.5.1567-3054d35`); all five ARMv7 cross builds passed. |
| Docker E2E | `tests/docker/run-all.sh` passed: 11 runs, 102 checks, 0 failed, 29 skipped (993s), including scale, shared-client reconnect, `rns-server` supervision, Direct Link NAT, and privileged `rntun`. |
| Hardware/manual validation | Daily impaired dual-VPS stress passed on `3054d35`; physical hardware validation remains unclaimed. |

## Caveats and Deferred Validation

This accepts the reviewed five-commit delta and does not broaden prior
compatibility claims. No signed `1.5.7` tag exists; the version is asserted from
`RNS/_version.py`. The GitHub mirror lagged the canonical rgit tip at
acceptance. Physical hardware validation remains unclaimed.

## Promotion Result

Reticulum 1.5.7 is accepted at
`a29bfb51c468945c96a1ee22cae0114e993e2391` as the canonical `rgit/master`
baseline. [UPSTREAM.md](../../UPSTREAM.md) records this normative baseline. All
five observed commits are dispositioned; no runtime port remains outstanding.
