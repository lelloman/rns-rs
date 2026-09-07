# Reticulum 1.5.3 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.2` rgit |
| Previous normative commit | `3bc149e3d587695f52e695f18edb11751b21c005` |
| Accepted version | `1.5.3` |
| Normative tag or ref | Canonical `rgit/master` at acceptance |
| Normative commit | `0bb41bf9486c1469854876a3c1d7c57324efc7c4` |
| Root tree | `9b8fb0e518ed627685c9508773ceca156452cad8` |
| `RNS` tree | `86976fc8b62b79d08e2174557744e636be74ed9e` |
| Version assertion | `RNS.__version__ == "1.5.3"` |
| Audited range | `3bc149e3d587695f52e695f18edb11751b21c005..0bb41bf9486c1469854876a3c1d7c57324efc7c4` |
| Acceptance date | `2026-09-07` |
| Detailed audit | [reticulum-1.5.3-audit.md](reticulum-1.5.3-audit.md) |

Acceptance pins the canonical development commit asserting version 1.5.3, not
a signed release tag. Both remotes refreshed successfully before acceptance;
GitHub remains behind at the signed 1.5.2 release `ea98db4f`. CI retains that
fetchable interop pin. Exact-target tests used a detached canonical checkout.
Historical conformance fixtures are unchanged; the new PNG media input was
generated locally and is documented in the audit.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Attached-interface diagnostics | 1 | Structurally covered by native targeted-interface diagnostics and regressions. |
| Python docstring and repository README/assets | 4 | Non-runtime; full diffs reviewed and repository-owned assets are not vendored. |
| rngit media handling, compression and conversion | 3 | Integrated `/media`, image previews, raw file responses, disabled compression, optional WebP conversion and fallback. |
| Version metadata | 1 | Non-runtime; identifies this accepted target, with independent Cargo versioning. |

All nine commits have exactly one non-empty local mapping with a full
`Upstream-Commit` trailer, in canonical ancestry order. The existing logging
mapping was preserved; eight new mappings were added. The audit records every
local hash and its evidence.

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Full workspace, crypto, protocol and historical fixture suites passed with unchanged fixture provenance. |
| Transport and interfaces | 948 hook-enabled and 942 default-feature rns-net unit tests passed; all 54 network E2E tests passed in both configurations. |
| Links, channels, and resources | Existing Resource value responses and new raw file responses pass regressions; Docker, exact-target Python and impaired dual-VPS tests passed. |
| Utilities and APIs | rngit passed 206 unit and 23 integration tests; the installed conversion-backend test passed separately. ACL, URL decoding, filename metadata, large previews, conversion configuration, timeout and fallback are covered. |
| Live interop | Python `0bb41bf` passed packet/link/Resource interoperability, all five utility cases, and media bytes, PNG-to-WebP dimensions/name metadata and rejection checks. |

## Acceptance Record

Validation used integration revision `6a48768`; subsequent promotion changes
are documentation and baseline metadata only. All results below were obtained
locally on 2026-09-07.

| Gate | Result |
|---|---|
| Focused regression suites | Passed; per-commit red/green and final evidence are in the audit. |
| Fixture regeneration/provenance | No regeneration required; existing fixture suites passed unchanged. |
| Exact-target Python/Rust interop | Passed packet/link/Resource, five utility checks and media conversion against `0bb41bf`. |
| Workspace and feature suites | Both default and `rns-hooks` workspace suites passed serially; TLS, four built-in network hook E2E cases and the built-in control-plane lifecycle case passed. |
| Formatting and lint | Formatting, diff checks, warning-free host lint, 19 Python tool tests and four web UI smoke tests passed. Hook WASM examples built successfully. |
| Release/cross builds | Full hook-enabled host release workspace build passed; ARMv7 rnsd and rns-ctl builds passed without hooks and with native hooks; ARMv7 rns-server with built-in hooks passed. |
| Docker E2E | All 11 runs passed, including scale, reconnect, supervision, NAT and privileged tunnels: 102 assertions passed, zero failed, 29 topology-dependent skips. |
| Hardware/manual validation | Daily dual-VPS profile passed with `rns-server 0.3.1226-6a48768`, including Resource boundaries, concurrent links, impairment and forced reconnect. Physical Weave HIL is unclaimed. |
| Post-promotion drift | Both remotes refreshed at 13:44:05/13:44:11 UTC; canonical rgit equals the accepted checkout with zero commits ahead. GitHub remains behind. |

## Caveats and Deferred Validation

- The GitHub mirror still trails canonical rgit; GitHub-backed CI retains the
  signed 1.5.2 interop pin until it can fetch the accepted target.
- Physical Weave HIL was unavailable and is not claimed, carrying the existing
  hardware caveat forward.
- Native conversion owns temporary files per call and returns owned Resource
  bytes, rather than retaining Python-style link-owned spool directories.

## Promotion Result

Reticulum 1.5.3 is accepted as the rns-rs upstream reference baseline at
`0bb41bf9486c1469854876a3c1d7c57324efc7c4`.
[UPSTREAM.md](../../UPSTREAM.md) records the accepted version and tree provenance.
