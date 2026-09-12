# Reticulum 1.5.4 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.3` |
| Previous normative commit | `fae64abf05a0ec5afabb2def9076f70d42bfe600` |
| Accepted version | `1.5.4` |
| Normative tag or ref | Canonical `rgit/master` at acceptance |
| Normative commit | `0dbc9e90a33c427befd3873aa29bd6e8463ba192` |
| Root tree | `c19f02deaed560e3ac9d9ff8b78704eac3003649` |
| `RNS` tree | `b4c1cf368718971e1dcaf7c1cf2d1459411a360e` |
| Version assertion | `RNS.__version__ == "1.5.4"` |
| Audited range | `fae64abf05a0ec5afabb2def9076f70d42bfe600..0dbc9e90a33c427befd3873aa29bd6e8463ba192` |
| Acceptance date | `2026-09-12` |
| Detailed audit | [reticulum-1.5.4-audit.md](reticulum-1.5.4-audit.md) |

This accepts the canonical rgit commit, not a verified signed release tag; no
`1.5.4` tag was advertised and GitHub has not mirrored it. Both remotes
refreshed successfully before promotion. GitHub remains behind at
`ea98db4f53dcf0defc0e71a16e60d28b1229c4e6`, so CI retains its fetchable
GitHub pin. Historical fixtures are unchanged and retain their recorded
provenance.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Desktop RNode BLE connectivity | `0c97853`, `996d822`, `851c18b` | Non-runtime. Fixes Windows paired-BLE address acquisition, a desktop reconnect deadlock, and BLE reconnect reliability. rns-rs implements RNode over serial only and has no host-side BLE client; the ESP32 support is a peripheral bridge. Matches the accepted `c6f9ef10` precedent. |
| Version and changelog metadata | `7785fd2`, `9199cc9` | Non-runtime. Upstream Python package version and release notes are not vendored; the release note describes only the three BLE fixes above. |
| Generated release docs | `0dbc9e9` | Non-runtime. `docs/manual` HTML, build metadata, search index and intersphinx inventory only; the `RNS` tree is identical to its parent. |

All six canonical commits have exactly one non-empty local mapping with one full
`Upstream-Commit` trailer, in ancestry order. The audit lists every mapping and
its evidence. No unresolved implementation dispositions remain.

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No wire or crypto surface changed; historical fixture suites remained byte-stable. |
| Transport and interfaces | No Rust transport or interface code changed. The serial RNode detect/configure path in `rns-net/src/interface/rnode/` is unaffected. |
| Links, channels and resources | No change. |
| Utilities and APIs | No change. |
| Live interop | Not applicable to `1.5.4`: no externally visible behavior changed and GitHub has not mirrored the release. The impaired dual-VPS daily smoke on local `9b6bfb4` passed the same day. |

## Acceptance Record

| Gate | Result |
|---|---|
| Focused regression suites | Not applicable; no runtime behavior changed, so no focused regression was required. |
| Fixture regeneration/provenance | Unchanged; no regeneration needed. |
| Exact-target Python/Rust interop | Not applicable; no wire or externally visible behavior changed and the target is not on GitHub. |
| Workspace and feature suites | `cargo test --workspace` passed on 2026-09-12: 2,517 passed, 0 failed. |
| Formatting and lint | `cargo fmt --check` passed; `scripts/lint-host.sh` (Clippy `-D warnings`, `--all-targets`) passed. |
| Release/cross builds | Host native-hook release builds of `rns-server` and `rns-ctl` passed on 2026-09-12 and supplied the daily smoke binaries. ARMv7 cross-builds were not rerun for this docs-only advancement. |
| Docker E2E | Not rerun for a docs-only advancement. |
| Hardware/manual validation | Impaired dual-VPS `--daily` smoke passed all Resource boundaries, concurrent link stress and forced Backbone reconnect on 2026-09-12. Physical Weave HIL is explicitly unclaimed. |
| Post-promotion freshness | Both remotes refreshed; rgit equals the accepted checkout with zero commits ahead. GitHub remains behind. |

The mapping commits and their gate evidence are recorded in the audit. The only
source changes in this range are inside the upstream Python BLE client, which
has no native counterpart.

## Caveats and Deferred Validation

- GitHub still trails rgit; the GitHub-backed CI interoperability pin remains at
  the preceding fetchable release (`1.5.2`).
- Physical Weave HIL is unavailable, carrying the existing hardware caveat.
- No signed `1.5.4` tag exists; acceptance is of the canonical rgit commit.
- The three BLE fixes are upstream-runtime behavior with no Rust equivalent. If
  rns-rs ever gains a host-side RNode BLE client, these changes would need to be
  ported to that new surface.

## Promotion Result

Reticulum 1.5.4 is accepted at
`0dbc9e90a33c427befd3873aa29bd6e8463ba192`. [UPSTREAM.md](../../UPSTREAM.md)
records the promoted normative commit and links this acceptance authority.
