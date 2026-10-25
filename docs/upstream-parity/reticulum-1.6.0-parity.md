# Reticulum 1.6.0 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.7` |
| Previous normative commit | `ee82fa75a75ec67555126eb16796ea1a52716a2b` |
| Accepted version | `1.6.0` |
| Normative tag or ref | Canonical `rgit/master` tip (no signed `1.6.0` tag; upstream changelog marks the release `Pending`; GitHub mirror behind at `e40191b3`) |
| Normative commit | `9a01a20ce66c4146dd8f8d31f18c19fe7600739d` |
| Root tree | `5c1bcc90971538c5df028fd9a40dc2e3cd1a5d94` |
| `RNS` tree | `461df28e901e3dd8ed3877a375c28e11a9fd2a0e` |
| Version assertion | `RNS.__version__ == "1.6.0"` |
| Audited range | `ee82fa75a75ec67555126eb16796ea1a52716a2b..9a01a20ce66c4146dd8f8d31f18c19fe7600739d` |
| Acceptance date | `2026-10-25` |
| Detailed audit | [reticulum-1.6.0-audit.md](reticulum-1.6.0-audit.md) |

This accepts a canonical `rgit/master` development tip, not a signed release.
Both remotes were freshly fetched; the GitHub mirror remained behind the
accepted 1.5.7 baseline while the canonical rgit tip advanced eight commits and
declared version 1.6.0. No signed 1.6.0 tag exists and upstream's changelog
still marks the release pending, so the exact accepted target is the reviewed
commit above.

No wire or crypto fixture was regenerated or changed by this range. The native
transport-state format gained a used-timestamp field, and the new SQLite stores
have round-trip coverage; neither is a wire fixture.

## Upstream Commit Audit

Every commit has a final disposition and a unique non-empty mapping commit in
upstream ancestry order. The detailed audit records full hashes, changed paths,
and the mapping-hash table.

| Area | Upstream commits | Final handling |
|---|---|---|
| RNode ifstats | `f3ebec9` | Integrated: RSSI, SNR, signal quality, radio parameters, and modulation flow through native interface telemetry into status/RPC/API. |
| Paths and persistence | `e24d207` | Integrated: path usage and unused-pool culling, `rnpath --usage`, SQLite known-destination/ratchet and announce-cache stores with legacy import and file fallback, expanded status counters, and `link_distribution`. |
| Version and docs | `af8d058`, `4ebd4dc` | Non-runtime: version metadata and upstream documentation paths; native `rnsh` already uses the corrected `~/.rns` identity locations. |
| Internal stamps | `044d4c9` | Structurally covered: native stamp generation/validation already replaces the LXMF dependency; pinned by `generated_discovery_stamp_is_accepted_without_external_stamper`. |
| Memory management | `1562907`, `3e83fcc` | Structurally covered / deferred: Rust has no cyclic GC, and native jemalloc defaults are retained per `bench/relay/allocator-findings.md`; no production allocator change. |
| Discovery hop validation | `9a01a20` | Integrated: discoveries above `PATHFINDER_M-1` are rejected before stamp validation. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No wire or crypto changes in range. Exact-target interop and the workspace crypto suites pass. RustSec RUSTSEC-2026-0385 in `ctutils` was fixed by updating both lockfiles to `0.4.5`. |
| Transport and interfaces | Path usage/culling, pool counts, RNode phy telemetry, status counters, and discovery hop-gate regressions pass. Daily impaired dual-VPS Backbone smoke passes. |
| Links, channels, and resources | Workspace suites pass; the full Docker matrix passes 102 checks across 12 runs, including links, channels, resources, restart, scale, NAT hole punching, and shared-instance cases. |
| Utilities and APIs | `rnpath --usage`, the expanded status/RPC fields, and the SQLite storage backend are covered by focused tests and documented. |
| Live interop | Exact target `9a01a20`: `python_interop` 2/2 and `utility_interop` 6/6 pass. |

## Acceptance Record

| Gate | Result |
|---|---|
| Focused regression suites | Passed on 2026-10-25: SQLite known-destination/ratchet and announce-cache round trips, legacy imports, read-only and file fallback, path usage and pool culling, `path_pool_counts`, `link_distribution`, RNode phy telemetry, status counters, and discovery hop boundary. |
| Fixture regeneration/provenance | Not applicable: no wire, crypto, or fixture bytes changed. Transport-state and SQLite persistence round trips were added. |
| Exact-target Python/Rust interop | Passed on 2026-10-25 at `9a01a20`: `python_interop` 2/2, `utility_interop` 6/6. |
| Workspace and feature suites | `cargo test --workspace` passed; `cargo test --workspace --features rns-hooks` passed (rns-net 1,167); TLS suite passed 134; built-in hook integration passed 4/4 and the rns-ctl built-in hook API test passed. |
| Formatting and lint | `cargo fmt --all --check` and `bash scripts/lint-host.sh` passed. |
| Release/cross builds | Host native-hook builds produced `rns-server 0.6.1622-9174bd0` and `rns-ctl 0.7.1622-9174bd0`; all five ARMv7 build-smoke commands passed; `dist/rns-server-linux-x86_64.tar.gz` was produced. |
| Docker E2E | Full `tests/docker/run-all.sh` matrix passed: 12 runs, 102 checks passed, 0 failed, 29 skipped. The rns-server suite alone passed 84 checks. |
| Hardware/manual validation | The impaired dual-VPS `--daily` Backbone smoke passed on the integrated binary at 2026-10-25T07:49:23Z. Physical hardware validation remains unclaimed. |
| Python tools and web UI | Python tools compiled and all 19 unit tests passed; `node --test rns-ctl/assets/app.smoke.test.js` passed 4/4. |
| RustSec audit | `cargo audit` passed for the workspace and `rns-esp32/Cargo.lock` after `ctutils` moved to `0.4.5` (RUSTSEC-2026-0385). |

## Caveats and Deferred Validation

- This is a canonical rgit development-tip acceptance, not a signed 1.6.0
  release acceptance. The GitHub mirror lagged the accepted baseline, and
  upstream still marks 1.6.0 as pending.
- Physical hardware validation remains unclaimed.
- Memory-management changes are not ported: the native daemon keeps jemalloc
  defaults, and no RSS-gated trim or arena setting is enabled.
- The native shared-instance client does not own a known-destination table, and
  the SQLite `packet_hash` column is stored as zero because the native
  in-memory state does not retain the announce packet hash.
- The built-in hook e2e target required a non-incremental rebuild after a stale
  rlib symbol-index linker error; it then passed 4/4.
- No signature, signed release manifest, Android client, or ESP32 firmware
  validation is claimed by this promotion.

## Promotion Result

Reticulum is accepted at `1.6.0`, normative commit
`9a01a20ce66c4146dd8f8d31f18c19fe7600739d` as a canonical `rgit/master`
development tip. [UPSTREAM.md](../../UPSTREAM.md) records this baseline and
links this record; the detailed work record remains
[reticulum-1.6.0-audit.md](reticulum-1.6.0-audit.md).
