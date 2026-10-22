# Reticulum 1.5.7 rgit Advancement Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.7` |
| Previous normative commit | `a29bfb51c468945c96a1ee22cae0114e993e2391` |
| Accepted version | `1.5.7` |
| Normative tag or ref | Canonical `rgit/master` tip (GitHub mirror behind at `e40191b3`) |
| Normative commit | `ee82fa75a75ec67555126eb16796ea1a52716a2b` |
| Root tree | `fde9c85ca4514cc3f1bd32280d19da870fad76a8` |
| `RNS` tree | `45eccb7ec1009d9b24f3d17f42d5cf8848537cec` |
| Version assertion | Target `RNS/_version.py` declares `1.5.7` |
| Audited range | `a29bfb51c468945c96a1ee22cae0114e993e2391..ee82fa75a75ec67555126eb16796ea1a52716a2b` |
| Acceptance date | `2026-10-22` |
| Detailed audit | [reticulum-1.5.7-rgit-audit.md](reticulum-1.5.7-rgit-audit.md) |

This accepts a same-version canonical development tip, not a new signed
release. Both upstream remotes were freshly fetched; the canonical rgit tip
advanced two commits past the accepted `1.5.7` baseline while the GitHub mirror
remained at `e40191b3` (behind the baseline, which is allowed). The target `RNS`
tree differs from the baseline (`c8cde8d0`) only through two Python-only files:
the rngit config-directory selection and the Android `RNodeInterface`
PHY-statistics flag. No native Rust runtime code changed; the local mappings
add focused regressions only. Historical fixtures and their provenance are
unchanged.

## Upstream Commit Audit

Every commit has a final disposition and a separate, non-empty local mapping
commit in upstream ancestry order. The detailed audit records full hashes,
changed paths, review rationale, and the verified unique `Upstream-Commit`
trailers.

| Area | Upstream commits | Final handling |
|---|---|---|
| Android RNode PHY statistics | `ee82fa75` | Structurally covered: rns-rs has no Python Android `RNodeInterface`, and the native RNode reader records RSSI/SNR unconditionally without a `reports_phy_stats` gate; the native invariant is pinned by `rnode_rx_metadata_reports_rssi_and_snr`. |
| rngit configuration path | `ae67448e` | Structurally covered: native `default_rngit_dir` already prefers `~/.config/rngit`; `default_rngit_dir_prefers_config_dir_over_legacy_path` covers the upstream mirror-vs-legacy branch. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No wire or crypto change in range; both upstream files are Python-only, and native fixtures and provenance are unchanged. |
| Transport and interfaces | Native RNode behavior is unchanged and the RSSI/SNR path is pinned by a focused regression; the daily impaired dual-VPS test passed all configured Resource boundaries, concurrency, and forced reconnect recovery. |
| Links, channels, and resources | Daily impaired dual-VPS test passed four Resource sizes through 1 MiB, concurrent links and Resources, and forced reconnect recovery. |
| Utilities and APIs | Native rngit configuration resolution already selects `~/.config/rngit` when present; the precedence regression records the behavior. |
| Live interop | Not rerun: the upstream delta is Python-only configuration and Android-interface code, no wire surface changed, and the native runtime is unchanged. |

## Acceptance Record

All results below were obtained on 2026-10-22. No planned test is counted as
passed.

| Gate | Result |
|---|---|
| Focused regression suites | All three `default_rngit_dir_*` tests and both RNode metadata tests passed. |
| Fixture regeneration/provenance | No regeneration; historical fixtures and provenance unchanged. |
| Exact-target Python/Rust interop | Not rerun; assessed inapplicable because the changed upstream files are Python rngit configuration selection and the Python Android RNode interface, and no native runtime code changed. |
| Workspace and feature suites | `cargo test --workspace` passed (2,888 tests, 0 failed). |
| Formatting and lint | `cargo fmt --all --check` and `bash scripts/lint-host.sh` passed. |
| Release builds | Native-hook `rns-server` and `rns-ctl` release builds passed (`0.6.1600-d06a2af` / `0.7.1600-d06a2af`). |
| Docker E2E | Not rerun for this test-only native delta. |
| Hardware/manual validation | Daily impaired dual-VPS `--daily` stress passed on 2026-10-22 on the unchanged native runtime; physical hardware validation remains unclaimed. |

## Caveats and Deferred Validation

This accepts only the reviewed two-commit delta and does not broaden prior
compatibility or hardware claims. The GitHub mirror lagged the canonical rgit
tip at acceptance. Docker, cross-builds, exact-target interop, and physical
hardware were not rerun at acceptance.

## Promotion Result

Reticulum 1.5.7 is accepted at
`ee82fa75a75ec67555126eb16796ea1a52716a2b` as a same-version canonical rgit
advancement. [UPSTREAM.md](../../UPSTREAM.md) records this normative baseline.
Both observed commits are dispositioned; no runtime port remains outstanding.
