# Reticulum 1.5.6 rgit Advancement Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.6` |
| Previous normative commit | `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62` |
| Accepted version | `1.5.6` |
| Normative tag or ref | Canonical `rgit/master` (GitHub mirror still at `e40191b3`) |
| Normative commit | `49ae71e06cadf5d846849661578a8ad9fcede443` |
| Root tree | `6a2af93c968be263dc918c2288f3553e2553c1e5` |
| `RNS` tree | `def82bf5dd3c9686e798ca032927d2e625829b50` |
| Version assertion | Target `RNS/_version.py` declares `1.5.6` |
| Audited range | `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62..49ae71e06cadf5d846849661578a8ad9fcede443` |
| Acceptance date | `2026-10-02` |
| Detailed audit | [reticulum-1.5.6-rgit-audit.md](reticulum-1.5.6-rgit-audit.md) |

This accepts a same-version canonical development tip, not a new signed
release. Both upstream remotes were freshly fetched; the canonical rgit tip
advanced while the GitHub mirror remained at `e40191b3`. The target `RNS` tree is
identical to the previously accepted baseline
(`def82bf5dd3c9686e798ca032927d2e625829b50`); only the root tree differs because
the two commits edit the upstream changelog and regenerate the manual. Historical
fixtures and their provenance remain unchanged.

## Upstream Commit Audit

Both commits have final **Non-runtime** dispositions and separate, non-empty
local mapping commits in upstream ancestry order. The detailed audit records
full hashes, changed paths, review rationale, and the verified unique
`Upstream-Commit` trailers.

| Area | Upstream commits | Final handling |
|---|---|---|
| Upstream changelog | `1e6ebd3f` | `Changelog.md` release-note edits; not vendored and with no Rust runtime counterpart. |
| Generated upstream manual | `49ae71e0` | Regenerated `docs/manual/` Sphinx output; not vendored; the `RNS` tree is unchanged. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No `RNS` change; wire and crypto behavior and native fixtures are unchanged. |
| Transport and interfaces | No observable runtime delta; workspace and feature suites plus the daily live-fabric test passed. |
| Links, channels, and resources | Daily impaired dual-VPS test passed all configured Resource boundaries, concurrency, and forced reconnect recovery. |
| Utilities and APIs | Documentation-only upstream changes; no native utility or API behavior is affected. |
| Live interop | Not rerun: the runtime tree is byte-identical to the accepted 1.5.6 baseline. |

## Acceptance Record

All results below were obtained on 2026-10-02. No planned test is counted as
passed.

| Gate | Result |
|---|---|
| Focused regression suites | Inapplicable: full diff review establishes documentation-only changes. |
| Fixture regeneration/provenance | No regeneration; historical fixtures and provenance unchanged. |
| Exact-target Python/Rust interop | Not rerun for this non-runtime advancement; the runtime tree is identical to the accepted baseline. |
| Workspace and feature suites | `cargo test --workspace` passed (2,547) and `cargo test --workspace --features rns-hooks` passed (2,594, 0 failed). An initial full-workspace run had two transient `rns-git` Python-interop failures that passed in isolation and on rerun. |
| Formatting and lint | `cargo fmt --check` and `bash scripts/lint-host.sh` passed. |
| Release/cross builds | Native-hook `rns-server` and `rns-ctl` release builds passed (`0.3.1417-ae9a5c5` / `0.4.1417-ae9a5c5`). No new cross-build claimed. |
| Docker E2E | Not rerun for this non-runtime advancement. |
| Hardware/manual validation | Daily impaired dual-VPS stress passed four Resource sizes through 1 MiB, concurrent Resources and links, and forced reconnect recovery. Physical hardware validation remains unclaimed. |

## Caveats and Deferred Validation

This accepts only the reviewed two-commit delta and does not broaden prior
compatibility or hardware claims. Exact-target interop, optional-feature
matrices, Docker, cross-builds, and physical hardware were not rerun at
acceptance. The GitHub mirror lagged the canonical rgit tip at acceptance.

## Promotion Result

Reticulum 1.5.6 is accepted at `49ae71e06cadf5d846849661578a8ad9fcede443` as a
same-version canonical rgit advancement. [UPSTREAM.md](../../UPSTREAM.md) records
this normative baseline. Both observed commits are dispositioned; no runtime port
remains outstanding.
