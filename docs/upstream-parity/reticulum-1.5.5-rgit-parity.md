# Reticulum 1.5.5 rgit Advancement Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.5` |
| Previous normative commit | `7f2b3b9b524c9386316379af1313b43a5e4f7a5d` |
| Accepted version | `1.5.5` |
| Normative tag or ref | Canonical `rgit/master`, matching `origin/master` |
| Normative commit | `e40191b3d193b46b7f2d8a44424a594cd758839b` |
| Root tree | `ed83d80cd2ced7b41528f8e3f873b3bb54b62ad9` |
| `RNS` tree | `192d74c76e5c56046a411492f219db1833c99365` |
| Version assertion | Target `RNS/_version.py` declares `1.5.5` |
| Audited range | `7f2b3b9b524c9386316379af1313b43a5e4f7a5d..e40191b3d193b46b7f2d8a44424a594cd758839b` |
| Acceptance date | `2026-10-02` |
| Detailed audit | [reticulum-1.5.5-rgit-audit.md](reticulum-1.5.5-rgit-audit.md) |

This accepts a same-version canonical development tip, not a new signed
release. Both upstream remotes were freshly fetched and agree at the accepted
commit. The target `RNS` tree is identical to the previously accepted baseline
(`192d74c76e5c56046a411492f219db1833c99365`); only the root tree differs because
the single commit edits an upstream project-history document. Historical
fixtures and their provenance remain unchanged.

## Upstream Commit Audit

The one commit in range has a final **Non-runtime** disposition and a separate,
non-empty local mapping commit in upstream ancestry order. The detailed audit
records the full hash, changed paths, review rationale, and the verified unique
`Upstream-Commit` trailer.

| Area | Upstream commits | Final handling |
|---|---|---|
| Upstream project history documentation | `e40191b3` | Hyperlink-only edit under `docs/history/`; not vendored and with no Rust runtime counterpart, so `Non-runtime`. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No `RNS` change; wire and crypto behavior and native fixtures are unchanged. |
| Transport and interfaces | No observable runtime delta; workspace suite and daily live-fabric test passed. |
| Links, channels, and resources | Daily impaired dual-VPS test passed all configured Resource boundaries, concurrency, and forced reconnect recovery. |
| Utilities and APIs | Documentation-only upstream change; no native utility or API behavior is affected. |
| Live interop | Not rerun: the runtime tree is byte-identical to the accepted 1.5.5 baseline. |

## Acceptance Record

All results below were obtained on 2026-10-02. No planned test is counted as
passed.

| Gate | Result |
|---|---|
| Focused regression suites | Inapplicable: full diff review establishes that the sole change is a documentation-only hyperlink. |
| Fixture regeneration/provenance | No regeneration; historical fixtures and provenance unchanged. |
| Exact-target Python/Rust interop | Not rerun for this non-runtime advancement; the runtime tree is identical to the accepted 1.5.5 baseline. |
| Workspace and feature suites | `cargo test --workspace` passed. The accepted 1.5.5 workspace (2,545) and `rns-hooks` feature (2,592) suites were recorded on 2026-09-30 on the identical runtime tree `192d74c7`. |
| Formatting and lint | `cargo fmt --check` and `bash scripts/lint-host.sh` passed. |
| Release/cross builds | Native-hook `rns-server` and `rns-ctl` release builds passed. No new cross-build claimed. |
| Docker E2E | Not rerun for this non-runtime advancement. |
| Hardware/manual validation | Daily dual-VPS stress passed twice with four Resource sizes through 1 MiB, concurrent Resources and links, impairment, and forced reconnect recovery. Physical hardware validation remains unclaimed. |

## Caveats and Deferred Validation

This accepts only the reviewed one-commit delta and does not broaden prior
compatibility or hardware claims. Exact-target interop, optional-feature
matrices, Docker, cross-builds, and physical hardware were not rerun at
acceptance. Upstream editorial and legal opinions are not independently verified
or adopted as native findings.

## Promotion Result

Reticulum 1.5.5 is accepted at `e40191b3d193b46b7f2d8a44424a594cd758839b` as a
same-version canonical rgit advancement. [UPSTREAM.md](../../UPSTREAM.md) records
this normative baseline. The single observed commit is dispositioned; no runtime
port remains outstanding.
