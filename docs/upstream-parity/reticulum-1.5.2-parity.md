# Reticulum 1.5.2 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.0` rgit |
| Previous normative commit | `d80245b62c7169f68995b2f11b30b971de7a5dbf` |
| Accepted version | `1.5.2` |
| Normative tag or ref | `1.5.2` |
| Normative commit | `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6` |
| Root tree | `c2471478c17f2723a7dd6eabd0b85942c9402baf` |
| `RNS` tree | `926167c7552b5bb538ff46cdd19b3ee2d16827b3` |
| Version assertion | `RNS.__version__ == "1.5.2"` |
| Audited range | `d80245b62c7169f68995b2f11b30b971de7a5dbf..ea98db4f53dcf0defc0e71a16e60d28b1229c4e6` |
| Acceptance date | `2026-08-29` |
| Detailed audit | [reticulum-1.5.2-audit.md](reticulum-1.5.2-audit.md) |

Canonical rgit and the GitHub mirror agreed at the tagged 1.5.2 target during
promotion. Historical fixtures retain their recorded source provenance; live
interop and the CI matrix advance to the exact target commit and `RNS` tree.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Dataplane control and interfaces | 1–12, 34, 39–43 | Integrated ingress producer gating, optimized HDLC decoding, coalesced bounded writes, egress hysteresis/drop/status behavior, raw empty-frame rejection, Local exemption, and final 90/68/10 ingress defaults. |
| Resources and page paths | 18, 31, 35, 40 | Integrated exact blob-path normalization and strengthened native stream segmentation/flush invariants. |
| Configuration and utilities | 45, 47 | Added the null-identity blocking example; native access-denial handlers already preserve upstream behavior without noisy warnings. |
| Language, build, release, and generated artifacts | 13–30, 32–33, 36–38, 42, 44, 46, 48 | Statically or architecturally covered where applicable; Python/Cython packaging and release-only changes are non-runtime. |

All 48 upstream hashes occur exactly once as full `Upstream-Commit` trailers
in local ancestry order, and every mapping commit is non-empty. Final
dispositions are 15 Integrated, 12 Structurally covered, and 21 Non-runtime.

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Full hook-enabled workspace and fixture suites passed; exact-target live packet traffic passed in both directions. |
| Transport and interfaces | Focused ingress/egress, HDLC, transmit-buffer, Backbone, Local, UDP, and status regressions passed, followed by 940 `rns-net` unit tests and 54 network E2E tests. |
| Links, channels, and resources | Exact-target link and Resource interoperability passed; workspace E2E covered Channels, multipart Resources, and reconnect behavior. |
| Utilities and APIs | Status/RPC/CLI regressions passed, including transmit metrics; all five exact-target `rncp`/`rnx` utility cases passed. |
| Live interop | Reticulum `ea98db4f`, `RNS` tree `926167c7`, and version 1.5.2 passed bidirectional packet, link, Resource, and utility interoperability on 2026-08-29. |

## Acceptance Record

| Gate | Result |
|---|---|
| Focused regression suites | Passed locally on 2026-08-29 for every applicable mapped behavior. |
| Fixture regeneration/provenance | No regeneration required; historical provenance is unchanged and all fixture suites remained byte-stable. |
| Exact-target Python/Rust interop | Packet, link, Resource, and all five utility cases passed locally against `ea98db4f` on 2026-08-29. |
| Workspace and feature suites | Hook-enabled workspace passed serially, including 940 `rns-net` unit and 54 network E2E tests. Two load-sensitive parallel failures passed in isolation and did not recur in the complete serialized run. |
| Formatting and lint | `cargo fmt --all -- --check`, warning-free host lint, `git diff --check`, Python tool tests, and web UI smoke tests passed. |
| Release/cross builds | Hook-enabled host release workspace build passed. ARMv7 was not rerun and remains CI-authoritative. |
| Docker E2E | Not rerun for 1.5.2 and explicitly unclaimed. |
| Hardware/manual validation | Dual-VPS daily smoke passed on 2026-08-29; physical Weave HIL was unavailable and is explicitly unclaimed. |

## Caveats and Deferred Validation

- The Docker topology E2E matrix was not rerun for this promotion.
- The ARMv7 cross-build was not rerun locally and remains CI-authoritative.
- Physical Weave HIL was not available and is not claimed.
- Two parallel full-workspace attempts exposed different load-sensitive E2E
  failures; both cases passed in isolation, and the authoritative serialized
  hook-enabled workspace run completed without failures.
- Upstream Python/Cython benchmark and packaging machinery and generated
  release documentation are not vendored; no cross-language performance
  equivalence is claimed.

## Promotion Result

Reticulum 1.5.2 is accepted as the rns-rs upstream reference baseline at
normative commit `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6`.
[UPSTREAM.md](../../UPSTREAM.md) records the promoted baseline and exact tree
provenance.
