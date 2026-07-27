# Reticulum 1.4.1 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.4.0` |
| Previous normative commit | `122f17fad69a483503cc5c1d8d81046712d78c96` |
| Accepted version | `1.4.1` |
| Normative tag or ref | Signed tag `1.4.1` |
| Normative commit | `b2188ce9a746a35b770b10bea1b7ccbe93b4e198` |
| Root tree | `28356de6a3562989367859b50ff584e334e4abb4` |
| `RNS` tree | `da3ed5fb64f432b04aa387576701182b8c82df8d` |
| Version assertion | `RNS.__version__ == "1.4.1"` |
| Audited range | `122f17fad69a483503cc5c1d8d81046712d78c96..b2188ce9a746a35b770b10bea1b7ccbe93b4e198` |
| Commits audited | 32 |
| Acceptance date | `2026-07-26` |
| Detailed audit | [reticulum-1.4.1-audit.md](reticulum-1.4.1-audit.md) |

The normative commit is the signed release-tag target and is present in both
the rgit normative repository and GitHub release mirror. Historical 1.4.0
fixtures retain their original provenance; the live interop lane, rather than
fixture regeneration, advances to the exact 1.4.1 runtime.

## Upstream Commit Audit

Every commit in the 32-commit range has a final disposition in the detailed
audit. The principal compatibility groups are:

| Area | Upstream commits | Final handling |
|---|---|---|
| Boundary routing and internal announces | `b051e76d`, `1af173e8`, `bebf211b`, `9bc73819`, `0f33d719` | Runtime behavior, configuration, discovery policy, and native documentation integrated with focused coverage. |
| Interface gravity and path selection | `c10c465c`, `5577e781`, `3ca71527`, `566aa68f`, `889c5ff5`, `c4297d31`, `4631d78b`, `b2188ce9` | Gravity configuration, inheritance, status, selection, and final logging policy integrated. |
| Authenticated link-path rebalancing | `90e1dbb9`, `6d4523c2`, `93526c17`, `bce5f859` | Signed rebalancing, bounded one-shot state, and diagnostics integrated and regression tested. |
| I2P and platform-specific lifecycle | `a4b61298`, `c25b56db`, `00d57a22` | Applicable I2P hardening integrated; Python-specific task ownership and Darwin construction are structurally covered by the Rust architecture. |
| Channels, requests, and responses | `a29a0871`, `1ecf845c`, `6a761a76`, `12c21d4e` | Channel receive-window and request/response bounds integrated; upstream-only test cleanup audited as non-runtime. |
| Discovery cleanup and utilities | `e46b012e`, `e29b8394` | rnsh logging separation and blackhole-aware historical discovery cleanup integrated. |
| Metadata and generated documentation | `224124aa`, `e5d37355`, `0d16e230` | Tracking metadata updated, changelog audited without vendoring, and applicable native documentation integrated. |
| Structurally covered fixes | `48388756`, `7611fca6`, `cbf50460` | Existing Rust invariants already provide the compatible behavior; focused evidence is recorded in the audit. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Transport and interfaces | Focused tests cover boundary path requests, per-interface internal announce overrides, discovery auto-connect modes, gravity selection, and dynamic-child inheritance. |
| Links and routing | Signed LRPROOF rebalancing, expected-hop mutation, one-shot limits, and gravity/path diagnostics have focused regressions. |
| Channels and application APIs | Channel receive-window bounds and destination/request response-size limits are covered by affected crate suites. |
| I2P, discovery, and utilities | I2P SAM failure handling, blackholed discovery cleanup, and separated rnsh initiator logging are regression tested. |
| Fixture provenance | Historical 1.4.0 fixtures remain independently pinned and tested. No 1.4.1 fixture provenance is claimed. |
| Live interop | Exact Reticulum 1.4.1 Python/Rust bidirectional TCP interop passed locally on 2026-07-26 and is repeated by CI. |

## Acceptance Record

| Gate | Result |
|---|---|
| Commit disposition | All 32 upstream commits have final implementation evidence or an explicit no-action rationale. |
| Focused regression suites | Passed during sequential integration. |
| Exact-target Python/Rust interop | Passed locally on 2026-07-26 against `b2188ce9`. |
| Workspace and all-target checks | Passed during integration; PR CI remains the final clean-environment authority. |
| Fixture policy | Existing 1.4.0 fixtures retained with unchanged provenance; live interop advanced to 1.4.1. |
| Physical Weave HIL | Not rerun and not claimed by this promotion. |
| Dual-VPS manual acceptance | Not rerun and not claimed by this promotion. |

## Caveats and Deferred Validation

- Physical Weave HIL remains outside this software-only promotion.
- Dual-VPS manual Backbone acceptance was not rerun.
- Python-only task ownership and Darwin interface-construction changes are
  structurally inapplicable to the Rust architecture.
- Generated upstream manuals and changelog text are not vendored.

## Promotion Result

Reticulum 1.4.1 was accepted as the rns-rs upstream reference baseline at
normative commit `b2188ce9a746a35b770b10bea1b7ccbe93b4e198`. `UPSTREAM.md`
records the promoted baseline and its exact repository and tree provenance.
