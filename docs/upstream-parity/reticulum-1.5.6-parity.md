# Reticulum 1.5.6 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.5` |
| Previous normative commit | `e40191b3d193b46b7f2d8a44424a594cd758839b` |
| Accepted version | `1.5.6` |
| Normative tag or ref | Canonical `rgit/master` (GitHub mirror not yet caught up) |
| Normative commit | `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62` |
| Root tree | `b6719f35e27d77d87e31c7ac9591a883948dcf83` |
| `RNS` tree | `def82bf5dd3c9686e798ca032927d2e625829b50` |
| Version assertion | Target `RNS/_version.py` declares `1.5.6` |
| Audited range | `e40191b3d193b46b7f2d8a44424a594cd758839b..2bae9ff0dca17ba39531d7f8c3078efd3a55ad62` |
| Acceptance date | `2026-10-02` |
| Detailed audit | [reticulum-1.5.6-audit.md](reticulum-1.5.6-audit.md) |

This accepts the canonical `rgit/master` development tip at Reticulum `1.5.6`.
The tip arrived as three commits on 2026-10-02 while the GitHub mirror remained
at the previously accepted `e40191b3`; mirror lag does not change the canonical
rgit baseline. Historical fixtures and their provenance are unchanged.

## Upstream Commit Audit

All three commits have final dispositions and separate, non-empty local mapping
commits in upstream ancestry order. The detailed audit records full hashes,
changed paths, review rationale, and the verified unique `Upstream-Commit`
trailers.

| Area | Upstream commits | Final handling |
|---|---|---|
| Discovery auto-connect | `d1a7e0c8` | Native auto-connect now requires `transport == true` discovery info first, even under the unverified-implementation override. |
| Discovery transport identity | `fca509ff` | A configured discoverable interface on a non-transport instance now enables the static transport identity. |
| Version metadata | `2bae9ff0` | Upstream `RNS/_version.py` moves to `1.5.6`; Rust crates remain independently versioned. |

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | No wire or crypto change; native fixtures are unchanged. |
| Transport and interfaces | Focused discovery auto-connect and static-transport-identity regressions pass. |
| Links, channels, and resources | Daily impaired dual-VPS test passed all configured Resource boundaries, concurrency, and forced reconnect recovery. |
| Utilities and APIs | No public utility or API surface changed. |
| Live interop | Not rerun: the changes affect local discovery decisions only and do not alter wire encoding. |

## Acceptance Record

All results below were obtained on 2026-10-02. No planned test is counted as
passed.

| Gate | Result |
|---|---|
| Focused regression suites | `discoverable_interface_forces_static_transport_identity_on_non_transport` and `discovered_peer_pool_requires_transport_enabled_interface` passed. |
| Fixture regeneration/provenance | No regeneration; historical fixtures and provenance unchanged. |
| Exact-target Python/Rust interop | Not rerun for this discovery-only delta. |
| Workspace and feature suites | `cargo test --workspace` passed; `cargo test --workspace --features rns-hooks` passed (2,594 passed, 0 failed). |
| Formatting and lint | `cargo fmt --check` and `bash scripts/lint-host.sh` passed. |
| Release/cross builds | Native-hook `rns-server` and `rns-ctl` release builds passed. No new cross-build claimed. |
| Docker E2E | Not rerun for this delta. |
| Hardware/manual validation | Daily impaired dual-VPS stress passed four Resource sizes through 1 MiB, concurrent Resources and links, and forced reconnect recovery. Physical hardware validation remains unclaimed. |

## Caveats and Deferred Validation

This accepts only the reviewed three-commit delta and does not broaden prior
compatibility or hardware claims. Exact-target interop, optional-feature
matrices, Docker, cross-builds, and physical hardware were not rerun at
acceptance. The GitHub mirror lagged the canonical rgit tip at acceptance. No
deployment of the `1.5.6` binaries to the VPS experiment nodes is part of this
acceptance.

## Promotion Result

Reticulum 1.5.6 is accepted at `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62`.
[UPSTREAM.md](../../UPSTREAM.md) records this normative baseline. All three
observed commits are dispositioned; no runtime port remains outstanding.
