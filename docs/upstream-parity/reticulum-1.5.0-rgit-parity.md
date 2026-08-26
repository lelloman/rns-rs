# Reticulum 1.5.0 rgit Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.0` rgit |
| Previous normative commit | `b3ef214e7257a1e5b674f8b1f002f05e78b090b8` |
| Accepted version | `1.5.0` rgit |
| Normative tag or ref | `rgit/master` at promotion time |
| Normative commit | `d80245b62c7169f68995b2f11b30b971de7a5dbf` |
| Root tree | `65b89f07749b33027b6e9b26410c826ff6e11b2a` |
| `RNS` tree | `131b3b0dcd512eb838bb79a574ec308477d49ae8` |
| Version assertion | `RNS.__version__ == "1.5.0"` |
| Audited range | `b3ef214e7257a1e5b674f8b1f002f05e78b090b8..d80245b62c7169f68995b2f11b30b971de7a5dbf` |
| Commits audited | 69 |
| Acceptance date | `2026-08-26` |
| Detailed audit | [reticulum-1.5.0-rgit-audit.md](reticulum-1.5.0-rgit-audit.md) |

The normative rgit development line advanced while retaining the same 1.5.0
version assertion. A fresh promotion-time fetch resolved canonical rgit
`master` to the accepted commit. GitHub `master` remained at `b123a756`, so the
mirror could not supply the exact normative object and the CI interop pin
remains at the fetchable signed-release target. Historical fixture provenance
is unchanged; exact-target live interoperability used a disposable extraction
of the canonical commit.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Transport, routing, and links | 74–81, 83–85, 89–90, 93–107, 114, 118–121, 129, 131–134, 141–142 | Integrated applicable packet validity, violation accounting, lookup, caching, timeout, MTU, queue, and traffic-class behavior; native ownership invariants structurally cover lock and lifecycle-only changes. |
| Status, RPC, and utilities | 75–77, 87–92, 108–113 | Integrated traffic/link/interface statistics, adaptive utility timeouts, discovery metadata, logging policy, and live profiler reporting across local and remote status surfaces. |
| Queueing and announce handling | 79–81, 84, 122–123, 136, 138, 140, 142 | Integrated independent queue defaults, announce retention, automatic MTU boundaries, protocol violations, and monotonic ingress-limited classification with focused saturation and boundary regressions. |
| Crypto and wire validation | 96–104, 124–126, 142 | Added IFAC/HKDF vectors and optimized-path coverage, bounded announce-signature caching, zero-length packet rejection, and exact-target interoperability evidence. |
| Benchmarks, merges, and source-only changes | 82, 86, 102, 106, 116–117, 127–128, 130, 132, 134–135, 137, 139 | Reviewed completely and mapped as structurally covered or non-runtime; benchmark-private capacity and labels do not alter production protocol limits. |

All 69 upstream hashes occur exactly once as full `Upstream-Commit` trailers
in local ancestry order. Every mapping commit is non-empty. Final dispositions
are 30 Integrated, 24 Structurally covered, and 15 Non-runtime.

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Full `rns-core` and `rns-net` suites passed, including fixture and Python interoperability tests; IFAC, HKDF, packet validity, announce signature, and malformed-input regressions cover the changed boundaries. |
| Transport and interfaces | Queue saturation/priority, protocol counters, adaptive timeouts, path-request batching, MTU selection, discovery, Backbone aggregation, and reconnect regressions passed. |
| Links, channels, and resources | Full feature-enabled workspace and 54-test network E2E suites passed; the daily dual-VPS run covered links, Channels, concurrent Resources, impairment, stress, and forced reconnect. |
| Utilities and APIs | Status/RPC/CLI focused tests and all five ignored `rncp`/`rnx` exact-target utility interoperability tests passed. |
| Live interop | Reticulum `d80245b6`, `RNS` tree `131b3b0d`, and version 1.5.0 passed bidirectional packet, link, Resource, and utility interoperability on 2026-08-26. |

## Acceptance Record

| Gate | Result |
|---|---|
| Commit disposition | All 69 commits have one final disposition and one ordered, non-empty local mapping. |
| Focused regression suites | Passed locally on 2026-08-26; complete `rns-core` and `rns-net` suites passed after the final mapping. |
| Fixture regeneration/provenance | Existing fixtures and their source provenance remain byte-stable; no target change required regeneration. |
| Exact-target Python/Rust interop | Packet, link, Resource, and all five utility cases passed locally against `d80245b6` on 2026-08-26. |
| Workspace and feature suites | `cargo test --workspace --features rns-hooks` passed locally, including 54 network E2E tests. |
| Formatting and lint | `cargo fmt --all -- --check`, warning-free host lint, `git diff --check`, and the web UI smoke tests passed. |
| Release/cross builds | Full hook-enabled host release build passed. The local ARMv7 attempt was inconclusive because the host cross-toolchain assembler rejected jemalloc output; ARMv7 remains CI-authoritative and is not claimed locally. |
| Docker E2E | The release image built successfully after constraining Docker release-build concurrency, codegen units, and stack size for this host. The topology matrix was not rerun and is not claimed. |
| Hardware/manual validation | Dual-VPS daily Backbone smoke passed on 2026-08-26, including impairment and forced reconnect. Physical Weave HIL was not available and is explicitly unclaimed. |

## Caveats and Deferred Validation

- GitHub `master` still trails canonical rgit, so CI cannot fetch the accepted
  commit by SHA and retains the signed-release exact-target pin.
- Physical Weave HIL was not rerun and is not claimed.
- The local ARMv7 cross-build did not complete because this host's cross
  assembler rejected generated jemalloc assembly. The host release build and
  Docker image build passed; the ARMv7 lane remains CI-authoritative.
- The Docker image build passed, but the topology E2E matrix was not rerun and
  is not claimed by this promotion.
- Upstream benchmark-only harness changes and generated documentation are not
  vendored. No cross-language performance equivalence is claimed.

## Promotion Result

Reticulum 1.5.0 rgit is accepted as the rns-rs upstream reference baseline at
normative commit `d80245b62c7169f68995b2f11b30b971de7a5dbf`.
[UPSTREAM.md](../../UPSTREAM.md) records the promoted baseline and exact tree
provenance.
