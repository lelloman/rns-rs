# Reticulum 1.5.2 rgit Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.2` |
| Previous normative commit | `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6` |
| Accepted version | `1.5.2` rgit |
| Normative tag or ref | `rgit/master` at promotion time |
| Normative commit | `3bc149e3d587695f52e695f18edb11751b21c005` |
| Root tree | `56c3051a72f953fd55f90e09c28ff33c09e1f002` |
| `RNS` tree | `7ec05287f5a6d9a476d3aba3aaf5789dd5766011` |
| Version assertion | `RNS.__version__ == "1.5.2"` |
| Audited range | `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6..3bc149e3d587695f52e695f18edb11751b21c005` |
| Acceptance date | `2026-09-01` |
| Detailed audit | [reticulum-1.5.2-rgit-audit.md](reticulum-1.5.2-rgit-audit.md) |

Canonical rgit advanced by two development commits while retaining the 1.5.2
version assertion. GitHub remained at the signed 1.5.2 baseline and could not
supply the exact normative object, so the GitHub-backed CI interop pin remains
at that fetchable release target. Exact-target acceptance used a detached
worktree created from the freshly fetched canonical object. Historical fixture
provenance is unchanged.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| HDLC and interfaces | 1 | Integrated canonical single-allocation framing in the shared helper used by Backbone and Local writers, with exact all-byte wire-output coverage. |
| rgit pages and operator configuration | 2 | Integrated the default and customizable `no_ident.mu` page across every registered page path when the null identity is blocked, with focused behavior tests and documentation. |

Both upstream hashes occur exactly once as full `Upstream-Commit` trailers in
local ancestry order, and both mapping commits are non-empty. Both final
dispositions are Integrated.

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | All 21 focused HDLC tests and the full hook-enabled workspace/fixture suites passed; the canonical framing regression covers every byte value and exact output size. |
| Transport and interfaces | 946 `rns-net` unit tests and all 54 network E2E tests passed serially; exact-target live packet traffic passed in both directions. |
| Links, channels, and resources | Exact-target link and Resource interoperability passed; the daily dual-VPS and Docker matrices covered Channels, Resources, impairment, reconnect and multihop routing. |
| Utilities and APIs | All 222 `rns-git` tests passed; the page-template tests cover all paths, identified/unidentified boundaries and custom override behavior. All five exact-target `rncp`/`rnx` cases passed. |
| Live interop | Reticulum `3bc149e3`, `RNS` tree `7ec05287`, and version 1.5.2 passed bidirectional packet, link, Resource and utility interoperability on 2026-09-01. |

## Acceptance Record

| Gate | Result |
|---|---|
| Focused regression suites | 21 HDLC tests and 222 complete `rns-git` tests passed locally on 2026-09-01. |
| Fixture regeneration/provenance | No regeneration required; historical provenance is unchanged and all fixture suites remained byte-stable. |
| Exact-target Python/Rust interop | Packet, link, Resource and all five utility cases passed locally against `3bc149e3` on 2026-09-01. |
| Workspace and feature suites | Serialized `cargo test --workspace --features rns-hooks` passed, including 946 `rns-net` unit and 54 network E2E tests. |
| Formatting and lint | `cargo fmt --check`, `git diff --check`, warning-free host lint, 19 Python tool tests, web UI smoke, TLS and built-in hook integration passed. |
| Release/cross builds | Full hook-enabled host release workspace build passed. ARMv7 no-hook, native-hook and built-in-hook runtime builds all passed. |
| Docker E2E | All 11 matrix runs passed: 102 assertions, 0 failures, including chain/star/mesh/scale, reconnect, supervision, NAT and privileged tunnel coverage. |
| Hardware/manual validation | The impaired dual-VPS daily smoke passed with forced reconnect recovery. Physical Weave HIL was unavailable and is explicitly unclaimed. |
| Post-promotion drift check | Fresh checks on 2026-09-02 found canonical rgit exactly at `3bc149e3` with zero commits ahead; GitHub remained behind at the signed 1.5.2 release. |

## Caveats and Deferred Validation

- GitHub still trails canonical rgit, so CI cannot fetch the accepted commit by
  SHA and retains the signed-release exact-target pin.
- Physical Weave HIL was not available and is not claimed.

## Promotion Result

Reticulum 1.5.2 rgit is accepted as the rns-rs upstream reference baseline at
normative commit `3bc149e3d587695f52e695f18edb11751b21c005`.
[UPSTREAM.md](../../UPSTREAM.md) records the promoted baseline and exact tree
provenance.
