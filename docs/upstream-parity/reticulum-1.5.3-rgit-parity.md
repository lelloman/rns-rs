# Reticulum 1.5.3 rgit Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.5.3` |
| Previous normative commit | `0bb41bf9486c1469854876a3c1d7c57324efc7c4` |
| Accepted version | `1.5.3` rgit |
| Normative tag or ref | Canonical `rgit/master` at acceptance |
| Normative commit | `fae64abf05a0ec5afabb2def9076f70d42bfe600` |
| Root tree | `b604b6447b083dc3188acc76a24b7ad063f9b732` |
| `RNS` tree | `d901a4098fa0c17da8c6dc3ce36634793f71d62b` |
| Version assertion | `RNS.__version__ == "1.5.3"` |
| Audited range | `0bb41bf9486c1469854876a3c1d7c57324efc7c4..fae64abf05a0ec5afabb2def9076f70d42bfe600` |
| Acceptance date | `2026-09-11` |
| Detailed audit | [reticulum-1.5.3-rgit-audit.md](reticulum-1.5.3-rgit-audit.md) |

This accepts the canonical rgit commit, not a verified signed release tag.
Both remotes refreshed successfully before promotion at 08:16:52/08:17:00 UTC.
GitHub remains behind at `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6`; CI retains
its fetchable GitHub pin. Historical fixtures are unchanged and retain their
recorded provenance. Existing 1.5.3 records remain point-in-time evidence.

## Upstream Commit Audit

| Area | Upstream commits | Final handling |
|---|---|---|
| Work lifecycle | `b0933d5c`, `409380a4` | Integrated activation from proposed scope and author/admin transitions, preserving stored authorship and explicit document denial. |
| Request context and denial disclosure | `859dc818`, `36a62e7b` | Structurally covered by one owned request supplying storage/ACL context and generic wire denial responses. |
| Permission updates | `f231fdcb` | Existing per-check sidecar reads provide immediate visibility; added executable-resolver protection and explicit binary status encoding. |
| Standalone WebP helper | `e7a7c48c` | Public native file-conversion API with quality, bounded dimensions, timeout and owned temporary-file cleanup. |
| Whitespace, changelog and generated docs | `87823c09`, `7330c20c`, `fae64abf` | Non-runtime; full diffs and generated artifacts inspected, no upstream documentation vendoring. |

All nine canonical commits have exactly one non-empty local mapping with one
full `Upstream-Commit` trailer, in ancestry order. The audit lists every mapping
and its focused evidence. No unresolved implementation dispositions remain.

## Compatibility Evidence

| Surface | Evidence |
|---|---|
| Wire and crypto | Historical fixture suites and both workspace configurations passed; fixture trees unchanged. |
| Transport and interfaces | 955 default / 961 hook-enabled network unit tests and 56 network E2E tests in each configuration passed. |
| Links, channels and resources | Exact-target Python protocol test, Docker matrix and impaired dual-VPS daily smoke passed. |
| Utilities and APIs | rngit: 211 library and 23 integration tests passed; two real-encoder tests passed with default and ffmpeg backends. New lifecycle, ACL visibility, resolver guard and file conversion regressions passed. |
| Live interop | Python at `fae64abf`: packet/link/Resource test, five utility cases, signed work lifecycle, cross-author admin transitions, permission set/get and resolver rejection, media bytes/dimensions/metadata all passed. |

## Acceptance Record

Runtime source last changed in `cfb946c`; subsequent mapping commits through
`38372a5` contain documentation only. The live integration binary was
`rns-server 0.3.1252-38372a5`. All results were obtained locally on 2026-09-11.

| Gate | Result |
|---|---|
| Focused regressions | Passed; pre-fix failures recorded for proposed activation, administrator transitions and executable-resolver protection. |
| Fixture provenance | Unchanged; no regeneration needed for this rngit range. |
| Exact-target Python/Rust interop | Passed against detached `fae64abf` checkout. |
| Workspace and feature suites | Default: 2,517 passed; hooks: 2,562 passed. Four built-in network hook checks, one control-plane lifecycle check and TLS suites passed separately. |
| Formatting and lint | Passed; 19 Python tool tests, four web UI smoke tests and all WASM example builds also passed. |
| Release/cross builds | Host release workspace with native hooks passed. ARMv7 rnsd/rns-ctl without and with native hooks, and rns-server with built-in hooks passed. |
| Docker E2E | All 11 rounds passed in 1,060 seconds: topology summary 102 passed/0 failed/29 topology skips; standalone reconnect 11, supervision 84, NAT 12 and tunnel 29 assertions passed. |
| Hardware/manual validation | Integration daily VPS smoke passed all Resource boundaries, concurrent links, impairment and forced reconnect. Physical Weave HIL is explicitly unclaimed. |
| Post-promotion freshness | Both remotes refreshed at 08:18:44/08:18:49 UTC; rgit equals the accepted checkout and zero commits are ahead. GitHub remains behind. |

Detailed command results and local log paths are in the audit. The earlier
daily report's first smoke attempt timed out and its reproduction passed;
the later integration smoke passed completely. An initial ARM invocation used
the host linker and failed; rerunning with the CI cross-linker settings passed
all five required builds.

## Caveats and Deferred Validation

- GitHub still trails rgit; the GitHub-backed CI interoperability pin remains
  at the preceding fetchable release.
- Physical Weave HIL is unavailable, carrying the existing hardware caveat.
- Rust file conversion uses typed options and returns a `NamedTempFile` deleted
  on drop; callers explicitly persist it when needed. Python returns a path.
- The existing native generic denial text is lowercase `not allowed` while
  upstream uses `Not allowed`; status and information disclosure agree.

## Promotion Result

Reticulum 1.5.3 rgit is accepted at
`fae64abf05a0ec5afabb2def9076f70d42bfe600`. [UPSTREAM.md](../../UPSTREAM.md)
records the promoted normative commit and links this acceptance authority.
