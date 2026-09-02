# Reticulum 1.5.2 rgit Upstream Audit

## Scope and Baseline

- audit date: `2026-09-01`
- previous accepted version: `1.5.2`
- previous normative commit: `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6`
- target version: `1.5.2` (unchanged at the current rgit tip)
- target tag or ref: canonical rgit tip `3bc149e3d587695f52e695f18edb11751b21c005`
- target normative commit: `3bc149e3d587695f52e695f18edb11751b21c005`
- target root tree: `56c3051a72f953fd55f90e09c28ff33c09e1f002`
- target `RNS` tree: `7ec05287f5a6d9a476d3aba3aaf5789dd5766011`
- version assertion: `RNS.__version__ == "1.5.2"`
- audited range: `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6..3bc149e3d587695f52e695f18edb11751b21c005`
- commits in range: `2`
- repositories checked: canonical rgit and GitHub mirror
- local branch and revision inspected: `dev@9b9103295017cd54a54687172f380003246c9dca`, integrated through `b6d8f0b825e777607b077f673b56e3aca03d371f`

The 2026-09-01 promotion refresh completed successfully for both remotes. The
GitHub mirror remained at the accepted 1.5.2 baseline, while canonical rgit
advanced by the two commits inventoried below. The exact canonical target was
accepted as a qualified 1.5.2 rgit baseline after the gates below passed.

## Audit Vocabulary

- **Needs port**: compatible behavior is absent or observably different.
- **Needs coordinated port**: related changes must be implemented together.
- **Needs decision**: architecture differs and the compatibility surface must
  be chosen explicitly.
- **Integrated**: applicable behavior is implemented with recorded evidence.
- **Structurally covered**: the Rust design already provides the behavior or
  avoids the upstream failure through a different invariant.
- **Documentation follow-up**: native documentation is required after the
  related behavior exists.
- **Deferred**: applicable work is deliberately postponed with rationale and
  impact recorded.
- **Non-runtime**: metadata, changelog, generated artifacts, or upstream-only
  tests require no independent Rust runtime change.

## Commit Inventory

Every commit in the audited range appears exactly once.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `eb8414bee98f07009b021b0b453fc8563865bdf2` | Killed a couple of allocs, canonical HDLC frame method | Integrated | Local `0a8e543`; native `rns-net::hdlc::frame` emits escaped bytes and both flags directly into one exactly sized allocation. All 21 HDLC tests passed, including the new all-byte canonical-frame regression. |
| 2 | `3bc149e3d587695f52e695f18edb11751b21c005` | Added no_ident template support to rngit | Integrated | Local `b6d8f0b`; all registered page paths select the built-in or custom `no_ident.mu` response for a blocked null identity. Three focused regressions and the complete 222-test `rns-git` suite passed; operator documentation lists the template. |

## Per-Commit Analysis

### 1. `eb8414be` — Killed a couple of allocs, canonical HDLC frame method

**Upstream change:** Adds the canonical `HDLC.frame()` helper, which escapes a
payload and writes the opening and closing flags into one pre-sized byte array.
Backbone and both Local-interface send paths now call that helper instead of
assembling the same frame inline. The wire encoding is unchanged.

**Rust applicability:** Rust already centralized this operation in
`rns-net/src/hdlc.rs::frame`, which Backbone and Local writers both call, but
the helper first allocated an escaped buffer and then copied it into its framed
output. The upstream allocation cleanup therefore applied directly even though
there were no duplicate native call-site implementations.

**Local handling and evidence:** Local `0a8e543` writes escaped data and both
flags directly into a single allocation whose capacity is the exact on-wire
length. The new all-byte regression compares the canonical helper against
wrapped `escape()` output and pins exact capacity. All 21 HDLC tests passed,
including special-byte escaping, length, round-trip, fragmentation and
coalescing coverage; formatting passed.

**Final disposition:** Integrated.

### 2. `3bc149e3` — Added no_ident template support to rngit

**Upstream change:** Registers a `no_ident` page template and selects it across
the Nomad Network page surface when a request has no remote identity and the
null identity hash is blocked. The default response explains that the page
requires identification. The operator documentation lists `no_ident.mu` as a
customizable template.

**Rust applicability:** Rust `rngit` supports the same null-identity blocking
configuration and customizable page templates. Its page renderers currently
surface ACL denial through the generic error/base-template path, however, and
the native template documentation does not list `no_ident.mu`. The observable
page response and customization surface therefore differ from upstream.

**Local handling and evidence:** Local `b6d8f0b` adds a single pre-render guard
covering every registered page path, a built-in `no_ident` fallback with a
custom `no_ident.mu` override, normal base-template wrapping, and native
operator documentation. Three focused tests cover all registered paths, the
blocked-null conjunction, identified and normally allowed unidentified
requesters, and a custom template. The complete `rns-git` suite passed: 199
unit, 6 end-to-end, 11 release and 6 stats tests.

**Final disposition:** Integrated.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable.
- [x] Exact-target live Python/Rust interop passes.
- [x] Workspace tests, feature suites, formatting, and lint pass.
- [x] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation is updated for user-visible behavior.
- [x] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-09-01`: Both remote refreshes succeeded. GitHub was at accepted
  baseline `ea98db4f`; canonical rgit was two commits ahead at `3bc149e3`.
  The dual-VPS snapshots were healthy and complete, and the impaired daily
  Backbone smoke passed announce/identity propagation, bidirectional packets,
  four Resource size boundaries, concurrent links and Resources, and forced
  reconnect recovery. This operational result does not complete the parity
  promotion gates above.
- `2026-09-01`: Entry 1 was integrated as local `0a8e543`. The canonical HDLC
  framing helper now uses one exact allocation; all 21 focused HDLC tests and
  formatting passed.
- `2026-09-01`: Entry 2 was integrated as local `b6d8f0b`. The complete
  222-test `rns-git` suite passed after adding the default/custom `no_ident`
  behavior and documentation. Both mapping commits carry exactly one full
  `Upstream-Commit` trailer and remain in upstream ancestry order.
- `2026-09-01`: Fresh two-remote checks after each mapping succeeded. GitHub
  remained at `ea98db4f`; canonical rgit remained at the exact audited target
  `3bc149e3` with no additional commits.
- `2026-09-01`: Exact-target interoperability passed from a detached canonical
  worktree at `3bc149e3`, `RNS` tree `7ec05287`, and version 1.5.2:
  bidirectional packet, link and Resource traffic plus all five ignored
  `rncp`/`rnx` Python/Rust utility cases.
- `2026-09-01`: The serialized hook-enabled workspace suite passed, including
  946 `rns-net` unit tests, all 54 network E2E tests, and byte-stable historical
  fixture suites. Warning-free host lint, formatting, `git diff --check`, 19
  Python tool tests, the web UI smoke test, TLS tests, and built-in hook
  integration tests passed.
- `2026-09-01`: The full hook-enabled host release build and all five ARMv7
  release build variants passed. The complete Docker matrix passed 11 runs
  with 102 topology assertions and no failures, including 30-node scale,
  supervision, reconnect, Direct Link NAT and privileged `rntun` coverage.
  The daily dual-VPS impairment/reconnect smoke passed earlier the same day.
  Physical Weave HIL was unavailable and is explicitly unclaimed.
- `2026-09-01`: Final mapping verification found exactly two unique, non-empty
  local commits in upstream ancestry order, each with exactly one full
  `Upstream-Commit` trailer. The qualified parity record was created and the
  normative baseline advanced to `3bc149e3`.
- `2026-09-02`: The post-promotion two-remote drift check completed fresh.
  Canonical rgit was exactly at `3bc149e3` with zero commits ahead; GitHub was
  correctly reported behind at the preceding signed 1.5.2 release.
