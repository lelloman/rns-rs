# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-09-13`
- previous accepted version: `1.5.4`
- previous normative commit: `0dbc9e90a33c427befd3873aa29bd6e8463ba192`
- target version and promotion target: pending selection; observed tip still reports `1.5.4`
- inspected refs: `origin/master` and `rgit/master` in the upstream checkout
- observed tip: `1565126ffd08b9d7bc750ce5df82d5aa3e38183e`
- observed root tree: `780e486cf31d518fc84aab5ec5bd9fb823ad6f45`
- observed `RNS` tree: `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`
- version evidence: observed tip's `RNS/_version.py` declares `1.5.4`
- audited range: `0dbc9e90a33c427befd3873aa29bd6e8463ba192..1565126ffd08b9d7bc750ce5df82d5aa3e38183e`
- commits in range: `1`
- repositories checked: normative rgit repository and GitHub mirror
- local branch and revision inspected: `dev@37272fc486f3fda74d44a23c12caf132e4d6a679`

Both remotes refreshed successfully and agree on the observed tip. GitHub fetch
completed at `2026-09-13T07:35:05+00:00`; rgit at
`2026-09-13T07:35:10+00:00`. The upstream checkout remains at the accepted
normative commit. This daily inventory does not promote the baseline.

## Audit Vocabulary

- **Non-runtime**: metadata, documentation, generated artifacts, or upstream-only
  tests require no independent Rust runtime change.

## Commit Inventory

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `1565126ffd08b9d7bc750ce5df82d5aa3e38183e` | Updated readme | Non-runtime | Complete diff reviewed: only `README.md` and `README.mu`; `RNS` tree identical to accepted baseline. Ordered local mapping pending. |

## Per-Commit Analysis

### 1. `1565126f` — Updated readme

**Upstream change:** Revises performance goals and throughput claims, explains
the Python execution assumptions, and expands guidance on practical performance
and correctness. Changed paths: `README.md` and `README.mu`. No dependencies on
earlier unintegrated commits exist.

**Rust applicability:** No protocol, runtime, configuration, RPC, CLI, or
persistence behavior changes. These upstream performance claims do not establish
native benchmark results or acceptance thresholds. The two README formats even
give different Raspberry Pi throughput figures; neither is imported as evidence.

**Local handling and evidence:** Full diff inspected with `git show`; both the
accepted baseline and observed tip have `RNS` tree
`b4c1cf368718971e1dcaf7c1cf2d1459411a360e`. No runtime port or synthetic regression
is required. This audit records the no-action rationale; a local mapping commit
and promotion validation remain pending under the parity workflow.

**Final disposition:** Non-runtime.

## Integration Plan

1. Record the ordered, non-empty local mapping with the full `Upstream-Commit`
   trailer when performing the parity update.
2. Select the exact promotion target and use the qualified same-version audit
   name if advancing the `1.5.4` rgit baseline.
3. Complete and record promotion gates before creating the final parity record
   or updating `UPSTREAM.md`.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change (none;
  documentation-only diff).
- [x] Fixture provenance and byte stability are checked where applicable (no
  fixture or runtime changes).
- [ ] Exact-target live Python/Rust interop passes or an applicability decision
  is recorded for promotion.
- [ ] Workspace tests, feature suites, formatting, and lint pass.
- [ ] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation is updated for user-visible behavior (none changed).
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-09-13`: EU and US daily snapshots are healthy, with no negative query
  sentinels and all packet-traffic queries successful. Each host has exactly one
  snapshot for the date. Database integrity and dashboard compatibility passed.
- `2026-09-13`: Release `rns-server` build with native hooks passed. The live
  `--daily` smoke passed announce propagation, identity recall, bidirectional
  packets, Links, Channels, four Resource sizes (1,024; 100,000; 1,048,575;
  1,048,576 bytes) with concurrency two per direction, two link batches with
  concurrency three per direction, and one forced Backbone reconnect/recovery
  cycle under 150 ms latency, 75 ms jitter and 2,000 kbps per VPS leg.
- No workspace suite, lint, Docker, physical hardware, or exact-target Python
  interop run is claimed by this daily report. Baseline promotion remains pending.
