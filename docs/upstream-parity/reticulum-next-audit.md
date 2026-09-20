# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-09-20`
- previous accepted version: `1.5.4`
- previous normative commit: `e699bb23f1306ed451568d647b497791a44be95a`
- observed upstream version: `1.5.4`
- observed refs: `origin/master`, `rgit/master` (agree)
- observed tip: `99de23c040d507e3fefca19e87b182302902725d`
- observed root tree: `42e27d27afbed126220bec5ae701a745e0568a10`
- observed `RNS` tree: `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`
- version evidence: `RNS/_version.py` contains `__version__ = "1.5.4"`
- inventoried range: `e699bb23f1306ed451568d647b497791a44be95a..99de23c040d507e3fefca19e87b182302902725d`
- commits in range: `16`
- repositories: `https://github.com/markqvist/Reticulum` and `rns://7649a50d84610232d1416b41d2896aff/reticulum/reticulum`
- local branch/revision: `dev@503d1fc6329068af0800160d3124c8fa00a1c201`
- promotion target: pending review and acceptance

Initial inventory from the daily VPS report. Both refreshes succeeded:
GitHub at `2026-09-20T14:01:37+00:00` and rgit at
`2026-09-20T14:02:13+00:00`. The configured checkout remains at
the accepted baseline. All changed paths are documentation; every commit's
`RNS` tree equals the baseline tree. This is initial scope evidence, not a
completed per-commit review or parity acceptance.

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

| # | Upstream commit | Subject | Disposition | Evidence / remaining work |
|---:|---|---|---|---|
| 1 | `484cf2d1a56e657e1310655e15b5a8159b71ce21` | Added history folder | Needs decision | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 2 | `abf355b4d72d5669496dae3220bf5836c5610bcf` | Formatting, link, wording, typos | Needs decision | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 3 | `29f6bc8652e490e6489741c16bdc2b7d142bbcc9` | Done, next chapter | Needs decision | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 4 | `7373f813495b8134e3ca3274a1b988c1fa97b106` | Markdown is markdown | Needs decision | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 5 | `58881af30703ad74d80e4e9135713abdba6b26dd` | Updates | Needs decision | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 6 | `9d85931c9d85c7a6549364c572fe2532ca5a9d99` | Updates | Needs decision | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 7 | `3c479ddb65bf86c0bbaa3565861db97171bb2a4a` | Updated readme | Needs decision | Paths: `README.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 8 | `2289a8effae984d63bc69d10aa4e1d01a3088ed3` | Updated readme | Needs decision | Paths: `README.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 9 | `23101e45f6013d0f54aa2f8651bcde271c0b7ae9` | Updated readme | Needs decision | Paths: `README.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 10 | `8743ddcbe52be7f88e764b1cdd7af009bd4d62a2` | Updated readme | Needs decision | Paths: `README.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 11 | `cb66b3d10fd34a6aedb16c78f00a720383dbb122` | Updated readme | Needs decision | Paths: `README.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 12 | `ddd55d50cc30c49bec99d359a0f73a9cc15d436d` | Updated readme | Needs decision | Paths: `README.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 13 | `34b36362ab9b2ef9b20bafb3db146261e1d75191` | Scratch that | Needs decision | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`. Runtime tree unchanged; full review and mapping commit pending. |
| 14 | `15e6dd4a882f0cea81b4e899120f46787aaeb8a2` | Updated docs | Needs decision | Paths: `docs/manual/searchindex.js`. Runtime tree unchanged; full review and mapping commit pending. |
| 15 | `395241b190ae4bc6e5d8070c8ff0a01afd24bdc9` | Updated docs | Needs decision | Paths: `docs/history/2026_09_18_Yes_I_am_Angry.md`, `docs/source/brandolinis.rst`. Runtime tree unchanged; full review and mapping commit pending. |
| 16 | `99de23c040d507e3fefca19e87b182302902725d` | Updated docs | Needs decision | Paths: `docs/manual/_sources/brandolinis.rst.txt`, `docs/manual/brandolinis.html`, `docs/manual/searchindex.js`, `docs/markdown/brandolinis.md`. Runtime tree unchanged; full review and mapping commit pending. |

## Per-Commit Analysis

Pending full diff review in ancestry order. The inventory records changed paths
and verifies runtime-tree equality independently for every commit. No integration
mapping commits or final dispositions have been claimed by this daily report.

## Integration Plan

1. Review each complete diff and determine native documentation applicability.
2. Record each final disposition and one mapping commit per upstream commit,
   following `README.md`; do not combine unrelated commits.
3. Select the promotion target and qualified versioned audit filename, then
   complete the required acceptance gates before changing the baseline.

## Promotion Gates

- [ ] Every upstream commit has a final disposition.
- [ ] Focused regressions pass for every applicable behavior change.
- [ ] Fixture provenance and byte stability are checked where applicable.
- [ ] Exact-target live Python/Rust interop passes.
- [ ] Workspace tests, feature suites, formatting, and lint pass.
- [ ] Required build, Docker, hardware, and manual gates are recorded honestly.
- [ ] Native documentation is updated for user-visible behavior.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

2026-09-20 daily operations: both VPS snapshots healthy and complete, no duplicate
same-day rows, SQLite integrity check passed. Release builds for `rns-server`
with native hooks and `rns-ctl` passed. The live `--daily` Backbone test passed:
bidirectional packets/channels, four Resource sizes through 1 MiB, concurrent
Resources, two link batches at concurrency three, latency/jitter/rate impairment,
and one forced disconnect/recovery cycle.

These are daily operational results only. Workspace tests, formatting/lint,
exact-target Python/Rust interop, hardware gates, and parity promotion were not
performed as part of this report. Accepted baseline remains unchanged.
