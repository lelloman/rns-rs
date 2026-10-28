# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-10-28`
- previous accepted version: `1.6.0`
- previous normative commit: `9a01a20ce66c4146dd8f8d31f18c19fe7600739d`
- target version: pending (upstream `RNS.__version__` is still `1.6.0`)
- target tag or ref: `rgit:master` tip `ca6451a02aead88734e47193dc228055d42c9854`
- target normative commit: `ca6451a02aead88734e47193dc228055d42c9854`
- target root tree: `a3b5484c6f56df70832deeaf725a42bda8abb63b`
- target `RNS` tree: `ff3e6127789b6111f265055fea7593f903feccfe`
- version assertion: `RNS.__version__ == "1.6.0"` (unchanged; no version bump yet)
- audited range: `9a01a20ce66c4146dd8f8d31f18c19fe7600739d..ca6451a02aead88734e47193dc228055d42c9854`
- commits in range: `15`
- repositories checked: rgit (normative) and GitHub mirror
- local branch and revision inspected: detached `HEAD` at `9a01a20c` (accepted checkout retained)

The GitHub `master` tip is `e40191b3d193b46b7f2d8a44424a594cd758839b`, which
is `behind` the accepted baseline and is allowed mirror lag. The normative rgit
`master` tip `ca6451a0` (committed 2026-10-28T01:22Z) is `ahead` of the baseline
by the 15 commits inventoried below. Both refreshes succeeded at
2026-10-28T06:16Z. The new commits implement announcement, path-request and
link-request stamps and landed on `master`; the `dev_pr_stamps` name only
survives in the subject of the historical merge commit `c68066ed`. No new tag
or version bump identifies a promotion target yet.

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

Every commit in the audited range must appear exactly once.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `d1da5c3d67dc30e9af300d5776c7e94c42b5a33b` | Implemented destination stamps | Needs coordinated port | No announce stamp policy in Rust; only `rns-core/src/stamp.rs` PoW primitives exist |
| 2 | `d2dd730801ca91197f22be56c85d5d855d97faed` | Adjusted stamp defaults | Needs coordinated port | Depends on #1; defaults only |
| 3 | `d3ec00cd510e7f8b72e3249a8a74a0d60f5c9f42` | Cleanup | Needs coordinated port | Default tuning plus path-request tag propagation; see analysis |
| 4 | `156c7323a510f1be3adfb8288e521559599d3809` | Implemented path request stamps | Needs coordinated port | No PR stamp validation or emission in `rns-core/src/transport` |
| 5 | `7ec975fc886de62c80bfebf1b2b108991ea75204` | Cleanup | Needs coordinated port | Renames `stamped_ext` to `ext_payload`; part of PR-stamp surface |
| 6 | `51be88fbd83417c8d21d2ce74922faa401658cee` | Fixed unused path cull order | Structurally covered | `cull_path_table` sorts ascending by expiry and takes the earliest (`rns-core/src/transport/jobs.rs:178`) |
| 7 | `c68066edffd14c3755ceb181c621a4f806ddfd46` | Merge branch 'master' into dev_pr_stamps | Structurally covered | Merge delta is patch-equivalent to #6 (same one-line cull-order fix) |
| 8 | `7c1b648607a13d9d7517f5a82c9a59c1bd776935` | Improved PR stamp handling | Needs coordinated port | Transitional PR-stamp relay diagnostics; depends on #4 |
| 9 | `8d5871915a4a0b846d2c7e637842ed0c8916425c` | Cleanup | Non-runtime | Constant reorder only, no value or control-flow change |
| 10 | `c3af19893f7e056bbe04f53f57133eddadc4ed71` | Cleanup | Non-runtime | Removes unused `DERIVED_KEY_LENGTH_LEGACY` |
| 11 | `30c6428e0b59bfc05563167c72c2e0f21ef015c0` | Added link establishment cost to announces | Needs coordinated port | No `lr_cost`/announce-cost field in Rust storage or announce encoding |
| 12 | `9955e1bf6777a1e5cddfd423de86b5a6824a64cc` | Implemented Identity stamps and added stamp key generation to stamper | Needs coordinated port | No identity stamp keying/validation in Rust |
| 13 | `c37b5f7f44900e1d80c166678d8bac565f238046` | Cleanup | Non-runtime | Collapses an `if` body to one line; no behavior change |
| 14 | `ba8c2d76db20be55a22578b840f78ef0489ef053` | Implemented link request stamps | Needs coordinated port | No link-request stamp emission/validation in `rns-core`/`rns-net` |
| 15 | `ca6451a02aead88734e47193dc228055d42c9854` | Parameter tuning | Needs coordinated port | Adjusts `LR_COST`/`LINK_STAMP_TIMEOUT`; depends on #14 |

## Per-Commit Analysis

### 1. `d1da5c3d` — Implemented destination stamps

**Upstream change:** Adds optional proof-of-work stamps to destination
announces, including announce stamp material, validation, configuration and
transport handling.

**Rust applicability:** Rust has the generic stamp primitives in
`rns-core/src/stamp.rs` but no destination announce stamp policy, storage or
validation.

**Local handling and evidence:** No implementation yet. Inventory recorded from
`RNS/Destination.py`, `RNS/Identity.py`, `RNS/Stamps.py` and
`RNS/Transport.py`.

**Final disposition:** Needs coordinated port.

### 2. `d2dd7308` — Adjusted stamp defaults

**Upstream change:** Retunes announce stamp defaults.

**Rust applicability:** Depends entirely on #1.

**Local handling and evidence:** Deferred behind #1.

**Final disposition:** Needs coordinated port.

### 3. `d3ec00cd` — Cleanup

**Upstream change:** Despite the subject, raises `DESTINATION_COST` and
`DESTINATION_VALUE` from 20 to 23, initializes `blocked_if`, propagates a shared
request tag when replaying path requests, and reformats log lines.

**Rust applicability:** Default tuning and tag propagation belong to the
destination/PR stamp work.

**Local handling and evidence:** Depends on #1 and #4.

**Final disposition:** Needs coordinated port.

### 4. `156c7323` — Implemented path request stamps

**Upstream change:** Adds stamp generation and validation for path requests,
including ingress and egress limiting integration and a large Transport
restructure.

**Rust applicability:** Rust path-request handling has no stamp extension
parsing or emission.

**Local handling and evidence:** No implementation yet; scope spans
`rns-core/src/transport` and packet encoding.

**Final disposition:** Needs coordinated port.

### 5. `7ec975fc` — Cleanup

**Upstream change:** Renames the internal `stamped_ext` parameter to
`ext_payload`, updates the docstring, and normalizes `RNS.Transport` references.

**Rust applicability:** Internal naming only; meaningful only alongside the
PR-stamp feature.

**Local handling and evidence:** No independent Rust surface.

**Final disposition:** Needs coordinated port.

### 6. `51be88fb` — Fixed unused path cull order

**Upstream change:** Fixes culling to remove the earliest-expiring unused paths
instead of the latest.

**Rust applicability:** `cull_path_table` already sorts unused paths ascending
by expiry and takes the first `remove_count`.

**Local handling and evidence:** `rns-core/src/transport/jobs.rs:178`; keep the
existing invariant test while integrating the stamp series.

**Final disposition:** Structurally covered.

### 7. `c68066ed` — Merge branch 'master' into dev_pr_stamps

**Upstream change:** Merge of the cull-order fix into `dev_pr_stamps`.

**Rust applicability:** The merge-resolution delta is the same one-line fix as
#6; no independent behavior.

**Local handling and evidence:** Compare with parents `7ec975fc` and
`51be88fb`; no additional mapping code required beyond #6.

**Final disposition:** Structurally covered.

### 8. `7c1b6486` — Improved PR stamp handling

**Upstream change:** Adds transitional diagnostics distinguishing unstamped
relayed path requests from invalid stamps, gates debug work, and forwards a
sentinel extension for unstamped PRs during migration.

**Rust applicability:** Tied to the PR-stamp extension format; no equivalent
state exists.

**Local handling and evidence:** Depends on #4.

**Final disposition:** Needs coordinated port.

### 9. `8d587191` — Cleanup

**Upstream change:** Reorders the `NAME_HASH_LENGTH` constant definition.

**Rust applicability:** None; no value or behavior change.

**Local handling and evidence:** Source-only.

**Final disposition:** Non-runtime.

### 10. `c3af1989` — Cleanup

**Upstream change:** Removes the unused `DERIVED_KEY_LENGTH_LEGACY` constant.

**Rust applicability:** None.

**Local handling and evidence:** Source-only.

**Final disposition:** Non-runtime.

### 11. `30c6428e` — Added link establishment cost to announces

**Upstream change:** Adds an announced link-request cost (`lr_cost`) to
destination announces and persists it in the known-destination store (schema
version 2).

**Rust applicability:** Rust announce encoding and
`known_destinations` schema have no link-establishment cost field.

**Local handling and evidence:** Needs encoding, persistence and migration
work; not started.

**Final disposition:** Needs coordinated port.

### 12. `9955e1bf` — Implemented Identity stamps and added stamp key generation to stamper

**Upstream change:** Adds identity-level stamp keys, stamp material/key
generation, and expanded `Stamps` helpers.

**Rust applicability:** `rns-core/src/stamp.rs` provides only stateless
workblock/value primitives; no identity stamp keys or generation API.

**Local handling and evidence:** Foundation for #1, #4 and #14.

**Final disposition:** Needs coordinated port.

### 13. `c37b5f7f` — Cleanup

**Upstream change:** Collapses the schema-migration branch onto one line.

**Rust applicability:** None.

**Local handling and evidence:** Source-only.

**Final disposition:** Non-runtime.

### 14. `ba8c2d76` — Implemented link request stamps

**Upstream change:** Adds link-request stamp emission/validation with timeout
handling across `Link`, `Destination` and `Transport`, plus an example update.

**Rust applicability:** No link-request stamp handling exists in Rust.

**Local handling and evidence:** Depends on #11 and #12.

**Final disposition:** Needs coordinated port.

### 15. `ca6451a0` — Parameter tuning

**Upstream change:** Lowers `LR_COST` from 14 to 11 and
`LINK_STAMP_TIMEOUT` from 16 to 15.

**Rust applicability:** Depends on the link-request stamp implementation.

**Local handling and evidence:** Apply with #14.

**Final disposition:** Needs coordinated port.

## Integration Plan

Process in upstream ancestry order. The stamp series is one coordinated body of
work; do not land announce, path-request or link-request stamps partially.

1. #12 identity stamp keys and `Stamps` helpers.
2. #1, #2, #3 destination/announce stamps (including the default changes).
3. #4, #5, #8 path-request stamps and the extension rename.
4. #11 link-establishment cost announce field and storage migration.
5. #14, #15 link-request stamps and parameter tuning.
6. #6/#7 need a mapping commit only to pin the existing cull invariant; no
   behavior change is expected.
7. #9, #10, #13 need one non-runtime mapping commit each under the
   per-commit procedure.

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

- `2026-10-28`: Daily drift check found rgit `master` at `ca6451a0`, 15 commits
  past the accepted `9a01a20c` baseline. GitHub `master` at `e40191b3` was
  `behind` and fresh. Both remote refreshes succeeded; inventory recorded. No
  integration work, deployment, restart or reconfiguration was performed.
