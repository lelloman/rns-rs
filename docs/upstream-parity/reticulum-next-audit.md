# Reticulum 1.5.4 rgit `3f95b472` Upstream Audit

## Scope and Baseline

- audit date: `2026-09-27`
- previous accepted version: `1.5.4`
- previous normative commit: `8a7ad40d649aae1cd755f060fa8f5619f7000b29`
- target version: `1.5.4`
- target tag or ref: `3f95b472820ddfb27f736143fb0b4d0d3aa610f1` (GitHub and rgit tips agree)
- target normative commit: `3f95b472820ddfb27f736143fb0b4d0d3aa610f1`
- target root tree: `a843be443c20aa15b5f63f36663a351230a93168`
- target `RNS` tree: `51f0e922420b47f482df9184b48ade41ac8d6ce3`
- version assertion: `RNS.__version__ == "1.5.4"` (unchanged from the accepted baseline)
- audited range: `8a7ad40d649aae1cd755f060fa8f5619f7000b29..3f95b472820ddfb27f736143fb0b4d0d3aa610f1`
- commits in range: `2`
- repositories checked: normative rgit repository and GitHub release mirror
- local branch and revision inspected: `dev@c60eb11c832990b9a25ebeb14f5a7e5bf9261432`

Both remotes refreshed successfully during the `2026-09-27` daily check
(GitHub `06:50:51` UTC, rgit `06:50:55` UTC). GitHub and rgit now agree on
`3f95b472820ddfb27f736143fb0b4d0d3aa610f1`, two commits ahead of the accepted
baseline: the previously inventoried `aeccf69f` runtime cleanup and a later
`3f95b472` edit to the upstream `AGENTS.md` guidance file. The `RNS` tree is
unchanged between `aeccf69f` and `3f95b472`, so only the first commit touches
runtime source. The promotion target is not decided until every commit has a
final disposition and the same-version rgit gates are completed, so the active
audit keeps its date-independent `reticulum-next-audit.md` name.

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
| 1 | `aeccf69fc724c6d245bdbd386a64261444334354` | Cleanup | Non-runtime | `5ab3c83`; source-only review. |
| 2 | `3f95b472820ddfb27f736143fb0b4d0d3aa610f1` | Updated AGENTS.md | Non-runtime | `ce36b1b`; source-only review. |

## Per-Commit Analysis

### 1. `aeccf69f` — Cleanup

**Upstream change:** Removes an unused local `import platform` statement from
`BLEConnection.find_target_device()` in `RNS/Interfaces/RNodeInterface.py`. The
function continues to call `RNS.vendor.platformutils.is_windows()`, so the
deleted statement was an unreferenced import that shadowed nothing and changed
no control flow, output, wire behavior, configuration, or API surface. The
commit touches exactly one file with one deleted line and no added lines.

**Rust applicability:** The native workspace has no RNode BLE connection
implementation and therefore no counterpart to this Python-local import. A
deleted unused import cannot change observable behavior in any language, so
there is no compatibility surface that requires a Rust change.

**Local handling and evidence:** No code change is required. The complete diff
was reviewed with `git show aeccf69fc724c6d245bdbd386a64261444334354 --stat` and
a full source diff. A workspace search found no `RNode`, `Bluetooth`, or
`find_target_device` implementation under `rns-core/src`, `rns-server/src`, or
`rns-ctl/src`.

**Final disposition:** Non-runtime.

### 2. `3f95b472` — Updated AGENTS.md

**Upstream change:** Rewrites the upstream `AGENTS.md` contributor guidance,
`496` insertions and `245` deletions in a single file. The commit touches
nothing under `RNS/`; the `RNS` tree stays at
`51f0e922420b47f482df9184b48ade41ac8d6ce3`, the same tree produced by
`aeccf69f`. `AGENTS.md` is upstream agent/documentation guidance and is not
imported or loaded by the Reticulum runtime.

**Rust applicability:** A documentation and agent-guidance edit cannot change
runtime behavior, wire format, configuration, or public API. There is no
compatibility surface that requires a Rust change, and the native workspace
maintains its own `AGENTS.md` independently.

**Local handling and evidence:** No code change is required. The complete diff
was reviewed with `git show --name-status 3f95b472820ddfb27f736143fb0b4d0d3aa610f1`,
which reports only `M AGENTS.md`. Tree verification shows the `RNS` tree is
unchanged from `aeccf69f`.

**Final disposition:** Non-runtime.

## Mapping Verification

| Upstream commit | Local mapping commit |
|---|---|
| `aeccf69fc724c6d245bdbd386a64261444334354` | `5ab3c830cc892803f4fce4a2ccd1bd3aa6d163d8` |
| `3f95b472820ddfb27f736143fb0b4d0d3aa610f1` | `ce36b1b2df4846da5754c0a12f0441f03e52de63` |

The mapping commits are non-empty, appear in the same ancestry order as the
upstream range, and each reviewed upstream hash appears exactly once in an
`Upstream-Commit` trailer.

## Integration Plan

Complete the applicable same-version rgit promotion gates.

## Promotion Gates

- [x] Every upstream commit has a final disposition (`Non-runtime`).
- [ ] Focused regressions pass for every applicable behavior change.
- [ ] Fixture provenance and byte stability are checked where applicable.
- [ ] Exact-target live Python/Rust interop passes.
- [ ] Workspace tests, feature suites, formatting, and lint pass.
- [ ] Required build, Docker, hardware, and manual gates are recorded honestly.
- [ ] Native documentation is updated for user-visible behavior.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

- `2026-09-26`: The daily upstream refresh succeeded for both remotes. GitHub
  reported `at_baseline` at `8a7ad40d649aae1cd755f060fa8f5619f7000b29`; rgit
  reported one commit ahead at
  `aeccf69fc724c6d245bdbd386a64261444334354` (`Cleanup`, commit date
  `2026-09-26 14:34:17 +0200`). Deduplicated commits ahead: `1`.
- `2026-09-26`: The one commit was reviewed in full. It deletes an unused
  `import platform` inside `BLEConnection.find_target_device()` in
  `RNS/Interfaces/RNodeInterface.py`; the `RNS` tree moved from
  `b4c1cf368718971e1dcaf7c1cf2d1459411a360e` to
  `51f0e922420b47f482df9184b48ade41ac8d6ce3` only because of that deletion. It
  is assigned a `Non-runtime` disposition. No promotion or `UPSTREAM.md`
  change is made by this inventory step.
- `2026-09-27`: The daily upstream refresh succeeded for both remotes. GitHub
  and rgit both reported `3f95b472820ddfb27f736143fb0b4d0d3aa610f1` as their
  tip, two commits ahead of the accepted baseline
  `8a7ad40d649aae1cd755f060fa8f5619f7000b29`. The newly observed commit
  `3f95b472` (`Updated AGENTS.md`, commit date `2026-09-26 22:09:29 +0200`)
  modifies only `AGENTS.md`; the `RNS` tree is unchanged from `aeccf69f`. It is
  appended to this inventory with a `Non-runtime` disposition. Deduplicated
  commits ahead: `2`. Both remotes agree. No promotion or `UPSTREAM.md` change
  is made by this inventory step.
