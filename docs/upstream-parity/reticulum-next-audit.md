# Reticulum 1.5.6 rgit `49ae71e0` Upstream Audit

## Scope and Baseline

- audit date: `2026-10-02`
- previous accepted version: `1.5.6`
- previous normative commit: `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62`
- target version: `1.5.6` (unchanged from the accepted baseline)
- target tag or ref: `49ae71e06cadf5d846849661578a8ad9fcede443` (canonical `rgit/master`; the GitHub mirror is still at `e40191b3`)
- target normative commit: `49ae71e06cadf5d846849661578a8ad9fcede443`
- target root tree: `6a2af93c968be263dc918c2288f3553e2553c1e5`
- target `RNS` tree: `def82bf5dd3c9686e798ca032927d2e625829b50`
- version assertion: `RNS.__version__ == "1.5.6"` (unchanged from the accepted baseline)
- audited range: `2bae9ff0dca17ba39531d7f8c3078efd3a55ad62..49ae71e06cadf5d846849661578a8ad9fcede443`
- commits in range: `2`
- repositories checked: normative rgit remote and GitHub release mirror
- local branch and revision inspected: `dev@539b516`

The canonical rgit tip advanced two source-only commits while the GitHub mirror
remained at `e40191b3` and `RNS/_version.py` still declares `1.5.6`. This is a
same-version canonical `rgit/master` advancement, accepted with the qualified
`-rgit` record filenames.

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
| 1 | `1e6ebd3fa0746c6f3299b0d3f74aaeb05c0e457b` | Updated changelog | `Non-runtime` | `43ea753`; source-only review. |
| 2 | `49ae71e06cadf5d846849661578a8ad9fcede443` | Updated documentation | `Non-runtime` | `ae9a5c5`; source-only review. |

## Per-Commit Analysis

### 1. `1e6ebd3f` — Updated changelog

**Upstream change:** Edits the upstream `Changelog.md` release notes. No source,
protocol, configuration, API, or bundled-resource file changes.

**Rust applicability:** None. The upstream changelog is not vendored and has no
Rust runtime counterpart.

**Local handling and evidence:** No code change is required; this mapping
records the source-only review required by
[docs/upstream-parity/README.md](README.md).

**Final disposition:** `Non-runtime`

### 2. `49ae71e0` — Updated documentation

**Upstream change:** Regenerates the upstream `docs/manual/` Sphinx HTML output
and its build metadata. No `RNS/` source changes and no runtime behavior change.

**Rust applicability:** None. The generated upstream manual artifacts are not
vendored.

**Local handling and evidence:** No code change is required. The `RNS` tree is
unchanged from the accepted baseline
(`def82bf5dd3c9686e798ca032927d2e625829b50`), so no runtime surface differs.

**Final disposition:** `Non-runtime`

## Mapping Verification

| Upstream commit | Local mapping commit |
|---|---|
| `1e6ebd3fa0746c6f3299b0d3f74aaeb05c0e457b` | `43ea753d33a2f2a3627013f46f1dc2c1eb66a3d7` |
| `49ae71e06cadf5d846849661578a8ad9fcede443` | `ae9a5c5be1f6d8448ec355c69d2eb7c7d5ee1ab1` |

The mapping commits are non-empty, appear in the same ancestry order as the
upstream range, and each reviewed upstream hash appears exactly once in an
`Upstream-Commit` trailer.

## Integration Plan

Land one non-empty ordered mapping commit per upstream commit (`1e6ebd3f`,
`49ae71e0`), then complete the same-version rgit promotion gates and create the
`1.5.6` rgit parity record.

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

2026-10-02: The canonical rgit tip advanced to
`49ae71e06cadf5d846849661578a8ad9fcede443`, two source-only commits past the
accepted `1.5.6` tip `2bae9ff0`. GitHub still reported `e40191b3`. The commits
edit `Changelog.md` and regenerate `docs/manual/`; the `RNS` tree is unchanged.
