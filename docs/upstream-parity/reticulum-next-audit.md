# Reticulum X.Y.Z Upstream Audit

## Scope and Baseline

- audit date: `2026-10-01`
- previous accepted version: `1.5.5`
- previous normative commit: `7f2b3b9b524c9386316379af1313b43a5e4f7a5d`
- target version: `pending` (no new upstream version or tag observed)
- target tag or ref: `pending`
- target normative commit: `e40191b3d193b46b7f2d8a44424a594cd758839b` (current observed tip; not yet a named promotion target)
- target root tree: `ed83d80cd2ced7b41528f8e3f873b3bb54b62ad9`
- target `RNS` tree: `192d74c76e5c56046a411492f219db1833c99365`
- version assertion: `RNS.__version__ == "1.5.5"` (unchanged from the accepted baseline)
- audited range: `7f2b3b9b524c9386316379af1313b43a5e4f7a5d..e40191b3d193b46b7f2d8a44424a594cd758839b`
- commits in range: `1`
- repositories checked: GitHub release mirror (`https://github.com/markqvist/Reticulum`) and the normative rgit remote
- local branch and revision inspected: detached HEAD `7f2b3b9b` (accepted baseline; newer commit read with `git show`)

Both remotes reported the same fresh tip `e40191b3` on the 2026-10-01 daily
drift check, so there is no mirror disagreement. The tip still asserts version
`1.5.5` and shares the accepted baseline `RNS` tree `192d74c7`, so this is a
post-release, source-only follow-up rather than a new runtime baseline. The
target version and promotion tag remain unknown and are marked pending.

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
| 1 | `e40191b3d193b46b7f2d8a44424a594cd758839b` | `Added link` | `Non-runtime` | `0081b9a`; source-only review. |

## Per-Commit Analysis

### 1. `e40191b3` — `Added link`

**Upstream change:** Adds a hyperlink to a paragraph in
`docs/history/2026_09_18_Yes_I_am_Angry.md`. No source, protocol, configuration,
API, or bundled-resource file changes.

**Rust applicability:** None. The change edits an upstream project-history
document that is not vendored and has no Rust runtime equivalent.

**Local handling and evidence:** `git show --stat` confirms the single changed
path is `docs/history/2026_09_18_Yes_I_am_Angry.md`; the `RNS` tree hash is
identical to the accepted baseline (`192d74c76e5c56046a411492f219db1833c99365`),
so no runtime behavior can differ. No code change is required; this mapping
records the source-only review required by
[docs/upstream-parity/README.md](README.md).

**Final disposition:** `Non-runtime`

## Mapping Verification

| Upstream commit | Local mapping commit |
|---|---|
| `e40191b3d193b46b7f2d8a44424a594cd758839b` | `0081b9ad85e6bded60122365b4ea81189b1b0bcd` |

The mapping commit is non-empty, appears in the same ancestry order as the
upstream range, and the reviewed upstream hash appears exactly once in an
`Upstream-Commit` trailer.

## Integration Plan

No outstanding per-commit mappings remain: `e40191b3` has its single non-empty
`upstream: Added link` mapping commit carrying the `Upstream-Commit` trailer.

Promotion is not appropriate yet: the target version and promotion target are
unknown, so no rename to `reticulum-X.Y.Z-audit.md` or parity record is created.

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

2026-10-01: daily operator drift check found one commit past the accepted
`1.5.5` baseline, `e40191b3` (`Added link`), identical on both the GitHub and
rgit remotes. Full diff review shows a documentation-only edit under
`docs/history/` and an unchanged `RNS` tree. Disposition recorded as
`Non-runtime`; the required non-empty mapping commit is not yet created. Both
VPS snapshots and the impaired `--daily` dual-VPS Backbone smoke test passed on
this date (see the [operator runbook](../rns-server-operator-runbook.md)).

2026-10-02: Landed the `upstream: Added link` mapping commit `0081b9a` for
`e40191b3` with the `Upstream-Commit` trailer. No new upstream commits were
observed. Both VPS experiment nodes were upgraded to `rns-server
0.3.1406-b93ed92` / `rns-ctl 0.4.1406-b93ed92`, and the impaired `--daily`
dual-VPS Backbone smoke test passed twice on the new binary.
