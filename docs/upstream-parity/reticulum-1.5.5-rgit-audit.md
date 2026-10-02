# Reticulum 1.5.5 rgit `e40191b3` Upstream Audit

## Scope and Baseline

- audit date: `2026-10-02`
- previous accepted version: `1.5.5`
- previous normative commit: `7f2b3b9b524c9386316379af1313b43a5e4f7a5d`
- target version: `1.5.5` (unchanged from the accepted baseline)
- target tag or ref: `e40191b3d193b46b7f2d8a44424a594cd758839b` (GitHub and rgit tips agree; same-version rgit advancement)
- target normative commit: `e40191b3d193b46b7f2d8a44424a594cd758839b`
- target root tree: `ed83d80cd2ced7b41528f8e3f873b3bb54b62ad9`
- target `RNS` tree: `192d74c76e5c56046a411492f219db1833c99365`
- version assertion: `RNS.__version__ == "1.5.5"` (unchanged from the accepted baseline)
- audited range: `7f2b3b9b524c9386316379af1313b43a5e4f7a5d..e40191b3d193b46b7f2d8a44424a594cd758839b`
- commits in range: `1`
- repositories checked: GitHub release mirror (`https://github.com/markqvist/Reticulum`) and the normative rgit remote
- local branch and revision inspected: `dev@7cc02bb` (mapping and mapping-evidence tip; accepted by this promotion)

Both remotes reported the same fresh tip `e40191b3` on the `2026-10-01` and
`2026-10-02` daily drift checks, so there is no mirror disagreement. The tip
still asserts version `1.5.5` and shares the accepted baseline `RNS` tree
`192d74c7`, so this is a post-release, source-only follow-up rather than a new
runtime baseline. Because the upstream version is unchanged, this is accepted as
a same-version canonical `rgit/master` advancement with the qualified
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

The single in-range commit has its `upstream: Added link` mapping and
mapping-evidence summary, and every same-version rgit promotion gate below is
satisfied. The accepted record is
[reticulum-1.5.5-rgit-parity.md](reticulum-1.5.5-rgit-parity.md); this audit is
retained as the detailed pre-promotion work record.

## Promotion Gates

- [x] Every upstream commit has a final `Non-runtime` disposition and a unique mapping.
- [x] Full diff reviewed; focused runtime regressions are inapplicable to this non-runtime delta.
- [x] Runtime-tree identity checked (`192d74c7` unchanged); fixture provenance is unchanged.
- [x] Exact-target interop assessed as inapplicable to this byte-identical runtime delta; not rerun.
- [x] Workspace tests, formatting, and warning-free host lint passed (`cargo test --workspace`, `cargo fmt --check`, `bash scripts/lint-host.sh`, 2026-10-02).
- [x] Native-hook `rns-server` and `rns-ctl` release builds passed; daily manual results recorded below.
- [x] Native tracking documentation updated; no upstream editorial content needs vendoring.
- [x] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

2026-10-01: daily operator drift check found one commit past the accepted
`1.5.5` baseline, `e40191b3` (`Added link`), identical on both the GitHub and
rgit remotes. Full diff review shows a documentation-only edit under
`docs/history/` and an unchanged `RNS` tree. Disposition recorded as
`Non-runtime`; the required non-empty mapping commit was not yet created. Both
VPS snapshots and the impaired `--daily` dual-VPS Backbone smoke test passed on
this date (see the [operator runbook](../rns-server-operator-runbook.md)).

2026-10-02: Landed the `upstream: Added link` mapping commit `0081b9a` for
`e40191b3` with the `Upstream-Commit` trailer, followed by the `7cc02bb`
mapping-evidence summary. The mapping is recorded in the Mapping Verification
table. No new upstream commits were observed; both remotes remain fresh and
agree on `e40191b3`.

2026-10-02: `cargo test --workspace`, `cargo fmt --check`, and
`bash scripts/lint-host.sh` passed. Native-hook `rns-server` and `rns-ctl`
release builds passed. Both VPS experiment nodes were upgraded to
`rns-server 0.3.1406-b93ed92` / `rns-ctl 0.4.1406-b93ed92`, and the impaired
`--daily` dual-VPS Backbone smoke test passed twice on the new binary; both
per-host snapshots were healthy. Docker, cross-build, exact-target interop, and
physical-hardware validation were not rerun and remain unclaimed.
