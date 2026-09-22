# Reticulum 1.5.4 rgit `c7be6757` Upstream Audit

## Scope and Baseline

- audit date: `2026-09-22`
- previous accepted version: `1.5.4`
- previous normative commit: `99de23c040d507e3fefca19e87b182302902725d`
- target version: `1.5.4`
- target tag or ref: `rgit/master@c7be675739a26bd56fa743678d7dd80ddca39491`
- target normative commit: `c7be675739a26bd56fa743678d7dd80ddca39491`
- target root tree: `8556cdf675d73b2dd0f0e16586c42f2653f41ace`
- target `RNS` tree: `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`
- version assertion: `RNS.__version__ == "1.5.4"`
- audited range: `99de23c040d507e3fefca19e87b182302902725d..c7be675739a26bd56fa743678d7dd80ddca39491`
- commits in range: `3`
- repositories checked: normative rgit and GitHub mirror, both freshly fetched and at `c7be6757`
- local branch and revision inspected: `dev@bb07f003b6003bb5053308be293c5126a1f189e7`

This is a same-version normative-rgit advancement. The target `RNS` tree is
unchanged from the previously accepted baseline; the three reviewed commits
only add or revise upstream documentation and generated manual artifacts.

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
| 1 | `21a2365045cbbed82c05f7401da3ccf1779c390f` | Formatting and wording | Non-runtime | This mapping records the source-only review. |
| 2 | `a22de54b4a6dc2f6f11a6908464203424b661139` | Added Void Grants | Pending review | Pending ordered mapping. |
| 3 | `c7be675739a26bd56fa743678d7dd80ddca39491` | Formatting and wording | Pending review | Pending ordered mapping. |

## Per-Commit Analysis

### 1. `21a23650` — Formatting and wording

**Upstream change:** Revises wording and formatting in the Void Grants history
page and its manual source and generated Markdown/HTML/search-index artifacts.
The changed paths are all under `docs/`; no executable `RNS` source changes.

**Rust applicability:** No wire, configuration, CLI, RPC, persistence, or
runtime behavior changes. The Rust repository does not mirror this upstream
editorial material, and its protocol source tree is unchanged.

**Local handling and evidence:** Full diff and changed-path review recorded in
this mapping; target `RNS` tree remains `b4c1cf368718971e1dcaf7c1cf2d1459411a360e`.

**Final disposition:** Non-runtime.

## Integration Plan

Review and map commits 2 and 3 in ancestry order, then complete the applicable
same-version rgit promotion gates.

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

The 2026-09-22 daily dual-VPS stress report passed before this audit began.
It is operational evidence only; it does not replace the promotion gates.
