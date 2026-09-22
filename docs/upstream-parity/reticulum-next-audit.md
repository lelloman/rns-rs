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
| 1 | `21a2365045cbbed82c05f7401da3ccf1779c390f` | Formatting and wording | Non-runtime | `5b996d2`; source-only review. |
| 2 | `a22de54b4a6dc2f6f11a6908464203424b661139` | Added Void Grants | Non-runtime | `86c319f`; source-only review. |
| 3 | `c7be675739a26bd56fa743678d7dd80ddca39491` | Formatting and wording | Non-runtime | `1e3adc5`; source-only review. |

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

### 2. `a22de54b` — Added Void Grants

**Upstream change:** Adds an upstream legal/editorial history page and wires
it into the upstream manual source, generated HTML, Markdown, search index,
and inventory. All nine changed paths are documentation artifacts.

**Rust applicability:** The change does not alter any `RNS` source, protocol
encoding, runtime interface, or supported native user workflow. The Rust
repository has no copy of this upstream legal commentary.

**Local handling and evidence:** Full diff and changed-path review recorded in
this mapping; the target and prior accepted `RNS` trees are identical.

**Final disposition:** Non-runtime.

### 3. `c7be6757` — Formatting and wording

**Upstream change:** Adjusts wording in the newly added upstream history page
and its reStructuredText manual source. The two changed files are editorial
documentation only.

**Rust applicability:** No `RNS` code, wire behavior, configuration, RPC,
CLI, storage, or native documentation surface changes. The `RNS` tree remains
identical to the accepted baseline.

**Local handling and evidence:** Full diff and changed-path review recorded in
this mapping; no native runtime port is applicable.

**Final disposition:** Non-runtime.

## Mapping Verification

| Upstream commit | Local mapping commit |
|---|---|
| `21a2365045cbbed82c05f7401da3ccf1779c390f` | `5b996d277dbc32cea0b9b3e919fdd39c338eabb5` |
| `a22de54b4a6dc2f6f11a6908464203424b661139` | `86c319ff68baa854a3313d6eceae15180603f5bf` |
| `c7be675739a26bd56fa743678d7dd80ddca39491` | `1e3adc548a63cb644d5a970e3f87b05786877332` |

The mapping commits are non-empty, appear in the same ancestry order as the
upstream range, and each reviewed upstream hash appears exactly once in an
`Upstream-Commit` trailer.

## Integration Plan

Complete the applicable same-version rgit promotion gates.

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
