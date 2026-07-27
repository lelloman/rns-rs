# Reticulum X.Y.Z Upstream Audit

## Scope and Baseline

- audit date: `YYYY-MM-DD`
- previous accepted version: `X.Y.Z`
- previous normative commit: `<40-character commit>`
- target version: `X.Y.Z`
- target tag or ref: `<tag-or-ref>`
- target normative commit: `<40-character commit>`
- target root tree: `<40-character tree>`
- target `RNS` tree: `<40-character tree>`
- version assertion: `RNS.__version__ == "X.Y.Z"`
- audited range: `<previous-commit>..<target-commit>`
- commits in range: `<count>`
- repositories checked: `<normative repository and mirrors>`
- local branch and revision inspected: `<branch>@<commit>`

State any tag-versus-tip distinction, mirror lag, generated-artifact commits,
or other provenance details here.

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
| 1 | `<commit>` | `<subject>` | `<vocabulary term>` | `<local commit/tests/rationale>` |

## Per-Commit Analysis

### 1. `<short commit>` — `<subject>`

**Upstream change:** Describe the externally relevant behavior.

**Rust applicability:** Explain whether and how it maps to this architecture.

**Local handling and evidence:** Identify implementation commits, tests,
documentation, or the structural no-action rationale.

**Final disposition:** Use one Audit Vocabulary term.

## Integration Plan

List unresolved work in dependency order. Remove this section only when every
inventory row has a final disposition and no implementation work remains.

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

Record dated results, delegated CI gates, waivers, and explicitly unclaimed
manual or hardware validation. This section is evidence, not a plan.
