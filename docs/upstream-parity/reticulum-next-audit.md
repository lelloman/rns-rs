# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-10-29`
- previous accepted version: `1.6.0`
- previous normative commit: `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5`
- target version: `1.6.0` (unchanged; no version bump yet)
- target tag or ref: `rgit:master` tip `c0fe08c08d75ffbcc8ef34bd7ad90636954b4738`
- target normative commit: `c0fe08c08d75ffbcc8ef34bd7ad90636954b4738` (provisional; rgit may advance before promotion)
- target root tree: `14ba7e4b639f2d8892f556d01ffd112e741fbdaf`
- target `RNS` tree: `262a61b232145db5c97b95d59e5f3d2a99e6ad36`
- version assertion: `RNS.__version__ == "1.6.0"`
- audited range: `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5..c0fe08c08d75ffbcc8ef34bd7ad90636954b4738`
- commits in range: `2`
- repositories checked: rgit (normative) and GitHub mirror
- local branch and revision inspected: local `dev` at `cbcce2e`

Both refreshes succeeded at 2026-10-29T06:16Z. The GitHub `master` tip is
`e40191b3d193b46b7f2d8a44424a594cd758839b`, which is `behind` the accepted
baseline and is allowed mirror lag. The normative rgit `master` tip
`c0fe08c0` (committed 2026-10-28T16:47Z) is `ahead` of the baseline by two
commits. No new tag or version bump exists, so there is no promotion target
yet. The new example-config text announces the phased stamp rollout: 1.6.1
enables generation and emission by default and 1.6.2 activates enforcement.

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
| 1 | `d7749b0b06008800601d18cd7be6e87b648d619b` | Stamp config wiring, path request stamp timeout, destination stamp handling | Needs coordinated port | Initial inventory only; see analysis |
| 2 | `c0fe08c08d75ffbcc8ef34bd7ad90636954b4738` | Fixed typo | Non-runtime | Comment-only typo in the `PR_STAMP_TIMEOUT` declaration |

## Per-Commit Analysis

### 1. `d7749b0b` — Stamp config wiring, path request stamp timeout, destination stamp handling

**Upstream change:**

- New `[stamps]` config section: `enforce_stamps` (sets both
  `STAMPS_ENFORCED` and `LR_STAMPS_ENFORCED`), `stamp_destinations`,
  `stamp_prs`, `stamp_lrs`, `destination_cost`, `destination_value`,
  `pr_cost`, `pr_value` (clamped to `0..=STAMP_COST_CAP`), `lr_cost` (clamped
  to `0..=LINK_COST_CAP`), and `lr_stamp_timeout` / `pr_stamp_timeout`
  (floats, floored at 0.020 s). The boolean options can only turn a feature on.
- New `[reticulum] hop_limiter`, clamped to `1..=PATHFINDER_M`, with a verbose
  log line at transport start when it differs from the default.
- Default changes: `STAMP_LRS` `True` → `False`; `DESTINATION_VALUE` 23 → 25.
- New `PR_STAMP_TIMEOUT = 15`: path request stamp generation runs under a
  watchdog that calls `cancel_work` on the job past the deadline, and emission
  is cancelled when no stamp results.
- `Destination` gains a per-destination target value (`set_value`, the
  `target_value` property, clamped to `DESTINATION_VALUE..=STAMP_COST_CAP`).
  `_announce` now reloads or regenerates the stamp when the held stamp's value
  is below the target, and both the store lookup and generation use the
  target value instead of `DESTINATION_COST` / `DESTINATION_VALUE`.
- `rnsd --exampleconfig` documents the new options; `using.rst` wording only.

**Rust applicability:** Applicable. On `dev` at `cbcce2e`:
`rns-net/src/common/config.rs` parses no `[stamps]` section or
`hop_limiter`; `rns-core/src/constants.rs` still has `STAMP_LRS = true`,
`DESTINATION_STAMP_VALUE = 23` and a constant `HOP_LIMITER`; the stamper's
`stamp_path_request` (`rns-net/src/stamper.rs`) has no timeout; and
`ensure_destination_stamp` (`rns-net/src/node.rs`) accepts any stored stamp
that meets `destination_cost` and has no per-destination target value. The
existing `global.stamp_destinations` / `global.stamp_path_requests` runtime
keys need reconciling with the new file options.

**Local handling and evidence:** None yet.

**Final disposition:** Needs coordinated port.

### 2. `c0fe08c0` — Fixed typo

**Upstream change:** Corrects "requset" in the `PR_STAMP_TIMEOUT` comment.

**Rust applicability:** None; comment text only.

**Local handling and evidence:** No change required.

**Final disposition:** Non-runtime.

## Integration Plan

1. Constant defaults: `STAMP_LRS = false`, `DESTINATION_STAMP_VALUE = 25`,
   `PATH_REQUEST_STAMP_TIMEOUT = 15`, with the constants tests updated.
2. Config: parse `[stamps]` and `[reticulum] hop_limiter` with upstream
   clamping and enable-only boolean semantics; make the hop limiter a runtime
   value instead of a constant; reconcile with the existing runtime config keys.
3. Path request stamp timeout: bound stamper path-request grinding by
   `pr_stamp_timeout` and cancel emission on expiry.
4. Destination target value: per-destination target with the upstream clamp,
   restamping when the held stamp is below target.
5. Native documentation for the new config options.

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

No acceptance results yet.
