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
- local branch and revision inspected: local `dev` at `cbcce2e`; integrated
  on `worktree-agent-a301172e8aa4682a6` from `a2b603d`

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
| 1 | `d7749b0b06008800601d18cd7be6e87b648d619b` | Stamp config wiring, path request stamp timeout, destination stamp handling | Integrated | `bf5112d`; `[stamps]` and `hop_limiter` parsing and startup wiring, runtime hop limiter, engine `StampRequirements`, `pr_stamp_timeout` cancellation, `Destination::set_value` target restamping, defaults `STAMP_LRS = false` / 25 / 15, `global.stamp_link_requests`, docs; `lr_cost` and `enforce_stamps` feed the shared per-destination link cost table of `290d6cc` |
| 2 | `c0fe08c08d75ffbcc8ef34bd7ad90636954b4738` | Fixed typo | Non-runtime | `0d125f2`; comment-only typo in the `PR_STAMP_TIMEOUT` declaration, recorded on the native constant |

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

**Local handling and evidence:** `bf5112d`, by integration plan step:

1. *Constants.* `rns-core/src/constants.rs`: `STAMP_LRS = false`,
   `DESTINATION_STAMP_VALUE = 25`, new `PATH_REQUEST_STAMP_TIMEOUT = 15` and
   `STAMP_TIMEOUT_MIN = 0.020`; `HOP_LIMITER` stays as the default of the
   now runtime limiter. Evidence: `stamp_defaults_match_upstream_parameters`.
2. *Config.* `rns-net/src/common/config.rs` parses a `[stamps]` section into
   `StampsSection` and `[reticulum] hop_limiter`. The four switches are
   enable-only (`no` keeps the default; an invalid boolean is an error, as
   ConfigObj `as_bool` raises); `enforce_stamps` sets both
   `stamps_enforced` and `lr_stamps_enforced`; costs and values clamp to
   `0..=STAMP_COST_CAP`, `lr_cost` to `0..=LINK_COST_CAP`, integers outside
   `i64` saturate before clamping, the timeouts are floored at 20 ms (NaN
   floors too, as Python's `max(0.020, nan)`; `inf` means no deadline), and
   `hop_limiter` clamps to `1..=PATHFINDER_M`. `RnsNode::from_config*`
   applies the result at startup through `Driver::apply_stamp_config`:
   the transport engine takes a runtime `StampRequirements`
   (`STAMPS_ENFORCED`, `DESTINATION_COST`, `PR_COST`) used by announce stamp
   validation and path request enforcement instead of the compile-time
   constants; the stamper and the node's announce builder take
   `destination_value` and `pr_value`; `lr_cost` becomes the default of the
   per-destination link cost table (`rns_net::stamps::LinkRequestCosts`,
   from `290d6cc`) that the announce builder and the responder share, which
   is upstream `get_link_cost`'s `LR_COST` fallback, and `enforce_stamps`
   turns on that table's `LR_STAMPS_ENFORCED` check; `stamp_lrs` and
   `lr_stamp_timeout` drive stamped link request creation in
   `driver/link_stamps.rs`; and the driver keeps the whole section as
   `stamp_settings`. Reconciliation with the runtime keys: the existing
   `global.stamp_destinations` and `global.stamp_path_requests`, the new
   `global.stamp_link_requests` and `global.lr_stamps_enforced` (from
   `290d6cc`) start from, and reset to, the configured values rather than
   the compile-time constants. The hop
   limiter is a driver value checked right after decoding and before the
   packet filter (Transport.py:2009). Review finding: the 1.6.0 rgit mapping
   of `134db17c` counted decode failures for hop counts at or above
   `PATHFINDER_M` as hop limiter hits, but upstream `Packet.unpack` rejects
   those first (Packet.py:250) and `Transport.inbound` counts a protocol
   violation (Transport.py:2008); the decoder check now uses `PATHFINDER_M`
   and such frames count as protocol violations, so with the default limiter
   `hop_limiter_hits` stays zero as upstream. Evidence:
   `stamps_section_defaults_to_the_protocol_constants`,
   `stamps_section_parses_every_option`,
   `stamps_section_booleans_can_only_enable`,
   `stamps_section_clamps_costs_and_timeouts`,
   `stamps_options_outside_the_stamps_section_are_ignored`,
   `hop_limiter_parses_and_clamps_to_pathfinder_range`,
   `apply_stamp_config_sets_engine_stamper_runtime_defaults_and_hop_limiter`,
   `from_config_applies_the_stamps_section_and_hop_limiter`,
   `hop_limited_frame_counts_a_hop_limiter_hit_not_a_protocol_violation`
   (rewritten for the configurable limiter and the malformed boundary),
   `runtime_config_stamp_flags_default_off_and_apply_to_engine_and_shared_flag`
   (extended to the new key),
   `stamp_requirements_default_to_the_protocol_constants`,
   `enforced_announce_stamps_use_the_configured_destination_cost`,
   `enforced_path_request_stamps_use_the_configured_cost`,
   `create_link_is_not_stamped_unless_stamp_lrs_is_enabled`, and
   `create_link_uses_the_configured_link_stamp_timeout`.
3. *Path request stamp timeout.* `rns-net/src/stamps.rs` gains
   `generate_stamp_until`, whose rayon workers check a deadline every 1024
   nonces; `stamper::stamp_path_request` grinds under `PR_STAMP_TIMEOUT`
   (`Stamper::set_path_request_timeout`) and on expiry logs the upstream
   warning, emits nothing and caches nothing. The deadline is exact rather
   than upstream's one-second watchdog polling. Evidence:
   `stamp_generation_gives_up_at_the_deadline`,
   `path_request_timeout_defaults_to_upstream_and_is_settable`, and
   `path_request_stamp_timeout_cancels_emission`.
4. *Destination target value.* `Destination` gains `target_value` and
   `set_value` (capped at `STAMP_COST_CAP`); the effective target is
   `min(STAMP_COST_CAP, max(value, destination_value))`
   (`StampTargets::destination_target`). Rust keeps no in-memory stamp per
   destination, so `announce_needs_stamp`, `ensure_destination_stamp` and
   `build_announce_packet` load the persisted stamp at the target value and
   grind at it, which regenerates a persisted stamp below the target as
   Destination.py:319-323 does. `StampTargets.destination_cost` is removed:
   emission no longer uses `DESTINATION_COST`, and the inbound requirement
   lives in the engine. Evidence:
   `destination_target_value_is_clamped_between_default_and_cap` and
   `destination_stamp_below_target_value_is_regenerated`.
5. *Documentation.* `docs/configuration.md` replaces the "no configuration
   key" Stamps text with the `[stamps]` reference, the enable-only and clamp
   semantics, the target-value restamping and the three runtime keys, and
   lists `hop_limiter`; `docs/rnstatus.md` describes the configurable
   limiter; the `rnsd --exampleconfig` text documents every new option
   (evidence: `example_config_documents_and_parses_the_stamps_section`).
   The upstream `using.rst` change is wording only.

Interop consequences: `python_rns_stamped_link_request_interop` now enables
`global.stamp_link_requests` before creating the stamped link, since link
request stamping is opt-in; against `c0fe08c0` Python stamps its destination
at value 25, the new default.

Responder-side enforcement against the per-destination cost
(`Destination.set_link_cost`, `LR_STAMPS_ENFORCED`) landed alongside in
`290d6cc` and is recorded in the 1.6.0 rgit parity record; `bf5112d` wires
`[stamps] lr_cost` and `enforce_stamps` into it.
Shared-instance clients (`connect_shared*`) parse only the instance keys and
have no stamper, so they neither apply `[stamps]` nor stamp their own
announces; this predates the range and is recorded as a caveat.

**Final disposition:** Integrated.

### 2. `c0fe08c0` — Fixed typo

**Upstream change:** Corrects "requset" in the `PR_STAMP_TIMEOUT` comment.

**Rust applicability:** None; comment text only.

**Local handling and evidence:** `0d125f2` records on the
`PATH_REQUEST_STAMP_TIMEOUT` documentation that upstream only corrected the
comment spelling; value and use are unchanged.

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

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable
  (not applicable: no pinned fixture changed and the range changes no wire
  encoding).
- [x] Exact-target live Python/Rust interop passes.
- [ ] Workspace tests, feature suites, formatting, and lint pass. Workspace,
  the `rns-hooks` workspace suite, formatting and both lints passed; the
  `rns-hooks-native`, `rns-ctl --features tls`, built-in hook E2E and web UI
  suites listed in earlier parity records were not run.
- [ ] Required build, Docker, hardware, and manual gates are recorded honestly.
  The rns-server Docker suite passed on the merged tree (see below); the
  full docker-e2e matrix, release builds, VPS smoke and hardware gates were
  not run.
  Not run: release and cross builds, the Docker matrix (notably
  `21_stamped_emission.sh`), the dual-VPS smoke and hardware validation.
- [x] Native documentation is updated for user-visible behavior.
- [ ] A final parity record is created from `PARITY-TEMPLATE.md`. Per the
  README workflow the parity record is written at promotion, after the
  target version is known and this file is renamed; rgit announces 1.6.1,
  so the records may become `reticulum-1.6.1-{audit,parity}.md` rather than
  `reticulum-1.6.0-rgit-2-{audit,parity}.md`.

## Acceptance Record

Integration run on 2026-10-29 at `0d125f2` (on `a2b603d`), x86_64 host with
32 cores. Exact-target interop used a disposable worktree of `c0fe08c0`
(`import RNS` reports 1.6.0 from that tree); the accepted baseline
`5d38ce30` was exercised from the configured checkout.

| Gate | Command | Result |
|---|---|---|
| Focused regressions | `cargo test -p rns-core --lib stamp`; `cargo test -p rns-net --lib` filtered to `config::tests`, `stamps::tests`, `stamper::`, `hop_limited`, `create_link`, `runtime_config_stamp`, `apply_stamp_config`, `destination_stamp_below`, `from_config_applies`; `cargo test -p rns-cli example_config` | All passed |
| Workspace | `cargo test --workspace --no-fail-fast` | 3,002 passed, 0 failed, 11 ignored (about 90 s wall) |
| Hooks feature suite | `cargo test --workspace --features rns-hooks --no-fail-fast` | 3,061 passed, 0 failed, 11 ignored |
| Formatting | `cargo fmt --all --check` | Clean |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings`; `cargo clippy -p rns-net --all-targets --features rns-hooks -- -D warnings`; `bash scripts/lint-host.sh` | Clean |
| Interop, baseline `5d38ce30` | `PYTHONPATH=<checkout> cargo test -p rns-net --test python_interop`; `PYTHONPATH=<checkout> cargo test -p rns-cli --test utility_interop -- --include-ignored` | 3/3 (Python stamped at value 24); 9/9 |
| Interop, target `c0fe08c0` | the same commands with `PYTHONPATH` at the `c0fe08c0` worktree | 3/3 (Python stamped at value 25; Rust cost-8 stamped link request in about 3 ms); 9/9 |
| Drift | `python3 scripts/check_upstream_drift.py --no-fetch --upstream-dir <checkout>` | Drift from cached refs: GitHub `e40191b3` behind, rgit `c0fe08c0` ahead by the two audited commits (the worktree has no `.local/reticulum-upstream.path`, hence `--upstream-dir`) |
| Docker, release builds, VPS smoke, hardware | Not run | Pending for promotion |

### Merged tree

Rerun on 2026-10-29 at `428c48a`, after the range landed on `dev` together
with the LINKCLOSE-on-timeout fix (`0e443a5`), the state snapshot
(`96be80f`), the per-destination link cost port (`290d6cc`) and the Docker
build change (`dce6ab6`), on the same host. The link cost port and this
range were reconciled in `bf5112d` and `428c48a` (see the per-commit
analysis).

| Gate | Command | Result |
|---|---|---|
| Formatting, lint | `cargo fmt --all --check`; both clippy commands; `bash scripts/lint-host.sh` | Clean |
| Workspace | `cargo test --workspace --no-fail-fast` | 3,021 passed, 0 failed |
| Hooks feature suite | `cargo test --workspace --features rns-hooks --no-fail-fast` | 3,080 passed, 0 failed |
| rns-net e2e, hooks | `cargo test -p rns-net --features rns-hooks --test e2e`, twice | 66 passed each run (about 39 s) |
| Interop, baseline `5d38ce30` | `python_interop`; `utility_interop -- --include-ignored` | 4/4; 9/9 |
| Interop, target `c0fe08c0` | the same against the `c0fe08c0` worktree | 4/4; 9/9 |
| Drift | `python3 scripts/check_upstream_drift.py --no-fetch` | rgit ahead by the two audited commits |
| Docker | `tests/docker/rns-server/run.sh` | 84 passed, 0 failed |

A first pass on the merged tree, taken while a Docker image build loaded
the host, failed `test_stamped_path_request_is_counted_by_the_transport_and_answered`
once (the new 15 s path request stamp timeout cancelled the grind) and the
link cost interop test against `c0fe08c0` (Python no longer stamps link
requests by default); `428c48a` records both fixes.

Mapping check: `git log --format='%h %(trailers:key=Upstream-Commit,valueonly)'
a2b603d..0d125f2` lists `d7749b0b…` for `bf5112d` and `c0fe08c0…` for
`0d125f2`, one trailer each.
