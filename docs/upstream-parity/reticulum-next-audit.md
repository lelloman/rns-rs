# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-10-29` (commit 5 integrated `2026-10-30`; extended to
  commit 15 on `2026-10-30`)
- previous accepted version: `1.6.0`
- previous normative commit: `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5`
- target version: `1.6.0` (unchanged; no version bump yet)
- target tag or ref: `rgit:master` tip `5b2b8afbdf0b71dc704515bec0d640be29ee4dfd`
  (extended on 2026-10-30 from `a8cc6cb239a3e9c44183b28eb1eaa1f88601e00b`,
  and on 2026-10-29 from the first tip `c0fe08c08d75ffbcc8ef34bd7ad90636954b4738`)
- target normative commit: `5b2b8afbdf0b71dc704515bec0d640be29ee4dfd` (provisional; rgit may advance before promotion)
- target root tree: `53c78882e8623cb930a27f44f7f73454da81e846`
- target `RNS` tree: `62151b00a54326194fd91d94157bfe37bf0dfbfb`
- version assertion: `RNS.__version__ == "1.6.0"`
- audited range: `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5..5b2b8afbdf0b71dc704515bec0d640be29ee4dfd`
- commits in range: `15` (2 inventoried at the first tip, 3 added when rgit
  advanced the same day, 10 added on 2026-10-30)
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
By the evening refresh (2026-10-29T20:24Z) rgit had advanced to `a8cc6cb2`
(committed 2026-10-29T20:01Z) with three further commits, inventoried as 3 to
5 below; `RNS.__version__` is still `1.6.0`.

The 2026-10-30 refresh found rgit at `5b2b8afb` (committed
2026-10-30T12:41Z), ten commits past `a8cc6cb2`, inventoried as 6 to 15. The
GitHub mirror is still at `e40191b3`, behind the baseline. The new range
announces the 1.6.0 release in the changelog, still without a version bump or
tag, and changes the announce wire format: the link request cost in the stamp
extension grows from one byte to two to carry a fraction (commit 9).

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
| 3 | `78fb90ea6f30baf7201a3fb79ec224bb5c1ca3c1` | Implemented fractional-value stamps | Integrated | `4d317ee`; `rns_crypto::stamp_value` with the verbatim `TAB` pinned by `TAB_DIGEST`/`PRM_DIGEST`, fixed-point `StampValue` replacing the integer value in validation, known destinations, path and link request stamps, discovery and the stamp store; floats on storage, RPC, API and `rnstatus`; integer values from earlier versions load as whole bits |
| 4 | `5f46fc6b4846b71929de62dc18c9fa0f3e9d651a` | Updated changelog | Non-runtime | `Changelog.md` adds the `hop_limiter` option, integrated under commit 1; not vendored and no runtime counterpart. Mapping landed. |
| 5 | `a8cc6cb239a3e9c44183b28eb1eaa1f88601e00b` | Cleanup, logging and parameter tuning | Integrated | `7993f1e`; fixed-point `StampCost` and `target_from_fp` behind `stamp_valid` and the key grinder, defaults 23.5 / 25 / 19.8 / 19.8 / 19.2, `STAMP_LRS = true`, `[stamps] always_stamp_lrs` and `global.always_stamp_link_requests`, docs; the link request cost fallback implements the documented intent rather than the expression as written (deliberate divergence, see analysis); stamped link keys ground on a thread per core |
| 6 | `2c142973bfb9b0ce6f46fa781d7ade4b81c796f0` | Cleanup (path request stamp diagnostics) | Integrated | Path request stamp diagnostics on the pathing target, with the new lenient-relay message |
| 7 | `34bb4ac88c8cf3a7b9ab2edc039213b878427eb8` | Cleanup (link request cost fallback) | Needs port | |
| 8 | `75465efad8aca353a622d934c2b54f001f72c164` | Fixed cap types | Needs port | |
| 9 | `796ef2d44b4aec30eb74a1d9210a432ebb1b9440` | Refactoring for fractional-value stamp support | Needs coordinated port | |
| 10 | `f57fa2655cabf928f2d7500b519442b6737b5e07` | Cleanup (defaults, default config, changelog) | Needs port | |
| 11 | `da027e9c0f68f5980d6425ab78e80ef13632bbbf` | Fixed pre-init link_id access | Needs port | |
| 12 | `2e6963c388ee99a5f9a93dab95a0514ed927e96c` | Updated changelog | Needs port | |
| 13 | `9b464382335bef878b282d19fea30d17bde8b847` | Added per-interface destination and PR cost configuration | Needs coordinated port | |
| 14 | `1a6e26ac2bdfc73e1cbaa7495e6cec04d25d8563` | Cleanup (whitespace) | Needs port | |
| 15 | `5b2b8afbdf0b71dc704515bec0d640be29ee4dfd` | Fixed missing interface parameter inheritances | Needs port | |

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

### 3. `78fb90ea` — Implemented fractional-value stamps

**Upstream change:** `stamp_value` returns a fractional value. The integer
part is the leading zero count of the stamp product (the former value, kept as
`stamp_value_legacy`); the fraction comes from the next 33 bits, normalized
and right-bisected into the authoritative 256-entry mantissa table `TAB`
(`TAB[f] = floor(2^33 * 2^(f/256))`), which floors the value onto a 1/256 grid
so a stamp is never over-valued. `stamp_valid` and every generator now compare
against `target_from_fp(cost_to_fp(cost))`; `load_destination_stamp` checks
the stored stamp with `stamp_valid` instead of comparing values. New
fixed-point helpers (`cost_to_fp`, `cost_to_bytes`, `cost_from_bytes`,
`cost_int`, `cost_str`) are added. `tests/stamps.py` is new.

**Rust applicability:** Applicable where a value is computed, recorded or
reported: announce validation (`Identity.validate_announce` records
`stamp_value`, exposed by `recall_stamp_value` and the known-destinations
store), link request validation (`Link.validate_request` sets
`link.stamp_cost`), path request stamps, interface discovery (`Discovery.py`
uses `RNS.Stamps`, and `rnstatus` prints `str(i["value"])`) and
`Identity.get_value`. Decisions do not change: a value lies in
`[lz, lz + 1)`, so comparing it with a whole-number cost gives the legacy
result, and `target_from_fp(c * 256)` is `2^(256 - c)`, the legacy target
(validity now includes a product exactly equal to the target, one point in
`2^256`). No caller uses the cost/byte helpers yet; they are not ported until
one does.

**Local handling and evidence:** `4d317ee`. `rns-crypto/src/stamp_value.rs`
adds `TAB` copied verbatim, `value_of_product`/`stamp_value`, and
`StampValue`, an exact fixed-point value in 1/256 units with `whole()`
(legacy value), `meets(cost)` (whole-number cost comparison), and `f64`
conversions. It replaces the `u32` value in `rns-core` announce validation,
path request stamps and the link request handshake, the `rns-crypto` stamped
key generator and `Identity::get_value`, and in `rns-net` known destinations,
announce events, stamped link keys, discovery, the destination stamp store and
the backbone peer pool ordering. Values leave the process as floats: the
known-destinations msgpack file, SQLite (`REAL` in the existing `INTEGER`
affinity column, so no migration), the stamp store, discovery persistence, the
RPC known-destination and discovered-interface entries, the `rns-ctl` identity
API, and `rnstatus`, which prints them as Python `str()` does. Integer values
written by earlier versions load as whole bits. The Docker
`21_stamped_emission.sh` poll floors the JSON value before its integer
comparison; `docs/configuration.md` describes fractional values. Evidence:
`table_matches_upstream_digests`, `values_match_upstream_vectors` (30
`(stamp, value)` pairs produced by upstream `78fb90ea` `stamp_value` over a
fixed workblock, leading zero counts 0 to 16),
`value_stays_within_its_legacy_integer_step`,
`value_is_monotone_in_the_product`, `extreme_products`,
`float_conversions_round_trip_on_the_grid`,
`integer_stamp_values_from_earlier_versions_load_as_whole_bits`,
`save_load_known_destinations_roundtrip` and the SQLite round trip with
fractional values, the SQLite v1 migration loading an `INTEGER` value,
`discovered_stamp_value_prints_like_python_str`, and
`insufficient_stamp_diagnostic_includes_calculated_value`. Against `5f46fc6b`
Python stamped its destination at value 25.78125 and `python_interop` matched
it, and the link request key value, exactly; against the baseline the whole
parts match.

**Final disposition:** Integrated.

### 4. `5f46fc6b` — Updated changelog

**Upstream change:** `Changelog.md` gains "Added `hop_limiter` configuration
option".

**Rust applicability:** Documentation only; the option itself is commit 1.

**Local handling and evidence:** Non-runtime. The upstream `Changelog.md`
release note is not vendored and carries no acceptance weight; the
`hop_limiter` option it announces is dispositioned under commit 1 and
documented in `docs/configuration.md`. Mapping landed.

**Final disposition:** Non-runtime.

### 5. `a8cc6cb2` — Cleanup, logging and parameter tuning

**Upstream change:**

- Fractional default costs and targets: `DESTINATION_COST` 23 → 23.5,
  `DESTINATION_VALUE` 25.0, `PR_COST` and `PR_VALUE` 19 → 19.8, `LR_COST`
  11 → 19.2; `STAMP_COST_CAP` and `LINK_COST_CAP` become floats. The
  `[stamps]` cost options are still parsed with `as_int`.
- `STAMP_LRS` returns to `True`; new `ALWAYS_STAMP_LRS = False` with the
  `[stamps] always_stamp_lrs` option, replacing `stamp_lrs`, which is no
  longer parsed or documented.
- `Link.__init__` sets `self.stamp_cost = RNS.Identity.recall_link_cost(h)
  or RNS.Transport.LR_COST if RNS.Transport.ALWAYS_STAMP_LRS else None`.
- A notice when link request stamp generation times out; `generate_stamp`
  and `generate_stamped_key` return `None` for the value and log an abort
  instead of a value of 0 when generation is cancelled.
- The example config now says link requests are stamped from 1.6.0 when the
  destination announced a cost.

**Rust applicability:** Applicable, and wider than the subject suggests.
`stamp_valid` turns the fractional costs into fixed-point targets, so an
announce stamp of value 23.3 is no longer valid at the default cost (it is not
stripped from the app data or recorded) even with enforcement off, and path
request stamps below 19.8 are no longer counted as stamped. Generation
targets (`DESTINATION_VALUE`, `PR_VALUE`, an `ALWAYS_STAMP_LRS` link cost of
19.2) are fractional too. Rust costs and targets were `u8` throughout
(`StampRequirements`, `StampTargets`, the generators), so this needed
fixed-point costs and `target_from_fp`. The announced link cost stays an
integer byte: `get_link_cost` applies `int()`, so the default announces 19.

Interop consequence, as upstream: releases before this commit grind
destination stamps at their old `DESTINATION_VALUE` of 23 (the 1.6.0 release)
or 25 (`d7749b0b`). A value-23 grind lands below 23.5 about half the time,
and such an announce from a 1.6.0 node that opted into `stamp_destinations`
is accepted while stamps are not enforced, but keeps its stamp extension in
the app data and records no link cost.

The new `Link.__init__` expression parses as
`(recall_link_cost(h) or LR_COST) if ALWAYS_STAMP_LRS else None` (confirmed
with `ast`: an `IfExp` whose test is `ALWAYS_STAMP_LRS`). As written, a link
request is never stamped unless `always_stamp_lrs` is set, whatever cost the
destination announced, and `STAMP_LRS = True` has no effect by default. The
option's own comment ("stamp link requests even when no link cost is
announced") and the example config of the same commit ("Link requests will
be stamped already from 1.6.0 if a cost has been announced by the
destination") both describe
`recall_link_cost(h) or (LR_COST if ALWAYS_STAMP_LRS else None)`.

**Decision (2026-10-30):** port the documented intent, not the expression as
written. This is a deliberate divergence until upstream corrects or confirms
the line. On the wire it only changes who stamps: an rns-rs initiator stamps
its request to a destination that announced a cost, where an `a8cc6cb2`
Python initiator without `always_stamp_lrs` sends it unstamped. Both are
accepted while `LR_STAMPS_ENFORCED` is off, and an enforcing Python responder
validates the rns-rs stamp normally. The divergence should be reported
upstream.

**Local handling and evidence:** `7993f1e`.

- `rns_crypto::stamp_value::StampCost` is a fixed-point cost in 1/256
  steps. `from_f64` rounds like `cost_to_fp` (19.8 → 5069/256) and clamps to
  `STAMP_COST_CAP`. `target()` is `target_from_fp` as a 256-bit big-endian
  number (only a zero cost has the 2^256 target, represented as "admits
  everything"), and `admits(product)` is the `stamp_valid` comparison. Unit
  tests pin nine costs and six fixed-point targets to values printed by
  upstream `a8cc6cb2`, check that whole costs reduce to the leading-zero
  check, and check that target and value agree off the exact-target boundary.
- `rns_core::stamp::stamp_valid`, `StampRequirements`, `StampTargets`,
  `Destination::effective_target_value`, the `[stamps]` section, the stamp
  store and every generator take `StampCost`; `StampValue::meets` compares
  fixed-point values (`value < get_link_cost()`). Path request stamps are
  validated against the target, as `path_request_stamp_valid` does, rather
  than through the value.
- Constants `DESTINATION_STAMP_COST` 23.5, `DESTINATION_STAMP_VALUE` 25,
  `PATH_REQUEST_STAMP_COST`/`_VALUE` 19.8, `LINK_REQUEST_STAMP_COST` 19.2,
  `STAMP_LRS = true`, `ALWAYS_STAMP_LRS = false`. Configured costs remain
  whole numbers (`as_int`); a leftover `stamp_lrs` line is ignored as
  upstream ignores it. `announced_link_cost` truncates the default to 19.
- `Driver::outbound_link_stamp_cost` implements the decision, including
  Python's falsy zero: an announced 0 falls back to `LR_COST` with
  `always_stamp_lrs`. `global.always_stamp_link_requests` switches it at
  runtime, and `global.stamp_link_requests` now defaults to true.
- Stamped link keys are ground on one thread per core
  (`available_parallelism`), as upstream grinds stamped keys in a process
  per core. The grind was single-threaded, which was harmless at the old
  default cost of 11 but averages 8.4 s at 19.2 on one core of the
  integration host (72k attempts/s), against a 15 s timeout. Attempts scale
  linearly (554k/s on 8 threads). The threads are dedicated rather than taken
  from the rayon pool: a first version on the pool let a grind running to its
  deadline stall path request and discovery stamps, which three driver tests
  caught.
- The aborted-generation logs of `generate_stamp`/`generate_stamped_key` have
  no counterpart: the Rust generators return `None` with no value, and the
  link stamp timeout was already logged (as a warning).
- Tests: `outbound_link_stamp_cost_prefers_the_announced_cost` (six cases
  plus the configured fallback),
  `create_link_is_stamped_without_an_announced_cost_when_always_stamp_lrs_is_set`,
  `create_link_is_not_stamped_when_stamp_lrs_is_off`,
  `runtime_config_stamp_link_requests_defaults_on_and_can_be_turned_off`,
  `stamps_section_ignores_the_removed_stamp_lrs_option`,
  `stamps_section_costs_are_whole_numbers`, the `StampCost` vectors above,
  and the updated config, runtime-config, stamper, e2e and Docker
  (`21_stamped_emission.sh`, now comparing fractional values with `jq`)
  expectations.
- `python_interop`: the Python helper grinds its destination stamp to at
  least the Rust cost rounded up (24), so the baseline's value-23 grind cannot
  fall below 23.5. The Python-initiated stamped link test sets
  `Transport.ALWAYS_STAMP_LRS` where it exists, because an `a8cc6cb2` Python
  initiator only stamps with it. Enabling it in the shared config instead made
  Python stamp every link at 19.2 and timed out the bidirectional test.

**Final disposition:** Integrated, with the documented link request
divergence.

### 6. `2c142973` — Cleanup (path request stamp diagnostics)

**Upstream change:** the transitional path request stamp diagnostics in
`Transport.inbound` move from `LOG_DEBUG` to `LOG_PATHING`. Every request
whose extension carries the marker now logs its value, as "Stamped path
request" or, when the flags byte is the `0xFF` sentinel of a stamp-aware
relay, as "Lenient-relayed path request", before the existing invalid or
unstamped-relay messages. "Unrecognized stamp payload" moves to
`LOG_PATHING` too.

**Rust applicability:** Applicable, logging only. The Rust messages were at
debug level and the value was only logged for valid stamps.

**Local handling and evidence:** `parse_path_request` logs on the pathing
target (Reticulum level 7) in upstream's order: the value as stamped or
lenient-relayed, then the reason the stamp fails. Unstamped requests stay at
trace. Covered by the existing path request tests; no behavior changed.

**Final disposition:** Integrated.

## Integration Plan

All five commits are integrated. Remaining before promotion: the gates below,
and reporting the `Link.py:311` precedence to upstream. If upstream confirms
the expression as written, `outbound_link_stamp_cost` must follow it.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable
  (not applicable: no pinned fixture changed and the range changes no wire
  encoding).
- [x] Exact-target live Python/Rust interop passes. Passed at `c0fe08c0`,
  `5f46fc6b` and the current tip `a8cc6cb2`; rerun if rgit advances.
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

### Fractional stamp values

Run on 2026-10-29 at `4d317ee` (on `a0bbaf4`, tree-identical to `fb6bc90`), same host. Interop against
`5f46fc6b` used a disposable worktree of that commit.

| Gate | Command | Result |
|---|---|---|
| Focused regressions | `cargo test -p rns-crypto --lib stamp_value`; `cargo test -p rns-net --lib storage`; `cargo test -p rns-cli --bin rnstatus discovered` | 6/6; 29/29; 4/4 |
| Formatting, lint | `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo clippy -p rns-net --all-targets --features rns-hooks -- -D warnings` | Clean |
| Workspace | `cargo test --workspace --no-fail-fast` | 3,030 passed, 0 failed, 11 ignored |
| Hooks feature suite | `cargo test --workspace --features rns-hooks --no-fail-fast` | 3,089 passed, 0 failed |
| Interop, baseline `5d38ce30` | `python_interop` | 4/4 (Python value 24, whole parts match) |
| Interop, `5f46fc6b` | `python_interop`; `utility_interop -- --include-ignored` | 4/4 (Python value 25.78125, matched exactly); 9/9 |
| Docker, release builds, VPS smoke, hardware | Not run | Pending for promotion |

### Cleanup and parameter tuning

Run on 2026-10-30 at `7993f1e` (on `ea0727b`), same host. Interop against
`a8cc6cb2` used the disposable worktree of that commit.

| Gate | Command | Result |
|---|---|---|
| Focused regressions | `cargo test -p rns-crypto --lib stamp_value`; `cargo test -p rns-core`; `cargo test -p rns-net --features rns-hooks --lib` | All passed (rns-net lib 1,241) |
| Formatting, lint | `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo clippy -p rns-net --all-targets --features rns-hooks -- -D warnings`; `bash scripts/lint-host.sh` | Clean |
| Workspace | `cargo test --workspace`, twice | 3,037 passed, 0 failed, 11 ignored each run |
| Hooks feature suite | `cargo test --workspace --features rns-hooks`, twice | 3,096 passed, 0 failed, 11 ignored each run |
| Feature checks | `cargo check -p rns-cli -p rns-ctl --bins --no-default-features`, and with `--features iface-tcp,rns-hooks-native` | Clean |
| Interop, baseline `5d38ce30` | `python_interop`; `utility_interop -- --include-ignored` | 4/4 (Python value 24); 9/9 |
| Interop, target `a8cc6cb2` | the same against the `a8cc6cb2` worktree | 4/4 (Python value 25.46875; Rust cost-8 stamped link request in about 1 ms); 9/9 |
| Upstream parse | `ast.parse` of `Link.py:311` | `IfExp` with test `ALWAYS_STAMP_LRS`, body `recall_link_cost(...) or LR_COST`, else `None` |
| Docker, release builds, VPS smoke, hardware | Not run | Pending for promotion; `21_stamped_emission.sh` changed and is unexercised |

The first full run after moving the link key grind onto the rayon pool failed
`own_path_request_with_stamp_prs_is_stamped_off_thread_then_broadcast`,
`stamp_path_request_action_sends_the_stamped_request_on_that_interface_only`,
`stamped_link_keys_give_up_at_deadline` and, in the hooks suite,
`discovery_announcer_emits_local_synthetic_announce`. Concurrent tests that
grind unattainable link costs to a deadline were holding every pool thread.
Dedicated threads fixed it; both suites then passed twice.
