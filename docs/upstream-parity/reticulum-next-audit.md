# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-10-29` (commit 5 integrated `2026-10-30`; extended to
  commit 15 on `2026-10-30` and to commit 23 on `2026-10-31`)
- previous accepted version: `1.6.0`
- previous normative commit: `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5`
- target version: `1.6.0` (unchanged; no version bump yet)
- target tag or ref: `rgit:master` tip `fe2fe94dd82030275bec150af87b4ec6292511c6`
  (extended on 2026-10-31 from `5b2b8afbdf0b71dc704515bec0d640be29ee4dfd`,
  on 2026-10-30 from `a8cc6cb239a3e9c44183b28eb1eaa1f88601e00b`,
  and on 2026-10-29 from the first tip `c0fe08c08d75ffbcc8ef34bd7ad90636954b4738`)
- target normative commit: `fe2fe94dd82030275bec150af87b4ec6292511c6` (provisional; rgit may advance before promotion)
- target root tree: `a236442f8591bc582d7cc958d8cb307af9f11b86`
- target `RNS` tree: `d60e3a206f47019ff541f93d1e47f5c036c8fa0e`
- version assertion: `RNS.__version__ == "1.6.0"`
- audited range: `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5..fe2fe94dd82030275bec150af87b4ec6292511c6`
- commits in range: `23` (2 inventoried at the first tip, 3 added when rgit
  advanced the same day, 10 added on 2026-10-30, 8 added on 2026-10-31)
- repositories checked: rgit (normative) and GitHub mirror
- local branch and revision inspected: local `dev` at `cbcce2e`; integrated
  on `worktree-agent-a301172e8aa4682a6` from `a2b603d`; commits 6 to 15
  integrated on `dev` from `7911858`; commits 16 to 23 on `dev` from
  `b857fed`

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

The rgit refresh failed on the morning of 2026-10-31 (the rgit service did
not answer link requests) and succeeded at 2026-10-31T15:07Z, finding
`fe2fe94d` (committed 2026-10-31T12:46Z), eight commits past `5b2b8afb`,
inventoried as 16 to 23. The GitHub mirror is still at `e40191b3`.
`RNS.__version__` is still `1.6.0`. The range adds an application flag and a
deferred initial hashmap to resource advertisements (commit 16), fixes the
unused path pool cull (commit 20) and makes the known destinations
`packet_hash` column nullable with a schema version 3 migration (commits 21
and 23). A new rgit branch, `patch_fix_channel_outlet_race`, holds one commit
(`794e437f`, 2026-05-19) that is already an ancestor of the accepted
baseline, so it adds nothing to the range.

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
| 5 | `a8cc6cb239a3e9c44183b28eb1eaa1f88601e00b` | Cleanup, logging and parameter tuning | Integrated | `7993f1e`; fixed-point `StampCost` and `target_from_fp` behind `stamp_valid` and the key grinder, defaults 23.5 / 25 / 19.8 / 19.8 / 19.2, `STAMP_LRS = true`, `[stamps] always_stamp_lrs` and `global.always_stamp_link_requests`, docs; the link request cost fallback implemented the documented intent rather than the expression as written (a divergence until upstream fixed the line in commit 7); stamped link keys ground on a thread per core |
| 6 | `2c142973bfb9b0ce6f46fa781d7ade4b81c796f0` | Cleanup (path request stamp diagnostics) | Integrated | `c615075`; path request stamp diagnostics on the pathing target, with the new lenient-relay message |
| 7 | `34bb4ac88c8cf3a7b9ab2edc039213b878427eb8` | Cleanup (link request cost fallback) | Integrated | `2d5540b`; `outbound_link_stamp_cost` follows the corrected fallback, `LR_COST` only for a missing announced cost; ends the commit 5 divergence |
| 8 | `75465efad8aca353a622d934c2b54f001f72c164` | Fixed cap types | Structurally covered | `62e5f68`; `STAMP_COST_CAP` and `LINK_COST_CAP` were never floats in Rust (`u8` 100 and 40, `u32` 100 for `StampCost`) |
| 9 | `796ef2d44b4aec30eb74a1d9210a432ebb1b9440` | Refactoring for fractional-value stamp support | Integrated | `2ee3d65`; two-byte fractional link cost in the announce extension (`EXT_PAYLOAD_LENGTH` 18), fractional link costs through the API, cost table, known destinations, storage (`REAL` columns), RPC and API, `as_float` for `[stamps]`, `required_discovery_value` and `discovery_stamp_value`, fractional `Destination::set_value`; the responder check implements the intent of an inverted upstream test (divergence, see analysis) |
| 10 | `f57fa2655cabf928f2d7500b519442b6737b5e07` | Cleanup (defaults, default config, changelog) | Integrated | `8cfb5f7`; defaults `PR_COST`/`PR_VALUE` 15.8 and `LR_COST` 12.5, the `rnsd --exampleconfig` values, docs and the Docker suite; the default config's commented `[stamps]` section has no generated counterpart (rns-rs writes no default config) and is pinned by the config parse test |
| 11 | `da027e9c0f68f5980d6425ab78e80ef13632bbbf` | Fixed pre-init link_id access | Structurally covered | `8d6d562`; a Rust link exists only once its keys do (`complete_create_link` after the stamped grind), with a fixed `[u8; 16]` id, so there is no id-less link to format |
| 12 | `2e6963c388ee99a5f9a93dab95a0514ed927e96c` | Updated changelog | Non-runtime | `8177ac8`; `Changelog.md` 1.6.0 release notes (phased stamp rollout, storage, sharding) and "cost-aware interface discovery and auto-connects", integrated under commit 13; not vendored |
| 13 | `9b464382335bef878b282d19fea30d17bde8b847` | Added per-interface destination and PR cost configuration | Integrated | `d9207a4`; `InterfaceStampCosts` on `InterfaceInfo`, parsed from the interface options and inherited by spawned interfaces; announce and path request stamps validated at the receiving interface's cost; `DST_COST`/`PR_COST` in discovery announces, parsed, stored and exposed over RPC; auto-connect gated on them and on Reticulum 1.5.7 |
| 14 | `1a6e26ac2bdfc73e1cbaa7495e6cec04d25d8563` | Cleanup (whitespace) | Non-runtime | `4c97527`; trailing whitespace on a blank line of `Reticulum.py`'s interface option parsing |
| 15 | `5b2b8afbdf0b71dc704515bec0d640be29ee4dfd` | Fixed missing interface parameter inheritances | Structurally covered | `2bf64fa`; spawned interfaces inherit through `DynamicInterfaceTemplate` and the driver's parent-to-child copy, which already cover every parameter the commit adds that rns-rs configures per interface |
| 16 | `c147201470f04c3240540d904b7190ac49f5e072` | Added app_flag signalling to resource advertisements | Integrated | Advertisement flag bit 6 (`AdvFlags::app_flag`) on every segment, delivered with the data (`DataReceived`, `ResourceReceived`, `ReceivedResourceFile`, `Callbacks::on_resource_received_with_app_flag`) and sent through `ResourceSendOptions`; advertisements over the link MDU are packed without their hashmap and the `HASHMAP_IS_EMPTY` (`0xFE`) request is implemented on both sides; the block-size rename in the MDU formulas changes no value |
| 17 | `9152bc1319de9eda8d675144bca38effa2e2911b` | Added app_flag getter | Integrated | `ResourceAdvertisement::app_flag_set`; the flag reaches the AcceptApp decision through `ResourceAcceptQuery` and `Callbacks::on_resource_accept_query_with_app_flag` |
| 18 | `81b6ba364cd5d5e0c6befd0770781ab1e45b9b85` | Enabled new stamp job runner on Android | Structurally covered | rns-rs grinds stamps and stamped link keys natively on every target (rayon pool and per-core threads in `rns-net::stamps`), with no Python `multiprocessing` runner to select |
| 19 | `2ef855c892947fa7a4b5ecc2797c0d0281a6ce52` | Fixed log formatting | Needs port | |
| 20 | `1ee89ad8d681e2fa2d2d041f7360ca3a95876be5` | Fixed cull entry index | Needs port | |
| 21 | `eab2983b9516a29d6699a3c54c36691e6113b0e3` | Fixed invalid schema constraint | Needs port | |
| 22 | `d45a5860fdf57b35c4906c22920653476f065f7e` | Cleanup | Needs port | |
| 23 | `fe2fe94dd82030275bec150af87b4ec6292511c6` | Pre-release migrations | Needs port | |

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
validates the rns-rs stamp normally. Upstream corrected the line the same
day (commit 7, `34bb4ac8`), before it was reported, which ends the
divergence.

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

**Final disposition:** Integrated. The link request divergence ended with
commit 7.

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

### 7. `34bb4ac8` — Cleanup (link request cost fallback)

**Upstream change:** `Link.__init__` replaces the `a8cc6cb2` expression with
`self.stamp_cost = recall_link_cost(h)` followed by
`if self.stamp_cost == None and ALWAYS_STAMP_LRS: self.stamp_cost = LR_COST`.

**Rust applicability:** Applicable. This is the documented intent that
commit 5 already implemented, with one difference: the fallback now tests
`== None` instead of Python truthiness, so a destination that announces cost
0 is not stamped even with `always_stamp_lrs`. rns-rs fell back to `LR_COST`
for an announced 0.

**Local handling and evidence:** `Driver::outbound_link_stamp_cost` returns
the announced cost whenever one was recalled, 0 included, and `LR_COST` only
when none was. `handle_create_link` still requires a non-zero cost and
`STAMP_LRS` before grinding. Tests:
`outbound_link_stamp_cost_prefers_the_announced_cost` (the zero cases now
expect cost 0) and
`create_link_is_not_stamped_when_zero_is_announced_even_with_always_stamp_lrs`.
The Python interop command that sets `ALWAYS_STAMP_LRS` stays, because an
`a8cc6cb2` Python initiator still needs it.

**Final disposition:** Integrated.

### 8. `75465efa` — Fixed cap types

**Upstream change:** `STAMP_COST_CAP` and `LINK_COST_CAP` return from the
floats `100.0` and `40.0` of `a8cc6cb2` to the integers 100 and 40.
`target_from_fp` asserts `fp <= STAMP_COST_CAP * COST_FP`, which an integer
cap keeps exact.

**Rust applicability:** Structurally covered. The Rust caps were never
floats: `constants::STAMP_COST_CAP` and `LINK_COST_CAP` are `u8` 100 and 40,
`rns_crypto::stamp_value::STAMP_COST_CAP` is `u32` 100, and a const assert
keeps the two cost caps equal.

**Final disposition:** Structurally covered; mapping only.

### 9. `796ef2d4` — Refactoring for fractional-value stamp support

**Upstream change:**

- **Wire format.** `Identity.LRCOSTLENGTH` 1 → 2, so `EXTPAYLOADLENGTH`
  17 → 18. `Destination.announce` ends the extension with
  `bytes([cost_bytes[1], cost_bytes[0]])` for `cost_to_bytes(get_link_cost())`:
  the 1/256 fraction, then the whole part as the trailing anchor.
  `validate_announce` reads the anchor's low seven bits and the byte before it
  as `cost_from_bytes`; a set anchor high bit or a cost above
  `STAMP_COST_CAP` still marks an unknown format.
- **Fractional link costs.** `Destination.set_link_cost` keeps
  `max(0, min(float(cost), LINK_COST_CAP))`, `get_link_cost` returns a float
  clamped to `STAMP_COST_CAP` instead of `int()`, `recall_link_cost` and
  `recall_value` document floats, and the SQLite `stamp_value` and `lr_cost`
  columns become `REAL` (also in the version 2 migration). `Examples/Link.py`
  sets 14.2.
- **Fractional targets and options.** `Destination.target_value` and
  `set_value` use `float()`, and the restamp check compares against
  `quantize_cost(target_value)` (new `Stamps.quantize_cost`). The `[stamps]`
  costs, `required_discovery_value` and `discovery_stamp_value` are read with
  `as_float`.
- **Responder check.** `Link.validate_request` becomes
  `if LR_STAMPS_ENFORCED and stamp_valid(peer_pub_bytes, owner.get_link_cost(),
  stamp_material): raise ValueError("Insufficient link request stamp value")`,
  replacing `value < owner.get_link_cost()`.
- **Discovery.** The redundant `value < required_value` line after the
  `stamp_valid` check is removed.
- **Logging.** Debug lines for incoming link request values and deferred key
  generation are removed; the link MTU signalling line moves to
  `LOG_PATHING`.

**Rust applicability:** Applicable, and the most invasive commit of the
range: the extension length is a wire format change, and every link cost was
a `u8`.

Interop consequence: the one-byte and two-byte extensions do not read each
other. A new parser takes the last 18 bytes of an old 17-byte extension, so
its marker check fails on the preceding app data byte (or the app data is
too short), and the announce is accepted as unstamped with the extension
left in its app data. The reverse holds on an old node. Stamped announces
therefore only interoperate between nodes at or after this commit. Releases
without destination stamping (1.5.x and earlier) are unaffected, and the
1.6.0 release does not emit destination stamps by default.

The new responder check is inverted as written: with `LR_STAMPS_ENFORCED`
it raises, and drops the request, exactly when the stamp *is* valid, and
accepts an insufficient one. The error message and the previous expression
both describe `not stamp_valid(...)`. Enforcement is off by default, so the
default behavior is unaffected.

**Decision (2026-10-30):** as for the commit 5 fallback, port the intent:
drop requests whose stamp is not valid for the destination's cost. This is a
deliberate divergence until upstream corrects or confirms the line. It is
not reported upstream: the maintainer has stated they do not want
LLM-assisted reports or contributions, so each audit rechecks the line
instead. `upstream_inverted_link_request_check_drops_valid_stamps`
(`rns-net/src/common/link_manager/tests.rs`) evaluates the upstream
expression on the same requests as the responder. On the wire it only matters to an enforcing
responder: an enforcing rns-rs node accepts sufficient stamps and drops
insufficient ones, where an enforcing `796ef2d4` Python node would do the
opposite.

**Local handling and evidence:**

- `constants::LR_COST_LENGTH = 2` (`EXT_PAYLOAD_LENGTH` 18).
  `rns_core::stamp::link_cost_ext_bytes` and `link_cost_from_ext_bytes`
  encode and decode the two bytes, and `ValidatedAnnounce::apply_stamp` reads
  `lr_cost` through the latter. `StampCost::from_fp_checked` rejects costs
  above the cap read off the wire.
- `lr_cost` is `Option<StampCost>` on `ValidatedAnnounce`, `ReceivedAnnounce`,
  the known destination state, events, `KnownDestination` and RPC entries.
  The file store writes a float, the SQLite columns are created (and added by
  the migration) as `REAL`, and both read integer costs of earlier versions
  as whole bits through `storage::stored_link_cost`. The RPC and the
  `/api/identity` JSON report a float.
- `LinkRequestCosts` holds `StampCost`; `RnsNode::set_link_cost` takes and
  returns `f64`, and `link_cost` returns `f64`. `rns_core::stamp::clamp_cost`
  mirrors `max(0, min(cost, cap))`, NaN to 0 and infinity to the cap, and is
  shared by `clamp_link_cost`, the `[stamps]` parser, `discovery_stamp_value`
  and `required_discovery_value`. `announced_link_cost` no longer truncates.
- `Destination::set_value` takes `f64`. The persisted stamp is reloaded only
  when `stamp_valid` at the effective target, which is the quantized target
  comparison.
- The responder check (`LinkManager`) drops a request when
  `link_request_stamp_valid` (new, `stamp_valid` over the request keys) is
  false, implementing the decision above.
- Discovery: `DiscoveryConfig::stamp_value`, the driver's required value,
  `generate_discovery_stamp` and `parse_interface_announce` take `StampCost`.
  The discovery runtime key `stamp_value` is a float (at most
  `STAMP_COST_CAP`). The removed `value < required_value` line had no Rust
  counterpart: validation was already `stamp_valid` only.
- The removed link debug lines have no Rust counterpart; Rust does not log
  the link MTU signalling.
- Tests: `link_cost_ext_bytes_round_trip_like_upstream` (bytes for 12.5 and
  14.2 as upstream builds them, the grid round trip, and the rejected
  encodings), `test_announce_stamp_with_one_byte_link_cost_is_not_stamped`,
  `link_cost_setter_clamps_like_upstream`, `stamps_section_costs_are_fractional`,
  the SQLite migration test (integer and out-of-range costs), and fractional
  costs in the existing link cost, stamper, storage, driver, e2e and Docker
  (`21_stamped_emission.sh` expects `lr_cost` 19.19921875) tests.
- `python_interop` reports Python's `Identity.LRCOSTLENGTH`. Against a
  one-byte release the Python-stamped test asserts the mixed-format behavior
  (accepted as unstamped, 17 extension bytes left in the app data, no link
  cost recorded) and the Rust-announced test skips. Both run in full against
  `796ef2d4` with fractional costs, 8.5 and 9.25.

**Final disposition:** Integrated, with the documented responder check
divergence.

### 10. `f57fa265` — Cleanup (defaults, default config, changelog)

**Upstream change:** `PR_COST` and `PR_VALUE` 19.8 → 15.8 and `LR_COST`
19.2 → 12.5. The default config gains a commented-out `[stamps]` section
listing the defaults (23.5, 25.0, 15.8, 15.8, 12.5, 15, 15) and `#####`
section separators; the `rnsd` example config shows the fractional
defaults. The changelog lists the stamp work, the stamper optimizations and
"various minor bugs".

**Rust applicability:** Applicable for the defaults and the example config.
The lower costs also shorten every grind: a stamped link request to a
destination that sets no cost now averages about 2^12.5 attempts, well below
the 15 s timeout even single-threaded. rns-rs generates no default config
file, so the new default config section has no counterpart; the changelog
is not vendored.

**Local handling and evidence:** `PATH_REQUEST_STAMP_COST` and
`PATH_REQUEST_STAMP_VALUE` are `cost_to_fp(15.8)` (4045/256) and
`LINK_REQUEST_STAMP_COST` is `cost_to_fp(12.5)` (3200/256), pinned in
`stamp_defaults_match_upstream_parameters`. `rnsd --exampleconfig` and
`docs/configuration.md` show the upstream defaults as fractional values, and
`parse_default_config` now includes the upstream default config's commented
`[stamps]` section and checks it leaves the defaults in place.
`21_stamped_emission.sh` expects the announced `lr_cost` of 12.5. The
dedicated link stamp threads of commit 5 stay: they cost nothing at the new
default and keep high per-destination costs fast.

**Final disposition:** Integrated.

### 11. `da027e9c` — Fixed pre-init link_id access

**Upstream change:** `Link.__str__` returns `"<pending link>"` while
`link_id` is still `None`. A stamped initiator link has no id until its
deferred keys are ground (commit 5's `STAMP_LRS` default), and logging such a
link raised.

**Rust applicability:** Structurally covered. The driver grinds stamped keys
before any link exists and only then calls `complete_create_link`, which
builds the link and its id together; ids are fixed `[u8; 16]` arrays and
never optional.

**Final disposition:** Structurally covered; mapping only.

### 12. `2e6963c3` — Updated changelog

**Upstream change:** `Changelog.md` gets the 1.6.0 release notes: the SQLite
storage backend, the memory rework, path table sharding, and the phased
network stamp rollout (1.6.0 verifies without enforcing and stamps link
requests to destinations that announce a cost, 1.6.1 enables emission,
1.6.2 enforcement). It adds "cost-aware interface discovery and
auto-connects" and moves the 1.5.7 entry below the verification
instructions. Still no version bump or tag.

**Rust applicability:** Non-runtime. The changelog is not vendored. The
rollout matches the defaults already integrated, and the cost-aware
discovery entry is the code of commit 13.

**Final disposition:** Non-runtime; mapping only.

### 13. `9b464382` — Added per-interface destination and PR cost configuration

**Upstream change:**

- Interface options `destination_cost` and `pr_cost` (`as_float`, clamped to
  `0..=STAMP_COST_CAP`) set `Interface._destination_cost` / `_pr_cost`. The
  `destination_cost` and `pr_cost` properties fall back to
  `Transport.DESTINATION_COST` / `PR_COST`. Spawned Auto, Backbone, I2P, TCP
  server and Weave interfaces copy them from their parent.
- `Identity.validate_announce` defaults `required_value` to
  `packet.receiving_interface.destination_cost` (else `DESTINATION_COST`), and
  `Transport.inbound` validates path request stamps at
  `packet.receiving_interface.pr_cost`.
- Discovery announces carry `DST_COST` (0xFB) and `PR_COST` (0xFA), the
  quantized costs of the announced interface. The handler parses them with
  `quantize_cost` into the `dst_cost` / `pr_cost` info keys. Auto-connect
  skips an interface whose `dst_cost` exceeds the local
  `quantize_cost(DESTINATION_VALUE)` or whose `pr_cost` exceeds
  `quantize_cost(PR_VALUE)`, a missing cost counting as 0.
  `AUTOCONNECT_MIN_V` rises from 1.5.2 to 1.5.7.
- Decode failures log "Could not decode discovered interface".

**Rust applicability:** Applicable. The costs are new configuration, the
validation sites move from node-wide to per-interface costs, and the
discovery fields are an additive wire change that older parsers ignore.

**Local handling and evidence:**

- `rns_core::transport::types::InterfaceStampCosts` (two optional
  `StampCost`s with fallback accessors) is a new `InterfaceInfo` field. The
  engine validates announce stamps at the receiving interface's
  `destination_cost` and path request stamps at its `pr_cost`, falling back to
  `StampRequirements`.
- `node::parse_interface_stamp_costs` reads the options (`as_float`,
  `clamp_cost`; a non-number is an interface configuration error, as
  ConfigObj raises). `InterfaceConfig`, `StartContext`, `StartedInterface`
  and `DynamicInterfaceTemplate` carry the costs, and backbone peer pool
  candidates keep them. Spawned interfaces inherit them through the
  template and through `handle_dynamic_interface_up_event`, the central
  parent-to-child copy that also serves Weave peers. `DiscoveryConfig` keeps
  the interface's costs for its announces.
- `InterfaceAnnouncer::pack_interface_info` adds `DST_COST` and `PR_COST` as
  floats, resolving costs the interface does not set against the node's
  current `StampRequirements` (set before each announce).
  `parse_interface_announce` reads them, and rejects an announce whose cost
  is not a finite number, as upstream's `quantize_cost` raises.
  `DiscoveredInterface::dst_cost` / `pr_cost` are persisted in the discovery
  store and reported over RPC (`dst_cost`, `pr_cost`).
- `discovered_costs_affordable` gates discovery-origin backbone peer pool
  candidates against the stamper's `destination_value` and
  `path_request_value`, with missing costs as 0.
  `AUTOCONNECT_MIN_VERSION` is 1.5.7 for `RNS`; rns-rs announcers remain
  exempt from the version check.
- The decode-failure wording has no Rust counterpart; the parser's
  rejections log their own reasons.
- Tests: `enforced_announce_stamps_use_the_receiving_interface_cost`,
  `enforced_path_request_stamps_use_the_receiving_interface_cost`,
  `interface_stamp_costs_are_fractional_and_clamped`, the static registration
  and dynamic inheritance tests (both now check the costs),
  `announcer_packs_the_interface_stamp_costs`,
  `parse_reads_announced_stamp_costs`, the discovery storage round trip,
  `discovered_peer_pool_requires_affordable_stamp_costs`, and the version
  bounds in `discovered_peer_pool_requires_verified_implementation_unless_overridden`.
  The cached discovered peers of two e2e peer pool tests announce 1.5.7
  instead of 1.5.5, which no longer qualifies.
- Docs: per-interface costs in `docs/configuration.md`, announced costs and
  the auto-connect gate in `docs/interface-discovery.md`.

**Final disposition:** Integrated.

### 14. `1a6e26ac` — Cleanup (whitespace)

**Upstream change:** removes trailing whitespace from a blank line after the
`ifac_size` option parsing in `Reticulum.py`.

**Rust applicability:** Non-runtime.

**Final disposition:** Non-runtime; mapping only.

### 15. `5b2b8afb` — Fixed missing interface parameter inheritances

**Upstream change:** configured I2P peers are spawned on a thread 1.5 s after
the parent starts, so they see the attributes `Reticulum.py` applies to the
parent after construction, and they now inherit `IN`/`OUT`, mode, bitrate,
`recursive_prs`, gravity, `HW_MTU`, `announces_to_internal` /
`announces_from_internal`, `announce_cap`, the ingress and egress control
parameters, the announce rate parameters and the stamp costs; a failing peer
is logged instead of aborting the others. Accepted I2P peers also take `IN`/
`OUT`, `announces_*`, `announce_cap` and `recursive_prs` from the parent,
and Weave peers `announces_*`, `announce_cap`, `recursive_prs` and the egress
control parameters. The changelog adds "path retainment prioritization for
slow interfaces" and this fix.

**Rust applicability:** Structurally covered. rns-rs does not copy fields
per interface class. Children of listener interfaces (I2P, TCP and Backbone
servers, Auto, local) are registered through `DynamicInterfaceTemplate`,
which applies mode, gravity, `recursive_prs`, `announces_*`, the stamp costs
and IFAC, while the factory hands them the parent's ingress control (which
includes the egress parameters). Children of registered parents (Weave
peers) also pass through `handle_dynamic_interface_up_event`, which copies
the same set plus `announce_cap` and the announce rate parameters. The
remaining fields have no per-interface configuration in rns-rs: I2P bitrate
and hardware MTU are fixed, `announce_cap` and the announce rate parameters
come from node-wide defaults or runtime keys, and I2P peers are always in and
out capable, as the upstream parent is once configured. The configured I2P
peers start with the interface, after its settings are known, so the 1.5 s
delay has no counterpart. The changelog's path retainment entry describes
behavior from the earlier, already audited range.

**Final disposition:** Structurally covered; mapping only.

### 16. `c1472014` — Added app_flag signalling to resource advertisements

**Upstream change** (`Examples/Resource.py`, `RNS/Link.py`, `RNS/Packet.py`,
`RNS/Resource.py`; no dependency on earlier unintegrated commits):

- `Resource(..., app_flag=False)` stores an application flag, packs it as bit 6
  of the advertisement flags (`self.a << 6`), passes it to every following
  segment, and sets `resource.app_flag` from the received advertisement. The
  example sets and logs it.
- `ResourceAdvertisement(..., mdu=None)` defaults to `Link.MDU`; the sender
  passes `self.link.mdu` for the first advertisement and its retries. When the
  packed advertisement exceeds that MDU, it is packed again with `m = b""`.
- A new request flag `HASHMAP_IS_EMPTY = 0xFE`. The receiver's adv-time
  hashmap update no longer cancels on zero hashes for segment 0, and
  `request_next` sends `0xFE` with no last map hash and no part hashes while
  `hashmap[0]` is unknown, then waits for an HMU. The sender treats `0xFE` as
  a hashmap request without the 4-byte last map hash, skips the search
  (`search_start = search_end = 0`, so `part_index` stays at the receiver's
  minimum consecutive height) and the alignment check, and sends that segment.
- `Link.MDU`, `link.update_mdu` and `Packet.ENCRYPTED_MDU` use
  `AES256_BLOCKSIZE` instead of `AES128_BLOCKSIZE`. Both are 16, so no value
  changes.

**Rust applicability:** Needs port. rns-rs ignored bit 6, and its receiver
answered an advertisement without a hashmap with `0xFF` and a zero last map
hash, which the upstream sender cannot match: a Python sender on a link with
an MDU below the advertisement size could not complete a transfer to rns-rs.
rns-rs senders also never deferred the hashmap, so on such a link their
advertisement exceeded the MDU.

**Implementation:**

- rns-core: `AdvFlags::app_flag` (bit 6), `RESOURCE_HASHMAP_IS_EMPTY`,
  `ResourceAdvertisement::pack_for_mdu`, `ResourceSender::advertisement_mdu`
  (default `LINK_MDU`) used by every advertisement, the `0xFE` request in
  `ResourceReceiver::request_next` and its handling in
  `ResourceSender::handle_request`/`build_hmu`, and `app_flag` on
  `ResourceAction::DataReceived` (carried through `AssemblyData`, so the
  assembly worker keeps it).
- rns-net: every sender, including stream segments, takes the flag and the
  link's current MDU (`configure_sender`). The flag reaches
  `LinkManagerAction::ResourceReceived`, disk-backed `ReceivedResourceFile`
  and split Resources (the last segment's flag, as Python reports the
  concluding segment's). New additive API: `ResourceSendOptions`,
  `NodeHandle::send_resource_with_options` and
  `send_resource_reader_with_options`, `LinkManager::send_resource_with_options`
  and `send_resource_stream_with_options`, and
  `Callbacks::on_resource_received_with_app_flag`, whose default forwards to
  `on_resource_received`, so existing callbacks are unchanged. Request and
  response Resources send the flag clear, as upstream.
- `docs/protocol-spec.md` documents bit 6, the deferred hashmap and `0xFE`.
- Not exposed: the rns-ctl HTTP/WebSocket resource events and send endpoint
  keep their fields; they can add the flag when a client needs it.

**Evidence:** `advertisement_too_large_for_link_mdu_defers_the_initial_hashmap`
(fails on the old receiver: the first request is `0xFF`),
`advertisement_within_link_mdu_keeps_its_hashmap`,
`app_flag_reaches_the_receiver`, `test_adv_flags_app_flag_is_bit_6`,
`resource_app_flag_is_advertised_and_delivered`,
`split_resource_segments_all_carry_the_app_flag`, and
`python_rns_bidirectional_tcp_interop`, which now sends a flagged Resource
each way: Python at `fe2fe94d` receives `app_flag = True` and its flagged
Resource arrives flagged; Python at the baseline sends the bit clear and has
no attribute for it. The deferred hashmap has no live Python case: a Python
advertisement fits the default link MDU (431 bytes) and only links with a
smaller negotiated MTU defer it.

**Final disposition:** Integrated.

### 17. `9152bc13` — Added app_flag getter

**Upstream change** (`RNS/Resource.py`): `ResourceAdvertisement.app_flag_set()`
returns bit 6 of the advertisement flags. Under `ACCEPT_APP`, `Link.py` passes
the unpacked `ResourceAdvertisement` to the application's resource callback,
so the getter lets an application decide acceptance by the flag.

**Rust applicability:** Needs port. rns-rs asks the application through
`Callbacks::on_resource_accept_query`, which carried the hash, the transfer
size and the metadata flag but not the application flag.

**Implementation:** `ResourceAdvertisement::app_flag_set`;
`LinkManagerAction::ResourceAcceptQuery` carries `app_flag` from the
receiver's advertised flags, and the driver calls the new
`Callbacks::on_resource_accept_query_with_app_flag`, whose default forwards
to `on_resource_accept_query`.

**Evidence:** `resource_accept_query_reports_the_app_flag` (both flag values,
from the advertisement getter to the accept query).

**Final disposition:** Integrated.

### 18. `81b6ba36` — Enabled new stamp job runner on Android

**Upstream change** (`RNS/Stamps.py`): `job_android` now dispatches to
`job_android_persistent` (forked worker processes sharing an `mmap` stop flag
and a manager dict) when `ANDROID_USE_PERSISTENT` is set, which it is, and
keeps the previous runner as `job_android_legacy`. Both runners use PyNaCl's
SHA-256 only when `ANDROID_PREFER_NACL` is set (also on). The persistent
runner's progress message names the stamp cost.

**Rust applicability:** Structurally covered. The Android runners choose how
Python spreads the grind across processes on that platform; the stamp,
workblock, target and validity are unchanged. rns-rs has no per-platform
runner: `rns_net::stamps::generate_stamp_until` grinds on the rayon pool and
`generate_stamped_link_keys` on one scoped thread per available core, on every
target including Android, with the same `rns_crypto` hash.

**Final disposition:** Structurally covered; mapping only.

## Integration Plan

Commits 1 to 15 have a final disposition; commits 16 to 23 are inventoried
and are integrated one at a time in upstream order. The `Link.py:311` precedence of
commit 5 was corrected upstream in commit 7 before it was reported. Remaining
before promotion: the gates below. The inverted `Link.validate_request`
stamp check of commit 9 is not reported upstream (see its analysis); each
audit rechecks it (still present at `fe2fe94d`). If upstream confirms that expression as written, the
`LinkManager` responder check must follow it.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable.
  No pinned fixture changed. Commit 9 changes the announce stamp extension;
  its two trailing bytes are pinned to the bytes upstream builds for 12.5 and
  14.2 (`link_cost_ext_bytes_round_trip_like_upstream`), and live interop
  covers both formats.
- [x] Exact-target live Python/Rust interop passes. Passed at `c0fe08c0`,
  `5f46fc6b`, `a8cc6cb2`, `796ef2d4` and the current tip `5b2b8afb`; rerun if
  rgit advances.
- [ ] Workspace tests, feature suites, formatting, and lint pass. Workspace,
  the `rns-hooks` workspace suite, formatting and both lints passed; the
  `rns-hooks-native`, `rns-ctl --features tls`, built-in hook E2E and web UI
  suites listed in earlier parity records were not run.
- [ ] Required build, Docker, hardware, and manual gates are recorded honestly.
  The rns-server Docker suite passed on the merged tree (see below); the
  full docker-e2e matrix, release builds, VPS smoke and hardware gates were
  not run.
  Not run: release and cross builds, the Docker matrix (notably
  `21_stamped_emission.sh`, which now expects an `lr_cost` of 12.5), the
  dual-VPS smoke and hardware validation.
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

### Commits 6 to 15 (rgit tip `5b2b8afb`)

Run on 2026-10-30 at `2bf64fa` (on `7911858`), same host. Interop against
`796ef2d4` and `5b2b8afb` used the disposable worktree checked out at each
commit.

| Gate | Command | Result |
|---|---|---|
| Focused regressions | `cargo test -p rns-core`; `cargo test -p rns-net --lib`; `cargo test -p rns-net --test e2e` | All passed (rns-net lib 1,230; e2e 66) |
| Formatting, lint | `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo clippy -p rns-net --all-targets --features rns-hooks -- -D warnings`; `bash scripts/lint-host.sh` | Clean |
| Workspace | `cargo test --workspace --no-fail-fast` | 3,046 passed, 0 failed, 11 ignored |
| Hooks feature suite | `cargo test --workspace --features rns-hooks --no-fail-fast` | 3,105 passed, 0 failed, 11 ignored |
| Feature checks | `cargo check -p rns-cli -p rns-ctl --bins --no-default-features`, and with `--features iface-tcp,rns-hooks-native` | Clean |
| Interop, baseline `5d38ce30` | `python_interop`; `utility_interop -- --include-ignored` | 4/4 (one-byte extension: the Python-stamped announce reads as unstamped with its 17 extension bytes in the app data, and the Rust-announced link cost test skips); 9/9 |
| Interop, `796ef2d4` | `python_interop` | 4/4 (two-byte extension, Rust cost-8.5 stamped link request, Python cost-9.25 request accepted by the enforcing Rust responder) |
| Interop, target `5b2b8afb` | `python_interop`; `utility_interop -- --include-ignored` | 4/4 (Python value 25.03515625); 9/9 |
| Docker, release builds, VPS smoke, hardware | Not run | Pending for promotion |

The first workspace run failed two e2e peer pool tests whose cached
discovered peers announced `RNS 1.5.5`, below the new auto-connect minimum
of 1.5.7; the commit 13 port updates them. The second run passed.
