# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-10-28`
- previous accepted version: `1.6.0`
- previous normative commit: `9a01a20ce66c4146dd8f8d31f18c19fe7600739d`
- target version: pending (upstream `RNS.__version__` is still `1.6.0`)
- target tag or ref: `rgit:master` tip `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5`
  (extended on 2026-10-28 from the earlier tip `ca6451a02aead88734e47193dc228055d42c9854`)
- target normative commit: `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5`
- target root tree: `dd5fb64d2e3778f7f20f70db461148885ee20082`
- target `RNS` tree: `8bd88056db225a1a6bd7b0e76a1b99f3e0c667df`
- version assertion: `RNS.__version__ == "1.6.0"` (unchanged; no version bump yet)
- audited range: `9a01a20ce66c4146dd8f8d31f18c19fe7600739d..5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5`
- commits in range: `20` (15 inventoried at the first tip, 5 added when rgit advanced the same day)
- repositories checked: rgit (normative) and GitHub mirror
- local branch and revision inspected: local `dev` from accepted `74bef18`

The GitHub `master` tip is `e40191b3d193b46b7f2d8a44424a594cd758839b`, which
is `behind` the accepted baseline and is allowed mirror lag. The normative rgit
`master` tip `ca6451a0` (committed 2026-10-28T01:22Z) was `ahead` of the
baseline by 15 commits at the morning refresh (2026-10-28T06:16Z); by the
afternoon refresh (2026-10-28T14:41Z) rgit had advanced to `5d38ce30` with five
further commits, inventoried as 16 to 20 below. The new commits implement announcement, path-request and
link-request stamps and landed on `master`; the `dev_pr_stamps` name only
survives in the subject of the historical merge commit `c68066ed`. No new tag
or version bump identifies a promotion target yet, so a versioned parity record
is not created.

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
| 1 | `d1da5c3d67dc30e9af300d5776c7e94c42b5a33b` | Implemented destination stamps | Integrated | `0eaf7dd` plus review follow-up; announce stamp parse/strip, known-destination stamp persistence, rayon generation, `data/stamps` store, RPC fields; unexpanded workblock fixed after exact-target interop rejected every Python stamp |
| 2 | `d2dd730801ca91197f22be56c85d5d855d97faed` | Adjusted stamp defaults | Integrated | `ca33cdb`; destination defaults 20 and PR defaults 19 |
| 3 | `d3ec00cd510e7f8b72e3249a8a74a0d60f5c9f42` | Cleanup | Integrated | `8231a7e`; destination defaults 23; PR tag propagation landed in #4 |
| 4 | `156c7323a510f1be3adfb8288e521559599d3809` | Implemented path request stamps | Integrated | `2c4a936` plus review follow-up; 64-byte PR parsing, validation, relay, outbound emission gate, unconditional transport id, oversized-tag truncation |
| 5 | `7ec975fc886de62c80bfebf1b2b108991ea75204` | Cleanup | Non-runtime | `f67dac1`; `ext_payload` naming already native, invariant documented |
| 6 | `51be88fbd83417c8d21d2ce74922faa401658cee` | Fixed unused path cull order | Structurally covered | `5992827`; `cull_path_table` takes earliest-expiring unused paths |
| 7 | `c68066edffd14c3755ceb181c621a4f806ddfd46` | Merge branch 'master' into dev_pr_stamps | Structurally covered | `512b234`; cull-order regression independent of insertion order |
| 8 | `7c1b648607a13d9d7517f5a82c9a59c1bd776935` | Improved PR stamp handling | Integrated | `0979c93` plus review follow-up; 0xFF relaying sentinel for unstamped requests relayed to local clients and recursively |
| 9 | `8d5871915a4a0b846d2c7e637842ed0c8916425c` | Cleanup | Non-runtime | `5e3b1b3`; constant-order invariant documented |
| 10 | `c3af19893f7e056bbe04f53f57133eddadc4ed71` | Cleanup | Non-runtime | `cc23e6f`; legacy derived-key constant never existed natively |
| 11 | `30c6428e0b59bfc05563167c72c2e0f21ef015c0` | Added link establishment cost to announces | Integrated | `f712c8f`; 17-byte announce extension anchor, `lr_cost` persistence, SQLite v2 migration |
| 12 | `9955e1bf6777a1e5cddfd423de86b5a6824a64cc` | Implemented Identity stamps and added stamp key generation to stamper | Integrated | `6816147`; stamped X25519 keys and stamped `Identity` constructor |
| 13 | `c37b5f7f44900e1d80c166678d8bac565f238046` | Cleanup | Non-runtime | `970eae8`; idempotent migration comment |
| 14 | `ba8c2d76db20be55a22578b840f78ef0489ef053` | Implemented link request stamps | Integrated | `5fe5f87` plus review follow-up; X25519 key stamp validation, off-thread stamped initiator with timeout, recalled cost |
| 15 | `ca6451a02aead88734e47193dc228055d42c9854` | Parameter tuning | Integrated | `6bd6601`; link cost 11 and stamp timeout 15, the timeout bounding the link stamp worker |
| 16 | `4867e889e2bf470af93f5ff58ae558789cb56087` | Added improved Android stamp job runner | Non-runtime | `aeb5241`; Python per-platform worker strategy, the rayon generator covers all native targets |
| 17 | `134db17c817065f90b8b8064ac7bf703227c7cf1` | Added transport hop limiter | Integrated | `13d0947`; `HOP_LIMITER`, per-interface `hop_limiter_hits` counted instead of protocol violations, exported over management, RPC and `rnstatus` |
| 18 | `ba3c42459b23913dfe37ca5d7f4b3875e8431425` | Added slow interface linger time factor and unused pool cull prioritization | Integrated | `8f1eca8`; leaf linger 12 min, `PATH_SLOW_BITRATE`, `PATH_SLOW_LINGER_FACTOR`, fast-first unused pool cull |
| 19 | `025f6d609f9a181342d3dd9a6738c8bce88a9a8d` | Cleanup | Non-runtime | `ea4e6be`; pathing log marker text |
| 20 | `5d38ce3072e3cd9b4d5c05c21bf4940f866dfef5` | Early-phase PR debug logging | Non-runtime | `6527b6f`; path request stamp diagnostics mirrored, decision unchanged |

## Per-Commit Analysis

### 1. `d1da5c3d` — Implemented destination stamps

**Upstream change:** Adds optional 14-byte detached stamps to destination
announces, including stamp material, validation, storage and transport
handling.

**Rust applicability:** The generic stamp primitives existed in
`rns-core/src/stamp.rs` but not the announce policy or persistence.

**Local handling and evidence:** `ValidatedAnnounce::apply_stamp` parses and
validates the extension after signature verification, strips it only when
valid, and records the value. Known destinations persist `stamp` and
`stamp_value` through the msgpack and SQLite stores and expose them over RPC.
Emission generates over `destination_hash || public_key || name_hash`, stores
`storage/stamps/<hash>.dstamp`, and remains disabled by the upstream default
`STAMP_DESTINATIONS = false`. Evidence:
`test_announce_stamp_valid_is_stripped_and_valued`,
`announce_stamp_is_stored_and_recalled`,
`generated_destination_stamp_validates_and_roundtrips`, and the storage
round-trips.

**Review follow-up (2026-10-28):** the first exact-target interop run with a
Python node announcing a stamped destination showed Rust keeping the extension
in `app_data` and recording no link cost: `rns_core::stamp::stamp_workblock`
returned an empty block for zero expansion rounds, whereas upstream
`stamp_workblock` returns the material itself when `expand_rounds` is falsy.
Rust therefore hashed the stamp alone and judged every Python destination
stamp invalid, while its own unit tests passed because generation and
validation shared the same function. Path request stamps used the same
unexpanded workblock and were equally affected; discovery stamps use expanded
workblocks and were not. The function now returns the material for zero
rounds. Evidence: `unexpanded_workblock_is_the_material`, the
Python-provenance vector
`python_destination_stamp_vector_validates_with_unexpanded_workblock`
(stamp generated by Reticulum 1.6.0 at `ca6451a0`), and the live
`python_rns_stamped_link_request_interop` case, which checks that the Rust
node strips the extension, recalls the announced link cost, and records the
same stamp value Python computed.

**Final disposition:** Integrated.

### 2. `d2dd7308` — Adjusted stamp defaults

**Upstream change:** Retunes announce and path request stamp defaults.

**Rust applicability:** Native constants mirror the same knobs.

**Local handling and evidence:** `DESTINATION_STAMP_COST`/`VALUE` became 20 and
`PATH_REQUEST_STAMP_COST`/`VALUE` were introduced at 19;
`stamp_defaults_match_upstream_parameters`.

**Final disposition:** Integrated.

### 3. `d3ec00cd` — Cleanup

**Upstream change:** Despite the subject, raises `DESTINATION_COST` and
`DESTINATION_VALUE` from 20 to 23, initializes `blocked_if`, propagates a shared
request tag when replaying path requests, and reformats log lines.

**Rust applicability:** Default tuning and stamped-request tag propagation are
applicable; the unbound-variable fix has no native equivalent.

**Local handling and evidence:** Destination defaults raised to 23. Relaying a
stamped path request with its original tag and extension landed with the
path-request mapping (#4) because the native tag path did not exist earlier.

**Final disposition:** Integrated.

### 4. `156c7323` — Implemented path request stamps

**Upstream change:** Adds stamp generation and validation for path requests,
including ingress and egress limiting integration and a large Transport
restructure.

**Rust applicability:** Native path requests are a fixed 48-byte frame; the
64-byte stamped form and extension payload were absent.

**Local handling and evidence:** `parse_path_request` accepts the 64-byte form,
validates over `destination_hash || tag`, drops requests longer than the
stamped length, and processes 49 to 63 byte unstamped requests with the tag
truncated to 16 bytes, as upstream does, while the driver counts the protocol
violation. Relayed requests keep their original tag in every branch, and own
and relayed requests always carry the transport identity, matching the
upstream 1.6.0 "path requests always carry transport ID" change in this
commit. Outbound emission is gated by `STAMP_PRS` (default false). Evidence:
`stamped_path_request_is_forwarded_without_treating_extension_as_tag`,
`path_request_with_oversized_tag_is_truncated_and_forwarded`,
`path_request_longer_than_stamped_length_is_dropped`,
`test_shared_instance_without_transport_relays_path_request_to_local_client`,
and `test_shared_instance_forwards_local_client_path_request`.

**Caveat:** when `STAMP_PRS` is enabled upstream stamps requests forwarded on
behalf of local clients through its stamper queue; the native engine forwards
them unstamped. See the deferred stamper queue under Remaining Work.

**Final disposition:** Integrated.

### 5. `7ec975fc` — Cleanup

**Upstream change:** Renames the internal `stamped_ext` parameter to
`ext_payload`, updates the docstring, and normalizes `RNS.Transport` references.

**Rust applicability:** Internal naming only; the native engine already used
`ext_payload`.

**Local handling and evidence:** Documented the relay invariant that the exact
extension bytes are preserved. `f67dac1`.

**Final disposition:** Non-runtime.

### 6. `51be88fb` — Fixed unused path cull order

**Upstream change:** Fixes culling to remove the earliest-expiring unused paths
instead of the latest.

**Rust applicability:** `cull_path_table` already sorts unused paths ascending
by expiry and takes the first `remove_count`.

**Local handling and evidence:** Existing regression retained; invariant
documented in `rns-core/src/transport/jobs.rs`. `5992827`.

**Final disposition:** Structurally covered.

### 7. `c68066ed` — Merge branch 'master' into dev_pr_stamps

**Upstream change:** Merge of the cull-order fix into `dev_pr_stamps`; the
merge-resolution delta is patch-equivalent to #6.

**Rust applicability:** No independent behavior.

**Local handling and evidence:** Added
`unused_path_pool_order_is_by_expiry_not_insertion`, which makes insertion order
disagree with expiry order. `512b234`.

**Final disposition:** Structurally covered.

### 8. `7c1b6486` — Improved PR stamp handling

**Upstream change:** Adds transitional diagnostics distinguishing unstamped
relayed path requests from invalid stamps, gates debug work, and marks
unstamped requests relayed to local clients with a sentinel extension.

**Rust applicability:** The native relay needed the same transition marker.

**Local handling and evidence:** `unstamped_relay_payload()` emits marker
`0xC1`, flags `0xFF`, zero stamp, and is applied when `STAMP_PRS` is enabled to
unstamped requests relayed to local clients and to unstamped recursive
discovery requests, the two sites upstream marks. `0979c93` and review
follow-up; `unstamped_relay_payload_has_marker_and_sentinel_flags`.

**Final disposition:** Integrated.

### 9. `8d587191` — Cleanup

**Upstream change:** Reorders the `NAME_HASH_LENGTH` declaration.

**Rust applicability:** None; no value or behavior change.

**Local handling and evidence:** Identity size block documented. `5e3b1b3`.

**Final disposition:** Non-runtime.

### 10. `c3af1989` — Cleanup

**Upstream change:** Removes the unused `DERIVED_KEY_LENGTH_LEGACY` constant.

**Rust applicability:** None; the legacy constant never existed natively.

**Local handling and evidence:** Documented the current 64-byte derived-key
length. `cc23e6f`.

**Final disposition:** Non-runtime.

### 11. `30c6428e` — Added link establishment cost to announces

**Upstream change:** Adds an announced link-request cost (`lr_cost`) to
destination announces and persists it in the known-destination store (schema
version 2).

**Rust applicability:** The announce extension grew from 16 to 17 bytes and the
known-destination stores had no link-cost field.

**Local handling and evidence:** The trailing anchor byte carries the cost in
its low seven bits; an extended-format high bit is not interpreted. `lr_cost`
is persisted in msgpack and SQLite, with a version-2 migration that names target
columns. Evidence: `test_announce_stamp_valid_is_stripped_and_valued`,
`sqlite_migrates_v1_schema_and_adds_lr_cost`, and the storage round-trips.
`f712c8f`.

**Final disposition:** Integrated.

### 12. `9955e1bf` — Implemented Identity stamps and added stamp key generation to stamper

**Upstream change:** Adds identity-level stamp keys, stamp material/key
generation, and expanded `Stamps` helpers.

**Rust applicability:** The native crypto crate had stateless stamp primitives
but no stamped key generation.

**Local handling and evidence:** `rns_crypto::identity::generate_stamped_key`
grinds an X25519 keypair over arbitrary material; `Identity::new_stamped` binds
the X25519 half to the Ed25519 public key and `get_value` reports it. Evidence:
`stamped_identity_carries_required_value` and
`stamped_key_public_half_validates_against_material`. `6816147`.

**Final disposition:** Integrated.

### 13. `c37b5f7f` — Cleanup

**Upstream change:** Collapses the schema-migration branch onto one line.

**Rust applicability:** None.

**Local handling and evidence:** Documented that the version-2 migration is a
single idempotent step. `970eae8`.

**Final disposition:** Non-runtime.

### 14. `ba8c2d76` — Implemented link request stamps

**Upstream change:** Adds link-request stamp emission/validation with timeout
handling across `Link`, `Destination` and `Transport`, plus an example update.

**Rust applicability:** Link requests carried no stamp semantics; the initiator
always generated an unconstrained X25519 key.

**Local handling and evidence:** Incoming requests compute the value of the
X25519 key over `destination_hash || ed25519_public_key` and enforce the
announced cost only when `LR_STAMPS_ENFORCED` (off). The initiator generates a
stamped key when the destination announced a non-zero cost and `STAMP_LRS` is
enabled (default true). As upstream defers key generation to a thread with a
`LINK_STAMP_TIMEOUT` watchdog, the driver grinds the key on a helper thread
(`rns-net/src/driver/link_stamps.rs`), posts it back as
`Event::CompleteStampedLink`, and on timeout answers the caller with the
all-zero link id that `RnsNode::create_link` maps to an error; the driver
thread never blocks. Evidence, layer by layer: key search
(`stamped_key_generation_until_meets_cost_when_never_stopped`,
`stamped_key_generation_stops_when_asked`), link engine
(`stamped_link_request_carries_required_value`,
`initiator_with_keys_uses_the_supplied_keys`), key helper
(`stamped_link_keys_meet_cost_and_bind_destination`,
`stamped_link_keys_give_up_at_deadline`,
`stamped_link_keys_honour_a_future_deadline`,
`stamped_link_keys_reject_cost_above_protocol_cap`,
`stamped_link_keys_are_fresh_per_call`,
`link_request_stamp_material_is_destination_then_signing_key`), link manager
(`create_link_with_stamped_keys_emits_stamped_link_request`,
`stamped_link_request_completes_the_handshake_with_a_responder`,
`create_link_with_keys_none_generates_fresh_unstamped_keys`), and driver
(`create_link_without_announced_cost_is_answered_synchronously`,
`create_link_with_announced_cost_defers_until_the_worker_reports`,
`create_link_with_announced_cost_stamps_off_thread_and_completes`,
`complete_stamped_link_event_rebuilds_the_worker_keys_exactly`,
`complete_stamped_link_while_draining_is_rejected`,
`stamped_link_request_timeout_fails_the_link_without_blocking_the_driver`,
`stamped_link_caller_is_not_left_waiting_when_the_driver_is_gone`,
`driver_stays_responsive_while_a_stamp_is_being_ground`), and live against
Python Reticulum 1.6.0 at `ca6451a0` (`python_rns_stamped_link_request_interop`:
Python announces link cost 8, the Rust initiator grinds the request on its
worker, Python's `validate_request` reports `stamp_status` true and a value at
or above the cost that agrees with `link_request_stamp_value`, and data flows
both ways over the link). `5fe5f87` and review follow-up. The first mapping ground the key synchronously on the
driver thread without a timeout; measured at 0.09 s for cost 11 and 0.8 s for
cost 16 in release mode, a destination announcing the cap would have stalled
every client that tried to link to it.

**Caveat:** the responder enforces against the global `LINK_REQUEST_STAMP_COST`
and there is no per-destination `set_link_cost`; both matter only once
`STAMP_DESTINATIONS` or `LR_STAMPS_ENFORCED` is enabled.

**Final disposition:** Integrated.

### 15. `ca6451a0` — Parameter tuning

**Upstream change:** Lowers `LR_COST` from 14 to 11 and
`LINK_STAMP_TIMEOUT` from 16 to 15.

**Rust applicability:** Native constants mirror the same knobs.

**Local handling and evidence:** `LINK_REQUEST_STAMP_COST = 11` and
`LINK_STAMP_TIMEOUT = 15`; `stamp_defaults_match_upstream_parameters`.
`6bd6601`.

**Final disposition:** Integrated.

### 16. `4867e889` — Added improved Android stamp job runner

**Upstream change:** Adds `job_android_persistent`, a fork-context worker pool
with a shared stop flag and optional `nacl` hashing for Android; at this commit
`generate_stamp` still dispatches to `job_android`, so the runner is not yet
wired in.

**Rust applicability:** None. Upstream picks a worker strategy per platform
because of Python's process model; the native rayon generator in
`rns-net/src/stamps.rs` covers every target, and the stamp format and value
computation are unchanged.

**Local handling and evidence:** Documented on `generate_stamp` as the native
counterpart of all upstream job runners. `aeb5241`.

**Final disposition:** Non-runtime.

### 17. `134db17c` — Added transport hop limiter

**Upstream change:** Adds `Transport.HOP_LIMITER = PATHFINDER_M` and drops
inbound packets whose hop count is not below it right after unpacking, before
the packet filter, counting them on the interface as `hop_limiter_hits`
(`Interface.hop_limiter_hit`). The counter is not yet shown by `rnstatus` or
exported over RPC upstream.

**Rust applicability:** The native decoder already rejected hop counts at or
above `PATHFINDER_M` (`PacketError::InvalidHopCount`), but counted them as
protocol violations.

**Local handling and evidence:** `HOP_LIMITER` added and used by the decoder;
`InvalidHopCount` decode failures count `hop_limiter_hits` on the receiving
interface instead of a protocol violation; the counter is carried through the
interface stats query, the aggregated dynamic-interface stats, the management
API and the RPC interface stats, and shown by `rnstatus` as `Hop Limit`. The
RPC key is additive and ignored by Python clients. Evidence:
`hop_limited_frame_counts_a_hop_limiter_hit_not_a_protocol_violation`, the
dynamic-interface aggregation test, `interface_stats_pickle_format`, and
`violation_stats_render_and_sort_independently`. `13d0947`.

**Final disposition:** Integrated.

### 18. `ba3c4245` — Added slow interface linger time factor and unused pool cull prioritization

**Upstream change:** Raises `UNUSED_PATH_LINGER_LEAF` from 5 to 12 minutes,
adds `PATH_SLOW_BITRATE = 25000` and `PATH_SLOW_LINGER_FACTOR = 10`, multiplies
the never-used linger by the factor for paths on interfaces with a known
bitrate below the threshold, and sorts the unused pool by `(slow, expiry)` so
fast-interface paths are culled first when the pool exceeds its target.

**Rust applicability:** `jobs::cull_path_table` implemented the plain linger and
expiry-ordered pool cull.

**Local handling and evidence:** Constants added and the leaf linger raised;
`cull_path_table` derives the slow flag from the receiving interface's
`bitrate`, applies the factor to never-used paths, and orders the pool cull
fast-first then by expiry. Evidence:
`never_used_paths_on_slow_interfaces_linger_longer`,
`used_paths_on_slow_interfaces_are_not_special`,
`unused_pool_cull_removes_fast_interface_paths_before_slow_ones`, and the
existing cull tests. `8f1eca8`.

**Final disposition:** Integrated.

### 19. `025f6d60` — Cleanup

**Upstream change:** Shortens the destination stamp value marker in the
pathing log line to `(v:N)` / `(v:n)`.

**Rust applicability:** Log text only.

**Local handling and evidence:** The equivalent trace line in
`rns-net/src/driver/dispatch.rs` uses the same marker. `ea4e6be`.

**Final disposition:** Non-runtime.

### 20. `5d38ce30` — Early-phase PR debug logging

**Upstream change:** Reworks the path request stamp diagnostics: stamped
requests log their value, unstamped relays with the 0xFF sentinel move to the
pathing level, invalid stamps log their value, plain unstamped requests drop to
the extreme level. The accept/drop decision is unchanged.

**Rust applicability:** Diagnostics only; the native validation emitted no logs.

**Local handling and evidence:** The same four diagnostics are emitted from
`parse_path_request` and the sentinel flags byte is named
`PR_FLAG_UNSTAMPED_RELAY`; the decision remains gated by `STAMPS_ENFORCED`.
Covered by the existing path request tests. `6527b6f`.

**Final disposition:** Non-runtime.

## Remaining Work

All twenty commits have a final disposition and a mapping commit. Before a
versioned parity record can be created:

- exact-target Python/Rust interoperability against the current target
  `5d38ce30`: **passed on 2026-10-28** (`python_interop` 3/3 including the
  stamped link request case, `utility_interop` 6/6) with `PYTHONPATH` at a
  disposable worktree of `5d38ce30`, imported version confirmed as 1.6.0.
  Must be rerun if the promotion target moves again;
- record build, Docker, hardware, and manual gates honestly (the daily
  dual-VPS Backbone smoke is operational evidence, not promotion acceptance);
- ~~document the user-visible stamp knobs natively~~: done on 2026-10-28 in
  `docs/configuration.md` (Stamps section: no configuration key exists on
  either side, the compile-time constants and their defaults are listed) and
  `docs/rnstatus.md` (Hop Limit counter);
- add 1.6.0 to the pinned CI interop matrix: **blocked** because the matrix
  clones from the GitHub mirror, which is still at `e40191b3` (1.5.5); none of
  the 1.6.0 commits are on GitHub yet, so the exact-target interop stays a
  manual gate from a local rgit checkout until the mirror catches up;
- **Deferred:** the upstream stamper queue (`WorkerQueues`, `stamper_job`,
  `pr_stamp_cache`) that stamps own and locally forwarded path requests and
  stamped announces asynchronously. Natively `handle_request_path` and
  announce emission generate stamps inline and locally forwarded requests are
  not stamped. Dormant while `STAMP_PRS` and `STAMP_DESTINATIONS` are false;
  must be implemented before either flag is enabled;
- **Deferred:** per-destination link request cost (`Destination.set_link_cost`)
  and responder enforcement against the announced cost rather than the global
  default. Dormant while `LR_STAMPS_ENFORCED` is false.

No version bump exists upstream, so `UPSTREAM.md` remains at `9a01a20c` and
this file stays the active audit.

## Acceptance Record

- `2026-10-28`: Daily drift check found rgit `master` at `ca6451a0`, 15 commits
  past the accepted `9a01a20c` baseline. GitHub `master` at `e40191b3` was
  `behind` and fresh. All 15 mapping commits landed in upstream ancestry order
  with `Upstream-Commit` trailers. `cargo test --workspace`,
  `cargo test -p rns-net --features rns-hooks-native`,
  `cargo check --workspace --all-targets`, the release `rns-server`
  `rns-hooks-native` build, `cargo fmt --all --check`, and workspace
  `clippy --all-targets -D warnings` all passed. Two non-trailer build fixes
  (`8e100d3`, `85e71f4`) carry the new known-destination and announce fields
  into the `rnid` test and hook-injected announce conversion. No deployment,
  restart, or reconfiguration of the VPS nodes was performed.
- `2026-10-28`: Review of the series against the upstream diff found that
  stamped link request keys were ground synchronously on the driver thread
  without the upstream timeout, that own and relayed path requests omitted the
  transport identity without transport enabled, that relayed requests derived
  a fresh tag instead of keeping the original, that the 0xFF sentinel was
  missing from the recursive branch, and that 49 to 63 byte path requests were
  dropped instead of truncated. All five were corrected in a follow-up without
  an `Upstream-Commit` trailer; the stamper queue and per-destination link
  cost were recorded as deferred. Both VPS nodes still run `fa4936b`, the
  1.6.0 promotion tree; nothing was deployed.
- `2026-10-28`: Exact-target Python/Rust interop at `ca6451a0` from a
  disposable worktree, `import RNS` confirmed to resolve to the worktree at
  version 1.6.0 (a plain `python3` on the host imports a pip-installed RNS
  1.1.3, which the suites would otherwise silently test against).
  `python_interop` 3/3 and `utility_interop` 6/6 passed. The new
  `python_rns_stamped_link_request_interop` case first failed and exposed the
  unexpanded-workblock divergence recorded under commit 1; after the fix all
  three cases pass, with Python stamping its destination at value 23 or above
  in under a second on this host and the Rust stamped link request at cost 8
  completing in about 0.4 s in a debug build. rgit advanced to `5d38ce30`
  during the day; the five new commits are listed under Remaining Work and
  not audited here. Nothing was deployed to the VPS nodes.
- `2026-10-28`: The five commits `4867e889` through `5d38ce30` were audited
  and mapped (`aeb5241`, `13d0947`, `8f1eca8`, `ea4e6be`, `6527b6f`), bringing
  all twenty commits past the baseline to a final disposition. Exact-target
  Python/Rust interop at `5d38ce30` from a disposable worktree, imported
  version confirmed as 1.6.0: `python_interop` 3/3 (Python destination stamp
  at value 23, Rust stamped link request at cost 8 in about 3.8 s under a
  concurrent build) and `utility_interop` 6/6. `cargo fmt --all --check`,
  workspace `clippy --all-targets -D warnings`, `scripts/lint-host.sh`,
  `cargo test --workspace --no-fail-fast` (2961 tests, none failed) and
  `cargo test -p rns-net --features rns-hooks-native --lib` (1192 passed)
  all passed. Two anomalies during the gate run, neither attributable to the
  series: rustc 1.96.0 stalled for 69 minutes in one LLVM optimizer thread
  while building the `rns-git` test target (killed; the same target rebuilt in
  ten seconds), and on the next run `sync_client_identifies_before_first_python_request`
  in `rns-git` timed out on its ten second wait for the spawned Python peer,
  poisoning the shared test lock for `sync_client_reidentifies_after_not_identified_response`.
  Both passed three times in isolation and in the full rerun; `rns-git` is
  untouched by this series. `scripts/check_upstream_drift.py --no-fetch`
  reports 20 commits ahead with the active audit present. Nothing was deployed
  to the VPS nodes.
