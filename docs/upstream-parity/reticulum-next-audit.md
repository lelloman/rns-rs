# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-11-14`
- previous accepted version: `1.6.0`
- previous normative commit: `134dc6777c0dd29404e61b36d4094f4e35b88b3e`
- target version: `1.6.0` (pending: no version bump in range)
- target tag or ref: `rgit/master` (pending promotion target)
- target normative commit: `c850cdac6c8bd5422af045652216ba451e98aa33`
- target root tree: `af323f9220c51ea4925a2b2d5422a61d6f917a07`
- target `RNS` tree: `77efe59cff06d6c9c17a7ecbd9b1f53308d44759`
- version assertion: `RNS.__version__ == "1.6.0"`
- audited range: `134dc6777c0dd29404e61b36d4094f4e35b88b3e..c850cdac6c8bd5422af045652216ba451e98aa33`
- commits in range: `13`
- repositories checked: rgit `master` (normative) and the GitHub mirror `master`
- local branch and revision inspected: `dev@9aa6de76b6bc5a67042f892af4481f6d8572d554`

Found by the 2026-11-14 daily drift check (`data/upstream-drift-2026-11-14.json`),
both remotes refreshed fresh. The GitHub mirror tip `3c4b271f` lags behind the
accepted baseline; all 13 commits are reachable only from rgit `master`.
No version bump, so the target version and promotion target stay pending.

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

Every commit in the audited range appears exactly once, in ancestry order.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `54159d1d93237612239f19653f6a99b8a62708b3` | Cleanup | Non-runtime | `InboundFrame::iface` invariant documented (`rns-core/src/transport/mod.rs`) |
| 2 | `04585ff2a8af37ee1683aca03d001cd49ae8399a` | Cleanup | Non-runtime | Formatting-only; audit records the diff review |
| 3 | `6852971d3c8e0e0d055bdb1472b51fa6de87b3a9` | Logging cleanup | Non-runtime | Log-only; no equivalent Rust log line |
| 4 | `d5f1e014dbec2921d70b8acd15c820601de6525d` | Persist and load announce rate table | Integrated | `storage/announce_rate_table` (`RNSART` v1) save/load; upstream-generated fixture `tests/fixtures/transport/announce_rate_table_d5f1e014.bin`; `announce_rate_block_survives_snapshot_restore` and storage tests |
| 5 | `01e7ed84433ee3e9a64643e40e892ccfcdb85243` | Refactored traffic accounting | Structurally covered | `every_received_frame_is_charged_once_to_received_or_filtered`; `record_filtered_inbound` doc |
| 6 | `d183791956f807c92d5eb0a9f9bc9e12f9135cd1` | Refactored traffic accounting | Structurally covered | Single-counting-site invariant documented in `handle_classified_frame_event` |
| 7 | `819076c3783565dc303abb2894c99e6ce6074342` | Track filtered announce count per interface | Integrated | `held_announces_limit_applies_only_while_ingress_limiting`, `announce_with_too_many_hops_to_hold_is_a_filtered_announce`, `blackholed_announce_is_a_filtered_announce`, `announce_over_a_full_hold_is_a_filtered_announce`, `announce_of_a_type_not_required_is_a_filtered_announce`, `filtered_announces_render_and_sort`; `afrxc` in RPC and `rnstatus` |
| 8 | `daec67a116347b28e2268beb1d7b004f827eebb2` | Cleanup | Integrated | `waiting_local_path_request_skips_ingress_limiting`; pathing-level skip log in `hold_decision` |
| 9 | `3281e283154af393ba1a521eaba4246a32d52f1f` | Added tunnel info to rnstatus | Integrated | `interface_stats_report_the_tunnel_this_node_synthesized`, `spawned_interface_is_detached_by_its_tunnel_id`, `a_static_unmanaged_interface_is_not_torn_down`, `tunnel_id_line_matches_upstream`, `tunnels_flag_takes_no_value`; prerequisite `1df27919` |
| 10 | `464e75986e06b4ad2050a5a4c572159ae2c2d647` | Added remote transport ID info to rnstatus | Integrated | `synthesis_records_and_reports_the_remote_transport`, `an_interface_takes_only_one_tunnel_synthesis`, `tunnels_are_not_synthesized_over_other_interface_types`, `remote_transport_line_matches_upstream`, RPC pickle assertion |
| 11 | `56b23c4810d477ed82daf06f2e34ac0a69d87bfc` | Typo | Integrated | `tunnel_synthesis_with_a_bad_signature_tears_the_interface_down`, `tunnel_synthesis_of_the_wrong_length_is_ignored` |
| 12 | `350b7e2614960cd6f521031cec966462c9f216c9` | Added ability to blackhole remote transport nodes | Integrated | `restore_skips_paths_of_blackholed_identities`, `synthesis_from_a_blackholed_transport_node_tears_the_interface_down`, `blackholing_a_transport_node_tears_down_its_connections` |
| 13 | `c850cdac6c8bd5422af045652216ba451e98aa33` | Traffic counting | Integrated | `held_and_released_announces_count_as_received`; `announce_over_a_full_hold_is_a_filtered_announce`, `announce_is_held_while_held_announces_have_room` and `duplicate_and_in_flight_path_requests_are_filtered_inbound` updated |

## Per-Commit Analysis

### 1. `54159d1d` — Cleanup

**Upstream change:** Removes the `if packet.receiving_interface` / `!= None` guards around the oversized-announce, invalid-signature, oversized and tagless path request, and invalid path request size protocol violations, and around the `received_announce` / `received_path_request` counters in `Transport.inbound`. `preprocess_inbound` already returns early when no interface is set, so every removed guard was always true; behavior and counters are unchanged.

**Rust applicability:** `InboundFrame::iface` is a required `InterfaceId`, so the engine cannot receive an interface-less frame and has no equivalent guards to remove.

**Local handling and evidence:** Mapping commit documents the invariant on `InboundFrame::iface`. No behavior change; `cargo test -p rns-core` passes.

**Final disposition:** Non-runtime.

### 2. `04585ff2` — Cleanup

**Upstream change:** Joins `if packet.destination_type == RNS.Destination.SINGLE: return True` onto one line in `Transport.packet_filter`. The full diff contains no other change and no control-flow change.

**Rust applicability:** None; Python source formatting.

**Local handling and evidence:** Full diff reviewed; no Rust change. Audit-only mapping.

**Final disposition:** Non-runtime.

### 3. `6852971d` — Logging cleanup

**Upstream change:** In `Identity.__finalize_av` the EXTREME-level "Valid announce for ..." log block moves inside the `not cache_hit or destination unknown` branch, so it is written only when the announce is (re-)remembered, not on every signature-cache hit. A stale `# TODO` comment is dropped. Remembering, ratchets, the caches and the return value are unchanged.

**Rust applicability:** rns-rs emits no per-announce "Valid announce" log line, and log text is not a compatibility surface.

**Local handling and evidence:** Full diff and the enclosing `__finalize_av` reviewed; no Rust change. Audit-only mapping.

**Final disposition:** Non-runtime.

### 4. `d5f1e014` — Persist and load announce rate table

**Upstream change:** `AnnounceRateTable` gains `persist`/`load` for a new binary file `storage/announce_rate_table`. The format is a 16-byte header (magic `RNSART`, version 1, zero flags, ring size, key length, two reserved bytes, u32 LE entry count), then little-endian columns: keys, `last` f64, `blocked_until` f64, `rate_violations` i32, ring length u8, ring head u8, and the timestamp ring (`max_ts` f64 per entry). Loading rejects the whole file on any header, size, duplicate-key or ring-cursor inconsistency, and replays rings of a different size oldest first. `Transport` loads the file at start when transport is enabled and the node is not a shared-instance client; a load failure logs a warning and keeps an empty table. `persist_data` saves it beside the packet hashlist, path table and tunnels (no retention filter). Rate penalties and accumulated violations therefore survive a restart.

**Rust applicability:** rns-rs already persists `packet_hashlist.raw`, `destination_table` and `tunnels` in upstream layouts from `TransportEngine::persistence_snapshot`. These are written only when transport is enabled, at the same points as upstream `persist_data`. The rate table (`AnnounceRateLimiter`, `RateEntry` with oldest-first timestamps capped at `MAX_RATE_TIMESTAMPS` = 16) was not persisted, so a restart reset every penalty: needs port.

**Local handling and evidence:** `TransportStateSnapshot` gains `announce_rates` (`PersistedAnnounceRate`); `persistence_snapshot` exports every rate entry and `restore_persistence_snapshot` restores them, keeping the newest 16 timestamps (`AnnounceRateLimiter::restore`). `rns-net/src/storage.rs` writes and reads `announce_rate_table` in the exact `RNSART` v1 layout with upstream's validation. Rings are written oldest first from slot 0 with `head = len % 16`, which upstream's ring logic treats identically. An unreadable file logs a warning and restores empty without failing the other tables. Evidence: `tests/generate_announce_rate_table_fixture.py` produced the 348-byte fixture with upstream's own `persist` at `d5f1e014` (deterministic across two runs; entry A has a wrapped ring and an active block). `upstream_announce_rate_table_decodes_with_wrapped_rings_in_order` decodes it. `announce_rate_table_encoding_matches_upstream_layout` matches every byte except the re-based wrapped ring. Further tests: `announce_rate_table_rejects_inconsistent_files`, `unreadable_announce_rate_table_restores_empty_without_failing_other_state`, `announce_rate_block_survives_snapshot_restore`, and `restored_announce_rate_keeps_only_the_newest_timestamps`. Reverse direction checked once, not committed: upstream `AnnounceRateTable.load` at `d5f1e014` accepted a Rust-written table, returned identical entries, and kept entry A blocked at t=1030. `cargo test -p rns-core -p rns-net`: 2347 passed, 0 failed. `cargo fmt --check` and `cargo clippy -p rns-core -p rns-net --all-targets -D warnings` clean.

**Final disposition:** Integrated.

### 5. `01e7ed84` — Refactored traffic accounting

**Upstream change:** Interfaces stop adding received bytes to `rxb` (and to `parent_interface.rxb` or `owner.rxb`) in `process_incoming`. The changed modules are AX.25 KISS, Auto, Backbone, I2P, KISS, Local, Pipe, RNode, RNode Multi, Serial, TCP, UDP and Weave. `Transport.inbound` now charges each frame once: `accepted_inbound` adds to `rxb` (and the parent's) when `preprocess_inbound` accepts, and `filtered_inbound` adds only to `frxb`, no longer subtracting from `rxb`. The non-queued `preprocess_inbound` path no longer returns `_inbound`'s result, so it stops counting accepted packets as filtered; upstream's default `USE_INBOUND_QUEUE = True` already returned `True`. Side effects: AX.25 counts bytes after the 16-byte header, and I2P outbound peers (`parent_count = False`) now add RX bytes to the parent I2P interface (TX unchanged).

**Rust applicability:** rns-rs counts `rxb`/`rx_packets` once, when a wire frame reaches the driver (`handle_classified_frame_event`). `record_filtered_inbound` moves a frame dropped where `preprocess_inbound` drops it to `frxb`. A deferred signature failure is moved the same way; upstream rejects it inline, with the same end state. The totals therefore equal upstream's new accepted/filtered split, and no interface counts bytes on its own. AX.25 frames reach the driver already stripped by `decode_ui_frame`, matching the new upstream count. There is no non-queued `_inbound` quirk to mirror. Caveat: rns-rs reports no row for the I2P parent interface (its peers are separate dynamic interfaces), so the I2P `parent_count` RX roll-up has no surface. That is a pre-existing representation difference, not introduced here.

**Local handling and evidence:** Mapping commit refreshes the `record_filtered_inbound` doc to describe upstream's new split. It also moves the misplaced `admit_decoded_inbound` doc back onto its function. New regression `every_received_frame_is_charged_once_to_received_or_filtered` sends accepted, IFAC-flagged and undecodable frames and requires `rxb + frxb` to equal the bytes received, with every filtered frame in `frxb`. The existing 134dc677 filtered-inbound tests still pass. `cargo test -p rns-net`: 1470 passed, 0 failed; fmt and clippy clean.

**Final disposition:** Structurally covered.

### 6. `d1837919` — Refactored traffic accounting

**Upstream change:** `Transport.inbound` gains `no_accounting=False`. The two cache replays (`cache_request_packet`, for a received CACHE_REQUEST, and `cache_request`, for a local request) pass `no_accounting=True`, so a cached packet re-injected into `inbound` is counted in neither `rxb` nor `frxb`. After 01e7ed84 it would otherwise have counted again on its original interface.

**Rust applicability:** rns-rs has no packet cache and no cache-request replay; `CONTEXT_CACHE_REQUEST` is only classified, never served. Received traffic is counted in one place, `handle_classified_frame_event`, and only frames read from an interface reach it. No internal re-injection passes through it, so nothing needs exempting.

**Local handling and evidence:** Mapping commit documents the invariant at the counting site. Searched for every `rxb` and `rx_packets` increment (only that site) and every `Event::Frame` producer (interfaces and tests). `cargo build -p rns-net` clean.

**Final disposition:** Structurally covered.

### 7. `819076c3` — Track filtered announce count per interface

**Upstream change:** Interfaces gain an `afrxc` counter (filtered announces, also added to `parent_interface.afrxc`), plus a `Transport.filtered_arxc` total that nothing reports. `ifstats` carries `afrxc` per interface only. A filtered announce is one rejected under `required_destinations_only`, one whose validation returns blackholed, `no_stamp` or `invalid_stamp`, or one `hold_announce` does not newly hold. That last case covers an announce with `hops >= PATHFINDER_M-1`, one replacing an already-held announce for the same destination, and one arriving when the hold is full. Blocked types, malformed or oversized announces and invalid signatures are not counted. f96cef7e's early `len(held_announces) >= ic_max_held_announces: return None` in `preprocess_inbound` is removed, so the limit now applies only inside `hold_announce`, while the interface is ingress-limiting. `hold_announce` returns `True` when it holds, so a held announce counts as accepted traffic (`rxb`). It was previously filtered by the bare `return`. `rnstatus` gains the `afrxc` sort key and appends `, N filtered` to the announce total line when the count is nonzero. Bare `return`s in `preprocess_inbound` become `return None` (no change).

**Rust applicability:** Needs port. rns-rs has f96cef7e's early drop in the driver (`announce_holding_saturated`) and marks every held announce as filtered. It has no `afrxc`, and its destination filter did not distinguish blocked from not-allowed types.

**Local handling and evidence:** `IngressControl::hold_announce` returns whether it newly held the announce. The engine's `hold_decision` yields `Pass`, `Held` or `Filtered`: `Held` leaves the frame received, and `Filtered` marks a filtered announce (`filter_announce`, which sets `inbound_filtered` and the new `inbound_filtered_announce`). `destination_filter_verdict` separates `Blocked` (filtered bytes only) from `NotAllowed` (filtered announce). Blackholed identities and failed enforced stamps are filtered announces. The driver turns `take_inbound_filtered_announce` into `stats.afrxc` on both the direct and deferred-verification paths; Backbone listener rows sum their children's `afrxc`. The early drop and `announce_holding_saturated` are removed. Per-interface RPC (`single_iface_to_pickle`) and remote-management stats carry `afrxc`; totals do not, as upstream. `rnstatus` gains the `afrxc` sort key and the `, N filtered` suffix. `docs/rnstatus.md` and the `ic_max_held_announces` paragraph of `docs/configuration.md` are updated. Caveats: (1) rns-rs decides ingress holding before signature validation and validates on release, whereas upstream validates first. A blackholed or stamp-failing announce arriving during a burst is therefore held in rns-rs, where upstream would count it as filtered; it is filtered on release instead. This ordering predates this commit. (2) `Transport.filtered_arxc` is not reported upstream and has no rns-rs equivalent. Tests: the core and driver tests above, plus the updated `announce_is_held_while_held_announces_have_room` (a held announce stays in `rxb`) and blocked-type and held-full assertions. `cargo test -p rns-core` (881), `-p rns-net --lib` (1392) and `-p rns-cli` (247) pass; `cargo check --workspace --all-targets`, fmt and clippy (`-D warnings`) are clean.

**Final disposition:** Integrated.

### 8. `daec67a1` — Cleanup

**Upstream change:** In `preprocess_inbound`'s ingress-limiting branch, the commented-out log for skipping the check, when the destination is in `path_requests` or `discovery_path_requests`, becomes a live `LOG_PATHING` line replacing `pass`. Behavior is unchanged; that skip predates this commit.

**Rust applicability:** Reviewing the branch exposed a pre-existing gap. rns-rs's `hold_decision` skipped ingress limiting only for `discovery_path_requests`, not for the local `path_requests` table (`record_outbound_path_request`, culled like upstream's). During a burst it therefore held a plain announce for a destination this node had asked for, where upstream processes it. Path responses (`CONTEXT_PATH_RESPONSE`) were already exempt.

**Local handling and evidence:** Mapping commit adds the `path_requests` check and the pathing-level trace log in `hold_decision`, recording the closure of the gap here because it is the branch this commit touches. Regression `waiting_local_path_request_skips_ingress_limiting` fails without the check (the announce was held) and passes with it. The same burst still holds an unrequested announce. `cargo test -p rns-core` (882) and `-p rns-net --lib` pass; fmt and clippy clean.

**Final disposition:** Integrated.

### 9. `3281e283` — Added tunnel info to rnstatus

**Upstream change:** `Interface` gains `local_tunnel_id`, set by `synthesize_tunnel` after sending; `ifstats["tunnel_id"]` becomes `tunnel_id or local_tunnel_id`. (`name` moves from a class attribute to `__init__`, with no effect.) `_detach_interface(name, internal_forced, interface_instance)` treats a name matching no interface as a hex tunnel id and looks it up in `tunnel_id`, then `local_tunnel_id`. It returns `None` for bad hex or no match, and logs the interface instead of the name. `rnstatus` gains `-T/--tunnels`, printing `    Tunnel ID : <hex>` or `None` after the rate line. `tunnel_synthesize_handler` now tries to tear down the receiving interface on an invalid signature. At this commit that path raises a NameError (`interface_instances`, fixed by 56b23c48), so it only logs an error; teardown takes effect in the 56b23c48 mapping.

**Rust applicability:** This needed working tunnel synthesis. Before it, rns-rs never synthesized tunnels and attached received ones to the wrong interface. That was fixed first in `1df27919` ("net: synthesize tunnels from dialing interfaces, attach them where they arrive"), a separate non-mapping commit, Python-interop checked against 134dc677. rns-rs then still had no local tunnel id, no detach by tunnel id, no way to detach a spawned interface, and no `-T`.

**Local handling and evidence:** `TransportEngine::synthesize_tunnel` (now `&mut self`) records the tunnel id per interface (`local_tunnel_id`, cleared on deregister). Interface stats, both over RPC and in remote management status, report `tunnel_id` or else `local_tunnel_id` (`test_status_request_reports_the_tunnel_this_node_synthesized`). `interface_for_tunnel_id` resolves a tunnel id, remote first, then local. Interface-management detach of a name that is no configured interface parses a 64-digit hex tunnel id and calls the new `Driver::teardown_interface`. That function refuses I2P and local interfaces, as upstream does, and detaches a configured interface through its config entry. An auto-connected interface uses `teardown_autoconnected`. A spawned interface gets `Writer::shutdown` (now implemented for the TCP client, TCP server and I2P writers, and forwarded through `AsyncWriter` to its worker) and is removed. Bad hex or no match returns `None`. `rnstatus -T/--tunnels` prints upstream's line, and `-T` is a valueless flag. `docs/rnstatus.md` documents both. The invalid-signature teardown is deliberately not ported here, because upstream's own code does not tear down until 56b23c48. Caveat: tearing down an outbound I2P peer closes its stream, but its loop reconnects, whereas upstream's detached peer stays down. `cargo test -p rns-core -p rns-net` (2363) and `-p rns-cli` (250) pass. Python interop passes against 134dc677 (5 tests). Clippy (default and `rns-hooks`) and fmt are clean.

**Final disposition:** Integrated.

### 10. `464e7598` — Added remote transport ID info to rnstatus

**Upstream change:** `Interface` gains `tunnels_allowed` (default `False`) and `remote_transport`. `tunnels_allowed` is `True` on TCP client and server, Backbone server and client, and I2P interface and peer; spawned children are TCP or Backbone client objects, so they are allowed too. `tunnel_synthesize_handler` ignores a synthesis on an interface without `tunnels_allowed`, or one that already has a `remote_transport` (logged at debug). On a valid synthesis it stores the remote transport identity before `handle_tunnel`. `ifstats` gains `remote_transport_id` (identity hash or `None`), and `tunnel_id` moves in the dict, with no effect. `rnstatus -T` prints `    Rem.Tr.ID : <hex>` or `Unknown`. A Backbone client's `else:` is reformatted with no change.

**Rust applicability:** Needs port on top of the 1df27919 synthesis fix. rns-rs accepted a synthesis on any interface type, any number of times per interface, and kept no remote transport.

**Local handling and evidence:** `interface::tunnels_allowed` covers the interface types that correspond to upstream's allowed classes: `TCPClientInterface`, `TCPServerClientInterface`, `BackboneInterface`, `BackboneClientInterface`, `BackboneInterfacePeer` and `I2PInterfacePeer`. Listeners never receive packets themselves. The driver's synthesis handler returns early for other types, and logs at debug and returns when the engine already has a `remote_transport` for the interface. On a valid synthesis it records the remote identity hash (`TransportEngine::set_remote_transport`, cleared on deregister) before `handle_tunnel`. `SingleInterfaceStat.remote_transport_id`, the RPC pickle and remote-management status carry it. `rnstatus -T` prints upstream's `Rem.Tr.ID` line, and `docs/rnstatus.md` is updated. Existing tunnel tests now register their server interfaces as spawned TCP or Backbone clients. `cargo test -p rns-core -p rns-net -p rns-cli` (2627) passes, as does Python interop against 134dc677 (5 tests); clippy and fmt are clean.

**Final disposition:** Integrated.

### 11. `56b23c48` — Typo

**Upstream change:** Fixes `interface = interface_instances` to `interface_instance` in `_detach_interface`. This makes 3281e283's teardown effective: a tunnel synthesis with an invalid signature now detaches the receiving interface (`internal_forced`, so even with interface management disabled). I2P and local interfaces refuse; spawned interfaces of the target are detached too, then the interface itself.

**Rust applicability:** Needs port: the 3281e283 mapping deliberately left the teardown out, because upstream's code could not reach it until this fix.

**Local handling and evidence:** `handle_tunnel_synth_delivery` calls `Driver::teardown_interface` (from the 3281e283 mapping) on `TunnelError::InvalidSignature`. A spawned interface has its connection closed and is removed; a configured one is detached through its config entry; I2P and local interfaces are refused. A synthesis of the wrong length is still ignored, and an unloadable key still counts a protocol violation. `docs/rnstatus.md` is updated. Caveat: without interface management (no config file) rns-rs cannot detach a static configured interface, so a bad synthesis received on one is only logged; upstream detaches it. `cargo test -p rns-net` passes and clippy is clean.

**Final disposition:** Integrated.

### 12. `350b7e26` — Added ability to blackhole remote transport nodes

**Upstream change:** (1) `tunnel_synthesize_handler`: a valid synthesis from a transport identity in `blackholed_identities` detaches the receiving interface (`internal_forced`) instead of recording `remote_transport` and handling the tunnel. (2) `remove_blackholed_paths`, run when an identity is blackholed and when blackhole lists load, now also detaches every interface whose `remote_transport` is blackholed. (3) Path-table loading compared the recalled `Identity` object with the hash-keyed blackhole dict, which never matched; it now uses `path_identity.hash`, so paths to blackholed identities are not restored. (4) `_detach_interface` also calls `teardown()` on an interface that is in its parent's `spawned_interfaces`, closing its connection. (5) `rnstatus` totals check `frxs`/`ftxs` in the totals `stats` rather than the last interface's `ifstat`.

**Rust applicability:** (1) and (2) need port on the remote transport kept since the 464e7598 mapping. (3) needs port: rns-rs restored paths after loading the blackhole list, filtering only by destination type. (4) is structurally covered: `Driver::teardown_interface` already closes a spawned interface's connection (`Writer::shutdown`) before removing it. (5) is structurally covered: `filtered_total_lines` already reads rates from the totals response.

**Local handling and evidence:** (1) `handle_tunnel_synth_delivery` tears the receiving interface down when the validated remote identity is blackholed, and does not record the remote transport or the tunnel. (2) `Driver::remove_blackholed_paths` (used by `blackhole_identity_local`, `load_blackhole` and the blackhole updater) tears down every interface whose engine `remote_transport` is blackholed. (3) `restore_persistence_snapshot` skips a path whose cached announce's public key hashes to a blackholed identity, counted in the new `RestoreStats::blackholed_paths` and logged at startup. The node loads the blackhole list before restoring. `docs/configuration.md` (Blackholes) is updated. `cargo test -p rns-core -p rns-net` (2371) passes; clippy and fmt are clean.

**Final disposition:** Integrated.

### 13. `c850cdac` — Traffic counting

**Upstream change:** (1) `process_held_announces` releases with `no_accounting=True`, so a released announce is not counted in `rxb`/`frxb` again. (2) `received_announce` and `Transport.announce_rxc` move after the ingress-limit decision. An announce handed to `hold_announce` counts `received_announce(size=0)`, whether it is held or dropped, and does not count in `announce_rxc`. Every other validly signed announce counts `received_announce(size=len(raw))` and `announce_rxc`, so a released announce counts with its size when it passes. (3) A path request batched into one in flight returns `True`, so it counts as accepted traffic instead of filtered. The enforced-stamp `return` becomes `return None` (no change).

**Rust applicability:** (1) is structurally covered: rns-rs releases held announces from the engine tick, which never passes through the driver's frame accounting. (2) needs port: rns-rs counted `arxc`/`arxb` only for announces the engine emitted as received from a frame, so held announces and releases were not counted. (Frequency samples are taken per announce frame and are unaffected.) (3) needs port: the 134dc677 mapping counted in-flight path requests as filtered.

**Local handling and evidence:** (2) The engine queues announce receipts (`take_announce_receipts`): `(interface, 0)` when ingress control takes an announce up (held or dropped), and `(interface, raw length)` when a released announce is accepted in the tick. The driver adds them to `arxc`/`arxb` after each frame and after each tick. Announces that pass straight through keep their existing count, so nothing is counted twice. (3) `accept_path_request` marks only dropped requests filtered; batched in-flight ones stay received. Tests: core `held_and_released_announces_count_as_received`; the driver hold tests now require `arxc` 1 with 0 bytes; the in-flight path request is received. `cargo test -p rns-core -p rns-net -p rns-cli` (2632) passes, as does Python interop against 134dc677 (5 tests); clippy (default and `rns-hooks`) and fmt are clean.

**Final disposition:** Integrated.

## Integration Plan

Review every commit above and give it a disposition.

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

None yet.
