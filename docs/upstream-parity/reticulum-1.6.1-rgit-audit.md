# Reticulum 1.6.1 rgit `cff4d03f` Upstream Audit

## Scope and Baseline

- audit date: `2026-11-20`
- previous accepted version: `1.6.1` (untagged at acceptance, see
  [the 1.6.1 parity record](reticulum-1.6.1-parity.md))
- previous normative commit: `884f109b2b821638c7addd456a52a2cd5bb8c5b1`
- target version: `1.6.1` (unchanged; upstream signed the `1.6.1` tag on
  2026-11-18, tag object `bde4cd790a78b5ed285243fcc17f6439bb582288`, pointing
  at the range tip `cff4d03f`)
- target tag or ref: `1.6.1` = `rgit:master` = GitHub `master` tip
  `cff4d03fdbd6bfb63b765280cd944756ac5cce8d`
- target normative commit: `cff4d03fdbd6bfb63b765280cd944756ac5cce8d`
  (provisional; rgit may advance before promotion)
- target root tree: `4e52b7a767251df1d5ce74f32383e207565169f9`
- target `RNS` tree: `bcab6ab7ff72c4315aceda97267ea9af4fcccbc4`
- version assertion: `RNS.__version__ == "1.6.1"`
- audited range: `884f109b2b821638c7addd456a52a2cd5bb8c5b1..cff4d03fdbd6bfb63b765280cd944756ac5cce8d`
- commits in range: `34` (no merge commits; 52 files changed, +842/-263)
- repositories checked: rgit (normative) and GitHub mirror, both fetched
  fresh by `scripts/check_upstream_drift.py` on 2026-11-20 05:56 UTC; the
  two tips agree
- local branch and revision inspected: branch `upstream/1.6.1-rgit` from `dev@b1f26c80`;
  rebased onto `dev@51ccbcc5` for the promotion gates (local hashes below are
  the rebased ones)

The accepted 1.6.1 baseline was an untagged rgit tip. Upstream has since
tagged `1.6.1` at the end of this range without changing
`RNS/_version.py`, so this record follows the `-rgit` naming used for
`reticulum-1.6.0-rgit-2` and leaves the 1.6.1 records unchanged. The tag is
SSH-signed; the signature has **not** been verified locally because no
`gpg.ssh.allowedSignersFile` is configured. Commit 34 (`cff4d03f`,
`Updated changelog`) carries the release notes; per the parity workflow the
changelog identifies the target but is not acceptance evidence.

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
The 2026-11-20 diff review proposed a disposition for each; every row now
has its final disposition, recorded with its mapping commit and the
evidence that ran.

| # | Upstream commit | Date | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|---|
| 1 | `da368e05` | 2026-11-16 | Deduplicate in-flight announce rebroadcasts | Integrated | `f779ae93`; `an_announce_heard_again_while_waiting_is_not_rebroadcast_to_that_interface`, `an_announce_heard_again_on_a_shared_medium_is_still_rebroadcast_there`, `a_newer_announce_replacing_the_waiting_one_starts_without_blocked_interfaces` |
| 2 | `aecc1547` | 2026-11-16 | Set sane autoconnect caps | Integrated | `0b755fcf`; `autoconnect_count_is_capped_unless_caps_are_disabled`, `autoconnect_caps_are_disabled_only_by_a_key_before_the_count` |
| 3 | `338df096` | 2026-11-16 | Updated docs | Non-runtime | `aba894d4`; `docs/interface-discovery.md` sizing guidance |
| 4 | `2b1a984c` | 2026-11-17 | Fixed IFAC identity not being available at early tunnel synthesis | Structurally covered | `472cd118`; `tunnel_synthesis_carries_the_interface_access_code` |
| 5 | `25cce0a8` | 2026-11-17 | Ensure transport identity availability before early tunnel synthesis | Structurally covered | `0d284df2`; `a_dialing_tcp_client_first_sends_a_synthesis_signed_by_the_transport_identity` |
| 6 | `cc5d6dd0` | 2026-11-17 | Logging | Structurally covered | `dcdae141`; invariant comment in `rns-cli/src/rnsh/initiator.rs` |
| 7 | `12b2b8c0` | 2026-11-17 | Updated link tests | Non-runtime | `e2fcde2f`; doc comment on `wait_for_link_established` (`rns-net/tests/e2e.rs`) |
| 8 | `4916017a` | 2026-11-17 | Abort early on non-enabled link mode | Structurally covered | `5ef23a30`; `every_outbound_link_request_signals_aes_256_cbc`; follow-ups `ba44bc2c` and `c0086c86` (decision 7) |
| 9 | `48c77061` | 2026-11-17 | Load known destinations over RPC in split mode | Integrated | `28b241ae`; `known_destinations_rpc_answers_upstreams_dict`, `known_destination_entries_rpc_keeps_the_native_list`, `a_split_mode_client_loads_known_destinations_over_rpc`, `python_split_mode_client_loads_rust_known_destinations_over_rpc` |
| 10 | `f876ed8d` | 2026-11-17 | Show remote transport status on tunnels | Integrated | `07c86976`; `rnstatus_view_matches_upstream` (fixtures regenerated at `f876ed8d`, new case `tunnels_remote_transport`) |
| 11 | `0123133e` | 2026-11-17 | Fixed CPython process fork stdin close deadlock | Structurally covered | `547b79ed`; module comment in `rns-net/src/stamps.rs` |
| 12 | `05ac4bba` | 2026-11-17 | Added ability to configure destination value and link cost to rngit | Integrated | `bbd0e4c6`; `destination_costs_default_to_upstreams`, `parses_and_quantizes_destination_costs`, `invalid_destination_costs_are_errors`, `rngit_destinations_carry_their_link_cost_and_stamp_value`, `rngit_invalid_page_cost_fails_the_page_destination` |
| 13 | `833f6cf2` | 2026-11-17 | Fixed path table culling being able to remove an instance's own local destination paths. Doh. | Integrated | `7428468e`; `a_local_clients_announce_marks_its_path_responsive`, `never_used_local_client_paths_stay_on_an_instance_serving_them` (replaced by 15's cull test) |
| 14 | `d72cfdd7` | 2026-11-17 | Mark local client paths responsive on PR responses | Structurally covered | `1338ab58`; `a_local_clients_path_response_marks_its_path_responsive` |
| 15 | `5bd93ad9` | 2026-11-17 | Ensure link-based rediscovery does not occur for instance-local paths | Integrated | `35028c47`; `failed_own_link_to_an_instance_local_destination_is_not_rediscovered`, `local_client_link_to_an_instance_local_destination_is_not_rediscovered`, `instance_local_paths_go_only_with_their_interface_or_the_pool_cap` |
| 16 | `70eb417d` | 2026-11-17 | Fixed non path table resident shared local instance destination path response announces broadcasting on all interfaces instead of requestor only | Integrated | `3d500abc`; `only_a_local_clients_path_response_answers_a_pending_request` (updated), `a_local_clients_path_response_answers_only_the_requesting_interface`, `test_shared_instance_without_transport_relays_path_request_to_local_client` (updated) |
| 17 | `8c73e203` | 2026-11-18 | Don't rebroadcast on unresponsive path lenient table insertions | Integrated | `0d994265`; `unresponsive_path_replacement_is_not_rebroadcast`; follow-up `53f34b11` (decision 8) |
| 18 | `4a058544` | 2026-11-18 | Well, yeah | Structurally covered | `bd431f23`; doc comment on `persist_known_destinations` (`rns-net/src/node/known_destinations.rs`) |
| 19 | `8e7dc8b7` | 2026-11-18 | Added medium reliability flag to interfaces | Integrated | `9f503ac2`; `lossless_medium_matches_upstreams_interface_classes` (decision 6) |
| 20 | `9568b704` | 2026-11-18 | Improved rnpath display and filtering options | Integrated | `b216a018`; `path_table_display_options_and_filters_as_upstream`, `path_table_prints_as_upstream` (updated), `parses_upstream_invocations_as_argparse_does` (extended), argparse fixture and golden help regenerated at `9568b704`, live `python_rnpath_reads_rust_remote_path_table` and `python_rnpath_lists_rust_path_table` at `9568b704` |
| 21 | `c90a5d58` | 2026-11-18 | Added destination type loading | Integrated | `6528b48c`; `known_destination_types_are_read_as_upstream`, `missing_unreadable_and_flagged_type_files_add_nothing`, `the_config_filter_names_come_first_and_the_file_overrides_them`, `splitlines_and_strip_follow_python`, `wanted_destination_types_are_named_in_the_type_map`, `unwant_all_reports_types_in_the_order_they_were_first_wanted`, `configured_destination_types_name_as_upstreams_type_map`, `path_and_rate_tables_follow_upstreams_keys_and_types` (extended), `path_table_prints_as_upstream` (JSON), live `python_rnpath_reads_rust_remote_path_table` at `c90a5d58` |
| 22 | `3f55e9eb` | 2026-11-18 | Added flagged destination type map, added per-link traffic counter, added link distribution stats getter | Integrated | `7f26a06d`; `forwarded_link_traffic_counts_raw_bytes`, `link_distribution_counts_per_destination`, `link_distribution_names_receiving_interfaces_by_hash`, `link_distribution_rpc_fails_as_upstreams_set_does`, `type_names_come_from_the_map_then_the_flagged_map_then_the_hash` (decision 2) |
| 23 | `f7b54ccc` | 2026-11-18 | Added prettynamehash convenience function | Non-runtime | `4815c264`; note in `rns-cli/src/pyfmt.rs` |
| 24 | `1a71073c` | 2026-11-18 | Initial rnpath analysis stub | Integrated | `8b9b4fbf`; `analysis_counts_destination_types_as_upstream`, `parses_upstream_invocations_as_argparse_does` (extended), argparse fixture and golden help regenerated at `1a71073c` (decision 3) |
| 25 | `b9903c53` | 2026-11-18 | Analysis mode capture argument | Integrated | `d78d7c76`; `parses_upstream_invocations_as_argparse_does` (`--capture`, ambiguous `--c`), argparse fixture and golden help regenerated at `b9903c53` |
| 26 | `1f7cd145` | 2026-11-18 | Cleanup and fixes | Integrated | `af10606b`; `link_distribution_follows_link_table_insertion_order`, `link_distribution_rpc_answer_keeps_upstreams_order`, `link_distribution_rpc_answers_with_from_ifs_lists`, argparse fixture and golden help regenerated at `1f7cd145` (decision 2) |
| 27 | `41260ea1` | 2026-11-18 | Added path state info to path table getters | Integrated | `54d13f99`; `test_path_state`, `query_path_table`, `path_and_rate_tables_follow_upstreams_keys_and_types`, `path_table_prints_as_upstream`, `path_state_marker_as_upstream`, `python_rnpath_lists_rust_path_table`, `python_rnpath_reads_rust_remote_path_table` |
| 28 | `48ba76df` | 2026-11-18 | Catch announce unpack failure | Structurally covered | `3ff7bfdb`; `analysis_counts_destination_types_as_upstream` (extended; the guard never fires, checked against upstream at `48ba76df`) (decision 3) |
| 29 | `ef3e8086` | 2026-11-18 | Added link traffic stats | Integrated | `ce679652`; `link_table_traffic_counts_relayed_bytes_but_local_clients`, `link_speeds_are_measured_as_upstreams_traffic_loop`, `link_traffic_speeds_are_reported_once_measured`, `link_traffic_keys_follow_upstreams_position_and_types`, `rnstatus_view_matches_upstream` (fixtures regenerated at `ef3e8086`, four new `totals_links*` cases), live idle-node comparison with Python at `ef3e8086` |
| 30 | `e8b3b14b` | 2026-11-18 | Classic | Integrated | `234f68d1`; `rnstatus_view_matches_upstream` (fixtures regenerated at `e8b3b14b`; `totals_links_control_only` now prints, `totals_links_control_only_tx` new; both raise at `ef3e8086`) |
| 31 | `eb00622f` | 2026-11-18 | Cleanup | Integrated | `755d9784`; `analysis_is_not_yet_implemented` (decision 3) |
| 32 | `01ffb98e` | 2026-11-18 | Local link traffic counting | Integrated | `f63b3dac`; `local_link_traffic_counts_raw_bytes_as_upstream`, `own_link_traffic_joins_the_link_totals`, `requested_parts_say_whether_they_were_sent_before`, `test_tick_retransmits_timed_out_packets` (extended) |
| 33 | `52898683` | 2026-11-18 | Raised listener backlogs | Structurally covered | `63f7689d`; `abstract_rpc_listener_queues_upstreams_backlog`, invariant comments at the listener binds |
| 34 | `cff4d03f` | 2026-11-18 | Updated changelog | Non-runtime | `4e5b04ce`; changelog cross-check in section 34, `UPSTREAM.md` tag note |

## Per-Commit Analysis

Each section answers the four questions of
[the parity workflow](README.md#per-commit-integration-procedure) from the
2026-11-20 review of the full diff against `dev@b1f26c80`. Line references are
to that revision. **Local handling** describes the planned mapping commit;
it becomes evidence only once that commit lands.

### 1. `da368e05` — Deduplicate in-flight announce rebroadcasts

**Upstream change:** Announce-table entries gain a set of interfaces
(`IDX_AT_DEDUP_IFS`). When a copy of an announce that is already waiting for
rebroadcast (same `packet_hash`, which ignores hops and transport id) arrives
on another interface, that interface is added to the set unless it is a
shared medium. The rebroadcast is sent on every interface except the ones in
the set, so a neighbour that already sent us the announce does not get it
back. An attached interface (path response) still takes priority.

**Rust applicability:** Missing. `AnnounceEntry` (`transport/tables.rs:30-54`)
has no packet hash or blocked set. A rejected duplicate returns at
`inbound_engine/verified_announce.rs:104-114`. `jobs::process_pending_announces`
emits `BroadcastOnAllInterfaces { exclude: None }`, and
`gate_retransmit_actions` can only skip one interface. The core
`InterfaceInfo` has no shared-medium flag; `rns_net::interface::shared_medium_hint`
already matches upstream's shared-medium classes but is only used for stats.
Same-sender copies still in the verify queue are collapsed by
`AnnounceVerifyQueue::enqueue`, a small existing deviation.

**Local handling and evidence:** `f779ae93`. As planned: `InterfaceInfo`
gains `shared_medium`, `AnnounceEntry` gains `packet_hash` and
`blocked_interfaces`, and the `MultiPathDecision::Reject` branch of
`process_verified_announce` adds the receiving interface to the waiting
entry's set when the packet hash matches and the interface is not a shared
medium. Every constructor fills the packet hash (a cached path response
uses the cached announce's). The set reaches the broadcast gating by
destination: `jobs::process_pending_announces` reports it for a broadcast
(never for an attached interface) and `gate_retransmit_actions` leaves those
interfaces out, so the public `BroadcastOnAllInterfaces` action is
unchanged. A replacing announce starts with an empty set. `shared_medium`
is set in the factories that match `shared_medium_hint` (Pipe, Serial, UDP,
RNode and its subinterfaces, KISS and AX25 KISS via the hint) and on the
ESP32 LoRa interface; announce retention accounting counts the set.

Notes: the verify-queue collapse of same-sender copies remains (a copy from
the same neighbour heard on a second interface while still queued is not
recorded); with the native `prefer_shorter_path` on, a shorter same-emission
copy replaces the entry instead of being recorded, as that option already
deviates; `rns-esp32` is outside the workspace and was not built.

Tests run: `cargo test -p rns-core --lib -- an_announce_heard_again
a_newer_announce_replacing` failed before the change for the main test
(`left: [1, 2, 3]`, `right: [1, 3]`), with 3 passed after it; `cargo test -p
rns-core -p rns-net -p rns-bench` passed (rns-core lib 1154, rns-net lib
1580, `e2e.rs` 74 with 1 ignored, `e2e_direct_connect.rs` 19, rns-bench 17
with 1 ignored, no failures); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed.

**Final disposition:** Integrated.

### 2. `aecc1547` — Set sane autoconnect caps

**Upstream change:** `autoconnect_discovered_interfaces` above 12 is clamped
to 12 with warnings, and any value above 6 logs advice to use 2–3.
`autoconnect_discovered_interfaces_disable_caps = yes` turns both off;
because options are read in file order, upstream honours it only when it
appears before the count.

**Rust applicability:** Missing. `common/config/reticulum.rs:344-354` parses
the count uncapped and does not know the disable key. Keys are held in a
`HashMap`, so file order is not available.

**Local handling and evidence:** `0b755fcf`. Per decision 4 the planned
"honour it wherever it appears" deviation was dropped: the parser records
the `[reticulum]` key order (a repeated key takes its last position), and
`autoconnect_discovered_interfaces_caps_disabled` is true only when the
disable key is `yes` and comes before the count (or there is no count). An
invalid boolean is a config error, as `as_bool`. The count stays as written
in the config; under `autoconnect_policy = upstream` startup
(`node_config.rs`, `upstream_autoconnect_target`) caps it at 12 and logs
upstream's warning lines word for word, blank lines included, at warning
level, for > 12 and > 6. Under `pool` the count is ignored as before, so
nothing is capped. `docs/interface-discovery.md` and
`docs/configuration.md` document the key and its order dependence.

Tests run: `cargo test -p rns-net --lib --
autoconnect_count_is_capped_unless_caps_are_disabled
autoconnect_caps_are_disabled_only_by_a_key_before_the_count`, 2 passed (20
gives 12 with both warnings, disabled 20 stays 20 silently, 7 gives the
second warning only, 6 and 0 nothing; key before / after / `no` / invalid).
Both use the new field and function, so they had no pre-change run; before,
the count was used uncapped. `cargo test -p rns-net` passed (lib 1582,
`e2e.rs` 74 with 1 ignored, `e2e_direct_connect.rs` 19); `cargo fmt --check`
and `bash scripts/lint-host.sh` passed.

**Final disposition:** Integrated.

### 3. `338df096` — Updated docs

**Upstream change:** Documentation only: guidance on how many discovered
interfaces to auto-connect (2–3 typical, up to 12 only in extreme cases), a
getting-started warning, and a reference entry for `get_instance_pid()`.

**Rust applicability:** No runtime change. `docs/interface-discovery.md`
documents the options without sizing guidance. There is no native
`get_instance_pid`.

**Local handling and evidence:** `aba894d4`. `docs/interface-discovery.md`
gains a "How many to auto-connect" section with upstream's sizing guidance,
pointing at the cap from commit 2. The `get_instance_pid()` reference entry
has no native counterpart.

Tests run: no crate code changed. `cargo test -p rns-net --lib --
documented_location_stanza`, which includes that document, 1 passed;
`cargo fmt --check` passed.

**Final disposition:** Non-runtime.

### 4. `2b1a984c` — Fixed IFAC identity not being available at early tunnel synthesis

**Upstream change:** The early tunnel-synthesis writes in the TCP, Backbone
and I2P clients now apply the IFAC mask, and the first connect moves to
`final_init()` after `ifac_identity` is set. Before, the first frame on an
IFAC-protected link went out unmasked and was dropped by the far end.

**Rust applicability:** Synthesis goes through `send_tunnel_synthesis`
(`driver/events/tunnels.rs:149-166`) and `SendOnInterface`, which always masks
with the entry's IFAC (`driver/dispatch/send.rs:187-205`). The IFAC is attached
when the entry is registered, before any connect event
(`interface_management.rs:247-264`, `backbone_pool.rs:722-760`,
`driver/events/interfaces.rs:209-210`). There is no unmasked early-write path.

**Local handling and evidence:** `472cd118`. Verified as reviewed: the
synthesis is a `SendOnInterface` masked with the entry's IFAC, and static,
managed and pool interfaces get their IFAC at registration. A dialing I2P
peer is registered offline (`reconnecting`) with its inherited IFAC and
brought up later, so its synthesis is masked too. Caveat: in
`handle_dynamic_interface_up_event` a registration that is not
`reconnecting` comes up (and would synthesize) before `entry.ifac` is set;
no current interface type takes that path with `wants_tunnel`, so this is
latent, not a live difference, and was left unchanged.

Related hardening (not part of this mapping, disposition unchanged):
`f5748851` (`driver: a dynamic interface has its IFAC before it comes up`,
no `Upstream-Commit` trailer) closes that caveat.
`handle_dynamic_interface_up_event` now registers the interface, completes
its entry (IFAC, type, names, parent) and only then runs the up handling
(tunnel synthesis, then the callback and `InterfaceUp` hooks), which moved
into `finish_interface_up`. Test
`a_dynamic_interface_has_its_ifac_before_it_comes_up` (a non-reconnecting
spawned interface that wants a tunnel, with its own IFAC and with its
parent's) failed before the change (`own IFAC true: masked`, flag byte `0`
instead of `128`) and passes after it. `cargo test -p rns-net` passed (lib 1590, `e2e.rs` 74
with 1 ignored, `e2e_direct_connect.rs` 19, no failures); `cargo fmt
--check` and `bash scripts/lint-host.sh` passed.

Tests run: `cargo test -p rns-net --lib --
tunnel_synthesis_carries_the_interface_access_code`, 1 passed (the frame
carries the IFAC flag, a peer with the same access code records the client's
transport, the unmasked frame is dropped); a pinning test of covered
behaviour, so it also passes without a code change. `cargo test -p rns-net`
passed (lib 1583, `e2e.rs` 74 with 1 ignored, `e2e_direct_connect.rs` 19);
`cargo fmt --check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Structurally covered.

### 5. `25cce0a8` — Ensure transport identity availability before early tunnel synthesis

**Upstream change:** Transport identity setup moves into
`Transport.ensure_identity()`, called before interfaces start, so a client
that connects during startup can sign its tunnel synthesis.

**Rust applicability:** The identity is built at `node/startup.rs:461-480` and
assigned to the driver at `:655-656`, before the interface start loop and
before the driver thread handles any interface event.

**Local handling and evidence:** `0d284df2`. The invariant comment sits
before `configure_driver_services` in `node/startup.rs`, which hands the
driver the transport identity before `start_interfaces`; the driver thread
only starts afterwards. Upstream's removal of the `hasattr` guards has no
Rust counterpart.

Tests run: `cargo test -p rns-net --lib --
a_dialing_tcp_client_first_sends_a_synthesis_signed_by_the_transport_identity`,
1 passed (a node without transport, so an ephemeral identity; the first HDLC
frame on the accepted socket validates as a synthesis whose signer is the
identity `QueryRequest::TransportIdentity` reports); a pinning test.
`cargo test -p rns-net`: the first run stopped on a rustc SIGSEGV while
compiling rns-core (a compiler crash, no test ran); the rerun passed (lib
1584, `e2e.rs` 74 with 1 ignored, `e2e_direct_connect.rs` 19).
`cargo fmt --check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Structurally covered.

### 6. `cc5d6dd0` — Logging

**Upstream change:** In rnsh's initiator, the "Establishing link with" INFO
log moves before link creation and a DEBUG "No link" line is removed.

**Rust applicability:** `rns-cli/src/rnsh/initiator.rs:52` already logs before
`create_link`; the debug line was never ported.

**Local handling and evidence:** `dcdae141`. Verified as reviewed: the rnsh
initiator logs "Establishing link with <hash>" at INFO (`pylog::INFO_TARGET`)
before `create_link`, and has no "No link" line. A comment there records
the match with upstream's order.

Tests run: no focused test (log ordering only; the comment is the mapping).
`cargo test -p rns-cli` passed (lib 133, the integration suites with no
failures; `utility_interop.rs` 5 passed with 32 ignored);
`cargo fmt --check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Structurally covered.

### 7. `12b2b8c0` — Updated link tests

**Upstream change:** `tests/link.py` waits for links to become active with a
deadline instead of fixed sleeps. Test-only.

**Rust applicability:** No port of `tests/link.py`. Native link tests already
wait with deadlines (`rns-net/tests/e2e.rs:425`, `wait_for_link_established`).

**Local handling and evidence:** `e2fcde2f`. The doc comment on
`wait_for_link_established` (`rns-net/tests/e2e.rs`) records that link tests
wait for establishment against a deadline, upstream's `await_link`. Test-only.

Tests run: `cargo test -p rns-net` passed (lib 1584, `e2e.rs` 74 with 1
ignored, `e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1 ignored
against the host's Python RNS 1.1.3, no failures); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed.

**Final disposition:** Non-runtime.

### 8. `4916017a` — Abort early on non-enabled link mode

**Upstream change:** `Link.__init__` raises immediately when an initiator asks
for a mode outside `ENABLED_MODES` (`[MODE_AES256_CBC]`), instead of failing
later.

**Rust applicability:** The only rns-net initiator path,
`LinkManager::create_link_with_keys` (`link_manager/establishment.rs:36`),
hard-codes `Aes256Cbc`; no public API takes a mode.

**Local handling and evidence:** `5ef23a30`. A comment at the mode in
`LinkManager::create_link_with_keys` records upstream's `ENABLED_MODES`, and
`every_outbound_link_request_signals_aes_256_cbc` pins that every outbound
request (generated keys, pre-stamped keys, and without MTU signalling, where
no mode is carried and AES-256-CBC is the default) signals AES-256-CBC and
the engine's mode matches. A pinning test of covered behaviour.

The pre-existing AES-128 divergence was resolved per decision 7 in the
separate commit `ba44bc2c` (`link: only AES-256-CBC is enabled, as
upstream`, no `Upstream-Commit` trailer). Upstream at `cff4d03f` reads the
signalled mode in `validate_request`, and for AES-128-CBC `handshake()`
succeeds but `prove()` raises in `signalling_bytes`, so the request is
dropped without a proof and logged at debug as "Validating incoming link
request failed: Requested link mode AES_128_CBC not enabled" (modes 2-7 fail
in `handshake()` instead). In rns-rs, `LinkMode` gains `ENABLED`,
`is_enabled()` and upstream's mode descriptions, `LinkError` gains
`ModeNotEnabled` with upstream's text, the three `LinkEngine` initiator
constructors return a `Result` and refuse a non-enabled mode before any key or
stamp work, and `new_responder` refuses an AES-128-CBC request. rns-net drops
such a request with upstream's debug line, sends no proof and does not count
a protocol violation (it is well formed). Modes 2-7 were already refused, as
malformed requests (`ProtocolViolation`, log "LINKREQUEST rejected:
Unsupported link mode"); that is resolved by `c0086c86`, below.
`docs/protocol-spec.md` 11.1 and 16 now say
only AES-256-CBC is enabled. `test_aes128_mode_handshake` became
`an_aes_128_link_is_refused_by_initiator_and_responder`, and rns-net gained
`an_aes_128_link_request_is_dropped_without_a_proof`, which failed with the
responder check removed and passes with it. The AES-128 wire codec, key
derivation and crypto vectors stay, as upstream keeps the mode defined.

Tests run, `5ef23a30`: `cargo test -p rns-net --lib --
every_outbound_link_request_signals_aes_256_cbc`, 1 passed; `cargo test -p
rns-net` passed (lib 1585, `e2e.rs` 74 with 1 ignored,
`e2e_direct_connect.rs` 19, no failures); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed. `ba44bc2c`: `cargo test -p rns-core -p
rns-net` passed (rns-core lib 1155 and its integration suites, rns-net lib
1586, `e2e.rs` 74 with 1 ignored, `e2e_direct_connect.rs` 19,
`python_interop.rs` 6 with 1 ignored, no failures); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed.

Decision 7 was completed by a second separate commit, `c0086c86` (`link:
refuse a reserved link mode as upstream does`, no `Upstream-Commit`
trailer). Upstream at `cff4d03f`, for a request signalling a reserved mode
(2-7): `validate_request` checks the stamp first (without reading the
mode), logs "Incoming link request with mode MODE_AES256_GCM" (the
`MODE_DESCRIPTIONS` name) at debug, then `handshake()` raises "Invalid link
mode 2 on <link_id>", so the request is dropped without a proof, logged at
debug as "Validating incoming link request failed: Invalid link mode 2 on
<...>", and nothing else happens: no link and no protocol violation, as for
any request `validate_request` refuses. rns-rs counted a protocol violation
(a per-interface counter, as upstream's, shown by rnstatus) and skipped the
stamp check for such requests. Now `new_responder` fails with
`LinkError::InvalidMode { mode, link_id }` (upstream's text), rns-net drops
it like `ModeNotEnabled` with upstream's debug line and no violation, the
stamp is read without the mode, and rns-net logs the "Incoming link request
with mode" line; `mode_description()` names all eight values.

Reading Transport for the same request found a second refusal that
`ba44bc2c` missed, for any mode outside `ENABLED_MODES` (AES-128-CBC
included): when Transport lowers the MTU a link request signals, forwarding
it or delivering it locally, it rebuilds the signalling with
`Link.signalling_bytes`, which raises, so the request is dropped with
`protocol_violation("Undecodable path MTU signalling bytes")` on the
receiving interface and "Dropping link request packet. The contained
exception was: Requested link mode X not enabled" (debug when forwarding,
warning with "... packet to local destination ..." when delivering).
`clamp_forwarded_link_request_mtu` and `clamp_local_link_request_mtu` now
return the mode in that case, and the transport engine drops the request
before any link table entry, transmission or path use, logs upstream's
lines and emits `ProtocolViolation`. Signalling that fits, or is stripped,
passes whatever its mode, as upstream. Two existing clamp tests that clamped
AES-128-CBC requests now use AES-256-CBC.

Tests, each failing before the change: `a_reserved_link_mode_is_refused_by_the_responder`
(rns-core), `a_reserved_link_mode_request_is_dropped_without_a_proof`
(rns-net; failed with `establishment.rs` reverted, a `ProtocolViolation`
came back), `lowering_the_mtu_of_a_mode_that_is_not_enabled_is_refused`,
`forwarded_link_request_needing_a_clamp_in_a_mode_not_enabled_is_dropped`
and `local_link_request_needing_a_clamp_in_a_mode_not_enabled_is_dropped`
(rns-core transport; both engine tests failed with the mode check
disabled). Tests run: `cargo test -p rns-core` passed (lib 1160 and its
integration suites); `cargo test -p rns-net` passed (lib 1591, `e2e.rs` 74
with 1 ignored, `e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1
ignored against the accepted checkout, no failures); `cargo fmt --check`
and `bash scripts/lint-host.sh` passed.

Left as they are, outside decision 7 (not link modes): upstream drops a
link request of a payload size other than 64 or 67 bytes without a protocol
violation ("Invalid link request payload size of N bytes, dropping
request"), where rns-rs counts one ("LINKREQUEST rejected: Invalid data");
and upstream's forwarding computes `min(nh_mtu, ph_mtu)`, which raises (and
drops the request as undecodable) when the receiving interface has no
hardware MTU, a case rns-rs interfaces do not produce.

**Final disposition:** Structurally covered.

### 9. `48c77061` — Load known destinations over RPC in split mode

**Upstream change:** A shared-instance client that cannot open the
instance's `known_destinations.db` asks the instance over RPC
(`{"get": "known_destinations"}`) and **replaces** `Identity.known_destinations`
with the reply. The instance answers with a dict
`{dest_hash: [last_heard, packet_hash, public_key, app_data, used, stamp, stamp_value, lr_cost]}`.

**Rust applicability:** Interop hazard. rns-rs already serves the same RPC
name (`rpc/handlers.rs:285-291`) but answers with a **list** of named dicts
(`known_destinations_to_pickle`, `rpc/responses.rs:828`). A Python 1.6.1
client of an rns-rs instance that takes the RPC path would load that list as
its table and then fail when it tries to remember a new destination (inferred
from the code, not yet run). On the client side, `load_instance_known_destinations`
(`shared_client.rs:939-964`) has no RPC fallback.

**Local handling and evidence:** `28b241ae`, per decision 1. The inferred
hazard was confirmed by running it: with the old list answer, a Python
client at `48c77061` loaded a `list` table, recalled nothing, and failed to
remember the next announce ("list indices must be integers or slices, not
bytes").

Instance side: `known_destinations` answers upstream's dict, destination hash
to `[last_heard, packet_hash, public_key, app_data, used, stamp,
stamp_value, lr_cost]` with upstream's element types: `last_heard` a float;
the announce's packet hash; the public key; `app_data` or None; `used` the
int `0` when never used, the float time of last use, or the int `-1` when
retained (as `Identity.remember` and `_retain_destination_data` write it);
the stamp or None; `stamp_value` the int `0` without a stamp, else a float;
`lr_cost` a float or None. rns-rs did not keep the packet hash, so
`ReceivedAnnounce` now carries it, the driver keeps it with the known
destination, and the SQLite store writes it to `packet_hash` (it wrote 32
zero bytes) and reads it back; it is part of the flush fingerprint. A hash
this node does not know (an entry from the legacy file, a hook-injected
announce) is still 32 zero bytes in the database and in the answer. The
native list moved to `{"get": "known_destination_entries"}`, which
`RpcClient::known_destinations` calls (it has no other callers);
`docs/getting-started.md` documents both names.

Client side: a Rust shared instance client loads the instance's known
destinations after its RPC is set up (upstream moved the load after
`rpc_key` for this). When the database cannot be read it asks over RPC with
upstream's texts and levels: debug "Could not load known destinations from
shared instance database: ...", debug "Potentially running in split mode,
attempting to load known destinations over RPC...", error "Shared instance
RPC failed while getting known destinations: ..." (then an empty table),
error "Could not load known destinations from shared instance: ..." for an
answer that is not a dict, and verbose "Loaded N known destinations from
shared instance". It no longer falls back to the instance's legacy snapshot
file, which upstream's client never read. Entries over RPC carry no hops or
receiving interface (zero), and a negative `used` reads as retained.

Tests run: `known_destinations_rpc_answers_upstreams_dict` (the msgpack
answer element by element, floats as float64, and the client parse) and
`a_split_mode_client_loads_known_destinations_over_rpc` (a client in its own
config directory loads an injected, retained destination from a daemon over
RPC) both failed with the port stubbed out (old handler, no RPC fallback)
and pass with it; `known_destination_entries_rpc_keeps_the_native_list`,
the packet hash in `announce_received_populates_known_destinations`,
`sqlite_known_destinations_roundtrip` and
`a_known_destination_fingerprint_follows_every_field` pass. Python interop,
`cargo test -p rns-cli --test utility_interop -- --ignored
python_split_mode_client_loads_rust_known_destinations_over_rpc` with
`PYTHONPATH` and `RETICULUM_UPSTREAM_DIR` at a disposable upstream worktree
at `48c77061`: a Python split mode client of the Rust client daemon logged
upstream's RPC path lines, loaded a `dict` whose entry for the known
destination is `[float, bytes, bytes, None, float|int, bytes, float, float]`,
recalled it, and remembered a destination announced after it loaded (an
8-element entry). Runs: the first draft's assertion expected `used` to be
the int 0, but the daemon had already used the destination, so it is a
float, and the assertion was relaxed to either; the next run failed earlier,
in the shared harness step "client daemon did not learn listener path"; the
final test then passed three runs in a row. Against the old list answer the
same test failed as described above. `cargo test -p rns-core -p
rns-net -p rns-cli` passed (rns-core lib 1155, rns-net lib 1598, `e2e.rs` 74
with 1 ignored, `e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1
ignored, rns-cli lib 133, `utility_interop.rs` 5 with 33 ignored, no
failures; rns-net's lib count is with the features rns-cli enables);
`cargo fmt --check` passed. `bash scripts/lint-host.sh` first
failed (the client-side parser is dead code without `iface-local`); it is
gated on that feature and the rerun passed.

**Final disposition:** Integrated.

### 10. `f876ed8d` — Show remote transport status on tunnels

**Upstream change:** `rnstatus -T` hides `Tunnel ID` for interfaces that have
clients, and appends `, transport enabled` / `, no transport` to
`Rem.Vers.` from `rem_is_tn`.

**Rust applicability:** `rns-cli/src/rnstatus_view.rs:340-368` prints the
old format. The daemon already sends `rem_is_tn`.

**Local handling and evidence:** `07c86976`. `render_tunnel` prints the
Tunnel ID line only when the interface's `clients` is not truthy (none or
0, as Python's `not clients`) and appends ", transport enabled" / ", no
transport" from `rem_is_tn` to a known remote version. The fixtures were
regenerated with `tests/generate_rnstatus_fixtures.py` from a disposable
upstream worktree at exactly `f876ed8d` (removed afterwards); the
generator's docstring pin moved from `884f109b` to `f876ed8d`, as `c4e6fbdc`
moved it before. Only `tunnels.txt` changed (Tunnel ID lines gone from the
interfaces with clients, ", transport enabled" on the TCP server), and a new
case `tunnels_remote_transport` covers ", no transport" and a server with 0
clients that keeps its Tunnel ID. `rnstatus_view_matches_upstream` failed
on `tunnels` and `tunnels_remote_transport` with the view change stashed and
passes with it. Tests run: `cargo test -p rns-cli` passed (lib 133,
`cli_golden.rs` 1, `jemalloc_smoke.rs` 3, `placeholders.rs` 2 with 1
ignored, `rnid_cli.rs` 4, `rnsd_cli.rs` 10, `rnsh_cli.rs` 4,
`utility_interop.rs` 5 with 33 ignored, no failures); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed.

**Final disposition:** Integrated.

### 11. `0123133e` — Fixed CPython process fork stdin close deadlock

**Upstream change:** On POSIX, `multiprocessing`'s stdin close in forked
children is patched to avoid a deadlock on the buffered-stdin lock.
CPython-specific.

**Rust applicability:** Stamp workers are threads (`rns-net/src/stamps.rs`,
`stamper.rs`). The one `fork` (`rns-cli/src/rnsh/process.rs:151`) only makes
async-signal-safe calls before `execve` and never touches the stdin lock.

**Local handling and evidence:** `547b79ed`. Verified: stamp searches run on
threads (`SearchPool`: a rayon scope or scoped threads in `stamps.rs`; the
stamper's queue worker is a `std::thread`), and nothing forks to search. The
forks rns-rs does make, rnsh's `libc::fork` (`rns-cli/src/rnsh/process.rs`)
and `std::process::Command` children (rnx's `pre_exec` only calls `setsid`),
make only async-signal-safe calls before `exec` and never take Rust's
`Stdin` lock. A module comment in `rns-net/src/stamps.rs` records why the
deadlock cannot occur. Tests run: `cargo test -p rns-net` passed (lib 1591,
`e2e.rs` 74 with 1 ignored, `e2e_direct_connect.rs` 19, `python_interop.rs`
6 with 1 ignored, no failures); `cargo fmt --check` and `bash
scripts/lint-host.sh` passed.

**Final disposition:** Structurally covered.

### 12. `05ac4bba` — Added ability to configure destination value and link cost to rngit

**Upstream change:** rngit's `[rngit]` and `[pages]` sections accept
`stamp_value` and `link_cost`. Both destinations now announce a link cost
of 18.0 by default instead of 12.5, which initiators see on the wire.

**Rust applicability:** `rns-git/src/config.rs` has neither key, and
`server.rs` / `pages.rs` announce the default 12.5. `RnsNode::set_link_cost`
and `Destination::set_value` already exist.

**Local handling and evidence:** `bbd0e4c6`, per decision 5.
`ServerConfig` gains `costs` (`[rngit]`) and `pages_costs` (`[pages]`), each a
`DestinationCosts { link_cost, stamp_value }`. Each key is
`quantize_cost(as_float(v))`: Python float syntax (underscores between
digits included), `StampCost::from_f64` rounding to 1/256 and clamping to
0..=100. The link cost defaults to 18.0 for both destinations and is applied
with `set_link_cost` (clamped to `LINK_COST_CAP` by the node); `stamp_value`
is applied with `set_value` only when non-zero, as upstream's `if
self.stamp_value:`. Both are applied as each destination is built, before
registration and the first announce; the returned `Destination` keeps the
target for re-announces. An invalid value (not a float, NaN, infinite) is a
startup error where upstream raises: `[rngit]` when the config is loaded
(before `--print-identity`, as upstream's `__apply_config`), `[pages]` only
when the page destination is registered (upstream reads it in
`NomadNetworkNode.__init__`), so `pages_costs` is a `Result`. The read order
per section follows upstream (`stamp_value` first in `[rngit]`,
`link_cost` first in `[pages]`). The generated `server_config` carries
upstream's new commented lines verbatim in both sections (rns-git's default
config is otherwise its own compact form), and `docs/rns-git.md` documents the
keys with upstream's example.

The 18.0 default does not slow the e2e tests: the harness turns destination
stamping off, so announces carry no link cost and clients grind no link
stamps; `e2e.rs` ran in 0.9-1.8 s, and no test-only cost was needed.

Tests (new, not compiling before the change):
`destination_costs_default_to_upstreams`,
`parses_and_quantizes_destination_costs`,
`invalid_destination_costs_are_errors`,
`rngit_destinations_carry_their_link_cost_and_stamp_value`,
`rngit_invalid_page_cost_fails_the_page_destination`. Tests run: `cargo test
-p rns-git` passed (lib 223 with 2 ignored, `e2e.rs` 8 with 1 ignored,
`releases.rs` 11, `stats.rs` 6, no failures); `python_work_lifecycle_interop`
(ignored by default) passed with `PYTHONPATH` at a disposable upstream
worktree at `05ac4bba`; `cargo fmt --check` and `bash scripts/lint-host.sh`
passed.

**Final disposition:** Integrated.

### 13. `833f6cf2` — Fixed path table culling being able to remove an instance's own local destination paths

**Upstream change:** The "never used" cull skips paths received on a local
client interface, and an accepted announce from a local client marks its path
responsive (refreshing expiry and `used`) instead of unknown. The cull
condition is replaced by commit 15; the responsive marking stays.

**Rust applicability:** Missing. `jobs::cull_path_table` (`transport/jobs.rs:196-206`)
has no exemption, and `process_verified_announce` always clears the path state
(`verified_announce.rs:248`). A shared instance culls a local client's
destination after the unused-path linger.

**Local handling and evidence:** `7428468e`. `process_verified_announce`
calls `mark_path_responsive` (timestamp and `used` set to now, expiry from
the receiving interface's mode, state responsive) right after the path is
stored, when the announce came from an interface the engine serves as a
shared instance (`serves_local_client`, the faithful counterpart of
upstream's `from_local_client`: a shared instance client's connection to the
instance is flagged `is_local_client` too but has no transport identity).
The cull exemption went into a new `cull_path_table_on_instance`, taking
whether the engine serves local clients (transport identity present), used
by the tick cull and the path destination cap; the public
`cull_path_table` kept its behaviour. Commit 15 removed that exemption
again.

Tests (new, failing before the change):
`a_local_clients_announce_marks_its_path_responsive` (inbound engine: a
served local client's announce leaves the path responsive with `used`,
timestamp and expiry refreshed; one from the network, or from the instance
connection of a shared instance client, does not) and
`never_used_local_client_paths_stay_on_an_instance_serving_them` (jobs).
Tests run: `cargo test -p rns-core` passed (lib 1162, integration suites
19, 26, 12, 9, 9, 7 and 1, no failures); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed. rns-net was not changed by this commit;
its full suite ran from commit 15 on.

**Final disposition:** Integrated.

### 14. `d72cfdd7` — Mark local client paths responsive on PR responses

**Upstream change:** A local client's path response marks the path
responsive. Once commit 13 is in, the same call after the path is stored
already covers it, so this adds no observable change.

**Rust applicability:** Covered by commit 13's port, which marks every
verified announce from a local client, path responses included.

**Local handling and evidence:** `1338ab58`. Traced in upstream at
`d72cfdd7`: the new call sits in the `elif is_from_local_client and
packet.context == PATH_RESPONSE` branch, before the path table entry is
written. It refreshes the old entry (or does nothing for an unknown
destination); the entry written next is built with `path_used` read before
the call; 833f6cf2's `mark_path_responsive` after the write then sets
timestamp, expiry, `used` and state again, and nothing in between reads the
path table. The outcome equals 13's alone, which rns-rs applies to every
accepted announce from a served local client, path responses included. No
code change; a pinning test.

Test: `a_local_clients_path_response_marks_its_path_responsive` (known or
unknown destination, with or without a pending request: responsive, with
timestamp, expiry and `used` set to now); the local client announce helper
gains `announce_with_random_blob`. Tests run: `cargo test -p rns-core`
passed (lib 1163, no failures); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed.

**Final disposition:** Structurally covered.

### 15. `5bd93ad9` — Ensure link-based rediscovery does not occur for instance-local paths

**Upstream change:** For hops-0 (instance-local) paths: a failed own link
neither expires the path nor requests rediscovery; an unproven link from a
local client to such a destination triggers nothing; and the cull no longer
removes them for expiry or non-use (only for a missing interface or the
unused-pool cap). Replaces commit 13's cull condition.

**Rust applicability:** Missing in all three places:
`Driver::rediscover_path_after_failed_link` (`driver/events/paths.rs:53-73`),
`rediscover_unproven_link_paths` (`transport/maintenance.rs:140-145`) and the
cull closure. Rust's `drop_path` removes paths directly, so upstream's
side effect on `rnpath -d` does not arise.

**Local handling and evidence:** `35028c47`.
`Driver::rediscover_path_after_failed_link` returns before expiring the
path or queueing a request when the destination's primary path is hops 0.
`rediscover_unproven_link_paths` keeps upstream's elif semantics: the
`taken_hops == 0` case matches and, for a hops-0 destination, triggers
nothing rather than falling through to the one-hop cases. The cull keeps a
hops-0 path through expiry and the unused linger; a missing interface, the
hop limiter and the never-used pool cap still remove it.
`cull_path_table_on_instance` (commit 13) is gone and the engine calls
`cull_path_table` again. rns-rs's own destination cap
(`max_path_destinations`, `enforce_path_destination_cap` in `retention.rs`)
is an rns-rs extension and keeps its behaviour: when the table is full it
evicts the oldest destinations and can still evict a hops-0 path. Rust's
`drop_path` removes a path directly, so upstream's side effect on `rnpath
-d` does not arise.

Tests (new, each failing with its guard disabled):
`failed_own_link_to_an_instance_local_destination_is_not_rediscovered`
(driver), `local_client_link_to_an_instance_local_destination_is_not_rediscovered`
(maintenance), `instance_local_paths_go_only_with_their_interface_or_the_pool_cap`
(jobs, replacing 13's cull test). Tests run: `cargo test -p rns-core`
passed (lib 1164); `cargo test -p rns-net` passed (1697 passed, 4 ignored,
no failures); `cargo fmt --check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Integrated.

### 16. `70eb417d` — Fixed non path table resident shared local instance destination path response announces broadcasting on all interfaces

**Upstream change:** When a local client's path response answers a pending
path request, it is now sent once, only to the requesting interface, as a path
response; before, it went out as a plain announce on every interface.

**Rust applicability:** Missing. `verified_announce.rs:253-278` discards the
requesting interface and builds the entry with `attached_interface: None,
block_rebroadcasts: false`. The sending side already supports attached path
responses.

**Local handling and evidence:** `3d500abc`. The announce table entry
for a local client's path response that answers a pending request now
carries the recorded requesting interface as `attached_interface` and
`block_rebroadcasts: true`; the announce job sends it there only, and
`build_retransmit_announce` gives it the path response context.

Tests: `only_a_local_clients_path_response_answers_a_pending_request`
(updated: expects the requesting interface and blocked rebroadcasts), the
new tick-level `a_local_clients_path_response_answers_only_the_requesting_interface`
(exactly one packet, on the requesting interface, as a path response, no
broadcast), and `test_shared_instance_without_transport_relays_path_request_to_local_client`
(issue 183, found pinning the old context by the first full run; updated to
expect the path response context). All three fail without the change. Tests
run: `cargo test -p rns-core` first failed only on that issue 183 test,
then passed after its update (1248 across all rns-core test binaries, no
failures); `cargo test -p rns-net` passed (1697 passed, 4 ignored);
`cargo fmt --check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Integrated.

### 17. `8c73e203` — Don't rebroadcast on unresponsive path lenient table insertions

**Upstream change:** When an announce replaces an unresponsive path only
because that path is unresponsive (more hops, same emission time), the path
table is updated but the announce is not rebroadcast.

**Rust applicability:** Missing: `process_validated_announce` always queues a
rebroadcast. Rust also accepts this lenient case in the `<=` hops branch
(`pathfinder.rs:182`), which upstream does not, and rejects an
already-known announce arriving through a **new** next hop even when the path
is unresponsive (`pathfinder.rs:304-323`), which is upstream's main recovery
case. That second difference predates this range.

**Local handling and evidence:** `0d994265`. `should_update_path`
returns the new `PathDecision::AddForUnresponsive` for every case it
accepts only because the path is unresponsive, and the multi-path decision
maps it to `MultiPathDecision::RecoverUnresponsive`: stored as
`ReplacePrimary`, but the announce table entry is not inserted. As
upstream's flag, it does not affect a local client's path response
answering a pending request. rns-rs's extra acceptances (over the same or
fewer hops, and for an expired path over more hops, where upstream takes
only an announce it has not heard) are made insertion-only too, by the
default behaviour. The new-next-hop difference is decision 8, implemented
in `53f34b11` (`transport: an option to recover unresponsive paths as
upstream does`, no trailer): `[reticulum] unresponsive_path_recovery =
native|upstream`, see decision 8.

Tests: `unresponsive_path_replacement_is_not_rebroadcast` (new, failing
before the change); the pathfinder tests for the two unresponsive cases now
expect `AddForUnresponsive` and are renamed `*_is_a_table_insertion`. Tests
run: `cargo test -p rns-core` passed (1249 across all binaries); `cargo
test -p rns-net` passed (1697 passed, 4 ignored); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed.

**Final disposition:** Integrated.

### 18. `4a058544` — Well, yeah

**Upstream change:** Crash guards: persistence and the exit handler check that
`Transport.owner` exists before using it.

**Rust applicability:** Persistence is only reachable through a constructed
`RnsNode` (`node/known_destinations.rs:233-249`, called from shutdown), and
shared clients are built without a store, which plays the role of upstream's
shared-instance check.

**Local handling and evidence:** `bd431f23`. Verified: the known
destinations and transport state are persisted only by methods of a
constructed `RnsNode`, from its shutdown, and a shared instance client is
built with `RnsNode::from_parts`, which leaves the known destinations store
and path and `transport_state_dir` unset, so both return at once. A doc
comment on `persist_known_destinations` records this. Tests run: `cargo
test -p rns-net` passed (1698 passed, 4 ignored); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed.

**Final disposition:** Structurally covered.

### 19. `8e7dc8b7` — Added medium reliability flag to interfaces

**Upstream change:** Adds `Interface.lossless_medium`, true for TCP, Backbone
and I2P interfaces. Nothing reads it yet.

**Rust applicability:** No equivalent. With no reader there is no observable
behaviour.

**Local handling and evidence:** `9f503ac2`. `lossless_medium()` in
`rns-net/src/interface/type_hints.rs` (in `interface/mod.rs` until the
rebase onto `dev@51ccbcc5`, which split that file), next to `shared_medium_hint` and
`tunnels_allowed` and keyed by the interface type like them, is true for
`TCPClientInterface`, `TCPServerInterface`, `TCPServerClientInterface` (a
TCP server's spawned clients, `TCPClientInterface` upstream),
`BackboneInterface`, `BackboneClientInterface`, `BackboneInterfacePeer` (a
Backbone server's spawned peers, `BackboneClientInterface` upstream),
`I2PInterface` and `I2PInterfacePeer`, and false for every other class. As
decision 6, nothing reads it; it is `pub(crate)` with `#[allow(dead_code)]`
and the reason in the attribute (upstream adds it with no reader, kept for
parity). It is not reported over RPC, as upstream. Test:
`lossless_medium_matches_upstreams_interface_classes` (new; the function did
not exist before). Tests run: `cargo test -p rns-net` passed (1699 passed,
0 failed); `cargo fmt --check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Integrated (decision 6).

### 20. `9568b704` — Improved rnpath display and filtering options

**Upstream change:** New `-a/--active`, `-V/--vias`, `-E/--expiry` and
`-M/--min-value`. The default `rnpath -t` line drops ` via …` and
` expires in …` unless `-V` / `-E` are given. Filters count a destination
before filtering it, so a filtered `rnpath -t <hash>` prints nothing; JSON
output ignores the flags.

**Rust applicability:** Missing. `rns-cli/src/bin/rnpath.rs` has none of the
flags and always prints via and expiry. The interop test
`rns-cli/tests/utility_interop.rs:2070` expects ` via ` in Python's output and
will fail against the new target unless it passes `-V`.

**Local handling and evidence:** `b216a018`. `rnpath` (and `rns-ctl path`,
which shares its option table and code) takes `-a/--active`, `-V/--vias`,
`-E/--expiry` and `-M/--min-value` (metavar `hops`, a float); a line shows
` via …` only with `-V` and ` expires in …` only with `-E`. The filters
follow upstream's code: a path counts as displayed before `-M` or `-a`
leave it out (so a filtered `rnpath -t <hash>` prints nothing and exits 0),
`-M` filters only when its value is non-zero and then drops paths with no or
a zero value and those below it (a negative or NaN value filters too), `-a`
drops paths whose `used` is falsy and none from a table without usage
info, and `-j` ignores all four. Both local and `-R` remote tables. The
parser table, `tests/fixtures/argparse/rnpath.pickle` and
`tests/fixtures/cli_golden/rnpath.txt` were regenerated with
`tests/generate_argparse_fixtures.py` and `RNS_GOLDEN_BLESS=1` from a
disposable upstream worktree at `9568b704`; only rnpath's entries changed,
and the golden help matches Python's `--help` at 80 columns apart from the
program name. The expected texts of the new test are upstream's rendering
code at `9568b704` run on the same tables. `utility_interop`'s remote path
table check passes `-V` when the Python rnpath has `--vias`.
`docs/cli-tools.md` lists the options; `docs/rns-ctl.md` lists no rnpath
flags.

Tests: `path_table_display_options_and_filters_as_upstream` (new),
`path_table_prints_as_upstream` (default line updated; fails before the
change), `parses_upstream_invocations_as_argparse_does` (new cases). Tests
run: `cargo test -p rns-cli` passed (163 passed, 34 ignored), `cargo test -p
rns-ctl` passed (131), `cargo fmt --check` and `bash scripts/lint-host.sh`
passed. Live, with `PYTHONPATH` and `RETICULUM_UPSTREAM_DIR` on a
disposable worktree at `9568b704`: `cargo test -p rns-cli --test
utility_interop -- --ignored --exact python_rns_is_available_for_utility_interop
python_rnpath_reads_rust_remote_path_table python_rnpath_lists_rust_path_table`
passed (3 passed).

**Final disposition:** Integrated.

### 21. `c90a5d58` — Added destination type loading

**Upstream change:** (a) Reads `known_destination_types` and
`flagged_destination_types` files into name maps used only for log text.
(b) Path-table entries gain `interface_hash`, visible over RPC and in
`rnpath -j`.

**Rust applicability:** (b) missing from `path_table_to_pickle`
(`rpc/responses.rs:26-74`); the display name it hashes is already available.
(a) has no consumer beyond logging.

**Local handling and evidence:** `6528b48c`. Both parts are ported (a is
needed by decision 3). The review's analysis was incomplete on two points:
upstream already had `destination_type_map` and `destination_type_name()`
at the `884f109b` baseline, and rns-rs had neither (it logged the requested
full name without the type hash and did not log the types `unwants_all`
withdraws); and at `c90a5d58` upstream's `Transport` has no
`flagged_type_map` (3f55e9eb adds it), so loading a flagged types file with
any line fails.

(a) `rns_net::destination_types::DestinationTypeNames` is the map: the
`[filter]` ignored and allowed types' names (for the bracketed form the kept
characters, as `block/allow_destination_type` record them, via the new
`rns_core` `configured_destination_type_name`), then
`<configdir>/known_destination_types`, read as upstream: only if it is a
file, `strip()` and `splitlines()` with Python's semantics, each line
stripped, `#` lines skipped, every other line (an empty one too) recorded
under its name hash; an unreadable file logs `Error while loading known
destination types list: …` (Rust's error text) and adds nothing.
`flagged_destination_types` with any line to record logs upstream's
`Error while loading flagged destination types list: type object
'Transport' has no attribute 'flagged_type_map'` and records nothing.
Shared instances and shared instance clients each load it with their config;
the driver holds it (`Driver::destination_type_names`), for commits 22 and
24. A wanted type records its name; the Registered, Deregistered and "No
remaining requesters" debug lines read as upstream's (`<name> <hash>
destinations …`), and `unwants_all_destination_types` logs each withdrawn
type in upstream's dict order (`DestinationTypeFilter` keeps it).
`docs/configuration.md` describes the files.

(b) Path table entries gain `interface_hash` after `interface`: the full
hash of the interface's display name, as `parent_interface_hash`. It reaches
the RPC path table, remote management `/path` and `rnpath -j`.
`utility_interop`'s remote table shape comparison drops `interface_hash`
only against a Python Reticulum without it.

Tests (new): `known_destination_types_are_read_as_upstream`,
`missing_unreadable_and_flagged_type_files_add_nothing`,
`the_config_filter_names_come_first_and_the_file_overrides_them`,
`splitlines_and_strip_follow_python`,
`wanted_destination_types_are_named_in_the_type_map`,
`unwant_all_reports_types_in_the_order_they_were_first_wanted`,
`configured_destination_types_name_as_upstreams_type_map`; extended:
`path_and_rate_tables_follow_upstreams_keys_and_types`,
`unwant_all_withdraws_only_that_requester` (both fail before the change),
and the JSON case of `path_table_prints_as_upstream`, whose table now
carries `interface_hash` (rnpath passes it through unchanged). Tests run:
`cargo test -p rns-core` passed (1253), `cargo test -p rns-net` passed
(1704 passed, 4 ignored), `cargo test -p rns-cli` passed (163 passed, 34
ignored), `cargo fmt --check` and `bash scripts/lint-host.sh` passed. Live,
on a disposable worktree at `c90a5d58`: `python_rns_is_available_for_utility_interop`,
`python_rnpath_reads_rust_remote_path_table` and
`python_rnpath_lists_rust_path_table` passed (3 passed).

Not ported in this commit (pre-existing, already at `884f109b`): upstream's
`Blocked …` and `Allowing …` debug lines when the `[filter]` section is
applied, and the `Could not … destination type …` error lines.

Follow-up `630f71bb` (`filter: log destination type filtering as upstream
does`, no `Upstream-Commit` trailer) adds the first two as at `884f109b`.
The parser records the `[filter]` key order (`FilterSection::key_order`, as
`0b755fcf` does for `[reticulum]`), and
`DestinationTypeNames::from_filter` applies the section in that order:
`Blocked <name> <hash> destinations` at debug for each ignored type, and
`Allowing <<name>> <hash> destinations` at debug for each allowed type only
once `required_only = yes` has been read, so only when it comes before
`allowed_types`; of a type listed under both keys the later key's name
stays in the map. `from_config` logs the lines, for a shared instance and a
client alike. The `Could not add … to blocked list` and `… to allowed list`
errors are not logged: their `try` blocks cannot fail for a config value,
which ConfigObj always decodes to a `str` (`_handle_bom` decodes the file as
UTF-8). The other `Could not …` lines (`… to clients required list`, `…
from clients required list`, `Could not deregister all destination types
…`) are left open: upstream reaches them only for an RPC call whose
`requester` is not bytes (None, a str, a number, a list or dict) or whose
name is not a str, where Python's exception text decides the message and,
for several of them, the `except` block raises again, so the line is never
logged and `rpc_loop` logs its own error instead. rns-rs's typed RPC
handler ignores such calls. Reproducing Python's dynamic type failures was
not attempted; it needs a decision. Test:
`filter_types_are_logged_as_upstream_applies_them` (its `Allowing` texts
follow `destination_type_name` as `3f55e9eb` changes it). Tests run:
`cargo test -p rns-net` passed (lib 1600, `e2e.rs` 74 with 1 ignored,
`e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1 ignored), `cargo
fmt --check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Integrated.

### 22. `3f55e9eb` — Added flagged destination type map, per-link traffic counter, link distribution stats getter

**Upstream change:** Link-table entries count forwarded bytes, and
`link_distribution()` returns
`{dst: {active, pending, traffic, from_ifs}}`. `from_ifs` is a Python set,
which upstream's msgpack RPC cannot encode until commit 26. The type-name
change affects logs only.

**Rust applicability:** `LinkEntry` has no traffic field, and
`link_distribution` returns a locally invented `{total, active}` shape
(`transport/queries.rs:388`, `rpc/responses.rs:6`) with no other consumer.

**Local handling and evidence:** `7f26a06d`, per decision 2. The review's
plan to encode `from_ifs` as a list at this commit was replaced by the
decision: the commit reproduces the set's failure.

Type names: `DestinationTypeNames` keeps `Transport.flagged_type_map`. The
`flagged_destination_types` file now loads into it (the `c90a5d58` error is
gone) and a type the `[filter]` section blocks is flagged too.
`type_name()` (`destination_type_name`) gives the name, else the flagged
name, else the bare hex of the hash, without angle brackets, so the
`Allowing`, `Registered`, `Deregistered` and `No remaining requesters`
lines read `lxmf.delivery <hash> …` and an unnamed type shows its hex where
it showed `<unknown>`. The review did not mention the bracket change.

Traffic: rns-core `LinkEntry::traffic` (`IDX_LT_TRXB`) adds the raw length
of every link packet `handle_link_table_routing` forwards along the link,
as upstream adds `len(new_raw)` after `transmit`; link request proofs and
packets not forwarded add nothing.

Distribution: `TransportEngine::link_distribution` returns
`LinkDistribution { destination_hash, active, pending, traffic,
from_interfaces }` per destination, the receiving interfaces each once; the
driver turns them into `get_hash()` values (the full hash of the
interface's display name, as the path table's `interface_hash`), so two
interfaces of one name count once, as in upstream's set
(`LinkDistributionEntry::from_interface_hashes`). The native `total` key
is gone. Destinations come in link table order, which in rns-rs is by link
id where upstream's dict keeps insertion order; at this commit no answer
shows the order (see below), from commit 26 on it decides the order of the
answer's keys and of `from_ifs`.

RPC: for any destination with links, upstream's `rpc_return` raises
`unsupported type: <class 'set'>` (umsgpack, checked against
`RNS/vendor/umsgpack.py`), `rpc_loop` logs `An error ocurred while handling
RPC call from local client: unsupported type: <class 'set'>` at error level
and closes the connection unanswered; the client sees EOF (Python's client
logs `Shared instance RPC failed while getting link distribution: ` and
returns None). rns-rs now does the same: `link_distribution_to_pickle`
fails with an `UpstreamRpcException`, `answer_request` logs upstream's line
and the connection closes without an answer. An empty table answers `{}`.
The legacy pickle codec, which upstream no longer speaks, fails the same
way. `docs/configuration.md` describes the flagged names and the `[filter]`
lines.

Tests (new): `forwarded_link_traffic_counts_raw_bytes` (fails with the
counter removed), `link_distribution_names_receiving_interfaces_by_hash`,
`link_distribution_rpc_fails_as_upstreams_set_does` (one link: error with
upstream's line and EOF at the client; none: `{}`),
`type_names_come_from_the_map_then_the_flagged_map_then_the_hash`;
rewritten: `link_distribution_counts_per_destination`; updated for the new
names: `known_destination_types_are_read_as_upstream`,
`missing_and_unreadable_type_files_add_nothing` (was
`missing_unreadable_and_flagged_type_files_add_nothing`),
`filter_types_are_logged_as_upstream_applies_them`,
`wanted_destination_types_are_named_in_the_type_map`. Tests run: `cargo
test -p rns-core` passed (lib 1171 and its other targets), `cargo test -p
rns-net` passed (lib 1603, `e2e.rs` 74 with 1 ignored,
`e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1 ignored), `cargo
fmt --check` and `bash scripts/lint-host.sh` passed. Not run live: a
Python client against an rns-rs instance with a relayed link.

**Final disposition:** Integrated.

### 23. `f7b54ccc` — Added prettynamehash convenience function

**Upstream change:** A Python helper `RNS.prettynamehash()` with no caller.

**Rust applicability:** No caller, no wire/RPC/CLI output. Verified:
`git grep prettynamehash cff4d03f` finds only its definition.

**Local handling and evidence:** `4815c264`: a note in
`rns-cli/src/pyfmt.rs`, beside `prettyhexrep`, that the helper is
`f"<{Transport.destination_type_name(name_hash)}>"`, has no caller up to
`cff4d03f`, and that the lookup it wraps is
`DestinationTypeNames::type_name`. Tests run: `cargo test -p rns-cli`
passed (lib 134, `utility_interop.rs` 5 with 33 ignored), `cargo fmt
--check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Non-runtime.

### 24. `1a71073c` — Initial rnpath analysis stub

**Upstream change:** Adds `rnpath -A/--analyze`, which fetches the path, rate
and link-distribution tables and prints statistics from private Python state.
Commit 31 replaces the body with "Not yet implemented".

**Rust applicability:** No `-A` in `rnpath.rs`.

**Local handling and evidence:** `8b9b4fbf`, per decision 3 (the
statistics as at this commit, not the review's recommendation of the tip's
`Not yet implemented`).

`-A/--analyze` counts as work on its own and comes after `-b`/`-p`, `-B`
and `-U` and before `-t`; with `-R` upstream analyzes the local tables once
the management link is up, and so does rns-rs (`RemoteAction::Analyze`).
The three RPC calls go in upstream's order, each on its own connection; a
failure is logged at error level as `Shared instance RPC failed while
getting <path table|rate table|link distribution>: <e>` (an unanswered
connection, which the link distribution of commit 22 gives, has Python's
empty `EOFError` text) and gives `[]` or None. An empty path table prints
`No path table to analyze`; otherwise `Analyzing tables...` and the six
counts, exit 0.

State: upstream reads the client's `Identity.known_destinations`, its
announce cache (`init_announce_cache` when connected to a shared instance)
and `Transport.destination_type_map`. rns-rs's rnpath reads its shared
instance client's known destinations (loaded as in commit 9's mapping), the
announce cache in `<configdir>/cache/announces.db` (where an rns-rs
instance keeps it; upstream's is `storage/cache/announces.db`) and the
client's destination type names (commit 21's mapping, the names map only,
through the new `RnsNode::destination_type_names`). The name hash is
`data[64:74]` of the cached announce after `Packet.unpack()`, cut short as
Python slices are. Upstream's rnpath also asks for
`rnstransport.remote.management` and `rnstransport.info.blackhole`
announces right after it starts, which names both types in its map;
rns-rs's local rnpath did not and now does, in every local mode
(`LocalInstance::open`). A cached announce that `unpack` cannot read up to
its data (shorter than its header, or 128 hops or more) makes upstream's
analysis die with `AttributeError: 'Packet' object has no attribute
'data'`; rns-rs prints that line to stderr and exits 1 (Python prints the
whole traceback).

Fixtures: the parser table, `tests/fixtures/argparse/rnpath.pickle` and
`tests/fixtures/cli_golden/rnpath.txt` were regenerated with
`tests/generate_argparse_fixtures.py` and `RNS_GOLDEN_BLESS=1` from a
disposable worktree at `1a71073c`; only rnpath's entries changed.
`docs/cli-tools.md` lists `-A`.

Comparison with Python: not added to the interop harness. Run by hand on
the same config (an rns-rs instance with an `rncp -l` destination), Python
rnpath at `1a71073c` printed all zeros where rns-rs's printed one unknown
type, because a Python client opens `storage/cache/announces.db`, which an
rns-rs instance does not write: the analysis is unit-tested instead.
`analysis_counts_destination_types_as_upstream` feeds the same path table,
known destinations, cached announces and type map to
`analyze_path_table` that upstream's `analyze_tables` at `1a71073c`
(Python 3.12, disposable worktree) was run on, and expects its printed
lines (2, 3, 5, 3, 3, 6), and its `AttributeError` for five unreadable
announces.

Tests: `analysis_counts_destination_types_as_upstream` (new),
`parses_upstream_invocations_as_argparse_does` (`-A` cases),
`utilities_offline_output_matches_snapshot` (regenerated golden). Tests
run: `cargo test -p rns-cli` passed (lib 135, `utility_interop.rs` 5 with
33 ignored, `cli_golden` 1), `cargo test -p rns-net` passed (lib 1603,
`e2e.rs` 74 with 1 ignored, `e2e_direct_connect.rs` 19,
`python_interop.rs` 6 with 1 ignored), `cargo test -p rns-ctl` passed (131),
`cargo fmt --check` and `bash scripts/lint-host.sh` passed. Live, with
`PYTHONPATH` and `RETICULUM_UPSTREAM_DIR` on a disposable worktree at
`1a71073c`: `cargo test -p rns-cli --test utility_interop -- --ignored
--exact python_rns_is_available_for_utility_interop
python_rnpath_manages_rust_blackhole
rnpath_looks_up_a_destination_as_python_does
rust_utilities_run_cleanly_against_python_instance
python_utilities_run_cleanly_against_rust_instance
rust_instance_fetches_python_blackhole_source
python_instance_fetches_rust_blackhole_source` passed (7 passed), for the
new startup registrations. By hand against an rns-rs instance: `rnpath -A`
printed `No path table to analyze` (exit 0) with no paths, and with an
`rncp -l` destination one unknown type, or one known type once
`rncp.receive` was in `known_destination_types`.

**Final disposition:** Integrated.

### 25. `b9903c53` — Analysis mode capture argument

**Upstream change:** Adds `--capture`, accepted and ignored. Changes help text
and creates a new ambiguous `--c` prefix.

**Rust applicability:** Missing from the parser.

**Local handling and evidence:** `d78d7c76`. `rnpath` takes `--capture`
(one value; metavar `hops` and help `path to capture file for analyze
mode`, as at this commit) and passes it to `analyze_tables`, locally and
with `-R` (`RemoteAction::Analyze(capture)`), where it is unused, as
upstream's TODO leaves it. `--c` now abbreviates `--config` and
`--capture`: argparse refuses it with `ambiguous option: --c could match
--config, --capture` (exit 2), also as `--c=VALUE` (whose text it
repeats), whatever follows; checked against Python at `b9903c53`, and
rns-rs does the same. The Rust-only `-c` short option is unaffected. The
parser table, `tests/fixtures/argparse/rnpath.pickle` (its error cases now
include `--c`) and `tests/fixtures/cli_golden/rnpath.txt` were regenerated
with `tests/generate_argparse_fixtures.py` and `RNS_GOLDEN_BLESS=1` from a
disposable worktree at `b9903c53`; only rnpath's entries changed.
`docs/cli-tools.md` mentions `--capture`.

Tests: `parses_upstream_invocations_as_argparse_does` (new `--capture`,
`--capt=` and `--co` cases, and the `--c` ambiguity through
`argparse::check`), `help_and_errors_match_upstreams_parsers` and
`utilities_offline_output_matches_snapshot` on the regenerated fixtures;
the first two fail with the option left out of the option table. Tests
run: `cargo test -p rns-cli` passed (lib 135, `cli_golden` 1,
`utility_interop.rs` 5 with 33 ignored), `cargo fmt --check` and `bash
scripts/lint-host.sh` passed.

**Final disposition:** Integrated.

### 26. `1f7cd145` — Cleanup and fixes

**Upstream change:** rnpath metavar fixes (help text only), and
`link_distribution`'s `from_ifs` becomes a de-duplicated list so the RPC can
encode it.

**Rust applicability:** Parser metavars differ; `from_ifs` follows commit 22's
port.

**Local handling and evidence:** `af10606b`, per decision 2.

Metavars: `-M/--min-value value` (was `hops`), `--duration hours` and
`--reason reason` (were argparse's `DURATION`/`REASON`), `--capture path`
(was `hops`). Parser table, argparse fixture and golden help regenerated
as for commit 25, from a disposable worktree at `1f7cd145`; only rnpath's
entries changed.

Link distribution: the answer is a map from destination hash to
`{"active", "pending", "traffic", "from_ifs"}`, `from_ifs` a list of
interface hashes in first-seen order, so it encodes and the client gets
it. The failure commit 22's mapping reproduced is gone, and with it the
`UpstreamRpcException` machinery that only it used (the logging in
`answer_request` is back to its pre-`7f26a06d` form).

Order: upstream iterates its `link_table` dict, so destinations come in
the order of their first link and `from_ifs` in the order first seen.
rns-core's link table was a `BTreeMap` by link id (the order commit 22's
mapping noted); it is now `tables::LinkTable`, which also keeps insertion
order as a Python dict does. Upstream assigns
`link_table[link_id] = link_entry` when it forwards a link request; for a
link id already present that keeps the key's place, and a key deleted (by
culling) and assigned again goes to the end. `LinkTable::insert` (the
forwarded link request, `register_link`) keeps the place of a present
link id, and `remove`/`retain` (culling, `remove_link`,
`drop_links_for_interface`) drop it from the order. Only
`link_distribution` walks the table in insertion order
(`in_insertion_order`); lookups and the other walks (culling, link path
rediscovery) are by link id as before.

Comparison with Python: the answer bytes of the driver test below were
compared by hand with what upstream's `Transport.link_distribution()` at
`1f7cd145` (disposable worktree, Python 3.12) gives for the same link
table (the same four entries in the same insertion order, interfaces
returning the same `get_hash()`), packed with its `umsgpack.packb`: the
bytes are identical, and `umsgpack.unpackb` of rns-rs's bytes (what
`get_link_distribution` returns over RPC) equals Python's dict. Not added
to the live interop harness: populating an rns-rs instance's link table
with relayed links from Python peers is beyond the existing utility
topologies.

Tests: `link_distribution_follows_link_table_insertion_order` (rns-core:
link ids inserted against their order, replacement in place, removal and
reinsertion at the end, `drop_links_for_interface`),
`link_distribution_rpc_answer_keeps_upstreams_order` (rns-net driver: two
links to one destination over one interface, one over a second, and a
second destination between them; through `answer_request`, `from_ifs`
holds the two distinct hashes in first-seen order, destinations come in
insertion order, and the msgpack answer unpacks and packs back to the
same bytes), `link_distribution_rpc_answers_with_from_ifs_lists`
(replaces `link_distribution_rpc_fails_as_upstreams_set_does`); the
first two fail with the table walked by link id. Tests run: `cargo test
-p rns-core` passed (lib 1172 and its other targets), `cargo test -p
rns-net` passed (lib 1604, `e2e.rs` 74 with 1 ignored,
`e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1 ignored),
`cargo test -p rns-cli` passed (lib 135, `utility_interop.rs` 5 with 33
ignored), `cargo fmt --check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Integrated.

### 27. `41260ea1` — Added path state info to path table getters

**Upstream change:** Path-table entries gain `state`, and `rnpath -t` prints
` (R)`, ` (u)` or ` (?)` after the hop count.

**Rust applicability:** Interop hazard: upstream rnpath reads `path["state"]`
without a fallback, so Python rnpath at this commit fails against an rns-rs
daemon. `path_states` exists in the engine but is not exposed in the table.

**Local handling and evidence:** `54d13f99`. `TransportEngine::path_state`
is `get_path_state` (`STATE_UNKNOWN` when unmarked); `PathTableEntry`
carries it, and `path_table_to_pickle` adds `state` (an int) after
`interface_hash`, so the shared instance RPC, the remote management
`/path` answer (`path_table_msgpack`) and `rnpath -j` have it. `rnpath -t`
prints ` (R)`, ` (u)` or ` (?)` right after `{hops:>3}h`, before ` via`,
compared as Python's `==` (`True` is unresponsive, `2.0` responsive).
Deviation: upstream raises `KeyError` on an entry without `state` (an
older daemon); rns-rs prints ` (?)`, as it prints `n` for a missing
`value` or `lr_cost`. `docs/cli-tools.md` describes the marker and key.

Tests: `test_path_state`, `query_path_table` (driver entries follow the
engine's marks), `path_and_rate_tables_follow_upstreams_keys_and_types`
(key order, `state` an int), `path_table_prints_as_upstream` and
`path_table_display_options_and_filters_as_upstream` (states 2, 0, 1, 7;
their PLAIN, USAGE, NO_USED, VIAS_EXPIRY, VIAS, EXPIRY and JSON texts are
byte for byte what upstream's `program_setup` at `41260ea1` printed for
the same table and time, run by hand), `path_state_marker_as_upstream`
(new); in `utility_interop.rs`, `python_rnpath_lists_rust_path_table`
now checks Python's marker and that Rust's `rnpath -t` prints the same
line, and `python_rnpath_reads_rust_remote_path_table` expects `state`
where Python's entries have it. Tests run: `cargo test -p rns-core`
passed (lib 1172), `cargo test -p rns-net` passed (lib 1604, `e2e.rs` 74
with 1 ignored, `e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1
ignored), `cargo test -p rns-cli` passed (lib 136, `utility_interop.rs` 5
with 33 ignored), `cargo test -p rns-ctl` passed, `cargo fmt --check` and
`bash scripts/lint-host.sh` passed. Live, with `PYTHONPATH` and
`RETICULUM_UPSTREAM_DIR` on a disposable worktree at `41260ea1`: `cargo
test -p rns-cli --test utility_interop -- --ignored --exact
python_rns_is_available_for_utility_interop
python_rnpath_lists_rust_path_table
python_rnpath_reads_rust_remote_path_table
rnpath_looks_up_a_destination_as_python_does
python_rnpath_manages_rust_blackhole
python_rnpath_manages_rust_instance_without_transport
python_rnpath_manages_python_instance_without_transport
rust_instance_fetches_python_blackhole_source
python_instance_fetches_rust_blackhole_source
rust_utilities_run_cleanly_against_python_instance
python_utilities_run_cleanly_against_rust_instance` passed (11 passed).
With the `state` key removed, `python_rnpath_lists_rust_path_table`
failed with Python's `KeyError: 'state'` and
`python_rnpath_reads_rust_remote_path_table` failed on the shape.

**Final disposition:** Integrated.

### 28. `48ba76df` — Catch announce unpack failure

**Upstream change:** A guard inside commit 24's analysis loop, which commit 31
withdraws: `try: announce_packet.unpack()` / `except: unresolvable +=1;
continue`.

**Rust applicability:** Under decision 3 the analysis of commit 24 is
ported, so the guard was to be ported too. It has no effect upstream:
`Packet.unpack` catches every exception itself and returns False, so the
`except` never runs, and an announce that `unpack` cannot read up to its
data still raises `AttributeError: 'Packet' object has no attribute
'data'` on the next line, `announce_packet.data[...]`, outside the guard.
The review's expectation (and the batch brief's) that such an entry is
now counted as unresolvable and the analysis continues does not match
upstream.

**Local handling and evidence:** `3ff7bfdb`. No behaviour change: the
doc comment of `analyze_path_table` and a comment at the `data` read say
why the guard does not apply. Upstream's `analyze_tables` at `48ba76df`
(Python 3.12, disposable worktree, a harness feeding it the inputs of
`analysis_counts_destination_types_as_upstream` through
`Identity.known_destinations`, `Transport.get_cached_packet` and
`Transport.destination_type_map`) printed the same six counts (2, 3, 5,
3, 3, 6) for the readable table, and raised the `AttributeError` for
each of the five unreadable announces, both alone and among the readable
ones in the whole table. The test now also checks the whole-table case.
Tests run: `cargo test -p rns-cli` passed (lib 136, `cli_golden` 1,
`utility_interop.rs` 5 with 33 ignored, the other targets), `cargo fmt
--check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Structurally covered (decision 3).

### 29. `ef3e8086` — Added link traffic stats

**Upstream change:** Global `link_rxb` / `link_txb` counters for link-table
transport (excluding local clients), rates in the traffic loop, four new
interface-stats RPC keys, and a `Links` section in `rnstatus -t -l`.

**Rust applicability:** None of it exists.

**Local handling and evidence:** `ce679652`.

Counters: `TransportEngine` keeps `link_rxb`/`link_txb`
(`link_traffic()`). In `handle_link_table_routing`, every link packet of a
validated entry adds its raw length to `link_rxb` before the route is
chosen, relayed or not, unless it came from a local client this instance
serves (`serves_local_client`, upstream's `is_local_client_interface`);
after the `SendOnInterface` of a relayed packet its relayed length goes to
`link_txb` unless the outbound interface is a local client. Unvalidated
entries, announces, link requests and LRPROOFs add nothing, as upstream
returns or skips before its counters.

Speeds: the driver's `LinkTrafficSampler` runs from the tick as
upstream's traffic loop: the first pass a second after start, then about
once a second, `(bytes - bytes at the previous pass) * 8` over the time
since that pass on the monotonic clock (`time::monotonic`, new:
`CLOCK_MONOTONIC` through libc on unix, as Python's `time.monotonic()`).
Upstream's first pass measures from `Transport.start_time`, a
`time.time()` reading, so its interval is negative and its speeds `-0.0`
(or a tiny negative value for link traffic in the first second); the
sampler does the same. Before the first pass the speeds are `None`,
upstream's class attribute `0`.

RPC: `lrxb`, `ltxb`, `lrxs`, `ltxs` come right after `txs`, as in
upstream's dict; the totals are ints, the speeds the integer 0 before
the first pass and floats after (`LinkTraffic` in
`InterfaceStatsResponse`). The shared instance RPC, remote management
`/status` and `rnstatus -j` carry them.

rnstatus: `-t -l` prints the `Links` section after `Filtered`, with
upstream's text, padding, `min(100.0, …)` share of the data flow (the
totals less announces and path requests) and `int()` truncation, under
this commit's guards (total speed and link speed nonzero). Where
announces and path requests are all of a nonzero total while link
traffic flows that way, upstream divides by zero: Python raises
`ZeroDivisionError: float division by zero` with a traceback and exits 1.
This was reproduced: `render` returned a `Crash` with what was printed
first, `rnstatus` printed that, the exception line to stderr, and exited
1; in monitor mode upstream buffers the frame and loses it, so nothing of
it was printed (the screen clear and `-R` progress moved into the frame
for this). Commit 30's mapping removes it again.

Base class: `is_local_shared_instance` and `is_connected_to_shared_instance`
now default to False and Transport tests their values instead of
`hasattr`. Checked for a behaviour difference: the only interface that
set one of them to False is the server side of a local client connection
(`LocalClientInterface` with `connected_socket`), for which
`interface_to_shared_instance` now answers False instead of True. Its two
callers (the `required_destinations_only` announce check and the hops
decrement in `inbound`) only reach it after `is_local_client_interface`
or when there are no local client interfaces, so neither changes
behaviour; rns-rs's `is_local_client` flags need nothing.

Fixtures: `tests/generate_rnstatus_fixtures.py` run from a disposable
worktree at `ef3e8086`. The stats gain the four keys (no existing output
changed; only the `.pickle` inputs did), and `totals_links`,
`totals_links_everything`, `totals_links_idle` and
`totals_links_control_only` are new; the last raised, and the generator
now records an exception's last line in `<case>.err`, which
`rnstatus_view_matches_upstream` checked. Without the Links section the
test fails on all four. `docs/rnstatus.md` describes the section.

Live: an rns-rs `rnsd` and a Python `rnsd` at `ef3e8086` (transport
enabled, no interfaces), each queried with `rnstatus -j`, both answered
`"lrxs": 0, "ltxs": 0` (ints) right after start and `"lrxs": 0.0,
"ltxs": 0.0` (floats) a few seconds later; Python's `rnstatus -j` and
`-t -l` against the rns-rs instance read the same, and the `-t -l` texts
of the two daemons matched but for the instance name, transport id and
uptime (`Links        : ↑0 B  0 bps, 0% of data flow` both ways). The first-pass
`-0.0` window was not caught live.

Tests: `link_table_traffic_counts_relayed_bytes_but_local_clients`
(rns-core), `link_speeds_are_measured_as_upstreams_traffic_loop`,
`link_traffic_speeds_are_reported_once_measured`,
`link_traffic_keys_follow_upstreams_position_and_types` (rns-net),
`rnstatus_view_matches_upstream` (new cases). Tests run: `cargo test -p
rns-core` passed (lib 1173 and its other targets), `cargo test -p
rns-net` passed (lib 1607, `e2e.rs` 74 with 1 ignored,
`e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1 ignored),
`cargo test -p rns-cli` passed (lib 136, `utility_interop.rs` 5 with 33
ignored), `cargo test -p rns-ctl` passed (69, `integration.rs` 59, `cli.rs`
3), `cargo fmt --check` and `bash scripts/lint-host.sh` passed. Not
covered by a test: `rnstatus`'s exit path for the crash (only `render`'s
result was tested), now removed by commit 30.

**Final disposition:** Integrated.

### 30. `e8b3b14b` — Classic

**Upstream change:** Fixes a division by zero in commit 29's rnstatus
percentage; it now prints `0% of data flow`.

**Rust applicability:** Follows commit 29.

**Local handling and evidence:** `234f68d1`. The link shares are guarded
by the data flow (`drxs`/`dtxs`) and the link speed, as upstream;
nothing in the display raises any more, so the `Crash` plumbing of
commit 29's mapping is gone and `rnstatus.rs` is back to its earlier
form. Fixtures regenerated from a disposable worktree at `e8b3b14b`:
`totals_links_control_only` now prints `0% of data flow` both ways, and
`totals_links_control_only_tx` is new (a transmitted flow all announces
and path requests, with `-A` and `-P`). Running the same generator at
`ef3e8086` raised `ZeroDivisionError: float division by zero` for both;
no other output changed. `rnstatus_view_matches_upstream` fails on any
case where upstream raised, and fails on both cases with commit 29's
mapping. `docs/rnstatus.md` updated. Tests run: `cargo test -p rns-cli`
passed (lib 136, `cli_golden` 1, `utility_interop.rs` 5 with 33 ignored,
the other targets), `cargo fmt --check` and `bash scripts/lint-host.sh`
passed.

**Final disposition:** Integrated.

### 31. `eb00622f` — Cleanup

**Upstream change:** `rnpath -A` now always prints `Not yet implemented` and
exits 0; the analysis body is commented out.

**Rust applicability:** Under decision 3 commit 24's analysis was ported,
so this withdraws it. The whole diff was read: apart from `analyze_tables`
(now `print("Not yet implemented")` and `exit()`, the old body commented
out) nothing in `rnpath.py` changes. `program_setup` still evaluates
`get_path_table()`, `get_rate_table()` and `get_link_distribution()` as
the arguments, in that order and each on its own connection, before the
call: a failure is still logged (`Shared instance RPC failed while
getting ...`, returning `[]` or None) and the output is the same. An
empty path table no longer prints `No path table to analyze`; Python's
bare `exit()` is status 0.

**Local handling and evidence:** `755d9784`. `analyze_tables` makes the
three calls through the unchanged `analysis_rpc`, then writes `Not yet
implemented` and returns 0, locally and with `-R`. Removed as dead code,
as upstream's is: `analyze_path_table`, `TypeAnalysis`,
`cached_announce_name_hash`, `analysis_counts_destination_types_as_upstream`
and `RnsNode::destination_type_names` with
`QueryRequest`/`QueryResponse::DestinationTypeNames` (commit 24's
mapping added them for the analysis only). Kept: `-A` and `--capture`
(help unchanged, no fixture regenerated) and the startup path requests
for `rnstransport.remote.management` and `rnstransport.info.blackhole`,
which upstream's rnpath still makes. `docs/cli-tools.md` updated.
`analysis_is_not_yet_implemented` runs `analyze_tables` against an RPC
server answering an empty path table and then two paths, and with every
call failing: the output is exactly `Not yet implemented\n`, status 0,
and the queries arrive in upstream's order; with commit 24's analysis it
fails on the empty table (`No path table to analyze\n`, checked by
restoring that branch). Tests run: `cargo test -p rns-cli` passed (lib
136, `cli_golden` 1, `utility_interop.rs` 5 with 33 ignored, the other
targets), `cargo test -p rns-net` passed (lib 1607, `e2e.rs` 74 with 1
ignored, `e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1
ignored), `cargo fmt --check` and `bash scripts/lint-host.sh` passed.

Unchanged, and not part of this commit: as in every local mode, rns-rs's
rnpath exits 1 with `Could not connect to rnsd` when no shared instance
runs, where upstream's would start its own instance and, here, print
`Not yet implemented`.

**Final disposition:** Integrated (decision 3).

### 32. `01ffb98e` — Local link traffic counting

**Upstream change:** Link endpoints also feed commit 29's counters: received
link DATA and resource proofs, and every packet sent on an open link.

**Rust applicability:** The hook points exist
(`link_manager/inbound.rs`, the driver's `SendPacket` dispatch); the
counters do not. Checked upstream at `cff4d03f`: `Link.__receive` counts
after its own guards (not CLOSED, not the initiator's `0xff` keepalive
echo, receiving interface equal to `attached_interface`), so a packet
that then fails to decrypt still counts. Transport calls `link.receive`
for link DATA of a link in `active_links_map` (a responder's from
`register_link`, an initiator's from `activate_link`) on its attached
interface, except CACHE_REQUEST, which it answers itself; and for
RESOURCE_PRF proofs, whose interface `Link.__receive` checks. LRPROOF
goes to `validate_proof` and other proofs to the receipts: not counted.
`Packet.send` counts `len(self.raw)` before `Transport.outbound`, for
every packet whose destination is a link not CLOSED: LRPROOF, LRRTT,
keepalives, packet and resource proofs, LINKIDENTIFY, requests,
responses, LINKCLOSE (sent before the status changes), channel
envelopes, resource advertisements, requests, HMUs, parts and cancels,
cache requests sent over a link and their answers; not LINKREQUEST
(its destination is the destination). Not counted either:
`Packet.resend()`, which a channel envelope's timeout resend
(`LinkChannelOutlet.resend`) and a resource part requested again
(`part.resend()`) use. The review did not list the resends.

**Local handling and evidence:** `f63b3dac`. The link manager counts
both sides. Received: `handle_local_delivery_into` adds `raw.len()` when
`link_receives` holds (link not closed and not a pending initiator link;
link DATA but CACHE_REQUEST, or a RESOURCE_PRF proof; on the attached
interface, which in rns-rs is `link_route_accepts`, the check the driver
already applies to link DATA). The initiator's keepalive echo returns
before it, as before. Sent: the driver calls `count_sent_link_packet` for
every `SendPacket` the link manager hands it, on the packet as packed,
before route hints add a transport header or an oversized packet is
dropped; destination type LINK only, so LINKREQUEST (SINGLE) is
excluded. Resends are taken off: rns-core's `ChannelAction::SendOnLink`
gains `resend` (true for a timeout resend, for the rns-rs-only
held-exhaustion resend of a direct path and, since the rebase onto
`dev@51ccbcc5`, for `dev`'s resend of what was outstanding when a direct
path falls back), and
`ResourceSender::handle_request_parts_into` reports with each part
whether it was sent before; the link manager records those packets'
bytes and `local_link_traffic` subtracts them. `Driver::link_traffic`
adds the link manager's totals to the engine's relayed ones (commit 29)
for `lrxb`/`ltxb` and for the speed sampler (`lrxs`/`ltxs`). The per-link
`rx`/`tx` statistics are unchanged (they still count resends and every
packet type; upstream's `Link.tx` does not count resends, a pre-existing
difference left as it was). rns-rs's Direct Link signalling packets are
link packets and count as sent. `docs/rnstatus.md` describes what the
Links totals include.

Tests: `local_link_traffic_counts_raw_bytes_as_upstream` (two link
managers with the driver's dispatch counting simulated: link request
uncounted on both sides, LRPROOF counted as sent and not as received,
LRRTT, data both ways, keepalive probe and answer counted but the
initiator's echo not, a cache request and a packet proof not counted, a
resource proof counted only on the link's interface, a channel envelope
and resource parts counted when first sent and not when resent, LINKCLOSE
counted, a closed link taking nothing; it fails if every delivered packet
counts, and if resends are not subtracted, both checked by mutation),
`own_link_traffic_joins_the_link_totals` (driver: a dispatched packet and
a packet received on the link's interface reach `interface_stats` and
the speeds; one on another interface does not),
`requested_parts_say_whether_they_were_sent_before` (rns-core), and the
channel tests `test_send_receive`/`test_tick_retransmits_timed_out_packets`
now check the flag. Tests run: `cargo test -p rns-core` passed (lib 1174
and its other targets), `cargo test -p rns-net` passed (lib 1609,
`e2e.rs` 74 with 1 ignored, `e2e_direct_connect.rs` 19,
`python_interop.rs` 6 with 1 ignored), `cargo fmt --check` passed;
`bash scripts/lint-host.sh` first failed on an unused `mut` in the new
driver test, which was removed, then passed, and that test passed again
alone. Not compared live with Python.

**Final disposition:** Integrated.

### 33. `52898683` — Raised listener backlogs

**Upstream change:** The Backbone listener backlog goes from 1 to 16 and the
shared-instance RPC listener from 1 to 128.

**Rust applicability:** Upstream's `BackboneInterface.add_listener` is
also how its shared instance listens where it has epoll (Linux:
`LocalInterface` on the abstract Unix socket or 127.0.0.1 TCP), so the
16 applies there too. Verified against the pinned toolchain (Rust
1.96.0, `rust-toolchain.toml`) and the std source it ships: `TcpListener`
listens with 128 (`library/std/src/sys/net/connection/socket/mod.rs`),
and `UnixListener::bind`/`bind_addr` on Linux with -1
(`library/std/src/os/unix/net/listener.rs`), which the kernel caps at
`net.core.somaxconn` (4096 by default since Linux 5.4, 128 before; 4096
on the audit host). Every listener rns-rs creates binds through std
without setting a backlog: Backbone (`interface/backbone/server.rs`),
TCP server (`interface/tcp_server.rs`; upstream's `TCPServerInterface`
is unchanged), the shared instance (`interface/local.rs`, abstract and
TCP), the threaded RPC server (`rpc/server.rs`, TCP and abstract) and
the driver's folded RPC service (`node/startup/services.rs`), and the
non-upstream listeners (`rns-ctl` HTTP 128, the provider bridge and
`rns-tun` Unix sockets). None is below upstream's new values.

**Local handling and evidence:** `63f7689d`. Comments citing upstream
and the std values at the Backbone, shared-instance and RPC binds, and
`abstract_rpc_listener_queues_upstreams_backlog` (128 connections to the
RPC abstract socket queue with nobody accepting). Tests run: `cargo test
-p rns-net` passed (lib 1610, `e2e.rs` 74 with 1 ignored,
`e2e_direct_connect.rs` 19, `python_interop.rs` 6 with 1 ignored),
`cargo fmt --check` and `bash scripts/lint-host.sh` passed.

**Final disposition:** Structurally covered.

### 34. `cff4d03f` — Updated changelog

**Upstream change:** The RNS 1.6.1 changelog section.

**Rust applicability:** Changelogs are not vendored. Every bullet is checked
against its source commit above, not taken as evidence.

**Local handling and evidence:** `4e5b04ce`: the analysis below, and
`UPSTREAM.md` no longer says upstream has no `1.6.1` tag. Documentation
only; no build or test was run for it.

**Tag target.** The commit adds the `### RNS 1.6.1` section and moves the
unchanged "Verified Retrieval" and "Release Signatures" text from 1.6.0 to
it; nothing else changes and `RNS/_version.py` stays `1.6.1`. The signed
`1.6.1` tag object `bde4cd79` points at this commit (`cff4d03f`) and its
message is the section's text, so the changelog identifies the tag
target as the tip of this range.

**Changelog cross-check.** The section covers `1.6.0` (tag at `cb126089`)
to `cff4d03f`, which rns-rs audited in six records: `1.6.0-rgit-2`
(`5d38ce30..c5d205ff`, from `cb126089` on), `1.6.0-rgit-3`
(`..16621a78`), `1.6.0-rgit-4` (`..134dc677`), `1.6.0-rgit-5`
(`..c850cdac`), `1.6.1` (`..884f109b`) and this one. Each bullet, with
the commits it describes:

| Bullet | Source | Range |
|---|---|---|
| Enabled network stamp generation by default | `51fa8413` | 1.6.1 |
| Filter destination types by hash | `e96c81c3` (filtering by name, `825c2e19`, is in 1.6.0) | 1.6.1 |
| Hop limiter options globally and per-interface | `bb63dd44` (per interface; the `[filter]` option, `01aef5bc`, is in 1.6.0) | 1.6.1 |
| Super fast announce ingress pre-filtering | `096e6726` | 1.6.1 |
| Filtered traffic stats in `rnstatus` | `134dc677` | rgit-4 |
| Link traffic stats in `rnstatus` | 29 `ef3e8086`, 30 `e8b3b14b`; 32 `01ffb98e` counts local links | this range |
| Remote transport IDs per client interface in `rnstatus` | `464e7598`; 10 `f876ed8d` | rgit-5; this range |
| Inspect filtered traffic, announces per interface | `134dc677`, `819076c3` | rgit-4, rgit-5 |
| Inspect tunnel properties, stamp costs, remote implementation info | `3281e283`, `464e7598`, `b7a93b9b`; 10 `f876ed8d` | rgit-5, 1.6.1; this range |
| `client_limit` on `BackboneInterface`, default 500 | `3c4b271f` | rgit-4 |
| Max stamp workers and worker niceness | `16621a78` | rgit-3 |
| `blocked_ips` file | `5f2dbc16` | rgit-4 |
| Directly blackhole remote transport nodes | `350b7e26` | rgit-5 |
| Stamp values and costs for `rngit` | 12 `05ac4bba` | this range |
| Held announce queue cleaning | `85d36979` | 1.6.1 |
| Bidirectional tunnel synthesis with stamp cost and version signalling | `b7a93b9b`, `f361a354`, `ad6c709e`; 4 `2b1a984c`, 5 `25cce0a8` | 1.6.1; this range |
| Announce rate table persistence | `d5f1e014` | rgit-5 |
| Default caps for auto-connect interface counts | 2 `aecc1547` | this range |
| Path state info in path table getters | 27 `41260ea1` | this range |
| Inbound announce filtering and deduplication | `096e6726`, `85d36979`, `a450be5d`; 1 `da368e05` | 1.6.1; this range |
| Filtering subsystem reworked for many interfaces | no single commit: `20e25a9f`, `134dc677`, `819076c3`, `e96c81c3` and this range's 21, 22 | rgit-4 to this range |
| Improved `rnpath` display and filtering | 20 `9568b704` (and 21, 24-28, 31 around it) | this range |
| Improved traffic counting | `01e7ed84`, `d1837919`, `c850cdac`, `29dc449a`; 29, 32 | rgit-5, 1.6.1; this range |
| Improved path responsiveness tracking | 13-17 | this range |
| Improved protocol violation tracking and logging | `715707b1` | 1.6.1 |
| Improved path pool and tunnel table culling | `023849ed` | rgit-4 |
| Tuned announce validation caches | `a450be5d` | 1.6.1 |
| Fixed 1.6.0 regression: culling removing own local destination paths | 13 `833f6cf2` | this range |
| Fixed DPEC state not resetting on Backbone client reconnect | `0bc5c37c` | rgit-4 |
| Fixed potential logging deadlock | `9ef6c90e` | rgit-4 |
| Fixed exit handler deadlock on a signal mid RPC call | `29ce7ca5` | 1.6.1 |
| Fixed missing wanted destination type for interface discovery | `884f109b` | 1.6.1 |
| Fixed split-instance known-destinations load on Android | 9 `48c77061` | this range |
| CPython process fork stdin deadlock mitigation | 11 `0123133e` | this range |

Nothing in the section describes commits 3, 6, 7, 8, 18, 19, 23 or 33,
and only the counting side of 32 ("Improved traffic counting"). Every
bullet that comes from this range matches the commit it names. One names
only the case its commit was made for: commit 9's RPC load is not
Android-specific, it runs for any split-mode client that finds no known
destinations file. The section is release communication,
not evidence: the evidence for each commit is its own row.

**Final disposition:** Non-runtime.

## Decisions (2026-11-20)

Reviewed with the maintainer. The rule is to do what upstream does,
utilities included.

1. **Commit 9:** `known_destinations` answers with upstream's dict exactly;
   the native list moves to a separate RPC name. Implemented in `28b241ae`;
   the native list is `known_destination_entries`.
2. **Commits 22 and 26:** `link_distribution` follows upstream's shape at each
   commit (a set at 22, the de-duplicated list at 26); the native `total` key
   goes. Commit 22 implemented in `7f26a06d`: the shape, and for a
   non-empty link table upstream's unencodable set (error logged, no
   answer), see commit 22. Commit 26 implemented in `af10606b`: the
   list, in upstream's order (the link table keeps insertion order), see
   commit 26.
3. **Commit 24:** the analysis statistics are ported as they are at that
   commit, then 28's guard, then 31's `Not yet implemented`. This brings in
   commit 21's destination-type files as well. Commit 24 implemented in
   `8b9b4fbf`, see commit 24. Commit 28 mapped in `3ff7bfdb`: its guard
   never fires upstream (`Packet.unpack` does not raise), so the analysis
   is unchanged, see commit 28.
   Commit 31 mapped in `755d9784`: `-A` prints `Not yet implemented` after
   the three RPC calls, and the analysis and the type names query it
   alone used are removed, see commit 31.
4. **Commit 2:** upstream's order dependence is reproduced: the disable key
   only takes effect when it appears before the count. The parser records key
   order for this.
5. **Commit 12:** default link cost 18.0, and an invalid `link_cost` or
   `stamp_value` is a startup error, as upstream. Implemented in
   `bbd0e4c6`, see commit 12.
6. **Commit 19:** the `lossless_medium` flag is added with upstream's
   per-class values, unread, marked `#[allow(dead_code)]` with the reason.
7. **AES-128 (found via commit 8, pre-existing):** match upstream. Only
   AES-256-CBC is enabled; a responder refuses any other signalled mode.
   Separate commit without an `Upstream-Commit` trailer. Implemented in
   `ba44bc2c` (`link: only AES-256-CBC is enabled, as upstream`) and
   completed in `c0086c86` (`link: refuse a reserved link mode as upstream
   does`: a reserved mode is refused as upstream's `handshake()` refuses
   it, and Transport drops a request in a mode that is not enabled when it
   must lower its MTU), see commit 8.
8. **New-next-hop recovery of an unresponsive path (found via commit 17,
   pre-existing):** rns-rs keeps its behaviour by default, the divergence is
   documented, and a runtime `[reticulum]` option selects upstream's
   behaviour. Separate commit without an `Upstream-Commit` trailer.
   Implemented in `53f34b11` (`transport: an option to recover
   unresponsive paths as upstream does`): `unresponsive_path_recovery =
   native` (default, unchanged) or `upstream`, any other value a config
   error. Under `upstream`, an announce for an unresponsive path is
   decided as Transport.py at `cff4d03f` decides it
   (`upstream_unresponsive_path_decision`, after the higher-gravity case),
   and an accepted one replaces the primary path whatever its next hop,
   keeping the replaced path's random blobs; the lenient case is a table
   insertion only, and the rns-rs-only acceptance over the same or fewer
   hops does not happen. The emission-time plausibility filter applies in
   both modes. With `max_paths_per_destination` above 1 a destination is
   only unresponsive with a single path (marking promotes an alternative),
   which `upstream` replaces rather than keeping beside the new one;
   `prefer_shorter_path` still takes a strictly shorter announce for an
   unresponsive path in either mode, so with it set `upstream` differs from
   upstream for those announces. Documented in `docs/interoperability.md`
   ("Unresponsive path recovery") and `docs/configuration.md`. Tests:
   `unresponsive_path_recovery_native_and_upstream`,
   `upstream_unresponsive_decision_scans_blobs_as_upstream`,
   `parses_unresponsive_path_recovery`; `cargo test -p rns-core` (1251),
   `-p rns-net` (1698, 4 ignored) and `-p rns-bench` (17, 1 ignored)
   passed, as did `cargo fmt --check` and `bash scripts/lint-host.sh`.
   `rns-esp32/src/main.rs` gained the field in its `TransportConfig`
   literal but is outside the workspace and was not built.

   Follow-up (`transport: decide every path update as upstream in upstream
   mode`): `upstream` covered only unresponsive paths, so a newer announce
   through another neighbour over more hops was still dropped with one
   path per destination, where upstream takes it. `upstream` now decides
   every path update as Transport.py's `inbound` at `cff4d03f`
   (`upstream_path_decision`: the same-or-fewer-hops case with the
   higher-gravity replacement, the expired-path, newer-emission and
   unresponsive cases over more hops, and the random blob checks) against
   the primary path, which an accepted announce replaces whatever its next
   hop; announces add no alternative paths in this mode, so
   `max_paths_per_destination` above 1 no longer disables the announce
   prefilter there. `prefer_shorter_path` still takes a strictly shorter
   announce by rns-rs's rules. Test:
   `upstream_recovery_decides_every_path_update_as_upstream` (fails before
   the change).

   Follow-up (`transport: trust future emission times in upstream mode`):
   upstream has no emission-time plausibility filter, so under `upstream`
   rns-rs no longer applies `MAX_EMISSION_TIME_SKEW_SECS`: path decisions,
   the higher-gravity replacement, the announce prefilter and tunnel path
   restoration compare raw emission times, as Transport.py does. `native`
   keeps the filter. Tests: `future_emission_time_filter_only_in_native_mode`,
   `tunnel_reattach_emission_time_filter_only_in_native_mode` (both fail
   before the change), and the `upstream` cases of
   `announce_prefilter_keeps_only_announces_that_could_update_the_path`.

## Integration Plan

All 34 commits are mapped, one mapping commit each in ancestry order, with
the follow-ups of decisions 7 and 8 and the filter logging commit
`630f71bb` beside them. Final dispositions: 21 Integrated, 9 Structurally
covered, 4 Non-runtime. The branch was rebased onto `dev@51ccbcc5` and the
promotion gates were run on it; see the acceptance record.

## Promotion Gates

- [x] Every upstream commit has a final disposition.
- [x] Focused regressions pass for every applicable behavior change.
- [x] Fixture provenance and byte stability are checked where applicable.
- [x] Exact-target live Python/Rust interop passes.
- [x] Workspace tests, feature suites, formatting, and lint pass.
- [x] Required build, Docker, hardware, and manual gates are recorded honestly.
- [x] Native documentation is updated for user-visible behavior.
- [x] A final parity record is created from `PARITY-TEMPLATE.md`.

## Acceptance Record

Gates were run on 2026-11-20 on `upstream/1.6.1-rgit` rebased onto
`dev@51ccbcc5`: the audit opening, the decisions, the 34 mapping commits,
the five separate commits (decisions 7 and 8, `f5748851`, `630f71bb`) and
the batch records, at `026de536`, then `c3401435`. x86_64 host, 32 cores.

**Rebase.** `dev` was 46 commits ahead of the branch's base. The branch's
first two commits (`rns-crypto: document the ESP-IDF RNG unsafe block`,
`rns-crypto: fold duplicate Token variants into their buffer forms`) were
already on `dev` with the same patch and were dropped. Four commits
conflicted, each resolved keeping both sides:

- `f779ae93` (commit 1) and `9f503ac2` (commit 19): `dev` split
  `rns-net/src/interface/mod.rs` into topic submodules (`4eac9184`).
  Commit 1's `shared_medium: false` moved to the two test `InterfaceInfo`
  literals now in `interface/entry.rs` and `interface/factory.rs`; commit
  19's `lossless_medium()` and its test moved to `interface/type_hints.rs`
  beside `shared_medium_hint` and `tunnels_allowed`, with the reason inside
  the `allow(dead_code)` attribute as `dev` now writes lint allows. Its
  commit message names the new place.
- `28b241ae` (commit 9): `dev` dropped the unused `hash_width` argument of
  `KnownDestinationsStore::open_read_only`, where the commit replaced the
  free `load_instance_known_destinations` with the RPC-capable method; the
  method keeps the commit's behaviour with the one-argument call.
- `af10606b` (commit 26): `dev` removed `allow(dead_code)` from
  `link_table_ref`, the commit changed its return type to `LinkTable`;
  both kept.
- `f63b3dac` (commit 32): `dev` factored the held-exhaustion resend into
  `Channel::push_resends`, shared with its new `resend_outstanding` (a
  Direct Link falling back resends what is outstanding, `b211d87e`). The
  commit's `resend: true` went into `push_resends`, so `dev`'s fallback
  resend is not counted as link traffic again either, and `dev`'s test of
  it checks the flag. The commit message says so.

Commit messages that named other branch commits by hash were rewritten to
the rebased hashes (messages only, trees unchanged), as was every local
hash in this audit. `git log --format='%(trailers:key=Upstream-Commit,valueonly)'
dev..HEAD` lists the 34 upstream hashes in ancestry order, one trailer per
mapping commit as its last line, with the mapping commit's subject equal
to `upstream: ` plus the upstream subject; no other commit on the branch
or on `dev` carries a trailer for them.

**Fix found by the gates.** `bash scripts/lint-host.sh` failed on
`026de536`: `dev` now denies `expect` in production code (`7db2ad7f`), and
`ba44bc2c` (decision 7) expects the initiator constructors to accept
AES-256-CBC in `LinkManager::create_link_with_keys`. `c3401435` (`link:
name the invariant behind the initiator's mode expect`, no trailer) adds
the scoped allow with its reason; their only error is a mode that is not
enabled. Attribute only: the test suites below compiled `026de536` for the
workspace run and `c3401435` from the hooks run on, and fmt and lint were
rerun on `c3401435`.

| Gate | Command | Result |
|---|---|---|
| Formatting | `cargo fmt --check` | Clean (on `026de536` and `c3401435`) |
| Lint | `bash scripts/lint-host.sh` | Failed on `026de536` (above); clean on `c3401435` |
| Feature checks | `cargo check -p rns-cli -p rns-ctl --bins --no-default-features`, again with `--features iface-tcp,rns-hooks-native`; `cargo check -p rns-crypto -p rns-core --no-default-features` | Clean |
| Workspace | `cargo test --workspace --no-fail-fast` | 3,846 passed, 0 failed, 76 ignored |
| Hooks feature suite | `./rns-hooks/build-examples.sh`; `cargo test --workspace --features rns-hooks --no-fail-fast` | 3,913 passed, 0 failed, 76 ignored |
| Hook backends and built-in hooks | `cargo test -p rns-hooks --features wasm,native`; `cargo test -p rns-net --test e2e_hooks` with `rns-hooks-wasm,rns-hooks-builtin`, plus `compact-threads`, plus `engine-parallel`; `cargo test -p rns-ctl --features rns-hooks-builtin test_hook_api_loads_reloads_lists_and_unloads_builtin_hook` | 85 passed, 1 ignored; `e2e_hooks` and the rns-ctl test 76 passed in all, 0 failed |
| rns-ctl TLS | `cargo test -p rns-ctl --features tls` | 139 passed, 0 failed |
| Compact engine | `cargo test -p rns-net`; `cargo test -p rns-net --features compact-threads`; `cargo test -p rns-net --lib --features iface-rnode-ble rnode` | 3,496 passed in all, 0 failed, 8 ignored |
| rns-esp32 host lane | `cargo metadata --locked`, both host `cargo clippy --locked` commands of CI, `cargo test --locked --manifest-path rns-esp32/Cargo.toml` | Clean; 68 passed. This lane builds the host library only, not `src/driver.rs` and `src/main.rs`, the two files the branch edits (commit 1's `shared_medium`, decision 8's `TransportConfig` field). The firmware build needs the ESP toolchain and was not run. |
| Python tools | `python3 -m compileall -q scripts tests`; `python3 -m unittest discover -s tests -p 'test_*.py'` | 47 passed |
| ARMv7 build smoke | CI's five `cargo build --release --target armv7-unknown-linux-gnueabihf` commands (`rnsd` and `rns-ctl` without and with `rns-hooks-native`, `rns-server` with `rns-hooks-builtin`), linker `arm-linux-gnueabihf-gcc` | All built, on `c3401435` |

The known flaky `direct_path_carries_more_than_a_base_mtu_link_and_falls_back_to_it`
passed in every run above.

**Exact-target interop.** A disposable worktree of
`/home/lelloman/Reticulum` at `cff4d03fdbd6bfb63b765280cd944756ac5cce8d`
(`HEAD:RNS` `bcab6ab7ff72c4315aceda97267ea9af4fcccbc4`, the pinned `RNS`
tree), with `PYTHONPATH` and `RETICULUM_UPSTREAM_DIR` set to it.
In the same run, `import RNS` loaded `RNS/__init__.py` from that worktree
and reported `1.6.1`, and `git rev-parse HEAD HEAD:RNS` there gave those
two hashes. The commands are CI's interop job:

| Command | Result |
|---|---|
| `cargo test -p rns-net --test python_interop -- --nocapture` | 6 passed, 1 ignored (`python_rns_idle_links_stay_open`, over a minute idle, ignored as in CI) |
| the same with `--features compact-threads` and with `--features engine-parallel` | 6 passed, 1 ignored, each |
| `cargo test -p rns-cli --test utility_interop -- --ignored --nocapture` | 34 passed, 0 failed, among them `python_split_mode_client_loads_rust_known_destinations_over_rpc`, `python_rnpath_lists_rust_path_table` and `python_rnpath_reads_rust_remote_path_table` |
| `cargo test -p rns-cli --test placeholders -- --ignored --nocapture` | 1 passed |
| `cargo test -p rns-rnodeconf --test rnodeconf -- --ignored --nocapture` | 32 passed |
| `cargo test -p rns-git --lib -- --nocapture` | 223 passed, 2 ignored (need a WebP backend); with `RETICULUM_UPSTREAM_DIR` set the Python-peer test cannot skip, and passed |

**Fixtures.** The fixtures this range regenerated are the `rnstatus`
fixtures (commits 10, 29, 30) and the argparse table, `rnpath.pickle` and
`cli_golden/rnpath.txt` (commits 20, 24, 25, 26).
`tests/generate_rnstatus_fixtures.py` names `rgit e8b3b14b`, the commit it
last ran at (30). `tests/generate_argparse_fixtures.py` pins only
`RNS.__version__ == "1.6.1"` (it has never named a commit) and last ran at
`1f7cd145` (26). In a scratch copy of the tree, with `PYTHONPATH` at the
`cff4d03f` worktree, both were rerun, and so were the default config,
example config and discovery record generators (all asserting 1.6.1):
after `rustfmt` on the generated `upstream_parsers.rs`, nothing differs
from the committed tree. `cli_golden/rnpath.txt` is rns-rs's own output,
checked by `cli_golden` in the workspace run. The rnid generator asserts
1.6.0 and the announce rate table generator its own reference commit;
neither is touched by this range and neither was rerun.

**Native documentation.** The user-visible changes are documented:
the autoconnect caps and their key order (`docs/configuration.md`,
`docs/interface-discovery.md`, which also takes commit 3's sizing advice),
the split-mode `known_destinations` RPC (`docs/getting-started.md`), the
reserved and AES-128 link modes (`docs/protocol-spec.md`), the remote
transport lines and link traffic totals (`docs/rnstatus.md`), the rnpath
options and the ` (R)`/` (u)`/` (?)` path state marker (`docs/cli-tools.md`),
rngit's `link_cost` and `stamp_value` (`docs/rns-git.md`), the
destination type files and filter logging (`docs/configuration.md`), and
`unresponsive_path_recovery` with the emission time filter
(`docs/configuration.md`, `docs/interoperability.md`).

**Drift.** `python3 scripts/check_upstream_drift.py --no-fetch
--upstream-dir <the cff4d03f worktree> --baseline cff4d03f…` reports
`current`: rgit and GitHub tips both `cff4d03f`, 0 commits ahead, from
refs cached by the 2026-11-20 05:56 UTC fetch (not refetched here). The
`1.6.1` tag object `bde4cd79` points at `cff4d03f`; its SSH signature was
not verified (no allowed signers file is configured).

**Not run.** Docker E2E, the dual-VPS Backbone smoke, the ESP32 firmware
build and physical hardware validation. Docker E2E and the CI interop
matrix, which this promotion moves to `cff4d03f`, are left to the
promotion pull request's CI; hardware validation is not claimed.

The final record is [reticulum-1.6.1-rgit-parity.md](reticulum-1.6.1-rgit-parity.md).
