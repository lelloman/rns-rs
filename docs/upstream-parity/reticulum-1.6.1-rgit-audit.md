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
- local branch and revision inspected: branch `upstream/1.6.1-rgit` from `dev@b1f26c80`

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
A `Proposed:` status is the outcome of the 2026-11-20 diff review. It
becomes a final disposition only when the commit's mapping commit and
evidence exist; until then nothing here is claimed as passed.

| # | Upstream commit | Date | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|---|
| 1 | `da368e05` | 2026-11-16 | Deduplicate in-flight announce rebroadcasts | Integrated | `41b2817b`; `an_announce_heard_again_while_waiting_is_not_rebroadcast_to_that_interface`, `an_announce_heard_again_on_a_shared_medium_is_still_rebroadcast_there`, `a_newer_announce_replacing_the_waiting_one_starts_without_blocked_interfaces` |
| 2 | `aecc1547` | 2026-11-16 | Set sane autoconnect caps | Integrated | `2d8dd594`; `autoconnect_count_is_capped_unless_caps_are_disabled`, `autoconnect_caps_are_disabled_only_by_a_key_before_the_count` |
| 3 | `338df096` | 2026-11-16 | Updated docs | Non-runtime | `35cd3471`; `docs/interface-discovery.md` sizing guidance |
| 4 | `2b1a984c` | 2026-11-17 | Fixed IFAC identity not being available at early tunnel synthesis | Structurally covered | `d8761e59`; `tunnel_synthesis_carries_the_interface_access_code` |
| 5 | `25cce0a8` | 2026-11-17 | Ensure transport identity availability before early tunnel synthesis | Structurally covered | `a097a14e`; `a_dialing_tcp_client_first_sends_a_synthesis_signed_by_the_transport_identity` |
| 6 | `cc5d6dd0` | 2026-11-17 | Logging | Structurally covered | `fa13858a`; invariant comment in `rns-cli/src/rnsh/initiator.rs` |
| 7 | `12b2b8c0` | 2026-11-17 | Updated link tests | Non-runtime | `39b2b2dd`; doc comment on `wait_for_link_established` (`rns-net/tests/e2e.rs`) |
| 8 | `4916017a` | 2026-11-17 | Abort early on non-enabled link mode | Structurally covered | `2309725b`; `every_outbound_link_request_signals_aes_256_cbc`; follow-ups `59af6496` and `26b4e735` (decision 7) |
| 9 | `48c77061` | 2026-11-17 | Load known destinations over RPC in split mode | Integrated | `55dc3aa5`; `known_destinations_rpc_answers_upstreams_dict`, `known_destination_entries_rpc_keeps_the_native_list`, `a_split_mode_client_loads_known_destinations_over_rpc`, `python_split_mode_client_loads_rust_known_destinations_over_rpc` |
| 10 | `f876ed8d` | 2026-11-17 | Show remote transport status on tunnels | Integrated | `23b51e35`; `rnstatus_view_matches_upstream` (fixtures regenerated at `f876ed8d`, new case `tunnels_remote_transport`) |
| 11 | `0123133e` | 2026-11-17 | Fixed CPython process fork stdin close deadlock | Structurally covered | `3312039e`; module comment in `rns-net/src/stamps.rs` |
| 12 | `05ac4bba` | 2026-11-17 | Added ability to configure destination value and link cost to rngit | Integrated | `3bbe4252`; `destination_costs_default_to_upstreams`, `parses_and_quantizes_destination_costs`, `invalid_destination_costs_are_errors`, `rngit_destinations_carry_their_link_cost_and_stamp_value`, `rngit_invalid_page_cost_fails_the_page_destination` |
| 13 | `833f6cf2` | 2026-11-17 | Fixed path table culling being able to remove an instance's own local destination paths. Doh. | Integrated | `8a7ced49`; `a_local_clients_announce_marks_its_path_responsive`, `never_used_local_client_paths_stay_on_an_instance_serving_them` (replaced by 15's cull test) |
| 14 | `d72cfdd7` | 2026-11-17 | Mark local client paths responsive on PR responses | Structurally covered | `f84da699`; `a_local_clients_path_response_marks_its_path_responsive` |
| 15 | `5bd93ad9` | 2026-11-17 | Ensure link-based rediscovery does not occur for instance-local paths | Integrated | `00431be5`; `failed_own_link_to_an_instance_local_destination_is_not_rediscovered`, `local_client_link_to_an_instance_local_destination_is_not_rediscovered`, `instance_local_paths_go_only_with_their_interface_or_the_pool_cap` |
| 16 | `70eb417d` | 2026-11-17 | Fixed non path table resident shared local instance destination path response announces broadcasting on all interfaces instead of requestor only | Integrated | `edb988ac`; `only_a_local_clients_path_response_answers_a_pending_request` (updated), `a_local_clients_path_response_answers_only_the_requesting_interface`, `test_shared_instance_without_transport_relays_path_request_to_local_client` (updated) |
| 17 | `8c73e203` | 2026-11-18 | Don't rebroadcast on unresponsive path lenient table insertions | Integrated | `b789aa30`; `unresponsive_path_replacement_is_not_rebroadcast`; follow-up `dac604d7` (decision 8) |
| 18 | `4a058544` | 2026-11-18 | Well, yeah | Structurally covered | `f2e7fdcf`; doc comment on `persist_known_destinations` (`rns-net/src/node/known_destinations.rs`) |
| 19 | `8e7dc8b7` | 2026-11-18 | Added medium reliability flag to interfaces | Integrated | `cc15c501`; `lossless_medium_matches_upstreams_interface_classes` (decision 6) |
| 20 | `9568b704` | 2026-11-18 | Improved rnpath display and filtering options | Integrated | `d0fb8d79`; `path_table_display_options_and_filters_as_upstream`, `path_table_prints_as_upstream` (updated), `parses_upstream_invocations_as_argparse_does` (extended), argparse fixture and golden help regenerated at `9568b704`, live `python_rnpath_reads_rust_remote_path_table` and `python_rnpath_lists_rust_path_table` at `9568b704` |
| 21 | `c90a5d58` | 2026-11-18 | Added destination type loading | Integrated | `f72cbf56`; `known_destination_types_are_read_as_upstream`, `missing_unreadable_and_flagged_type_files_add_nothing`, `the_config_filter_names_come_first_and_the_file_overrides_them`, `splitlines_and_strip_follow_python`, `wanted_destination_types_are_named_in_the_type_map`, `unwant_all_reports_types_in_the_order_they_were_first_wanted`, `configured_destination_types_name_as_upstreams_type_map`, `path_and_rate_tables_follow_upstreams_keys_and_types` (extended), `path_table_prints_as_upstream` (JSON), live `python_rnpath_reads_rust_remote_path_table` at `c90a5d58` |
| 22 | `3f55e9eb` | 2026-11-18 | Added flagged destination type map, added per-link traffic counter, added link distribution stats getter | Integrated | `73ff693b`; `forwarded_link_traffic_counts_raw_bytes`, `link_distribution_counts_per_destination`, `link_distribution_names_receiving_interfaces_by_hash`, `link_distribution_rpc_fails_as_upstreams_set_does`, `type_names_come_from_the_map_then_the_flagged_map_then_the_hash` (decision 2) |
| 23 | `f7b54ccc` | 2026-11-18 | Added prettynamehash convenience function | Non-runtime | `ea62398b`; note in `rns-cli/src/pyfmt.rs` |
| 24 | `1a71073c` | 2026-11-18 | Initial rnpath analysis stub | Integrated | `959bb94f`; `analysis_counts_destination_types_as_upstream`, `parses_upstream_invocations_as_argparse_does` (extended), argparse fixture and golden help regenerated at `1a71073c` (decision 3) |
| 25 | `b9903c53` | 2026-11-18 | Analysis mode capture argument | Integrated | `aa5b6c13`; `parses_upstream_invocations_as_argparse_does` (`--capture`, ambiguous `--c`), argparse fixture and golden help regenerated at `b9903c53` |
| 26 | `1f7cd145` | 2026-11-18 | Cleanup and fixes | Integrated | `baa60b0a`; `link_distribution_follows_link_table_insertion_order`, `link_distribution_rpc_answer_keeps_upstreams_order`, `link_distribution_rpc_answers_with_from_ifs_lists`, argparse fixture and golden help regenerated at `1f7cd145` (decision 2) |
| 27 | `41260ea1` | 2026-11-18 | Added path state info to path table getters | Integrated | `3b7651b4`; `test_path_state`, `query_path_table`, `path_and_rate_tables_follow_upstreams_keys_and_types`, `path_table_prints_as_upstream`, `path_state_marker_as_upstream`, `python_rnpath_lists_rust_path_table`, `python_rnpath_reads_rust_remote_path_table` |
| 28 | `48ba76df` | 2026-11-18 | Catch announce unpack failure | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 29 | `ef3e8086` | 2026-11-18 | Added link traffic stats | Proposed: Needs coordinated port | Reviewed 2026-11-20; no mapping commit yet |
| 30 | `e8b3b14b` | 2026-11-18 | Classic | Proposed: Needs coordinated port | Reviewed 2026-11-20; no mapping commit yet |
| 31 | `eb00622f` | 2026-11-18 | Cleanup | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 32 | `01ffb98e` | 2026-11-18 | Local link traffic counting | Proposed: Needs coordinated port | Reviewed 2026-11-20; no mapping commit yet |
| 33 | `52898683` | 2026-11-18 | Raised listener backlogs | Proposed: Structurally covered | Reviewed 2026-11-20; no mapping commit yet |
| 34 | `cff4d03f` | 2026-11-18 | Updated changelog | Proposed: Non-runtime | Reviewed 2026-11-20; no mapping commit yet |

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

**Local handling and evidence:** `41b2817b`. As planned: `InterfaceInfo`
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

**Local handling and evidence:** `2d8dd594`. Per decision 4 the planned
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

**Local handling and evidence:** `35cd3471`. `docs/interface-discovery.md`
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

**Local handling and evidence:** `d8761e59`. Verified as reviewed: the
synthesis is a `SendOnInterface` masked with the entry's IFAC, and static,
managed and pool interfaces get their IFAC at registration. A dialing I2P
peer is registered offline (`reconnecting`) with its inherited IFAC and
brought up later, so its synthesis is masked too. Caveat: in
`handle_dynamic_interface_up_event` a registration that is not
`reconnecting` comes up (and would synthesize) before `entry.ifac` is set;
no current interface type takes that path with `wants_tunnel`, so this is
latent, not a live difference, and was left unchanged.

Related hardening (not part of this mapping, disposition unchanged):
`46cdb689` (`driver: a dynamic interface has its IFAC before it comes up`,
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

**Local handling and evidence:** `a097a14e`. The invariant comment sits
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

**Local handling and evidence:** `fa13858a`. Verified as reviewed: the rnsh
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

**Local handling and evidence:** `39b2b2dd`. The doc comment on
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

**Local handling and evidence:** `2309725b`. A comment at the mode in
`LinkManager::create_link_with_keys` records upstream's `ENABLED_MODES`, and
`every_outbound_link_request_signals_aes_256_cbc` pins that every outbound
request (generated keys, pre-stamped keys, and without MTU signalling, where
no mode is carried and AES-256-CBC is the default) signals AES-256-CBC and
the engine's mode matches. A pinning test of covered behaviour.

The pre-existing AES-128 divergence was resolved per decision 7 in the
separate commit `59af6496` (`link: only AES-256-CBC is enabled, as
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
Unsupported link mode"); that is resolved by `26b4e735`, below.
`docs/protocol-spec.md` 11.1 and 16 now say
only AES-256-CBC is enabled. `test_aes128_mode_handshake` became
`an_aes_128_link_is_refused_by_initiator_and_responder`, and rns-net gained
`an_aes_128_link_request_is_dropped_without_a_proof`, which failed with the
responder check removed and passes with it. The AES-128 wire codec, key
derivation and crypto vectors stay, as upstream keeps the mode defined.

Tests run, `2309725b`: `cargo test -p rns-net --lib --
every_outbound_link_request_signals_aes_256_cbc`, 1 passed; `cargo test -p
rns-net` passed (lib 1585, `e2e.rs` 74 with 1 ignored,
`e2e_direct_connect.rs` 19, no failures); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed. `59af6496`: `cargo test -p rns-core -p
rns-net` passed (rns-core lib 1155 and its integration suites, rns-net lib
1586, `e2e.rs` 74 with 1 ignored, `e2e_direct_connect.rs` 19,
`python_interop.rs` 6 with 1 ignored, no failures); `cargo fmt --check` and
`bash scripts/lint-host.sh` passed.

Decision 7 was completed by a second separate commit, `26b4e735` (`link:
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
`59af6496` missed, for any mode outside `ENABLED_MODES` (AES-128-CBC
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

**Local handling and evidence:** `55dc3aa5`, per decision 1. The inferred
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

**Local handling and evidence:** `23b51e35`. `render_tunnel` prints the
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

**Local handling and evidence:** `3312039e`. Verified: stamp searches run on
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

**Local handling and evidence:** `3bbe4252`, per decision 5.
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

**Local handling and evidence:** `8a7ced49`. `process_verified_announce`
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

**Local handling and evidence:** `f84da699`. Traced in upstream at
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

**Local handling and evidence:** `00431be5`.
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

**Local handling and evidence:** `edb988ac`. The announce table entry
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

**Local handling and evidence:** `b789aa30`. `should_update_path`
returns the new `PathDecision::AddForUnresponsive` for every case it
accepts only because the path is unresponsive, and the multi-path decision
maps it to `MultiPathDecision::RecoverUnresponsive`: stored as
`ReplacePrimary`, but the announce table entry is not inserted. As
upstream's flag, it does not affect a local client's path response
answering a pending request. rns-rs's extra acceptances (over the same or
fewer hops, and for an expired path over more hops, where upstream takes
only an announce it has not heard) are made insertion-only too, by the
default behaviour. The new-next-hop difference is decision 8, implemented
in `dac604d7` (`transport: an option to recover unresponsive paths as
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

**Local handling and evidence:** `f2e7fdcf`. Verified: the known
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

**Local handling and evidence:** `cc15c501`. `interface::lossless_medium()`
in `rns-net/src/interface/mod.rs`, next to `shared_medium_hint` and
`tunnels_allowed` and keyed by the interface type like them, is true for
`TCPClientInterface`, `TCPServerInterface`, `TCPServerClientInterface` (a
TCP server's spawned clients, `TCPClientInterface` upstream),
`BackboneInterface`, `BackboneClientInterface`, `BackboneInterfacePeer` (a
Backbone server's spawned peers, `BackboneClientInterface` upstream),
`I2PInterface` and `I2PInterfacePeer`, and false for every other class. As
decision 6, nothing reads it; it is `pub(crate)` with `#[allow(dead_code)]`
and a comment giving the reason (upstream adds it with no reader, kept for
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

**Local handling and evidence:** `d0fb8d79`. `rnpath` (and `rns-ctl path`,
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

**Local handling and evidence:** `f72cbf56`. Both parts are ported (a is
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

Follow-up `4e2459a9` (`filter: log destination type filtering as upstream
does`, no `Upstream-Commit` trailer) adds the first two as at `884f109b`.
The parser records the `[filter]` key order (`FilterSection::key_order`, as
`2d8dd594` does for `[reticulum]`), and
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

**Local handling and evidence:** `73ff693b`, per decision 2. The review's
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

**Local handling and evidence:** `ea62398b`: a note in
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

**Local handling and evidence:** `959bb94f`, per decision 3 (the
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

**Local handling and evidence:** `aa5b6c13`. `rnpath` takes `--capture`
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

**Local handling and evidence:** `baa60b0a`, per decision 2.

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
`answer_request` is back to its pre-`73ff693b` form).

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

**Local handling and evidence:** `3b7651b4`. `TransportEngine::path_state`
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
withdraws.

**Rust applicability:** None under the recommended handling of commit 24.

**Local handling:** Analysis, plus a comment at the native `-A` branch.

**Proposed disposition:** Needs port (decision 3).

### 29. `ef3e8086` — Added link traffic stats

**Upstream change:** Global `link_rxb` / `link_txb` counters for link-table
transport (excluding local clients), rates in the traffic loop, four new
interface-stats RPC keys, and a `Links` section in `rnstatus -t -l`.

**Rust applicability:** None of it exists.

**Local handling:** Engine counters, driver rates, RPC keys in upstream's
position and types, the rnstatus section, and fixtures regenerated at
`ef3e8086`.

**Proposed disposition:** Needs coordinated port.

### 30. `e8b3b14b` — Classic

**Upstream change:** Fixes a division by zero in commit 29's rnstatus
percentage; it now prints `0% of data flow`.

**Rust applicability:** Follows commit 29.

**Local handling:** Change the guard and add a fixture case generated at
`e8b3b14b`.

**Proposed disposition:** Needs coordinated port.

### 31. `eb00622f` — Cleanup

**Upstream change:** `rnpath -A` now always prints `Not yet implemented` and
exits 0; the analysis body is commented out.

**Rust applicability:** Covered if commit 24 is mapped as recommended.

**Local handling:** A regression that `-A` prints exactly
`Not yet implemented` and exits 0, even with an empty path table.

**Proposed disposition:** Needs port (decision 3).

### 32. `01ffb98e` — Local link traffic counting

**Upstream change:** Link endpoints also feed commit 29's counters: received
link DATA and resource proofs, and every packet sent on an open link.

**Rust applicability:** The hook points exist
(`link_manager/inbound.rs:52-75`, `link_manager/outbound.rs:120-129`); the
counters do not.

**Local handling:** Link-manager counters summed into the driver's totals,
with `local_link_traffic_counts_raw_bytes_for_link_packets`. The
CACHE_REQUEST exclusion needs checking.

**Proposed disposition:** Needs coordinated port.

### 33. `52898683` — Raised listener backlogs

**Upstream change:** The Backbone listener backlog goes from 1 to 16 and the
shared-instance RPC listener from 1 to 128.

**Rust applicability:** The listeners use std `bind`, whose backlog on the
pinned toolchain is 128 for TCP and `somaxconn` for Unix sockets, already at or
above the new values.

**Local handling:** Comments at `interface/backbone/server.rs:206` and
`rpc/server.rs` citing the std values.

**Proposed disposition:** Structurally covered.

### 34. `cff4d03f` — Updated changelog

**Upstream change:** The RNS 1.6.1 changelog section.

**Rust applicability:** Changelogs are not vendored. Every bullet is checked
against its source commit above, not taken as evidence.

**Local handling:** Analysis only.

**Proposed disposition:** Non-runtime.

## Decisions (2026-11-20)

Reviewed with the maintainer. The rule is to do what upstream does,
utilities included.

1. **Commit 9:** `known_destinations` answers with upstream's dict exactly;
   the native list moves to a separate RPC name. Implemented in `55dc3aa5`;
   the native list is `known_destination_entries`.
2. **Commits 22 and 26:** `link_distribution` follows upstream's shape at each
   commit (a set at 22, the de-duplicated list at 26); the native `total` key
   goes. Commit 22 implemented in `73ff693b`: the shape, and for a
   non-empty link table upstream's unencodable set (error logged, no
   answer), see commit 22. Commit 26 implemented in `baa60b0a`: the
   list, in upstream's order (the link table keeps insertion order), see
   commit 26.
3. **Commit 24:** the analysis statistics are ported as they are at that
   commit, then 28's guard, then 31's `Not yet implemented`. This brings in
   commit 21's destination-type files as well. Commit 24 implemented in
   `959bb94f`, see commit 24.
4. **Commit 2:** upstream's order dependence is reproduced: the disable key
   only takes effect when it appears before the count. The parser records key
   order for this.
5. **Commit 12:** default link cost 18.0, and an invalid `link_cost` or
   `stamp_value` is a startup error, as upstream. Implemented in
   `3bbe4252`, see commit 12.
6. **Commit 19:** the `lossless_medium` flag is added with upstream's
   per-class values, unread, marked `#[allow(dead_code)]` with the reason.
7. **AES-128 (found via commit 8, pre-existing):** match upstream. Only
   AES-256-CBC is enabled; a responder refuses any other signalled mode.
   Separate commit without an `Upstream-Commit` trailer. Implemented in
   `59af6496` (`link: only AES-256-CBC is enabled, as upstream`) and
   completed in `26b4e735` (`link: refuse a reserved link mode as upstream
   does`: a reserved mode is refused as upstream's `handshake()` refuses
   it, and Transport drops a request in a mode that is not enabled when it
   must lower its MTU), see commit 8.
8. **New-next-hop recovery of an unresponsive path (found via commit 17,
   pre-existing):** rns-rs keeps its behaviour by default, the divergence is
   documented, and a runtime `[reticulum]` option selects upstream's
   behaviour. Separate commit without an `Upstream-Commit` trailer.
   Implemented in `dac604d7` (`transport: an option to recover
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

## Integration Plan

Mapping commits land in ancestry order, one per upstream commit. The
interop-breaking changes are commits 9 and 27; the others are user-visible
behaviour or CLI changes. Dependencies: 13 → 14 → 15; 21 → 27; 20 → 24 → 25 →
26 → 28 → 31; 22 → 26 → 29 → 30 → 32. The rnpath and rnstatus commits each
regenerate their fixtures from a disposable upstream worktree at that exact
commit.

Summary of proposed dispositions: 16 Needs port, 5 Needs coordinated port,
1 Integrated, 8 Structurally covered, 4 Non-runtime.

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

No results yet.
