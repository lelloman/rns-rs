# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-11-13`
- previous accepted version: `1.6.0`
- previous normative commit: `16621a78e35e2ba5156c72af7fe492458ba092d5`
- target version: `1.6.0` (pending: no version bump in range)
- target tag or ref: `rgit/master` (pending promotion target)
- target normative commit: `134dc6777c0dd29404e61b36d4094f4e35b88b3e`
- target root tree: `da30506871f4036968e0355447e3d0e79b39942d`
- target `RNS` tree: `aa29f48513fca2a1be8c9940bcee9ca7bbb074db`
- version assertion: `RNS.__version__ == "1.6.0"`
- audited range: `16621a78e35e2ba5156c72af7fe492458ba092d5..134dc6777c0dd29404e61b36d4094f4e35b88b3e`
- commits in range: `15`
- repositories checked: rgit `master` (normative) and the GitHub mirror `master`
- local branch and revision inspected: `upstream-next-audit@bf4d7bab1801c818503783fdf1a4ffcc82a535f3`

Found by the 2026-11-13 daily drift check (`data/upstream-drift-2026-11-13.json`),
both remotes refreshed fresh. The GitHub mirror tip `3c4b271f` (10 commits) is
contained in rgit `master`; rgit adds five later commits (`db67adea`, `f96cef7e`,
`9b6b724b`, `20e25a9f`, `134dc677`). No version bump, so the target version and
promotion target stay pending.

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
| 1 | `50b6733a1cc0c85cc0caa94ee2f5e38c6692e462` | Cleanup | Structurally covered | `oversized_announce_of_a_blocked_type_counts_a_protocol_violation` |
| 2 | `023849ed29e230441499f1adf6eb135696d067b6` | Improved path pool and tunnel culling | Integrated | Reverse timeout, dynamic unused pool target and tunnel reconnect window, with focused tests |
| 3 | `3ac3236b2f11f5e58ca9d86564ee44222bfacd9b` | Updated stale doc defaults | Integrated | Held announce cap 64, section 0 keeps the default, docs |
| 4 | `7852f53a4c24fe7e063e02c00d35eb06568f0b15` | Always init announce_queue | Structurally covered | `interface_without_a_queue_has_nothing_queued` |
| 5 | `70b9d58f15d88a3e33402f06f30cad411001e0ed` | Cleaned up announce cap properties | Structurally covered | `new_interface_queue_allows_its_first_announce_at_once` |
| 6 | `1855f9927fe23990c2da8d49c1409b85b1b7ef8f` | Cleanup | Non-runtime | Log wording only |
| 7 | `0bc5c37c399cb6c489ade2ea3678c531bfc21390` | Reset DPEC on reconnect | Structurally covered | Fresh writer per connection, documented on `BackboneClientWriter` |
| 8 | `9ef6c90ea6196057278685aabab06674e73ffa44` | Use RLock in logging | Structurally covered | No re-entrant logging path; documented on `RotatingLogWriter` |
| 9 | `5f2dbc169d5b3cb497d0f7067acef823e5619f30` | Added ability to load a blocked_ips file from the current config dir | Integrated | `blocked_ips` file loaded at startup into the shared fast-flap table, with focused and live socket tests |
| 10 | `3c4b271f4133ed1f00eae04b1f3160365f4d02ec` | Added client_limit option to BackboneInterface | Integrated | `client_limit` with the upstream default of 500, checked first |
| 11 | `db67adea0a6cc4289580ff7a19923605d48870e8` | Fixed path usage display | Integrated | `rnpath` reads Python's integer `used`; Python `rnpath -t -u` interop |
| 12 | `f96cef7ed94029c8028fd688c55f3af5946b5d3c` | Drop announces early when held announces is full | Integrated | Early held-full announce drop in the driver; hop-limiter path cull |
| 13 | `9b6b724b08e6c8681cfb9edd34edd905fb2238b3` | Diagnostics | Pending review | Changes `RNS/Reticulum.py`, `RNS/Utilities/rnstatus.py` |
| 14 | `20e25a9f0cd4bde8958642d36690cf709849f5ee` | Filter destinations at path table load time | Pending review | Changes `RNS/Transport.py` |
| 15 | `134dc6777c0dd29404e61b36d4094f4e35b88b3e` | Added filtered traffic stats and display in rnstatus | Pending review | Changes `RNS/Interfaces/Interface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py` |

## Per-Commit Analysis

### 1. `50b6733a` — Cleanup

**Upstream change:** `Packet.unpack` failures and the malformed-packet protocol violation log at EXTREME instead of DEBUG (counters unchanged). The oversized-announce check (`len(raw) > Reticulum.MTU`, a protocol violation) moves ahead of the `blocked_destination_types` and `required_destinations_only` filters, so an oversized announce of a blocked or not-allowed type now counts a protocol violation where it was dropped silently.

**Rust applicability:** rns-rs checks the announce frame size in the driver (`admit_decoded_inbound`, `rns-net/src/driver/events.rs`) before the engine applies its destination type filter, and logs malformed packets at trace, so it already behaves as the new upstream. One counter-only nuance predates this commit: upstream runs `packet_filter` before the size check, so an oversized announce that is also a duplicate counts a packet-filter hit upstream and a protocol violation in rns-rs.

**Local handling and evidence:** Regression `oversized_announce_of_a_blocked_type_counts_a_protocol_violation` (`rns-net/src/driver/tests.rs`) blocks the announce's name hash and still requires one protocol violation.

**Final disposition:** Structurally covered.

### 2. `023849ed` — Improved path pool and tunnel culling

**Upstream change:** Three retention changes. (a) `REVERSE_TIMEOUT` drops from 8 to 3 minutes, so a transport node stops routing proofs back for packets it relayed more than three minutes earlier. (b) The never-used path pool target is no longer a fixed 2048: it is `PATH_POOL_UNUSED_MAX` (1536) until more than `PATH_POOL_USED_TARGET` (2048) paths are in use, then shrinks by one per extra used path down to `PATH_POOL_UNUSED_MIN` (512); used paths are counted over the whole table before stale ones are removed. (c) `TUNNEL_RECONNECT_WINDOW` (10 minutes): a tunnel whose interface is no longer in `Transport.interfaces` gets that window to be synthesized again before it is culled, and a tunnel restored from storage keeps at most that window, instead of up to 8 hours.

**Rust applicability:** rns-rs had all three old behaviours: `REVERSE_TIMEOUT = 480`, a fixed `PATH_POOL_UNUSED_TARGET = 2048` passed to `jobs::cull_path_table`, and tunnels voided without changing their expiry (`TunnelTable::void_tunnel_interface`, `void_missing_interfaces`) and restored with their stored expiry. Upstream only starts the window for interfaces removed from `Transport.interfaces` (spawned clients); static interfaces that go offline stay registered and keep their tunnel's expiry. rns-rs voids the tunnel on every interface-down event (a pre-existing difference), so the window is applied only when the interface is dynamic and therefore removed.

**Local handling and evidence:** `REVERSE_TIMEOUT = 180`; `PATH_POOL_UNUSED_MAX`/`MIN`/`USED_TARGET` and `jobs::UnusedPoolLimits` (`UPSTREAM` in production, `fixed` for focused tests), with `cull_path_table` counting used paths first; `TUNNEL_RECONNECT_WINDOW = 600`, `TunnelTable::release_tunnel_interface` for removed dynamic interfaces (`driver/events.rs`), `void_missing_interfaces(now, ..)` starting the window, and the restore clamp in `restore_persistence_snapshot`. Tests: `test_cull_reverse_table_timeout` (kept at 3 min, culled after), `unused_path_pool_target_follows_used_count`, `unused_pool_shrinks_once_used_paths_exceed_their_target`, `test_tunnel_table_void_missing_interfaces`, `test_tunnel_table_released_interface_starts_reconnect_window`, `test_tunnel_table_reattach_within_window_restores_expiry`, `test_tunnel_table_void_tunnel_keeps_expiry`, `detached_tunnel_round_trips_when_at_least_one_cached_path_survives` (restore clamp, and an expiry inside the window kept), `removed_dynamic_interface_starts_tunnel_reconnect_window` (driver). rns-core and rns-net library suites pass.

**Final disposition:** Integrated.

### 3. `3ac3236b` — Updated stale doc defaults

**Upstream change:** `Interface.MAX_HELD_ANNOUNCES` drops from 256 to 64. It is the default `ic_max_held_announces` of every interface (through `Reticulum._default_ic_max_held_announces`, which reads the `[reticulum]` value with `or`, so a section value of 0 also means 64), so an interface without an explicit setting holds at most 64 unique announces while it bursts. The rest is documentation: the stated defaults of `ic_burst_freq_new` (3.0), `ic_burst_freq` (10.0), `ic_max_held_announces` (64), `ic_burst_hold` (15), `ic_burst_penalty` (15) and `ic_held_release_interval` (5) are corrected to the values the code already used.

**Rust applicability:** rns-rs used 256 (`IC_MAX_HELD_ANNOUNCES`), so held capacity differed on every ingress-controlled interface. The other ingress control constants already matched the corrected defaults. A `[reticulum] ic_max_held_announces = 0` was stored as 0, where upstream uses the default; with the early drop of `f96cef7e` (row 12) that would refuse every announce on every interface, so the section value now follows upstream's `or`. A per-interface 0 stays literal, as upstream applies it. `docs/configuration.md` implied that its example values (256, 60, 3.5, 12, 300, 30) were the defaults.

**Local handling and evidence:** `IC_MAX_HELD_ANNOUNCES = 64`; `[reticulum] ic_max_held_announces = 0` keeps the default; `docs/configuration.md` lists the held cap, `ic_new_time` and `ec_pr_freq` defaults and no longer calls the example values defaults. Tests: `test_upstream_1_2_5_default_thresholds` pins 64, `parse_reticulum_ic_max_held_announces_zero_keeps_default`. rns-core and rns-net library suites pass.

**Final disposition:** Integrated.

### 4. `7852f53a` — Always init announce_queue

**Upstream change:** `Interface.__init__` always creates `announce_queue = []`, `process_announce_queue` returns early on an empty queue, and the lazy `hasattr(..., "announce_queue")` initialisations in `Transport.outbound` and `request_path` are removed. No change on the wire or for operators; only third-party Python interfaces that skip `Interface.__init__` would now fail.

**Rust applicability:** Announce queues are engine-owned and typed (`AnnounceQueues`, `InterfaceAnnounceQueue::new`), created on demand with `entry(..).or_default()`; an interface without a queue is one with nothing queued, so there is no missing-attribute state to initialise.

**Local handling and evidence:** Invariant pinned by `interface_without_a_queue_has_nothing_queued` (`rns-core/src/transport/announce_queue.rs`): no queue, no queued work, recursive path requests not held back.

**Final disposition:** Structurally covered.

### 5. `70b9d58f` — Cleaned up announce cap properties

**Upstream change:** `Interface.__init__` sets `announce_allowed_at = 0` (with `announce_cap`, already set there), and the lazy `hasattr` defaults for both in `Transport.outbound` and `request_path` are removed. No behaviour change.

**Rust applicability:** `InterfaceAnnounceQueue::new` starts `announce_allowed_at` at 0.0, and `InterfaceInfo.announce_cap` is a required field defaulting to `constants::ANNOUNCE_CAP`; neither can be missing.

**Local handling and evidence:** Invariant pinned by `new_interface_queue_allows_its_first_announce_at_once` (`rns-core/src/transport/announce_queue.rs`).

**Final disposition:** Structurally covered.

### 6. `1855f992` — Cleanup

**Upstream change:** Two EXTREME-level "Added announce to queue" log lines in `Transport.outbound` format their wait time with `RNS.prettyshorttime(..., compact=True, tight=True)`. Log wording only, behind `RNS.sl(LOG_EXTREME)`; no counter, queue or exit path changes.

**Rust applicability:** rns-rs's announce queue logging is its own and carries no upstream log format contract.

**Local handling and evidence:** Analysis recorded here; no runtime change.

**Final disposition:** Non-runtime.

### 7. `0bc5c37c` — Reset DPEC on reconnect

**Upstream change:** `BackboneClientInterface.reconnect()` now calls `BackboneInterface._dp_ec_reset`, which zeroes the dataplane egress control (DPEC) counters, installs a fresh `TransmitBuffer` and clears `tx_stalled`. Before, only the dead-time teardown reset them, so after any other disconnect a persistent Python initiator could carry buffered frame bytes, a set stall gate (dropping every frame) or an old drain timestamp (an immediate teardown) into the new connection.

**Rust applicability:** rns-rs builds a new `BackboneClientWriter`, with an empty `TransmitBuffer` and a fresh egress controller, for every connection: the initial connect, each reconnect (handed to the driver with the new interface writer), and every accepted peer. No egress state survives a connection, so the upstream failure cannot occur. Same reasoning as the 1.5.7 audit's `f0875ac4` entry; the existing regression is `fresh_egress_state_does_not_immediately_reescalate_after_teardown` (`rns-net/src/interface/transmit_buffer.rs`).

**Local handling and evidence:** The invariant's documentation on `BackboneClientWriter` (`rns-net/src/interface/backbone.rs`) now cites `0bc5c37c`.

**Final disposition:** Structurally covered.

### 8. `9ef6c90e` — Use RLock in logging

**Upstream change:** `RNS.logging_lock` becomes an `RLock`. `RNS.log` holds it while writing, and when a log file write or rotation fails, or the log callback raises, its exception handler calls `log()` again from inside the lock; with a plain `Lock` that deadlocked the logging thread, and with it the process. Operator-visible only: a full disk or broken log callback no longer hangs `rnsd`.

**Rust applicability:** rns-rs logs through the `log` facade and `env_logger`; the service log file writer (`RotatingLogWriter`, `rns-cli/src/rnsd.rs`) returns write and rotation failures as `io::Error` and never logs, so nothing re-enters the logger. A pre-existing difference outside this commit: on a log file failure upstream falls back to stdout, while rns-rs drops the line.

**Local handling and evidence:** The non-re-entrant failure path is documented on `RotatingLogWriter` with this commit cited.

**Final disposition:** Structurally covered.

### 9. `5f2dbc16` — Added ability to load a blocked_ips file from the current config dir

**Upstream change:** At startup, `Reticulum` reads `<configdir>/blocked_ips` when it exists: the whole file is stripped and split into lines, each line stripped, lines starting with `#` skipped, and every line that `ipaddress.ip_address()` accepts is put in `BackboneInterface.fast_flapping` with a flap time 1000 years ahead and a flap count of 0xFFFF. Every listening `BackboneInterface` with `block_fast_flapping` on (and a grace below 0xFFFF) then refuses connections from those addresses for the life of the process, and lists them in `rnstatus -b`. Errors are logged and load nothing; ranges, host names and trailing comments are skipped. The table is keyed by the address string as written.

**Rust applicability:** rns-rs had no file-loaded block list. It already has the shared fast-flap table (`BackboneFastFlapMonitor`, process-wide like upstream's class-level table, with per-listener policy), rejection before interface allocation in `admit()`, and `rnstatus -b` reporting. A far-future `Instant` would not fit that table (`checked_add` overflow, absurd remaining times), so the file's addresses are kept as permanent entries instead.

**Local handling and evidence:** `read_blocked_ips_file` / `load_blocked_ips_file` (`rns-net/src/interface/backbone.rs`) read the file as upstream does; `RnsNode::from_config_dirs` loads it from the config directory before interfaces start. `BackboneFastFlapMonitor` keeps the addresses in canonical form, applies them only when the listener's fast-flap blocking is on and its grace is below `STATIC_BLOCK_FLAP_COUNT` (0xFFFF), never expires them, lists them with the dynamic blocks, and forgets one on clear (an rns-rs operator extension; it returns at the next start). `admit()` rejects them first, recording `blocked_ips file` as the reason. Documented in `docs/rns-server-operator-runbook.md`, including two intended differences: addresses are compared by value (case and IPv4-mapped forms match), and scoped IPv6 addresses are not accepted. Tests: `blocked_ips_file_parses_addresses_and_skips_comments_and_garbage`, `missing_or_unreadable_blocked_ips_file_blocks_nothing`, `file_blocked_ip_never_expires_and_is_listed`, `file_blocked_ip_follows_the_listener_fast_flap_policy`, `file_blocked_ipv4_matches_its_ipv4_mapped_form`, `backbone_blocked_ips_file_rejects_before_allocating_interface` (live socket).

**Final disposition:** Integrated.

### 10. `3c4b271f` — Added client_limit option to BackboneInterface

**Upstream change:** `BackboneInterface` gains `CLIENT_LIMIT = 500` and a `client_limit` option (`int(...)`, so a non-integer fails the interface; `client_limit or CLIENT_LIMIT`, so 0 or absent means 500). `incoming_connection` first refuses a connection, silently, when the listener already has `client_limit` spawned client interfaces. It is a total for the listener across all addresses, not a per-address limit. Initiators and `TCPServerInterface` are unaffected; no RPC field reports it.

**Rust applicability:** rns-rs had the same mechanism as `max_connections` (a total per listener, enforced in `admit()`, adjustable at runtime) but did not read `client_limit` and defaulted to unlimited, checked the limit after the blocked-address checks, and logged every rejection as a warning. This is not the per-address limit rns-rs decided against for NAT reasons.

**Local handling and evidence:** `BACKBONE_CLIENT_LIMIT = 500` and `parse_client_limit` (`rns-net/src/interface/backbone.rs`): `client_limit` as upstream reads it (an invalid or negative value is a configuration error, where upstream would fail the interface or refuse everyone), with `max_connections`, when set, taking precedence and keeping its meaning (0 = no limit). `admit()` now checks the limit first and logs at pathing trace. Both VPS listeners set `max_connections = 512`, so their limit is unchanged. Documented in `docs/rns-server-operator-runbook.md`. Tests: `client_limit_defaults_to_upstream_500`, `client_limit_rejects_invalid_values`, `max_connections_takes_precedence_over_client_limit`; the existing `backbone_max_connections_rejects_excess` and `backbone_max_connections_allows_after_disconnect` cover enforcement.

**Final disposition:** Integrated.

### 11. `db67adea` — Fixed path usage display

**Upstream change:** `rnpath -t -u` printed nothing for path usage: the suffix (`, last used <time> ago`, `, never used`, or `, no usage info` when an entry has no `used` key) was computed and never added to the line. The fix appends it. No RPC change; `get path_table` already returned `used` (the integer 0 for a never-used path, a float time after use).

**Rust applicability:** rns-rs's `rnpath` already printed the suffix and sorted by `used` under `-u`, and the rns-rs daemon sends `used` (a float) on every path table entry, so Python's fixed `rnpath -u` works against it. Reviewing this found an rns-rs bug: against a Python daemon, rns-rs's `rnpath` read `used` only as a float, so a never-used path (integer 0) printed `, no usage info`.

**Local handling and evidence:** `path_used` / `usage_suffix` (`rns-cli/src/bin/rnpath.rs`) read `used` as an integer or a float. Tests: `usage_suffix_reads_python_and_rust_used_values`; `python_rnpath_lists_rust_path_table` (`rns-cli/tests/utility_interop.rs`) now runs Python `rnpath -t -u` against a Rust daemon and requires the suffix where the Python release prints it, passing against RNS 1.4.2 (no `-u`), 1.5.4, 16621a78 and 134dc677.

**Final disposition:** Integrated.

### 12. `f96cef7e` — Drop announces early when held announces is full

**Upstream change:** Two changes. (1) In `Transport` inbound preprocessing, after the packet filter and the malformed / oversize announce checks and before the blocked destination type check, an announce is dropped (`return None`, no protocol violation, no filter hit) when its interface already holds `ic_max_held_announces` announces. The check does not look at whether ingress control is on, so an interface with `ic_max_held_announces = 0` accepts no announces. Releases are popped from `held_announces` before they re-enter `inbound`, so they are never dropped by it. (2) Path table culling also removes a path, used or not, whose hops exceed `Transport.HOP_LIMITER`.

**Rust applicability:** rns-rs held an announce or dropped it in the engine only after full processing (the drop was `hold_announce` at the limit); the driver had already recorded the incoming-announce sample and fed the frequency to the engine. Paths were never culled for their hops, and the engine did not know the hop limiter (only the driver did, for the inbound check).

**Local handling and evidence:** `TransportEngine::announce_holding_saturated` (`rns-core/src/transport/queries.rs`) and the early drop in `admit_decoded_inbound` (`rns-net/src/driver/events.rs`), after the oversize, path-request and packet-filter checks; held announces are released from the engine tick, not through it. The engine now has a `hop_limiter` (default `HOP_LIMITER`) set from `[filter] hop_limiter` by `Driver::apply_stamp_config`, and `jobs::cull_path_table` takes it and removes paths with more hops. Documented in `docs/configuration.md`. Tests: `announce_is_dropped_early_when_held_announces_are_full`, `announce_is_held_while_held_announces_have_room`, `apply_stamp_config_sets_the_engine_hop_limiter` (`rns-net/src/driver/tests.rs`), `cull_removes_paths_with_more_hops_than_the_hop_limiter` (`rns-core/src/transport/jobs.rs`). Upstream 134dc677 later counts this drop as filtered inbound; that is mapped with that commit.

**Final disposition:** Integrated.

### 13. `9b6b724b` — Diagnostics

**Upstream change:** Pending review (changes `RNS/Reticulum.py`, `RNS/Utilities/rnstatus.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 14. `20e25a9f` — Filter destinations at path table load time

**Upstream change:** Pending review (changes `RNS/Transport.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

### 15. `134dc677` — Added filtered traffic stats and display in rnstatus

**Upstream change:** Pending review (changes `RNS/Interfaces/Interface.py`, `RNS/Reticulum.py`, `RNS/Transport.py`, `RNS/Utilities/rnstatus.py`).

**Rust applicability:** Pending review.

**Local handling and evidence:** None yet.

**Final disposition:** Pending review.

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
