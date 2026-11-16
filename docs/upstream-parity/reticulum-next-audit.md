# Reticulum Next Upstream Audit

## Scope and Baseline

- audit date: `2026-11-16`
- previous accepted version: `1.6.0` (rgit `c850cdac`)
- previous normative commit: `c850cdac6c8bd5422af045652216ba451e98aa33`
- target version: `1.6.1` (version bumped in `fd36a972`, not yet tagged)
- target tag or ref: canonical `rgit/master` tip, equal to the GitHub mirror
  `master`; no `1.6.1` tag on either remote yet
- target normative commit: `884f109b2b821638c7addd456a52a2cd5bb8c5b1`
  (provisional; re-check for a `1.6.1` tag before promotion)
- target root tree: `353dfad65ab6f5db19a15962923a39586db82207`
- target `RNS` tree: `00ef77fcbaadad0ce252306c26bebaa301b77366`
- version assertion: `RNS.__version__ == "1.6.1"`
- audited range: `c850cdac6c8bd5422af045652216ba451e98aa33..884f109b2b821638c7addd456a52a2cd5bb8c5b1`
- commits in range: `17`
- repositories checked: rgit `master` (normative) and the GitHub mirror `master`
- local branch and revision inspected: `upstream-1.6.1@474078b0` (branched from
  `dev@474078b0`; audit opened)

Found by the 2026-11-15 daily drift check (9 commits, rgit only) and extended
by the 2026-11-16 check (17 commits). Both remotes refreshed fresh on
2026-11-16 and agree at `884f109b`: the GitHub mirror caught up past the
accepted baseline. Upstream bumped `RNS/_version.py` to `1.6.1` in
`fd36a972` but neither remote has a `1.6.1` tag, so the promotion target is
the untagged tip until a tag appears; if a tag lands on a later commit, this
audit is extended rather than restarted.

The work is done on the `upstream-1.6.1` branch in a separate worktree while
other work continues on `dev`, and is rebased onto `dev` before it lands.

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
Dispositions are provisional until each mapping commit lands.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `29dc449af89adb41b142141bee63093f6edb76b4` | Traffic counting | Integrated | `held_frames_are_filtered_and_releases_are_charged_again`, `released_announces_are_charged_as_received_traffic`; `held_announces_limit_applies_only_while_ingress_limiting` and `announce_is_held_while_held_announces_have_room` updated |
| 2 | `85d3697938393fbe68661ae9b06d2047269252d3` | Pre-emptively cull held announce queue for useless announces | Integrated | `held_announces_that_cannot_update_a_path_are_culled`, `announce_prefilter_keeps_only_announces_that_could_update_the_path` |
| 3 | `a450be5d7ed40c78353f547f1373587bb2b85d9f` | Raised announce validation caches to 384 | Structurally covered | `ANNOUNCE_SIG_CACHE_MAXSIZE` (2,000 entries, 600 s TTL, configurable) documented against upstream's sizes |
| 4 | `096e6726b4361db72e42e519037dc46c0feb6efc` | Added announce ingress prefiltering in inbound preprocessing | Integrated | `announces_that_cannot_update_a_known_path_are_prefiltered`, `announce_with_insufficient_payload_counts_a_protocol_violation`; `announce_with_cached_signature_but_different_fields_is_verified_again` adjusted |
| 5 | `f361a354ba299f0cd3672f8066683ad0232c43c8` | Ensure early tunnel synthesis on BackboneInterface | Integrated | `tunnel_synthesis_is_sent_before_the_interface_is_announced_up`, `dialing_interface_synthesizes_a_tunnel_on_each_connect` |
| 6 | `ad6c709e800b1e48ab6a4f3a57e1854075b8e858` | Ensure early tunnel synthesis on TCP and I2P interfaces | Structurally covered | Same `InterfaceUp` ordering as commit 5; TCP client and outbound I2P peer bring each connect up through it (comments in `tcp.rs` and `i2p/mod.rs`) |
| 7 | `29ce7ca5681b2e422f49cf8c0e285d0d61b0e937` | Fixed exit handler deadlock if signal arrives in the middle of an RPC call | Integrated | `withdrawing_from_an_unresponsive_shared_instance_is_bounded`; `SHARED_RPC_EXIT_TIMEOUT` |
| 8 | `e96c81c3f20b4e08a1c9206d1117ddc54bfa0feb` | Added ability to filter destination types by hash | Integrated | `configured_destination_types_take_names_or_bracketed_hashes`, `filter_section_takes_name_hashes_in_brackets`; `docs/configuration.md` |
| 9 | `bb63dd4406f14eb72bc67b63edec7efdc059caf2` | Added per-interface hop_limiter option | Integrated | `an_interface_hop_limiter_applies_before_the_transport_one`, `interface_hop_limiter_parser_clamps_and_treats_zero_as_unset`, `dynamic_registration_inherits_announces_to_internal` extended; `docs/configuration.md` |
| 10 | `d077d1ab00bad832f7ff6fdd7c16dbab91e66d05` | Ensure announce conforms to downstream transport insertion MTU at pack time | Integrated | `header_1_announce_leaves_room_for_a_transport_id`; `proptest_codec` generator updated |
| 11 | `715707b1bfc515b144cf94007de9b21264e1a7c5` | Excessive non transport-inserted announce payload protocol violation | Integrated | `header_1_announce_without_transport_room_counts_a_protocol_violation` |
| 12 | `e35bd08f186cc7662ad445a974616e97643abe8e` | Only run instance teardown at exit from main process | Structurally covered | No forked instances (supervisor children are executed, not forked); withdrawal only after a shared-instance registration (documented on `withdraw_from_shared_instance`) |
| 13 | `13b98a6bc2fa044ea47c754115f82a6ed0be2845` | Cleaned up tunnel synthesis handler | Integrated | `tunnel_synthesis_of_the_wrong_length_is_a_protocol_violation`, `a_longer_tunnel_synthesis_within_the_mdu_is_accepted`, `an_interface_takes_only_one_tunnel_synthesis`, `longer_synthesis_validates_up_to_the_mdu` |
| 14 | `b7a93b9b6be76090d052ffbeb3e8a72d9a23d570` | Bidirectional tunnel synthesis and stamp cost exchange on non shared-medium interfaces | Integrated | `tunnel_synthesis_is_answered_and_both_ends_learn_the_other`, `a_synthesis_without_an_extension_is_not_answered`, `an_invalid_synthesis_extension_is_a_protocol_violation`, `tunnel_extension` unit tests, `the_signature_covers_the_extension`, RPC pickle assertions, regenerated `tunnels` rnstatus fixture; interop `python_rns_receives_tunnel_synthesis_from_rust_client` against `884f109b` and `c850cdac` |
| 15 | `51fa8413277ef7308925aef610e409f9af0d9c3b` | Enabled stamp generation | Integrated | constants test, `stamps_section_defaults_to_the_protocol_constants`, `runtime_config_stamp_flags_default_as_upstream_and_apply_to_engine_and_shared_flag`, the no-store case in `destination_stamp_below_target_value_is_regenerated`; existing stamper tests and e2e stamps suite; interop against `884f109b` and `c850cdac` |
| 16 | `fd36a97220a40383ce7f0a1d0f40bc7043f4494f` | Updated version | Needs decision | |
| 17 | `884f109b2b821638c7addd456a52a2cd5bb8c5b1` | Fixed missing wanted destination type for interface discovery | Needs port | |

## Per-Commit Analysis

### 1. `29dc449a` — Traffic counting

**Upstream change:** A held announce is released by calling
`Transport.inbound` synchronously instead of from a new thread, and without
`no_accounting`, so the released frame is charged to received or filtered
bytes again. `hold_announce` no longer decides acceptance:
`preprocess_inbound` always returns `False` after holding, so the held frame's
bytes are filtered (`frxb`) while the announce still counts as received
without bytes. `no_accounting` is now passed through to `preprocess_inbound`
and also suppresses the exception path's filtered count. The traffic-counter
job iterates a copy of `Transport.interfaces` and measures rate intervals with
`time.monotonic()`.

**Rust applicability:** Applies to the held-announce accounting ported last
cycle (`c850cdac`, rns-rs `1040e200`), where a held frame is accepted traffic
and a released frame is not counted again. The thread-versus-inline release,
the interface list copy and the monotonic clock are Python concurrency and
clock details; the engine releases held announces inline from its tick, and
the driver's rate sampling has no shared interface list to copy.

**Local handling and evidence:** `hold_decision` marks a held frame as
filtered, so the driver moves its bytes from `rxb` to `frxb` and its packet
out of `rx_packets`, while it still counts as a received announce without
bytes. The tick's ingress release records each released frame as a
`ReleasedTraffic` (interface, size, whether preprocessing filtered it and
whether it was a filtered announce), read with
`TransportEngine::take_released_traffic`. The driver's
`record_released_traffic` charges an accepted release to `rxb` and
`rx_packets` (upstream counts it in `Transport.rx_packets`) and a filtered
one to `frxb`, and counts a filtered announce in `afrxc`, which a release
dropped as blackholed previously lost. An accepted release still counts in
`arxc`/`arxb` with its size. Tests:
`held_frames_are_filtered_and_releases_are_charged_again` (rns-core: held
flags, an accepted and a blackholed release) and
`released_announces_are_charged_as_received_traffic` (driver); the two hold
tests that pinned the `c850cdac` accounting are updated.
`docs/rnstatus.md` and `docs/configuration.md` describe the double count.

**Final disposition:** Integrated.

### 2. `85d36979` — Pre-emptively cull held announce queue for useless announces

**Upstream change:** While choosing which held announce to release,
`process_held_announces` drops every held announce whose destination already
has a path that the announce could not update: the announce was emitted before
the newest random blob on the path, or at the same time from a lower-gravity
interface while the path is not unresponsive. Culled announces free queue
slots without being released.

**Rust applicability:** The engine's held-announce release
(`maintenance.rs`, `IngressControl::process_held_announces`) only selected
the lowest-hop announce. Commit 4 moves the keep test into
`Transport.announce_prefilter` and also uses it in inbound preprocessing, so
it is ported here in the form commit 4 shares.

**Local handling and evidence:** `pathfinder::announce_prefilter` is the keep
test, comparing emission times as `should_update_path` does (an
implausibly-future emission time counts as unknown, the existing rns-rs
deviation). `maintenance::announce_passes_prefilter` applies it to a
destination's primary path, with the gravity of both receiving interfaces and
the path state; a path whose receiving interface is gone keeps the announce,
as upstream does for a path without one. It keeps every announce when
`max_paths_per_destination` is above 1 or `prefer_shorter_path` is set: both
are rns-rs extensions under which an older or same-time announce can still add
an alternative or shorter path, and upstream has neither.
`IngressControl::process_held_announces` takes the test as a closure and,
once the release conditions hold, drops every held announce that fails it
before selecting the lowest-hop one; with none left the release interval does
not restart, as upstream. Tests:
`announce_prefilter_keeps_only_announces_that_could_update_the_path`
(predicate cases) and `held_announces_that_cannot_update_a_path_are_culled`
(a held announce outdated by a newer one on another interface is culled
without a release, while another is released; nothing is culled during the
burst).

**Final disposition:** Integrated.

### 3. `a450be5d` — Raised announce validation caches to 384

**Upstream change:** `Identity.__valid_cache_max` and
`Identity.__invalid_cache_max`, the sizes of the per-process caches of
announce validation results, go from 128 to 384.

**Rust applicability:** rns-rs caches verified announce signatures in the
engine's `AnnounceSignatureCache`, keyed on the signed data and signature
rather than the packet hash: `ANNOUNCE_SIG_CACHE_MAXSIZE` is 2,000 entries
with a 600 s TTL, configurable as `announce_sig_cache_max_entries` and
`announce_sig_cache_ttl_secs`. That is already larger than upstream's new
384. rns-rs has no cache of invalid results; that predates this range, which
only changes sizes.

**Local handling and evidence:** The mapping commit documents the relation on
`ANNOUNCE_SIG_CACHE_MAXSIZE`, including the absent invalid-result cache. No
behavior change.

**Final disposition:** Structurally covered.

### 4. `096e6726` — Added announce ingress prefiltering in inbound preprocessing

**Upstream change:** Announce preprocessing is reordered: the MTU check comes
first, then a new protocol violation for a payload shorter than the public
key, name hash and 10 bytes ("Insufficient announce payload"), replacing the
malformed name hash check. For a destination already in the path table, an
announce that is not a path response, has no waiting local or discovery path
request and is not in the announce table is checked with the new
`Transport.announce_prefilter` before signature validation. If it could not
update the path it counts as a received announce without bytes and as a
filtered announce, and is dropped. `announce_prefilter` is the keep test from
commit 2, now shared with the held-queue cull.

**Rust applicability:** The engine decides path updates after validation in
`inbound_engine.rs` using the same random-blob timebase comparison. The
prefilter moves the decision ahead of signature validation for known
destinations, so useless announces skip the Ed25519 check. The keep test
itself was ported with commit 2. The payload-length violation belongs with
the driver's other admission checks, where the oversized-announce check
already runs before the engine's destination type filter.

**Local handling and evidence:** The driver's `admit_decoded_inbound` counts
an announce payload shorter than 84 bytes (public key, name hash, random
hash) as a protocol violation and filters the frame, before the engine's
destination type filter, so a short announce of a blocked type is a violation
as upstream. `TransportEngine::prefilter_announce` runs in both announce
paths (synchronous and the verification queue) after unpacking and before
ingress holding and signature validation. For a destination in the path
table, unless the announce is a path response, a local or discovery path
request waits for it, or it is in the announce table, it applies
`announce_passes_prefilter`; a failing announce counts as a received
announce without bytes and as a filtered announce, and its frame is
filtered. Tests: `announces_that_cannot_update_a_known_path_are_prefiltered`
(an older announce with a corrupted signature is filtered without a
violation; a path response and a waiting path request are exempt) and
`announce_with_insufficient_payload_counts_a_protocol_violation` (83 and 84
byte payloads of a blocked type). The signature cache test that replayed an
accepted announce's random blob under a known path now removes the path
first, since the prefilter would drop those variants before the cache is
consulted. The `proptest_transport` path model gains the prefilter: a
destination still in the path table, expired or not, only takes an announce
emitted after the path's newest one, until the expired path is culled.
`docs/rnstatus.md` lists the new filtered announces.

**Final disposition:** Integrated.

### 5. `f361a354` — Ensure early tunnel synthesis on BackboneInterface

**Upstream change:** A Backbone client sets `wants_tunnel` and synthesizes its
tunnel inside `connect`, before it is marked online, by writing the synthesis
frame straight into its transmit buffer (`early_synthesis`); reconnects no
longer synthesize separately. `synthesize_tunnel` returns early without a
transport identity or when the interface does not want a tunnel, and sends
through `early_synthesis` when the interface is not online yet. Every
interface job pass synthesizes for an online interface that still wants a
tunnel. `Interface.wants_tunnel` gets a default of `False`.

**Rust applicability:** rns-rs synthesizes when the driver sees a dialing
interface come up (`1df27919`), on every connect, in the `InterfaceUp`
handler that marks it online. Nothing the driver dispatches for the interface
can precede that, except what the application callback and the
`InterfaceUp` hook do: hook-injected actions are dispatched at once, and they
ran before the synthesis. The retry in the interface jobs covers a synthesis
that returned early, in practice for want of a transport identity; the driver
always has one before its event loop starts, so there is nothing to retry. A
Backbone client in rns-rs already wanted a tunnel on its first connect.

**Local handling and evidence:** `handle_interface_up_event` now synthesizes
before `notify_interface_up` runs the callback and the hook, so the synthesis
is the first frame on the connection, as upstream's `early_synthesis` makes
it. Tests: `tunnel_synthesis_is_sent_before_the_interface_is_announced_up`
(the callback sees the synthesis already sent, on the first connect and a
reconnect) and the existing
`dialing_interface_synthesizes_a_tunnel_on_each_connect`.

**Final disposition:** Integrated.

### 6. `ad6c709e` — Ensure early tunnel synthesis on TCP and I2P interfaces

**Upstream change:** The same early synthesis for `TCPClientInterface` and
outbound `I2PInterfacePeer` (not with KISS framing): the synthesis frame is
written to the socket in `connect` before the interface goes online, and the
separate synthesis after (re)connect is removed.

**Rust applicability:** As commit 5, for the TCP client and outbound I2P peer
writers. Both send `InterfaceUp` on every connect and reconnect (the I2P peer
through `peer_up`), so both reach the handler that commit 5 made send the
synthesis first. rns-rs has no KISS-framed TCP client, which upstream
exempts from synthesis; its I2P peers frame with HDLC.

**Local handling and evidence:** No further code change: commit 5's ordering
covers both. The mapping commit documents it where the two interfaces want
a tunnel. Evidence as commit 5.

**Final disposition:** Structurally covered.

### 7. `29ce7ca5` — Fixed exit handler deadlock if signal arrives in the middle of an RPC call

**Upstream change:** The exit handler closes every open shared-instance RPC
client connection, then runs `unwants_all_destination_types` in a daemon
thread with a 0.5 s timeout, so a signal that arrives during an RPC call
cannot deadlock shutdown.

**Rust applicability:** The deadlock itself is Python's: the signal handler
runs on the main thread in the middle of an RPC call and then makes another
one. rns-rs shuts down from ordinary control flow, and each RPC call opens
and closes its own connection, so there are no open client connections to
close. What does apply is the bound: `RnsNode::shutdown` withdrew this
application's destination types from the shared instance with a synchronous
RPC call under 10 s socket timeouts, so an instance that accepts but does not
answer could hold shutdown up for seconds.

**Local handling and evidence:**
`DestinationTypeRequester::withdraw_from_shared_instance` makes the call on
its own thread and waits at most `SHARED_RPC_EXIT_TIMEOUT` (0.5 s, upstream
`RPC_EXIT_TIMEOUT`), logging a timeout at debug level as upstream does, and
leaves the call to finish by itself. The request building and the call are
split out so the thread owns its data. Test:
`withdrawing_from_an_unresponsive_shared_instance_is_bounded` (a listener
that accepts and never authenticates; shutdown returns after the bound).

**Final disposition:** Integrated.

### 8. `e96c81c3` — Added ability to filter destination types by hash

**Upstream change:** `block_destination_type` and `allow_destination_type`
accept a name hash written as `<hex>` (the first 20 hex characters inside the
angle brackets) instead of a full destination name. The manual documents it
for the blocked and allowed destination type options.

**Rust applicability:** The `[filter]` type lists in rns-rs took names
only; `FilterSection::destination_filter` is the one place they are hashed.
Upstream's other callers of `Destination.name_hash`, such as
`wants_destination_type`, are unchanged.

**Local handling and evidence:**
`destination_filter::configured_destination_type` reads an entry as upstream
does: an empty entry is ignored; `<...>` keeps the 20 characters after the
`<`, decodes them as hex, and if they are not hex (which includes shorter hex
that keeps the `>`), hashes them as a name. Upstream's `bytes.fromhex` also
skips whitespace between bytes, giving a short key that matches nothing; such
an entry is hashed as a name here, which is recorded as a harmless
difference. `FilterSection::destination_filter` uses it for `ignored_types`
and `allowed_types`. Tests:
`configured_destination_types_take_names_or_bracketed_hashes` (names, lower
and upper case hex, a 32-character hash, non-hex, short hex, empty, an
unbalanced bracket) and `filter_section_takes_name_hashes_in_brackets`
(through the config parser). `docs/configuration.md` documents the form with
upstream's example.

**Final disposition:** Integrated.

### 9. `bb63dd44` — Added per-interface hop_limiter option

**Upstream change:** An interface section can set `hop_limiter`, clamped to
`0..=PATHFINDER_M`. Inbound, a packet with `hops >= hop_limiter` is a hop
limiter hit on that interface, before the global limiter. A value of 0 is
falsy in Python, so it disables the per-interface limit. Spawned TCP server,
Backbone, I2P and Weave peers inherit the parent's value.

**Rust applicability:** rns-rs had only the global `[filter] hop_limiter`,
checked in the driver before the engine sees a packet. Per-interface options
reach a static interface through `register_started_interface` and spawned
peers through `DynamicInterfaceTemplate`, as `gravity` and the stamp costs
do; Weave keeps its parent's options on its session.

**Local handling and evidence:** `InterfaceInfo::hop_limiter` holds the
interface's own limit. `parse_interface_hop_limiter` reads the option as
upstream (`as_int`, clamped to `0..=PATHFINDER_M`, 0 meaning unset; a
non-integer is ignored, where upstream's `as_int` would refuse the config).
`InterfaceConfig`, `StartContext`, `StartedInterface` and
`DynamicInterfaceTemplate` carry it. TCP server, Backbone and I2P templates
and Weave peers inherit it; the Auto and local server templates set `None`,
as upstream passes it only to those four. The driver checks it before the
global limiter.

Found while porting: a frame over either limiter stayed in received bytes,
while upstream's `hop_limiter_hit` returns `None` so `Transport.inbound`
charges it to filtered bytes, as `docs/rnstatus.md` already said. Both
limiters now move the frame to filtered. Tests:
`an_interface_hop_limiter_applies_before_the_transport_one` (limit on one
interface only, the frame filtered, a lower hop count passing),
`interface_hop_limiter_parser_clamps_and_treats_zero_as_unset`, and the
template registration test now checks inheritance.
`docs/configuration.md` documents the option. `InterfaceConfig` is public,
so examples and integration tests set the new field.

**Final disposition:** Integrated.

### 10. `d077d1ab` — Ensure announce conforms to downstream transport insertion MTU at pack time

**Upstream change:** Packing a `HEADER_1` announce fails if the packet would
exceed the MTU once a transport node inserts its 16-byte transport id.

**Rust applicability:** Applies to rns-core packet packing, which every
announce builder goes through: `RawPacket::pack` and its shared and in-place
variants each check the length against the MTU.

**Local handling and evidence:** The three packing paths share
`packet::exceeds_mtu`, which for a `HEADER_1` announce adds the 16 bytes of
a transport id before comparing with the MTU, so such an announce fails with
`PacketError::ExceedsMtu` as upstream's `pack` raises. An announce already in
`HEADER_2` form and every other packet keep the whole MTU. Test:
`header_1_announce_leaves_room_for_a_transport_id` (the boundary on both
sides, the shared packer, a data packet and a `HEADER_2` announce). The
`proptest_codec` packet generator now leaves that room for `HEADER_1`
announces. The workspace suite passes (3,378 tests), so no existing caller
builds an announce that large.

**Final disposition:** Integrated.

### 11. `715707b1` — Excessive non transport-inserted announce payload protocol violation

**Upstream change:** Inbound, a `HEADER_1` announce with fewer than 16 bytes
of room left under the MTU is a protocol violation ("Excessive announce
payload").

**Rust applicability:** The receiving side of commit 10. The announce size
checks of upstream's preprocessing live in the driver's
`admit_decoded_inbound`, before the engine's destination type filter.

**Local handling and evidence:** After the frame MTU check and before the
payload-length check of commit 4, as upstream orders them, a `HEADER_1`
announce whose frame (after IFAC unmasking) plus 16 bytes exceeds the MTU is
a protocol violation, logged at debug level as "Excessive announce payload",
and its frame is filtered. Test:
`header_1_announce_without_transport_room_counts_a_protocol_violation` (one
byte over and exactly at the boundary, with a blocked type so the one that
passes admission is dropped without a violation of its own). A peer that
still sends such announces, rns-rs before commit 10 or Python before
`d077d1ab`, now gets the same violation count from rns-rs as from upstream.

**Final disposition:** Integrated.

### 12. `e35bd08f` — Only run instance teardown at exit from main process

**Upstream change:** Reticulum records the main process id. The exit handler,
the signal handlers' interface detach and `Transport.exit_handler` do nothing
in a forked child process. Deregistration of wanted destination types at exit
only runs when connected to a shared instance. Adds
`Stamps.cancel_all_work` and `Reticulum.get_instance_pid`.

**Rust applicability:** The fix is for Python processes forked from a
running instance (`multiprocessing`), which inherit its exit and signal
handlers. rns-rs never forks a running instance: stamp workers are threads,
and `rns-server`'s supervisor starts `rnsd`, `rns-statsd` and
`rns-sentineld` by executing `/proc/self/exe` with an internal role, so each
child runs its own startup and shutdown. `Stamps.cancel_all_work` is not
called inside RNS; it is API for applications. The condition that only a
client of a shared instance deregisters its wanted types is already how
`DestinationTypeRequester` works: it withdraws only after a successful
registration with a shared instance.

**Local handling and evidence:** No behavior change. The mapping commit
documents the shared-instance condition on `withdraw_from_shared_instance`.

**Final disposition:** Structurally covered.

### 13. `13b98a6b` — Cleaned up tunnel synthesis handler

**Upstream change:** A synthesis on an interface that already has a remote
transport, or a second synthesis on the same interface, is now a protocol
violation instead of being ignored (new `synthesis_received` flag). A
synthesis longer than the MDU or shorter than the required length is a
protocol violation; a longer one is no longer ignored, which makes room for
the extension payload of commit 14.

**Rust applicability:** rns-rs ignored a repeated synthesis and a synthesis
of the wrong length (`an_interface_takes_only_one_tunnel_synthesis`,
`tunnel_synthesis_of_the_wrong_length_is_ignored`). The handler changes stand
on their own, so they are ported here; commit 14 then gives the extra bytes
a meaning.

**Local handling and evidence:** The engine records which interfaces have
received a synthesis (`mark_synthesis_received`, cleared when the interface
is deregistered). `handle_tunnel_synth_delivery`, after the
`tunnels_allowed` gate, counts a protocol violation for a synthesis on an
interface that has a remote transport, then marks the interface and counts
one for a second synthesis, then for data longer than the MDU or shorter
than the 176 bytes of fixed fields, in upstream's order and with its log
texts. `validate_tunnel_synthesize_data` accepts any length in that range;
at this commit the bytes after the signature are not signed and are
ignored. Tests: `tunnel_synthesis_of_the_wrong_length_is_a_protocol_violation`
(one byte short, one byte over the MDU),
`a_longer_tunnel_synthesis_within_the_mdu_is_accepted`,
`an_interface_takes_only_one_tunnel_synthesis` (after an established tunnel,
and after a failed first synthesis), and the rns-core
`longer_synthesis_validates_up_to_the_mdu`. `docs/rnstatus.md` lists the new
violations.

**Final disposition:** Integrated.

### 14. `b7a93b9b` — Bidirectional tunnel synthesis and stamp cost exchange on non shared-medium interfaces

**Upstream change:** The synthesis packet gains a signed msgpack extension
payload after the signature: implementation name, version, transport status,
and the interface's destination and path request stamp costs (keys
`0xFD`, `0xFC`, `0x01`, `0xFB`, `0xFA` from `RNS.Discovery`). The signature
now covers the extension. On receipt the extension is validated (each missing
or mistyped field is a protocol violation), stored as `remote_impl`,
`remote_vers`, `remote_is_tn`, `remote_dst_cost` and `remote_pr_cost`, and
answered with a reverse synthesis if this side has not emitted one. A node
that synthesized locally records only the remote transport; the receiving side
sets `tunnel_id` and handles the tunnel. Reconnecting TCP, Backbone and I2P
clients reset `remote_transport` and `synthesis_received`. Interface stats
report `rem_impl`, `rem_vers`, `rem_is_tn`, `rem_dst_cost` and `rem_pr_cost`
(`None` on shared-medium interfaces), and `rnstatus -T` prints the tunnel id
as plain hex plus `Rem.Vers.` and `Rem.Csts.` lines.

**Rust applicability:** A wire format change. A Python 1.6.1 client's
synthesis is longer than the 1.6.0 layout; since commit 13 rns-rs accepts the
length, and now it reads the extension. Python before 1.6.1 requires the
exact 1.6.0 length, so it ignores a synthesis with an extension, from a 1.6.1
Python client or an rns-rs client alike. That follows upstream, but it means
older Python servers record no tunnel from rns-rs clients any more, as they
did from `1df27919` until here.

**Local handling and evidence:**

- rns-core: `build_tunnel_synthesize_data` takes the extension, signs it with
  the fixed fields and appends it after the signature;
  `validate_tunnel_synthesize_data` returns it and verifies the signature over
  it. The engine records `synthesis_emitted` and each interface's
  `RemoteTransportInfo` (implementation, version components, transport
  status, quantized destination and path request costs);
  `synthesize_tunnel(.., extension, reverse, ..)` records a local tunnel only
  for a forward synthesis; `reset_tunnel_synthesis` clears an interface's
  remote transport, report and received and emitted flags.
- rns-net `common::tunnel_extension`: `encode` writes upstream's `ext_info`
  map in its key order with rns-rs's implementation name and version as
  interface discovery announces them, transport status, and the interface's
  effective destination and path request costs. `decode` checks it as
  upstream: undecodable, not a map, each missing field, the version
  (`version_tuple`, now in `common::discovery`), the implementation name
  (already sanitized), float costs and a boolean status, each with upstream's
  violation text. Costs are quantized; a non-finite cost, where upstream's
  quantization raises, is its parsing exception.
- Driver: a synthesis with an extension records the report, or counts the
  violation and stops before any tunnel; a node that has not emitted a
  synthesis on the interface answers with a reverse one. The tunnel is
  attached only where no local tunnel exists, so a client that receives the
  answer learns the remote transport without attaching the server's tunnel,
  as upstream's `if not interface.local_tunnel_id` does. A dialing interface
  resets its synthesis state on each connect before synthesizing; upstream
  resets the remote transport and received flag and leaves the report until
  the next one overwrites it, which this does not wait for.
- Stats: `SingleInterfaceStat::remote_transport_info`, `None` on a shared
  medium; RPC carries `rem_impl`, `rem_vers` (a list, which Python reads as
  upstream's tuple), `rem_is_tn`, `rem_dst_cost` and `rem_pr_cost`.
- `rnstatus -T`: the tunnel id in plain hex, and for an interface with a
  tunnel `Rem.Tr.ID`, `Rem.Vers.` and `Rem.Csts.`, as upstream prints them.
  Upstream indexes the new keys directly and would fail on an instance that
  predates them; a missing key reads as `None` here. The `tunnels` fixture
  was regenerated with upstream's own `rnstatus` at `884f109b` (generator
  updated with remote reports and a tunnel without one); only that case's
  output changed, so the range has no other `rnstatus` difference.

Tests: `tunnel_synthesis_is_answered_and_both_ends_learn_the_other` (the
server records the client and answers, the client records the server without
answering or attaching a tunnel, stats report it, a reconnect resets it),
`a_synthesis_without_an_extension_is_not_answered`,
`an_invalid_synthesis_extension_is_a_protocol_violation`, the
`tunnel_extension` unit tests (round trip, upstream's map, every violation),
`the_signature_covers_the_extension`, the RPC pickle assertions and the
`rnstatus` fixture. Commit 13's tests now build a short synthesis below the
fixed fields; its `a_longer_tunnel_synthesis_within_the_mdu_is_accepted`,
which appended unsigned bytes, is replaced by the signed round trip. Live
interop: `python_rns_receives_tunnel_synthesis_from_rust_client` now checks
that Python 1.6.1 records the Rust client's tunnel and answers, and that the
Rust client records Python's transport identity and `RNS` implementation; on
Python without the extension it checks the synthesis is ignored. Passed
against exports of `884f109b` and `c850cdac`. `docs/rnstatus.md` describes
the exchange, the new lines and the older-Python behavior.

**Final disposition:** Integrated.

### 15. `51fa8413` — Enabled stamp generation

**Upstream change:** `STAMP_DESTINATIONS` and `STAMP_PRS` default to `True`:
announces of local destinations and emitted path requests carry stamps.

**Rust applicability:** The stamping paths were ported with 1.6.0
(`rns-net/src/stamper.rs`, the engine's `stamp_prs`, the node API's
`announce_needs_stamp`) and exercised with the switches turned on at runtime;
only the defaults change. Every announce and path request a node emits now
waits for a stamp the first time, and a transport node grinds one per egress
interface for each unstamped path request it forwards, as upstream.

**Local handling and evidence:**

- `STAMP_DESTINATIONS` and `STAMP_PRS` are `true` in
  `rns-core/src/constants.rs`; `StampsSection::default()`, the driver's
  runtime config defaults, the engine's `stamp_prs` and the node handle's
  shared flag all follow them. As upstream applies `[stamps]`, `no` cannot
  turn them off; `global.stamp_destinations` and
  `global.stamp_path_requests` can, and reset to the new defaults.
- A node with no stamp store (a shared instance client, or one started in
  code without storage) used to fail every announce with stamping on, which
  only runtime switches could reach before; it now announces unstamped, the
  condition `announce_needs_stamp` already used. Upstream clients stamp
  their own announces with their own storage; rns-rs shared clients do not
  yet, which is a known gap (announces are not refused for lack of a stamp
  until enforcement, planned for 1.6.2). `rnid -a` and the shared client
  tests run through this path.
- Tests of other behavior that announced or requested paths unstamped now
  switch stamping off explicitly: `set_stamp_prs(false)` in the affected
  rns-core tests, an `unstamped` driver test helper, an unstamped
  `StampsSection` for the e2e nodes, the runtime keys for the `rngit` e2e
  nodes, and `STAMP_DESTINATIONS`/`STAMP_PRS` off in the Python interop
  harness, whose stamp test turns them on itself. The tests of the defaults
  expect them on.
- `docs/configuration.md` gives the new defaults, the first-announce delay
  and the runtime keys as the way to switch emission off;
  `docs/engines.md` notes that forwarded path request stamping is now the
  default.

**Final disposition:** Integrated.

### 16. `fd36a972` — Updated version

**Upstream change:** `RNS/_version.py` goes to `1.6.1`.

**Rust applicability:** rns-rs advertises its own implementation name and
version (`rns-rs`, crate version) in discovery, and will in the synthesis
extension. Decide whether any surface claims the upstream protocol version
(for example the default config or utilities' `--version`) and must follow.

**Local handling and evidence:** Pending.

**Final disposition:** Needs decision.

### 17. `884f109b` — Fixed missing wanted destination type for interface discovery

**Upstream change:** With interface discovery enabled, the instance declares
that it wants `rnstransport.discovery.interface` announces, so a node with
`required_destinations_only` still receives discovery announces.

**Rust applicability:** rns-rs registers wanted types for remote management
and the blackhole list (`remote_management.rs`); check the discovery start-up
path.

**Local handling and evidence:** Pending.

**Final disposition:** Needs port.

## Integration Plan

Mapping commits follow ancestry order, one per upstream commit, each with an
`Upstream-Commit:` trailer. Coordinated pairs land at the later commit, with
the earlier one recording where its behavior is carried.

1. Commit 1: held and released announce byte accounting.
2. Commits 2 and 4: the shared prefilter predicate, the held-queue cull, the
   inbound prefilter with its accounting, and the reordered announce payload
   checks.
3. Commit 3: decide on a validation cache.
4. Commits 5 and 6: synthesis ordering on connect and the retry while online.
5. Commits 7 and 12: shared-client deregistration at exit.
6. Commit 8: `<hex>` destination type filters.
7. Commit 9: per-interface `hop_limiter`, including spawned interfaces.
8. Commits 10 and 11: the transport-insertion MTU check on pack and receipt.
9. Commits 13 and 14: synthesis extension, validation, reverse synthesis,
   stats, RPC and `rnstatus`; interop with a 1.6.1 Python client and server.
10. Commit 15: stamp emitted announces and path requests by default.
11. Commits 16 and 17: version surfaces and the discovery wanted type.

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

No gates have been run yet.
