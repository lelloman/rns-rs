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
| 4 | `096e6726b4361db72e42e519037dc46c0feb6efc` | Added announce ingress prefiltering in inbound preprocessing | Needs coordinated port (with 2) | |
| 5 | `f361a354ba299f0cd3672f8066683ad0232c43c8` | Ensure early tunnel synthesis on BackboneInterface | Needs port | |
| 6 | `ad6c709e800b1e48ab6a4f3a57e1854075b8e858` | Ensure early tunnel synthesis on TCP and I2P interfaces | Needs port | |
| 7 | `29ce7ca5681b2e422f49cf8c0e285d0d61b0e937` | Fixed exit handler deadlock if signal arrives in the middle of an RPC call | Needs decision | |
| 8 | `e96c81c3f20b4e08a1c9206d1117ddc54bfa0feb` | Added ability to filter destination types by hash | Needs port | |
| 9 | `bb63dd4406f14eb72bc67b63edec7efdc059caf2` | Added per-interface hop_limiter option | Needs port | |
| 10 | `d077d1ab00bad832f7ff6fdd7c16dbab91e66d05` | Ensure announce conforms to downstream transport insertion MTU at pack time | Needs port | |
| 11 | `715707b1bfc515b144cf94007de9b21264e1a7c5` | Excessive non transport-inserted announce payload protocol violation | Needs port | |
| 12 | `e35bd08f186cc7662ad445a974616e97643abe8e` | Only run instance teardown at exit from main process | Needs decision | |
| 13 | `13b98a6bc2fa044ea47c754115f82a6ed0be2845` | Cleaned up tunnel synthesis handler | Needs coordinated port (with 14) | |
| 14 | `b7a93b9b6be76090d052ffbeb3e8a72d9a23d570` | Bidirectional tunnel synthesis and stamp cost exchange on non shared-medium interfaces | Needs coordinated port (with 13) | |
| 15 | `51fa8413277ef7308925aef610e409f9af0d9c3b` | Enabled stamp generation | Needs port | |
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
prefilter moves that decision ahead of signature validation for known
destinations, so useless announces skip the Ed25519 check and the hold queue.
Needs the same predicate, the payload-length violation, and the accounting.

**Local handling and evidence:** Pending.

**Final disposition:** Needs coordinated port (with 2).

### 5. `f361a354` — Ensure early tunnel synthesis on BackboneInterface

**Upstream change:** A Backbone client sets `wants_tunnel` and synthesizes its
tunnel inside `connect`, before it is marked online, by writing the synthesis
frame straight into its transmit buffer (`early_synthesis`); reconnects no
longer synthesize separately. `synthesize_tunnel` returns early without a
transport identity or when the interface does not want a tunnel, and sends
through `early_synthesis` when the interface is not online yet. Every
interface job pass synthesizes for an online interface that still wants a
tunnel. `Interface.wants_tunnel` gets a default of `False`.

**Rust applicability:** rns-rs synthesizes when the driver sees the dialing
interface come up (`1df27919`). Check whether anything can be sent on the
connection before the synthesis frame, and whether a failed synthesis is
retried while the interface stays up.

**Local handling and evidence:** Pending.

**Final disposition:** Needs port.

### 6. `ad6c709e` — Ensure early tunnel synthesis on TCP and I2P interfaces

**Upstream change:** The same early synthesis for `TCPClientInterface` and
outbound `I2PInterfacePeer` (not with KISS framing): the synthesis frame is
written to the socket in `connect` before the interface goes online, and the
separate synthesis after (re)connect is removed.

**Rust applicability:** As commit 5, for the TCP client and outbound I2P peer
writers.

**Local handling and evidence:** Pending.

**Final disposition:** Needs port.

### 7. `29ce7ca5` — Fixed exit handler deadlock if signal arrives in the middle of an RPC call

**Upstream change:** The exit handler closes every open shared-instance RPC
client connection, then runs `unwants_all_destination_types` in a daemon
thread with a 0.5 s timeout, so a signal that arrives during an RPC call
cannot deadlock shutdown.

**Rust applicability:** `rns-net/src/shared_client.rs` deregisters wanted
destination types on drop through an RPC call. Check whether that call can
block shutdown (no timeout, or a held connection) and decide whether a bounded
deregistration is needed.

**Local handling and evidence:** Pending.

**Final disposition:** Needs decision.

### 8. `e96c81c3` — Added ability to filter destination types by hash

**Upstream change:** `block_destination_type` and `allow_destination_type`
accept a name hash written as `<hex>` (the first 20 hex characters inside the
angle brackets) instead of a full destination name. The manual documents it
for the blocked and allowed destination type options.

**Rust applicability:** The destination type filter config in rns-rs takes
names only.

**Local handling and evidence:** Pending.

**Final disposition:** Needs port.

### 9. `bb63dd44` — Added per-interface hop_limiter option

**Upstream change:** An interface section can set `hop_limiter`, clamped to
`0..=PATHFINDER_M`. Inbound, a packet with `hops >= hop_limiter` is a hop
limiter hit on that interface, before the global limiter. A value of 0 is
falsy in Python, so it disables the per-interface limit. Spawned TCP server,
Backbone, I2P and Weave peers inherit the parent's value.

**Rust applicability:** rns-rs has only the global `[filter] hop_limiter`.

**Local handling and evidence:** Pending.

**Final disposition:** Needs port.

### 10. `d077d1ab` — Ensure announce conforms to downstream transport insertion MTU at pack time

**Upstream change:** Packing a `HEADER_1` announce fails if the packet would
exceed the MTU once a transport node inserts its 16-byte transport id.

**Rust applicability:** Applies to rns-core packet packing and to the
announce builders that can produce near-MTU announces (large app data).

**Local handling and evidence:** Pending.

**Final disposition:** Needs port.

### 11. `715707b1` — Excessive non transport-inserted announce payload protocol violation

**Upstream change:** Inbound, a `HEADER_1` announce with fewer than 16 bytes
of room left under the MTU is a protocol violation ("Excessive announce
payload").

**Rust applicability:** The receiving side of commit 10, in the announce
preprocessing reordered by commit 4.

**Local handling and evidence:** Pending.

**Final disposition:** Needs port.

### 12. `e35bd08f` — Only run instance teardown at exit from main process

**Upstream change:** Reticulum records the main process id. The exit handler,
the signal handlers' interface detach and `Transport.exit_handler` do nothing
in a forked child process. Deregistration of wanted destination types at exit
only runs when connected to a shared instance. Adds
`Stamps.cancel_all_work` and `Reticulum.get_instance_pid`.

**Rust applicability:** Python `multiprocessing` fork semantics; rns-rs stamp
workers are threads and the supervisor's children are separate executables
with their own lifecycles. The shared-instance condition on deregistration
needs checking against `shared_client.rs`.

**Local handling and evidence:** Pending.

**Final disposition:** Needs decision.

### 13. `13b98a6b` — Cleaned up tunnel synthesis handler

**Upstream change:** A synthesis on an interface that already has a remote
transport, or a second synthesis on the same interface, is now a protocol
violation instead of being ignored (new `synthesis_received` flag). A
synthesis longer than the MDU or shorter than the required length is a
protocol violation; a longer one is no longer ignored, which makes room for
the extension payload of commit 14.

**Rust applicability:** rns-rs ignores a repeated synthesis and a synthesis of
the wrong length (`an_interface_takes_only_one_tunnel_synthesis`,
`tunnel_synthesis_of_the_wrong_length_is_ignored`). Ported with commit 14.

**Local handling and evidence:** Pending.

**Final disposition:** Needs coordinated port (with 14).

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
synthesis is longer than the 1.6.0 layout, which rns-rs currently ignores, so
1.6.1 clients get no tunnel on rns-rs servers until this is ported. rns-rs
synthesis without an extension is still accepted by 1.6.1, but gets no reverse
synthesis. Needs the extension encoder and validator (sharing the discovery
constants and name sanitizing in `common/discovery.rs`), reverse synthesis,
the new interface state, stats and RPC keys, and `rnstatus` output.

**Local handling and evidence:** Pending.

**Final disposition:** Needs coordinated port (with 13).

### 15. `51fa8413` — Enabled stamp generation

**Upstream change:** `STAMP_DESTINATIONS` and `STAMP_PRS` default to `True`:
announces of local destinations and emitted path requests carry stamps.

**Rust applicability:** `rns-core/src/constants.rs` keeps
`STAMP_DESTINATIONS = false`, and the engine's `stamp_prs` default follows the
compile-time constant. The stamping paths exist (`rns-net/src/stamper.rs`) but
switching them on changes every announce and path request this node emits, so
it needs interop and load checks.

**Local handling and evidence:** Pending.

**Final disposition:** Needs port.

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
