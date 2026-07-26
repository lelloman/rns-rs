# Reticulum 1.4.1 integration analysis (2026-07-25)

## Scope

This working document audits every upstream Reticulum commit after the accepted
rns-rs 1.4.0 baseline and through the signed Reticulum 1.4.1 release tag. It is
an integration plan, not an acceptance record: `UPSTREAM.md` remains normative
at 1.4.0 until the applicable work is ported, tested and accepted.

- accepted rns-rs baseline: `122f17fad69a483503cc5c1d8d81046712d78c96`
- accepted baseline version: Reticulum `1.4.0`
- upstream release tag: annotated tag `1.4.1`
- release tag target: `b2188ce9a746a35b770b10bea1b7ccbe93b4e198`
- release runtime tree: `28356de6a3562989367859b50ff584e334e4abb4`
- release version assertion: `RNS.__version__ == 1.4.1`
- commits in the audited range: 32
- upstream commit dates: 2026-07-22 through 2026-07-24
- remote containment checked on 2026-07-25: both `origin/master` and
  `rgit/master` contain the tag target
- local branch inspected: rns-rs `dev` at `c827cb1`

The range is exactly:

```text
122f17fad69a483503cc5c1d8d81046712d78c96..1.4.1
```

The phrase "not integrated" in this document means "not represented by the
accepted baseline". Some commits need no Rust code because the local design
already avoids the Python-specific failure. Those commits are still listed and
audited so advancing the baseline cannot silently skip them.

## Disposition meanings

- **Needs port**: compatible behavior is absent or observably different in the
  inspected Rust tree.
- **Needs coordinated port**: the behavior is absent and belongs to a cluster
  that should be implemented and tested as one change rather than commit by
  commit.
- **Needs decision**: upstream and local architecture differ enough that the
  desired compatibility surface must be chosen before implementation.
- **Structurally covered**: Rust already avoids the upstream bug or provides the
  relevant behavior through a different, stronger invariant. Focused evidence
  should still be recorded in the eventual parity matrix.
- **Documentation follow-up**: source documentation should be represented in
  local native docs after its underlying runtime/API behavior exists; generated
  upstream manuals should not be copied.
- **Non-runtime**: version metadata, changelog text, generated manuals or
  upstream-only tests with no independent local runtime change.

## Commit inventory

| # | Upstream commit | Subject | Initial disposition |
|---:|---|---|---|
| 1 | `483887569134b26d9be66859a8685c5289e4bcb0` | Fixed ingress control burst active flag deadlocking until new announces arrived under burst timing patterns | Structurally covered |
| 2 | `b051e76d00ab97baa948e69cdacadba3cf4739da` | Allow boundary -> boundary and boundary -> gateway path requests | Needs port |
| 3 | `1af173e8a59d4f8c28a3e52fa97875a3d96930f4` | Added announces_to_internal interface option | Needs port |
| 4 | `bebf211b01c5c08fcd4b1bcdb2cadc773e2b5127` | Added autoconnect_discovered_mode and autoconnect_announces_to_internal options | Needs decision |
| 5 | `9bc73819f641db25868355e494f66f49c8b71a84` | Updated documentation | Documentation follow-up |
| 6 | `c10c465c0231f29536e66fa1c3713eb064ea71ea` | Interface gravity base property and configuration | Needs coordinated port |
| 7 | `7611fca6bf422c81e73e3411a4a541f188a17a3a` | Fixed loglevel 8 not being respected | Structurally covered |
| 8 | `5577e781fbe44154621b38a9179cfe197e1f7a37` | Basic gravity processing for announces | Needs coordinated port |
| 9 | `3ca71527d9869010ada97b2b029cd699d024720f` | Propagate gravity to spawned interfaces | Needs coordinated port |
| 10 | `566aa68fc00cec224fb6818038ba622ba1974147` | Added gravity, default_gravity and autoconnect_interface_gravity options and updated documentation | Needs coordinated port |
| 11 | `889c5ff55fc8538737f6c86e14e3043caf729488` | Added sort by gravity to rnstatus | Needs coordinated port |
| 12 | `cbf50460c2b80d0cab67a94fe54d96c26992bb66` | Cleaned up logging | Structurally covered |
| 13 | `90e1dbb9125c7576a17b7b73320ccff1a4a28b09` | Link request path re-balancing | Needs coordinated port |
| 14 | `c4297d318f9ede3e52145bf6267392c82228acb3` | Cleanup | Gravity-cluster follow-up |
| 15 | `6d4523c27ee5f32e1b27a176d6a1d2ed1c70206b` | Added rebalanced time to links | Needs coordinated port |
| 16 | `93526c17f54528d3aa6019a71aa1893202242229` | Added rebalanced time to links | Needs coordinated port |
| 17 | `bce5f859daf4bdfb0454c4bdc47f0de7fc112541` | Logging consistency | Rebalancing-cluster follow-up |
| 18 | `a4b612987568ee0a9b752c830b0fbb582067581b` | Fixed i2p tunnel handler futures getting garbage collected, thanks to **welo** | Structurally covered |
| 19 | `c25b56db9aaa7e144ae4da48a2256ecfa2a720cb` | Fixed discovered interfaces getting connected as BackboneInterface clients instead of TCPClientInterface on darwin | Structurally covered |
| 20 | `00d57a22eecb7adb775b0f11d48fde21ddc2dc21` | Cleaned up I2P interface and control process code, fixed various i2plib bugs | Needs decision |
| 21 | `0f33d71966b69d5a15819106b53edab4c6cfb355` | Updated documentation | Documentation follow-up |
| 22 | `e46b012e954ef632f68d21fa83a30649182b8233` | Allow loglevels above LOG_DEBUG, cleaned up logging | Partially covered; needs decision |
| 23 | `a29a08716fc76afe9867fd16b61f80b3c79ced1e` | Cleaned up channel class logging and deprecated code | Needs port |
| 24 | `1ecf845ceafd0d0154ea6657a3ea958d7cac944f` | Added set_max_request_size to Destination API | Integrated |
| 25 | `6a761a768cc118e2e70c1f8d76a0563975d78377` | Added max_response_size parameter to Link request API | Integrated |
| 26 | `12c21d4e252d6b49b0e7e0acc5249af77be8f1ec` | Cleanup | Non-runtime upstream test cleanup |
| 27 | `e29b839429b8aa98265a4146d85e888374037c33` | Ensure historical interface discoveries are cleaned according to blackholed identities | Integrated |
| 28 | `224124aac7d1e2aded3c781b783c009419efabf3` | Updated version | Non-runtime |
| 29 | `e5d37355b87e25a7868cdace5b04459091749e5c` | Updated changelog | Non-runtime |
| 30 | `0d16e2305eb2f7f350c1202bc0d3c9764bea1b3e` | Updated documentation | Documentation follow-up |
| 31 | `4631d78beaa1652709b4815a41916a618548baaf` | Adjusted re-balance loglevel | Integrated |
| 32 | `b2188ce9a746a35b770b10bea1b7ccbe93b4e198` | Adjusted gravity update loglevel | Integrated |

## Per-commit analysis

### 1. `48388756` — Release ingress burst state with the correct sample threshold

Upstream changes the announce ingress-control deactivation guard from
`IC_BURST_MIN_SAMPLES` (6) to `IC_DEQUE_MIN_SAMPLE` (2). Requiring six samples
could leave the active flag stuck after a short burst because the announce
frequency deque might never reach the larger threshold without more traffic.

Rust does not reproduce that invariant. `IngressControl::should_ingress_limit`
in `rns-core/src/transport/ingress_control.rs` releases an elapsed, below-rate
burst without requiring a sample count, and `process_held_announces` can clear
the state and release queued announces from the periodic jobs path. The focused
tests already cover elapsed burst deactivation and background held-announce
release. This is more permissive than upstream's two-sample guard but avoids the
deadlock that motivated the commit.

**Disposition:** structurally covered. Add an explicit parity regression named
for the short-burst/no-new-announce case when preparing the 1.4.1 acceptance
record; no production change is currently indicated.

### 2. `b051e76d` — Boundary path requests may search boundary and gateway links

Upstream introduces `BOUNDARY_SEARCH_MODES = [boundary, gateway]`. An unknown
path request arriving on a boundary interface becomes eligible for recursive
discovery, but its egress is restricted to boundary- or gateway-mode
interfaces. Existing access-point, gateway, roaming and internal behavior is
unchanged.

Rust's `handle_discovery_path_request` in
`rns-core/src/transport/path_requests.rs` only admits `DISCOVER_PATHS_FOR` or an
interface with `recursive_prs`; `MODE_BOUNDARY` is not in that constant. Once
admitted, the Rust egress candidate loop has no mode filter. It therefore lacks
both halves of the new behavior.

**Disposition:** needs port. Add the boundary ingress exception and carry an
optional egress mode filter into candidate selection. Cover boundary-to-boundary
and boundary-to-gateway forwarding, rejection toward full/access-point/internal
links, attached-interface exclusion, and ingress/egress rate limiting.

### 3. `1af173e8` — Per-interface `announces_to_internal` override

Upstream adds a tri-state interface field and configuration option. When set to
true on the interface through which an announce arrived, it overrides the
normal boundary-to-internal propagation block. Unset retains the existing mode
matrix; this is not a global permission and does not replace
`announces_from_internal` on the outbound interface.

Rust `InterfaceInfo` contains `announces_from_internal` but no
`announces_to_internal`. `should_transmit_announce` in
`rns-core/src/transport/outbound.rs` unconditionally rejects a boundary-origin
announce for an internal outbound interface.

**Disposition:** needs port. Thread the field through config parsing, interface
registration, dynamic child templates, RPC/ifstats, runtime configuration and
the announce matrix. Preserve the distinction between unset/false and true if
the management surfaces expose upstream-compatible values.

### 4. `bebf211b` — Auto-connected discovery mode and internal propagation

Upstream adds two Reticulum-level settings for automatically connected
discovered interfaces:

- `autoconnect_discovered_mode`, selecting the spawned interface mode; and
- `autoconnect_announces_to_internal`, setting the new override from commit 3.

It also exposes `announces_to_internal` in interface statistics and marks the
mode with `(a>i)` in `rnstatus`. Commit 10 renames the first setting to the final
1.4.1 spelling `autoconnect_interface_mode`; the transitional name should not
be introduced as the primary local option.

rns-rs implements discovery-driven Backbone connectivity through a bounded
peer pool rather than upstream's generic auto-connected interface list. Pool
candidates currently inherit fixed/local defaults, and there are no equivalent
global settings.

**Disposition:** needs decision, then coordinated port with commits 3 and 10.
Define whether these settings apply only to discovery-origin peer-pool members
or to all automatically created discovery interfaces. The final parser should
prefer `autoconnect_interface_mode`; accepting the one-commit transitional
spelling as an alias is optional compatibility policy.

### 5. `9bc73819` — Internal propagation and auto-connect documentation

The source documentation explains `announces_to_internal`, the two initial
auto-connect settings, and links to an external announce-propagation simulator.
Most changed files are generated HTML/Markdown/search artifacts.

**Disposition:** documentation follow-up. Document the local configuration and
propagation matrix after commits 3 and 4 are resolved. Do not vendor generated
upstream manuals. The third-party simulator link is informational and not
required for runtime parity.

### 6. `c10c465c` — Interface gravity field, configuration and status

Upstream gives every interface an integer `gravity`, defaulting to zero, parses
an interface-level `gravity` option, propagates it through programmatic
interface creation, exposes it in ifstats, and displays non-zero values in
`rnstatus`.

Rust `InterfaceInfo` and the node/driver configuration structures have no
gravity field. Adding it affects every static and dynamic interface constructor,
registration/RPC serialization, runtime configuration and status rendering.

**Disposition:** needs coordinated port with commits 8-11, 14 and 32. Treat the
field as a signed integer; positive and negative values are both meaningful.

### 7. `7611fca6` — Permit configured loglevel 8

Upstream fixes a clamp that still capped the configured level at 7 after
`LOG_EXTREME` moved to 8.

rns-rs already accepts Reticulum-compatible levels through 8 as part of the
1.4.0 baseline's pathing-log work. The Rust logger maps those levels to its
targets/filters rather than using the faulty Python integer clamp.

**Disposition:** structurally covered; retain the existing level-8 parser and
filter tests in the 1.4.1 evidence set.

### 8. `5577e781` — Prefer higher-gravity reception of the same announce

Upstream changes path-table selection. When an already known destination
receives the same emitted announce again, ordinary replay/timebase checks would
reject it; the path may nevertheless move to the receiving interface if that
interface's gravity is strictly greater than the current path interface's
gravity. Equal or lower gravity does not replace the path. Normal newer-announce,
expiry, unresponsive-path and hop-count logic remains in force.

Rust's `should_update_path`/`decide_announce_multipath` in
`rns-core/src/transport/pathfinder.rs` has no gravity input. rns-rs also stores a
`PathSet`, so the port must deliberately define how the upstream single-primary
rule interacts with local alternative paths and primary ordering; merely adding
a field to `PathEntry` would be incomplete.

**Disposition:** needs coordinated port. Add same-emission higher-gravity
selection without allowing stale/replayed announces to bypass signature,
timebase or loop protections. Test positive, zero and negative gravity, equal
gravity, lower gravity, different hop counts, unresponsive recovery, and
multi-path primary/alternative behavior.

### 9. `3ca71527` — Dynamic children inherit gravity

Upstream copies parent gravity to spawned Auto, Backbone, I2P, TCP and Weave
peer interfaces. Without this, a configured listener's affinity is lost as soon
as traffic is represented by a per-peer interface.

rns-rs centralizes inherited dynamic metadata in `DynamicInterfaceTemplate` and
its registration flow, which currently carries mode, `recursive_prs`,
`announces_from_internal` and IFAC data but no gravity.

**Disposition:** needs coordinated port in the gravity cluster. Add gravity to
the common template so all dynamic interface implementations inherit it by
construction, with focused listener-child tests for the enabled interface
features.

### 10. `566aa68f` — Complete gravity configuration and final auto-connect name

Upstream adds global `default_gravity` and
`autoconnect_interface_gravity`, applies the global default to interfaces
without an explicit value, and applies the auto-connect value to discovered
connections. It renames `autoconnect_discovered_mode` from commit 4 to the final
`autoconnect_interface_mode` spelling and documents interface gravity as pathing
affinity. Zero is the default; positive values increase affinity and negative
values decrease it.

No equivalent fields exist in `ReticulumSection` or the runtime configuration
schema. The local discovery peer pool makes the auto-connect portion an
architectural choice rather than a mechanical copy.

**Disposition:** needs coordinated port with commits 4, 6, 8 and 9. Parse signed
values, define precedence as explicit interface value over auto-connect/global
default, expose live/startup/reset semantics, and use the final 1.4.1 option
name in local docs and help.

### 11. `889c5ff5` — Sort `rnstatus` by gravity

Upstream accepts `gravity` and `g` as sort keys and sorts the new ifstats field.

Rust `rnstatus` cannot implement this until gravity is serialized in interface
statistics. Its current sort parser and JSON/text renderers have no gravity
surface.

**Disposition:** needs coordinated port at the end of the gravity cluster.
Cover long and short sort names, ascending/reverse behavior, zero/default
values, text rendering and JSON shape.

### 12. `cbf50460` — Link logging guards and level cleanup

Upstream guards eager link log formatting, moves MTU-signalling detail to
`LOG_EXTREME`, and normalizes several messages. There is no link state-machine
or wire-format change.

Rust logging macros already avoid evaluating disabled formatted messages and
the corresponding diagnostics use Rust logger levels. Exact prose and Python's
`RNS.sl()` guards are not compatibility surfaces.

**Disposition:** structurally covered; no port identified.

### 13. `90e1dbb9` — Signed LRPROOF path rebalancing

This is the largest protocol behavior change in the release. Upstream no longer
always discards a link-request proof whose hop count differs from the stored
expectation:

- At a transport relay, if the proof arrives on the recorded next-hop interface,
  its LRPROOF shape and destination signature are validated. For an unvalidated
  link entry, a valid proof updates the link entry's remaining hops and the
  destination path-table hop count, after which normal proof forwarding can
  continue.
- At the initiating terminus, a pending link with an unexpected proof hop count
  validates the signed LRPROOF fields (including mode and optional MTU
  signalling). A valid proof updates the link's expected hops and the
  destination path-table hop count before normal establishment.
- Invalid signatures, shapes, link modes or interfaces do not rebalance.

Rust's transport-relay path currently emits a detailed mismatch diagnostic and
rejects a mismatched-hop LRPROOF. A local pending link is delivered to
`LinkManager`, whose signature validation does not compare `packet.hops`; it can
therefore establish, but it neither records a rebalance nor updates the
engine's expected hops or destination path-table hops. `LinkEntry` also has no
rebalanced state. The relay path has a pre-existing comment that signature
validation is simplified/skipped for normal matched-hop forwarding; the
rebalancing port must not inherit that shortcut for the mismatch exception.

**Disposition:** needs coordinated port with commits 15-17 and 31, high
priority. Centralize LRPROOF parsing/signature validation so the relay and local
terminus use the same exact signed-data rules. Test valid and invalid signatures,
wrong interface, unexpected mode/MTU shape, first versus repeated mismatch,
path-table update, link establishment and multi-hop forwarding.

### 14. `c4297d31` — Lower the initial gravity replacement log level

Upstream changes the new gravity path-replacement message from an unconditional
warning to a guarded debug message. Commit 32 later moves it to `LOG_PATHING`.
There is no selection behavior change.

**Disposition:** gravity-cluster follow-up. Implement only the final
`LOG_PATHING` behavior from commit 32; do not reproduce the transient warning or
debug level.

### 15. `6d4523c2` — Record and limit terminus rebalancing

Upstream adds `Link.rebalanced`, records the first successful terminus
rebalance time, and only updates the destination path-table hop count when the
link has not already rebalanced. This prevents repeated mismatched proofs from
continually rewriting path state.

**Disposition:** needs coordinated port with commit 13. Store an optional
timestamp (not just a boolean) on the appropriate managed link state, and prove
that only the first valid mismatch can change expected/path hops.

### 16. `93526c17` — Make expected-hop mutation first-rebalance-only

This follow-up moves the log and `expected_hops` mutation inside the
`not link.rebalanced` guard. Commit 15 guarded the path-table write but still
changed `expected_hops` repeatedly; commit 16 supplies the intended final
invariant.

**Disposition:** needs coordinated port. Implement the final combined behavior,
not commit 15's intermediate state. A second valid mismatched LRPROOF must not
change the stored expectation or path table.

### 17. `bce5f859` — Avoid false rebalancing signature errors

Upstream suppresses the "invalid signature" message when a relay link entry is
already validated and performs minor comment cleanup. It does not alter packet
acceptance.

**Disposition:** rebalancing-cluster follow-up. Preserve this diagnostic
condition when implementing commit 13 so already validated links are not
misreported as signature failures.

### 18. `a4b61298` — Keep I2P asyncio tunnel tasks alive

Upstream's vendored Python `i2plib` stored connection attempts and proxy tasks
in sets and removes completed background tasks with callbacks. This prevents
unreferenced asyncio tasks from being garbage-collected mid-tunnel. It also
fixes a `ConnectionRefusedError` handler that referenced an unbound exception
variable.

rns-rs does not use asyncio or the vendored Python library. Its I2P coordinator,
outbound loops, acceptor and per-peer readers are OS threads; dropping a Rust
`JoinHandle` detaches a thread rather than cancelling it, and I/O failures are
typed values bound in `match` arms.

**Disposition:** structurally covered. Add or retain a live/mock SAM regression
that keeps concurrent proxy directions active after their spawning function
returns; no direct production port is indicated.

### 19. `c25b56db` — Use TCP clients for discovered endpoints on Darwin

Python treats `BackboneInterface` clients as unsupported on both Windows and
Darwin, so discovered Backbone/TCP server announcements auto-connect with
`TCPClientInterface` on those platforms.

Rust's Backbone client is a native `std::net` implementation without Python's
platform exclusion, and discovery-origin peer-pool candidates use that same
portable client. There is no separate Python-style TCP fallback type required
on macOS.

**Disposition:** structurally covered, subject to a macOS compile/runtime smoke
in the eventual acceptance gates. Do not add an OS-name branch without evidence
that the Rust Backbone transport fails on Darwin.

### 20. `00d57a22` — I2P controller/library cleanup and error handling

This commit is mostly aggressive Python formatting and vendored-library cleanup,
but its observable pieces include clearer SAM setup failures, corrected peer
error diagnostics, explicit fallback logging for unknown I2P errors, socket
shutdown/close cleanup and revised internal log levels. It builds on commit 18's
task ownership fix.

rns-rs owns a separate synchronous SAM v3.1 implementation in
`rns-net/src/interface/i2p/` and does not vendor `i2plib`. Many upstream changes
therefore have no line-for-line equivalent. The current Rust coordinator keeps
the SAM control socket alive, reconnects outbound peers, retries accepts, owns
reader/writer streams and reports typed `SamError`s, but a commit-level audit is
not a substitute for failure-path tests.

**Disposition:** needs decision/evidence rather than a direct port. Diff the
final 1.4.1 SAM command/reply and teardown behavior against
`rns-net/src/interface/i2p/sam.rs`, then test empty/invalid replies, unreachable
peers, duplicate sessions, disconnect cleanup, accept retry and reconnect. Port
only semantic gaps; do not copy Python formatting or vendored code.

### 21. `0f33d719` — Document the final auto-connect mode option name

Upstream changes documentation from the transitional
`autoconnect_discovered_mode` name to `autoconnect_interface_mode`.

**Disposition:** documentation follow-up tied to commits 4 and 10. Local docs
must use the final name if the option is adopted.

### 22. `e46b012e` — `rnsh` high loglevels and initiator logging cleanup

Upstream expands `rnsh` verbosity clamping from critical-through-debug to
none-through-extreme, stops debug-logging raw stdout/stderr payloads, fixes
passing the logfile into initiator setup, and writes initiator logs to an
`.initiator`-suffixed path.

Rust `rnsh` already supports off-through-trace filtering and does not log raw
remote stdout/stderr bytes. It initializes a file logger under the selected
rnsh configuration directory, but both listener and initiator currently select
`logfile`, not the upstream initiator suffix.

**Disposition:** partially covered; needs a compatibility decision. Adopting
`logfile.initiator` would match final upstream behavior but changes the local
operator-visible path. If adopted, update `rnsh_log_path`, migration/operator
docs and path tests; retain the existing no-payload-logging invariant.

### 23. `a29a0871` — Channel receive-window bound and API cleanup

Most of the patch removes the deprecated Python `ChannelOutletBase`, makes
`LinkChannelOutlet` the direct abstraction, guards log calls and reformats the
module. One runtime hardening change is important: in the non-wrap case, an
incoming sequence greater than `next_rx_sequence + WINDOW_MAX` is rejected
instead of being inserted into the receive ring.

Rust already has a native Channel abstraction and needs none of the Python base
class removal. However, `Channel::receive` only calls `is_behind_rx_window`;
that helper rejects old sequences but does not reject an excessively far-ahead
sequence in the ordinary non-wrap case. Such envelopes can accumulate while
the receiver waits for missing sequence numbers.

**Disposition:** needs port, high priority. Implement a modular bounded-forward
distance check and test exact window edge, one past the edge, far-ahead input,
duplicates, ordinary out-of-order delivery, and both sides of the `0xffff -> 0`
wrap. Do not regress the stronger local modular ordering tests.

### 24. `1ecf845c` — Destination maximum accepted request size

Upstream adds `Destination.set_max_request_size()`, rejects negative/invalid
values, checks decrypted packet requests before unpacking/dispatch, and rejects
resource request advertisements whose declared size exceeds the limit. An
unset limit remains unlimited.

Rust request handlers are global/path-indexed in `LinkManager`, and
`LinkDestination` has no maximum request size. Packet requests are unpacked and
resource requests accepted without an application-configured bound.

**Disposition:** integrated. The limit belongs to each registered link
destination and is inherited by incoming links. Packet requests are checked on
the complete decrypted MessagePack payload before decoding or dispatch;
resource requests are checked against their declared uncompressed `data_size`
before any receiver is accepted. The public `Destination` API rejects negative
limits, node registration carries the optional limit into the driver, and the
HTTP destination API accepts `max_request_size`. Tests cover unset, zero,
positive and negative configuration, inheritance, exact packet/resource
boundaries, one byte over, unknown destinations, and ordinary non-request
resources.

### 25. `6a761a76` — Per-request maximum accepted response size

Upstream adds `max_response_size` to `Link.request()` and stores it on the
request receipt. Oversized packet responses fail the pending request; oversized
resource advertisements are rejected before transfer and also fail/remove the
pending request. Both response forms share the same inclusive byte limit.

Rust pending requests currently map request IDs only to optional deadlines.
They do not retain a response limit or an explicit receipt failure reason, and
both packet/resource response paths accept any size allowed by lower transport
limits.

**Disposition:** integrated. Pending request state now retains both its deadline
and optional response limit. `LinkManager` and `NodeHandle` expose compatible
request methods with an optional maximum while their existing methods remain
unlimited. Packet responses are checked before delivery, resource responses are
checked against the advertisement's uncompressed `data_size` before transfer,
and rejection removes the pending request and emits `RequestFailed` with a
typed `ResponseTooLarge` reason through the application callback. Tests cover
unset behavior, exact packet/resource boundaries, one byte over, failure
details, cleanup, and compressed-resource-safe declared-size enforcement.

### 26. `12c21d4e` — Update upstream Channel test outlet type

Upstream changes its Python Channel test double to inherit the surviving
`LinkChannelOutlet` after commit 23 removes `ChannelOutletBase`. There is no
runtime source change.

**Disposition:** non-runtime upstream test cleanup. Local Channel tests use the
native Rust API and should instead gain the receive-window cases identified in
commit 23.

### 27. `e29b8394` — Remove invalid or blackholed historical discoveries

Upstream extends persistent discovery cleanup. Records are removed when they
lack a usable `transport_id` or `network_id`, when either identity is currently
blackholed, or when existing expiry/source/type/address checks fail.

Rust `DiscoveredInterfaceStorage::cleanup` removes stale, unsupported-type and
invalid-address entries but has no access to the transport blackhole set. Its
deserializer rejects malformed identity lengths, yet corrupt files skipped by
`list_unlocked` are not necessarily deleted. Cached discovery candidates can
therefore outlive a later blackhole decision.

**Disposition:** integrated. Discovery cleanup now receives an active-blackhole
predicate from the transport engine and removes records when either their
network or transport identity is blackholed. It also deletes malformed cache
files, including records with missing, empty, or invalid-length identity
fields, instead of silently skipping them forever. Removed cache records are
culled from the discovered Backbone peer pool so they cannot reconnect. The
original predicate-free cleanup method remains available. Tests cover network
and transport blackholes, normal retained records, missing and empty identities,
and corrupt MessagePack; the transport engine's expiration tests ensure expired
blackholes do not match the predicate.

### 28. `224124aa` — Set Python version to 1.4.1

Upstream changes `RNS/_version.py` from `1.4.0` to `1.4.1`.

**Disposition:** non-runtime for Rust crates. Record it as release metadata when
promoting `UPSTREAM.md`; do not change independent Rust crate versions solely
for upstream parity.

### 29. `e5d37355` — Reticulum 1.4.1 changelog

The changelog summarizes path rebalancing, gravity, auto-connect options,
request/response size APIs, boundary path requests, I2P fixes, ingress-control
release, loglevel handling and discovery cleanup. It also restores the 1.4.0
release section.

**Disposition:** non-runtime. Use it as a cross-check against this audit; do not
vendor upstream changelog text. Every listed runtime item maps to commits above.

### 30. `0d16e230` — Regenerate release/API documentation

Upstream regenerates the manual for 1.4.1 and adds API reference entries for
`Destination.set_max_request_size()` and `Link.request(max_response_size=...)`.

**Disposition:** documentation follow-up after commits 24 and 25. Add native
Rust API/operator documentation appropriate to the final local signatures; do
not copy generated HTML, inventory or search-index artifacts.

### 31. `4631d78b` — Move rebalancing diagnostics to debug

Upstream changes the temporary rebalancing log level from warning to debug once
the feature is release-ready. No routing behavior changes.

**Disposition:** integrated. Authenticated rebalancing events now use a named
debug-level policy instead of warning, with a logger-filter regression test to
ensure normal debug configuration exposes the diagnostic.

### 32. `b2188ce9` — Move gravity replacement diagnostics to pathing

The release tag target changes gravity-driven path replacement logging from
debug to `LOG_PATHING`. No path-selection behavior changes.

**Disposition:** integrated. The gravity-only replacement condition is shared
between selection and diagnostics, and accepted replacements emit at trace on
the dedicated `rns::pathing` target (the Rust mapping of `LOG_PATHING`). Tests
pin both the exact gravity predicate and logging target/level. This is the
signed 1.4.1 tag target.

## Proposed integration queue

The order below follows behavioral dependencies rather than upstream commit
order.

1. **Channel and request bounds** — commits 23-25, with commit 26 as upstream
   test-only context. These are bounded-input and receive-state hardening and
   should land with focused adversarial tests first.
2. **Boundary and internal propagation** — commits 2-5 and 21. Implement the
   path-request mode filter and `announces_to_internal`, then resolve how final
   auto-connect settings map to the discovery peer pool.
3. **Gravity** — commits 6, 8-11, 14 and 32. Land data model/config/status
   plumbing before path selection, then dynamic inheritance and `rnstatus`.
4. **LRPROOF path rebalancing** — commits 13, 15-17 and 31. Treat signature
   validation and first-rebalance-only state as one atomic feature.
5. **Historical discovery cleanup** — commit 27, including peer-pool eviction
   and malformed-cache cleanup.
6. **I2P evidence and any semantic fixes** — commits 18-20. Most code is
   structurally different; close the audit with SAM failure-path tests instead
   of importing vendored Python changes.
7. **rnsh logging policy** — commit 22. Decide the initiator filename before
   changing operator-visible behavior.
8. **Release documentation and promotion** — commits 28-30, exact 1.4.1
   fixtures/interop, parity matrix, `UPSTREAM.md`, and only then the accepted
   baseline update.

## Acceptance requirements for eventual 1.4.1 promotion

- Every commit in the 32-row inventory has a final disposition linked to local
  code/tests or an explicit no-action rationale.
- Exact source is the dereferenced signed `1.4.1` tag target `b2188ce9`; verify
  its runtime tree and `RNS.__version__` before fixture generation or interop.
- Focused tests cover Channel forward-window bounds, request/response limits,
  boundary mode filtering, internal announce overrides, gravity selection and
  inheritance, LRPROOF rebalancing signatures/one-shot state, and blackholed
  discovery cleanup.
- Existing 1.4.0 conformance, resource, link, pathing, discovery, I2P, rnsh and
  management tests remain green.
- Regenerate or add 1.4.1 fixtures only from the exact tag target and confirm
  historical fixture byte stability.
- Run exact Python 1.4.1/Rust live interop, workspace tests, feature-specific
  suites, formatting/lint, web UI smoke and required CI topology gates.
- Do not claim physical Weave HIL or dual-VPS manual acceptance unless those
  gates are actually rerun for the completed port.
