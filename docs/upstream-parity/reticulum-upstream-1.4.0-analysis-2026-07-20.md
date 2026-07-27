# Reticulum post-baseline integration analysis (2026-07-20)

## Scope

This is an untracked working document. It audits every Reticulum commit in the
range after the accepted rns-rs baseline and through the current tips fetched on
2026-07-20:

- accepted baseline: `cf6010da591e9361e26672b6917081a153f1f2c3`
- GitHub `origin/master`: `122f17fad69a483503cc5c1d8d81046712d78c96`
- rns-git `rgit/master`: `122f17fad69a483503cc5c1d8d81046712d78c96`
- topology: the baseline is an ancestor of both tips, with `0` commits on the
  baseline side and `28` commits on the remote side
- release boundaries in the range: Reticulum `1.3.9` at `bfade970` and
  Reticulum `1.4.0` at `be36abd8`; `122f17fa` is a generated release-artifact
  follow-up after the `1.4.0` tag
- local branch inspected: rns-rs `dev` at `fd21db1`

The word "post-baseline" is deliberate. A commit being in this range does not
mean its behavior is absent from rns-rs: seven local `dev` commits already port
the main 1.3.9 runtime changes, but `UPSTREAM.md` has not yet been advanced.

## Status meanings

- **Integrated**: applicable behavior is present on the inspected rns-rs
  `dev` branch, normally with focused tests.
- **Partially integrated**: the main behavior is present, but a documented or
  compatibility-visible part is still absent.
- **Needs port**: applicable behavior is absent or observably different.
- **Needs decision**: the upstream change targets a subsystem whose local
  persistence/architecture differs enough that a direct patch would be
  misleading.
- **Audited, no action**: the Rust design already avoids the problem or has no
  equivalent behavior to change.
- **Non-runtime**: version metadata, changelog text, or generated artifacts that
  are not independently versioned or vendored by rns-rs.

## Commit inventory

| # | Upstream commit | Subject | Disposition |
|---:|---|---|---|
| 1 | `3a36c367fe0aab76fee96d22f45d31d7633a439b` | Improved resource handling | Integrated |
| 2 | `b95c51b96e94cfd62b6c3bfc5dbca5a0fc1848d3` | Added LOG_PATHING loglevel | Integrated |
| 3 | `cd6911ed537b3ce453da67d43abfb12436e8da3c` | Implemented automated fast-flapping client blocking on BackboneInterface | Integrated |
| 4 | `88833f170b13059c644e28d1d8476e2e748cc943` | Updated documentation | Partially integrated |
| 5 | `d93f9798ae4d12cc901ca627551877e80298e9ce` | Cleanup | Integrated (applicable behavior) |
| 6 | `a5ed0a4321e5fe1348f91b5bb3f99986ca555281` | Improved HDLC handling | Integrated |
| 7 | `13a538168f8c1a9a2b108cf11c0ade56c498c6bd` | Cleanup | Audited, no action |
| 8 | `5081255317bedd1128292b5ed373e349e54a85d8` | Updated logging | Integrated / audited |
| 9 | `ec8d43a548017de41cdf73e7e3eb9844a5d349cd` | Updated rnsh config args to work similarly to other RNS utils | Integrated |
| 10 | `3898d63689ca602c1d9ef0d8877f38e4d7201dc6` | Block fast flapping configuration | Integrated |
| 11 | `3c4ef622cc30d209a5e730ed92ca8e89963a2fe8` | Updated changelog | Non-runtime |
| 12 | `bfade970511cb8b864bb86b99073a4ebed7c21a7` | Prepare release | Non-runtime |
| 13 | `e64d815033cca0eed4393c200d9258ce7438b849` | Fixed link stale teardown due to missing keepalive from initiator side when destination continuously sends packets | Needs port |
| 14 | `2d811dc398ca9cdd8986b3ed2745d703a0a85250` | Updated logging | Needs port (diagnostic only) |
| 15 | `ef9244f79fa35ec0b25d500080fe3583c6000d8b` | Store interface hashes instead of recomputing every time | Needs port (optimization) |
| 16 | `2c9edc43f15cd5cb51d859a2e1182b288113daf1` | Improved backbone interface logging | Audited, no action |
| 17 | `2b79db03c0fa2d3775c45d80212ded682deec9bb` | Added invalid discovery stamp cache | Needs port |
| 18 | `cbba3502b7796cd463e53cacede98b1ebe0bcede` | Optimized transport data persistence to avoid CPU spikes on low-powered systems | Needs decision |
| 19 | `6c6238ce29928dcf44bd3d2508efa30e5e89b225` | Deprecated known destination on-disk recombination on background data persist | Audited, no action |
| 20 | `d8bc20d4cbb8429437274d0c42576d86dd1febce` | Cleanup | Audited, no action |
| 21 | `65274235266cba54b7374eecc5ee236e3d275b15` | Run known destinations cleaning at background priority | Needs port |
| 22 | `f81b2675094c6fee9c1c4d390ad90f74207a4491` | Added blocked IPs list to ifstats | Partially integrated |
| 23 | `fb7479a6f61b0cfb258daeafc995dafd8735ecaf` | Fixed race condition in link watchdog timing | Audited, no action |
| 24 | `032b1aa3b2808dc5aca0aebada0776c8ee7c6b20` | Updated version | Non-runtime |
| 25 | `a5728be421646153bb35d0250cfed2c61b589d7d` | Fixed Backbone fast-flap None-check and exception logging | Audited, no action |
| 26 | `fa4d4c6716d4894aba8ebddbdeec6f8061ade577` | Implemented valid discovery announce caching and sequential validation lock | Needs port |
| 27 | `be36abd85715afd9dd7dccdda29d024d3d0f2353` | Increased default discovery stamp value to 16 | Needs port |
| 28 | `122f17fad69a483503cc5c1d8d81046712d78c96` | Prepare release | Non-runtime |

## Per-commit analysis

### 1. `3a36c367` — Improved resource handling

Upstream hardens malformed resource-advertisement handling, suppresses request
resources when no handler exists, rejects empty hashmap updates, aborts sends on
inactive links, and tightens request/response resource lifecycle cleanup. Much
of the patch is Python formatting, but the lifecycle changes are substantive.

This is integrated by local commit `af2ee6e` (`Port upstream resource handling
hardening`). The Rust port covers advertisement bounds and parse failures,
request/response resource classification, large request resources, empty HMUs,
pending-request cleanup, inactive-link cancellation, split-resource handling,
and focused regressions in `rns-core/src/resource/` and
`rns-net/src/common/link_manager.rs`. The local handling is in several places
stricter than upstream, including explicit malformed-advertisement link teardown
tests.

**Disposition:** integrated; no further work identified.

### 2. `b95c51b9` — Added `LOG_PATHING` loglevel

Upstream inserts numeric level 7 between debug and extreme, moves path-selection
and routing diagnostics to it, and changes extreme to level 8.

This is integrated by local commit `55b8545` (`Port upstream pathing log level`).
The Rust implementation adds Reticulum-compatible numeric levels, a dedicated
pathing log target/filter, config validation through level 8, daemon and
`rns-git` logger integration, and routing/pathing call-site changes with tests.

**Disposition:** integrated; no further work identified.

### 3. `cd6911ed` — Automated Backbone fast-flap blocking

Upstream tracks short-lived inbound Backbone connections by IP, blocks an IP
after its grace count, expires blocks, exposes a blocked count in interface
stats, and adds listener configuration defaults.

This is integrated by local commit `e7819ae` (`Port upstream Backbone fast-flap
blocking`). The Rust port has a shared process-wide monitor, pre-allocation
rejection, expiry, configurable threshold/grace/block duration, peer-state and
`rnstatus` exposure, RPC serialization, and unit/live-socket regressions.

The later upstream correction in `3898d636` is also covered by this same local
commit: disabling the feature disables tracking, blocking and reporting.

**Disposition:** integrated; the later `f81b2675` list field is handled
separately below.

### 4. `88833f17` — Fast-flap documentation

The source change documents why automatic blocking exists and the four
Backbone listener settings with their defaults:
`block_fast_flapping`, `fast_flapping_block_time`,
`fast_flapping_threshold`, and `fast_flapping_grace`. Most other files in the
commit are generated manuals.

The runtime and parser are integrated by `e7819ae`, but the local Markdown docs
do not currently explain these operator-facing knobs. rns-rs should not vendor
the generated HTML/PDF artifacts; it should add concise native documentation to
the appropriate Backbone/operator page.

**Disposition:** partially integrated; add local operator documentation.

### 5. `d93f9798` — `rnsh` cleanup and authorization hardening

Despite the generic subject, the important change introduces explicit
`authenticated` and `terminated` session invariants. It prevents commands from
starting before authentication or after termination, stops rejected identities
from continuing to the version state, and rejects protocol messages in invalid
states. The remainder is an `rnsh` Python version bump, dead-comment removal,
and formatting.

The security-relevant behavior is integrated by local commit `326ac55`
(`Harden rnsh session authorization invariants`) with focused Rust tests. Python
`rnsh` package version metadata and formatting are not local compatibility
surfaces.

**Disposition:** integrated for all applicable behavior.

### 6. `a5ed0a43` — Improved HDLC handling

Upstream bounds decoded TCP/Backbone HDLC frames to values strictly greater
than `HEADER_MINSIZE` and no greater than `HW_MTU + IFAC size`, drops oversized
unterminated buffers, reports invalid frame lengths, and recovers for the next
frame.

This is integrated by local commit `8d5129f` (`Port upstream bounded HDLC
handling`). The Rust decoder has explicit Reticulum bounds and diagnostics and
is wired into Backbone client/server and TCP client/server paths with lower,
upper, IFAC, fragmentation, oversized-tail, and recovery tests.

**Disposition:** integrated; no further work identified.

### 7. `13a53816` — Guard one pathing log call

Upstream avoids formatting/emitting the fast-flap rejection message when
`LOG_PATHING` is disabled.

Rust pathing calls use the `log` facade's dedicated target and are filtered by
the logger added in `55b8545`; the fast-flap rejection site is already a pathing
`trace!` call. There is no eager equivalent that needs a separate guard.

**Disposition:** audited, no action.

### 8. `50812553` — Discovery and persistence logging

Upstream changes an invalid discovery-stamp message to include the calculated
stamp value and moves successful known-destination persistence messages from
verbose to debug.

The discovery diagnostic is integrated by local commit `733a432` (`Align
discovery stamp diagnostics`) with a focused assertion. The Rust persistence
path only logs failures, not the upstream success messages, so there is no
success-log level to move.

**Disposition:** applicable discovery part integrated; persistence logging
part has no local equivalent and needs no action.

### 9. `ec8d43a5` — Separate `rnsh` and Reticulum config directories

Upstream changes `--config/-c` to select the `rnsh` application directory,
adds long-only `--rnsconfig` for the Reticulum directory, moves identities,
allowlists and logs under the selected `rnsh` directory, and updates help/docs.

This is integrated by local commit `fd21db1` (`Port upstream rnsh config
directory split`). It includes explicit path resolution, identity migration
warning without copying private keys, allowlist/log relocation, CLI boundary
tests, and updated local help text.

**Disposition:** integrated; no further work identified.

### 10. `3898d636` — Respect disabled fast-flap configuration

Upstream fixes the initial fast-flap implementation so a listener with
`block_fast_flapping = no` neither records new flaps nor reports/blocks stored
ones.

Local `e7819ae` implemented the corrected behavior directly and includes a
`disabled_fast_flapping_neither_tracks_nor_blocks` regression.

**Disposition:** integrated.

### 11. `3c4ef622` — Reticulum 1.3.9 changelog

The changelog describes the `rnsh` security fix and config migration, fast-flap
blocking, resource hardening, internal discovery and location commands, and
`LOG_PATHING`.

The applicable runtime items are accounted for by the local commits above and
the already accepted `cf6010da` baseline. rns-rs records upstream handling in
parity documents instead of copying Reticulum's changelog.

**Disposition:** non-runtime; do not vendor.

### 12. `bfade970` — Prepare Reticulum 1.3.9 release

This tagged commit (`1.3.9`) refreshes generated `rnsh` manual outputs. It has
no source/runtime delta beyond `ec8d43a5`.

**Disposition:** non-runtime generated artifacts; do not vendor.

### 13. `e64d8150` — Keepalive during continuous one-way traffic

Upstream fixes a real link-liveness bug. An initiator now sends a keepalive when
either inbound traffic has been quiet for a keepalive interval **or its own
outbound traffic has been quiet for that interval**. This prevents a destination
that continuously sends data from declaring the otherwise silent initiator
stale. The destination also avoids an unnecessary keepalive reply if it has
sent other outbound traffic recently.

The current Rust `LinkEngine::needs_keepalive()` checks only
`last_inbound + keepalive_interval`; continuous destination-to-initiator traffic
therefore suppresses the initiator's keepalive even when `last_outbound` is old.
The Rust manager also uses a simplified symmetric empty keepalive packet rather
than explicitly modelling upstream's initiator probe (`0xff`) and destination
reply (`0xfe`) behavior.

**Disposition:** needs port, high priority. Add a regression that advances a
live link through more than one keepalive interval while only the destination
sends application traffic, and assert that the initiator emits the keepalive
needed to keep the destination active. Review probe/reply payload and responder
suppression semantics as part of the same change.

### 14. `2d811dc3` — Link-proof hop-mismatch diagnostic

Upstream expands one debug message to include remaining hops, next-hop
interface and receiving interface instead of printing the wrong single index.
There is no routing behavior change.

Rust correctly refuses LRPROOF routing when the receiving interface/hop
conditions do not match, but `route_via_link_table()` currently returns `None`
without an equivalent detailed diagnostic.

**Disposition:** needs port only for diagnostic parity; low priority. Add a
pathing/debug message at the caller where the `LinkEntry` and ingress interface
are both available, without changing routing behavior.

### 15. `ef9244f7` — Cache interface hashes

Upstream caches `SHA-256(str(interface))` on the interface object instead of
recomputing it on every `get_hash()` call. Interface identity strings are stable
after construction, so this is an allocation/CPU optimization with no wire
change.

Rust currently recomputes `full_hash(info.name.as_bytes())` in
`TransportEngine::synthesize_tunnel()`. The call frequency is much lower than
upstream's general `get_hash()` use, and other local interface bookkeeping uses
stable numeric `InterfaceId`s, so the performance impact is limited.

**Disposition:** needs port as a low-priority optimization. If implemented,
store a stable hash in `InterfaceInfo` or compute it when registering the
interface and use it for tunnel synthesis; add a test locking the hash to the
interface name.

### 16. `2c9edc43` — Suppress expected Backbone socket errors

Upstream suppresses additional string-matched errors (`No route to host`,
`Broken pipe`, and bad-file-descriptor shutdown cases) during disconnect races.

Rust does not use the Python epoll exception/logging paths. Poller deletion and
socket shutdown during cleanup intentionally discard errors, while write/read
errors are returned or handled through typed `io::Error` paths. There is no
matching noisy string-based exception handler.

**Disposition:** audited, no action.

### 17. `2b79db03` — Cache invalid discovery stamps

Upstream keeps the hashes of the last 2048 invalid discovery payloads. Repeated
reception of a known-invalid announcement then avoids the expensive stamp
workblock/value/validation calculation.

Rust's `parse_interface_announce()` is stateless and repeats the full stamp
calculation for every copy. The existing general announce signature cache does
not replace this cache: it covers announce signature validation, while this
commit protects the separate discovery-stamp work.

**Disposition:** needs port, high priority for CPU-constrained and hostile
networks. Put bounded discovery-validation state at driver/handler scope, key it
from the same post-flag discovery payload bytes as upstream, cap it at 2048, and
test that repeated invalid payloads do not re-run stamp validation. Coordinate
this with `fa4d4c67` rather than building two independent caches.

### 18. `cbba3502` — Low-priority transport persistence

Upstream changes several persistence hot paths:

- packet hashes are stored as fixed-width raw 32-byte records in
  `packet_hashlist.raw`, only for transport nodes;
- background packet-hash, path-table and tunnel-table saves yield after roughly
  10 ms of work;
- path persistence snapshots active interface hashes instead of repeatedly
  searching all interfaces;
- save-in-progress flags are reset with `finally`.

The current Rust node has an in-memory packet hashlist and path/tunnel tables,
but repository-wide inspection finds no persistence for the packet hashlist,
path table or tunnel table. `RnsNode` persists known destinations separately at
shutdown. This means the new upstream optimization cannot be directly ported:
the underlying persistence surface is absent. It also conflicts with the broad
"paths, tunnels" persistence claim in `docs/upstream-parity/reticulum-1.3.8-parity.md`, which
should be reconciled.

**Disposition:** needs an explicit design decision. For strict persistence
parity, first add restart-compatible packet-hash/path/tunnel persistence and
then make snapshot serialization incremental or worker-based, with atomic file
replacement and restart/corruption tests. If those tables are intentionally
ephemeral in rns-rs, record that as a deliberate parity exception and treat
this optimization as not applicable. Do not claim this commit integrated merely
because known destinations are persisted.

### 19. `6c6238ce` — Stop recombining known destinations from disk

Upstream changes background known-destination saves to overwrite from the
authoritative in-memory table rather than loading and merging the on-disk table
while saving. This removes file work and lock contention and is safe because
shared clients no longer write the authoritative file.

Rust loads the file during startup and later atomically writes a snapshot of its
authoritative in-memory map. It has no recombine-on-save path and does not let a
shared client merge the file during persistence.

**Disposition:** audited, no action; Rust already has the intended ownership
and overwrite behavior.

### 20. `d8bc20d4` — Remove deprecated recombination code

Upstream removes the commented recombination implementation and warns if a
caller still passes `recombine=True`.

Rust has neither the recombination behavior nor a public `recombine` argument.

**Disposition:** audited, no action.

### 21. `65274235` — Lower-priority known-destination cleaning

Upstream runs scheduled known-destination cleanup in a background thread,
yields once per destination, refreshes the scheduling timestamp during work,
and logs completion. The goal is to keep large identity/ratchet tables from
causing foreground CPU and lock stalls.

Rust performs known-destination retention/cap cleanup and ratchet-store cleanup
synchronously inside the single driver tick in `rns-net/src/driver/events.rs`.
The tables are bounded, but a full scan plus filesystem-backed ratchet cleanup
can still lengthen a tick on constrained machines. Sleeping in the driver loop
would be incorrect; the Rust analogue should be incremental batches across
ticks or a carefully owned worker snapshot/result handoff.

**Disposition:** needs port, medium operational priority. Add a deterministic
large-table test proving cleanup is split into bounded batches while eventually
removing the same stale destinations/ratchets and preserving active, used and
retained entries.

### 22. `f81b2675` — Blocked IP list in interface stats

Upstream adds `blocked_ip_list` alongside the previously added `blocked_ips`
count in `ifstats`.

Rust already exposes the count in `SingleInterfaceStat.blocked_ips` and exposes
detailed IP-addressed `BackbonePeerStateEntry` records through a separate
management/RPC query. It does not serialize `blocked_ip_list` in the standard
Reticulum-compatible interface-stats object.

**Disposition:** partially integrated. No information is lost through the
local management API, but strict `ifstats` RPC compatibility needs an optional
IP list field, pickle serialization, and focused RPC tests. Low priority unless
an upstream consumer specifically expects the new key.

### 23. `fb7479a6` — Link-watchdog timing race

Upstream takes one `now` sample and reuses it for stale comparison and sleep
calculation. Previously, two `time.time()` calls could straddle a boundary and
produce a negative sleep, tearing down an otherwise valid link.

Rust's `LinkEngine::tick(now)` receives one timestamp from the driver and uses
that value for all decisions. It has no watchdog sleep calculation and no
second wall-clock read in the state transition.

**Disposition:** audited, no action; the Rust state machine is structurally
immune to this Python race.

### 24. `032b1aa3` — Version 1.4.0 metadata

This changes only Python `RNS.__version__` from `1.3.9` to `1.4.0`.
rns-rs crates are versioned independently and are not bumped for upstream
Python release markers.

**Disposition:** non-runtime; update parity metadata when the runtime queue is
accepted, not Cargo package versions.

### 25. `a5728be4` — Backbone None-check and exception logging fixes

Upstream guards fast-flap teardown when a dynamic client has no parent
interface, fixes a bare `except` handler that referenced an undefined exception
variable, and suppresses expected epoll deregistration errors.

Rust passes fast-flap configuration/state explicitly into client cleanup; it
does not dereference a nullable parent interface. Poller deletion intentionally
discards teardown-race errors, and Rust's typed error bindings cannot reproduce
the undefined Python exception variable.

**Disposition:** audited, no action; the affected failure modes are absent in
the Rust design.

### 26. `fa4d4c67` — Cache valid discovery validation and serialize expensive work

Upstream adds a bounded 2048-entry cache for previously validated discovery
payloads and permits only one stamp validation at a time; a concurrent incoming
discovery announce is dropped while validation is busy. Together with
`2b79db03`, this prevents repeated or parallel stamp work from overwhelming
small CPUs.

Rust discovery dispatch runs on the single driver thread, so validation is
already sequential and does not need a mutex. However, both valid and invalid
payloads are recomputed every time, and expensive validation currently blocks
the driver while it runs. A cache is therefore still applicable; an async/drop
policy should only be added if measurement shows one validation can starve the
driver.

**Disposition:** needs port, high priority together with `2b79db03`. Prefer one
bounded cache keyed by full discovery payload hash and storing the validated
parse result or invalid outcome. Test valid and invalid hits, FIFO/capacity
eviction, and changed-payload misses. Preserve the current single-owner driver
model unless a benchmark justifies worker offload.

### 27. `be36abd8` — Increase default discovery stamp value to 16

This tagged `1.4.0` commit changes the default discovery stamp requirement and
generation cost from 14 to 16.

rns-rs still defines `DEFAULT_STAMP_VALUE` as 14 and uses it for both discovery
generation and the default acceptance threshold. With upstream 1.4.0 defaults,
an rns-rs discovery announcement generated at value 14 can be rejected by an
upstream peer requiring 16.

**Disposition:** needs port, high priority and small scope. Change the default
to 16, update the stale `default: 14` API comment and affected tests, retain
explicit configuration overrides, and add interop coverage showing a default
rns-rs announcement is accepted by the exact 1.4.0 runtime.

### 28. `122f17fa` — Post-tag release artifact refresh

This changes generated manual HTML/search/build metadata after the `1.4.0` tag.
It has no source/runtime delta.

**Disposition:** non-runtime generated artifacts; do not vendor.

## Proposed integration queue

### Priority 0 — compatibility and liveness

1. Port `e64d8150` keepalive/outbound-idle behavior and add unilateral-traffic
   liveness coverage.
2. Port `be36abd8` default discovery cost 16 and exact-1.4.0 interop coverage.
3. Port `2b79db03` and `fa4d4c67` as one bounded discovery-validation cache,
   with repeat-work and capacity tests.

### Priority 1 — constrained-node operational behavior

4. Make known-destination/ratchet cleanup incremental or worker-backed for
   `65274235`.
5. Decide whether packet-hash/path/tunnel persistence is required. If yes,
   implement the missing persistence surface and the low-priority serialization
   behavior from `cbba3502`; if no, document the parity exception and correct
   the existing broad persistence claim.

### Priority 2 — observable and documentation parity

6. Add the fast-flap operator documentation represented by `88833f17`.
7. Add `blocked_ip_list` to compatible interface stats for `f81b2675` if strict
   upstream RPC parity is required.
8. Add the LRPROOF mismatch diagnostic from `2d811dc3`.
9. Cache interface hashes for `ef9244f7` if profiling justifies it, or record
   the lower-frequency Rust call pattern as the reason to defer it.

## Baseline promotion gate

Do not advance `UPSTREAM.md` to Reticulum 1.4.0 solely because the raw 28-commit
range has been enumerated. Promotion should require:

- every **Needs port** row above to become implemented or explicitly deferred;
- the `cbba3502` persistence decision and parity-document correction;
- focused tests for all ported behavior;
- exact-commit fixture/interop review against at least the `1.3.9` release
  commit and the `1.4.0` tag;
- the normal workspace, native-hook, TLS, lint/format, release/ARM, Docker and
  manual-backbone acceptance gates used by the prior baseline promotions.
