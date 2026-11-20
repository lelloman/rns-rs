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
| 1 | `da368e05` | 2026-11-16 | Deduplicate in-flight announce rebroadcasts | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 2 | `aecc1547` | 2026-11-16 | Set sane autoconnect caps | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 3 | `338df096` | 2026-11-16 | Updated docs | Proposed: Non-runtime | Reviewed 2026-11-20; no mapping commit yet |
| 4 | `2b1a984c` | 2026-11-17 | Fixed IFAC identity not being available at early tunnel synthesis | Proposed: Structurally covered | Reviewed 2026-11-20; no mapping commit yet |
| 5 | `25cce0a8` | 2026-11-17 | Ensure transport identity availability before early tunnel synthesis | Proposed: Structurally covered | Reviewed 2026-11-20; no mapping commit yet |
| 6 | `cc5d6dd0` | 2026-11-17 | Logging | Proposed: Structurally covered | Reviewed 2026-11-20; no mapping commit yet |
| 7 | `12b2b8c0` | 2026-11-17 | Updated link tests | Proposed: Non-runtime | Reviewed 2026-11-20; no mapping commit yet |
| 8 | `4916017a` | 2026-11-17 | Abort early on non-enabled link mode | Proposed: Structurally covered | Reviewed 2026-11-20; no mapping commit yet |
| 9 | `48c77061` | 2026-11-17 | Load known destinations over RPC in split mode | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 10 | `f876ed8d` | 2026-11-17 | Show remote transport status on tunnels | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 11 | `0123133e` | 2026-11-17 | Fixed CPython process fork stdin close deadlock | Proposed: Structurally covered | Reviewed 2026-11-20; no mapping commit yet |
| 12 | `05ac4bba` | 2026-11-17 | Added ability to configure destination value and link cost to rngit | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 13 | `833f6cf2` | 2026-11-17 | Fixed path table culling being able to remove an instance's own local destination paths. Doh. | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 14 | `d72cfdd7` | 2026-11-17 | Mark local client paths responsive on PR responses | Proposed: Structurally covered | Reviewed 2026-11-20; no mapping commit yet |
| 15 | `5bd93ad9` | 2026-11-17 | Ensure link-based rediscovery does not occur for instance-local paths | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 16 | `70eb417d` | 2026-11-17 | Fixed non path table resident shared local instance destination path response announces broadcasting on all interfaces instead of requestor only | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 17 | `8c73e203` | 2026-11-18 | Don't rebroadcast on unresponsive path lenient table insertions | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 18 | `4a058544` | 2026-11-18 | Well, yeah | Proposed: Structurally covered | Reviewed 2026-11-20; no mapping commit yet |
| 19 | `8e7dc8b7` | 2026-11-18 | Added medium reliability flag to interfaces | Proposed: Integrated | Reviewed 2026-11-20; no mapping commit yet |
| 20 | `9568b704` | 2026-11-18 | Improved rnpath display and filtering options | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 21 | `c90a5d58` | 2026-11-18 | Added destination type loading | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 22 | `3f55e9eb` | 2026-11-18 | Added flagged destination type map, added per-link traffic counter, added link distribution stats getter | Proposed: Needs coordinated port | Reviewed 2026-11-20; no mapping commit yet |
| 23 | `f7b54ccc` | 2026-11-18 | Added prettynamehash convenience function | Proposed: Non-runtime | Reviewed 2026-11-20; no mapping commit yet |
| 24 | `1a71073c` | 2026-11-18 | Initial rnpath analysis stub | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 25 | `b9903c53` | 2026-11-18 | Analysis mode capture argument | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
| 26 | `1f7cd145` | 2026-11-18 | Cleanup and fixes | Proposed: Needs coordinated port | Reviewed 2026-11-20; no mapping commit yet |
| 27 | `41260ea1` | 2026-11-18 | Added path state info to path table getters | Proposed: Needs port | Reviewed 2026-11-20; no mapping commit yet |
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

**Local handling:** Add `shared_medium` to `InterfaceInfo` (from
`shared_medium_hint`), `packet_hash` and `blocked_interfaces` to
`AnnounceEntry`, record the interface on the reject branch, and carry the set
into the broadcast action. Focused regression:
`an_announce_heard_again_while_waiting_is_not_rebroadcast_to_that_interface`
(sends on {1, 3}, not {1, 2, 3}), plus shared-medium and replacement cases.

**Proposed disposition:** Needs port.

### 2. `aecc1547` — Set sane autoconnect caps

**Upstream change:** `autoconnect_discovered_interfaces` above 12 is clamped
to 12 with warnings, and any value above 6 logs advice to use 2–3.
`autoconnect_discovered_interfaces_disable_caps = yes` turns both off;
because options are read in file order, upstream honours it only when it
appears before the count.

**Rust applicability:** Missing. `common/config/reticulum.rs:344-354` parses
the count uncapped and does not know the disable key. Keys are held in a
`HashMap`, so file order is not available.

**Local handling:** Parse the disable key as a bool, apply the cap and
upstream's warnings where the upstream-policy count is resolved
(`node/startup.rs:237`), nothing under `Pool`. Honour the disable key wherever
it appears and record that as a deliberate deviation. Regression:
`autoconnect_count_is_capped_unless_caps_are_disabled` (20→12, 20 with
disable→20, 7→7, invalid bool is an error). Note: `dev` has since rewritten
config parsing (`19fc22e5`), so the port goes on top of that.

**Proposed disposition:** Needs port.

### 3. `338df096` — Updated docs

**Upstream change:** Documentation only: guidance on how many discovered
interfaces to auto-connect (2–3 typical, up to 12 only in extreme cases), a
getting-started warning, and a reference entry for `get_instance_pid()`.

**Rust applicability:** No runtime change. `docs/interface-discovery.md`
documents the options without sizing guidance. There is no native
`get_instance_pid`.

**Local handling:** Add a short sizing paragraph to
`docs/interface-discovery.md`, mentioning the cap from commit 2.

**Proposed disposition:** Non-runtime.

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

**Local handling:** Add `tunnel_synthesis_carries_the_interface_access_code`
(driver tests) pinning that the synthesis frame is IFAC-masked and is accepted
by a peer with the same IFAC.

**Proposed disposition:** Structurally covered.

### 5. `25cce0a8` — Ensure transport identity availability before early tunnel synthesis

**Upstream change:** Transport identity setup moves into
`Transport.ensure_identity()`, called before interfaces start, so a client
that connects during startup can sign its tunnel synthesis.

**Rust applicability:** The identity is built at `node/startup.rs:461-480` and
assigned to the driver at `:655-656`, before the interface start loop and
before the driver thread handles any interface event.

**Local handling:** Comment the invariant at `startup.rs:655` and add a node
test showing the first frame a dialing TCP client sends is a synthesis signed
by the node's transport identity.

**Proposed disposition:** Structurally covered.

### 6. `cc5d6dd0` — Logging

**Upstream change:** In rnsh's initiator, the "Establishing link with" INFO
log moves before link creation and a DEBUG "No link" line is removed.

**Rust applicability:** `rns-cli/src/rnsh/initiator.rs:52` already logs before
`create_link`; the debug line was never ported.

**Local handling:** A comment at `initiator.rs:52` recording the match.

**Proposed disposition:** Structurally covered.

### 7. `12b2b8c0` — Updated link tests

**Upstream change:** `tests/link.py` waits for links to become active with a
deadline instead of fixed sleeps. Test-only.

**Rust applicability:** No port of `tests/link.py`. Native link tests already
wait with deadlines (`rns-net/tests/e2e.rs:425`, `wait_for_link_established`).

**Local handling:** Doc comment on `wait_for_link_established`.

**Proposed disposition:** Non-runtime.

### 8. `4916017a` — Abort early on non-enabled link mode

**Upstream change:** `Link.__init__` raises immediately when an initiator asks
for a mode outside `ENABLED_MODES` (`[MODE_AES256_CBC]`), instead of failing
later.

**Rust applicability:** The only rns-net initiator path,
`LinkManager::create_link_with_keys` (`link_manager/establishment.rs:36`),
hard-codes `Aes256Cbc`; no public API takes a mode.

**Local handling:** Doc comment at `establishment.rs:36` and a test that an
outbound link request signals AES-256-CBC. Separately, rns-rs as a responder
accepts AES-128 requests (documented in `docs/protocol-spec.md` §11.1) where
upstream rejects them; that predates this range and is listed under Open
decisions.

**Proposed disposition:** Structurally covered.

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

**Local handling:** Serve upstream's dict shape under `known_destinations`
and move the native list to a new name (decision pending), add the client RPC
fallback, and add an interop test where Python 1.6.1 loads known destinations
from an rns-rs instance and can still learn new ones.

**Proposed disposition:** Needs port.

### 10. `f876ed8d` — Show remote transport status on tunnels

**Upstream change:** `rnstatus -T` hides `Tunnel ID` for interfaces that have
clients, and appends `, transport enabled` / `, no transport` to
`Rem.Vers.` from `rem_is_tn`.

**Rust applicability:** `rns-cli/src/rnstatus_view.rs:340-368` prints the
old format. The daemon already sends `rem_is_tn`.

**Local handling:** Port both changes and regenerate the rnstatus fixtures at
`f876ed8d` in a disposable worktree.

**Proposed disposition:** Needs port.

### 11. `0123133e` — Fixed CPython process fork stdin close deadlock

**Upstream change:** On POSIX, `multiprocessing`'s stdin close in forked
children is patched to avoid a deadlock on the buffered-stdin lock.
CPython-specific.

**Rust applicability:** Stamp workers are threads (`rns-net/src/stamps.rs`,
`stamper.rs`). The one `fork` (`rns-cli/src/rnsh/process.rs:151`) only makes
async-signal-safe calls before `execve` and never touches the stdin lock.

**Local handling:** A doc comment in `stamps.rs` recording why the deadlock
cannot occur.

**Proposed disposition:** Structurally covered.

### 12. `05ac4bba` — Added ability to configure destination value and link cost to rngit

**Upstream change:** rngit's `[rngit]` and `[pages]` sections accept
`stamp_value` and `link_cost`. Both destinations now announce a link cost
of 18.0 by default instead of 12.5, which initiators see on the wire.

**Rust applicability:** `rns-git/src/config.rs` has neither key, and
`server.rs` / `pages.rs` announce the default 12.5. `RnsNode::set_link_cost`
and `Destination::set_value` already exist.

**Local handling:** Parse and quantize both keys per section, default link
cost 18.0, apply on registration, keep the value for re-announces, update
`docs/rns-git.md`. The e2e harness may need `link_cost = 0` to keep debug-build
tests fast.

**Proposed disposition:** Needs port.

### 13. `833f6cf2` — Fixed path table culling being able to remove an instance's own local destination paths

**Upstream change:** The "never used" cull skips paths received on a local
client interface, and an accepted announce from a local client marks its path
responsive (refreshing expiry and `used`) instead of unknown. The cull
condition is replaced by commit 15; the responsive marking stays.

**Rust applicability:** Missing. `jobs::cull_path_table` (`transport/jobs.rs:196-206`)
has no exemption, and `process_verified_announce` always clears the path state
(`verified_announce.rs:248`). A shared instance culls a local client's
destination after the unused-path linger.

**Local handling:** Call `mark_path_responsive` after storing a path from an
interface that serves local clients, and exempt such paths in the cull.
Regressions in inbound-engine and jobs tests.

**Proposed disposition:** Needs port.

### 14. `d72cfdd7` — Mark local client paths responsive on PR responses

**Upstream change:** A local client's path response marks the path
responsive. Once commit 13 is in, the same call after the path is stored
already covers it, so this adds no observable change.

**Rust applicability:** Covered by commit 13's port, which marks every
verified announce from a local client, path responses included.

**Local handling:** A test that a local client's path response leaves the
path responsive with `used == now`.

**Proposed disposition:** Structurally covered (after 13).

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

**Local handling:** Hops-0 guards in all three places, replacing commit 13's
exemption, with one focused test each. The rns-rs-only per-destination path cap
(`retention.rs`) can still evict hops-0 paths; to be documented.

**Proposed disposition:** Needs port.

### 16. `70eb417d` — Fixed non path table resident shared local instance destination path response announces broadcasting on all interfaces

**Upstream change:** When a local client's path response answers a pending
path request, it is now sent once, only to the requesting interface, as a path
response; before, it went out as a plain announce on every interface.

**Rust applicability:** Missing. `verified_announce.rs:253-278` discards the
requesting interface and builds the entry with `attached_interface: None,
block_rebroadcasts: false`. The sending side already supports attached path
responses.

**Local handling:** Attach the requesting interface and block rebroadcasts.
Update `only_a_local_clients_path_response_answers_a_pending_request`, which
pins the old behaviour, and add a tick-level test that exactly one path
response goes to the requester.

**Proposed disposition:** Needs port.

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

**Local handling:** A shared predicate for "accepted only because unresponsive"
and a table-insertion-only flag, with
`unresponsive_path_replacement_is_not_rebroadcast`. The new-next-hop
difference is listed under Open decisions.

**Proposed disposition:** Needs port.

### 18. `4a058544` — Well, yeah

**Upstream change:** Crash guards: persistence and the exit handler check that
`Transport.owner` exists before using it.

**Rust applicability:** Persistence is only reachable through a constructed
`RnsNode` (`node/known_destinations.rs:233-249`, called from shutdown), and
shared clients are built without a store, which plays the role of upstream's
shared-instance check.

**Local handling:** A doc comment on `persist_known_destinations`.

**Proposed disposition:** Structurally covered.

### 19. `8e7dc8b7` — Added medium reliability flag to interfaces

**Upstream change:** Adds `Interface.lossless_medium`, true for TCP, Backbone
and I2P interfaces. Nothing reads it yet.

**Rust applicability:** No equivalent. With no reader there is no observable
behaviour.

**Local handling:** Add `lossless_medium_hint` next to `shared_medium_hint`
with a class-defaults test, documented as having no runtime reader yet, or
record only the analysis (decision pending).

**Proposed disposition:** Integrated (decision 6).

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

**Local handling:** Port the flags and quirks, regenerate the parser table,
argparse fixture and golden help at `9568b704`, update the docs and the
interop assertion.

**Proposed disposition:** Needs port.

### 21. `c90a5d58` — Added destination type loading

**Upstream change:** (a) Reads `known_destination_types` and
`flagged_destination_types` files into name maps used only for log text.
(b) Path-table entries gain `interface_hash`, visible over RPC and in
`rnpath -j`.

**Rust applicability:** (b) missing from `path_table_to_pickle`
(`rpc/responses.rs:26-74`); the display name it hashes is already available.
(a) has no consumer beyond logging.

**Local handling:** Add `interface_hash` and extend
`path_and_rate_tables_follow_upstreams_keys_and_types`; record (a) as
deferred until something other than logging reads the map.

**Proposed disposition:** Needs port.

### 22. `3f55e9eb` — Added flagged destination type map, per-link traffic counter, link distribution stats getter

**Upstream change:** Link-table entries count forwarded bytes, and
`link_distribution()` returns
`{dst: {active, pending, traffic, from_ifs}}`. `from_ifs` is a Python set,
which upstream's msgpack RPC cannot encode until commit 26. The type-name
change affects logs only.

**Rust applicability:** `LinkEntry` has no traffic field, and
`link_distribution` returns a locally invented `{total, active}` shape
(`transport/queries.rs:388`, `rpc/responses.rs:6`) with no other consumer.

**Local handling:** Add per-link traffic, return upstream's shape, encode
`from_ifs` as a list of interface hashes (the form commit 26 settles on).
Coordinated with 26, 29, 30 and 32; each still gets its own commit.

**Proposed disposition:** Needs coordinated port.

### 23. `f7b54ccc` — Added prettynamehash convenience function

**Upstream change:** A Python helper `RNS.prettynamehash()` with no caller.

**Rust applicability:** No caller, no wire/RPC/CLI output.

**Local handling:** Analysis only, plus a note in `rns-cli/src/pyfmt.rs`.

**Proposed disposition:** Non-runtime.

### 24. `1a71073c` — Initial rnpath analysis stub

**Upstream change:** Adds `rnpath -A/--analyze`, which fetches the path, rate
and link-distribution tables and prints statistics from private Python state.
Commit 31 replaces the body with "Not yet implemented".

**Rust applicability:** No `-A` in `rnpath.rs`.

**Local handling:** Recommended: port the option, its dispatch position and the
three RPC fetches, and print the final `Not yet implemented`; record the
withdrawn statistics as deferred. Needs agreement because the commit then
shows the tip's output rather than this commit's.

**Proposed disposition:** Needs port (decision 3).

### 25. `b9903c53` — Analysis mode capture argument

**Upstream change:** Adds `--capture`, accepted and ignored. Changes help text
and creates a new ambiguous `--c` prefix.

**Rust applicability:** Missing from the parser.

**Local handling:** Add the option, regenerate parser fixtures and golden help
at `b9903c53`.

**Proposed disposition:** Needs port.

### 26. `1f7cd145` — Cleanup and fixes

**Upstream change:** rnpath metavar fixes (help text only), and
`link_distribution`'s `from_ifs` becomes a de-duplicated list so the RPC can
encode it.

**Rust applicability:** Parser metavars differ; `from_ifs` follows commit 22's
port.

**Local handling:** Regenerate fixtures at `1f7cd145` and add a regression
that `from_ifs` is a list of distinct interface hashes in first-seen order
that round-trips through the msgpack RPC codec.

**Proposed disposition:** Needs coordinated port.

### 27. `41260ea1` — Added path state info to path table getters

**Upstream change:** Path-table entries gain `state`, and `rnpath -t` prints
` (R)`, ` (u)` or ` (?)` after the hop count.

**Rust applicability:** Interop hazard: upstream rnpath reads `path["state"]`
without a fallback, so Python rnpath at this commit fails against an rns-rs
daemon. `path_states` exists in the engine but is not exposed in the table.

**Local handling:** Add a `path_state` getter, the RPC field after
`interface_hash`, and the rnpath marker; extend the key-order and render
tests.

**Proposed disposition:** Needs port.

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
   the native list moves to a separate RPC name.
2. **Commits 22 and 26:** `link_distribution` follows upstream's shape at each
   commit (a set at 22, the de-duplicated list at 26); the native `total` key
   goes.
3. **Commit 24:** the analysis statistics are ported as they are at that
   commit, then 28's guard, then 31's `Not yet implemented`. This brings in
   commit 21's destination-type files as well.
4. **Commit 2:** upstream's order dependence is reproduced: the disable key
   only takes effect when it appears before the count. The parser records key
   order for this.
5. **Commit 12:** default link cost 18.0, and an invalid `link_cost` or
   `stamp_value` is a startup error, as upstream.
6. **Commit 19:** the `lossless_medium` flag is added with upstream's
   per-class values, unread, marked `#[allow(dead_code)]` with the reason.
7. **AES-128 (found via commit 8, pre-existing):** match upstream. Only
   AES-256-CBC is enabled; a responder refuses any other signalled mode.
   Separate commit without an `Upstream-Commit` trailer.
8. **New-next-hop recovery of an unresponsive path (found via commit 17,
   pre-existing):** rns-rs keeps its behaviour by default, the divergence is
   documented, and a runtime `[reticulum]` option selects upstream's
   behaviour. Separate commit without an `Upstream-Commit` trailer.

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
