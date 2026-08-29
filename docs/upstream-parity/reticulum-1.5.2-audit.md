# Reticulum 1.5.2 Upstream Audit

## Scope and Baseline

- audit date: `2026-08-29`
- previous accepted version: `1.5.0`
- previous normative commit: `d80245b62c7169f68995b2f11b30b971de7a5dbf`
- target version: `1.5.2`
- target tag or ref: `1.5.2`
- target normative commit: `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6`
- target root tree: `c2471478c17f2723a7dd6eabd0b85942c9402baf`
- target `RNS` tree: `926167c7552b5bb538ff46cdd19b3ee2d16827b3`
- version assertion: `RNS.__version__ == "1.5.2"`
- audited range: `d80245b62c7169f68995b2f11b30b971de7a5dbf..ea98db4f53dcf0defc0e71a16e60d28b1229c4e6`
- commits in range: `48`
- repositories checked: normative rgit repository and `https://github.com/markqvist/Reticulum`
- local branch and revision inspected: `rns-rs-baseline@d80245b62c7169f68995b2f11b30b971de7a5dbf`, with target inspected through `rgit/master`

Both remotes were refreshed successfully on 2026-08-29 and agree at the tagged
`1.5.2` commit `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6`, 48 commits ahead of the
accepted baseline.

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

Every commit in the audited range appears once. The review found three coupled
implementation groups: Backbone dataplane ingress gating, HDLC/transmit-buffer
efficiency, and dataplane egress control.

| # | Upstream commit | Subject | Final disposition | Local evidence |
|---:|---|---|---|---|
| 1 | `de76b8939fb7e73e0b0c681623d1177d422492b7` | Added dataplane ingress control | Integrated | Local `b953832`; accepted Backbone peers now account production, gate the busiest readable socket at DATA pressure, and release it after queue recovery and its calculated hold |
| 2 | `3b7cfc066689b540ca306f06c3aff68fd9d09f1a` | Cleanup | Non-runtime | Local `9f5edb3`; threshold initialization remains silent and native routing retains one authoritative link table, with no secondary forwarding cache |
| 3 | `1a16fdb727da242a3c258c3566c0994240eeaf85` | Fixed inbound queue high-water mark initialization order | Integrated | Local `a4b426e`; the Backbone poll loop derives and fixes all ingress watermarks from the configured DATA capacity before registering its listener or accepting peers |
| 4 | `419956bada9a21d082b9faf54cc83a4a99e16057` | Over-optimization is the root of all evil | Structurally covered | Local `925413f`; native accepted peers keep read polling independent from a cloned writer, and the strengthened async-writer regression proves queued output progresses without another send trigger |
| 5 | `bafc09d3a6e61137cd5e302314d8ce710af4c28d` | Cleanup | Non-runtime | Local `360f095`; records that the native standalone client's blocking socket is deliberately split between a dedicated reader thread and cloned writer path |
| 6 | `54a919f04564cb0e9bcc291a558ab8aad403cb95` | Added optimized HDLC implementation | Integrated | Local `a513526`; the shared native decoder now uses a consumed offset with half-buffer compaction, preserves unknown escape pairs, and covers a 20,000-frame coalesced flood |
| 7 | `ac9130f01fff37d25a60c7984d94ace32f1e26fc` | Added coalesced transmit test | Integrated | Local `f1fd1a3` adds the 50,000-frame ordered async-writer burst; the entry 8 buffer tests complete the chunk, partial-write, tail-release, and accounting contract |
| 8 | `0ec84c7491433b25031741988382646489767d1b` | Added coalescing transmit buffer | Integrated | Local `257e162`; a standalone native buffer coalesces below 64 KiB, isolates larger frames, resumes partial writes, releases its tail, and accounts bytes, frames, and chunks |
| 9 | `89e73db94aacc1d7f83fb921438fe90c913b5bbb` | Wired coalescing transmit buffer and optimized HDLC deframer into Backbone and Local interfaces | Integrated | Local `ce58265`; async writers batch queued frames, Backbone and Local socket writers drain coalesced on-wire chunks, and partial Backbone writes resume without duplicate enqueue |
| 10 | `10848b7cffdaf4f604c6899ed9af1db731e0524b` | Added egress control HWM limiter test | Integrated | Local `f541abe` stages drain/reopen accounting; entries 11 and 12 complete the hard valve, exact async admission budget, drop gate, hysteresis, and dead-peer scenarios |
| 11 | `cb9071b478ff54daae210f91796c19b8a54da129` | Added HWM limit option to TransmitBuffer | Integrated | Local `7106de0`; optional byte-limited append atomically rejects any frame that would cross the bound, leaves state unchanged, and admits again after drain |
| 12 | `99c428a9f5406560a8ae7247630b2947eba8cc8d` | Added dataplane egress control | Integrated | Local `2ac7733`; Backbone and Local HDLC writers share an exact 4 MiB queued/in-flight byte budget, admission drops while gated, and accepted Backbone peers apply the upstream drain-rate hysteresis and dead-peer policy |
| 13 | `281c47f3e0998527c22aaf66017b606b91cda5f7` | Fixed invalid reference in exception description | Structurally covered | Local `136a2d2`; AES-128 and AES-256 constructors accept only fixed 16-byte and 32-byte array references, so invalid key lengths and an unavailable instance reference are unrepresentable |
| 14 | `de0dac695b4fcb19550824b7b8d4cebd8fdb9aa1` | Fixed missing exception reference | Structurally covered | Local `fb23eeb`; egress evaluation is writer-owned and its typed Rust errors cannot lose a dynamically scoped exception binding |
| 15 | `79cad39e7835a24b74d49c92e1caeea82550a9ad` | Fixed missing import | Structurally covered | Local `df857f3`; native retry/logging dependencies resolve statically and rns-rs has no Python rnsh module-global `RNS` binding |
| 16 | `0a1b9453b278efc537c03ae424f952183b3b66f0` | Fixed non-epoll backend keepalive | Structurally covered | Local `bf4a6fb`; the physical keepalive loop passes a literal empty payload to the shared writer and its focused test observes exactly two HDLC flags |
| 17 | `e71c01959f1b055ca141570d25862a7ec59212df` | Fixed stray non-imported variable | Structurally covered | Local `7835313`; rns-rs ships no rnir binary and therefore exposes neither its broken `--exampleconfig` option nor the undefined value |
| 18 | `67a45ac5e9a32cfca5c7fd26c797db185400bb54` | Fixed nav init order | Structurally covered | Local `1a042a7`; the release page resolves `latest` before constructing output, and the regression pins the resolved tag in both breadcrumb and heading |
| 19 | `803b54895186d0396c71dcee57a640351ca9721e` | Allow loading compiled modules | Non-runtime | Local `9d0da01`; Python/Cython mirror compilation, extension loading, and package globbing do not apply to statically resolved and linked Rust crates |
| 20 | `ff3a72209e5001eb8ecaec836ea4e6c8a80d09f7` | Avoid rebind of exception reference | Structurally covered | Local `6f09d8a`; native persistence uses distinct lexical `io::Error` values, so cleanup cannot erase an outer serialization failure |
| 21 | `d32ba8c1a17d2b244bc201b2c0cbcda4f7a1d7c1` | Fixed inconsistency against advertised return type | Structurally covered | Local `1d28228`; fixed-width identity constructors return `Self` directly, eliminating fall-through `None` or mismatched boolean contracts |
| 22 | `75cbc73f64f3d1d020b7e86ec12f6fd0f3cfdca3` | Removed dead Python 2 code from umsgpack | Non-runtime | Local `55ec0c2`; removes Python 2 pack/unpack branches and aliases from vendored `umsgpack.py`, which native MessagePack does not vendor or execute |
| 23 | `e714c559cc00ce4d7abc232a86a62d5d3b5c7376` | Updated tests init | Non-runtime | Local `94d2b21`; switches upstream tests between CRNS compiled and interpreted imports via `RNS_COMPILE` and prints the Python mode, without a native surface change |
| 24 | `ae0191578f2ce439e209b8982af7ae033e954e2f` | Updated Cython dev shim | Non-runtime | Local `67f054d`; parallelizes CRNS compilation, stamps directives/ABI, rebuilds stale modules, and narrows fallback, with no Cargo/rustc shim counterpart |
| 25 | `5fdd661081893cd5b5ce90662ca0ddf40a9c41ad` | Updated makefile | Non-runtime | Local `3752fff`; adds `build_native` and `native` targets around `setup.py --native`, while Rust uses Cargo and gains no runtime or packaging behavior from them |
| 26 | `5b04a880268f8f4e1d136e43dba10b74f1713516` | Updated makefile | Non-runtime | Local `2d8613a`; extends upstream `clean` with generated C-file paths for Python/Cython packages, which do not exist in the Cargo workspace |
| 27 | `3543dc980213770155e86b5d209bfb387fbfc407` | Load module compilation status from buildinfo if available | Non-runtime | Local `d886156`; prefers generated `RNS._buildinfo.compiled` with Cython fallback, while Rust build identity is compile-time Cargo metadata rather than a Python flag |
| 28 | `b7fe01237d8189c54931cdd302d9835e81f55440` | Updated setup.py | Non-runtime | Local `f0f1b2e`; adds Cython discovery/exclusions, compiler flags, stripping, build info, and `--native` wheel plumbing, while Cargo packaging remains independent |
| 29 | `fa07c8c87c33d2408e9560e1e8367cab1991b85c` | Updated setup.py | Non-runtime | Local `03bf58d`; refines native-wheel exclusions to explicit utility modules and adds rnpath, rnprobe, rnstatus, and `_version`, without changing Rust artifacts |
| 30 | `dc9cf0c2f4f3432283148abc82146301682aaf99` | Updated setup.py | Non-runtime | Local `2bbeb80`; changes the Cython native-wheel default from `-Os` to `-O3`, while Rust optimization profiles are independently defined by Cargo |
| 31 | `77c8256a1a8f8e638ff50906b7aa00f6bd450a0a` | Fixed invalid prefix stripping in rngit page server | Integrated | Local `f1bf5ce`; blob paths remove only one exact `./`, retain dotfiles and other leading dots, normalize inner `/./`, and leave absolute paths for rejection |
| 32 | `b28f5ebf7a4fbedbbedafd539d9d33d2f1992a9e` | Allow inbound queue utilization in drainer benchmarks | Non-runtime | Local `4b0aad3`; benchmark pacing waits to `target - 800`, leaving most of an assumed 1024-entry queue occupied without changing production or native acceptance limits |
| 33 | `6e8c976421748584b10cf964bfede577370aebd7` | Worker spawn prep | Structurally covered | Local `5943fbc`; introduces `TRANSPORT_WORKERS = 1` and a one-iteration spawn loop, while native queue workers already have explicit single-owner lifecycle |
| 34 | `9878b1837726109a3a9a5b4e59db067a3e40ca7a` | Added transmit buffer, TX drops and stalled status output to rnstatus | Integrated | Local `1a36ad6`; exact queued/in-flight HDLC bytes, drop frames/bytes and stall state flow through local and remote status, aggregate Backbone peers, and rnstatus rendering/sorts |
| 35 | `c1d7c12b52117cc4c81cb87632556069ef8f878b` | Fixed stream-based resource initialized transfer failing when total sized happened to not fall withing MAX_EFFICIENT_SIZE | Structurally covered | Local `368eb76`; native declared-length streaming reduces only the first segment capacity for metadata, and an exact data-limit regression proves the resulting two-segment plan |
| 36 | `ccc5468bcc65842f9c44c8d80249df7645033297` | Updated changelog | Non-runtime | Local `e61b701`; adds the 1.5.1 release narrative and moves unchanged signed-retrieval instructions; compatibility claims remain inventory context, not acceptance evidence |
| 37 | `53ed9c1ed3fd10b4cba477c00786e17d7f1d4a95` | Updated version | Non-runtime | Local `4ab552b`; changes only Python package metadata from 1.5.0 to intermediate 1.5.1; native crate versions remain independently released |
| 38 | `149e4151095adf098b8f53eab0c03b37169e8559` | Prepare release | Non-runtime | Local `25abe40`; regenerates 1.5.1 docs, fixes documented queue defaults to 1024/128/128/8, and changes no runtime; native defaults are verified from code/tests instead of vendored generated output |
| 39 | `4eebf0b685322c9240d07e545fb5585e4dfcc16d` | Guard empty keepalive frames | Integrated | Local `c2ee65f`; HDLC readers already discard empty flag pairs and raw UDP now ignores zero-length datagrams while delivering the following non-empty frame |
| 40 | `6bc0481cdfbd691bc0b5e401da4ad256c2fee42a` | Always remember to flush | Structurally covered | Local `ae0ddb0`; native declared-length streaming reads the source directly without a buffered proxy to flush/rewind, while receive files are synced before publication |
| 41 | `5b4117dadc3a0ef6deffb87efbe039d1b77f966a` | Skip local shared instance interfaces in ingress/egress control | Integrated | Local `3a10336`; Local shared-instance writers retain HDLC coalescing but expose no egress-control budget/gate, and Local ingress was already outside the Backbone-only controller |
| 42 | `943771a3f9cf2318401aa469fa42093e01b2d126` | Updated version | Non-runtime | Local `37ecca6`; changes only Python package metadata from 1.5.1 to the audited 1.5.2 target; native crate versions remain independently released |
| 43 | `83a30b187adfef6fa4454dddd940082180be6a7f` | Tuned dataplane control defaults | Integrated | Local `723077e`; Backbone ingress high/mid/low watermarks now derive as 90/68/10 percent, with exact default/small-capacity and live gate/release regressions |
| 44 | `d5b2fc56094cadba6bf660d2422c67aa93112383` | Updated changelog | Non-runtime | Full diff review: adds the 1.5.2 maintenance-release narrative and moves unchanged signed-retrieval instructions; its three compatibility claims are verified from source entries 35, 39 and 43 |
| 45 | `a3cd84111fd5f1bac7afa935edd373a473abef0d` | Updated default config with null_ident blocking example | Documentation follow-up | Native rns-git supports `blocked_identities`, but its generated config and operator documentation do not show the null-identity hash example |
| 46 | `9ce45029612d1781c449a5ad5aa15f24c02cee57` | Updated changelog | Non-runtime | Release notes only |
| 47 | `ad3c06636b8d32afb0e68fe25cc12847c240926f` | Adjusted logging | Non-runtime | Changes denied/missing rngit artifact and page-download messages from warning to debug without changing responses or access decisions |
| 48 | `ea98db4f53dcf0defc0e71a16e60d28b1229c4e6` | Prepare release | Non-runtime | Generated documentation and tagged 1.5.2 release metadata |

## Per-Commit Analysis

### 1. `de76b893` — Added dataplane ingress control

**Upstream change:** Adds a process-wide Backbone ingress controller. Accepted
Backbone peers count received bytes and decoded packets. At DATA queue pressure,
the controller selects the largest packet producer, removes `EPOLLIN` from that
peer, holds it according to its measured share and a 32-interface allocation
floor, and re-enables reads after the DATA queue drops below a low watermark.
An immediate high-water trigger complements the 250 ms periodic controller,
and accepted sockets receive a 32 KiB kernel receive-buffer request.

**Rust applicability:** Rust already has four independently bounded inbound
classes and cumulative drop counters in `rns-net/src/event.rs`. A full class is
deliberately dropped without blocking the interface reader. This bounds memory
but does not provide upstream's earlier, per-peer TCP flow control or its
producer fairness: the busiest Backbone peer can continue consuming CPU and
kernel input while frames are dropped only at queue capacity.

**Local handling and evidence:** `rns-net/src/interface/backbone.rs` registers
every accepted stream for readable one-shot polling and unconditionally rearms
it after a read. `EventSender::send()` classifies and drops a full inbound class
without exposing a pause signal to that poll loop. Existing queue saturation
tests verify the current drop policy; they do not prove the new gate.

**Final disposition:** Integrated by local `b953832`. The existing queue
snapshot is read by the single-owner Backbone poll loop, which now maintains
per-child byte/packet samples, gates the largest producer by removing readable
interest at the periodic or immediate DATA watermark, preserves the calculated
hold, and releases one eligible child after pressure recovers. Accepted sockets
request the upstream 32 KiB receive buffer. Focused tests pin the initial
85/10/1 thresholds, largest-producer selection, absence of queue overflow while
gated, and delivery after release. `cargo test -p rns-net --features
iface-backbone` passed 913 unit tests, 54 network E2E tests, and all integration
tests on 2026-08-29; formatting and warning-free all-target `rns-net` Clippy
also passed.

### 2. `3b7cfc06` — Cleanup

**Upstream change:** Removes a temporary critical high-water-mark diagnostic
and the unused `Transport.link_fp_cache` class attribute left after the earlier
forwarding-cache experiment was removed.

**Rust applicability:** Neither deletion changes successful runtime behavior.
Rust never retained the denormalized forwarding cache and has no matching
diagnostic.

**Local handling and evidence:** The authoritative native link-table invariant
and absence of a secondary forwarding cache are recorded beside the routing
lookup by local mapping `5979f92`. Local `9f5edb3` additionally records that
threshold initialization remains silent and only actual throttle/release
transitions are operational events. The complete two-line upstream diff was
reviewed. The complete `rns-net` feature suite, formatting, and warning-free
all-target crate lint passed on 2026-08-29.

**Final disposition:** Non-runtime.

### 3. `1a16fdb7` — Fixed inbound queue high-water mark initialization order

**Upstream change:** Moves ingress-controller watermark derivation out of its
worker thread and into Reticulum initialization after configured queue lengths
are known but before Local/Backbone interfaces start. This prevents
`InboundQueues` from observing unset or stale class watermarks.

**Rust applicability:** Native inbound capacities are built from parsed
configuration before interface readers begin. There is currently no second set
of dataplane gate watermarks, so the exact upstream bug is absent until entry 1
is implemented.

**Local handling and evidence:** `InboundQueueCapacities` and queue construction
already establish the configured DATA bound before `Driver` starts. Local
`a4b426e` now snapshots that actual DATA capacity and derives the gate's
high/mid/low thresholds before the Backbone listener is registered. The custom
200-packet capacity regression proves that the resulting 170-packet immediate
watermark gates the producer without drops and releases it after recovery. The
complete `rns-net` feature suite, formatting, and warning-free all-target crate
lint passed on 2026-08-29.

**Final disposition:** Integrated.

### 4. `419956ba` — Over-optimization is the root of all evil

**Upstream change:** Reverts the empty-buffer check around `tx_ready()` so every
Backbone append asks the shared epoll loop to arm writable interest. This avoids
stranding output when buffer visibility and writable-interest state no longer
move in lockstep.

**Rust applicability:** Rust has no shared read/write epoll-interest state. The
accepted-peer poller owns only the readable stream, while a cloned
`BackboneWriter` owns output. Above it, every successful `AsyncWriter` enqueue
wakes the dedicated consumer channel; output visibility is not inferred from a
buffer-empty transition.

**Local handling and evidence:** Local mapping `e095553` documents this
read-poller/writer separation. Local `925413f` strengthens
`async_writer_returns_wouldblock_when_queue_is_full` to release the active
write and prove that the already-queued second frame enters the worker without
another sender-side trigger. On 2026-08-29, that focused test and the complete
`rns-net` feature suite passed (913 unit tests, 54 E2E tests, and all
interoperability and fixture tests), along with formatting and warning-free
all-target crate lint.

**Final disposition:** Structurally covered.

### 5. `bafc09d3` — Cleanup

**Upstream change:** Removes a duplicate `epoll = None` class assignment and
adds a TODO noting that the standalone Backbone client may need an explicit
nonblocking call. Executable client behavior is unchanged.

**Rust applicability:** Rust has one poller instance per listener and no
duplicate equivalent initialization. Its standalone client reader and cloned
writer use blocking I/O by design and are isolated from the driver by their own
threads; the upstream TODO is not a behavior change to port.

**Local handling and evidence:** The complete two-line source diff was
reviewed; it changes no executed branch or value. Local `360f095` records the
native ownership invariant at `client_reader_loop`: the blocking socket is
intentional because the dedicated thread owns reads and the cloned interface
writer owns writes. Focused client connect, receive, and send tests passed on
2026-08-29. The complete `rns-net` feature suite also passed (913 unit tests,
54 E2E tests, and all interoperability and fixture tests), along with
formatting and warning-free all-target crate lint.

**Final disposition:** Non-runtime.

### 6. `54a919f0` — Added optimized HDLC implementation

**Upstream change:** Extracts HDLC escaping/unescaping and introduces a reusable
`ReceiveBuffer`. The decoder keeps a consumed offset, compacts only after the
offset crosses half the buffer, retains the closing flag, enforces strict frame
bounds, resets oversized partial tails, and carries callbacks for valid and
invalid frames. Eleven regressions cover fragmentation, escape-heavy streams,
garbage, size boundaries, legacy parity, a 20,000-frame flood, large frames and
post-burst compaction.

**Rust applicability:** `rns-net/src/hdlc.rs` already provides shared streaming
decoding with Reticulum bounds, diagnostics and oversized-tail recovery. It
currently calls `Vec::drain(..end)` for every decoded frame, shifting the
remaining batch each time; a large coalesced small-frame batch therefore lacks
upstream's linear offset/periodic-compaction behavior. Native `unescape()` also
XORs every byte following `ESC`, whereas upstream and its legacy implementation
replace only the two defined escape sequences, so malformed escape sequences
do not have identical output.

**Local handling and evidence:** Local `a513526` ports the consumed-offset model
to the shared native decoder, compacts only after the offset reaches half of
the allocation, preserves the closing flag, and bounds only the unconsumed
tail. Unescaping now replaces only the two defined HDLC pairs, preserving
unknown and trailing escape bytes like upstream. Nineteen focused HDLC tests
passed, including new malformed-escape and delayed-compaction regressions; the
20,000-frame coalesced flood completed in 0.01 seconds. The complete `rns-net`
feature suite passed 915 unit tests, 54 E2E tests, and all interoperability and
fixture tests on 2026-08-29. Formatting and warning-free all-target crate lint
also passed.

**Final disposition:** Integrated.

### 7. `ac9130f0` — Added coalesced transmit test

**Upstream change:** Adds twelve test scenarios for the forthcoming transmit
buffer: idle visibility, 64 KiB chunk bounds, large-frame isolation, partial
writes, `WouldBlock`, in-order integrity, explicit and automatic tail flush,
concurrent producer/consumer access, accounting, and a 50,000-frame burst.
This test-first commit references `TransmitBuffer` before entry 8 adds it.

**Rust applicability:** Native `AsyncWriter` tests cover a bounded channel,
queue-full `WouldBlock`, worker failure and interface-down notification. They do
not cover byte chunks, partial chunk resumption, coalescing-tail visibility, or
byte/frame accounting.

**Local handling and evidence:** Local `f1fd1a3` adds a 50,000-frame burst
through the current async writer and proves exact in-order delivery without
loss in 0.02 seconds. This stages the architecture-neutral portion of the
upstream test-first commit. Entry 8 mapping `257e162` completes the buffer-side
contract with focused chunk-bound, large-frame, partial-write, `WouldBlock`,
tail-release, byte/frame accounting, and 50,000-frame burst tests. Native
producer/consumer synchronization remains at the existing channel boundary,
so the async burst and standalone single-owner buffer together cover the
upstream concurrency scenario without adding a second lock.

**Final disposition:** Integrated.

### 8. `0ec84c74` — Added coalescing transmit buffer

**Upstream change:** Adds a single-producer/single-consumer buffer that packs
small complete frames into immutable chunks up to 65,536 bytes, isolates larger
frames, resumes partial socket writes, flushes a hidden producer tail when the
visible queue drains, and maintains total, visible, sent, frame and chunk
accounting.

**Rust applicability:** Native `AsyncWriter` queues owned packet vectors by
frame count and the concrete Backbone/Local writers frame and write each item
separately. The server-side `BackboneWriter` has a private 512 KiB partial-write
buffer, but it neither coalesces frames nor supplies the accounting needed by
entry 12. Standalone Backbone and Local writers use `write_all()` in their
worker and have no equivalent buffer.

**Local handling and evidence:** Local `257e162` adds a standalone,
single-owner `TransmitBuffer` with immutable visible chunks, a resumable head
offset, a producer tail, automatic and explicit tail release, and cumulative
byte/frame/chunk accounting. Six focused tests cover sparse visibility, 64 KiB
chunk bounds, large-frame isolation, partial writes, clean `WouldBlock`, exact
ordering/accounting, and a 50,000-frame burst. The complete `rns-net` feature
suite passed 922 unit tests, 54 E2E tests, and all interoperability and fixture
tests on 2026-08-29; formatting and warning-free all-target crate lint also
passed. Wiring remains deliberately reserved for entry 9.

**Final disposition:** Integrated.

### 9. `89e73db9` — Wire coalesced TX and optimized HDLC into interfaces

**Upstream change:** Replaces copied Backbone and Local HDLC implementations
with the shared `ReceiveBuffer`, replaces byte-string transmit buffers with
`TransmitBuffer`, drains chunks on writable events, and uses `sendable` rather
than total buffered length when arming output. Frame bounds and invalid-frame
diagnostics remain interface-specific.

**Rust applicability:** Rust already wires its shared `hdlc::Decoder` into
Backbone and Local readers, including Backbone's MTU/IFAC maximum. Its writer
side still frames one queue item at a time, so only the decoder-extraction half
is structurally present.

**Local handling and evidence:** Local `ce58265` extends the native writer
boundary with batch delivery, drains every batch through `TransmitBuffer` in
accepted and standalone Backbone writers and TCP/Unix Local writers, and lets
the dedicated async worker resume a partial nonblocking Backbone chunk without
re-appending its frame. The pre-existing shared `hdlc::Decoder` remains the
single receive implementation. Focused tests prove deterministic batching,
Backbone read progress under write backpressure, standalone Backbone wire
output, and all 12 Local-interface paths. The complete `rns-net` feature suite
passed 923 unit tests, 54 E2E tests, and all interoperability and fixture tests
on 2026-08-29; formatting and warning-free all-target crate lint also passed.

**Final disposition:** Integrated.

### 10. `10848b7c` — Added egress control HWM limiter test

**Upstream change:** Adds eleven test scenarios for a hard byte valve and
periodic egress controller: exact memory bounds, oversized-frame rejection,
acceptance after drain, optional unlimited operation, zero-drain stall entry,
release below the mid watermark, ETA-based entry/release hysteresis, empty
reset, dead-peer teardown, and outbound drop accounting.

**Rust applicability:** Native tests prove frame-count queue saturation and a
configurable Backbone write-stall disconnect, but not a 4 MiB byte ceiling or
the drain-rate state machine. With the default 256-frame async queue and a
Backbone MTU up to 1 MiB, the queue's retained bytes are not bounded near the
upstream limit.

**Local handling and evidence:** Local `f541abe` stages the independent
accounting prerequisite: a 2,020-byte burst drains to exact zero bytes and zero
frames, after which a second equal burst is fully visible and admissible. The
focused test and complete `rns-net` feature suite passed 924 unit tests, 54 E2E
tests, and all interoperability and fixture tests on 2026-08-29; formatting and
warning-free all-target crate lint also passed. Entries 11 and 12 subsequently
completed the hard byte valve and controller-transition coverage.

**Final disposition:** Integrated by local `f541abe`, with its staged scenarios
completed by the ordered entry 11 and 12 mappings.

### 11. `cb9071b4` — Add HWM admission to `TransmitBuffer`

**Upstream change:** Makes buffer append optionally reject a complete framed
item when accepting it would exceed the supplied byte limit. The check and
append occur under the producer-tail lock, and unlimited callers retain the
previous behavior.

**Rust applicability:** The native async channel atomically limits the number
of queued frames, not their bytes. The server writer's later 512 KiB pending
limit applies only after an item has left that queue and reached a
nonblocking socket. Neither bound can enforce a per-interface 4 MiB total
admission ceiling across queued and partially written frames.

**Local handling and evidence:** Local `7106de0` adds optional byte-limited
append at the single-owner coalescing boundary. Admission uses the total
buffered byte count, rejects overflow and oversized frames before changing any
counter or chunk, preserves unlimited callers, and immediately admits again
after drain. Focused tests exercise a repeated 4 KiB hard bound, exact-limit
admission, oversized rejection, unchanged state, drain/reopen, and unlimited
operation. The complete `rns-net` feature suite passed 926 unit tests, 54 E2E
tests, and all interoperability and fixture tests on 2026-08-29; formatting and
warning-free all-target crate lint also passed.

**Final disposition:** Integrated.

### 12. `99c428a9` — Added dataplane egress control

**Upstream change:** Adds a 1-second controller with 128 KiB mid and 4 MiB hard
watermarks. It gates new Backbone/epoll-Local frames after three zero-drain
ticks or a drain ETA above ten seconds, releases below five seconds or the mid
watermark, counts dropped frames and bytes, and tears down a peer after twelve
seconds without drain progress. Admission uses entry 11's hard valve.

**Rust applicability:** Native output already has useful but non-equivalent
pieces: a 256-frame async queue returns `WouldBlock`, driver sends back off,
accepted Backbone peers preserve independent reads, and their concrete writer
disconnects on a configured stall timeout or a 512 KiB pending overflow. The
async queue is not byte-bounded, current rejected actions are not retained,
drop bytes/counts are not exposed, client/Local blocking writers have no
drain-rate monitor, and there is no matching ETA hysteresis or default
12-second dead-peer rule.

**Local handling and evidence:** Local `2ac7733` gives each applicable HDLC
writer one shared egress-control handle spanning the async producer and concrete
socket writer. Exact escaped on-wire lengths are reserved before enqueue and
remain charged until the complete batch drains, so queued and in-flight data
cannot jointly exceed 4 MiB. A full valve or asserted stall gate drops at
admission and records the exact framed byte count. Accepted Backbone peers
sample coalesced-buffer drain once per second, gate after three zero-progress
ticks or a greater-than-ten-second ETA, release below five seconds or 128 KiB,
and tear down after twelve seconds without progress. Local and standalone
Backbone writers use the same hard byte valve; entry 41 will apply upstream's
later Local-interface exemption in ancestry order. Focused tests cover exact
HDLC sizing, shared queued/in-flight admission, drop accounting, stall-gate
admission, hard-limit drain/reopen, ETA hysteresis, zero-drain gating, empty
reset, dead-peer escalation, Backbone read independence, and write-stall event
delivery. The complete `rns-net` feature suite passed 931 unit tests, 54 E2E
tests, and all interoperability and fixture tests on 2026-08-29; formatting and
warning-free all-target crate lint also passed.

**Final disposition:** Integrated.

### 13. `281c47f3` — Fixed invalid reference in exception description

**Upstream change:** Replaces four invalid `self` interpolations in static AES
key-length errors with the concrete AES-128-CBC or AES-256-CBC class name.

**Rust applicability and evidence:** Native AES constructors take `&[u8; 16]`
and `&[u8; 32]`, so an invalid key length cannot cross the API boundary and no
runtime error needs an instance description. Local `136a2d2` makes that typed
invariant explicit on both constructors. The complete `rns-crypto` suite passed
73 unit tests, 11 benchmark-harness tests, 11 interoperability tests, and doc
tests on 2026-08-29; formatting and warning-free all-target crate lint also
passed.

**Final disposition:** Structurally covered.

### 14. `de0dac69` — Fixed missing exception reference

**Upstream change:** Binds the `RuntimeError` caught while snapshotting the
process-wide spawned-interface map so its diagnostic can safely include the
exception.

**Rust applicability and evidence:** Native egress evaluation is owned by each
`BackboneWriter`; it does not concurrently iterate a process-wide interface
map. Errors are lexical `io::Error` values passed directly to the writer worker
and interface-down path, so there is no dynamically scoped exception name to
lose. The complete entry 12 `rns-net` suite exercises egress evaluation and
write-stall teardown without an unbound diagnostic path.

**Local handling:** Mapping commit `fb23eeb` records this ownership and error
binding invariant against the complete upstream diff.

**Final disposition:** Structurally covered.

### 15. `79cad39e` — Fixed missing import

**Upstream change:** Imports the top-level `RNS` module used by rnsh retry
diagnostics.

**Rust applicability and evidence:** rns-rs does not implement the upstream
Python rnsh utility. Native retry paths use statically resolved `log` macros
and typed module imports, all checked during compilation; there is no dynamic
module-global `RNS` name that can be omitted. The entry is therefore a
source-language/runtime binding fix rather than a wire or CLI compatibility
change for an implemented native surface.

**Local handling:** Mapping commit `df857f3` records the absent native surface
and the compile-time dependency-resolution invariant.

**Final disposition:** Structurally covered.

### 16. `0a1b9453` — Fixed non-epoll backend keepalive

**Upstream change:** Changes the non-epoll Local physical keepalive path from
framing an unrelated `data` value to framing an empty payload.

**Rust applicability and evidence:** Native Local keepalives already call
`Writer::send_frame(&[])`. Local `bf4a6fb` documents at that call site that the
literal payload prevents prior application data from being captured or
retransmitted. The focused socket test observes exactly `[0x7e, 0x7e]`. The
complete `rns-net` feature suite passed 931 unit tests, 54 E2E tests, and all
interoperability and fixture tests on 2026-08-29; formatting and warning-free
all-target crate lint also passed.

**Final disposition:** Structurally covered.

### 17. `e71c0195` — Fixed stray non-imported variable

**Upstream change:** Removes rnir's `--exampleconfig` option and its reference
to the undefined `__example_rns_config__` value, while retaining `--config`.

**Rust applicability and evidence:** rns-rs does not currently ship an `rnir`
binary, so it exposes neither the broken option nor the undefined value. Native
argument dispatch is compiled from explicit binary entry points and match arms;
the separate rnsd `--exampleconfig` option is implemented and is not the
surface changed upstream.

**Local handling:** Mapping commit `7835313` records the executable inventory
and distinguishes the implemented rnsd option from the absent rnir surface.

**Final disposition:** Structurally covered.

### 18. `67a45ac5` — Fixed nav init order

**Upstream change:** Initializes release-page navigation before resolving the
special `latest` tag, preventing uninitialized navigation state when no latest
release exists while retaining the requested tag in that early breadcrumb.

**Rust applicability and evidence:** Native `render_release_page()` resolves
`latest`, handles its not-found result, loads the published release, and only
then constructs the breadcrumb and heading from `release.tag`. Local `1a042a7`
strengthens the release-page integration test to prove a `latest` request emits
the concrete `v1` tag in both breadcrumb and heading and never leaves `latest`
in the navigation. The complete `rns-git` suite passed 195 unit tests, 6 E2E
tests, 11 release integration tests, 6 statistics tests, and doc tests on
2026-08-29; formatting and warning-free all-target crate lint also passed.

**Final disposition:** Structurally covered.

### 19. `803b5489` — Allow loading compiled modules

**Upstream change:** Replaces the simple pyximport shim with an RNS-tree import
finder that precompiles Python sources into an ABI-suffixed mirror, falls back
for unbuildable modules, and teaches ten package initializers to discover
`.so` and `.pyd` modules alongside Python sources.

**Rust applicability and evidence:** Cargo resolves the native crate/module
graph statically and rustc links compiled artifacts before execution. rns-rs
does not load Python package initializers, Cython mirrors, namespace packages,
or ABI-suffixed extension modules, so there is no corresponding runtime loader
or package export list to change. The full upstream diff affects only Python
development/import machinery and introduces no protocol, persistence, config,
RPC, or CLI behavior consumed by native code.

**Local handling:** Mapping commit `9d0da01` records the complete loader and
package-initializer review; no Rust crate changed, so no crate suite was
triggered for this documentation-only mapping.

**Final disposition:** Non-runtime.

### 20. `ff3a7220` — Avoid rebind of exception reference

**Upstream change:** Renames the nested temporary-file cleanup exception so it
does not erase the outer serialization exception that must be re-raised.

**Rust applicability and evidence:** Native persistence binds each filesystem
failure to a separate lexical `io::Error`; inner cleanup scopes cannot mutate or
erase an outer error binding. Atomic known-destination saves return the original
typed result rather than re-raising a dynamically scoped exception. This is a
Python exception-lifetime fix with no independent Rust runtime change.

**Local handling:** Mapping commit `6f09d8a` records the complete one-line
upstream fix and the native lexical-error invariant.

**Final disposition:** Structurally covered.

### 21. `d32ba8c` — Fixed inconsistency against advertised return type

**Upstream change:** Makes the private loader log and return `false` instead of
raising, and makes the public loader explicitly return `true` or `false` rather
than falling through with `None` on success.

**Rust applicability and evidence:** Native `Identity::from_private_key()` and
`Identity::from_public_key()` accept only 64-byte array references and return
`Self` directly. Invalid lengths are unrepresentable and successful
construction cannot fall through to a different return type. Local `1d28228`
documents this contract on both constructors. The complete `rns-crypto` suite
passed 73 unit tests, 11 benchmark-harness tests, 11 interoperability tests, and
doc tests on 2026-08-29; formatting and warning-free all-target crate lint also
passed.

**Final disposition:** Structurally covered.

### 22–30. Python compatibility, build, and packaging maintenance

Entries 22–30 remove dead Python 2 serializer code, simplify upstream test
package initialization, and add Cython/build-info/setup support. None changes a
wire format or production behavior used by the Rust crates. They are
**Non-runtime**; the native build remains governed by Cargo and does not embed
the affected Python modules.

### 31. `77c8256a` — Fix rngit blob-path prefix stripping

**Upstream change:** Replaces `lstrip("./")`, which treats its argument as a set
of removable leading characters, with exact `removeprefix("./")` handling.

**Rust applicability and evidence:** Native `normalize_blob_path()` performed
the equivalent over-broad `trim_start_matches(['.', '/'])`, rewriting dotfiles
and turning absolute paths into relative ones. Local `f1bf5ce` now removes only
one exact `./`, retains the later `/./` normalization, and leaves other leading
dots and slashes untouched. The focused regression covers explicit relative
paths, inner dot components, dotfiles, repeated dots, and absolute-path
rejection. The complete `rns-git` suite passed 196 unit tests, 6 E2E tests, 11
release integration tests, 6 statistics tests, and doc tests on 2026-08-29;
formatting and warning-free all-target crate lint also passed.

**Final disposition:** Integrated.

### 32. `b28f5ebf` — Allow inbound queue utilization in drainer benchmarks

This changes only upstream throughput-benchmark pacing so the default inbound
queue may remain partially occupied. It does not change production queue
behavior and is **Non-runtime**.

### 33. `6e8c9764` — Worker spawn prep

Entry 33 preserves the single Python transport worker while preparing a
configurable worker count. Native event and async-writer workers are spawned
from explicit lifecycle owners and do not infer worker count from duplicated
thread-start statements, so it is **Structurally covered**.

Mapping commit `5943fbc` records the complete two-site spawn refactor; no Rust
crate changed for this documentation-only structural mapping.

### 34. Egress status reporting

Entry 34 adds transmit-buffer bytes, dropped frames and bytes, and stalled
state to the interface-statistics and `rnstatus` surfaces. Local `1a36ad6`
exposes the exact shared reservation established by entry 12 (including queued
and concrete-writer bytes), publishes all four upstream-compatible keys over
both local RPC and remote management, aggregates dynamic Backbone children,
and adds the display, waiting/stalled annotation and `txdrp`, `txdrb`, and
`txbuf` sorts. Focused metric, pickle, and renderer regressions passed. The
complete all-feature `rns-net` suite passed 937 unit tests, 54 network E2E
tests, 23 hook E2E tests and all interoperability/fixture tests; the complete
`rns-cli` suite passed 122 library tests and all binary/integration tests.
This entry is **Integrated**.

### 35. `c1d7c12b` — Fix initialized stream Resource segmentation

Upstream corrects readable-source initialization and the split calculation
around `MAX_EFFICIENT_SIZE`, including metadata-bearing first segments. Native
stream Resources require a declared length, calculate the first segment's
reduced payload capacity explicitly, and reject short or trailing source data.
Existing exact-limit and multipart stream tests cover the native invariant, so
this entry is **Structurally covered**. Local `368eb76` adds the exact upstream
edge case: a stream whose data alone equals `MAX_EFFICIENT_SIZE` and whose
metadata therefore makes the logical transfer larger. The regression proves a
two-segment advertisement and that only `MAX_EFFICIENT_SIZE - metadata` bytes
are consumed for segment one. The focused test and complete `rns-net` Backbone
feature suite passed 932 unit and 54 network E2E tests plus all enabled
interop/fixture tests; formatting and warning-free all-target lint passed.

### 36–38. Intermediate release metadata

The changelog, version bump, and generated documentation do not independently
change native runtime behavior. These entries are **Non-runtime**.

### 39. `4eebf0b6` — Guard empty keepalive frames

Upstream rejects empty payloads before all affected interfaces deliver them to
Transport. Native HDLC decoders already discard empty flag pairs, but
`udp_reader_loop()` previously emitted an `Event::Frame` for a zero-length UDP
datagram. Local `c2ee65f` now ignores that datagram at the raw interface
boundary, and its regression sends an empty datagram followed by data and
proves that only the latter reaches Transport. The focused test and complete
`rns-net` Backbone feature suite passed 933 unit and 54 network E2E tests plus
all enabled interop/fixture tests; formatting and warning-free all-target lint
passed. This entry is **Integrated**.

### 40. `6bc0481c` — Flush proxied Resource streams

The upstream fix flushes and rewinds a temporary file used to proxy a
zero-stat readable source. Native stream Resources consume a caller-provided
reader against an explicit declared length and do not use that proxy; received
files are flushed and synced before publication. This entry is **Structurally
covered**. Local `ae0ddb0` pins the direct-reader invariant on the streaming
API. The complete `rns-net` Backbone feature suite passed 933 unit and 54
network E2E tests plus all enabled interop/fixture tests; formatting and
warning-free all-target lint passed.

### 41 and 43. Dataplane-control exclusions and tuned defaults

Entry 41 exempts Local shared-instance clients from global ingress and egress
control. Local `3a10336` removes the shared byte budget and hard valve from all
Local TCP/Unix writers while retaining coalescing. Local ingress was already
outside the Backbone accepted-peer controller. The focused exemption test and
complete `rns-net` Backbone feature suite passed 934 unit and 54 network E2E
tests plus all enabled interop/fixture tests; formatting and warning-free
all-target lint passed. Entry 41 is **Integrated**.

Entry 43 changes Backbone ingress watermarks to 90/68/10 percent. Local
`723077e` applies those final defaults to the entry-1 controller and updates
both exact arithmetic and live gating regressions. The focused tests and
complete `rns-net` Backbone feature suite passed 934 unit and 54 network E2E
tests plus all enabled interop/fixture tests; formatting and warning-free
all-target lint passed. Entry 43 is **Integrated**.

### 42, 44, and 46–48. Final release and logging metadata

The version/changelog/generated-documentation changes and lower-severity rngit
diagnostics do not alter wire behavior, authorization, or successful runtime
results. They are **Non-runtime**.

### 45. `a3cd8411` — Document null-identity blocking

Native rns-git already parses and enforces `blocked_identities`, including for
page and management access, but its generated configuration and operator guide
do not show upstream's null-identity hash. This entry is a **Documentation
follow-up**.

## Integration Plan

1. Integrate entry 1's Backbone ingress gate and entry 3's initialization-order
   correction around the existing prioritized queue. Preserve entry 2 as its
   own non-runtime mapping and entry 4's split-reader/writer invariant as its
   own structural mapping.
2. Optimize the shared HDLC decoder for entry 6, then add the entry-7 tests and
   entry-8 coalescing/accounting primitive before wiring it into Backbone and
   Local for entry 9. Preserve entry 5 as its own non-runtime mapping.
3. Add entry 10's native egress regression contract, entry 11's atomic byte
   admission, and entry 12's unified gate/hysteresis/drop/teardown behavior.
4. Port entry 31's exact blob-path prefix handling and add focused dotfile and
   explicit-relative-path page-server regressions.
5. Reject empty raw-interface ingress for entry 39 and add a zero-length UDP
   regression.
6. Add entry 34's status fields, entry 41's Local exemption, and entry 43's
   final defaults to the coordinated dataplane-control implementation.
7. Add entry 45's null-identity blocking example to the generated rns-git
   configuration and operator documentation.
8. Preserve entries 13–30, 32–33, 35–38, 40, 42, 44, and 46–48 as
   structural/non-runtime mappings with their
   recorded source evidence.
9. Run focused queue, HDLC, Backbone, Local, UDP and rns-git page suites after each ordered
   mapping, then complete exact-target Python/Rust interoperability and the
   full promotion gates.

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

- 2026-08-27: both upstream remotes refreshed successfully; drift inventory
  opened from the accepted baseline through the normative rgit tip.
- 2026-08-27: the dual-VPS daily smoke profile passed before this audit was
  opened, including impairment, concurrent Resources and links, and forced
  Backbone reconnection recovery. This is operational evidence only, not an
  exact-target upstream interop acceptance result.
- 2026-08-27: completed source and architecture review of all 12 commits. The
  review found two non-runtime cleanups, one structurally covered writer-wakeup
  change, and nine commits requiring three coordinated native work groups.
- 2026-08-27: existing focused evidence passed: 21 HDLC-related tests, the
  Backbone read-under-write-backpressure regression, two async-writer tests,
  and three inbound-queue/configuration tests. These results establish the
  current baseline only; they are not acceptance evidence for behavior marked
  `Needs port` or `Needs coordinated port`.
- 2026-08-28: both upstream remotes refreshed successfully. GitHub remained
  behind the accepted baseline; normative rgit advanced to `b28f5ebf`, making
  32 deduplicated commits ahead of the accepted baseline. Entries 13–32 were
  inventoried and given initial source/architecture dispositions; entry 31 is
  the only newly observed native behavior requiring a port.
- 2026-08-28: the dual-VPS daily snapshots were healthy and complete, and the
  extended live smoke profile passed Resources, concurrent links, impairment,
  and forced Backbone reconnect recovery. This remains operational evidence,
  not exact-target upstream interop acceptance.
- 2026-08-29: both upstream remotes refreshed successfully and agreed at the
  newly tagged `1.5.2` commit `ea98db4f`, 48 commits ahead of the accepted
  baseline. Entries 33–48 were inventoried and given initial
  source/architecture dispositions; newly observed native work is concentrated
  in status reporting, empty raw-frame rejection, dataplane-control details,
  and the null-identity configuration example.
- 2026-08-29: the dual-VPS snapshots were healthy and complete, and the daily
  live smoke profile passed Resources, concurrent links, impairment, and
  forced Backbone reconnect recovery. This is operational evidence only, not
  exact-target 1.5.2 interoperability acceptance.
- 2026-08-29: entry 34 was integrated as local `1a36ad6`. Exact transmit
  reservations, drops and stall state now reach local/remote status and
  `rnstatus`; focused regressions, the complete all-feature `rns-net` suite
  (937 unit, 54 network E2E and 23 hook E2E tests plus interop/fixtures), and
  the complete `rns-cli` suite passed.
- 2026-08-29: entry 1 was integrated as local `b953832`. The focused ingress
  controller regressions, complete `rns-net` feature suite (913 unit and 54
  network E2E tests plus integration tests), formatting, and warning-free
  all-target crate lint passed.
- 2026-08-29: entry 2 was mapped as non-runtime by local `9f5edb3`; the
  complete two-line cleanup was reviewed and the full `rns-net` validation
  remained green.
