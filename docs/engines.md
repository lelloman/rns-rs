# Engines: compact and parallel

Status: in progress. The engine switch, the folded timers group, folded
announce verification, resource compression and resource assembly, and
single-core stamp generation, and the services group (RPC servers,
provider bridge, probe server), UDP, serial, KISS (including AX.25), RNode,
Auto, pipe, I2P and Weave interfaces and the shared-instance server and client on the driver loop
are in; the rest is design. Nothing here changes the wire
protocol.

## Purpose

`rns-net` runs a node in one shape today: a driver thread that owns all
protocol state, plus a growing set of helper threads (announce verification,
resource preparation and assembly, stamps, persistence, timers, interface
readers and writers, and the optional link proof pool). That shape is a
compromise. On a single CPU the helper threads time-slice with the driver and
cost throughput; on a many-core host there are too few of them, and too much
still waits on the one driver thread, to use the hardware.

This document splits the node into two engines chosen at build time:

- **compact**: one thread for everything, small and predictable. For small
  VPSes, embedded Linux devices and anything confined to one CPU.
- **parallel**: uses the cores a host has. For transport nodes and servers
  carrying heavy traffic.

Both engines run the same protocol code and expose the same application API.
Choosing an engine is a Cargo feature, not a code change.

## Goals and non-goals

Goals:

- One protocol implementation. `rns-core` and `rns-crypto` stay shared, so
  behaviour and interoperability are defined and tested once.
- One application API. `RnsNode`, `NodeConfig` and the callbacks are the same
  in both builds.
- The compact engine is at least as fast as today's node on one CPU, with less
  memory and no threads beyond the driver when fully folded.
- The parallel engine carries more traffic than today's node wherever a host
  has idle cores, without slowing a single link's round trip.

Non-goals:

- Selecting the engine at run time. The engines differ in which code is
  compiled in; a binary contains one of them.
- Changing what a node does on the network: routing, announces, links,
  channels and resources behave identically in both engines.

## Where the split sits

```text
 application ─────────── RnsNode API (identical in both builds) ───────────
 rns-net/common     shared: link manager, interfaces, config, storage, RPC,
                    destinations, events
 ┌──────────────────────────────────┬──────────────────────────────────────┐
 │ compact (default)                 │ parallel (`engine-parallel`)         │
 │ driver loop; helpers folded into  │ interface I/O threads, a driver that │
 │ it or kept as threads, per group  │ owns protocol state, a crypto pool   │
 └──────────────────────────────────┴──────────────────────────────────────┘
 rns-core           shared, sans-IO protocol state machines (no_std)
 rns-crypto         shared primitives (no_std)
```

`rns-core` never decides when or on which thread anything runs; that is the
driver's job. The split therefore lives in `rns-net`, below `common/`.

## Build-time selection

`rns-net` has one engine feature, `engine-parallel`; without it a build runs
the compact engine. Cargo merges the features every crate in a build asks of
`rns-net`, so mutually exclusive engine features would break any build that
compiles a compact crate and a parallel one together (a workspace build, for
example). With one additive feature, such a build runs the parallel engine,
and each crate built on its own gets its own default. The crates above
`rns-net` that default to parallel (`rns-cli`, `rns-ctl`, `rns-server`) have
an `engine-parallel` feature of their own, on by default, that passes the
choice down; building them with it off gives the compact engine. A node logs
which engine it runs when it starts (`rns_net::engine::ENGINE`).

Defaults:

| Crate or product | Default engine | Why |
|---|---|---|
| `rns-net` (the library) | compact | embedded in applications, phones and small devices; it should start small and never spawn threads nobody asked for |
| `rnsd` (`rns-cli`), `rns-server`, `rns-ctl daemon` | parallel | the processes that route traffic for others |
| `rns-tun`, `rns-git` and other single-purpose products | compact | private nodes serving one application |

Release packaging ships both builds of `rnsd` and `rns-server`: the default
parallel build and a compact build for single-CPU hosts. On one CPU the
parallel engine still works (it starts no crypto workers and does the work
inline) but keeps its interface I/O threads, so the compact build is the
better choice there, and the operator documentation says so.

The compact engine folds four groups of helpers into the driver loop by
default. Each group has a feature that keeps its threads instead, exactly as
today; the features only matter without `engine-parallel`:

| Feature | Keeps these threads |
|---|---|
| `compact-threads-timers` | timers and housekeeping |
| `compact-threads-work` | CPU work |
| `compact-threads-io` | interface I/O |
| `compact-threads-services` | services off the packet path |

The features are additive for the same reason as the engine feature: one that
adds threads merges cleanly, one that removes them would not. The job code is
the same either way; only where it runs changes, so every combination is
valid. CI tests the workspace (parallel), `rns-net` alone (compact, fully
folded) and `rns-net` with the thread features (compact, unfolded).

The existing optional features map as follows:

| Today | Becomes |
|---|---|
| `low-latency-flush` | the parallel engine's normal behaviour; the compact engine flushes at the end of each pass. `flush_after_us` still overrides either |
| `proof-pool` | replaced by the parallel engine's crypto pool; removed from the compact engine |
| `x25519-aws-lc` (`rns-crypto`) | stays a `rns-crypto` feature usable with either engine. It brings a C and CMake build dependency, so it is opt-in even for parallel builds; release builds of `rnsd` and `rns-server` turn it on |

## What is shared

- `rns-crypto` is unchanged apart from additions: a batch Ed25519 verification
  call for the parallel engine. The multi-lane SHA-256 kernels already help
  both engines.
- `rns-core` keeps all protocol logic. The parallel engine needs a few
  two-phase entry points (see [Two-phase steps](#two-phase-steps)); these are
  additions, and the compact engine keeps calling the existing one-step
  versions.
- `rns-net/src/common/` (link manager, interfaces, configuration, storage,
  destinations, events) is shared. Interfaces gain a pollable form where the
  compact engine folds their I/O; the threaded form stays for the parallel
  engine and for compact builds with `compact-threads-io`.
- Hooks run where they run today: on the thread that owns protocol state, at
  the same attach points, in the same order. Neither engine moves a hook onto
  a worker.

## Compact engine

### Shape

One thread, the driver loop, owns everything. With every group folded, a
compact node runs no other thread. Every packet's work (receive, deduplicate,
route, decrypt, deliver, prove, write) happens on that thread without
handoffs, which keeps a single message's latency and CPU cost at their lowest
on one core.

Memory policy: buffers sized to the traffic actually seen, no huge pages, and
bounded queues. The resource receiver's growth-with-data storage and the
decrypt-ahead path already follow this.

### Folding rules

A folded job runs in the driver's idle time, under the rules the stream work
established:

- Pending socket data and timers always go before folded work. Between two
  slices of folded work the driver polls its sources without waiting; a run of
  folded jobs never leaves received data unread.
- Every folded job is sliced to a bounded cost per turn (a target of about
  100 µs), so a long job never delays packet handling by more than one slice.
- Folded work that has a deadline (a timer tick, a persistence interval) is
  driven by the loop's own timed wait, not by a sleeping thread.

### Groups

| Group | Helpers today | Folded form | Effort |
|---|---|---|---|
| Timers and housekeeping (`compact-threads-timers` keeps the threads) | `rns-timer` (sends `Tick` every N ms), `rns-persist` (transport state snapshot every 12 h), `rns-destination-cleanup` (stale ratchet removal) | the tick comes from a periodic timerfd watched by the loop on Linux and Android (a timed wait would make the kernel arm and cancel a timer on every wait), and from a deadline the loop checks elsewhere; persistence and ratchet cleanup become idle jobs, and queued ones complete at shutdown as a joined thread would. The snapshot is written as one job; slicing it is left for a measured stall on a large path table | small (done) |
| CPU work (`compact-threads-work` keeps the threads) | `rns-verify` (announce signatures), `rns-resource-prepare` (compression of outgoing resources), `rns-resource-receive` (assembly of incoming ones), `rns-stamper` and `rns-link-stamp` (stamp generation), `rns-proof-N` (link proof pool) | idle jobs, and one unit every 64 events when the driver never goes idle. Announce verification (done): one announce per slice, through the same bounded queue. Resource compression (done): bzip2 one block per slice at level 1 (100 kB blocks, about 10 ms each on a desktop core), within the worker's job and byte budget; bzip2 sorts a block in one call, so a block is the smallest slice. Split resources and stream segments are compressed inline when built, in both engines, as before. Assembly of incoming compressed resources (done): decompressed and hashed 256 KiB of output per slice, within the worker's output bound and job limit; a slice that reaches a new bzip2 block also decodes that block, whose size the sender chose (up to 900 kB). Stamp generation (done, deliberately not folded): see below; link proofs verified inline | medium (done) |
| Interface I/O (`compact-threads-io` keeps the threads) | readers for UDP, serial, KISS, RNode, pipe, local, Auto, I2P and Weave; `iface-writer-N`; reconnect threads for TCP, Backbone, serial and KISS | non-blocking, pollable sources and writers in the loop (TCP already works this way); reconnects as non-blocking connects with timers. UDP (done): the listening socket is a loop source reading at most 64 datagrams per wake-up, and the writer is called by the driver directly on a non-blocking socket, with no worker thread; a datagram the socket buffer cannot take is dropped, as the network may drop it, while a confirmed link send is retried by the driver. Shared-instance server (done): the listener (Unix or TCP) and each client are loop sources and each client's writer is written by the driver, as the TCP server's are; a client keeps being served after the listener stops, as with reader threads, and where clients may sleep (Android) the writer keeps its worker thread so it can drop frames while the client is paused. Shared-instance client (done): its connection is a loop source and its writer is driver-written; after the connection is lost a thread reconnects, as the TCP client's does, and exits once the new connection is served. Serial (done): the port is a loop source and its HDLC writer is driver-written, with `read`/`write` on the non-blocking device instead of socket calls, and at most 128 KiB buffered (about what the threaded writer's queue holds) so frames on a slow line do not wait behind a long backlog; a reconnect thread runs only while the port is gone. KISS and AX.25 KISS (done): the port is a loop source, and the driver calls the writer directly; writer and reader share the port's unwritten bytes and, with flow control, the frames held until the TNC reports ready (a confirmed send is taken only when it can be written at once, else the driver retries it). The flow-control timeout and the beacon are checked on the driver's tick instead of after each read, so a TNC that never answers is unlocked even on an idle line; the same 128 KiB bound applies, to bytes held and unwritten together. RNode (done): the connection (serial or TCP) is a loop source that also sends the 15-second keepalive from a timer, and the subinterfaces' writers, called by the driver directly, share one device writer that buffers up to 128 KiB and writes without blocking; runtime reconfiguring writes through it too. Detecting and configuring the device waits on its replies, so a setup thread does it, at start and after the connection is lost, and exits once the device is served. Backbone (done): already served on the driver loop in both engines, like TCP: the listener, every peer and the client connection are loop sources and their writers are driver-written; only the client's reconnect thread remains, while it is disconnected. Auto (done): each adopted network interface's three receiving sockets (multicast and unicast discovery, data) are loop sources, and a controller source runs the supervisor's rescan, the peer-jobs cull and the discovery multicast from timers, replacing the supervisor, peer-jobs and per-interface sender and receiver threads (whose receivers woke every 2 seconds on a read timeout); peers' writers are called by the driver directly on non-blocking sockets, dropping a datagram the socket buffer cannot take, as UDP does. Pipe (done): the subprocess's stdout is a loop source and its stdin is written by the driver like a serial port, HDLC-framed and non-blocking; after the subprocess exits, a thread waits for it, respawns it after the delay and exits once the new one is served, and the subprocess is killed when its source goes away with the driver. I2P (done): every SAM stream is a loop source (the session's control socket, which also answers the bridge's PINGs, each peer's data stream, and the pending accept, which becomes the accepted peer's stream once the bridge names the peer), and peers' writers are driver-written; talking to the bridge before a stream carries data blocks, for up to tens of seconds while I2P builds tunnels, so short-lived threads set the session up, connect or reconnect each outbound peer and ask for the next incoming connection, each exiting once its stream is served. This replaces the coordinator thread parked for the session's lifetime, the acceptor, and a reader and a writer thread per peer. Weave (done): the device is a loop source with timers for the connection handshake and for the next peer to time out, instead of a session thread polling it four times a second, and the peers' writers share the device writer RNode uses (buffered, non-blocking, driver-run); opening the device, and reopening it five seconds after it fails, runs on a short-lived thread | large: one interface type at a time |
| Services (`compact-threads-services` keeps the threads) | `rpc-server` and `rpc-unix-server` with an `rpc-client` thread per connection, the provider bridge, hole-punch probes | pollable listeners and connections in the loop. RPC servers (done): the listeners and connections are watched by the driver's poller under keys of their own, each connection runs the same exchange as a server thread (challenge both ways, one request, one answer) as a non-blocking state machine, and the driver answers the request itself, with no event queue in between; at most 32 connections, each closed after 10 s without progress, as the threads' socket timeouts close it. Provider bridge (done): its socket and consumer connections are on the driver's poller too, and the driver writes each consumer's queue right after queueing an event and again when the socket can take more; queues, limits and overflow are the threaded bridge's, but a consumer that stops reading keeps its connection and its queue overflows, where a consumer thread drops it after a write blocks for a second, and a consumer that hangs up is noticed at once rather than at the next write. Probe server (done): its UDP socket is on the driver's poller, answering at most 64 requests per wake-up so a flood cannot hold the loop, where the thread woke every second on a read timeout. Hole-punch probe workers and punchers stay threads: they live only for the seconds of one hole-punch attempt, block on purpose with their own timing, and are gone after it; the direct UDP interface a punch opens belongs to interface I/O | done |

Stamp generation is the one CPU job the compact engine keeps on a thread
in every build. Stamps are off by default; when on, a node grinds them for
its own announces, its own path requests, the link requests it starts and
its own discovery announces, and checks the stamps of others with one hash,
inline. A grind runs for seconds and one attempt can hash several hundred
kB, so folding it would take a resumable search with the hash state kept
between slices, and moving every caller's completion onto the loop, for work
that is rare and costs the same CPU either way. The compact engine therefore
keeps the existing threads (the lazily started `rns-stamper`, and one
`rns-link-stamp` or discovery thread per request) but each searches on that
thread alone, where the parallel engine spreads a search over every core.
The compact engine has no rayon pool at all. One case makes stamping transit
work: a transport node with `STAMP_PRS` grinds a stamp, per egress
interface, for every unstamped path request it forwards. A router in that
role should run the parallel engine.

Every listener that stays on a thread waits in a poller for a connection
or a stop request, in both engines. They used to retry a non-blocking accept
every 10 to 50 ms, which on an idle node with a shared instance was about
220 wake-ups a second, nearly all of its idle wake-ups. The shared-instance
server (`local-server` and a reader per client) is an interface and folds
with interface I/O (done).

Interface I/O folds one interface type at a time. Until an interface type has
a pollable form, it keeps its threads even without `compact-threads-io`, and the
documentation lists which types are folded. The order follows deployment:
TCP (done), UDP (done), local/shared instance (done), serial (done), KISS (done), RNode (done), Backbone (done),
Auto (done), pipe (done), I2P (done), Weave (done).

Shared-instance clients (`shared_client.rs`, the `rns-driver-client` and
`rns-timer-client` threads) follow the same rules as the node: in a compact
build they fold with their groups.

## Parallel engine

### Version 1: one protocol owner, parallel crypto and I/O

```text
 interface I/O threads ──frames──▶ driver ──batched crypto jobs──▶ crypto pool
                                  (transport,                     (N workers,
                                   links, hooks,                   one queue
                                   bookkeeping)                    each)
                                       ▲                                │
                                       └────── batched results ─────────┘
```

- **Driver.** Owns all protocol state exactly as today: `TransportEngine`,
  the link manager, hooks. It does the cheap per-packet work (deduplication,
  routing, window bookkeeping) and hands every expensive cryptographic step to
  the pool.
- **Crypto pool.** N workers, each with its own lock-free single-producer
  single-consumer queue for jobs and another for results. The driver assigns
  jobs round-robin, or by link id where a link's jobs must stay ordered. Jobs
  move in batches: the driver collects the jobs of one pass and submits them
  together; a worker returns every result it has ready at once, and one wake
  event stands for all results until the driver drains them. Pending proof
  verifications are checked with batch Ed25519 verification.
- **Interface I/O.** Each interface reads and writes on its own thread and
  exchanges frames with the driver through lock-free queues, so socket
  syscalls leave the driver.
- **Defaults.** Flush deadline 25 µs; X25519 on aws-lc where the CLI crates
  enable it.

Why batching and per-worker queues matter: measured on six cores, a link
carrying 16 messages in flight spends most of each message's round trip
queued behind the others on the one thread that receives, decrypts and signs
them (about 22 µs each). Moving that work to one shared-queue worker, one job
and one wake per message, made the round trip longer, not shorter: the
handoff costs more than it saves unless jobs move in batches and run on
several workers at once.

#### Worker count

Default: the CPUs the process may run on (`available_parallelism`, which
honours affinity) minus two, at least one. A process confined to one CPU
runs the parallel engine with zero workers, doing the crypto inline, which is
correct but pointless: such hosts should use the compact engine. A
`NodeConfig` setting overrides the count.

#### Ordering

The one-thread engine handles packets strictly in arrival order. The parallel
engine keeps that order where the protocol and applications depend on it,
and nowhere else:

- **Within a link, order is kept.** The driver tags each job with a per-link
  sequence number and holds a result until those before it on the same link
  are applied, so channel messages, requests, proofs and window updates are
  applied in the order the link's packets arrived.
- **Across links, and for single packets, there is no ordering promise.** A
  message on one link may be delivered before a message that arrived slightly
  earlier on another link. Reticulum has never promised order across links or
  for single packets: they travel independent paths and can arrive in any
  order on the network itself.

#### Two-phase steps

A step that does cryptography inside a state transition is split so the
driver can hand the cryptography to the pool and apply the result later. The
one-step form stays, and the compact engine keeps using it. The resource
receiver already works this way (`prepare_assembly` / `complete_assembly`).

| Step | Where today | Crypto | Two-phase form |
|---|---|---|---|
| Receive link data | `LinkManager::handle_link_data_into` (`engine.decrypt_into`) | token decrypt | begin: hand the ciphertext out; finish: apply the plaintext to the link, channel or request |
| Send link data and channel messages | `link_manager.rs` (`encrypt_into`), `channel_handling.rs` | token encrypt | encrypt on the pool, then queue the packet |
| Prove a link packet | `build_link_packet_proof` (`sign_packet_hash`) | Ed25519 sign | sign on the pool, then send the proof |
| Verify a link proof | `handle_link_proof` | Ed25519 verify | exists (proof pool), moves to batched verification |
| Prove a single packet | `driver/dispatch.rs` (`identity.sign`) | Ed25519 sign | sign on the pool, then send |
| Verify a single-packet proof | `driver/dispatch.rs` (cached key) | Ed25519 verify | verify on the pool, batched |
| Establish a link | `rns-core` link handshake | X25519, HKDF, Ed25519 | handshake crypto on the pool; link state advanced on completion |
| Verify announces | `rns-verify` thread and queue | Ed25519 verify | moves into the pool, batched |
| Build and assemble resources | resource prepare and receive workers | AES, HMAC, SHA-256, compression | move into the pool |
| Encrypt a single packet | `RnsNode::send_packet_queued` on the caller's thread | X25519, token encrypt | stays on the caller's thread (the returned packet hash depends on the ciphertext); a later off-thread send API may move it |

### Version 2, only if measured: a sharded transport

In version 1 every packet still passes through one `TransportEngine` on the
driver thread. Splitting it (a read-mostly routing view shared by several
drivers, a concurrent deduplication set, links owned by shards by link id)
is a large change to `rns-core`, and is done only if the many-peer benchmark
shows the driver thread saturated while workers and cores sit idle. Raw
transport relaying on one driver thread is not a measured bottleneck today.

## Measuring each engine

Each engine is judged on its own terms, with paired, interleaved runs on a
quiet host:

| Engine | Primary measures |
|---|---|
| compact | throughput and CPU per message pinned to one CPU; peak memory; binary size; no regression against today's node pinned |
| parallel | throughput unpinned on the endpoint scenarios (link messages, single packets, request-response, resources) and the relay scenarios; a many-peer scaling scenario (to be added) with hundreds of links |

## Rollout

1. **This document.** Agree the shape before code.
2. **Engine switch and compact engine.** Add the `engine-parallel` switch
   (parallel initially equal to today's driver with its helper threads), then fold the groups into the compact engine in this
   order: timers, CPU work, services, interface I/O one type at a time. Each
   fold lands with a pinned A/B and a memory comparison; none may regress.
3. **Parallel version 1.** Crypto pool with per-worker queues, batching and
   batch verification, first carrying the steps that already have two-phase
   forms (proof verification, resource work, announce verification); then the
   new two-phase steps one at a time, each with an unpinned A/B; then
   interface I/O threads.
4. **Many-peer benchmark.** Decides whether version 2 is needed.
5. **`rns-esp32` on the compact engine** (later). The firmware drives
   `rns-core` and `rns-crypto` with its own loop today. It moves onto the
   compact engine once three things hold: the compact engine is fully folded
   (no threads), its memory footprint fits the device, and it has an
   interface for the device's own radio. The firmware then shares the link
   manager, resource handling and interfaces with every other build instead
   of keeping its own.
