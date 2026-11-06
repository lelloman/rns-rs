# Engines: compact and parallel

Status: design, not yet implemented. Nothing here changes the wire protocol.

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
 │ engine-compact                    │ engine-parallel                      │
 │ driver loop; helpers folded into  │ interface I/O threads, a driver that │
 │ it or kept as threads, per group  │ owns protocol state, a crypto pool   │
 └──────────────────────────────────┴──────────────────────────────────────┘
 rns-core           shared, sans-IO protocol state machines (no_std)
 rns-crypto         shared primitives (no_std)
```

`rns-core` never decides when or on which thread anything runs; that is the
driver's job. The split therefore lives in `rns-net`, below `common/`.

## Build-time selection

`rns-net` gains two mutually exclusive features:

| Feature | Engine |
|---|---|
| `engine-compact` | the compact engine |
| `engine-parallel` | the parallel engine |

Enabling both, or neither, is a compile error with a message naming the two
features. Crates above `rns-net` forward the choice (`rns-cli`, `rns-ctl`,
`rns-server`, `rns-tun` gain the same two features and pass them down).

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

The compact engine has four further features, one per group of helpers,
described below. They are enabled by default and only meaningful with
`engine-compact`:

| Feature | Group |
|---|---|
| `compact-fold-timers` | timers and housekeeping |
| `compact-fold-work` | CPU work |
| `compact-fold-io` | interface I/O |
| `compact-fold-services` | services off the packet path |

With a fold feature on, that group's jobs run on the driver loop. With it off,
the group keeps its threads, exactly as today. The job code is the same either
way; only where it runs changes, so every combination is valid. CI builds at
least: compact fully folded, compact with no folds, and parallel.

The existing optional features map as follows:

| Today | Becomes |
|---|---|
| `low-latency-flush` | the parallel engine's normal behaviour; the compact engine flushes at the end of each pass. `flush_after_us` still overrides either |
| `proof-pool` | replaced by the parallel engine's crypto pool; removed from the compact engine |
| `x25519-aws-lc` (`rns-crypto`) | stays a `rns-crypto` feature usable with either engine; on by default in `engine-parallel` builds of the CLI crates |

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
  engine and for compact builds that keep `compact-fold-io` off.
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
| Timers and housekeeping (`compact-fold-timers`) | `rns-timer` (sends `Tick` every N ms), `rns-persist` (transport state snapshot every 12 h), `rns-destination-cleanup` (stale ratchet removal) | the tick becomes the loop's timed wait; persistence and cleanup become idle jobs, the snapshot written in slices | small |
| CPU work (`compact-fold-work`) | `rns-verify` (announce signatures), `rns-resource-prepare` (compression of outgoing resources), `rns-resource-receive` (assembly of incoming ones), `rns-stamper` and `rns-link-stamp` (stamp generation), `rns-proof-N` (link proof pool) | idle jobs; announce verification one announce per slice; compression and assembly in bounded chunks; stamp generation as a resumable search of a fixed number of candidates per slice; link proofs verified inline | medium: compression and stamping need resumable slicing |
| Interface I/O (`compact-fold-io`) | readers for UDP, serial, KISS, RNode, pipe, local, Auto, I2P and Weave; `iface-writer-N`; reconnect threads for TCP, Backbone, serial and KISS | non-blocking, pollable sources and writers in the loop (TCP already works this way); reconnects as non-blocking connects with timers | large: one interface type at a time |
| Services (`compact-fold-services`) | RPC servers and clients, the shared-instance server, the provider bridge, hole-punch probes | pollable listeners and connections in the loop | medium |

Interface I/O folds one interface type at a time. Until an interface type has
a pollable form, it keeps its threads even with `compact-fold-io` on, and the
documentation lists which types are folded. The order follows deployment:
TCP (done), UDP, local/shared instance, serial and KISS, RNode, Backbone,
Auto, pipe, I2P, Weave.

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
2. **Engine switch and compact engine.** Add `engine-compact` and
   `engine-parallel` (parallel initially equal to today's driver with its
   helper threads), then fold the groups into the compact engine in this
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
