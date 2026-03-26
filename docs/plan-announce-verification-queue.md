# Plan: Announce Verification Queue

## Problem

When a destination announces, the announce propagates through the network and
arrives at our node from N peers, each at a different hop count. Even when the
existing signature cache helps, announce verification still happens
**synchronously on the driver thread** inside `handle_inbound`, and bursty
announce traffic can monopolize the event loop.

Observed burst: 26 copies of destination `219a60c2` validated in 1 second,
plus 7 copies each of two other destinations — 53 verifications in 10 seconds.
20-minute monitoring on the VPS showed 200% CPU (both cores saturated) in 160
out of 1007 one-second samples (~16% of the time).

Because the driver thread is the single event loop that handles **everything**
(packet forwarding, connection management, tick maintenance), blocking it on
crypto verification causes cascading issues: outbound forwarding stalls, TCP
write buffers fill up, peers get disconnected for write stalls.

## Solution

Add a **dedicated verification thread** (`rns-verify`) with a bounded
coalescing queue between it and the driver. The goal is not to replace the
existing signature cache, but to keep expensive Ed25519 work off the driver
thread during bursts. The driver does only cheap parsing, cache checks, and
bookkeeping; the verify thread drains queued work at its own pace and sends
results back.

## Architecture

### Threading model

```
Driver thread (fast, never blocks on crypto)
──────────────────────────────────────────────
Event::Frame arrives
  → unpack announce (cheap, no crypto)
  → extract emission_ts from random blob (cheap)
  → run cheap pre-queue bookkeeping
    (local-path-response/retransmit cleanup, local-destination check)
  → check bypass conditions (cache hit, path response)
    → if bypass: process immediately (no verify needed)
    → otherwise: enqueue in shared queue, move on

Event::AnnounceVerified arrives (from verify thread)
  → run post-verification logic on TransportEngine
    (path table update, retransmit, known_destinations, etc.)
  → dispatch resulting actions

Verify thread (low OS priority via nice/setpriority)
──────────────────────────────────────────────────────
Loop:
  → drain entries from shared queue
  → Ed25519 signature verification
  → send Event::AnnounceVerified back to driver via tx channel
```

### Why a dedicated thread

- The driver thread stays responsive for forwarding and connection
  management even during announce floods.
- The verify thread can run at lower OS priority (`nice` / `setpriority`)
  so it doesn't compete with the driver for CPU.
- The queue gives us a bounded backlog and an explicit load-shedding point
  during floods.
- All `TransportEngine` state mutations remain on the driver thread — no
  locking needed on engine internals.

### Shared queue

The queue sits between the driver (producer) and the verify thread (consumer).
It is a `Mutex<HashMap<AnnounceVerifyKey, QueueEntry>>` keyed by announce path
identity:

```rust
struct AnnounceVerifyKey {
    destination_hash: [u8; 16],
    random_blob: [u8; 10],
    received_from: [u8; 16],
}
```

```rust
struct PendingAnnounce {
    /// Raw packet bytes (pre-hop-increment, for cache storage).
    original_raw: Vec<u8>,
    /// Parsed packet as received by this node.
    packet: RawPacket,
    /// Receiving interface.
    interface: InterfaceId,
    /// Timestamp when first buffered.
    queued_at: f64,
    /// Best (lowest) hop count seen so far for this emission.
    best_hops: u8,
    /// Emission timestamp extracted from random blob (no crypto needed).
    emission_ts: u64,
    /// Random blob bytes for post-verification processing.
    random_blob: [u8; 10],
}
```

The shared wrapper:

```rust
enum QueueEntry {
    Pending(PendingAnnounce),
    InFlight {
        queued_at: f64,
        best_hops: u8,
    },
}

struct AnnounceVerifyQueue {
    /// Pending/in-flight announces keyed by exact path identity.
    pending: HashMap<AnnounceVerifyKey, QueueEntry>,
    /// Max entries.
    max_entries: usize,
    /// Approximate retained bytes across queued entries.
    max_bytes: usize,
    /// Drop queued/in-flight entries older than this.
    max_stale_secs: f64,
    /// Backpressure policy when the queue is full.
    overflow_policy: OverflowPolicy,
}
```

Wrapped in `Arc<Mutex<AnnounceVerifyQueue>>`, shared between driver and
verify thread. The mutex is held only briefly (HashMap insert/drain), never
during crypto.

### Queue states

For a given `AnnounceVerifyKey`, the queue has three states:

| State | Meaning |
|------|---------|
| `Absent` | No queued or in-flight work for this announce/path |
| `Pending` | Waiting in the queue for the verify thread |
| `InFlight` | Currently being verified by the verify thread |

Duplicates must be deduplicated against both `Pending` and `InFlight` entries.

### Replacement policy

The driver extracts the emission timestamp from the random blob **before**
enqueuing (cheap: `extract_random_blob` + `timebase_from_random_blob`, just
byte slicing).

| Case | Action |
|------|--------|
| Same key, lower hops | **Replace** if `Pending`, **update stored packet/best_hops** if `InFlight` |
| Same key, equal/higher hops | **Drop** — same queued work, worse or equal path |
| New key, queue not full | **Insert** |
| New key, queue full/over byte cap | Apply overflow policy (`drop_worst`, `drop_oldest`, or `drop_newest`) |

Notes:

- Because the key includes `random_blob`, newer announce emissions naturally
  get a different key and do not overwrite older ones.
- Because the key includes `received_from`, alternative paths are preserved and
  still reach the normal multipath logic after verification.
- The queue is a coalescing buffer, not a replacement for the announce
  signature cache.

### Staleness

Entries older than the configured queue TTL are evicted on drain. If the verify
thread falls behind, stale announces are discarded rather than verified — the
network has moved on.

### Bypass cases (process immediately on driver, skip queue)

- **Signature cache hit**: verification is free (hash lookup), no reason to
  defer. Process inline.
- **Path response announces** (`context == CONTEXT_PATH_RESPONSE`): replies to
  explicit path requests, latency-sensitive. Process inline.
- **Retransmit completion bookkeeping**: keep this on the driver before
  queueing so queued verification cannot delay announce-table cleanup.

### What runs where

| Step | Thread | Expensive? |
|------|--------|------------|
| Unpack `RawPacket` | Driver | No |
| Unpack `AnnounceData` | Driver | No |
| Extract random blob + emission_ts | Driver | No |
| Check signature cache | Driver | No (hash lookup) |
| Check bypass conditions | Driver | No |
| Retransmit completion bookkeeping | Driver | No |
| Enqueue in shared HashMap | Driver | No (mutex + insert) |
| Ed25519 signature verification | **Verify** | **Yes** (~0.15ms) |
| Insert into signature cache | Driver (on verified event) | No |
| Send `AnnounceVerified` event | Verify | No (channel send) |
| Path table update | Driver | No |
| Announce table / retransmit | Driver | No |
| Known destinations update | Driver | No |
| Emit `TransportAction`s | Driver | No |

### Event flow

New event variant:

```rust
Event::AnnounceVerified {
    destination_hash: [u8; 16],
    packet: RawPacket,
    original_raw: Vec<u8>,
    interface: InterfaceId,
    validated: ValidatedAnnounce,
    random_blob: [u8; 10],
    emission_ts: u64,
    sig_cache_key: [u8; 32],
}
```

The verify thread produces this after successful Ed25519 verification. The
driver handles it by:

1. inserting `sig_cache_key` into the announce signature cache,
2. clearing the queue entry for that key, and
3. running the post-verification path of `process_inbound_announce`.

Failed verifications (invalid signature) are silently dropped by the verify
thread — same as the current inline behavior. The queue entry must remain
`InFlight` until the driver processes the completion event to avoid a window
where duplicates can be re-enqueued before the signature cache is populated.

### Configuration

Add to the `[reticulum]` config section:

| Key | Default | Description |
|-----|---------|-------------|
| `announce_queue_max_entries` | 256 | Max pending announces in the shared queue |
| `announce_queue_max_bytes` | 262144 | Approximate byte cap for queued announce payloads |
| `announce_queue_ttl` | 30 | Max age in seconds for queued/in-flight announce work |
| `announce_queue_overflow_policy` | `drop_worst` | Queue overflow behavior: `drop_worst`, `drop_oldest`, `drop_newest` |

### MEMSTATS

Add `ann_verify_q=N` to the MEMSTATS log line showing the current queue depth.

---

## Tasks

### 1. Add `PendingAnnounce` and `AnnounceVerifyQueue`

- [ ] Create new file `rns-core/src/transport/announce_verify_queue.rs`
- [ ] Define `PendingAnnounce` struct with fields: `original_raw`, `packet`
  (`RawPacket`), `interface` (`InterfaceId`), `queued_at` (`f64`),
  `best_hops` (`u8`), `emission_ts` (`u64`), `random_blob` (`[u8; 10]`)
- [ ] Define `AnnounceVerifyKey` with fields: `destination_hash`,
  `random_blob`, `received_from`
- [ ] Define `QueueEntry::{Pending, InFlight}`
- [ ] Define `AnnounceVerifyQueue` struct with
  `BTreeMap<AnnounceVerifyKey, QueueEntry>`, `max_entries`, `max_bytes`,
  `max_stale_secs`, and `overflow_policy`
- [ ] Implement `new(max_entries)` and
  `with_limits(max_entries, max_bytes, max_stale_secs, overflow_policy)`
- [ ] Implement `enqueue(key, entry) -> bool` with the replacement
  policy described above (same-key hops comparison, eviction)
- [ ] Implement approximate queue byte accounting for admission/eviction
- [ ] Implement `take_pending(now) -> Vec<(AnnounceVerifyKey, PendingAnnounce)>`:
  evict stale entries, move only `Pending` entries to `InFlight`, and return
  the work batch
- [ ] Implement `complete_success(key)` / `complete_failure(key)` so the
  driver clears `InFlight` after handling the completion event
- [ ] Implement `len() -> usize` for MEMSTATS
- [ ] Implement `queued_bytes() -> usize` for future observability/debugging
- [ ] Add unit tests for:
  - Enqueue single entry
  - Same key, lower hops replaces pending entry
  - Same key, higher hops is dropped
  - Same key while in-flight updates best_hops or is dropped correctly
  - Different `received_from` keeps both entries
  - Different `random_blob` keeps both entries
  - Queue full — evicts highest-hops entry
  - Queue full — new entry with worst hops is itself dropped
  - `take_pending` marks entries in-flight instead of removing them outright
  - Stale pending/in-flight entries are cleaned up

### 2. Add config fields

- [ ] Add `announce_queue_max_entries: usize` to `TransportConfig`
- [ ] Set default: `max_entries = 256`
- [ ] Parse from config file in `rns-net/src/common/config.rs` under
  `[reticulum]`
- [ ] Add `announce_queue_max_bytes`, `announce_queue_ttl`, and
  `announce_queue_overflow_policy` to the `[reticulum]` config section

### 3. Add `Event::AnnounceVerified` variant

- [ ] Add the new variant to the `Event` enum in
  `rns-net/src/common/event.rs` carrying: `destination_hash`, `packet`,
  `original_raw`, `interface`, `validated` (the `ValidatedAnnounce`),
  `random_blob`, `emission_ts`, `sig_cache_key`
- [ ] Ensure `ValidatedAnnounce` is `Send` (it should already be, but verify)

### 4. Split `process_inbound_announce`

In `rns-core/src/transport/mod.rs`:

- [ ] Extract the **pre-verification** part of `process_inbound_announce`
  into `try_enqueue_announce`:
  - Unpack `AnnounceData` (no crypto)
  - Check signature cache — if hit, reconstruct `ValidatedAnnounce` and
    call `process_verified_announce` directly, return actions
  - Run retransmit completion bookkeeping before queueing
  - Check bypass conditions (path response only) — if so, verify inline and
    call `process_verified_announce`, return actions
  - Extract random blob + emission_ts
  - Build `AnnounceVerifyKey` from `destination_hash`, `random_blob`,
    `received_from`
  - Build `PendingAnnounce`, enqueue in the shared queue
  - Return empty actions (processing deferred)
- [ ] Extract the **post-verification** part of `process_inbound_announce`
  into `process_verified_announce`:
  - Takes `ValidatedAnnounce`, `packet`, `original_raw`, `interface`,
    `random_blob`, `emission_ts`
  - Runs: blackhole check, ingress control,
    multipath decision, rate limiting, path table update, announce table,
    retransmit, known_destinations, emit actions
  - This is called from the driver when it receives `Event::AnnounceVerified`
- [ ] In `handle_inbound` (line 802), replace the call to
  `process_inbound_announce` with `try_enqueue_announce`

### 5. Spawn the verify thread

In `rns-net/src/node.rs`:

- [ ] Create `Arc<Mutex<AnnounceVerifyQueue>>`, pass a clone to the driver
  and to the verify thread
- [ ] Spawn a `"rns-verify"` thread that:
  - Sets lower OS priority (`libc::setpriority` / `libc::nice`) if
    available, best-effort (don't fail if it can't)
  - Loops:
    - Lock the queue, call `take_pending(30.0)` to move non-stale `Pending`
      entries to `InFlight`, unlock immediately
    - If empty, sleep briefly (e.g. 50ms) and retry
    - For each entry: run `AnnounceData::validate()` (Ed25519 verify)
    - On success: send `Event::AnnounceVerified` via the driver's `tx`
      channel
    - On failure: send a lightweight failure/completion event or otherwise
      arrange for the driver to clear the `InFlight` state
  - Exits on shutdown (check an `AtomicBool` or when channel closes)

### 6. Handle `Event::AnnounceVerified` in the driver

In `rns-net/src/driver.rs`:

- [ ] Add a match arm for `Event::AnnounceVerified` in the `run()` loop
- [ ] Insert the sig_cache_key into the engine's signature cache
- [ ] Clear the matching `InFlight` queue entry before dispatching actions
- [ ] Call `engine.process_verified_announce(...)` with the validated data
- [ ] Dispatch the resulting actions
- [ ] Run the same post-processing as the current announce path (hooks,
  known_destinations, logging, callbacks)

### 7. Wire the shared queue into the driver

- [ ] Add `announce_verify_queue: Arc<Mutex<AnnounceVerifyQueue>>` to the
  `Driver` struct
- [ ] Pass it through from `Node` during construction
- [ ] The driver's `try_enqueue_announce` path locks the queue briefly to
  insert

### 8. Add MEMSTATS reporting

- [ ] Add `ann_verify_q=N` to the MEMSTATS log line, reading the queue's
  `len()` under lock
- [ ] Keep the lock duration minimal (just read len, release)

### 9. Tests

- [ ] Unit tests in `announce_verify_queue.rs` (covered in task 1)
- [ ] Integration test in `transport/mod.rs`:
  - Call `try_enqueue_announce` with N exact duplicates for same
    `(dest, random_blob, received_from)`
  - Verify queue has 1 entry with lowest hops
  - Call `try_enqueue_announce` with same `(dest, random_blob)` but different
    `received_from`
  - Verify both entries are retained for later multipath processing
  - Verify retransmit completion bookkeeping still happens even when the
    announce is queued instead of processed inline
  - Verify duplicates cannot be re-enqueued after verify-thread success but
    before driver-side cache insertion
- [ ] E2E test in `rns-net/tests/e2e.rs`:
  - Flood duplicate announces into a node
  - Verify they eventually get verified and produce path updates
  - Verify the verify thread handles the load without blocking the driver
- [ ] Verify thread shutdown test:
  - Start node, enqueue announces, shut down, verify clean exit

### 10. Deploy and validate

- [ ] Build, run full test suite (unit + E2E)
- [ ] Deploy to VPS following `docs/vps-deploy-runbook.md`
- [ ] Monitor with btop — verify CPU bursts are eliminated or greatly reduced
- [ ] Check MEMSTATS for `ann_verify_q` depth during burst periods
- [ ] Compare announce processing latency before/after (path table population
  rate on fresh start)
- [ ] Write production findings document
