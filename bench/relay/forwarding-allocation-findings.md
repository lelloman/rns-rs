# Linux forwarding allocation investigation — 2026-10-05

Three full packet parses account for approximately 63% of allocated bytes in
this TCP Resource relay workload. The async writer handoff accounts for about
7%. This supports testing cheaper header classification before another shared
writer-buffer prototype. Allocation shares are not CPU shares or promised speed
improvements. No production code or defaults changed in this investigation.

## Capture scope

The diagnostic calls the actual `rns_cli::rnsd::main_entry()` at `a5d54eb`, using
jemalloc with its `stats` and `profiling` build features enabled. All dependency
versions match the root lockfile; only the local diagnostic package is extra.
The portable release build retains debug symbols. A separate observer thread,
excluded from profiling, accepts start/stop commands and acknowledges completed
profile resets/dumps. Startup, link establishment and warmups are outside the
allocation windows. `prof_accum:true` retains cumulative allocation histories;
these profiles include freed allocations, not just surviving heap objects.

Each fresh daemon enables transport with an eager dedup table, one loopback TCP
listener and instance sharing disabled. Fixed endpoints verify 1 MiB
SHA-256-counter Resources without compression, including lengths, digests,
operation IDs, completion and endpoint counts. Two captures each profile 128
transfers on one link, then 32 per link on eight concurrent links, sampling at
an average interval of 64 KiB of allocation activity. A smaller confirmation
profiles every allocation (`lg_prof_sample:0`): 16 transfers on one link and
four per link on eight links. All three captures complete successfully:
**840 verified transfers, 816 inside profile windows and 24 warmups**.

This measures ordinary established-link forwarding, including associated
control traffic. It does not measure IFAC, broadcast fanout, small-message
latency, stalled queues, rejected traffic or allocation peaks during load.
Profiler overhead changes allocation behavior and timing; these runs cannot
serve as normal-daemon timing or resident-memory comparisons.

## Allocated bytes

Jemalloc/jeprof cumulative allocated-space totals include allocator sizing and
reallocation activity. They are not unique payload bytes, bytes copied, live
memory or process RSS. Sampled totals are estimates.

| Capture | Verified payload in window | Allocated MiB | Allocated MiB per payload MiB |
|---|---:|---:|---:|
| First, one link | 128 MiB | 1,835.05 | 14.336 |
| Second, one link | 128 MiB | 1,843.31 | 14.401 |
| First, eight links | 256 MiB | 3,685.70 | 14.397 |
| Second, eight links | 256 MiB | 3,685.87 | 14.398 |
| Every allocation, one link | 16 MiB | 233.06 | 14.566 |
| Every allocation, eight links | 32 MiB | 466.17 | 14.568 |

The full-sampling result is a cross-check of the ranking, not a calibration
factor to apply to the sampled runs. Allocation-count estimates at 64 KiB
sampling vary substantially for small objects; use the full-sampling capture
for counts instead.

The following stack groups are disjoint on the measured forwarding path.
Percentages span the four sampled windows; counts are cumulative allocation
events, including reallocations, in the full-sampling **one-link** window.

| Boundary / call site | Share of allocated bytes | Allocation events |
|---|---:|---:|
| Inbound queue: `EventSender::classify` | 20.8–21.1% | 1,856 |
| Driver: `DecodedPacket::unpack` | 20.8–21.0% | 1,856 |
| Outbound: `is_outbound_path_request` | 20.8–21.1% | 1,856 |
| Link-table forwarding, including action/Arc construction | 14.0–14.3% | 1,856 |
| Async output: `AsyncWriter::enqueue` | 6.9–7.1% | 464 |
| HDLC decode: `unescape` | 7.9–8.1% | 464 |
| HDLC encode: `frame` | 7.9–8.2% | 464 |

The entire full-sampling window contains 10,476 allocation events; the eight-link
window contains 21,007. Small control/action/batch allocations account for the
remainder. The counts at the three main unpack sites are consistent with four
allocation events per packet: payload, raw packet, and a hashable temporary
that grows from its initial allocation. Across all unpack callers,
`compute_hashable_part` accounts for approximately 21% of allocated bytes;
that is **included** in the parsing rows, not an additional cost.

## Ownership and copying map

Source inspection explains the sampled stacks without treating allocated bytes
as a measurement of copying:

- **Socket to decoder:** a stack read buffer is appended to a retained decoder
  `Vec`. Unescaping creates a per-frame `Vec`, moved into the inbound event.
  Decoder compaction shifts remaining bytes; its backing capacity is retained.
- **Inbound queue:** classification invokes `RawPacket::unpack` and then drops
  the result. It copies payload, raw bytes and hashable bytes just to distinguish
  announce/path-request/data queues. The queued event retains only its original
  frame, not a second decoded packet.
- **Driver and engine:** driver unpacking repeats those copies. The accepted
  decoded-packet reuse passes that result into the engine, preserving current
  admission checks. Link routing builds a hop-rewritten `Vec`; converting it to
  `Arc<[u8]>` allocates shared storage and copies its contents. Arc clones can
  share those immutable bytes, but this capture does not exercise broadcast
  fanout and cannot quantify its benefit.
- **Outbound classification:** `is_outbound_path_request` invokes full unpack,
  including hashing and owned buffers, to inspect destination hash, destination
  type and packet type. This happens before the ordinary targeted send.
- **Async handoff:** `AsyncWriter::enqueue` copies borrowed packet bytes into
  an owned queue entry. The worker drains available entries into a batch.
  Ownership keeps bytes alive through writes and failures; an ownership change
  must preserve completion, byte-budget and rejection cleanup behavior.
- **TCP encoding:** `hdlc::frame` allocates one buffer at the calculated escaped
  size. `write_all` handles partial writes, then the temporary is dropped.
  This is already a single framing allocation, not an escape-then-wrap pair.
- **IFAC, source inspection only:** masking/unmasking introduces a derived mask,
  intermediate packet storage and final packet storage. It requires a separate
  authenticated workload; do not extrapolate the unmasked relay percentages.

For a valid HEADER_1 packet of N bytes, each full unpack explicitly copies
N−19 payload bytes, N raw bytes and N−1 hashable bytes, besides temporary growth.
This is a source-derived per-call description, not an observed whole-run copy
counter. Copies into retained decoder storage and compaction may allocate
nothing, so allocation profiling alone cannot measure total memory traffic.

At the end of the full-sampling windows, profiled live storage is zero for one
link and 32 KiB for eight links. This excludes all allocations made before the
window, including dedup and established connection storage. It is not a claim
that the daemon has no live heap. Short-lived turnover dominates this capture;
peak live bytes, retained capacities and stalled-peer queue occupancy remain
unmeasured here. See the separate daemon memory report for normal RSS/retention.

## Next isolated change

First trial a header-only outbound path-request predicate. Preserve the full
unpack predicate's structural acceptance rules, including minimum lengths,
hop limits and nonempty payload; compare both predicates on malformed and valid
HEADER_1/HEADER_2 inputs. It must preserve accounting/classification and leave
actual packet validation and authentication intact. Then run the normal
correctness suite and matched bulk/mixed relay checks with profiling disabled.
The roughly 21% allocation share is an opportunity, not a speedup prediction.

Queue classification is another similarly sized opportunity, but should be a
separate change because its behavior affects admission and queue budgets.
Keep broader borrowed parsing, shared writer ownership, bounded batching and
encoding reuse separate. This first B pass establishes the unmasked forwarding
ranking; IFAC/fanout, exact copy counters and pressure/retained-capacity coverage
remain open. The previous shared-handoff candidate stays parked.

Raw captures, manifests, frozen binaries, local observer/capture sources and
jeprof reports live under `.local/forwarding-allocation/`. The profiler script
comes from the installed jemalloc dependency. Original heap dumps are retained;
`*.symbols.heap` copies only replace the executable mapping path with the matching
frozen binary path for symbolization. The restored sampled binary's SHA-256
matches both original manifests. All capture processes were stopped.

## Outbound classification implemented — 2026-10-05

The outbound path-request predicate now uses a crate-private borrowed header
reader. It preserves `RawPacket::unpack`'s structural acceptance, including
truncation, empty payloads, hop limits and flag interpretation, without copying
payloads or hashing. Actual packet validation/authentication is unchanged.
Differential tests cover all flag bytes and wire-length/hop boundaries. All 990
network unit tests, 58 network end-to-end tests and net/bench all-target Clippy
checks passed. An initial sandboxed unit run could not open sockets; the full
unsandboxed rerun passed.

Normal portable `profiling` builds, with no sampling instrumentation, were used
for acceptance. Frozen endpoints and alternating run order were retained.
The standard System-allocator relay comparison passed 576 cases across three
initial bulk/mixed pairs plus a confirmation pair of each. Initial bulk pair 0
is excluded from timing conclusions because it overlapped the end-to-end tests.
The other bulk CPU changes were −12.45%, +0.21% and −9.49%; elapsed changes were
−2.40%, +7.33% and −0.06%. The bulk latency spike did not repeat in confirmation.

Mixed CPU changes were +4.76%, −6.24%, −1.97% and +2.14%: no consistent mixed CPU
win. RSS medians stayed within 0.2%. Probe tails varied considerably. Pooled
small-message-only p95/p99 was 0.634/3.786 ms before and 0.602/4.093 ms after;
with a Resource active it was 60.320/134.857 ms before and 55.020/91.599 ms after.
Individual pairs improved and regressed, including a candidate latency outlier;
these short uncontrolled runs do not establish latency equivalence or a
universal improvement. All results, including regressions, remain in evidence.

A separate actual `rnsd`/jemalloc comparison used three alternating pairs with
128 verified 1 MiB transfers at one link and 32 per link at eight links, after
warmup. All 2,352 transfers including warmups passed. Daemon CPU is measured
from `/proc/PID/stat` (10 ms accounting resolution); endpoint work is excluded.

| Pair | One-link CPU | Eight-link CPU | Eight-link elapsed |
|---|---:|---:|---:|
| 0 | −9.21% | −5.50% | −5.03% |
| 1 | −15.95% | −4.53% | −4.89% |
| 2 | +5.26% | −2.30% | −3.59% |

Eight-link RSS was 0.52–0.76 MiB lower and Resource p99 improved in all three
pairs. One-link pair 2 had an elapsed/p99 outlier (+48% elapsed, 36→94 ms p99);
one-link RSS stayed within 0.4 MiB. Retain the narrowly scoped allocation/hash
removal based on the sustained eight-link gain and equivalent behavior, while
keeping tail-latency qualification open. This is not a completed latency gate,
a general mixed-workload CPU improvement, or a deployment-scale guarantee.

Evidence: `.local/perf-opportunities/outbound-header-relay`,
`outbound-header-confirm`, `outbound-header-daemon`, the frozen
`relay-outbound-header.bin` and `rnsd-outbound-header.bin`, plus test/build logs.
The original baseline binaries remain unchanged. Queue classification is next
and must be evaluated relative to this outbound-only change.
