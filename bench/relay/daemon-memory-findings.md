# Linux daemon memory investigation — 2026-10-04

The dominant idle cost is the fixed deduplication table storage, not thread
stacks. Load adds allocator and connection overhead; after disconnect, thread
count recovers while several MiB of anonymous memory remain resident. No
production defaults or allocator choices were changed in this investigation.

## Measurement scope

The normal executable is `rns-cli`'s actual `rnsd` at `c9fd9ec`, built with default
features and the portable optimized `profiling` profile. It selects jemalloc.
Each run used a fresh, isolated user-systemd service and daemon-only cgroup:
transport enabled, one loopback TCP listener, instance sharing disabled, no
configured hooks or discovery interfaces, other settings at defaults. This is
a controlled forwarding configuration, not a snapshot of a deployed server.

Fixed benchmark endpoints ran outside the daemon cgroup. They checked Resource
lengths, SHA-256 digests, operation IDs, proofs/application completion and counts.
Payloads were 1 MiB of SHA-256-counter data with compression disabled. Measurements
covered idle, warmup, 20 seconds at one link, 20 seconds at eight concurrent
links, and approximately 15–18 seconds after disconnect. Process `/proc` memory
and cgroup counters were sampled every 500 ms; detailed mappings, thread names
and logs were retained at phase transitions. Builds finished before workloads.

There were 18,260 verified Resource transfers across four runs. This excludes
the incomplete stalled-peer probe train described below. These short diagnostic
runs are not long-duration soak tests, matched timing comparisons or performance
gates; achieved traffic volume varied between runs.

## Normal daemon: phase medians

All memory figures are MiB. The second normal run also exercised a stalled peer.

| Phase | RSS, first / second run | PSS, first run | Anonymous, first run | Cgroup current, first run | Threads |
|---|---:|---:|---:|---:|---:|
| Idle | 30.23 / 30.26 | 28.56 | 24.97 | 25.61 | 6 |
| One link | 33.34 / 33.13 | 31.67 | 27.77 | 28.84 | 10 |
| Eight links | 44.63 / 45.19 | 42.96 | 39.06 | 42.31 | 38 |
| Post-disconnect recovery | 37.32 / 37.19 | 35.52 | 31.62 | 32.58 | 6 |

Normal-daemon cgroup peaks were 45.49 and 45.87 MiB. Peak RSS samples were
45.75 and 46.02 MiB. RSS, PSS and cgroup usage have different accounting scopes:
file-backed pages can be resident in this process but charged to another cgroup
that first populated the cache. These measurements do not reconstruct the
earlier approximately 33 MiB benchmark-worker cgroup peak, and that historical
number must not be interpreted as live heap.

## Ranked memory budget

1. **Fixed deduplication storage dominates idle memory.** With 250,000 retained
   entries, the FIFO requests 8,000,000 bytes of hash payload, the hash table
   requests 16,777,216 bytes, and controls request 524,288 bytes: 24.13 MiB in
   total, before allocator rounding. Eager initialization touches the 23.63 MiB
   of payload storage. This matches the large resident anonymous mapping and
   the calibration below. Other caches and allocations are not individually
   attributed by this pass.
2. **Allocator overhead/retention is a stronger post-load candidate than a
   growing live application heap.** In a separate stats-enabled diagnostic,
   live jemalloc allocations returned close to idle after disconnect, while
   metadata, allocator mappings and process RSS stayed higher. This supports
   investigating arenas and decay, but does not precisely apportion every
   retained byte in the uninstrumented daemon.
3. **Connections and kernel buffers add load-dependent memory.** Six base
   threads grew to 38 for 16 TCP connections: one reader and one writer per
   connection. The first run's sampled kernel accounting was about 0.38 MiB
   idle, 1.83 MiB during many-link load and 0.91 MiB after recovery; socket
   counters varied with queued traffic. These are cgroup counter observations,
   not disjoint terms to add to RSS.
4. **Resident stacks are comparatively small here.** Guarded anonymous mappings
   of approximately 2 MiB, consistent with worker stacks, totaled about 0.10 MiB
   resident idle, 0.68 MiB after many-link load and 0.45 MiB after recovery in
   the second run. Some mappings persisted after threads exited. Their virtual
   reservations were much larger (10/74/48 MiB). This is mapping-pattern
   attribution, not a definitive TID-to-stack mapping; it does not justify
   shrinking thread stacks.

## Allocator diagnostic, kept separate

Normal jemalloc builds disable detailed stats. A local diagnostic executable
called the same `rns_cli::rnsd::main_entry`, enabled jemalloc stats and added one
500 ms observer thread. Dependency versions were pinned to the repository lock.
An initial build with dependency drift was discarded before measurement.

| Phase | Allocated | Active pages | Metadata | Process RSS |
|---|---:|---:|---:|---:|
| Idle | 24.76 | 24.94 | 8.08 | 31.59 |
| One link | 25.18 | 26.11 | 8.56 | 34.30 |
| Eight links | 27.75 | 31.30 | 15.87 | 47.84 |
| Recovery | 24.96 | 25.63 | 15.00 | 39.84 |

These are allocator counters from an instrumented build, not a partition of
normal-daemon RSS. Jemalloc's `stats.resident` is an upper estimate that includes
demand-zero pages; `stats.retained` describes virtual mappings, not physically
resident memory. The diagnostic's latter counter rose from about 15 to 78 MiB,
which must not be presented as 63 MiB of extra RAM consumption. Non-jemalloc
allocations and kernel memory are outside these live-allocation counters.

Arena allocation/deallocation counters showed substantial balanced turnover
under traffic, including hundreds of thousands of large-allocation events.
They do not identify forwarding call sites or count every Rust allocation when
thread caches are involved. Call-site attribution remains the next profiling step.

## Existing lazy-allocation setting: attribution calibration

Using the same normal executable with `packet_hashlist_allocation = lazy`
reduced idle RSS to 6.63 MiB and anonymous memory to 1.33 MiB. The anonymous
difference, about 23.64 MiB, closely matches the payload pages eagerly touched
by the default policy. Live storage capacity is unchanged.

RSS grew during traffic: median 24.44 MiB at one link, 38.98 MiB at eight links,
and 34.86 MiB after disconnect. Lazy allocation defers page commitment; it is
not a sustained 24 MiB saving on a busy relay. Loaded figures are descriptive,
since this run forwarded a different amount of verified traffic. No new default
or latency/throughput recommendation follows from this single calibration.

## Stalled-peer test and limits

A separate probe link attempted 50,000 verified echoes at 100 microsecond
intervals while its receiving process was paused for six seconds. TCP inspection
showed about 2.58 MB of unsent relay data and a full approximately 2.63 MB kernel
send buffer. An independent link completed a verified 1 MiB Resource in 29 ms
while the peer remained paused; this single observation is not a latency bound.

After resume, the receiver reported `outbound queue is full` while echoing, and
the sender ultimately hit its probe deadline. The probe round is **incomplete**;
it is not evidence of lossless stalled-peer recovery or of daemon packet loss.
Endpoint logs and failure results are retained. Daemon memory and thread count
recovered as shown above. Exact daemon writer-queue occupancy and per-boundary
copy counts were not instrumented; a bounded dedicated pressure workload is
needed before adopting any queue or batching changes.

## Next work and evidence

Proceed with forwarding allocation/copy attribution (plan B), separating packet
ownership, framing buffers and immutable fanout. This budget also supports
separate arena/decay experiments using actual `rnsd`, with CPU and tail-latency
checks before any allocator/configuration change. Keep current defaults.

Raw evidence and local measurement tools are under `.local/daemon-memory/`:
`eager-baseline`, `eager-pressure`, `eager-allocator-diagnostic`, and
`lazy-calibration`, plus build provenance and mapping summaries. The first run
did not label connection setup separately in the sampler; settled idle/load
medians and named mapping snapshots are used here. Later runs label setup
explicitly. All temporary services were stopped after capture.
