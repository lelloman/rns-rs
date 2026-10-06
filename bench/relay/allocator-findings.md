# Linux daemon allocator comparison — 2026-10-06

## Decision

These findings are preliminary: two original pairs completed, while the third
System trial failed during link setup and was retried with endpoint setup logs.
The retry completed but does not explain the failure. Do not treat this as three
clean independent pairs or a qualification gate.

Keep jemalloc as the daemon default. System reduces resident memory in this
forwarding workload, but is not a clear performance winner. Investigate jemalloc
reclamation/arena settings separately before proposing a default change. No
production code, allocator configuration, Cargo feature or release profile was
changed by this experiment.

## What ran

The real `rns_cli::rnsd::main_entry` was built twice from revision `903430a`:
one minimal executable uses the daemon's normal `tikv_jemallocator::Jemalloc`
global allocator, the other uses Rust's System allocator. Daemon code and
interface features are identical. This changes Rust allocation; prefixed jemalloc
does not replace every native library's `malloc`. Symbol checks confirm the
allocator selection. No allocation tracing or stats instrumentation was enabled.

Portable release settings, full default interfaces, no hooks, Rust 1.96.0,
Ryzen 9 5950X, Linux x86_64. Allocator tuning environment variables were removed
for both variants; neither jemalloc nor glibc was given custom arena/decay
settings. Exact binaries, toolchain/libc version, source/lockfile hashes and
CPU affinity are retained locally. The host was not isolated or pinned.

Each daemon used a fresh configuration/state directory: transport enabled,
instance sharing disabled, one loopback TCP listener with ingress control
disabled, and the normal eager 250,000-entry deduplication table. It first idled
for ten seconds, then ran one link, recovered for ten seconds after endpoint
exit, ran eight links, and recovered for another ten seconds. Each link has
its own sender/receiver process pair and two TCP connections through the daemon.
The eight-link phase therefore has 16 daemon TCP connections. Threads rise from
6 to 10/38 under load and return to 6 during recovery in every completed run.

Both traffic endpoints always use System, with identical frozen executables.
All links must reach a setup barrier before any Resource load begins. Each sender
keeps at most two outstanding Resources for 30 seconds, then drains. Payloads
are 512 KiB of SHA-256-counter data with compression disabled. Receivers verify
length, SHA-256 digest and operation IDs, reject duplicates/gaps, and send an
application acknowledgement; sender settlement also requires Resource proof
completion. Final send/receive/proof accounting must agree.

The planned three pairs alternate jemalloc/System order. Pairs 1 and 2 complete
as planned. Pair 3's System run times out before eight-link traffic starts;
the entire System trial is repeated later with lightweight endpoint setup logging
and unchanged daemon logging. The original failure remains recorded. Rows marked
3* use that follow-up, not the failed trial, and have a longer time gap. Both
workloads run on the same daemon within a trial, so the eight-link phase includes the previous
one-link phase's history. Counts vary because the load is time-bounded. CPU is
normalized by verified Resources; RSS comparisons are not equal-work allocation
snapshots. No builds or tests overlapped these measurements.

## Memory

RSS is sampled from `/proc/PID/status` every 100 ms. Load medians include connection
setup/barrier, the continuous load and drain. Recovery is the median of the last
three seconds of the ten-second idle period after all endpoints exit. Values
are jemalloc → System, in MiB. These are process RSS observations, not live heap,
cgroup usage or allocation counts.

| Pair | Links | Initial RSS | Load median RSS | Sampled peak RSS | Recovery RSS |
|---|---:|---:|---:|---:|---:|
| 1 | 1 | 30.83 → 29.28 | 32.65 → 30.47 | 33.66 → 30.59 | 32.36 → 30.40 |
| 1 | 8 | 30.83 → 29.28 | 41.60 → 35.32 | 42.72 → 35.63 | 37.19 → 34.82 |
| 2 | 1 | 30.99 → 29.12 | 32.73 → 30.30 | 33.05 → 30.62 | 32.29 → 30.30 |
| 2 | 8 | 30.99 → 29.12 | 41.59 → 35.05 | 43.00 → 35.39 | 37.04 → 34.58 |
| 3* | 1 | 30.83 → 29.19 | 32.57 → 30.38 | 32.76 → 30.56 | 32.11 → 30.31 |
| 3* | 8 | 30.83 → 29.19 | 41.66 → 35.12 | 45.03 → 35.52 | 36.69 → 34.22 |

Across the eight-link pairs, System saves 6.29–6.54 MiB during
load and 2.37–2.47 MiB at recovery. After subtracting
each executable's own initial RSS, the difference in additional post-load RSS is
only 0.59–0.83 MiB. Much of the raw recovery difference was
already present before traffic; it must not all be described as reduced retention.
Code mappings, allocator metadata, retained pages and live application buffers
are not separated by these measurements. Observed maximum sample gap was
0.115 seconds; the sampled peaks can miss shorter spikes.

## CPU and transfer latency

CPU comes from the daemon's `/proc/PID/stat` user+system time, bracketing each
whole connection/setup/load/drain phase. Endpoint verification CPU is excluded.
Latency is observed by the fixed sender after submission, when its queue entry
has both the application acknowledgement and a proof and can retire from the
queue head. It includes endpoint work and queueing, and is not a wire RTT or an
independent interactive echo measurement. Values are jemalloc → System.

| Pair | Links | Verified Resources | Daemon CPU ms/Resource | Completion median ms | Completion p99 ms |
|---|---:|---:|---:|---:|---:|
| 1 | 1 | 3,236 → 2,938 | 5.037 → 6.545 | 15.471 → 19.390 | 53.481 → 29.143 |
| 1 | 8 | 27,703 → 27,700 | 5.358 → 5.510 | 16.042 → 16.215 | 20.442 → 20.941 |
| 2 | 1 | 2,753 → 2,893 | 6.219 → 6.225 | 18.942 → 16.542 | 30.809 → 52.552 |
| 2 | 8 | 27,446 → 27,677 | 5.346 → 5.498 | 16.080 → 16.169 | 20.711 → 20.740 |
| 3* | 1 | 2,474 → 2,610 | 6.342 → 7.157 | 22.547 → 19.922 | 31.342 → 30.240 |
| 3* | 8 | 24,694 → 27,758 | 5.452 → 5.504 | 16.410 → 16.164 | 80.033 → 20.326 |

Eight-link System CPU cost changes by +2.83%, +2.84%, +0.94% across
the two original pairs and follow-up comparison. One-link CPU and tail results vary more. These short, busy-host
runs do not establish a universal allocator ranking or a performance gate.

The six completed daemon runs retained for the tables contain twelve valid
load phases: **179,882 verified Resources**, excluding smoke/diagnostic trials. Every daemon shut down cleanly.
The fixed outstanding-work bound, payload and configuration were the same for
both variants. This is a 30-second continuous-load screen, not a long-duration
soak or a saturated/stalled-peer memory bound.

## Setup correction and remaining work

Initial attempts allowed the first connected pairs to start data traffic while
others were still discovering routes. Two attempts exceeded setup deadlines;
they are retained as failed/incomplete and excluded from allocator comparisons.
Explicit path requests alone did not make that setup reliable. The final harness
adds a barrier for every sender and receiver before starting the load. It improves
measurement validity, but did not eliminate the setup failure: in the original
third System trial, only three of eight pairs reached the barrier before the
25-second setup deadline. No eight-link data traffic had begun. Five earlier
synchronized trials and the later retry completed. At the time of this screen,
the setup failure was unresolved and prevented promoting it to qualification.
The follow-up below identifies a transport scheduling defect; it does not
retroactively qualify these allocator trials. The original third System trial's
completed one-link phase is also excluded from the tables to avoid mixing trials.

Next, inspect live/active/resident jemalloc accounting in a separate diagnostic
and test reclamation settings one at a time, retaining this untuned allocator as
the baseline. Actual allocation churn and retained-page attribution remain
unmeasured here. Interactive probes during bulk traffic, constrained CPUs,
other payload/compression mixes, slow peers and additional machines still need
qualification before selecting a general default. A System switch alone does
not explain or eliminate the daemon's post-load memory growth.

Compact ignored evidence (~107 MiB) is in `.local/allocator-daemon/`: harness sources and
lockfile, build/provenance/symbol records, three frozen executables, raw phase
samples and transfer latencies, summaries and excluded attempts. The long setup
trace is compressed. Builds reused the existing target directory; no independent
build trees were created. Reproduce with the retained `run.py` and binaries;
`barrier-*` retains both the original failed attempt and its later retry;
`summary.json` identifies the six completed runs used in the tables.

## Setup-timeout follow-up

Lightweight endpoint tracing reproduced the timeout with jemalloc
(`setup-trace-11`), and relay pathing logs reproduced it with System
(`setup-trace-12`). Affected senders repeatedly reported no path and never
created a link. The relay nevertheless learned their destinations and scheduled
known-path responses. For one destination, it logged 25 path updates and 25
scheduled responses, with a roughly 22-second gap between actual retransmissions.
The eight-link load barrier never opened in either failed run.

Announces and path requests arriving near the one-second maintenance tick could
replace an already-pending announce with a later deadline. Repeating this moved
the send past successive ticks. Replacement now keeps the earlier pending
deadline while using the replacement payload and routing metadata. Expired and
completed entries do not supply deadlines, and the existing interface announce
queues still govern transmission. Known-path replies retain the active entry
until replacement so the same rule applies there.

Two deterministic regressions fail against the original code and pass with this
fix: a repeated known-path request, and an incoming announce replacing either an
ordinary pending announce or a path response. Another test covers expired and
completed entries. Core and networking unit suites pass (667 and 1,023 tests),
as do core Clippy, formatting and no-default-features checks.

Twelve short live runs, alternating allocators, completed all 108 link setups and
verified 11,490 Resources. These are correctness checks, not allocator performance
measurements. The diagnostic endpoints retain the original behavior of one link
attempt per destination; no retry loop or longer setup deadline hides failures.

Two further runs used the original 30-second load and 10-second idle/recovery
phases, one per allocator (`setup-fixed-long-1` and `setup-fixed-long-2`). Both
passed, verifying 58,434 more Resources across 18 link setups. Together these
checks completed 126 link setups and 69,924 verified transfers.

Ignored evidence includes the failed setup traces, compressed relay log,
before-fix regression output, corrected build diff/hashes, and all validation
summaries. Original measured binaries remain at their original paths;
`*-setup-fixed` preserves the corrected daemon builds and diagnostic endpoint.
Use those binaries for a new run of `setup-trace.py` (with fresh output names).
These runs do not replace the earlier allocator measurements or establish
long-soak reliability.
