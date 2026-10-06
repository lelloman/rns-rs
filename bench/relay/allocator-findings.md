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


## Live allocation and reclamation diagnostic — revision `154a731`

Two runs of the corrected daemon verified 59,781 Resources. The workload and
payload are unchanged: 30-second one/eight-link phases, depth two, ten seconds
initial idle and one-link recovery. Eight-link recovery now lasts 60 seconds,
followed by an explicit all-arena purge and ten more seconds idle. Every worker
exits before recovery; daemon threads return from 39 to 7, including the observer.

This separate executable enables jemalloc statistics in the ignored diagnostic
manifest, calls the real daemon entry point, and adds one observer thread. It
refreshes `epoch` and reads counters once per second; the external controller
samples process RSS every 100 ms. Both runs report 128 arenas, background
purging disabled, dirty decay 10,000 ms, muzzy decay zero, and 4 KiB pages. Normal
builds still have statistics disabled. No production allocator settings changed.

Values below are MiB and keep runs separate. Idle/recovery/purge rows are medians
of the last five seconds; load uses the ten-second window ending two seconds
before the load phase ends. Recovery-at-10s uses seconds five through ten after
endpoint exit. Each counter sample is paired with the preceding process sample,
less than 0.5 seconds apart. Maximum counter sample gap was 1.009 seconds.

| Run | Window | Allocated | Active pages | Metadata | Dirty pages | Process RSS |
|---|---|---:|---:|---:|---:|---:|
| 1 | Initial idle | 24.95 | 25.19 | 8.26 | 2.10 | 32.37 |
| 1 | Eight-link load | 27.78 | 30.54 | 13.86 | 5.59 | 44.41 |
| 1 | Recovery, 10 s | 25.08 | 25.80 | 12.99 | 3.87 | 39.35 |
| 1 | Recovery, 60 s | 25.05 | 25.80 | 12.99 | 3.87 | 39.35 |
| 1 | After purge | 25.05 | 25.80 | 12.99 | 0.00 | 37.66 |
| 2 | Initial idle | 24.95 | 25.19 | 8.26 | 2.10 | 32.43 |
| 2 | Eight-link load | 27.77 | 30.41 | 17.86 | 5.88 | 44.38 |
| 2 | Recovery, 10 s | 25.06 | 25.79 | 16.99 | 4.25 | 39.77 |
| 2 | Recovery, 60 s | 25.02 | 25.79 | 16.99 | 4.25 | 39.77 |
| 2 | After purge | 25.02 | 25.79 | 16.99 | 0.00 | 37.71 |

Allocator-reported allocated bytes return to within 0.08–0.10 MiB of initial
idle, while process RSS remains 6.98–7.34 MiB higher. Active-page overhead also
remains higher; metadata grows by 4.73–8.73 MiB. Passive recovery from ten to
60 seconds does not materially reduce RSS or dirty pages. There is no evidence
here of megabytes of additional application allocations remaining after the
transfers, but this short diagnostic is not a leak test or a long soak.

The explicit purge clears 3.87–4.25 MiB of dirty pages and reduces RSS by only
1.69–2.07 MiB. Allocated bytes, active pages and metadata are essentially unchanged;
RSS remains about 5.3 MiB above initial idle. The purge covers all arenas, including
pages already dirty before the load, so its effect is not solely reclamation of
load-induced growth. A more aggressive purge alone does not remove the entire
post-load footprint.

Interpret these counters carefully. `stats.resident` is an upper accounting bound,
not process RSS: after passive recovery it reports 42.54/46.91 MiB, versus process
RSS of 39.35/39.77 MiB. `stats.retained` describes virtual mappings, not resident
unused pages; it increases after purging even as RSS falls. Metadata accounting
is also not a direct measurement of its physical residency. Thread caches can
make allocation counters approximate. Definitions were checked against the
bundled jemalloc manual and the [jemalloc documentation](https://jemalloc.net/jemalloc.3.html#stats.allocated).

The observer, statistics-enabled allocator, and extra thread affect allocation,
metadata, CPU and RSS. These values must not be substituted for the original
uninstrumented allocator comparison, and no CPU or latency improvement is claimed.
The different metadata totals despite similar RSS reinforce that limitation.
This remains one Linux x86_64 host, with no constrained-CPU or slow-peer coverage.

Next, screen a smaller arena count (initial candidate: 8 versus the observed 128),
changing only that setting. Confirm the effective setting and attribution with
this diagnostic, then measure CPU, completion tails and memory with statistics
disabled. Test background reclamation separately afterward. Both are hypotheses;
neither is ready for a default change or a portable Linux-server recommendation.

Ignored evidence is in `.local/allocator-daemon/`: `stats.rs`, `run-stats.py`,
`summarize-accounting.py`, `accounting-provenance.json`, `accounting-summary.json`,
and `accounting-{1,2}/` raw counters, process samples, configuration and verified
transfer summaries. The diagnostic is `rnsd-stats`; measured baseline binaries
were preserved. Rebuilding uses the local manifest and shared `target` directory;
reruns require fresh output names in the runner. Total local allocator evidence
is about 193 MiB; no independent target tree or per-allocation trace was created.


## Arena-limit screen — revision `1ef8f6d`

Keep the default arena policy. An automatic arena limit of 8 reduces memory in
this workload, but is not a general performance improvement. All three one-link
pairs show higher CPU per Resource and worse completion latency; eight-link CPU
and latency results are mixed. Keep this as an experimental memory tradeoff,
not a recommended deployment setting or a new Cargo feature.

Only the daemon's `narenas` option changes. The baseline uses its default
configuration, which reports 128 on this host; the candidate sets
`_RJEM_MALLOC_CONF=narenas:8`. This limits automatic arenas, not the number of
arenas actually active. Effective options are read back and asserted on every
run. Background threads remain disabled, dirty decay remains 10,000 ms, and
muzzy decay remains zero. Endpoints receive neither the candidate setting nor
any allocator change.

Two accounting runs (128 then 8) use the previous frozen statistics-enabled
executable. Six performance runs use one new statistics-disabled executable,
with a startup options check but no observer thread. The three performance pairs
run in orders 128/8, 8/128, 128/8. Builds finish before measurements, and frozen
endpoint and daemon hashes are checked. Runtime library code is unchanged from
`154a731`; intervening commits contain findings only.

Each run uses the existing verified 512 KiB, compression-disabled Resource
workload: one then eight links, depth two, 30 seconds per load phase, fresh daemon
state, ten seconds initial idle and recovery. Accounting alone extends eight-link
recovery to 60 seconds and follows it with an explicit purge. All eight runs
succeed: 61,141 accounting transfers plus 167,576 performance transfers, or
228,717 total. No failures or retries are excluded.

### Accounting mechanism

Values are MiB, default → 8, using the same windows as the preceding accounting
section. These instrumented measurements explain allocation behavior; they do
not replace the statistics-disabled RSS measurements below.

| Window | Allocated | Active pages | Metadata | Dirty pages | Process RSS |
|---|---:|---:|---:|---:|---:|
| Initial idle | 24.95 → 24.95 | 25.22 → 25.22 | 8.26 → 5.46 | 2.10 → 2.10 | 32.37 → 31.77 |
| Eight-link load | 27.66 → 27.78 | 30.50 → 29.40 | 13.86 → 8.38 | 5.37 → 4.31 | 44.11 → 38.41 |
| Recovery, 60 s | 25.03 → 25.06 | 25.75 → 25.73 | 12.99 → 7.51 | 4.12 → 5.00 | 39.50 → 35.71 |
| After purge | 25.03 → 25.06 | 25.75 → 25.73 | 12.99 → 7.51 | 0.00 → 0.00 | 37.59 → 33.18 |

Lower metadata and active-page overhead are consistent with the intended
mechanism. Dirty pages after recovery increase rather than decrease; fewer
arenas do not automatically mean better reclamation. Allocated bytes after
recovery remain close to initial idle for both settings. As before, allocator
metadata and resident counters must not be equated with physical RSS.

### Statistics-disabled results

RSS is the load median and the last-three-second recovery median. Values are
MiB, default → 8. These runs have no forced purge.

| Pair | Eight-link load RSS | Eight-link recovery RSS | Sampled peak RSS |
|---|---:|---:|---:|
| 1 | 42.51 → 37.84 | 37.75 → 35.14 | 44.26 → 39.34 |
| 2 | 43.16 → 37.83 | 37.69 → 35.20 | 44.67 → 39.27 |
| 3 | 41.80 → 37.93 | 37.31 → 35.53 | 43.69 → 39.00 |

Eight-link load RSS falls by 3.87–5.33 MiB (9.3–12.3%); recovery RSS falls by
1.78–2.61 MiB. One-link load RSS changes by only −0.26 to +0.004 MiB, and its
recovery change is inconsistent (−0.50 to +0.19 MiB). Threads return from 10/38
to 6 in every performance run. Maximum process sample gap is 0.135 seconds.

CPU brackets daemon setup/load/drain and is normalized by verified Resources;
endpoint CPU is excluded. Completion latency runs from submission return through
proof/application acknowledgement settlement and includes queued work. Goodput
is verified payload divided by the whole load-phase duration, including setup
and drain. Values are default → 8; pairs and link counts are kept separate.

| Pair | Links | CPU ms/Resource | Median completion ms | p99 completion ms | Phase goodput MiB/s |
|---|---:|---:|---:|---:|---:|
| 1 | 1 | 4.767 → 5.389 | 14.127 → 16.266 | 19.924 → 26.369 | 59.142 → 51.146 |
| 1 | 8 | 6.177 → 6.000 | 19.269 → 17.847 | 28.819 → 25.498 | 350.981 → 390.776 |
| 2 | 1 | 5.116 → 5.325 | 14.370 → 15.713 | 26.664 → 39.314 | 56.942 → 50.421 |
| 2 | 8 | 6.519 → 5.977 | 21.662 → 17.780 | 33.054 → 24.933 | 322.771 → 383.789 |
| 3 | 1 | 5.079 → 5.622 | 15.189 → 17.279 | 27.235 → 80.025 | 53.594 → 43.302 |
| 3 | 8 | 5.692 → 5.810 | 16.678 → 17.001 | 21.530 → 22.010 | 416.870 → 385.609 |

One-link CPU/Resource rises 4.1–13.1%; median completion rises 9.3–15.1%, and
p99 rises 32.3–193.8%. The largest tail observation is exploratory, not an estimate
of a universal regression. Eight-link CPU changes by −8.3% to +2.1%, and p99 by
−24.6% to +2.2%. The worst individual sender's eight-link p99 also improves in
pairs 1/2 and worsens in pair 3: the worst-sender metric follows the aggregate
direction. This does not establish that every sender improved.

The host remains the unpinned, non-isolated 5950X with 32 CPUs available,
`schedutil` and boost enabled. Recorded one-minute load averages range from
3.39 to 18.69 and include this workload. Scheduling, allocator placement and
host interference are not isolated causes of the timing differences. Three
alternating pairs establish a useful memory tradeoff, not a portable performance
guarantee. No interactive, constrained-CPU, slow-peer or long-soak qualification
has been added. There is no basis here to promote the candidate to a default.

The following screen evaluates background reclamation separately with the
default arena policy.

Compact ignored evidence is in `.local/allocator-daemon/`: `arena.rs`,
`arena-{stats,perf}.py`, `run-arena-screen.py`, the two `summarize-arena-*.py`
scripts, `arena-provenance.json`, `arena-host.jsonl`, the screen contract,
`arena-{accounting,perf}-summary.json`, and all eight raw run directories.
`rnsd-arena` is the statistics-disabled comparison binary; `rnsd-stats` is the
accounting binary. Reproduction requires fresh output directory names. Total
local allocator evidence is about 260 MiB, using the existing shared target.


## Background-reclamation screen — revision `eb5da8a`

Keep background reclamation disabled by default. It releases dirty pages after
traffic stops and reduces recovery RSS, but increases loaded RSS and persistent
thread count in every performance pair. One-link p99 completion worsens in all
three pairs. CPU and throughput effects are mixed. This is a demonstrated idle
memory tradeoff, not a generally qualified performance improvement.

Only `background_thread:true` changes, supplied through `_RJEM_MALLOC_CONF` to
the daemon. The control leaves the environment override unset. Effective startup
options and the runtime `background_thread` flag are asserted for every run.
Both settings retain the observed default automatic arena limit of 128, dirty
decay of 10,000 ms, muzzy decay of zero, and background-thread limit of four.
The accounting executable additionally records actual background thread count
and work counters. Endpoints are frozen and receive no allocator override.

Two accounting runs (off/on) use one statistics-enabled executable and the
previous 60-second recovery/purge sequence. Six performance runs use a separate,
statistics-disabled executable with startup checks and no observer thread.
Their three pairs run off/on, on/off, off/on. Each run retains the same verified
512 KiB Resource workload: one then eight links, depth two, compression disabled,
30-second load phases, ten seconds initial idle and one-link recovery. Eight-link
performance recovery is extended to 30 seconds, with no explicit purge. All
builds finish before timing; hashes and effective settings are verified.

All eight runs pass without retries: 59,658 accounting and 160,471 performance
transfers, totaling 220,129. This does not add interactive, constrained-CPU,
slow-peer or long-soak coverage.

### Reclamation mechanism

Accounting values are MiB, off → on. Initial/load windows follow the earlier
accounting method. Recovery-at-10s uses seconds 5–10, recovery-at-30s uses 25–30,
and recovery-at-60s uses the last five seconds. The final row follows the
explicit all-arena purge and ten more seconds idle.

| Window | Allocated | Dirty pages | Process RSS | Background threads |
|---|---:|---:|---:|---:|
| Initial idle | 24.97 → 24.97 | 2.10 → 0.05 | 32.50 → 32.29 | 0.00 → 4.00 |
| Eight-link load | 27.65 → 27.78 | 5.46 → 4.66 | 44.14 → 45.33 | 0.00 → 4.00 |
| Recovery, 10 s | 25.02 → 25.05 | 4.08 → 4.32 | 39.58 → 40.90 | 0.00 → 4.00 |
| Recovery, 30 s | 25.00 → 25.03 | 4.08 → 0.00 | 39.58 → 37.65 | 0.00 → 4.00 |
| Recovery, 60 s | 24.99 → 25.02 | 4.08 → 0.00 | 39.58 → 37.65 | 0.00 → 4.00 |
| After purge | 24.99 → 25.02 | 0.00 → 0.00 | 37.65 → 37.65 | 0.00 → 4.00 |

The candidate clears dirty pages by the 30-second window; the control retains
4.08 MiB through 60 seconds. Explicit purge has no further RSS benefit for the
candidate. Background work counters reach 53 runs versus zero in the control.
Allocated bytes return near initial idle in both. Allocator metadata differs
between these runs (12.99 versus 14.98 MiB after recovery), so do not attribute
all RSS differences directly to dirty-page accounting. Statistics and the
observer affect these values; use the uninstrumented comparison for performance.

### Statistics-disabled results

RSS values are MiB, off → on. Load is the full load-phase median; the 10-second
recovery window uses seconds 5–10, and the 30-second window uses the last three
seconds. CPU in the last column is total daemon CPU over the entire 30-second
recovery interval, not isolated background-thread CPU.

| Pair | Eight-link load RSS | Recovery RSS, 10 s | Recovery RSS, 30 s | Recovery CPU seconds |
|---|---:|---:|---:|---:|
| 1 | 41.770 → 43.125 | 36.531 → 36.008 | 36.531 → 35.254 | 0.030 → 0.040 |
| 2 | 42.957 → 44.871 | 37.676 → 36.203 | 37.676 → 35.363 | 0.030 → 0.030 |
| 3 | 42.977 → 43.508 | 37.473 → 37.969 | 37.473 → 35.500 | 0.030 → 0.020 |

Thirty-second recovery RSS improves by 1.28–2.31 MiB (3.5–6.1%). Ten-second
recovery is not consistently better. Eight-link loaded RSS increases by
0.53–1.91 MiB; one-link loaded RSS increases by 0.29–1.00 MiB. Performance
threads rise from 6 to 10 at recovery and from 38 to 42 under eight-link load.
The idle CPU observations are quantized to 10 ms and cannot establish a precise
incremental background-worker cost; no zero-overhead claim is supported.

CPU and completion/goodput boundaries are unchanged from the arena screen:
daemon setup/load/drain CPU per verified Resource, submission-return through
proof/acknowledgement completion, and payload goodput including setup and drain.
Values are off → on, without pooling link counts or hiding individual pairs.

| Pair | Links | CPU ms/Resource | Median completion ms | p99 completion ms | Phase goodput MiB/s |
|---|---:|---:|---:|---:|---:|
| 1 | 1 | 5.169 → 5.254 | 16.085 → 15.813 | 27.957 → 59.704 | 49.120 → 45.939 |
| 1 | 8 | 5.578 → 5.844 | 16.372 → 17.635 | 26.008 → 23.496 | 409.561 → 380.472 |
| 2 | 1 | 5.200 → 5.724 | 16.010 → 15.915 | 24.841 → 42.278 | 50.994 → 50.940 |
| 2 | 8 | 6.395 → 6.297 | 21.120 → 19.897 | 119.031 → 46.754 | 291.946 → 321.767 |
| 3 | 1 | 5.162 → 4.774 | 16.077 → 14.463 | 22.291 → 24.308 | 51.999 → 57.353 |
| 3 | 8 | 6.453 → 5.561 | 21.454 → 16.457 | 31.447 → 21.245 | 320.283 → 387.104 |

One-link CPU changes by −7.5% to +10.1%, while one-link p99 worsens by
9.0–113.6% in all three pairs. Eight-link CPU changes by −13.8% to +4.8%.
Eight-link p99 and worst-sender p99 improve in every pair, but the second
control has a large retained tail outlier (aggregate 119 ms, worst sender
131 ms). These observations do not establish a general latency benefit.

This remains the non-isolated, unpinned 5950X with `schedutil`, boost enabled,
and 32 CPUs available. Recorded one-minute load averages span 5.40–19.50 and
include this workload; one host sample reports 138 runnable tasks. Timing
variation and outliers cannot be assigned solely to allocator behavior. Maximum
process sample gap is 0.321 seconds; accounting sample gaps stay below 1.002
seconds. Sampled RSS peaks can miss short spikes. These are exploratory results,
not deployment qualification or precise estimates of causal slowdowns.

The allocator screen is complete without a default, feature or production-code
change. The remaining allocator questions are workload-specific qualification
and speculative tuning, not demonstrated changes ready to ship. Further tuning
needs a concrete deployment requirement and a quieter controlled comparison;
there is no need to keep expanding this benchmark setup by default.

Ignored evidence is in `.local/allocator-daemon/`: `background-{stats,perf}.rs`,
`background-{stats,perf}.py`, `run-background-screen.py`, the corresponding
summarizers, provenance/host/summary/validation JSON files, screen contract and
eight raw run directories. `rnsd-background-stats` and
`rnsd-background-perf` preserve the separate comparison binaries. Reruns require
fresh output names. Total allocator evidence is about 359 MiB, with the existing
shared target reused and no per-allocation trace or independent target tree.
