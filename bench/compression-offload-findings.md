# Sender compression offload

Screening decision (2026-10-05): proceed to a bounded production-worker design. Moving
sender compression off the driver substantially reduced echo stalls in all
three measured pairs for every loaded payload family. The diagnostic is saved
locally. The production implementation and its separate validation are recorded
below; the original screening results describe the earlier diagnostic only.

## Mechanism and diagnostic scope

`driver/events.rs` handles `SendResource` synchronously by calling
`LinkManager::send_resource_with_auto_compress`. Resource construction invokes
bzip2 before returning to the driver event loop. Inbound Resource assembly also
decrypts/decompresses synchronously in `resource_handling.rs`. Independent links
share this driver, so codec work can delay their packets.

The diagnostic moves only compression of a single-segment buffered Resource to
a worker thread. It retains the existing default level 6, metadata encoding,
compression selection, encryption, hashes and proof handling. A completion
event returns the prepared result to the driver; exact input equality is
asserted before the existing constructor consumes the cached codec result.
The driver still performs encryption, hashing and part construction. Receiver
assembly is unchanged.

The experiment admits one pending compression job per process, with no waiting
job queue. A second concurrent eligible submission deliberately fails an
assertion rather than silently creating more workers. Eligibility is at least
16 KiB of payload, with payload plus metadata fitting one Resource segment.
Each job creates a fresh thread and retains an extra metadata-prefixed input
copy; this is not the proposed production allocation/thread lifecycle.
Completion checks draining state and the current derived link key, then the
existing constructor rechecks active link state. These checks are not a
substitute for tested generation-based cancellation.

## Workload and results

One frozen executable toggled the diagnostic off/on. Three alternating pairs
per family, one warmup and five measured rounds per case: **30 valid cases,
180 probe trains, 23,040 verified echoes and 144 verified Resource transfers**,
including warmups. Four loaded families use a 512 KiB Resource; a separate
control has only probes. Each train schedules 128 echoes on a second link every
2 ms and starts the Resource after 20 ms. Topology is unshaped loopback with
one sender node and one receiver node in separate processes.

Pooled echo RTT p99 uses 1,920 measured echoes per cell. Resource latency is the
median of 15 measured completions, including receiver digest/length/operation-ID
validation and sender proof plus application acknowledgement:

| Workload | Inline echo p99 ms | Offload echo p99 ms | Inline Resource ms | Offload Resource ms |
| --- | ---: | ---: | ---: | ---: |
| Probes only | 0.43 | 0.44 | — | — |
| Seeded | 53.89 | 39.27 | 97.65 | 78.58 |
| SHA-256 counter | 60.08 | 4.94 | 68.78 | 49.35 |
| Random first half | 71.37 | 17.87 | 94.44 | 70.49 |
| Repeated random block | 148.36 | 13.68 | 169.05 | 148.78 |

Per-run echo p99 ranges across the three rounds, inline → offload:

- Seeded: 50.86–54.28 → 34.53–41.68 ms.
- SHA-256 counter: 59.50–60.55 → 4.23–5.35 ms.
- Random first half: 70.51–71.74 → 16.40–19.58 ms.
- Repeated random block: 146.00–149.02 → 13.18–15.58 ms.
- Probes only: 0.41–0.46 → 0.42–0.44 ms.

Scheduled-to-echo p99 tracks the same effect (offload: 39.34, 5.00, 17.93 and
13.75 ms respectively). The result is not merely later probe submission hiding
the stall. All admitted probes completed; no failed cases were excluded.

Diagnostic stage medians, including warmups, in milliseconds:

| Payload | Inline driver preparation | Worker compression | Driver finalization |
| --- | ---: | ---: | ---: |
| Seeded | 53.98 | 30.22 | 4.37 |
| SHA-256 counter | 60.35 | 35.47 | 4.76 |
| Random first half | 70.99 | 46.85 | 3.03 |
| Repeated random block | 148.44 | 128.33 | 1.86 |

Worker start medians were 0.09–0.11 ms; completion-event queue delay medians
were about 0.012–0.013 ms. All 72 offloaded preparations returned and all 72
inline preparations completed. Stage times are wall-clock diagnostic probes;
they neither sum to whole-transfer latency nor isolate CPU costs. Different
thread/core placement, cache state and uncontrolled host load can affect codec
timing. Do not describe moving work as making bzip2 inherently faster.

Process CPU snapshots include worker threads. Median sender CPU per measured
train fell from 88.88 to 72.66 ms for seeded data, 93.66 to 80.00 for SHA-256,
103.58 to 87.69 for half-random and 170.41 to 165.42 for repeated blocks.
Receiver CPU sometimes increased; these short runs do not qualify total CPU
improvement under contention. Responsiveness is the primary demonstrated gain.

Post-load sender RSS medians changed by about +1.59, +0.15, +0.87 and +0.02 MiB
respectively. These snapshots are not in-flight peaks. A persistent worker pool
may retain codec/allocator memory differently from these short-lived threads.
Production memory qualification must therefore be repeated with its actual
worker lifetime and admission budgets.

## Remaining work and limitations

The seeded residual stall is consistent with the receiver's synchronous
assembly/decompression path, but that stage was not timed here. Attribute it
before offloading receive work. Sender offload alone does not eliminate all
interactive interference.

This diagnostic deliberately does not support multiple queued sends, same-link
ordering under concurrent submissions, streamed/split Resources, request
responses, cancellation races, queue saturation or joined worker shutdown.
Its completion send may block on the control queue; its fresh threads and
thread-local cached result are unsuitable as a production design. The actual
implementation needs bounded job/byte admission, ordered ownership transfer,
stale-result rejection, reliable completion delivery and deterministic cleanup.
It must preserve authentication and decompression limits and be retested under
single-CPU contention, concurrent transfers and slow peers. No default is
changed solely on this diagnostic.

## Reproduction and provenance

Baseline: `603b54c`. Build: `cargo build --locked --profile profiling -p
rns-bench`, System allocator, portable settings. Local evidence lives under
`.local/compression-offload/`: `trial.patch`, `trial.bin`, `build.log`, `run.py`,
`summarize.py` and `runs/`. `runs/manifest.json` records executable/patch/lockfile
hashes, CPU/toolchain, workload and host load. The patch was frozen and removed
before measurement; the per-run clean-checkout metadata alone does not describe
the diagnostic binary. Every case preserves events, stderr stage probes,
metrics and status; `runs/summary.json` retains individual-pair p99 values.

Rebuild from the saved patch or use the frozen binary, then run `run.py` with
a fresh `runs/` directory and `summarize.py` after completion. Only the diagnostic
recognizes `RNS_TRIAL_OFFLOAD`; this is not a supported application setting.
The local custom-case entry point supplies explicit mixed cases; stock scenario
metadata in the runner is not this diagnostic's workload definition. No builds
or separate test jobs ran concurrently with measurement. Host load and thread
placement were uncontrolled; these are exploratory Linux endpoint results,
not daemon/jemalloc or constrained-device qualification.

## Production implementation and validation

The implemented scope is buffered application sends of at least 16 KiB whose
payload plus metadata fits one efficient Resource segment (1 MiB minus one
byte). One persistent worker starts lazily per node. Admission is capped at
eight jobs and 8 MiB, charged against actual owned input/metadata capacities
plus reserved retained compressed output. Completed results and cancelled jobs
retain their charge until consumed. Native codec workspace, one running job's
temporary metadata-prefixed input/output and driver finalization are additional;
this is not a bound on whole-node RSS or existing active Resources.

The driver owns all link state, encryption, hashes, advertisements and proofs.
Compression stays at level 6 with identical selection/format. Results return
through a bounded private mailbox; a nonblocking wake event cannot deadlock
against a full control queue. The driver polls the mailbox before waiting for
events. Work is FIFO, and link-generation tokens prevent installation after
teardown/replacement. Queued cancelled jobs skip compression; a running codec
call finishes before its result is discarded. Shutdown joins the worker and
drops queued work. Drain accounting includes admitted preparations and allows
accepted work to finish until shutdown/the drain deadline.

Small, split, reader and response paths retain synchronous preparation. A full
budget or worker-start failure also uses the synchronous path, after earlier
buffered preparations on the same link are resolved. Explicit reader/request/
deferred-response submissions have the same ordering barrier. Independent
inbound request handlers retain their existing synchronous behavior. There is
no new overload rejection policy. Saturation can therefore still stall the
driver; fairness under arbitrary overload is not promised. Joining cannot
preempt bzip2 and may extend shutdown by the current bounded-size codec call.

Validation passed: 1,002 network unit tests, 59 end-to-end tests, Clippy with
warnings denied, formatting, and the network crate without default features.
New tests cover job/byte limits including owned capacity, metadata/segment
boundaries, FIFO, a full wake queue, cancellation before/during/after preparation,
stale generations, draining, joined shutdown and worker panic recovery. A live
12-send burst checks every payload/metadata and all completion proofs. A separate
deterministic driver test fills admission and verifies synchronous fallback
ordering without dropping sends.

### Production timing comparison

The unchanged `97fdcdf` baseline and production candidate each use the same
local custom-case adapter, without diagnostic timing probes or per-job threads.
The matrix matches the screening workload: 512 KiB payload, 128 echoes at 2 ms,
bulk starting at 20 ms, one warmup and five measured rounds. Three alternating
pairs cover four loaded families and a probes-only control. A second identical
matrix pins the controller and both endpoints to **one shared logical CPU**;
this is stricter than one CPU per endpoint. Both 30-case matrices passed.

Pooled measured echo RTT p99, milliseconds:

| Workload | Unpinned baseline | Unpinned worker | One-CPU baseline | One-CPU worker |
| --- | ---: | ---: | ---: | ---: |
| Probes only | 4.92 | 0.38 | 0.68 | 1.15 |
| Seeded | 119.02 | 173.33 | 33.41 | 22.64 |
| SHA-256 counter | 52.96 | 7.00 | 40.92 | 6.80 |
| Random first half | 62.51 | 14.14 | 52.61 | 15.69 |
| Repeated random block | 139.17 | 7.85 | 140.52 | 6.59 |

All three one-CPU pairs improved loaded p99 for every family. Resource median
completion on that CPU increased by 2.69, 5.00, 2.85 and 8.83 ms respectively:
interactive fairness has a scheduling cost. Sender CPU per train rose slightly
there; this change is not adopted as a general CPU/throughput optimization.
The unpinned high-entropy, half-random and repeated-block improvements also
held in every pair.

The unpinned seeded regression is retained. Its first pair was 133.82 → 193.80
ms p99; the other pairs improved (45.38 → 27.40 and 41.09 → 39.21). A longer
follow-up used three more alternating pairs with 20 measured rounds and matched
probes-only controls: all 12 cases passed, but seeded pooled p99 remained worse,
78.91 → 86.09 ms. Individual pairs were 80.28 → 25.07, 53.71 → 105.18 and
104.55 → 89.36 ms. Seeded p95 improved from 51.48 to 22.09 ms and Resource
median from 97.28 to 65.54 ms. Control p99 also varied widely; no universal
unpinned-tail improvement is established. Spikes occur during the Resource
window; the receiver stage was not independently timed, so host contention or
receiver work cannot be assigned as the cause from these results alone.

Decision: retain the bounded sender implementation for the repeated large
responsiveness gains, including under one-CPU contention, while explicitly
leaving seeded extreme-tail behavior and receiver-side attribution open. Do
not turn these measurements into a general latency guarantee. The worker
mostly moves work; it does not eliminate compression/decompression costs.

Warm post-load sender RSS increased by up to about 1.7 MiB in the seeded
comparisons; other families were closer. These snapshots do not qualify peak
RSS, long-running slow-peer retention or a daemon allocator. The eight-job/
byte bounds are covered by deterministic tests, not inferred from RSS. The
existing stalled-writer end-to-end tests also pass, but they do not replace a
sustained Resource memory qualification.

Across production comparisons and follow-up, **72 valid cases, 414 Resources
and 78,336 echoes** completed, including warmups (separate from the unit/e2e
suite and earlier prototype). Raw artifacts are in
`.local/compression-offload/implementation/`: both binaries and build logs,
production source snapshots/patch, the local fixture patch, `compare.py`,
`followup.py`, summaries and per-case events/metrics. Each matrix manifest pins
binary/source hashes, affinity and host load. The later metadata-boundary/saturation tests
and API documentation do not change the measured production code. No builds
or separate tests overlapped timing runs. Host load remained uncontrolled.

## Receiver stage attribution (2026-10-05)

Receiver decompression is now a measured driver stall. The next scheduling
candidate is bounded receive-side offload; its fairness, memory and lifecycle
behavior still need a separate experiment. This diagnostic does not establish
an improvement or explain all variation in the earlier sender comparison.

### Method

A frozen profiling/System/portable build of `2b8ae1e` retains the production
sender worker and adds temporary receiver timing. Around the immediate
`handle_resource_part` assembly call, it records monotonic wall time and
**thread** CPU time for total assembly, nested link decryption and bounded
bzip2 decompression. One log line is emitted after assembly; there is no
logging inside those intervals. Residual assembly includes joining parts,
hashes, proof construction and metadata extraction, without separately
attributing those operations. Subsequent action dispatch is outside the timer.

A single monotonic timestamp per probe train aligns endpoint clocks. The
recorded clock alignment bound was at most 281 ns; probe submission is
reconstructed from its scheduled offset plus measured send lateness. The
assembly timer does not cover the tick fallback, but every loaded round had
exactly one immediate assembly record, including warmups.

Three repetitions per family/affinity use fresh endpoint pairs, one warmup and
10 measured rounds each. Each loaded round sends 512 KiB while a separate link
carries 128 echoes every 2 ms, starting the Resource at 20 ms. Families are
probes-only, seeded with compression on/off, SHA-256 counter, random first half,
and repeated random block. The latter two are explicitly local payload
variants. Family order reverses in the middle repetition. One affinity mode
inherits the host mask; the other shares **one logical CPU across controller
and both endpoints**. Host load/frequency remain uncontrolled; timings across
these modes must not be interpreted as a CPU-scaling comparison.

All **36 cases, 330 Resources and 50,688 echoes** passed, including warmups.
Tables exclude warmups (30 measured rounds per cell). No builds or tests ran
alongside measurements. Instrumentation is removed from the working tree;
these are diagnostic measurements, not an uninstrumented performance baseline.

### Results

Median receiver assembly elapsed / thread CPU / decompression thread CPU,
all in milliseconds:

| Payload | Unpinned | One shared CPU |
| --- | ---: | ---: |
| Seeded, compression enabled | 38.14 / 38.13 / 36.43 | 19.30 / 18.80 / 17.72 |
| Seeded, compression disabled | 3.02 / 2.97 / 0 | 1.39 / 1.35 / 0 |
| SHA-256 counter | 2.32 / 2.32 / 0 | 1.40 / 1.37 / 0 |
| Random first half | 18.76 / 18.76 / 17.36 | 9.91 / 9.68 / 9.00 |
| Repeated random block | 11.75 / 11.75 / 10.94 | 7.91 / 7.69 / 7.21 |

SHA-256 counter uses the existing uncompressed fallback after the sender's
compression attempt. For compressed families, the median per-assembly
fraction of CPU spent decompressing is **93–95%**. Median decryption CPU is
0.01–1.08 ms across loaded cells; residual assembly CPU is 0.47–1.83 ms.

Pooled diagnostic echo RTT p99, milliseconds:

| Payload | Unpinned | One shared CPU |
| --- | ---: | ---: |
| Probes only | 2.60 | 0.51 |
| Seeded, compression enabled | 121.10 | 21.13 |
| Seeded, compression disabled | 8.21 | 5.87 |
| SHA-256 counter | 3.67 | 3.98 |
| Random first half | 21.16 | 10.56 |
| Repeated random block | 11.63 | 6.00 |

All 390 unpinned seeded echoes exceeding 20 ms overlap receiver assembly;
so do all 51 such echoes on one CPU. These echoes share assembly events and
are not independent samples. The worst echo took 162.69 ms and overlapped an
entire 149.26 ms assembly: 104.10 ms thread CPU, of which decompression used
102.18 ms CPU / 147.28 ms elapsed. Approximately 45.16 ms of that assembly
was off-CPU. Thus the stall combines expensive decompression and scheduling
interference; it cannot be dismissed as scheduling alone. These clocks do not
identify why decompression CPU time itself varies across rounds.

The unpinned half-random and repeated-block echoes over 20 ms also overlap
assembly (48 and one respectively). One uncompressed seeded echo over 20 ms
finishes before assembly, so receiver assembly does not explain every outlier.
Compression-disabled runs change sender work and wire size too; their p99
difference is not an isolated measurement of receiver offload benefit.

### Next experiment and retained evidence

Prototype a bounded receive worker, starting with buffered, compressed,
single-segment application Resources. Preserve authentication before decode,
output limits, hash/proof verification, and publish success only after the
driver validates the current link/resource generation. Explicitly account for
queued parts/input, output reservation, decoder workspace and retained
completions; test cancellation, duplicate parts, timeouts, ordering, drain,
shutdown and saturation. Moving work is a responsiveness hypothesis, not a
promise of lower CPU cost. Decide the assembly handoff boundary before changing
production scheduling. Split, reader and request/response extensions remain
separate work.

Re-run a matched uninstrumented baseline/candidate matrix, with queue-delay
and memory evidence, before accepting a worker. Keep the earlier adverse
unpinned sender results: this diagnostic supports a new candidate, not a
retroactive claim that those results improved.

Local artifacts: `.local/receiver-stages/` contains `instrument.py`, the exact
`diagnostic.patch`, frozen binary, build log, host/compiler information,
`run.py`, `summarize.py`, `summary.json` and per-case results/events/stderr.
`runs/manifest.json` records source revision, binary/patch hashes, affinity and
host load. The runner's clean-checkout revision alone omits the temporary
instrumentation; the diagnostic patch and frozen binary hashes identify the
actual measured executable.

## Bounded receive-worker screening (2026-10-05)

Decision: proceed to production design for receive-side offload. The local
prototype materially improves compressed-Resource echo responsiveness in both
affinity modes, especially seeded payloads. It is **not production code**: its
memory admission, startup/error handling and timeout policy still need work.
No receive-worker environment switch or source change is retained in the tree.

### Handoff, bounds and validation

The driver joins parts and authenticates/decrypts them before handing owned
plaintext to a persistent worker. The worker performs bounded decompression,
Resource hash verification, metadata extraction and proof construction. The
driver retains an assembling marker and publishes actions only when the link
is active, its generation matches, the unique job still identifies that
Resource, and it has not been cancelled. Duplicate parts cannot reassemble the
marker; periodic cleanup retains it. Unsupported paths stay synchronous.

Eligibility is compressed, nonsplit application Resources delivered to memory,
with advertised data between 16 KiB and the efficient single-segment limit.
The advertisement selects eligibility but **does not lower the decode bound**.
The prototype allows four jobs and 256 MiB of accounting reservations. It charges
three times retained input/state capacity plus three times the decoder output
limit and fixed overhead, covering the snapshot, joined/decrypted input,
output growth and metadata copy. Cancellation and completed-but-unconsumed
results keep their reservation. Native decoder workspace, thread stack,
allocator overhead and unrelated node work are additional; this is not a
whole-node memory cap or a 256 MiB allocation made at startup.

The existing decode limit is 64 MiB, so default-limit jobs each reserve over
192 MiB and **only one fits**. A small advertised payload cannot justify a
smaller worst-case reservation. This deliberately conservative design is useful
for screening, not an adopted admission default. Other-link saturation uses
synchronous assembly; a same-link barrier finishes older work first, preserving
completion order but potentially blocking the driver again.

Validation passed: **661 core and 1,007 network unit tests**, plus **59 e2e
tests with the worker enabled**. Five prototype unit tests cover authentication
failure, decode bounds, hash/metadata handling, duplicate parts, FIFO/full wake
queue, job/byte admission, cancelled-result retention, joined shutdown, worker
panic recovery, stale link generations, cancellation, timeout and tick cleanup.
A separate live compressed burst verifies 12 payloads/metadata and all 12
completion proofs; diagnostics confirm all 12 used the receive worker. Synthetic
queue tests use small reservations to exercise multiple jobs. They do not
qualify adversarial peak memory or prolonged overload.

### Uninstrumented timing comparison

The baseline is `03f70ac` with only the local custom-case adapter. The candidate
adds the local prototype. Frozen profiling/System/portable executables run
three alternating pairs for each of five families in each affinity mode: one
warmup plus ten measured rounds, 512 KiB Resources, 128 echoes every 2 ms on
another link, Resource start at 20 ms. One-CPU mode shares a single logical CPU
between controller and both endpoints. Host load/frequency remain uncontrolled.
No stage logging, RSS polling, builds or tests overlapped this matrix.

All **60 cases, 528 Resources and 84,480 echoes** passed, including warmups.
Pooled measured echo RTT p99, milliseconds:

| Payload | Unpinned baseline | Unpinned candidate | One-CPU baseline | One-CPU candidate |
| --- | ---: | ---: | ---: | ---: |
| Probes only | 0.42 | 0.44 | 4.60 | 3.68 |
| Seeded | 111.04 | 3.37 | 23.25 | 5.53 |
| SHA-256 counter | 3.68 | 4.01 | 6.51 | 4.81 |
| Random first half | 19.64 | 1.62 | 12.33 | 3.90 |
| Repeated random block | 9.29 | 6.22 | 6.44 | 3.60 |

Seeded and half-random improve in all three pairs in both modes. All three
one-CPU repeated-block pairs also improve. Retain the exceptions: unpinned
repeated-block pairs are 8.28 → 0.38, 13.14 → 3.33 and **7.63 → 10.40 ms**;
unpinned SHA-256 counter worsens in every pair (3.65 → 3.76, 2.52 → 3.02,
4.47 → 5.13). SHA-256 counter selects uncompressed transmission and creates
no receive job. Its comparison still includes the prototype's eager idle
thread, polling and assembly refactor, so it is an important control.

One-CPU median Resource completion increases by 1.32, 1.15, 0.55 and 0.66 ms
for seeded, SHA-256 counter, half-random and repeated-block respectively.
Unpinned repeated-block completion rises from 147.40 to 159.64 ms. This is a
fairness candidate, not a general throughput/CPU improvement. Receiver CPU
per train is mixed: unpinned SHA-256 counter rises from 33.53 to 39.69 ms and
repeated-block from 34.45 to 44.10 ms; one-CPU seeded is almost unchanged,
45.68 → 45.80 ms. CPU values include all receiver process threads.

### Separate queue and memory diagnostic

Eight additional valid cases compare both binaries across the four loaded
families, with the same warmup/round count. Candidate job logging and a separate
controller sampling `/proc` RSS at a target 10 ms run only in this pass. Each
compressed candidate case records 11 jobs; SHA-256 counter records none.
Measured queue medians are 0.011–0.019 ms and the largest measured wait is
0.026 ms. These sequential transfers do not exercise a backed-up receive queue.

Observed receiver RSS maxima, MiB (samples, **not guaranteed peaks**):

| Payload | Baseline | Candidate |
| --- | ---: | ---: |
| Seeded | 36.93 | 35.66 |
| SHA-256 counter | 34.19 | 33.09 |
| Random first half | 35.59 | 34.02 |
| Repeated random block | 34.03 | 34.04 |

Maximum polling gaps range from 10.4 to 15.7 ms and can miss shorter allocations.
In the separate uninstrumented matrices, warm post-load seeded receiver RSS
instead rises by 2.20 MiB unpinned and 2.42 MiB on one CPU. The two observations
measure different points in allocation lifetimes; neither establishes a memory
reduction, strict peak bound, or sustained slow-peer behavior.

### Production work remaining

Replace the prototype's cloned receiver snapshot with a consuming assembly
handoff and explicit completion state. Keep authentication before decoding and
the existing output limit; do not shrink that limit using untrusted advertised
size to make admission look cheaper. Make worker startup lazy, recover from
startup/disconnection failures, and specify saturation/order behavior. Replace
the experimental 30-second assembly deadline with a lifecycle policy grounded
in existing protocol timeouts and drain semantics. The prototype intentionally
asserts on unexpected worker disconnection; it is not a production fallback.

Then repeat lifecycle/overload tests and a matched timing/memory comparison on
the actual implementation. Split/file/request/response paths remain outside
this slice. The results justify this next implementation step, not marking
all interference or memory qualification complete.

Reproduction artifacts are under `.local/receiver-offload/`: `candidate.patch`
(including unit tests), `fixture.patch`, `compressed-burst.patch`, `admission-validation.patch`, both frozen
binaries, build/test logs, host/compiler information, matrix scripts/manifests,
validated summaries and raw case events. Manifests hash both executables and
source patches. `diagnostic/` additionally contains per-process RSS samples and
queue/service timings. The extra compressed-burst test and strengthened byte-admission assertions ran
after all timing and memory measurements; they do not change the measured
benchmark code.

## Production receiver worker (2026-10-05)

Retained as `436a101` (owning assembly handoff) and `7f8bcf3` (network worker).
This supersedes the screening prototype for eligible compressed application
Resources. The reason to retain it is the repeated responsiveness improvement;
bulk completion and some controls regress, as recorded below.

### Implementation and correctness

The driver joins and authenticates/decrypts parts, then hands owned plaintext
and fixed verification fields to a lazy, persistent node-owned worker. The
worker decompresses, verifies the Resource hash, extracts metadata and constructs
the proof. The receiver keeps a unique assembly identity; consuming results
cannot be applied to a different receiver, even with the same Resource hash.
Cancelled, replaced or closed-link results are discarded before delivery/proof
publication. Synchronous callers use the same assembly logic without allocating
an asynchronous identity. No cloned receiver snapshot is retained.

Admission is four jobs/256 MiB, charging actual plaintext capacity, three times
the decode bound and fixed job overhead. The three output bounds cover growable
output, temporary hash/proof input and metadata extraction; cancellation and
unconsumed completions remain charged. The unchanged 64 MiB decoder limit
permits **one default-limit job**. These are accounting reservations, not eager
allocations. Native decoder workspace, allocator overhead, thread stack and
unrelated node memory remain additional. Advertised size selects eligibility
but never reduces the output reservation.

Eligibility remains compressed, nonsplit application data delivered to memory,
16 KiB through the efficient segment limit. Startup or admission failure uses
synchronous assembly; failed submission reuses the authenticated handoff.
Same-link assembly barriers preserve completion order, including unsupported
paths, and can block under overload. A disconnected worker fails its lost jobs
locally, releases reservations and permits lazy restart. Codec panics become
local failures rather than peer protocol violations. Full wake queues cannot
block result publication or joined shutdown.

There is **no new 30-second assembly timeout**. Part-receive timers stop while
assembling; existing link cancellation, teardown and node drain deadlines still
invalidate results. Both forced drain and shutdown stop/join the worker before
returning. A running native codec call may finish before joining; queued jobs
are discarded. Standalone LinkManager users without the node wake integration
remain synchronous.

Validation: **664 core unit tests, 1,014 network unit tests and 60 e2e tests**
pass; default all-target network Clippy with warnings denied, core Clippy,
formatting and the core `no_std` check pass. The final minimal-feature network
check passes with existing feature-specific warnings. Twelve worker tests cover
admission arithmetic/capacity, FIFO, full wake queues, cancellation, wrong
link/resource generations, tick retention, corrupt results, panic/disconnection
recovery, startup failure, saturation, ordering and joined drain/shutdown.
The e2e compressed burst verifies 12 payloads/metadata and 12 completion proofs.

Review caught an action-conversion bug before retention: a preceding application
completion could be consumed by a following request/response conversion. A
regression test failed on that code and now verifies both real request and
response flows while preserving the earlier application delivery. All final
measurements below were rebuilt and rerun after this fix.

### Corrected production comparison

Same workload as screening: 512 KiB, 128 echoes every 2 ms, bulk start at 20 ms,
three alternating pairs, one warmup plus ten measured rounds, five families,
two affinity modes. Portable profiling/System builds; one-CPU mode shares one
logical CPU across controller and both endpoints. The unchanged baseline is
the frozen `03f70ac` executable plus the local case adapter; the candidate
includes both production commits above. Host load/frequency are uncontrolled.
No builds, tests, stage logging or RSS sampling overlapped timing measurements.

All **60 cases, 528 Resources and 84,480 echoes** pass, including warmups.
Pooled measured echo RTT p99, milliseconds:

| Payload | Unpinned baseline | Unpinned worker | One-CPU baseline | One-CPU worker |
| --- | ---: | ---: | ---: | ---: |
| Probes only | 0.38 | 0.39 | 0.55 | 0.51 |
| Seeded | 42.97 | 2.63 | 22.56 | 4.28 |
| SHA-256 counter | 2.63 | 4.54 | 4.45 | 4.49 |
| Random first half | 18.12 | 8.92 | 11.20 | 3.47 |
| Repeated random block | 8.16 | 0.37 | 6.21 | 4.03 |

Every pair improves for each compressed family in both modes. Preserve the
uncompressed control regression: SHA-256 counter's unpinned pairs are
3.08 → 6.67, 2.50 → 2.89 and 2.63 → 2.41 ms. That workload creates no receive
worker; this comparison includes the shared assembly refactor and driver
integration, not just thread placement. One unpinned half-random baseline pair
has 261.89 ms p99; its extreme tail is retained in the raw/individual summaries,
not used as evidence of a stable host-independent gain.

Candidate minus baseline median Resource completion, milliseconds:

| Payload | Unpinned | One shared CPU |
| --- | ---: | ---: |
| Seeded | +0.44 | +9.30 |
| SHA-256 counter | +14.02 | +16.26 |
| Random first half | +7.25 | +7.48 |
| Repeated random block | +0.50 | +4.24 |

These costs are larger than in screening and are not hidden or attributed to
host noise without evidence. In particular, the high-entropy completion
regression remains a follow-up item. Receiver CPU per train is mixed: seeded
falls from 57.02 to 52.27 ms unpinned and 44.85 to 43.81 ms on one CPU, while
unpinned half-random rises from 40.72 to 48.13 ms. No general CPU/throughput
improvement or latency guarantee is claimed.

### Memory evidence and remaining qualification

A separate eight-case pass uses the corrected binaries with `/proc` RSS sampling
at a target 10 ms. All cases pass. It adds no worker timing logs and does not
measure production queue delay; screening queue timings are not relabelled as
production results. Observed receiver RSS maxima, MiB:

| Payload | Baseline | Worker |
| --- | ---: | ---: |
| Seeded | 37.09 | 35.78 |
| SHA-256 counter | 34.96 | 33.07 |
| Random first half | 35.44 | 34.11 |
| Repeated random block | 34.23 | 33.99 |

Sampling gaps reached 17.1 ms; these are not strict peaks. Warm post-load seeded
receiver RSS in the timing matrices increases by 2.33 MiB unpinned and 2.47 MiB
on one CPU. Neither set of snapshots qualifies sustained concurrent transfers,
slow peers, adversarial decode expansion or whole-node memory.

Authoritative production artifacts are under
`.local/receiver-offload/production/final/`: frozen binaries, complete source
patch, source hashes, build log, case manifests/results, validated summaries and
separate RSS samples. The parent directory retains correctness logs and the
superseded pre-fix matrix; the latter is excluded from the tables above. The
local adapter and diagnostic scripts remain untracked/ignored. The next
qualification work is sustained multi-link overload and memory behavior, plus
attribution of the high-entropy completion cost. Split/file/request/response
offload remains separate work; broad interference qualification is still open.


## Multi-link receive memory screening (2026-10-05)

A local diagnostic exercised the retained `2c320ba` revision with eight links
sharing one receiver and its single receive worker. Four runs each completed
64 bounded batches of eight 512 KiB Resources: **2,048 Resources / 1 GiB total**.
Every payload, metadata identifier, receiving link and sender completion proof
was checked; all four runs passed. Each batch drained before submitting the
next. This is repeated concurrent work, not an unbounded saturation producer.

The optimized profiling build used the System allocator and the existing e2e
TCP relay setup. Sender, receiver, relay and test application share **one
process**: the following RSS values are their aggregate, not receiver-only
measurements. Each run used a fresh process. Sampling targeted 10 ms; actual
maximum gaps were 10.7–23.9 ms, so sampled maxima are not strict peaks. No timing
comparison, other benchmark, build or test overlapped these runs.

| Payload / consumer | Sampled max RSS MiB | Drained RSS, last 16 batches MiB | RSS after 5 s idle MiB | RSS after node shutdown MiB |
|---|---:|---:|---:|---:|
| Repeated SHA-derived 4 KiB block | 100.21 | 92.18–92.25 | 92.25 | 19.79 |
| Same, application waits 1 s before consuming each batch | 102.81 | 93.54–93.63 | 93.63 | 21.17 |
| Repeated byte, high compression ratio | 90.78 | 90.26–90.48 | 90.49 | 18.10 |
| SHA-derived high entropy, compression attempted | 100.03 | 98.30–98.61 | 98.61 | 20.68 |

Ready-state aggregate RSS was 78.84–79.15 MiB. Compressed runs observed one
receive-worker thread; the high-entropy run observed none. Late drained RSS
spans were below 0.31 MiB, but small growth remains visible. Memory retained
during the five-second idle period was released substantially at node shutdown.
These observations do not attribute retention to a particular allocator, cache,
queue or receiver object, and do not establish absence of a leak over longer
runs. They also are not evidence of improvement against the old implementation:
this pass has no baseline variant.

The delayed-consumer case pauses the test application's event consumption;
callbacks and socket readers keep running. It is **not a stalled network peer**.
The highly compressible case expands to 512 KiB, not the 64 MiB decoder bound.
Worker admission/fallback occupancy was not instrumented, so eight active links
do not prove eight concurrent assembly jobs or quantify saturation. Receiver-only
RSS, continuous overload, stalled sockets, hostile maximum-bound expansion and
longer recovery remain open. The 256 MiB worker reservation is still not a
whole-node memory limit.

Reproduction evidence is retained under ignored `.local/receiver-memory/`:
`harness.rs`, `harness.patch`, frozen `candidate.bin`, build logs, source revision
and SHA-256 manifest, `run.py`, `summarize.py`, per-run logs and 10 ms RSS samples.
The harness was appended temporarily to `rns-net/tests/e2e.rs`, built using
`cargo test -p rns-net --test e2e --profile profiling --no-run`, then the original
source was restored before execution. Production code was not changed.
