# Sender compression offload

Artifact availability (2026-10-05): most historical ignored `.local/` artifacts
referenced below were deleted during disk cleanup. The recorded findings remain,
but those old binary, patch and raw-measurement paths are historical references.
Only the compact stalled-peer reconstruction described at the end is currently
retained under `.local/worker-pressure-recovery/`; it does not reproduce the old
build layouts or restore the deleted evidence.

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


## High-entropy completion regression: endpoint isolation (2026-10-05)

The slowdown follows the **production sender executable when compression is
attempted**, including when it talks to the pre-refactor receiver. Swapping only
the receiver does not reproduce the prior 14–16 ms completion penalty. This
narrows the next profile to sender preparation/compression/finalization and
publication; it does not yet identify the responsible function or source change.

Both experiments reused the exact frozen baseline (`03f70ac` plus local fixture)
and production (`436a101`/`7f8bcf3` plus fixture) endpoint binaries from
`.local/receiver-offload/production/final/`. Each case sent 512 KiB SHA256-counter
data, with one warmup and ten measured transfers, 128 echoes at 2 ms intervals
on another link, and bulk starting 20 ms into the echo train. Three alternating
repetitions ran unpinned and with controller and endpoints sharing one logical
CPU. These were uninstrumented timing passes; no build, test or RSS sampler ran
alongside them. Host load/frequency were not controlled.

### Compression on/off control

Both endpoints used the same revision in each case. Pooled Resource median
completion times, milliseconds:

| Affinity | Compression attempted | Baseline | Production |
|---|---|---:|---:|
| Unpinned | Yes | 53.80 | 64.28 |
| Unpinned | No | 13.38 | 10.93 |
| One shared CPU | Yes | 56.78 | 70.23 |
| One shared CPU | No | 13.20 | 14.44 |

Compression rejects this high-entropy payload as unhelpful; the receive worker
is not used. Disabling the attempt removes most of the pooled completion gap,
but is **not** a proposed default: compressible data still benefits from it.
The compression-disabled differences are inconsistent across pairs.

All outliers remain: unpinned compression-on first-pair medians were
141.80/124.78 ms, and one-CPU baseline compression-on second-pair median was
136.47 ms. The one-CPU production compression-off second-pair median was
27.80 ms. Those observations prevent describing the aggregate as a uniform
per-transfer cost or using this rerun to dismiss earlier echo-tail regressions.

### Crossed endpoint binaries

A local controller-only adapter selects independently frozen sender and receiver
executables. Endpoint code is unchanged; the benchmark's ordinary environment
manifest identifies the controller, so the separate crossover manifest is the
authority for endpoint hashes. Baseline/production combinations completed:

| Affinity | Sender | Receiver | Pooled median ms | Three run medians ms |
|---|---|---|---:|---|
| normal | baseline | baseline | 50.26 | 51.36 / 47.24 / 50.30 |
| normal | production | baseline | 61.68 | 61.36 / 61.16 / 63.14 |
| normal | baseline | production | 47.35 | 48.60 / 45.90 / 48.21 |
| normal | production | production | 63.08 | 62.38 / 63.41 / 62.45 |
| one-cpu | baseline | baseline | 52.10 | 52.75 / 51.75 / 52.46 |
| one-cpu | production | baseline | 68.20 | 69.09 / 67.56 / 67.65 |
| one-cpu | baseline | production | 52.58 | 52.95 / 52.56 / 52.79 |
| one-cpu | production | production | 68.82 | 68.82 / 67.65 / 70.16 |

Together these passes validated **48 cases, 528 Resource transfers and 67,584
echoes**, including warmups. They localize the observed penalty to the sender
binary and compression-enabled workload, not specifically to codec execution:
queue wait, setup/finalization, driver scheduling and build/code-layout effects
still need stage measurements. No production optimization was made from this
screening alone, and the earlier receiver responsiveness gains and regression
measurements remain on record.

Raw evidence is under ignored `.local/receiver-regression/` and its `crossover/`
subdirectory: scripts, frozen controller, exact temporary controller patch,
build logs, endpoint SHA-256 manifests, all case results/events and summaries.
Temporary benchmark source edits were restored before timing. Next: separately
measure sender queue wait, compression CPU/wall time, finalization and time to
first advertisement, using diagnostic builds followed by an uninstrumented
comparison of any proposed fix.


## Sender-stage attribution and build sensitivity (2026-10-05)

The original frozen sender penalty reproduces without instrumentation: three
one-CPU pairs with a fixed baseline receiver give Resource medians of
50.69/64.76, 49.87/65.22 and 50.18/65.05 ms (baseline/production). The pooled
medians are 50.03/65.14 ms. Six cases/66 Resources/8,448 echoes passed.

A separate external `/proc` diagnostic sampled the original preparation worker's
cumulative scheduler CPU runtime every 10 ms. It added no endpoint code or
breakpoints. Twelve cases/132 Resources/16,896 echoes passed. CPU per transfer
includes all eleven transfers, including warmup, and worker startup/metadata,
compression and result handling. It is not a direct codec-only measurement.

| Affinity | Baseline worker CPU ms/transfer, three runs | Production worker CPU ms/transfer, three runs |
|---|---|---|
| Unpinned | 35.22 / 36.23 / 34.97 | 49.03 / 49.03 / 49.13 |
| One shared CPU | 34.98 / 34.82 / 34.88 | 47.99 / 48.11 / 48.01 |

The last observed worker CPU value stayed constant for 157–192 ms before shutdown,
reducing the risk of missing final compression work. Polling gaps reached 11.45 ms.
This independently places about 13–14 ms of additional CPU in the preparation
worker; a completion-queue wait alone cannot explain the original result.

### Why rebuilt stage timings cannot be substituted for the original binaries

The sender worker and compressor sources are identical between the two revisions.
Temporary instrumentation measured submission-to-worker wait, worker and codec
wall/thread CPU, completed-result wait, sender finalization and action dispatch.
Twelve cases/132 Resources/16,896 echoes passed. Rebuilding **reversed** the gap:

| Affinity / stage | Instrumented baseline median ms | Instrumented production median ms |
|---|---:|---:|
| Unpinned codec CPU | 49.96 | 35.15 |
| Unpinned queue wait | 0.015 | 0.026 |
| Unpinned ready wait | 0.012 | 0.015 |
| Unpinned finalization wall | 2.83 | 3.56 |
| One-CPU codec CPU | 49.78 | 35.93 |
| One-CPU ready wait | 0.005 | 0.005 |
| One-CPU finalization wall | 2.09 | 2.06 |

These are diagnostic results, not before/after performance improvements. The
first baseline diagnostic run also had a large codec outlier (81.97 ms median
wall, 74.85 ms CPU); it remains in the raw evidence. Action dispatch is not a
measurement of first advertisement bytes reaching the socket.

Debugger breakpoints at native codec initialization and end entry were tried on
the original frozen executables. Six cases/66 Resources/8,448 echoes passed,
but the CPU ordering also changed: baseline run medians 55.36/51.93/50.53 ms,
production 50.11/48.81/46.95 ms. All-stop debugging perturbs execution, so these
values cannot explain the uninstrumented gap. An initial wrapper invocation
lost participant arguments and failed before transfers; that failure is retained.

### Concrete alignment hypothesis

The native `mainSort.isra.0` function has 1,887 normalized instructions in all four
binaries, with the same normalized disassembly digest (absolute branch addresses
and RIP displacements excluded). Its entry address modulo 64 correlates with
codec speed: original baseline and instrumented production start at 0; original
production and instrumented baseline start at 16. The function size is 8,521 bytes
in each. This supports a native code-placement hypothesis, not a demonstrated
queueing defect. Alignment still needs a controlled intervention; no global
compiler flag, CPU-specific default or production scheduling change is justified
by this correlation alone.

Artifacts: ignored `.local/sender-stages/`, including instrumentation script and
patch, both diagnostic binaries/build logs, exact baseline source archive,
stage results, original-binary debugger logs, the uninstrumented `recheck/`,
external `sampled/` counters, symbol addresses and normalized disassembly.
The archived baseline build inherits the enclosing checkout's embedded version
string; its source revision is `03f70ac`, not the embedded git label. Original
frozen endpoint identities remain the SHA-256 values in the manifests.


## Native sorter alignment trial (2026-10-05)

A controlled local dependency trial added `__attribute__((aligned(64)))` only
to bzip2 1.0.8's native `mainSort` function. The control and candidate use the
same production Rust source. The native function still has 8,521 bytes and
1,887 identical normalized instructions; its address modulo 64 changes from
16 to 0. The trial uses a local `bzip2-sys` Cargo patch, not a production fork.
All temporary benchmark source and lockfile changes were restored before timing.

Eight codec tests passed, including the fixed reference wire vector, malformed
streams, decompression limits and multiblock data. Sixty uninstrumented network
cases passed: **528 Resources and 84,480 echoes**, including warmups. The receiver
was the same frozen production binary for both senders. Each of five traffic
families had three alternating pairs in both affinity modes, with the same
512 KiB / ten measured plus one warmup / 128-echo contract as the earlier runs.
No profiler, build, test or RSS sampler overlapped timing.

Pooled Resource median completion time and echo p99, milliseconds. CPU is the
median across three runs of sender process CPU per measured round, including
probe work; it is not codec-only CPU.

| Affinity | Payload | Completion control → aligned | Sender CPU control → aligned | Echo p99 control → aligned |
|---|---|---:|---:|---:|
| normal | control | — | 27.73 → 27.21 | 0.41 → 0.42 |
| normal | seeded | 68.74 → 62.46 | 69.84 → 66.99 | 2.21 → 2.67 |
| normal | sha256-counter | 62.71 → 47.85 | 88.49 → 72.02 | 3.34 → 3.74 |
| normal | random-prefix | 73.09 → 66.81 | 88.13 → 78.79 | 1.93 → 1.75 |
| normal | repeated-random-block | 145.91 → 146.99 | 165.10 → 169.04 | 0.41 → 0.55 |
| one-cpu | control | — | 32.71 → 34.40 | 0.56 → 0.51 |
| one-cpu | seeded | 75.45 → 67.94 | 67.23 → 60.58 | 4.33 → 4.60 |
| one-cpu | sha256-counter | 66.97 → 52.31 | 78.49 → 66.58 | 4.04 → 4.19 |
| one-cpu | random-prefix | 80.07 → 74.70 | 81.57 → 75.48 | 3.70 → 3.68 |
| one-cpu | repeated-random-block | 160.08 → 160.17 | 151.40 → 150.09 | 3.17 → 3.15 |

The native placement intervention removes the high-entropy completion penalty
in the tested binaries on this AMD Ryzen 9 5950X. Together with unchanged
normalized sorter instructions and the original worker CPU samples, this is
strong evidence for a native code-placement effect, rather than a reason to
change worker scheduling or skip compression.

This remains a **local candidate, not a portable default or a production fix**.
Alignment also changes surrounding linked code placement, so it does not isolate
a specific instruction-cache or branch-predictor mechanism. Echo tails vary;
all per-pair values and unfavorable results remain in `summary.json`. The
repeated-block unpinned completion median regresses in all three pairs; pooled
sender CPU rises about 2.4%. Seeded and high-entropy pooled echo p99 also worsen
in both affinity modes. These trade-offs must be retained. This one host does
not qualify other Linux CPUs, architectures, compilers or allocator/build
combinations. No host-specific instruction set was enabled.

A maintainable build-time integration still needs evaluation. The one-function
attribute is not equivalent to globally passing `-falign-functions=64`: that
flag changes other native functions too and was **not tested here**. Avoid adding
an entire dependency fork or a global compiler default solely from this screen.
Next for this candidate: test a scoped build option across build layouts and
representative Linux-server targets before adoption. Worker overload/stalled-peer
memory qualification remains separate and unfinished.

Local artifacts: `.local/sender-alignment/` contains the native one-line patch,
local dependency source, original/trial lockfiles, frozen senders, exact build
logs and codec test output, symbol/disassembly checks, hashes, CPU/compiler
metadata and every case result. `run.py` uses the frozen crossover controller
and fixed production receiver; it does not expand permanent benchmark tooling.


## Maximum decoder expansion and synchronous fallback (2026-10-05)

The unchanged 64 MiB decompression bound holds for both the receive worker and
synchronous fallback. A separate assembly-boundary diagnostic used serialized
113-byte bzip2 streams generated with Python's independent bz2 interface. They
expand to exactly 64 MiB or 64 MiB plus one byte, while the fixture advertises
512 KiB. The real `ResourceReceiver`, `ResourceAssembly`, native decoder and
private production receive `Worker` are exercised. The fixture uses identity
decryption; this is not a network admission or authentication test.

Each case ran eight rounds. The first job was admitted to the worker; the second
was rejected by worker admission and executed synchronously while the first
could still run or retain its result. Each admitted job reserved **201,330,805
bytes** (about 192 MiB), irrespective of the smaller advertised size. Reservation
remained charged until result consumption, and jobs/bytes returned to zero each
round. Sixteen exact-limit assemblies validated every payload byte and the
reference proof, totaling 1 GiB delivered across the fixture. Sixteen over-limit
assemblies returned `TooLarge`, with no data delivery or proof.

| Fixture | Sampled max process RSS MiB | RSS after 5 s recovery MiB | RSS after worker shutdown MiB |
|---|---:|---:|---:|
| Exactly 64 MiB output | 262.23 | 6.21 | 6.46 |
| 64 MiB + 1 byte output | 141.66 | 6.22 | 6.41 |

These are System-allocator test-process observations, including one worker and
one synchronous assembly, not receiver-node RSS or strict peak bounds. Sampling
targeted 10 ms; maximum observed gaps were 18.8/14.2 ms for the two cases.
Fixture generation and builds finished before measurement.
The small compressed input does not imply a small memory demand; verification
also allocates payload-sized temporary hash/proof inputs. The result confirms
that **256 MiB worker accounting is not a whole-process memory cap**: synchronous
fallback, result ownership, native codec workspace and allocator costs are
additional. Short post-drain recovery does not establish a long-duration leak
bound. No decoder limit, authentication rule, fallback policy or production
memory setting was changed from this test.

Artifacts under ignored `.local/worker-pressure/maximum/` include fixture
construction, compressed bytes, reference hashes/proofs, exact local test source,
frozen test executable and hashes, build logs, phase logs and raw RSS samples.
Both isolated tests passed; each exercised eight worker jobs and eight rejected
admissions followed by synchronous assembly. The temporary test was restored
out of the repository source before either measurement.


## Continuous load and stalled-peer recovery (2026-10-05)

Four continuous-load runs completed before the local-artifact cleanup. These
numbers were preserved in session notes; the original raw samples, diagnostic
counter source and binaries are **no longer available for reanalysis**. They
used two System-allocator nodes, eight links over direct TCP, 512 KiB payloads,
45 seconds of replenished load, full drain and 12 seconds of idle recovery.
The corrected harness tolerated independent Resources completing out of order;
an earlier harness incorrectly rejected that legitimate behavior.

| Payload / pending per link | Verified Resources | Sender peak / idle / shutdown RSS MiB | Receiver peak / idle / shutdown RSS MiB |
|---|---:|---:|---:|
| Repeated byte / 4 | 17,235 | 41.46 / 41.00 / 13.27 | 38.02 / 38.02 / 13.85 |
| Repeated byte / 16 | 13,273 | 40.14 / 35.10 / 10.94 | 35.84 / 35.84 / 9.27 |
| Repeated block / 4 | 388 | 45.71 / 33.25 / 9.09 | 36.38 / 36.38 / 12.22 |
| SHA-256 counter / 4 | 1,209 | 61.67 / 47.83 / 23.67 | 37.42 / 37.29 / 13.18 |

The four valid runs delivered 32,105 Resources. Diagnostic counters observed
sender admission peaks of seven jobs / 7,340,165 reserved bytes, below the eight
job / 8 MiB budget. Compressed receive work peaked at one admitted job, reserving
201,330,768 bytes for repeated-byte payloads or 201,339,264 for repeated blocks.
Both sender and receiver saturation invoked synchronous fallback in the matrix;
all current worker reservations returned to zero after drain. High-entropy
uncompressed receives did not enter the receive worker. These observations do
not impose a whole-process RSS cap, establish a long-duration leak bound, or
qualify fully backed-up socket output queues.

The original three-second receiver pause exposed a TCP read returning `EINTR`
after resume. The server treated that as fatal and removed the interface.
Commit `e9f251f` retries interrupted reads on both TCP client and server, retaining
the decoder state. A Linux child-process regression sends a frame split after
an HDLC escape byte across three stop/resume cycles. It failed before the fix
and passes afterward. The 1,015 network unit tests, compressed-Resource burst
e2e regression, formatting and all-target network Clippy passed.

### Compact reconstruction after cleanup

The recreated diagnostic keeps source, a lockfile, small JSONL RSS/phase logs,
exit statuses, socket snapshots and binary hashes; it uses the existing target
directory and does not copy build trees or retain profiler captures. Its
optimized binary uses portable release settings and the System allocator.
This is a new build, **not a performance comparison with the deleted binaries**.
No temporary worker admission instrumentation was restored.

The reconstructed harness uses the same eight-link, 512 KiB repeated-byte
compressed workload, with up to 16 pending transfers per link for 45 seconds.
It checks payload length/digest, metadata IDs, individual application
acknowledgements and per-link proof counts; proof callbacks do not expose
individual Resource IDs. Payloads are dropped after verification, out-of-order
completion is accepted, and callback queue overflow fails the case. RSS is
sampled every 50 ms, followed by 12 seconds idle after drain and three seconds
following node shutdown. Each pause stops the entire isolated peer process,
including its reader, driver and codec worker; this is broader than pausing only
socket reads. Builds and tests did not overlap these runs.

The five-second depth-four smoke check completed 1,818 verified Resources.
The recreated 45-second unpaused run completed 12,521 Resources, drained all
pending transfers and shut down cleanly. Sender peak / idle / shutdown RSS was
39.80 / 39.50 / 15.46 MiB; receiver RSS was 35.43 / 35.43 / 11.45 MiB.
Its maximum sampling gap was 51.1 ms.
The paused-sender run resumed successfully after 3.02 seconds and completed
11,585 verified Resources, with zero pending transfers and clean shutdown of
both nodes. Sender sampled peak / idle / shutdown RSS was
40.44 / 40.14 / 16.17 MiB; receiver RSS was 35.46 / 35.46 / 11.62 MiB.
The maximum sampling gap was 67.4 ms; these are sampled maxima, not hard bounds.

**Paused-receiver recovery is still failing.** With the TCP fix present, the
sender reported `Resource rejected` after the receiver resumed from its
3.02-second pause. At the last sender snapshot 3,312 transfers were complete
and 128 pending. The controller stopped the remaining process on failure;
this case provides no successful drain or idle-recovery evidence. Both TCP
sockets were still established immediately before resume, and the receiver
had 47,377 bytes queued in its kernel socket, well below its roughly 2.5 MB
receive buffer. This did not establish full socket backpressure. The rejection
has not yet been attributed to a specific protocol path; it must not be
reported as a worker admission failure or a qualified recovery.

Current artifacts: `.local/worker-pressure-recovery/`. Case summaries include
the source revision plus the TCP patch, binary SHA-256 and every exit status.
Keep failed cases alongside passing cases. The next task is to diagnose the
receiver-pause rejection and rerun recovery after any separately tested fix.
Broader slow-socket, long-duration, split/file and request/response qualification
remains open.


## Receiver-pause duplicate advertisement fix (2026-10-05)

The earlier `Resource rejected` result was a secondary error. The stopped
receiver accumulated retries of the same Resource advertisements. On resume,
`handle_resource_adv` created another receiver for each retry; requests and
parts could then complete the same Resource more than once. The diagnostic
correctly rejected duplicate application delivery. Node cleanup sent Resource
cancellations, which made the sender report `Resource rejected`; the controller
then terminated the receiver before its original error appeared after cleanup.
The harness now logs validation failures immediately, exposing the first error.

Two deterministic regressions establish the cause. Repeated advertisements
before parts and after the first part delivered one Resource five times before
the fix. Pending application approval also produced repeated queries. The fix
ignores advertisements whose Resource hash already belongs to a retained
receiver on that link. It preserves approval, received parts and worker assembly;
normal receiver timers still retry lost requests. This adds no replay cache or
new timeout policy. Protection lasts while that receiver is retained, including
its completed state before tick cleanup; it is not an indefinite replay history.
Advertisement parsing and validation still happen before this check.

After the fix, both regressions pass, including uncompressed multi-part transfer
and compressed worker assembly, exact metadata/payload delivery and sender
completion. A distinct Resource still produces its own application approval.
All 1,017 network unit tests, 60 network e2e tests, formatting and all-target
network Clippy passed. Temporary production tracing was removed before these
checks and the final live runs. Diagnostic source, failed cases and before/after
regression logs remain in `.local/worker-pressure-recovery/`.

The production fix is committed as `2b16017`. Three final 45-second live runs
used the same uninstrumented production binary, eight links and 16 pending
Resources per link, with a three-second peer pause after 12 seconds of load.
Each completed with matching deliveries, acknowledgements and proof counts,
zero pending application transfers after drain, and clean node/process shutdown.

| Case | Verified Resources | Sender peak / idle / shutdown RSS MiB | Receiver peak / idle / shutdown RSS MiB |
|---|---:|---:|---:|
| receiver-fixed-1 | 13,409 | 40.05 / 39.72 / 15.75 | 38.26 / 38.01 / 14.10 |
| sender-fixed | 11,627 | 39.93 / 39.60 / 15.63 | 35.87 / 35.68 / 11.71 |
| receiver-fixed-2 | 12,039 | 40.54 / 35.31 / 11.46 | 38.31 / 38.12 / 14.15 |

Together these runs verified **37,075 Resources**. The maximum RSS sampling
gap was 68.0 ms. Idle samples follow 12 seconds of recovery, with post-shutdown
samples taken during the three-second process linger. Retained allocator memory
is visible after drain; these short runs do not establish a leak bound. No
worker reservation counters were restored, and kernel socket buffers did not
fill. This qualifies recovery for the tested whole-peer pauses, not arbitrary
network stalls, permanent backpressure or long-duration memory behavior. These
runs do not measure a CPU or throughput improvement over the old binary.

Final binary SHA-256:
`94da273f62297f767d0ed9650d7a38b9571fa4678afd2d2198382e6f0051944e`.
Cases retain their exact revision/patch and small raw RSS/phase logs. Original
failures remain alongside the passing runs. The next performance item is
long-history ratchet decryption; broader worker memory/latency qualification
remains scoped as described above.
