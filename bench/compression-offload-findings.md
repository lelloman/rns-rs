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
