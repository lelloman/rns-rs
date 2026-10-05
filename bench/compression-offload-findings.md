# Sender compression offload screening

Decision (2026-10-05): proceed to a bounded production-worker design. Moving
sender compression off the driver substantially reduced echo stalls in all
three measured pairs for every loaded payload family. The diagnostic is saved
locally; no production scheduling change is retained yet. Ordering, overload,
cancellation and shutdown qualification remain required before adoption.

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
