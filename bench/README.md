# Benchmarking rns-rs

The benchmark runner measures verified application work using two separate Rust
processes and the public `rns-net` API over loopback TCP. It is an exploratory
workload runner. Its current results do not establish maximum stack throughput
or release performance guarantees.

## Run

From the repository root:

```sh
./scripts/bench doctor
./scripts/bench list
./scripts/bench plan --profile smoke
./scripts/bench run --profile smoke
./scripts/bench run --profile quick
./scripts/bench plan --suite resource-mixed --profile mixed-quick
./scripts/bench run --suite resource-mixed --profile mixed-smoke
./scripts/bench run --suite resource-mixed --profile mixed-quick
./scripts/bench profile resources
./scripts/bench profile report target/bench-results/<profile-run-id>
./scripts/bench report target/bench-results/<run-id>
```

The wrapper builds the release executable before invoking it. The initial
supported measurement platform is Linux. Rust/Cargo, Git, and permission to open
loopback sockets are required; no administrator privileges or network shaping
are needed. `doctor` records environment information but installs nothing.
The binary itself refuses measurements in a debug build. Build time is excluded.

`smoke` runs six 4 KiB cases with one warmup and two measured transfers each.
`quick` runs 4 KiB and 1 MiB payloads, three payload families, compression on/off,
and three independent process-pair repetitions: 36 cases, each with two warmups
and eight measured transfers. These are short, functional exploratory samples.
There is currently no `full` profile or automatic regression gate.
The default `resource-transfer` workload is version 2: it adds SHA-256-derived
payloads and records its version in case IDs. Old report artifacts remain readable,
but compare only compatible workloads and boundaries. Comparison order reverses
in odd-numbered repetitions; each case still uses fresh processes.

Scenario and profile definitions live in `scenarios/` and `profiles/`. Unknown
fields, unsupported settings, duplicate cases, and oversized matrices fail
validation. Use `plan` to inspect the resolved matrix before running. Each
transfer has a shared sender/receiver deadline. Setup and shutdown events have
separate deadlines. Each case gets fresh nodes and one outstanding Resource.

## Synthetic bandwidth constraints

Both live suites accept `--rate-bps`, in **bits per second per direction**:

```sh
./scripts/bench plan --profile smoke --rate-bps 64000
./scripts/bench run --profile smoke --rate-bps 64000
./scripts/bench run --suite resource-mixed --profile mixed-smoke --rate-bps 1000000
```

This inserts an owned userspace TCP relay between the two participants. The cap
applies independently in each direction to TCP stream bytes, including RNS
framing, encryption overhead, probes and acknowledgements. It excludes TCP/IP
headers and retransmissions. It is a synthetic byte-stream constraint, not a
kernel bandwidth/delay/loss model or a simulation of a radio. Both protocol links
in the mixed suite still share one TCP stream and its queues.

The relay pays each chunk's serialization time before forwarding it. Chunks are
at most 4096 bytes and at most 10 ms of the configured rate. Idle time does not
accumulate credit; scheduling stalls reduce delivered capacity rather than
causing catch-up bursts. Socket buffers still exist, and the added TCP hop and
chunking change latency even at high caps. Compare explicitly named variants;
a high-cap relay is not an identical substitute for direct loopback.

Each shaped run first verifies raw data in both directions through a separate
relay. `network-calibration.json` retains actual durations and byte counts. The
calibration targets 250 ms of serialization per direction, capped at 1 MiB, so
very high rates have shorter checks. Reports flag a raw rate below 80% of the
requested cap as pacer-limited; this is a diagnostic threshold, not performance
qualification. Calibration is outside all workload measurements. It does not
establish concurrent workload-generator headroom.

Per-case snapshots retain forwarded bytes, chunks and lifetime maximum pacing
lateness in each direction. Reports give stream-byte deltas and observed rates
over the measured batch; these can include incidental protocol traffic. Snapshot
boundaries are not packet barriers, and a chunk already in flight can straddle a
boundary. Lifetime pacing lateness includes setup and warmup. Endpoint CPU/RSS
measurements exclude relay threads, which run in the controller process.

Caps must be 64,000–1,000,000,000 bit/s. Planning rejects a Resource whose existing
operation deadline cannot accommodate twice its raw serialization time plus
10 seconds. This is a conservative budget check, not a completion guarantee;
very slow 1 MiB cases need a deliberately longer scenario deadline. The unshaped
variant remains the default, with unchanged case IDs. Shaped IDs include the
rate and pacer version, and manifests record the network model explicitly.
No administrator access or host network changes are required. Relay buffers are
bounded; case cleanup stops its threads and closes only its own sockets.

## What is measured

The receiver registers a destination and accepts the TCP connection. Both sides
must observe the connection before discovery starts, and both must establish
the link before warmup. Setup and warmup are outside the measured batch.

Each transfer carries a monotonically increasing operation ID. The receiver
checks length, a precomputed SHA-256 digest, and expected operation order before
sending a benchmark application acknowledgement over the same encrypted link.
The sender completes only after that acknowledgement and the Resource protocol
proof. The controller independently checks delivery and completion counts.
The current driver also emits receiver-side Resource-completion callbacks;
these are checked separately from sender proof completion.

| Metric | Boundary |
|---|---|
| Transfer latency | Sender submission through receiver validation, application acknowledgement, and sender proof settlement; payload cloning is excluded |
| Batch goodput | Verified application bytes divided by the complete measured batch interval, including controller gaps, payload cloning, and completion drain |
| Role CPU | `getrusage` user/system CPU deltas bracketing the measured batch, including endpoint control/verification overhead |
| RSS snapshots | Linux `/proc` resident-memory snapshots around the batch |
| Peak RSS | `getrusage` full-process high-water mark sampled after the batch; includes setup/warmup, excludes subsequent shutdown |
| Process readiness | Controller-observed launch-to-ready, with sender connection readiness included; this is not launch-to-usable-link latency |

RSS sources have different kernel accounting and update behavior; snapshots and
high-water marks are retained as separate metrics. There is no sampled
measurement-window peak yet. Latency samples use a sender-local monotonic clock.
The report suppresses p99 for fewer than 100 samples; the default profiles do not
have enough samples for useful tail claims. Repetitions are reported separately.

Payload generation is versioned, deterministic application data. `repeated` uses
byte `0x5a`; `seeded` uses the documented xorshift64 byte sequence and a fixed
seed. This seeded fixture is partially compressible (about 11% smaller with bzip2
in the 1 MiB Resource profile); it must not be labelled incompressible.
`sha256-counter` uses the same deterministic high-entropy fixture as the stage
profiler; a golden-vector test fixes its byte sequence across both paths.
Protocol identities and crypto still use OS randomness. The receiver
retains its generated payload in this first implementation, so RSS includes that
fixture as well as stack and verification work. Streaming-memory claims require
a different workload. There is no generator-headroom calibration yet.

Runtime settings use `NodeConfig` and TCP defaults at the recorded revision,
except ingress control is disabled on the configured benchmark interface and
interface startup errors are fatal. No shared instance, persistent state, hook,
or transport relay is configured. The package currently uses default network
features. Public API behavior and production defaults are unchanged.

## Artifacts and failures

Runs create a new directory under `target/bench-results/`; use `--output DIR` to
choose another new directory. Existing directories are rejected. Each run keeps:

- Resolved scenario/profile/cases and environment/source/executable fingerprints.
- A frozen participant executable, so rebuilding cannot change later cases.
- Per-case JSON results, exact latency samples, role metrics and protocol logs.
- Human-readable `report.txt` and an explicit complete/failed/interrupted status.

The source record includes the current tracked diff digest, untracked source
digests and lockfile hash. Local `LOCAL-*.txt` planning notes are excluded from
source identity. The executable hash identifies the exact artifact; use the
wrapper to rebuild after source changes. Direct invocation of an older binary
does not prove that it was built from the current checkout. Host load is recorded,
not controlled. Never compare unrelated machines or changed measurement contracts
as if they differed only by a production optimization.

Case failures retain their diagnostics and make `run` exit unsuccessfully. There
are no measured retries. Missing/failed results remain visible when regenerating
a report, even if the recorded suite status says complete. Ctrl-C interrupts the
current case, reaps owned participants and preserves partial artifacts. Abrupt
termination leaves an interrupted marker; participants also stop on control EOF.
The runner does not change machine network settings or kill unrelated processes.

No artifacts are staged, committed, published or deleted automatically. Reports
are generated from JSON; do not manually edit results to repair a failed run.

## Development and existing benches

```sh
cargo test -p rns-bench
cargo test -p rns-bench network::tests::relay_preserves_bytes_caps_rate_and_stops_without_client -- --ignored
cargo clippy -p rns-bench --all-targets -- -D warnings
bash scripts/test-benchmarks.sh
```

The benchmark package is outside workspace `default-members`. Its tests exercise
schema and matrix rejection, golden payload vectors, invalid delivery, bounded
control messages, child failure/timeouts, cleanup, and report completeness.
The live smoke run is a separate integration check requiring loopback sockets.

## Small-message latency during a Resource transfer

The `resource-mixed` suite establishes a second encrypted link between the same
nodes. Both links share the same node drivers and TCP interface. It sends
128 verified 64-byte echo requests at a scheduled interval of 2 ms, starting
before the bulk transfer. A 1 MiB Resource is submitted after a 20 ms lead-in.
A baseline case uses the same probe schedule and resident fixture without bulk
traffic. Payload, compression, and baseline/loaded cases are explicit dimensions.

`mixed-smoke` runs 12 cases, one warmup round and two measured rounds per case.
`mixed-quick` runs 36 cases across three independent repetitions, one warmup
round and three measured rounds per case. Compression and baseline/loaded order
reverse in alternating repetitions. A round completes only after all 128 echoes
are verified and, when present, the Resource is verified and settled.

Probe submission uses nonblocking admission and does not wait for the preceding
reply. The run fails on queue rejection, event overflow, missing/duplicate/corrupt
echoes or mismatched accounting. Delayed scheduling catches up with bounded
outstanding work; the lateness and resulting burst are retained, not hidden.
Loaded cases must include actual probe submission during the Resource interval.

The sender records three per-probe values in sequence order:

- RTT: public-API submission to the echoed payload's arrival callback.
- Scheduled latency: intended send time to that callback, including submission lag.
- Send lateness: actual submission time minus intended send time.

Echo content and sequence are verified before accepting a result. The arrival
callback timestamp excludes later controller/report handling. Receiver echo
handling, node queues, crypto, framing and socket scheduling remain included.
The receiver's Resource validation/acknowledgement can also delay echo processing.
Raw results retain Resource start/finish offsets and completion latency for each
round, allowing probes before/during/after the transfer to be inspected separately.

Report percentiles describe the observed probes within one case; they are not
independent-trial confidence estimates. Compare the separate process repetitions
and sender lateness before interpreting tails. A late generator can make a run
uninformative even though every delivery was correct. There is no qualified
latency gate. Mixed-suite batch goodput includes the fixed probe schedule and
must not be interpreted as maximum Resource-transfer capacity.

This suite measures contention between separate links in the same node and
underlay connection. It does not isolate driver CPU blocking from TCP
head-of-line blocking, nor model unrelated nodes or rate-limited links.

## Resource stage profiling

`./scripts/bench profile resources [--output DIR]` instruments real core Resource
sender/receiver state machines in one process, without sockets or a LinkManager.
It verifies payload, metadata, part counts and sender proof settlement for every
cycle. No production code is instrumented or modified. It uses the production
bzip2 compressor and AES-256 Token operations with OS-generated keys/IVs.

The fixed initial profile has 1 MiB payloads, SDUs of 464 and 16,348 bytes, and
compression off/on. In addition to the existing fixtures it includes
`sha256-counter`: concatenated SHA-256 blocks of a 16-byte input containing the
seed and counter as little-endian u64 values, truncated to the desired size.
Payload generation is untimed. This fixture tests compression rejection rather
than assuming the existing seeded fixture has high entropy.

There is one warmup per configuration and five measured cycles per configuration
(60 samples). Compression order alternates between repetitions. The output has
`manifest.json`, `samples.json`, `status.json` and `report.txt`. Configuration,
host/source identity and measurement boundaries are captured in the manifest.

Timers record sender preparation, sender part serving, receiver part ingestion,
receiver assembly, application verification and proof settlement. Compression
and encryption are nested inside preparation; decompression and decryption are
nested inside assembly. Do not add parent and child times together. The total
also includes the synchronous driver, allocations and intermediate data cleanup;
final sender/receiver destruction, key setup and payload generation are excluded.
CPU deltas bracket the cycle; OS counter sampling adds small overhead.

Protocol timestamps are virtual and advance by 10 microseconds per action to
exercise window/hashmap progression; reported durations use real monotonic time.
These numbers are stage profiles, not live-link latency or network goodput. SDU
is explicitly chosen, not claimed to match a negotiated live TCP link. Encrypted
Resource byte counts exclude packet headers, framing and control messages.

This instrumented profile does not collect call stacks, allocation counts, or
isolate individual copying/hashing costs. Use its stage attribution to decide
which narrower profile to run next; do not subtract its times from separate live
runs and call the remainder socket overhead.

Crate-local Criterion benches remain useful for isolated transport/link/hook
operations. `scripts/test-benchmarks.sh` is their correctness/API smoke check,
not a statistical performance run. `three_node/` remains the separate HTTP-facing
harness and includes its control-API costs.

Planned extensions include LinkManager-level in-process transfers, crypto/ratchet
scaling, allocation/CPU profiles, more protocols and topologies, network
impairment, build variants, compatible baseline comparisons and qualified runs.
Those capabilities are not provided by this initial runner.
