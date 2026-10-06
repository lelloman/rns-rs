# Release-profile tradeoffs on Linux

## Decision

Keep the current release defaults. ThinLTO and size-oriented optimization have
repeatable Resource regressions in this screen. One codegen unit is a smaller
candidate with near-baseline core-cycle timings, but the live follow-up below
finds configuration-specific latency costs on one CPU. No new Cargo profile is installed.

Stripping a deployment copy is an independent disk-size improvement: the default
full-interface `rnsd` shrinks by **17.7%**, from 6,134,296 to 5,051,152 bytes.
Every executable ELF load segment remains byte-for-byte identical. Keep the
matching unstripped artifact for symbol lookup. These release binaries have
symbol tables, not full source-level debug information; the existing `profiling`
profile remains available for source-level profiling.

## Build and size screen

2026-10-06, revision `e5d9c6a`, Rust 1.96.0 / LLVM 22.1.2,
x86_64 Linux, Ryzen 9 5950X. Full default interfaces, no hooks, no CPU-specific
Rust flags. Each alternative changes one release setting. The daemon uses its
normal jemalloc allocator; the benchmark executable uses the system allocator.

| Setting | rnsd bytes | Stripped bytes | Observed build seconds |
|---|---:|---:|---:|
| Current release | 6,134,296 | 5,051,152 | 11.71 |
| LTO = thin | 6,004,920 | 5,028,784 | 41.49 |
| Codegen units = 1 | 5,338,592 | 4,565,200 | 39.33 |
| Opt level = s | 5,825,568 | 4,304,720 | 22.96 |

Build times cover `rnsd` plus `rns-bench` in a shared, already-populated target
directory. The baseline reuses more artifacts; changed settings cause dependency
recompilation. These are observed costs, **not comparable cold-build times** or
proof of a build-time ratio. No separate target trees were created. The normal
release executables were restored in `target/release` after the measurements.

Relative to the stripped baseline, ThinLTO saves 0.4%, one codegen unit saves
9.6%, and opt-level `s` saves 14.8%. Unstripped sizes also include compiler-dependent
symbol-table differences. Stripping is not a throughput or resident-memory
optimization.

## Verified Resource cycles

The existing `profile resources` workload performs real sender/receiver Resource
state-machine cycles with AES256 Token encryption, payload verification and proof
settlement. Each configuration uses 1 MiB payloads, both SDUs, and compression on
and off. This is stage-instrumented core work, **not socket throughput, LinkManager
behavior, worker latency, or a daemon benchmark**.

Three rounds ran all four frozen executables, reversing order in round two.
Each run contains 60 measured cycles plus 12 warmups: all **720 measured cycles**
passed. No builds/tests overlapped measurements. The host was not isolated or
CPU-pinned. Round medians use five samples per configuration; the table reports
the median of three per-round percentage differences from that round's baseline.
Negative means faster. Small differences should be treated as noise.

| Payload | SDU | Compression | Baseline median ms | ThinLTO delta | One CGU delta | Size delta |
|---|---:|---|---:|---:|---:|---:|
| repeated | 464 | off | 7.70 | -8.9% | -1.9% | +20.1% |
| repeated | 464 | on | 10.11 | -1.4% | +1.1% | +1.8% |
| repeated | 16348 | off | 7.04 | -9.1% | -0.6% | +17.1% |
| repeated | 16348 | on | 10.08 | -0.5% | +1.0% | +3.2% |
| seeded | 464 | off | 7.60 | -8.6% | -0.2% | +22.3% |
| seeded | 464 | on | 99.33 | +13.8% | -0.1% | +12.5% |
| seeded | 16348 | off | 7.04 | -9.2% | -0.8% | +17.6% |
| seeded | 16348 | on | 98.81 | +13.4% | +0.6% | +12.2% |
| sha256-counter | 464 | off | 7.59 | -8.8% | +0.2% | +20.2% |
| sha256-counter | 464 | on | 75.14 | +34.2% | -0.3% | +21.1% |
| sha256-counter | 16348 | off | 7.02 | -9.8% | -0.2% | +15.1% |
| sha256-counter | 16348 | on | 74.07 | +35.0% | -0.2% | +20.4% |

ThinLTO's uncompressed cycles improve 7.6–11.1% across all round comparisons,
but seeded compressed cycles regress 12.4–15.2% and SHA-256-counter compressed
cycles regress 33.8–37.0%. At SDU 16348, pooled median compression time for the
SHA-256-counter case rises from 66.97 to 93.85 ms, while assembly stays around
1.8 ms. This locates the regression primarily in compression; it does not prove
its cause. Prior native-code-placement findings make layout sensitivity a
plausible explanation, not an established attribution for this trial.

One-CGU round comparisons range from -3.4% to +2.6%; this short screen establishes
no runtime speedup. Size optimization slows every uncompressed case in every
round (14.7–23.9%) and the high-entropy compressed cases (18.9–26.5%).

All four stripped benchmark executables also passed a verified compressed
SHA-256-counter cycle; all four stripped daemons passed `--help`. Executable ELF
segments match their unstripped originals in all eight comparisons. These smoke
checks do not replace live-server qualification.

## Reproduction and remaining work

Build each variant separately, preserving the resulting executables before the
next build. Use the same package selections for each variant:

```sh
cargo build --release -p rns-cli --bin rnsd -p rns-bench --bin rns-bench
CARGO_PROFILE_RELEASE_LTO=thin cargo build --release -p rns-cli --bin rnsd -p rns-bench --bin rns-bench
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 cargo build --release -p rns-cli --bin rnsd -p rns-bench --bin rns-bench
CARGO_PROFILE_RELEASE_OPT_LEVEL=s cargo build --release -p rns-cli --bin rnsd -p rns-bench --bin rns-bench
```

Run each frozen benchmark executable with `profile resources --output UNIQUE_DIR`.
Use `strip --strip-all -o DEPLOYMENT_COPY ORIGINAL` for the independent stripping
comparison. Do not combine the compiler options based on these single-setting
results: combinations have not been measured.

The live one-CGU qualification is recorded below. Cold builds, additional
architectures, daemon startup/allocator retention, and scoped native-function
alignment remain unmeasured here. Do not turn this host's results into portable
defaults.

Ignored evidence lives in `.local/release-profiles/`: build settings/logs,
revision/toolchain metadata, hashes, frozen original/stripped executables,
per-cycle records, reports and diagnostic scripts (~85 MiB). Compilation reused
the existing shared target (approximately 1 GiB growth during this slice).
README documentation changed during the last measurement runs; their source
manifests record that difference. All measured code was frozen from `e5d9c6a`.

## Live one-codegen-unit qualification (2026-10-06)

The follow-up keeps the release default unchanged and parks one codegen unit
as a general server-performance recommendation. Its smaller artifact remains a
real size tradeoff, but aggregate echo statistics hid configuration-specific
latency costs on one CPU. No new Cargo profile or runtime change is introduced.

The frozen baseline and one-CGU executables from the screen above ran the existing
`resource-mixed` suite over real loopback TCP. Both endpoints use the selected
build and the System allocator; this is not a jemalloc daemon measurement.
A separate link schedules 128 verified 64-byte echoes every 2 ms, with and without
a 1 MiB Resource starting after 20 ms. Three payload families and both compression
settings are tested. Resource completion includes receiver verification and
sender settlement. Scheduled echo latency includes submission lateness.

Three alternating pairs used `mixed-smoke` (one warmup, two measured rounds per
case) unrestricted, and three pairs used the same suite with the controller,
both endpoints and all their workers pinned to logical CPU 0. That CPU was not
reserved; affinity is a contention screen, not an isolated server or a CPU quota.
The host exposes 32 logical CPUs. No builds/tests ran during the measurements.

Pooled scheduled echo p99 and total endpoint CPU across the six Resource-active
configurations in each run are below. Each p99 contains 1,536 measured echoes;
CPU snapshots bracket the measured batches and exclude the controller. Pooling
is a summary, not a substitute for the per-configuration checks below.

| Affinity | Pair | Echo p99 baseline → one CGU, ms | Endpoint CPU baseline → one CGU, s |
|---|---:|---:|---:|
| unrestricted | 1 | 87.293 → 74.757 | 1.6143 → 1.4456 |
| unrestricted | 2 | 83.422 → 80.429 | 1.6200 → 1.4419 |
| unrestricted | 3 | 87.111 → 78.464 | 1.5344 → 1.5366 |
| one-cpu | 1 | 67.670 → 66.561 | 1.1090 → 1.0952 |
| one-cpu | 2 | 66.343 → 65.640 | 1.1081 → 1.0858 |
| one-cpu | 3 | 65.104 → 65.016 | 1.1254 → 1.1024 |

Echo-only pooled p99 stays below 0.6 ms in these initial runs, with mixed CPU
changes. Endpoint post-batch RSS sums are modestly smaller for one CGU (roughly
0.6–1.0 MiB across the two processes); these snapshots are not a peak-memory or
long-term retention measurement.

### Checking the configuration hidden by pooling

Uncompressed SHA-256-counter Resource completion on one CPU was 3.9%, 4.3% and
6.2% slower in the three short pairs. Those medians contain only two completions,
so two additional alternating pairs used `mixed-quick`: three fresh process-pair
repetitions and three measured rounds, yielding nine Resource completions per
configuration per executable per pair. The full matrix was retained, rather than
changing the workload to favor one observed case.

| Longer pair | Payload | Compression | Resource median baseline → one CGU, ms | Scheduled echo p99 baseline → one CGU, ms |
|---|---|---|---:|---:|
| 4 | repeated | off | 24.460 → 25.277 | 9.533 → 10.823 |
| 4 | repeated | on | 15.979 → 16.340 | 11.341 → 11.474 |
| 4 | seeded | off | 24.492 → 25.221 | 10.305 → 11.191 |
| 4 | seeded | on | 120.475 → 119.587 | 64.180 → 64.073 |
| 4 | sha256-counter | off | 23.992 → 25.121 | 9.917 → 10.160 |
| 4 | sha256-counter | on | 94.855 → 105.065 | 76.932 → 96.782 |
| 5 | repeated | off | 25.073 → 25.468 | 10.816 → 10.668 |
| 5 | repeated | on | 16.654 → 15.001 | 12.170 → 10.203 |
| 5 | seeded | off | 24.351 → 26.220 | 10.285 → 15.242 |
| 5 | seeded | on | 121.535 → 126.272 | 65.741 → 725.364 |
| 5 | sha256-counter | off | 24.524 → 25.385 | 10.146 → 10.347 |
| 5 | sha256-counter | on | 96.316 → 99.910 | 79.595 → 81.002 |

The uncompressed SHA-256-counter Resource slowdown persists in both longer pairs
(+4.7% and +3.5%), after +3.9–6.2% in the initial screen. Pair 5's 725 ms seeded
compressed echo p99 is localized to one of its three process-pair repetitions:
its Resource completions are 408–1,217 ms, while the other two repetitions remain
around 125–126 ms. This outlier is retained, but its cause is unresolved on the
unisolated host; it is not evidence by itself of a deterministic compiler effect.

These are observed short-run medians and empirical p99 values, not population
estimates or a proof of mechanism. The per-configuration results do not support
promoting the smaller executable as an unconditional server improvement.

All **288 live cases passed**, with **92,160 measured verified echoes** and
**360 measured verified Resource transfers**, plus warmups. Run status, payload,
probe-count, Resource completion and executable hashes were checked. No timeout
or correctness failure occurred. These tests do not cover a saturated link,
transport relay, additional hardware, or daemon allocator retention.

Compact ignored evidence is in `.local/cgu-live/`: exact invocations, build
provenance, baked source identity, affinity, raw case results, paired summaries,
and logs. The runner's redundant frozen binaries are replaced after worker exit
by verified hard links to the original retained executables; no builds or new
target trees were needed. Original code revision remains `e5d9c6a`; subsequent
commits only document these experiments.
