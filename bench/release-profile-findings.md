# Release-profile tradeoffs on Linux

## Decision

Keep the current release defaults. ThinLTO and size-oriented optimization have
repeatable Resource regressions in this screen. One codegen unit is a smaller
candidate with near-baseline core-cycle timings, but is not yet qualified for
live-server latency or other machines. No new Cargo profile is installed.

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

Next candidate qualification is one codegen unit under live mixed traffic,
including constrained-CPU latency, before proposing an opt-in deployment profile.
Cold builds, additional architectures, startup/RSS, and scoped native-function
alignment remain unmeasured here. Do not turn this host's results into portable
defaults.

Ignored evidence lives in `.local/release-profiles/`: build settings/logs,
revision/toolchain metadata, hashes, frozen original/stripped executables,
per-cycle records, reports and diagnostic scripts (~85 MiB). Compilation reused
the existing shared target (approximately 1 GiB growth during this slice).
README documentation changed during the last measurement runs; their source
manifests record that difference. All measured code was frozen from `e5d9c6a`.
