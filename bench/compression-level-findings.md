# Compression level comparison

Decision (2026-10-05): retain bzip2 level 6 as the default. Levels 1 and 3 offer
useful workload-specific CPU/memory tradeoffs, but neither is a general speedup.
Level 9 sometimes saves bytes, with no consistent latency benefit here. No
production level override or new build feature is retained.

## Isolated codec measurements

The diagnostic used the existing bzip2 dependency at levels 1, 3, 6 and 9 with
the current empty output `Vec`. No reservation change was combined with this
trial. Nine families, three sizes (4 KiB, 64 KiB, 1 MiB), five rotated/reversed
rounds produced 540 uninstrumented observations. A separate Rust allocation
build produced 108 more observations; its timing is excluded. All outputs
passed encryption/decryption and exact payload recovery.

Median compression process CPU in milliseconds for selected 1 MiB inputs:

| Input | Level 1 | Level 3 | Level 6 | Level 9 |
| --- | ---: | ---: | ---: | ---: |
| Repeated byte | 5.60 | 5.56 | 5.53 | 5.79 |
| Repeated log text | 124.71 | 136.06 | 144.98 | 146.92 |
| Seeded | 86.16 | 72.41 | 72.22 | 75.12 |
| SHA-256 counter | 96.60 | 93.77 | 95.19 | 99.13 |
| Random first half | 53.54 | 73.73 | 108.19 | 108.43 |
| Repeated random block | 181.84 | 226.36 | 248.87 | 260.66 |

Selected encrypted payload lengths, including Resource prefix, padding, IV and
HMAC, but excluding advertisements, framing and other protocol traffic:

| Input | Level 1 | Level 3 | Level 6 | Level 9 |
| --- | ---: | ---: | ---: | ---: |
| Repeated log text | 2,528 | 1,040 | 608 | 592 |
| Seeded | 970,944 | 945,648 | 935,584 | 934,160 |
| Random first half | 528,960 | 527,600 | 527,264 | 527,264 |
| Repeated random block | 89,456 | 37,312 | 19,904 | 19,136 |

Lowering the level does not monotonically reduce CPU. In particular, level 1
uses more CPU and sends more bytes for the seeded fixture. Lower levels also
limit the redundancy captured across a large input: the repeated random block
case pays a substantial byte penalty despite lower compression CPU.

## Live Resource transfers

A frozen diagnostic `rns-bench` build compared four levels at direct loopback
and an 8 Mbit/s userspace TCP cap per direction. Four 1 MiB families, three
rotated/reversed rounds, fresh participants per case, one warmup and two measured
transfers yielded **96 valid cases, 192 measured transfers and 96 warmups**.
All transfers required receiver digest/length/operation-ID checks and sender
Resource proof plus application acknowledgement. The receiver's decompressor
was unchanged across levels.

Median completion latency across six measured transfers per cell, milliseconds;
stream bytes are the median per-transfer measured bidirectional TCP-stream
byte delta in capped runs, including framing and protocol traffic:

| Input | Level | Direct ms | Capped ms | Capped stream bytes |
| --- | ---: | ---: | ---: | ---: |
| Seeded | 1 | 123.0 | 1,144.8 | 980,196 |
| Seeded | 3 | 117.8 | 1,110.4 | 954,523 |
| Seeded | 6 | 118.3 | 1,111.9 | 944,037 |
| Seeded | 9 | 127.0 | 1,100.6 | 942,854 |
| SHA-256 counter | 1 | 90.5 | 1,189.2 | 1,058,699 |
| SHA-256 counter | 3 | 87.1 | 1,184.8 | 1,058,699 |
| SHA-256 counter | 6 | 90.0 | 1,200.9 | 1,058,705 |
| SHA-256 counter | 9 | 94.0 | 1,188.7 | 1,058,733 |
| Random first half | 1 | 87.4 | 639.1 | 534,429 |
| Random first half | 3 | 106.1 | 659.6 | 533,184 |
| Random first half | 6 | 133.0 | 699.0 | 532,892 |
| Random first half | 9 | 135.4 | 694.0 | 532,879 |
| Repeated random block | 1 | 210.0 | 321.6 | 91,297 |
| Repeated random block | 3 | 252.0 | 290.9 | 38,699 |
| Repeated random block | 6 | 278.7 | 300.0 | 21,148 |
| Repeated random block | 9 | 290.4 | 308.4 | 20,374 |

Level 1 helps the half-random payload on both tested networks. For repeated
blocks, it saves about 69 ms on direct loopback but is about 22 ms slower under
the cap. Level 3 lies between these choices; its capped block-case ranges
overlap level 6. Small differences, particularly among high-entropy cases, do
not establish reliable improvements. Six samples per cell do not qualify tails.

Endpoint CPU was measured separately from the controller/pacer. For example,
direct sender CPU per transfer fell from 102.17 to 50.82 ms for half-random data
at level 1, while receiver CPU rose from 32.11 to 44.08 ms. For seeded data,
sender CPU rose from 71.09 to 78.23 ms. Full endpoint CPU, RSS snapshots and
latency ranges are in the local summary; sender codec savings alone must not
be called whole-stack savings.

All 48 capped runs passed raw bidirectional pacing calibration: the slower
direction achieved 96.3–98.1% of the requested rate. This is a synthetic stream
cap, not a radio model. Stream counts exclude TCP/IP headers/retransmissions;
random encryption/framing and snapshot boundaries cause small count variation.
Live fixtures include operation metadata, and their SHA-256 generator includes
the seed as well as the counter. Therefore their byte totals must not be
subtracted directly from the isolated codec fixtures.

## Memory and compatibility

A separate C diagnostic linked the same static native codec and counted its
allocator callbacks during `BZ2_bzCompressInit`/`End`:

| Level | Native initialization allocations | Requested bytes |
| --- | ---: | ---: |
| 1 | 4 | 1,118,052 |
| 3 | 4 | 2,718,052 |
| 6 | 4 | 5,118,052 |
| 9 | 4 | 7,518,052 |

This confirms a real codec workspace tradeoff. These are requested native
allocation sizes, not touched/resident pages or whole-process peaks. The native
codec sets its block workspace from the level; Rust output-capacity tuning does
not remove these arrays. Post-transfer RSS snapshots do not isolate this
temporary workspace, and sustained/concurrent memory was not qualified.

Python's standard-library `bz2` independently decoded eight generated streams:
the reference-vector plaintext and a 1.1 MB multiblock payload at all four
levels. This validates codec-format compatibility, alongside the live Rust
Resource checks. No live Python Reticulum peer was run. Authentication,
decompression output limits and production receiver behavior were unchanged.

## Scope, decision and reproducibility

The workload-dependent CPU/byte costs rule out a universal level change from
this evidence. Keep level 6 and avoid a global build flag that changes every
application's bandwidth tradeoff. A future caller-selectable level could be
useful for a demonstrated workload or constrained-memory target, but requires
API/policy design and explicit opt-in; these measurements do not select it for
all Linux servers. Codec-state reuse remains unmeasured. Scheduling/offload is
a separate next opportunity.

The live binary was built at `1001a1b` with a local diagnostic patch using
`cargo build --locked --profile profiling -p rns-bench`, System allocator and
portable settings. Only the diagnostic supports `RNS_TRIAL_LEVEL` and
`RNS_TRIAL_PAYLOAD`; the level lookup is identical across variants and is not
a supported product setting. The frozen patch also supplies the custom cases
and payload transformations. It was saved and removed before running; run
manifests describe the clean checkout, while the explicit build patch/hash
records describe the actual binary. No diagnostic source changes are retained
in production. Isolated binaries were built at `fb62b32` using existing profiler
dependencies; the intervening commits only change documentation.

No builds or separate test jobs ran concurrently with timing experiments. Host load was
uncontrolled. These short tests do not qualify mixed echo latency, concurrent
senders, constrained hardware, maximum payload limits or daemon/jemalloc gains.

Ignored evidence: `.local/compression-tuning/`. `trial.rs`, build commands,
manifest and `*-levels.csv` preserve the codec experiment. `native-init.c`,
its build command and CSV preserve native allocation counts. `interop/` and
`interop-results.json` preserve cross-decoder checks. `live.patch`, `live.bin`,
`live.py` and `live-build.log` pin the live variant; `live/manifest.json` records
the matrix, binary/patch hashes and host load. Each case retains raw events,
metrics, status and calibration; `live/summary.json` retains all ranges.
Run `timing.bin levels` and `allocations.bin levels` into the named CSVs, then
`summarize.py levels`; `live.py` creates a fresh `live/` directory and
`summarize-live.py` checks all 96 results. Retain the frozen binary or rebuild
from the recorded patch before reproducing the live experiment.
