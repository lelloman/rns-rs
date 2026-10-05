# Compression output allocation trial

Decision (2026-10-05): retain `Vec::new()` for bzip2 output. Tested reservations
reduce allocation calls, but establish no practical CPU benefit and can waste
capacity on compressible inputs. No production allocation change is retained.

## Comparison

Source baseline: `fb62b32`. The isolated codec diagnostic used default bzip2
level 6 with four initial output capacities: zero (current behavior),
`min(input.len(), 4096)`, `min(input.len(), 65536)`, and
`input.len() + input.len()/100 + 600`. The last is a trial reservation, not an
enforced output limit. All variants use the same `BzEncoder::read_to_end` path.

Nine deterministic payload families and sizes 4 KiB, 64 KiB and 1 MiB match the
[sampling trial](compression-sampling-findings.md). Five rotated/reversed rounds
per cell yielded 540 uninstrumented observations. A separate allocator-counting
build ran 108 observations; its timings are not used. Both use System allocation,
portable `rustc -O` and the existing profiler's bzip2 dependency. No builds or
other benchmarks ran concurrently with measurement. Host load was uncontrolled.

Compression-stage CPU excludes generation, encryption and verification. All
648 outputs passed AES-256 Token encryption/decryption and exact payload
recovery. Selected payload lengths matched across reservations. Allocation
counts include Rust codec-wrapper allocations and reallocations; they exclude
native bzip2 malloc. Requested bytes sum allocation/reallocation requests,
including successive capacities: they are neither peak live bytes nor RSS.

Representative 1 MiB inputs, median process CPU in milliseconds:

| Input / reservation | CPU ms | Rust allocation calls | Output capacity |
| --- | ---: | ---: | ---: |
| Repeated / zero | 5.31 | 4 | 64 B |
| Repeated / 4 KiB | 5.35 | 3 | 4 KiB |
| Repeated / 64 KiB | 5.36 | 3 | 64 KiB |
| Repeated / input-sized | 5.36 | 3 | 1,059,661 B |
| Seeded / zero | 72.34 | 18 | 1 MiB |
| Seeded / 4 KiB | 72.28 | 11 | 1 MiB |
| Seeded / 64 KiB | 72.23 | 7 | 1 MiB |
| Seeded / input-sized | 72.46 | 3 | 1,059,661 B |
| SHA-256 counter / zero | 94.41 | 19 | 2 MiB |
| SHA-256 counter / 4 KiB | 94.24 | 12 | 2 MiB |
| SHA-256 counter / 64 KiB | 94.56 | 8 | 2 MiB |
| SHA-256 counter / input-sized | 94.35 | 3 | 1,059,661 B |

The input-sized reservation reduces high-entropy output capacity and cumulative
Rust-requested bytes (4,202,544 to 1,067,933), but reserves that capacity even
when the compressed result is only 48 bytes. Smaller reservations save calls,
not the eventual large-output capacity. These observations do not justify a
universal input-size reservation or a new workload-guessing heuristic.

Codec output capacity is temporary: Resources subsequently encrypt selected
bytes and drop this output. It must not be described as persistent per-link
retention. Native codec allocations, process peak memory, concurrent callers
and live transfer latency were not qualified. The small timing differences do
not establish an end-to-end gain. Revisit only with a demonstrated allocation
bottleneck or a different approach that avoids disproportionate reservations.

Local ignored evidence: `.local/compression-tuning/`, with `trial.rs`,
`make-trial.py`, `build-commands.json`, `manifest.json`, `timing.bin`,
`allocations.bin`, `timing-allocation.csv`, `allocations-allocation.csv`,
`summary-allocation.json` and `summarize.py`. The manifest pins diagnostic
hashes/toolchain; build arguments identify the dependency artifacts. Reproduce
with `timing.bin allocation`, `allocations.bin allocation`, then
`python3 summarize.py allocation` after saving CSVs under those names.
