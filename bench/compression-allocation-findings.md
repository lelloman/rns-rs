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

## Independent codec-state reuse screen (2026-10-07)

Decision: park codec-state reuse with the current backend. No production change,
configuration option or performance benchmark infrastructure is added. This is a
completed feasibility screen, not a measured optimization or a pooling trial.

At source revision `46bb8b9`, Cargo.lock selects `bzip2 0.6.1` and
`bzip2-sys 0.1.13+1.0.8`. Inspection of the installed crate sources shows that
`Compress`/`Decompress` have no reset API. The read/write wrappers expose their
underlying I/O object, but replacing that object does not reset codec state.
`Compress::new` allocates a new native stream and calls `BZ2_bzCompressInit`;
dropping it calls `BZ2_bzCompressEnd`. The native workspace is private to the
stream. Our compressor produces an independent finished stream per call.

The [libbzip2 1.0.8 manual](https://sourceware.org/bzip2/manual/manual.html#low-level)
documents the finish/end lifecycle and custom allocator callbacks. A flush keeps
one stream running; it does not produce independent complete streams for separate
Resources. Replacing Finish with Flush would change that contract. A finished
stream cannot simply accept the next Resource.

A small standalone C probe compiled the seven bundled libbzip2 1.0.8 source files
with `clang -O2 -DBZ_NO_STDIO` and an aborting internal-error handler. It exercised
empty, one-byte and 4 KiB repeated inputs at level 6 / work factor 30. Custom
allocation callbacks counted native requested bytes, excluding callback metadata,
output/input arrays and allocator overhead. For every input:

- Init makes four allocations requesting 5,118,052 B in total (~4.88 MiB).
- Finish produces a complete stream and retains all four allocations.
- A subsequent Run on that finished stream returns `BZ_SEQUENCE_ERROR` (-1).
- End frees all four allocations, returning counted live bytes to zero.

All three independently produced streams decode to exact input bytes with
Python's `bz2`. The probe deliberately uses the bundled source; it does not
measure a deployed daemon's allocator, RSS or CPU. Source hashes, compiler
command, probe source, output and tiny streams are retained in ignored
`.local/codec-state-reuse/`. An initial diagnostic link failed because the
stdio-free build requires an internal-error handler; adding that handler fixed
the diagnostic without modifying dependency sources.

Native `bzalloc`/`bzfree` callbacks could pool raw allocation blocks while still
running End/Init for each independent stream. That is workspace allocation reuse,
not a codec reset, and the current Rust wrapper does not expose those callbacks.
It would require a separate lower-level integration or an upstream API addition,
plus bounded per-worker retention, allocation-failure handling and concurrency
qualification. Retaining one complete level-6 workspace would retain the counted
~4.88 MiB per pool slot, not necessarily that amount of resident memory. Existing
allocator caching may already amortize allocation cost; no CPU saving from an
explicit pool was measured here. A pool is not justified by allocation counts
alone. Revisit only with evidence that native initialization/allocation dominates
a relevant workload and a maintainable bounded integration is available.

No repository test run is claimed for this documentation-only slice. The local
lifecycle assertions and three independent decompression checks passed. Prior
compression-level, output-reservation and wire/correctness findings still apply.
