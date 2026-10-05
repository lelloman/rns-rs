# Resource compression sampling trial

Decision (2026-10-05): reject the tested sampling heuristic as a default.
Keep existing compression behavior and the caller's `auto_compress` choice.
This is a completed screening experiment, not an adopted optimization or an
end-to-end performance result. Compression level tuning remains separate.

## Method

Baseline source: `b1f0c1dcbd569b59e950aabf29f1b597d1e2205a`.
An isolated Rust diagnostic used the existing bzip2 dependency and default
level 6, System allocator, `rustc -O`, portable x86-64 Linux settings. No
production compressor was modified. The candidate compressed a concatenation
of three 4 KiB samples at offset zero, midpoint and end. It attempted full
compression only if the sample shrank by more than 5%. Inputs at most 12 KiB
always used full compression. Both variants retained compressed output only
when smaller than the input, matching Resource selection behavior.

Nine deterministic families at 4 KiB, 64 KiB and 1 MiB, three alternating
full/sample pairs per cell, produced 162 observations. Families included repeated
bytes, repeated log text, xorshift seeded bytes, SHA-256 counter bytes, random
first/second halves, repeated random 4 KiB blocks, and two deliberate sampling
counterexamples. The sample-trap fills only sampled regions with high-entropy
bytes; the rest repeats one byte. Sample-holes does the reverse.

Generation, warmup and verification were outside timing. Process CPU and wall
time cover sampling plus any full compression, including output allocation.
Every result passed real AES-256 Token encryption/decryption and byte-for-byte
recovery, with bzip2 decoding when selected. Token lengths include a four-byte
Resource prefix, PKCS#7 padding, IV and HMAC. They exclude Resource advertisements,
packet headers, framing, acknowledgements and retries: these are **encrypted
payload sizes, not total network bytes**. No metadata was used.

## Results

Medians for 1 MiB inputs; CPU is compression-stage process time in milliseconds.

| Input | Full CPU | Sample CPU | Full token bytes | Sample token bytes |
| --- | ---: | ---: | ---: | ---: |
| Repeated byte | 5.80 | 5.83 | 112 | 112 |
| Repeated log text | 146.54 | 160.91 | 608 | 608 |
| Seeded | 60.62 | 1.62 | 935,584 | 1,048,640 |
| SHA-256 counter | 68.80 | 1.49 | 1,048,640 | 1,048,640 |
| Random first half | 106.28 | 101.84 | 527,264 | 527,264 |
| Random second half | 112.01 | 107.81 | 527,360 | 527,360 |
| Sample-trap | 8.33 | 1.60 | 12,864 | 1,048,640 |
| Repeated random block | 268.81 | 268.12 | 19,904 | 19,904 |
| Sample-holes | 70.97 | 71.72 | 1,041,984 | 1,041,984 |

The high-entropy case saves about 98% of compression CPU without changing the
chosen payload. However, the seeded fixture loses useful compression, and the
sample-trap grows the encrypted payload by roughly 82 times. Sampling also adds
work when it chooses to attempt compression. Short-run timing differences on
accepted cases are not evidence of reliable wins or regressions.

For scale, the extra 113,056 seeded bytes alone take 0.90 seconds to serialize
at 1 Mbit/s, or 14.13 seconds at 64 kbit/s. The trap's extra 1,035,776 bytes take
8.29 or 129.47 seconds respectively. These are arithmetic serialization costs
(`extra_bytes * 8 / rate`), **not measured completion or echo latencies**.
They exclude protocol overhead and scheduling.

## Consequences and limits

Reject before live-network qualification: the deterministic byte regression
already fails the intended default-policy tradeoff. Full Resource interop,
loaded echo tails, shaped completion latency and sustained memory were not
measured for this candidate. No protocol or receive-side changes are proposed.
The existing `cargo test --locked -p rns-net compress --lib` selection passed
all 11 tests, including reference codec vectors, output bounds, the caller
compression flag and corrupt compressed Resource rejection. These validate
the unchanged implementation; they are not live external-peer qualification.
The 64 MiB auto-compression boundary was not benchmarked. Host load was
uncontrolled (load average roughly 19); CPU figures are exploratory and apply
to this codec diagnostic, not transit relay or jemalloc daemon performance.

This rejects this particular heuristic, not every possible compression policy.
Sparse samples cannot guarantee the compressibility of unobserved content;
adjusting the threshold alone does not solve the demonstrated mixed-data case.
Randomized sampling or workload-specific policies would need their own measured
error rates and an explicit bandwidth/CPU tradeoff before adoption.

Applications with known compressed/encrypted content can already call
`Node::send_resource_with_auto_compress(..., false)` or pass `false` to
`send_resource_reader`. This skips codec work while retaining link encryption
and Resource integrity checks. Unknown or mixed content should retain the
existing automatic compression behavior until better evidence supports a
different policy. No new build flag or public configuration is warranted by
this experiment.

Raw local evidence (ignored): `.local/compression-sampling/`, including
`trial.rs`, `trial.bin`, `build-command.json`, `manifest.json`, `results.csv`,
`summary.json` and `compression-tests.log`. The manifest records toolchain,
source/binary/dependency hashes, CPU and host load. Rebuild using the saved
argument array; run `trial.bin` to emit CSV. The artifacts use existing profiler
dependency builds; source revision identifies the inspected checkout, not a
fresh full-workspace compilation. The report retains the decision and method
if local artifacts are removed.
