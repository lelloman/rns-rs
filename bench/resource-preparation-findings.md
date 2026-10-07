# Resource preparation buffer borrowing

Accepted 2026-10-07: borrow the application payload when metadata is absent,
and borrow the uncompressed input when compression is disabled or rejected.
Only metadata concatenation and accepted compression need an owned buffer.
The API, compression policy, random-byte consumption, encryption input, hashes,
proofs and retained parts are unchanged. No build-time tuning is needed.

## Allocation result

Compared production baseline `20a7c8a` with this change using the existing
allocation profiler: 108 verified cycles per build, three repetitions across
4 KiB / 1 MiB / 2 MiB payloads, SDUs 464 / 16348, repeated / seeded /
SHA-256-counter data, and compression off / on. The driver includes eight
metadata bytes plus a three-byte prefix.

| Payload | Compression disabled or rejected: fewer requested bytes and lower peak live bytes | Fewer allocations |
| --- | ---: | ---: |
| 4 KiB | 4,107 B | 1 |
| 1 MiB | 1,048,587 B | 1 |
| 2 MiB | 2,097,163 B | 1 |

Every corresponding sample had these exact reductions. Accepted compression
with metadata had unchanged allocation counts and peaks. Every cycle returned
to its starting live-byte count after teardown. These are Rust `GlobalAlloc`
requested sizes and logical live-byte peaks using System, excluding native
bzip2 allocations and allocator bookkeeping; they are not process RSS.

Without metadata, source inspection shows an additional eliminated payload
allocation/copy, including when compression succeeds. The allocation driver
always supplies metadata, so that additional saving was not measured here.

## Timing and correctness

Two pairs of uninstrumented stage-profile runs used before/after then
after/before order, five observations per configuration, 240 verified cycles
in total. Per-configuration sender-preparation median changes ranged from
-2.67% to +2.89%; total-cycle median changes ranged from -2.13% to +2.91%.
The direction varied between runs. Retain this as a memory/copy reduction;
there is no established latency or throughput gain.

Both builds used the same root Cargo.lock, portable release settings and
rustc 1.96.0 on Linux x86_64 / Ryzen 5950X. Timing runs used separate frozen
uninstrumented binaries with no concurrent builds or agent-launched benchmarks;
host load was uncontrolled. Allocation builds were separate. Existing benchmark
commands were reused without infrastructure changes.

The golden regression test captures the original advertisement, parts, hashes
and proofs across 90 combinations of payload size, absent/empty/nonempty
metadata, skipped/unavailable/equal/larger/accepted compression and response
flags. It passes before and after the change. All core unit and integration
tests pass, as do no-default-features checking and all-target Clippy.

The modified binary also passed the live `quick` transfer profile: 36 cases,
288 measured transfers plus 72 warmups. This checks correctness over local
sockets; it is not a before/after performance comparison. The initial sandbox
attempt could not open sockets and was rerun with authorization. All 12 cases
of `mixed-smoke` also passed, covering echo traffic with and without bulk
Resources, across the three payload families and both compression policies.

## Reproduction

Build and freeze `rns-bench` at each revision using the same lockfile:

```sh
cargo build --release --offline --locked -p rns-bench
# Save target/release/rns-bench before switching revisions.
<binary> profile resources --output <directory>
<binary> run --profile quick --output <directory>
cargo build --release --offline --locked -p rns-bench --features allocation-profiler
# Save this instrumented binary separately; do not use it for timing.
<allocation-binary> allocations --output <directory>
```

Ignored raw artifacts, manifests, reports and frozen binaries are retained in
`.local/resource-borrow/`; the durable result is recorded here.

## Contiguous sender part storage (2026-10-07)

A second isolated change, measured against `9e758f4`, retains the encrypted
buffer instead of allocating and copying each part during preparation. Map
hashes are computed directly over its chunks; requested parts still get owned
action buffers, preserving retransmissions and asynchronous consumers. Collision
retries recompute hashes without copying parts. A boxed slice releases spare
capacity supplied by the encryption callback. A private partition size preserves
part boundaries even if a caller subsequently changes the public SDU field.
The public `split_into_parts` helper and action API are unchanged.

The same 108-case allocation matrix passed on each build. Representative 2 MiB
results below are exact in all three repetitions; savings are before minus after.

| Input / compression / SDU | Fewer allocation calls | Fewer requested bytes over cycle | Less retained sender storage |
| --- | ---: | ---: | ---: |
| Any / off / 464 | 4,521 | 2,205,696 B | 108,480 B |
| Any / off / 16348 | 130 | 2,100,312 B | 3,096 B |
| Seeded / on / 464 | 4,028 | 1,964,776 B | 96,648 B |
| Seeded / on / 16348 | 116 | 1,870,888 B | 2,760 B |
| Repeated / on / either | 2 | 136 B | 24 B |

Rejected SHA-256-counter compression has the same savings as compression off.
Overall logical peak live bytes are unchanged in the uncompressed and seeded
examples: another phase sets the peak. The repeated compressed example reduces
that peak by 24 B. Every cycle returns to its starting live-byte count after
teardown. These remain Rust/System counters, not native heap or daemon RSS.
Callbacks returning excess capacity can require a shrink reallocation when the
buffer becomes a boxed slice; its cost depends on the allocator and callback.

Three alternating timing pairs (before/after, after/before, before/after) yielded
360 verified core cycles. Per-configuration preparation median changes range
from -8.64% to +6.08%; total-cycle changes range from -6.99% to +4.81%.
Directions change across pairs, including unchanged codec work. No general
speedup is established; the accepted benefit is fewer allocations/copies and
less retained sender metadata. No agent builds or benchmarks ran concurrently
with these timing runs, but host load was uncontrolled. Toolchain, platform,
lockfile and portable settings match the first experiment above. Baseline
binaries were reused from that experiment's accepted version.

Validation: 669 core unit tests and 56 integration tests pass, including the
original 90-case wire transcript. A new request/retry test verifies exact bytes
at empty, exact-boundary and multipart sizes and checks partition stability
when the public SDU changes. no-default-features, Clippy and formatting pass.
The uninstrumented candidate passes all 36 live quick-transfer cases (288
measured transfers plus 72 warmups) and 12 mixed-smoke cases. Live runs check
correctness, not a before/after latency claim. No benchmark infrastructure was
added. Raw evidence and frozen binaries: `.local/resource-parts/`.
