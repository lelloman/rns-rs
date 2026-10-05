# TCP output experiments — 2026-10-05

## Bounded write batching: parked

The bounded batching prototype is not retained. It preserved wire behavior, but
neither syscall attribution nor unprofiled CPU measurements established enough
benefit to justify it. Encoding-buffer reuse is a separate experiment against
the unchanged baseline (`7cc2302`).

The prototype limited each TCP async dequeue to 16 already-available frames and
coalesced complete HDLC frames into at most 256 KiB per write. It never waited
for more frames. A larger individual frame was written alone to preserve the
existing MTU. Confirmed sends stayed on the existing individual completion path;
other interface implementations retained their previous batch policy.

Correctness checks passed: 995 network unit tests, an additional real TCP
stalled-reader test, 58 end-to-end tests and net/bench all-target Clippy. The new
coverage checked escaped bytes/order, frame and byte limits, oversized frames,
partial writes, interruptions, write-zero/failure, bounded queue draining and
reverse-direction read progress while output was stalled. Resuming the receiver
produced byte-identical output. This does not qualify every shutdown/loss case.

### Syscall attribution

`strace -f -ttt -yy -s 0` traced actual daemon write/writev/sendto/sendmsg calls.
Phase-gated counts below exclude startup and warmups. Fixed endpoints verified
32 one-link and 64 eight-link 1 MiB SHA-256-counter Resources without compression.
Each trace passed 104 transfers including warmups. Unfinished/resumed syscall
records were joined by thread before counting returns.

| Phase | Baseline sendto calls | Candidate sendto calls | Approximate wire bytes |
|---|---:|---:|---:|
| One link | 929 | 929 | 33.88 MB |
| Eight links | 1,859 | 1,859 | 67.76 MB |

There were no partial/error returns in these traces; maximum writes were about
66.1 KiB. Small byte-count differences reflect escaping/control traffic. No
coalescing benefit appeared under tracing. Ptrace changes scheduling and queue
occupancy, so this is not proof that untraced batches never combine frames.
Traced timings are not used as performance measurements.

### Unprofiled comparisons

Portable optimized builds retained default features/allocators. Endpoints were
frozen; baseline/candidate run order alternated. Builds and correctness tests
finished before the performance runs. Real `rnsd` uses jemalloc; standard relay
workers use System, and their results are kept separate.

Three actual-daemon pairs passed 2,352 transfers including warmups. One-link
CPU changed +6.20%, +0.76%, +6.25%; eight-link CPU changed +2.78%, −4.14%, +0.68%.
Eight-link elapsed improved 7.92–13.01% and p99 improved, but CPU did not improve
consistently. RSS varied by less than 1 MiB. These gains alone do not establish
that the additional batching machinery is worthwhile.

Two bulk relay pairs passed 144 cases. CPU increased 12.41% and 6.39%, elapsed
increased 24.26% and 3.83%, and aggregate p99 increased 174.39% and 35.69%.
RSS medians were about 0.4% lower. These repeated bulk regressions reject the
candidate even if another workload benefits.

Two mixed pairs also passed 144 cases. CPU changed −0.54% and −5.67%, elapsed
was effectively unchanged, and pooled probe p99 changed −0.34% and +4.45%.
Small-message-only p99 changed +13.97% and −11.60%; Resource-active p99 changed
−0.17% and +5.55%. This does not overturn the bulk rejection.

Evidence under `.local/tcp-output/`: `baseline`, `batch-trace`, `batch-daemon`,
`batch-bulk`, `batch-mixed`, frozen `rnsd-batch.bin` / `relay-batch.bin`,
`batch-candidate.patch` (including tests) and build/validation logs. The saved
patch applies cleanly to the baseline. No batching production code is retained.

## Bounded encoding-buffer reuse: parked

The separate reuse candidate is also not retained. It reduced measured RSS and
helped bulk System-allocator relay CPU slightly, but did not establish a CPU or
latency improvement for the actual jemalloc daemon and mixed traffic.

Each TCP writer lazily cached up to 128 KiB of encoded storage. Frames larger
than that used an exact-sized temporary that was dropped after writing without
enlarging the cache. The cache remained while an established connection was idle
and was released when its writer was dropped. Wire bytes, per-frame writes,
queue behavior and completion semantics were unchanged; no batching was included.
Tests checked storage reuse, the oversized-frame retention bound, stale bytes
after errors, interrupted/partial writes and real stalled-peer recovery. All
994 unit tests, 58 end-to-end tests, formatting and net/bench Clippy passed.

### Actual daemon: CPU and resident memory

Three alternating pairs again passed 2,352 transfers including warmups. The
baseline was the unchanged production implementation from `7cc2302`; `9a2ad26`
only added the batching report. Builds/tests finished before these runs.

| Pair | One-link CPU | Eight-link CPU | Eight-link elapsed | Eight-link RSS before → after |
|---|---:|---:|---:|---:|
| 0 | −0.77% | +5.61% | +4.43% | 41.86 → 41.34 MiB |
| 1 | +8.89% | +5.19% | +1.24% | 42.16 → 41.84 MiB |
| 2 | +21.17% | −0.33% | −3.22% | 42.77 → 41.99 MiB |

One-link elapsed changed −5.86%, +0.77%, +29.07%; pair 2 also had a p99 outlier
(48.93→96.50 ms). Eight-link p99 changed 33.12→34.27, 33.97→33.43 and
40.98→37.38 ms. The outlier is retained, not removed from the result.

RSS after two seconds of connected idle matched the eight-link snapshots above.
After disconnect and a further two seconds, baseline→candidate RSS was
37.18→36.46, 37.42→37.32 and 37.53→37.47 MiB. These are short process-RSS snapshots,
not live-buffer accounting or long-term allocator recovery. A lower RSS snapshot
does not mean the idle connection has no retained cache; the explicit bound
remains 128 KiB per writer, excluding allocator overhead.

### Standard relay and focused encoder check

Two bulk pairs passed 144 cases: CPU fell 2.19% and 3.99%, elapsed changed
+3.53% and −12.53%, and aggregate p99 changed +13.06% and −66.11%. RSS medians
were effectively unchanged. Two mixed pairs passed another 144 cases: CPU
changed +2.16% and −5.70%; pooled probe p99 changed +36.09% and −42.57%.
Small-message-only p99 changed −9.56% and +20.01%; Resource-active p99 changed
+50.81% and −57.12%. These do not establish a repeatable mixed-latency benefit.

A local System-allocator encoder-only diagnostic then compared fresh allocation,
the cached buffer and a local-owned-buffer variant. Five alternating rounds of
10,000 operations used fixed pseudorandom 128-byte and 65,554-byte inputs. Median
ns/op for fresh/cached/local-owned was 170/160/158 for small inputs and
88,503/89,818/88,759 for large inputs. Output was passed through `black_box` to a
sink; this excluded sockets, routing and jemalloc. Moving the buffer locally did
not establish a compelling large-frame gain, so that variant was not promoted
to another production trial. This diagnostic does not identify a definitive
compiler/allocator cause for the end-to-end results.

Evidence: `.local/tcp-output/reuse-daemon`, `reuse-bulk`, `reuse-mixed`, frozen
`rnsd-reuse.bin` / `relay-reuse.bin`, `reuse-candidate.patch`, `reuse-source.rs`,
validation logs and `encoder-micro.{rs,bin,csv}`. Applying the saved patch restores
the source needed by the local encoder diagnostic. Both experiment patches
apply cleanly to the baseline. Production TCP output remains unchanged.
