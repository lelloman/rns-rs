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
