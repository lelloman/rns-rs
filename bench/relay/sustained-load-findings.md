# Sustained forwarding load — 2026-10-09

Earlier relay measurements kept one exchange outstanding per link, so the
daemon idled between packets and never filled a queue. A native load generator
keeping 256 small frames in flight per direction (each answered by a proof)
and a second scenario of near-MTU link parts exposed three defects and the
dominant costs under saturation. All were fixed on `perf/wire-driver-fixes`.

## Defects

- **Writer queue blackhole.** One `WouldBlock` from a full interface writer
  queue made the driver skip every send to that interface for 25 ms, doubling
  to 1 s. A single burst stalled forwarding at about 77 frames/s. Async
  writers now wait up to 20 ms for space, then make single attempts until a
  frame is admitted again; the driver no longer defers async writers.
- **Reader drops.** Readers discarded data frames when the inbound queue was
  full. They now wait for space, so TCP flow control slows the sender.
  Announce, path-request and ingress-limited classes keep dropping.
- **Link MTU not clamped.** Forwarded link requests kept the signalled MTU,
  as Transport.py does not: endpoints negotiated frames larger than this hop
  accepts and every full-size part was rejected. The signalled MTU is now
  lowered to the smaller of the two hop MTUs, or stripped without one.

## Results

`rnsd`, one CPU (cpuset 2, quota 1.0), 512 MiB, three rounds, 10-second
windows. CPU is the cgroup inside the measured window.

| Workload | Build | Lossless | Frames/s | MB/s | CPU µs/frame | Peak MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 60-420 B frames + proofs | `2948f05` | 0/3 | 77 | 0.0 | stalled | 15.9 |
| 60-420 B frames + proofs | `b01fead` | 3/3 | 177,761 | 42.7 | 5.63 | 15.8 |
| near-MTU link parts | `2948f05` | failed | — | — | — | — |
| near-MTU link parts | `b01fead` | 3/3 | 11,538 | 755.9 | 86.8 | 19.2 |

The one-exchange workload is unchanged within noise (relay CPU 9.16 s,
peak 17.9 MiB, four trials).

## Cost reductions found by profiling

An in-process sampler (pprof, SIGPROF) located each step:

- Dedup bucket hashing was byte-wise FNV (16.5% of CPU): packet hashes are
  SHA-256, so the leading 64 bits index directly. Eviction re-inserted whole
  probe clusters; it now uses backward-shift deletion. Buckets are u32.
- The std sync channel between driver and writer spun on a single CPU (13%);
  it is replaced by a mutex queue the writer drains in one acquisition.
- Condvars notified on every enqueue and dequeue; they now notify only when
  a thread waits. Readers enqueue all frames from one read under one lock,
  the driver receives up to 16 events per lock, and burst state is published
  only on change. The writer's space lock is taken only after a refused
  admission (it was the most contended lock).
- Packet hashing builds no temporary buffer; TCP writers coalesce frames into
  256 KiB writes and read 64 KiB at a time; interface lookups avoid SipHash;
  an idle per-iteration HashSet construction is skipped.

Remaining profile: SHA-256 about 14%, dedup memory access about 17% (once the
250,000-entry table fills, every insert evicts), packet copies in unpack,
`Arc<[u8]>` drops and B-tree route lookups.

## Validation

rns-core 679, rns-net 1,050, end-to-end 60 and the smaller suites pass after
every commit; new tests cover batch enqueue ordering and wakeup, blocking
reader delivery, writer backpressure and stall fail-fast, the MTU clamp, and a
randomized dedup FIFO model with colliding keys. The nine-case Python 1.5.7
smoke and the restart scenario pass.
