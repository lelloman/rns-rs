# HDLC decoder experiment — 2026-10-04

Decision: retain the existing decoder. The candidate saved bulk relay CPU but
increased mixed-workload CPU in all three matched pairs. Investigate that
tradeoff before adopting it as a general Linux-server default.

The candidate copied runs of ordinary bytes together and decoded consecutive
escapes directly. Encoding, delimiter scanning, buffer limits and allocation
capacity were unchanged. Unknown and trailing escapes retained their behavior.
No dependencies or CPU-specific build flags were introduced.

## Relay results

Baseline: `2e77697`. Only the relay executable changed; both endpoints used the
same frozen executable throughout. Workers used the System allocator and a
portable optimized `profiling` build, without a profiler attached. Three
alternating pairs per suite used `quick` and `mixed-quick`; all 432 cases passed.
Host contention was recorded but uncontrolled. These are exploratory results.

Changes below are candidate relative to baseline; negative CPU means less CPU.

| Workload | Pair | Relay CPU | Elapsed time | Scheduled probe p99 |
|---|---:|---:|---:|---:|
| Bulk | 1 | −9.87% | −0.96% | — |
| Bulk | 2 | −8.69% | −2.84% | — |
| Bulk | 3 | −2.67% | +6.71% | — |
| Mixed | 1 | +2.62% | −0.02% | +11.83% |
| Mixed | 2 | +2.09% | −3.22% | −49.05% |
| Mixed | 3 | +1.30% | +0.20% | +27.34% |

RSS-after medians changed by less than 0.2%. Probe tails varied substantially;
the experiment does not establish a consistent latency or throughput effect.
The mixed CPU increase is a reason for further investigation, not proof that
every span-copy implementation is slower on mixed traffic.

## Validation and focused measurements

All 22 HDLC tests, 989 networking unit tests and 58 end-to-end tests passed.
Clippy passed for networking and benchmark targets. Differential checks matched
the original decoder for every byte pair and escape-alphabet sequences through
length six, with four chunk sizes and two frame-bound policies. A regression
test covered known, unknown, repeated and trailing escapes at every split.

A decoder microbenchmark used 32-, 512- and 16,348-byte payloads with ordinary,
sparse and dense escapes, 10,000 feeds per variant and three alternating repeats.
Ordinary/sparse input took roughly 14–52% less time. Dense short frames were
around parity; larger dense frames improved. An earlier design regressed dense
input and was superseded. These microbenchmarks do not establish daemon gains.

## Retained evidence

Local artifacts are intentionally excluded from Git. On the measurement host,
`.local/perf-opportunities/item12-relay/` contains source patches, binary hashes,
build provenance, manifests and per-case results. `item12/` contains the focused
benchmarks and validation logs; `item12-tested-candidate.patch` preserves the
withdrawn implementation and regression test. Full notes are in
`HDLC-DECODE-FINDINGS.txt` alongside those directories.

The next investigation should compare relay thread CPU stacks under mixed
traffic, keeping endpoints fixed. Profiling runs must remain separate from
unprofiled timing comparisons.
