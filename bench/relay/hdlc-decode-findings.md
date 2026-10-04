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

## CPU capture follow-up

A subsequent capture completed all 72 cases (36 per version) with fixed
endpoints and matching frozen binary hashes. It sampled each relay process tree
at 499 Hz using `cpu-clock` and 16 KiB DWARF stacks. Workers ran unprivileged.
Captures cover the entire worker lifetime, including startup and warmup; they
do not isolate the measured interval. Profiler timings are not acceptance data.

Splitting the **original unprofiled** mixed results by the presence of a
background Resource exposes the workload tradeoff more clearly:

| Pair | Small-message probes alone: CPU change | Probes with a Resource: CPU change |
|---|---:|---:|
| 1 | +7.27% | −0.58% |
| 2 | +5.40% | −0.17% |
| 3 | +5.65% | −1.58% |

Each cell sums relay user plus system CPU over 18 matched cases. The aggregate
mixed regression comes from the small-message-only controls. This locates the
affected workload; it does not establish which instruction or runtime behavior
causes the increase.

Capture quality and observations:

- All files decoded successfully, with zero reported lost samples. There were
  1,521 baseline and 1,633 candidate samples; exclude 141 and 132 `sudo` samples
  respectively from worker analysis.
- Worker samples comprised 619/630 user-space samples and 761/871 kernel samples
  (baseline/candidate). Kernel leaves were unresolved, limiting diagnosis of
  system CPU. No loss warnings is not a guarantee of unbiased sampling.
- Stacks containing `unescape` numbered 77/32 across all cases. This supports
  further investigation of the intended reduction, but is not a speedup ratio:
  the captures include startup, profiler overhead and different execution times.
- In the small-message-only controls, just 8/3 stacks contained `unescape`, out
  of 493/560 worker samples. These counts cannot attribute a few-percent CPU
  change to a specific decoder operation.
- Delimiter searches outside `unescape`, within `feed_with_diagnostics`, appeared
  in 101/110 stacks. This is a separate visible cost, not an explanation of the
  regression; the candidate did not change delimiter scanning.

Decision remains unchanged: keep the candidate parked. A causal investigation
needs longer steady-state small-message profiling with setup excluded. Delimiter
search improvements can also be tested independently; neither result justifies
an automatic frame-size threshold or a host-specific default.

Capture evidence is retained locally under `.local/hdlc-mixed-cpu/`. The
`analysis/` directory contains per-case symbol reports and stacks, sample
summaries, capture hashes, and `unprofiled-split.json`. No production code was
changed during this follow-up.
