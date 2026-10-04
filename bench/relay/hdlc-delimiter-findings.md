# HDLC delimiter search experiment — 2026-10-04

Decision: park the candidate. Replacing the closing-delimiter search with
`memchr` consistently reduced bulk relay CPU, but small-message tail latency
remains a concern. Host contention was uncontrolled, so these observations do
not establish causality or justify a general server default.

The prototype changed only the closing-FLAG search in `feed_with_diagnostics`.
It added a direct dependency on the already locked `memchr` 2.8.3 package.
Opening-delimiter search, unescape behavior, encoding, allocation policy and
frame bounds were unchanged. Runtime CPU dispatch required no machine-specific
build flags. The parked unescape and shared-handoff candidates were excluded.

## Measurements

Frozen baseline relay: production revision `2e77697` (subsequent commits were
documentation). Endpoints stayed identical throughout. Both relays used portable
optimized profiling builds and the System allocator, with no profiler attached.
Builds and tests finished before measurements. Three alternating matched pairs
per suite completed 432 valid cases.

| Pair | Bulk relay CPU change | Mixed relay CPU change | Small-message-only CPU change | Small-message-only scheduled p99, before → after |
|---|---:|---:|---:|---:|
| 1 | −22.92% | +3.78% | +5.24% | 0.657 → 0.658 ms |
| 2 | −25.74% | −5.68% | −1.37% | 0.700 → 0.685 ms |
| 3 | −33.82% | −12.11% | −9.03% | 0.678 → 4.354 ms |

The third pair's small-message tail spike was concentrated in two cases.
One additional matched mixed pair was run specifically to check repeatability;
all 72 additional cases passed. Its mixed CPU improved 4.88%, while
small-message-only CPU increased 1.72% and scheduled p99 rose from 0.632 to
1.108 ms. The original spike did not repeat at the same magnitude, but this
confirmation did not clear the tail-latency concern.

Median per-case p99 was much steadier than pooled p99. That observation does not
justify removing slow cases. All observations are retained; none of these runs
is a controlled latency qualification. RSS-after medians changed by less than
0.5%; no allocation reduction is claimed.

## Validation

All 21 HDLC tests, 988 networking unit tests and 58 end-to-end tests passed.
Clippy passed for networking and benchmark targets with warnings denied.
Differential checks covered every byte pair and escape-alphabet sequences
through length six, four fragment sizes and two frame-bound policies.

A focused decoder benchmark used three alternating repeats of 10,000 feeds,
32/512/16,348-byte payloads, and ordinary/sparse/dense escapes. Small ordinary
and sparse frames were roughly unchanged; larger frames mostly improved
19–33%, with one 46% outlier. Dense short frames improved 10–19%. This supports
the search optimization's mechanism, not a general networking speedup claim.

## Retained evidence and next decision

Local artifacts under `.local/perf-opportunities/` include:

- `item12-scan/`: source snapshots, focused measurements and equivalence checks.
- `item12-scan-relay/`: original matched runs, hashes, source patch and provenance.
- `item12-scan-confirm/`: the additional mixed pair, retaining the latency concern.
- `item12-scan-tested-candidate.patch`: the complete withdrawn production patch.

Before adopting this candidate, establish a small-message latency noise floor
with repeated identical-binary comparisons on a quieter or isolated host.
An explicit bulk-oriented build option could be evaluated later, but is not
implemented or recommended by this experiment.
