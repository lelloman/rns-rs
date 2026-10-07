# Link packet packing without a discarded hash

Accepted 2026-10-07, baseline `e420fcc`: `build_link_packet` requested both raw
bytes and a packet hash, then discarded the hash. It now uses
`RawPacket::pack_raw_with_max_mtu`, which encodes identical bytes with the same
validation. Existing hash-producing APIs call the shared encoder and still
compute their hash. Only this one network caller switches to byte-only packing.
No authentication, proof, routing, deduplication or sent-packet tracking hash
is removed. The driver's outbound unpack still supplies the hash to consumers.

## Confirmed work reduction

A focused release diagnostic compares both APIs with identical inputs and
asserts byte equality. Three observations per payload length use a Rust
GlobalAlloc wrapper over System. Counts below include alloc and realloc calls;
requested bytes include successive realloc sizes, not peak live memory or RSS.
Both paths run in the same executable; diagnostic timings are not used.

| Payload | Calls before / after | Requested bytes before / after |
| --- | ---: | ---: |
| 0 B | 5 / 3 | 88 / 62 |
| 64 B | 6 / 4 | 235 / 145 |
| 464 B | 6 / 4 | 1,035 / 545 |
| 16,348 B | 6 / 4 | 32,803 / 16,429 |

Every observation matches. The removed work is the temporary hashable-input
buffer (one allocation and one reallocation) and one SHA-256 call. Packet
payload copies and downstream hashing remain. No whole-daemon memory saving
was measured. Allocation source and CSV are retained under
`.local/link-packet-packing/`.

## Live comparison and validation

Three alternating before/after pairs used the existing mixed-smoke suite:
before/after, after/before, before/after. All 72 cases passed, covering repeated,
seeded and SHA-256-counter 1 MiB inputs, compression off/on and background
Resource traffic off/on. This verified 108 Resources and 27,648 echoes including
warmups. Separate frozen binaries use the same root lockfile, portable release
settings and rustc 1.96.0 on Linux x86_64 / Ryzen 5950X. No agent builds or tests
ran alongside timing, but host contention was uncontrolled.

For the six bulk-active cases in each pair, the median of per-case combined
endpoint CPU changes was -3.60%, +2.77%, and -6.94%. Individual changes ranged
from -30.45% to +55.77%. Echo p99 improved in 2/6, 3/6 and 5/6 cases respectively.
Echo-only controls also varied substantially. These short exploratory runs do
not establish an end-to-end CPU, throughput or latency improvement. Retain the
change for removing demonstrably unused computation and allocation; no new
benchmark infrastructure or default tuning is introduced.

All 670 core unit, 56 core integration and 1,023 networking unit tests pass.
The new test covers both headers, present/absent transport IDs, empty and bulk
payloads, and MTU boundaries. It checks explicit wire layouts, error precedence,
and hash-producing API compatibility. Packing's existing empty-payload acceptance
and unpacking's rejection are both preserved; the initial test incorrectly
expected empty payload unpacking to succeed and was corrected. Existing link
packet MTU and traffic-accounting tests pass. no-default-features, formatting
and all-target Clippy for core/networking pass.

Reproduce live runs with each frozen revision's `rns-bench run --suite
resource-mixed --profile mixed-smoke --output <fresh-directory>`. Ignored local
artifacts contain manifests, allocation diagnostic, pair runner and comparisons.
