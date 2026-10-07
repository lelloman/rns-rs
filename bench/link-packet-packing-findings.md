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

## Reuse the outbound link decode (2026-10-07)

Follow-up against `8940df5`: the driver previously decoded unattached link
packets for their route hint, discarded that object, then decoded them again
for outbound accounting and transport. It now retains the first decode. If a
route adds a transport header, it drops the old decoded buffers and reparses the
rewritten bytes, preserving existing flag normalization and error handling.
Already-attached and non-link packets continue to decode once. No packet hash
consumer, route lookup, traffic accounting or proof tracking is skipped.

A focused allocation diagnostic compares two calls to `RawPacket::unpack` with
one call on identical HEADER_1 packets. Three observations per size verify raw
bytes, payload and packet hash equality. This isolates the avoided decode, not
full driver allocation totals. Rust/System allocation plus reallocation counts:

| Payload | Calls before / after | Requested bytes before / after |
| --- | ---: | ---: |
| 1 B | 8 / 4 | 96 / 48 |
| 64 B | 8 / 4 | 474 / 237 |
| 464 B | 8 / 4 | 2,874 / 1,437 |
| 16,348 B | 8 / 4 | 98,178 / 49,089 |

All observations match. Eligible packets avoid raw/payload copies, one hash
computation and its temporary input buffer. Rewritten packets still decode twice;
already-attached packets still decode once. These are cumulative requested bytes,
not live heap, peak memory or RSS. Frozen binaries, the focused diagnostic and
live reports are retained in `.local/link-decode-reuse/`.

The new driver test verifies exact transmitted bytes and original proof hashes
for direct routing, transport-header insertion, an attached-interface bypass and
an already-present transport header. It exercises the context flag during header
rewriting and confirms malformed packets are neither emitted nor tracked.

All 1,024 networking unit tests passed; the focused routing test was rerun after
ensuring the old decode is dropped before reparsing. All-target Clippy and
formatting pass. The no-default-features build passes with 30 unused/dead-code
warnings in feature-disabled code.

Three alternating before/after pairs of the existing mixed-smoke suite passed
all 72 cases: 108 Resources and 27,648 echoes including warmups. The median of
per-case combined endpoint CPU changes for bulk-active cases was -9.98%, -4.70%
and -0.31%; individual changes ranged from -30.61% to +25.66%. Echo p99 improved
in 4/6 bulk-active cases in each pair. Echo-only CPU medians were +1.95%, -1.03%
and -0.94%, with p99 improving in only 2/6, 1/6 and 2/6 cases. These short,
contended-host measurements suggest potential bulk benefit but do not establish
a general CPU or latency improvement. Allocation reduction is the confirmed
result. Host, lockfile, toolchain and portable release settings match the prior
slice; no agent builds/tests ran concurrently with timing. No new benchmark
infrastructure or tuning setting was added.
