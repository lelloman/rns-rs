# Retained ratchet search (2026-10-06)

Commit `d874f3b` removes unnecessary key searches for ciphertexts too short to
contain a decryptable token. It does not speed up full-length oldest-key,
no-match or identity-fallback scans by changing their search algorithm.

## Attribution and accepted change

A compact release-mode diagnostic on the AMD Ryzen 9 5950X measured isolated
per-attempt stages: X25519 exchange 71.2 microseconds, 64-byte HKDF 0.600
microseconds, and Token construction plus unsuccessful authentication 0.277
microseconds. Each stage ran 20,000 times. These are separate timings, not an
additive end-to-end CPU profile; they identify exchange as the dominant cost
without establishing precise percentages or allocation counts. Lock contention
in the network ratchet owner was not measured.

An 80-byte identity ciphertext contains only a 32-byte ephemeral key and the
48 bytes of token overhead. The existing Token decryptor rejects that length
regardless of the key. Previously the ratchet path still derived a shared secret
and token key for every retained key. Even inputs of at most 32 bytes walked the
ring, constructing and zeroizing each private-key wrapper before rejection.

The change checks this key-independent length before searching the ring, and
before key exchange in the ordinary identity decryptor. Existing enforced-mode,
identity-fallback and public-only identity errors are preserved. A minimum valid
96-byte ciphertext carrying empty plaintext still authenticates and decrypts;
modified authentication data is rejected. Retention, newest-first search order,
identity salt, fallback policy and the full-length authentication path are
unchanged. No extra cache, threads or retained secret copies were introduced.

## Measurements and limits

Three alternating pairs used frozen portable release binaries with the System
allocator. Each binary exercised histories of 1, 512 and 4,096 keys, newest and
oldest successful matches, a full-length no-match, identity fallback, truncated
input and an 80-byte short token. All 108 case measurements passed their payload
or rejection checks. Fixture setup and builds were outside measurement; no
builds or tests ran concurrently with these comparisons. No CPU affinity or
exclusive host reservation was used.

| Input / retained keys | Before, range across three runs | After |
|---|---:|---:|
| 80-byte short token / 1 | 79.8–83.7 µs | below 1 µs |
| 80-byte short token / 512 | 42.5–43.1 ms | below 1 µs |
| 80-byte short token / 4,096 | 346.7–423.3 ms | below 1 µs |
| At most 32 bytes / 4,096 | 67.5–189.5 µs | below 1 µs |

The changed path reaches the timing floor; the long-history short-token case
used only four iterations per case. Do not treat its tens-of-nanoseconds outputs
as precise latency estimates or derive a precise speedup ratio. The structural
result is elimination of the retained-key loop and all key exchanges for these
inputs. Full-length valid/no-match scan times varied substantially: oldest-key
4,096-key scans ranged 311.7–565.6 ms before and 237.2–349.5 ms after. These
measurements do **not** establish a general speedup or isolate small regressions.
All per-pair observations, including unfavorable changes, are retained.

Validation: 77 crypto unit tests, two 11-test integration suites, 664 core unit
tests and eight local-ratchet lifecycle tests passed. Crypto all-target Clippy,
workspace formatting and the crypto no-default-features build passed. New tests
cover short-input boundaries, empty/nonempty histories, private/public identities,
fallback errors, minimum valid ciphertext and tampering.

Ignored `.local/ratchet-search/` contains the small harness, lockfile, stage
measurements, all pair outputs/statuses, source patch/revision, toolchain/CPU
metadata, binary hashes and frozen executables. No build tree or perf capture
was copied. Further work on full-length scans and lock scope remains open;
reducing retained history or weakening authentication is not an accepted shortcut.


## Shared-owner read-lock trial (2026-10-06): parked

`LocalRatchets::decrypt` holds an exclusive state mutex throughout its newest-first
search. That serializes concurrent calls sharing one owner. A local candidate
changed only the owner state to `RwLock`: decryption, current-key lookup and
retention queries borrowed a read guard; rotation, pruning, enforcement,
recovery, persistence updates and announcement pins retained exclusive access.
No history snapshots, secret caches, extra worker threads or search-order
changes were introduced. Mutations still waited for active readers to release
history. This prototype is **not retained in production**.

Three alternating pairs on the same 5950X tested histories of 512 and 4,096
keys with one/four callers sharing an actual `LocalRatchets` owner. Newest,
oldest, full-length no-match and identity-fallback cases used 128-byte payloads.
Fallback was allowed in this diagnostic. Each caller performed two operations
for full scans or 64 for newest-key matches. Thread creation, signed-history
import and fixture encryption were outside the timed barrier-to-join batches.
Every successful operation verified its plaintext; no-match operations verified
rejection. Process CPU time was measured separately from elapsed time. These
are owner-API measurements, not network throughput or a single driver's latency.

With unrestricted affinity, four-caller full-scan batches improved in all three
pairs. The table shows medians for 4,096 keys; newest batches contain 256 calls,
while other rows contain eight calls.

| Case | Mutex elapsed ms | Mutex CPU ms | Read lock elapsed ms | Read lock CPU ms |
|---|---:|---:|---:|---:|
| newest | 20.06 | 21.37 | 4.76 | 18.96 |
| oldest | 1495.25 | 1495.35 | 364.09 | 1446.56 |
| no-match | 1478.25 | 1478.35 | 363.95 | 1454.20 |
| fallback | 1463.45 | 1463.60 | 366.06 | 1455.88 |

The improvement is concurrency, not fewer exchanges: four callers can consume
roughly four CPUs at once. Single-caller full scans remain linear and about the
same cost. This does not make a node driver issue parallel decryptions.

A further three alternating pairs pinned both binaries to one available CPU,
without reserving that CPU. Four-caller full-scan batches remained about
1.43–1.47 seconds. However, newest-key maximum call times at 4,096 keys regressed
in every pair: **10.274 -> 13.696 ms**, **10.576 -> 13.695 ms**, and
**10.730 -> 14.042 ms**. Median call time remained about 0.07 ms and batch time
about 18 ms. These are observed maxima from 256-call batches, not population
p99 guarantees. Making all callers runnable changes scheduling and removes the
mutex's serialization; attributing the precise tail increase would need a
scheduler trace. The repeated regression is retained rather than averaged away.

Decision: park the read-lock default. The multicore benefit is real in this
workload, but the plan requires interactive-latency trade-offs to be resolved
before adopting portable defaults. Reconsider only for an explicitly scoped
concurrent-owner policy or a mechanism that also addresses the single-CPU case.
Do not infer a universal benefit or silently select a CPU-count threshold.

All 192 case measurements completed successfully. The prototype passed 1,024
network unit tests, 60 e2e tests, all-target Clippy and formatting. The minimal
network library build passed with its disabled-interface warnings. A controlled
shared-history guard regression verified concurrent decryption and that pruning
and enforcement wait for readers; after retirement, the old ratchet and forbidden
identity fallback were rejected. Builds/tests did not overlap measurements.
No production source or prototype test remains in the working tree.

Ignored `.local/ratchet-lock/` retains the candidate patch, baseline source,
small harness/lockfile, frozen binaries, revision/patch/hashes, CPU/toolchain
metadata, all per-call timings and exit statuses, and test logs. Local artifacts
remain compact; no build trees or profiler captures were copied. Single-request
X25519 cost and broader mutation-wait behavior remain open.
