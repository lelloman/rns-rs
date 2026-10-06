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
