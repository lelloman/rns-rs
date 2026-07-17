# Reticulum 1.3.9 Candidate Parity Matrix

Candidate source: Reticulum commit
`cf6010da591e9361e26672b6917081a153f1f2c3` (`RNS.__version__ == 1.3.9`).
The accepted baseline remains 1.3.8 until the acceptance gates below are
recorded and a separate promotion commit updates `UPSTREAM.md` and the README.

## Upstream commit audit

| Upstream commit | Local handling | Coverage |
|---|---|---|
| `9adf045a31aad7037f8b84eaa8eef554443073d1` | `99eb3c9` documentation port | Executable semantics and exact documented stanza/output surface test |
| `00b2f81a82f8e38e5052631117398d4bb94a455e` | `9d6e48b` runtime port, after `657db29` preparation | Parser boundaries, bounded direct execution, failure/retry, packed dynamic coordinates, runtime set/reset/null |
| `406b141370fe69a347ab2cbf59eb7f5391f23fb2` | Candidate metadata commit containing this matrix | Exact version/commit pins, retained 1.3.8 fixtures, candidate fixture stability test |
| `bb2897445f3a2bba4b943557241b29e37b8b6954` | `6c73f0f` runtime port | Repeated identify, teardown states, sender/receiver cancellation, active/stale/closed packet gating and cleanup |
| `cf6010da591e9361e26672b6917081a153f1f2c3` | `73f635f` runtime port, after `53b886f` normalization preparation | Interface-type, configured-mode, discoverable and warning matrix including internal mode |

The `location_cmd` implementation intentionally hardens upstream behavior: it
correctly validates longitude, rejects non-finite numbers, reports location
errors accurately, and bounds both execution time and output size.

## Candidate fixture and interop policy

- General crypto/protocol/transport/link/resource/IFAC vectors regenerate
  byte-for-byte unchanged at `cf6010da`.
- Candidate runtime vectors live in `conformance_1_3_9`; historical
  `conformance_1_3_8` vectors remain committed and tested.
- The CI interop lane checks out exactly `cf6010da`, asserts version `1.3.9`,
  and runs the live Python/Rust test.
- Rust crate versions are unchanged because this is an upstream compatibility
  baseline, not a Rust crate release.

## Acceptance record

| Gate | Result |
|---|---|
| Focused discovery, runtime-config, link and resource suites | passed locally, 2026-07-17 |
| Exact `cf6010da` fixture regeneration and byte-stability check | passed locally, 2026-07-17 |
| Workspace tests | pending |
| Native-hook and TLS suites | pending |
| Exact `cf6010da` live Python/Rust interop | passed locally, 2026-07-17 |
| rustfmt and host lint | pending |
| Host release and ARMv7 builds | pending |
| Docker topologies | pending |
| Dual-VPS manual Backbone smoke | pending |

The existing physical Weave HIL caveat is unchanged because this upstream range
contains no Weave changes. No VPS deployment or Rust crate release is part of
this integration.
