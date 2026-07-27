# Reticulum 1.4.0 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.3.9` |
| Previous normative commit | `cf6010da591e9361e26672b6917081a153f1f2c3` |
| Accepted version | `1.4.0` |
| Normative tag or ref | Tag `1.4.0` plus the following artifact-only tip |
| Normative commit | `122f17fad69a483503cc5c1d8d81046712d78c96` |
| Release tag commit | `be36abd85715afd9dd7dccdda29d024d3d0f2353` |
| `RNS` tree | `5e1b42cb553f6cdd34145dc2bcbf93f653705368` |
| Version assertion | `RNS.__version__ == "1.4.0"` |
| Acceptance date | `2026-07-20` |
| Detailed audit | [reticulum-1.4.0-audit.md](reticulum-1.4.0-audit.md) |

The normative tip adds generated release artifacts without changing the tagged
runtime tree.

The README badge and accepted baseline in `UPSTREAM.md` are promoted to 1.4.0.
The PR CI matrix remains the final software acceptance authority.

## Upstream Commit Audit

| # | Upstream commit | Local handling and coverage |
|---:|---|---|
| 1 | `3a36c367` | Already ported by `af2ee6e`; malformed and oversized resource advertisements have stricter link-teardown tests. |
| 2 | `b95c51b9` | Already ported by `55b8545`; pathing visibility is covered by logging-filter tests. |
| 3 | `cd6911ed` | Already ported by `e7819ae`; threshold, duration, shared-history and expiry boundaries are tested. |
| 4 | `88833f17` | Operator documentation ported by `ab0d8fa`; referenced option defaults are executable-test backed. |
| 5 | `d93f9798` | Already covered by `326ac55`; rnsh authorization and teardown invariants are tested. |
| 6 | `a5ed0a43` | Already ported by `8d5129f`; exact/minimum/oversized HDLC frame boundaries and recovery are tested. |
| 7 | `13a53816` | Python-only exception/log guard; Rust decoding is typed and cannot reference an unbound exception value. |
| 8 | `50812553` | Discovery diagnostic ported by `733a432`; the Python persistence-success log has no Rust callback equivalent. |
| 9 | `ec8d43a5` | Already ported by `fd21db1`; separate local/remote rnsh config resolution is tested. |
| 10 | `3898d636` | Already covered by `e7819ae`; disabling fast-flap protection is tested as a complete no-op. |
| 11 | `3c4ef622` | Upstream changelog text only; no vendored changelog source. |
| 12 | `bfade970` | Generated 1.3.9 manual/release artifacts only. |
| 13 | `e64d8150` | Ported by `e6729ba`; initiator probe, responder acknowledgement, silence rules and no-ping-pong behavior are tested. |
| 14 | `2d811dc3` | Ported by `9a58b89`; complete hop/interface route context and wrong-interface distinction are tested. |
| 15 | `ef9244f7` | Ported by `29fcee3`; registration-time caching, replacement refresh and deregistration removal are tested. |
| 16 | `2c9edc43` | Python socket exception-string suppression; Rust uses typed I/O results and existing shutdown handling. |
| 17 | `2b79db03` | Ported by `a96b875`; invalid cache keying, FIFO bounds, malformed input and persistent driver reuse are tested. |
| 18 | `cbba3502` | Ported by `4850e7f`; exact raw/msgpack files, atomic replacement, 10 ms yielding, 12-hour scheduling and restart reconstruction are tested. |
| 19 | `6c6238ce` | No port required; Rust route insertion already authoritatively overwrites the destination entry. |
| 20 | `d8bc20d4` | No port required; Rust never exposed the deprecated recombination argument. |
| 21 | `65274235` | Ported by `2a3bfb5`; bounded batches, mid-pass insert/refresh safety, background ratchet cleanup and shutdown joining are tested. |
| 22 | `f81b2675` | Ported by `d91ac56`; sorted current block lists, disabled/expired behavior, query and RPC shapes are tested. |
| 23 | `fb7479a6` | Structurally covered: a link tick receives one `now` snapshot used by all keepalive and stale decisions. |
| 24 | `032b1aa3` | Python version metadata; recorded as the baseline metadata commit without changing Rust crate versions. |
| 25 | `a5728be4` | Python `None`/exception logging fix; Rust listener state is typed and only evaluates registered handles. |
| 26 | `fa4d4c67` | Ported by `efbd6ca`; valid-cache hits, FIFO bounds, payload keying, dynamic metadata and raised requirements are tested. Driver ownership provides sequential validation. |
| 27 | `be36abd8` | Ported by `771762b`; default value 16 and explicit lower override behavior are tested. |
| 28 | `122f17fa` | Generated 1.4.0 manual/release artifacts only; selected as the normative shared remote tip. |

## Compatibility Evidence

- General crypto/protocol/transport/link/resource/IFAC vectors are regenerated
  only from exact commit `122f17fa`.
- Reticulum 1.4.0 runtime vectors live in `conformance_1_4_0`; historical 1.3.9
  and 1.3.8 vectors remain committed and tested.
- CI checks out the exact GitHub-mirrored commit directly, verifies its `RNS`
  tree and reported version, then runs live Python/Rust interoperability.
- Rust crate versions are unchanged because this is an upstream compatibility
  baseline, not a Rust crate release.

## Acceptance Record

| Gate | Result |
|---|---|
| Focused regression suites for all applicable commits | passed locally, 2026-07-20 |
| Exact `122f17fa` fixture regeneration and byte-stability check | passed locally, 2026-07-20 |
| Workspace tests | passed locally, 2026-07-20; repeated by PR CI |
| Native-hook, built-in-hook and TLS suites | passed locally, 2026-07-20; repeated by PR CI |
| Exact `122f17fa` live Python/Rust interop | passed locally, 2026-07-20 |
| Web UI smoke suite | passed locally, 2026-07-20; repeated by PR CI |
| rustfmt and host lint | passed locally, 2026-07-20; repeated by PR CI |
| ARMv7 and Docker topology gates | delegated to required PR CI |
| Dual-VPS manual Backbone smoke | manual follow-up; not claimed by this source promotion |

## Caveats and Deferred Validation

The existing physical Weave HIL caveat is unchanged. No VPS deployment or Rust
crate release is part of this integration, and no manual or CI-only gate is
claimed as locally passed.

## Promotion Result

Reticulum 1.4.0 was accepted as the rns-rs upstream reference baseline at
normative commit `122f17fad69a483503cc5c1d8d81046712d78c96`.
