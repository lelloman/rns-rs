# Reticulum 1.3.8 Parity Record

## Baseline

| Field | Value |
|---|---|
| Previous accepted version | `1.3.7` |
| Accepted version | `1.3.8` |
| Normative tag or ref | `rgit/master` at promotion time |
| Normative commit | `de0f399a1696895dcb95ad1efa19f3b21a7886ab` |
| Version assertion | `RNS.__version__ == "1.3.8"` |
| Acceptance date | `2026-07-11` |
| Detailed audit | Not retained |

The release tag commit is `dca2a928`; the normative `de0f399a` commit contains
one subsequent release-artifact update.

The README badge and accepted baseline in `UPSTREAM.md` were promoted to 1.3.8
after software acceptance. Physical Weave HIL was explicitly waived because the
required external lab hardware was unavailable; it remains a follow-up caveat.

## Status Vocabulary

- `covered`: implemented and covered by deterministic Rust tests.
- `interop`: covered by exact-baseline Python/Rust interop.
- `in progress`: runtime work or fixture coverage remains.
- `HIL`: implemented software requires the stated hardware acceptance run.
- `non-runtime`: audited release, documentation, or generated artifact only.

## Upstream Commit Audit

| Upstream commit | Classification | Rust handling | Status |
|---|---|---|---|
| `dd3ddb9d` | Runtime | Weave `ET_BOARD_INIT = 0x0003` is parsed and retained | covered |
| `b7068888` | Runtime | `LinkEngine.expected_hops`; initiator path value and authenticated responder LRRTT hop | covered |
| `72db6e0e` | Runtime | Per-link packet and packed data/ciphertext byte counters; API fields | covered |
| `a0f0f318` | Runtime | Reject wire hops `>= PATHFINDER_M`, checked ingress increment, announce boundary, fallible cached parsing | covered |
| `b1b3ff71` | Version metadata | No crate release bump in this milestone | non-runtime |
| `dca2a928` | Changelog/release artifacts | Not vendored | non-runtime |
| `de0f399a` | Generated release artifacts | Not vendored | non-runtime |

## Compatibility Evidence

| Subsystem | Compatibility surface | Evidence/status |
|---|---|---|
| Cryptography | X25519, Ed25519, HKDF, AES, token, hashes, IFAC | Existing Python fixtures and interop; exact generator now rejects other baselines (`interop`) |
| Packet codec | Header 1/2, hashes, MTU, permissive pack, strict inbound hops | Unit boundary tests for 127/128/255 (`covered`) |
| Transport | announce/path selection, ingress control, held announces, cache/restore safety | Exact-baseline hop/held vectors and malformed-cache regressions (`interop`) |
| Links | handshake, expected hops, identify, keepalive, close, requests/responses | Engine and manager tests (`covered`) |
| Link accounting | LRPROOF/LRRTT, data, request, channel, resource contexts | Central inbound/outbound accounting, lifecycle/context tests, and exact Python ciphertext-padding vectors (`interop`) |
| Channels | envelopes, windows, proofs, retry timing | Existing fixtures/tests (`covered`) |
| Resources | advertise/request/parts/proofs/cancel, persistence | Existing fixtures/tests (`covered`) |
| Persistence | destinations, ratchets, announces, paths, tunnels | Existing restart/corruption tests (`covered`) |
| Shared RPC | pickle/msgpack status and management | Existing RPC tests; new optional telemetry fields serialized (`covered`) |
| Discovery | accepted types and generated Weave configuration | Existing discovery tests plus Weave type/config rendering (`covered`) |
| TCP/UDP/Local/Auto/I2P/Pipe/Serial/KISS | Built-in interface behavior | Existing suites plus typed dynamic peer registration and inherited IFAC (`covered`) |
| Backbone client compatibility | `BackboneClientInterface`; `remote`/`port` and `target_host`/`target_port` aliases | Factory registration and parser tests (`covered`) |
| AX.25 KISS | callsign/SSID validation, APZRNS UI header, KISS transport behavior | Default feature, deterministic UI frame tests, inherited KISS reconnect/flow control (`covered`) |
| RNode single | Existing single-radio behavior unchanged | Existing RNode tests (`covered`) |
| RNode multi | third-level sections, up to 11 enabled radios, actual virtual-port demux, outgoing flag | Parser/factory, non-sequential vport tests, and exact outbound wire vector (`interop`) |
| Weave codec | bounded WDCL HDLC, command/event/display/endpoint frames | Deterministic fragmented/coalesced codec and state tests (`covered`) |
| Weave session | signed discovery/connect, two-second gate, five-second reconnect | Authenticated shared session and simulated-device integration (`covered`); physical session is gated below |
| Weave peers | dynamic typed peers, IFAC inheritance, duplicates, expiry/reconnect | Simulated bidirectional delivery, duplicate/expiry, teardown, and reconnect (`covered`) |
| Weave telemetry | CPU/memory, IDs, via, peers, logs, 128x64 display | Live update plumbing and status/RPC serialization (`covered`); hardware telemetry is gated below |
| `rnstatus` | optional telemetry and hidden Weave peers unless `--all` | Text/JSON handling implemented (`covered`) |
| Existing Rust CLI tools | daemon, status, path, probe, identity, HTTP/RPC | Workspace/CLI integration tests (`covered`) |

## Acceptance Gates

Software acceptance requires all `in progress` rows above to become `covered`
or `interop`, followed by:

- `cargo test --workspace`
- hook-enabled and TLS test suites
- host lint and rustfmt
- release builds and ARMv7 smoke build
- all Docker topologies
- exact `de0f399a` live Python/Rust interop
- manual Backbone smoke

Physical Weave HIL additionally requires a current-firmware USB switch and a
separately reachable endpoint. The run must capture sanitized traces and prove
authenticated startup, board-init/log and CPU/memory telemetry, dynamic peer
creation, bidirectional RNS delivery, peer expiry, and serial reconnect. This
was not available during baseline promotion and remains outstanding; simulated
integration is the acceptance evidence for Weave in the 1.3.8 software profile.

## Acceptance Record

The complete software acceptance run passed on Linux x86_64 on 2026-07-11:

- exact `de0f399a` fixture regeneration was byte-stable and live Python/Rust
  bidirectional TCP interop passed with `PYTHONPATH` pinned to that checkout;
- workspace, native-hook, TLS, rustfmt, and host lint checks passed;
- release builds passed for the host and ARMv7 GNU/Linux runtime binaries;
- all nine Docker runs passed (102 assertions, zero failures), covering chain,
  mesh, star, 30-node scale, shared-client reconnection, and process supervision;
- the live backbone smoke passed through independent `vps-eu` and `vps-us`
  entry points, including announcements, identity recall, packets, links, and
  bidirectional channel messages.

## Caveats and Deferred Validation

Reticulum 1.3.8 was promoted with the explicit caveat that physical Weave HIL
remains outstanding until the required switch and reachable endpoint are
available. No physical Weave compatibility claim is made by this acceptance.

## Promotion Result

Reticulum 1.3.8 was accepted as the rns-rs upstream reference baseline at
normative commit `de0f399a1696895dcb95ad1efa19f3b21a7886ab`.
