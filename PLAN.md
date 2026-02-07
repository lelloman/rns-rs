# Reticulum Rust Rewrite — Grand Plan (Strict TDD)

## Context

The Reticulum roadmap lists a lightweight C implementation for microcontrollers and a portable high-performance C/C++ implementation. This plan achieves the same goal in Rust, targeting embedded/no_std environments with full feature parity. The Rust code lives in `rns-rs/` within the existing repo.

**This is a rewrite.** The Python implementation IS the specification. Every behavior we implement must be derived from and validated against the Python code. We do not invent — we replicate.

## TDD Methodology

**Every line of production code is written to make a failing test pass.** The cycle:

1. **Red**: Write a test that captures a specific Python behavior. Run it. It fails (or doesn't compile).
2. **Green**: Write the minimum Rust code to make that test pass. Nothing more.
3. **Refactor**: Clean up duplication, improve naming, extract types — tests stay green.

### Test Vector Generation

Since this is a rewrite, tests are derived from the Python implementation:

- **Golden master tests**: Run Python code with known inputs, capture outputs as test fixtures (binary files or inline byte literals). Rust tests assert identical output.
- **Round-trip tests**: Python encrypts → Rust decrypts (and vice versa). Python packs → Rust unpacks.
- **Characterization tests**: For complex behaviors (Transport routing decisions, Link state transitions), capture Python's actual behavior as test cases — even if the behavior seems surprising.

A `tests/generate_vectors.py` script will produce all test fixtures by exercising the Python RNS library directly. This script is maintained alongside the Rust code and re-run whenever the Python implementation changes.

### Test Anatomy

Each phase has three layers of tests:

1. **Unit tests** (in each `.rs` file): Pure logic, no I/O, fast. Test one function/struct at a time.
2. **Integration tests** (in `tests/`): Cross-module, cross-crate. Test compositions (e.g., Identity uses Token uses HKDF).
3. **Interop tests** (in `tests/wire_compat/`): Binary compatibility with Python. Run Python to generate → Rust to consume (and reverse).

---

## Workspace Structure

```
rns-rs/
├── Cargo.toml                       # Workspace root
├── rns-crypto/                      # no_std — cryptographic primitives
├── rns-core/                        # no_std — protocol logic
├── rns-net/                         # std — networking, config, I/O
├── rns-cli/                         # std — CLI binaries
└── tests/
    ├── generate_vectors.py          # Python script to produce test fixtures
    ├── fixtures/                    # Generated binary test data
    │   ├── crypto/                  # Token, HKDF, PKCS7 vectors
    │   ├── packet/                  # Packed packets
    │   ├── identity/                # Encryption, signing, announces
    │   ├── destination/             # Hash computations
    │   ├── link/                    # Handshake sequences
    │   ├── channel/                 # Envelope framing
    │   └── resource/                # Advertisement, hashmap
    └── wire_compat/                 # Rust interop test harnesses
```

### Crate Graph

```
rns-cli → rns-net → rns-core → rns-crypto
                     (no_std)    (no_std)
```

---

## Phase 1: Cryptographic Primitives (`rns-crypto`)

**Milestone**: Rust can encrypt/decrypt/sign/verify identically to Python. A ciphertext produced by Python's `Token.encrypt()` can be decrypted by Rust, and vice versa.

### TDD Sequence

Each item below is a Red→Green→Refactor cycle (or a small cluster of cycles):

#### 1.1 PKCS7 Padding
1. Test: `pad(b"hello", 16)` produces expected 11-byte padding
2. Test: `unpad(padded)` recovers original
3. Test: full-block input gets extra 16 bytes of padding
4. Test: `unpad` rejects invalid padding (wrong byte values, zero-length)

#### 1.2 HMAC-SHA256
1. Test: HMAC of known message with known key matches Python `HMAC.new(key, msg).digest()`
2. Test: empty message, empty key edge cases
3. Test: key longer than block size (64 bytes) is hashed first

*Note: likely just wiring `hmac` + `sha2` crates, but tests confirm the wiring is correct.*

#### 1.3 Custom HKDF
1. Test: `hkdf(length=32, derive_from, salt, context=None)` matches Python output
2. Test: `hkdf(length=64, ...)` — multi-block derivation
3. Test: with non-None context
4. Test: with empty salt

**Critical**: Python's HKDF is NOT RFC 5869. The counter starts at 1, previous block is prepended. Tests must use vectors generated from `RNS/Cryptography/HKDF.py` directly.

#### 1.4 AES-CBC
1. Test: AES-128-CBC encrypt with known key/iv/plaintext matches Python
2. Test: AES-256-CBC encrypt matches
3. Test: decrypt round-trips
4. Test: ciphertext is PKCS7-padded before encryption

*Wiring `aes` + `cbc` crates with PKCS7 from 1.1.*

#### 1.5 Token (Modified Fernet)
1. Test: `Token::new(32-byte key)` selects AES-128, splits key correctly
2. Test: `Token::new(64-byte key)` selects AES-256, splits key correctly
3. Test: `Token::new(48-byte key)` is rejected
4. Test: `encrypt(plaintext)` with **fixed IV** (for deterministic testing) produces byte-identical output to Python
5. Test: `decrypt(python_ciphertext)` recovers original plaintext
6. Test: `decrypt` rejects tampered HMAC
7. Test: `decrypt` rejects truncated token
8. Test: round-trip with random IV (encrypt then decrypt)
9. Test: TOKEN_OVERHEAD == 48

#### 1.6 SHA-256 / SHA-512 Wrappers
1. Test: `sha256(b"test")` matches known digest
2. Test: `sha512(b"test")` matches known digest

#### 1.7 X25519 Key Exchange
1. Test: `X25519PrivateKey::from_private_bytes(known_bytes)` produces expected public key
2. Test: `exchange()` with known keypairs produces same shared secret as Python
3. Test: `generate()` produces valid 32-byte keys

#### 1.8 Ed25519 Signing
1. Test: `sign(message)` with known private key produces same signature as Python
2. Test: `verify(signature, message)` accepts valid Python-generated signature
3. Test: `verify` rejects tampered signature
4. Test: `from_private_bytes` / `from_public_bytes` round-trip

#### 1.9 Full Crypto Integration
1. Test: Python `Identity.encrypt(plaintext)` → Rust decrypts correctly (requires ephemeral key extraction + ECDH + HKDF + Token — this is the final integration proof)

### Python Reference Files
- `RNS/Cryptography/Token.py` — Token format
- `RNS/Cryptography/HKDF.py` — Custom KDF
- `RNS/Cryptography/PKCS7.py` — Padding
- `RNS/Cryptography/HMAC.py` — HMAC
- `RNS/Cryptography/X25519.py` — Key exchange
- `RNS/Cryptography/Ed25519.py` — Signatures

---

## Phase 2: Core Protocol Types (`rns-core`)

**Milestone**: Rust can pack/unpack every packet type, compute destination hashes, and validate announces — all producing byte-identical results to Python.

### TDD Sequence

#### 2.1 Constants
1. Test: MTU == 500, TRUNCATED_HASHLENGTH == 128, HEADER_MINSIZE == 19, HEADER_MAXSIZE == 35
2. Test: all packet type values (DATA=0, ANNOUNCE=1, LINKREQUEST=2, PROOF=3)
3. Test: all context values match Python

*These are trivial but establish the constants module and catch typos.*

#### 2.2 Hashing Utilities
1. Test: `full_hash(data)` == SHA-256(data)
2. Test: `truncated_hash(data)` == first 16 bytes of SHA-256(data)
3. Test: `get_random_hash()` returns 16 bytes

#### 2.3 Packet — Flag Encoding
1. Test: `get_packed_flags()` for HEADER_1 + DATA + SINGLE → expected byte
2. Test: flags for HEADER_2 + ANNOUNCE + SINGLE
3. Test: flags for all destination types (SINGLE/GROUP/PLAIN/LINK)
4. Test: context_flag SET vs UNSET
5. Test: round-trip — pack flags then extract via bitmask

#### 2.4 Packet — Pack
1. Test: pack a HEADER_1 DATA packet → raw bytes match Python output
2. Test: pack a HEADER_2 ANNOUNCE (with transport_id) → matches Python
3. Test: pack with LINKREQUEST context (not encrypted) → matches
4. Test: pack raises error when raw > MTU
5. Test: context byte is at correct offset (position 18 for H1, 34 for H2)

#### 2.5 Packet — Unpack
1. Test: unpack known Python-packed HEADER_1 DATA → correct fields
2. Test: unpack HEADER_2 → transport_id and destination_hash extracted correctly
3. Test: unpack malformed data → returns error (not panic)
4. Test: packet hash after unpack matches Python's hash for same raw bytes

#### 2.6 Packet — Hashing
1. Test: `get_hashable_part()` returns correct byte range
2. Test: `update_hash()` produces same hash as Python for same raw packet
3. Test: truncated hash is first 16 bytes of full hash

#### 2.7 Destination — Hash Computation
1. Test: `Destination::hash(identity, "app", "aspect")` matches Python for same identity
2. Test: `expand_name(identity, "app", "aspect")` → "app.aspect.{hexhash}"
3. Test: `name_hash` is first 10 bytes of SHA-256(full_name)
4. Test: SINGLE, GROUP, PLAIN types produce correct hashes

#### 2.8 Destination — Announce Packing
1. Test: announce data layout — `pubkey(64) | name_hash(10) | random(10) | sig(64) | [app_data]`
2. Test: with ratchet (context_flag=SET) — ratchet(32) inserted before signature
3. Test: announce from Python unpacks correctly in Rust
4. Test: announce packed in Rust validates in Python

#### 2.9 Identity — Core Operations
1. Test: `Identity::from_bytes(prv_bytes)` recovers same pub key as Python
2. Test: `get_public_key()` returns 64 bytes (32 X25519 + 32 Ed25519)
3. Test: `get_private_key()` returns 64 bytes
4. Test: `encrypt(plaintext)` → Python can decrypt
5. Test: Python `encrypt(plaintext)` → Rust can decrypt
6. Test: `sign(message)` matches Python signature for same key
7. Test: `validate(signature, message)` accepts Python-signed message

#### 2.10 Identity — Announce Validation
1. Test: `validate_announce(valid_python_announce)` → true, extracts identity
2. Test: `validate_announce(tampered_announce)` → false
3. Test: `validate_announce(announce_with_ratchet)` → true, ratchet extracted

#### 2.11 PacketReceipt
1. Test: receipt created with SENT status
2. Test: `validate_proof(valid_proof)` → status becomes DELIVERED
3. Test: `is_timed_out()` after timeout period → true

### Python Reference Files
- `RNS/Packet.py:168-271` — Wire format
- `RNS/Destination.py` — Hash computation, announce packing
- `RNS/Identity.py` — Key operations, announce validation

---

## Phase 3: Transport & Routing (`rns-core`)

**Milestone**: Rust Transport can process inbound/outbound packets, maintain routing tables, and make identical routing decisions to Python for the same packet sequences.

### TDD Sequence

#### 3.1 Path Table
1. Test: `register_path(dest_hash, next_hop, hops, expires, interface_id)` → entry exists
2. Test: `has_path(dest_hash)` → true after register, false before
3. Test: `hops_to(dest_hash)` → correct hop count
4. Test: `next_hop(dest_hash)` → correct next hop hash
5. Test: expired path → `has_path` returns false after cull
6. Test: path update with fewer hops replaces existing entry

#### 3.2 Announce Table
1. Test: announce stored with retransmit state
2. Test: announce retransmit timeout fires correctly
3. Test: duplicate announce (same random blobs) is dropped
4. Test: announce with more hops doesn't replace fewer-hops path

#### 3.3 Packet Deduplication
1. Test: first seen packet hash → not duplicate
2. Test: same hash again → duplicate
3. Test: after cull cycle, old hashes are removed
4. Test: hashlist doesn't grow unbounded

#### 3.4 Reverse Table
1. Test: outbound packet creates reverse entry
2. Test: proof routes back via reverse entry
3. Test: reverse entry expires after REVERSE_TIMEOUT (480s)

#### 3.5 Link Table
1. Test: link registration creates entry
2. Test: link packet routed to correct interface via link table
3. Test: link removal cleans entry

#### 3.6 Outbound Processing
1. Test: outbound DATA to known destination → correct interface selected
2. Test: outbound DATA to unknown destination → path request triggered
3. Test: outbound ANNOUNCE → rewritten as HEADER_2 when transport
4. Test: hop count incremented on forward

#### 3.7 Inbound Processing
1. Test: inbound packet for local destination → delivered
2. Test: inbound packet for remote destination (transport mode) → forwarded
3. Test: inbound duplicate packet → dropped
4. Test: inbound announce → path table updated
5. Test: inbound proof → routed via reverse table

#### 3.8 PATHFINDER Rate Limiting
1. Test: announce rebroadcast respects 2% bandwidth cap
2. Test: rate limiting per destination (20s minimum interval)
3. Test: max hops (128) → packet dropped

#### 3.9 Job Tick
1. Test: `tick()` culls expired paths
2. Test: `tick()` retransmits pending announces
3. Test: `tick()` checks link timeouts
4. Test: `tick()` cleans packet hashlist

*Note: Transport tests use mock interfaces (trait objects) and a controllable clock.*

### Python Reference Files
- `RNS/Transport.py` — Full routing engine

---

## Phase 4: Links & Higher Protocols (`rns-core`)

**Milestone**: Rust can establish an encrypted link with a Python node, exchange channel messages, and transfer resources.

### TDD Sequence

#### 4.1 Link — State Machine
1. Test: new Link starts in PENDING
2. Test: valid state transitions (PENDING→HANDSHAKE→ACTIVE→STALE→CLOSED)
3. Test: invalid transitions are rejected
4. Test: CLOSED is terminal

#### 4.2 Link — Handshake (Initiator)
1. Test: `create_request()` produces LINKREQUEST with ephemeral pub(32) + ed25519 pub(32) + signalling(3)
2. Test: `validate_proof(python_lrproof)` → transitions to ACTIVE, derives correct session key
3. Test: session key matches what Python derived for same handshake
4. Test: `validate_proof(bad_signature)` → link closed

#### 4.3 Link — Handshake (Responder)
1. Test: `validate_request(linkrequest_data)` → creates link in HANDSHAKE
2. Test: `prove()` → produces LRPROOF with signature + pub key
3. Test: LRPROOF verifiable by Python initiator

#### 4.4 Link — Session Encryption
1. Test: `encrypt(plaintext)` with known session key → Python can decrypt
2. Test: Python `encrypt(plaintext)` → Rust `decrypt` recovers original
3. Test: token mode selection (AES-128 vs AES-256) based on derived key length

#### 4.5 Link — Keepalive & Timeout
1. Test: no activity for keepalive interval → keepalive sent
2. Test: no activity for stale_time → status becomes STALE
3. Test: stale + grace period elapsed → CLOSED
4. Test: activity resets timers

#### 4.6 Link — Identify
1. Test: `identify(identity)` sends identity proof over link
2. Test: receiving identity proof → `remote_identity` populated

#### 4.7 Channel — Envelope Framing
1. Test: pack envelope → `msgtype(2) | sequence(2) | length(2) | payload`
2. Test: unpack envelope → correct fields
3. Test: sequence wraps at 0xFFFF → 0x0000

#### 4.8 Channel — Send/Receive
1. Test: send message → envelope created with next sequence
2. Test: receive in-order message → delivered to handler
3. Test: receive out-of-order → buffered until gap filled
4. Test: message type registry → correct factory called

#### 4.9 Channel — Flow Control
1. Test: window starts at 2
2. Test: successful delivery → window grows (up to max)
3. Test: timeout → window shrinks (down to min)
4. Test: window_max adapts to RTT (fast/medium/slow thresholds)

#### 4.10 Channel — Retry
1. Test: unacknowledged envelope retransmitted after timeout
2. Test: max retries (5) exceeded → message FAILED
3. Test: timeout formula: `1.5^(tries-1) * max(rtt*2.5, 0.025) * (ring_len+1.5)`

#### 4.11 Buffer — Stream I/O
1. Test: stream header encodes `stream_id(14) | compressed(1) | eof(1)` correctly
2. Test: writer chunks data to fit channel MDU
3. Test: reader accumulates chunks, returns complete data
4. Test: EOF flag terminates stream
5. Test: compression applied when beneficial (payload > 32 bytes, compressed < original)

#### 4.12 Resource — Advertisement
1. Test: pack advertisement msgpack matches Python format
2. Test: unpack Python-generated advertisement → correct fields
3. Test: hashmap contains correct 4-byte part hashes

#### 4.13 Resource — Transfer State Machine
1. Test: NONE → QUEUED → ADVERTISED on advertise()
2. Test: receiver accepts → TRANSFERRING
3. Test: all parts received → ASSEMBLING → COMPLETE
4. Test: hash mismatch → CORRUPT
5. Test: timeout → FAILED

#### 4.14 Resource — Selective Retransmission
1. Test: receiver requests missing parts by hash
2. Test: sender retransmits only requested parts
3. Test: hashmap exhaustion triggers new hashmap from sender

#### 4.15 Resource — Window Adaptation
1. Test: window starts at 4
2. Test: fast rate → window grows to WINDOW_MAX_FAST (75)
3. Test: slow rate → window shrinks to WINDOW_MAX_SLOW (10)

### Python Reference Files
- `RNS/Link.py` — Handshake, encryption, keepalive
- `RNS/Channel.py` — Messaging, flow control
- `RNS/Buffer.py` — Stream I/O
- `RNS/Resource.py` — Transfer protocol

---

## Phase 5: Networking & Interfaces (`rns-net`)

**Milestone**: A Rust `rnsd` daemon can join an existing Python Reticulum network, discover paths, and route packets.

### TDD Sequence

#### 5.1 Config Parsing
1. Test: parse minimal config → correct defaults
2. Test: parse `[reticulum]` section → enable_transport, share_instance, etc.
3. Test: parse `[logging]` section → loglevel
4. Test: parse `[[Interface_Name]]` → interface type + params extracted
5. Test: parse Python's example config (from rnsd --exampleconfig) without error
6. Test: missing config file → defaults created

#### 5.2 Interface Trait & Mock
1. Test: mock interface implements trait
2. Test: mock interface receives outbound data
3. Test: mock interface pushes inbound data to Transport

#### 5.3 LocalInterface
1. Test: server binds to Unix socket (or TCP fallback)
2. Test: client connects to server
3. Test: data sent from client arrives at server (and vice versa)
4. Test: HDLC framing round-trip
5. Test: Rust LocalClient connects to Python LocalServer (interop)

#### 5.4 TCPInterface
1. Test: TCP server accepts connection
2. Test: TCP client connects, sends data, receives response
3. Test: reconnection after disconnect
4. Test: Rust TCP client connects to Python TCP server (interop)

#### 5.5 UDPInterface
1. Test: UDP broadcast send/receive on loopback
2. Test: packet framing round-trip
3. Test: Rust UDP ↔ Python UDP on same broadcast domain (interop)

#### 5.6 SerialInterface
1. Test: write/read over virtual serial port pair
2. Test: framing (HDLC) round-trip

#### 5.7 KISSInterface
1. Test: KISS frame encoding/decoding
2. Test: preamble, txtail, persistence parameters applied

#### 5.8 RNodeInterface
1. Test: RNode serial protocol command/response framing
2. Test: frequency/bandwidth/SF/CR configuration
3. Test: data send/receive via RNode (requires hardware or mock)

#### 5.9 Master Instance (Reticulum)
1. Test: init with config → interfaces started, Transport running
2. Test: shared instance mode → LocalServer listening
3. Test: client mode → connects to existing shared instance
4. Test: graceful shutdown cleans up interfaces and Transport

#### 5.10 Storage & Persistence
1. Test: save/load known_destinations round-trip
2. Test: save/load ratchets round-trip
3. Test: cache write/read/clean
4. Test: file format compatible with Python (msgpack)

#### 5.11 Full Network Interop
1. Test: Rust rnsd + Python rnsd on Docker network → path discovery works
2. Test: Python node announces → Rust node discovers path
3. Test: Rust node sends packet → Python node receives
4. Test: Link establishment: Python initiator → Rust responder
5. Test: Link establishment: Rust initiator → Python responder
6. Test: Resource transfer across implementations

### Python Reference Files
- `RNS/Reticulum.py` — Config, lifecycle, shared instance
- `RNS/Interfaces/Interface.py` — Base class
- `RNS/Interfaces/TCPInterface.py`, `UDPInterface.py`, `LocalInterface.py`

---

## Phase 6: CLI Tools (`rns-cli`)

**Milestone**: `rnsd-rs`, `rnstatus-rs`, `rnpath-rs`, `rnprobe-rs` are drop-in replacements that produce equivalent output and behavior.

### TDD Sequence

#### 6.1 rnsd
1. Test: `--version` prints version
2. Test: `--exampleconfig` prints valid config
3. Test: starts daemon, binds shared instance socket
4. Test: `-s` (service mode) logs to file
5. Test: SIGTERM → clean shutdown

#### 6.2 rnstatus
1. Test: connects to shared instance, retrieves interface stats
2. Test: output format matches Python rnstatus for same network state

#### 6.3 rnpath
1. Test: `rnpath <dest_hash>` shows path info
2. Test: `rnpath -d <dest_hash>` drops path

#### 6.4 rnprobe
1. Test: sends probe to reachable destination → success
2. Test: probe to unreachable destination → timeout

---

## Milestone Summary

| Phase | Crate | Milestone Gate | Interop Proof |
|-------|-------|---------------|---------------|
| **1** | `rns-crypto` | All crypto ops produce byte-identical output to Python | `Python Token.encrypt() → Rust decrypt()` ✓ |
| **2** | `rns-core` | Packet pack/unpack, Identity, Destination wire-compatible | `Python pack() → Rust unpack()` ✓ |
| **3** | `rns-core` | Transport routes packets identically to Python | Routing decision parity for same packet sequences |
| **4** | `rns-core` | Link handshake, Channel, Resource protocols complete | `Python Link ↔ Rust Link` handshake succeeds |
| **5** | `rns-net` | Daemon joins Python network, routes real traffic | Docker: mixed Rust+Python network operates |
| **6** | `rns-cli` | CLI tools produce equivalent output | `rnsd-rs` replaces `rnsd` on live network |

Each phase is self-contained: it has its own detailed plan (to be written before starting), its own test fixtures, and a clear gate before moving to the next phase. No phase starts until the previous milestone gate passes.

---

## Test Infrastructure

### `tests/generate_vectors.py`

A Python script that imports RNS and generates all test fixtures:

```
# Phase 1 vectors
- pkcs7_vectors.bin        # Known pad/unpad pairs
- hmac_vectors.bin         # Known HMAC outputs
- hkdf_vectors.bin         # Custom HKDF outputs
- token_vectors.bin        # Token encrypt with fixed IV
- x25519_vectors.bin       # Known key exchanges
- ed25519_vectors.bin      # Known signatures
- identity_encrypt.bin     # Full Identity.encrypt() pipeline

# Phase 2 vectors
- packet_header1.bin       # Packed HEADER_1 packets
- packet_header2.bin       # Packed HEADER_2 packets
- destination_hashes.bin   # Hash computations
- announce_packets.bin     # Full announce payloads
- announce_with_ratchet.bin

# Phase 4 vectors
- link_request.bin         # LINKREQUEST payload
- link_proof.bin           # LRPROOF payload
- channel_envelope.bin     # Channel message framing
- resource_advertisement.bin
```

Each fixture file contains: `[input_params | expected_output]` as msgpack or length-prefixed binary, loadable from both Python and Rust.

### Fixture format (simple length-prefixed binary)

```
[u32 num_vectors]
For each vector:
  [u32 input_len] [input_bytes...]
  [u32 output_len] [output_bytes...]
```

---

## Key Crate Dependencies

### rns-crypto (no_std)
- `x25519-dalek`, `ed25519-dalek` — Key exchange, signatures
- `aes`, `cbc` — AES-CBC encryption
- `sha2` — SHA-256/512
- `hmac` — HMAC-SHA256
- `rand_core` — RNG trait
- `zeroize` — Secure memory clearing

### rns-core (no_std, uses alloc)
- `rns-crypto`
- `heapless` — Fixed-capacity collections for constrained targets
- `hashbrown` — no_std HashMap (behind feature flag)

### rns-net (std)
- `rns-core`, `rns-crypto`
- `tokio` — Async runtime
- `serde`, `rmp-serde` — Serialization (msgpack compat with Python)
- `configparser` — INI config parsing
- `socket2` — Low-level sockets
- `log`, `env_logger` — Logging
- `thiserror` — Error types

### rns-cli (std)
- `rns-net`
- `clap` — Argument parsing

---

## no_std Strategy

**`rns-crypto` + `rns-core`** are `#![no_std]` with `extern crate alloc`.

For embedded targets, the user provides a `Platform` trait:
```rust
trait Platform {
    fn now_ms(&self) -> u64;
    fn random_bytes(&self, buf: &mut [u8]);
}
```

Core protocol is driven by caller via `tick()` / `handle_event()` — no threads, no async runtime, no OS required. The `rns-net` crate provides the `std` Platform impl and the tokio-based runtime.

---

## Critical Python Reference Files

| File | What to Extract |
|------|----------------|
| `RNS/Cryptography/Token.py:40-114` | Token format, key split logic |
| `RNS/Cryptography/HKDF.py` | Custom KDF (NOT RFC 5869) |
| `RNS/Packet.py:168-271` | Wire format, flag encoding, pack/unpack |
| `RNS/Identity.py:391-493` | Announce validation pipeline |
| `RNS/Identity.py:668-698` | Encryption: ephemeral ECDH → HKDF → Token |
| `RNS/Link.py:186-457` | 4-way handshake, key derivation |
| `RNS/Transport.py:939-1600` | Inbound/outbound packet processing |
| `RNS/Destination.py` | Hash computation, announce packing |
| `RNS/Channel.py` | Envelope framing, flow control |
| `RNS/Resource.py` | Transfer protocol, hashmap, windowing |
