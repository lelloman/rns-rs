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
├── Cargo.toml                       # Workspace root (members: rns-crypto, rns-core)
├── rns-crypto/                      # no_std — cryptographic primitives [DONE]
│   ├── src/
│   │   ├── lib.rs                   # Rng trait, FixedRng, OsRng
│   │   ├── bigint.rs, pkcs7.rs, sha256.rs, sha512.rs
│   │   ├── hmac.rs, hkdf.rs, aes.rs, aes128.rs, aes256.rs
│   │   └── token.rs, x25519.rs, ed25519.rs, identity.rs
│   └── tests/interop.rs            # 11 interop tests
├── rns-core/                        # no_std — protocol logic [DONE]
│   ├── src/
│   │   ├── lib.rs
│   │   ├── constants.rs, hash.rs, packet.rs
│   │   ├── destination.rs, announce.rs, receipt.rs
│   │   ├── transport/              # Phase 3: Routing engine
│   │   │   ├── mod.rs, types.rs, tables.rs, dedup.rs
│   │   │   ├── pathfinder.rs, announce_proc.rs
│   │   │   ├── inbound.rs, outbound.rs, rate_limit.rs, jobs.rs
│   │   ├── link/                   # Phase 4a: Link engine
│   │   │   ├── mod.rs              # LinkEngine struct, state machine
│   │   │   ├── types.rs            # LinkId, LinkState, LinkMode, LinkAction, LinkError
│   │   │   ├── handshake.rs        # LINKREQUEST/LRPROOF/LRRTT building & validation
│   │   │   ├── crypto.rs           # Session key derivation, encrypt/decrypt via Token
│   │   │   ├── keepalive.rs        # Keepalive timing, stale detection
│   │   │   └── identify.rs         # LINKIDENTIFY build/validate
│   │   ├── channel/                # Phase 4a: Channel messaging
│   │   │   ├── mod.rs              # Channel struct, send/receive/tick, window mgmt
│   │   │   ├── types.rs            # ChannelAction, ChannelError
│   │   │   └── envelope.rs         # 6-byte header pack/unpack
│   │   └── buffer/                 # Phase 4a: Buffer streaming
│   │       ├── mod.rs              # StreamDataMessage, BufferWriter, BufferReader
│   │       └── types.rs            # StreamId, Compressor trait, BufferError
│   └── tests/
│       ├── interop.rs              # 7 interop tests (incl. milestone)
│       ├── transport_integration.rs # 15 integration tests for transport engine
│       └── link_integration.rs     # 9 integration tests for link/channel/buffer
├── rns-net/                         # std — networking, config, I/O [PLANNED]
├── rns-cli/                         # std — CLI binaries [PLANNED]
└── tests/
    ├── generate_vectors.py          # Generates JSON fixtures from Python RNS
    └── fixtures/
        ├── crypto/                  # 11 JSON fixture files (Phase 1)
        ├── protocol/               # 6 JSON fixture files (Phase 2)
        ├── transport/              # 4 JSON fixture files (Phase 3)
        └── link/                   # 5 JSON fixture files (Phase 4a)
```

### Crate Graph

```
rns-cli → rns-net → rns-core → rns-crypto
                     (no_std)    (no_std)
```

---

## Phase 1: Cryptographic Primitives (`rns-crypto`) — COMPLETE ✓

**Milestone**: Rust can encrypt/decrypt/sign/verify identically to Python. A ciphertext produced by Python's `Token.encrypt()` can be decrypted by Rust, and vice versa.

**Result**: 65 unit tests + 11 interop tests = 76 tests passing. Zero external dependencies, pure Rust, `no_std` compatible. All crypto ops produce byte-identical output to Python PROVIDER_INTERNAL.

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

## Phase 2: Core Protocol Types (`rns-core`) — COMPLETE ✓

**Milestone**: Rust can pack/unpack every packet type, compute destination hashes, and validate announces — all producing byte-identical results to Python.

**Result**: 39 unit tests + 7 interop tests = 46 tests passing. Modules: constants, hash, packet (flags + pack/unpack + hashable part), destination (expand_name + hash), announce (pack/unpack/validate with signature + dest hash verification), receipt (explicit/implicit proof validation). Milestone test confirms: Python-generated announce → Rust unpack → signature valid → destination hash verified → identity extracted, all byte-identical to Python.

**Intentional scope limits**: This crate handles wire-format operations only. Higher-level concerns left for future phases: encryption/decryption during pack (handled by caller), LRPROOF destination type special-case in flag packing, PacketReceipt state management, Link/Channel/Resource protocols.

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

## Phase 3: Transport & Routing (`rns-core`) — COMPLETE ✓

**Milestone**: Rust Transport can process inbound/outbound packets, maintain routing tables, and make identical routing decisions to Python for the same packet sequences.

**Result**: 121 unit tests + 7 interop tests + 15 integration tests = 143 tests passing (219 total across workspace). Action queue model: `handle_inbound()`/`handle_outbound()`/`tick()` return `Vec<TransportAction>` — no callbacks, no I/O. All tables use `BTreeMap` for `no_std` compatibility. `InterfaceId(u64)` instead of trait objects. Explicit `now: f64` and `rng` parameters for deterministic testing.

**Bugs found and fixed during review:**
1. `outbound.rs` broadcast exclude logic was dead code (always `None`) — fixed to match Python Transport.py:1037-1038
2. `jobs.rs` local rebroadcast limit checked wrong field (`local_rebroadcasts` instead of `retries`) — fixed to match Python Transport.py:523

**Out of scope (deferred):** Tunnels, shared-instance/local-client handling, IFAC masking, packet caching to disk, per-interface announce bandwidth queuing, management destinations, blackhole support, Discovery.

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

## Phase 4a: Link, Channel & Buffer (`rns-core`) — COMPLETE ✓

**Milestone**: Two Rust `LinkEngine` instances complete a full 4-way handshake, derive identical session keys, exchange encrypted Channel messages, and stream data via Buffer — all producing byte-identical wire output to Python for the same inputs.

**Result**: 105 unit tests + 9 integration tests = 114 new tests (248 total rns-core, 324 total workspace). Action queue model matching transport: `LinkEngine`, `Channel`, and `BufferWriter` return `Vec<Action>`. No callbacks, no I/O. Composition via actions, not references. All wire formats validated against Python-generated test vectors.

**Modules added**:
- `link/` — LinkEngine state machine (Pending→Handshake→Active→Stale→Closed), 4-way handshake (LINKREQUEST/LRPROOF/LRRTT), session crypto (AES-128/AES-256 via Token), keepalive/stale timing, LINKIDENTIFY
- `channel/` — Window-based flow control with RTT adaptation (fast/medium/slow), envelope framing, retry with exponential backoff, sequence wrapping at 0xFFFF
- `buffer/` — StreamDataMessage with 14-bit stream_id + EOF/compressed flags, BufferWriter chunking, BufferReader reassembly, Compressor trait for `no_std`

**Key design decisions**:
1. Minimal msgpack: only float64 encoding (0xcb + 8 BE bytes) for LRRTT — no full msgpack dependency
2. Explicit time (`now: f64`) and RNG (`&mut dyn Rng`) for deterministic testing
3. `Compressor` trait with `NoopCompressor` default for `no_std`; `std` users can provide bz2

### Python Reference Files
- `RNS/Link.py` — Handshake, encryption, keepalive
- `RNS/Channel.py` — Messaging, flow control
- `RNS/Buffer.py` — Stream I/O

---

## Phase 4b: Resource Transfer (`rns-core`)

**Milestone**: Rust can advertise, segment, transfer, and reassemble Resources with windowed flow control, producing byte-identical wire output to Python.

### TDD Sequence

#### 4b.1 Resource — Advertisement
1. Test: pack advertisement msgpack matches Python format
2. Test: unpack Python-generated advertisement → correct fields
3. Test: hashmap contains correct 4-byte part hashes

#### 4b.2 Resource — Transfer State Machine
1. Test: NONE → QUEUED → ADVERTISED on advertise()
2. Test: receiver accepts → TRANSFERRING
3. Test: all parts received → ASSEMBLING → COMPLETE
4. Test: hash mismatch → CORRUPT
5. Test: timeout → FAILED

#### 4b.3 Resource — Selective Retransmission
1. Test: receiver requests missing parts by hash
2. Test: sender retransmits only requested parts
3. Test: hashmap exhaustion triggers new hashmap from sender

#### 4b.4 Resource — Window Adaptation
1. Test: window starts at 4
2. Test: fast rate → window grows to WINDOW_MAX_FAST (75)
3. Test: slow rate → window shrinks to WINDOW_MAX_SLOW (10)

### Python Reference Files
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

| Phase | Crate | Milestone Gate | Status |
|-------|-------|---------------|--------|
| **1** | `rns-crypto` | All crypto ops produce byte-identical output to Python | **DONE** — 76 tests, `Python Token.encrypt() → Rust decrypt()` ✓ |
| **2** | `rns-core` | Packet pack/unpack, Destination, Announce wire-compatible | **DONE** — 46 tests, `Python announce → Rust validate()` ✓ |
| **3** | `rns-core` | Transport routes packets identically to Python | **DONE** — 143 tests, `Python announce → Rust route + retransmit` ✓ |
| **4a** | `rns-core` | Link handshake, Channel messaging, Buffer streaming | **DONE** — 248 tests, full 4-way handshake + encrypted channel + buffer streaming ✓ |
| **4b** | `rns-core` | Resource segmented transfer with windowed flow control | Planned |
| **5** | `rns-net` | Daemon joins Python network, routes real traffic | Planned |
| **6** | `rns-cli` | CLI tools produce equivalent output | Planned |

Each phase is self-contained: it has its own detailed plan (to be written before starting), its own test fixtures, and a clear gate before moving to the next phase. No phase starts until the previous milestone gate passes.

---

## Test Infrastructure

### `tests/generate_vectors.py`

A Python script that imports RNS (with PROVIDER_INTERNAL forced) and generates JSON test fixtures with hex-encoded byte fields.

```
# Phase 1 vectors (tests/fixtures/crypto/)
- pkcs7_vectors.json       # 5 Known pad/unpad pairs
- sha256_vectors.json      # 7 SHA-256 digests
- sha512_vectors.json      # 6 SHA-512 digests
- hmac_vectors.json        # 6 HMAC-SHA256 outputs
- hkdf_vectors.json        # 7 Custom HKDF outputs
- aes128_vectors.json      # 3 AES-128-CBC test cases
- aes256_vectors.json      # 3 AES-256-CBC test cases
- token_vectors.json       # 4 Token encrypt with fixed IV
- x25519_vectors.json      # 5 Key exchange vectors
- ed25519_vectors.json     # 3 Signature vectors
- identity_vectors.json    # 1 Full encrypt/decrypt/sign/verify milestone

# Phase 2 vectors (tests/fixtures/protocol/)
- hash_vectors.json        # 10 full_hash, truncated_hash, name_hash
- flags_vectors.json       # 9 Packed/unpacked flag bytes
- packet_vectors.json      # 5 HEADER_1/HEADER_2 pack/unpack with hashes
- destination_vectors.json # 5 expand_name, name_hash, destination_hash
- announce_vectors.json    # 4 Announce pack/unpack/validate (±ratchet, ±app_data)
- proof_vectors.json       # 5 Explicit/implicit proof validation

# Phase 3 vectors (tests/fixtures/transport/)
- pathfinder_vectors.json          # Timebase extraction, path update decisions
- announce_retransmit_vectors.json # Retransmitted announce raw bytes
- transport_routing_vectors.json   # HEADER_2 rewrite scenarios
- full_pipeline_vectors.json       # End-to-end announce → route → retransmit

# Phase 4a vectors (tests/fixtures/link/)
- link_handshake_vectors.json     # 2 Full handshake (AES-128 + AES-256)
- link_crypto_vectors.json        # 5 Session encryption with fixed IVs
- link_identify_vectors.json      # 2 LINKIDENTIFY plaintext/encrypted
- channel_envelope_vectors.json   # 8 Envelope pack/unpack
- stream_data_vectors.json        # 9 StreamDataMessage pack/unpack

# Future phases (not yet generated)
- resource_advertisement, resource_transfer
```

### Fixture format

JSON arrays of objects with hex-encoded byte fields:
```json
[
  {
    "description": "test_case_name",
    "input": "deadbeef",
    "expected": "cafebabe"
  }
]
```

Loaded in Rust via `serde_json` (dev-dependency only).

---

## Crate Dependencies

### rns-crypto (no_std) — ZERO external dependencies
All crypto is implemented in pure Rust with no third-party crates:
- BigUint arithmetic, SHA-256/512, HMAC, HKDF, PKCS7
- AES-128/256-CBC, Token (modified Fernet)
- X25519 (Curve25519 ECDH), Ed25519 (signatures)
- `Rng` trait for caller-provided randomness; `OsRng` via getrandom(2) syscall
- Dev-only: `serde_json` for test fixture loading

### rns-core (no_std, uses alloc)
- `rns-crypto` (path dependency, only runtime dep)
- Wire protocol types (packet, destination, announce, receipt) + transport routing engine
- Dev-only: `serde_json` for test fixture loading

### rns-net (std) — PLANNED
- `rns-core`, `rns-crypto`
- External deps TBD (tokio, serde, socket2, etc.)

### rns-cli (std) — PLANNED
- `rns-net`
- External deps TBD (clap, etc.)

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
