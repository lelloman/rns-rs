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
├── Cargo.toml                       # Workspace root (members: rns-crypto, rns-core, rns-net, rns-cli, rns-ctl)
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
│   │   ├── types.rs                 # Phase 9a: Typed wrappers (DestHash, IdentityHash, LinkId, PacketHash) + enums
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
│   │   ├── buffer/                 # Phase 4a: Buffer streaming
│   │   │   ├── mod.rs              # StreamDataMessage, BufferWriter, BufferReader
│   │   │   └── types.rs            # StreamId, Compressor trait, BufferError
│   │   ├── msgpack.rs              # Phase 4b: Minimal msgpack encode/decode
│   │   └── resource/               # Phase 4b: Resource transfer
│   │       ├── mod.rs              # Re-exports, top-level docs
│   │       ├── types.rs            # ResourceState, ResourceAction, ResourceError
│   │       ├── advertisement.rs    # ResourceAdvertisement pack/unpack (msgpack)
│   │       ├── parts.rs            # Part hashing, hashmap, collision guard
│   │       ├── window.rs           # Window adaptation, rate tracking
│   │       ├── sender.rs           # ResourceSender state machine
│   │       ├── receiver.rs         # ResourceReceiver state machine
│   │       └── proof.rs            # Resource proof generation/validation
│   └── tests/
│       ├── interop.rs              # 12 interop tests (incl. milestone + resource)
│       ├── transport_integration.rs # 15 integration tests for transport engine
│       ├── link_integration.rs     # 9 integration tests for link/channel/buffer
│       └── resource_integration.rs # Integration tests for resource transfer
├── rns-net/                         # std — networking, I/O [Phase 9 DONE]
│   ├── src/
│   │   ├── lib.rs                   # Public API, re-exports
│   │   ├── destination.rs           # Phase 9b: Destination + AnnouncedIdentity structs
│   │   ├── hdlc.rs                  # HDLC escape/unescape/frame + streaming Decoder
│   │   ├── kiss.rs                  # KISS framing (FEND/FESC) + streaming Decoder
│   │   ├── rnode_kiss.rs            # RNode KISS commands + streaming RNodeDecoder
│   │   ├── event.rs                 # Event enum + QueryRequest/QueryResponse
│   │   ├── time.rs                  # now() → f64 Unix epoch
│   │   ├── config.rs                # ConfigObj parser for Python RNS config files
│   │   ├── storage.rs               # Identity + known destinations persistence
│   │   ├── ifac.rs                  # IFAC derive/mask/unmask (Interface Access Codes)
│   │   ├── serial.rs                # Raw serial I/O via libc termios
│   │   ├── pickle.rs               # Minimal pickle codec (proto 2 encode, 2–5 decode)
│   │   ├── md5.rs                   # MD5 + HMAC-MD5 for Python multiprocessing auth
│   │   ├── rpc.rs                   # Python multiprocessing.connection wire protocol
│   │   ├── announce_cache.rs        # Announce packet caching to disk (Phase 7c)
│   │   ├── link_manager.rs          # Link lifecycle, request/response, resources, ACL (Phase 7e+8a)
│   │   ├── management.rs            # Remote management destinations /status /path /list (Phase 7f+8c)
│   │   ├── shared_client.rs         # Shared instance client mode (Phase 8e)
│   │   ├── driver.rs                # Callbacks, Driver loop, InterfaceStats, query dispatch
│   │   ├── node.rs                  # RnsNode lifecycle + share_instance/RPC config
│   │   └── interface/
│   │       ├── mod.rs               # Writer trait, InterfaceEntry
│   │       ├── tcp.rs               # TCP client: connect, reconnect, reader thread
│   │       ├── tcp_server.rs        # TCP server: accept, per-client reader threads
│   │       ├── udp.rs               # UDP broadcast: no HDLC framing
│   │       ├── local.rs             # Unix abstract socket + TCP fallback
│   │       ├── serial_iface.rs      # Serial + HDLC framing, reconnect
│   │       ├── kiss_iface.rs        # KISS + flow control, TNC config
│   │       ├── pipe.rs              # Subprocess stdin/stdout + HDLC, auto-respawn
│   │       ├── rnode.rs             # RNode LoRa radio, multi-sub, flow control
│   │       ├── backbone.rs          # TCP mesh backbone, Linux epoll
│   │       ├── auto.rs              # AutoInterface: IPv6 multicast LAN discovery (Phase 8d)
│   │       └── i2p/                 # I2P interface using SAM v3.1 protocol
│   │           ├── mod.rs           # I2P coordinator, outbound/inbound peer handling
│   │           └── sam.rs           # SAM v3.1 wire protocol (DEST GENERATE, SESSION CREATE, etc.)
│   ├── examples/
│   │   ├── tcp_connect.rs           # Connect to Python RNS, log announces
│   │   ├── rnsd.rs                  # Rust rnsd daemon (config-driven)
│   │   └── echo.rs                  # Phase 9f: Echo server/client via TCP loopback
│   └── tests/
│       ├── python_interop.rs        # Rust↔Python announce reception
│       └── ifac_interop.rs          # IFAC mask/unmask vs Python vectors
├── rns-cli/                         # std — CLI binaries [Phase 9 DONE]
│   ├── src/
│   │   ├── lib.rs                   # Re-exports
│   │   ├── args.rs                  # Simple argument parser (no external deps)
│   │   ├── format.rs                # size_str, speed_str, prettytime, prettyhexrep, prettyfrequency, base32
│   │   ├── remote.rs                # Remote management query helper (Phase 8g)
│   │   └── bin/
│   │       ├── rnsd.rs              # Daemon: start node, signal handling, service mode, exampleconfig
│   │       ├── rnstatus.rs          # Interface stats via RPC, sorting, totals, announces, monitor, -R
│   │       ├── rnpath.rs            # Path/rate table, blackhole management via RPC, -R
│   │       ├── rnid.rs              # Identity management (standalone), base32, stdin/stdout
│   │       └── rnprobe.rs           # Path probe diagnostic tool (Phase 8f)
├── rns-ctl/                         # std — HTTP/WebSocket control server [DONE]
│   ├── src/
│   │   ├── main.rs                  # CLI entry point, args, logging, node startup
│   │   ├── config.rs                # Config from env vars/CLI args
│   │   ├── server.rs                # HTTP server
│   │   ├── http.rs                 # HTTP request/response parsing
│   │   ├── ws.rs                   # WebSocket implementation (33 unit tests)
│   │   ├── api.rs                  # REST API handlers (all endpoints implemented)
│   │   ├── auth.rs                 # Bearer token auth middleware
│   │   ├── state.rs                # Shared state management
│   │   ├── bridge.rs               # RNS callbacks → state integration
│   │   ├── encode.rs               # Base64/hex encoding utilities
│   │   └── sha1.rs                # SHA-1 for WebSocket handshake
│   ├── tests/
│   │   └── integration.rs           # 28 integration tests
│   └── Dockerfile                  # Docker image for running rns-ctl
└── tests/
    ├── generate_vectors.py          # Generates JSON fixtures from Python RNS
    ├── fixtures/                 # JSON test fixtures for interop tests
    └── docker/                  # Docker-based E2E test framework [untracked in git]
        ├── Dockerfile
        ├── run-all.sh             # Run full test matrix
        ├── run.sh                # Run single topology/suite
        ├── lib/                  # Helper libraries
        ├── topologies/           # Topology generators (chain, star, mesh)
        ├── configs/              # Generated topology configs
        │   ├── chain-3/, chain-5/
        │   ├── star-5/, star-30/
        │   └── mesh-4/
        └── suites/               # Test suites (12 suites)
            ├── 01_health.sh
            ├── 02_announce_direct.sh
            ├── 03_announce_multihop.sh
            ├── 04_packet_delivery.sh
            ├── 05_proof_receipt.sh
            ├── 06_bidirectional.sh
            ├── 07_identity_recall.sh
            ├── 08_path_table.sh
            ├── 09_convergence.sh
            ├── 10_scale.sh
            ├── 11_star_announce.sh
            └── 12_mesh_routing.sh
```

### Test Summary
        ├── crypto/                  # 11 JSON fixture files (Phase 1)
        ├── protocol/               # 6 JSON fixture files (Phase 2)
        ├── transport/              # 4 JSON fixture files (Phase 3)
        ├── link/                   # 5 JSON fixture files (Phase 4a)
        ├── resource/               # 5 JSON fixture files (Phase 4b)
        └── ifac/                   # 1 JSON fixture file (Phase 5c)
```

### Crate Graph

```
rns-ctl ──┐
           │
rns-cli ──┴── rns-net ──→ rns-core ──→ rns-crypto
                          (no_std)      (no_std)
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

## Phase 4b: Resource Transfer (`rns-core`) — COMPLETE ✓

**Milestone**: Rust can advertise, segment, transfer, and reassemble Resources with windowed flow control, producing byte-identical wire output to Python. A Rust `ResourceSender` can create an advertisement that Python unpacks correctly, and a Rust `ResourceReceiver` can unpack a Python-generated advertisement and drive the full request→parts→proof cycle.

**Result**: 82 unit tests + 12 interop tests + 8 integration tests = 102 new tests (375 total rns-core, 451 total workspace). Modules: msgpack (minimal encode/decode with depth limit), resource/types (states, actions, errors, flags), resource/parts (map_hash, split, hashmap, collision guard), resource/advertisement (msgpack pack/unpack), resource/proof (resource_hash, expected_proof), resource/window (adaptation, rate tracking), resource/sender (state machine with deduped sent_parts tracking), resource/receiver (state machine with EIFR tracking). All wire formats validated against Python-generated test vectors. Post-implementation review fixed: sent_parts dedup, EIFR persistence, timeout calculations, proof validation matching Python, msgpack recursion depth limit, sdu==0 guard.

### Architecture

**Action queue model** (matching transport/link/channel): `ResourceSender` and `ResourceReceiver` return `Vec<ResourceAction>`. No callbacks, no I/O. The caller (future `rns-net`) dispatches actions to the link layer.

**Two separate structs** instead of Python's single `Resource` class:
- `ResourceSender` — creates advertisement, handles part requests, sends parts, validates proof
- `ResourceReceiver` — unpacks advertisement, requests parts, receives parts, assembles data, sends proof

**Minimal msgpack** — Resource advertisements use msgpack dicts. A `msgpack.rs` module in rns-core implements the subset needed: fixmap/map16, fixstr/str8, fixint/uint/int, bin8/bin16/bin32, fixarray/array16, nil. No external dependency.

**Compression** — Reuses `Compressor` trait from buffer module. Resource data is compressed before encryption. `NoopCompressor` for `no_std`; `std` users provide bz2.

**Encryption boundary** — In Python, `Resource.__init__` calls `link.encrypt(data)` to encrypt the entire resource data blob, then splits into SDU-sized parts. Parts are NOT individually encrypted. In Rust, `ResourceSender` accepts **already-encrypted** data from the caller (the caller handles link-level encryption). Similarly, `ResourceReceiver` returns encrypted assembled data for the caller to decrypt. The resource hash and proof are computed on the **unencrypted** data (before the caller encrypts), so the caller must provide both encrypted and unencrypted forms, or the Resource must handle encryption itself. **Decision**: ResourceSender takes unencrypted data + an encryption function (closure/trait), matching Python's design where Resource calls `link.encrypt()`.

**Metadata** — In Python, `Resource` calls `umsgpack.packb(metadata)` itself. In Rust, metadata is accepted as pre-serialized `Vec<u8>` — the caller uses the `msgpack` module to encode. This is an intentional API simplification; the Rust `msgpack` module must be public for callers. The 3-byte big-endian length prefix is added/stripped by the Resource code.

### Module Structure

```
rns-core/src/
├── msgpack.rs                  # Minimal msgpack encode/decode
└── resource/
    ├── mod.rs                  # Re-exports, top-level docs
    ├── types.rs                # ResourceState, ResourceAction, ResourceError, ResourceConfig
    ├── advertisement.rs        # ResourceAdvertisement pack/unpack (msgpack wire format)
    ├── parts.rs                # Part hashing (map_hash), hashmap construction, collision guard
    ├── window.rs               # Window adaptation, rate tracking, EIFR
    ├── sender.rs               # ResourceSender state machine + request handling
    ├── receiver.rs             # ResourceReceiver state machine + part assembly
    └── proof.rs                # Resource completion proof generation/validation
```

### Constants (from Resource.py)

```
# Window sizes
WINDOW               = 4         # Initial window size
WINDOW_MIN           = 2         # Absolute minimum
WINDOW_MAX_SLOW      = 10        # Slow link max
WINDOW_MAX_VERY_SLOW = 4         # Very slow link max
WINDOW_MAX_FAST      = 75        # Fast link max
WINDOW_MAX           = 75        # Global max for calculations
WINDOW_FLEXIBILITY   = 4         # Ratchet flexibility

# Rate thresholds
FAST_RATE_THRESHOLD      = 4     # = WINDOW_MAX_SLOW - WINDOW - 2 = 10 - 4 - 2
VERY_SLOW_RATE_THRESHOLD = 2     # Rounds before capping to very slow
RATE_FAST            = 6250.0    # 50000 bps / 8 (bytes/s)
RATE_VERY_SLOW       = 250.0     # 2000 bps / 8 (bytes/s)

# Timeout and retry
PART_TIMEOUT_FACTOR           = 4
PART_TIMEOUT_FACTOR_AFTER_RTT = 2   # After first RTT measured
PROOF_TIMEOUT_FACTOR          = 3   # Reduced timeout when awaiting proof
MAX_RETRIES          = 16
MAX_ADV_RETRIES      = 4
SENDER_GRACE_TIME    = 10.0     # seconds
PROCESSING_GRACE     = 1.0      # seconds, grace for advertisement response
RETRY_GRACE_TIME     = 0.25     # seconds
PER_RETRY_DELAY      = 0.5      # seconds
WATCHDOG_MAX_SLEEP   = 1.0      # seconds, max tick interval
RESPONSE_MAX_GRACE_TIME = 10.0  # seconds, request timeout grace

# Data sizing
MAPHASH_LEN          = 4        # bytes per part hash
SDU                  = 464      # = Packet.MDU (NOT ENCRYPTED_MDU)
RANDOM_HASH_SIZE     = 4        # collision detection random
MAX_EFFICIENT_SIZE   = 1048575  # 1 MB - 1
METADATA_MAX_SIZE    = 16777215 # 16 MB - 1
AUTO_COMPRESS_MAX_SIZE = 67108864 # 64 MB

# Hashmap / collision
ADVERTISEMENT_OVERHEAD = 134    # Fixed msgpack overhead for advertisement
HASHMAP_MAX_LEN      = 74      # = floor((Link.MDU(431) - 134) / 4)
COLLISION_GUARD_SIZE = 224      # = 2 * WINDOW_MAX(75) + HASHMAP_MAX_LEN(74)

HASHMAP_IS_NOT_EXHAUSTED = 0x00
HASHMAP_IS_EXHAUSTED     = 0xFF
```

**Important SDU note**: Python `Resource.SDU = RNS.Packet.MDU = 464`, NOT `ENCRYPTED_MDU` (383). Resource data is already encrypted by the link layer, so parts are not individually encrypted — the full resource is encrypted once as a blob, then split into SDU-sized parts.

### Wire Formats

**Advertisement (msgpack dict):**
```
{
  "t": transfer_size (int),     # encrypted data size (after compress+encrypt)
  "d": data_size (int),         # total uncompressed size (data + metadata overhead)
  "n": num_parts (int),         # hashmap entry count
  "h": resource_hash (bin32),   # SHA-256(unencrypted_data + random_hash), full 32 bytes
  "r": random_hash (bin4),      # collision detection
  "o": original_hash (bin32),   # first segment hash (multi-segment)
  "m": hashmap (bin),           # concatenated 4-byte part hashes (segment)
  "f": flags (int),             # bit flags (see below)
  "i": segment_index (int),     # 1-based segment number
  "l": total_segments (int),    # total segments
  "q": request_id (bin/nil),    # optional request/response ID
}
```

**Flags byte:**
```
Bit 0: encrypted
Bit 1: compressed
Bit 2: split (multi-segment)
Bit 3: is_request
Bit 4: is_response
Bit 5: has_metadata
```

**Part request (RESOURCE_REQ context):**
```
[exhausted_flag: u8] [last_map_hash: 4 bytes if exhausted] [resource_hash: 32 bytes] [requested_hashes: N*4 bytes]
```

**Hashmap update (RESOURCE_HMU context):**
```
[resource_hash: 32 bytes] [msgpack([segment: int, hashmap: bytes])]
```

**Resource proof (RESOURCE_PRF context):**
```
[resource_hash: 32 bytes] [proof: SHA-256(unencrypted_data + resource_hash)]
```
Note: `proof = SHA-256(data + resource_hash)` where `data` is the uncompressed, metadata-prefixed data (same `data` used to compute `resource_hash`). NOT encrypted data.

**Cancel (RESOURCE_ICL/RESOURCE_RCL context):**
```
[resource_hash: 32 bytes]
```

**Note**: `resource_hash` is always the full SHA-256 (32 bytes) everywhere in the wire protocol — part requests, HMU, proofs, and cancels. The `truncated_hash` (16 bytes) exists on the Resource but is not used in any wire format.

### TDD Sequence

#### 4b.0 Minimal Msgpack (`msgpack.rs`)

Wire-compatible msgpack subset for Resource advertisements and HMU packets.

1. Test: encode nil → `0xc0`
2. Test: encode bool true/false → `0xc3`/`0xc2`
3. Test: encode positive fixint (0..127) → single byte
4. Test: encode uint8/uint16/uint32/uint64 → `0xcc`/`0xcd`/`0xce`/`0xcf` + value
5. Test: encode negative fixint (-32..-1) → single byte
6. Test: encode fixstr (0..31 chars) → `0xa0|len` + bytes
7. Test: encode str8 (32..255 chars) → `0xd9` + len + bytes
8. Test: encode bin8/bin16/bin32 → `0xc4`/`0xc5`/`0xc6` + len + bytes
9. Test: encode fixarray (0..15 items) → `0x90|len` + items
10. Test: encode fixmap (0..15 entries) → `0x80|len` + key-value pairs
11. Test: decode all the above formats (roundtrip)
12. Test: decode uint64 for file sizes > 4GB
13. Test: decode Python-generated advertisement msgpack bytes → correct fields
14. Test: Rust-encoded advertisement msgpack → Python can decode (via fixture)
15. Test: encode/decode [int, bytes] array for HMU

#### 4b.1 Resource Types (`resource/types.rs`)

1. Test: ResourceState enum covers all states: None, Queued, Advertised, Transferring, AwaitingProof, Assembling, Complete, Failed, Corrupt, Rejected
2. Test: ResourceAction variants: SendAdvertisement, SendPart, SendRequest, SendHmu, SendProof, SendCancel, DataReceived, ProgressUpdate, Completed, Failed
3. Test: ResourceError variants: InvalidAdvertisement, InvalidPart, InvalidProof, HashMismatch, Timeout, Rejected, TooLarge
4. Test: advertisement flags byte pack/unpack roundtrip (encrypted, compressed, split, is_request, is_response, has_metadata)
5. Test: HASHMAP_MAX_LEN = floor((LINK_MDU(431) - 134) / MAPHASH_LEN) = 74
6. Test: COLLISION_GUARD_SIZE = 2 * WINDOW_MAX(75) + HASHMAP_MAX_LEN(74) = 224

#### 4b.2 Part Hashing (`resource/parts.rs`)

1. Test: `map_hash(part_data, random_hash)` = SHA-256(part_data + random_hash)[:4]
2. Test: map_hash matches Python-generated fixture for same inputs
3. Test: build_hashmap from data + random_hash → concatenated 4-byte hashes, matches Python
4. Test: split data into parts of SDU bytes → correct number of parts
5. Test: collision_guard detects duplicate map_hash within COLLISION_GUARD_SIZE window
6. Test: last part may be shorter than SDU
7. Test: empty data → 0 parts (edge case)

#### 4b.3 Advertisement (`resource/advertisement.rs`)

1. Test: pack advertisement with no ratchet, no metadata → msgpack matches Python fixture
2. Test: pack advertisement with metadata flag set → correct flags byte
3. Test: pack advertisement with compressed flag → correct flags byte
4. Test: pack multi-segment advertisement (split=true, segment_index=2, total_segments=5)
5. Test: pack advertisement with request_id → "q" field present
6. Test: unpack Python-generated advertisement → all fields extracted correctly
7. Test: unpack advertisement with nil request_id → request_id is None
8. Test: hashmap segmentation: advertisement carries ≤ HASHMAP_MAX_LEN hashes
9. Test: is_request / is_response flag detection
10. Test: reject advertisement with invalid fields (negative size, etc.)

#### 4b.4 Metadata Handling

1. Test: prepend_metadata(data, metadata_bytes) → [3-byte BE length] + metadata + data
2. Test: extract_metadata(assembled_data) → (metadata_bytes, remaining_data)
3. Test: metadata max size (16 MB - 1) enforced
4. Test: no metadata → data passed through unchanged
5. Test: roundtrip: prepend then extract recovers original metadata and data

#### 4b.5 Resource Sender State Machine (`resource/sender.rs`)

1. Test: new() from data bytes → state is Queued, parts built, hashmap computed
2. Test: advertise() → state Advertised, returns SendAdvertisement action with packed advertisement
3. Test: advertise with auto_compress → data compressed if smaller, flags reflect compression
4. Test: receive_acceptance() → state Transferring
5. Test: handle_request(request_data) → returns SendPart actions for requested map_hashes
6. Test: handle_request with unknown map_hash → no parts sent (graceful skip)
7. Test: handle_request with HASHMAP_IS_EXHAUSTED → returns SendHmu action
8. Test: HMU contains correct next segment of hashmap
9. Test: all parts sent → state AwaitingProof, retries_left = 3 (hardcoded, not MAX_RETRIES)
10. Test: validate_proof(proof_data) → proof = SHA-256(unencrypted_data + resource_hash), state Complete
11. Test: invalid proof → state Failed
12. Test: timeout with no requests → retry advertise (up to MAX_ADV_RETRIES), uses PROCESSING_GRACE
13. Test: exceed MAX_ADV_RETRIES → state Failed
14. Test: receive cancel (RESOURCE_RCL) → state Rejected
15. Test: send cancel (RESOURCE_ICL) → returns SendCancel action
16. Test: multi-segment sender: segment_index, total_segments, original_hash set correctly
17. Test: resource_hash = SHA-256(unencrypted_data + random_hash) [full 32 bytes]
18. Test: expected_proof = SHA-256(unencrypted_data + resource_hash) [full 32 bytes]
19. Test: AwaitingProof timeout queries network cache for expected proof packet
20. Test: req_hashlist deduplication — same request packet hash is not processed twice

#### 4b.6 Resource Receiver State Machine (`resource/receiver.rs`)

1. Test: from_advertisement(adv_data) → hashmap stored, parts array initialized
2. Test: accept() → state Transferring, returns SendRequest for first window of parts
2a. Test: accept() inherits previous window/EIFR from link if available
3. Test: reject() → returns SendCancel (RESOURCE_RCL)
4. Test: receive_part(part_data) → matches map_hash, stores in correct slot
5. Test: receive_part with unknown map_hash → ignored
6. Test: receive_part completes window → requests next window
7. Test: consecutive_completed_height tracks contiguous received parts
8. Test: window increases by 1 when all outstanding parts received
9. Test: window_min ratchets up with flexibility
10. Test: timeout waiting for parts → window decreases, retry with remaining hashes
11. Test: exceed MAX_RETRIES → state Failed
12. Test: hashmap exhaustion → request with HASHMAP_IS_EXHAUSTED flag + last_map_hash
13. Test: receive hashmap_update → new hashes available, resume requesting
14. Test: all parts received → state Assembling → assemble data → verify hash → state Complete
15. Test: assembled data hash mismatch → state Corrupt
16. Test: assembled data with compression → decompress via Compressor trait
17. Test: assembled data with metadata → extract metadata, return separately
18. Test: send proof after successful assembly → SHA-256(unencrypted_data + resource_hash)
19. Test: receive cancel (RESOURCE_ICL) → state Failed
20. Test: multi-segment: accept each segment, chain via original_hash

#### 4b.7 Window Adaptation (`resource/window.rs`)

1. Test: initial window = WINDOW (4), window_max = WINDOW_MAX_SLOW (10)
2. Test: window increases when all outstanding parts received (window < window_max)
3. Test: window_min ratchets up: (window - window_min) > (flexibility - 1) → window_min += 1
4. Test: window decreases on timeout: window -= 1, window_max -= 1, and if gap > flexibility-1 then window_max -= 1 again (can decrease by 2)
5. Test: fast rate detection: req_resp_rtt_rate > RATE_FAST for FAST_RATE_THRESHOLD(4) rounds → window_max = WINDOW_MAX_FAST (75)
6. Test: very slow rate detection: only when fast_rate_rounds == 0, req_data_rtt_rate < RATE_VERY_SLOW for VERY_SLOW_RATE_THRESHOLD rounds → window_max = WINDOW_MAX_VERY_SLOW (4)
7. Test: EIFR calculation: expected_inflight_rate = req_data_rtt_rate * 8; fallback to previous_eifr; then to establishment_cost * 8 / rtt
8. Test: fast_rate_rounds only increments (never resets) — once fast mode is entered, it stays
9. Test: window never goes below WINDOW_MIN (2)
10. Test: window never exceeds window_max
11. Test: previous window/EIFR from prior transfer on same link carries over to next transfer

#### 4b.8 Tick / Timeout Logic

1. Test: sender tick() with no response after PART_TIMEOUT_FACTOR(4) * RTT → timeout
2. Test: sender tick() uses PART_TIMEOUT_FACTOR_AFTER_RTT(2) once RTT is measured
3. Test: sender AwaitingProof uses PROOF_TIMEOUT_FACTOR(3)
4. Test: sender AwaitingProof timeout → queries cache for expected proof, retries_left -= 1
5. Test: receiver tick() with no parts after timeout → decrease window, retry
6. Test: tick() with SENDER_GRACE_TIME → grace period before declaring failure
7. Test: tick() with PROCESSING_GRACE → added to timeout when in Advertised state
8. Test: tick() returns ProgressUpdate actions with completion percentage
9. Test: tick() must be called at least every WATCHDOG_MAX_SLEEP(1s) for correct behavior

#### 4b.9 Integration Tests

1. Test: full sender↔receiver cycle — create sender, generate advertisement, receiver unpacks, requests parts, sender sends parts, receiver assembles, sends proof, sender validates — both reach Complete
2. Test: full cycle with simulated packet loss — some parts not delivered, receiver re-requests, sender retransmits
3. Test: full cycle with hashmap exhaustion — enough parts that receiver exhausts initial hashmap, triggers HMU
4. Test: full cycle with compression — sender compresses, receiver decompresses, data matches
5. Test: full cycle with metadata — metadata round-trips through advertisement → assembly
6. Test: cancel from sender mid-transfer → receiver gets Failed
7. Test: cancel from receiver mid-transfer → sender gets Failed

#### 4b.10 Interop Tests (vs Python fixtures)

1. Test: Python-packed advertisement → Rust unpack → all fields match
2. Test: Rust-packed advertisement → Python unpack → all fields match (via fixture)
3. Test: Python-generated part map_hashes → Rust computes same hashes
4. Test: Python-generated resource proof → Rust validates
5. Test: Rust-generated resource proof → matches Python expected value

### Test Fixture Generation

New fixtures in `tests/fixtures/resource/`:
```
- msgpack_vectors.json           # Msgpack encode/decode test pairs
- advertisement_vectors.json     # 4+ advertisement pack/unpack cases
- part_hash_vectors.json         # map_hash computation for known data+random
- resource_proof_vectors.json    # Proof generation/validation
- metadata_vectors.json          # Metadata prepend/extract
- hmu_vectors.json               # Hashmap update msgpack pack/unpack
```

### Python Reference Files
- `RNS/Resource.py` — Transfer protocol (1361 lines)
- `RNS/Packet.py:71-92` — RESOURCE_* context constants
- `RNS/Link.py:1069-1187` — Link-side resource packet dispatch
- `RNS/Identity.py` — full_hash for proof/map_hash computation

---

## Phase 5a: Minimum Viable Network Node (`rns-net`) — COMPLETE ✓

**Milestone**: A Rust process connects to a Python RNS TCP server, receives HDLC-framed packets, processes announces, discovers paths. Proves the full stack works end-to-end.

**Result**: 35 unit tests + 1 interop test = 36 tests. Thread model: single Driver thread owns TransportEngine, per-interface Reader threads decode HDLC and send events, Timer thread sends periodic ticks. All communication via single mpsc channel. Writer refresh on reconnect ensures the driver always holds a live socket.

**Modules (initial)**:
- `hdlc.rs` — HDLC escape/unescape/frame + streaming Decoder (matches TCPInterface.py)
- `event.rs` — Event enum (Frame, InterfaceUp with optional writer, InterfaceDown, Tick, Shutdown)
- `time.rs` — `now()` → f64 Unix epoch
- `interface/mod.rs` — Writer trait, InterfaceEntry struct
- `interface/tcp.rs` — TCP client with socket options (TCP_NODELAY, keepalive, Linux TCP_USER_TIMEOUT), reader thread, reconnect with writer refresh
- `driver.rs` — Callbacks trait, Driver event loop dispatching TransportActions
- `node.rs` — RnsNode start/shutdown lifecycle wiring

**Dependencies**: `rns-core`, `rns-crypto`, `log`, `libc`. Dev: `env_logger`, `serde_json`, `ctrlc`.

---

## Phase 5b: Full Networking & Interfaces (`rns-net`) — COMPLETE ✓

**Milestone**: A Rust `rnsd` daemon reads standard Python RNS config files, opens TCP server/client, UDP, and Local interfaces, persists identity and known destinations, and interoperates with Python nodes.

**Result**: 79 unit tests + 1 interop test = 80 tests (531 total workspace). All interface types implemented (TCP client/server, UDP, Local with Unix abstract socket + TCP fallback). ConfigObj parser handles nested `[[sections]]`, `Yes`/`No` booleans, `interface_mode`/`mode` fallback. Identity and known destinations persistence via msgpack. Dynamic interface registration for TCP server and Local server clients.

**New modules**:
- `config.rs` — ConfigObj parser for Python RNS config files (14 tests)
- `interface/tcp_server.rs` — TCP server, spawns per-client reader threads with dynamic InterfaceId (6 tests)
- `interface/udp.rs` — UDP broadcast interface, no HDLC framing (5 tests)
- `interface/local.rs` — Unix abstract socket (`\0rns/{name}`) on Linux with TCP fallback (5 tests)
- `storage.rs` — Identity save/load (64 bytes), known destinations msgpack, storage dir creation (7 tests)
- `examples/rnsd.rs` — Rust rnsd daemon (config-driven)

**Extended modules**:
- `event.rs` — `InterfaceUp` now has 3 fields: `(InterfaceId, Option<Writer>, Option<InterfaceInfo>)` for dynamic registration
- `driver.rs` — Dynamic interface register/deregister, `on_interface_up`/`on_interface_down` callbacks (3 new tests)
- `node.rs` — `InterfaceConfig` struct with `variant: InterfaceVariant` + `mode: u8`, `from_config()` reads config + creates/loads identity, `parse_interface_mode()` maps mode strings to constants (4 new tests)
- `interface/mod.rs` — `InterfaceEntry` gained `dynamic: bool` field

**Not included**: Serial/KISS/RNode interfaces (need hardware, Phase 5c), AutoInterface (complex multicast discovery, Phase 8d), IFAC (Interface Access Codes, Phase 5c), RPC control port (Phase 6a), I2P interface (completed separately).

---

## Phase 5c: IFAC, KISS & Serial Interfaces (`rns-net`) — COMPLETE ✓

**Milestone**: IFAC masking/unmasking, raw serial I/O, Serial interface with HDLC framing, KISS interface with flow control, and TNC configuration — all validated against Python-generated test vectors.

**Result**: 117 unit tests + 2 interop tests = 119 tests (570 total workspace). IFAC key derivation matches Python's HKDF(SHA256(SHA256(netname)||SHA256(netkey)), IFAC_SALT). Serial I/O via libc termios with PTY pairs for testing. KISS framing with FEND/FESC escaping. KISS interface with flow control (CMD_READY), TNC config commands after 2s init delay, and reconnect pattern. Default IFAC sizes: 8 bytes for Serial/KISS/RNode, 16 for TCP/UDP/Auto/Local.

**New modules**:
- `ifac.rs` — IFAC derive/mask/unmask with HKDF key derivation (7 tests + 1 interop)
- `serial.rs` — Raw serial I/O via libc termios, `open_pty_pair()` for testing (4 tests)
- `kiss.rs` — KISS framing (FEND=0xC0, FESC=0xDB) + streaming Decoder (10 tests)
- `interface/serial_iface.rs` — Serial + HDLC framing, reader thread, reconnect (5 tests)
- `interface/kiss_iface.rs` — KISS + flow control, TNC config, beacon support (8 tests)

**Deferred**: RNode/Pipe/Backbone (Phase 5d). Note: AutoInterface and I2P were completed in later phases.

---

## Phase 5d: RNode, Pipe & Backbone Interfaces (`rns-net`) — COMPLETE ✓

**Milestone**: RNode LoRa radio modem interface with multi-subinterface support, Pipe subprocess interface, and Backbone TCP mesh interface using Linux epoll — all matching Python reference implementations.

**Result**: 152 unit tests + 2 interop tests = 154 tests (605 total workspace). RNode KISS protocol module with streaming decoder and 12-subinterface data routing. Pipe interface spawns subprocess via `sh -c`, communicates over stdin/stdout with HDLC framing, auto-respawns on failure. RNode interface manages serial connection to hardware, runs detect/configure sequence, creates per-subinterface writers with flow control. Backbone interface uses single epoll thread to multiplex listener + all client sockets, creates dynamic per-peer interfaces.

**New modules**:
- `rnode_kiss.rs` — RNode-specific KISS commands, RNodeDecoder, subinterface data routing (10 tests)
- `interface/pipe.rs` — Subprocess stdin/stdout + HDLC framing, auto-respawn (5 tests)
- `interface/rnode.rs` — RNode LoRa radio, detect/configure, multi-sub writers, flow control (8 tests)
- `interface/backbone.rs` — TCP mesh backbone, Linux epoll, dynamic per-client interfaces (8 tests)

**Extended modules**:
- `node.rs` — `InterfaceVariant::Pipe/RNode/Backbone`, config parsing, start handling (4 tests)
- `lib.rs` — Re-exports for `PipeConfig`, `RNodeConfig`, `RNodeSubConfig`, `BackboneConfig`

**Deferred**: RNodeMultiInterface config nesting (`[[[triple-bracket]]]`) — Multi-subinterface RNode with nested config syntax. Note: Basic RNode (single subinterface), AutoInterface, and I2P are complete.

---

## Phase 6a: CLI Tools & RPC Infrastructure (`rns-cli` + `rns-net`) — COMPLETE ✓

**Milestone**: Core CLI binaries work, RPC layer connects Rust tools to running `rnsd` instances.

**Result**: `rns-cli` crate with 4 binaries + RPC/pickle/MD5 infrastructure in `rns-net`. 677 tests passing across workspace.

### What was built

#### RPC Infrastructure (`rns-net`)
- `pickle.rs`: Minimal pickle codec (protocol 2 encoder, protocol 2–5 decoder) for Python `multiprocessing` compatibility
- `md5.rs`: MD5 + HMAC-MD5 for legacy Python multiprocessing auth handshake
- `rpc.rs`: Full Python `multiprocessing.connection` wire protocol (4-byte BE length prefix + pickle, HMAC-SHA256 auth)
- `event.rs`: QueryRequest/QueryResponse enums for driver state queries via `Event::Query` with mpsc response channel
- `driver.rs`: InterfaceStats tracking (rxb/txb/rx_packets/tx_packets), handle_query/handle_query_mut dispatch
- `node.rs`: `share_instance` + `rpc_port` config, RPC server thread

#### CLI Binaries (`rns-cli`)
- `args.rs`: Simple argument parser (no external deps)
- `format.rs`: Shared formatting (size_str, speed_str, prettytime, prettyhexrep)
- **rnsd**: Daemon — starts node from config, SIGINT/SIGTERM shutdown, verbosity flags
- **rnstatus**: Interface stats — connects via RPC, displays mode/traffic/uptime, sorting, JSON output, name filtering
- **rnpath**: Path management — path table, rate table, lookup, drop paths/queues via RPC, JSON output
- **rnid**: Identity tool — generate, inspect, encrypt/decrypt files, sign/verify, import/export (hex/base64), destination hash computation (standalone, no RPC needed)

---

## Phase 6b: CLI Enhancements (`rns-cli` + `rns-core` + `rns-net`) — COMPLETE ✓

**Milestone**: CLI tools gain sorting, monitoring, announce stats, traffic totals, blackhole management, base32 encoding, and service mode. Core transport gains blackhole infrastructure.

**Result**: 689 tests passing across workspace. Added 4 blackhole tests to rns-core (335 total), updated rns-net stats/queries (215 tests), added 8 new CLI tests (17 total).

### What was built

#### Core Blackhole Infrastructure (`rns-core`)
- `transport/types.rs`: `BlackholeEntry` struct (created, expires, reason)
- `transport/mod.rs`: `blackholed_identities: BTreeMap`, methods (`blackhole_identity`, `unblackhole_identity`, `is_blackholed`, `blackholed_entries`, `cull_blackholed`), announce rejection in `process_inbound_announce()`, culling in `tick()`

#### Network Layer Enhancements (`rns-net`)
- `interface/mod.rs`: Announce tracking on `InterfaceStats` (bounded Vec<f64> with max 6 samples, frequency computation)
- `event.rs`: `total_rxb`/`total_txb` on `InterfaceStatsResponse`, `ia_freq`/`oa_freq` on `SingleInterfaceStat`, `BlackholeInfo` struct, `GetBlackholed`/`BlackholeIdentity`/`UnblackholeIdentity` query variants
- `driver.rs`: Traffic totals computation, announce tracking in `dispatch_all()` (detect via `raw[0] & 0x03 == 0x01`), blackhole query handling
- `rpc.rs`: Blackhole RPC translation (`get: "blackholed"`, `blackhole`, `unblackhole` requests), serialization of new fields

#### CLI Enhancements (`rns-cli`)
- `format.rs`: `prettyfrequency()`, `base32_encode()`/`base32_decode()` (RFC 4648)
- `args.rs`: Smart flag parsing (value flags detect `-`-prefixed next args as separate flags)
- **rnsd**: `--exampleconfig` (prints full example config), `-s` service mode (logs to file)
- **rnstatus**: Sorting (`-s rate/traffic/rx/tx`, `-r` reverse), traffic totals (`-t`), link count (`-l`), announce stats (`-A`), monitor mode (`-m`, `-I SECONDS`)
- **rnpath**: Max hops filter (`-m HOPS`), rate hourly frequency, blackhole commands (`-b`/`-B HASH`/`-U HASH`/`--duration HOURS`/`--reason TEXT`)
- **rnid**: Base32 (`-B`), force overwrite (`-f`/`--force`), stdin/stdout (`--stdin`/`--stdout`), large file warning (>16MB)

### Deferred to future phases
- Discovery interfaces (`-d`/`-D`) — CLI flags for managing discovery announcements
- `rnid -a` (announce destination — requires application-layer)
- RNodeMultiInterface config nesting (`[[[triple-bracket]]]`) — Multi-subinterface RNode with nested config syntax

Note: `rnprobe` and Remote management CLI (`-R HASH`) were completed in Phase 8f/8g.

---

## Phase 7: Close Transport Gaps + Link Wiring + Management (`rns-core` + `rns-net`) — COMPLETE ✓

**Milestone**: Transport engine gains per-interface announce bandwidth queuing, local-client handling, disk-based announce cache, tunnel support, link wiring in the driver, and remote management destinations. 773 tests passing.

### What was built

#### Phase 7a: Per-Interface Announce Bandwidth Queuing (`rns-core`)
- `transport/announce_queue.rs`: Per-interface bandwidth queuing with dedup, priority (min hops, FIFO), stale removal
- `constants.rs`: `ANNOUNCE_CAP`, `MAX_QUEUED_ANNOUNCES`, `QUEUED_ANNOUNCE_LIFE`
- `InterfaceInfo.announce_cap`, `gate_announce()`, `process_announce_queues()` in tick
- 15 unit tests

#### Phase 7b: Shared-Instance/Local-Client Transport (`rns-core`)
- `InterfaceInfo.is_local_client`: hop adjustment, announce forwarding, broadcast bridging
- `TransportAction::ForwardToLocalClients`, `ForwardPlainBroadcast` variants
- Driver dispatches new action variants to local/external interfaces
- 8 unit tests

#### Phase 7c: Announce Cache to Disk (`rns-core` + `rns-net`)
- `TransportAction::CacheAnnounce`, `PathEntry.announce_raw` for pre-hop-increment bytes
- `announce_cache.rs`: File-based cache (msgpack format, hex filenames), periodic cleanup
- Driver handles CacheAnnounce action, stores on disk
- 8 unit tests

#### Phase 7d: Tunnels (`rns-core` + `rns-net`)
- `transport/tunnel.rs`: TunnelTable, TunnelEntry, TunnelPath, compute/build/validate tunnel synthesis
- `TransportAction::TunnelSynthesize`, `TunnelEstablished`
- `InterfaceInfo.wants_tunnel`, `tunnel_id` fields
- Driver registers tunnel.synthesize destination, handles synthesis/reattach/void
- 22 unit tests

#### Phase 7e: Link Wiring (`rns-net`)
- `link_manager.rs`: LinkManager with ManagedLink, LinkDestination, RequestHandlerEntry
- Full link lifecycle: LINKREQUEST→LRPROOF→ACTIVE, encrypted data, keepalive/stale/close
- Request/response with Python-compatible msgpack format and ACL
- Channel data routing, IDENTIFY handling
- Driver integration: DeliverLocal → LinkManager dispatch, Event::CreateLink, Event::SendOnLink
- Callbacks: `on_link_established`, `on_link_closed`, `on_remote_identified`
- 7 unit/integration tests

#### Phase 7f: Management Destinations (`rns-net`)
- `management.rs`: ManagementConfig, destination hash computation, request handlers
- `/status` handler: interface stats, traffic totals, uptime, link count (msgpack response)
- `/path` handler: path table and rate table queries with dest filter and max hops
- `/list` handler: blackholed identities
- ACL enforcement: ALLOW_LIST for /status+/path, ALLOW_ALL for /list
- Config parsing: `enable_remote_management`, `remote_management_allowed`, `publish_blackhole`
- Driver registers management destinations as SINGLE + link destinations on startup
- 13 unit tests (11 management + 2 config)

---

## Phase 8: Application API Completion + AutoInterface + CLI (`rns-core` + `rns-net` + `rns-cli`) — COMPLETE ✓

**Milestone**: Application-level APIs wired through network layer (resource transfers, channel messages, management announces), AutoInterface for zero-config LAN discovery, shared instance client mode, rnprobe CLI tool, and remote management `-R` flags. 842 tests passing.

### What was built

#### Phase 8a: Resource Wiring in LinkManager + Driver (`rns-net`)
- `link_manager.rs`: Resource context dispatch for all 7 context types (ADV/REQ/HMU/RESOURCE/PRF/ICL/RCL)
- ResourceSender/ResourceReceiver lifecycle wired through ManagedLink with encryption closures
- ResourceStrategy (AcceptNone/AcceptAll/AcceptApp) for incoming resource filtering
- `resource_tick()` drives active transfers; driver dispatches resource callbacks
- New Callbacks: `on_resource_received`, `on_resource_completed`, `on_resource_failed`, `on_resource_progress`
- New Node API: `send_resource()`, `set_resource_strategy()`

#### Phase 8b: Channel Message Delivery + Data Callbacks (`rns-net`)
- Channel `MessageReceived` → `LinkManagerAction::ChannelMessageReceived` → `on_channel_message` callback
- Generic link data (CONTEXT_NONE) → `on_link_data` callback
- Response delivery with msgpack unpacking → `on_response` callback
- New Node API: `send_channel_message()`, `send_on_link()`

#### Phase 8c: Management Destination Announcing (`rns-net`)
- `management.rs`: `build_management_announce()`, `build_blackhole_announce()` build full ANNOUNCE packets
- Driver emits management/blackhole announces on startup + periodic re-announce (300s interval)
- Only when `enable_remote_management`/`publish_blackhole` config is true

#### Phase 8d: AutoInterface (`rns-net`)
- `interface/auto.rs`: Zero-config LAN auto-discovery via IPv6 multicast
- Multicast address derivation from SHA-256(group_id), discovery tokens, peer management
- Thread model: discovery sender, multicast receiver, unicast receiver, data receiver, peer jobs (per interface)
- `socket2` crate for multicast socket setup (`join_multicast_v6`, `set_reuse_port`)
- Peer tracking with PEERING_TIMEOUT=22s, dedup deque (48 entries, 0.75s TTL)
- Network interface enumeration via `libc::getifaddrs()` (fe80::/10 link-local addresses)
- 19 unit tests including Python interop vectors

#### Phase 8e: Shared Instance Client Mode (`rns-net`)
- `shared_client.rs`: `SharedClientConfig` + `RnsNode::connect_shared()` constructor
- Connects via LocalClientInterface with `transport_enabled: false`, proxies through daemon
- `from_parts()` internal constructor for building RnsNode from pre-assembled components
- 5 unit tests

#### Phase 8f: rnprobe CLI Tool (`rns-cli`)
- `bin/rnprobe.rs`: Path probe utility using RPC to query running rnsd
- Combines next_hop, next_hop_if_name, and path_table RPC queries
- Polls path table with 250ms interval until timeout (default 15s)
- 10 unit tests

#### Phase 8g: CLI `-R` Remote Management Flags (`rns-cli`)
- `remote.rs`: `remote_query()` helper using shared client → link → identify → request → response
- `RemoteCallbacks` captures link_established and response via mpsc channels
- `-R HASH` flag added to rnstatus and rnpath (stub implementations)
- 3 unit tests

---

## Phase 9: Application-Facing API (`rns-core` + `rns-net`) — COMPLETE ✓

**Milestone**: Ergonomic application-facing API with typed wrappers, Destination abstraction, announce/discover/send_packet/proof lifecycle, and an end-to-end echo example. 887 tests passing.

### What was built

#### Phase 9a: Typed Wrappers + Enums (`rns-core`)
- `types.rs`: `DestHash([u8;16])`, `IdentityHash([u8;16])`, `LinkId([u8;16])`, `PacketHash([u8;32])` newtypes
- `DestinationType`, `Direction`, `ProofStrategy` enums with `to_wire_constant()` conversions
- `Display` (hex), `From`, `PartialEq`, `Eq`, `Hash` implementations
- 10 unit tests

#### Phase 9b: Destination + AnnouncedIdentity Structs (`rns-net`)
- `destination.rs`: `Destination` struct with constructors (`single_in`, `single_out`, `plain`, `group`)
- `AnnouncedIdentity` struct for announce data
- Uses `rns_core::destination::destination_hash()` internally for hash computation
- `set_proof_strategy()` builder method
- GROUP: `group_key` field, `create_keys()`, `load_private_key()`, `encrypt()`/`decrypt()` via Token
- `GroupKeyError` error type, re-exported from `lib.rs`
- 21 unit tests (8 original + 13 GROUP)

#### Phase 9c: Node Methods — Announce + Discovery (`rns-net`)
- `RnsNode::announce()`: builds announce packet on calling thread, signs with identity, sends via SendOutbound
- `RnsNode::request_path()`: sends RequestPath event to driver
- `RnsNode::has_path()`, `hops_to()`: convenience wrappers over Query mechanism
- `RnsNode::recall_identity()`: retrieves announced identity from driver's known_destinations cache
- Driver maintains `known_destinations: HashMap<[u8;16], AnnouncedIdentity>` populated from AnnounceReceived actions
- New Query variants: HasPath, HopsTo, RecallIdentity, RequestPath
- 15 unit tests

#### Phase 9d: Node Methods — send_packet + Proofs (`rns-net`)
- `RnsNode::send_packet()`: encrypts (SINGLE) or wraps (PLAIN) data, returns PacketHash for tracking
- `RnsNode::register_destination_with_proof()`: registers destination + proof strategy
- Driver proof infrastructure: `proof_strategies` HashMap, `sent_packets` tracking, auto-prove (ProveAll/ProveApp/ProveNone)
- Inbound proof matching: validates explicit proofs, computes RTT, fires `on_proof` callback
- New Callbacks: `on_proof(dest_hash, packet_hash, rtt)`, `on_proof_requested(dest_hash, packet_hash) -> bool`
- 15 unit tests (10 driver + 5 node)

#### Phase 9e: Migrate Callbacks + Link Methods to Typed Wrappers (`rns-net`)
- Updated all Callbacks trait signatures to use `DestHash`, `IdentityHash`, `LinkId`, `PacketHash`
- `on_announce` now takes `AnnouncedIdentity` struct instead of 5 flat params
- Updated all implementations: driver, node, shared_client, CLI binaries, examples
- Updated all test assertions
- Compile-time type safety prevents mixing up destination/identity/link hashes

#### Phase 9f: Echo Example (`rns-net`)
- `examples/echo.rs`: Full end-to-end echo server/client via TCP loopback
- Server: creates identity, destination, registers with ProveAll, announces
- Client: receives announce, creates OUT destination, sends encrypted packet
- Server auto-generates proof, client receives proof with RTT measurement
- Validates announce→discover→send→receive→proof lifecycle

---

## GROUP Destination Support (`rns-net`) — COMPLETE ✓

**Milestone**: GROUP destinations with symmetric Token encryption — create, load/generate keys, encrypt/decrypt, send via `send_packet()`. 900 tests passing.

### What was built

#### Destination GROUP Support (`rns-net/src/destination.rs`)
- `Destination::group(app_name, aspects)` constructor — hash based on name only (no identity)
- `group_key: Option<Vec<u8>>` field on `Destination` struct
- `create_keys()` — generates random 64-byte AES-256 key via `OsRng`
- `load_private_key(key)` — accepts 32-byte (AES-128) or 64-byte (AES-256)
- `get_private_key()` — retrieve key bytes
- `encrypt(plaintext)` / `decrypt(ciphertext)` — delegates to `rns_crypto::Token`
- `GroupKeyError` enum (NoKey, InvalidKeyLength, EncryptionFailed, DecryptionFailed)
- `GroupKeyError` re-exported from `lib.rs`

#### send_packet() GROUP Wiring (`rns-net/src/node.rs`)
- `DestinationType::Group` branch calls `dest.encrypt(data)` (was `return Err(SendError)`)

#### Tests (13 new)
- Hash determinism, GROUP/PLAIN hash equivalence, key generation (64 bytes)
- Key loading (32 + 64), invalid key rejection
- Encrypt/decrypt roundtrip (AES-128 + AES-256), wrong-key failure, no-key error
- Bidirectional Token interop (Token↔Destination encrypt/decrypt)

---

## Milestone Summary

| Phase | Crate | Milestone Gate | Status |
|-------|-------|---------------|--------|
| **1** | `rns-crypto` | All crypto ops produce byte-identical output to Python | **DONE** — 80 tests, `Python Token.encrypt() → Rust decrypt()` ✓ |
| **2** | `rns-core` | Packet pack/unpack, Destination, Announce wire-compatible | **DONE** — 435 tests, `Python announce → Rust validate()` ✓ |
| **3** | `rns-core` | Transport routes packets identically to Python | **DONE** — included in rns-core tests |
| **4a** | `rns-core` | Link handshake, Channel messaging, Buffer streaming | **DONE** — included in rns-core tests |
| **4b** | `rns-core` | Resource segmented transfer with windowed flow control | **DONE** — included in rns-core tests |
| **5a** | `rns-net` | TCP connect → receive announces → discover paths | **DONE** — included in rns-net tests |
| **5b** | `rns-net` | Config, TCP server, UDP, Local, persistence | **DONE** — included in rns-net tests |
| **5c** | `rns-net` | IFAC, Serial, KISS interfaces | **DONE** — included in rns-net tests |
| **5d** | `rns-net` | RNode, Pipe, Backbone interfaces | **DONE** — 470 tests (1 failing), RNode LoRa + Pipe subprocess + Backbone epoll TCP mesh ✓ |
| **6a** | `rns-cli` + `rns-net` | Core CLI tools + RPC infrastructure | **DONE** — included in rns-net/rns-cli tests |
| **6b** | `rns-cli` + `rns-core` + `rns-net` | CLI enhancements + blackhole infrastructure | **DONE** — included in rns-net tests |
| **7** | `rns-core` + `rns-net` | Transport gaps + link wiring + management | **DONE** — included in rns-core/rns-net tests |
| **8** | `rns-core` + `rns-net` + `rns-cli` | App API + AutoInterface + shared client + CLI | **DONE** — included in rns-core/rns-net tests |
| **8d** | `rns-net` | AutoInterface: IPv6 multicast LAN discovery | **DONE** — 19 tests including Python interop vectors ✓ |
| **I2P** | `rns-net` | I2P interface using SAM v3.1 protocol | **DONE** — SAM client, outbound/inbound peers, key persistence ✓ |
| **9** | `rns-core` + `rns-net` | Application-facing API + typed wrappers + echo example | **DONE** — included in rns-core/rns-net tests |
| **GROUP** | `rns-net` | GROUP destinations with symmetric Token encryption | **DONE** — included in rns-net tests |
| **rns-ctl** | `rns-ctl` | HTTP/WebSocket control server | **DONE** — 61 tests, full REST API + WebSocket + auth + state management ✓ |
| **E2E** | `tests/docker/` | Docker-based end-to-end test framework | **DONE** — 12 test suites, chain/star/mesh topologies (untracked in git) ✓ |

**Total Workspace Tests: ~1,056 tests passing** (as of 2026-02-12)

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

# Phase 4b vectors (tests/fixtures/resource/)
- msgpack_vectors.json           # Msgpack encode/decode test pairs
- advertisement_vectors.json     # Advertisement pack/unpack cases
- part_hash_vectors.json         # map_hash computation
- resource_proof_vectors.json    # Proof generation/validation
- metadata_vectors.json          # Metadata prepend/extract
- hmu_vectors.json               # Hashmap update msgpack
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

### rns-net (std)
- `rns-core`, `rns-crypto` (path dependencies)
- `log` (logging facade), `libc` (socket options via setsockopt), `socket2` (multicast for AutoInterface)
- Dev-only: `env_logger`, `serde_json`, `ctrlc`, `tempfile`
- No tokio — std threads are sufficient for the interface count we handle

### rns-cli (std) — DONE (Phase 6a)
- `rns-net`, `rns-core`, `rns-crypto`
- External deps: `log`, `env_logger`, `libc`
- No clap — uses custom `args.rs` parser (zero external dep for arg parsing)

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
