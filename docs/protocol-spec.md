# RNS Protocol Specification

Status: Draft

Version: 0.1

This document is the normative protocol specification for the wire protocol
implemented by `rns-rs`. It describes packet formats, cryptographic framing,
destination derivation, announce validation, link establishment, and the
transport rules required for interoperable nodes.

This document intentionally focuses on protocol behavior. CLI behavior, local
storage layout, log formatting, and runtime configuration syntax are out of
scope unless they affect interoperability.

## 1. Scope

The protocol defined here provides:

- destination-based addressing
- encrypted single-packet delivery
- multi-hop forwarding via transport nodes
- authenticated announce propagation
- anonymous link establishment
- reliable resource transfer over links

The protocol does not require any specific physical carrier. It assumes a
medium capable of carrying binary frames with an MTU of at least 500 bytes.

## 2. Terminology

- `Destination`: a network-reachable endpoint identified by a 16-byte hash
- `Identity`: a pair of public/private keypairs consisting of one X25519 key and
  one Ed25519 key
- `Announce`: a signed broadcast stating that a destination is reachable
- `Link`: a bidirectional encrypted session addressed by a `link_id`
- `Transport Node`: a node that stores paths and forwards packets for others
- `Instance`: any node speaking this protocol
- `Packet Hash`: the SHA-256 hash of a packet's hashable part
- `Truncated Hash`: the first 16 bytes of a SHA-256 hash
- `Name Hash`: the first 10 bytes of SHA-256 over a destination name

Unless otherwise stated, all multi-byte integers are unsigned and encoded in
network byte order.

## 3. Constants

The current protocol profile uses the following constants:

- MTU: 500 bytes
- Truncated hash length: 128 bits
- Full hash length: 256 bits
- Name hash length: 80 bits
- Identity public key length: 64 bytes
- Signature length: 64 bytes
- Ratchet public key length: 32 bytes
- Token overhead: 48 bytes
- Maximum hops: 128

Current cryptographic algorithms:

- destination encryption: X25519 + HKDF-SHA256 + AES-CBC + HMAC-SHA256
- signatures: Ed25519
- hashes: SHA-256
- session derivation: HKDF-SHA256

## 4. Identities

An identity consists of:

- one X25519 keypair used for ECDH
- one Ed25519 keypair used for signatures

The public identity encoding is:

```text
[x25519_pub:32][ed25519_pub:32]
```

The private identity encoding is:

```text
[x25519_prv:32][ed25519_prv:32]
```

The identity hash is:

```text
identity_hash = SHA256(public_identity)[:16]
```

## 5. Destination Model

### 5.1 Destination Types

The protocol defines four destination types:

- `SINGLE` = `0x00`
- `GROUP` = `0x01`
- `PLAIN` = `0x02`
- `LINK` = `0x03`

`SINGLE` destinations are identity-bound and support encrypted multi-hop
delivery. `PLAIN` destinations are unencrypted and intended for local/broadcast
use. `GROUP` destinations are shared-key endpoints for local one-hop delivery in
the current compatibility profile. `LINK` destinations are ephemeral session
destinations derived from a link handshake.

In `RNS-Compat/1`, `PLAIN` and `GROUP` traffic is restricted as follows:

- packets to `PLAIN` or `GROUP` destinations MUST NOT be forwarded over multiple hops
- packets to `PLAIN` or `GROUP` destinations are valid only with `hops <= 1`
- `ANNOUNCE` packets for `PLAIN` or `GROUP` destinations are invalid

### 5.2 Destination Naming

A destination name is formed from:

```text
app_name.aspect_1.aspect_2...
```

`app_name` and every `aspect` element MUST NOT contain `.`.

The name hash is:

```text
name_hash = SHA256(utf8("app.aspect1.aspect2..."))[:10]
```

For `SINGLE` destinations, the destination hash is:

```text
destination_hash = SHA256(name_hash || identity_hash)[:16]
```

For destinations not bound to an identity, the destination hash is:

```text
destination_hash = SHA256(name_hash)[:16]
```

## 6. Packet Format

### 6.1 Top-Level Layout

The protocol defines two packet header layouts.

`HEADER_1`:

```text
[flags:1][hops:1][destination_hash:16][context:1][data:*]
```

`HEADER_2`:

```text
[flags:1][hops:1][transport_id:16][destination_hash:16][context:1][data:*]
```

### 6.2 Flags Byte

The flags byte packs five fields:

```text
bit 6      header_type
bit 5      context_flag
bit 4      transport_type
bits 3-2   destination_type
bits 1-0   packet_type
```

Field values:

- `header_type`: `HEADER_1 = 0`, `HEADER_2 = 1`
- `context_flag`: unset `0`, set `1`
- `transport_type`: `BROADCAST = 0`, `TRANSPORT = 1`, `RELAY = 2`, `TUNNEL = 3`
- `packet_type`: `DATA = 0`, `ANNOUNCE = 1`, `LINKREQUEST = 2`, `PROOF = 3`

### 6.3 Hashable Part

The packet hash is computed over the packet's hashable part.

Construction rules:

- start with `flags & 0x0f`
- for `HEADER_1`, append `raw[2..]`
- for `HEADER_2`, skip `transport_id` and append `raw[18..]`

The packet hash is:

```text
packet_hash = SHA256(hashable_part)
```

The truncated packet hash is:

```text
packet_truncated_hash = packet_hash[:16]
```

## 7. Packet Contexts

Defined packet contexts:

- `NONE = 0x00`
- `RESOURCE = 0x01`
- `RESOURCE_ADV = 0x02`
- `RESOURCE_REQ = 0x03`
- `RESOURCE_HMU = 0x04`
- `RESOURCE_PRF = 0x05`
- `RESOURCE_ICL = 0x06`
- `RESOURCE_RCL = 0x07`
- `CACHE_REQUEST = 0x08`
- `REQUEST = 0x09`
- `RESPONSE = 0x0a`
- `PATH_RESPONSE = 0x0b`
- `COMMAND = 0x0c`
- `COMMAND_STATUS = 0x0d`
- `CHANNEL = 0x0e`
- `KEEPALIVE = 0xfa`
- `LINKIDENTIFY = 0xfb`
- `LINKCLOSE = 0xfc`
- `LINKPROOF = 0xfd`
- `LRRTT = 0xfe`
- `LRPROOF = 0xff`

## 8. Cryptographic Token Format

The token format is:

```text
[iv:16][ciphertext:*][hmac:32]
```

Token generation:

1. split the derived key into signing key and encryption key
2. PKCS7-pad the plaintext to a 16-byte block size
3. encrypt with AES-CBC
4. compute `HMAC-SHA256(signing_key, iv || ciphertext)`
5. append the HMAC

Derived key sizes:

- 32 bytes for AES-128-CBC
- 64 bytes for AES-256-CBC

The currently enabled link mode is AES-256-CBC.

## 9. Single-Packet Encryption

To encrypt data to a `SINGLE` destination:

1. generate an ephemeral X25519 keypair
2. perform ECDH against the destination encryption public key, or a ratchet key
3. derive a token key using `HKDF-SHA256(shared_key, salt=identity_hash, context=None)`
4. encrypt the payload with the token format above
5. prepend the ephemeral public key

The resulting ciphertext token is:

```text
[ephemeral_x25519_pub:32][token:*]
```

The receiver:

1. extracts the 32-byte ephemeral public key
2. derives the same shared key with its private key, or a stored ratchet key
3. derives the token key
4. verifies HMAC
5. decrypts and unpads the ciphertext

## 10. Announce Format

Announces are not encrypted. The destination hash remains in the packet header.

Announce payload without ratchet:

```text
[public_key:64][name_hash:10][random_hash:10][signature:64][app_data:*]
```

Announce payload with ratchet, indicated by `context_flag = 1`:

```text
[public_key:64][name_hash:10][random_hash:10][ratchet:32][signature:64][app_data:*]
```

Signature input:

```text
signed_data =
    destination_hash ||
    public_key ||
    name_hash ||
    random_hash ||
    ratchet? ||
    app_data?
```

Validation rules:

1. parse the payload according to `context_flag`
2. construct the announcing identity from `public_key`
3. verify the Ed25519 signature
4. compute `identity_hash = SHA256(public_key)[:16]`
5. compute `expected_hash = SHA256(name_hash || identity_hash)[:16]`
6. reject if `expected_hash != destination_hash`

If a ratchet key is present, it becomes the newest known ratchet for the
destination.

`random_hash` is a 10-byte freshness discriminator used by transport nodes to
reject repeated announces.

## 11. Link Establishment

### 11.1 Link Modes

Defined link modes:

- `AES128_CBC = 0x00`
- `AES256_CBC = 0x01`
- `0x02` through `0x07` are reserved in `RNS-Compat/1`

The current interoperable profile enables:

- `AES128_CBC`
- `AES256_CBC`

Receivers implementing `RNS-Compat/1` MUST reject unknown mode values.

### 11.2 LINKREQUEST

The initiator generates:

- ephemeral X25519 keypair for the link
- ephemeral Ed25519 keypair for the link

LINKREQUEST payload:

```text
[link_x25519_pub:32][link_ed25519_pub:32][signalling?:3]
```

The optional 3-byte signalling field encodes:

- MTU in 21 bits
- mode in 3 bits

The `link_id` is:

```text
link_id = SHA256(hashable_part_without_optional_signalling)[:16]
```

### 11.3 LRPROOF

The responder:

1. parses the request
2. computes `link_id`
3. generates a responder X25519 keypair
4. derives the session key using X25519 + HKDF-SHA256 with `salt = link_id`
5. signs the proof with the destination's long-term Ed25519 signing key

LRPROOF payload:

```text
[signature:64][responder_x25519_pub:32][signalling?:3]
```

Signature input:

```text
link_id || responder_x25519_pub || destination_ed25519_pub || signalling?
```

The initiator validates the signature using the destination's known Ed25519
public key, performs the same ECDH, derives the same session key, and activates
the link.

### 11.4 Link State Machine

The link state machine is asymmetric during establishment.

Initiator-side behavior:

1. create a local pending link
2. transmit `LINKREQUEST`
3. on valid `LRPROOF`, derive the session key
4. transition immediately from `Pending` to `Active`
5. send encrypted `LRRTT`

Responder-side behavior:

1. on valid `LINKREQUEST`, create a responder link in `Handshake`
2. derive the session key
3. transmit `LRPROOF`
4. remain in `Handshake` until a valid encrypted `LRRTT` is received
5. transition from `Handshake` to `Active`

### 11.5 LRRTT

After successful LRPROOF validation, the initiator sends an encrypted RTT
measurement payload encoded as msgpack float64:

```text
[0xcb][rtt_be_f64:8]
```

The responder decrypts this payload, computes the final RTT as:

```text
max(local_measured_rtt, initiator_reported_rtt)
```

and only then marks the link active.

### 11.6 Link Session Key

The link session key is derived from the raw X25519 shared secret:

```text
derived_key = HKDF-SHA256(shared_key, salt=link_id, context=None, length=mode_length)
```

The link token uses that derived key directly.

## 12. Link Data and Control

Packets addressed to a link use destination type `LINK`.

Encrypted link payloads use the link session token format. The following contexts
are defined for control traffic:

- `KEEPALIVE`
- `LINKIDENTIFY`
- `LINKCLOSE`
- `LINKPROOF`
- `LRRTT`

`LINKIDENTIFY` carries:

```text
[identity_public_key:64][signature:64]
```

where the signature input is:

```text
link_id || identity_public_key
```

This reveals the initiator identity only to the remote link peer, not to the
transport layer.

## 13. Proofs

Packet proofs are sent as `PROOF` packets.

The explicit proof format is:

```text
[packet_hash:32][signature:64]
```

where the signature is over `packet_hash`.

The current interoperable profile uses explicit proofs.

## 14. Resource Transfer

Resource transfer is performed over a link and is used for payloads that exceed
single-packet limits.

The resource subsystem consists of:

- `RESOURCE_ADV`: advertisement
- `RESOURCE_REQ`: part request
- `RESOURCE_HMU`: hash map update
- `RESOURCE_PRF`: proof of completion
- `RESOURCE_ICL`: initiator cancel
- `RESOURCE_RCL`: receiver cancel

Resource transfer is a distinct subprotocol carried by the packet context
system.

### 14.1 Resource Constants

`RNS-Compat/1` uses the following resource constants:

- map-hash length: 4 bytes
- random prefix length inside encrypted payload: 4 bytes
- resource SDU: 464 bytes
- maximum hashmap entries per advertisement segment: 74
- hashmap exhaustion flag values:
  - `0x00` = not exhausted
  - `0xff` = exhausted

### 14.2 Sender-Side Data Preparation

To prepare a resource for transfer:

1. start from application data bytes
2. if metadata is present, prepend a 3-byte big-endian metadata length, then the
   metadata bytes, then the application data
3. optionally compress that assembled plaintext
4. prepend a 4-byte random prefix to the compressed-or-uncompressed payload
5. encrypt the result using the enclosing link's encryption function
6. split the encrypted byte stream into parts of at most 464 bytes
7. compute a 4-byte map hash for each part

Metadata framing:

```text
[metadata_len_be24:3][metadata:*][application_data:*]
```

Part map hash:

```text
map_hash = SHA256(part_data || random_hash)[:4]
```

Resource hash:

```text
resource_hash = SHA256(unencrypted_data || random_hash)
```

Expected resource proof:

```text
expected_proof = SHA256(unencrypted_data || resource_hash)
```

where `unencrypted_data` means the metadata-prefixed plaintext before
compression/encryption and `random_hash` is the 4-byte resource random hash used
for map hashing and resource hash computation.

### 14.3 Advertisement Payload

The advertisement payload is MessagePack-encoded as a map with string keys. Key
order for the compatible profile is:

```text
t, d, n, h, r, o, i, l, q, f, m
```

Fields:

- `t`: transfer size, unsigned integer
- `d`: unencrypted data size, unsigned integer
- `n`: number of parts, unsigned integer
- `h`: full 32-byte resource hash, binary
- `r`: 4-byte random hash, binary
- `o`: original hash, binary
- `i`: segment index, unsigned integer, 1-based
- `l`: total segments, unsigned integer
- `q`: request id, binary or nil
- `f`: advertisement flags, unsigned integer
- `m`: hashmap segment bytes, binary

Advertisement flags:

```text
bit 0  encrypted
bit 1  compressed
bit 2  split
bit 3  is_request
bit 4  is_response
bit 5  has_metadata
```

The hashmap segment is the concatenation of consecutive 4-byte part map hashes.

### 14.4 Advertisement Semantics

The sender advertises the first hashmap segment first. If the complete hashmap
does not fit in a single advertisement, additional segments are supplied through
HMU packets described below.

`original_hash` is the first segment hash for multi-segment resources. For a
single-segment resource it equals `resource_hash`.

### 14.5 Part Request Payload

`RESOURCE_REQ` is link-encrypted before transport.

Request payload format:

```text
[hashmap_exhausted:1]
[last_map_hash:4 if exhausted]
[resource_hash:32]
[requested_map_hashes:(N*4)]
```

Rules:

- if `hashmap_exhausted == 0x00`, `last_map_hash` is omitted
- if `hashmap_exhausted == 0xff`, `last_map_hash` MUST be present
- `requested_map_hashes` is a concatenation of 4-byte map hashes for requested
  parts

The receiver builds requests by scanning forward from the current consecutive
completion point. If it reaches unknown hashmap entries, it sets
`hashmap_exhausted = 0xff`, includes the last known map hash, and waits for an
HMU before requesting more parts.

### 14.6 Resource Parts

Each `RESOURCE` packet carries one encrypted part exactly as sliced from the
sender's encrypted resource byte stream.

There is no additional per-part framing beyond the packet context.

The receiver identifies a part by computing:

```text
SHA256(part_data || random_hash)[:4]
```

and matching it against expected hashes in its current request window.

### 14.7 HMU Payload

`RESOURCE_HMU` is link-encrypted before transport.

HMU format:

```text
[resource_hash:32][msgpack([segment, hashmap_segment])]
```

where:

- `segment` is the zero-based hashmap segment index
- `hashmap_segment` is a binary blob containing consecutive 4-byte map hashes

The sender only emits HMU data when the receiver explicitly reports hashmap
exhaustion in a `RESOURCE_REQ`.

### 14.8 Completion Proof Payload

`RESOURCE_PRF` is not additionally encrypted at the packet layer.

Proof payload format:

```text
[resource_hash:32][proof:32]
```

where:

```text
proof = SHA256(unencrypted_data || resource_hash)
```

Compatibility note: in `RNS-Compat/1`, proof validation checks only the trailing
32-byte `proof` value against the locally expected proof. The leading
`resource_hash` field is present on wire but is not part of the current
validation decision.

### 14.9 Cancel Payloads

`RESOURCE_ICL` and `RESOURCE_RCL` both carry:

```text
[resource_hash:32]
```

Semantics:

- `RESOURCE_ICL`: sender cancels an in-flight transfer
- `RESOURCE_RCL`: receiver rejects or cancels a transfer

### 14.10 Receiver Assembly Rules

After all parts are received:

1. concatenate parts in part-index order
2. decrypt the concatenated encrypted byte stream
3. remove the leading 4-byte random prefix
4. if the advertisement marked `compressed`, decompress the remaining bytes
5. compute `resource_hash = SHA256(unencrypted_data || random_hash)` and verify
   it matches the advertised resource hash
6. compute the expected proof as `SHA256(unencrypted_data || resource_hash)`
7. emit `RESOURCE_PRF`
8. if `has_metadata` is set and `segment_index == 1`, parse the leading metadata
   block as `[len_be24][metadata][data]`

If the hash check fails, the resource is corrupt and the transfer fails.

### 14.11 Multi-Segment Resources

If a resource is split across multiple resource segments:

- the advertisement `split` flag is set
- `segment_index` is 1-based
- `total_segments` gives the total number of segments
- `original_hash` identifies the first segment

Segment coordination and higher-level reassembly are above the single-resource
packet formats defined here, but every segment individually follows the same
advertisement, request, part, HMU, and proof rules.

## 15. Transport Behavior

### 15.1 Core Transport Rules

Transport nodes:

- learn paths from validated announces
- forward transport traffic toward known destinations
- store reverse paths for proofs and responses
- maintain link routing state keyed by `link_id`

### 15.2 Path Freshness

Each path entry stores:

- destination hash
- next hop
- hop count
- expiry time
- a bounded set of seen `random_hash` values
- receiving interface

An incoming announce is admissible when:

- it is not for a local destination
- hop count is at most 128
- signature and destination binding validate
- its `random_hash` has not already been seen for the current path state
- it is not blocked by announce rate limiting or ingress control

### 15.3 Path Expiry

Default path expiry:

- normal interfaces: 7 days
- access point mode: 1 day
- roaming mode: 6 hours
- internal mode: normal 7 day expiry

Interface mode values:

- full: `0x01`
- point-to-point: `0x02`
- access point: `0x03`
- roaming: `0x04`
- boundary: `0x05`
- gateway: `0x06`
- internal: `0x07`

Transport nodes perform recursive path discovery for path requests received on
access point, gateway, roaming and internal interfaces. The per-interface
`recursive_prs` option can enable recursive path discovery regardless of the
configured mode.

For announce propagation, internal interfaces designate networks that belong to
a network different from any marked as boundary. Announces from boundary or
roaming interfaces do not propagate to internal interfaces, but announces from
internal interfaces can propagate to boundary interfaces.

### 15.4 Retransmission

Validated announces may be queued for retransmission with:

- up to 1 retransmit retry
- a random grace window up to 0.5 seconds
- local rebroadcast cap of 2

### 15.5 Deduplication

Transport nodes maintain a packet hash list for duplicate suppression.

### 15.6 Blackholing and Ingress Control

Nodes may locally suppress traffic from selected identity hashes. This is a
local policy feature, not a global protocol censorship mechanism.

Nodes may also hold or drop announces based on interface-local ingress control
thresholds.

## 16. Compatibility Profile

This document currently specifies the `RNS-Compat/1` profile:

- MTU 500
- 128-bit truncated destination hashes
- announce format as defined in Section 10
- packet layout as defined in Section 6
- explicit proofs
- AES-256-CBC link mode enabled by default
- transport heuristics as defined in Section 15

Future profiles may define distinct packet layouts, AEAD-based framing, revised
announce freshness rules, or different extension negotiation.

## 17. Extensions

Extensions MUST NOT silently change the meaning of core packet types or contexts.

`rns-rs` currently implements non-core extensions outside this document, notably:

- direct UDP link upgrade
- WASM transport hooks

These extensions are explicitly non-normative for `RNS-Compat/1`.

## 18. Security Considerations

This protocol provides:

- confidentiality for `SINGLE` destinations and links
- destination authentication through signed announces
- initiator anonymity at the transport layer
- per-packet or per-link forward secrecy where ephemeral keys are used

Known limitations of the current compatible profile:

- destination hashes remain visible in packet headers for routing
- announce replay resistance is heuristic, not globally sequenced
- the compatible token format uses CBC + HMAC rather than a modern AEAD
- open networks remain susceptible to resource-exhaustion attacks

## 19. Out of Scope

The following are not part of this protocol specification:

- CLI command names
- daemon RPC layout
- local identity file paths
- local path table persistence format
- log message wording
- app store distribution terms

## 20. Next Steps

To evolve this specification into a standalone protocol standard, the next work
items should be:

1. define resource subprotocol messages in full
2. define a machine-readable packet and state-model appendix
3. separate normative constants from implementation-derived heuristics
4. publish conformance vectors derived from this document rather than from code

## Appendix A. Conformance Vectors

This appendix records canonical vectors that an independent implementation can
use to validate packet encoding, announce construction, link handshake
derivation, and resource advertisement encoding.

The authoritative machine-readable vector files currently live in:

- `tests/fixtures/protocol/packet_vectors.json`
- `tests/fixtures/protocol/announce_vectors.json`
- `tests/fixtures/link/link_handshake_vectors.json`
- `tests/fixtures/resource/advertisement_vectors.json`

The vectors below are representative anchors. A conforming implementation
should reproduce these values exactly.

### A.1 Packet Encoding Vector

Description: `h1_data_single`

Fields:

```text
header_type      = 0
context_flag     = 0
transport_type   = 0
destination_type = 0
packet_type      = 0
hops             = 0
destination_hash = 11111111111111111111111111111111
context          = 00
data             = 68656c6c6f20776f726c64
```

Expected raw packet:

```text
0000111111111111111111111111111111110068656c6c6f20776f726c64
```

Expected hashable part:

```text
00111111111111111111111111111111110068656c6c6f20776f726c64
```

Expected packet hash:

```text
8d3c3f2870fce596d23948839542d9d1280180dba0a2349ade61111f47be4723
```

Expected truncated packet hash:

```text
8d3c3f2870fce596d23948839542d9d1
```

### A.2 Announce Encoding Vector

Description: `no_ratchet_no_appdata`

Fields:

```text
public_key       = 8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7
identity_hash    = aca31af0441d81dbec71e82da0b4b5f5
name_hash        = 675555a31d5cc7a9cfd6
destination_hash = 452471d74137d6380aa232f1ea1765cf
random_hash      = aaaaaaaaaaaaaaaaaaaa
```

Expected signature:

```text
e3003008aff37426520812471d887f8b6125cd6e32b1e3561bc42a63ff04b08f5d9c45429fda01876298f4659b51aa30f02c8c71d3a0980de7821b8f2cfc630b
```

Expected announce payload:

```text
8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7675555a31d5cc7a9cfd6aaaaaaaaaaaaaaaaaaaae3003008aff37426520812471d887f8b6125cd6e32b1e3561bc42a63ff04b08f5d9c45429fda01876298f4659b51aa30f02c8c71d3a0980de7821b8f2cfc630b
```

### A.3 Link Handshake Vector

Description: `handshake_aes256_cbc`

Fields:

```text
mode                   = 1
dest_hash              = 310f23ba06979cf967cb060b1972df16
initiator_x25519_pub   = 8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f
initiator_ed25519_pub  = 29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7
responder_x25519_pub   = e8980c4ea5ebf8fb6c281098b75cdd32862922a638778251979b6d322ed7e02e
destination_ed25519_pub= 7d59c5623dd40a74aa4d5a32ac645d3b3f95daeae4c22be25476dd6a486f7382
signalling_bytes       = 2001f4
link_id                = 0eed4280e7770b8157cd66fac3f9b8d0
shared_key             = 97e68feaf1f54b3f7bdb458f7c7e3cb2b4c8f8d4afac4dff031e7bf8b5fdfe3c
```

Expected derived key:

```text
6080e432a453d453938cc0ebd1e53f73a5d48e5f21c6dd9c7db7db7da41337c4c2059963e08e4b9d8073d2fcc6c51f2de39c81fc09d2e7a4ebeda4340b556bb3
```

Expected LRPROOF payload:

```text
5243f11746c113379c1dc0aa191d781e91f2923b12aa724ddf075d643fc00e3c20986c6f58f149b6f707a005d959da725033aa03ae2748fac541945b8851050fe8980c4ea5ebf8fb6c281098b75cdd32862922a638778251979b6d322ed7e02e2001f4
```

### A.4 Resource Advertisement Vector

Description: `simple_advertisement`

Fields:

```text
transfer_size = 1000
data_size     = 900
num_parts     = 3
resource_hash = 1111111111111111111111111111111111111111111111111111111111111111
random_hash   = aabbccdd
original_hash = 1111111111111111111111111111111111111111111111111111111111111111
flags         = 0x01
segment_index = 1
total_segments= 1
hashmap       = 010203040102030401020304
```

Expected packed advertisement:

```text
8ba174cd03e8a164cd0384a16e03a168c4201111111111111111111111111111111111111111111111111111111111111111a172c404aabbccdda16fc4201111111111111111111111111111111111111111111111111111111111111111a16601a16901a16c01a171c0a16dc40c010203040102030401020304
```

### A.5 Vector Policy

Future revisions should add vectors for:

- additional proof validation edge cases
- timeout/retry edge cases
- multi-segment resource request sequences

Independent implementations should treat the machine-readable vector files as
test fixtures, not as the normative source of protocol meaning. The normative
source remains this specification.

### A.6 LINKIDENTIFY Vector

Description: `identity_range`

Fields:

```text
link_id     = 0eed4280e7770b8157cd66fac3f9b8d0
public_key  = 8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7
```

Expected signature input:

```text
0eed4280e7770b8157cd66fac3f9b8d08f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7
```

Expected plaintext payload:

```text
8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7ba4ce9320ee5094486a65af6bd111639d3df9b701c350748e11df5dfe884e1bfa6c983bd5e211bf0fa66eab28b8d5898a8343876d47010db6ddaf32b86e3c60f
```

For a derived key of:

```text
6080e432a453d453938cc0ebd1e53f73a5d48e5f21c6dd9c7db7db7da41337c4c2059963e08e4b9d8073d2fcc6c51f2de39c81fc09d2e7a4ebeda4340b556bb3
```

and fixed IV:

```text
dddddddddddddddddddddddddddddddd
```

the expected encrypted payload is:

```text
ddddddddddddddddddddddddddddddddb86d81dd6ab97f6204bd68fd7fcfe7c2630f4286f09094c31a9f21533de96a38c33baacefa870395f5a6fef84cb3539e270349f7235ed443c7dce00670ce92499f34e8dbd8a493fd23599a76b1bf1c1aeffcda2941cef713d23dada493209af470dfe640e6f3e11bbbf86496b42e16c7b6d9a322606c6ab1b9e13d38106b8189cffd0b16eb1a536e8326e6a649e9c62cc41d6f4c008c1f5517177da4965a8e51e54a826cd6df456f6e595895431b8e23
```

### A.7 Resource Proof Vector

Description: `small_data`

Fields:

```text
data        = 7265736f757263652064617461
random_hash = aabbccdd
```

Expected resource hash:

```text
f833e4de9045577fa75ec3f9870f278c6ad73b9d18aab838867d3213bc22f861
```

Expected proof:

```text
972c84a8b1074a2a0ecd6de4a9f1fcc2c60c84df3ea5e7e9cc01f8a6b103c1e3
```

Expected `RESOURCE_PRF` payload:

```text
f833e4de9045577fa75ec3f9870f278c6ad73b9d18aab838867d3213bc22f861972c84a8b1074a2a0ecd6de4a9f1fcc2c60c84df3ea5e7e9cc01f8a6b103c1e3
```

### A.8 HMU Vector

Description: `segment_1`

Fields:

```text
resource_hash = 1111111111111111111111111111111111111111111111111111111111111111
segment       = 1
hashmap_bytes = 01020304010203040102030401020304010203040102030401020304010203040102030401020304
```

Expected MessagePack payload:

```text
9201c42801020304010203040102030401020304010203040102030401020304010203040102030401020304
```

Expected full `RESOURCE_HMU` payload:

```text
11111111111111111111111111111111111111111111111111111111111111119201c42801020304010203040102030401020304010203040102030401020304010203040102030401020304
```

### A.9 Resource Request Vector

The receiver constructs `RESOURCE_REQ` payloads directly; this vector is
canonical for the request format.

Example:

```text
hashmap_exhausted = 00
resource_hash     = 1111111111111111111111111111111111111111111111111111111111111111
requested_hashes  = 01020304aabbccdd
```

Expected `RESOURCE_REQ` plaintext:

```text
00111111111111111111111111111111111111111111111111111111111111111101020304aabbccdd
```

Exhaustion example:

```text
hashmap_exhausted = ff
last_map_hash     = 01020304
resource_hash     = 1111111111111111111111111111111111111111111111111111111111111111
requested_hashes  = aabbccdd
```

Expected `RESOURCE_REQ` plaintext:

```text
ff010203041111111111111111111111111111111111111111111111111111111111111111aabbccdd
```
