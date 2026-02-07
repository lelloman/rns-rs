#!/usr/bin/env python3
"""
Generate JSON test vectors from Python RNS crypto for Rust interop testing.
Uses PROVIDER_INTERNAL (pure Python) to ensure we test against the same code path.
"""

import json
import os
import sys

# Add the parent Reticulum directory to path so we can import RNS
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Force internal provider before importing RNS modules
import RNS.Cryptography.Provider as cp
cp.PROVIDER = cp.PROVIDER_INTERNAL

from RNS.Cryptography.PKCS7 import PKCS7
from RNS.Cryptography.SHA256 import sha256
from RNS.Cryptography.SHA512 import sha512
from RNS.Cryptography import HMAC
from RNS.Cryptography.HKDF import hkdf
from RNS.Cryptography.aes.aes128 import AES128
from RNS.Cryptography.aes.aes256 import AES256
from RNS.Cryptography.X25519 import X25519PrivateKey, X25519PublicKey
from RNS.Cryptography.Ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Reload AES module now that PROVIDER is set to internal
import importlib
import RNS.Cryptography.AES
importlib.reload(RNS.Cryptography.AES)
from RNS.Cryptography.Token import Token

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'crypto')
os.makedirs(FIXTURE_DIR, exist_ok=True)

PROTOCOL_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'protocol')
os.makedirs(PROTOCOL_DIR, exist_ok=True)


def to_hex(data):
    if isinstance(data, (bytes, bytearray)):
        return data.hex()
    return data


def write_fixture(name, data):
    path = os.path.join(FIXTURE_DIR, name)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Written {path} ({len(data)} vectors)")


def generate_pkcs7():
    vectors = []
    for desc, data, bs in [
        ("hello_16", b"hello", 16),
        ("empty_16", b"", 16),
        ("aligned_16", b"0123456789abcdef", 16),
        ("short_16", b"a", 16),
        ("two_blocks", b"0123456789abcdef0", 16),
    ]:
        padded = PKCS7.pad(data, bs)
        unpadded = PKCS7.unpad(padded, bs)
        vectors.append({
            "description": desc,
            "input": to_hex(data),
            "block_size": bs,
            "padded": to_hex(padded),
            "unpadded": to_hex(unpadded),
        })
    write_fixture("pkcs7_vectors.json", vectors)


def generate_sha256():
    vectors = []
    for desc, data in [
        ("empty", b""),
        ("abc", b"abc"),
        ("1000_a", b"a" * 1000),
        ("hello_world", b"Hello, World!"),
        ("64_bytes", bytes(range(64))),
        ("65_bytes", bytes(range(65))),
        ("128_bytes", bytes(range(128))),
    ]:
        digest = sha256(data).digest()
        vectors.append({
            "description": desc,
            "input": to_hex(data),
            "digest": to_hex(digest),
        })
    write_fixture("sha256_vectors.json", vectors)


def generate_sha512():
    vectors = []
    for desc, data in [
        ("empty", b""),
        ("abc", b"abc"),
        ("hello_world", b"Hello, World!"),
        ("128_bytes", bytes(range(128))),
        ("129_bytes", bytes(range(129))),
        ("256_bytes", bytes(range(256))),
    ]:
        digest = sha512(data).digest()
        vectors.append({
            "description": desc,
            "input": to_hex(data),
            "digest": to_hex(digest),
        })
    write_fixture("sha512_vectors.json", vectors)


def generate_hmac():
    vectors = []
    for desc, key, data in [
        ("basic", b"secret_key", b"message"),
        ("empty_msg", b"key", b""),
        ("long_key", b"k" * 100, b"data"),
        ("short_key", b"k", b"data"),
        ("rfc4231_1", bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), b"Hi There"),
        ("rfc4231_2", b"Jefe", b"what do ya want for nothing?"),
    ]:
        result = HMAC.new(key, data).digest()
        vectors.append({
            "description": desc,
            "key": to_hex(key),
            "data": to_hex(data),
            "digest": to_hex(result),
        })
    write_fixture("hmac_vectors.json", vectors)


def generate_hkdf():
    vectors = []
    for desc, length, ikm, salt, context in [
        ("32_bytes_with_salt", 32, b"input key material", b"salt value", None),
        ("64_bytes_with_salt", 64, b"input key material", b"salt value", None),
        ("32_bytes_with_context", 32, b"input key material", b"salt", b"context info"),
        ("32_bytes_none_salt", 32, b"input key material", None, None),
        ("32_bytes_empty_salt", 32, b"input key material", b"", None),
        ("16_bytes", 16, b"short ikm here", b"salt", None),
        ("48_bytes", 48, b"medium length input key material", b"longer salt value", b"ctx"),
    ]:
        result = hkdf(length=length, derive_from=ikm, salt=salt, context=context)
        vectors.append({
            "description": desc,
            "length": length,
            "ikm": to_hex(ikm),
            "salt": to_hex(salt) if salt is not None else None,
            "context": to_hex(context) if context is not None else None,
            "derived": to_hex(result),
        })
    write_fixture("hkdf_vectors.json", vectors)


def generate_aes128():
    vectors = []
    for desc, key_hex, iv_hex, plaintext_hex in [
        ("nist_vector", "2b7e151628aed2a6abf7158809cf4f3c",
         "000102030405060708090a0b0c0d0e0f",
         "6bc1bee22e409f96e93d7e117393172a"),
        ("zeros", "00000000000000000000000000000000",
         "00000000000000000000000000000000",
         "00000000000000000000000000000000"),
        ("two_blocks", "01020304050607080102030405060708",
         "0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d",
         "00112233445566778899aabbccddeeff" + "ffeeddccbbaa99887766554433221100"),
    ]:
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        plaintext = bytes.fromhex(plaintext_hex)
        cipher = AES128(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        decrypted = cipher.decrypt(ciphertext, iv)
        assert decrypted == plaintext, f"AES128 roundtrip failed for {desc}"
        vectors.append({
            "description": desc,
            "key": key_hex,
            "iv": iv_hex,
            "plaintext": plaintext_hex,
            "ciphertext": to_hex(ciphertext),
        })
    write_fixture("aes128_vectors.json", vectors)


def generate_aes256():
    vectors = []
    for desc, key_hex, iv_hex, plaintext_hex in [
        ("nist_vector",
         "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
         "000102030405060708090a0b0c0d0e0f",
         "6bc1bee22e409f96e93d7e117393172a"),
        ("zeros",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "00000000000000000000000000000000",
         "00000000000000000000000000000000"),
        ("two_blocks",
         "0102030405060708010203040506070801020304050607080102030405060708",
         "0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d",
         "00112233445566778899aabbccddeeff" + "ffeeddccbbaa99887766554433221100"),
    ]:
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        plaintext = bytes.fromhex(plaintext_hex)
        cipher = AES256(key)
        ciphertext = cipher.encrypt_cbc(plaintext, iv)
        decrypted = cipher.decrypt_cbc(ciphertext, iv)
        assert decrypted == plaintext, f"AES256 roundtrip failed for {desc}"
        vectors.append({
            "description": desc,
            "key": key_hex,
            "iv": iv_hex,
            "plaintext": plaintext_hex,
            "ciphertext": to_hex(ciphertext),
        })
    write_fixture("aes256_vectors.json", vectors)


def generate_token():
    vectors = []

    # Token with 32-byte key (AES-128 mode) and fixed IV
    for desc, key_hex, iv_hex, plaintext in [
        ("aes128_hello", "00" * 32, "aa" * 16, b"Hello, Reticulum!"),
        ("aes256_hello", "00" * 64, "bb" * 16, b"Hello, Reticulum!"),
        ("aes256_empty", "ff" * 64, "cc" * 16, b""),
        ("aes256_long", "42" * 64, "dd" * 16, b"A" * 200),
    ]:
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)

        token = Token(key)

        # Monkey-patch os.urandom to return fixed IV
        original_urandom = os.urandom
        os.urandom = lambda n: iv[:n]
        try:
            ciphertext = token.encrypt(plaintext)
        finally:
            os.urandom = original_urandom

        # Verify we can decrypt
        decrypted = token.decrypt(ciphertext)
        assert decrypted == plaintext, f"Token roundtrip failed for {desc}"

        vectors.append({
            "description": desc,
            "key": key_hex,
            "iv": iv_hex,
            "plaintext": to_hex(plaintext),
            "ciphertext": to_hex(ciphertext),
        })
    write_fixture("token_vectors.json", vectors)


def generate_x25519():
    vectors = []

    # Known private keys for deterministic testing
    test_keys = [
        ("key_1", bytes(range(32))),
        ("key_2", bytes(range(32, 64))),
        ("key_all_ff", b"\xff" * 32),
        ("key_all_01", b"\x01" * 32),
    ]

    for desc, prv_bytes in test_keys:
        prv = X25519PrivateKey.from_private_bytes(prv_bytes)
        pub = prv.public_key()
        vectors.append({
            "description": desc + "_pubkey",
            "private": to_hex(prv.private_bytes()),
            "public": to_hex(pub.public_bytes()),
        })

    # Key exchange
    prv_a = X25519PrivateKey.from_private_bytes(bytes(range(32)))
    prv_b = X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    pub_a = prv_a.public_key()
    pub_b = prv_b.public_key()
    shared_ab = prv_a.exchange(pub_b)
    shared_ba = prv_b.exchange(pub_a)
    assert shared_ab == shared_ba, "X25519 exchange mismatch"
    vectors.append({
        "description": "exchange_ab",
        "private_a": to_hex(prv_a.private_bytes()),
        "public_a": to_hex(pub_a.public_bytes()),
        "private_b": to_hex(prv_b.private_bytes()),
        "public_b": to_hex(pub_b.public_bytes()),
        "shared_secret": to_hex(shared_ab),
    })

    write_fixture("x25519_vectors.json", vectors)


def generate_ed25519():
    vectors = []

    # Known seeds for deterministic testing
    test_seeds = [
        ("seed_42", bytes([42] * 32)),
        ("seed_01", bytes([1] * 32)),
        ("seed_range", bytes(range(32))),
    ]

    for desc, seed in test_seeds:
        prv = Ed25519PrivateKey.from_private_bytes(seed)
        pub = prv.public_key()
        msg = b"test message for ed25519"
        sig = prv.sign(msg)
        pub.verify(sig, msg)  # will raise if invalid

        vectors.append({
            "description": desc,
            "seed": to_hex(seed),
            "public": to_hex(pub.public_bytes()),
            "message": to_hex(msg),
            "signature": to_hex(sig),
        })

    write_fixture("ed25519_vectors.json", vectors)


def generate_identity():
    """Generate the milestone identity vectors: full encrypt/decrypt pipeline."""
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    # Known private key for deterministic testing
    x25519_prv_bytes = bytes(range(32))       # X25519 private key
    ed25519_seed = bytes(range(32, 64))        # Ed25519 seed
    prv_key = x25519_prv_bytes + ed25519_seed  # 64-byte combined key

    # Build identity from private key
    x25519_prv = X25519PrivateKey.from_private_bytes(x25519_prv_bytes)
    ed25519_prv = Ed25519PrivateKey.from_private_bytes(ed25519_seed)

    x25519_pub = x25519_prv.public_key()
    ed25519_pub = ed25519_prv.public_key()

    pub_key = x25519_pub.public_bytes() + ed25519_pub.public_bytes()
    identity_hash = rns_sha256(pub_key)[:16]  # truncated hash

    # Encrypt with known ephemeral key and IV
    ephemeral_prv_bytes = bytes([0xAA] * 32)
    fixed_iv = bytes([0xBB] * 16)

    ephemeral_prv = X25519PrivateKey.from_private_bytes(ephemeral_prv_bytes)
    ephemeral_pub = ephemeral_prv.public_key()
    shared_key = ephemeral_prv.exchange(x25519_pub)

    derived_key = hkdf(
        length=64,
        derive_from=shared_key,
        salt=identity_hash,
        context=None,
    )

    plaintext = b"Hello from Python to Rust! This is the milestone test."
    token = Token(derived_key)

    # Monkey-patch os.urandom for fixed IV
    original_urandom = os.urandom
    os.urandom = lambda n: fixed_iv[:n]
    try:
        ciphertext_token = token.encrypt(plaintext)
    finally:
        os.urandom = original_urandom

    full_ciphertext = ephemeral_pub.public_bytes() + ciphertext_token

    # Verify decrypt works
    # Reconstruct decrypt path
    peer_pub_bytes = full_ciphertext[:32]
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared_key2 = x25519_prv.exchange(peer_pub)
    derived_key2 = hkdf(length=64, derive_from=shared_key2, salt=identity_hash, context=None)
    token2 = Token(derived_key2)
    decrypted = token2.decrypt(full_ciphertext[32:])
    assert decrypted == plaintext, "Identity decrypt verification failed!"

    # Sign/verify
    msg_to_sign = b"Message to sign for identity test"
    signature = ed25519_prv.sign(msg_to_sign)
    ed25519_pub.verify(signature, msg_to_sign)

    vectors.append({
        "description": "milestone_python_to_rust",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "identity_hash": to_hex(identity_hash),
        "ephemeral_private": to_hex(ephemeral_prv.private_bytes()),
        "ephemeral_public": to_hex(ephemeral_pub.public_bytes()),
        "shared_key": to_hex(shared_key),
        "derived_key": to_hex(derived_key),
        "fixed_iv": to_hex(fixed_iv),
        "plaintext": to_hex(plaintext),
        "ciphertext": to_hex(full_ciphertext),
        "sign_message": to_hex(msg_to_sign),
        "signature": to_hex(signature),
    })

    write_fixture("identity_vectors.json", vectors)


def write_protocol_fixture(name, data):
    path = os.path.join(PROTOCOL_DIR, name)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Written {path} ({len(data)} vectors)")


def generate_hash_vectors():
    """Generate hash test vectors for rns-core hash module."""
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    test_cases = [
        ("empty", b""),
        ("test", b"test"),
        ("hello_world", b"Hello, World!"),
        ("app_aspect", b"app.aspect"),
        ("app_a_b", b"app.a.b"),
        ("long_data", bytes(range(256))),
    ]

    for desc, data in test_cases:
        full = rns_sha256(data)
        truncated = full[:16]
        vectors.append({
            "description": desc,
            "input": to_hex(data),
            "full_hash": to_hex(full),
            "truncated_hash": to_hex(truncated),
        })

    # Name hash vectors
    name_hash_cases = [
        ("app_aspect", "app", ["aspect"]),
        ("app_a_b", "app", ["a", "b"]),
        ("testapp_test", "testapp", ["test"]),
        ("lxmf_delivery", "lxmf", ["delivery"]),
    ]

    for desc, app_name, aspects in name_hash_cases:
        name_str = app_name + "." + ".".join(aspects)
        full = rns_sha256(name_str.encode("utf-8"))
        name_hash = full[:10]
        vectors.append({
            "description": "name_hash_" + desc,
            "app_name": app_name,
            "aspects": aspects,
            "name_string": name_str,
            "name_hash": to_hex(name_hash),
        })

    write_protocol_fixture("hash_vectors.json", vectors)


def generate_flags_vectors():
    """Generate packet flags test vectors."""
    import struct

    vectors = []

    test_cases = [
        # (desc, header_type, context_flag, transport_type, dest_type, pkt_type)
        ("h1_data_single_broadcast", 0x00, 0x00, 0x00, 0x00, 0x00),
        ("h2_announce_single_transport", 0x01, 0x00, 0x01, 0x00, 0x01),
        ("h1_announce_single_broadcast", 0x00, 0x00, 0x00, 0x00, 0x01),
        ("h1_data_plain_broadcast", 0x00, 0x00, 0x00, 0x02, 0x00),
        ("h1_linkrequest_single", 0x00, 0x00, 0x00, 0x00, 0x02),
        ("h1_proof_link", 0x00, 0x00, 0x00, 0x03, 0x03),
        ("h1_announce_context_set", 0x00, 0x01, 0x00, 0x00, 0x01),
        ("h2_announce_context_set", 0x01, 0x01, 0x01, 0x00, 0x01),
        ("all_bits_set", 0x01, 0x01, 0x01, 0x03, 0x03),
    ]

    for desc, ht, cf, tt, dt, pt in test_cases:
        packed = (ht << 6) | (cf << 5) | (tt << 4) | (dt << 2) | pt
        vectors.append({
            "description": desc,
            "header_type": ht,
            "context_flag": cf,
            "transport_type": tt,
            "destination_type": dt,
            "packet_type": pt,
            "packed": packed,
        })

    write_protocol_fixture("flags_vectors.json", vectors)


def generate_packet_vectors():
    """Generate packet pack/unpack test vectors."""
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    # Helper to build raw packet bytes and compute hash
    def make_packet(header_type, context_flag, transport_type, dest_type, pkt_type,
                    hops, dest_hash, transport_id, context, data):
        flags = (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (dest_type << 2) | pkt_type
        raw = bytes([flags, hops])
        if header_type == 0x01:  # HEADER_2
            raw += transport_id
        raw += dest_hash
        raw += bytes([context])
        raw += data

        # Compute hashable part
        hashable = bytes([raw[0] & 0x0F])
        if header_type == 0x01:
            hashable += raw[18:]  # skip flags + hops + transport_id (16 bytes)
        else:
            hashable += raw[2:]   # skip flags + hops

        packet_hash = rns_sha256(hashable)
        truncated = packet_hash[:16]

        return raw, hashable, packet_hash, truncated

    # Test case 1: HEADER_1 DATA
    dest_hash = bytes([0x11] * 16)
    data = b"hello world"
    raw, hashable, phash, thash = make_packet(0x00, 0x00, 0x00, 0x00, 0x00, 0, dest_hash, None, 0x00, data)
    vectors.append({
        "description": "h1_data_single",
        "header_type": 0x00,
        "context_flag": 0x00,
        "transport_type": 0x00,
        "destination_type": 0x00,
        "packet_type": 0x00,
        "hops": 0,
        "destination_hash": to_hex(dest_hash),
        "transport_id": None,
        "context": 0x00,
        "data": to_hex(data),
        "raw": to_hex(raw),
        "hashable_part": to_hex(hashable),
        "packet_hash": to_hex(phash),
        "truncated_hash": to_hex(thash),
    })

    # Test case 2: HEADER_1 ANNOUNCE with context_flag set
    dest_hash = bytes([0x22] * 16)
    data = b"announce data payload"
    raw, hashable, phash, thash = make_packet(0x00, 0x01, 0x00, 0x00, 0x01, 3, dest_hash, None, 0x00, data)
    vectors.append({
        "description": "h1_announce_context_set",
        "header_type": 0x00,
        "context_flag": 0x01,
        "transport_type": 0x00,
        "destination_type": 0x00,
        "packet_type": 0x01,
        "hops": 3,
        "destination_hash": to_hex(dest_hash),
        "transport_id": None,
        "context": 0x00,
        "data": to_hex(data),
        "raw": to_hex(raw),
        "hashable_part": to_hex(hashable),
        "packet_hash": to_hex(phash),
        "truncated_hash": to_hex(thash),
    })

    # Test case 3: HEADER_2 ANNOUNCE with transport
    dest_hash = bytes([0x33] * 16)
    transport_id = bytes([0x44] * 16)
    data = b"transported announce"
    raw, hashable, phash, thash = make_packet(0x01, 0x00, 0x01, 0x00, 0x01, 5, dest_hash, transport_id, 0x00, data)
    vectors.append({
        "description": "h2_announce_transport",
        "header_type": 0x01,
        "context_flag": 0x00,
        "transport_type": 0x01,
        "destination_type": 0x00,
        "packet_type": 0x01,
        "hops": 5,
        "destination_hash": to_hex(dest_hash),
        "transport_id": to_hex(transport_id),
        "context": 0x00,
        "data": to_hex(data),
        "raw": to_hex(raw),
        "hashable_part": to_hex(hashable),
        "packet_hash": to_hex(phash),
        "truncated_hash": to_hex(thash),
    })

    # Test case 4: HEADER_1 with RESOURCE context
    dest_hash = bytes([0x55] * 16)
    data = b"resource data"
    raw, hashable, phash, thash = make_packet(0x00, 0x00, 0x00, 0x00, 0x00, 10, dest_hash, None, 0x01, data)
    vectors.append({
        "description": "h1_data_resource_context",
        "header_type": 0x00,
        "context_flag": 0x00,
        "transport_type": 0x00,
        "destination_type": 0x00,
        "packet_type": 0x00,
        "hops": 10,
        "destination_hash": to_hex(dest_hash),
        "transport_id": None,
        "context": 0x01,
        "data": to_hex(data),
        "raw": to_hex(raw),
        "hashable_part": to_hex(hashable),
        "packet_hash": to_hex(phash),
        "truncated_hash": to_hex(thash),
    })

    # Test case 5: HEADER_2 with context_flag set (ratchet announce)
    dest_hash = bytes([0x66] * 16)
    transport_id = bytes([0x77] * 16)
    data = b"ratchet announce"
    raw, hashable, phash, thash = make_packet(0x01, 0x01, 0x01, 0x00, 0x01, 2, dest_hash, transport_id, 0x00, data)
    vectors.append({
        "description": "h2_announce_context_flag_set",
        "header_type": 0x01,
        "context_flag": 0x01,
        "transport_type": 0x01,
        "destination_type": 0x00,
        "packet_type": 0x01,
        "hops": 2,
        "destination_hash": to_hex(dest_hash),
        "transport_id": to_hex(transport_id),
        "context": 0x00,
        "data": to_hex(data),
        "raw": to_hex(raw),
        "hashable_part": to_hex(hashable),
        "packet_hash": to_hex(phash),
        "truncated_hash": to_hex(thash),
    })

    write_protocol_fixture("packet_vectors.json", vectors)


def generate_destination_vectors():
    """Generate destination hash test vectors."""
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    # Build identity from known key
    x25519_prv_bytes = bytes(range(32))
    ed25519_seed = bytes(range(32, 64))
    x25519_prv = X25519PrivateKey.from_private_bytes(x25519_prv_bytes)
    ed25519_prv = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    pub_key = x25519_prv.public_key().public_bytes() + ed25519_prv.public_key().public_bytes()
    identity_hash = rns_sha256(pub_key)[:16]

    # expand_name tests
    expand_cases = [
        ("app_aspect", "app", ["aspect"], None),
        ("app_a_b", "app", ["a", "b"], None),
        ("with_identity", "app", ["aspect"], identity_hash),
        ("lxmf_delivery", "lxmf", ["delivery"], None),
        ("lxmf_with_id", "lxmf", ["delivery"], identity_hash),
    ]

    for desc, app_name, aspects, id_hash in expand_cases:
        name = app_name
        for aspect in aspects:
            name += "." + aspect
        if id_hash is not None:
            name += "." + id_hash.hex()

        name_hash = rns_sha256((app_name + "." + ".".join(aspects)).encode("utf-8"))[:10]

        if id_hash is not None:
            addr_material = name_hash + id_hash
        else:
            addr_material = name_hash

        dest_hash = rns_sha256(addr_material)[:16]

        vectors.append({
            "description": desc,
            "app_name": app_name,
            "aspects": aspects,
            "identity_hash": to_hex(id_hash) if id_hash is not None else None,
            "expanded_name": name,
            "name_hash": to_hex(name_hash),
            "destination_hash": to_hex(dest_hash),
        })

    write_protocol_fixture("destination_vectors.json", vectors)


def generate_announce_vectors():
    """Generate announce pack/unpack/validate test vectors."""
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    # Identity from known key
    x25519_prv_bytes = bytes(range(32))
    ed25519_seed = bytes(range(32, 64))
    prv_key = x25519_prv_bytes + ed25519_seed

    x25519_prv = X25519PrivateKey.from_private_bytes(x25519_prv_bytes)
    ed25519_prv = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    x25519_pub = x25519_prv.public_key()
    ed25519_pub = ed25519_prv.public_key()

    pub_key = x25519_pub.public_bytes() + ed25519_pub.public_bytes()
    identity_hash = rns_sha256(pub_key)[:16]

    # Test 1: Announce without ratchet, without app_data
    app_name, aspects = "testapp", ["aspect"]
    name_str = app_name + "." + ".".join(aspects)
    name_hash = rns_sha256(name_str.encode("utf-8"))[:10]
    addr_material = name_hash + identity_hash
    dest_hash = rns_sha256(addr_material)[:16]
    random_hash = bytes([0xAA] * 10)

    signed_data = dest_hash + pub_key + name_hash + random_hash
    signature = ed25519_prv.sign(signed_data)
    announce_data = pub_key + name_hash + random_hash + signature

    vectors.append({
        "description": "no_ratchet_no_appdata",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "identity_hash": to_hex(identity_hash),
        "app_name": app_name,
        "aspects": aspects,
        "name_hash": to_hex(name_hash),
        "destination_hash": to_hex(dest_hash),
        "random_hash": to_hex(random_hash),
        "ratchet": None,
        "app_data": None,
        "has_ratchet": False,
        "signed_data": to_hex(signed_data),
        "signature": to_hex(signature),
        "announce_data": to_hex(announce_data),
        "valid": True,
    })

    # Test 2: Announce with app_data, no ratchet
    app_data = b"Hello from test announce"
    signed_data2 = dest_hash + pub_key + name_hash + random_hash + app_data
    signature2 = ed25519_prv.sign(signed_data2)
    announce_data2 = pub_key + name_hash + random_hash + signature2 + app_data

    vectors.append({
        "description": "no_ratchet_with_appdata",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "identity_hash": to_hex(identity_hash),
        "app_name": app_name,
        "aspects": aspects,
        "name_hash": to_hex(name_hash),
        "destination_hash": to_hex(dest_hash),
        "random_hash": to_hex(random_hash),
        "ratchet": None,
        "app_data": to_hex(app_data),
        "has_ratchet": False,
        "signed_data": to_hex(signed_data2),
        "signature": to_hex(signature2),
        "announce_data": to_hex(announce_data2),
        "valid": True,
    })

    # Test 3: Announce with ratchet
    ratchet = bytes([0xCC] * 32)
    signed_data3 = dest_hash + pub_key + name_hash + random_hash + ratchet
    signature3 = ed25519_prv.sign(signed_data3)
    announce_data3 = pub_key + name_hash + random_hash + ratchet + signature3

    vectors.append({
        "description": "with_ratchet_no_appdata",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "identity_hash": to_hex(identity_hash),
        "app_name": app_name,
        "aspects": aspects,
        "name_hash": to_hex(name_hash),
        "destination_hash": to_hex(dest_hash),
        "random_hash": to_hex(random_hash),
        "ratchet": to_hex(ratchet),
        "app_data": None,
        "has_ratchet": True,
        "signed_data": to_hex(signed_data3),
        "signature": to_hex(signature3),
        "announce_data": to_hex(announce_data3),
        "valid": True,
    })

    # Test 4: Announce with ratchet AND app_data
    signed_data4 = dest_hash + pub_key + name_hash + random_hash + ratchet + app_data
    signature4 = ed25519_prv.sign(signed_data4)
    announce_data4 = pub_key + name_hash + random_hash + ratchet + signature4 + app_data

    vectors.append({
        "description": "with_ratchet_and_appdata",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "identity_hash": to_hex(identity_hash),
        "app_name": app_name,
        "aspects": aspects,
        "name_hash": to_hex(name_hash),
        "destination_hash": to_hex(dest_hash),
        "random_hash": to_hex(random_hash),
        "ratchet": to_hex(ratchet),
        "app_data": to_hex(app_data),
        "has_ratchet": True,
        "signed_data": to_hex(signed_data4),
        "signature": to_hex(signature4),
        "announce_data": to_hex(announce_data4),
        "valid": True,
    })

    write_protocol_fixture("announce_vectors.json", vectors)


def generate_proof_vectors():
    """Generate proof validation test vectors."""
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    # Identity from known key
    x25519_prv_bytes = bytes(range(32))
    ed25519_seed = bytes(range(32, 64))
    prv_key = x25519_prv_bytes + ed25519_seed

    ed25519_prv = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    ed25519_pub = ed25519_prv.public_key()

    x25519_pub = X25519PrivateKey.from_private_bytes(x25519_prv_bytes).public_key()
    pub_key = x25519_pub.public_bytes() + ed25519_pub.public_bytes()

    packet_hash = rns_sha256(b"test packet data for proof")

    # Test 1: Valid explicit proof
    signature = ed25519_prv.sign(packet_hash)
    explicit_proof = packet_hash + signature

    vectors.append({
        "description": "valid_explicit",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "packet_hash": to_hex(packet_hash),
        "proof": to_hex(explicit_proof),
        "proof_type": "explicit",
        "result": "valid",
    })

    # Test 2: Valid implicit proof
    implicit_proof = signature

    vectors.append({
        "description": "valid_implicit",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "packet_hash": to_hex(packet_hash),
        "proof": to_hex(implicit_proof),
        "proof_type": "implicit",
        "result": "valid",
    })

    # Test 3: Explicit proof with wrong hash
    wrong_hash = rns_sha256(b"wrong data")
    wrong_proof = wrong_hash + signature

    vectors.append({
        "description": "explicit_wrong_hash",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "packet_hash": to_hex(packet_hash),
        "proof": to_hex(wrong_proof),
        "proof_type": "explicit",
        "result": "invalid_hash",
    })

    # Test 4: Explicit proof with bad signature
    bad_sig = bytes([0xFF] * 64)
    bad_proof = packet_hash + bad_sig

    vectors.append({
        "description": "explicit_bad_signature",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "packet_hash": to_hex(packet_hash),
        "proof": to_hex(bad_proof),
        "proof_type": "explicit",
        "result": "invalid_signature",
    })

    # Test 5: Wrong length
    vectors.append({
        "description": "wrong_length",
        "private_key": to_hex(prv_key),
        "public_key": to_hex(pub_key),
        "packet_hash": to_hex(packet_hash),
        "proof": to_hex(bytes([0] * 50)),
        "proof_type": "unknown",
        "result": "invalid_length",
    })

    write_protocol_fixture("proof_vectors.json", vectors)


TRANSPORT_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'transport')
os.makedirs(TRANSPORT_DIR, exist_ok=True)


def write_transport_fixture(name, data):
    path = os.path.join(TRANSPORT_DIR, name)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Written {path} ({len(data)} vectors)")


def generate_pathfinder_vectors():
    """Generate pathfinder/timebase extraction test vectors."""
    import struct

    vectors = []

    # Timebase extraction: random_blob bytes [5:10] as big-endian u64
    # In Python: Transport.py:2930-2952
    # announce_emitted = int.from_bytes(random_hash[5:10], "big")
    test_blobs = [
        ("zero_timebase", bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x00, 0x00, 0x00, 0x00])),
        ("small_timebase", bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00, 0x00, 0x01])),
        ("medium_timebase", bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00])),
        ("large_timebase", bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])),
        ("typical_timestamp", bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x00, 0x00, 0x60, 0xD8])),
    ]

    for desc, blob in test_blobs:
        timebase = int.from_bytes(blob[5:10], "big")
        vectors.append({
            "description": desc,
            "random_blob": to_hex(blob),
            "timebase": timebase,
        })

    write_transport_fixture("pathfinder_vectors.json", vectors)


def generate_announce_retransmit_vectors():
    """Generate announce retransmit packet building test vectors."""
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    # Identity from known key
    x25519_prv_bytes = bytes(range(32))
    ed25519_seed = bytes(range(32, 64))

    x25519_prv = X25519PrivateKey.from_private_bytes(x25519_prv_bytes)
    ed25519_prv = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    x25519_pub = x25519_prv.public_key()
    ed25519_pub = ed25519_prv.public_key()

    pub_key = x25519_pub.public_bytes() + ed25519_pub.public_bytes()
    identity_hash = rns_sha256(pub_key)[:16]

    # Build a real announce to retransmit
    app_name, aspects = "testapp", ["aspect"]
    name_str = app_name + "." + ".".join(aspects)
    name_hash = rns_sha256(name_str.encode("utf-8"))[:10]
    addr_material = name_hash + identity_hash
    dest_hash = rns_sha256(addr_material)[:16]
    random_hash = bytes([0xAA] * 10)

    signed_data = dest_hash + pub_key + name_hash + random_hash
    signature = ed25519_prv.sign(signed_data)
    announce_data = pub_key + name_hash + random_hash + signature

    # Build the original HEADER_1 announce packet
    original_flags = (0x00 << 6) | (0x00 << 5) | (0x00 << 4) | (0x00 << 2) | 0x01  # H1, broadcast, single, announce
    original_hops = 2
    original_raw = bytes([original_flags, original_hops]) + dest_hash + bytes([0x00]) + announce_data

    # Build retransmit: HEADER_2, TRANSPORT, preserve lower bits
    transport_id = bytes([0xBB] * 16)
    retransmit_flags = (0x01 << 6) | (0x00 << 5) | (0x01 << 4) | (original_flags & 0x0F)
    retransmit_raw = bytes([retransmit_flags, original_hops]) + transport_id + dest_hash + bytes([0x00]) + announce_data

    vectors.append({
        "description": "basic_retransmit",
        "original_raw": to_hex(original_raw),
        "original_flags": original_flags,
        "original_hops": original_hops,
        "destination_hash": to_hex(dest_hash),
        "announce_data": to_hex(announce_data),
        "transport_id": to_hex(transport_id),
        "retransmit_flags": retransmit_flags,
        "retransmit_raw": to_hex(retransmit_raw),
        "context": 0x00,
    })

    # Build retransmit with block_rebroadcasts (PATH_RESPONSE context = 0x0B)
    retransmit_raw_pr = bytes([retransmit_flags, original_hops]) + transport_id + dest_hash + bytes([0x0B]) + announce_data
    vectors.append({
        "description": "retransmit_path_response",
        "original_raw": to_hex(original_raw),
        "original_flags": original_flags,
        "original_hops": original_hops,
        "destination_hash": to_hex(dest_hash),
        "announce_data": to_hex(announce_data),
        "transport_id": to_hex(transport_id),
        "retransmit_flags": retransmit_flags,
        "retransmit_raw": to_hex(retransmit_raw_pr),
        "context": 0x0B,
    })

    # Build retransmit with context_flag set (ratchet announce)
    ratchet_flags = (0x00 << 6) | (0x01 << 5) | (0x00 << 4) | (0x00 << 2) | 0x01  # H1, ctx=1, broadcast, single, announce
    ratchet_retransmit_flags = (0x01 << 6) | (0x01 << 5) | (0x01 << 4) | (ratchet_flags & 0x0F)
    ratchet_raw = bytes([ratchet_retransmit_flags, 3]) + transport_id + dest_hash + bytes([0x00]) + announce_data

    vectors.append({
        "description": "retransmit_with_context_flag",
        "original_raw": to_hex(bytes([ratchet_flags, 3]) + dest_hash + bytes([0x00]) + announce_data),
        "original_flags": ratchet_flags,
        "original_hops": 3,
        "destination_hash": to_hex(dest_hash),
        "announce_data": to_hex(announce_data),
        "transport_id": to_hex(transport_id),
        "retransmit_flags": ratchet_retransmit_flags,
        "retransmit_raw": to_hex(ratchet_raw),
        "context": 0x00,
    })

    write_transport_fixture("announce_retransmit_vectors.json", vectors)


def generate_transport_routing_vectors():
    """Generate transport routing (H1->H2 rewrite) test vectors."""
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    # Test 1: HEADER_1 -> HEADER_2 rewrite for multi-hop routing
    dest_hash = bytes([0x11] * 16)
    next_hop = bytes([0xAA] * 16)
    data = b"hello transport"

    # Original H1 packet
    h1_flags = (0x00 << 6) | (0x00 << 5) | (0x00 << 4) | (0x00 << 2) | 0x00  # H1, broadcast, single, data
    h1_raw = bytes([h1_flags, 0]) + dest_hash + bytes([0x00]) + data

    # Rewritten H2 packet (transport type = TRANSPORT)
    h2_flags = (0x01 << 6) | (0x00 << 5) | (0x01 << 4) | (h1_flags & 0x0F)
    h2_raw = bytes([h2_flags, 0]) + next_hop + dest_hash + bytes([0x00]) + data

    # Compute hashes
    h1_hashable = bytes([h1_raw[0] & 0x0F]) + h1_raw[2:]
    h1_hash = rns_sha256(h1_hashable)

    vectors.append({
        "description": "h1_to_h2_rewrite",
        "original_flags": h1_flags,
        "original_hops": 0,
        "destination_hash": to_hex(dest_hash),
        "next_hop": to_hex(next_hop),
        "data": to_hex(data),
        "original_raw": to_hex(h1_raw),
        "rewritten_flags": h2_flags,
        "rewritten_raw": to_hex(h2_raw),
        "original_hash": to_hex(h1_hash),
    })

    # Test 2: H2 forward (replace transport_id, keep dest)
    old_transport = bytes([0x22] * 16)
    new_transport = bytes([0x33] * 16)

    h2_fwd_flags = (0x01 << 6) | (0x00 << 5) | (0x01 << 4) | (0x00 << 2) | 0x00  # H2, transport, single, data
    h2_original = bytes([h2_fwd_flags, 3]) + old_transport + dest_hash + bytes([0x00]) + data
    h2_forwarded = bytes([h2_fwd_flags, 3]) + new_transport + dest_hash + bytes([0x00]) + data

    vectors.append({
        "description": "h2_forward_replace_transport",
        "original_flags": h2_fwd_flags,
        "original_hops": 3,
        "destination_hash": to_hex(dest_hash),
        "old_transport_id": to_hex(old_transport),
        "new_transport_id": to_hex(new_transport),
        "data": to_hex(data),
        "original_raw": to_hex(h2_original),
        "rewritten_raw": to_hex(h2_forwarded),
    })

    # Test 3: H2 to H1 strip (last hop)
    h2_strip_flags = (0x01 << 6) | (0x00 << 5) | (0x01 << 4) | (0x00 << 2) | 0x00  # H2, transport, single, data
    h2_strip_raw = bytes([h2_strip_flags, 4]) + old_transport + dest_hash + bytes([0x00]) + data
    h1_stripped_flags = (0x00 << 6) | (0x00 << 5) | (0x00 << 4) | (0x00 << 2) | 0x00  # H1, broadcast, single, data
    h1_stripped = bytes([h1_stripped_flags, 4]) + dest_hash + bytes([0x00]) + data

    vectors.append({
        "description": "h2_to_h1_strip_last_hop",
        "original_flags": h2_strip_flags,
        "original_hops": 4,
        "destination_hash": to_hex(dest_hash),
        "transport_id": to_hex(old_transport),
        "data": to_hex(data),
        "original_raw": to_hex(h2_strip_raw),
        "stripped_flags": h1_stripped_flags,
        "stripped_raw": to_hex(h1_stripped),
    })

    write_transport_fixture("transport_routing_vectors.json", vectors)


def generate_full_announce_pipeline_vector():
    """Generate an end-to-end transport announce pipeline test vector.

    This creates a complete announce packet that the Rust TransportEngine
    can ingest via handle_inbound(), verifying:
    1. Packet unpacking
    2. Announce validation (signature check)
    3. Path table update
    4. Announce retransmission scheduling
    """
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    # Identity from known key
    x25519_prv_bytes = bytes(range(32))
    ed25519_seed = bytes(range(32, 64))

    x25519_prv = X25519PrivateKey.from_private_bytes(x25519_prv_bytes)
    ed25519_prv = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    x25519_pub = x25519_prv.public_key()
    ed25519_pub = ed25519_prv.public_key()

    pub_key = x25519_pub.public_bytes() + ed25519_pub.public_bytes()
    identity_hash = rns_sha256(pub_key)[:16]

    # Build announce
    app_name, aspects = "testapp", ["aspect"]
    name_str = app_name + "." + ".".join(aspects)
    name_hash = rns_sha256(name_str.encode("utf-8"))[:10]
    addr_material = name_hash + identity_hash
    dest_hash = rns_sha256(addr_material)[:16]

    # Create random_hash with known timebase
    # timebase is encoded in bytes [5:10] as big-endian
    timebase = 1000000
    timebase_bytes = timebase.to_bytes(5, "big")
    random_hash = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE]) + timebase_bytes

    # Sign and pack announce data
    signed_data = dest_hash + pub_key + name_hash + random_hash
    signature = ed25519_prv.sign(signed_data)
    announce_data = pub_key + name_hash + random_hash + signature

    # Build HEADER_1 announce packet
    flags = (0x00 << 6) | (0x00 << 5) | (0x00 << 4) | (0x00 << 2) | 0x01  # H1, broadcast, single, announce
    hops = 0  # Original announce, no hops yet
    context = 0x00  # CONTEXT_NONE
    raw_packet = bytes([flags, hops]) + dest_hash + bytes([context]) + announce_data

    # Compute packet hash
    hashable = bytes([raw_packet[0] & 0x0F]) + raw_packet[2:]
    packet_hash = rns_sha256(hashable)

    vectors.append({
        "description": "full_pipeline_announce",
        "private_key": to_hex(x25519_prv_bytes + ed25519_seed),
        "public_key": to_hex(pub_key),
        "identity_hash": to_hex(identity_hash),
        "destination_hash": to_hex(dest_hash),
        "name_hash": to_hex(name_hash),
        "random_hash": to_hex(random_hash),
        "timebase": timebase,
        "announce_data": to_hex(announce_data),
        "flags": flags,
        "hops": hops,
        "context": context,
        "raw_packet": to_hex(raw_packet),
        "packet_hash": to_hex(packet_hash),
    })

    write_transport_fixture("full_pipeline_vectors.json", vectors)


def main():
    print("Generating test vectors from Python RNS crypto...")
    generate_pkcs7()
    generate_sha256()
    generate_sha512()
    generate_hmac()
    generate_hkdf()
    generate_aes128()
    generate_aes256()
    generate_token()
    generate_x25519()
    generate_ed25519()
    generate_identity()
    print("\nGenerating Phase 2 protocol test vectors...")
    generate_hash_vectors()
    generate_flags_vectors()
    generate_packet_vectors()
    generate_destination_vectors()
    generate_announce_vectors()
    generate_proof_vectors()
    print("\nGenerating Phase 3 transport test vectors...")
    generate_pathfinder_vectors()
    generate_announce_retransmit_vectors()
    generate_transport_routing_vectors()
    generate_full_announce_pipeline_vector()
    print("Done! All vectors generated successfully.")


if __name__ == "__main__":
    main()
