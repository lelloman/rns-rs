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


LINK_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'link')
os.makedirs(LINK_DIR, exist_ok=True)


def write_link_fixture(name, data):
    path = os.path.join(LINK_DIR, name)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Written {path} ({len(data)} vectors)")


def generate_link_handshake_vectors():
    """Generate link handshake test vectors.

    Simulates both initiator and responder sides of the Link handshake:
    1. Initiator builds LINKREQUEST with ephemeral X25519+Ed25519 pub keys
    2. link_id is computed from the LINKREQUEST packet's hashable part
    3. Responder does ECDH + HKDF to derive session key
    4. Responder builds LRPROOF (signature + ephemeral pub + signalling)
    5. Initiator validates proof, does same ECDH + HKDF (keys must match)
    6. Initiator sends encrypted RTT via Token

    References:
      Link.py:148-151  signalling_bytes()
      Link.py:340-347  link_id_from_lr_packet() / set_link_id()
      Link.py:353-366  handshake() - ECDH + HKDF
      Link.py:371-378  prove() - builds LRPROOF
      Link.py:396-457  validate_proof()
      Link.py:459-474  identify()
      Link.py:1191-1213 encrypt/decrypt via Token
    """
    import struct
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    # ---- Protocol constants (from Link.py) ----
    ECPUBSIZE = 32 + 32        # X25519 pub (32) + Ed25519 pub (32) = 64
    KEYSIZE = 32
    LINK_MTU_SIZE = 3
    MTU_BYTEMASK = 0x1FFFFF
    MODE_BYTEMASK = 0xE0
    SIGLENGTH_BYTES = 64       # Ed25519 signature = 512 bits / 8
    TRUNCATED_HASH_LEN = 16    # 128 bits / 8

    MODE_AES128_CBC = 0x00
    MODE_AES256_CBC = 0x01

    def signalling_bytes(mtu, mode):
        signalling_value = (mtu & MTU_BYTEMASK) + (((mode << 5) & MODE_BYTEMASK) << 16)
        return struct.pack(">I", signalling_value)[1:]

    # ---- Fixed keys for initiator ----
    init_x25519_prv_bytes = bytes(range(32))
    init_ed25519_seed = bytes(range(32, 64))
    init_x25519_prv = X25519PrivateKey.from_private_bytes(init_x25519_prv_bytes)
    init_ed25519_prv = Ed25519PrivateKey.from_private_bytes(init_ed25519_seed)
    init_x25519_pub = init_x25519_prv.public_key()
    init_ed25519_pub = init_ed25519_prv.public_key()
    init_pub_bytes = init_x25519_pub.public_bytes()        # 32 bytes
    init_sig_pub_bytes = init_ed25519_pub.public_bytes()   # 32 bytes

    # ---- Fixed keys for responder/owner identity (destination) ----
    owner_x25519_prv_bytes = bytes([0xAA] * 32)
    owner_ed25519_seed = bytes([0xBB] * 32)
    owner_x25519_prv = X25519PrivateKey.from_private_bytes(owner_x25519_prv_bytes)
    owner_ed25519_prv = Ed25519PrivateKey.from_private_bytes(owner_ed25519_seed)
    owner_x25519_pub = owner_x25519_prv.public_key()
    owner_ed25519_pub = owner_ed25519_prv.public_key()
    owner_pub_key = owner_x25519_pub.public_bytes() + owner_ed25519_pub.public_bytes()
    owner_identity_hash = rns_sha256(owner_pub_key)[:TRUNCATED_HASH_LEN]

    # Build destination hash for the owner
    app_name = "testapp"
    aspects = ["link"]
    name_str = app_name + "." + ".".join(aspects)
    name_hash = rns_sha256(name_str.encode("utf-8"))[:10]
    addr_material = name_hash + owner_identity_hash
    dest_hash = rns_sha256(addr_material)[:TRUNCATED_HASH_LEN]

    # ---- Fixed keys for responder ephemeral X25519 ----
    resp_x25519_prv_bytes = bytes([0xCC] * 32)
    resp_x25519_prv = X25519PrivateKey.from_private_bytes(resp_x25519_prv_bytes)
    resp_x25519_pub = resp_x25519_prv.public_key()
    resp_pub_bytes = resp_x25519_pub.public_bytes()

    # ---- Test both AES modes ----
    for mode_desc, mode, derived_key_length in [
        ("aes256_cbc", MODE_AES256_CBC, 64),
        ("aes128_cbc", MODE_AES128_CBC, 32),
    ]:
        MTU = 500
        sig_bytes = signalling_bytes(MTU, mode)

        # ==== Step 1: Build LINKREQUEST data (initiator side) ====
        # Link.__init__: self.request_data = self.pub_bytes + self.sig_pub_bytes + signalling_bytes
        request_data = init_pub_bytes + init_sig_pub_bytes + sig_bytes
        assert len(request_data) == ECPUBSIZE + LINK_MTU_SIZE

        # ==== Step 2: Build LINKREQUEST packet ====
        # Packet type LINKREQUEST=0x02, HEADER_1, broadcast, SINGLE dest
        lr_flags = (0x00 << 6) | (0x00 << 5) | (0x00 << 4) | (0x00 << 2) | 0x02
        lr_hops = 0
        lr_context = 0x00  # NONE
        lr_raw = bytes([lr_flags, lr_hops]) + dest_hash + bytes([lr_context]) + request_data

        # ==== Step 3: Compute link_id ====
        # Packet.get_hashable_part() for HEADER_1:
        #   hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]
        hashable_part = bytes([lr_raw[0] & 0x0F]) + lr_raw[2:]

        # Link.link_id_from_lr_packet():
        #   if len(packet.data) > ECPUBSIZE:
        #       diff = len(packet.data) - ECPUBSIZE
        #       hashable_part = hashable_part[:-diff]
        lr_data = request_data  # this is what Packet.data would be after unpack
        if len(lr_data) > ECPUBSIZE:
            diff = len(lr_data) - ECPUBSIZE
            hashable_for_linkid = hashable_part[:-diff]
        else:
            hashable_for_linkid = hashable_part

        # link_id = Identity.truncated_hash(hashable_part) = SHA256(...)[:16]
        link_id = rns_sha256(hashable_for_linkid)[:TRUNCATED_HASH_LEN]

        # ==== Step 4: Responder-side ECDH + HKDF ====
        # Link.handshake(): shared_key = self.prv.exchange(self.peer_pub)
        # Responder prv = resp_x25519_prv, peer_pub = initiator's init_x25519_pub
        shared_key = resp_x25519_prv.exchange(init_x25519_pub)

        # Link.handshake(): derived_key = hkdf(length=..., derive_from=shared_key,
        #                                      salt=self.get_salt(), context=self.get_context())
        # get_salt() -> self.link_id, get_context() -> None
        derived_key = hkdf(length=derived_key_length, derive_from=shared_key,
                           salt=link_id, context=None)

        # ==== Step 5: Build LRPROOF (responder side) ====
        # Link.prove():
        #   signalling_bytes = Link.signalling_bytes(self.mtu, self.mode)
        #   signed_data = self.link_id + self.pub_bytes + self.sig_pub_bytes + signalling_bytes
        #   signature = self.owner.identity.sign(signed_data)
        #   proof_data = signature + self.pub_bytes + signalling_bytes
        proof_sig_bytes = signalling_bytes(MTU, mode)
        proof_signed_data = link_id + resp_pub_bytes + owner_ed25519_pub.public_bytes() + proof_sig_bytes
        proof_signature = owner_ed25519_prv.sign(proof_signed_data)
        proof_data = proof_signature + resp_pub_bytes + proof_sig_bytes

        assert len(proof_data) == SIGLENGTH_BYTES + ECPUBSIZE // 2 + LINK_MTU_SIZE

        # ==== Step 6: Build LRPROOF packet ====
        # Packet context=LRPROOF (0xFF), type=PROOF (0x03)
        # get_packed_flags for LRPROOF forces dest_type=LINK (0x03)
        # Packet.pack for LRPROOF: header += self.destination.link_id (not dest hash)
        lrp_flags = (0x00 << 6) | (0x00 << 5) | (0x00 << 4) | (0x03 << 2) | 0x03
        lrp_hops = 0
        lrp_context = 0xFF  # LRPROOF
        lrp_raw = bytes([lrp_flags, lrp_hops]) + link_id + bytes([lrp_context]) + proof_data

        # ==== Step 7: Initiator-side ECDH + HKDF (must match) ====
        # Initiator extracts peer_pub_bytes from proof_data
        peer_pub_from_proof = proof_data[SIGLENGTH_BYTES:SIGLENGTH_BYTES + ECPUBSIZE // 2]
        peer_pub_obj = X25519PublicKey.from_public_bytes(peer_pub_from_proof)
        shared_key_init = init_x25519_prv.exchange(peer_pub_obj)
        assert shared_key_init == shared_key, "Shared keys must match!"

        derived_key_init = hkdf(length=derived_key_length, derive_from=shared_key_init,
                                salt=link_id, context=None)
        assert derived_key_init == derived_key, "Derived keys must match!"

        # Initiator validates proof signature
        # validate_proof: signed_data = link_id + peer_pub_bytes + peer_sig_pub_bytes + signalling_bytes
        peer_sig_pub_bytes = owner_pub_key[ECPUBSIZE // 2:ECPUBSIZE]
        verify_signed_data = link_id + peer_pub_from_proof + peer_sig_pub_bytes + proof_sig_bytes
        owner_ed25519_pub.verify(proof_signature, verify_signed_data)

        # ==== Step 8: Encrypt RTT using Token with fixed IV ====
        fixed_iv = bytes([0xDD] * 16)
        rtt_value = 0.125
        # Python uses umsgpack.packb(self.rtt) -> 9 bytes for float64
        # cb 3f c0 00 00 00 00 00 00
        rtt_data = bytes([0xcb]) + struct.pack(">d", rtt_value)
        assert len(rtt_data) == 9

        token = Token(derived_key)
        original_urandom = os.urandom
        os.urandom = lambda n, _iv=fixed_iv: _iv[:n]
        try:
            encrypted_rtt = token.encrypt(rtt_data)
        finally:
            os.urandom = original_urandom

        # Verify decrypt
        decrypted_rtt = token.decrypt(encrypted_rtt)
        assert decrypted_rtt == rtt_data, "RTT roundtrip failed!"

        vectors.append({
            "description": "handshake_" + mode_desc,
            "mode": mode,
            "mtu": MTU,
            "derived_key_length": derived_key_length,
            # Initiator keys
            "initiator_x25519_prv": to_hex(init_x25519_prv_bytes),
            "initiator_x25519_pub": to_hex(init_pub_bytes),
            "initiator_ed25519_seed": to_hex(init_ed25519_seed),
            "initiator_ed25519_pub": to_hex(init_sig_pub_bytes),
            # Owner (responder destination) keys
            "owner_x25519_prv": to_hex(owner_x25519_prv_bytes),
            "owner_x25519_pub": to_hex(owner_x25519_pub.public_bytes()),
            "owner_ed25519_seed": to_hex(owner_ed25519_seed),
            "owner_ed25519_pub": to_hex(owner_ed25519_pub.public_bytes()),
            "owner_pub_key": to_hex(owner_pub_key),
            "owner_identity_hash": to_hex(owner_identity_hash),
            # Destination
            "app_name": app_name,
            "aspects": aspects,
            "dest_hash": to_hex(dest_hash),
            # Responder ephemeral keys
            "responder_x25519_prv": to_hex(resp_x25519_prv_bytes),
            "responder_x25519_pub": to_hex(resp_pub_bytes),
            # Signalling
            "signalling_bytes": to_hex(sig_bytes),
            # LINKREQUEST
            "request_data": to_hex(request_data),
            "lr_flags": lr_flags,
            "lr_hops": lr_hops,
            "lr_context": lr_context,
            "lr_raw": to_hex(lr_raw),
            "hashable_part": to_hex(hashable_part),
            "hashable_for_linkid": to_hex(hashable_for_linkid),
            "link_id": to_hex(link_id),
            # Handshake
            "shared_key": to_hex(shared_key),
            "derived_key": to_hex(derived_key),
            # LRPROOF
            "proof_signed_data": to_hex(proof_signed_data),
            "proof_signature": to_hex(proof_signature),
            "proof_data": to_hex(proof_data),
            "lrp_flags": lrp_flags,
            "lrp_hops": lrp_hops,
            "lrp_context": lrp_context,
            "lrp_raw": to_hex(lrp_raw),
            # RTT encryption
            "fixed_iv": to_hex(fixed_iv),
            "rtt_value": rtt_value,
            "rtt_data_msgpack": to_hex(rtt_data),
            "encrypted_rtt": to_hex(encrypted_rtt),
        })

    write_link_fixture("link_handshake_vectors.json", vectors)


def generate_link_crypto_vectors():
    """Generate link session encryption/decryption test vectors.

    Tests the Token-based encrypt/decrypt used for link traffic
    (Link.encrypt/decrypt at Link.py:1191-1213).

    Uses derived keys from the handshake to encrypt various payloads.
    """
    vectors = []

    # Test multiple key sizes and payloads
    test_cases = [
        # (desc, derived_key_hex, fixed_iv_hex, plaintext)
        ("aes256_short",
         "6080e432a453d453938cc0ebd1e53f73a5d48e5f21c6dd9c7db7db7da41337c4"
         "c2059963e08e4b9d8073d2fcc6c51f2de39c81fc09d2e7a4ebeda4340b556bb3",
         "dd" * 16, b"Hello Link!"),
        ("aes256_empty",
         "6080e432a453d453938cc0ebd1e53f73a5d48e5f21c6dd9c7db7db7da41337c4"
         "c2059963e08e4b9d8073d2fcc6c51f2de39c81fc09d2e7a4ebeda4340b556bb3",
         "ee" * 16, b""),
        ("aes256_block_aligned",
         "6080e432a453d453938cc0ebd1e53f73a5d48e5f21c6dd9c7db7db7da41337c4"
         "c2059963e08e4b9d8073d2fcc6c51f2de39c81fc09d2e7a4ebeda4340b556bb3",
         "ff" * 16, b"A" * 16),
        ("aes256_multi_block",
         "6080e432a453d453938cc0ebd1e53f73a5d48e5f21c6dd9c7db7db7da41337c4"
         "c2059963e08e4b9d8073d2fcc6c51f2de39c81fc09d2e7a4ebeda4340b556bb3",
         "aa" * 16, b"B" * 100),
        ("aes128_short",
         "6080e432a453d453938cc0ebd1e53f73a5d48e5f21c6dd9c7db7db7da41337c4",
         "bb" * 16, b"AES-128 link data"),
    ]

    for desc, key_hex, iv_hex, plaintext in test_cases:
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)

        token = Token(key)
        original_urandom = os.urandom
        os.urandom = lambda n, _iv=iv: _iv[:n]
        try:
            ciphertext = token.encrypt(plaintext)
        finally:
            os.urandom = original_urandom

        # Verify roundtrip
        decrypted = token.decrypt(ciphertext)
        assert decrypted == plaintext, f"Link crypto roundtrip failed for {desc}"

        vectors.append({
            "description": desc,
            "derived_key": key_hex,
            "fixed_iv": iv_hex,
            "plaintext": to_hex(plaintext),
            "ciphertext": to_hex(ciphertext),
        })

    write_link_fixture("link_crypto_vectors.json", vectors)


def generate_link_identify_vectors():
    """Generate LINKIDENTIFY test vectors.

    Tests the identify() method at Link.py:459-474:
      signed_data = self.link_id + identity.get_public_key()
      signature = identity.sign(signed_data)
      proof_data = identity.get_public_key() + signature

    The proof_data is then encrypted via Token and sent as a DATA packet
    with context LINKIDENTIFY.

    On the receiving side (Link.py:1014-1032):
      plaintext is decrypted, then:
      public_key = plaintext[:KEYSIZE//8]
      signed_data = self.link_id + public_key
      signature = plaintext[KEYSIZE//8:KEYSIZE//8+SIGLENGTH//8]
      identity.validate(signature, signed_data)
    """
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    KEYSIZE_BYTES = 64     # Identity.KEYSIZE // 8 = 512 // 8 = 64
    SIGLENGTH_BYTES = 64   # Identity.SIGLENGTH // 8 = 512 // 8 = 64

    # Use a fixed link_id
    link_id = bytes.fromhex("0eed4280e7770b8157cd66fac3f9b8d0")

    # Use a fixed derived key (from the AES-256 handshake above)
    derived_key = bytes.fromhex(
        "6080e432a453d453938cc0ebd1e53f73a5d48e5f21c6dd9c7db7db7da41337c4"
        "c2059963e08e4b9d8073d2fcc6c51f2de39c81fc09d2e7a4ebeda4340b556bb3"
    )
    fixed_iv = bytes([0xDD] * 16)

    # Identity that will identify itself
    test_identities = [
        ("identity_range", bytes(range(32)), bytes(range(32, 64))),
        ("identity_aa", bytes([0xAA] * 32), bytes([0x55] * 32)),
    ]

    for desc, x_prv_bytes, ed_seed in test_identities:
        x_prv = X25519PrivateKey.from_private_bytes(x_prv_bytes)
        ed_prv = Ed25519PrivateKey.from_private_bytes(ed_seed)
        x_pub = x_prv.public_key()
        ed_pub = ed_prv.public_key()
        pub_key = x_pub.public_bytes() + ed_pub.public_bytes()
        assert len(pub_key) == KEYSIZE_BYTES

        # identify():
        #   signed_data = self.link_id + identity.get_public_key()
        #   signature = identity.sign(signed_data)
        #   proof_data = identity.get_public_key() + signature
        signed_data = link_id + pub_key
        signature = ed_prv.sign(signed_data)
        proof_data = pub_key + signature
        assert len(proof_data) == KEYSIZE_BYTES + SIGLENGTH_BYTES

        # The proof_data is sent encrypted over the link
        token = Token(derived_key)
        original_urandom = os.urandom
        os.urandom = lambda n, _iv=fixed_iv: _iv[:n]
        try:
            encrypted = token.encrypt(proof_data)
        finally:
            os.urandom = original_urandom

        # Verify roundtrip
        decrypted = token.decrypt(encrypted)
        assert decrypted == proof_data

        vectors.append({
            "description": desc,
            "link_id": to_hex(link_id),
            "derived_key": to_hex(derived_key),
            "fixed_iv": to_hex(fixed_iv),
            "x25519_prv": to_hex(x_prv_bytes),
            "ed25519_seed": to_hex(ed_seed),
            "public_key": to_hex(pub_key),
            "signed_data": to_hex(signed_data),
            "signature": to_hex(signature),
            "proof_data_plaintext": to_hex(proof_data),
            "proof_data_encrypted": to_hex(encrypted),
        })

    write_link_fixture("link_identify_vectors.json", vectors)


def generate_channel_envelope_vectors():
    """Generate Channel Envelope pack/unpack test vectors.

    The Envelope format (Channel.py:192-198):
      packed = struct.pack(">HHH", msgtype, sequence, len(data)) + data

    Where:
      - msgtype: u16 big-endian, the message class MSGTYPE
      - sequence: u16 big-endian, the envelope sequence number
      - len(data): u16 big-endian, length of the packed message payload
      - data: the packed message bytes

    Total header overhead: 6 bytes (3 x u16)
    """
    import struct

    vectors = []

    test_cases = [
        # (desc, msgtype, sequence, payload_bytes)
        ("simple_msg", 0x0001, 0, b"hello"),
        ("empty_payload", 0x0002, 5, b""),
        ("seq_wrap", 0x1234, 0xFFFF, b"\x01\x02\x03"),
        ("max_user_msgtype", 0xEFFF, 100, b"test data payload"),
        ("system_stream_data", 0xFF00, 42, b"stream bytes"),
        ("zero_all", 0x0000, 0, b""),
        ("binary_payload", 0x0010, 1000, bytes(range(256))),
        ("single_byte", 0x0001, 1, b"\x42"),
    ]

    for desc, msgtype, seq, data in test_cases:
        packed = struct.pack(">HHH", msgtype, seq, len(data)) + data
        vectors.append({
            "description": desc,
            "msgtype": msgtype,
            "sequence": seq,
            "data": to_hex(data),
            "data_length": len(data),
            "packed": to_hex(packed),
        })

    write_link_fixture("channel_envelope_vectors.json", vectors)


def generate_stream_data_vectors():
    """Generate StreamDataMessage pack/unpack test vectors.

    The StreamDataMessage format (Buffer.py:80-95):
      header_val = (0x3fff & stream_id)
                 | (0x8000 if eof else 0x0000)
                 | (0x4000 if compressed else 0x0000)
      packed = struct.pack(">H", header_val) + data

    Header is a big-endian u16 with:
      - bits 0-13: stream_id (0x3FFF mask, max 16383)
      - bit 14: compressed flag (0x4000)
      - bit 15: eof flag (0x8000)

    On unpack (Buffer.py:87-95):
      raw_header = struct.unpack(">H", raw[:2])[0]
      eof = (0x8000 & raw_header) > 0
      compressed = (0x4000 & raw_header) > 0
      stream_id = raw_header & 0x3fff
      data = raw[2:]
    """
    import struct

    vectors = []

    test_cases = [
        # (desc, stream_id, eof, compressed, data)
        ("basic", 0, False, False, b"hello world"),
        ("eof_set", 1, True, False, b"last chunk"),
        ("compressed_set", 2, False, True, b"compressed data"),
        ("eof_and_compressed", 100, True, True, b"final"),
        ("empty_eof", 0, True, False, b""),
        ("max_stream_id", 0x3FFF, False, False, b"max id"),
        ("zero_stream_data", 0, False, False, b""),
        ("binary_data", 42, False, False, bytes(range(64))),
        ("large_stream_id_eof", 16383, True, False, b"\xff\xfe\xfd"),
    ]

    for desc, stream_id, eof, compressed, data in test_cases:
        header_val = (0x3FFF & stream_id) \
                   | (0x8000 if eof else 0x0000) \
                   | (0x4000 if compressed else 0x0000)
        packed = struct.pack(">H", header_val) + data
        vectors.append({
            "description": desc,
            "stream_id": stream_id,
            "eof": eof,
            "compressed": compressed,
            "data": to_hex(data),
            "header_value": header_val,
            "packed": to_hex(packed),
        })

    write_link_fixture("stream_data_vectors.json", vectors)


RESOURCE_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'resource')
os.makedirs(RESOURCE_DIR, exist_ok=True)


def write_resource_fixture(name, data):
    path = os.path.join(RESOURCE_DIR, name)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Written {path} ({len(data)} vectors)")


def generate_msgpack_vectors():
    """Generate msgpack encode/decode test vectors.

    Uses Python's umsgpack (vendored in RNS) to produce reference encodings.
    """
    import RNS.vendor.umsgpack as umsgpack

    vectors = []

    test_cases = [
        ("nil", None),
        ("true", True),
        ("false", False),
        ("fixint_0", 0),
        ("fixint_1", 1),
        ("fixint_127", 127),
        ("uint8_200", 200),
        ("uint16_1000", 1000),
        ("uint32_100000", 100000),
        ("uint64_large", 2**40),
        ("negfixint_minus1", -1),
        ("negfixint_minus32", -32),
        ("int8_minus100", -100),
        ("int16_minus1000", -1000),
        ("fixstr_empty", ""),
        ("fixstr_hello", "hello"),
        ("str8_long", "a" * 40),
        ("bin8_short", umsgpack.Ext(0, b"")),  # Use raw bytes via special handling
        ("fixarray_empty", []),
        ("fixarray_ints", [1, 2, 3]),
        ("fixmap_empty", {}),
        ("fixmap_str_keys", {"a": 1, "b": 2}),
    ]

    for desc, value in test_cases:
        # Special handling for binary data (umsgpack uses Ext for bin in some modes)
        if desc == "bin8_short":
            # Pack raw bytes using umsgpack
            raw_value = b"\x01\x02\x03\x04"
            packed = umsgpack.packb(raw_value)
            vectors.append({
                "description": desc,
                "type": "bin",
                "bin_value": to_hex(raw_value),
                "packed": to_hex(packed),
            })
            continue

        packed = umsgpack.packb(value)
        entry = {
            "description": desc,
            "packed": to_hex(packed),
        }

        if value is None:
            entry["type"] = "nil"
        elif isinstance(value, bool):
            entry["type"] = "bool"
            entry["bool_value"] = value
        elif isinstance(value, int):
            entry["type"] = "int"
            entry["int_value"] = value
        elif isinstance(value, str):
            entry["type"] = "str"
            entry["str_value"] = value
        elif isinstance(value, list):
            entry["type"] = "array"
            entry["array_value"] = value
        elif isinstance(value, dict):
            entry["type"] = "map"
            entry["map_value"] = value

        vectors.append(entry)

    # Add binary vectors directly
    for desc, data in [
        ("bin8_empty", b""),
        ("bin8_4bytes", b"\x01\x02\x03\x04"),
        ("bin8_32bytes", bytes(range(32))),
        ("bin16_300bytes", bytes([i % 256 for i in range(300)])),
    ]:
        packed = umsgpack.packb(data)
        vectors.append({
            "description": desc,
            "type": "bin",
            "bin_value": to_hex(data),
            "packed": to_hex(packed),
        })

    write_resource_fixture("msgpack_vectors.json", vectors)


def generate_resource_part_hash_vectors():
    """Generate resource map_hash test vectors.

    map_hash = SHA-256(part_data + random_hash)[:4]
    """
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    test_cases = [
        ("small_part", b"hello world part data", bytes([0xAA, 0xBB, 0xCC, 0xDD])),
        ("empty_part", b"", bytes([0x11, 0x22, 0x33, 0x44])),
        ("full_sdu", bytes(range(256)) * 2, bytes([0xFF, 0xEE, 0xDD, 0xCC])),  # 512 bytes > SDU
        ("repeated_data", b"\xAB" * 464, bytes([0x01, 0x02, 0x03, 0x04])),
    ]

    for desc, part_data, random_hash in test_cases:
        full_hash = rns_sha256(part_data + random_hash)
        map_hash = full_hash[:4]
        vectors.append({
            "description": desc,
            "part_data": to_hex(part_data),
            "random_hash": to_hex(random_hash),
            "map_hash": to_hex(map_hash),
            "full_hash": to_hex(full_hash),
        })

    write_resource_fixture("part_hash_vectors.json", vectors)


def generate_resource_proof_vectors():
    """Generate resource hash and proof computation test vectors.

    resource_hash = SHA-256(unencrypted_data + random_hash)  (32 bytes)
    expected_proof = SHA-256(unencrypted_data + resource_hash)  (32 bytes)
    """
    from RNS.Cryptography.Hashes import sha256 as rns_sha256

    vectors = []

    test_cases = [
        ("small_data", b"resource data", bytes([0xAA, 0xBB, 0xCC, 0xDD])),
        ("empty_data", b"", bytes([0x11, 0x22, 0x33, 0x44])),
        ("large_data", bytes(range(256)) * 4, bytes([0xFF, 0xEE, 0xDD, 0xCC])),
        ("with_metadata_prefix",
         bytes([0x00, 0x00, 0x08]) + b"metadata" + b"actual data",
         bytes([0x55, 0x66, 0x77, 0x88])),
    ]

    for desc, data, random_hash in test_cases:
        resource_hash = rns_sha256(data + random_hash)
        expected_proof = rns_sha256(data + resource_hash)
        proof_data = resource_hash + expected_proof  # 64 bytes

        vectors.append({
            "description": desc,
            "data": to_hex(data),
            "random_hash": to_hex(random_hash),
            "resource_hash": to_hex(resource_hash),
            "expected_proof": to_hex(expected_proof),
            "proof_data": to_hex(proof_data),
        })

    write_resource_fixture("resource_proof_vectors.json", vectors)


def generate_resource_advertisement_vectors():
    """Generate ResourceAdvertisement msgpack test vectors.

    Advertisement is a msgpack map with keys: t, d, n, h, r, o, i, l, q, f, m
    (Python: Resource.py advertise() builds this dict)
    """
    import RNS.vendor.umsgpack as umsgpack

    vectors = []

    test_cases = [
        {
            "description": "simple_advertisement",
            "t": 1000,         # transfer_size
            "d": 900,          # data_size
            "n": 3,            # num_parts
            "h": bytes([0x11] * 32),  # resource_hash
            "r": bytes([0xAA, 0xBB, 0xCC, 0xDD]),  # random_hash
            "o": bytes([0x11] * 32),  # original_hash
            "f": 0b00000001,   # flags: encrypted=1
            "i": 1,            # segment_index
            "l": 1,            # total_segments
            "q": None,         # request_id
            "m": bytes([0x01, 0x02, 0x03, 0x04] * 3),  # hashmap (3 * 4 bytes)
        },
        {
            "description": "with_request_id",
            "t": 5000,
            "d": 4800,
            "n": 11,
            "h": bytes(range(32)),
            "r": bytes([0x55, 0x66, 0x77, 0x88]),
            "o": bytes(range(32)),
            "f": 0b00010001,   # flags: encrypted=1, is_request=1
            "i": 1,
            "l": 1,
            "q": bytes([0xDE, 0xAD, 0xBE, 0xEF]),  # request_id
            "m": bytes([i % 256 for i in range(44)]),  # 11 * 4 bytes hashmap
        },
        {
            "description": "multi_segment",
            "t": 50000,
            "d": 48000,
            "n": 108,
            "h": bytes([0x33] * 32),
            "r": bytes([0xCC, 0xDD, 0xEE, 0xFF]),
            "o": bytes([0x22] * 32),
            "f": 0b00000101,   # flags: encrypted=1, split=1
            "i": 2,
            "l": 3,
            "q": None,
            "m": bytes([i % 256 for i in range(296)]),  # 74 * 4 = 296 bytes (max segment)
        },
    ]

    for tc in test_cases:
        adv_dict = {
            "t": tc["t"],
            "d": tc["d"],
            "n": tc["n"],
            "h": tc["h"],
            "r": tc["r"],
            "o": tc["o"],
            "f": tc["f"],
            "i": tc["i"],
            "l": tc["l"],
            "q": tc["q"],
            "m": tc["m"],
        }
        packed = umsgpack.packb(adv_dict)

        vectors.append({
            "description": tc["description"],
            "transfer_size": tc["t"],
            "data_size": tc["d"],
            "num_parts": tc["n"],
            "resource_hash": to_hex(tc["h"]),
            "random_hash": to_hex(tc["r"]),
            "original_hash": to_hex(tc["o"]),
            "flags": tc["f"],
            "segment_index": tc["i"],
            "total_segments": tc["l"],
            "request_id": to_hex(tc["q"]) if tc["q"] is not None else None,
            "hashmap": to_hex(tc["m"]),
            "packed": to_hex(packed),
        })

    write_resource_fixture("advertisement_vectors.json", vectors)


def generate_resource_hmu_vectors():
    """Generate hashmap update (HMU) msgpack test vectors.

    HMU payload (after 32-byte resource_hash prefix):
      msgpack([segment_index, hashmap_bytes])
    """
    import RNS.vendor.umsgpack as umsgpack

    vectors = []

    test_cases = [
        ("segment_1", 1, bytes([0x01, 0x02, 0x03, 0x04] * 10)),  # 10 hashes
        ("segment_2", 2, bytes([0xAA, 0xBB, 0xCC, 0xDD] * 5)),   # 5 hashes
        ("segment_0_full", 0, bytes([i % 256 for i in range(296)])),  # 74 hashes
    ]

    for desc, segment, hashmap_bytes in test_cases:
        resource_hash = bytes([0x11] * 32)
        payload = umsgpack.packb([segment, hashmap_bytes])
        full_hmu = resource_hash + payload

        vectors.append({
            "description": desc,
            "resource_hash": to_hex(resource_hash),
            "segment": segment,
            "hashmap_bytes": to_hex(hashmap_bytes),
            "payload": to_hex(payload),
            "full_hmu": to_hex(full_hmu),
        })

    write_resource_fixture("hmu_vectors.json", vectors)


# --- Phase 5c: IFAC vectors ---

IFAC_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'ifac')
os.makedirs(IFAC_DIR, exist_ok=True)


def write_ifac_fixture(name, data):
    path = os.path.join(IFAC_DIR, name)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Written {path} ({len(data)} vectors)")


def generate_ifac_vectors():
    """Generate IFAC mask/unmask test vectors matching Reticulum.py and Transport.py."""
    import RNS

    # Force internal provider
    cp.PROVIDER = cp.PROVIDER_INTERNAL
    import importlib
    importlib.reload(RNS.Cryptography)

    IFAC_SALT = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")

    vectors = []

    test_cases = [
        {
            "description": "netname_only_size8",
            "netname": "testnet",
            "netkey": None,
            "ifac_size": 8,
            "raw_packet": bytes([0x00, 0x01]) + bytes(range(32)),
        },
        {
            "description": "netkey_only_size16",
            "netname": None,
            "netkey": "secretpassword",
            "ifac_size": 16,
            "raw_packet": bytes([0x40, 0x03]) + bytes([0xAA] * 50),
        },
        {
            "description": "both_size8",
            "netname": "mynetwork",
            "netkey": "mypassphrase",
            "ifac_size": 8,
            "raw_packet": bytes([0x10, 0x00]) + bytes([i ^ 0x55 for i in range(100)]),
        },
        {
            "description": "both_size16_large_packet",
            "netname": "production",
            "netkey": "strongkey123",
            "ifac_size": 16,
            "raw_packet": bytes([0x20, 0x05]) + bytes([(i * 7 + 13) & 0xFF for i in range(400)]),
        },
    ]

    for tc in test_cases:
        netname = tc["netname"]
        netkey = tc["netkey"]
        ifac_size = tc["ifac_size"]
        raw_packet = tc["raw_packet"]

        # Derive IFAC key (same as Reticulum.py:811-828)
        ifac_origin = b""
        if netname is not None:
            ifac_origin += RNS.Identity.full_hash(netname.encode("utf-8"))
        if netkey is not None:
            ifac_origin += RNS.Identity.full_hash(netkey.encode("utf-8"))

        ifac_origin_hash = RNS.Identity.full_hash(ifac_origin)
        ifac_key = RNS.Cryptography.hkdf(
            length=64,
            derive_from=ifac_origin_hash,
            salt=IFAC_SALT,
            context=None,
        )
        ifac_identity = RNS.Identity.from_bytes(ifac_key)

        # Mask outbound (Transport.py:894-930)
        ifac = ifac_identity.sign(raw_packet)[-ifac_size:]

        mask = RNS.Cryptography.hkdf(
            length=len(raw_packet) + ifac_size,
            derive_from=ifac,
            salt=ifac_key,
            context=None,
        )

        new_header = bytes([raw_packet[0] | 0x80, raw_packet[1]])
        new_raw = new_header + ifac + raw_packet[2:]

        i = 0; masked_raw = b""
        for byte in new_raw:
            if i == 0:
                masked_raw += bytes([byte ^ mask[i] | 0x80])
            elif i == 1 or i > ifac_size + 1:
                masked_raw += bytes([byte ^ mask[i]])
            else:
                masked_raw += bytes([byte])
            i += 1

        # Verify unmask works (Transport.py:1241-1303)
        # Extract IFAC from masked
        extracted_ifac = masked_raw[2:2+ifac_size]

        verify_mask = RNS.Cryptography.hkdf(
            length=len(masked_raw),
            derive_from=extracted_ifac,
            salt=ifac_key,
            context=None,
        )

        i = 0; unmasked_raw = b""
        for byte in masked_raw:
            if i <= 1 or i > ifac_size + 1:
                unmasked_raw += bytes([byte ^ verify_mask[i]])
            else:
                unmasked_raw += bytes([byte])
            i += 1

        new_header_u = bytes([unmasked_raw[0] & 0x7f, unmasked_raw[1]])
        recovered = new_header_u + unmasked_raw[2+ifac_size:]

        assert recovered == raw_packet, f"Roundtrip failed for {tc['description']}: {recovered.hex()} != {raw_packet.hex()}"

        # Get the identity hash for verification
        identity_hash = RNS.Identity.truncated_hash(ifac_identity.get_public_key())

        vectors.append({
            "description": tc["description"],
            "netname": netname,
            "netkey": netkey,
            "ifac_size": ifac_size,
            "raw_packet": to_hex(raw_packet),
            "masked_packet": to_hex(masked_raw),
            "ifac_key": to_hex(ifac_key),
            "identity_hash": to_hex(identity_hash),
        })

    write_ifac_fixture("ifac_vectors.json", vectors)


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
    print("\nGenerating Phase 4a link/channel/buffer test vectors...")
    generate_link_handshake_vectors()
    generate_link_crypto_vectors()
    generate_link_identify_vectors()
    generate_channel_envelope_vectors()
    generate_stream_data_vectors()
    print("\nGenerating Phase 4b resource test vectors...")
    generate_msgpack_vectors()
    generate_resource_part_hash_vectors()
    generate_resource_proof_vectors()
    generate_resource_advertisement_vectors()
    generate_resource_hmu_vectors()
    print("\nGenerating Phase 5c IFAC test vectors...")
    generate_ifac_vectors()
    print("Done! All vectors generated successfully.")


if __name__ == "__main__":
    main()
