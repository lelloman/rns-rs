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
    print("Done! All vectors generated successfully.")


if __name__ == "__main__":
    main()
