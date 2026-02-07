//! Interop tests: verify Rust crypto matches Python RNS crypto output.
//! Run `python3 ../tests/generate_vectors.py` first to generate fixtures.

use std::fs;
use std::path::PathBuf;

use rns_crypto::*;

fn fixture_path(name: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("..").join("tests").join("fixtures").join("crypto").join(name)
}

fn load_fixture(name: &str) -> serde_json::Value {
    let path = fixture_path(name);
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}. Run generate_vectors.py first.", path.display(), e));
    serde_json::from_str(&content).unwrap()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_pkcs7_interop() {
    let vectors = load_fixture("pkcs7_vectors.json");
    for v in vectors.as_array().unwrap() {
        let input = hex_to_bytes(v["input"].as_str().unwrap());
        let bs = v["block_size"].as_u64().unwrap() as usize;
        let expected_padded = hex_to_bytes(v["padded"].as_str().unwrap());
        let expected_unpadded = hex_to_bytes(v["unpadded"].as_str().unwrap());

        let padded = pkcs7::pad(&input, bs);
        assert_eq!(padded, expected_padded, "PKCS7 pad mismatch: {}", v["description"]);
        let unpadded = pkcs7::unpad(&padded, bs).unwrap();
        assert_eq!(unpadded, &expected_unpadded[..], "PKCS7 unpad mismatch: {}", v["description"]);
    }
}

#[test]
fn test_sha256_interop() {
    let vectors = load_fixture("sha256_vectors.json");
    for v in vectors.as_array().unwrap() {
        let input = hex_to_bytes(v["input"].as_str().unwrap());
        let expected = hex_to_bytes(v["digest"].as_str().unwrap());

        let result = sha256::sha256(&input);
        assert_eq!(result.to_vec(), expected, "SHA256 mismatch: {}", v["description"]);
    }
}

#[test]
fn test_sha512_interop() {
    let vectors = load_fixture("sha512_vectors.json");
    for v in vectors.as_array().unwrap() {
        let input = hex_to_bytes(v["input"].as_str().unwrap());
        let expected = hex_to_bytes(v["digest"].as_str().unwrap());

        let result = sha512::sha512(&input);
        assert_eq!(result.to_vec(), expected, "SHA512 mismatch: {}", v["description"]);
    }
}

#[test]
fn test_hmac_interop() {
    let vectors = load_fixture("hmac_vectors.json");
    for v in vectors.as_array().unwrap() {
        let key = hex_to_bytes(v["key"].as_str().unwrap());
        let data = hex_to_bytes(v["data"].as_str().unwrap());
        let expected = hex_to_bytes(v["digest"].as_str().unwrap());

        let result = hmac::hmac_sha256(&key, &data);
        assert_eq!(result.to_vec(), expected, "HMAC mismatch: {}", v["description"]);
    }
}

#[test]
fn test_hkdf_interop() {
    let vectors = load_fixture("hkdf_vectors.json");
    for v in vectors.as_array().unwrap() {
        let length = v["length"].as_u64().unwrap() as usize;
        let ikm = hex_to_bytes(v["ikm"].as_str().unwrap());
        let salt = v["salt"].as_str().map(|s| hex_to_bytes(s));
        let context = v["context"].as_str().map(|s| hex_to_bytes(s));
        let expected = hex_to_bytes(v["derived"].as_str().unwrap());

        let result = hkdf::hkdf(
            length,
            &ikm,
            salt.as_deref(),
            context.as_deref(),
        ).unwrap();
        assert_eq!(result, expected, "HKDF mismatch: {}", v["description"]);
    }
}

#[test]
fn test_aes128_interop() {
    let vectors = load_fixture("aes128_vectors.json");
    for v in vectors.as_array().unwrap() {
        let key_bytes = hex_to_bytes(v["key"].as_str().unwrap());
        let iv_bytes = hex_to_bytes(v["iv"].as_str().unwrap());
        let plaintext = hex_to_bytes(v["plaintext"].as_str().unwrap());
        let expected_ct = hex_to_bytes(v["ciphertext"].as_str().unwrap());

        let key: [u8; 16] = key_bytes.try_into().unwrap();
        let iv: [u8; 16] = iv_bytes.try_into().unwrap();

        let cipher = aes128::Aes128::new(&key);
        let ciphertext = cipher.encrypt_cbc(&plaintext, &iv);
        assert_eq!(ciphertext, expected_ct, "AES128 encrypt mismatch: {}", v["description"]);

        let decrypted = cipher.decrypt_cbc(&ciphertext, &iv);
        assert_eq!(decrypted, plaintext, "AES128 decrypt mismatch: {}", v["description"]);
    }
}

#[test]
fn test_aes256_interop() {
    let vectors = load_fixture("aes256_vectors.json");
    for v in vectors.as_array().unwrap() {
        let key_bytes = hex_to_bytes(v["key"].as_str().unwrap());
        let iv_bytes = hex_to_bytes(v["iv"].as_str().unwrap());
        let plaintext = hex_to_bytes(v["plaintext"].as_str().unwrap());
        let expected_ct = hex_to_bytes(v["ciphertext"].as_str().unwrap());

        let key: [u8; 32] = key_bytes.try_into().unwrap();
        let iv: [u8; 16] = iv_bytes.try_into().unwrap();

        let cipher = aes256::Aes256::new(&key);
        let ciphertext = cipher.encrypt_cbc(&plaintext, &iv);
        assert_eq!(ciphertext, expected_ct, "AES256 encrypt mismatch: {}", v["description"]);

        let decrypted = cipher.decrypt_cbc(&ciphertext, &iv);
        assert_eq!(decrypted, plaintext, "AES256 decrypt mismatch: {}", v["description"]);
    }
}

#[test]
fn test_token_interop() {
    let vectors = load_fixture("token_vectors.json");
    for v in vectors.as_array().unwrap() {
        let key = hex_to_bytes(v["key"].as_str().unwrap());
        let iv_bytes = hex_to_bytes(v["iv"].as_str().unwrap());
        let plaintext = hex_to_bytes(v["plaintext"].as_str().unwrap());
        let expected_ct = hex_to_bytes(v["ciphertext"].as_str().unwrap());

        let iv: [u8; 16] = iv_bytes.try_into().unwrap();

        let token = token::Token::new(&key).unwrap();
        let ciphertext = token.encrypt_with_iv(&plaintext, &iv);
        assert_eq!(ciphertext, expected_ct, "Token encrypt mismatch: {}", v["description"]);

        let decrypted = token.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext, "Token decrypt mismatch: {}", v["description"]);

        // Also test decrypting Python-generated ciphertext directly
        let decrypted2 = token.decrypt(&expected_ct).unwrap();
        assert_eq!(decrypted2, plaintext, "Token decrypt Python ciphertext mismatch: {}", v["description"]);
    }
}

#[test]
fn test_x25519_interop() {
    let vectors = load_fixture("x25519_vectors.json");
    for v in vectors.as_array().unwrap() {
        let desc = v["description"].as_str().unwrap();
        if desc.ends_with("_pubkey") {
            // Public key derivation test
            let prv_bytes = hex_to_bytes(v["private"].as_str().unwrap());
            let expected_pub = hex_to_bytes(v["public"].as_str().unwrap());

            let prv_arr: [u8; 32] = prv_bytes.try_into().unwrap();
            let key = x25519::X25519PrivateKey::from_bytes(&prv_arr);
            let pub_key = key.public_key();
            assert_eq!(pub_key.public_bytes().to_vec(), expected_pub, "X25519 pubkey mismatch: {}", desc);
        } else if desc == "exchange_ab" {
            // Key exchange test
            let prv_a = hex_to_bytes(v["private_a"].as_str().unwrap());
            let pub_b = hex_to_bytes(v["public_b"].as_str().unwrap());
            let expected_shared = hex_to_bytes(v["shared_secret"].as_str().unwrap());

            let prv_a_arr: [u8; 32] = prv_a.try_into().unwrap();
            let pub_b_arr: [u8; 32] = pub_b.try_into().unwrap();

            let a = x25519::X25519PrivateKey::from_bytes(&prv_a_arr);
            let b_pub = x25519::X25519PublicKey::from_bytes(&pub_b_arr);
            let shared = a.exchange(&b_pub);
            assert_eq!(shared.to_vec(), expected_shared, "X25519 exchange mismatch");
        }
    }
}

#[test]
fn test_ed25519_interop() {
    let vectors = load_fixture("ed25519_vectors.json");
    for v in vectors.as_array().unwrap() {
        let seed = hex_to_bytes(v["seed"].as_str().unwrap());
        let expected_pub = hex_to_bytes(v["public"].as_str().unwrap());
        let message = hex_to_bytes(v["message"].as_str().unwrap());
        let expected_sig = hex_to_bytes(v["signature"].as_str().unwrap());

        let seed_arr: [u8; 32] = seed.try_into().unwrap();
        let key = ed25519::Ed25519PrivateKey::from_bytes(&seed_arr);

        let pub_key = key.public_key();
        assert_eq!(pub_key.public_bytes().to_vec(), expected_pub, "Ed25519 pubkey mismatch: {}", v["description"]);

        let sig = key.sign(&message);
        assert_eq!(sig.to_vec(), expected_sig, "Ed25519 sign mismatch: {}", v["description"]);

        // Verify Python signature
        let sig_arr: [u8; 64] = expected_sig.try_into().unwrap();
        assert!(pub_key.verify(&sig_arr, &message), "Ed25519 verify Python sig failed: {}", v["description"]);
    }
}

#[test]
fn test_identity_interop() {
    let vectors = load_fixture("identity_vectors.json");
    let v = &vectors.as_array().unwrap()[0];

    let prv_key = hex_to_bytes(v["private_key"].as_str().unwrap());
    let expected_pub = hex_to_bytes(v["public_key"].as_str().unwrap());
    let expected_hash = hex_to_bytes(v["identity_hash"].as_str().unwrap());
    let plaintext = hex_to_bytes(v["plaintext"].as_str().unwrap());
    let python_ciphertext = hex_to_bytes(v["ciphertext"].as_str().unwrap());
    let sign_message = hex_to_bytes(v["sign_message"].as_str().unwrap());
    let python_signature = hex_to_bytes(v["signature"].as_str().unwrap());

    let prv_arr: [u8; 64] = prv_key.try_into().unwrap();
    let id = identity::Identity::from_private_key(&prv_arr);

    // Verify public key matches
    let pub_key = id.get_public_key().unwrap();
    assert_eq!(pub_key.to_vec(), expected_pub, "Identity public key mismatch");

    // Verify hash matches
    assert_eq!(id.hash().to_vec(), expected_hash, "Identity hash mismatch");

    // THE MILESTONE: Decrypt Python-generated ciphertext
    let decrypted = id.decrypt(&python_ciphertext).unwrap();
    assert_eq!(decrypted, plaintext, "MILESTONE FAILED: Cannot decrypt Python ciphertext in Rust!");

    // Verify deterministic encryption matches Python
    let ephemeral_prv = hex_to_bytes(v["ephemeral_private"].as_str().unwrap());
    let fixed_iv = hex_to_bytes(v["fixed_iv"].as_str().unwrap());
    let eph_arr: [u8; 32] = ephemeral_prv.try_into().unwrap();
    let iv_arr: [u8; 16] = fixed_iv.try_into().unwrap();

    let rust_ciphertext = id.encrypt_deterministic(&plaintext, &eph_arr, &iv_arr).unwrap();
    assert_eq!(rust_ciphertext, python_ciphertext, "Rust encrypt doesn't match Python encrypt");

    // Verify Python signature
    let sig_arr: [u8; 64] = python_signature.clone().try_into().unwrap();
    assert!(id.verify(&sig_arr, &sign_message), "Cannot verify Python signature in Rust!");

    // Sign in Rust and verify the round-trip
    let rust_sig = id.sign(&sign_message).unwrap();
    assert_eq!(rust_sig.to_vec(), python_signature, "Rust signature doesn't match Python signature");

    println!("=== MILESTONE ACHIEVED ===");
    println!("Python Token.encrypt() -> Rust decrypt(): OK");
    println!("Rust Token.encrypt()   -> matches Python: OK");
    println!("Python Ed25519 sign()  -> Rust verify():  OK");
    println!("Rust Ed25519 sign()    -> matches Python: OK");
}
