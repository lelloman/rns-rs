//! Simple timing benchmarks for crypto operations.
//! Run with: cargo test -p rns-crypto bench_ -- --nocapture

use rns_crypto::*;

fn now() -> std::time::Instant {
    std::time::Instant::now()
}

#[test]
fn bench_ed25519_sign() {
    let seed = [42u8; 32];
    let key = ed25519::Ed25519PrivateKey::from_bytes(&seed);
    let msg = b"benchmark message for signing";

    // Warmup
    let _ = key.sign(msg);

    let n = 1000;
    let start = now();
    for _ in 0..n {
        let _ = key.sign(msg);
    }
    let elapsed = start.elapsed();
    println!(
        "Ed25519 sign: {} iterations in {:.3}s ({:.3} ms/op)",
        n,
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0 / n as f64
    );
}

#[test]
fn bench_ed25519_verify() {
    let seed = [42u8; 32];
    let key = ed25519::Ed25519PrivateKey::from_bytes(&seed);
    let pubkey = key.public_key();
    let msg = b"benchmark message for verification";
    let sig = key.sign(msg);

    // Warmup
    let _ = pubkey.verify(&sig, msg);

    let n = 1000;
    let start = now();
    for _ in 0..n {
        let _ = pubkey.verify(&sig, msg);
    }
    let elapsed = start.elapsed();
    println!(
        "Ed25519 verify: {} iterations in {:.3}s ({:.3} ms/op)",
        n,
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0 / n as f64
    );
}

#[test]
fn bench_x25519_keygen() {
    let bytes = [42u8; 32];
    let key = x25519::X25519PrivateKey::from_bytes(&bytes);

    // Warmup
    let _ = key.public_key();

    let n = 1000;
    let start = now();
    for _ in 0..n {
        let _ = key.public_key();
    }
    let elapsed = start.elapsed();
    println!(
        "X25519 keygen: {} iterations in {:.3}s ({:.3} ms/op)",
        n,
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0 / n as f64
    );
}

#[test]
fn bench_x25519_exchange() {
    let a_bytes = [42u8; 32];
    let b_bytes = [99u8; 32];
    let a = x25519::X25519PrivateKey::from_bytes(&a_bytes);
    let b = x25519::X25519PrivateKey::from_bytes(&b_bytes);
    let b_pub = b.public_key();

    // Warmup
    let _ = a.exchange(&b_pub);

    let n = 1000;
    let start = now();
    for _ in 0..n {
        let _ = a.exchange(&b_pub);
    }
    let elapsed = start.elapsed();
    println!(
        "X25519 exchange: {} iterations in {:.3}s ({:.3} ms/op)",
        n,
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0 / n as f64
    );
}

#[test]
fn bench_identity_encrypt() {
    let mut rng = FixedRng::new(&(0..128).collect::<Vec<u8>>());
    let id = identity::Identity::new(&mut rng);
    let plaintext = b"Hello, Reticulum! Benchmarking encrypt/decrypt.";

    // Warmup
    let mut rng2 = FixedRng::new(&(128..255).collect::<Vec<u8>>());
    let ct = id.encrypt(plaintext, &mut rng2).unwrap();
    let _ = id.decrypt(&ct).unwrap();

    let n = 100;
    let start = now();
    for _ in 0..n {
        let mut rng3 = FixedRng::new(&(128..255).collect::<Vec<u8>>());
        let ct = id.encrypt(plaintext, &mut rng3).unwrap();
        let _ = id.decrypt(&ct).unwrap();
    }
    let elapsed = start.elapsed();
    println!(
        "Identity encrypt+decrypt: {} iterations in {:.3}s ({:.3} ms/op)",
        n,
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0 / n as f64
    );
}

#[test]
fn bench_sha256() {
    let data = vec![0xABu8; 1024];
    let n = 10_000;

    let _ = sha256::sha256(&data);

    let start = now();
    for _ in 0..n {
        let _ = sha256::sha256(&data);
    }
    let elapsed = start.elapsed();
    println!(
        "SHA-256 (1 KB x {}): {:.3} ms/op",
        n,
        elapsed.as_secs_f64() * 1000.0 / n as f64,
    );
}

#[test]
fn bench_sha512() {
    let data = vec![0xABu8; 1024];
    let n = 10_000;

    let _ = sha512::sha512(&data);

    let start = now();
    for _ in 0..n {
        let _ = sha512::sha512(&data);
    }
    let elapsed = start.elapsed();
    println!(
        "SHA-512 (1 KB x {}): {:.3} ms/op",
        n,
        elapsed.as_secs_f64() * 1000.0 / n as f64,
    );
}

#[test]
fn bench_hmac_sha256() {
    let key = [0x42u8; 32];
    let data = vec![0xABu8; 1024];
    let n = 10_000;

    let _ = hmac::hmac_sha256(&key, &data);

    let start = now();
    for _ in 0..n {
        let _ = hmac::hmac_sha256(&key, &data);
    }
    let elapsed = start.elapsed();
    println!(
        "HMAC-SHA256 (1 KB x {}): {:.3} ms/op",
        n,
        elapsed.as_secs_f64() * 1000.0 / n as f64,
    );
}

#[test]
fn bench_aes128_cbc() {
    let key = [0x42u8; 16];
    let iv = [0x00u8; 16];
    let plaintext = vec![0xABu8; 1024];
    let padded = pkcs7::pad(&plaintext, 16);
    let n = 10_000;

    let cipher = aes128::Aes128::new(&key);
    let ciphertext = cipher.encrypt_cbc(&padded, &iv);

    let start = now();
    for _ in 0..n {
        let _ = cipher.encrypt_cbc(&padded, &iv);
    }
    let enc = start.elapsed();

    let start = now();
    for _ in 0..n {
        let _ = cipher.decrypt_cbc(&ciphertext, &iv);
    }
    let dec = start.elapsed();

    println!(
        "AES-128-CBC (1 KB x {}): encrypt {:.3} ms/op, decrypt {:.3} ms/op",
        n,
        enc.as_secs_f64() * 1000.0 / n as f64,
        dec.as_secs_f64() * 1000.0 / n as f64,
    );
}

#[test]
fn bench_aes256_cbc() {
    let key = [0x42u8; 32];
    let iv = [0x00u8; 16];
    let plaintext = vec![0xABu8; 1024];
    let padded = pkcs7::pad(&plaintext, 16);
    let n = 10_000;

    let cipher = aes256::Aes256::new(&key);
    let ciphertext = cipher.encrypt_cbc(&padded, &iv);

    let start = now();
    for _ in 0..n {
        let _ = cipher.encrypt_cbc(&padded, &iv);
    }
    let enc = start.elapsed();

    let start = now();
    for _ in 0..n {
        let _ = cipher.decrypt_cbc(&ciphertext, &iv);
    }
    let dec = start.elapsed();

    println!(
        "AES-256-CBC (1 KB x {}): encrypt {:.3} ms/op, decrypt {:.3} ms/op",
        n,
        enc.as_secs_f64() * 1000.0 / n as f64,
        dec.as_secs_f64() * 1000.0 / n as f64,
    );
}

#[test]
fn bench_token() {
    let key = [0x42u8; 32];
    let plaintext = vec![0xABu8; 1024];
    let n = 1_000;

    let tok = token::Token::new(&key).unwrap();

    let start = now();
    for _ in 0..n {
        let mut rng = FixedRng::new(&(0..128).collect::<Vec<u8>>());
        let ct = tok.encrypt(&plaintext, &mut rng);
        let _ = tok.decrypt(&ct).unwrap();
    }
    let elapsed = start.elapsed();

    println!(
        "Token encrypt+decrypt (1 KB x {}): {:.3} ms/op",
        n,
        elapsed.as_secs_f64() * 1000.0 / n as f64,
    );
}
