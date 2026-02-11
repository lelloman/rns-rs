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
