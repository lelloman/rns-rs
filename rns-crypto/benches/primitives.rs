//! Deterministic microbench fixtures only; never use these keys/IVs in applications.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rns_crypto::{
    identity::Identity,
    token::{Token, TokenError},
    x25519::X25519PrivateKey,
};
use std::hint::black_box;

fn signatures(c: &mut Criterion) {
    let private = Identity::from_private_key(&[0x37; 64]);
    let public = Identity::from_public_key(&private.get_public_key().unwrap());
    let mut group = c.benchmark_group("crypto-v1/ed25519");
    for bytes in [32, 1024, 65536] {
        let message: Vec<u8> = (0..bytes).map(|n| (n % 251) as u8).collect();
        let signature = private.sign(&message).unwrap();
        let mut wrong_message = message.clone();
        wrong_message[0] ^= 1;
        assert!(public.verify(&signature, &message));
        assert!(!public.verify(&signature, &wrong_message));
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_with_input(BenchmarkId::new("sign", bytes), &message, |b, m| {
            b.iter(|| black_box(private.sign(black_box(m)).unwrap()))
        });
        group.bench_with_input(BenchmarkId::new("verify-valid", bytes), &message, |b, m| {
            b.iter(|| {
                assert!(black_box(
                    public.verify(black_box(&signature), black_box(m))
                ))
            })
        });
        group.bench_with_input(
            BenchmarkId::new("verify-wrong-message", bytes),
            &wrong_message,
            |b, m| {
                b.iter(|| {
                    assert!(!black_box(
                        public.verify(black_box(&signature), black_box(m))
                    ))
                })
            },
        );
    }
    group.finish();
}

fn agreement(c: &mut Criterion) {
    let alice = X25519PrivateKey::from_bytes(&[0x31; 32]);
    let bob = X25519PrivateKey::from_bytes(&[0x73; 32]);
    let peer = bob.public_key();
    assert_eq!(alice.exchange(&peer), bob.exchange(&alice.public_key()));
    assert_ne!(alice.exchange(&peer), [0; 32]);
    c.bench_function("crypto-v1/x25519/exchange", |b| {
        b.iter(|| black_box(alice.exchange(black_box(&peer))))
    });
}

fn tokens(c: &mut Criterion) {
    for key_bytes in [32, 64] {
        let token = Token::new(&vec![0x42; key_bytes]).unwrap();
        let mut group = c.benchmark_group(format!(
            "crypto-v1/token-aes{}",
            if key_bytes == 32 { 128 } else { 256 }
        ));
        for bytes in [32, 1024, 65536] {
            let data: Vec<u8> = (0..bytes).map(|n| (n % 251) as u8).collect();
            // Exclude RNG and key construction: this fixture measures the codec.
            let iv = [0x19; 16];
            let encrypted = token.encrypt_with_iv(&data, &iv);
            let mut corrupt = encrypted.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            assert_eq!(token.decrypt(&encrypted).unwrap(), data);
            assert_eq!(
                token.decrypt(&corrupt).unwrap_err(),
                TokenError::HmacMismatch
            );
            group.throughput(Throughput::Bytes(bytes as u64));
            group.bench_with_input(
                BenchmarkId::new("encrypt-fixed-iv", bytes),
                &data,
                |b, data| {
                    b.iter(|| black_box(token.encrypt_with_iv(black_box(data), black_box(&iv))))
                },
            );
            group.bench_with_input(
                BenchmarkId::new("decrypt-valid", bytes),
                &encrypted,
                |b, data| b.iter(|| black_box(token.decrypt(black_box(data)).unwrap())),
            );
            group.bench_with_input(
                BenchmarkId::new("reject-bad-mac", bytes),
                &corrupt,
                |b, data| {
                    b.iter(|| {
                        assert_eq!(
                            black_box(token.decrypt(black_box(data))).unwrap_err(),
                            TokenError::HmacMismatch
                        )
                    })
                },
            );
        }
        group.finish();
    }
}
criterion_group! {
    name = benches;
    config = Criterion::default().output_directory(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/criterion")
    );
    targets = signatures, agreement, tokens
}
criterion_main!(benches);
