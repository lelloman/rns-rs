//! Retained-key search scaling. Fixture generation and ring destruction are untimed.
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use rns_crypto::{
    identity::Identity,
    ratchet::{ratchet_id, RatchetRing},
    sha256::sha256,
    x25519::X25519PrivateKey,
    FixedRng,
};
use std::hint::black_box;

fn key(index: u64) -> [u8; 32] {
    let mut input = [0x52; 16];
    input[8..].copy_from_slice(&index.to_le_bytes());
    sha256(&input)
}

fn ratchets(c: &mut Criterion) {
    let identity = Identity::from_private_key(&[0x37; 64]);
    let data: Vec<u8> = (0..128).map(|n| n as u8).collect();
    let mut rng = FixedRng::new(&[0x63; 64]);
    let legacy = identity.encrypt(&data, &mut rng).unwrap();
    let missing_key = X25519PrivateKey::from_bytes(&key(4096))
        .public_key()
        .public_bytes();
    let missing = identity
        .encrypt_with_ratchet(&data, Some(&missing_key), &mut rng)
        .unwrap();
    let mut group = c.benchmark_group("ratchets-v1/decrypt-128B");
    // Flat sampling avoids a triangular iteration budget for 4096-key scans.
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));
    for retained in [1, 32, 512, 4096] {
        let ring = RatchetRing::from_keys((0..retained).map(|n| key(n as u64)).collect()).unwrap();
        for (position, index) in [("newest", 0), ("oldest", retained - 1)] {
            let public = X25519PrivateKey::from_bytes(&ring.keys()[index])
                .public_key()
                .public_bytes();
            let ciphertext = identity
                .encrypt_with_ratchet(&data, Some(&public), &mut rng)
                .unwrap();
            for enforce in [true, false] {
                let result = identity
                    .decrypt_with_ratchets(&ciphertext, &ring, enforce)
                    .unwrap();
                assert_eq!(result.plaintext, data);
                assert_eq!(result.ratchet_id, Some(ratchet_id(&public)));
                let policy = if enforce {
                    "enforced"
                } else {
                    "fallback-allowed"
                };
                group.bench_function(
                    BenchmarkId::new(format!("{position}-{policy}"), retained),
                    |b| {
                        b.iter(|| {
                            black_box(
                                identity
                                    .decrypt_with_ratchets(
                                        black_box(&ciphertext),
                                        black_box(&ring),
                                        enforce,
                                    )
                                    .unwrap(),
                            )
                        })
                    },
                );
            }
        }
        for enforce in [true, false] {
            let policy = if enforce {
                "enforced"
            } else {
                "fallback-allowed"
            };
            assert!(identity
                .decrypt_with_ratchets(&missing, &ring, enforce)
                .is_err());
            group.bench_function(
                BenchmarkId::new(format!("no-match-{policy}"), retained),
                |b| {
                    b.iter(|| {
                        assert!(black_box(identity.decrypt_with_ratchets(
                            black_box(&missing),
                            black_box(&ring),
                            enforce
                        ))
                        .is_err())
                    })
                },
            );
        }
        let result = identity
            .decrypt_with_ratchets(&legacy, &ring, false)
            .unwrap();
        assert_eq!(result.plaintext, data);
        assert_eq!(result.ratchet_id, None);
        assert!(identity
            .decrypt_with_ratchets(&legacy, &ring, true)
            .is_err());
        group.bench_function(
            BenchmarkId::new("identity-fallback-success", retained),
            |b| {
                b.iter(|| {
                    black_box(
                        identity
                            .decrypt_with_ratchets(black_box(&legacy), black_box(&ring), false)
                            .unwrap(),
                    )
                })
            },
        );
        group.bench_function(
            BenchmarkId::new("identity-fallback-forbidden", retained),
            |b| {
                b.iter(|| {
                    assert!(black_box(identity.decrypt_with_ratchets(
                        black_box(&legacy),
                        black_box(&ring),
                        true
                    ))
                    .is_err())
                })
            },
        );
    }
    group.finish();
}
criterion_group! {
    name = benches;
    config = Criterion::default().output_directory(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/criterion")
    );
    targets = ratchets
}
criterion_main!(benches);
