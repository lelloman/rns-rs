//! Link requests and link proofs arrive from the network.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rns_core::link::handshake::{
    parse_linkrequest_data, parse_signalling_bytes, unpack_rtt, validate_lrproof,
};
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};

fn key() -> &'static (Ed25519PublicKey, [u8; 32]) {
    static KEY: OnceLock<(Ed25519PublicKey, [u8; 32])> = OnceLock::new();
    KEY.get_or_init(|| {
        let public = Ed25519PrivateKey::from_bytes(&[7; 32]).public_key();
        let bytes = public.public_bytes();
        (public, bytes)
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_linkrequest_data(data);
    if let Some(bytes) = data.first_chunk::<3>() {
        let _ = parse_signalling_bytes(bytes);
    }
    let _ = unpack_rtt(data);
    let (public, public_bytes) = key();
    let link_id = [0x42; 16];
    let _ = validate_lrproof(data, &link_id, public, public_bytes);
});
