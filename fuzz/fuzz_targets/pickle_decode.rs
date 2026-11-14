//! The RPC server decodes whatever reaches its socket with this hand-written
//! pickle decoder: it must never panic, and what it decodes must survive
//! re-encoding.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_net::pickle::{decode, encode};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = decode(data) {
        let reencoded = encode(&value);
        let again = decode(&reencoded).expect("re-encoded pickle must decode");
        // NaN floats do not compare equal to themselves.
        if format!("{value:?}").contains("NaN") {
            return;
        }
        assert_eq!(value, again);
    }
});
