//! Announce parsing and validation, on bytes from the network.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_core::announce::AnnounceData;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let has_ratchet = selector & 1 == 1;
    let Some((dest, payload)) = rest.split_at_checked(16) else {
        return;
    };
    let destination_hash: [u8; 16] = dest.try_into().unwrap();
    if let Ok(announce) = AnnounceData::unpack(payload, has_ratchet) {
        let _ = announce.validate(&destination_hash);
    }
});
