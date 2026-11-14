//! IFAC unmasking runs on every frame of an interface with access codes,
//! before anything else checks it. Masking then unmasking must round-trip.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rns_net::ifac::{derive_ifac, mask_outbound, unmask_inbound, IfacState};

fn state() -> &'static IfacState {
    static STATE: OnceLock<IfacState> = OnceLock::new();
    STATE.get_or_init(|| derive_ifac(Some("fuzz"), Some("passphrase"), 16).unwrap())
}

fuzz_target!(|data: &[u8]| {
    let state = state();
    let _ = unmask_inbound(data, state);
    // A packet with the IFAC flag clear and a payload, masked and unmasked
    // again (two bytes are header only, which upstream rejects too).
    if data.len() >= 3 {
        let mut raw = data.to_vec();
        raw[0] &= 0x7f;
        let masked = mask_outbound(&raw, state);
        assert_eq!(unmask_inbound(&masked, state).as_deref(), Some(&raw[..]));
    }
});
