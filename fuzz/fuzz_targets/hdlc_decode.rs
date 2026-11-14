//! HDLC deframing of byte streams from TCP, serial and pipe interfaces.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_net::hdlc::{frame, Decoder};

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::reticulum(500, 16);
    for chunk in data.chunks(7) {
        let _ = decoder.feed_with_diagnostics(chunk);
    }
    // A framed payload longer than the header minimum and within the MTU
    // decodes back to itself (shorter frames are dropped, as upstream).
    if (20..=500).contains(&data.len()) {
        let mut decoder = Decoder::reticulum(500, 0);
        let frames = decoder.feed(&frame(data));
        assert_eq!(frames, vec![data.to_vec()]);
    }
});
