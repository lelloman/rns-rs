//! KISS deframing of byte streams from TNCs and RNodes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_net::kiss::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new();
    for chunk in data.chunks(5) {
        let _ = decoder.feed(chunk);
    }
});
