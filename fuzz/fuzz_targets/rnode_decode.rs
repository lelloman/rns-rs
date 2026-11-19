//! KISS frames from an RNode: radio data, status, statistics and replies.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_net::rnode_kiss::RNodeDecoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = RNodeDecoder::new();
    for chunk in data.chunks(5) {
        let _ = decoder.feed(chunk);
    }
});
