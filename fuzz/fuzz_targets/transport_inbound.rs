//! Packets from any interface into a transport node: path requests and
//! responses, announces, link traffic and proofs to forward or deliver.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rns_core::transport::fuzz::inbound(data);
});
