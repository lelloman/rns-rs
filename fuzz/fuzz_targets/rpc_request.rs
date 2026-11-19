//! What a local client can send the RPC server: the handshake before it
//! authenticates, and a request after.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_net::rpc::fuzz;

fuzz_target!(|data: &[u8]| {
    fuzz::handshake(data);
    fuzz::request(data);
});
