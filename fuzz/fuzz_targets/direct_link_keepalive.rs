//! A direct path's keepalives and path MTU probes arrive from the peer's
//! address, which anyone can spoof.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_net::holepunch::fuzz;

fuzz_target!(|data: &[u8]| {
    fuzz::keepalive(data);
    fuzz::path_mtu_datagram(data);
});
