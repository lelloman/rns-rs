//! Punch packets and their acknowledgements arrive from anyone who can
//! send to the punch socket.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_net::holepunch::fuzz;

fuzz_target!(|data: &[u8]| {
    fuzz::punch_datagram(data);
});
