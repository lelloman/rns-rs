//! Probe requests arrive at a facilitator from anyone; probe replies (RNSP
//! and STUN) arrive at the probing socket from anyone.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_net::fuzz::holepunch as fuzz;

fuzz_target!(|data: &[u8]| {
    fuzz::probe_request(data);
    fuzz::probe_reply(data);
});
