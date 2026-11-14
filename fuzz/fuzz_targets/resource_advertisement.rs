//! Resource advertisements arrive from link peers.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_core::resource::ResourceAdvertisement;

fuzz_target!(|data: &[u8]| {
    let _ = ResourceAdvertisement::unpack(data);
});
