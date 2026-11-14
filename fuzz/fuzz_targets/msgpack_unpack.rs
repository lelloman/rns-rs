//! msgpack carries announce app data, resource advertisements, requests and
//! responses from the network.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_core::msgpack;

fuzz_target!(|data: &[u8]| {
    let _ = msgpack::unpack(data);
    let _ = msgpack::unpack_exact(data);
    let _ = msgpack::unpack_exact_ref(data);
    if let Ok((value, used)) = msgpack::unpack(data) {
        let packed = msgpack::pack(&value);
        let (again, _) = msgpack::unpack(&packed).expect("packed msgpack must unpack");
        let _ = (again, used);
    }
});
