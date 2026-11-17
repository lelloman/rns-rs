//! Direct Link signalling arrives from the link peer: the version and kind
//! framing and each message's msgpack body, with the optional fields of
//! UPGRADE_REQUEST and UPGRADE_READY (host candidates `h`, largest packet
//! `m`).
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_core::holepunch::{self, HolePunchEngine, ProbeProtocol};

fuzz_target!(|data: &[u8]| {
    if let Some((kind, body)) = holepunch::decode_signal(data) {
        let _ = holepunch::validate_signal(kind, body);
    }
    for kind in 0..=6u8 {
        let _ = holepunch::validate_signal(kind, data);
    }
    let _ = holepunch::decode_hello(data);
    let _ = holepunch::decode_fallback(data);
    let _ = HolePunchEngine::validate_upgrade_request(data);
    let _ = HolePunchEngine::request_session_id(data);
    // A responder taking the body as a request, then as each later message.
    let mut engine = HolePunchEngine::new([1; 16], None, ProbeProtocol::Rnsp);
    let _ = engine.handle_signal(holepunch::UPGRADE_REQUEST, data, Some(&[7; 64]), 1.0);
    let _ = engine.endpoints_discovered(
        holepunch::Endpoint {
            addr: vec![203, 0, 113, 1],
            port: 4000,
        },
        2.0,
    );
    let _ = engine.peer_max_packet();
    let _ = engine.peer_host_endpoints();
    let _ = engine.replay_replies();
    for kind in [
        holepunch::UPGRADE_ACCEPT,
        holepunch::UPGRADE_REJECT,
        holepunch::UPGRADE_READY,
    ] {
        let _ = engine.handle_signal(kind, data, None, 3.0);
    }
    // An initiator taking the body as the responder's READY.
    let mut initiator = HolePunchEngine::new(
        [1; 16],
        Some(holepunch::Endpoint {
            addr: vec![203, 0, 113, 9],
            port: 4343,
        }),
        ProbeProtocol::Rnsp,
    );
    let mut rng = rns_crypto::FixedRng::new(&[3; 32]);
    if initiator.propose(&[7; 64], 1.0, &mut rng).is_ok() {
        let _ = initiator.endpoints_discovered(
            holepunch::Endpoint {
                addr: vec![203, 0, 113, 2],
                port: 4000,
            },
            2.0,
        );
        let _ = initiator.handle_signal(holepunch::UPGRADE_ACCEPT, data, None, 3.0);
        let _ = initiator.handle_signal(holepunch::UPGRADE_READY, data, None, 4.0);
        let _ = initiator.peer_max_packet();
        let _ = initiator.peer_host_endpoints();
    }
});
