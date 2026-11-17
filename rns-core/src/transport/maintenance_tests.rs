use super::super::engine_fixtures::engine;
use super::*;

/// Upstream culls a path request gate once more than
/// PATH_REQUEST_GATE_TIMEOUT has passed, and a discovery path request once
/// past its timeout: both are still there at exactly that time.
#[test]
fn path_request_gates_and_searches_last_through_their_timeout() {
    let mut engine = engine(true);
    let mut rng = rns_crypto::FixedRng::new(&[0x21; 32]);
    let gated = [0xA1; 16];
    let searched = [0xA2; 16];
    engine.record_outbound_path_request(gated, 1000.0 - constants::PATH_REQUEST_GATE_TIMEOUT);
    engine.discovery_path_requests.insert(
        searched,
        DiscoveryPathRequest {
            timestamp: 1000.0 - constants::DISCOVERY_PATH_REQUEST_TIMEOUT,
            requesting_interfaces: Vec::new(),
            engaged: true,
        },
    );
    engine.tick(1000.0, &mut rng);
    assert!(engine.path_requests.contains_key(&gated));
    assert!(engine.discovery_path_requests.contains_key(&searched));

    engine.tick(1006.0, &mut rng);
    assert!(!engine.path_requests.contains_key(&gated));
    assert!(!engine.discovery_path_requests.contains_key(&searched));
}
