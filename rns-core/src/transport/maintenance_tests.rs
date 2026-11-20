use super::super::engine_fixtures::{config, engine, interface, path_entry};
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

fn random_blob(timebase: u64) -> [u8; 10] {
    let mut blob = [0u8; 10];
    blob[5..10].copy_from_slice(&timebase.to_be_bytes()[3..8]);
    blob
}

fn announce_data(timebase: u64) -> Vec<u8> {
    let mut data = vec![0u8; constants::KEYSIZE / 8 + constants::NAME_HASH_LENGTH / 8];
    data.extend_from_slice(&random_blob(timebase));
    data.extend_from_slice(&[0x55; 64]);
    data
}

/// The prefilter drops an announce older than the known path only under
/// upstream's single path per destination and without preferring shorter
/// paths; otherwise every announce may still change the path table.
#[test]
fn prefilter_keeps_every_announce_with_multiple_paths_or_shorter_preference() {
    let destination = [0xB1; 16];
    let mut interfaces = BTreeMap::new();
    interfaces.insert(InterfaceId(1), interface(1, constants::MODE_FULL));
    let mut path = path_entry(&destination, 1000.0, 2, InterfaceId(1), [0x77; 16]);
    path.random_blobs = vec![random_blob(1000)];
    let mut path_table = BTreeMap::new();
    path_table.insert(destination, PathSet::from_single(path, 1));
    let older = announce_data(900);

    let passes = |config: &TransportConfig| {
        announce_passes_prefilter(
            config,
            &path_table,
            &BTreeMap::new(),
            &interfaces,
            &destination,
            &older,
            InterfaceId(1),
            1000.0,
        )
    };
    let mut single = config(true);
    assert!(!passes(&single));
    single.max_paths_per_destination = 2;
    assert!(passes(&single));
    let mut shorter = config(true);
    shorter.prefer_shorter_path = true;
    assert!(passes(&shorter));
}

fn rediscovery_engine() -> TransportEngine {
    let mut engine = engine(true);
    for id in 1..=2 {
        engine.register_interface(interface(id, constants::MODE_FULL));
    }
    engine
}

fn unproven_link(engine: &mut TransportEngine, link: u8, destination: [u8; 16], proof: f64) {
    engine.link_table.insert(
        [link; 16],
        LinkEntry {
            timestamp: 1000.0,
            next_hop_transport_id: [0x77; 16],
            next_hop_interface: InterfaceId(2),
            remaining_hops: 2,
            received_interface: InterfaceId(1),
            taken_hops: 3,
            destination_hash: destination,
            validated: false,
            proof_timeout: proof,
        },
    );
}

fn one_hop_path(engine: &mut TransportEngine, destination: [u8; 16]) {
    engine.path_table.insert(
        destination,
        PathSet::from_single(
            path_entry(&destination, 1000.0, 1, InterfaceId(2), [0x77; 16]),
            1,
        ),
    );
}

fn queued_rediscoveries(engine: &TransportEngine) -> Vec<[u8; 16]> {
    engine
        .pending_discovery_prs
        .iter()
        .map(|(destination, _)| *destination)
        .collect()
}

/// Transport.py:1046: only a link request whose proof timeout has passed
/// counts as unproven.
#[test]
fn link_awaiting_its_proof_triggers_no_rediscovery() {
    let mut engine = rediscovery_engine();
    let mut rng = rns_crypto::FixedRng::new(&[0x21; 32]);
    unproven_link(&mut engine, 1, [0xC1; 16], 1020.0);
    unproven_link(&mut engine, 2, [0xC2; 16], 1030.0);
    engine.tick(1020.0, &mut rng);
    assert!(engine.pending_discovery_prs.is_empty());
}

/// Every vanished destination is queued, each once.
#[test]
fn unproven_links_queue_each_destination_once() {
    let mut engine = rediscovery_engine();
    let mut rng = rns_crypto::FixedRng::new(&[0x21; 32]);
    unproven_link(&mut engine, 1, [0xC1; 16], 1010.0);
    unproven_link(&mut engine, 2, [0xC2; 16], 1010.0);
    unproven_link(&mut engine, 3, [0xC1; 16], 1010.0);
    engine.tick(1020.0, &mut rng);
    assert_eq!(queued_rediscoveries(&engine), vec![[0xC1; 16], [0xC2; 16]]);
}

/// A known path is rediscovered again once PATH_REQUEST_MI has passed
/// since the last path request for it.
#[test]
fn rediscovery_throttle_lasts_path_request_mi() {
    for (requested, throttled) in [
        (1020.0 - constants::PATH_REQUEST_MI + 0.5, true),
        (1020.0 - constants::PATH_REQUEST_MI, false),
    ] {
        let mut engine = rediscovery_engine();
        let mut rng = rns_crypto::FixedRng::new(&[0x21; 32]);
        one_hop_path(&mut engine, [0xC3; 16]);
        unproven_link(&mut engine, 1, [0xC3; 16], 1010.0);
        engine.record_outbound_path_request([0xC3; 16], requested);
        engine.tick(1020.0, &mut rng);
        assert_eq!(
            engine.pending_discovery_prs.is_empty(),
            throttled,
            "requested at {requested}"
        );
    }
}

fn due_announce(engine: &mut TransportEngine, destination: [u8; 16], due: f64) {
    engine.insert_announce_entry(
        destination,
        AnnounceEntry {
            timestamp: due,
            retransmit_timeout: due,
            retries: 0,
            received_from: [0xAA; 16],
            hops: 2,
            packet_raw: super::super::engine_fixtures::announce_raw(&destination, &[0xCC; 10]),
            packet_data: vec![0xCC; 10],
            destination_hash: destination,
            context_flag: 0,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
            packet_hash: [0; 32],
            blocked_interfaces: Default::default(),
        },
        due,
    );
}

/// Pending announces are checked once every ANNOUNCES_CHECK_INTERVAL.
#[test]
fn pending_announces_are_checked_every_check_interval() {
    let mut engine = engine(true);
    engine.register_interface(interface(1, constants::MODE_FULL));
    let mut rng = rns_crypto::FixedRng::new(&[0x21; 32]);
    assert!(engine.tick(100.0, &mut rng).is_empty());

    due_announce(&mut engine, [0xD1; 16], 100.1);
    assert!(engine.tick(100.5, &mut rng).is_empty());
    assert!(!engine
        .tick(100.0 + constants::ANNOUNCES_CHECK_INTERVAL + 0.25, &mut rng)
        .is_empty());
}

/// The tables are culled once every TABLES_CULL_INTERVAL.
#[test]
fn tables_are_culled_every_cull_interval() {
    let mut engine = engine(true);
    let mut rng = rns_crypto::FixedRng::new(&[0x21; 32]);
    engine.tick(1000.0, &mut rng);
    engine.record_outbound_path_request([0xE1; 16], 900.0);
    engine.tick(1002.0, &mut rng);
    assert!(engine.path_requests.contains_key(&[0xE1; 16]));
    engine.tick(1000.0 + constants::TABLES_CULL_INTERVAL + 0.5, &mut rng);
    assert!(!engine.path_requests.contains_key(&[0xE1; 16]));
}

/// A path request waiting on a local client's answer is forgotten once
/// its interface is gone or PATH_REQUEST_TIMEOUT has passed.
#[test]
fn waiting_local_path_requests_expire() {
    let mut engine = engine(true);
    engine.register_interface(interface(1, constants::MODE_FULL));
    let mut rng = rns_crypto::FixedRng::new(&[0x21; 32]);
    let now = 1000.0;
    let timeout = constants::PATH_REQUEST_TIMEOUT;
    for (destination, interface, requested) in [
        (0xF1, 1, now - timeout + 1.0),
        (0xF2, 1, now - timeout),
        (0xF3, 9, now),
        (0xF4, 1, now - 2.0 * timeout),
    ] {
        engine
            .pending_local_path_requests
            .insert([destination; 16], (InterfaceId(interface), requested));
    }
    engine.tick(now, &mut rng);
    let left: Vec<_> = engine.pending_local_path_requests.keys().copied().collect();
    assert_eq!(left, vec![[0xF1; 16]]);
}

#[test]
fn rebroadcast_skips_the_excluded_interface() {
    let mut engine = engine(true);
    for id in 1..=3 {
        engine.register_interface(interface(id, constants::MODE_FULL));
    }
    engine.register_destination([0xD2; 16], constants::DESTINATION_SINGLE);
    let raw = super::super::engine_fixtures::announce_raw(&[0xD2; 16], &[0xCC; 10]);
    let actions = engine.gate_retransmit_actions(
        vec![TransportAction::BroadcastOnAllInterfaces {
            raw: raw.into(),
            exclude: Some(InterfaceId(2)),
        }],
        &BTreeMap::new(),
        1000.0,
    );
    let sent: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            TransportAction::SendOnInterface { interface, .. } => Some(*interface),
            _ => None,
        })
        .collect();
    assert_eq!(sent, vec![InterfaceId(1), InterfaceId(3)]);
}

#[test]
fn announce_info_reads_the_destination_from_a_minimal_header() {
    let mut raw = vec![constants::PACKET_TYPE_ANNOUNCE, 4];
    raw.extend_from_slice(&[0xD3; 16]);
    assert_eq!(
        TransportEngine::extract_announce_info(&raw),
        ([0xD3; 16], 4)
    );
    assert_eq!(
        TransportEngine::extract_announce_info(&raw[..17]),
        ([0; 16], 0)
    );
}
