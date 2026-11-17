use super::*;
use crate::event;
use crate::interface::Writer;
use rns_core::announce::AnnounceData;
use rns_core::constants;
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::stamp::StampCost;
use rns_core::transport::announce_verify_queue::{AnnounceVerifyKey, PendingAnnounce};
use rns_core::transport::types::InterfaceInfo;
use rns_crypto::identity::Identity;
use std::collections::HashSet;
use std::io;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type Shared<T> = Arc<Mutex<T>>;
type DestinationHops = Shared<Vec<(DestHash, u8)>>;
type LinkEstablishedEvents = Shared<Vec<(TypedLinkId, f64, bool)>>;
type RemoteIdentifiedEvents = Shared<Vec<(TypedLinkId, IdentityHash)>>;
type ResourceEvents = Shared<Vec<(TypedLinkId, Vec<u8>)>>;
type ChannelEvents = Shared<Vec<(TypedLinkId, u16, Vec<u8>)>>;
type LinkDataEvents = Shared<Vec<(TypedLinkId, u8, Vec<u8>)>>;
type ResponseEvents = Shared<Vec<(TypedLinkId, [u8; 16], Vec<u8>)>>;
type ProofEvents = Shared<Vec<(DestHash, PacketHash, f64)>>;
type DirectConnectEvents = Shared<Vec<(TypedLinkId, Option<IdentityHash>)>>;
type MockCallbacksFixture = (
    MockCallbacks,
    DestinationHops,
    DestinationHops,
    Shared<Vec<DestHash>>,
    Shared<Vec<InterfaceId>>,
    Shared<Vec<InterfaceId>>,
);

struct MockWriter {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MockWriter {
    fn new() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (MockWriter { sent: sent.clone() }, sent)
    }
}

impl Writer for MockWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.sent.lock().unwrap().push(data.to_vec());
        Ok(())
    }
}

struct BlockingWriter {
    entered_tx: std::sync::mpsc::Sender<()>,
    release_rx: std::sync::mpsc::Receiver<()>,
}

impl Writer for BlockingWriter {
    fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
        let _ = self.entered_tx.send(());
        let _ = self.release_rx.recv();
        Ok(())
    }
}

struct WouldBlockWriter {
    attempts: Arc<Mutex<usize>>,
}

impl WouldBlockWriter {
    fn new() -> (Self, Arc<Mutex<usize>>) {
        let attempts = Arc::new(Mutex::new(0));
        (
            WouldBlockWriter {
                attempts: attempts.clone(),
            },
            attempts,
        )
    }
}

impl Writer for WouldBlockWriter {
    fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
        *self.attempts.lock().unwrap() += 1;
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "intentional stall",
        ))
    }
}

fn wait_for_sent_len(sent: &Arc<Mutex<Vec<Vec<u8>>>>, expected: usize) {
    let deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < deadline {
        if sent.lock().unwrap().len() == expected {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(sent.lock().unwrap().len(), expected);
}

use crate::event::HolePunchPolicy;
use rns_core::types::{DestHash, IdentityHash, LinkId as TypedLinkId, PacketHash};

struct MockCallbacks {
    announces: DestinationHops,
    paths: DestinationHops,
    deliveries: Arc<Mutex<Vec<DestHash>>>,
    iface_ups: Arc<Mutex<Vec<InterfaceId>>>,
    iface_downs: Arc<Mutex<Vec<InterfaceId>>>,
    link_established: LinkEstablishedEvents,
    link_closed: Arc<Mutex<Vec<TypedLinkId>>>,
    remote_identified: RemoteIdentifiedEvents,
    resources_received: ResourceEvents,
    resource_completed: Arc<Mutex<Vec<TypedLinkId>>>,
    resource_failed: Arc<Mutex<Vec<(TypedLinkId, String)>>>,
    channel_messages: ChannelEvents,
    link_data: LinkDataEvents,
    responses: ResponseEvents,
    proofs: ProofEvents,
    proof_requested: Arc<Mutex<Vec<(DestHash, PacketHash)>>>,
}

impl MockCallbacks {
    fn new() -> MockCallbacksFixture {
        let announces = Arc::new(Mutex::new(Vec::new()));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let iface_ups = Arc::new(Mutex::new(Vec::new()));
        let iface_downs = Arc::new(Mutex::new(Vec::new()));
        (
            MockCallbacks {
                announces: announces.clone(),
                paths: paths.clone(),
                deliveries: deliveries.clone(),
                iface_ups: iface_ups.clone(),
                iface_downs: iface_downs.clone(),
                link_established: Arc::new(Mutex::new(Vec::new())),
                link_closed: Arc::new(Mutex::new(Vec::new())),
                remote_identified: Arc::new(Mutex::new(Vec::new())),
                resources_received: Arc::new(Mutex::new(Vec::new())),
                resource_completed: Arc::new(Mutex::new(Vec::new())),
                resource_failed: Arc::new(Mutex::new(Vec::new())),
                channel_messages: Arc::new(Mutex::new(Vec::new())),
                link_data: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(Vec::new())),
                proofs: Arc::new(Mutex::new(Vec::new())),
                proof_requested: Arc::new(Mutex::new(Vec::new())),
            },
            announces,
            paths,
            deliveries,
            iface_ups,
            iface_downs,
        )
    }

    fn with_link_tracking() -> (
        Self,
        LinkEstablishedEvents,
        Arc<Mutex<Vec<TypedLinkId>>>,
        RemoteIdentifiedEvents,
    ) {
        let link_established = Arc::new(Mutex::new(Vec::new()));
        let link_closed = Arc::new(Mutex::new(Vec::new()));
        let remote_identified = Arc::new(Mutex::new(Vec::new()));
        (
            MockCallbacks {
                announces: Arc::new(Mutex::new(Vec::new())),
                paths: Arc::new(Mutex::new(Vec::new())),
                deliveries: Arc::new(Mutex::new(Vec::new())),
                iface_ups: Arc::new(Mutex::new(Vec::new())),
                iface_downs: Arc::new(Mutex::new(Vec::new())),
                link_established: link_established.clone(),
                link_closed: link_closed.clone(),
                remote_identified: remote_identified.clone(),
                resources_received: Arc::new(Mutex::new(Vec::new())),
                resource_completed: Arc::new(Mutex::new(Vec::new())),
                resource_failed: Arc::new(Mutex::new(Vec::new())),
                channel_messages: Arc::new(Mutex::new(Vec::new())),
                link_data: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(Vec::new())),
                proofs: Arc::new(Mutex::new(Vec::new())),
                proof_requested: Arc::new(Mutex::new(Vec::new())),
            },
            link_established,
            link_closed,
            remote_identified,
        )
    }
}

pub(crate) fn make_transport_config(transport_enabled: bool) -> TransportConfig {
    TransportConfig {
        transport_enabled,
        identity_hash: None,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    }
}

pub(crate) fn new_test_driver() -> Driver {
    let transport_config = make_transport_config(false);
    let (callbacks, _, _, _, _, _) = MockCallbacks::new();
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(transport_config, rx, tx, Box::new(callbacks));
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
    driver
}

#[test]
fn driver_reuses_invalid_discovery_stamp_cache_across_announces() {
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.discovery_required_value = StampCost::from_whole(100);

    let packed = rns_core::msgpack::pack(&rns_core::msgpack::Value::Map(vec![
        (
            rns_core::msgpack::Value::UInt(crate::discovery::INTERFACE_TYPE as u64),
            rns_core::msgpack::Value::Str("BackboneInterface".into()),
        ),
        (
            rns_core::msgpack::Value::UInt(crate::discovery::TRANSPORT as u64),
            rns_core::msgpack::Value::Bool(true),
        ),
        (
            rns_core::msgpack::Value::UInt(crate::discovery::NAME as u64),
            rns_core::msgpack::Value::Str("cached-invalid".into()),
        ),
        (
            rns_core::msgpack::Value::UInt(crate::discovery::TRANSPORT_ID as u64),
            rns_core::msgpack::Value::Bin(vec![0x42; 16]),
        ),
        (
            rns_core::msgpack::Value::UInt(crate::discovery::REACHABLE_ON as u64),
            rns_core::msgpack::Value::Str("example.com".into()),
        ),
    ]));
    let mut app_data = Vec::with_capacity(1 + packed.len() + crate::discovery::STAMP_SIZE);
    app_data.push(0);
    app_data.extend_from_slice(&packed);
    app_data.extend_from_slice(&[0; crate::discovery::STAMP_SIZE]);

    let announce =
        TransportAction::AnnounceReceived(Box::new(rns_core::transport::types::ReceivedAnnounce {
            destination_hash: [0x31; 16],
            identity_hash: [0x32; 16],
            public_key: [0x33; 64],
            name_hash: driver.discovery_name_hash,
            random_hash: [0x34; 10],
            ratchet: None,
            app_data: Some(app_data.clone()),
            stamp: None,
            stamp_value: rns_core::stamp::StampValue::ZERO,
            lr_cost: None,
            hops: 1,
            receiving_interface: InterfaceId(9),
            rx: rns_core::transport::RxMetadata::default(),
        }));

    driver.dispatch_all(vec![announce.clone()]);
    assert_eq!(driver.discovery_stamp_cache.invalid_len(), 1);
    assert!(driver
        .discovery_stamp_cache
        .contains_invalid_app_data(&app_data));

    // Even if the requirement changes, the repeated payload is rejected from
    // the driver's persistent cache before proof-of-work validation is retried.
    driver.discovery_required_value = StampCost::ZERO;
    driver.dispatch_all(vec![announce]);
    assert_eq!(driver.discovery_stamp_cache.invalid_len(), 1);
}

#[test]
fn discovery_announces_from_non_source_networks_are_ignored() {
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.discovery_required_value = StampCost::from_whole(100);
    let mut app_data = vec![0];
    app_data.extend_from_slice(&rns_core::msgpack::pack(&rns_core::msgpack::Value::Map(
        vec![(
            rns_core::msgpack::Value::UInt(crate::discovery::NAME as u64),
            rns_core::msgpack::Value::Str("from-a-network".into()),
        )],
    )));
    app_data.extend_from_slice(&[0; crate::discovery::STAMP_SIZE]);
    let announce = |identity_hash: [u8; 16]| {
        TransportAction::AnnounceReceived(Box::new(rns_core::transport::types::ReceivedAnnounce {
            destination_hash: [0x31; 16],
            identity_hash,
            public_key: [0x33; 64],
            name_hash: driver.discovery_name_hash,
            random_hash: [0x34; 10],
            ratchet: None,
            app_data: Some(app_data.clone()),
            stamp: None,
            stamp_value: rns_core::stamp::StampValue::ZERO,
            lr_cost: None,
            hops: 1,
            receiving_interface: InterfaceId(9),
            rx: rns_core::transport::RxMetadata::default(),
        }))
    };
    let from_other = announce([0x32; 16]);
    let from_source = announce([0x55; 16]);

    // An announce that is looked at leaves its insufficient stamp in the
    // invalid cache; one from a network that is not a source is not looked at.
    driver.interface_discovery_sources = vec![[0x55; 16]];
    driver.dispatch_all(vec![from_other]);
    assert_eq!(driver.discovery_stamp_cache.invalid_len(), 0);
    driver.dispatch_all(vec![from_source]);
    assert_eq!(driver.discovery_stamp_cache.invalid_len(), 1);
}

fn make_announced_identity(
    dest_hash: [u8; 16],
    received_at: f64,
    receiving_interface: InterfaceId,
) -> crate::destination::AnnouncedIdentity {
    crate::destination::AnnouncedIdentity {
        dest_hash: rns_core::types::DestHash(dest_hash),
        identity_hash: rns_core::types::IdentityHash([dest_hash[0]; 16]),
        public_key: [dest_hash[0]; 64],
        app_data: None,
        hops: 1,
        received_at,
        receiving_interface,
        rssi: Some(-100),
        snr: Some(10.5),
    }
}

#[test]
fn the_known_destinations_flush_gets_only_what_changed() {
    let mut driver = new_test_driver();
    let changes = |driver: &mut Driver| match driver
        .handle_query_mut(QueryRequest::KnownDestinationChanges)
    {
        QueryResponse::KnownDestinationChanges { changed, removed } => {
            let mut changed: Vec<_> = changed
                .into_iter()
                .map(|(entry, fingerprint)| (entry.dest_hash, fingerprint))
                .collect();
            changed.sort();
            (changed, removed)
        }
        other => panic!("unexpected response {other:?}"),
    };
    let record = |driver: &mut Driver, stored, removed, seed| {
        assert!(matches!(
            driver.handle_query_mut(QueryRequest::RecordKnownDestinationFlush {
                stored,
                removed,
                seed,
            }),
            QueryResponse::KnownDestinationFlushRecorded
        ));
    };
    let (a, b) = ([0xA1; 16], [0xB2; 16]);
    driver.upsert_known_destination(a, make_announced_identity(a, 10.0, InterfaceId(1)));
    driver.upsert_known_destination(b, make_announced_identity(b, 20.0, InterfaceId(1)));

    // Both are new; once stored, nothing is handed over again.
    let (changed, removed) = changes(&mut driver);
    assert_eq!(
        changed.iter().map(|(hash, _)| *hash).collect::<Vec<_>>(),
        vec![a, b]
    );
    assert!(removed.is_empty());
    record(&mut driver, changed.clone(), Vec::new(), false);
    assert_eq!(changes(&mut driver), (Vec::new(), Vec::new()));

    // A use changes one entry; a removal shows as removed.
    assert!(driver.mark_known_destination_used(&a));
    driver.known_destinations.remove(&b);
    let (changed, removed) = changes(&mut driver);
    assert_eq!(
        changed.iter().map(|(hash, _)| *hash).collect::<Vec<_>>(),
        vec![a]
    );
    assert_eq!(removed, vec![b]);

    // Not recorded (a failed save), the same changes come back.
    assert_eq!(changes(&mut driver), (changed.clone(), removed.clone()));
    record(&mut driver, changed, removed, false);
    assert_eq!(changes(&mut driver), (Vec::new(), Vec::new()));

    // A seed replaces the record, as with what storage held at start.
    record(&mut driver, Vec::new(), Vec::new(), true);
    assert_eq!(changes(&mut driver).0.len(), 1);
}

#[derive(Default)]
struct TestRatchetStore {
    remembered: Mutex<Vec<([u8; 16], crate::storage::RatchetEntry)>>,
    cleanup_calls: Mutex<Vec<HashSet<[u8; 16]>>>,
}

impl crate::storage::RatchetStore for TestRatchetStore {
    fn remember(&self, dest_hash: [u8; 16], entry: crate::storage::RatchetEntry) -> io::Result<()> {
        self.remembered.lock().unwrap().push((dest_hash, entry));
        Ok(())
    }

    fn current(
        &self,
        _dest_hash: &[u8; 16],
        _now: f64,
        _expiry_secs: f64,
    ) -> io::Result<Option<crate::storage::RatchetEntry>> {
        Ok(None)
    }

    fn cleanup(
        &self,
        known_destinations: &HashSet<[u8; 16]>,
        _now: f64,
        _expiry_secs: f64,
    ) -> io::Result<crate::storage::RatchetCleanupStats> {
        self.cleanup_calls
            .lock()
            .unwrap()
            .push(known_destinations.clone());
        Ok(Default::default())
    }
}

#[test]
fn dispatch_announce_received_persists_ratchet() {
    let mut driver = new_test_driver();
    let store = Arc::new(TestRatchetStore::default());
    driver.ratchet_store = Some(store.clone());
    let dest_hash = [0x44; 16];
    let ratchet = [0x55; 32];

    driver.dispatch_all(vec![
        rns_core::transport::types::TransportAction::AnnounceReceived(Box::new(
            rns_core::transport::types::ReceivedAnnounce {
                destination_hash: dest_hash,
                identity_hash: [0x66; 16],
                public_key: [0x77; 64],
                name_hash: [0x88; 10],
                random_hash: [0x99; 10],
                ratchet: Some(ratchet),
                app_data: None,
                stamp: None,
                stamp_value: rns_core::stamp::StampValue::ZERO,
                lr_cost: None,
                hops: 1,
                receiving_interface: InterfaceId(1),
                rx: rns_core::transport::RxMetadata::default(),
            },
        )),
    ]);

    let remembered = store.remembered.lock().unwrap();
    assert_eq!(remembered.len(), 1);
    assert_eq!(remembered[0].0, dest_hash);
    assert_eq!(remembered[0].1.ratchet, ratchet);
}

#[test]
fn dispatch_remote_identified_closes_blackholed_link() {
    let transport_config = make_transport_config(false);
    let (callbacks, _established, closed, identified) = MockCallbacks::with_link_tracking();
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(transport_config, rx, tx, Box::new(callbacks));
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));

    let mut rng = rns_crypto::OsRng;
    let dest_hash = [0xDD; 16];
    let (link_id, _) = driver.link_manager.create_link(
        &dest_hash,
        &[0xAA; 32],
        1,
        constants::MTU as u32,
        &mut rng,
    );
    let identity_hash = [0x42; 16];
    driver
        .engine
        .blackhole_identity(identity_hash, time::now(), None, Some("test".into()));

    driver.dispatch_link_actions(vec![LinkManagerAction::RemoteIdentified {
        link_id,
        identity_hash,
        public_key: [0x99; 64],
    }]);

    assert!(
        identified.lock().unwrap().is_empty(),
        "blackholed identity must not trigger remote-identified callback"
    );
    assert_eq!(closed.lock().unwrap().as_slice(), &[TypedLinkId(link_id)]);
}

fn make_known_destination_state(
    dest_hash: [u8; 16],
    received_at: f64,
    receiving_interface: InterfaceId,
) -> KnownDestinationState {
    KnownDestinationState {
        announced: make_announced_identity(dest_hash, received_at, receiving_interface),
        was_used: false,
        last_used_at: None,
        retained: false,
        stamp: None,
        stamp_value: rns_core::stamp::StampValue::ZERO,
        lr_cost: None,
    }
}

/// Know `identity` as the identity of `destination`, so the proofs of
/// packets sent to it can be checked.
fn know_identity(driver: &mut Driver, destination: [u8; 16], identity: &Identity) {
    let mut known = make_known_destination_state(destination, time::now(), InterfaceId(1));
    known.announced.public_key = identity.get_public_key().unwrap();
    driver.known_destinations.insert(destination, known);
}

fn sent_contains_linkclose(sent: &[Vec<u8>], link_id: [u8; 16]) -> bool {
    sent.iter().any(|raw| {
        RawPacket::unpack(raw)
            .map(|packet| {
                packet.destination_hash == link_id && packet.context == constants::CONTEXT_LINKCLOSE
            })
            .unwrap_or(false)
    })
}

pub(super) fn active_link_manager_with_route(
    interface_id: InterfaceId,
) -> (crate::link_manager::LinkManager, [u8; 16]) {
    let mut initiator = crate::link_manager::LinkManager::new();
    let (_responder, link_id) = establish_link(&mut initiator, [0xDD; 16], interface_id);
    initiator.set_link_route_hint(&link_id, interface_id, None);
    (initiator, link_id)
}

/// Establish a link from `initiator` to a fresh responder serving
/// `dest_hash`: the responder (which signs the link's packet proofs) and
/// the link id.
fn establish_link(
    initiator: &mut crate::link_manager::LinkManager,
    dest_hash: [u8; 16],
    interface_id: InterfaceId,
) -> (crate::link_manager::LinkManager, [u8; 16]) {
    let mut rng = OsRng;
    let mut responder = crate::link_manager::LinkManager::new();
    let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
    let sig_pub_bytes = sig_prv.public_key().public_bytes();
    responder.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        crate::link_manager::ResourceStrategy::AcceptNone,
    );

    let (link_id, init_actions) = initiator.create_link(
        &dest_hash,
        &sig_pub_bytes,
        1,
        constants::MTU as u32,
        &mut rng,
    );
    let linkrequest_raw = init_actions
        .iter()
        .find_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.clone()),
            _ => None,
        })
        .expect("link request send packet");
    let linkrequest = RawPacket::unpack(&linkrequest_raw).unwrap();
    let resp_actions = responder.handle_local_delivery(
        linkrequest.destination_hash,
        &linkrequest_raw,
        linkrequest.packet_hash,
        interface_id,
        &mut rng,
    );

    let lrproof_raw = resp_actions
        .iter()
        .find_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.clone()),
            _ => None,
        })
        .expect("lrproof send packet");
    let lrproof = RawPacket::unpack(&lrproof_raw).unwrap();
    let init_actions = initiator.handle_local_delivery(
        lrproof.destination_hash,
        &lrproof_raw,
        lrproof.packet_hash,
        interface_id,
        &mut rng,
    );

    let lrrtt_raw = init_actions
        .iter()
        .find_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.clone()),
            _ => None,
        })
        .expect("lrrtt send packet");
    let lrrtt = RawPacket::unpack(&lrrtt_raw).unwrap();
    responder.handle_local_delivery(
        lrrtt.destination_hash,
        &lrrtt_raw,
        lrrtt.packet_hash,
        interface_id,
        &mut rng,
    );
    (responder, link_id)
}

#[cfg(feature = "iface-backbone")]
fn make_pool_candidate(name: &str, port: u16, id: u64) -> BackbonePeerPoolCandidateConfig {
    make_pool_candidate_with_priority(
        name,
        port,
        id,
        crate::driver::BACKBONE_PEER_POOL_CONFIGURED_DEFAULT_PRIORITY,
    )
}

#[cfg(feature = "iface-backbone")]
fn make_pool_candidate_with_priority(
    name: &str,
    port: u16,
    id: u64,
    priority: u8,
) -> BackbonePeerPoolCandidateConfig {
    let mut client = BackboneClientConfig {
        name: name.to_string(),
        target_host: "127.0.0.1".to_string(),
        target_port: port,
        interface_id: InterfaceId(id),
        reconnect_wait: Duration::from_millis(10),
        max_reconnect_tries: Some(0),
        connect_timeout: Duration::from_millis(50),
        transport_identity: None,
        ..BackboneClientConfig::default()
    };
    client.runtime = Arc::new(Mutex::new(BackboneClientRuntime::from_config(&client)));
    BackbonePeerPoolCandidateConfig {
        client,
        mode: constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
        stamp_costs: Default::default(),
        ifac_runtime: IfacRuntimeConfig {
            netname: None,
            netkey: None,
            size: 16,
        },
        ifac_enabled: false,
        interface_type_name: "BackboneInterface".to_string(),
        source: BackbonePeerPoolCandidateSource::Configured,
        priority,
        discovery: None,
    }
}

#[cfg(feature = "iface-backbone")]
fn make_discovered_backbone(
    name: &str,
    host: &str,
    port: Option<u16>,
    transport_seed: u8,
    hops: u8,
    stamp_value: u32,
    last_heard: f64,
) -> crate::discovery::DiscoveredInterface {
    let stamp_value = rns_core::stamp::StampValue::from_whole(stamp_value);
    let mut transport_id = [transport_seed; 16];
    transport_id[15] = transport_seed;
    let discovery_hash = crate::discovery::compute_discovery_hash(&transport_id, name);
    crate::discovery::DiscoveredInterface {
        dst_cost: None,
        pr_cost: None,
        interface_type: "BackboneInterface".to_string(),
        impl_name: Some("RNS".to_string()),
        impl_version: Some("1.5.7".to_string()),
        transport: true,
        name: name.to_string(),
        discovered: last_heard,
        last_heard,
        heard_count: 1,
        status: crate::discovery::DiscoveredStatus::Available,
        stamp: vec![0; crate::discovery::STAMP_SIZE],
        stamp_value,
        transport_id,
        network_id: [0x55; 16],
        hops,
        latitude: None,
        longitude: None,
        height: None,
        operator_lxmf_address: None,
        reachable_on: Some(host.to_string()),
        port,
        frequency: None,
        bandwidth: None,
        spreading_factor: None,
        coding_rate: None,
        modulation: None,
        channel: None,
        ifac_netname: None,
        ifac_netkey: None,
        config_entry: None,
        discovery_hash,
    }
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_respects_max_connected_order() {
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let port_b = listener_b.local_addr().unwrap().port();
    let mut driver = new_test_driver();

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![
            make_pool_candidate("first", port_a, 7001),
            make_pool_candidate("second", port_b, 7002),
        ],
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.max_connected, 1);
    assert_eq!(status.active_count, 1);
    assert_eq!(status.standby_count, 1);
    assert_eq!(status.members[0].name, "first");
    assert_eq!(status.members[0].interface_id, Some(7001));
    assert_eq!(status.members[1].name, "second");
    assert_eq!(status.members[1].state, "standby");
    drop(listener_a);
    drop(listener_b);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_discovered_fill_target_after_configured() {
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let port_b = listener_b.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 2,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![make_pool_candidate("configured", port_a, 7031)],
    );

    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "discovered",
            "127.0.0.1",
            Some(port_b),
            0x71,
            1,
            20,
            time::now(),
        ))
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.max_connected, 2);
    assert_eq!(status.active_count, 2);
    assert_eq!(status.members[0].source, "configured");
    assert_eq!(status.members[1].source, "discovered");
    assert_eq!(status.members[1].remote, format!("127.0.0.1:{port_b}"));

    // As upstream, a discovered interface reports the network it was
    // discovered from; a configured one none.
    let source = |id: Option<u64>| driver.autoconnect_source(InterfaceId(id.unwrap()));
    assert_eq!(source(status.members[0].interface_id), None);
    assert_eq!(
        source(status.members[1].interface_id).as_deref(),
        Some("55".repeat(16).as_str())
    );
    // Named as upstream names the BackboneClientInterface it starts.
    let discovered = InterfaceId(status.members[1].interface_id.unwrap());
    let name = &driver.interfaces[&discovered].info.name;
    assert_eq!(
        driver.interface_display_names[&discovered],
        format!("BackboneInterface[{name}/127.0.0.1:{port_b}]")
    );
}

#[cfg(feature = "iface-backbone")]
#[test]
fn discovered_peer_pool_candidate_uses_autoconnect_overrides() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.autoconnect_interface_mode = Some(constants::MODE_BOUNDARY);
    driver.autoconnect_interface_gravity = -5;
    driver.autoconnect_announces_to_internal = Some(true);
    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![],
    );

    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "discovered",
            "127.0.0.1",
            Some(port),
            0x7a,
            1,
            20,
            time::now(),
        ))
    );

    let pool = driver.backbone_peer_pool.as_ref().unwrap();
    assert_eq!(pool.candidates[0].config.mode, constants::MODE_BOUNDARY);
    assert_eq!(pool.candidates[0].config.gravity, -5);
    assert_eq!(pool.candidates[0].config.announces_to_internal, Some(true));
}

#[cfg(feature = "iface-backbone")]
#[test]
fn discovered_peer_pool_requires_verified_implementation_unless_overridden() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 3,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![],
    );

    let mut iface = make_discovered_backbone(
        "unverified",
        "127.0.0.1",
        Some(port),
        0x7b,
        1,
        20,
        time::now(),
    );
    iface.impl_name = None;
    iface.impl_version = None;
    assert!(!driver.upsert_discovered_backbone_peer_pool_candidate(iface.clone()));

    iface.impl_name = Some("Other".into());
    iface.impl_version = Some("9.9.9".into());
    assert!(!driver.upsert_discovered_backbone_peer_pool_candidate(iface.clone()));

    // AUTOCONNECT_MIN_V is 1.5.7 since upstream 9b464382.
    iface.impl_name = Some("RNS".into());
    iface.impl_version = Some("1.5.6".into());
    assert!(!driver.upsert_discovered_backbone_peer_pool_candidate(iface.clone()));

    iface.impl_version = Some("1.5.7".into());
    assert!(driver.upsert_discovered_backbone_peer_pool_candidate(iface));

    // Native discoverers are trusted even though their version tracks the
    // crate release cycle instead of the upstream protocol version.
    let mut native_iface = make_discovered_backbone(
        "native",
        "127.0.0.1",
        Some(port + 1),
        0x7d,
        1,
        20,
        time::now(),
    );
    native_iface.impl_name = Some(crate::common::discovery::TRANSPORT_IMPLEMENTATION_NAME.into());
    native_iface.impl_version = Some("0.7.2".into());
    assert!(driver.upsert_discovered_backbone_peer_pool_candidate(native_iface));

    let mut override_iface = make_discovered_backbone(
        "override",
        "127.0.0.1",
        Some(port + 2),
        0x7c,
        1,
        20,
        time::now(),
    );
    override_iface.impl_name = None;
    override_iface.impl_version = None;
    driver.autoconnect_unverified_implementations = true;
    assert!(driver.upsert_discovered_backbone_peer_pool_candidate(override_iface));
}

#[cfg(feature = "iface-backbone")]
#[test]
fn discovered_peer_pool_requires_affordable_stamp_costs() {
    // 9b464382: auto-connect only when the announced costs are within this
    // node's DESTINATION_VALUE and PR_VALUE.
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    let port = 41_000;
    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 3,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![],
    );
    let targets = driver.stamper.targets();
    let discovered = |name: &str, offset: u16, id: u8| {
        let mut iface = make_discovered_backbone(
            name,
            "127.0.0.1",
            Some(port + offset),
            id,
            1,
            20,
            time::now(),
        );
        iface.impl_name = Some("RNS".into());
        iface.impl_version = Some("1.6.0".into());
        iface
    };

    let mut costly = discovered("costly-dst", 0, 0x81);
    costly.dst_cost = Some(StampCost::from_fp(targets.destination_value.fp() + 1));
    assert!(!driver.upsert_discovered_backbone_peer_pool_candidate(costly));

    let mut costly = discovered("costly-pr", 1, 0x82);
    costly.pr_cost = Some(StampCost::from_fp(targets.path_request_value.fp() + 1));
    assert!(!driver.upsert_discovered_backbone_peer_pool_candidate(costly));

    let mut affordable = discovered("affordable", 2, 0x83);
    affordable.dst_cost = Some(targets.destination_value);
    affordable.pr_cost = Some(targets.path_request_value);
    assert!(driver.upsert_discovered_backbone_peer_pool_candidate(affordable));

    // An interface that announced no costs requires none.
    assert!(driver.upsert_discovered_backbone_peer_pool_candidate(discovered("legacy", 3, 0x84)));
}

#[cfg(feature = "iface-backbone")]
#[test]
fn discovered_peer_pool_requires_transport_enabled_interface() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 3,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![],
    );

    let mut iface = make_discovered_backbone(
        "non-transport",
        "127.0.0.1",
        Some(port),
        0x7e,
        1,
        20,
        time::now(),
    );
    iface.transport = false;
    // Even the unverified-implementation override must not auto-connect a
    // non-transport interface.
    driver.autoconnect_unverified_implementations = true;
    assert!(!driver.upsert_discovered_backbone_peer_pool_candidate(iface.clone()));

    iface.transport = true;
    assert!(driver.upsert_discovered_backbone_peer_pool_candidate(iface));
}

#[cfg(feature = "iface-backbone")]
#[test]
fn parse_version_tuple_matches_upstream_semantics() {
    let parse = crate::driver::runtime_config::parse_version_tuple;
    assert_eq!(parse("1.5.2"), Some(vec![1, 5, 2]));
    assert_eq!(parse("1.5.2-beta"), Some(vec![1, 5, 2]));
    assert_eq!(parse("  1.6  "), Some(vec![1, 6]));
    assert_eq!(parse("1.5"), Some(vec![1, 5]));
    assert_eq!(parse("not-a-version"), None);
    assert_eq!(parse(""), None);
    // Missing trailing components compare as smaller.
    assert!(parse("1.5").unwrap().as_slice() < [1u32, 5, 2].as_slice());
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_prefers_configured_over_discovered() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let configured_port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![make_pool_candidate("configured", configured_port, 7041)],
    );
    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "better-discovered",
            "127.0.0.1",
            Some(configured_port + 1),
            0x72,
            0,
            32,
            time::now(),
        ))
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    assert_eq!(status.members[0].source, "configured");
    assert_eq!(status.members[0].priority, 60);
    assert!(matches!(
        status.members[0].state.as_str(),
        "connecting" | "active"
    ));
    assert_eq!(status.members[1].source, "discovered");
    assert_eq!(status.members[1].priority, 40);
    assert_eq!(status.members[1].state, "standby");
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_priority_can_prefer_discovered_over_configured() {
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let configured_port = listener_a.local_addr().unwrap().port();
    let discovered_port = listener_b.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![make_pool_candidate_with_priority(
            "low-configured",
            configured_port,
            7051,
            20,
        )],
    );
    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "default-discovered",
            "127.0.0.1",
            Some(discovered_port),
            0x73,
            1,
            20,
            time::now(),
        ))
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    assert_eq!(status.members[0].source, "discovered");
    assert_eq!(status.members[0].priority, 40);
    assert_eq!(
        status.members[0].remote,
        format!("127.0.0.1:{discovered_port}")
    );
    assert_eq!(status.members[1].source, "configured");
    assert_eq!(status.members[1].priority, 20);
    assert_eq!(status.members[1].state, "standby");
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_priority_does_not_preempt_active_peer() {
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let configured_port = listener_a.local_addr().unwrap().port();
    let discovered_port = listener_b.local_addr().unwrap().port();
    let mut driver = new_test_driver();

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![make_pool_candidate_with_priority(
            "low-configured",
            configured_port,
            7061,
            20,
        )],
    );
    let before = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(before.active_count, 1);
    assert_eq!(before.members[0].source, "configured");
    assert_eq!(before.members[0].interface_id, Some(7061));

    driver.discover_interfaces = true;
    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "default-discovered",
            "127.0.0.1",
            Some(discovered_port),
            0x74,
            1,
            20,
            time::now(),
        ))
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    let active = status
        .members
        .iter()
        .find(|member| member.state == "active" || member.state == "connecting")
        .unwrap();
    assert_eq!(active.source, "configured");
    assert_eq!(active.interface_id, Some(7061));
    let discovered = status
        .members
        .iter()
        .find(|member| member.source == "discovered")
        .unwrap();
    assert_eq!(discovered.state, "standby");
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_sorts_configured_candidates_by_priority() {
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let port_b = listener_b.local_addr().unwrap().port();
    let mut driver = new_test_driver();

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![
            make_pool_candidate_with_priority("low", port_a, 7071, 10),
            make_pool_candidate_with_priority("high", port_b, 7072, 90),
        ],
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    assert_eq!(status.members[0].name, "high");
    assert_eq!(status.members[0].priority, 90);
    assert_eq!(status.members[0].interface_id, Some(7072));
    assert_eq!(status.members[1].name, "low");
    assert_eq!(status.members[1].priority, 10);
    assert_eq!(status.members[1].state, "standby");
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_sorts_discovered_candidates_by_quality() {
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_c = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    let now = time::now();

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 3,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        Vec::new(),
    );

    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "high-stamp",
            "127.0.0.1",
            Some(listener_b.local_addr().unwrap().port()),
            0x82,
            2,
            40,
            now,
        ))
    );
    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "few-hops",
            "127.0.0.1",
            Some(listener_a.local_addr().unwrap().port()),
            0x81,
            1,
            10,
            now - 10.0,
        ))
    );
    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "newer",
            "127.0.0.1",
            Some(listener_c.local_addr().unwrap().port()),
            0x83,
            2,
            40,
            now + 1.0,
        ))
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    let names: Vec<&str> = status
        .members
        .iter()
        .map(|member| member.name.split(" (").next().unwrap())
        .collect();
    assert_eq!(names, vec!["few-hops", "newer", "high-stamp"]);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_deduplicates_discovered_candidates() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 2,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        Vec::new(),
    );

    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "one",
            "127.0.0.1",
            Some(port),
            0x91,
            1,
            10,
            time::now(),
        ))
    );
    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "same-remote",
            "127.0.0.1",
            Some(port),
            0x92,
            1,
            20,
            time::now(),
        ))
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.members.len(), 1);
    assert_eq!(status.members[0].source, "discovered");
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_failed_discovered_candidate_retries_replacement() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let replacement_port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        Vec::new(),
    );

    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "failed",
            "127.0.0.1",
            Some(1),
            0xa1,
            1,
            10,
            time::now(),
        ))
    );
    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "replacement",
            "127.0.0.1",
            Some(replacement_port),
            0xa2,
            2,
            10,
            time::now(),
        ))
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    assert_eq!(status.members[0].name.split(" (").next().unwrap(), "failed");
    assert_eq!(status.members[0].failure_count, 1);
    assert_eq!(
        status.members[1].name.split(" (").next().unwrap(),
        "replacement"
    );
    assert!(matches!(
        status.members[1].state.as_str(),
        "connecting" | "active"
    ));
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_removes_stale_standby_discovered_candidates() {
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        Vec::new(),
    );
    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "stale-soon",
            "127.0.0.1",
            Some(1),
            0xb1,
            1,
            10,
            time::now(),
        ))
    );

    if let Some(pool) = driver.backbone_peer_pool.as_mut() {
        let candidate = pool.candidates.first_mut().unwrap();
        candidate.active_id = None;
        let discovery = candidate.config.discovery.as_mut().unwrap();
        discovery.status = crate::discovery::DiscoveredStatus::Stale;
        discovery.last_heard = time::now() - crate::discovery::THRESHOLD_REMOVE - 1.0;
    }
    driver.cull_stale_discovered_backbone_peer_pool_candidates();

    let status = driver.backbone_peer_pool_status().unwrap();
    assert!(status.members.is_empty());
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_cools_down_failed_peer_and_tries_next() {
    // Discovered peers that keep failing go on the pool cooldown.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let reachable_port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 1,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(900),
        },
        Vec::new(),
    );
    for (name, port, seed, hops) in [
        ("failed", 1, 0xc1, 1),
        ("replacement", reachable_port, 0xc2, 2),
    ] {
        assert!(
            driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
                name,
                "127.0.0.1",
                Some(port),
                seed,
                hops,
                10,
                time::now(),
            ))
        );
    }

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    assert_eq!(status.cooldown_count, 1);
    assert_eq!(status.members[0].name.split(" (").next().unwrap(), "failed");
    assert_eq!(status.members[0].state, "cooldown");
    assert_eq!(status.members[0].failure_count, 1);
    let remaining = status.members[0].cooldown_remaining_seconds.unwrap();
    assert!(remaining > 890.0 && remaining <= 900.0, "{remaining}");
    assert_eq!(
        status.members[1].name.split(" (").next().unwrap(),
        "replacement"
    );
    assert!(matches!(
        status.members[1].state.as_str(),
        "connecting" | "active"
    ));
    drop(listener);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_configured_failed_peer_backs_off_and_tries_next() {
    // A failing configured peer still fails over to the next configured one,
    // but waits out a short backoff instead of the pool cooldown.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let reachable_port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 1,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(900),
        },
        vec![
            make_pool_candidate("failed", 1, 7011),
            make_pool_candidate("replacement", reachable_port, 7012),
        ],
    );

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    assert_eq!(status.cooldown_count, 0);
    assert_eq!(status.members[0].name, "failed");
    assert_eq!(status.members[0].state, "standby");
    assert_eq!(status.members[0].failure_count, 1);
    assert_eq!(status.members[1].name, "replacement");
    assert_eq!(status.members[1].interface_id, Some(7012));
    let pool = driver.backbone_peer_pool.as_ref().unwrap();
    assert!(pool.candidates[0].cooldown_until.is_none());
    assert!(pool.candidates[0].retry_after.unwrap() <= time::now() + 1.0);
    drop(listener);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_configured_peer_backoff_is_bounded() {
    // Python retries a configured Backbone client every 5 s forever. A
    // configured pool peer that keeps failing must back off like a
    // standalone client (5 s doubling, capped at 320 s, ±25 % jitter) and
    // never wait out the pool cooldown.
    let mut driver = new_test_driver();
    let mut candidate = make_pool_candidate("down", 1, 7111);
    candidate.client.reconnect_wait = Duration::from_secs(5);
    candidate.client.runtime = Arc::new(Mutex::new(BackboneClientRuntime::from_config(
        &candidate.client,
    )));
    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(600),
            cooldown: Duration::from_secs(900),
        },
        vec![candidate],
    );

    // The initial connect already failed once; keep failing it.
    for attempt in 1..20u32 {
        driver.record_backbone_peer_pool_failure(0, "connection refused".into());
        let now = time::now();
        let pool = driver.backbone_peer_pool.as_ref().unwrap();
        let candidate = &pool.candidates[0];
        assert!(candidate.cooldown_until.is_none());
        let wait = candidate.retry_after.unwrap() - now;
        let nominal = 5.0 * f64::from(2u32.pow(attempt.min(6)));
        assert!(
            wait >= nominal * 0.75 - 1.0 && wait <= nominal * 1.25,
            "attempt {attempt}: waits {wait}s, nominal {nominal}s"
        );
        assert!(wait <= 320.0 * 1.25);
    }
    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.cooldown_count, 0);
    assert_eq!(status.members[0].state, "standby");
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_configured_peer_returns_after_repeated_drops() {
    // Dropping more often than the failure threshold must not park a
    // configured peer on the cooldown: it reconnects once its backoff
    // expires, and a successful connect resets the backoff.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 1,
            failure_window: Duration::from_secs(600),
            cooldown: Duration::from_secs(900),
        },
        vec![make_pool_candidate("configured", port, 7121)],
    );

    for _ in 0..3 {
        let status = driver.backbone_peer_pool_status().unwrap();
        assert_eq!(status.members[0].interface_id, Some(7121));
        driver.handle_backbone_peer_pool_down(InterfaceId(7121));

        let status = driver.backbone_peer_pool_status().unwrap();
        assert_eq!(status.cooldown_count, 0);
        assert_eq!(status.members[0].state, "standby");
        let pool = driver.backbone_peer_pool.as_ref().unwrap();
        assert_eq!(pool.candidates[0].consecutive_failures, 1);

        // reconnect_wait is 10 ms: the first retry is due within 12.5 ms.
        std::thread::sleep(Duration::from_millis(30));
        driver.maintain_backbone_peer_pool();
        let pool = driver.backbone_peer_pool.as_ref().unwrap();
        assert_eq!(pool.candidates[0].consecutive_failures, 0);
    }
    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.members[0].interface_id, Some(7121));
    assert_eq!(status.members[0].failure_count, 3);
    drop(listener);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_rotates_after_runtime_disconnect() {
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let port_b = listener_b.local_addr().unwrap().port();
    let mut driver = new_test_driver();

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 1,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![
            make_pool_candidate("first", port_a, 7021),
            make_pool_candidate("second", port_b, 7022),
        ],
    );
    driver.handle_backbone_peer_pool_down(InterfaceId(7021));

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    // Configured peers back off instead of entering the pool cooldown.
    assert_eq!(status.cooldown_count, 0);
    assert_eq!(status.members[0].state, "standby");
    assert_eq!(status.members[1].interface_id, Some(7022));
    drop(listener_a);
    drop(listener_b);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_configured_peer_reclaims_slot_from_discovered() {
    // A configured peer drops (e.g. the remote restarts) while the pool is
    // full; a discovered standby takes its slot while it waits to retry. Once
    // the configured peer may retry, it must get its slot back instead of
    // waiting for some unrelated peer to disconnect.
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let configured_port = listener_a.local_addr().unwrap().port();
    let discovered_port = listener_b.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![make_pool_candidate("configured", configured_port, 7081)],
    );
    assert!(
        driver.upsert_discovered_backbone_peer_pool_candidate(make_discovered_backbone(
            "discovered",
            "127.0.0.1",
            Some(discovered_port),
            0x75,
            1,
            20,
            time::now(),
        ))
    );
    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.members[0].interface_id, Some(7081));
    assert_eq!(status.members[1].state, "standby");

    driver.handle_backbone_peer_pool_down(InterfaceId(7081));
    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    assert_eq!(status.members[0].state, "standby");
    assert_eq!(status.members[0].failure_count, 1);
    let discovered_id = status.members[1].interface_id.unwrap();
    assert!(driver.interfaces.contains_key(&InterfaceId(discovered_id)));

    std::thread::sleep(Duration::from_millis(30));
    driver.maintain_backbone_peer_pool();

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    assert_eq!(status.members[0].name, "configured");
    assert_eq!(status.members[0].interface_id, Some(7081));
    assert!(matches!(
        status.members[0].state.as_str(),
        "connecting" | "active"
    ));
    assert_eq!(status.members[1].source, "discovered");
    assert_eq!(status.members[1].state, "standby");
    assert_eq!(status.members[1].failure_count, 0);
    assert!(!driver.interfaces.contains_key(&InterfaceId(discovered_id)));
    assert!(driver
        .engine
        .interface_info(&InterfaceId(discovered_id))
        .is_none());
    drop(listener_a);
    drop(listener_b);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_pool_full_pool_keeps_active_configured_peer() {
    // Configured peers rotate among themselves; a ready configured standby
    // never evicts another configured peer.
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let port_b = listener_b.local_addr().unwrap().port();
    let mut driver = new_test_driver();

    driver.configure_backbone_peer_pool(
        BackbonePeerPoolSettings {
            max_connected: 1,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        },
        vec![
            make_pool_candidate_with_priority("high", port_a, 7091, 90),
            make_pool_candidate_with_priority("low", port_b, 7092, 10),
        ],
    );
    driver.handle_backbone_peer_pool_down(InterfaceId(7091));
    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.members[1].interface_id, Some(7092));

    std::thread::sleep(Duration::from_millis(30));
    driver.maintain_backbone_peer_pool();

    let status = driver.backbone_peer_pool_status().unwrap();
    assert_eq!(status.active_count, 1);
    assert_eq!(status.members[0].state, "standby");
    assert_eq!(status.members[1].interface_id, Some(7092));
    drop(listener_a);
    drop(listener_b);
}

#[cfg(feature = "iface-backbone")]
fn register_test_backbone(driver: &mut Driver, name: &str) {
    let startup = BackboneServerRuntime {
        max_connections: Some(8),
        idle_timeout: Some(Duration::from_secs(10)),
        write_stall_timeout: Some(Duration::from_secs(30)),
        abuse: BackboneAbuseConfig {
            max_penalty_duration: Some(Duration::from_secs(3600)),
        },
    };
    let peer_state = Arc::new(std::sync::Mutex::new(
        crate::interface::backbone::BackbonePeerMonitor::new(),
    ));
    driver.register_backbone_runtime(BackboneRuntimeConfigHandle {
        interface_name: name.to_string(),
        runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
        startup,
    });
    driver.register_backbone_peer_state(BackbonePeerStateHandle {
        interface_id: InterfaceId(1),
        interface_name: name.to_string(),
        mode: rns_core::constants::MODE_FULL,
        gravity: 0,
        announces_to_internal: None,
        peer_state,
        fast_flap: crate::interface::backbone::BackboneFastFlapConfig::default(),
        fast_flap_state: Arc::new(std::sync::Mutex::new(
            crate::interface::backbone::BackboneFastFlapMonitor::new(),
        )),
    });
}

#[cfg(feature = "iface-backbone")]
fn register_test_backbone_client(driver: &mut Driver, name: &str) {
    let startup = BackboneClientRuntime {
        reconnect_wait: Duration::from_secs(5),
        max_reconnect_tries: Some(3),
        connect_timeout: Duration::from_secs(5),
    };
    driver.register_backbone_client_runtime(BackboneClientRuntimeConfigHandle {
        interface_name: name.to_string(),
        runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
        startup,
    });
}

#[cfg(feature = "iface-backbone")]
fn register_test_backbone_discovery(driver: &mut Driver, name: &str, discoverable: bool) {
    let startup = BackboneDiscoveryRuntime {
        discoverable,
        config: crate::discovery::DiscoveryConfig {
            publish_ifac: false,
            encrypt: false,
            radio: Default::default(),
            stamp_costs: Default::default(),
            discovery_name: name.to_string(),
            announce_interval: 3600,
            stamp_value: crate::discovery::DEFAULT_STAMP_VALUE,
            reachable_on: None,
            interface_type: "BackboneInterface".to_string(),
            listen_port: Some(4242),
            location_cmd: None,
            latitude: None,
            longitude: None,
            height: None,
            operator_lxmf_address: None,
        },
        transport_enabled: true,
        ifac_netname: None,
        ifac_netkey: None,
    };
    driver.register_backbone_discovery_runtime(BackboneDiscoveryRuntimeHandle {
        interface_name: name.to_string(),
        current: startup.clone(),
        startup,
    });
}

#[cfg(feature = "iface-tcp")]
fn register_test_tcp_server(driver: &mut Driver, name: &str) {
    let startup = TcpServerRuntime {
        max_connections: Some(4),
    };
    driver.register_tcp_server_runtime(TcpServerRuntimeConfigHandle {
        interface_name: name.to_string(),
        runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
        startup,
    });
}

#[cfg(feature = "iface-tcp")]
fn register_test_tcp_server_discovery(driver: &mut Driver, name: &str, discoverable: bool) {
    let startup = TcpServerDiscoveryRuntime {
        discoverable,
        config: crate::discovery::DiscoveryConfig {
            publish_ifac: false,
            encrypt: false,
            radio: Default::default(),
            stamp_costs: Default::default(),
            discovery_name: name.to_string(),
            announce_interval: 3600,
            stamp_value: crate::discovery::DEFAULT_STAMP_VALUE,
            reachable_on: None,
            interface_type: "TCPServerInterface".to_string(),
            listen_port: Some(4242),
            location_cmd: None,
            latitude: None,
            longitude: None,
            height: None,
            operator_lxmf_address: None,
        },
        transport_enabled: true,
        ifac_netname: None,
        ifac_netkey: None,
    };
    driver.register_tcp_server_discovery_runtime(TcpServerDiscoveryRuntimeHandle {
        interface_name: name.to_string(),
        current: startup.clone(),
        startup,
    });
}

#[cfg(feature = "iface-tcp")]
fn register_test_tcp_client(driver: &mut Driver, name: &str) {
    let startup = crate::interface::tcp::TcpClientRuntime {
        target_host: "127.0.0.1".into(),
        target_port: 4242,
        reconnect_wait: Duration::from_secs(5),
        max_reconnect_tries: Some(3),
        connect_timeout: Duration::from_secs(5),
    };
    driver.register_tcp_client_runtime(crate::interface::tcp::TcpClientRuntimeConfigHandle {
        interface_name: name.to_string(),
        runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
        startup,
    });
}

#[cfg(feature = "iface-udp")]
fn register_test_udp(driver: &mut Driver, name: &str) {
    let startup = UdpRuntime {
        forward_ip: Some("127.0.0.1".into()),
        forward_port: Some(4242),
    };
    driver.register_udp_runtime(UdpRuntimeConfigHandle {
        interface_name: name.to_string(),
        runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
        startup,
    });
}

fn register_test_generic_interface(driver: &mut Driver, id: u64, name: &str) {
    let mut info = make_interface_info(id);
    info.name = name.to_string();
    info.mode = rns_core::constants::MODE_FULL;
    info.announce_rate_target = Some(1.5);
    info.announce_rate_grace = 2;
    info.announce_rate_penalty = 0.25;
    info.announce_cap = 0.05;
    info.ingress_control.enabled = true;
    driver.register_interface_runtime_defaults(&info);
    driver.register_interface_ifac_runtime(
        &info.name,
        IfacRuntimeConfig {
            netname: None,
            netkey: None,
            size: 16,
        },
    );
    driver.engine.register_interface(info.clone());
    let (writer, _) = MockWriter::new();
    driver.interfaces.insert(
        InterfaceId(id),
        InterfaceEntry {
            id: InterfaceId(id),
            info,
            writer: Box::new(writer),
            async_writer_metrics: None,
            enabled: true,
            online: true,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats {
                started: time::now(),
                ..Default::default()
            },
            interface_type: "TestInterface".to_string(),
            send_retry_at: None,
            send_retry_backoff: Duration::ZERO,
        },
    );
}

#[cfg(feature = "iface-auto")]
fn register_test_auto(driver: &mut Driver, name: &str) {
    let startup = AutoRuntime {
        announce_interval_secs: 1.6,
        peer_timeout_secs: 22.0,
        peer_job_interval_secs: 4.0,
    };
    driver.register_auto_runtime(AutoRuntimeConfigHandle {
        interface_name: name.to_string(),
        runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
        startup,
    });
}

#[cfg(feature = "iface-i2p")]
fn register_test_i2p(driver: &mut Driver, name: &str) {
    let startup = I2pRuntime {
        reconnect_wait: Duration::from_secs(15),
    };
    driver.register_i2p_runtime(I2pRuntimeConfigHandle {
        interface_name: name.to_string(),
        runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
        startup,
    });
}

#[cfg(feature = "iface-pipe")]
fn register_test_pipe(driver: &mut Driver, name: &str) {
    let startup = PipeRuntime {
        respawn_delay: Duration::from_secs(5),
    };
    driver.register_pipe_runtime(PipeRuntimeConfigHandle {
        interface_name: name.to_string(),
        runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
        startup,
    });
}

#[cfg(feature = "iface-rnode")]
fn register_test_rnode(driver: &mut Driver, name: &str) {
    let startup = RNodeRuntime {
        sub: RNodeSubConfig {
            name: name.to_string(),
            vport: 0,
            outgoing: true,
            frequency: 868_000_000,
            bandwidth: 125_000,
            txpower: 7,
            spreading_factor: 8,
            coding_rate: 5,
            flow_control: false,
            st_alock: None,
            lt_alock: None,
        },
        writer: None,
    };
    driver.register_rnode_runtime(RNodeRuntimeConfigHandle {
        interface_name: name.to_string(),
        runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
        startup,
    });
}

impl Callbacks for MockCallbacks {
    fn on_announce(&mut self, announced: crate::destination::AnnouncedIdentity) {
        self.announces
            .lock()
            .unwrap()
            .push((announced.dest_hash, announced.hops));
    }

    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        self.paths.lock().unwrap().push((dest_hash, hops));
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
        self.deliveries.lock().unwrap().push(dest_hash);
    }

    fn on_interface_up(&mut self, id: InterfaceId) {
        self.iface_ups.lock().unwrap().push(id);
    }

    fn on_interface_down(&mut self, id: InterfaceId) {
        self.iface_downs.lock().unwrap().push(id);
    }

    fn on_link_established(
        &mut self,
        link_id: TypedLinkId,
        _dest_hash: DestHash,
        rtt: f64,
        is_initiator: bool,
    ) {
        self.link_established
            .lock()
            .unwrap()
            .push((link_id, rtt, is_initiator));
    }

    fn on_link_closed(
        &mut self,
        link_id: TypedLinkId,
        _reason: Option<rns_core::link::TeardownReason>,
    ) {
        self.link_closed.lock().unwrap().push(link_id);
    }

    fn on_remote_identified(
        &mut self,
        link_id: TypedLinkId,
        identity_hash: IdentityHash,
        _public_key: [u8; 64],
    ) {
        self.remote_identified
            .lock()
            .unwrap()
            .push((link_id, identity_hash));
    }

    fn on_resource_received(
        &mut self,
        link_id: TypedLinkId,
        data: Vec<u8>,
        _metadata: Option<Vec<u8>>,
    ) {
        self.resources_received
            .lock()
            .unwrap()
            .push((link_id, data));
    }

    fn on_resource_completed(&mut self, link_id: TypedLinkId) {
        self.resource_completed.lock().unwrap().push(link_id);
    }

    fn on_resource_failed(&mut self, link_id: TypedLinkId, error: String) {
        self.resource_failed.lock().unwrap().push((link_id, error));
    }

    fn on_channel_message(&mut self, link_id: TypedLinkId, msgtype: u16, payload: Vec<u8>) {
        self.channel_messages
            .lock()
            .unwrap()
            .push((link_id, msgtype, payload));
    }

    fn on_link_data(&mut self, link_id: TypedLinkId, context: u8, data: Vec<u8>) {
        self.link_data
            .lock()
            .unwrap()
            .push((link_id, context, data));
    }

    fn on_response(&mut self, link_id: TypedLinkId, request_id: [u8; 16], data: Vec<u8>) {
        self.responses
            .lock()
            .unwrap()
            .push((link_id, request_id, data));
    }

    fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
        self.proofs
            .lock()
            .unwrap()
            .push((dest_hash, packet_hash, rtt));
    }

    fn on_proof_requested(&mut self, dest_hash: DestHash, packet_hash: PacketHash) -> bool {
        self.proof_requested
            .lock()
            .unwrap()
            .push((dest_hash, packet_hash));
        true
    }
}

struct DirectConnectCallbacks {
    proposals: DirectConnectEvents,
    accept: bool,
}

struct ProofReplyCallbacks {
    tx: event::EventSender,
    reply: Vec<u8>,
}

impl Callbacks for ProofReplyCallbacks {
    fn on_announce(&mut self, _announced: crate::destination::AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
    }

    fn on_proof(&mut self, _dest_hash: DestHash, _packet_hash: PacketHash, _rtt: f64) {
        self.tx
            .send(Event::SendOutbound {
                raw: self.reply.clone(),
                dest_type: constants::DESTINATION_PLAIN,
                attached_interface: None,
            })
            .expect("proof callback should enqueue its reply");
    }
}

impl Callbacks for DirectConnectCallbacks {
    fn on_announce(&mut self, _announced: crate::destination::AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
    }

    fn on_direct_connect_proposed(
        &mut self,
        link_id: TypedLinkId,
        peer_identity: Option<IdentityHash>,
    ) -> bool {
        self.proposals
            .lock()
            .unwrap()
            .push((link_id, peer_identity));
        self.accept
    }
}

fn make_interface_info(id: u64) -> InterfaceInfo {
    InterfaceInfo {
        stamp_costs: Default::default(),
        id: InterfaceId(id),
        name: format!("test-{}", id),
        mode: constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate: None,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: rns_core::constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: constants::MTU as u32,
        mtu_upgradable: false,
        ia_freq: 0.0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
    }
}

fn make_entry(id: u64, writer: Box<dyn Writer>, online: bool) -> InterfaceEntry {
    InterfaceEntry {
        id: InterfaceId(id),
        info: make_interface_info(id),
        writer,
        async_writer_metrics: None,
        enabled: true,
        online,
        dynamic: false,
        ifac: None,
        stats: InterfaceStats::default(),
        interface_type: String::new(),
        send_retry_at: None,
        send_retry_backoff: Duration::ZERO,
    }
}

#[test]
fn confirmed_outbound_fanout_waits_for_all_interfaces_and_reports_partial_failure() {
    use crate::link_send::{Completion, LinkSendError};
    use futures::FutureExt;
    struct HeldWriter(Arc<Mutex<Vec<Completion>>>, bool);
    impl Writer for HeldWriter {
        fn send_frame(&mut self, _: &[u8]) -> io::Result<()> {
            panic!("confirmed send bypassed completion tracking")
        }
        fn enqueue_confirmed(
            &mut self,
            _: &[u8],
            completion: &mut Option<Completion>,
        ) -> io::Result<()> {
            if self.1 {
                self.1 = false;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.0.lock().unwrap().push(completion.take().unwrap());
            Ok(())
        }
    }
    // PLAIN uses BroadcastOnAllInterfaces, while a local announce produces
    // individual SendOnInterface actions. Exercise both fanout paths.
    for (packet_type, fail_first) in [
        (constants::PACKET_TYPE_DATA, false),
        (constants::PACKET_TYPE_DATA, true),
        (constants::PACKET_TYPE_ANNOUNCE, false),
        (constants::PACKET_TYPE_ANNOUNCE, true),
    ] {
        let (tx, rx) = event::channel_with_capacity(1);
        let (cbs, ..) = MockCallbacks::new();
        let mut driver = Driver::new(make_transport_config(false), rx, tx.clone(), Box::new(cbs));
        let first = Arc::new(Mutex::new(Vec::new()));
        let second = Arc::new(Mutex::new(Vec::new()));
        for (id, held) in [(1, first.clone()), (2, second.clone())] {
            let entry = make_entry(id, Box::new(HeldWriter(held, true)), true);
            driver.engine.register_interface(entry.info.clone());
            driver.interfaces.insert(entry.id, entry);
        }
        let dest = [0x31; 16];
        let dest_type = if packet_type == constants::PACKET_TYPE_DATA {
            constants::DESTINATION_PLAIN
        } else {
            constants::DESTINATION_SINGLE
        };
        driver.engine.register_destination(dest, dest_type);
        let packet = RawPacket::pack(
            PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: dest_type,
                packet_type,
            },
            0,
            &dest,
            None,
            constants::CONTEXT_NONE,
            b"confirmed",
        )
        .unwrap();
        let (completion, mut receipt) = Completion::new(tx.link_send_pool().try_acquire().unwrap());
        driver.handle_confirmed_outbound(packet.raw, dest_type, None, completion, None);
        driver.flush_pending_link_frames();
        assert!(first.lock().unwrap().is_empty());
        assert!(second.lock().unwrap().is_empty());
        assert_eq!(driver.pending_link_frames.len(), 2);
        assert!((&mut receipt).now_or_never().is_none());
        driver.flush_pending_link_frames();
        assert!(driver.pending_link_frames.is_empty());
        assert_eq!(first.lock().unwrap().len(), 1);
        assert_eq!(second.lock().unwrap().len(), 1);
        let expected = if fail_first {
            Err(LinkSendError::WriteFailed("broken pipe".into()))
        } else {
            Ok(())
        };
        first
            .lock()
            .unwrap()
            .pop()
            .unwrap()
            .finish(expected.clone());
        assert!((&mut receipt).now_or_never().is_none());
        assert!(matches!(
            tx.link_send_pool().try_acquire(),
            Err(LinkSendError::QueueFull)
        ));
        second.lock().unwrap().pop().unwrap().finish(Ok(()));
        assert_eq!(receipt.wait(), expected);
        assert_eq!(tx.link_send_pool().in_flight(), 0);
    }
}

#[test]
fn driver_validates_and_routes_mismatched_lrproof_using_known_identity() {
    use rns_crypto::ed25519::Ed25519PrivateKey;

    let (callbacks, _, _, _, _, _) = MockCallbacks::new();
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
    for id in [1, 2] {
        driver.engine.register_interface(make_interface_info(id));
    }
    let (outbound_writer, outbound_frames) = MockWriter::new();
    driver.interfaces.insert(
        InterfaceId(1),
        make_entry(1, Box::new(outbound_writer), true),
    );
    let (inbound_writer, _) = MockWriter::new();
    driver.interfaces.insert(
        InterfaceId(2),
        make_entry(2, Box::new(inbound_writer), true),
    );

    let link_id = [0x44; 16];
    let destination_hash = [0xBB; 16];
    driver.engine.register_link(
        link_id,
        rns_core::transport::tables::LinkEntry {
            timestamp: 100.0,
            next_hop_transport_id: [0xAA; 16],
            next_hop_interface: InterfaceId(2),
            remaining_hops: 3,
            received_interface: InterfaceId(1),
            taken_hops: 1,
            destination_hash,
            validated: false,
            proof_timeout: 200.0,
        },
    );
    driver.engine.inject_path(
        destination_hash,
        rns_core::transport::tables::PathEntry {
            timestamp: 99.0,
            next_hop: [0xAA; 16],
            hops: 3,
            expires: 999.0,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(2),
            packet_hash: [0xCC; 32],
            announce_raw: None,
            used: 0.0,
        },
    );

    let mut key_rng = rns_crypto::FixedRng::new(&[0x71; 128]);
    let signing_key = Ed25519PrivateKey::generate(&mut key_rng);
    let signing_public = signing_key.public_key().public_bytes();
    let mut public_key = [0u8; 64];
    public_key[32..].copy_from_slice(&signing_public);
    driver.upsert_known_destination(
        destination_hash,
        crate::destination::AnnouncedIdentity {
            dest_hash: rns_core::types::DestHash(destination_hash),
            identity_hash: rns_core::types::IdentityHash([0x99; 16]),
            public_key,
            app_data: None,
            hops: 3,
            received_at: 99.0,
            receiving_interface: InterfaceId(2),
            rssi: None,
            snr: None,
        },
    );
    let proof = rns_core::link::handshake::build_lrproof(
        &link_id,
        &[0x22; 32],
        &signing_public,
        &signing_key,
        None,
        rns_core::link::LinkMode::Aes256Cbc,
    );
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        },
        4,
        &link_id,
        None,
        constants::CONTEXT_LRPROOF,
        &proof,
    )
    .unwrap();

    driver.handle_frame_event(InterfaceId(2), packet.raw, None, None);

    assert_eq!(driver.engine.hops_to(&destination_hash), Some(5));
    assert_eq!(outbound_frames.lock().unwrap().len(), 1);
}

#[test]
fn established_initiator_rebalances_destination_path_to_authenticated_hops() {
    let mut driver = new_test_driver();
    let destination_hash = [0xBC; 16];
    driver.engine.inject_path(
        destination_hash,
        rns_core::transport::tables::PathEntry {
            timestamp: 99.0,
            next_hop: [0xAA; 16],
            hops: 2,
            expires: 999.0,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(1),
            packet_hash: [0xCC; 32],
            announce_raw: None,
            used: 0.0,
        },
    );

    driver.dispatch_link_actions(vec![LinkManagerAction::LinkEstablished {
        link_id: [0x45; 16],
        dest_hash: destination_hash,
        hops: 6,
        rebalanced_at: Some(100.0),
        rtt: 0.25,
        is_initiator: true,
    }]);

    assert_eq!(driver.engine.hops_to(&destination_hash), Some(6));

    driver.dispatch_link_actions(vec![LinkManagerAction::LinkEstablished {
        link_id: [0x46; 16],
        dest_hash: destination_hash,
        hops: 7,
        rebalanced_at: None,
        rtt: 0.25,
        is_initiator: true,
    }]);
    assert_eq!(driver.engine.hops_to(&destination_hash), Some(6));
}

fn make_pending_verify_announce(dest: [u8; 16]) -> (AnnounceVerifyKey, PendingAnnounce) {
    let random_blob = [0xA1; 10];
    let received_from = [0xB2; 16];
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        },
        1,
        &dest,
        None,
        constants::CONTEXT_NONE,
        &[0xCC; 16],
    )
    .unwrap();
    (
        AnnounceVerifyKey {
            destination_hash: dest,
            random_blob,
            received_from,
        },
        PendingAnnounce {
            original_raw: packet.raw.clone(),
            packet: packet.map_raw(rns_core::transport::types::PacketBytes::from),
            interface: InterfaceId(1),
            received_from,
            queued_at: 100.0,
            best_hops: 1,
            emission_ts: 42,
            random_blob,
            ingress_limited: false,
        },
    )
}

/// Build a valid announce packet that the engine will accept.
fn build_announce_packet(identity: &Identity) -> Vec<u8> {
    let dest_hash =
        rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));
    let name_hash = rns_core::destination::name_hash("test", &["app"]);
    let random_hash = [0x42u8; 10];

    let (announce_data, _has_ratchet) =
        AnnounceData::pack(identity, &dest_hash, &name_hash, &random_hash, None, None).unwrap();

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };

    let packet = RawPacket::pack(
        flags,
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();
    packet.raw
}

#[test]
fn malformed_inbound_frame_does_not_block_later_valid_frame() {
    let (tx, rx) = event::channel();
    let (cbs, announces, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info.clone());
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);

    // A malformed frame must be contained to this delivery; the event loop
    // must continue and process the valid announce that follows it.
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: vec![0xff].into(),
        rssi: None,
        snr: None,
    })
    .unwrap();
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(announces.lock().unwrap().len(), 1);
}

#[test]
fn queued_startup_events_register_dynamic_interface_before_frame() {
    let (tx, rx) = event::channel();
    let (cbs, announces, _, _, iface_ups, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let info = make_interface_info(100);
    let (writer, _sent) = MockWriter::new();
    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);

    tx.send(Event::InterfaceUp(
        InterfaceId(100),
        Some(Box::new(writer)),
        Some(Box::new(info)),
    ))
    .unwrap();
    tx.send(Event::Frame {
        interface_id: InterfaceId(100),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let entry = driver.interfaces.get(&InterfaceId(100)).unwrap();
    assert!(entry.online);
    assert!(entry.dynamic);
    assert_eq!(entry.stats.rx_packets, 1);
    assert_eq!(iface_ups.lock().unwrap().as_slice(), &[InterfaceId(100)]);
    assert_eq!(announces.lock().unwrap().len(), 1);
}

#[test]
fn dispatch_send() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    driver.dispatch_all(vec![TransportAction::SendOnInterface {
        interface: InterfaceId(1),
        raw: vec![0x01, 0x02, 0x03].into(),
    }]);
    driver.wake_writers();

    assert_eq!(sent.lock().unwrap().len(), 1);
    assert_eq!(sent.lock().unwrap()[0], vec![0x01, 0x02, 0x03]);

    drop(tx);
}

#[test]
fn driver_selects_ifac_handlers_for_outbound_and_inbound_frames() {
    let mut driver = new_test_driver();
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    let state = crate::ifac::derive_ifac(Some("network"), Some("key"), 16).unwrap();
    let mut entry = make_entry(1, Box::new(writer), true);
    entry.ifac = Some(state.clone());
    driver.interfaces.insert(InterfaceId(1), entry);

    let raw = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &[0xaa; 16],
        None,
        constants::CONTEXT_NONE,
        b"ifac handler selection",
    )
    .unwrap()
    .raw;

    driver.dispatch_all(vec![TransportAction::SendOnInterface {
        interface: InterfaceId(1),
        raw: raw.clone().into(),
    }]);
    driver.wake_writers();

    let frame = sent.lock().unwrap()[0].clone();
    assert_eq!(crate::ifac::unmask_inbound(&frame, &state), Some(raw));
    driver.handle_frame_event(InterfaceId(1), frame, None, None);
    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.ifac_violations, 0);
    assert_eq!(stats.protocol_violations, 0);
    assert_eq!(stats.rx_packets, 1);
}

#[test]
fn offline_attached_interface_does_not_fall_back_to_other_interfaces() {
    let mut driver = new_test_driver();
    for id in [1, 2] {
        driver.engine.register_interface(make_interface_info(id));
    }
    let (attached_writer, attached_sent) = MockWriter::new();
    driver.interfaces.insert(
        InterfaceId(1),
        make_entry(1, Box::new(attached_writer), false),
    );
    let (other_writer, other_sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(other_writer), true));

    let raw = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &[0xbb; 16],
        None,
        constants::CONTEXT_NONE,
        b"attached only",
    )
    .unwrap()
    .raw;

    driver.handle_send_outbound_event(raw, constants::DESTINATION_SINGLE, Some(InterfaceId(1)));

    assert!(attached_sent.lock().unwrap().is_empty());
    assert!(other_sent.lock().unwrap().is_empty());
}

#[test]
fn missing_attached_interface_does_not_fall_back_to_other_interfaces() {
    let mut driver = new_test_driver();
    driver.engine.register_interface(make_interface_info(2));
    let (other_writer, other_sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(other_writer), true));

    let raw = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &[0xbc; 16],
        None,
        constants::CONTEXT_NONE,
        b"missing attached only",
    )
    .unwrap()
    .raw;

    driver.handle_send_outbound_event(raw, constants::DESTINATION_SINGLE, Some(InterfaceId(1)));

    assert!(other_sent.lock().unwrap().is_empty());
    assert_eq!(driver.interfaces[&InterfaceId(2)].stats.tx_packets, 0);
}

#[test]
fn dispatch_broadcast() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let (w1, sent1) = MockWriter::new();
    let (w2, sent2) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

    driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
        raw: vec![0xAA].into(),
        exclude: None,
    }]);

    assert_eq!(sent1.lock().unwrap().len(), 1);
    assert_eq!(sent2.lock().unwrap().len(), 1);

    drop(tx);
}

#[test]
fn dispatch_broadcast_exclude() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let (w1, sent1) = MockWriter::new();
    let (w2, sent2) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

    driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
        raw: vec![0xBB].into(),
        exclude: Some(InterfaceId(1)),
    }]);

    assert_eq!(sent1.lock().unwrap().len(), 0); // excluded
    assert_eq!(sent2.lock().unwrap().len(), 1);

    drop(tx);
}

#[test]
fn tick_event() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some([0x42; 16]),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info.clone());
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Send Tick then Shutdown
    tx.send(Event::Tick).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();
    // No crash = tick was processed successfully
}

#[test]
fn shutdown_event() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    tx.send(Event::Shutdown).unwrap();
    driver.run(); // Should return immediately
}

#[test]
fn graceful_shutdown_voids_async_announce_and_receipt_state() {
    let mut driver = new_test_driver();
    let (key, pending) = make_pending_verify_announce([0xD1; 16]);
    {
        let mut queue = driver.announce_verify_queue.lock().unwrap();
        assert!(queue.enqueue(key, pending));
        assert!(!queue.is_empty());
        assert!(queue.queued_bytes() > 0);
    }
    driver.sent_packets.insert([0xA1; 32], ([0xB1; 16], 100.0));
    driver.completed_proofs.insert([0xA2; 32], (0.25, 101.0));

    driver.graceful_shutdown();

    assert_eq!(driver.lifecycle_state, LifecycleState::Stopped);
    {
        let queue = driver.announce_verify_queue.lock().unwrap();
        assert!(queue.is_empty());
        assert_eq!(queue.queued_bytes(), 0);
    }
    assert!(driver.sent_packets.is_empty());
    assert!(driver.completed_proofs.is_empty());
}

#[test]
fn begin_drain_updates_driver_status() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx,
        Box::new(cbs),
    );

    driver.begin_drain(Duration::from_secs(3));

    let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus) else {
        panic!("expected drain status response");
    };
    assert_eq!(status.state, LifecycleState::Draining);
    assert!(status.drain_complete);
    assert!(status.drain_age_seconds.is_some());
    assert!(status.deadline_remaining_seconds.is_some());
    assert_eq!(
            status.detail.as_deref(),
            Some("node is draining existing work; no active links, resource transfers, hole-punch sessions, or queued writer/provider work remain")
        );
}

#[test]
fn begin_drain_with_pending_link_reports_incomplete_status() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx,
        Box::new(cbs),
    );

    let _ = driver.link_manager.create_link(
        &[0xDD; 16],
        &[0x11; 32],
        1,
        rns_core::constants::MTU as u32,
        &mut OsRng,
    );

    driver.begin_drain(Duration::from_secs(3));

    let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus) else {
        panic!("expected drain status response");
    };
    assert_eq!(status.state, LifecycleState::Draining);
    assert!(!status.drain_complete);
    assert!(status
        .detail
        .unwrap_or_default()
        .contains("1 link(s) still active"));
}

#[test]
fn begin_drain_with_queued_writer_frames_reports_incomplete_status() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx,
        Box::new(cbs),
    );

    let info = make_interface_info(77);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (writer, async_writer_metrics) = crate::interface::wrap_async_writer(
        Box::new(BlockingWriter {
            entered_tx,
            release_rx,
        }),
        InterfaceId(77),
        &info.name,
        driver.event_tx.clone(),
        1,
    );

    driver.interfaces.insert(
        InterfaceId(77),
        InterfaceEntry {
            id: InterfaceId(77),
            info,
            writer,
            async_writer_metrics: Some(async_writer_metrics),
            enabled: true,
            online: true,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats::default(),
            interface_type: "TestInterface".to_string(),
            send_retry_at: None,
            send_retry_backoff: Duration::ZERO,
        },
    );

    driver.dispatch_all(vec![TransportAction::SendOnInterface {
        interface: InterfaceId(77),
        raw: vec![0x01].into(),
    }]);
    driver.wake_writers();
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    driver.dispatch_all(vec![TransportAction::SendOnInterface {
        interface: InterfaceId(77),
        raw: vec![0x02].into(),
    }]);
    driver.wake_writers();

    driver.begin_drain(Duration::from_secs(3));

    let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus) else {
        panic!("expected drain status response");
    };
    assert_eq!(status.state, LifecycleState::Draining);
    assert!(!status.drain_complete);
    assert_eq!(status.interface_writer_queued_frames, 1);
    assert!(status
        .detail
        .unwrap_or_default()
        .contains("queued interface writer frame"));

    let _ = release_tx.send(());
}

#[test]
fn enforce_drain_deadline_tears_down_remaining_links() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx,
        Box::new(cbs),
    );

    let _ = driver.link_manager.create_link(
        &[0xDD; 16],
        &[0x11; 32],
        1,
        rns_core::constants::MTU as u32,
        &mut OsRng,
    );
    driver.begin_drain(Duration::ZERO);

    driver.enforce_drain_deadline();

    assert_eq!(driver.lifecycle_state, LifecycleState::Stopping);
    assert_eq!(driver.link_manager.link_count(), 0);
    let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus) else {
        panic!("expected drain status response");
    };
    assert!(status.drain_complete);
    assert_eq!(status.state, LifecycleState::Stopping);
}

#[test]
fn begin_drain_with_holepunch_session_reports_incomplete_status_and_deadline_aborts_it() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx,
        Box::new(cbs),
    );
    driver.holepunch_manager = crate::holepunch::orchestrator::HolePunchManager::new(
        vec!["127.0.0.1:4343".parse().unwrap()],
        rns_core::holepunch::ProbeProtocol::Rnsp,
        None,
    );

    let _ = driver.holepunch_manager.propose_to_supported(
        [0x44; 16],
        &[0xAA; 32],
        &mut OsRng,
        &driver.get_event_sender(),
    );
    assert_eq!(driver.holepunch_manager.session_count(), 1);

    driver.begin_drain(Duration::from_secs(3));

    let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus) else {
        panic!("expected drain status response");
    };
    assert_eq!(status.state, LifecycleState::Draining);
    assert!(!status.drain_complete);
    assert!(status
        .detail
        .unwrap_or_default()
        .contains("1 hole-punch session(s) still active"));

    driver.begin_drain(Duration::ZERO);
    driver.enforce_drain_deadline();

    assert_eq!(driver.holepunch_manager.session_count(), 0);
    let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus) else {
        panic!("expected drain status response");
    };
    assert!(status.drain_complete);
    assert_eq!(status.state, LifecycleState::Stopping);
}

#[test]
fn begin_drain_event_is_processed_by_run_loop() {
    let (tx, rx) = event::channel();
    let tx_query = tx.clone();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let handle = std::thread::spawn(move || driver.run());
    tx.send(Event::BeginDrain {
        timeout: Duration::from_secs(2),
    })
    .unwrap();
    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
    tx_query
        .send(Event::query(QueryRequest::DrainStatus, resp_tx))
        .unwrap();
    let status = match resp_rx.recv().unwrap() {
        QueryResponse::DrainStatus(status) => status,
        other => panic!("expected drain status response, got {:?}", other),
    };
    assert_eq!(status.state, LifecycleState::Draining);
    tx_query.send(Event::Shutdown).unwrap();
    handle.join().unwrap();
}

#[test]
fn send_channel_message_returns_error_while_draining() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    tx.send(Event::BeginDrain {
        timeout: Duration::from_secs(2),
    })
    .unwrap();
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::SendChannelMessage {
        link_id: [0xAA; 16],
        msgtype: 7,
        payload: b"drain".to_vec(),
        response_tx: resp_tx,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let response = resp_rx.recv().unwrap();
    assert_eq!(
        response,
        Err("cannot send channel message while node is draining".into())
    );
}

#[test]
fn send_outbound_is_ignored_while_draining() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let identity = Identity::new(&mut OsRng);
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    tx.send(Event::BeginDrain {
        timeout: Duration::from_secs(2),
    })
    .unwrap();
    tx.send(Event::SendOutbound {
        raw: build_announce_packet(&identity),
        dest_type: constants::DESTINATION_SINGLE,
        attached_interface: None,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(sent.lock().unwrap().is_empty());
    assert!(driver.sent_packets.is_empty());
}

#[test]
fn request_path_is_ignored_while_draining() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    tx.send(Event::BeginDrain {
        timeout: Duration::from_secs(2),
    })
    .unwrap();
    tx.send(Event::RequestPath {
        dest_hash: [0xAA; 16],
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(sent.lock().unwrap().is_empty());
}

#[test]
fn create_link_returns_zero_link_id_while_draining() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    tx.send(Event::BeginDrain {
        timeout: Duration::from_secs(2),
    })
    .unwrap();
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::CreateLink {
        dest_hash: [0xAB; 16],
        dest_sig_pub_bytes: [0xCD; 32],
        response_tx: resp_tx,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(resp_rx.recv().unwrap(), [0u8; 16]);
}

#[test]
fn announce_callback() {
    let (tx, rx) = event::channel();
    let (cbs, announces, paths, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info.clone());
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let ann = announces.lock().unwrap();
    assert_eq!(ann.len(), 1);
    // Hops should be 1 (incremented from 0 by handle_inbound)
    assert_eq!(ann[0].1, 1);

    let p = paths.lock().unwrap();
    assert_eq!(p.len(), 1);
}

#[test]
fn dispatch_skips_offline_interface() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let (w1, sent1) = MockWriter::new();
    let (w2, sent2) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(w1), false)); // offline
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

    // Direct send to offline interface: should be skipped
    driver.dispatch_all(vec![TransportAction::SendOnInterface {
        interface: InterfaceId(1),
        raw: vec![0x01].into(),
    }]);
    driver.wake_writers();
    assert_eq!(sent1.lock().unwrap().len(), 0);

    // Broadcast: only online interface should receive
    driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
        raw: vec![0x02].into(),
        exclude: None,
    }]);
    assert_eq!(sent1.lock().unwrap().len(), 0); // still offline
    assert_eq!(sent2.lock().unwrap().len(), 1);

    drop(tx);
}

#[test]
fn interface_up_refreshes_writer() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let (w_old, sent_old) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(w_old), false));

    // Simulate reconnect: InterfaceUp with new writer
    let (w_new, sent_new) = MockWriter::new();
    tx.send(Event::InterfaceUp(
        InterfaceId(1),
        Some(Box::new(w_new)),
        None,
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Interface should be online now
    assert!(driver.interfaces[&InterfaceId(1)].online);

    // Send via the (now-refreshed) interface
    driver.dispatch_all(vec![TransportAction::SendOnInterface {
        interface: InterfaceId(1),
        raw: vec![0xFF].into(),
    }]);
    driver.wake_writers();

    // Old writer should not have received anything
    assert_eq!(sent_old.lock().unwrap().len(), 0);
    // New writer should have received the data
    wait_for_sent_len(&sent_new, 1);
    assert_eq!(sent_new.lock().unwrap()[0], vec![0xFF]);

    drop(tx);
}

#[test]
fn dynamic_interface_register() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, iface_ups, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(false), rx, tx.clone(), Box::new(cbs));

    let info = make_interface_info(100);
    let (writer, sent) = MockWriter::new();

    // InterfaceUp with InterfaceInfo = new dynamic interface
    tx.send(Event::InterfaceUp(
        InterfaceId(100),
        Some(Box::new(writer)),
        Some(Box::new(info)),
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Should be registered and online
    assert!(driver.interfaces.contains_key(&InterfaceId(100)));
    assert!(driver.interfaces[&InterfaceId(100)].online);
    assert!(driver.interfaces[&InterfaceId(100)].dynamic);

    // Callback should have fired
    assert_eq!(iface_ups.lock().unwrap().len(), 1);
    assert_eq!(iface_ups.lock().unwrap()[0], InterfaceId(100));

    // Can send to it
    driver.dispatch_all(vec![TransportAction::SendOnInterface {
        interface: InterfaceId(100),
        raw: vec![0x42].into(),
    }]);
    // As the driver loop does at the end of its pass.
    driver.wake_writers();
    wait_for_sent_len(&sent, 1);

    drop(tx);
}

#[test]
fn dynamic_interface_inherits_parent_announce_cap() {
    let (callbacks, ..) = MockCallbacks::new();
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));

    let (writer, _) = MockWriter::new();
    let mut parent = make_entry(10, Box::new(writer), true);
    parent.info.announce_cap = 0.5;
    // Upstream 9b464382 copies `_destination_cost` / `_pr_cost` to spawned
    // interfaces too.
    parent.info.stamp_costs.destination_cost = Some(StampCost::from_f64(17.5));
    parent.info.stamp_costs.pr_cost = Some(StampCost::ZERO);
    driver.interfaces.insert(InterfaceId(10), parent);

    let mut info = make_interface_info(11);
    info.announce_cap = rns_core::constants::ANNOUNCE_CAP;
    let (writer, _) = MockWriter::new();
    driver.handle_dynamic_interface_up_event(
        InterfaceId(11),
        Box::new(writer),
        event::DynamicInterfaceRegistration {
            info,
            interface_type: "BackboneClientInterface".into(),
            parent_id: InterfaceId(10),
            telemetry: event::InterfaceTelemetry::default(),
            ifac: None,
            display_name: None,
            short_name: None,
            reconnecting: false,
        },
    );

    let registered = driver.engine.interface_info(&InterfaceId(11)).unwrap();
    assert_eq!(registered.announce_cap, 0.5);
    assert_eq!(
        registered.stamp_costs.destination_cost,
        Some(StampCost::from_f64(17.5))
    );
    assert_eq!(registered.stamp_costs.pr_cost, Some(StampCost::ZERO));
}

#[test]
fn dynamic_burst_counts_are_scoped_to_parent_and_cleaned_on_disconnect() {
    let (callbacks, ..) = MockCallbacks::new();
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));
    for parent_id in [10, 20] {
        let (writer, _) = MockWriter::new();
        let mut parent = make_entry(parent_id, Box::new(writer), true);
        parent.info.mode = constants::MODE_ACCESS_POINT;
        parent.info.ingress_control = rns_core::transport::types::IngressControlConfig::enabled();
        driver.interfaces.insert(InterfaceId(parent_id), parent);
    }

    for (child_id, parent_id, announce_burst, path_request_burst) in [
        (11, 10, true, false),
        (12, 10, false, true),
        (21, 20, false, true),
    ] {
        let mut info = make_interface_info(child_id);
        if announce_burst {
            info.ia_freq = constants::IC_BURST_FREQ + 1.0;
        }
        if path_request_burst {
            info.ip_freq = constants::IC_PR_BURST_FREQ + 1.0;
        }
        let (writer, _) = MockWriter::new();
        driver.handle_dynamic_interface_up_event(
            InterfaceId(child_id),
            Box::new(writer),
            event::DynamicInterfaceRegistration {
                info,
                interface_type: "BackboneClientInterface".into(),
                parent_id: InterfaceId(parent_id),
                telemetry: event::InterfaceTelemetry::default(),
                ifac: None,
                display_name: None,
                short_name: None,
                reconnecting: false,
            },
        );
        let registered = driver
            .engine
            .interface_info(&InterfaceId(child_id))
            .unwrap();
        assert!(registered.ingress_control.enabled);

        if announce_burst {
            let identity = Identity::new(&mut OsRng);
            let raw = build_announce_packet(&identity);
            driver.engine.handle_inbound(
                rns_core::transport::InboundFrame {
                    raw: &raw,
                    iface: InterfaceId(child_id),
                    now: time::now(),
                    rx: rns_core::transport::RxMetadata::default(),
                },
                &mut driver.rng,
            );
            assert!(driver.engine.burst_active(&InterfaceId(child_id)));
        }
        if path_request_burst {
            let mut request = vec![0xC3; 16];
            request.extend_from_slice(&[child_id as u8; 16]);
            driver
                .engine
                .handle_path_request(&request, InterfaceId(child_id), time::now());
            assert!(driver.engine.pr_burst_active(&InterfaceId(child_id)));
        }
        assert_eq!(
            driver.dynamic_interface_parents[&InterfaceId(child_id)],
            InterfaceId(parent_id)
        );
    }

    assert_eq!(driver.dynamic_burst_counts(InterfaceId(10)), (1, 1));
    assert_eq!(driver.dynamic_burst_counts(InterfaceId(20)), (0, 1));

    driver.handle_interface_down_event(InterfaceId(12));
    assert_eq!(driver.dynamic_burst_counts(InterfaceId(10)), (1, 0));
    assert!(!driver
        .dynamic_interface_parents
        .contains_key(&InterfaceId(12)));
}

/// Upstream 023849ed: a tunnel whose interface is removed waits
/// TUNNEL_RECONNECT_WINDOW to be synthesized again; an interface that only
/// goes offline (a static one, which upstream keeps registered) leaves the
/// tunnel's expiry alone.
#[test]
fn removed_dynamic_interface_starts_tunnel_reconnect_window() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "static-tunnel");
    register_test_generic_interface(&mut driver, 2, "dynamic-tunnel");
    driver.interfaces.get_mut(&InterfaceId(2)).unwrap().dynamic = true;
    let (static_tunnel, dynamic_tunnel) = ([0x31; 32], [0x32; 32]);
    let now = time::now();
    for (id, tunnel) in [(1, static_tunnel), (2, dynamic_tunnel)] {
        driver.engine.handle_tunnel(tunnel, InterfaceId(id), now);
        driver
            .interfaces
            .get_mut(&InterfaceId(id))
            .unwrap()
            .info
            .tunnel_id = Some(tunnel);
    }

    driver.handle_interface_down_event(InterfaceId(1));
    driver.handle_interface_down_event(InterfaceId(2));

    let table = driver.engine.tunnel_table();
    let static_entry = table.get(&static_tunnel).unwrap();
    assert_eq!(static_entry.interface, None);
    assert!(static_entry.expires >= now + rns_core::constants::TUNNEL_TIMEOUT);
    let dynamic_entry = table.get(&dynamic_tunnel).unwrap();
    assert_eq!(dynamic_entry.interface, None);
    assert!(dynamic_entry.expires <= time::now() + rns_core::constants::TUNNEL_RECONNECT_WINDOW);
    assert!(dynamic_entry.expires >= now + rns_core::constants::TUNNEL_RECONNECT_WINDOW);
}

#[test]
fn dynamic_interface_applies_transport_announce_rate_defaults() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(true), rx, tx.clone(), Box::new(cbs));
    driver.set_announce_rate_defaults(AnnounceRateDefaults {
        target: Some(7200.0),
        penalty: 15.0,
        grace: 7,
    });

    let info = make_interface_info(100);
    let (writer, _sent) = MockWriter::new();
    tx.send(Event::InterfaceUp(
        InterfaceId(100),
        Some(Box::new(writer)),
        Some(Box::new(info)),
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let info = &driver.interfaces[&InterfaceId(100)].info;
    assert_eq!(info.announce_rate_target, Some(7200.0));
    assert_eq!(info.announce_rate_penalty, 15.0);
    assert_eq!(info.announce_rate_grace, 7);
}

#[test]
fn dynamic_interface_keeps_explicit_announce_rate_values() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(true), rx, tx.clone(), Box::new(cbs));
    driver.set_announce_rate_defaults(AnnounceRateDefaults {
        target: Some(7200.0),
        penalty: 15.0,
        grace: 7,
    });

    let mut info = make_interface_info(100);
    info.announce_rate_target = Some(120.0);
    info.announce_rate_penalty = 2.0;
    info.announce_rate_grace = 3;
    let (writer, _sent) = MockWriter::new();
    tx.send(Event::InterfaceUp(
        InterfaceId(100),
        Some(Box::new(writer)),
        Some(Box::new(info)),
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let info = &driver.interfaces[&InterfaceId(100)].info;
    assert_eq!(info.announce_rate_target, Some(120.0));
    assert_eq!(info.announce_rate_penalty, 2.0);
    assert_eq!(info.announce_rate_grace, 3);
}

#[test]
fn dynamic_interface_skips_announce_rate_defaults_without_transport() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(false), rx, tx.clone(), Box::new(cbs));
    driver.set_announce_rate_defaults(AnnounceRateDefaults {
        target: Some(7200.0),
        penalty: 15.0,
        grace: 7,
    });

    let info = make_interface_info(100);
    let (writer, _sent) = MockWriter::new();
    tx.send(Event::InterfaceUp(
        InterfaceId(100),
        Some(Box::new(writer)),
        Some(Box::new(info)),
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let info = &driver.interfaces[&InterfaceId(100)].info;
    assert_eq!(info.announce_rate_target, None);
    assert_eq!(info.announce_rate_penalty, 0.0);
    assert_eq!(info.announce_rate_grace, 0);
}

#[test]
fn dynamic_interface_applies_transport_ingress_control_defaults() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(true), rx, tx.clone(), Box::new(cbs));
    let mut defaults = rns_core::transport::types::IngressControlConfig::enabled();
    defaults.max_held_announces = 17;
    defaults.burst_hold = 1.5;
    defaults.burst_freq_new = 2.5;
    defaults.burst_freq = 3.5;
    defaults.pr_burst_freq_new = 4.5;
    defaults.pr_burst_freq = 5.5;
    defaults.new_time = 6.5;
    defaults.burst_penalty = 7.5;
    defaults.held_release_interval = 8.5;
    defaults.egress_enabled = true;
    defaults.egress_pr_freq = 9.5;
    driver.set_ingress_control_defaults(defaults);

    let info = make_interface_info(100);
    let (writer, _sent) = MockWriter::new();
    tx.send(Event::InterfaceUp(
        InterfaceId(100),
        Some(Box::new(writer)),
        Some(Box::new(info)),
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let ic = driver.interfaces[&InterfaceId(100)].info.ingress_control;
    assert_eq!(ic.max_held_announces, 17);
    assert_eq!(ic.burst_hold, 1.5);
    assert_eq!(ic.burst_freq_new, 2.5);
    assert_eq!(ic.burst_freq, 3.5);
    assert_eq!(ic.pr_burst_freq_new, 4.5);
    assert_eq!(ic.pr_burst_freq, 5.5);
    assert_eq!(ic.new_time, 6.5);
    assert_eq!(ic.burst_penalty, 7.5);
    assert_eq!(ic.held_release_interval, 8.5);
    assert!(ic.egress_enabled);
    assert_eq!(ic.egress_pr_freq, 9.5);
}

#[test]
fn dynamic_interface_keeps_explicit_ingress_control_values() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(true), rx, tx.clone(), Box::new(cbs));
    let mut defaults = rns_core::transport::types::IngressControlConfig::enabled();
    defaults.burst_hold = 1.5;
    defaults.pr_burst_freq = 5.5;
    defaults.egress_enabled = true;
    driver.set_ingress_control_defaults(defaults);

    let mut info = make_interface_info(100);
    info.ingress_control.burst_hold = 12.0;
    info.ingress_control.pr_burst_freq = 13.0;
    let (writer, _sent) = MockWriter::new();
    tx.send(Event::InterfaceUp(
        InterfaceId(100),
        Some(Box::new(writer)),
        Some(Box::new(info)),
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let ic = driver.interfaces[&InterfaceId(100)].info.ingress_control;
    assert_eq!(ic.burst_hold, 12.0);
    assert_eq!(ic.pr_burst_freq, 13.0);
    assert!(ic.egress_enabled);
}

#[test]
fn dynamic_interface_skips_ingress_control_defaults_without_transport() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(false), rx, tx.clone(), Box::new(cbs));
    let mut defaults = rns_core::transport::types::IngressControlConfig::enabled();
    defaults.burst_hold = 1.5;
    defaults.egress_enabled = true;
    driver.set_ingress_control_defaults(defaults);

    let info = make_interface_info(100);
    let (writer, _sent) = MockWriter::new();
    tx.send(Event::InterfaceUp(
        InterfaceId(100),
        Some(Box::new(writer)),
        Some(Box::new(info)),
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let ic = driver.interfaces[&InterfaceId(100)].info.ingress_control;
    assert_eq!(ic.burst_hold, rns_core::constants::IC_BURST_HOLD);
    assert!(!ic.egress_enabled);
}

#[test]
fn dynamic_interface_deregister() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, iface_downs) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    // Register a dynamic interface
    let info = make_interface_info(200);
    driver.engine.register_interface(info.clone());
    let (writer, _sent) = MockWriter::new();
    driver.interfaces.insert(
        InterfaceId(200),
        InterfaceEntry {
            id: InterfaceId(200),
            info,
            writer: Box::new(writer),
            async_writer_metrics: None,
            enabled: true,
            online: true,
            dynamic: true,
            ifac: None,
            stats: InterfaceStats::default(),
            interface_type: String::new(),
            send_retry_at: None,
            send_retry_backoff: Duration::ZERO,
        },
    );

    // InterfaceDown for dynamic → should be removed entirely
    tx.send(Event::InterfaceDown(InterfaceId(200))).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(!driver.interfaces.contains_key(&InterfaceId(200)));
    assert_eq!(iface_downs.lock().unwrap().len(), 1);
    assert_eq!(iface_downs.lock().unwrap()[0], InterfaceId(200));
}

#[test]
fn send_wouldblock_is_backed_off_between_dispatches() {
    let (tx, rx) = event::channel();
    let (cbs, ..) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx,
        Box::new(cbs),
    );
    let (writer, attempts) = WouldBlockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(7), make_entry(7, Box::new(writer), true));

    let action = TransportAction::SendOnInterface {
        interface: InterfaceId(7),
        raw: vec![0x01, 0x00, 0x42].into(),
    };
    driver.dispatch_all(vec![action.clone()]);
    assert_eq!(*attempts.lock().unwrap(), 1);

    driver.dispatch_all(vec![action.clone()]);
    assert_eq!(
        *attempts.lock().unwrap(),
        1,
        "second dispatch should be deferred during backoff"
    );

    let entry = driver.interfaces.get_mut(&InterfaceId(7)).unwrap();
    entry.send_retry_at = Some(Instant::now() - Duration::from_millis(1));
    driver.dispatch_all(vec![action]);
    assert_eq!(*attempts.lock().unwrap(), 2);
}

#[test]
fn interface_callbacks_fire() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, iface_ups, iface_downs) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    // Static interface
    let (writer, _) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), false));

    tx.send(Event::InterfaceUp(InterfaceId(1), None, None))
        .unwrap();
    tx.send(Event::InterfaceDown(InterfaceId(1))).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(iface_ups.lock().unwrap().len(), 1);
    assert_eq!(iface_downs.lock().unwrap().len(), 1);
    // Static interface should still exist but be offline
    assert!(driver.interfaces.contains_key(&InterfaceId(1)));
    assert!(!driver.interfaces[&InterfaceId(1)].online);
}

// =========================================================================
// New tests for Phase 6a
// =========================================================================

#[test]
fn frame_updates_rx_stats() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info.clone());
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);
    let announce_len = announce_raw.len() as u64;

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(-10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.rxb, announce_len);
    assert_eq!(stats.arxb, announce_len);
    assert_eq!(stats.rx_packets, 1);
}

#[test]
fn inbound_rejections_are_counted_by_reason() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "violations");

    driver.handle_frame_event(InterfaceId(1), vec![0x00], None, None);
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.protocol_violations,
        1
    );

    driver.interfaces.get_mut(&InterfaceId(1)).unwrap().ifac =
        Some(crate::ifac::derive_ifac(Some("network"), Some("key"), 8).unwrap());
    driver.handle_frame_event(InterfaceId(1), vec![0x00; 32], None, None);
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.ifac_violations, 1);
    driver.interfaces.get_mut(&InterfaceId(1)).unwrap().ifac = None;

    let path_request_flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let tagless = RawPacket::pack(
        path_request_flags,
        0,
        &driver.path_request_dest,
        None,
        constants::CONTEXT_NONE,
        &[0x44; 16],
    )
    .unwrap();
    driver.handle_frame_event(InterfaceId(1), tagless.raw, None, None);
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.protocol_violations,
        2
    );

    let mut tagged_request_data = vec![0x55; 16];
    tagged_request_data.extend_from_slice(&[0x66; 16]);
    let tagged_request = RawPacket::pack(
        path_request_flags,
        0,
        &driver.path_request_dest,
        None,
        constants::CONTEXT_NONE,
        &tagged_request_data,
    )
    .unwrap();
    driver.handle_frame_event(InterfaceId(1), tagged_request.raw, None, None);
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.protocol_violations,
        2,
        "destination plus tag is a valid non-transport path request"
    );

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &[0x55; 16],
        None,
        constants::CONTEXT_NONE,
        b"duplicate",
    )
    .unwrap();
    driver.handle_frame_event(InterfaceId(1), packet.raw.clone(), None, None);
    driver.handle_frame_event(InterfaceId(1), packet.raw, None, None);
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.packet_filter_hits,
        1
    );

    let identity = Identity::new(&mut OsRng);
    let mut invalid_announce = build_announce_packet(&identity);
    let last = invalid_announce.len() - 1;
    invalid_announce[last] ^= 0x01;
    driver.handle_frame_event(InterfaceId(1), invalid_announce, None, None);
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.protocol_violations,
        3
    );

    let blocked_identity = Identity::new(&mut OsRng);
    driver.engine.blackhole_identity(
        *blocked_identity.hash(),
        time::now(),
        None,
        Some("test".into()),
    );
    let mut blocked_announce = build_announce_packet(&blocked_identity);
    let last = blocked_announce.len() - 1;
    blocked_announce[last] ^= 0x01;
    driver.handle_frame_event(InterfaceId(1), blocked_announce, None, None);
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.protocol_violations,
        3,
        "blackholed identities are policy drops, not peer protocol violations"
    );
}

#[test]
fn packet_filter_protocol_rejections_are_not_counted_as_duplicate_hits() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "filter-violations");

    let plain_data = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        1,
        &[0x11; 16],
        None,
        constants::CONTEXT_NONE,
        b"transported plain",
    )
    .unwrap();
    driver.handle_frame_event(InterfaceId(1), plain_data.raw, None, None);

    let plain_announce = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        },
        0,
        &[0x22; 16],
        None,
        constants::CONTEXT_NONE,
        b"invalid announce",
    )
    .unwrap();
    driver.handle_frame_event(InterfaceId(1), plain_announce.raw, None, None);

    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.protocol_violations, 2);
    assert_eq!(stats.packet_filter_hits, 0);
}

#[test]
fn an_interface_hop_limiter_applies_before_the_transport_one() {
    // Upstream bb63dd44: an interface's own `hop_limiter` drops what the
    // transport-wide limiter would let through, on that interface only.
    // The dropped frame is filtered traffic: `hop_limiter_hit` returns None.
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "limited");
    register_test_generic_interface(&mut driver, 2, "unlimited");
    driver
        .interfaces
        .get_mut(&InterfaceId(1))
        .unwrap()
        .info
        .hop_limiter = Some(4);
    let mut frame = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &[0x34; 16],
        None,
        constants::CONTEXT_NONE,
        b"how far",
    )
    .unwrap()
    .raw;
    let size = frame.len() as u64;

    frame[1] = 4;
    driver.handle_frame_event(InterfaceId(1), frame.clone(), None, None);
    let limited = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(limited.hop_limiter_hits, 1);
    assert_eq!((limited.rxb, limited.frxb), (0, size));
    assert_eq!(limited.protocol_violations, 0);

    driver.handle_frame_event(InterfaceId(2), frame.clone(), None, None);
    assert_eq!(driver.interfaces[&InterfaceId(2)].stats.hop_limiter_hits, 0);

    // Below the limit; a different payload, so not a duplicate either.
    frame[1] = 3;
    *frame.last_mut().unwrap() ^= 0x01;
    driver.handle_frame_event(InterfaceId(1), frame, None, None);
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.hop_limiter_hits, 1);
}

#[test]
fn hop_limited_frame_counts_a_hop_limiter_hit_not_a_protocol_violation() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "hop-limiter");

    let mut limited = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &[0x33; 16],
        None,
        constants::CONTEXT_NONE,
        b"too far",
    )
    .unwrap()
    .raw;
    // Upstream drops packets whose hop count is not below HOP_LIMITER and
    // counts them on the interface as hop_limiter_hits, separately from
    // protocol violations (Transport.py:2009). The limiter is configurable
    // (`[reticulum] hop_limiter`, d7749b0b).
    driver.hop_limiter = 16;
    limited[1] = 16;
    driver.handle_frame_event(InterfaceId(1), limited.clone(), None, None);
    limited[1] = 100;
    driver.handle_frame_event(InterfaceId(1), limited.clone(), None, None);

    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.hop_limiter_hits, 2);
    assert_eq!(stats.protocol_violations, 0);
    assert_eq!(stats.packet_filter_hits, 0);

    // One hop below the limit passes; whatever the packet filter then
    // decides, it is no longer a hop limiter hit.
    limited[1] = 15;
    driver.handle_frame_event(InterfaceId(1), limited.clone(), None, None);
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.hop_limiter_hits, 2);

    // Hop counts at or above PATHFINDER_M fail `Packet.unpack` before the
    // limiter is consulted, so upstream counts them as malformed packets
    // (Packet.py:250, Transport.py:2008), also with the default limiter.
    driver.hop_limiter = constants::HOP_LIMITER;
    let violations_before = driver.interfaces[&InterfaceId(1)].stats.protocol_violations;
    limited[1] = constants::PATHFINDER_M;
    driver.handle_frame_event(InterfaceId(1), limited.clone(), None, None);
    limited[1] = u8::MAX;
    driver.handle_frame_event(InterfaceId(1), limited.clone(), None, None);
    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.hop_limiter_hits, 2);
    assert_eq!(stats.protocol_violations, violations_before + 2);

    // With the default limiter every decodable hop count passes it.
    limited[1] = constants::PATHFINDER_M - 1;
    driver.handle_frame_event(InterfaceId(1), limited, None, None);
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.hop_limiter_hits, 2);
}

#[test]
fn path_requests_of_invalid_length_are_protocol_violations_and_dropped() {
    // Upstream cda4d72b: only the legacy (32), unstamped (48) and stamped
    // (64) lengths are processed; any other tagged request counts a protocol
    // violation and is dropped before it is recorded or answered.
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "path-request-violations");
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let invalid_lengths = [17, 31, 33, 47, 49, 63, 65];
    for (index, len) in invalid_lengths.into_iter().enumerate() {
        let mut request_data = vec![0x44; 16];
        request_data.resize(len, 0x50 + index as u8);
        let request = RawPacket::pack(
            flags,
            0,
            &driver.path_request_dest,
            None,
            constants::CONTEXT_NONE,
            &request_data,
        )
        .unwrap();
        driver.handle_frame_event(InterfaceId(1), request.raw, None, None);

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.protocol_violations, index as u64 + 1, "length {len}");
        assert_eq!(stats.prxc, 0, "a {len} byte path request was recorded");
    }

    for (index, len) in [
        constants::PATH_REQUEST_LEGACY_LENGTH,
        constants::PATH_REQUEST_LENGTH,
    ]
    .into_iter()
    .enumerate()
    {
        let mut request_data = vec![0x45; 16];
        request_data.resize(len, 0x60 + index as u8);
        let request = RawPacket::pack(
            flags,
            0,
            &driver.path_request_dest,
            None,
            constants::CONTEXT_NONE,
            &request_data,
        )
        .unwrap();
        driver.handle_frame_event(InterfaceId(1), request.raw, None, None);

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(
            stats.protocol_violations,
            invalid_lengths.len() as u64,
            "length {len}"
        );
        assert_eq!(
            stats.prxc,
            index as u64 + 1,
            "a {len} byte path request was dropped"
        );
    }
}

#[test]
fn path_requests_shorter_than_a_destination_hash_are_dropped_silently() {
    // Upstream Transport.inbound returns early, without a protocol violation,
    // when a path request is shorter than a truncated hash. A 16 byte one is
    // a tagless request and still counts.
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "short-path-requests");
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    // An empty payload is a malformed packet, rejected before this check.
    for (len, violations) in [(1, 0), (15, 0), (16, 1)] {
        let request = RawPacket::pack(
            flags,
            0,
            &driver.path_request_dest,
            None,
            constants::CONTEXT_NONE,
            &vec![0x47; len],
        )
        .unwrap();
        driver.handle_frame_event(InterfaceId(1), request.raw, None, None);

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.protocol_violations, violations, "length {len}");
        assert_eq!(stats.prxc, 0, "a {len} byte path request was recorded");
    }
}

#[test]
fn oversized_announce_counts_a_protocol_violation() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "announce-size-violations");

    let packet = RawPacket::pack_with_max_mtu(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        },
        0,
        &[0xA5; 16],
        None,
        constants::CONTEXT_NONE,
        &vec![0x55; constants::MTU],
        constants::MTU * 2,
    )
    .unwrap();
    assert!(packet.raw.len() > constants::MTU);

    driver.handle_frame_event(InterfaceId(1), packet.raw, None, None);

    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.protocol_violations,
        1
    );
}

/// Upstream 50b6733a moved the oversized-announce check ahead of the
/// destination type filters, so an oversized announce of a blocked type is a
/// protocol violation rather than a silent drop. rns-rs checks the frame size
/// in the driver, before the engine's type filter.
#[test]
fn oversized_announce_of_a_blocked_type_counts_a_protocol_violation() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "blocked-announce-size-violations");
    // The announce's name hash: the ten bytes after the public key.
    driver
        .engine
        .destination_filter_mut()
        .block([0x55; constants::NAME_HASH_LENGTH / 8]);

    let packet = RawPacket::pack_with_max_mtu(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        },
        0,
        &[0xA6; 16],
        None,
        constants::CONTEXT_NONE,
        &vec![0x55; constants::MTU],
        constants::MTU * 2,
    )
    .unwrap();
    assert!(packet.raw.len() > constants::MTU);

    driver.handle_frame_event(InterfaceId(1), packet.raw, None, None);

    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.protocol_violations,
        1
    );
}

/// Upstream 715707b1: a HEADER_1 announce that leaves less than a transport
/// id's room under the MTU is a protocol violation; one with exactly that
/// room is not.
#[test]
fn header_1_announce_without_transport_room_counts_a_protocol_violation() {
    let header_1_room = constants::MTU - RawPacket::data_offset(constants::HEADER_1);
    for (len, violations) in [(header_1_room - 15, 1), (header_1_room - 16, 0)] {
        let mut driver = new_test_driver();
        register_test_generic_interface(&mut driver, 1, "announce-room");
        // A blocked type, so an announce that passes admission is dropped
        // by the type filter without a violation of its own.
        driver
            .engine
            .destination_filter_mut()
            .block([0x55; constants::NAME_HASH_LENGTH / 8]);
        let packet = RawPacket::pack_with_max_mtu(
            PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            0,
            &[0xA8; 16],
            None,
            constants::CONTEXT_NONE,
            &vec![0x55; len],
            constants::MTU * 2,
        )
        .unwrap();
        let size = packet.raw.len() as u64;

        driver.handle_frame_event(InterfaceId(1), packet.raw, None, None);

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.protocol_violations, violations, "length {len}");
        assert_eq!(stats.frxb, size, "length {len}");
    }
}

/// Upstream 096e6726: an announce payload shorter than a public key, a name
/// hash and a random hash is a protocol violation, before the destination
/// type filter, so it is one even for a blocked type. One byte more is not.
#[test]
fn announce_with_insufficient_payload_counts_a_protocol_violation() {
    let min = constants::KEYSIZE / 8 + constants::NAME_HASH_LENGTH / 8 + 10;
    for (len, violations) in [(min - 1, 1), (min, 0)] {
        let mut driver = new_test_driver();
        register_test_generic_interface(&mut driver, 1, "short-announce");
        driver
            .engine
            .destination_filter_mut()
            .block([0x55; constants::NAME_HASH_LENGTH / 8]);
        let packet = RawPacket::pack(
            PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            0,
            &[0xA7; 16],
            None,
            constants::CONTEXT_NONE,
            &vec![0x55; len],
        )
        .unwrap();
        let size = packet.raw.len() as u64;

        driver.handle_frame_event(InterfaceId(1), packet.raw, None, None);

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.protocol_violations, violations, "length {len}");
        // Either way the frame is filtered: by the violation, or by the
        // blocked type.
        assert_eq!(stats.frxb, size, "length {len}");
    }
}

/// An interface with ingress control that holds one announce and may hold
/// `max_held`; returns the driver.
fn driver_holding_one_announce(max_held: usize) -> Driver {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "held-announces");
    let mut info = driver
        .engine
        .interface_info(&InterfaceId(1))
        .unwrap()
        .clone();
    info.ingress_control.max_held_announces = max_held;
    driver.engine.register_interface(info);
    // An announce burst: the engine holds announces from now on.
    driver
        .engine
        .update_interface_freqs(InterfaceId(1), 1000.0, 0.0, 0.0, 0);
    let raw = build_announce_packet(&Identity::new(&mut OsRng));
    driver.engine.handle_inbound(
        rns_core::transport::InboundFrame {
            raw: &raw,
            iface: InterfaceId(1),
            now: time::now(),
            rx: rns_core::transport::RxMetadata::default(),
        },
        &mut driver.rng,
    );
    assert_eq!(driver.engine.held_announce_count(&InterfaceId(1)), 1);
    // As the driver does after a frame.
    driver.record_announce_receipts();
    driver
        .interfaces
        .get_mut(&InterfaceId(1))
        .unwrap()
        .stats
        .arxc = 0;
    driver
}

#[test]
fn announce_over_a_full_hold_is_a_filtered_announce() {
    // Upstream 819076c3 replaced f96cef7e's early drop: while ingress
    // control limits, an announce the full hold cannot take is processed up
    // to the hold and counted as a filtered announce.
    let mut driver = driver_holding_one_announce(1);
    let identity = Identity::new(&mut OsRng);
    let dest_hash =
        rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));
    let announce = build_announce_packet(&identity);
    let len = announce.len() as u64;

    driver.handle_frame_event(InterfaceId(1), announce, None, None);

    assert_eq!(driver.engine.held_announce_count(&InterfaceId(1)), 1);
    assert!(!driver.engine.has_path(&dest_hash));
    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.afrxc, 1);
    assert_eq!((stats.rxb, stats.frxb), (0, len));
    // Upstream c850cdac: taken up by ingress control, it counts as a
    // received announce without bytes.
    assert_eq!((stats.arxc, stats.arxb), (1, 0));
    assert_eq!(stats.protocol_violations, 0);
    assert_eq!(stats.packet_filter_hits, 0);
}

#[test]
fn announce_is_held_while_held_announces_have_room() {
    let mut driver = driver_holding_one_announce(2);
    let announce = build_announce_packet(&Identity::new(&mut OsRng));
    let len = announce.len() as u64;

    driver.handle_frame_event(InterfaceId(1), announce, None, None);

    assert_eq!(driver.engine.held_announce_count(&InterfaceId(1)), 2);
    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.ia_timestamps.len(), 1);
    // Upstream 29dc449a: the held frame's bytes are filtered until the
    // release counts them again; it is not a filtered announce.
    assert_eq!((stats.rxb, stats.frxb, stats.afrxc), (0, len, 0));
    assert_eq!(stats.rx_packets, 0);
    // Upstream c850cdac: and a received announce, without bytes.
    assert_eq!((stats.arxc, stats.arxb), (1, 0));
}

#[test]
fn released_announces_are_charged_as_received_traffic() {
    // Upstream 29dc449a: a release goes through `Transport.inbound` with
    // accounting, so its frame counts again in `rxb`.
    let mut driver = driver_holding_one_announce(2);
    let announce = build_announce_packet(&Identity::new(&mut OsRng));
    let len = announce.len() as u64;
    driver.handle_frame_event(InterfaceId(1), announce, None, None);
    let frxb_held = driver.interfaces[&InterfaceId(1)].stats.frxb;

    // The burst ends; ingress control releases one held announce per tick,
    // as `handle_tick_event` does.
    driver
        .engine
        .update_interface_freqs(InterfaceId(1), 0.0, 0.0, 0.0, 0);
    let mut now = time::now() + constants::IC_BURST_PENALTY + 1.0;
    while driver.engine.held_announce_count(&InterfaceId(1)) > 0 {
        let actions = driver.engine.tick(now, &mut driver.rng);
        driver.record_released_traffic();
        driver.record_announce_receipts();
        driver.dispatch_all(actions);
        now += constants::IC_HELD_RELEASE_INTERVAL + 1.0;
    }

    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.frxb, frxb_held);
    assert_eq!(stats.rx_packets, 2);
    assert!(stats.rxb >= len);
    assert_eq!(stats.afrxc, 0);
}

#[test]
fn apply_stamp_config_sets_the_engine_hop_limiter() {
    // The path table is culled against `[filter] hop_limiter` (f96cef7e).
    let mut driver = new_test_driver();
    assert_eq!(driver.engine.hop_limiter(), constants::HOP_LIMITER);
    driver.apply_stamp_config(&crate::config::StampsSection::default(), 7);
    assert_eq!(driver.engine.hop_limiter(), 7);
}

/// A client driver whose interface 1 dials out (`wants_tunnel`); returns
/// the frames it sends.
fn dialing_client_driver() -> (Driver, Arc<Mutex<Vec<Vec<u8>>>>) {
    let mut driver = new_test_driver();
    driver.transport_identity = Some(Identity::new(&mut OsRng));
    let mut info = make_interface_info(1);
    info.name = "TCPInterface[dialer]".into();
    info.wants_tunnel = true;
    driver.engine.register_interface(info.clone());
    let (writer, sent) = MockWriter::new();
    let mut entry = make_entry(1, Box::new(writer), false);
    entry.info = info;
    driver.interfaces.insert(InterfaceId(1), entry);
    (driver, sent)
}

/// Register a server-side interface of `interface_type`, as a spawned
/// TCP server client is.
fn register_typed_interface(driver: &mut Driver, id: u64, name: &str, interface_type: &str) {
    register_test_generic_interface(driver, id, name);
    driver
        .interfaces
        .get_mut(&InterfaceId(id))
        .unwrap()
        .interface_type = interface_type.into();
}

#[test]
fn dialing_interface_synthesizes_a_tunnel_on_each_connect() {
    let (mut client, sent) = dialing_client_driver();
    client.handle_interface_up_event(InterfaceId(1), None, None);
    assert_eq!(sent.lock().unwrap().len(), 1);
    client.handle_interface_down_event(InterfaceId(1));
    client.handle_interface_up_event(InterfaceId(1), None, None);
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    // The same tunnel id each time (same identity and interface), so the
    // server can reattach paths after a reconnect.
    assert_eq!(sent[0][..2 + 16 + 1 + 96], sent[1][..2 + 16 + 1 + 96]);
}

/// Records how many frames the interface had sent when the application
/// heard that it came up.
struct SentAtInterfaceUp {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    seen: Arc<Mutex<Vec<usize>>>,
}

impl Callbacks for SentAtInterfaceUp {
    fn on_announce(&mut self, _announced: crate::destination::AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}
    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _hash: PacketHash) {}
    fn on_interface_up(&mut self, _id: InterfaceId) {
        let count = self.sent.lock().unwrap().len();
        self.seen.lock().unwrap().push(count);
    }
}

#[test]
fn tunnel_synthesis_is_sent_before_the_interface_is_announced_up() {
    // Upstream f361a354 and ad6c709e send the synthesis while connecting,
    // so it is the first frame on the connection. rns-rs sends it before the
    // callback and the `InterfaceUp` hook can use the interface.
    let (mut client, sent) = dialing_client_driver();
    let seen = Arc::new(Mutex::new(Vec::new()));
    client.callbacks = Box::new(SentAtInterfaceUp {
        sent: sent.clone(),
        seen: seen.clone(),
    });
    client.handle_interface_up_event(InterfaceId(1), None, None);
    client.handle_interface_down_event(InterfaceId(1));
    client.handle_interface_up_event(InterfaceId(1), None, None);
    assert_eq!(*seen.lock().unwrap(), vec![1, 2]);
}

#[test]
fn synthesized_tunnel_attaches_to_the_receiving_interface() {
    // `Transport.tunnel_synthesize_handler` hands the tunnel to the
    // interface the synthesis arrived on.
    let (mut client, sent) = dialing_client_driver();
    client.handle_interface_up_event(InterfaceId(1), None, None);
    let synthesis = sent.lock().unwrap()[0].clone();

    let mut server = new_test_driver();
    register_typed_interface(&mut server, 4, "other-client", "TCPServerClientInterface");
    register_typed_interface(&mut server, 5, "spawned-client", "TCPServerClientInterface");
    server.handle_frame_event(InterfaceId(5), synthesis, None, None);

    let tunnel_id = server
        .engine
        .interface_info(&InterfaceId(5))
        .and_then(|info| info.tunnel_id)
        .expect("tunnel on the receiving interface");
    assert_eq!(
        server
            .engine
            .tunnel_table()
            .get(&tunnel_id)
            .unwrap()
            .interface,
        Some(InterfaceId(5))
    );
    assert_eq!(
        server
            .engine
            .interface_info(&InterfaceId(4))
            .and_then(|info| info.tunnel_id),
        None
    );
    assert_eq!(
        server.interfaces[&InterfaceId(5)].stats.protocol_violations,
        0
    );
}

/// A writer recording whether the driver closed its connection.
struct ShutdownRecorder(Arc<std::sync::atomic::AtomicBool>);

impl Writer for ShutdownRecorder {
    fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
        Ok(())
    }

    fn shutdown(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn enable_interface_management(driver: &mut Driver) {
    driver.interface_management = Some(crate::node::InterfaceManagementConfig {
        config_file: std::path::PathBuf::from("/nonexistent/config"),
        storage_dir: std::path::PathBuf::from("/nonexistent/storage"),
        initial_ids: HashMap::new(),
        queue_capacity: 16,
        transport_enabled: true,
        underlay_mark: None,
    });
}

#[test]
fn tunnel_synthesis_with_a_bad_signature_tears_the_interface_down() {
    // Upstream 3281e283, effective since 56b23c48 fixed its typo.
    let (mut synthesis, _) = client_synthesis();
    let last = synthesis.len() - 1;
    synthesis[last] ^= 0x01;

    let mut server = new_test_driver();
    register_typed_interface(&mut server, 5, "spawned-client", "TCPServerClientInterface");
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let entry = server.interfaces.get_mut(&InterfaceId(5)).unwrap();
        entry.dynamic = true;
        entry.writer = Box::new(ShutdownRecorder(Arc::clone(&closed)));
    }
    server.handle_frame_event(InterfaceId(5), synthesis, None, None);

    assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!server.interfaces.contains_key(&InterfaceId(5)));
    assert_eq!(server.engine.tunnel_table().iter().count(), 0);
}

#[test]
fn a_bad_synthesis_detaches_a_static_interface_without_interface_management() {
    // Upstream detaches the interface with internal_forced, whether or not
    // interface management is enabled: a node started without a config
    // file detaches its static TCP client too, and stops its I/O.
    let (mut synthesis, _) = client_synthesis();
    let last = synthesis.len() - 1;
    synthesis[last] ^= 0x01;

    let mut node = new_test_driver();
    assert!(node.interface_management.is_none());
    register_typed_interface(&mut node, 5, "static-client", "TCPClientInterface");
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    node.interfaces.get_mut(&InterfaceId(5)).unwrap().writer =
        Box::new(ShutdownRecorder(Arc::clone(&closed)));
    let control = crate::interface::ListenerControl::new();
    node.unmanaged_static_interfaces
        .insert(InterfaceId(5), Some(control.clone()));
    node.handle_frame_event(InterfaceId(5), synthesis, None, None);

    assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(control.should_stop());
    assert!(!node.interfaces.contains_key(&InterfaceId(5)));
    assert!(node.engine.interface_info(&InterfaceId(5)).is_none());

    // A static interface the driver knows no control for stays.
    register_typed_interface(&mut node, 6, "other", "TCPClientInterface");
    assert_eq!(node.teardown_interface(InterfaceId(6)), Some(false));
    assert!(node.interfaces.contains_key(&InterfaceId(6)));
}

/// A client synthesis cut to one byte less than the fixed fields.
fn short_synthesis() -> Vec<u8> {
    let (mut synthesis, _) = client_synthesis();
    synthesis.truncate(
        RawPacket::data_offset(constants::HEADER_1)
            + rns_core::transport::tunnel::TUNNEL_SYNTH_LENGTH
            - 1,
    );
    synthesis
}

/// A server whose dynamic TCP client interface 5 has received `frames`.
fn server_after_synthesis_frames(frames: Vec<Vec<u8>>) -> Driver {
    let mut server = new_test_driver();
    register_typed_interface(&mut server, 5, "spawned-client", "TCPServerClientInterface");
    server.interfaces.get_mut(&InterfaceId(5)).unwrap().dynamic = true;
    for frame in frames {
        server.handle_frame_event(InterfaceId(5), frame, None, None);
    }
    server
}

#[test]
fn tunnel_synthesis_of_the_wrong_length_is_a_protocol_violation() {
    // Upstream 13b98a6b: shorter than the fixed fields or longer than the
    // MDU is a protocol violation, and no tunnel.
    let short = short_synthesis();
    let (mut long, _) = client_synthesis();
    let data_len = long.len() - RawPacket::data_offset(constants::HEADER_1);
    long.extend(std::iter::repeat_n(0x77, constants::MDU + 1 - data_len));
    for frame in [short, long] {
        let server = server_after_synthesis_frames(vec![frame]);
        assert!(server.interfaces.contains_key(&InterfaceId(5)));
        assert_eq!(server.engine.tunnel_table().iter().count(), 0);
        assert_eq!(
            server.interfaces[&InterfaceId(5)].stats.protocol_violations,
            1
        );
    }
}

#[test]
fn interface_stats_report_the_tunnel_this_node_synthesized() {
    // Upstream 3281e283: `tunnel_id or local_tunnel_id`.
    let (mut client, _) = dialing_client_driver();
    client.handle_interface_up_event(InterfaceId(1), None, None);
    let local = client
        .engine
        .local_tunnel_id(&InterfaceId(1))
        .expect("a synthesized tunnel");
    let QueryResponse::InterfaceStats(stats) = client.handle_query(QueryRequest::InterfaceStats)
    else {
        panic!("expected interface stats");
    };
    assert_eq!(stats.interfaces[0].tunnel_id, Some(local));
    assert_eq!(
        client.engine.interface_for_tunnel_id(&local),
        Some(InterfaceId(1))
    );
}

#[test]
fn spawned_interface_is_detached_by_its_tunnel_id() {
    let (mut client, sent) = dialing_client_driver();
    client.handle_interface_up_event(InterfaceId(1), None, None);
    let synthesis = sent.lock().unwrap()[0].clone();

    let mut server = new_test_driver();
    enable_interface_management(&mut server);
    register_typed_interface(&mut server, 5, "spawned-client", "TCPServerClientInterface");
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let entry = server.interfaces.get_mut(&InterfaceId(5)).unwrap();
        entry.dynamic = true;
        entry.writer = Box::new(ShutdownRecorder(Arc::clone(&closed)));
    }
    server.handle_frame_event(InterfaceId(5), synthesis, None, None);
    let tunnel_id = server
        .engine
        .interface_info(&InterfaceId(5))
        .and_then(|info| info.tunnel_id)
        .unwrap();
    let hex: String = tunnel_id.iter().map(|b| format!("{b:02x}")).collect();

    assert_eq!(
        server.manage_interface(crate::event::InterfaceManagementOperation::Detach, &hex),
        Some(true)
    );
    assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!server.interfaces.contains_key(&InterfaceId(5)));
    // Upstream returns None for anything naming no interface.
    for name in [hex.as_str(), "not-hex", "abcd"] {
        assert_eq!(
            server.manage_interface(crate::event::InterfaceManagementOperation::Detach, name),
            None
        );
    }
}

#[test]
fn a_static_unmanaged_interface_is_not_torn_down() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 3, "static");
    assert_eq!(driver.teardown_interface(InterfaceId(3)), Some(false));
    assert!(driver.interfaces.contains_key(&InterfaceId(3)));
}

/// A synthesis from a fresh dialing client.
fn client_synthesis() -> (Vec<u8>, [u8; 16]) {
    let (mut client, sent) = dialing_client_driver();
    let identity_hash = *client.transport_identity.as_ref().unwrap().hash();
    client.handle_interface_up_event(InterfaceId(1), None, None);
    let synthesis = sent.lock().unwrap()[0].clone();
    (synthesis, identity_hash)
}

/// A dialing TCP client that has connected once: the driver, the frames it
/// sent (its synthesis first) and its transport identity hash.
fn connected_client() -> (Driver, SentFrames, [u8; 16]) {
    let (mut client, sent) = dialing_client_driver();
    client
        .interfaces
        .get_mut(&InterfaceId(1))
        .unwrap()
        .interface_type = "TCPClientInterface".into();
    let identity_hash = *client.transport_identity.as_ref().unwrap().hash();
    client.handle_interface_up_event(InterfaceId(1), None, None);
    (client, sent, identity_hash)
}

/// A server with a transport identity whose spawned TCP client interface 5
/// records the frames it sends; returns them and the identity hash.
fn tunnel_server() -> (Driver, SentFrames, [u8; 16]) {
    let mut server = new_test_driver();
    let identity = Identity::new(&mut OsRng);
    let identity_hash = *identity.hash();
    server.transport_identity = Some(identity);
    register_typed_interface(&mut server, 5, "spawned-client", "TCPServerClientInterface");
    let (writer, sent) = MockWriter::new();
    server.interfaces.get_mut(&InterfaceId(5)).unwrap().writer = Box::new(writer);
    (server, sent, identity_hash)
}

/// A synthesis signed by `client`'s transport identity on its interface 1
/// with `extension` after the signature.
fn synthesis_with_extension(client: &mut Driver, sent: &SentFrames, extension: &[u8]) -> Vec<u8> {
    let identity = client.transport_identity.take().unwrap();
    let actions =
        client
            .engine
            .synthesize_tunnel(&identity, InterfaceId(1), extension, false, &mut OsRng);
    client.transport_identity = Some(identity);
    client.dispatch_all(actions);
    sent.lock().unwrap().last().unwrap().clone()
}

#[test]
fn tunnel_synthesis_is_answered_and_both_ends_learn_the_other() {
    // Upstream b7a93b9b: the synthesis carries a signed extension; the
    // server records it and answers with a reverse synthesis, which the
    // client records without answering again or attaching a tunnel.
    let (mut client, client_sent, client_transport) = connected_client();
    let synthesis = client_sent.lock().unwrap()[0].clone();
    let (mut server, server_sent, server_transport) = tunnel_server();

    server.handle_frame_event(InterfaceId(5), synthesis, None, None);
    let reported = server
        .engine
        .remote_transport_info(&InterfaceId(5))
        .cloned()
        .expect("the client's extension");
    assert_eq!(reported.implementation, "rns-rs");
    assert!(!reported.version.is_empty());
    assert_eq!(
        server.engine.remote_transport(&InterfaceId(5)),
        Some(client_transport)
    );
    assert_eq!(server.engine.tunnel_table().iter().count(), 1);
    // The reverse synthesis records no local tunnel on the server.
    assert_eq!(server.engine.local_tunnel_id(&InterfaceId(5)), None);
    let reverse = {
        let sent = server_sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        sent[0].clone()
    };

    client.handle_frame_event(InterfaceId(1), reverse, None, None);
    assert_eq!(
        client.engine.remote_transport(&InterfaceId(1)),
        Some(server_transport)
    );
    assert_eq!(
        client
            .engine
            .remote_transport_info(&InterfaceId(1))
            .map(|info| info.implementation.as_str()),
        Some("rns-rs")
    );
    assert_eq!(client_sent.lock().unwrap().len(), 1);
    assert_eq!(client.engine.tunnel_table().iter().count(), 0);
    assert!(client.engine.local_tunnel_id(&InterfaceId(1)).is_some());
    assert_eq!(
        client.interfaces[&InterfaceId(1)].stats.protocol_violations,
        0
    );

    // Each end reports what the other said about itself.
    let QueryResponse::InterfaceStats(stats) = server.handle_query(QueryRequest::InterfaceStats)
    else {
        panic!("expected interface stats");
    };
    let entry = stats.interfaces.iter().find(|e| e.id == 5).unwrap();
    assert_eq!(entry.remote_transport_info.as_ref(), Some(&reported));

    // A reconnect starts over: no remote transport until the next answer.
    // What the server reported stays until its next synthesis replaces it,
    // as upstream keeps the interface's remote_impl, remote_vers and costs.
    let before = client
        .engine
        .remote_transport_info(&InterfaceId(1))
        .cloned();
    assert!(before.is_some());
    client.handle_interface_down_event(InterfaceId(1));
    client.handle_interface_up_event(InterfaceId(1), None, None);
    assert_eq!(client.engine.remote_transport(&InterfaceId(1)), None);
    assert_eq!(
        client
            .engine
            .remote_transport_info(&InterfaceId(1))
            .cloned(),
        before
    );
    assert_eq!(client_sent.lock().unwrap().len(), 2);
}

#[test]
fn a_synthesis_without_an_extension_is_not_answered() {
    // A 1.6.0 synthesis: the tunnel is attached, nothing is reported and no
    // reverse synthesis is sent.
    let (mut client, client_sent, client_transport) = connected_client();
    let synthesis = synthesis_with_extension(&mut client, &client_sent, &[]);
    assert_eq!(
        synthesis.len(),
        RawPacket::data_offset(constants::HEADER_1)
            + rns_core::transport::tunnel::TUNNEL_SYNTH_LENGTH
    );
    let (mut server, server_sent, _) = tunnel_server();
    server.handle_frame_event(InterfaceId(5), synthesis, None, None);
    assert_eq!(
        server.engine.remote_transport(&InterfaceId(5)),
        Some(client_transport)
    );
    assert!(server
        .engine
        .remote_transport_info(&InterfaceId(5))
        .is_none());
    assert_eq!(server.engine.tunnel_table().iter().count(), 1);
    assert!(server_sent.lock().unwrap().is_empty());
}

#[test]
fn an_invalid_synthesis_extension_is_a_protocol_violation() {
    // Upstream b7a93b9b: an extension that does not decode, or lacks a
    // field, is a protocol violation, with no tunnel and no answer.
    let (mut client, client_sent, _) = connected_client();
    let synthesis = synthesis_with_extension(&mut client, &client_sent, b"\xc1");
    let (mut server, server_sent, _) = tunnel_server();
    server.handle_frame_event(InterfaceId(5), synthesis, None, None);
    assert_eq!(
        server.interfaces[&InterfaceId(5)].stats.protocol_violations,
        1
    );
    assert_eq!(server.engine.remote_transport(&InterfaceId(5)), None);
    assert_eq!(server.engine.tunnel_table().iter().count(), 0);
    assert!(server_sent.lock().unwrap().is_empty());
}

#[test]
fn synthesis_records_and_reports_the_remote_transport() {
    // Upstream 464e7598 `remote_transport_id`.
    let (synthesis, client_transport) = client_synthesis();
    let mut server = new_test_driver();
    register_typed_interface(&mut server, 5, "spawned-client", "BackboneInterfacePeer");
    server.handle_frame_event(InterfaceId(5), synthesis, None, None);
    assert_eq!(
        server.engine.remote_transport(&InterfaceId(5)),
        Some(client_transport)
    );
    let QueryResponse::InterfaceStats(stats) = server.handle_query(QueryRequest::InterfaceStats)
    else {
        panic!("expected interface stats");
    };
    let entry = stats.interfaces.iter().find(|e| e.id == 5).unwrap();
    assert_eq!(entry.remote_transport_id, Some(client_transport));
}

#[test]
fn an_interface_takes_only_one_tunnel_synthesis() {
    // Upstream 13b98a6b: a synthesis on an established tunnel is a protocol
    // violation, and so is a second one after one that failed.
    let (first, first_transport) = client_synthesis();
    let (second, _) = client_synthesis();
    let server = server_after_synthesis_frames(vec![first, second]);
    let tunnel = server
        .engine
        .interface_info(&InterfaceId(5))
        .and_then(|info| info.tunnel_id);
    assert!(tunnel.is_some());
    assert_eq!(server.engine.tunnel_table().iter().count(), 1);
    assert_eq!(
        server.engine.remote_transport(&InterfaceId(5)),
        Some(first_transport)
    );
    assert_eq!(
        server.interfaces[&InterfaceId(5)].stats.protocol_violations,
        1
    );

    let (valid, _) = client_synthesis();
    let server = server_after_synthesis_frames(vec![short_synthesis(), valid]);
    assert_eq!(server.engine.tunnel_table().iter().count(), 0);
    assert_eq!(
        server.interfaces[&InterfaceId(5)].stats.protocol_violations,
        2
    );
}

#[test]
fn tunnels_are_not_synthesized_over_other_interface_types() {
    // Upstream 464e7598: `tunnels_allowed` only on TCP, Backbone and I2P.
    for interface_type in ["UDPInterface", "AutoInterfacePeer", "LocalClientInterface"] {
        let (synthesis, _) = client_synthesis();
        let mut server = new_test_driver();
        register_typed_interface(&mut server, 5, "other", interface_type);
        server.handle_frame_event(InterfaceId(5), synthesis, None, None);
        assert_eq!(
            server.engine.tunnel_table().iter().count(),
            0,
            "{interface_type}"
        );
        assert_eq!(server.engine.remote_transport(&InterfaceId(5)), None);
    }
}

/// A server whose dynamic interface 5 records whether it was closed.
fn server_with_closable_spawned_client() -> (Driver, Arc<std::sync::atomic::AtomicBool>) {
    let mut server = new_test_driver();
    register_typed_interface(&mut server, 5, "spawned-client", "TCPServerClientInterface");
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let entry = server.interfaces.get_mut(&InterfaceId(5)).unwrap();
    entry.dynamic = true;
    entry.writer = Box::new(ShutdownRecorder(Arc::clone(&closed)));
    (server, closed)
}

#[test]
fn synthesis_from_a_blackholed_transport_node_tears_the_interface_down() {
    // Upstream 350b7e26.
    let (synthesis, client_transport) = client_synthesis();
    let (mut server, closed) = server_with_closable_spawned_client();
    server.blackhole_identity_local(client_transport, None, None);

    server.handle_frame_event(InterfaceId(5), synthesis, None, None);

    assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!server.interfaces.contains_key(&InterfaceId(5)));
    assert_eq!(server.engine.tunnel_table().iter().count(), 0);
}

#[test]
fn blackholing_a_transport_node_tears_down_its_connections() {
    // Upstream 350b7e26 `remove_blackholed_paths`: interfaces whose remote
    // transport becomes blackholed are detached.
    let (synthesis, client_transport) = client_synthesis();
    let (mut server, closed) = server_with_closable_spawned_client();
    register_typed_interface(&mut server, 6, "other-client", "TCPServerClientInterface");
    server.interfaces.get_mut(&InterfaceId(6)).unwrap().dynamic = true;
    let (other, _) = client_synthesis();
    server.handle_frame_event(InterfaceId(5), synthesis, None, None);
    server.handle_frame_event(InterfaceId(6), other, None, None);
    assert!(!closed.load(std::sync::atomic::Ordering::SeqCst));

    server.blackhole_identity_local(client_transport, None, None);

    assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!server.interfaces.contains_key(&InterfaceId(5)));
    assert!(server.interfaces.contains_key(&InterfaceId(6)));
}

#[test]
fn interface_stats_report_the_tunnel_id() {
    // Upstream 9b6b724b reports `tunnel_id` per interface: none until a
    // tunnel is established on it.
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "tunnelled");
    let tunnel_id_of = |driver: &mut Driver| {
        let QueryResponse::InterfaceStats(stats) =
            driver.handle_query(QueryRequest::InterfaceStats)
        else {
            panic!("expected interface stats");
        };
        stats
            .interfaces
            .iter()
            .find(|entry| entry.name == "tunnelled")
            .expect("interface stats")
            .tunnel_id
    };
    assert_eq!(tunnel_id_of(&mut driver), None);

    driver
        .engine
        .handle_tunnel([0x7C; 32], InterfaceId(1), time::now());
    assert_eq!(tunnel_id_of(&mut driver), Some([0x7C; 32]));
}

/// (rxb, frxb, rx_packets) of an interface.
fn rx_and_filtered(driver: &Driver, id: u64) -> (u64, u64, u64) {
    let stats = &driver.interfaces[&InterfaceId(id)].stats;
    (stats.rxb, stats.frxb, stats.rx_packets)
}

#[test]
fn filtered_inbound_moves_the_frame_from_received_to_filtered() {
    // Upstream 134dc677 `filtered_inbound`: a frame dropped before transport
    // processes it leaves `rxb` (and the received packet count) for `frxb`;
    // one that passes stays received.
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "filtered");
    let mut flagged = build_announce_packet(&Identity::new(&mut OsRng));
    flagged[0] |= 0x80;
    let flagged_len = flagged.len() as u64;
    driver.handle_frame_event(InterfaceId(1), flagged, None, None);
    assert_eq!(rx_and_filtered(&driver, 1), (0, flagged_len, 0));

    let announce = build_announce_packet(&Identity::new(&mut OsRng));
    let announce_len = announce.len() as u64;
    driver.handle_frame_event(InterfaceId(1), announce, None, None);
    assert_eq!(rx_and_filtered(&driver, 1), (announce_len, flagged_len, 1));
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.ftxb, 0);
}

#[test]
fn every_received_frame_is_charged_once_to_received_or_filtered() {
    // Upstream 01e7ed84 moves byte accounting into `Transport.inbound`:
    // accepted frames count in `rxb`, filtered ones in `frxb`, none in both.
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "partition");
    let mut total = 0u64;
    let mut filtered = 0u64;
    for round in 0..3 {
        // Usually accepted; ingress control may hold a later one back.
        let announce = build_announce_packet(&Identity::new(&mut OsRng));
        total += announce.len() as u64;
        driver.handle_frame_event(InterfaceId(1), announce, None, None);

        // IFAC flag set on an interface without IFAC.
        let mut flagged = build_announce_packet(&Identity::new(&mut OsRng));
        flagged[0] |= 0x80;
        filtered += flagged.len() as u64;
        driver.handle_frame_event(InterfaceId(1), flagged, None, None);

        // Undecodable.
        let short = vec![0x00; 2 + round];
        filtered += short.len() as u64;
        driver.handle_frame_event(InterfaceId(1), short, None, None);
    }
    total += filtered;
    let (rxb, frxb, rx_packets) = rx_and_filtered(&driver, 1);
    assert_eq!(rxb + frxb, total);
    assert!(frxb >= filtered);
    assert!(rxb > 0 && rx_packets > 0);
}

#[test]
fn announce_of_a_blocked_type_is_filtered_inbound() {
    // Dropped by the engine's destination type filter.
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "blocked-type");
    driver
        .engine
        .destination_filter_mut()
        .block(rns_core::destination::name_hash("test", &["app"]));
    let announce = build_announce_packet(&Identity::new(&mut OsRng));
    let len = announce.len() as u64;
    driver.handle_frame_event(InterfaceId(1), announce, None, None);
    assert_eq!(rx_and_filtered(&driver, 1), (0, len, 0));
    // Upstream 819076c3 does not count a blocked type as a filtered announce.
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.afrxc, 0);
}

#[test]
fn announce_of_a_type_not_required_is_a_filtered_announce() {
    // With `required_destinations_only`, upstream 819076c3 counts it.
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "required-only");
    driver
        .engine
        .destination_filter_mut()
        .set_required_only(true);
    let announce = build_announce_packet(&Identity::new(&mut OsRng));
    let len = announce.len() as u64;
    driver.handle_frame_event(InterfaceId(1), announce, None, None);
    assert_eq!(rx_and_filtered(&driver, 1), (0, len, 0));
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.afrxc, 1);
}

#[test]
fn held_announces_full_drop_is_filtered_inbound() {
    let mut driver = driver_holding_one_announce(1);
    let announce = build_announce_packet(&Identity::new(&mut OsRng));
    let len = announce.len() as u64;
    driver.handle_frame_event(InterfaceId(1), announce, None, None);
    assert_eq!(rx_and_filtered(&driver, 1), (0, len, 0));
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.afrxc, 1);
}

#[test]
fn duplicate_and_in_flight_path_requests_are_filtered_inbound() {
    let (tx, rx) = event::channel();
    let (callbacks, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));
    register_test_generic_interface(&mut driver, 1, "requests");
    let request = |driver: &Driver, transport_id: u8, tag: u8| {
        let mut data = vec![0xDB; 16];
        data.extend_from_slice(&[transport_id; 16]);
        data.extend_from_slice(&[tag; 16]);
        RawPacket::pack(
            PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_PLAIN,
                packet_type: constants::PACKET_TYPE_DATA,
            },
            0,
            &driver.path_request_dest,
            None,
            constants::CONTEXT_NONE,
            &data,
        )
        .unwrap()
        .raw
    };

    let first = request(&driver, 0x71, 0x01);
    let len = first.len() as u64;
    driver.handle_frame_event(InterfaceId(1), first, None, None);
    assert_eq!(rx_and_filtered(&driver, 1), (len, 0, 1));

    // The same tag from another transport instance: a duplicate.
    driver.handle_frame_event(InterfaceId(1), request(&driver, 0x72, 0x01), None, None);
    assert_eq!(rx_and_filtered(&driver, 1), (len, len, 1));

    // A new tag for the unknown destination already requested: in flight,
    // batched into it and received since upstream c850cdac.
    driver.handle_frame_event(InterfaceId(1), request(&driver, 0x73, 0x02), None, None);
    assert_eq!(rx_and_filtered(&driver, 1), (2 * len, len, 2));
}

#[test]
fn announce_failing_its_queued_signature_check_is_filtered_inbound() {
    let mut driver = new_test_driver();
    driver.async_announce_verification = true;
    register_test_generic_interface(&mut driver, 1, "queued-check");
    let mut tampered = build_announce_packet(&Identity::new(&mut OsRng));
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let len = tampered.len() as u64;
    driver.handle_frame_event(InterfaceId(1), tampered, None, None);
    // Queued for checking: still received.
    assert_eq!(rx_and_filtered(&driver, 1), (len, 0, 1));

    let pending = driver
        .announce_verify_queue
        .lock()
        .unwrap()
        .take_pending(time::now());
    assert_eq!(pending.len(), 1);
    driver.handle_announce_verify_failed(pending[0].0);
    assert_eq!(rx_and_filtered(&driver, 1), (0, len, 0));
}

#[test]
fn filtered_inbound_rate_is_sampled() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "filtered-rate");
    driver.sample_interface_traffic(100.0);
    driver
        .interfaces
        .get_mut(&InterfaceId(1))
        .unwrap()
        .stats
        .frxb = 250;
    driver.sample_interface_traffic(102.0);
    let rates = driver.interfaces[&InterfaceId(1)].stats.traffic_rates;
    assert_eq!((rates.frxs, rates.ftxs), (1000.0, 0.0));
}

#[test]
fn ifac_flag_without_ifac_counts_an_ifac_violation() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "ifac-violations");

    let mut flagged = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &[0x33; 16],
        None,
        constants::CONTEXT_NONE,
        b"ifac flag",
    )
    .unwrap()
    .raw;
    flagged[0] |= 0x80;
    driver.handle_frame_event(InterfaceId(1), flagged, None, None);

    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.ifac_violations, 1);
    assert_eq!(stats.protocol_violations, 0);
}

#[test]
fn send_updates_tx_stats() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    driver.dispatch_all(vec![TransportAction::SendOnInterface {
        interface: InterfaceId(1),
        raw: vec![0x01, 0x02, 0x03].into(),
    }]);
    driver.wake_writers();

    let stats = &driver.interfaces[&InterfaceId(1)].stats;
    assert_eq!(stats.txb, 3);
    assert_eq!(stats.atxb, 3);
    assert_eq!(stats.tx_packets, 1);

    drop(tx);
}

#[test]
fn broadcast_updates_tx_stats() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let (w1, _s1) = MockWriter::new();
    let (w2, _s2) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

    driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
        raw: vec![0xAA, 0xBB].into(),
        exclude: None,
    }]);

    // Both interfaces should have tx stats updated
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.txb, 2);
    assert_eq!(driver.interfaces[&InterfaceId(1)].stats.tx_packets, 1);
    assert_eq!(driver.interfaces[&InterfaceId(2)].stats.txb, 2);
    assert_eq!(driver.interfaces[&InterfaceId(2)].stats.tx_packets, 1);

    drop(tx);
}

#[test]
fn query_interface_stats() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some([0x42; 16]),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let (writer, _sent) = MockWriter::new();
    let mut entry = make_entry(1, Box::new(writer), true);
    entry.stats.started = time::now() - 10.0;
    entry.stats.rxb = 1_000;
    entry.stats.txb = 2_000;
    entry.stats.arxb = 100;
    entry.stats.atxb = 200;
    entry.stats.prxb = 300;
    entry.stats.ptxb = 400;
    entry.stats.traffic_rates = crate::interface::TrafficRates {
        rxs: 800.0,
        txs: 1_600.0,
        rxpps: 8.0,
        txpps: 16.0,
        arxs: 80.0,
        atxs: 160.0,
        prxs: 240.0,
        ptxs: 320.0,
        frxs: 40.0,
        ftxs: 0.0,
    };
    entry.stats.frxb = 70;
    entry.stats.ia_timestamps = vec![1.0, 2.0, 3.0];
    entry.stats.oa_timestamps = vec![1.0, 3.0];
    entry.stats.ip_timestamps = vec![1.0, 3.0, 5.0];
    entry.stats.op_timestamps = vec![1.0, 5.0];
    driver.interfaces.insert(InterfaceId(1), entry);

    let (local_writer, _) = MockWriter::new();
    let mut local = make_entry(2, Box::new(local_writer), true);
    local.info.is_local_client = true;
    local.stats.rxb = 10_000;
    local.stats.txb = 20_000;
    local.stats.traffic_rates.rxs = 8_000.0;
    local.stats.traffic_rates.txs = 16_000.0;
    local.stats.traffic_rates.rxpps = 80.0;
    local.stats.traffic_rates.txpps = 160.0;
    driver.interfaces.insert(InterfaceId(2), local);

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::InterfaceStats, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let resp = resp_rx.recv().unwrap();
    match resp {
        QueryResponse::InterfaceStats(stats) => {
            assert_eq!(stats.interfaces.len(), 2);
            assert!(stats.interfaces.iter().all(|interface| interface.status));
            assert_eq!(stats.transport_id, Some([0x42; 16]));
            assert!(stats.transport_enabled);
            assert_eq!((stats.traffic.arxb, stats.traffic.atxb), (100, 200));
            assert_eq!((stats.traffic.prxb, stats.traffic.ptxb), (300, 400));
            assert_eq!((stats.traffic.rxs, stats.traffic.txs), (800.0, 1_600.0));
            assert_eq!((stats.traffic.frxb, stats.traffic.frxs), (70, 40.0));
            assert_eq!((stats.rx_pps, stats.tx_pps), (8.0, 16.0));
            assert_eq!((stats.total_rxb, stats.total_txb), (1_000, 2_000));
            assert_eq!((stats.traffic.arxs, stats.traffic.atxs), (80.0, 160.0));
            assert_eq!((stats.traffic.prxs, stats.traffic.ptxs), (240.0, 320.0));
            assert_eq!((stats.traffic.arxf, stats.traffic.atxf), (1.5, 1.0));
            assert_eq!((stats.traffic.prxf, stats.traffic.ptxf), (0.75, 0.5));
        }
        _ => panic!("unexpected response"),
    }
}

#[test]
fn traffic_sampler_reports_current_window_and_resets_idle_rates() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "sampler");
    {
        let stats = &mut driver.interfaces.get_mut(&InterfaceId(1)).unwrap().stats;
        stats.rxb = 100;
        stats.txb = 200;
        stats.arxb = 10;
        stats.atxb = 20;
        stats.prxb = 30;
        stats.ptxb = 40;
        stats.rx_packets = 5;
        stats.tx_packets = 10;
    }

    driver.sample_interface_traffic(1_000.0);
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.traffic_rates.rxs,
        0.0
    );

    {
        let stats = &mut driver.interfaces.get_mut(&InterfaceId(1)).unwrap().stats;
        stats.rxb += 100;
        stats.txb += 200;
        stats.arxb += 10;
        stats.atxb += 20;
        stats.prxb += 30;
        stats.ptxb += 40;
        stats.rx_packets += 6;
        stats.tx_packets += 8;
    }
    driver.sample_interface_traffic(1_002.0);

    let rates = driver.interfaces[&InterfaceId(1)].stats.traffic_rates;
    assert_eq!((rates.rxs, rates.txs), (400.0, 800.0));
    assert_eq!((rates.rxpps, rates.txpps), (3.0, 4.0));
    assert_eq!((rates.arxs, rates.atxs), (40.0, 80.0));
    assert_eq!((rates.prxs, rates.ptxs), (120.0, 160.0));

    driver.sample_interface_traffic(1_003.0);
    let idle = driver.interfaces[&InterfaceId(1)].stats.traffic_rates;
    assert_eq!(
        (idle.rxs, idle.txs, idle.rxpps, idle.txpps, idle.arxs, idle.atxs, idle.prxs, idle.ptxs),
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    );
}

#[test]
fn query_path_table() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Feed an announce to create a path entry
    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::PathTable { max_hops: None },
        resp_tx,
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let resp = resp_rx.recv().unwrap();
    let dest_hash = match resp {
        QueryResponse::PathTable(entries) => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].hops, 1);
            // The announce is unstamped and carries no link request cost.
            assert_eq!(
                entries[0].stamp_value,
                Some(rns_core::stamp::StampValue::ZERO)
            );
            assert_eq!(entries[0].lr_cost, None);
            entries[0].hash
        }
        _ => panic!("unexpected response"),
    };

    // Upstream 21170877: entries carry the known destination's stamp value
    // and link request cost, and neither once it is no longer known.
    let known = driver.known_destinations.get_mut(&dest_hash).unwrap();
    known.stamp_value = rns_core::stamp::StampValue::from_fp(25 * 256 + 64);
    known.lr_cost = Some(rns_core::stamp::StampCost::from_fp(4915));
    let QueryResponse::PathTable(entries) = driver.handle_path_table_query(None) else {
        panic!("unexpected response");
    };
    assert_eq!(entries[0].stamp_value.map(|v| v.as_f64()), Some(25.25));
    assert_eq!(entries[0].lr_cost.map(|c| c.fp()), Some(4915));

    driver.known_destinations.remove(&dest_hash);
    let QueryResponse::PathTable(entries) = driver.handle_path_table_query(None) else {
        panic!("unexpected response");
    };
    assert_eq!(entries[0].stamp_value, None);
    assert_eq!(entries[0].lr_cost, None);
}

#[test]
fn query_drop_path() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Feed an announce to create a path entry
    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);
    let dest_hash =
        rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::DropPath { dest_hash }, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let resp = resp_rx.recv().unwrap();
    match resp {
        QueryResponse::DropPath(dropped) => {
            assert!(dropped);
        }
        _ => panic!("unexpected response"),
    }
}

#[test]
fn send_outbound_event() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let (writer, sent) = MockWriter::new();
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Build a DATA packet to a destination
    let dest = [0xAA; 16];
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

    tx.send(Event::SendOutbound {
        raw: packet.raw,
        dest_type: constants::DESTINATION_PLAIN,
        attached_interface: None,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // PLAIN packet should be broadcast on all interfaces
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[test]
fn register_destination_and_deliver() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let dest = [0xBB; 16];

    // Register destination then send a data packet to it
    tx.send(Event::RegisterDestination {
        dest_hash: dest,
        dest_type: constants::DESTINATION_SINGLE,
    })
    .unwrap();

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"data").unwrap();
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(deliveries.lock().unwrap().len(), 1);
    assert_eq!(deliveries.lock().unwrap()[0], DestHash(dest));
}

#[test]
fn query_transport_identity() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some([0xAA; 16]),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::TransportIdentity, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::TransportIdentity(Some(hash)) => {
            assert_eq!(hash, [0xAA; 16]);
        }
        _ => panic!("unexpected response"),
    }
}

#[test]
fn query_link_count() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let (count_tx, count_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::LinkCount, count_tx))
        .unwrap();
    let (active_tx, active_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::ActiveLinkCount, active_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match count_rx.recv().unwrap() {
        QueryResponse::LinkCount(count) => assert_eq!(count, 0),
        _ => panic!("unexpected response"),
    }
    match active_rx.recv().unwrap() {
        QueryResponse::ActiveLinkCount(count) => assert_eq!(count, 0),
        _ => panic!("unexpected response"),
    }
}

#[test]
fn query_rate_table() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::RateTable, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::RateTable(entries) => assert!(entries.is_empty()),
        _ => panic!("unexpected response"),
    }
}

#[test]
fn query_next_hop() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let dest = [0xBB; 16];
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::NextHop { dest_hash: dest },
        resp_tx,
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::NextHop(None) => {}
        _ => panic!("unexpected response"),
    }
}

#[test]
fn query_next_hop_of_an_own_destination_is_the_transport_identity() {
    // Upstream's Transport.next_hop answers a destination this node hosts,
    // with no path to it, with the transport identity's hash; without a
    // shared instance interface the interface is unknown.
    let mut driver = new_test_driver();
    let identity = Identity::new(&mut OsRng);
    let identity_hash = *identity.hash();
    driver.transport_identity = Some(identity);
    let dest = [0xBD; 16];
    driver
        .local_destinations
        .insert(dest, constants::DESTINATION_SINGLE);
    let QueryResponse::NextHop(Some(next_hop)) =
        driver.handle_query(QueryRequest::NextHop { dest_hash: dest })
    else {
        panic!("expected a next hop");
    };
    assert_eq!(next_hop.next_hop, identity_hash);
    assert_eq!(next_hop.hops, rns_core::constants::PATHFINDER_M);
    assert!(matches!(
        driver.handle_query(QueryRequest::NextHopIfName { dest_hash: dest }),
        QueryResponse::NextHopIfName(None)
    ));
    assert!(matches!(
        driver.handle_query(QueryRequest::NextHop {
            dest_hash: [0xBE; 16]
        }),
        QueryResponse::NextHop(None)
    ));
}

#[test]
fn query_next_hop_if_name() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let dest = [0xCC; 16];
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::NextHopIfName { dest_hash: dest },
        resp_tx,
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::NextHopIfName(None) => {}
        _ => panic!("unexpected response"),
    }
}

#[test]
fn query_drop_all_via() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let transport = [0xDD; 16];
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::DropAllVia {
            transport_hash: transport,
        },
        resp_tx,
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::DropAllVia(count) => assert_eq!(count, 0),
        _ => panic!("unexpected response"),
    }
}

#[test]
fn query_drop_announce_queues() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::DropAnnounceQueues, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::DropAnnounceQueues => {}
        _ => panic!("unexpected response"),
    }
}

// =========================================================================
// Phase 7e: Link wiring integration tests
// =========================================================================

#[test]
fn register_link_dest_event() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let mut rng = OsRng;
    let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
    let sig_pub_bytes = sig_prv.public_key().public_bytes();
    let sig_prv_bytes = sig_prv.private_bytes();
    let dest_hash = [0xDD; 16];

    tx.send(Event::RegisterLinkDestination {
        dest_hash,
        sig_prv_bytes,
        sig_pub_bytes,
        resource_strategy: 0,
        max_request_size: None,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Link manager should know about the destination
    assert!(driver.link_manager.is_link_destination(&dest_hash));
}

#[test]
fn create_link_event() {
    let (tx, rx) = event::channel();
    let (cbs, _link_established, _, _) = MockCallbacks::with_link_tracking();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let dest_hash = [0xDD; 16];
    let dummy_sig_pub = [0xAA; 32];

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::CreateLink {
        dest_hash,
        dest_sig_pub_bytes: dummy_sig_pub,
        response_tx: resp_tx,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Should have received a link_id
    let link_id = resp_rx.recv().unwrap();
    assert_ne!(link_id, [0u8; 16]);

    // Shutdown should tear down and clean up pending links.
    assert_eq!(driver.link_manager.link_count(), 0);

    // The LINKREQUEST packet won't be sent on the wire without a path
    // to the destination (DESTINATION_LINK requires a known path or
    // attached_interface). In a real scenario, the path would exist from
    // an announce received earlier.
}

#[test]
fn create_link_uses_known_destination_interface_without_path() {
    let (tx, rx) = event::channel();
    let (cbs, _link_established, _, _) = MockCallbacks::with_link_tracking();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    for id in [1, 2] {
        driver.engine.register_interface(make_interface_info(id));
    }
    let (writer, sent) = MockWriter::new();
    let (writer2, sent2) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(writer2), true));

    let dest_hash = [0xD1; 16];
    driver.known_destinations.insert(
        dest_hash,
        make_known_destination_state(dest_hash, 10.0, InterfaceId(2)),
    );

    let dummy_sig_pub = [0xA1; 32];
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::CreateLink {
        dest_hash,
        dest_sig_pub_bytes: dummy_sig_pub,
        response_tx: resp_tx,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let link_id = resp_rx.recv().unwrap();
    assert_ne!(link_id, [0u8; 16]);
    assert_eq!(driver.link_manager.link_count(), 0);

    let sent_packets = sent.lock().unwrap();
    let sent_packets2 = sent2.lock().unwrap();
    assert!(
            sent_packets.is_empty(),
            "LINKREQUEST should not broadcast to unrelated interfaces when a known destination interface exists"
        );
    assert_eq!(sent_packets2.len(), 1);
    let flags = PacketFlags::unpack(sent_packets2[0][0] & 0x7F);
    assert_eq!(flags.packet_type, constants::PACKET_TYPE_LINKREQUEST);
    assert_eq!(extract_dest_hash(&sent_packets2[0]), dest_hash);
    assert!(!sent_contains_linkclose(&sent_packets2, link_id));
}

#[test]
fn create_link_ignores_sentinel_known_destination_interface() {
    let (tx, rx) = event::channel();
    let (cbs, _link_established, _, _) = MockCallbacks::with_link_tracking();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    for id in [1, 2] {
        driver.engine.register_interface(make_interface_info(id));
    }
    let (writer, sent) = MockWriter::new();
    let (writer2, sent2) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(writer2), true));

    let dest_hash = [0xD2; 16];
    driver.known_destinations.insert(
        dest_hash,
        make_known_destination_state(dest_hash, 10.0, InterfaceId(0)),
    );

    let dummy_sig_pub = [0xA2; 32];
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::CreateLink {
        dest_hash,
        dest_sig_pub_bytes: dummy_sig_pub,
        response_tx: resp_tx,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let link_id = resp_rx.recv().unwrap();
    assert_ne!(link_id, [0u8; 16]);
    assert_eq!(driver.link_manager.link_count(), 0);

    let sent_packets = sent.lock().unwrap();
    let sent_packets2 = sent2.lock().unwrap();
    assert!(
        sent_packets.len() == 1 && sent_packets2.len() == 1,
        "sentinel InterfaceId(0) must not suppress the default broadcast behavior"
    );
    let flags = PacketFlags::unpack(sent_packets[0][0] & 0x7F);
    assert_eq!(flags.packet_type, constants::PACKET_TYPE_LINKREQUEST);
}

#[test]
fn deliver_local_routes_to_link_manager() {
    // Verify that DeliverLocal for a registered link destination goes to
    // the link manager instead of the callbacks.
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Register a link destination
    let mut rng = OsRng;
    let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
    let sig_pub_bytes = sig_prv.public_key().public_bytes();
    let dest_hash = [0xEE; 16];
    driver.link_manager.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        crate::link_manager::ResourceStrategy::AcceptNone,
    );

    // dispatch_all with a DeliverLocal for that dest should route to link_manager
    // (not to callbacks). We can't easily test this via run() since we need
    // a valid LINKREQUEST, but we can check is_link_destination works.
    assert!(driver.link_manager.is_link_destination(&dest_hash));

    // Non-link destination should go to callbacks
    assert!(!driver.link_manager.is_link_destination(&[0xFF; 16]));

    drop(tx);
}

#[test]
fn stale_link_interface_arrival_releases_packet_hash_for_current_route() {
    let mut driver = new_test_driver();
    let current_interface = InterfaceId(1);
    let stale_interface = InterfaceId(2);
    let (link_manager, link_id) = active_link_manager_with_route(current_interface);
    driver.link_manager = link_manager;

    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &link_id,
        None,
        constants::CONTEXT_NONE,
        b"in flight",
    )
    .unwrap();

    driver.engine.handle_outbound(
        &packet,
        constants::DESTINATION_LINK,
        Some(current_interface),
        10.0,
    );
    assert_eq!(driver.engine.packet_hashlist_len(), 1);

    driver.dispatch_all(vec![TransportAction::DeliverLocal {
        destination_hash: link_id,
        raw: packet.raw.clone().into(),
        packet_hash: packet.packet_hash,
        receiving_interface: stale_interface,
    }]);

    assert_eq!(driver.engine.packet_hashlist_len(), 0);
    assert!(driver
        .engine
        .accepts_inbound_frame(rns_core::transport::InboundFrame {
            raw: &packet.raw,
            iface: current_interface,
            now: 11.0,
            rx: rns_core::transport::RxMetadata::default(),
        }));
}

#[test]
fn shutdown_tears_down_pending_link() {
    let (tx, rx) = event::channel();
    let (cbs, _, link_closed, _) = MockCallbacks::with_link_tracking();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Create a link first
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::CreateLink {
        dest_hash: [0xDD; 16],
        dest_sig_pub_bytes: [0xAA; 32],
        response_tx: resp_tx,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let link_id = resp_rx.recv().unwrap();
    assert_ne!(link_id, [0u8; 16]);
    assert_eq!(driver.link_manager.link_count(), 0);
    assert_eq!(link_closed.lock().unwrap().len(), 1);
    assert_eq!(link_closed.lock().unwrap()[0], TypedLinkId(link_id));
    assert!(!sent_contains_linkclose(&sent.lock().unwrap(), link_id));
}

#[test]
fn shutdown_tears_down_active_link() {
    let (tx, rx) = event::channel();
    let (cbs, _, link_closed, _) = MockCallbacks::with_link_tracking();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let (link_manager, link_id) = active_link_manager_with_route(InterfaceId(1));
    driver.link_manager = link_manager;

    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(driver.link_manager.link_count(), 0);
    assert_eq!(
        link_closed.lock().unwrap().as_slice(),
        &[TypedLinkId(link_id)]
    );
    assert!(sent_contains_linkclose(&sent.lock().unwrap(), link_id));
}

#[test]
fn link_count_includes_link_manager() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Create a link via link_manager directly
    let mut rng = OsRng;
    let dummy_sig = [0xAA; 32];
    driver
        .link_manager
        .create_link(&[0xDD; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

    // Query link count — should include link_manager links
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::LinkCount, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::LinkCount(count) => assert_eq!(count, 1),
        _ => panic!("unexpected response"),
    }
}

#[test]
fn register_request_handler_event() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    tx.send(Event::RegisterRequestHandler {
        path: "/status".to_string(),
        allowed_list: None,
        handler: Box::new(|_link_id, _path, _data, _remote| Some(b"OK".to_vec())),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Handler should be registered (we can't directly query the count,
    // but at least verify no crash)
}

// Phase 8c: Management announce timing tests

#[test]
fn management_announces_emitted_after_delay() {
    let (tx, rx) = event::channel();
    let (cbs, _announces, _, _, _, _) = MockCallbacks::new();
    let identity = Identity::new(&mut OsRng);
    let identity_hash = *identity.hash();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some(identity_hash),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    unstamped(&mut driver);

    // Register interface so announces can be sent
    let info = make_interface_info(1);
    driver.engine.register_interface(info.clone());
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Enable management announces
    driver.management_config.enable_remote_management = true;
    driver.transport_identity = Some(identity);

    // Started long enough ago for the startup delay to have passed
    driver.started = time::now() - Driver::MANAGEMENT_ANNOUNCE_DELAY - 5.0;

    // Send Tick then Shutdown
    tx.send(Event::Tick).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Should have sent at least one packet (the management announce)
    let sent_packets = sent.lock().unwrap();
    assert!(
        !sent_packets.is_empty(),
        "Management announce should be sent after startup delay"
    );
}

/// Runs a driver whose interface announcer publishes one discoverable
/// interface until it sends its first discovery announce, and returns it.
fn first_discovery_announce(
    transport_identity: Identity,
    network_identity: Option<Identity>,
    encrypt: bool,
) -> RawPacket {
    let (tx, rx) = event::channel();
    let (cbs, _announces, _, _, _, _) = MockCallbacks::new();
    let identity_hash = *transport_identity.hash();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some(identity_hash),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx,
        Box::new(cbs),
    );

    driver.engine.register_interface(make_interface_info(1));
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    driver.transport_identity = Some(transport_identity);
    driver.network_identity = network_identity;
    let announcer = driver.new_interface_announcer(
        identity_hash,
        vec![crate::discovery::DiscoverableInterface {
            interface_name: "public".into(),
            config: crate::discovery::DiscoveryConfig {
                publish_ifac: false,
                encrypt,
                radio: Default::default(),
                stamp_costs: Default::default(),
                discovery_name: "Public Test".into(),
                announce_interval: 1,
                stamp_value: rns_core::stamp::StampCost::ZERO,
                reachable_on: Some("127.0.0.1".into()),
                interface_type: "TCPServerInterface".into(),
                listen_port: Some(4242),
                location_cmd: None,
                latitude: None,
                longitude: None,
                height: None,
                operator_lxmf_address: None,
            },
            transport_enabled: true,
            ifac_netname: None,
            ifac_netkey: None,
        }],
    );
    driver.interface_announcer = Some(announcer);

    let now = time::now();
    driver.tick_discovery_announcer(now);
    let deadline = Instant::now() + Duration::from_secs(2);
    while sent.lock().unwrap().is_empty() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
        driver.tick_discovery_announcer(now + 1.0);
    }

    let sent_packets = sent.lock().unwrap();
    assert!(
        !sent_packets.is_empty(),
        "discovery announce should be sent on a registered local synthetic destination"
    );
    RawPacket::unpack(&sent_packets[0]).expect("sent discovery announce should unpack")
}

#[test]
fn discovery_announcer_emits_local_synthetic_announce() {
    let packet = first_discovery_announce(Identity::new(&mut OsRng), None, false);
    assert_eq!(packet.flags.packet_type, constants::PACKET_TYPE_ANNOUNCE);
    assert_eq!(packet.flags.destination_type, constants::DESTINATION_SINGLE);
}

/// With a network identity, the discovery destination belongs to it while
/// the announce carries the transport identity's hash, as upstream's
/// `InterfaceAnnouncer` does, and an encrypted announce is read with the
/// network identity alone.
#[test]
fn discovery_announces_come_from_the_network_identity() {
    let transport_identity = Identity::new(&mut OsRng);
    let transport_hash = *transport_identity.hash();
    let network_identity = Identity::new(&mut OsRng);
    let network_hash = *network_identity.hash();
    let packet = first_discovery_announce(
        transport_identity,
        Some(Identity::from_private_key(
            &network_identity.get_private_key().unwrap(),
        )),
        true,
    );
    assert_eq!(
        packet.destination_hash,
        rns_core::destination::destination_hash(
            crate::discovery::APP_NAME,
            &["discovery", "interface"],
            Some(&network_hash),
        )
    );
    let announce = rns_core::announce::AnnounceData::unpack(packet.data(), false).unwrap();
    let announced_hash = *Identity::from_public_key(&announce.public_key)
        .unwrap()
        .hash();
    assert_eq!(announced_hash, network_hash);
    let app_data = announce.app_data.unwrap();
    let parse = |identity: Option<&Identity>| {
        crate::discovery::parse_interface_announce_with_identity(
            &app_data,
            &announced_hash,
            0,
            rns_core::stamp::StampCost::ZERO,
            &mut crate::discovery::DiscoveryStampCache::default(),
            identity,
        )
    };
    let discovered = parse(Some(&network_identity)).expect("decrypts with the network identity");
    assert_eq!(discovered.transport_id, transport_hash);
    assert_eq!(discovered.network_id, network_hash);
    assert!(parse(None).is_none());
}

#[test]
fn runtime_config_list_contains_global_keys() {
    let driver = new_test_driver();
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"global.tick_interval_ms".to_string()));
    assert!(keys.contains(&"global.known_destinations_ttl_secs".to_string()));
    assert!(keys.contains(&"global.rate_limiter_ttl_secs".to_string()));
    assert!(keys.contains(&"global.direct_connect_policy".to_string()));
    assert!(keys.contains(&"global.stamp_destinations".to_string()));
    assert!(keys.contains(&"global.stamp_path_requests".to_string()));
    assert!(keys.contains(&"global.stamps_enforced".to_string()));
    assert!(keys.contains(&"global.lr_stamps_enforced".to_string()));
    assert!(keys.contains(&"global.stamp_link_requests".to_string()));
    assert!(keys.contains(&"global.always_stamp_link_requests".to_string()));
}

#[test]
fn runtime_config_stamp_flags_default_as_upstream_and_apply_to_engine_and_shared_flag() {
    let mut driver = new_test_driver();
    // Upstream 51fa8413 stamps announces and path requests by default.
    let defaults = [
        ("global.stamp_destinations", true),
        ("global.stamp_path_requests", true),
        ("global.stamps_enforced", false),
        ("global.lr_stamps_enforced", false),
        ("global.always_stamp_link_requests", false),
    ];
    for (key, default) in defaults {
        let QueryResponse::RuntimeConfigEntry(Some(entry)) =
            driver.handle_query(QueryRequest::GetRuntimeConfig { key: key.into() })
        else {
            panic!("expected runtime config entry for {key}");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(default), "{key}");
        assert_eq!(entry.source, RuntimeConfigSource::Startup, "{key}");
    }
    assert!(driver.engine.stamp_prs());
    assert!(driver.stamp_destinations.load(Ordering::Relaxed));

    // The node handle reads the same flag the driver flips.
    let shared = Arc::new(AtomicBool::new(true));
    driver.set_stamp_destinations_flag(Arc::clone(&shared));

    for ((key, read_back), (_, default)) in [
        (
            "global.stamp_destinations",
            Box::new(|d: &Driver| d.stamp_destinations.load(Ordering::Relaxed))
                as Box<dyn Fn(&Driver) -> bool>,
        ),
        (
            "global.stamp_path_requests",
            Box::new(|d: &Driver| d.engine.stamp_prs()),
        ),
        (
            "global.stamps_enforced",
            Box::new(|d: &Driver| d.engine.stamp_requirements().enforced),
        ),
        (
            // The node API and the announce builder read the same handle.
            "global.lr_stamps_enforced",
            Box::new(|d: &Driver| {
                assert_eq!(
                    d.link_manager.link_request_costs().enforced(),
                    d.event_tx.link_request_costs().enforced()
                );
                d.link_manager.link_request_costs().enforced()
            }),
        ),
        (
            "global.always_stamp_link_requests",
            Box::new(|d: &Driver| d.stamp_settings.always_stamp_lrs),
        ),
    ]
    .into_iter()
    .zip(defaults)
    {
        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: key.into(),
            value: RuntimeConfigValue::Bool(!default),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success for {key}");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(!default));
        assert_eq!(entry.source, RuntimeConfigSource::RuntimeOverride);
        assert_eq!(read_back(&driver), !default, "{key} not applied");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: key.into(),
            value: RuntimeConfigValue::Int(1),
        });
        let QueryResponse::RuntimeConfigSet(Err(err)) = response else {
            panic!("expected a type error for {key}");
        };
        assert_eq!(err.code, RuntimeConfigErrorCode::InvalidType);
        assert_eq!(
            read_back(&driver),
            !default,
            "{key} changed by a rejected value"
        );

        let response =
            driver.handle_query_mut(QueryRequest::ResetRuntimeConfig { key: key.into() });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success for {key}");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(default));
        assert_eq!(read_back(&driver), default, "{key} not reset");
    }
    assert!(shared.load(Ordering::Relaxed));
}

#[test]
fn runtime_config_stamps_enforced_keeps_the_configured_costs() {
    let mut driver = new_test_driver();
    let stamps = crate::config::StampsSection {
        destination_cost: StampCost::from_whole(18),
        pr_cost: StampCost::from_whole(11),
        ..Default::default()
    };
    driver.apply_stamp_config(&stamps, rns_core::constants::HOP_LIMITER);
    let configured = driver.engine.stamp_requirements();
    assert!(!configured.enforced);

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "global.stamps_enforced".into(),
        value: RuntimeConfigValue::Bool(true),
    });
    assert!(matches!(response, QueryResponse::RuntimeConfigSet(Ok(_))));
    let enforced = driver.engine.stamp_requirements();
    assert!(enforced.enforced);
    assert_eq!(enforced.destination_cost, configured.destination_cost);
    assert_eq!(enforced.path_request_cost, configured.path_request_cost);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "global.stamps_enforced".into(),
    });
    assert!(matches!(response, QueryResponse::RuntimeConfigReset(Ok(_))));
    assert_eq!(driver.engine.stamp_requirements(), configured);
}

#[test]
fn runtime_config_stamp_link_requests_defaults_on_and_can_be_turned_off() {
    // Upstream a8cc6cb2 turned STAMP_LRS back on and removed its config
    // option; the runtime key still switches it.
    let mut driver = new_test_driver();
    let key = "global.stamp_link_requests";
    let QueryResponse::RuntimeConfigEntry(Some(entry)) =
        driver.handle_query(QueryRequest::GetRuntimeConfig { key: key.into() })
    else {
        panic!("expected runtime config entry for {key}");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Bool(true));
    assert_eq!(entry.default, RuntimeConfigValue::Bool(true));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: key.into(),
        value: RuntimeConfigValue::Bool(false),
    });
    assert!(matches!(response, QueryResponse::RuntimeConfigSet(Ok(_))));
    assert!(!driver.stamp_settings.stamp_lrs);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig { key: key.into() });
    assert!(matches!(response, QueryResponse::RuntimeConfigReset(Ok(_))));
    assert!(driver.stamp_settings.stamp_lrs);
}

#[test]
fn runtime_config_set_and_reset_tick_interval() {
    let mut driver = new_test_driver();

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "global.tick_interval_ms".into(),
        value: RuntimeConfigValue::Int(250),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.key, "global.tick_interval_ms");
    assert_eq!(entry.value, RuntimeConfigValue::Int(250));
    assert_eq!(driver.tick_interval_ms.load(Ordering::Relaxed), 250);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "global.tick_interval_ms".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(1000));
    assert_eq!(driver.tick_interval_ms.load(Ordering::Relaxed), 1000);
}

#[test]
fn runtime_config_rejects_invalid_policy() {
    let mut driver = new_test_driver();
    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "global.direct_connect_policy".into(),
        value: RuntimeConfigValue::String("bogus".into()),
    });
    let QueryResponse::RuntimeConfigSet(Err(err)) = response else {
        panic!("expected runtime config set failure");
    };
    assert_eq!(err.code, RuntimeConfigErrorCode::InvalidValue);
}

#[test]
fn runtime_config_supports_identified_only_and_configured_reset_default() {
    let mut driver = new_test_driver();
    driver.runtime_config_defaults.direct_connect_policy = HolePunchPolicy::Reject;
    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "global.direct_connect_policy".into(),
        value: RuntimeConfigValue::String("identified_only".into()),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(
        entry.value,
        RuntimeConfigValue::String("identified_only".into())
    );
    assert_eq!(
        driver.holepunch_manager.policy(),
        HolePunchPolicy::IdentifiedOnly
    );

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "global.direct_connect_policy".into(),
    });
    assert!(matches!(response, QueryResponse::RuntimeConfigReset(Ok(_))));
    assert_eq!(driver.holepunch_manager.policy(), HolePunchPolicy::Reject);
}

#[test]
fn direct_connect_policy_is_identity_aware_and_ask_app_calls_once() {
    let proposals = Arc::new(Mutex::new(Vec::new()));
    let callbacks = DirectConnectCallbacks {
        proposals: proposals.clone(),
        accept: true,
    };
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(false), rx, tx, Box::new(callbacks));
    let link = [0x11; 16];
    let identity = [0x22; 16];

    assert!(!driver.authorize_direct_connect(HolePunchPolicy::Reject, link, Some(identity)));
    assert!(driver.authorize_direct_connect(HolePunchPolicy::AcceptAll, link, None));
    assert!(!driver.authorize_direct_connect(HolePunchPolicy::IdentifiedOnly, link, None));
    assert!(driver.authorize_direct_connect(HolePunchPolicy::IdentifiedOnly, link, Some(identity)));
    assert!(proposals.lock().unwrap().is_empty());

    assert!(driver.authorize_direct_connect(HolePunchPolicy::AskApp, link, Some(identity)));
    assert_eq!(
        proposals.lock().unwrap().as_slice(),
        &[(TypedLinkId(link), Some(IdentityHash(identity)))]
    );

    let proposals = Arc::new(Mutex::new(Vec::new()));
    let callbacks = DirectConnectCallbacks {
        proposals: proposals.clone(),
        accept: false,
    };
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(false), rx, tx, Box::new(callbacks));
    assert!(!driver.authorize_direct_connect(HolePunchPolicy::AskApp, link, None));
    assert_eq!(
        proposals.lock().unwrap().as_slice(),
        &[(TypedLinkId(link), None)]
    );
}

#[test]
fn allowlisted_identity_is_accepted_whatever_the_policy() {
    let proposals = Arc::new(Mutex::new(Vec::new()));
    let callbacks = DirectConnectCallbacks {
        proposals: proposals.clone(),
        accept: false,
    };
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(false), rx, tx, Box::new(callbacks));
    let link = [0x11; 16];
    let friend = [0x22; 16];
    let stranger = [0x33; 16];
    driver
        .holepunch_manager
        .set_allowed_identities(vec![friend]);

    for policy in [
        HolePunchPolicy::Reject,
        HolePunchPolicy::AskApp,
        HolePunchPolicy::IdentifiedOnly,
    ] {
        assert!(driver.authorize_direct_connect(policy, link, Some(friend)));
    }
    // The application is not asked about an allowlisted identity.
    assert!(proposals.lock().unwrap().is_empty());
    // Others still go through the policy; an anonymous peer cannot match.
    assert!(!driver.authorize_direct_connect(HolePunchPolicy::Reject, link, Some(stranger)));
    assert!(!driver.authorize_direct_connect(HolePunchPolicy::Reject, link, None));
    assert!(!driver.authorize_direct_connect(HolePunchPolicy::AskApp, link, Some(stranger)));
}

#[test]
fn malformed_direct_connect_proposal_does_not_call_application() {
    let proposals = Arc::new(Mutex::new(Vec::new()));
    let callbacks = DirectConnectCallbacks {
        proposals: proposals.clone(),
        accept: true,
    };
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(false), rx, tx, Box::new(callbacks));
    assert_eq!(
        driver.authorize_direct_connect_proposal(
            HolePunchPolicy::AskApp,
            [0x11; 16],
            Some([0x22; 16]),
            &[1, 2, 3],
        ),
        None
    );
    assert!(proposals.lock().unwrap().is_empty());
}

#[test]
fn runtime_config_set_and_reset_rate_limiter_ttl() {
    let mut driver = new_test_driver();

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "global.rate_limiter_ttl_secs".into(),
        value: RuntimeConfigValue::Float(600.0),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(600.0));
    assert_eq!(driver.rate_limiter_ttl_secs, 600.0);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "global.rate_limiter_ttl_secs".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(
        entry.value,
        RuntimeConfigValue::Float(DEFAULT_RATE_LIMITER_TTL_SECS)
    );
    assert_eq!(driver.rate_limiter_ttl_secs, DEFAULT_RATE_LIMITER_TTL_SECS);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn runtime_config_lists_backbone_keys() {
    let mut driver = new_test_driver();
    register_test_backbone(&mut driver, "public");
    register_test_backbone_client(&mut driver, "uplink");
    register_test_backbone_discovery(&mut driver, "public", false);
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"backbone.public.idle_timeout_secs".to_string()));
    assert!(keys.contains(&"backbone.public.write_stall_timeout_secs".to_string()));
    assert!(keys.contains(&"backbone.public.max_connections".to_string()));
    assert!(keys.contains(&"backbone.public.discoverable".to_string()));
    assert!(keys.contains(&"backbone.public.discovery_name".to_string()));
    assert!(keys.contains(&"backbone.public.location_cmd".to_string()));
    assert!(keys.contains(&"backbone.public.latitude".to_string()));
    assert!(keys.contains(&"backbone.public.longitude".to_string()));
    assert!(keys.contains(&"backbone.public.height".to_string()));
    assert!(keys.contains(&"backbone_client.uplink.connect_timeout_secs".to_string()));
    assert!(keys.contains(&"backbone_client.uplink.reconnect_wait_secs".to_string()));
    assert!(keys.contains(&"backbone_client.uplink.max_reconnect_tries".to_string()));
}

#[cfg(feature = "iface-backbone")]
#[test]
fn runtime_config_sets_backbone_values() {
    let mut driver = new_test_driver();
    register_test_backbone(&mut driver, "public");
    register_test_backbone_discovery(&mut driver, "public", false);
    driver.transport_identity = Some(rns_crypto::identity::Identity::new(&mut OsRng));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.idle_timeout_secs".into(),
        value: RuntimeConfigValue::Float(2.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.write_stall_timeout_secs".into(),
        value: RuntimeConfigValue::Float(15.0),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(15.0));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.max_connections".into(),
        value: RuntimeConfigValue::Int(0),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(0));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "backbone.public.max_connections".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(8));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "backbone.public.write_stall_timeout_secs".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(30.0));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.discoverable".into(),
        value: RuntimeConfigValue::Bool(true),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Bool(true));
    assert!(driver
        .interface_announcer
        .as_ref()
        .map(|announcer| announcer.contains_interface("public"))
        .unwrap_or(false));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.discovery_name".into(),
        value: RuntimeConfigValue::String("Public Backbone".into()),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(
        entry.value,
        RuntimeConfigValue::String("Public Backbone".into())
    );

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.latitude".into(),
        value: RuntimeConfigValue::Float(45.4642),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(45.4642));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.longitude".into(),
        value: RuntimeConfigValue::Float(9.19),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(9.19));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.height".into(),
        value: RuntimeConfigValue::Int(120),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(120.0));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.location_cmd".into(),
        value: RuntimeConfigValue::String("/opt/bin/location".into()),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(
        entry.value,
        RuntimeConfigValue::String("/opt/bin/location".into())
    );

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone.public.location_cmd".into(),
        value: RuntimeConfigValue::Null,
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected nullable runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Null);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "backbone.public.location_cmd".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Null);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "backbone.public.discoverable".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Bool(false));
    assert!(driver.interface_announcer.is_none());

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "backbone.public.latitude".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Null);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn runtime_config_sets_backbone_client_values() {
    let mut driver = new_test_driver();
    register_test_backbone_client(&mut driver, "uplink");

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone_client.uplink.connect_timeout_secs".into(),
        value: RuntimeConfigValue::Float(2.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "backbone_client.uplink.max_reconnect_tries".into(),
        value: RuntimeConfigValue::Int(0),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(0));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "backbone_client.uplink.connect_timeout_secs".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(5.0));
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_state_query_lists_entries() {
    let mut driver = new_test_driver();
    register_test_backbone(&mut driver, "public");
    driver
        .backbone_peer_state
        .get("public")
        .unwrap()
        .peer_state
        .lock()
        .unwrap()
        .seed_entry(BackbonePeerStateEntry {
            interface_name: "public".into(),
            peer_ip: "203.0.113.10".parse().unwrap(),
            connected_count: 1,
            blacklisted_remaining_secs: Some(120.0),
            blacklist_reason: Some("repeated idle timeouts".into()),
            reject_count: 7,
        });

    let response = driver.handle_query(QueryRequest::BackbonePeerState {
        interface_name: Some("public".into()),
    });
    let QueryResponse::BackbonePeerState(entries) = response else {
        panic!("expected backbone peer state list");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].peer_ip.to_string(), "203.0.113.10");
    assert_eq!(entries[0].connected_count, 1);
    assert_eq!(entries[0].reject_count, 7);
    assert_eq!(
        entries[0].blacklist_reason.as_deref(),
        Some("repeated idle timeouts")
    );
    assert!(entries[0].blacklisted_remaining_secs.unwrap() > 0.0);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn interface_stats_include_backbone_clients_and_fast_flap_blocks() {
    let mut driver = new_test_driver();
    register_test_backbone(&mut driver, "public");
    let handle = driver.backbone_peer_state.get("public").unwrap().clone();
    let peer_ip = "203.0.113.20".parse().unwrap();
    handle
        .peer_state
        .lock()
        .unwrap()
        .seed_entry(BackbonePeerStateEntry {
            interface_name: "public".into(),
            peer_ip,
            connected_count: 2,
            blacklisted_remaining_secs: None,
            blacklist_reason: None,
            reject_count: 0,
        });
    let now = Instant::now();
    for offset in 0..=handle.fast_flap.grace {
        handle
            .fast_flap_state
            .lock()
            .unwrap()
            .record_disconnect(
                peer_ip,
                Duration::from_secs(1),
                &handle.fast_flap,
                now + Duration::from_secs(offset),
            )
            .unwrap();
    }
    let child_id = InterfaceId(999);
    let (writer, _) = MockWriter::new();
    let mut child = make_entry(child_id.0, Box::new(writer), true);
    child.stats.arxb = 101;
    child.stats.atxb = 202;
    child.stats.prxb = 303;
    child.stats.ptxb = 404;
    child.stats.protocol_violations = 5;
    child.stats.ifac_violations = 6;
    child.stats.packet_filter_hits = 7;
    child.stats.hop_limiter_hits = 8;
    driver.interfaces.insert(child_id, child);
    driver
        .dynamic_interface_parents
        .insert(child_id, handle.interface_id);

    let QueryResponse::InterfaceStats(stats) = driver.handle_query(QueryRequest::InterfaceStats)
    else {
        panic!("expected interface stats");
    };
    let public = stats
        .interfaces
        .iter()
        .find(|entry| entry.name == "public")
        .expect("backbone listener stats");
    assert_eq!(public.interface_type, "BackboneInterface");
    assert_eq!(public.clients, Some(2));
    assert_eq!(public.blocked_ips, Some(1));
    assert_eq!(public.blocked_ip_list, Some(vec![peer_ip.to_string()]));
    assert_eq!((public.traffic.arxb, public.traffic.atxb), (101, 202));
    assert_eq!((public.traffic.prxb, public.traffic.ptxb), (303, 404));
    assert_eq!(public.protocol_violations, 5);
    assert_eq!(public.ifac_violations, 6);
    assert_eq!(public.packet_filter_hits, 7);
    assert_eq!(public.hop_limiter_hits, 8);
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_state_clear_removes_entry() {
    let mut driver = new_test_driver();
    register_test_backbone(&mut driver, "public");
    let handle = driver.backbone_peer_state.get("public").unwrap().clone();
    let peer_ip = "203.0.113.11".parse().unwrap();
    handle
        .peer_state
        .lock()
        .unwrap()
        .seed_entry(BackbonePeerStateEntry {
            interface_name: "public".into(),
            peer_ip,
            connected_count: 0,
            blacklisted_remaining_secs: None,
            blacklist_reason: None,
            reject_count: 0,
        });
    let now = Instant::now();
    for offset in 0..=handle.fast_flap.grace {
        handle
            .fast_flap_state
            .lock()
            .unwrap()
            .record_disconnect(
                peer_ip,
                Duration::from_secs(1),
                &handle.fast_flap,
                now + Duration::from_secs(offset),
            )
            .unwrap();
    }
    assert!(handle.fast_flap_state.lock().unwrap().is_blocked(
        peer_ip,
        &handle.fast_flap,
        now + Duration::from_secs(handle.fast_flap.grace),
    ));

    let response = driver.handle_query_mut(QueryRequest::ClearBackbonePeerState {
        interface_name: "public".into(),
        peer_ip,
    });
    let QueryResponse::ClearBackbonePeerState(true) = response else {
        panic!("expected successful peer-state clear");
    };

    let response = driver.handle_query(QueryRequest::BackbonePeerState {
        interface_name: Some("public".into()),
    });
    let QueryResponse::BackbonePeerState(entries) = response else {
        panic!("expected backbone peer state list");
    };
    assert!(entries.is_empty());
    assert_eq!(
        handle.fast_flap_state.lock().unwrap().flap_count(peer_ip),
        0
    );
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_blacklist_sets_blacklist() {
    let mut driver = new_test_driver();
    register_test_backbone(&mut driver, "public");
    driver
        .backbone_peer_state
        .get("public")
        .unwrap()
        .peer_state
        .lock()
        .unwrap()
        .seed_entry(BackbonePeerStateEntry {
            interface_name: "public".into(),
            peer_ip: "203.0.113.50".parse().unwrap(),
            connected_count: 1,
            blacklisted_remaining_secs: None,
            blacklist_reason: None,
            reject_count: 0,
        });

    let response = driver.handle_query_mut(QueryRequest::BlacklistBackbonePeer {
        interface_name: "public".into(),
        peer_ip: "203.0.113.50".parse().unwrap(),
        duration: Duration::from_secs(300),
        reason: "sentinel blacklist".into(),
        penalty_level: 2,
    });
    let QueryResponse::BlacklistBackbonePeer(true) = response else {
        panic!("expected successful blacklist");
    };

    // Verify the peer is now blacklisted
    let response = driver.handle_query(QueryRequest::BackbonePeerState {
        interface_name: Some("public".into()),
    });
    let QueryResponse::BackbonePeerState(entries) = response else {
        panic!("expected backbone peer state list");
    };
    let entry = entries
        .iter()
        .find(|e| e.peer_ip == "203.0.113.50".parse::<std::net::IpAddr>().unwrap())
        .expect("expected entry for blacklisted peer");
    assert!(entry.blacklisted_remaining_secs.is_some());
    let remaining = entry.blacklisted_remaining_secs.unwrap();
    assert!(remaining > 290.0 && remaining <= 300.0);
    assert_eq!(
        entry.blacklist_reason.as_deref(),
        Some("sentinel blacklist")
    );
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_blacklist_unknown_interface_returns_false() {
    let mut driver = new_test_driver();
    let response = driver.handle_query_mut(QueryRequest::BlacklistBackbonePeer {
        interface_name: "nonexistent".into(),
        peer_ip: "203.0.113.50".parse().unwrap(),
        duration: Duration::from_secs(60),
        reason: "sentinel blacklist".into(),
        penalty_level: 1,
    });
    let QueryResponse::BlacklistBackbonePeer(false) = response else {
        panic!("expected false for unknown interface");
    };
}

#[cfg(feature = "iface-backbone")]
#[test]
fn backbone_peer_blacklist_creates_entry_for_unknown_ip() {
    let mut driver = new_test_driver();
    register_test_backbone(&mut driver, "public");

    // Blacklist an IP that has no existing peer state
    let response = driver.handle_query_mut(QueryRequest::BlacklistBackbonePeer {
        interface_name: "public".into(),
        peer_ip: "198.51.100.1".parse().unwrap(),
        duration: Duration::from_secs(120),
        reason: "sentinel blacklist".into(),
        penalty_level: 1,
    });
    let QueryResponse::BlacklistBackbonePeer(true) = response else {
        panic!("expected successful blacklist for new IP");
    };

    let response = driver.handle_query(QueryRequest::BackbonePeerState {
        interface_name: Some("public".into()),
    });
    let QueryResponse::BackbonePeerState(entries) = response else {
        panic!("expected backbone peer state list");
    };
    let entry = entries
        .iter()
        .find(|e| e.peer_ip == "198.51.100.1".parse::<std::net::IpAddr>().unwrap())
        .expect("expected entry for newly blacklisted IP");
    assert!(entry.blacklisted_remaining_secs.is_some());
}

#[cfg(feature = "iface-tcp")]
#[test]
fn runtime_config_lists_tcp_server_keys() {
    let mut driver = new_test_driver();
    register_test_tcp_server(&mut driver, "public");
    register_test_tcp_server_discovery(&mut driver, "public", false);
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"tcp_server.public.max_connections".to_string()));
    assert!(keys.contains(&"tcp_server.public.discoverable".to_string()));
    assert!(keys.contains(&"tcp_server.public.discovery_name".to_string()));
    assert!(keys.contains(&"tcp_server.public.location_cmd".to_string()));
}

#[cfg(feature = "iface-tcp")]
#[test]
fn runtime_config_sets_tcp_server_values() {
    let mut driver = new_test_driver();
    register_test_tcp_server(&mut driver, "public");
    register_test_tcp_server_discovery(&mut driver, "public", false);
    driver.transport_identity = Some(rns_crypto::identity::Identity::new(&mut OsRng));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "tcp_server.public.max_connections".into(),
        value: RuntimeConfigValue::Int(0),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(0));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "tcp_server.public.max_connections".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(4));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "tcp_server.public.discoverable".into(),
        value: RuntimeConfigValue::Bool(true),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Bool(true));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "tcp_server.public.latitude".into(),
        value: RuntimeConfigValue::Float(41.9028),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(41.9028));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "tcp_server.public.location_cmd".into(),
        value: RuntimeConfigValue::String("/opt/bin/location".into()),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(
        entry.value,
        RuntimeConfigValue::String("/opt/bin/location".into())
    );

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "tcp_server.public.location_cmd".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Null);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "tcp_server.public.latitude".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Null);
}

#[cfg(feature = "iface-tcp")]
#[test]
fn runtime_config_lists_tcp_client_keys() {
    let mut driver = new_test_driver();
    register_test_tcp_client(&mut driver, "uplink");
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"tcp_client.uplink.connect_timeout_secs".to_string()));
    assert!(keys.contains(&"tcp_client.uplink.reconnect_wait_secs".to_string()));
    assert!(keys.contains(&"tcp_client.uplink.max_reconnect_tries".to_string()));
}

#[cfg(feature = "iface-tcp")]
#[test]
fn runtime_config_sets_tcp_client_values() {
    let mut driver = new_test_driver();
    register_test_tcp_client(&mut driver, "uplink");

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "tcp_client.uplink.connect_timeout_secs".into(),
        value: RuntimeConfigValue::Float(2.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "tcp_client.uplink.max_reconnect_tries".into(),
        value: RuntimeConfigValue::Int(0),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected runtime config set success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(0));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "tcp_client.uplink.connect_timeout_secs".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected runtime config reset success");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(5.0));
}

#[cfg(feature = "iface-udp")]
#[test]
fn runtime_config_lists_udp_keys() {
    let mut driver = new_test_driver();
    register_test_udp(&mut driver, "lan");
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"udp.lan.forward_ip".to_string()));
    assert!(keys.contains(&"udp.lan.forward_port".to_string()));
}

#[cfg(feature = "iface-udp")]
#[test]
fn runtime_config_sets_udp_values() {
    let mut driver = new_test_driver();
    register_test_udp(&mut driver, "lan");

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "udp.lan.forward_ip".into(),
        value: RuntimeConfigValue::String("192.168.1.10".into()),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(
        entry.value,
        RuntimeConfigValue::String("192.168.1.10".into())
    );

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "udp.lan.forward_port".into(),
        value: RuntimeConfigValue::Null,
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Null);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "udp.lan.forward_port".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(4242));
}

#[cfg(feature = "iface-auto")]
#[test]
fn runtime_config_lists_auto_keys() {
    let mut driver = new_test_driver();
    register_test_auto(&mut driver, "lan");
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"auto.lan.announce_interval_secs".to_string()));
    assert!(keys.contains(&"auto.lan.peer_timeout_secs".to_string()));
    assert!(keys.contains(&"auto.lan.peer_job_interval_secs".to_string()));
}

#[cfg(feature = "iface-auto")]
#[test]
fn runtime_config_sets_auto_values() {
    let mut driver = new_test_driver();
    register_test_auto(&mut driver, "lan");

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "auto.lan.announce_interval_secs".into(),
        value: RuntimeConfigValue::Float(2.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "auto.lan.peer_timeout_secs".into(),
        value: RuntimeConfigValue::Float(30.0),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(30.0));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "auto.lan.peer_job_interval_secs".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(4.0));
}

#[cfg(feature = "iface-i2p")]
#[test]
fn runtime_config_lists_i2p_keys() {
    let mut driver = new_test_driver();
    register_test_i2p(&mut driver, "anon");
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"i2p.anon.reconnect_wait_secs".to_string()));
}

#[cfg(feature = "iface-i2p")]
#[test]
fn runtime_config_sets_i2p_values() {
    let mut driver = new_test_driver();
    register_test_i2p(&mut driver, "anon");

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "i2p.anon.reconnect_wait_secs".into(),
        value: RuntimeConfigValue::Float(3.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(3.5));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "i2p.anon.reconnect_wait_secs".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(15.0));
}

#[cfg(feature = "iface-pipe")]
#[test]
fn runtime_config_lists_pipe_keys() {
    let mut driver = new_test_driver();
    register_test_pipe(&mut driver, "worker");
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"pipe.worker.respawn_delay_secs".to_string()));
}

#[cfg(feature = "iface-pipe")]
#[test]
fn runtime_config_sets_pipe_values() {
    let mut driver = new_test_driver();
    register_test_pipe(&mut driver, "worker");

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "pipe.worker.respawn_delay_secs".into(),
        value: RuntimeConfigValue::Float(2.0),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(2.0));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "pipe.worker.respawn_delay_secs".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(5.0));
}

#[cfg(feature = "iface-rnode")]
#[test]
fn runtime_config_lists_rnode_keys() {
    let mut driver = new_test_driver();
    register_test_rnode(&mut driver, "radio");
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"rnode.radio.frequency_hz".to_string()));
    assert!(keys.contains(&"rnode.radio.bandwidth_hz".to_string()));
    assert!(keys.contains(&"rnode.radio.txpower_dbm".to_string()));
    assert!(keys.contains(&"rnode.radio.spreading_factor".to_string()));
    assert!(keys.contains(&"rnode.radio.coding_rate".to_string()));
    assert!(keys.contains(&"rnode.radio.st_alock_pct".to_string()));
    assert!(keys.contains(&"rnode.radio.lt_alock_pct".to_string()));
}

#[cfg(feature = "iface-rnode")]
#[test]
fn runtime_config_sets_rnode_values() {
    let mut driver = new_test_driver();
    register_test_rnode(&mut driver, "radio");

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "rnode.radio.frequency_hz".into(),
        value: RuntimeConfigValue::Int(915_000_000),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(915_000_000));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "rnode.radio.st_alock_pct".into(),
        value: RuntimeConfigValue::Float(12.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(12.5));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "rnode.radio.frequency_hz".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(868_000_000));
}

#[test]
fn runtime_config_lists_generic_interface_keys() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "public");
    let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
    let QueryResponse::RuntimeConfigList(entries) = response else {
        panic!("expected runtime config list");
    };
    let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
    assert!(keys.contains(&"interface.public.enabled".to_string()));
    assert!(keys.contains(&"interface.public.mode".to_string()));
    assert!(keys.contains(&"interface.public.announce_rate_target".to_string()));
    assert!(keys.contains(&"interface.public.announce_rate_grace".to_string()));
    assert!(keys.contains(&"interface.public.announce_rate_penalty".to_string()));
    assert!(keys.contains(&"interface.public.announce_cap".to_string()));
    assert!(keys.contains(&"interface.public.ingress_control".to_string()));
    assert!(keys.contains(&"interface.public.ic_max_held_announces".to_string()));
    assert!(keys.contains(&"interface.public.ic_burst_hold".to_string()));
    assert!(keys.contains(&"interface.public.ic_burst_freq_new".to_string()));
    assert!(keys.contains(&"interface.public.ic_burst_freq".to_string()));
    assert!(keys.contains(&"interface.public.ic_pr_burst_freq_new".to_string()));
    assert!(keys.contains(&"interface.public.ic_pr_burst_freq".to_string()));
    assert!(keys.contains(&"interface.public.egress_control".to_string()));
    assert!(keys.contains(&"interface.public.ec_pr_freq".to_string()));
    assert!(keys.contains(&"interface.public.ic_new_time".to_string()));
    assert!(keys.contains(&"interface.public.ic_burst_penalty".to_string()));
    assert!(keys.contains(&"interface.public.ic_held_release_interval".to_string()));
    assert!(keys.contains(&"interface.public.ifac_netname".to_string()));
    assert!(keys.contains(&"interface.public.ifac_passphrase".to_string()));
    assert!(keys.contains(&"interface.public.ifac_size_bytes".to_string()));
}

#[test]
fn interface_stats_include_announce_rate_control_values() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "public");

    let response = driver.handle_query(QueryRequest::InterfaceStats);
    let QueryResponse::InterfaceStats(stats) = response else {
        panic!("expected interface stats");
    };
    let public = stats
        .interfaces
        .iter()
        .find(|iface| iface.name == "public")
        .expect("public interface stats should be present");

    assert_eq!(public.announce_rate_target, Some(1.5));
    assert_eq!(public.announce_rate_grace, 2);
    assert_eq!(public.announce_rate_penalty, 0.25);
}

#[test]
fn interface_stats_include_phy_telemetry() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "radio");

    driver.handle_interface_telemetry_event(
        InterfaceId(1),
        event::InterfaceTelemetry {
            rssi: Some(-101),
            snr: Some(7.25),
            signal_quality: Some(88.5),
            frequency: Some(868_000_000),
            bandwidth: Some(125_000),
            txpower: Some(14),
            spreading_factor: Some(8),
            coding_rate: Some(5),
            channel: Some(3),
            modulation: Some("LoRa".into()),
            ..Default::default()
        },
    );

    let response = driver.handle_query(QueryRequest::InterfaceStats);
    let QueryResponse::InterfaceStats(stats) = response else {
        panic!("expected interface stats");
    };
    let radio = stats
        .interfaces
        .iter()
        .find(|iface| iface.name == "radio")
        .expect("radio interface stats should be present");

    assert_eq!(radio.rssi, Some(-101));
    assert_eq!(radio.snr, Some(7.25));
    assert_eq!(radio.signal_quality, Some(88.5));
    assert_eq!(radio.frequency, Some(868_000_000));
    assert_eq!(radio.bandwidth, Some(125_000));
    assert_eq!(radio.txpower, Some(14));
    assert_eq!(radio.spreading_factor, Some(8));
    assert_eq!(radio.coding_rate, Some(5));
    assert_eq!(radio.channel, Some(3));
    assert_eq!(radio.modulation.as_deref(), Some("LoRa"));
}

#[test]
fn interface_stats_include_packet_and_path_pool_counts() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "public");

    let entry = driver.interfaces.get_mut(&InterfaceId(1)).unwrap();
    entry.stats.rx_packets = 10;
    entry.stats.tx_packets = 20;
    entry.stats.arxc = 3;
    entry.stats.atxc = 4;
    entry.stats.prxc = 5;
    entry.stats.ptxc = 6;

    let now = time::now();
    let make_path = |used: f64, next_hop: [u8; 16]| rns_core::transport::tables::PathEntry {
        timestamp: now,
        next_hop,
        hops: 1,
        expires: now + 3600.0,
        random_blobs: Vec::new(),
        receiving_interface: InterfaceId(1),
        packet_hash: [0; 32],
        announce_raw: None,
        used,
    };
    driver
        .engine
        .inject_path([0xAA; 16], make_path(0.0, [0x11; 16]));
    driver
        .engine
        .inject_path([0xBB; 16], make_path(now, [0x22; 16]));

    let response = driver.handle_query(QueryRequest::InterfaceStats);
    let QueryResponse::InterfaceStats(stats) = response else {
        panic!("expected interface stats");
    };

    assert_eq!(stats.total_rx_packets, 10);
    assert_eq!(stats.total_tx_packets, 20);
    assert_eq!(stats.total_announce_rx, 3);
    assert_eq!(stats.total_announce_tx, 4);
    assert_eq!(stats.total_path_request_rx, 5);
    assert_eq!(stats.total_path_request_tx, 6);
    assert_eq!(stats.path_pool_total, 2);
    assert_eq!(stats.path_pool_unused, 1);
    assert_eq!(stats.path_pool_active, 1);
    assert_eq!(stats.total_links, 0);
    assert_eq!(stats.active_links, 0);
    assert_eq!(stats.pending_links, 0);
}

#[test]
fn runtime_config_sets_generic_interface_values() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "public");

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.enabled".into(),
        value: RuntimeConfigValue::Bool(false),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Bool(false));
    assert!(!driver.interfaces.get(&InterfaceId(1)).unwrap().enabled);

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.announce_cap".into(),
        value: RuntimeConfigValue::Float(0.15),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(0.15));
    assert_eq!(
        driver
            .engine
            .interface_info(&InterfaceId(1))
            .unwrap()
            .announce_cap,
        0.15
    );

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.mode".into(),
        value: RuntimeConfigValue::String("gateway".into()),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::String("gateway".into()));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.mode".into(),
        value: RuntimeConfigValue::String("internal".into()),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::String("internal".into()));
    assert_eq!(
        driver.engine.interface_info(&InterfaceId(1)).unwrap().mode,
        constants::MODE_INTERNAL
    );

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "interface.public.mode".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::String("full".into()));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.gravity".into(),
        value: RuntimeConfigValue::Int(-7),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(-7));
    assert_eq!(
        driver
            .engine
            .interface_info(&InterfaceId(1))
            .unwrap()
            .gravity,
        -7
    );

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "interface.public.gravity".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(0));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ic_max_held_announces".into(),
        value: RuntimeConfigValue::Int(17),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(17));
    assert_eq!(
        driver
            .engine
            .interface_info(&InterfaceId(1))
            .unwrap()
            .ingress_control
            .max_held_announces,
        17
    );

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ic_burst_hold".into(),
        value: RuntimeConfigValue::Float(1.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(1.5));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ic_burst_freq_new".into(),
        value: RuntimeConfigValue::Float(2.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ic_burst_freq".into(),
        value: RuntimeConfigValue::Float(3.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(3.5));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ic_pr_burst_freq_new".into(),
        value: RuntimeConfigValue::Float(3.25),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(3.25));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ic_pr_burst_freq".into(),
        value: RuntimeConfigValue::Float(8.25),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(8.25));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.egress_control".into(),
        value: RuntimeConfigValue::Bool(true),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Bool(true));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ec_pr_freq".into(),
        value: RuntimeConfigValue::Float(5.25),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(5.25));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ic_new_time".into(),
        value: RuntimeConfigValue::Float(4.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(4.5));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ic_burst_penalty".into(),
        value: RuntimeConfigValue::Float(5.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(5.5));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ic_held_release_interval".into(),
        value: RuntimeConfigValue::Float(6.5),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Float(6.5));

    let ingress_control = driver
        .engine
        .interface_info(&InterfaceId(1))
        .unwrap()
        .ingress_control;
    assert_eq!(ingress_control.burst_hold, 1.5);
    assert_eq!(ingress_control.burst_freq_new, 2.5);
    assert_eq!(ingress_control.burst_freq, 3.5);
    assert_eq!(ingress_control.pr_burst_freq_new, 3.25);
    assert_eq!(ingress_control.pr_burst_freq, 8.25);
    assert!(ingress_control.egress_enabled);
    assert_eq!(ingress_control.egress_pr_freq, 5.25);
    assert_eq!(ingress_control.new_time, 4.5);
    assert_eq!(ingress_control.burst_penalty, 5.5);
    assert_eq!(ingress_control.held_release_interval, 6.5);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "interface.public.ic_max_held_announces".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(
        entry.value,
        RuntimeConfigValue::Int(rns_core::constants::IC_MAX_HELD_ANNOUNCES as i64)
    );

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "interface.public.ic_pr_burst_freq".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(
        entry.value,
        RuntimeConfigValue::Float(rns_core::constants::IC_PR_BURST_FREQ)
    );

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "interface.public.egress_control".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Bool(false));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "interface.public.enabled".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Bool(true));
    assert!(driver.interfaces.get(&InterfaceId(1)).unwrap().enabled);

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ifac_netname".into(),
        value: RuntimeConfigValue::String("mesh".into()),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::String("mesh".into()));
    assert_eq!(
        driver
            .interfaces
            .get(&InterfaceId(1))
            .unwrap()
            .ifac
            .as_ref()
            .unwrap()
            .size,
        16
    );

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ifac_passphrase".into(),
        value: RuntimeConfigValue::String("secret".into()),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::String("<redacted>".into()));

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "interface.public.ifac_size_bytes".into(),
        value: RuntimeConfigValue::Int(24),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(24));
    let ifac = driver
        .interfaces
        .get(&InterfaceId(1))
        .unwrap()
        .ifac
        .as_ref()
        .unwrap();
    assert_eq!(ifac.size, 24);

    let response = driver.handle_query(QueryRequest::GetRuntimeConfig {
        key: "interface.public.ifac_passphrase".into(),
    });
    let QueryResponse::RuntimeConfigEntry(Some(entry)) = response else {
        panic!("expected runtime config entry");
    };
    assert_eq!(entry.value, RuntimeConfigValue::String("<redacted>".into()));

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "interface.public.ifac_netname".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Null);
    assert!(driver
        .interfaces
        .get(&InterfaceId(1))
        .unwrap()
        .ifac
        .is_some());

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "interface.public.ifac_passphrase".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Null);
    assert!(driver
        .interfaces
        .get(&InterfaceId(1))
        .unwrap()
        .ifac
        .is_none());
}

#[cfg(feature = "hooks")]
#[test]
fn runtime_config_sets_provider_bridge_values() {
    let mut driver = new_test_driver();

    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("provider.sock");
    let bridge = crate::provider_bridge::ProviderBridge::start(
        crate::provider_bridge::ProviderBridgeConfig {
            enabled: true,
            socket_path,
            queue_max_events: 1024,
            queue_max_bytes: 1024 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    driver.runtime_config_defaults.provider_queue_max_events = 1024;
    driver.runtime_config_defaults.provider_queue_max_bytes = 1024 * 1024;
    driver.provider_bridge = Some(bridge);

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "provider.queue_max_events".into(),
        value: RuntimeConfigValue::Int(4096),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(4096));
    assert_eq!(entry.source, RuntimeConfigSource::RuntimeOverride,);

    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "provider.queue_max_bytes".into(),
        value: RuntimeConfigValue::Int(2 * 1024 * 1024),
    });
    let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
        panic!("expected set ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(2 * 1024 * 1024));

    // Reject zero values
    let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
        key: "provider.queue_max_events".into(),
        value: RuntimeConfigValue::Int(0),
    });
    assert!(matches!(response, QueryResponse::RuntimeConfigSet(Err(_))));

    // Reset
    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "provider.queue_max_events".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(1024));
    assert_eq!(entry.source, RuntimeConfigSource::Startup);

    let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
        key: "provider.queue_max_bytes".into(),
    });
    let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
        panic!("expected reset ok");
    };
    assert_eq!(entry.value, RuntimeConfigValue::Int(1024 * 1024));
}

#[test]
fn disabled_interface_drops_ingress_and_egress() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.register_interface_runtime_defaults(&info);
    driver.engine.register_interface(info.clone());
    let (writer, sent) = MockWriter::new();
    driver.interfaces.insert(
        InterfaceId(1),
        InterfaceEntry {
            id: InterfaceId(1),
            info,
            writer: Box::new(writer),
            async_writer_metrics: None,
            enabled: false,
            online: true,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats::default(),
            interface_type: String::new(),
            send_retry_at: None,
            send_retry_backoff: Duration::ZERO,
        },
    );

    driver.dispatch_all(vec![TransportAction::SendOnInterface {
        interface: InterfaceId(1),
        raw: vec![0x00, 0x01, 0x42].into(),
    }]);
    driver.wake_writers();
    assert!(sent.lock().unwrap().is_empty());

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: vec![0x00, 0x01, 0x42].into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let entry = driver.interfaces.get(&InterfaceId(1)).unwrap();
    assert_eq!(entry.stats.rxb, 0);
    assert_eq!(entry.stats.rx_packets, 0);
}

#[test]
fn management_announces_not_emitted_when_disabled() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let identity = Identity::new(&mut OsRng);
    let identity_hash = *identity.hash();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some(identity_hash),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let info = make_interface_info(1);
    driver.engine.register_interface(info.clone());
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Management announces disabled (default)
    driver.transport_identity = Some(identity);
    driver.started = time::now() - Driver::MANAGEMENT_ANNOUNCE_DELAY - 5.0;

    tx.send(Event::Tick).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Should NOT have sent any packets
    let sent_packets = sent.lock().unwrap();
    assert!(
        sent_packets.is_empty(),
        "No announces should be sent when management is disabled"
    );
}

#[test]
fn management_announces_not_emitted_before_delay() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let identity = Identity::new(&mut OsRng);
    let identity_hash = *identity.hash();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some(identity_hash),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let info = make_interface_info(1);
    driver.engine.register_interface(info.clone());
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    driver.management_config.enable_remote_management = true;
    driver.transport_identity = Some(identity);
    // Started just now - delay hasn't passed
    driver.started = time::now();

    tx.send(Event::Tick).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let sent_packets = sent.lock().unwrap();
    assert!(sent_packets.is_empty(), "No announces before startup delay");
}

// =========================================================================
// Phase 9c: Announce + Discovery tests
// =========================================================================

#[test]
fn announce_stamp_is_stored_and_recalled() {
    let mut driver = new_test_driver();
    let dest = [0x91; 16];
    let stamp = [0xAB; rns_core::constants::STAMP_LENGTH];

    driver.dispatch_all(vec![TransportAction::AnnounceReceived(Box::new(
        rns_core::transport::types::ReceivedAnnounce {
            destination_hash: dest,
            identity_hash: [0x92; 16],
            public_key: [0x93; 64],
            name_hash: [0x94; 10],
            random_hash: [0x95; 10],
            ratchet: None,
            app_data: Some(b"payload".to_vec()),
            stamp: Some(stamp),
            stamp_value: rns_core::stamp::StampValue::from_whole(19),
            lr_cost: Some(StampCost::from_f64(12.5)),
            hops: 1,
            receiving_interface: InterfaceId(1),
            rx: rns_core::transport::RxMetadata::default(),
        },
    ))]);

    let entry = driver
        .known_destination_entries()
        .into_iter()
        .find(|entry| entry.dest_hash == dest)
        .expect("announce stored");
    assert_eq!(entry.stamp, Some(stamp));
    assert_eq!(
        entry.stamp_value,
        rns_core::stamp::StampValue::from_whole(19)
    );
    assert_eq!(entry.lr_cost, Some(StampCost::from_f64(12.5)));
    assert_eq!(
        driver.recall_stamp_value(&dest),
        Some(rns_core::stamp::StampValue::from_whole(19))
    );
    assert_eq!(
        driver.recall_link_cost(&dest),
        Some(StampCost::from_f64(12.5))
    );
}

#[test]
fn announce_received_populates_known_destinations() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);

    let dest_hash =
        rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // known_destinations should be populated
    assert!(driver.known_destinations.contains_key(&dest_hash));
    let recalled = &driver.known_destinations[&dest_hash];
    assert_eq!(recalled.announced.dest_hash.0, dest_hash);
    assert_eq!(recalled.announced.identity_hash.0, *identity.hash());
    assert_eq!(
        &recalled.announced.public_key,
        &identity.get_public_key().unwrap()
    );
    assert_eq!(recalled.announced.hops, 1);
    assert_eq!(recalled.announced.rssi, Some(-100));
    assert_eq!(recalled.announced.snr, Some(10.5));
}

#[test]
fn known_destinations_cleanup_respects_ttl() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    driver.known_destinations_ttl = 10.0;
    driver.cache_cleanup_counter = 3599;

    let stale_dest = [0x11; 16];
    let fresh_dest = [0x22; 16];
    driver.known_destinations.insert(
        stale_dest,
        KnownDestinationState {
            announced: crate::destination::AnnouncedIdentity {
                dest_hash: rns_core::types::DestHash(stale_dest),
                identity_hash: rns_core::types::IdentityHash([0x33; 16]),
                public_key: [0x44; 64],
                app_data: None,
                hops: 1,
                received_at: time::now() - 20.0,
                receiving_interface: InterfaceId(1),
                rssi: Some(-100),
                snr: Some(10.5),
            },
            was_used: false,
            last_used_at: None,
            retained: false,
            stamp: None,
            stamp_value: rns_core::stamp::StampValue::ZERO,
            lr_cost: None,
        },
    );
    driver.known_destinations.insert(
        fresh_dest,
        KnownDestinationState {
            announced: crate::destination::AnnouncedIdentity {
                dest_hash: rns_core::types::DestHash(fresh_dest),
                identity_hash: rns_core::types::IdentityHash([0x55; 16]),
                public_key: [0x66; 64],
                app_data: None,
                hops: 1,
                received_at: time::now() - 5.0,
                receiving_interface: InterfaceId(1),
                rssi: Some(-100),
                snr: Some(10.5),
            },
            was_used: false,
            last_used_at: None,
            retained: false,
            stamp: None,
            stamp_value: rns_core::stamp::StampValue::ZERO,
            lr_cost: None,
        },
    );

    tx.send(Event::Tick).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(!driver.known_destinations.contains_key(&stale_dest));
    assert!(driver.known_destinations.contains_key(&fresh_dest));
}

#[test]
fn known_destinations_cleanup_is_incremental_and_bounded_per_tick() {
    let mut driver = new_test_driver();
    driver.known_destinations_ttl = 1.0;
    driver.known_destinations_cleanup_interval_ticks = 1;
    let stale_at = time::now() - 60.0;
    for n in 0..(KNOWN_DESTINATION_CLEANUP_BATCH_SIZE + 1) {
        let mut dest = [0u8; 16];
        dest[..8].copy_from_slice(&(n as u64).to_be_bytes());
        driver.known_destinations.insert(
            dest,
            make_known_destination_state(dest, stale_at, InterfaceId(1)),
        );
    }

    driver.handle_tick_event();
    assert_eq!(driver.known_destinations.len(), 1);
    assert!(driver.known_destination_cleanup.is_some());

    driver.handle_tick_event();
    assert!(driver.known_destinations.is_empty());
    assert!(driver.known_destination_cleanup.is_none());
}

#[test]
fn incremental_cleanup_rechecks_entries_changed_after_snapshot() {
    let mut driver = new_test_driver();
    driver.known_destinations_ttl = 1.0;
    driver.known_destinations_cleanup_interval_ticks = 1;
    let stale_at = time::now() - 60.0;
    for n in 0..(KNOWN_DESTINATION_CLEANUP_BATCH_SIZE + 1) {
        let mut dest = [0u8; 16];
        dest[..8].copy_from_slice(&(n as u64).to_be_bytes());
        driver.known_destinations.insert(
            dest,
            make_known_destination_state(dest, stale_at, InterfaceId(1)),
        );
    }

    driver.handle_tick_event();
    let remaining = *driver.known_destinations.keys().next().unwrap();
    driver
        .known_destinations
        .get_mut(&remaining)
        .unwrap()
        .announced
        .received_at = time::now();
    driver.handle_tick_event();

    assert!(driver.known_destinations.contains_key(&remaining));
    assert!(driver.known_destination_cleanup.is_none());
}

#[test]
fn incremental_cleanup_does_not_remove_destinations_added_mid_pass() {
    let mut driver = new_test_driver();
    driver.known_destinations_ttl = 1.0;
    driver.known_destinations_cleanup_interval_ticks = 1;
    let stale_at = time::now() - 60.0;
    for n in 0..(KNOWN_DESTINATION_CLEANUP_BATCH_SIZE + 1) {
        let mut dest = [0u8; 16];
        dest[..8].copy_from_slice(&(n as u64).to_be_bytes());
        driver.known_destinations.insert(
            dest,
            make_known_destination_state(dest, stale_at, InterfaceId(1)),
        );
    }

    driver.handle_tick_event();
    let added = [0xFA; 16];
    driver.known_destinations.insert(
        added,
        make_known_destination_state(added, stale_at, InterfaceId(1)),
    );
    driver.handle_tick_event();

    assert!(driver.known_destinations.contains_key(&added));
}

#[test]
fn known_destinations_cleanup_prunes_ratchets_to_surviving_destinations() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let store = Arc::new(TestRatchetStore::default());
    driver.ratchet_store = Some(store.clone());
    driver.known_destinations_ttl = 10.0;
    driver.cache_cleanup_counter = 3599;

    let stale_dest = [0x31; 16];
    let fresh_dest = [0x32; 16];
    driver.known_destinations.insert(
        stale_dest,
        make_known_destination_state(stale_dest, time::now() - 20.0, InterfaceId(1)),
    );
    driver.known_destinations.insert(
        fresh_dest,
        make_known_destination_state(fresh_dest, time::now() - 5.0, InterfaceId(1)),
    );

    tx.send(Event::Tick).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let cleanup_calls = store.cleanup_calls.lock().unwrap();
    assert_eq!(cleanup_calls.len(), 1);
    assert!(!cleanup_calls[0].contains(&stale_dest));
    assert!(cleanup_calls[0].contains(&fresh_dest));
}

#[test]
fn known_destinations_cap_prefers_evicting_oldest_non_active_non_local() {
    let mut driver = new_test_driver();
    driver.known_destinations_max_entries = 2;
    driver.engine.register_interface(make_interface_info(1));

    let active_dest = [0x11; 16];
    let evictable_dest = [0x22; 16];
    let new_dest = [0x33; 16];

    driver.engine.inject_path(
        active_dest,
        PathEntry {
            timestamp: 100.0,
            next_hop: [0x44; 16],
            hops: 1,
            expires: 1000.0,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(1),
            packet_hash: [0x55; 32],
            announce_raw: None,
            used: 0.0,
        },
    );

    driver.upsert_known_destination(
        active_dest,
        make_announced_identity(active_dest, 10.0, InterfaceId(1)),
    );
    driver.upsert_known_destination(
        evictable_dest,
        make_announced_identity(evictable_dest, 20.0, InterfaceId(1)),
    );
    driver.upsert_known_destination(
        new_dest,
        make_announced_identity(new_dest, 30.0, InterfaceId(1)),
    );

    assert!(driver.known_destinations.contains_key(&active_dest));
    assert!(!driver.known_destinations.contains_key(&evictable_dest));
    assert!(driver.known_destinations.contains_key(&new_dest));
    assert_eq!(driver.known_destinations_cap_evict_count, 1);
}

#[test]
fn known_destinations_cap_falls_back_to_oldest_overall_when_all_protected() {
    let mut driver = new_test_driver();
    driver.known_destinations_max_entries = 2;

    let local_oldest = [0x41; 16];
    let local_newer = [0x42; 16];
    let new_dest = [0x43; 16];
    driver
        .local_destinations
        .insert(local_oldest, rns_core::constants::DESTINATION_SINGLE);
    driver
        .local_destinations
        .insert(local_newer, rns_core::constants::DESTINATION_SINGLE);

    driver.upsert_known_destination(
        local_oldest,
        make_announced_identity(local_oldest, 10.0, InterfaceId(1)),
    );
    driver.upsert_known_destination(
        local_newer,
        make_announced_identity(local_newer, 20.0, InterfaceId(1)),
    );
    driver.upsert_known_destination(
        new_dest,
        make_announced_identity(new_dest, 30.0, InterfaceId(1)),
    );

    assert!(!driver.known_destinations.contains_key(&local_oldest));
    assert!(driver.known_destinations.contains_key(&local_newer));
    assert!(driver.known_destinations.contains_key(&new_dest));
    assert_eq!(driver.known_destinations_cap_evict_count, 1);
}

#[test]
fn known_destinations_cap_update_existing_entry_does_not_evict() {
    let mut driver = new_test_driver();
    driver.known_destinations_max_entries = 1;

    let dest = [0x61; 16];
    driver.upsert_known_destination(dest, make_announced_identity(dest, 10.0, InterfaceId(1)));
    driver.upsert_known_destination(dest, make_announced_identity(dest, 20.0, InterfaceId(2)));

    assert_eq!(driver.known_destinations.len(), 1);
    assert_eq!(
        driver.known_destinations[&dest]
            .announced
            .receiving_interface,
        InterfaceId(2)
    );
    assert_eq!(driver.known_destinations_cap_evict_count, 0);
}

#[test]
fn known_destinations_cleanup_enforces_cap() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    driver.known_destinations_ttl = 1000.0;
    driver.known_destinations_max_entries = 2;
    driver.cache_cleanup_counter = 3599;
    let now = time::now();
    driver.known_destinations.insert(
        [0x71; 16],
        make_known_destination_state([0x71; 16], now - 30.0, InterfaceId(1)),
    );
    driver.known_destinations.insert(
        [0x72; 16],
        make_known_destination_state([0x72; 16], now - 20.0, InterfaceId(1)),
    );
    driver.known_destinations.insert(
        [0x73; 16],
        make_known_destination_state([0x73; 16], now - 10.0, InterfaceId(1)),
    );

    tx.send(Event::Tick).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(driver.known_destinations.len(), 2);
    assert!(!driver.known_destinations.contains_key(&[0x71; 16]));
    assert_eq!(driver.known_destinations_cap_evict_count, 1);
}

#[test]
fn recall_identity_marks_known_destination_used() {
    let mut driver = new_test_driver();
    let dest = [0x81; 16];
    driver.upsert_known_destination(dest, make_announced_identity(dest, 10.0, InterfaceId(1)));

    let response = driver.handle_query_mut(QueryRequest::RecallIdentity { dest_hash: dest });
    assert!(matches!(response, QueryResponse::RecallIdentity(Some(_))));

    let entry = driver.known_destinations.get(&dest).unwrap();
    assert!(entry.was_used);
    assert!(entry.last_used_at.is_some());
}

#[test]
fn retained_known_destination_survives_cleanup() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    driver.known_destinations_ttl = 10.0;
    driver.cache_cleanup_counter = 3599;

    let dest = [0x82; 16];
    driver.upsert_known_destination(
        dest,
        make_announced_identity(dest, time::now() - 30.0, InterfaceId(1)),
    );
    assert!(driver.retain_known_destination(&dest));

    tx.send(Event::Tick).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(driver.known_destinations.contains_key(&dest));
}

#[test]
fn retain_identity_marks_all_matching_known_destinations() {
    let mut driver = new_test_driver();
    let identity_hash = [0x42; 16];
    let other_identity = [0x43; 16];
    let dest_a = [0xA1; 16];
    let dest_b = [0xA2; 16];
    let dest_c = [0xA3; 16];

    let mut announced_a = make_announced_identity(dest_a, 10.0, InterfaceId(1));
    announced_a.identity_hash = IdentityHash(identity_hash);
    let mut announced_b = make_announced_identity(dest_b, 11.0, InterfaceId(1));
    announced_b.identity_hash = IdentityHash(identity_hash);
    let mut announced_c = make_announced_identity(dest_c, 12.0, InterfaceId(1));
    announced_c.identity_hash = IdentityHash(other_identity);

    driver.upsert_known_destination(dest_a, announced_a);
    driver.upsert_known_destination(dest_b, announced_b);
    driver.upsert_known_destination(dest_c, announced_c);

    assert!(driver.retain_identity(&identity_hash));

    assert!(driver.known_destinations[&dest_a].retained);
    assert!(driver.known_destinations[&dest_b].retained);
    assert!(!driver.known_destinations[&dest_c].retained);
}

#[test]
fn retain_identity_returns_false_when_no_known_destination_matches() {
    let mut driver = new_test_driver();
    let dest = [0xB1; 16];
    driver.upsert_known_destination(dest, make_announced_identity(dest, 10.0, InterfaceId(1)));

    assert!(!driver.retain_identity(&[0xFE; 16]));
    assert!(!driver.known_destinations[&dest].retained);
}

#[test]
fn used_known_destination_cleanup_uses_last_used_time() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    driver.known_destinations_ttl = 10.0;
    driver.cache_cleanup_counter = 3599;

    let dest = [0x83; 16];
    driver.known_destinations.insert(
        dest,
        KnownDestinationState {
            announced: make_announced_identity(dest, time::now() - 50.0, InterfaceId(1)),
            was_used: true,
            last_used_at: Some(time::now() - 5.0),
            retained: false,
            stamp: None,
            stamp_value: rns_core::stamp::StampValue::ZERO,
            lr_cost: None,
        },
    );

    tx.send(Event::Tick).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(driver.known_destinations.contains_key(&dest));
}

#[test]
fn query_has_path() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // No path yet
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::HasPath {
            dest_hash: [0xAA; 16],
        },
        resp_tx,
    ))
    .unwrap();

    // Feed an announce to create a path
    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);
    let dest_hash =
        rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();

    let (resp_tx2, resp_rx2) = mpsc::channel();
    tx.send(Event::query(QueryRequest::HasPath { dest_hash }, resp_tx2))
        .unwrap();

    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // First query — no path
    match resp_rx.recv().unwrap() {
        QueryResponse::HasPath(false) => {}
        other => panic!("expected HasPath(false), got {:?}", other),
    }

    // Second query — path exists
    match resp_rx2.recv().unwrap() {
        QueryResponse::HasPath(true) => {}
        other => panic!("expected HasPath(true), got {:?}", other),
    }
}

#[test]
fn query_hops_to() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Feed an announce
    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);
    let dest_hash =
        rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::HopsTo { dest_hash }, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::HopsTo(Some(1)) => {}
        other => panic!("expected HopsTo(Some(1)), got {:?}", other),
    }
}

#[test]
fn query_recall_identity() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);
    let dest_hash =
        rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();

    // Recall identity
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::RecallIdentity { dest_hash },
        resp_tx,
    ))
    .unwrap();

    // Also recall unknown destination
    let (resp_tx2, resp_rx2) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::RecallIdentity {
            dest_hash: [0xFF; 16],
        },
        resp_tx2,
    ))
    .unwrap();

    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::RecallIdentity(Some(recalled)) => {
            assert_eq!(recalled.dest_hash.0, dest_hash);
            assert_eq!(recalled.identity_hash.0, *identity.hash());
            assert_eq!(recalled.public_key, identity.get_public_key().unwrap());
            assert_eq!(recalled.hops, 1);
        }
        other => panic!("expected RecallIdentity(Some(..)), got {:?}", other),
    }

    match resp_rx2.recv().unwrap() {
        QueryResponse::RecallIdentity(None) => {}
        other => panic!("expected RecallIdentity(None), got {:?}", other),
    }
}

#[test]
fn request_path_sends_packet() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    unstamped(&mut driver);
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Send path request
    tx.send(Event::RequestPath {
        dest_hash: [0xAA; 16],
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Should have sent a packet on the wire (broadcast)
    let sent_packets = sent.lock().unwrap();
    assert!(
        !sent_packets.is_empty(),
        "Path request should be sent on wire"
    );
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.ptxb,
        sent_packets[0].len() as u64
    );

    // Verify the sent packet is a DATA PLAIN BROADCAST packet
    let raw = &sent_packets[0];
    let flags = rns_core::packet::PacketFlags::unpack(raw[0] & 0x7F);
    assert_eq!(flags.packet_type, constants::PACKET_TYPE_DATA);
    assert_eq!(flags.destination_type, constants::DESTINATION_PLAIN);
    assert_eq!(flags.transport_type, constants::TRANSPORT_BROADCAST);
}

#[test]
fn recursive_path_request_does_not_reach_offline_interface_writer() {
    let (tx, rx) = event::channel();
    let (callbacks, _, _, _, _, _) = MockCallbacks::new();
    let mut config = make_transport_config(true);
    config.identity_hash = Some([0x42; 16]);
    let mut driver = Driver::new(config, rx, tx, Box::new(callbacks));
    unstamped(&mut driver);

    let mut ingress = make_interface_info(1);
    ingress.recursive_prs = true;
    let egress = make_interface_info(2);
    driver.engine.register_interface(ingress);
    driver.engine.register_interface(egress);

    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(writer), false));

    let destination_hash = [0xD9; 16];
    let request_tag = [0x09; 16];
    let mut request_data = Vec::new();
    request_data.extend_from_slice(&destination_hash);
    request_data.extend_from_slice(&request_tag);
    let actions = driver
        .engine
        .handle_path_request(&request_data, InterfaceId(1), 1000.0);

    assert_eq!(actions.len(), 1, "engine should emit one recursive request");
    let TransportAction::SendOnInterface { interface, raw } = &actions[0] else {
        panic!("expected recursive SendOnInterface action");
    };
    assert_eq!(*interface, InterfaceId(2));
    let packet = RawPacket::unpack(raw).expect("valid recursive path request");
    assert_eq!(packet.destination_hash, driver.path_request_dest);
    assert_eq!(packet.data().len(), 48);
    assert_eq!(&packet.data()[..16], &destination_hash);
    assert_eq!(&packet.data()[16..32], &[0x42; 16]);
    assert_eq!(&packet.data()[32..], &request_tag);

    driver.dispatch_all(actions);

    assert!(
        sent.lock().unwrap().is_empty(),
        "offline interface writer must not receive recursive path requests"
    );
    let entry = driver.interfaces.get(&InterfaceId(2)).unwrap();
    assert_eq!(entry.stats.tx_packets, 0);
    assert_eq!(entry.stats.txb, 0);
}

#[test]
fn recursive_path_request_is_late_limited_before_interface_send() {
    let (tx, rx) = event::channel();
    let (callbacks, _, _, _, _, _) = MockCallbacks::new();
    let mut config = make_transport_config(true);
    config.identity_hash = Some([0x42; 16]);
    let mut driver = Driver::new(config, rx, tx, Box::new(callbacks));

    let mut ingress = make_interface_info(1);
    ingress.recursive_prs = true;
    let mut egress = make_interface_info(2);
    egress.ingress_control.egress_enabled = true;
    driver.engine.register_interface(ingress);
    driver.engine.register_interface(egress);

    let (writer, sent) = MockWriter::new();
    let mut entry = make_entry(2, Box::new(writer), true);
    entry.info.ingress_control.egress_enabled = true;
    driver.interfaces.insert(InterfaceId(2), entry);

    let mut request_data = Vec::new();
    request_data.extend_from_slice(&[0xD8; 16]);
    request_data.extend_from_slice(&[0x08; 16]);
    let actions = driver
        .engine
        .handle_path_request(&request_data, InterfaceId(1), 1000.0);
    assert_eq!(
        actions.len(),
        1,
        "early gate should initially allow the request"
    );

    let entry = driver.interfaces.get_mut(&InterfaceId(2)).unwrap();
    entry.stats.record_outgoing_path_request(1000.0);
    entry.stats.record_outgoing_path_request(1000.5);

    driver.dispatch_all(actions);

    assert!(
        sent.lock().unwrap().is_empty(),
        "live egress state must be checked again immediately before dispatch"
    );
    assert_eq!(driver.interfaces[&InterfaceId(2)].stats.ptxc, 0);
}

#[test]
fn queued_ingress_limited_path_request_remains_suppressed_during_dispatch() {
    let (tx, rx) = event::channel();
    let (callbacks, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));

    let mut ingress = make_interface_info(1);
    ingress.recursive_prs = true;
    ingress.ingress_control = rns_core::transport::types::IngressControlConfig::enabled();
    driver.engine.register_interface(ingress);
    driver.engine.register_interface(make_interface_info(2));

    let (ingress_writer, _) = MockWriter::new();
    driver.interfaces.insert(
        InterfaceId(1),
        make_entry(1, Box::new(ingress_writer), true),
    );
    let (egress_writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(egress_writer), true));

    let mut request_data = Vec::new();
    request_data.extend_from_slice(&[0xDA; 16]);
    request_data.extend_from_slice(&[0x0A; 16]);
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &driver.path_request_dest,
        None,
        constants::CONTEXT_NONE,
        &request_data,
    )
    .unwrap();
    driver.dispatch_all_with_ingress_class(
        vec![TransportAction::DeliverLocal {
            destination_hash: driver.path_request_dest,
            raw: Arc::from(packet.raw),
            packet_hash: [0xCC; 32],
            receiving_interface: InterfaceId(1),
        }],
        true,
    );

    assert!(
        sent.lock().unwrap().is_empty(),
        "a queued ingress-limited request must not escape after live burst state clears"
    );
    assert!(!driver.engine.pr_burst_active(&InterfaceId(1)));
}

#[test]
fn duplicate_path_request_is_not_counted_as_new_ingress() {
    let (tx, rx) = event::channel();
    let (callbacks, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));
    driver.engine.register_interface(make_interface_info(1));

    let (writer, _) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let mut request_data = Vec::new();
    request_data.extend_from_slice(&[0xdb; 16]);
    request_data.extend_from_slice(&[0x0b; 16]);
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &driver.path_request_dest,
        None,
        constants::CONTEXT_NONE,
        &request_data,
    )
    .unwrap();

    for packet_hash in [[0xcc; 32], [0xdd; 32]] {
        driver.dispatch_all(vec![TransportAction::DeliverLocal {
            destination_hash: driver.path_request_dest,
            raw: Arc::from(packet.raw.clone()),
            packet_hash,
            receiving_interface: InterfaceId(1),
        }]);
    }

    assert_eq!(driver.engine.discovery_pr_tags_count(), 1);
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.prxb,
        packet.raw.len() as u64,
        "a duplicate tag must not contribute duplicate path-request bytes"
    );
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.ip_timestamps.len(),
        1,
        "a duplicate tag must not contribute another ingress sample"
    );
}

#[test]
fn request_path_includes_transport_id() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some([0xBB; 16]),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    unstamped(&mut driver);
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    tx.send(Event::RequestPath {
        dest_hash: [0xAA; 16],
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let sent_packets = sent.lock().unwrap();
    assert!(!sent_packets.is_empty());

    // Unpack the packet to check data length includes transport_id
    let raw = &sent_packets[0];
    if let Ok(packet) = RawPacket::unpack(raw) {
        // Data: dest_hash(16) + transport_id(16) + random_tag(16) = 48 bytes
        assert_eq!(
            packet.data().len(),
            48,
            "Path request data should be 48 bytes with transport_id"
        );
        assert_eq!(
            &packet.data()[..16],
            &[0xAA; 16],
            "First 16 bytes should be dest_hash"
        );
        assert_eq!(
            &packet.data()[16..32],
            &[0xBB; 16],
            "Next 16 bytes should be transport_id"
        );
    } else {
        panic!("Could not unpack sent packet");
    }
}

#[test]
fn path_request_dest_registered() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    // The path request dest should be registered as a local PLAIN destination
    let expected_dest =
        rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
    assert_eq!(driver.path_request_dest, expected_dest);

    drop(tx);
}

// =========================================================================
// Phase 9d: send_packet + proofs tests
// =========================================================================

#[test]
fn register_proof_strategy_event() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let dest = [0xAA; 16];
    let identity = Identity::new(&mut OsRng);
    let prv_key = identity.get_private_key().unwrap();

    tx.send(Event::RegisterProofStrategy {
        dest_hash: dest,
        strategy: rns_core::types::ProofStrategy::ProveAll,
        signing_key: Some(prv_key),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(driver.proof_strategies.contains_key(&dest));
    let (strategy, ref id_opt) = driver.proof_strategies[&dest];
    assert_eq!(strategy, rns_core::types::ProofStrategy::ProveAll);
    assert!(id_opt.is_some());
}

#[test]
fn register_proof_strategy_prove_none_no_identity() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let dest = [0xBB; 16];
    tx.send(Event::RegisterProofStrategy {
        dest_hash: dest,
        strategy: rns_core::types::ProofStrategy::ProveNone,
        signing_key: None,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(driver.proof_strategies.contains_key(&dest));
    let (strategy, ref id_opt) = driver.proof_strategies[&dest];
    assert_eq!(strategy, rns_core::types::ProofStrategy::ProveNone);
    assert!(id_opt.is_none());
}

#[test]
fn send_outbound_tracks_sent_packets() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Build a DATA packet
    let dest = [0xCC; 16];
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet =
        RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test data").unwrap();
    let expected_hash = packet.packet_hash;

    driver.handle_send_outbound_event(packet.raw, constants::DESTINATION_PLAIN, None);

    // Should be tracking the sent packet
    assert!(driver.sent_packets.contains_key(&expected_hash));
    let (tracked_dest, _sent_time) = &driver.sent_packets[&expected_hash];
    assert_eq!(tracked_dest, &dest);
}

#[test]
fn prove_all_generates_proof_on_delivery() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Register a destination with ProveAll
    let dest = [0xDD; 16];
    let identity = Identity::new(&mut OsRng);
    let prv_key = identity.get_private_key().unwrap();
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);
    driver.proof_strategies.insert(
        dest,
        (
            rns_core::types::ProofStrategy::ProveAll,
            Some(Identity::from_private_key(&prv_key)),
        ),
    );

    // Send a DATA packet to that destination
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Should have delivered the packet
    assert_eq!(deliveries.lock().unwrap().len(), 1);

    // Should have sent at least one proof packet on the wire
    let sent_packets = sent.lock().unwrap();
    // The original DATA is not sent out (it was delivered locally), but a PROOF should be
    let has_proof = sent_packets.iter().any(|raw| {
        let flags = PacketFlags::unpack(raw[0] & 0x7F);
        flags.packet_type == constants::PACKET_TYPE_PROOF
    });
    assert!(
        has_proof,
        "ProveAll should generate a proof packet: sent {} packets",
        sent_packets.len()
    );
}

#[test]
fn proofs_go_back_only_on_the_receiving_interface() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let mut sent = Vec::new();
    for id in [1, 2] {
        driver.engine.register_interface(make_interface_info(id));
        let (writer, frames) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(id), make_entry(id, Box::new(writer), true));
        sent.push(frames);
    }

    // Register a destination with ProveAll
    let dest = [0xDD; 16];
    let identity = Identity::new(&mut OsRng);
    let prv_key = identity.get_private_key().unwrap();
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);
    driver.proof_strategies.insert(
        dest,
        (
            rns_core::types::ProofStrategy::ProveAll,
            Some(Identity::from_private_key(&prv_key)),
        ),
    );

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();
    tx.send(Event::Frame {
        interface_id: InterfaceId(2),
        data: packet.raw.into(),
        rssi: None,
        snr: None,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(deliveries.lock().unwrap().len(), 1);
    let proofs = |frames: &Arc<Mutex<Vec<Vec<u8>>>>| {
        frames
            .lock()
            .unwrap()
            .iter()
            .filter(|raw| {
                PacketFlags::unpack(raw[0] & 0x7F).packet_type == constants::PACKET_TYPE_PROOF
            })
            .count()
    };
    // As upstream attaches a proof to the proved packet's interface, rather
    // than broadcasting it on every interface.
    assert_eq!(proofs(&sent[1]), 1, "proved on the receiving interface");
    assert_eq!(proofs(&sent[0]), 0, "not sent on other interfaces");
}

#[test]
fn prove_none_does_not_generate_proof() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Register a destination with ProveNone
    let dest = [0xDD; 16];
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);
    driver
        .proof_strategies
        .insert(dest, (rns_core::types::ProofStrategy::ProveNone, None));

    // Send a DATA packet to that destination
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Should have delivered the packet
    assert_eq!(deliveries.lock().unwrap().len(), 1);

    // Should NOT have sent any proof
    let sent_packets = sent.lock().unwrap();
    let has_proof = sent_packets.iter().any(|raw| {
        let flags = PacketFlags::unpack(raw[0] & 0x7F);
        flags.packet_type == constants::PACKET_TYPE_PROOF
    });
    assert!(!has_proof, "ProveNone should not generate a proof packet");
}

#[test]
fn no_proof_strategy_does_not_generate_proof() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Register destination but NO proof strategy
    let dest = [0xDD; 16];
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(deliveries.lock().unwrap().len(), 1);

    let sent_packets = sent.lock().unwrap();
    let has_proof = sent_packets.iter().any(|raw| {
        let flags = PacketFlags::unpack(raw[0] & 0x7F);
        flags.packet_type == constants::PACKET_TYPE_PROOF
    });
    assert!(!has_proof, "No proof strategy means no proof generated");
}

#[test]
fn prove_app_calls_callback() {
    let (tx, rx) = event::channel();
    let proof_requested = Arc::new(Mutex::new(Vec::new()));
    let deliveries = Arc::new(Mutex::new(Vec::new()));
    let cbs = MockCallbacks {
        announces: Arc::new(Mutex::new(Vec::new())),
        paths: Arc::new(Mutex::new(Vec::new())),
        deliveries: deliveries.clone(),
        iface_ups: Arc::new(Mutex::new(Vec::new())),
        iface_downs: Arc::new(Mutex::new(Vec::new())),
        link_established: Arc::new(Mutex::new(Vec::new())),
        link_closed: Arc::new(Mutex::new(Vec::new())),
        remote_identified: Arc::new(Mutex::new(Vec::new())),
        resources_received: Arc::new(Mutex::new(Vec::new())),
        resource_completed: Arc::new(Mutex::new(Vec::new())),
        resource_failed: Arc::new(Mutex::new(Vec::new())),
        channel_messages: Arc::new(Mutex::new(Vec::new())),
        link_data: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
        proofs: Arc::new(Mutex::new(Vec::new())),
        proof_requested: proof_requested.clone(),
    };

    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Register dest with ProveApp
    let dest = [0xDD; 16];
    let identity = Identity::new(&mut OsRng);
    let prv_key = identity.get_private_key().unwrap();
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);
    driver.proof_strategies.insert(
        dest,
        (
            rns_core::types::ProofStrategy::ProveApp,
            Some(Identity::from_private_key(&prv_key)),
        ),
    );

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet =
        RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"app test").unwrap();

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // on_proof_requested should have been called
    let prs = proof_requested.lock().unwrap();
    assert_eq!(prs.len(), 1);
    assert_eq!(prs[0].0, DestHash(dest));

    // Since our mock returns true, a proof should also have been sent
    let sent_packets = sent.lock().unwrap();
    let has_proof = sent_packets.iter().any(|raw| {
        let flags = PacketFlags::unpack(raw[0] & 0x7F);
        flags.packet_type == constants::PACKET_TYPE_PROOF
    });
    assert!(
        has_proof,
        "ProveApp (callback returns true) should generate a proof"
    );
}

#[test]
fn inbound_proof_fires_callback() {
    let (tx, rx) = event::channel();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    let cbs = MockCallbacks {
        announces: Arc::new(Mutex::new(Vec::new())),
        paths: Arc::new(Mutex::new(Vec::new())),
        deliveries: Arc::new(Mutex::new(Vec::new())),
        iface_ups: Arc::new(Mutex::new(Vec::new())),
        iface_downs: Arc::new(Mutex::new(Vec::new())),
        link_established: Arc::new(Mutex::new(Vec::new())),
        link_closed: Arc::new(Mutex::new(Vec::new())),
        remote_identified: Arc::new(Mutex::new(Vec::new())),
        resources_received: Arc::new(Mutex::new(Vec::new())),
        resource_completed: Arc::new(Mutex::new(Vec::new())),
        resource_failed: Arc::new(Mutex::new(Vec::new())),
        channel_messages: Arc::new(Mutex::new(Vec::new())),
        link_data: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
        proofs: proofs.clone(),
        proof_requested: Arc::new(Mutex::new(Vec::new())),
    };

    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Register a destination so proof packets can be delivered locally
    let dest = [0xEE; 16];
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);

    // Simulate a sent packet that we're tracking
    let tracked_hash = [0x42u8; 32];
    let sent_time = time::now() - 0.5; // 500ms ago
    driver.sent_packets.insert(tracked_hash, (dest, sent_time));

    // Build a PROOF packet with the tracked hash, signed by the destination
    let identity = Identity::new(&mut OsRng);
    know_identity(&mut driver, dest, &identity);
    let mut proof_data = Vec::new();
    proof_data.extend_from_slice(&tracked_hash);
    proof_data.extend_from_slice(&identity.sign(&tracked_hash).unwrap());

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_PROOF,
    };
    let packet =
        RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // on_proof callback should have been fired
    let proof_list = proofs.lock().unwrap();
    assert_eq!(proof_list.len(), 1);
    assert_eq!(proof_list[0].0, DestHash(dest));
    assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
    assert!(
        proof_list[0].2 >= 0.4,
        "RTT should be approximately 0.5s, got {}",
        proof_list[0].2
    );

    // Tracked packet should be removed
    assert!(!driver.sent_packets.contains_key(&tracked_hash));
}

#[test]
fn inbound_proof_for_unknown_packet_is_ignored() {
    let (tx, rx) = event::channel();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    let cbs = MockCallbacks {
        announces: Arc::new(Mutex::new(Vec::new())),
        paths: Arc::new(Mutex::new(Vec::new())),
        deliveries: Arc::new(Mutex::new(Vec::new())),
        iface_ups: Arc::new(Mutex::new(Vec::new())),
        iface_downs: Arc::new(Mutex::new(Vec::new())),
        link_established: Arc::new(Mutex::new(Vec::new())),
        link_closed: Arc::new(Mutex::new(Vec::new())),
        remote_identified: Arc::new(Mutex::new(Vec::new())),
        resources_received: Arc::new(Mutex::new(Vec::new())),
        resource_completed: Arc::new(Mutex::new(Vec::new())),
        resource_failed: Arc::new(Mutex::new(Vec::new())),
        channel_messages: Arc::new(Mutex::new(Vec::new())),
        link_data: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
        proofs: proofs.clone(),
        proof_requested: Arc::new(Mutex::new(Vec::new())),
    };

    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let dest = [0xEE; 16];
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);

    // Build a PROOF packet for an untracked hash
    let unknown_hash = [0xFF; 32];
    let mut proof_data = Vec::new();
    proof_data.extend_from_slice(&unknown_hash);
    proof_data.extend_from_slice(&[0xAA; 64]);

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_PROOF,
    };
    let packet =
        RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // on_proof should NOT have been called
    assert!(proofs.lock().unwrap().is_empty());
}

#[test]
fn inbound_implicit_proof_matches_truncated_destination() {
    let (tx, rx) = event::channel();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    let cbs = MockCallbacks {
        announces: Arc::new(Mutex::new(Vec::new())),
        paths: Arc::new(Mutex::new(Vec::new())),
        deliveries: Arc::new(Mutex::new(Vec::new())),
        iface_ups: Arc::new(Mutex::new(Vec::new())),
        iface_downs: Arc::new(Mutex::new(Vec::new())),
        link_established: Arc::new(Mutex::new(Vec::new())),
        link_closed: Arc::new(Mutex::new(Vec::new())),
        remote_identified: Arc::new(Mutex::new(Vec::new())),
        resources_received: Arc::new(Mutex::new(Vec::new())),
        resource_completed: Arc::new(Mutex::new(Vec::new())),
        resource_failed: Arc::new(Mutex::new(Vec::new())),
        channel_messages: Arc::new(Mutex::new(Vec::new())),
        link_data: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
        proofs: proofs.clone(),
        proof_requested: Arc::new(Mutex::new(Vec::new())),
    };

    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let tracked_hash = [0x3Cu8; 32];
    let sent_time = time::now() - 0.25;
    driver
        .sent_packets
        .insert(tracked_hash, ([0xEE; 16], sent_time));

    let mut proof_dest = [0u8; 16];
    proof_dest.copy_from_slice(&tracked_hash[..16]);
    driver
        .engine
        .register_destination(proof_dest, constants::DESTINATION_SINGLE);

    // Implicit proof is signature-only (64 bytes)
    let identity = Identity::new(&mut OsRng);
    know_identity(&mut driver, [0xEE; 16], &identity);
    let proof_data = identity.sign(&tracked_hash).unwrap().to_vec();
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_PROOF,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &proof_dest,
        None,
        constants::CONTEXT_NONE,
        &proof_data,
    )
    .unwrap();

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let proof_list = proofs.lock().unwrap();
    assert_eq!(proof_list.len(), 1);
    assert_eq!(proof_list[0].0, DestHash([0xEE; 16]));
    assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
    assert!(!driver.sent_packets.contains_key(&tracked_hash));
}

#[test]
fn link_dispatch_preserves_route_headers_and_proof_tracking() {
    for (header, routed, attached, context) in [
        (constants::HEADER_1, false, false, constants::CONTEXT_NONE),
        (constants::HEADER_1, true, false, constants::CONTEXT_NONE),
        (constants::HEADER_1, true, true, constants::CONTEXT_NONE),
        (constants::HEADER_2, true, false, constants::CONTEXT_NONE),
        (
            constants::HEADER_1,
            false,
            false,
            constants::CONTEXT_RESOURCE,
        ),
        (
            constants::HEADER_1,
            true,
            false,
            constants::CONTEXT_RESOURCE,
        ),
        (
            constants::HEADER_2,
            true,
            false,
            constants::CONTEXT_RESOURCE,
        ),
    ] {
        // No proof answers a resource part, so it is not tracked.
        let tracked = usize::from(context != constants::CONTEXT_RESOURCE);
        let mut driver = new_test_driver();
        let (manager, link_id) = active_link_manager_with_route(InterfaceId(1));
        driver.link_manager = manager;
        if routed {
            driver
                .link_manager
                .set_link_route_hint(&link_id, InterfaceId(1), Some([0x88; 16]));
        }
        let (writer, sent) = MockWriter::new();
        let entry = make_entry(1, Box::new(writer), true);
        driver.engine.register_interface(entry.info.clone());
        driver.interfaces.insert(InterfaceId(1), entry);
        let flags = PacketFlags {
            header_type: header,
            context_flag: constants::FLAG_SET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet = RawPacket::pack(
            flags,
            0,
            &link_id,
            if header == constants::HEADER_2 {
                Some(&[0x99; 16])
            } else {
                None
            },
            context,
            b"preserve part bytes",
        )
        .unwrap();
        let mut expected = packet.raw.clone();
        if header == constants::HEADER_1 && routed && !attached {
            expected = vec![
                (constants::HEADER_2 << 6)
                    | (constants::TRANSPORT_TRANSPORT << 4)
                    | (packet.raw[0] & 0x0F),
                0,
            ];
            expected.extend_from_slice(&[0x88; 16]);
            expected.extend_from_slice(&packet.raw[2..]);
        }
        driver.dispatch_link_actions(vec![LinkManagerAction::SendPacket {
            raw: packet.raw.into(),
            dest_type: constants::DESTINATION_LINK,
            attached_interface: attached.then_some(InterfaceId(1)),
        }]);
        assert_eq!(sent.lock().unwrap().as_slice(), &[expected]);
        assert_eq!(driver.sent_packets.len(), tracked);
        if tracked == 1 {
            assert_eq!(driver.sent_packets[&packet.packet_hash].0, link_id);
        }
        driver.dispatch_link_actions(vec![LinkManagerAction::SendPacket {
            raw: vec![0].into(),
            dest_type: constants::DESTINATION_LINK,
            attached_interface: None,
        }]);
        assert_eq!(sent.lock().unwrap().len(), 1);
        assert_eq!(driver.sent_packets.len(), tracked);
    }
}

#[test]
fn link_manager_data_send_is_tracked_for_proofs() {
    let mut driver = new_test_driver();
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_LINK,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &[0x77; 16],
        None,
        constants::CONTEXT_NONE,
        b"track me",
    )
    .unwrap();
    let packet_hash = packet.packet_hash;
    let destination_hash = packet.destination_hash;

    driver.dispatch_link_actions(vec![LinkManagerAction::SendPacket {
        raw: packet.raw.into(),
        dest_type: constants::DESTINATION_LINK,
        attached_interface: Some(InterfaceId(1)),
    }]);

    assert_eq!(
        driver.sent_packets.get(&packet_hash).map(|(dest, _)| *dest),
        Some(destination_hash)
    );
}

#[test]
fn inbound_proof_with_valid_signature_fires_callback() {
    // When the destination IS in known_destinations, the proof signature is verified
    let (tx, rx) = event::channel();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    let cbs = MockCallbacks {
        announces: Arc::new(Mutex::new(Vec::new())),
        paths: Arc::new(Mutex::new(Vec::new())),
        deliveries: Arc::new(Mutex::new(Vec::new())),
        iface_ups: Arc::new(Mutex::new(Vec::new())),
        iface_downs: Arc::new(Mutex::new(Vec::new())),
        link_established: Arc::new(Mutex::new(Vec::new())),
        link_closed: Arc::new(Mutex::new(Vec::new())),
        remote_identified: Arc::new(Mutex::new(Vec::new())),
        resources_received: Arc::new(Mutex::new(Vec::new())),
        resource_completed: Arc::new(Mutex::new(Vec::new())),
        resource_failed: Arc::new(Mutex::new(Vec::new())),
        channel_messages: Arc::new(Mutex::new(Vec::new())),
        link_data: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
        proofs: proofs.clone(),
        proof_requested: Arc::new(Mutex::new(Vec::new())),
    };

    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let dest = [0xEE; 16];
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);

    // Create real identity and add to known_destinations
    let identity = Identity::new(&mut OsRng);
    let pub_key = identity.get_public_key();
    driver.known_destinations.insert(
        dest,
        KnownDestinationState {
            announced: crate::destination::AnnouncedIdentity {
                dest_hash: DestHash(dest),
                identity_hash: IdentityHash(*identity.hash()),
                public_key: pub_key.unwrap(),
                app_data: None,
                hops: 0,
                received_at: time::now(),
                receiving_interface: InterfaceId(0),
                rssi: Some(-100),
                snr: Some(10.5),
            },
            was_used: false,
            last_used_at: None,
            retained: false,
            stamp: None,
            stamp_value: rns_core::stamp::StampValue::ZERO,
            lr_cost: None,
        },
    );

    // Sign a packet hash with the identity
    let tracked_hash = [0x42u8; 32];
    let sent_time = time::now() - 0.5;
    driver.sent_packets.insert(tracked_hash, (dest, sent_time));

    let signature = identity.sign(&tracked_hash).unwrap();
    let mut proof_data = Vec::new();
    proof_data.extend_from_slice(&tracked_hash);
    proof_data.extend_from_slice(&signature);

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_PROOF,
    };
    let packet =
        RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Valid signature: on_proof should fire
    let proof_list = proofs.lock().unwrap();
    assert_eq!(proof_list.len(), 1);
    assert_eq!(proof_list[0].0, DestHash(dest));
    assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
}

#[test]
fn inbound_proof_with_invalid_signature_rejected() {
    // When known_destinations has the public key, bad signatures are rejected
    let (tx, rx) = event::channel();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    let cbs = MockCallbacks {
        announces: Arc::new(Mutex::new(Vec::new())),
        paths: Arc::new(Mutex::new(Vec::new())),
        deliveries: Arc::new(Mutex::new(Vec::new())),
        iface_ups: Arc::new(Mutex::new(Vec::new())),
        iface_downs: Arc::new(Mutex::new(Vec::new())),
        link_established: Arc::new(Mutex::new(Vec::new())),
        link_closed: Arc::new(Mutex::new(Vec::new())),
        remote_identified: Arc::new(Mutex::new(Vec::new())),
        resources_received: Arc::new(Mutex::new(Vec::new())),
        resource_completed: Arc::new(Mutex::new(Vec::new())),
        resource_failed: Arc::new(Mutex::new(Vec::new())),
        channel_messages: Arc::new(Mutex::new(Vec::new())),
        link_data: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
        proofs: proofs.clone(),
        proof_requested: Arc::new(Mutex::new(Vec::new())),
    };

    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let dest = [0xEE; 16];
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);

    // Create identity and add to known_destinations
    let identity = Identity::new(&mut OsRng);
    let pub_key = identity.get_public_key();
    driver.known_destinations.insert(
        dest,
        KnownDestinationState {
            announced: crate::destination::AnnouncedIdentity {
                dest_hash: DestHash(dest),
                identity_hash: IdentityHash(*identity.hash()),
                public_key: pub_key.unwrap(),
                app_data: None,
                hops: 0,
                received_at: time::now(),
                receiving_interface: InterfaceId(0),
                rssi: Some(-100),
                snr: Some(10.5),
            },
            was_used: false,
            last_used_at: None,
            retained: false,
            stamp: None,
            stamp_value: rns_core::stamp::StampValue::ZERO,
            lr_cost: None,
        },
    );

    // Track a sent packet
    let tracked_hash = [0x42u8; 32];
    let sent_time = time::now() - 0.5;
    driver.sent_packets.insert(tracked_hash, (dest, sent_time));

    // Use WRONG signature (all 0xAA — invalid for this identity)
    let mut proof_data = Vec::new();
    proof_data.extend_from_slice(&tracked_hash);
    proof_data.extend_from_slice(&[0xAA; 64]);

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_PROOF,
    };
    let packet =
        RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Invalid signature: on_proof should NOT fire
    assert!(proofs.lock().unwrap().is_empty());
}

#[test]
fn proof_data_is_valid_explicit_proof() {
    // Verify that the proof generated by ProveAll is a valid explicit proof
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let dest = [0xDD; 16];
    let identity = Identity::new(&mut OsRng);
    let prv_key = identity.get_private_key().unwrap();
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);
    driver.proof_strategies.insert(
        dest,
        (
            rns_core::types::ProofStrategy::ProveAll,
            Some(Identity::from_private_key(&prv_key)),
        ),
    );

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let data_packet =
        RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"verify me").unwrap();
    let data_packet_hash = data_packet.packet_hash;

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: data_packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Find the proof packet in sent
    let sent_packets = sent.lock().unwrap();
    let proof_raw = sent_packets.iter().find(|raw| {
        let f = PacketFlags::unpack(raw[0] & 0x7F);
        f.packet_type == constants::PACKET_TYPE_PROOF
    });
    assert!(proof_raw.is_some(), "Should have sent a proof");

    let proof_packet = RawPacket::unpack(proof_raw.unwrap()).unwrap();
    // Proof data should be 96 bytes: packet_hash(32) + signature(64)
    assert_eq!(
        proof_packet.data().len(),
        96,
        "Explicit proof should be 96 bytes"
    );

    // Validate using rns-core's receipt module
    let result = rns_core::receipt::validate_proof(
        proof_packet.data(),
        &data_packet_hash,
        &Identity::from_private_key(&prv_key), // same identity
    );
    assert_eq!(result, rns_core::receipt::ProofResult::Valid);
}

#[test]
fn query_local_destinations_empty() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let driver_config = TransportConfig {
        transport_enabled: false,
        identity_hash: None,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    };
    let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::LocalDestinations, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::LocalDestinations(entries) => {
            // Should contain the two internal destinations (tunnel_synth + path_request)
            assert_eq!(entries.len(), 2);
            for entry in &entries {
                assert_eq!(entry.dest_type, rns_core::constants::DESTINATION_PLAIN);
            }
        }
        other => panic!("expected LocalDestinations, got {:?}", other),
    }
}

#[test]
fn query_local_destinations_with_registered() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let driver_config = TransportConfig {
        transport_enabled: false,
        identity_hash: None,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    };
    let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

    let dest_hash = [0xAA; 16];
    tx.send(Event::RegisterDestination {
        dest_hash,
        dest_type: rns_core::constants::DESTINATION_SINGLE,
    })
    .unwrap();

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::LocalDestinations, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::LocalDestinations(entries) => {
            // 2 internal + 1 registered
            assert_eq!(entries.len(), 3);
            assert!(entries
                .iter()
                .any(|e| e.hash == dest_hash
                    && e.dest_type == rns_core::constants::DESTINATION_SINGLE));
        }
        other => panic!("expected LocalDestinations, got {:?}", other),
    }
}

#[test]
fn query_local_destinations_tracks_link_dest() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let driver_config = TransportConfig {
        transport_enabled: false,
        identity_hash: None,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    };
    let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

    let dest_hash = [0xBB; 16];
    tx.send(Event::RegisterLinkDestination {
        dest_hash,
        sig_prv_bytes: [0x11; 32],
        sig_pub_bytes: [0x22; 32],
        resource_strategy: 0,
        max_request_size: None,
    })
    .unwrap();

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::LocalDestinations, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::LocalDestinations(entries) => {
            // 2 internal + 1 link destination
            assert_eq!(entries.len(), 3);
            assert!(entries
                .iter()
                .any(|e| e.hash == dest_hash
                    && e.dest_type == rns_core::constants::DESTINATION_SINGLE));
        }
        other => panic!("expected LocalDestinations, got {:?}", other),
    }
}

#[test]
fn query_links_empty() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let driver_config = TransportConfig {
        transport_enabled: false,
        identity_hash: None,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    };
    let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::Links, resp_tx)).unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::Links(entries) => {
            assert!(entries.is_empty());
        }
        other => panic!("expected Links, got {:?}", other),
    }
}

#[test]
fn query_resources_empty() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let driver_config = TransportConfig {
        transport_enabled: false,
        identity_hash: None,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    };
    let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::Resources, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::Resources(entries) => {
            assert!(entries.is_empty());
        }
        other => panic!("expected Resources, got {:?}", other),
    }
}

#[test]
fn infer_interface_type_from_name() {
    assert_eq!(
        super::infer_interface_type("TCPServerInterface/Client-1234"),
        "TCPServerClientInterface"
    );
    assert_eq!(
        super::infer_interface_type("BackboneInterface/5"),
        "BackboneInterface"
    );
    assert_eq!(
        super::infer_interface_type("LocalInterface"),
        "LocalServerClientInterface"
    );
    assert_eq!(
        super::infer_interface_type("MyAutoGroup:fe80::1"),
        "AutoInterface"
    );
}

// ---- extract_dest_hash tests ----

#[test]
fn test_extract_dest_hash_empty() {
    assert_eq!(super::extract_dest_hash(&[]), [0u8; 16]);
}

// =========================================================================
// Probe tests: SendProbe, CheckProof, completed_proofs, probe_responder
// =========================================================================

#[test]
fn send_probe_unknown_dest_returns_none() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // SendProbe for a dest_hash with no known identity should return None
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::SendProbe {
            dest_hash: [0xAA; 16],
            payload_size: 16,
        },
        resp_tx,
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::SendProbe(Err(event::SendProbeError::UnknownIdentity)) => {}
        other => panic!("expected SendProbe(Err(UnknownIdentity)), got {:?}", other),
    }
}

#[test]
fn send_probe_known_dest_returns_packet_hash() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Inject a known identity so SendProbe can encrypt to it
    let remote_identity = Identity::new(&mut OsRng);
    let dest_hash = rns_core::destination::destination_hash(
        "rnstransport",
        &["probe"],
        Some(remote_identity.hash()),
    );

    // First inject the identity via announce
    let inject_response = driver.handle_query_mut(QueryRequest::InjectIdentity {
        dest_hash,
        identity_hash: *remote_identity.hash(),
        public_key: remote_identity.get_public_key().unwrap(),
        app_data: None,
        hops: 1,
        received_at: 0.0,
    });

    // Now send the probe
    let probe_response = driver.handle_query_mut(QueryRequest::SendProbe {
        dest_hash,
        payload_size: 16,
    });

    // Verify injection succeeded
    match inject_response {
        QueryResponse::InjectIdentity(true) => {}
        other => panic!("expected InjectIdentity(true), got {:?}", other),
    }

    // Verify probe sent
    match probe_response {
        QueryResponse::SendProbe(Ok((packet_hash, _hops))) => {
            // Packet hash should be non-zero
            assert_ne!(packet_hash, [0u8; 32]);
            // Should be tracked in sent_packets
            assert!(driver.sent_packets.contains_key(&packet_hash));
            // Should have sent a DATA packet on the wire
            let sent_data = sent.lock().unwrap();
            assert!(!sent_data.is_empty(), "Probe packet should be sent on wire");
            // Verify it's a DATA SINGLE packet
            let raw = &sent_data[0];
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            assert_eq!(flags.packet_type, constants::PACKET_TYPE_DATA);
            assert_eq!(flags.destination_type, constants::DESTINATION_SINGLE);
        }
        other => panic!("expected SendProbe(Ok(..)), got {:?}", other),
    }
}

#[test]
fn send_probe_encrypts_to_the_announced_ratchet() {
    let (mut driver, _) = probe_test_driver();
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    let store = Arc::new(crate::storage::SharedClientRatchetStore::new(None));
    driver.ratchet_store = Some(store.clone());

    let remote_identity = Identity::new(&mut OsRng);
    let dest_hash = rns_core::destination::destination_hash(
        "rnstransport",
        &["probe"],
        Some(remote_identity.hash()),
    );
    let ratchet_private = rns_crypto::x25519::X25519PrivateKey::generate(&mut OsRng);
    let ratchet_public = ratchet_private.public_key().public_bytes();
    crate::storage::RatchetStore::remember(
        store.as_ref(),
        dest_hash,
        crate::storage::RatchetEntry {
            ratchet: ratchet_public,
            received_at: time::now(),
        },
    )
    .unwrap();
    assert!(matches!(
        driver.handle_query_mut(QueryRequest::InjectIdentity {
            dest_hash,
            identity_hash: *remote_identity.hash(),
            public_key: remote_identity.get_public_key().unwrap(),
            app_data: None,
            hops: 1,
            received_at: 0.0,
        }),
        QueryResponse::InjectIdentity(true)
    ));

    match driver.handle_query_mut(QueryRequest::SendProbe {
        dest_hash,
        payload_size: 16,
    }) {
        QueryResponse::SendProbe(Ok(_)) => {}
        other => panic!("expected SendProbe(Ok(..)), got {:?}", other),
    }
    let raw = sent.lock().unwrap()[0].clone();
    let packet = RawPacket::unpack(&raw).unwrap();
    assert!(
        remote_identity.decrypt(packet.data()).is_err(),
        "the probe was encrypted to the identity key, not the announced ratchet"
    );
    let ring =
        rns_crypto::ratchet::RatchetRing::from_keys(vec![ratchet_private.private_bytes()]).unwrap();
    let decrypted = remote_identity
        .decrypt_with_ratchets(packet.data(), &ring, true)
        .unwrap();
    assert_eq!(decrypted.plaintext.len(), 16);
}

fn probe_test_driver() -> (Driver, [u8; 16]) {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    let remote_identity = Identity::new(&mut OsRng);
    let dest_hash = rns_core::destination::destination_hash(
        "rnstransport",
        &["probe"],
        Some(remote_identity.hash()),
    );
    let inject_response = driver.handle_query_mut(QueryRequest::InjectIdentity {
        dest_hash,
        identity_hash: *remote_identity.hash(),
        public_key: remote_identity.get_public_key().unwrap(),
        app_data: None,
        hops: 1,
        received_at: 0.0,
    });
    assert!(matches!(
        inject_response,
        QueryResponse::InjectIdentity(true)
    ));
    (driver, dest_hash)
}

#[test]
fn max_probe_payload_size_is_largest_encrypted_payload_fitting_mtu() {
    // 399 at MTU 500: 19-byte HEADER_1 + 32 ephemeral key + 16 IV + 400
    // padded ciphertext + 32 HMAC = 499 bytes; 400 bytes pads to 416 and
    // produces a 515-byte packet.
    assert_eq!(event::MAX_PROBE_PAYLOAD_SIZE, 399);

    let remote = Identity::new(&mut OsRng);
    let public = Identity::from_public_key(&remote.get_public_key().unwrap()).unwrap();
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let pack = |size: usize| {
        let ciphertext = public.encrypt(&vec![0u8; size], &mut OsRng).unwrap();
        RawPacket::pack(
            flags,
            0,
            &[0x11; 16],
            None,
            constants::CONTEXT_NONE,
            &ciphertext,
        )
    };
    assert!(pack(event::MAX_PROBE_PAYLOAD_SIZE).is_ok());
    assert!(pack(event::MAX_PROBE_PAYLOAD_SIZE + 1).is_err());
}

#[test]
fn send_probe_payload_size_limits() {
    let (mut driver, dest_hash) = probe_test_driver();
    for size in [1, 16, 300, event::MAX_PROBE_PAYLOAD_SIZE] {
        match driver.handle_query_mut(QueryRequest::SendProbe {
            dest_hash,
            payload_size: size,
        }) {
            QueryResponse::SendProbe(Ok(_)) => {}
            other => panic!("size {}: expected SendProbe(Ok(..)), got {:?}", size, other),
        }
    }
    for size in [event::MAX_PROBE_PAYLOAD_SIZE + 1, 400, 1000] {
        match driver.handle_query_mut(QueryRequest::SendProbe {
            dest_hash,
            payload_size: size,
        }) {
            QueryResponse::SendProbe(Err(event::SendProbeError::PayloadTooLarge { max })) => {
                assert_eq!(max, event::MAX_PROBE_PAYLOAD_SIZE);
            }
            other => panic!(
                "size {}: expected SendProbe(Err(PayloadTooLarge)), got {:?}",
                size, other
            ),
        }
    }
}

#[test]
fn check_proof_not_found_returns_none() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::CheckProof {
            packet_hash: [0xBB; 32],
        },
        resp_tx,
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::CheckProof(None) => {}
        other => panic!("expected CheckProof(None), got {:?}", other),
    }
}

#[test]
fn check_proof_found_returns_rtt() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    // Pre-populate completed_proofs
    let packet_hash = [0xCC; 32];
    driver
        .completed_proofs
        .insert(packet_hash, (0.123, time::now()));

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::CheckProof { packet_hash },
        resp_tx,
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::CheckProof(Some(rtt)) => {
            assert!(
                (rtt - 0.123).abs() < 0.001,
                "RTT should be ~0.123, got {}",
                rtt
            );
        }
        other => panic!("expected CheckProof(Some(..)), got {:?}", other),
    }
    // Should be consumed (removed) after checking
    assert!(!driver.completed_proofs.contains_key(&packet_hash));
}

#[test]
fn proof_callback_can_enqueue_outbound_message() {
    let (tx, rx) = event::channel_with_capacity(2);
    let reply_dest = [0x44; 16];
    let reply = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &reply_dest,
        None,
        constants::CONTEXT_NONE,
        b"reply from proof callback",
    )
    .unwrap();
    let mut driver = Driver::new(
        make_transport_config(false),
        rx,
        tx.clone(),
        Box::new(ProofReplyCallbacks {
            tx: tx.clone(),
            reply: reply.raw.clone(),
        }),
    );
    driver.engine.register_interface(make_interface_info(1));
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let tracked_hash = [0xA5; 32];
    let tracked_dest = [0x5A; 16];
    driver
        .sent_packets
        .insert(tracked_hash, (tracked_dest, time::now()));
    let identity = Identity::new(&mut OsRng);
    know_identity(&mut driver, tracked_dest, &identity);
    let mut proof = Vec::with_capacity(96);
    proof.extend_from_slice(&tracked_hash);
    proof.extend_from_slice(&identity.sign(&tracked_hash).unwrap());

    // The callback synchronously enqueues another message. This must happen only
    // after receipt state is released, or callback-driven sends can deadlock.
    driver.handle_inbound_proof(tracked_dest, &proof, &[0; 32]);
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(sent.lock().unwrap().as_slice(), &[reply.raw]);
    assert!(!driver.sent_packets.contains_key(&tracked_hash));
}

#[test]
fn inbound_proof_populates_completed_proofs() {
    let (tx, rx) = event::channel();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    let cbs = MockCallbacks {
        announces: Arc::new(Mutex::new(Vec::new())),
        paths: Arc::new(Mutex::new(Vec::new())),
        deliveries: Arc::new(Mutex::new(Vec::new())),
        iface_ups: Arc::new(Mutex::new(Vec::new())),
        iface_downs: Arc::new(Mutex::new(Vec::new())),
        link_established: Arc::new(Mutex::new(Vec::new())),
        link_closed: Arc::new(Mutex::new(Vec::new())),
        remote_identified: Arc::new(Mutex::new(Vec::new())),
        resources_received: Arc::new(Mutex::new(Vec::new())),
        resource_completed: Arc::new(Mutex::new(Vec::new())),
        resource_failed: Arc::new(Mutex::new(Vec::new())),
        channel_messages: Arc::new(Mutex::new(Vec::new())),
        link_data: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
        proofs: proofs.clone(),
        proof_requested: Arc::new(Mutex::new(Vec::new())),
    };

    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Register a destination with ProveAll so we can get a proof back
    let dest = [0xDD; 16];
    let identity = Identity::new(&mut OsRng);
    let prv_key = identity.get_private_key().unwrap();
    driver
        .engine
        .register_destination(dest, constants::DESTINATION_SINGLE);
    driver.proof_strategies.insert(
        dest,
        (
            rns_core::types::ProofStrategy::ProveAll,
            Some(Identity::from_private_key(&prv_key)),
        ),
    );

    // Build and send a DATA packet to the dest (this creates a sent_packet + proof)
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let data_packet = RawPacket::pack(
        flags,
        0,
        &dest,
        None,
        constants::CONTEXT_NONE,
        b"probe data",
    )
    .unwrap();
    let data_packet_hash = data_packet.packet_hash;

    // Track it as a sent packet so the proof handler recognizes it
    driver
        .sent_packets
        .insert(data_packet_hash, (dest, time::now()));

    // Deliver the frame — this generates a proof which gets sent on wire
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: data_packet.raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // The proof was generated and sent on the wire
    let sent_packets = sent.lock().unwrap();
    let proof_packets: Vec<_> = sent_packets
        .iter()
        .filter(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        })
        .collect();
    assert!(!proof_packets.is_empty(), "Should have sent a proof packet");

    // Now feed the proof packet back to the driver so handle_inbound_proof fires.
    // We need a fresh driver run since the previous one shut down.
    // Instead, verify the data flow: the proof was sent on wire, and when
    // handle_inbound_proof processes a matching proof, completed_proofs gets populated.
    // Since our DATA packet was both delivered locally AND tracked in sent_packets,
    // the proof was generated on delivery. But the proof is for the *sender* to verify --
    // the proof gets sent back to the sender. So in this test (same driver = both sides),
    // the proof was sent on wire but not yet received back.
    //
    // Let's verify handle_inbound_proof directly by feeding the proof frame back.
    let proof_raw = proof_packets[0].clone();
    drop(sent_packets); // release lock

    // Create a new event loop to handle the proof frame
    let (tx2, rx2) = event::channel();
    let proofs2 = Arc::new(Mutex::new(Vec::new()));
    let cbs2 = MockCallbacks {
        announces: Arc::new(Mutex::new(Vec::new())),
        paths: Arc::new(Mutex::new(Vec::new())),
        deliveries: Arc::new(Mutex::new(Vec::new())),
        iface_ups: Arc::new(Mutex::new(Vec::new())),
        iface_downs: Arc::new(Mutex::new(Vec::new())),
        link_established: Arc::new(Mutex::new(Vec::new())),
        link_closed: Arc::new(Mutex::new(Vec::new())),
        remote_identified: Arc::new(Mutex::new(Vec::new())),
        resources_received: Arc::new(Mutex::new(Vec::new())),
        resource_completed: Arc::new(Mutex::new(Vec::new())),
        resource_failed: Arc::new(Mutex::new(Vec::new())),
        channel_messages: Arc::new(Mutex::new(Vec::new())),
        link_data: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
        proofs: proofs2.clone(),
        proof_requested: Arc::new(Mutex::new(Vec::new())),
    };
    let mut driver2 = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx2,
        tx2.clone(),
        Box::new(cbs2),
    );
    let info2 = make_interface_info(1);
    driver2.engine.register_interface(info2);
    let (writer2, _sent2) = MockWriter::new();
    driver2
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer2), true));

    // Track the original sent packet in driver2 so it recognizes the proof,
    // as a probe (SendProbe), whose proof is kept for CheckProof polling.
    driver2
        .sent_packets
        .insert(data_packet_hash, (dest, time::now()));
    driver2.pending_probes.insert(data_packet_hash);
    know_identity(&mut driver2, dest, &identity);

    // Feed the proof frame without shutting down, since shutdown now clears
    // completed proof state.
    driver2.handle_frame_event(InterfaceId(1), proof_raw, Some(-100), Some(10.5));

    // The on_proof callback should have fired
    let proof_events = proofs2.lock().unwrap();
    assert_eq!(proof_events.len(), 1, "on_proof callback should fire once");
    assert_eq!(
        proof_events[0].1 .0, data_packet_hash,
        "proof should match original packet hash"
    );
    assert!(proof_events[0].2 >= 0.0, "RTT should be non-negative");

    // completed_proofs should contain the entry
    assert!(
        driver2.completed_proofs.contains_key(&data_packet_hash),
        "completed_proofs should contain the packet hash"
    );
    let (rtt, _received) = driver2.completed_proofs[&data_packet_hash];
    assert!(rtt >= 0.0, "RTT should be non-negative");
    assert!(driver2.pending_probes.is_empty());
}

#[test]
fn interface_stats_includes_probe_responder() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some([0x42; 16]),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    // Set probe_responder_hash
    driver.probe_responder_hash = Some([0xEE; 16]);

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::InterfaceStats, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::InterfaceStats(stats) => {
            assert_eq!(stats.probe_responder, Some([0xEE; 16]));
        }
        other => panic!("expected InterfaceStats, got {:?}", other),
    }
}

#[test]
fn interface_stats_probe_responder_none_when_disabled() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::InterfaceStats, resp_tx))
        .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::InterfaceStats(stats) => {
            assert_eq!(stats.probe_responder, None);
        }
        other => panic!("expected InterfaceStats, got {:?}", other),
    }
}

#[test]
fn test_extract_dest_hash_too_short() {
    // Packet too short to contain a full dest hash
    assert_eq!(super::extract_dest_hash(&[0x00, 0x00, 0xAA]), [0u8; 16]);
}

#[test]
fn test_extract_dest_hash_header1() {
    // HEADER_1: bit 6 = 0, dest at bytes 2..18
    let mut raw = vec![0x00, 0x00]; // flags (header_type=0), hops
    let dest = [0x11; 16];
    raw.extend_from_slice(&dest);
    raw.extend_from_slice(&[0xFF; 10]); // trailing data
    assert_eq!(super::extract_dest_hash(&raw), dest);
}

#[test]
fn test_extract_dest_hash_header2() {
    // HEADER_2: bit 6 = 1, transport_id at 2..18, dest at 18..34
    let mut raw = vec![0x40, 0x00]; // flags (header_type=1), hops
    raw.extend_from_slice(&[0xAA; 16]); // transport_id (bytes 2..18)
    let dest = [0x22; 16];
    raw.extend_from_slice(&dest); // dest (bytes 18..34)
    raw.extend_from_slice(&[0xFF; 10]); // trailing data
    assert_eq!(super::extract_dest_hash(&raw), dest);
}

#[test]
fn test_extract_dest_hash_header2_too_short() {
    // HEADER_2 packet that's too short for the dest portion
    let mut raw = vec![0x40, 0x00];
    raw.extend_from_slice(&[0xAA; 16]); // transport_id only, no dest
    assert_eq!(super::extract_dest_hash(&raw), [0u8; 16]);
}

#[test]
fn announce_stores_receiving_interface_in_known_destinations() {
    // When an announce arrives on interface 1, the AnnouncedIdentity
    // stored in known_destinations must have receiving_interface == InterfaceId(1).
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);

    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // The identity should be cached with the correct receiving interface
    assert_eq!(driver.known_destinations.len(), 1);
    let (_, announced) = driver.known_destinations.iter().next().unwrap();
    assert_eq!(
        announced.announced.receiving_interface,
        InterfaceId(1),
        "receiving_interface should match the interface the announce arrived on"
    );
}

#[test]
fn frame_from_removed_interface_is_dropped() {
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(false), rx, tx, Box::new(cbs));
    let identity = Identity::new(&mut OsRng);

    driver.handle_frame_event(
        InterfaceId(999),
        build_announce_packet(&identity),
        Some(-100),
        Some(10.5),
    );

    assert!(driver.known_destinations.is_empty());
    assert_eq!(driver.engine.path_table_count(), 0);
}

#[test]
fn announce_on_different_interfaces_stores_correct_id() {
    // Announces arriving on interface 2 should store InterfaceId(2).
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    // Register two interfaces
    for id in [1, 2] {
        driver.engine.register_interface(make_interface_info(id));
        let (writer, _) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(id), make_entry(id, Box::new(writer), true));
    }

    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);

    // Send on interface 2
    tx.send(Event::Frame {
        interface_id: InterfaceId(2),
        data: announce_raw.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert_eq!(driver.known_destinations.len(), 1);
    let (_, announced) = driver.known_destinations.iter().next().unwrap();
    assert_eq!(announced.announced.receiving_interface, InterfaceId(2));
}

#[test]
fn inject_identity_stores_sentinel_interface() {
    // InjectIdentity (used for persistence restore) should store InterfaceId(0)
    // because the identity wasn't received from a real interface.
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let identity = Identity::new(&mut OsRng);
    let dest_hash =
        rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::InjectIdentity {
            dest_hash,
            identity_hash: *identity.hash(),
            public_key: identity.get_public_key().unwrap(),
            app_data: Some(b"restored".to_vec()),
            hops: 2,
            received_at: 99.0,
        },
        resp_tx,
    ))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    match resp_rx.recv().unwrap() {
        QueryResponse::InjectIdentity(true) => {}
        other => panic!("expected InjectIdentity(true), got {:?}", other),
    }

    let announced = driver
        .known_destinations
        .get(&dest_hash)
        .expect("identity should be cached");
    assert_eq!(
        announced.announced.receiving_interface,
        InterfaceId(0),
        "injected identity should have sentinel InterfaceId(0)"
    );
    assert_eq!(announced.announced.dest_hash.0, dest_hash);
    assert_eq!(announced.announced.identity_hash.0, *identity.hash());
    assert_eq!(
        announced.announced.public_key,
        identity.get_public_key().unwrap()
    );
    assert_eq!(announced.announced.app_data, Some(b"restored".to_vec()));
    assert_eq!(announced.announced.hops, 2);
    assert_eq!(announced.announced.received_at, 99.0);
}

#[test]
fn inject_identity_overwrites_previous_entry() {
    // A second InjectIdentity for the same dest_hash should overwrite the first.
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );

    let identity = Identity::new(&mut OsRng);
    let dest_hash =
        rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

    // First injection
    let (resp_tx1, resp_rx1) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::InjectIdentity {
            dest_hash,
            identity_hash: *identity.hash(),
            public_key: identity.get_public_key().unwrap(),
            app_data: Some(b"first".to_vec()),
            hops: 1,
            received_at: 10.0,
        },
        resp_tx1,
    ))
    .unwrap();

    // Second injection with different app_data
    let (resp_tx2, resp_rx2) = mpsc::channel();
    tx.send(Event::query(
        QueryRequest::InjectIdentity {
            dest_hash,
            identity_hash: *identity.hash(),
            public_key: identity.get_public_key().unwrap(),
            app_data: Some(b"second".to_vec()),
            hops: 3,
            received_at: 20.0,
        },
        resp_tx2,
    ))
    .unwrap();

    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(matches!(
        resp_rx1.recv().unwrap(),
        QueryResponse::InjectIdentity(true)
    ));
    assert!(matches!(
        resp_rx2.recv().unwrap(),
        QueryResponse::InjectIdentity(true)
    ));

    // Should have the second injection's data
    let announced = driver.known_destinations.get(&dest_hash).unwrap();
    assert_eq!(announced.announced.app_data, Some(b"second".to_vec()));
    assert_eq!(announced.announced.hops, 3);
    assert_eq!(announced.announced.received_at, 20.0);
}

#[test]
fn re_announce_updates_receiving_interface() {
    // If we get two announces for the same dest from different interfaces,
    // the latest should win (known_destinations is a HashMap keyed by dest_hash).
    let (tx, rx) = event::channel();
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        },
        rx,
        tx.clone(),
        Box::new(cbs),
    );
    for id in [1, 2] {
        driver.engine.register_interface(make_interface_info(id));
        let (writer, _) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(id), make_entry(id, Box::new(writer), true));
    }

    let identity = Identity::new(&mut OsRng);
    let announce_raw = build_announce_packet(&identity);

    // Same announce on interface 1, then interface 2
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: announce_raw.clone().into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    // The second announce of the same identity will be dropped by the transport
    // engine's deduplication (same random_hash). Build a second identity instead
    // to verify the field is correctly set per-announce.
    let identity2 = Identity::new(&mut OsRng);
    let announce_raw2 = build_announce_packet(&identity2);
    tx.send(Event::Frame {
        interface_id: InterfaceId(2),
        data: announce_raw2.into(),
        rssi: Some(-100),
        snr: Some(10.5),
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    // Both should be cached with their respective interface IDs
    assert_eq!(driver.known_destinations.len(), 2);
    for announced in driver.known_destinations.values() {
        // We can't predict ordering, but each should have a valid non-zero interface
        assert!(
            announced.announced.receiving_interface == InterfaceId(1)
                || announced.announced.receiving_interface == InterfaceId(2)
        );
    }
    // Verify we actually got both interfaces represented
    let ifaces: Vec<_> = driver
        .known_destinations
        .values()
        .map(|a| a.announced.receiving_interface)
        .collect();
    assert!(ifaces.contains(&InterfaceId(1)));
    assert!(ifaces.contains(&InterfaceId(2)));
}

#[test]
fn test_extract_dest_hash_other_flags_preserved() {
    // Ensure other flag bits don't affect header type detection
    // 0x3F = all bits set except bit 6 -> still HEADER_1
    let mut raw = vec![0x3F, 0x00];
    let dest = [0x33; 16];
    raw.extend_from_slice(&dest);
    raw.extend_from_slice(&[0xFF; 10]);
    assert_eq!(super::extract_dest_hash(&raw), dest);

    // 0xFF = all bits set including bit 6 -> HEADER_2
    let mut raw2 = vec![0xFF, 0x00];
    raw2.extend_from_slice(&[0xBB; 16]); // transport_id
    let dest2 = [0x44; 16];
    raw2.extend_from_slice(&dest2);
    raw2.extend_from_slice(&[0xFF; 10]);
    assert_eq!(super::extract_dest_hash(&raw2), dest2);
}

#[test]
fn local_ratchets_reconnect_replay_and_writer_queue_retention() {
    let mut driver = new_test_driver();
    let identity = Identity::from_private_key(&[73; 64]);
    let dest = crate::Destination::single_in(
        "test",
        &["ratchet"],
        rns_core::types::IdentityHash(*identity.hash()),
    );
    let owner = crate::LocalRatchets::with_store(
        &dest,
        identity,
        Arc::new(crate::MemoryRatchetStore::default()),
    )
    .unwrap();
    owner.set_interval(1).unwrap();
    owner.set_retained(1).unwrap();
    driver
        .event_tx
        .local_ratchets()
        .lock()
        .unwrap()
        .insert(dest.hash.0, owner.clone());
    let record = SharedAnnounceRecord {
        name_hash: rns_core::destination::name_hash("test", &["ratchet"]),
        identity_prv_key: [73; 64],
        app_data: Some(b"replay".to_vec()),
    };
    let raw = driver
        .build_shared_announce_raw(&dest.hash.0, &record, true)
        .unwrap();
    let packet = RawPacket::unpack(&raw).unwrap();
    assert_eq!(packet.flags.context_flag, constants::FLAG_SET);
    assert_eq!(packet.context, constants::CONTEXT_PATH_RESPONSE);
    let announce = AnnounceData::unpack(packet.data(), true).unwrap();
    announce.validate(&dest.hash.0).unwrap();
    assert_eq!(announce.ratchet, owner.current_public());
    struct RatchetWriter {
        held: Arc<Mutex<Vec<crate::link_send::Completion>>>,
        blocked: bool,
    }
    impl Writer for RatchetWriter {
        fn send_frame(&mut self, _: &[u8]) -> io::Result<()> {
            panic!("ratchet bypassed writer completion")
        }
        fn enqueue_confirmed(
            &mut self,
            _: &[u8],
            completion: &mut Option<crate::link_send::Completion>,
        ) -> io::Result<()> {
            if self.blocked {
                self.blocked = false;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.held.lock().unwrap().push(completion.take().unwrap());
            Ok(())
        }
    }
    let held = Arc::new(Mutex::new(Vec::new()));
    let writer = RatchetWriter {
        held: held.clone(),
        blocked: true,
    };
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    let permit = driver.event_tx.link_send_pool().try_acquire().unwrap();
    let (completion, _receipt) = crate::link_send::Completion::new(permit);
    driver.tracked_link_send = Some((packet.packet_hash, completion));
    driver.dispatch_send_on_interface_action(InterfaceId(1), raw.clone().into(), &mut Vec::new());
    assert_eq!(driver.pending_link_frames.len(), 1);
    let future = time::now() as u64 + 10;
    assert_eq!(
        owner.public_for_announce(future).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    driver.flush_pending_link_frames();
    assert_eq!(driver.pending_link_frames.len(), 1);
    assert_eq!(
        owner.public_for_announce(future).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    driver.flush_pending_link_frames();
    assert!(driver.pending_link_frames.is_empty());
    assert_eq!(
        owner.public_for_announce(future).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    held.lock().unwrap().clear();
    owner.public_for_announce(future).unwrap();
    let writer = RatchetWriter {
        held: held.clone(),
        blocked: false,
    };
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    driver.dispatch_send_on_interface_action(InterfaceId(1), raw.into(), &mut Vec::new());
    assert!(
        held.lock().unwrap().is_empty(),
        "cached retired key must not be sent"
    );
    let fresh = driver
        .build_shared_announce_raw(&dest.hash.0, &record, true)
        .unwrap();
    driver.dispatch_send_on_interface_action(InterfaceId(1), fresh.into(), &mut Vec::new());
    driver.flush_pending_link_frames();
    assert_eq!(held.lock().unwrap().len(), 1);
}

#[cfg(feature = "hooks")]
mod hook_modify {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HOOK_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn attach_hook(driver: &mut Driver, point: HookPoint, hook: impl rns_hooks::BuiltinHook) {
        let id = format!(
            "test.driver.hook_modify.{}.{}",
            std::process::id(),
            HOOK_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        rns_hooks::register_builtin_hook(id.clone(), hook).unwrap();
        let program = driver
            .hook_manager
            .as_ref()
            .expect("hook manager")
            .load_builtin(id.clone(), id.as_str(), 0)
            .unwrap();
        driver.hook_slots[point as usize].attach(program);
    }

    /// A hook that answers every call with `Modify` and the given bytes.
    fn attach_replacing_hook(driver: &mut Driver, point: HookPoint, replacement: Vec<u8>) {
        attach_hook(
            driver,
            point,
            move |_call: rns_hooks::BuiltinHookCall<'_>, host: &mut rns_hooks::BuiltinHookHost| {
                host.set_modified_data(replacement.clone());
                Ok(rns_hooks::HookResult::modify_result(0, 0))
            },
        );
    }

    /// A hook that records the packet hash it was handed and continues.
    fn attach_hash_recorder(driver: &mut Driver, point: HookPoint) -> Arc<Mutex<Vec<[u8; 32]>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        attach_hook(
            driver,
            point,
            move |call: rns_hooks::BuiltinHookCall<'_>, _host: &mut rns_hooks::BuiltinHookHost| {
                if let HookContext::Packet { ctx, .. } = call.ctx {
                    recorded.lock().unwrap().push(ctx.packet_hash);
                }
                Ok(rns_hooks::HookResult::continue_result())
            },
        );
        seen
    }

    fn data_packet(dest: [u8; 16], payload: &[u8]) -> RawPacket {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, payload).unwrap()
    }

    /// A well-formed header followed by enough payload to exceed the MTU.
    fn oversize_packet_bytes(dest: [u8; 16]) -> Vec<u8> {
        let mut raw = vec![0x00, 0x00];
        raw.extend_from_slice(&dest);
        raw.push(constants::CONTEXT_NONE);
        raw.resize(constants::MTU + 1, 0x42);
        assert!(RawPacket::unpack(&raw).is_ok());
        raw
    }

    fn driver_with_sender() -> (Driver, Arc<Mutex<Vec<Vec<u8>>>>) {
        let mut driver = new_test_driver();
        driver.engine.register_interface(make_interface_info(1));
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
        (driver, sent)
    }

    fn driver_with_local_destinations(dests: &[[u8; 16]]) -> (Driver, Arc<Mutex<Vec<DestHash>>>) {
        let (callbacks, _, _, deliveries, _, _) = MockCallbacks::new();
        let (tx, rx) = event::channel();
        let mut driver = Driver::new(make_transport_config(false), rx, tx, Box::new(callbacks));
        driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
        driver.engine.register_interface(make_interface_info(1));
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
        for dest in dests {
            driver
                .engine
                .register_destination(*dest, constants::DESTINATION_SINGLE);
        }
        (driver, deliveries)
    }

    fn rejected(driver: &Driver, point: HookPoint) -> u64 {
        driver.hook_rejected_modifications[point as usize]
    }

    #[test]
    fn send_hook_replacement_is_sent_instead_of_the_original() {
        let (mut driver, sent) = driver_with_sender();
        let original = data_packet([0x11; 16], b"first");
        let replacement = data_packet([0x22; 16], b"second");
        attach_replacing_hook(
            &mut driver,
            HookPoint::SendOnInterface,
            replacement.raw.clone(),
        );

        driver.dispatch_send_on_interface_action(
            InterfaceId(1),
            original.raw.clone().into(),
            &mut Vec::new(),
        );

        assert_eq!(sent.lock().unwrap().as_slice(), &[replacement.raw]);
        assert_eq!(rejected(&driver, HookPoint::SendOnInterface), 0);
    }

    #[test]
    fn broadcast_hook_replacement_is_sent_instead_of_the_original() {
        let (mut driver, sent) = driver_with_sender();
        let original = data_packet([0x11; 16], b"first");
        let replacement = data_packet([0x22; 16], b"second");
        attach_replacing_hook(
            &mut driver,
            HookPoint::BroadcastOnAllInterfaces,
            replacement.raw.clone(),
        );

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: original.raw.clone().into(),
            exclude: None,
        }]);

        assert_eq!(sent.lock().unwrap().as_slice(), &[replacement.raw]);
        assert_eq!(rejected(&driver, HookPoint::BroadcastOnAllInterfaces), 0);
    }

    #[test]
    fn send_hook_replacement_that_fails_validation_is_dropped_and_counted() {
        let cases: [(&str, Vec<u8>); 4] = [
            ("empty", Vec::new()),
            ("too short", vec![0x00, 0x00, 0x01]),
            ("hop count out of range", {
                let mut raw = data_packet([0x22; 16], b"second").raw;
                raw[1] = constants::PATHFINDER_M;
                raw
            }),
            ("over the interface MTU", oversize_packet_bytes([0x22; 16])),
        ];
        for (name, replacement) in cases {
            let (mut driver, sent) = driver_with_sender();
            attach_replacing_hook(&mut driver, HookPoint::SendOnInterface, replacement);

            driver.dispatch_send_on_interface_action(
                InterfaceId(1),
                data_packet([0x11; 16], b"first").raw.into(),
                &mut Vec::new(),
            );

            assert!(sent.lock().unwrap().is_empty(), "{name}: nothing is sent");
            assert_eq!(
                rejected(&driver, HookPoint::SendOnInterface),
                1,
                "{name}: the replacement is counted"
            );
        }
    }

    #[test]
    fn modify_without_replacement_bytes_sends_the_original() {
        let (mut driver, sent) = driver_with_sender();
        attach_hook(
            &mut driver,
            HookPoint::SendOnInterface,
            |_call: rns_hooks::BuiltinHookCall<'_>, _host: &mut rns_hooks::BuiltinHookHost| {
                Ok(rns_hooks::HookResult::modify_result(0, 0))
            },
        );
        let original = data_packet([0x11; 16], b"first");

        driver.dispatch_send_on_interface_action(
            InterfaceId(1),
            original.raw.clone().into(),
            &mut Vec::new(),
        );

        assert_eq!(sent.lock().unwrap().as_slice(), &[original.raw]);
        assert_eq!(rejected(&driver, HookPoint::SendOnInterface), 0);
    }

    #[test]
    fn pre_ingress_replacement_is_decoded_and_delivered_with_its_own_hash() {
        let first = [0x31; 16];
        let second = [0x32; 16];
        let (mut driver, deliveries) = driver_with_local_destinations(&[first, second]);
        let original = data_packet(first, b"first");
        let replacement = data_packet(second, b"second");
        attach_replacing_hook(&mut driver, HookPoint::PreIngress, replacement.raw.clone());
        let delivered_hashes = attach_hash_recorder(&mut driver, HookPoint::DeliverLocal);

        driver.handle_frame_event(InterfaceId(1), original.raw.clone(), None, None);

        assert_eq!(deliveries.lock().unwrap().as_slice(), &[DestHash(second)]);
        assert_eq!(
            delivered_hashes.lock().unwrap().as_slice(),
            &[replacement.packet_hash]
        );
        assert_eq!(rejected(&driver, HookPoint::PreIngress), 0);
    }

    #[test]
    fn pre_ingress_replacement_that_fails_validation_is_dropped_and_counted() {
        let first = [0x31; 16];
        let (mut driver, deliveries) = driver_with_local_destinations(&[first]);
        attach_replacing_hook(&mut driver, HookPoint::PreIngress, vec![0x00]);

        driver.handle_frame_event(InterfaceId(1), data_packet(first, b"first").raw, None, None);

        assert!(deliveries.lock().unwrap().is_empty());
        assert_eq!(rejected(&driver, HookPoint::PreIngress), 1);
    }

    #[test]
    fn pre_ingress_replacement_still_passes_admission_checks() {
        let first = [0x31; 16];
        let (mut driver, deliveries) = driver_with_local_destinations(&[first]);
        // A path request without a tag is refused on receipt, so it is refused
        // as a replacement too.
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let tagless = RawPacket::pack(
            flags,
            0,
            &driver.path_request_dest,
            None,
            constants::CONTEXT_NONE,
            &[0x44; 16],
        )
        .unwrap();
        attach_replacing_hook(&mut driver, HookPoint::PreIngress, tagless.raw);

        driver.handle_frame_event(InterfaceId(1), data_packet(first, b"first").raw, None, None);

        assert!(deliveries.lock().unwrap().is_empty());
        assert_eq!(
            driver.interfaces[&InterfaceId(1)].stats.protocol_violations,
            1
        );
    }

    #[test]
    fn deliver_local_replacement_is_delivered_to_its_own_destination() {
        let first = [0x31; 16];
        let second = [0x32; 16];
        let (mut driver, deliveries) = driver_with_local_destinations(&[first, second]);
        let original = data_packet(first, b"first");
        let replacement = data_packet(second, b"second");
        attach_replacing_hook(
            &mut driver,
            HookPoint::DeliverLocal,
            replacement.raw.clone(),
        );

        driver.handle_frame_event(InterfaceId(1), original.raw.clone(), None, None);

        assert_eq!(deliveries.lock().unwrap().as_slice(), &[DestHash(second)]);
        assert_eq!(rejected(&driver, HookPoint::DeliverLocal), 0);
    }

    #[test]
    fn pre_dispatch_modify_acts_as_continue() {
        let first = [0x31; 16];
        let second = [0x32; 16];
        let (mut driver, deliveries) = driver_with_local_destinations(&[first, second]);
        attach_replacing_hook(
            &mut driver,
            HookPoint::PreDispatch,
            data_packet(second, b"second").raw,
        );

        driver.handle_frame_event(InterfaceId(1), data_packet(first, b"first").raw, None, None);

        assert_eq!(deliveries.lock().unwrap().as_slice(), &[DestHash(first)]);
        assert_eq!(rejected(&driver, HookPoint::PreDispatch), 0);
    }

    #[test]
    fn tick_modify_acts_as_continue() {
        let (mut driver, sent) = driver_with_sender();
        attach_replacing_hook(&mut driver, HookPoint::Tick, vec![0x00]);

        driver.handle_tick_event();

        assert!(sent.lock().unwrap().is_empty());
        assert_eq!(rejected(&driver, HookPoint::Tick), 0);
    }
}

// ---- Path requests for local destinations (Transport.py:3450-3457) ----

fn local_path_request_frame(driver: &Driver, dest: &[u8; 16], tag: &[u8; 16]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(dest);
    // Requesting transport instance id + tag, as a transport node sends it.
    data.extend_from_slice(&[0x77; 16]);
    data.extend_from_slice(tag);
    RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &driver.path_request_dest,
        None,
        constants::CONTEXT_NONE,
        &data,
    )
    .unwrap()
    .raw
}

struct LocalPathResponseFixture {
    driver: Driver,
    tx: crate::event::EventSender,
    sent_1: Arc<Mutex<Vec<Vec<u8>>>>,
    sent_2: Arc<Mutex<Vec<Vec<u8>>>>,
    probe_dest: [u8; 16],
    mgmt_dest: [u8; 16],
    app_dest: [u8; 16],
}

/// A transport driver hosting the probe responder, the management
/// destination and an in-process app destination that was announced once.
/// With `via_events`, the app destination is registered and its announce
/// record stored through queued node API events, applied by `run()`.
fn local_path_response_fixture(via_events: bool) -> LocalPathResponseFixture {
    let (tx, rx) = event::channel();
    let (callbacks, _, _, _, _, _) = MockCallbacks::new();
    let transport_identity = Identity::new(&mut OsRng);
    let mut config = make_transport_config(true);
    config.identity_hash = Some(*transport_identity.hash());
    let mut driver = Driver::new(config, rx, tx.clone(), Box::new(callbacks));
    unstamped(&mut driver);
    let (writer_1, sent_1) = MockWriter::new();
    let (writer_2, sent_2) = MockWriter::new();
    for (id, writer) in [(1, writer_1), (2, writer_2)] {
        driver.engine.register_interface(make_interface_info(id));
        driver
            .interfaces
            .insert(InterfaceId(id), make_entry(id, Box::new(writer), true));
    }
    driver.transport_identity = Some(Identity::from_private_key(
        &transport_identity.get_private_key().unwrap(),
    ));

    // Built-in destinations, registered as node.rs does.
    let probe_dest = crate::management::probe_dest_hash(transport_identity.hash());
    let mgmt_dest = crate::management::management_dest_hash(transport_identity.hash());
    for dest in [probe_dest, mgmt_dest] {
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver
            .local_destinations
            .insert(dest, constants::DESTINATION_SINGLE);
    }
    driver.probe_responder_hash = Some(probe_dest);
    driver.management_config.enable_remote_management = true;

    // In-process app destination, registered and announced via the node API.
    let app_identity = Identity::new(&mut OsRng);
    let app_dest =
        rns_core::destination::destination_hash("pathresp", &["svc"], Some(app_identity.hash()));
    let name_hash = rns_core::destination::name_hash("pathresp", &["svc"]);
    let identity_prv_key = app_identity.get_private_key().unwrap();
    let app_data = Some(b"hello".to_vec());
    if via_events {
        tx.send(Event::RegisterDestination {
            dest_hash: app_dest,
            dest_type: constants::DESTINATION_SINGLE,
        })
        .unwrap();
        tx.send(Event::StoreSharedAnnounce {
            dest_hash: app_dest,
            name_hash,
            identity_prv_key,
            app_data,
        })
        .unwrap();
    } else {
        driver
            .engine
            .register_destination(app_dest, constants::DESTINATION_SINGLE);
        driver
            .local_destinations
            .insert(app_dest, constants::DESTINATION_SINGLE);
        driver.shared_announces.insert(
            app_dest,
            SharedAnnounceRecord {
                name_hash,
                identity_prv_key,
                app_data,
            },
        );
    }

    LocalPathResponseFixture {
        driver,
        tx,
        sent_1,
        sent_2,
        probe_dest,
        mgmt_dest,
        app_dest,
    }
}

fn path_responses_for(frames: &[Vec<u8>], dest: &[u8; 16]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .filter(|raw| {
            RawPacket::unpack(raw).is_ok_and(|p| {
                p.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
                    && p.destination_hash == *dest
                    && p.context == constants::CONTEXT_PATH_RESPONSE
            })
        })
        .cloned()
        .collect()
}

fn is_announce(raw: &[u8]) -> bool {
    RawPacket::unpack(raw).is_ok_and(|p| p.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE)
}

#[test]
fn transport_node_answers_path_requests_for_local_destinations() {
    let LocalPathResponseFixture {
        mut driver,
        tx,
        sent_1,
        sent_2,
        probe_dest,
        mgmt_dest,
        app_dest,
    } = local_path_response_fixture(true);
    let unknown_dest = [0x5E; 16];

    for (dest, tag) in [
        (probe_dest, [0xA1; 16]),
        (mgmt_dest, [0xA2; 16]),
        (app_dest, [0xB2; 16]),
        (unknown_dest, [0xC3; 16]),
    ] {
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: local_path_request_frame(&driver, &dest, &tag).into(),
            rssi: None,
            snr: None,
        })
        .unwrap();
    }
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let frames_1 = sent_1.lock().unwrap().clone();
    let frames_2 = sent_2.lock().unwrap().clone();
    for dest in [probe_dest, mgmt_dest, app_dest] {
        let answers = path_responses_for(&frames_1, &dest);
        assert_eq!(
            answers.len(),
            1,
            "expected one path response for {dest:02x?}"
        );
        let packet = RawPacket::unpack(&answers[0]).unwrap();
        let announce = AnnounceData::unpack(packet.data(), false).unwrap();
        assert!(announce.validate(&dest).is_ok());
    }
    assert!(
        !frames_2.iter().any(|raw| is_announce(raw)),
        "path responses must go out on the requesting interface only"
    );
    let app_answer = RawPacket::unpack(&path_responses_for(&frames_1, &app_dest)[0]).unwrap();
    let app_announce = AnnounceData::unpack(app_answer.data(), false).unwrap();
    assert_eq!(app_announce.app_data.as_deref(), Some(&b"hello"[..]));
    // A path request for a destination this node does not host draws no
    // announce for it.
    assert!(!frames_1.iter().any(|raw| RawPacket::unpack(raw)
        .is_ok_and(|p| p.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
            && p.destination_hash == unknown_dest)));
}

/// A destination registered with its identity but never announced is
/// announced on demand for a path request, as upstream does: before, a
/// listener such as `rncp -l` without `-b` could not be reached by a peer
/// that had not heard it announce (found over LoRa with a Python peer).
#[test]
fn path_request_for_a_never_announced_registered_destination_is_answered() {
    let LocalPathResponseFixture {
        mut driver,
        tx,
        sent_1,
        ..
    } = local_path_response_fixture(true);
    let identity = Identity::new(&mut OsRng);
    let dest =
        rns_core::destination::destination_hash("quiet", &["listener"], Some(identity.hash()));
    tx.send(Event::RegisterDestination {
        dest_hash: dest,
        dest_type: constants::DESTINATION_SINGLE,
    })
    .unwrap();
    tx.send(Event::RegisterPathResponder {
        destination: Box::new(crate::destination::Destination::single_in(
            "quiet",
            &["listener"],
            rns_core::types::IdentityHash(*identity.hash()),
        )),
        identity_prv_key: identity.get_private_key().unwrap(),
    })
    .unwrap();
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: local_path_request_frame(&driver, &dest, &[0xD4; 16]).into(),
        rssi: None,
        snr: None,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let frames = sent_1.lock().unwrap().clone();
    let answers = path_responses_for(&frames, &dest);
    assert_eq!(answers.len(), 1, "expected one path response");
    let packet = RawPacket::unpack(&answers[0]).unwrap();
    let announce = AnnounceData::unpack(packet.data(), false).unwrap();
    assert!(announce.validate(&dest).is_ok());
    assert!(announce.app_data.is_none());
    // The key only answers path requests: it is not a shared-client replay
    // record, so a reconnect does not start announcing the destination.
    assert!(!driver.shared_announces.contains_key(&dest));
}

#[test]
fn local_path_response_replays_identical_bytes_for_repeated_tag() {
    let LocalPathResponseFixture {
        mut driver,
        sent_1,
        sent_2,
        probe_dest,
        mgmt_dest,
        app_dest,
        ..
    } = local_path_response_fixture(false);

    let answer = |driver: &mut Driver, dest: [u8; 16], tag: &[u8]| {
        sent_1.lock().unwrap().clear();
        driver.dispatch_all(vec![TransportAction::AnnounceLocalPathResponse {
            destination_hash: dest,
            tag: tag.to_vec(),
            interface: InterfaceId(1),
        }]);
        let answers = path_responses_for(&sent_1.lock().unwrap(), &dest);
        assert_eq!(answers.len(), 1, "expected one path response");
        answers[0].clone()
    };

    for dest in [probe_dest, mgmt_dest, app_dest] {
        let first = answer(&mut driver, dest, &[0x11; 16]);
        let repeat = answer(&mut driver, dest, &[0x11; 16]);
        assert_eq!(first, repeat, "repeated tag must replay identical bytes");
        let other_tag = answer(&mut driver, dest, &[0x22; 16]);
        assert_ne!(first, other_tag, "a new tag builds a fresh announce");
    }
    assert!(!sent_2.lock().unwrap().iter().any(|raw| is_announce(raw)));

    // Entries expire after the replay window.
    assert_eq!(driver.local_path_responses.len(), 6);
    let later = time::now() + Driver::LOCAL_PATH_RESPONSE_WINDOW + 1.0;
    driver.expire_local_path_responses(later);
    assert!(driver.local_path_responses.is_empty());

    // The cache is bounded.
    for i in 0..(Driver::LOCAL_PATH_RESPONSE_MAX_ENTRIES + 5) {
        let tag = (i as u32).to_be_bytes();
        driver.dispatch_all(vec![TransportAction::AnnounceLocalPathResponse {
            destination_hash: probe_dest,
            tag: tag.to_vec(),
            interface: InterfaceId(1),
        }]);
    }
    assert_eq!(
        driver.local_path_responses.len(),
        Driver::LOCAL_PATH_RESPONSE_MAX_ENTRIES
    );
}

#[test]
fn registered_but_never_announced_destination_is_not_answered() {
    let LocalPathResponseFixture {
        mut driver,
        tx,
        sent_1,
        ..
    } = local_path_response_fixture(false);
    let never_announced = [0x6D; 16];
    tx.send(Event::RegisterDestination {
        dest_hash: never_announced,
        dest_type: constants::DESTINATION_SINGLE,
    })
    .unwrap();
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: local_path_request_frame(&driver, &never_announced, &[0xD4; 16]).into(),
        rssi: None,
        snr: None,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    assert!(!sent_1.lock().unwrap().iter().any(|raw| is_announce(raw)));
    assert!(driver.local_path_responses.is_empty());
}

// =========================================================================
// Stamped link requests
// =========================================================================

/// Driver with one online interface whose outbound frames are captured, and a
/// known destination `dest` learnt on that interface with the given announced
/// link request cost.
fn stamped_link_driver(
    tx: event::EventSender,
    rx: event::EventReceiver,
    dest: [u8; 16],
    lr_cost: Option<u8>,
) -> (Driver, Arc<Mutex<Vec<Vec<u8>>>>) {
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(false), rx, tx, Box::new(cbs));
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
    driver.engine.register_interface(make_interface_info(1));
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    let mut state = make_known_destination_state(dest, time::now(), InterfaceId(1));
    state.lr_cost = lr_cost.map(|cost| StampCost::from_whole(u32::from(cost)));
    driver.known_destinations.insert(dest, state);
    (driver, sent)
}

#[test]
fn create_link_is_not_stamped_when_stamp_lrs_is_off() {
    // Link.__init__ defers to a stamped key only `if self.stamp_cost and
    // RNS.Transport.STAMP_LRS` (Link.py:313).
    let (tx, rx) = event::channel();
    let dest = [0x69; 16];
    let (mut driver, sent) = stamped_link_driver(tx, rx, dest, Some(4));
    assert!(driver.stamp_settings.stamp_lrs);
    driver.stamp_settings.stamp_lrs = false;

    let (resp_tx, resp_rx) = mpsc::channel();
    driver.handle_create_link(dest, [0xAA; 32], resp_tx);
    let link_id = resp_rx
        .try_recv()
        .expect("an unstamped link is answered synchronously");
    assert_ne!(link_id, [0u8; 16]);
    driver.flush_pending_link_frames();
    driver.flush_writers();
    assert!(sent_link_request(&sent.lock().unwrap(), dest).is_some());
}

#[test]
fn create_link_is_not_stamped_when_zero_is_announced_even_with_always_stamp_lrs() {
    // 34bb4ac8: only a missing cost falls back to LR_COST, so an announced 0
    // leaves `stamp_cost` falsy and the request unstamped.
    let (tx, rx) = event::channel();
    let dest = [0x6C; 16];
    let (mut driver, sent) = stamped_link_driver(tx, rx, dest, Some(0));
    driver.stamp_settings.always_stamp_lrs = true;

    let (resp_tx, resp_rx) = mpsc::channel();
    driver.handle_create_link(dest, [0xAA; 32], resp_tx);
    let link_id = resp_rx
        .try_recv()
        .expect("an unstamped link is answered synchronously");
    assert_ne!(link_id, [0u8; 16]);
    driver.flush_pending_link_frames();
    driver.flush_writers();
    assert!(sent_link_request(&sent.lock().unwrap(), dest).is_some());
}

#[test]
fn outbound_link_stamp_cost_prefers_the_announced_cost() {
    // Link.__init__ since 34bb4ac8: the announced cost, else LR_COST when
    // ALWAYS_STAMP_LRS is set and nothing was announced.
    let dest = [0x6A; 16];
    let lr_cost = rns_core::constants::LINK_REQUEST_STAMP_COST;
    let cases = [
        (Some(4), false, Some(StampCost::from_whole(4))),
        (Some(4), true, Some(StampCost::from_whole(4))),
        (None, false, None),
        (None, true, Some(lr_cost)),
        // An announced zero is kept (`== None`, not falsy), and
        // `handle_create_link` then sends the request unstamped.
        (Some(0), false, Some(StampCost::ZERO)),
        (Some(0), true, Some(StampCost::ZERO)),
    ];
    for (announced, always, expected) in cases {
        let (tx, rx) = event::channel();
        let (mut driver, _sent) = stamped_link_driver(tx, rx, dest, announced);
        driver.stamp_settings.always_stamp_lrs = always;
        assert_eq!(
            driver.outbound_link_stamp_cost(&dest),
            expected,
            "announced {announced:?}, always_stamp_lrs {always}"
        );
    }

    // The fallback is the local, configurable LR_COST, fraction included.
    let (tx, rx) = event::channel();
    let (mut driver, _sent) = stamped_link_driver(tx, rx, dest, None);
    driver.stamp_settings.always_stamp_lrs = true;
    driver
        .link_manager
        .link_request_costs()
        .set_default_cost(StampCost::from_whole(3));
    assert_eq!(
        driver.outbound_link_stamp_cost(&dest),
        Some(StampCost::from_whole(3))
    );
}

#[test]
fn create_link_is_stamped_without_an_announced_cost_when_always_stamp_lrs_is_set() {
    let (tx, rx) = event::channel();
    let dest = [0x6B; 16];
    let (mut driver, sent) = stamped_link_driver(tx.clone(), rx, dest, None);
    driver.stamp_settings.always_stamp_lrs = true;
    driver
        .link_manager
        .link_request_costs()
        .set_default_cost(StampCost::from_whole(4));

    let (resp_tx, resp_rx) = mpsc::channel();
    driver.handle_create_link(dest, [0xAA; 32], resp_tx);
    // The stamped key is ground off the driver thread.
    assert!(matches!(resp_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));

    shutdown_after(tx, Duration::from_secs(2));
    driver.run();
    driver.flush_pending_link_frames();
    driver.flush_writers();
    let link_id = resp_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_ne!(link_id, [0u8; 16]);
    let request = sent_link_request(&sent.lock().unwrap(), dest).expect("LINKREQUEST sent");
    let value = rns_core::link::handshake::link_request_stamp_value(&dest, request.data())
        .expect("link request parses");
    assert!(value.meets(StampCost::from_whole(4)));
}

#[test]
fn create_link_uses_the_configured_link_stamp_timeout() {
    // `[stamps] lr_stamp_timeout` bounds the stamped key grind
    // (Transport.LINK_STAMP_TIMEOUT); an unattainable cost then fails the
    // link with the all-zero id instead of grinding for the default 15 s.
    let (tx, rx) = event::channel();
    let dest = [0x68; 16];
    let (mut driver, _sent) =
        stamped_link_driver(tx, rx, dest, Some(rns_core::constants::LINK_COST_CAP));
    driver.stamp_settings.lr_stamp_timeout = rns_core::constants::STAMP_TIMEOUT_MIN;

    let (resp_tx, resp_rx) = mpsc::channel();
    let started = Instant::now();
    driver.handle_create_link(dest, [0xAA; 32], resp_tx);
    assert_eq!(
        resp_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        [0u8; 16]
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(driver.link_manager.link_count(), 0);
}

fn sent_link_request(sent: &[Vec<u8>], dest: [u8; 16]) -> Option<RawPacket> {
    sent.iter()
        .filter_map(|raw| RawPacket::unpack(raw).ok())
        .find(|packet| {
            packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
                && packet.destination_hash == dest
        })
}

fn shutdown_after(tx: event::EventSender, delay: Duration) {
    thread::spawn(move || {
        thread::sleep(delay);
        let _ = tx.send(Event::Shutdown);
    });
}

#[test]
fn create_link_without_announced_cost_is_answered_synchronously() {
    for lr_cost in [None, Some(0)] {
        let (tx, rx) = event::channel();
        let dest = [0x6A; 16];
        let (mut driver, sent) = stamped_link_driver(tx, rx, dest, lr_cost);

        let (resp_tx, resp_rx) = mpsc::channel();
        driver.handle_create_link(dest, [0xAA; 32], resp_tx);

        // No stamp work: the link exists and the caller is answered before the
        // handler returns.
        let link_id = resp_rx
            .try_recv()
            .unwrap_or_else(|_| panic!("lr_cost {lr_cost:?}: no synchronous answer"));
        assert_ne!(link_id, [0u8; 16]);
        assert_eq!(driver.link_manager.link_count(), 1);
        assert_eq!(
            driver.link_manager.link_state(&link_id),
            Some(rns_core::link::LinkState::Pending)
        );
        driver.flush_pending_link_frames();
        driver.flush_writers();
        assert!(sent_link_request(&sent.lock().unwrap(), dest).is_some());
    }
}

#[test]
fn create_link_with_announced_cost_defers_until_the_worker_reports() {
    let (tx, rx) = event::channel();
    let dest = [0x6B; 16];
    let (mut driver, sent) = stamped_link_driver(tx.clone(), rx, dest, Some(4));

    let (resp_tx, resp_rx) = mpsc::channel();
    let started = Instant::now();
    driver.handle_create_link(dest, [0xAA; 32], resp_tx);
    assert!(started.elapsed() < Duration::from_secs(1));

    // Nothing happens on the driver thread until the worker posts the keys.
    assert!(matches!(resp_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert_eq!(driver.link_manager.link_count(), 0);
    driver.flush_pending_link_frames();
    driver.flush_writers();
    assert!(sent.lock().unwrap().is_empty());

    // Running the event loop delivers the worker's CompleteStampedLink.
    shutdown_after(tx, Duration::from_secs(2));
    driver.run();
    driver.flush_pending_link_frames();
    driver.flush_writers();
    let link_id = resp_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_ne!(link_id, [0u8; 16]);
    let request = sent_link_request(&sent.lock().unwrap(), dest).expect("LINKREQUEST sent");
    let value = rns_core::link::handshake::link_request_stamp_value(&dest, request.data())
        .expect("link request parses");
    assert!(value.meets(StampCost::from_whole(4)));
}

#[test]
fn stamped_link_request_timeout_fails_the_link_without_blocking_the_driver() {
    let mut driver = new_test_driver();
    let (resp_tx, resp_rx) = mpsc::channel();
    let started = Instant::now();
    // Cost 100 is unattainable; an already-expired deadline must make the
    // worker give up and answer with the all-zero link id (STAMP_FAILURE).
    driver.spawn_stamped_link_keys(
        [0x6D; 16],
        [0xAA; 32],
        StampCost::from_whole(100),
        Duration::ZERO,
        resp_tx,
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "stamp work must not run on the driver thread"
    );
    assert_eq!(
        resp_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        [0u8; 16]
    );
    assert_eq!(driver.link_manager.link_count(), 0);
}

#[test]
fn create_link_with_announced_cost_stamps_off_thread_and_completes() {
    let (tx, rx) = event::channel();
    let dest = [0x6C; 16];
    let (mut driver, sent) = stamped_link_driver(tx.clone(), rx, dest, Some(4));

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::CreateLink {
        dest_hash: dest,
        dest_sig_pub_bytes: [0xAA; 32],
        response_tx: resp_tx,
    })
    .unwrap();
    // The completion event is posted by the worker well within this delay;
    // the control queue is FIFO, so it is handled before the shutdown.
    shutdown_after(tx, Duration::from_secs(2));
    driver.run();
    driver.flush_pending_link_frames();
    driver.flush_writers();

    // The shutdown that ends the run tears pending links down, so only the
    // response and the frame that went out are checked.
    let link_id = resp_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_ne!(link_id, [0u8; 16]);

    let request = sent_link_request(&sent.lock().unwrap(), dest)
        .expect("stamped LINKREQUEST sent on the recalled interface");
    let value = rns_core::link::handshake::link_request_stamp_value(&dest, request.data())
        .expect("link request parses");
    assert!(
        value.meets(StampCost::from_whole(4)),
        "link request key must carry the announced cost"
    );
}

#[test]
fn complete_stamped_link_event_rebuilds_the_worker_keys_exactly() {
    let (tx, rx) = event::channel();
    let dest = [0x6E; 16];
    let (mut driver, sent) = stamped_link_driver(tx.clone(), rx, dest, Some(4));

    let deadline = Instant::now() + Duration::from_secs(30);
    let (prv, sig_prv, stamp_value) =
        crate::stamps::generate_stamped_link_keys(&dest, StampCost::from_whole(4), deadline)
            .unwrap();
    let expected_pub = prv.public_key().public_bytes();
    let expected_sig_pub = sig_prv.public_key().public_bytes();

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::CompleteStampedLink(Box::new(
        crate::common::event::StampedLinkKeys {
            dest_hash: dest,
            dest_sig_pub_bytes: [0xAA; 32],
            prv_bytes: prv.private_bytes(),
            sig_prv_bytes: sig_prv.private_bytes(),
            stamp_value,
            response_tx: resp_tx,
        },
    )))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();
    driver.flush_pending_link_frames();
    driver.flush_writers();

    let link_id = resp_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_ne!(link_id, [0u8; 16]);
    let request = sent_link_request(&sent.lock().unwrap(), dest).expect("LINKREQUEST sent");
    let (peer_pub, peer_sig_pub, _, _) =
        rns_core::link::handshake::parse_linkrequest_data(request.data()).unwrap();
    assert_eq!(peer_pub, expected_pub, "X25519 key must be the stamped one");
    assert_eq!(
        peer_sig_pub, expected_sig_pub,
        "Ed25519 key is part of the stamp material"
    );
    assert_eq!(
        rns_core::link::handshake::link_request_stamp_value(&dest, request.data()),
        Some(stamp_value)
    );
    // `sent` is the writer of the interface the destination was learnt on, so
    // finding the request there proves the recalled route hint was applied.
}

#[test]
fn complete_stamped_link_while_draining_is_rejected() {
    let (tx, rx) = event::channel();
    let dest = [0x6F; 16];
    let (mut driver, sent) = stamped_link_driver(tx.clone(), rx, dest, Some(4));
    driver.begin_drain(Duration::from_secs(30));

    let deadline = Instant::now() + Duration::from_secs(30);
    let (prv, sig_prv, stamp_value) =
        crate::stamps::generate_stamped_link_keys(&dest, StampCost::from_whole(1), deadline)
            .unwrap();
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::CompleteStampedLink(Box::new(
        crate::common::event::StampedLinkKeys {
            dest_hash: dest,
            dest_sig_pub_bytes: [0xAA; 32],
            prv_bytes: prv.private_bytes(),
            sig_prv_bytes: sig_prv.private_bytes(),
            stamp_value,
            response_tx: resp_tx,
        },
    )))
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();
    driver.flush_pending_link_frames();
    driver.flush_writers();

    assert_eq!(
        resp_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        [0u8; 16],
        "a draining node must not open new links"
    );
    assert_eq!(driver.link_manager.link_count(), 0);
    assert!(sent.lock().unwrap().is_empty());
}

#[test]
fn stamped_link_caller_is_not_left_waiting_when_the_driver_is_gone() {
    let mut driver = new_test_driver();
    let (resp_tx, resp_rx) = mpsc::channel();
    driver.spawn_stamped_link_keys(
        [0x70; 16],
        [0xAA; 32],
        StampCost::from_whole(4),
        Duration::from_secs(30),
        resp_tx,
    );
    // The driver goes away before (or while) the worker finishes. Either the
    // worker's post fails and it answers with the zero id, or the completion
    // event is dropped with the queue and the channel closes. The caller must
    // never hang; RnsNode::create_link maps both outcomes to an error.
    drop(driver);
    match resp_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(link_id) => assert_eq!(link_id, [0u8; 16]),
        Err(mpsc::RecvTimeoutError::Disconnected) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("caller left waiting for a stamped link"),
    }
}

fn stamping_path_request_driver(
    tx: event::EventSender,
    rx: event::EventReceiver,
) -> (Driver, Arc<Mutex<Vec<Vec<u8>>>>) {
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut config = make_transport_config(false);
    config.identity_hash = Some([0x42; 16]);
    let mut driver = Driver::new(config, rx, tx.clone(), Box::new(cbs));
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
    driver.engine.set_stamp_prs(true);
    driver.set_stamper(Arc::new(crate::stamper::Stamper::with_targets(
        tx,
        None,
        crate::stamper::StampTargets {
            destination_value: StampCost::from_whole(6),
            path_request_value: StampCost::from_whole(6),
        },
    )));
    driver.engine.register_interface(make_interface_info(1));
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    (driver, sent)
}

fn sent_path_requests(sent: &[Vec<u8>], dest: &[u8; 16]) -> Vec<Vec<u8>> {
    let path_request_dest =
        rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
    sent.iter()
        .filter_map(|raw| RawPacket::unpack(raw).ok())
        .filter(|packet| {
            packet.destination_hash == path_request_dest && packet.data().starts_with(dest)
        })
        .map(|packet| packet.data().to_vec())
        .collect()
}

fn assert_valid_path_request_stamp(data: &[u8], dest: &[u8; 16], tag: &[u8]) {
    assert_eq!(data.len(), constants::PATH_REQUEST_STAMPED_LENGTH);
    assert_eq!(&data[16..32], &[0x42; 16], "transport identity");
    assert_eq!(&data[32..48], tag);
    assert_eq!(data[48], constants::EXT_PAYLOAD_MARKER);
    assert_eq!(
        data[49], 0x00,
        "a stamped request, not the unstamped-relay sentinel"
    );
    let material = crate::stamper::Stamper::path_request_stamp_material(dest, tag);
    let workblock = rns_core::stamp::stamp_workblock(&material, 0);
    assert!(rns_core::stamp::stamp_valid(
        &data[50..],
        StampCost::from_whole(6),
        &workblock
    ));
}

#[test]
fn own_path_request_with_stamp_prs_is_stamped_off_thread_then_broadcast() {
    let (tx, rx) = event::channel();
    let (mut driver, sent) = stamping_path_request_driver(tx.clone(), rx);
    let dest = [0xA1; 16];

    let started = Instant::now();
    driver.handle_request_path(dest);
    assert!(started.elapsed() < Duration::from_secs(1));
    // Nothing is sent until the worker reports; the request is already
    // recorded as pending so duplicates are gated meanwhile.
    driver.flush_writers();
    assert!(sent_path_requests(&sent.lock().unwrap(), &dest).is_empty());

    // Running the event loop delivers the worker's SendStampedPathRequest.
    shutdown_after(tx, Duration::from_secs(2));
    driver.run();
    driver.flush_writers();
    let requests = sent_path_requests(&sent.lock().unwrap(), &dest);
    assert_eq!(requests.len(), 1, "exactly one stamped request goes out");
    let tag = requests[0][32..48].to_vec();
    assert_valid_path_request_stamp(&requests[0], &dest, &tag);
    assert_eq!(driver.stamper.cached_path_request_stamps(), 1);
}

#[test]
fn stamp_path_request_action_sends_the_stamped_request_on_that_interface_only() {
    let (tx, rx) = event::channel();
    let (mut driver, sent) = stamping_path_request_driver(tx.clone(), rx);
    // A second interface that must not see the forwarded request.
    driver.engine.register_interface(make_interface_info(2));
    let (other_writer, other_sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(2), make_entry(2, Box::new(other_writer), true));

    let dest = [0xA2; 16];
    let tag = vec![0x5A; 16];
    driver.dispatch_all(vec![TransportAction::StampPathRequest {
        destination_hash: dest,
        tag: tag.clone(),
        interface: InterfaceId(1),
    }]);
    driver.flush_writers();
    assert!(sent_path_requests(&sent.lock().unwrap(), &dest).is_empty());

    shutdown_after(tx, Duration::from_secs(2));
    driver.run();
    driver.flush_writers();
    let requests = sent_path_requests(&sent.lock().unwrap(), &dest);
    assert_eq!(requests.len(), 1);
    assert_valid_path_request_stamp(&requests[0], &dest, &tag);
    assert!(
        sent_path_requests(&other_sent.lock().unwrap(), &dest).is_empty(),
        "a forwarded request goes out only on the interface it was queued for"
    );
}

#[test]
fn path_request_without_stamp_prs_is_sent_synchronously_with_the_transport_identity() {
    let (tx, rx) = event::channel();
    let (mut driver, sent) = stamping_path_request_driver(tx, rx);
    driver.engine.set_stamp_prs(false);
    let dest = [0xA3; 16];
    driver.handle_request_path(dest);
    driver.flush_writers();
    let requests = sent_path_requests(&sent.lock().unwrap(), &dest);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].len(), constants::PATH_REQUEST_LENGTH);
    assert_eq!(&requests[0][16..32], &[0x42; 16]);
    assert_eq!(driver.stamper.queued(), 0);
}

#[test]
fn driver_stays_responsive_while_a_stamp_is_being_ground() {
    let (tx, rx) = event::channel();
    let plain_dest = [0x71; 16];
    let (mut driver, sent) = stamped_link_driver(tx.clone(), rx, plain_dest, None);

    // Start an unattainable stamp with a 3 s watchdog on the worker thread.
    let stamped_dest = [0x72; 16];
    let (stamped_tx, stamped_rx) = mpsc::channel();
    let started = Instant::now();
    driver.spawn_stamped_link_keys(
        stamped_dest,
        [0xAA; 32],
        StampCost::from_whole(100),
        Duration::from_secs(3),
        stamped_tx,
    );

    // Meanwhile an unstamped link to another destination must go through
    // immediately.
    let (plain_tx, plain_rx) = mpsc::channel();
    tx.send(Event::CreateLink {
        dest_hash: plain_dest,
        dest_sig_pub_bytes: [0xBB; 32],
        response_tx: plain_tx,
    })
    .unwrap();
    tx.send(Event::Shutdown).unwrap();
    driver.run();
    driver.flush_pending_link_frames();
    driver.flush_writers();

    let plain_link = plain_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_ne!(plain_link, [0u8; 16]);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "unstamped link waited on the stamp worker"
    );
    assert!(sent_link_request(&sent.lock().unwrap(), plain_dest).is_some());
    assert!(sent_link_request(&sent.lock().unwrap(), stamped_dest).is_none());

    // The watchdog then fails the stamped link.
    assert_eq!(
        stamped_rx.recv_timeout(Duration::from_secs(6)).unwrap(),
        [0u8; 16]
    );
    assert!(started.elapsed() >= Duration::from_secs(3));
}

#[test]
fn state_snapshot_publishes_links_and_interfaces_on_tick() {
    let mut driver = new_test_driver();
    let info = make_interface_info(1);
    driver.engine.register_interface(info);
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    let (link_id, _) = driver.link_manager.create_link(
        &[0xDD; 16],
        &[0xAA; 32],
        1,
        constants::MTU as u32,
        &mut OsRng,
    );
    let tx = driver.event_tx.clone();

    let before = tx.state_snapshot().load();
    assert_eq!(before.sequence, 0);
    assert!(before.links.is_empty());

    driver.handle_tick_event();

    let snapshot = tx.state_snapshot().load();
    assert_eq!(snapshot.sequence, 1);
    assert!(snapshot.published_at > 0.0);
    let QueryResponse::Links(links) = driver.handle_query(QueryRequest::Links) else {
        panic!("expected links");
    };
    let exact = links.iter().find(|link| link.link_id == link_id).unwrap();
    let published = snapshot.link(&link_id).expect("link in the snapshot");
    assert_eq!(published.state, exact.state);
    assert_eq!(published.dest_hash, [0xDD; 16]);
    assert_eq!(published.tx_packets, exact.tx_packets);
    assert_eq!(published.tx_bytes, exact.tx_bytes);
    assert_eq!(snapshot.interfaces.interfaces.len(), 1);
    assert_eq!(snapshot.interfaces.total_links, 1);
    // A reader keeps the copy it loaded; the next tick publishes a new one.
    driver.handle_tick_event();
    assert_eq!(tx.state_snapshot().load().sequence, 2);
    assert_eq!(snapshot.sequence, 1);
}

#[test]
fn state_snapshot_publishes_new_link_without_waiting_for_a_tick() {
    let mut driver = new_test_driver();
    // No timer thread runs in this test, so only a state change publishes.
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(3_600_000)));
    let tx = driver.event_tx.clone();
    let handle = thread::spawn(move || driver.run());

    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(Event::CreateLink {
        dest_hash: [0xDD; 16],
        dest_sig_pub_bytes: [0xAA; 32],
        response_tx: resp_tx,
    })
    .unwrap();
    let link_id = resp_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // The driver publishes before taking the next event, so after this
    // ordered query the snapshot holds the link.
    let (query_tx, query_rx) = mpsc::channel();
    tx.send(Event::query(QueryRequest::LinkCount, query_tx))
        .unwrap();
    query_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let snapshot = tx.state_snapshot().load();
    assert!(snapshot.sequence >= 1);
    assert!(snapshot.link(&link_id).is_some());

    tx.send(Event::Shutdown).unwrap();
    handle.join().unwrap();
}

#[test]
fn state_snapshot_read_does_not_wait_on_a_full_queue() {
    let (tx, rx) = event::channel_with_capacity(4);
    let (callbacks, _, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(
        make_transport_config(false),
        rx,
        tx.clone(),
        Box::new(callbacks),
    );
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
    driver.link_manager.create_link(
        &[0xDD; 16],
        &[0xAA; 32],
        1,
        constants::MTU as u32,
        &mut OsRng,
    );
    driver.handle_tick_event();

    // Nothing consumes the queue: a query would wait behind these forever.
    while tx.try_send(Event::Tick).is_ok() {}
    assert!(matches!(
        tx.try_send(Event::Tick),
        Err(mpsc::TrySendError::Full(_))
    ));

    let started = Instant::now();
    let snapshot = tx.state_snapshot().load();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(snapshot.sequence, 1);
    assert_eq!(snapshot.links.len(), 1);
}

#[test]
fn apply_stamp_config_sets_engine_stamper_runtime_defaults_and_hop_limiter() {
    let mut driver = new_test_driver();
    let shared = Arc::new(AtomicBool::new(false));
    driver.set_stamp_destinations_flag(Arc::clone(&shared));
    let stamps = crate::config::parse(
        "[stamps]\n\
         enforce_stamps = yes\n\
         stamp_destinations = yes\n\
         stamp_prs = yes\n\
         always_stamp_lrs = yes\n\
         destination_cost = 18\n\
         destination_value = 27\n\
         pr_cost = 11\n\
         pr_value = 13\n\
         lr_cost = 9\n\
         lr_stamp_timeout = 4\n\
         pr_stamp_timeout = 3\n",
    )
    .unwrap()
    .stamps;
    driver.apply_stamp_config(&stamps, 12);

    assert_eq!(driver.hop_limiter, 12);
    assert_eq!(
        driver.engine.stamp_requirements(),
        rns_core::transport::types::StampRequirements {
            enforced: true,
            destination_cost: StampCost::from_whole(18),
            path_request_cost: StampCost::from_whole(11),
        }
    );
    assert!(driver.engine.stamp_prs());
    assert!(shared.load(Ordering::Relaxed));
    assert!(driver.stamp_settings.stamp_lrs);
    assert!(driver.stamp_settings.always_stamp_lrs);
    assert!(driver.stamp_settings.lr_stamps_enforced);
    assert_eq!(driver.stamp_settings.lr_cost, StampCost::from_whole(9));
    assert_eq!(
        driver.stamp_settings.link_stamp_timeout(),
        Duration::from_secs(4)
    );
    assert_eq!(
        driver.stamper.targets(),
        crate::stamper::StampTargets {
            destination_value: StampCost::from_whole(27),
            path_request_value: StampCost::from_whole(13),
        }
    );
    assert_eq!(
        driver.link_manager.link_request_costs().get(&[0u8; 16]),
        StampCost::from_whole(9)
    );
    assert!(driver.link_manager.link_request_costs().enforced());
    assert_eq!(
        driver.stamper.path_request_timeout(),
        Duration::from_secs(3)
    );

    // The configured values are the startup defaults of the runtime keys:
    // an override followed by a reset returns to the config file.
    for key in [
        "global.stamp_destinations",
        "global.stamp_path_requests",
        "global.stamp_link_requests",
        "global.always_stamp_link_requests",
    ] {
        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: key.into(),
            value: RuntimeConfigValue::Bool(false),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success for {key}");
        };
        assert_eq!(entry.source, RuntimeConfigSource::RuntimeOverride, "{key}");
        let response =
            driver.handle_query_mut(QueryRequest::ResetRuntimeConfig { key: key.into() });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success for {key}");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(true), "{key}");
        assert_eq!(entry.source, RuntimeConfigSource::Startup, "{key}");
    }
    assert!(driver.engine.stamp_prs());
    assert!(shared.load(Ordering::Relaxed));
    assert!(driver.stamp_settings.stamp_lrs);
}

#[test]
fn destination_type_queries_register_and_withdraw_requirements() {
    use rns_core::transport::destination_filter::destination_type;
    let mut driver = new_test_driver();
    driver
        .engine
        .destination_filter_mut()
        .block(destination_type("nomadnetwork.node"));
    let registration = |driver: &mut Driver, request| match driver.handle_query_mut(request) {
        QueryResponse::DestinationTypeRegistration(registered) => registered,
        other => panic!("unexpected response {other:?}"),
    };
    let wants = |full_name: &str, requester: &[u8]| QueryRequest::WantsDestinationType {
        full_name: full_name.into(),
        requester: requester.to_vec(),
    };
    let unwants = |full_name: &str, requester: &[u8]| QueryRequest::UnwantsDestinationType {
        full_name: full_name.into(),
        requester: requester.to_vec(),
    };

    assert!(registration(&mut driver, wants("rncp.receive", b"a")));
    assert!(registration(&mut driver, wants("rnx.execute", b"a")));
    assert!(registration(&mut driver, wants("rnx.execute", b"b")));
    assert!(!registration(&mut driver, wants("nomadnetwork.node", b"a")));
    let filter = driver.engine.destination_filter();
    assert!(filter.is_wanted(&destination_type("rncp.receive")));
    assert!(!filter.is_wanted(&destination_type("nomadnetwork.node")));

    assert!(registration(&mut driver, unwants("rncp.receive", b"a")));
    assert!(!registration(&mut driver, unwants("rncp.receive", b"a")));
    assert!(registration(
        &mut driver,
        QueryRequest::UnwantsAllDestinationTypes {
            requester: b"a".to_vec()
        }
    ));
    let filter = driver.engine.destination_filter();
    assert!(!filter.is_wanted(&destination_type("rncp.receive")));
    assert!(filter.is_wanted(&destination_type("rnx.execute")));
}

#[test]
fn plain_link_packets_are_proved_by_the_destination_strategy() {
    use rns_core::types::ProofStrategy;
    let dest = [0x6D; 16];
    let packet_hash = [0x2B; 32];
    for (strategy, proved, asked) in [
        (None, false, false),
        (Some(ProofStrategy::ProveNone), false, false),
        (Some(ProofStrategy::ProveApp), true, true),
        (Some(ProofStrategy::ProveAll), true, false),
    ] {
        let proof_requested = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: Arc::new(Mutex::new(Vec::new())),
            proof_requested: proof_requested.clone(),
        };
        let (tx, rx) = event::channel();
        let mut driver = Driver::new(make_transport_config(false), rx, tx, Box::new(cbs));
        if let Some(strategy) = strategy {
            driver.proof_strategies.insert(dest, (strategy, None));
        }
        assert_eq!(
            driver.link_packet_proof_wanted(dest, &packet_hash),
            proved,
            "{strategy:?}"
        );
        // The mock application agrees to every PROVE_APP request.
        let requests = proof_requested.lock().unwrap().clone();
        assert_eq!(
            requests,
            if asked {
                vec![(DestHash(dest), PacketHash(packet_hash))]
            } else {
                Vec::new()
            },
            "{strategy:?}"
        );
    }
}

/// A compact driver with folded timers ticks by itself, with no timer thread
/// sending `Tick` events.
#[cfg(not(any(feature = "engine-parallel", feature = "compact-threads-timers")))]
#[test]
fn folded_timers_tick_without_a_timer_thread() {
    let mut driver = new_test_driver();
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(10)));
    driver.folded.next_tick = Instant::now();
    let tx = driver.event_tx.clone();
    let handle = std::thread::spawn(move || {
        driver.run();
        driver
    });
    std::thread::sleep(Duration::from_millis(200));
    tx.send(Event::Shutdown).unwrap();
    let driver = handle.join().unwrap();
    // About twenty ticks; a loaded test host may manage fewer.
    assert!(
        driver.cache_cleanup_counter >= 3,
        "ticks counted: {}",
        driver.cache_cleanup_counter
    );
}

/// A compact driver with folded timers writes the transport-state snapshot
/// itself when it is due, and finishes a pending write at shutdown.
#[cfg(not(any(feature = "engine-parallel", feature = "compact-threads-timers")))]
#[test]
fn folded_timers_persist_transport_state() {
    let dir = std::env::temp_dir().join(format!(
        "rns-folded-persist-{}-{}",
        std::process::id(),
        time::now().to_bits()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut driver = new_test_driver();
    driver.folded.persist_dir = Some(dir.clone());
    driver.folded.next_persist = Instant::now();
    // The tick queues the due snapshot; shutdown finishes it.
    driver.event_tx.send(Event::Tick).unwrap();
    driver.event_tx.send(Event::Shutdown).unwrap();
    driver.run();
    assert!(driver.folded.jobs.is_empty());
    assert!(
        std::fs::read_dir(&dir).unwrap().next().is_some(),
        "the snapshot was written"
    );
    crate::storage::load_transport_state(&dir).expect("the snapshot loads back");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A compact driver with folded CPU work verifies queued announces itself,
/// with no verification thread: a valid one is delivered and a tampered one
/// counts as a protocol violation.
#[cfg(not(any(feature = "engine-parallel", feature = "compact-threads-work")))]
#[test]
fn folded_work_verifies_queued_announces() {
    let (tx, rx) = event::channel();
    let (cbs, announces, _, _, _, _) = MockCallbacks::new();
    let mut driver = Driver::new(make_transport_config(false), rx, tx.clone(), Box::new(cbs));
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
    driver.async_announce_verification = true;
    driver.engine.register_interface(make_interface_info(1));
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

    let valid = build_announce_packet(&Identity::new(&mut OsRng));
    let mut tampered = build_announce_packet(&Identity::new(&mut OsRng));
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let (valid_len, tampered_len) = (valid.len() as u64, tampered.len() as u64);
    for raw in [valid, tampered] {
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: raw.into(),
            rssi: None,
            snr: None,
        })
        .unwrap();
    }
    let handle = std::thread::spawn(move || {
        driver.run();
        driver
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while announces.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(50));
    tx.send(Event::Shutdown).unwrap();
    let driver = handle.join().unwrap();
    assert_eq!(announces.lock().unwrap().len(), 1);
    assert_eq!(
        driver.interfaces[&InterfaceId(1)].stats.protocol_violations,
        1
    );
    // The tampered announce is filtered inbound once its check fails.
    assert_eq!(rx_and_filtered(&driver, 1), (valid_len, tampered_len, 1));
    assert!(driver.folded.announces.is_empty());
}

/// The frames a `MockWriter` recorded.
type SentFrames = Arc<Mutex<Vec<Vec<u8>>>>;

/// Turn off the announce and path request stamping that is on by default
/// since upstream 51fa8413, for tests of behavior other than stamping.
fn unstamped(driver: &mut Driver) {
    driver.engine.set_stamp_prs(false);
    driver.stamp_destinations.store(false, Ordering::Relaxed);
}

/// A driver with three online interfaces, each with its own writer.
fn rediscovery_driver(
    tx: event::EventSender,
    rx: event::EventReceiver,
    transport_enabled: bool,
) -> (Driver, Vec<SentFrames>) {
    let (cbs, _, _, _, _, _) = MockCallbacks::new();
    let mut config = make_transport_config(transport_enabled);
    config.identity_hash = Some([0x42; 16]);
    let mut driver = Driver::new(config, rx, tx.clone(), Box::new(cbs));
    unstamped(&mut driver);
    driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
    driver.set_stamper(Arc::new(crate::stamper::Stamper::with_targets(
        tx,
        None,
        crate::stamper::StampTargets {
            destination_value: StampCost::from_whole(6),
            path_request_value: StampCost::from_whole(6),
        },
    )));
    let mut sent = Vec::new();
    for id in 1..=3 {
        driver.engine.register_interface(make_interface_info(id));
        let (writer, interface_sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(id), make_entry(id, Box::new(writer), true));
        sent.push(interface_sent);
    }
    (driver, sent)
}

#[test]
fn rediscovery_skipping_an_interface_sends_one_request_on_the_others() {
    let (tx, rx) = event::channel();
    let (mut driver, sent) = rediscovery_driver(tx, rx, true);
    let dest = [0xB1; 16];

    driver.dispatch_all(vec![TransportAction::RediscoverPath {
        destination_hash: dest,
        skip_interface: Some(InterfaceId(2)),
    }]);
    driver.flush_writers();

    let first = sent_path_requests(&sent[0].lock().unwrap(), &dest);
    let skipped = sent_path_requests(&sent[1].lock().unwrap(), &dest);
    let third = sent_path_requests(&sent[2].lock().unwrap(), &dest);
    assert!(skipped.is_empty());
    assert_eq!(first.len(), 1);
    // One request with one tag, unstamped.
    assert_eq!(first, third);
    assert_eq!(first[0].len(), 48);
    assert!(driver.engine.last_path_request(&dest).is_some());
}

#[test]
fn stamped_rediscovery_grinds_one_stamp_for_every_interface() {
    // Upstream acb38a8a: one stamp, computed up front, on every interface.
    let (tx, rx) = event::channel();
    let (mut driver, sent) = rediscovery_driver(tx.clone(), rx, true);
    driver.engine.set_stamp_prs(true);
    let dest = [0xB2; 16];

    driver.dispatch_all(vec![TransportAction::RediscoverPath {
        destination_hash: dest,
        skip_interface: Some(InterfaceId(1)),
    }]);
    driver.flush_writers();
    assert!(sent_path_requests(&sent[1].lock().unwrap(), &dest).is_empty());

    shutdown_after(tx, Duration::from_secs(2));
    driver.run();
    driver.flush_writers();
    assert!(sent_path_requests(&sent[0].lock().unwrap(), &dest).is_empty());
    let second = sent_path_requests(&sent[1].lock().unwrap(), &dest);
    let third = sent_path_requests(&sent[2].lock().unwrap(), &dest);
    assert_eq!(second.len(), 1);
    assert_eq!(second, third);
    let tag = second[0][32..48].to_vec();
    assert_valid_path_request_stamp(&second[0], &dest, &tag);
    assert_eq!(driver.stamper.cached_path_request_stamps(), 1);
}

#[test]
fn rediscovery_without_an_interface_to_skip_is_a_plain_path_request() {
    let (tx, rx) = event::channel();
    let (mut driver, sent) = rediscovery_driver(tx, rx, true);
    let dest = [0xB3; 16];

    driver.dispatch_all(vec![TransportAction::RediscoverPath {
        destination_hash: dest,
        skip_interface: None,
    }]);
    driver.flush_writers();
    for interface_sent in &sent {
        assert_eq!(
            sent_path_requests(&interface_sent.lock().unwrap(), &dest).len(),
            1
        );
    }
}

fn queued_rediscoveries(driver: &mut Driver, now: f64) -> Vec<([u8; 16], Option<InterfaceId>)> {
    let mut rng = rns_crypto::OsRng;
    let mut found = Vec::new();
    for step in 0..8 {
        for action in driver.engine.tick(now + f64::from(step) * 0.25, &mut rng) {
            if let TransportAction::RediscoverPath {
                destination_hash,
                skip_interface,
            } = action
            {
                found.push((destination_hash, skip_interface));
            }
        }
    }
    found
}

#[test]
fn failed_own_link_on_a_non_transport_node_rediscovers_the_path() {
    let (tx, rx) = event::channel();
    let (mut driver, _sent) = rediscovery_driver(tx, rx, false);
    let dest = [0xB4; 16];

    driver.dispatch_link_actions(vec![LinkManagerAction::PendingLinkFailed {
        dest_hash: dest,
    }]);
    assert_eq!(
        queued_rediscoveries(&mut driver, time::now()),
        vec![(dest, None)]
    );
}

#[test]
fn failed_own_link_rediscovery_is_throttled_and_left_to_transport_and_shared_instances() {
    let dest = [0xB5; 16];

    // A recent path request for the destination.
    let (tx, rx) = event::channel();
    let (mut driver, _sent) = rediscovery_driver(tx, rx, false);
    driver
        .engine
        .record_outbound_path_request(dest, time::now() - 5.0);
    driver.dispatch_link_actions(vec![LinkManagerAction::PendingLinkFailed {
        dest_hash: dest,
    }]);
    assert!(queued_rediscoveries(&mut driver, time::now()).is_empty());

    // A transport node relies on its link table job.
    let (tx, rx) = event::channel();
    let (mut driver, _sent) = rediscovery_driver(tx, rx, true);
    driver.dispatch_link_actions(vec![LinkManagerAction::PendingLinkFailed {
        dest_hash: dest,
    }]);
    assert!(queued_rediscoveries(&mut driver, time::now()).is_empty());

    // A shared instance client leaves the request to the instance.
    let (tx, rx) = event::channel();
    let (mut driver, _sent) = rediscovery_driver(tx, rx, false);
    driver.connected_to_shared_instance = true;
    driver.dispatch_link_actions(vec![LinkManagerAction::PendingLinkFailed {
        dest_hash: dest,
    }]);
    assert!(queued_rediscoveries(&mut driver, time::now()).is_empty());
}

/// Built-in destination announces in `sent`, validated, by destination.
fn sent_builtin_announces(
    sent: &[Vec<u8>],
    dest_hash: &[u8; 16],
) -> Vec<rns_core::announce::ValidatedAnnounce> {
    sent.iter()
        .filter_map(|raw| RawPacket::unpack(raw).ok())
        .filter(|packet| {
            packet.destination_hash == *dest_hash
                && packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
        })
        .map(|packet| {
            rns_core::announce::AnnounceData::unpack(packet.data(), false)
                .unwrap()
                .validate(dest_hash)
                .unwrap()
        })
        .collect()
}

#[test]
fn stamped_management_announces_wait_for_their_stamp_and_announce_their_link_cost() {
    // Upstream announces management destinations through
    // `Destination.announce`, so they are stamped like any other.
    let (tx, rx) = event::channel();
    let (mut driver, sent) = rediscovery_driver(tx.clone(), rx, true);
    let identity = Identity::new(&mut OsRng);
    let identity_hash = *identity.hash();
    driver.transport_identity = Some(identity);
    driver.management_config.enable_remote_management = true;
    driver.management_config.publish_blackhole = true;
    driver.stamp_destinations.store(true, Ordering::Relaxed);
    let dir = tempfile::tempdir().unwrap();
    driver
        .stamper
        .set_stamp_store(Some(crate::stamps::DestinationStampStore::new(dir.path())));
    let blackhole = crate::management::blackhole_dest_hash(&identity_hash);
    let management = crate::management::management_dest_hash(&identity_hash);
    driver
        .link_manager
        .link_request_costs()
        .set(blackhole, rns_core::constants::BLACKHOLE_LINK_COST.as_f64());

    // No stamps yet: nothing goes out until the stamper has ground them.
    driver.emit_management_announces(time::now());
    driver.flush_writers();
    assert!(sent_builtin_announces(&sent[0].lock().unwrap(), &blackhole).is_empty());

    shutdown_after(tx, Duration::from_secs(2));
    driver.run();
    driver.flush_writers();
    let required = StampCost::from_whole(6);
    for (dest_hash, link_cost) in [
        (blackhole, rns_core::constants::BLACKHOLE_LINK_COST),
        (management, rns_core::constants::LINK_REQUEST_STAMP_COST),
    ] {
        let mut announces = sent_builtin_announces(&sent[0].lock().unwrap(), &dest_hash);
        assert_eq!(announces.len(), 1, "{dest_hash:02x?}");
        assert_eq!(
            announces[0].apply_stamp(&dest_hash, required),
            rns_core::announce::AnnounceStampStatus::Valid
        );
        assert_eq!(announces[0].lr_cost, Some(link_cost));
    }

    // With the stamps persisted, the next announces go out at once.
    sent[0].lock().unwrap().clear();
    driver.emit_management_announces(time::now());
    driver.flush_writers();
    assert_eq!(
        sent_builtin_announces(&sent[0].lock().unwrap(), &blackhole).len(),
        1
    );
}

/// `Transport.register_destination`: a shared instance client announces a
/// SINGLE IN destination registered with its identity as a path response,
/// stamped once the stamper has its stamp, so that its instance knows the
/// path before anyone asks for it. A node of its own does not.
#[test]
fn shared_client_announces_a_registered_path_responder_stamped() {
    for shared_client in [false, true] {
        let (tx, rx) = event::channel();
        let (mut driver, sent) = rediscovery_driver(tx.clone(), rx, false);
        driver.connected_to_shared_instance = shared_client;
        driver.stamp_destinations.store(true, Ordering::Relaxed);
        let dir = tempfile::tempdir().unwrap();
        driver
            .stamper
            .set_stamp_store(Some(crate::stamps::DestinationStampStore::new(dir.path())));
        let identity = Identity::new(&mut OsRng);
        let destination = crate::destination::Destination::single_in(
            "quiet",
            &["listener"],
            rns_core::types::IdentityHash(*identity.hash()),
        );
        let dest_hash = destination.hash.0;
        tx.send(Event::RegisterDestination {
            dest_hash,
            dest_type: constants::DESTINATION_SINGLE,
        })
        .unwrap();
        tx.send(Event::RegisterPathResponder {
            destination: Box::new(destination),
            identity_prv_key: identity.get_private_key().unwrap(),
        })
        .unwrap();
        shutdown_after(tx, Duration::from_secs(2));
        driver.run();
        driver.flush_writers();

        let frames = sent[0].lock().unwrap().clone();
        let mut announces = sent_builtin_announces(&frames, &dest_hash);
        if !shared_client {
            assert!(announces.is_empty());
            continue;
        }
        assert_eq!(announces.len(), 1);
        assert_eq!(path_responses_for(&frames, &dest_hash).len(), 1);
        assert_eq!(
            announces[0].apply_stamp(&dest_hash, StampCost::from_whole(6)),
            rns_core::announce::AnnounceStampStatus::Valid
        );
    }
}

/// A path request for a destination registered with its identity is
/// answered with a stamped path response, once its stamp is ground, on the
/// interface the request came from.
#[test]
fn path_request_for_a_registered_path_responder_is_answered_stamped() {
    let (tx, rx) = event::channel();
    let (mut driver, sent) = rediscovery_driver(tx.clone(), rx, false);
    driver.stamp_destinations.store(true, Ordering::Relaxed);
    let dir = tempfile::tempdir().unwrap();
    driver
        .stamper
        .set_stamp_store(Some(crate::stamps::DestinationStampStore::new(dir.path())));
    let identity = Identity::new(&mut OsRng);
    let destination = crate::destination::Destination::single_in(
        "quiet",
        &["listener"],
        rns_core::types::IdentityHash(*identity.hash()),
    );
    let dest_hash = destination.hash.0;
    tx.send(Event::RegisterDestination {
        dest_hash,
        dest_type: constants::DESTINATION_SINGLE,
    })
    .unwrap();
    tx.send(Event::RegisterPathResponder {
        destination: Box::new(destination),
        identity_prv_key: identity.get_private_key().unwrap(),
    })
    .unwrap();
    tx.send(Event::Frame {
        interface_id: InterfaceId(1),
        data: local_path_request_frame(&driver, &dest_hash, &[0xD5; 16]).into(),
        rssi: None,
        snr: None,
    })
    .unwrap();
    shutdown_after(tx, Duration::from_secs(2));
    driver.run();
    driver.flush_writers();

    let frames = sent[0].lock().unwrap().clone();
    assert_eq!(path_responses_for(&frames, &dest_hash).len(), 1);
    let mut announces = sent_builtin_announces(&frames, &dest_hash);
    assert_eq!(
        announces[0].apply_stamp(&dest_hash, StampCost::from_whole(6)),
        rns_core::announce::AnnounceStampStatus::Valid
    );
    assert!(path_responses_for(&sent[1].lock().unwrap(), &dest_hash).is_empty());
}

#[test]
fn management_announces_stay_unstamped_without_stamp_destinations() {
    let (tx, rx) = event::channel();
    let (mut driver, sent) = rediscovery_driver(tx, rx, true);
    let identity = Identity::new(&mut OsRng);
    let blackhole = crate::management::blackhole_dest_hash(identity.hash());
    driver.transport_identity = Some(identity);
    driver.management_config.publish_blackhole = true;

    driver.emit_management_announces(time::now());
    driver.flush_writers();
    let announces = sent_builtin_announces(&sent[0].lock().unwrap(), &blackhole);
    assert_eq!(announces.len(), 1);
    assert!(announces[0].app_data.is_none());
}

/// The hashes of `rnstransport.network.instance.<hash>` and
/// `rnstransport.network` under `network_identity`.
fn network_destination_hashes(network_identity: &Identity) -> [[u8; 16]; 2] {
    let network_hash = *network_identity.hash();
    let hex: String = network_hash.iter().map(|b| format!("{b:02x}")).collect();
    [
        rns_core::destination::destination_hash(
            "rnstransport",
            &["network", "instance", &hex],
            Some(&network_hash),
        ),
        rns_core::destination::destination_hash("rnstransport", &["network"], Some(&network_hash)),
    ]
}

fn copy_identity(identity: &Identity) -> Identity {
    Identity::from_private_key(&identity.get_private_key().unwrap())
}

#[test]
fn the_network_identity_announces_its_management_destinations() {
    // Upstream Transport.start: a network identity gets the
    // `rnstransport.network.instance.<hash>` and `rnstransport.network`
    // destinations, announced with the other management destinations
    // through `Destination.announce`, so stamped at the default link cost.
    let (tx, rx) = event::channel();
    let (mut driver, sent) = rediscovery_driver(tx.clone(), rx, false);
    driver.transport_identity = Some(Identity::new(&mut OsRng));
    let network_identity = Identity::new(&mut OsRng);
    driver.network_identity = Some(copy_identity(&network_identity));
    driver.register_network_destinations();
    driver.stamp_destinations.store(true, Ordering::Relaxed);
    let dir = tempfile::tempdir().unwrap();
    driver
        .stamper
        .set_stamp_store(Some(crate::stamps::DestinationStampStore::new(dir.path())));
    let dests = network_destination_hashes(&network_identity);
    for dest in dests {
        assert!(driver.local_destinations.contains_key(&dest));
    }

    driver.emit_management_announces(time::now());
    shutdown_after(tx, Duration::from_secs(2));
    driver.run();
    driver.flush_writers();

    let frames = sent[0].lock().unwrap().clone();
    let required = StampCost::from_whole(6);
    for dest in dests {
        let mut announces = sent_builtin_announces(&frames, &dest);
        assert_eq!(announces.len(), 1, "{dest:02x?}");
        assert_eq!(
            announces[0].public_key,
            network_identity.get_public_key().unwrap()
        );
        assert_eq!(
            announces[0].apply_stamp(&dest, required),
            rns_core::announce::AnnounceStampStatus::Valid
        );
        assert_eq!(
            announces[0].lr_cost,
            Some(rns_core::constants::LINK_REQUEST_STAMP_COST)
        );
    }
    // Only the network destinations: nothing else is enabled.
    assert_eq!(frames.iter().filter(|raw| is_announce(raw)).count(), 2);
}

#[test]
fn path_requests_for_the_network_destinations_are_answered() {
    let LocalPathResponseFixture {
        mut driver,
        tx,
        sent_1,
        ..
    } = local_path_response_fixture(false);
    let network_identity = Identity::new(&mut OsRng);
    driver.network_identity = Some(copy_identity(&network_identity));
    driver.register_network_destinations();
    let dests = network_destination_hashes(&network_identity);
    for (dest, tag) in dests.iter().zip([[0xE1; 16], [0xE2; 16]]) {
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: local_path_request_frame(&driver, dest, &tag).into(),
            rssi: None,
            snr: None,
        })
        .unwrap();
    }
    tx.send(Event::Shutdown).unwrap();
    driver.run();

    let frames = sent_1.lock().unwrap().clone();
    for dest in dests {
        let answers = path_responses_for(&frames, &dest);
        assert_eq!(
            answers.len(),
            1,
            "expected one path response for {dest:02x?}"
        );
        let packet = RawPacket::unpack(&answers[0]).unwrap();
        let announce = AnnounceData::unpack(packet.data(), false)
            .unwrap()
            .validate(&dest)
            .unwrap();
        assert_eq!(
            announce.public_key,
            network_identity.get_public_key().unwrap()
        );
    }
}

#[test]
fn network_destinations_need_a_network_identity_and_no_shared_instance() {
    for shared_client in [false, true] {
        let (tx, rx) = event::channel();
        let (mut driver, sent) = rediscovery_driver(tx, rx, true);
        driver.transport_identity = Some(Identity::new(&mut OsRng));
        let network_identity = Identity::new(&mut OsRng);
        if shared_client {
            driver.connected_to_shared_instance = true;
            driver.network_identity = Some(copy_identity(&network_identity));
        }
        let local_before = driver.local_destinations.len();
        driver.register_network_destinations();
        assert_eq!(driver.local_destinations.len(), local_before);

        driver.emit_management_announces(time::now());
        driver.flush_writers();
        assert!(
            !sent[0].lock().unwrap().iter().any(|raw| is_announce(raw)),
            "shared_client {shared_client}"
        );
        // Nor are path requests for them answered.
        for dest in network_destination_hashes(&network_identity) {
            assert!(driver
                .build_local_path_response(&dest, time::now(), None)
                .is_none());
        }
    }
}

#[cfg(feature = "proof-pool")]
#[test]
fn single_packet_proofs_are_signed_and_checked_on_the_proof_pool() {
    let (tx, rx) = event::channel();
    let (mut cbs, ..) = MockCallbacks::new();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    cbs.proofs = proofs.clone();
    let mut driver = Driver::new(make_transport_config(false), rx, tx.clone(), Box::new(cbs));
    driver.link_manager.set_receive_worker_wake(tx.clone());
    driver
        .link_manager
        .set_proof_verify_threads(crate::ProofVerifyThreads::Fixed(2));
    driver.engine.register_interface(make_interface_info(1));
    let (writer, sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    let identity = Identity::new(&mut OsRng);
    let public = identity.get_public_key().unwrap();
    let signing =
        rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&public[32..].try_into().unwrap())
            .unwrap();
    let take_outcomes = |driver: &mut Driver, done: &dyn Fn(&Driver) -> bool| {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !done(driver) {
            assert!(
                std::time::Instant::now() < deadline,
                "no outcome from the pool"
            );
            thread::sleep(Duration::from_millis(5));
            let mut rng = OsRng;
            driver
                .link_manager
                .poll_proof_pool(&mut rng)
                .expect("the pool is running");
            driver.apply_packet_proofs();
        }
    };

    // Proving a received packet: the signature comes from the pool, and the
    // proof is sent once it is applied.
    let dest = [0xDD; 16];
    driver.proof_strategies.insert(
        dest,
        (
            rns_core::types::ProofStrategy::ProveAll,
            Some(Identity::from_private_key(
                &identity.get_private_key().unwrap(),
            )),
        ),
    );
    let received = [0x31; 32];
    driver.maybe_generate_proof(dest, &received, None);
    assert!(
        sent.lock().unwrap().is_empty(),
        "signed on the pool, not inline"
    );
    take_outcomes(&mut driver, &|_| !sent.lock().unwrap().is_empty());
    let proof = RawPacket::unpack(&sent.lock().unwrap()[0]).unwrap();
    assert_eq!(proof.flags.packet_type, constants::PACKET_TYPE_PROOF);
    assert_eq!(&proof.data()[..32], &received);
    assert!(signing.verify(&proof.data()[32..96].try_into().unwrap(), &received));

    // Checking proofs of sent packets: the good one completes its receipt,
    // the forged one does not.
    let peer = [0xD1; 16];
    let mut known = make_known_destination_state(peer, time::now(), InterfaceId(1));
    known.announced.public_key = public;
    driver.known_destinations.insert(peer, known);
    let (good, forged) = ([0x41; 32], [0x42; 32]);
    for hash in [good, forged] {
        driver.sent_packets.insert(hash, (peer, time::now()));
    }
    for (hash, signature) in [
        (good, identity.sign(&good).unwrap()),
        (forged, identity.sign(&good).unwrap()),
    ] {
        let mut data = hash.to_vec();
        data.extend_from_slice(&signature);
        driver.handle_inbound_proof(hash[..16].try_into().unwrap(), &data, &[0; 32]);
    }
    assert!(
        proofs.lock().unwrap().is_empty(),
        "checked on the pool, not inline"
    );
    take_outcomes(&mut driver, &|_| !proofs.lock().unwrap().is_empty());
    // Let the forged proof's verdict arrive too.
    thread::sleep(Duration::from_millis(100));
    take_outcomes(&mut driver, &|_| true);
    let proofs = proofs.lock().unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].0, DestHash(peer));
    assert_eq!(proofs[0].1, PacketHash(good));
    // The forged proof leaves its receipt for the genuine proof to complete.
    assert_eq!(
        driver.sent_packets.keys().collect::<Vec<_>>(),
        vec![&forged]
    );
}

/// Deferred-send reports, with how many frames were written when each came.
type DeferredSendReports = Arc<Mutex<Vec<(crate::SendTicket, Option<PacketHash>, usize)>>>;

/// Records deferred-send reports.
struct DeferredSendCallbacks {
    reports: DeferredSendReports,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Callbacks for DeferredSendCallbacks {
    fn on_announce(&mut self, _: crate::destination::AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
    fn on_packet_sent(&mut self, ticket: crate::SendTicket, packet_hash: Option<PacketHash>) {
        let written = self.sent.lock().unwrap().len();
        self.reports
            .lock()
            .unwrap()
            .push((ticket, packet_hash, written));
    }
}

fn deferred_send_driver(threads: usize) -> (Driver, DeferredSendReports, Arc<Mutex<Vec<Vec<u8>>>>) {
    let (tx, rx) = event::channel();
    let (writer, sent) = MockWriter::new();
    let reports = Arc::new(Mutex::new(Vec::new()));
    let mut driver = Driver::new(
        make_transport_config(false),
        rx,
        tx.clone(),
        Box::new(DeferredSendCallbacks {
            reports: reports.clone(),
            sent: sent.clone(),
        }),
    );
    driver.link_manager.set_receive_worker_wake(tx);
    driver
        .link_manager
        .set_proof_verify_threads(crate::ProofVerifyThreads::Fixed(threads));
    driver.engine.register_interface(make_interface_info(1));
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    (driver, reports, sent)
}

fn deferred_send(
    identity: &Identity,
    ticket: u64,
    data: &[u8],
) -> Box<crate::common::event::DeferredSend> {
    Box::new(crate::common::event::DeferredSend {
        ticket,
        destination: [0x7D; 16],
        public_key: identity.get_public_key().unwrap(),
        ratchet: None,
        data: data.to_vec(),
        encrypted: false,
    })
}

#[test]
fn a_deferred_send_reports_its_hash_before_it_is_written() {
    let identity = Identity::new(&mut OsRng);
    // No pool: encrypted on the driver.
    let threads = if cfg!(feature = "proof-pool") {
        [0, 2].as_slice()
    } else {
        &[0]
    };
    for &threads in threads {
        let (mut driver, reports, sent) = deferred_send_driver(threads);
        driver.handle_send_deferred(deferred_send(&identity, 7, b"hello"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while reports.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "no report ({threads} threads)");
            thread::sleep(Duration::from_millis(5));
            if driver.link_manager.poll_proof_pool(&mut OsRng).is_some() {
                driver.apply_packet_proofs();
            }
        }
        let reports = reports.lock().unwrap();
        let (ticket, hash, written) = reports[0];
        assert_eq!(ticket, crate::SendTicket(7));
        assert_eq!(written, 0, "reported before the packet is written");
        let hash = hash.expect("sent");
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let packet = RawPacket::unpack(&sent[0]).unwrap();
        assert_eq!(packet.packet_hash, hash.0);
        assert_eq!(packet.destination_hash, [0x7D; 16]);
        assert_eq!(identity.decrypt(packet.data()).unwrap(), b"hello");
        // Tracked for its proof, as any sent packet.
        assert!(driver.sent_packets.contains_key(&hash.0));
    }
}

#[test]
fn a_deferred_send_while_draining_is_reported_unsent() {
    let identity = Identity::new(&mut OsRng);
    let (mut driver, reports, sent) = deferred_send_driver(0);
    driver.begin_drain(Duration::from_secs(1));
    driver.handle_send_deferred(deferred_send(&identity, 3, b"late"));
    assert_eq!(
        reports.lock().unwrap().as_slice(),
        &[(crate::SendTicket(3), None, 0)]
    );
    assert!(sent.lock().unwrap().is_empty());
}

#[test]
fn a_deferred_send_encrypted_by_the_caller_is_sent_as_given() {
    let identity = Identity::new(&mut OsRng);
    let (mut driver, reports, sent) = deferred_send_driver(0);
    let mut send = deferred_send(&identity, 5, b"");
    send.data = identity.encrypt(b"ready", &mut OsRng).unwrap();
    send.encrypted = true;
    driver.handle_send_deferred(send);
    let hash = reports.lock().unwrap()[0].1.expect("sent");
    let sent = sent.lock().unwrap();
    let packet = RawPacket::unpack(&sent[0]).unwrap();
    assert_eq!(packet.packet_hash, hash.0);
    assert_eq!(identity.decrypt(packet.data()).unwrap(), b"ready");
}

/// Decrypted deliveries: destination, plaintext, packet hash.
type DecryptedDeliveries = Arc<Mutex<Vec<(DestHash, Vec<u8>, PacketHash)>>>;

/// Records decrypted and raw deliveries.
#[derive(Default, Clone)]
struct DeliveryRecord {
    decrypted: DecryptedDeliveries,
    raw: Arc<Mutex<Vec<DestHash>>>,
}

impl Callbacks for DeliveryRecord {
    fn on_announce(&mut self, _: crate::destination::AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, dest: DestHash, _: Vec<u8>, _: PacketHash) {
        self.raw.lock().unwrap().push(dest);
    }
    fn on_packet_received(&mut self, dest: DestHash, data: Vec<u8>, hash: PacketHash) {
        self.decrypted.lock().unwrap().push((dest, data, hash));
    }
}

fn single_data_packet(dest: [u8; 16], payload: &[u8]) -> RawPacket {
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, payload).unwrap()
}

#[test]
fn a_destination_that_delivers_decrypted_proves_only_what_decrypts() {
    let identity = Identity::new(&mut OsRng);
    let threads = if cfg!(feature = "proof-pool") {
        [0, 2].as_slice()
    } else {
        &[0]
    };
    // Also a link destination, as a destination accepting links is: its
    // packets take the link manager's delivery path first.
    let cases = threads
        .iter()
        .flat_map(|&threads| [(threads, false), (threads, true)]);
    for (threads, links_too) in cases {
        let (tx, rx) = event::channel();
        let record = DeliveryRecord::default();
        let mut driver = Driver::new(
            make_transport_config(false),
            rx,
            tx.clone(),
            Box::new(record.clone()),
        );
        driver.link_manager.set_receive_worker_wake(tx);
        driver
            .link_manager
            .set_proof_verify_threads(crate::ProofVerifyThreads::Fixed(threads));
        driver.engine.register_interface(make_interface_info(1));
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
        let dest = [0xDE; 16];
        driver.proof_strategies.insert(
            dest,
            (
                rns_core::types::ProofStrategy::ProveAll,
                Some(Identity::from_private_key(
                    &identity.get_private_key().unwrap(),
                )),
            ),
        );
        driver.decrypted_destinations.insert(
            dest,
            Arc::new(Identity::from_private_key(
                &identity.get_private_key().unwrap(),
            )),
        );
        if links_too {
            let key = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&[9; 32]);
            let public = key.public_key().public_bytes();
            driver.link_manager.register_link_destination(
                dest,
                key,
                public,
                crate::link_manager::ResourceStrategy::AcceptNone,
            );
        }

        let good = single_data_packet(dest, &identity.encrypt(b"secret", &mut OsRng).unwrap());
        let other = Identity::new(&mut OsRng);
        let bad = single_data_packet(dest, &other.encrypt(b"not ours", &mut OsRng).unwrap());
        for packet in [&good, &bad] {
            driver.dispatch_deliver_local_action(
                dest,
                packet.raw.clone().into(),
                packet.packet_hash,
                InterfaceId(1),
                false,
                &mut Vec::new(),
                false,
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while record.decrypted.lock().unwrap().is_empty() {
            assert!(
                Instant::now() < deadline,
                "nothing delivered ({threads} threads)"
            );
            thread::sleep(Duration::from_millis(5));
            if driver.link_manager.poll_proof_pool(&mut OsRng).is_some() {
                driver.apply_packet_proofs();
            }
        }
        // Let the bad packet's outcome arrive too.
        thread::sleep(Duration::from_millis(100));
        if driver.link_manager.poll_proof_pool(&mut OsRng).is_some() {
            driver.apply_packet_proofs();
        }
        let decrypted = record.decrypted.lock().unwrap();
        assert_eq!(
            decrypted.as_slice(),
            &[(
                DestHash(dest),
                b"secret".to_vec(),
                PacketHash(good.packet_hash)
            )]
        );
        assert!(record.raw.lock().unwrap().is_empty(), "not delivered raw");
        // One proof, for the packet that decrypted.
        let proofs: Vec<RawPacket> = sent
            .lock()
            .unwrap()
            .iter()
            .map(|raw| RawPacket::unpack(raw).unwrap())
            .filter(|packet| packet.flags.packet_type == constants::PACKET_TYPE_PROOF)
            .collect();
        assert_eq!(proofs.len(), 1);
        assert_eq!(&proofs[0].data()[..32], &good.packet_hash);
    }
}

#[test]
fn a_destination_that_delivers_decrypted_uses_its_attached_ratchets() {
    let identity = Identity::from_private_key(&[31; 64]);
    let destination = crate::Destination::single_in(
        "test",
        &["decrypted"],
        rns_core::types::IdentityHash(*identity.hash()),
    );
    let owner = crate::LocalRatchets::with_store(
        &destination,
        Identity::from_private_key(&[31; 64]),
        Arc::new(crate::MemoryRatchetStore::default()),
    )
    .unwrap();
    owner.enforce();
    let ratchet = owner.public_for_announce(100).unwrap();
    let (tx, rx) = event::channel();
    let record = DeliveryRecord::default();
    let mut driver = Driver::new(
        make_transport_config(false),
        rx,
        tx.clone(),
        Box::new(record.clone()),
    );
    tx.local_ratchets()
        .lock()
        .unwrap()
        .insert(destination.hash.0, owner);
    let dest = destination.hash.0;
    driver
        .decrypted_destinations
        .insert(dest, Arc::new(Identity::from_private_key(&[31; 64])));
    // Enforced ratchets refuse the identity key: only the ratcheted packet
    // decrypts.
    let ratcheted = single_data_packet(
        dest,
        &identity
            .encrypt_with_ratchet(b"ratcheted", Some(&ratchet), &mut OsRng)
            .unwrap(),
    );
    let plain = single_data_packet(dest, &identity.encrypt(b"identity", &mut OsRng).unwrap());
    for packet in [&ratcheted, &plain] {
        driver.dispatch_deliver_local_action(
            dest,
            packet.raw.clone().into(),
            packet.packet_hash,
            InterfaceId(1),
            false,
            &mut Vec::new(),
            false,
        );
    }
    let decrypted = record.decrypted.lock().unwrap();
    assert_eq!(decrypted.len(), 1);
    assert_eq!(decrypted[0].1, b"ratcheted");
}

#[test]
fn blackholing_an_identity_drops_its_paths_and_persists_the_list() {
    // Transport.blackhole_identity: add once (a second call changes nothing),
    // persist_blackhole, remove_blackholed_paths; reload_blackhole on start.
    use rns_core::transport::tables::PathEntry;
    let dir = tempfile::tempdir().unwrap();
    let mut driver = new_test_driver();
    driver.engine.register_interface(make_interface_info(1));
    driver.load_blackhole(dir.path().to_path_buf());
    let path = || PathEntry {
        timestamp: 100.0,
        next_hop: [0x44; 16],
        hops: 1,
        expires: f64::MAX,
        random_blobs: Vec::new(),
        receiving_interface: InterfaceId(1),
        packet_hash: [0x55; 32],
        announce_raw: None,
        used: 0.0,
    };
    // make_announced_identity names the identity after the first byte.
    let (spammer, neighbour) = ([0xA1; 16], [0xB2; 16]);
    for dest in [spammer, neighbour] {
        driver.engine.inject_path(dest, path());
        driver.upsert_known_destination(dest, make_announced_identity(dest, 10.0, InterfaceId(1)));
    }

    assert!(driver.blackhole_identity_local([0xA1; 16], None, Some("spam".into())));
    assert!(!driver.engine.has_path(&spammer), "its path is dropped");
    assert!(driver.engine.has_path(&neighbour));
    assert!(
        !driver.blackhole_identity_local([0xA1; 16], Some(1.0), None),
        "already blackholed: unchanged"
    );
    assert!(dir.path().join("local").is_file());

    // A restarted node loads it back.
    let mut restarted = new_test_driver();
    restarted.load_blackhole(dir.path().to_path_buf());
    let entries: Vec<_> = restarted.engine.blackholed_entries().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1.reason.as_deref(), Some("spam"));
    assert_eq!(entries[0].1.expires, 0.0, "still indefinite");

    assert!(restarted.unblackhole_identity_local(&[0xA1; 16]));
    assert!(!restarted.unblackhole_identity_local(&[0xA1; 16]));
    let mut again = new_test_driver();
    again.load_blackhole(dir.path().to_path_buf());
    assert_eq!(again.engine.blackholed_entries().count(), 0);
}

#[test]
fn packet_signal_readings_are_cached_per_packet_hash() {
    let mut driver = new_test_driver();
    register_test_generic_interface(&mut driver, 1, "radio");
    driver
        .interfaces
        .get_mut(&InterfaceId(1))
        .unwrap()
        .stats
        .signal_quality = Some(88.5);

    let query = |driver: &mut Driver, raw: &[u8]| {
        let packet = RawPacket::unpack(raw).unwrap();
        match driver.handle_query(QueryRequest::PacketSignal {
            packet_hash: packet.packet_hash,
        }) {
            QueryResponse::PacketSignal(signal) => signal,
            other => panic!("unexpected response {other:?}"),
        }
    };

    // A packet from an interface that reports readings is remembered with
    // the interface's current signal quality.
    let with_readings = build_announce_packet(&Identity::new(&mut OsRng));
    driver.handle_frame_event(
        InterfaceId(1),
        with_readings.clone(),
        Some(-100),
        Some(10.5),
    );
    assert_eq!(
        query(&mut driver, &with_readings),
        Some(event::PacketSignal {
            rssi: Some(-100),
            snr: Some(10.5),
            q: Some(88.5),
        })
    );

    // A packet without readings is not.
    let without = build_announce_packet(&Identity::new(&mut OsRng));
    driver.handle_frame_event(InterfaceId(1), without.clone(), None, None);
    assert_eq!(query(&mut driver, &without), None);

    // The cache keeps the newest PACKET_SIGNAL_CACHE_MAXSIZE readings.
    for i in 0..super::PACKET_SIGNAL_CACHE_MAXSIZE {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&(i as u64).to_be_bytes());
        hash[31] = 0xee;
        driver.record_packet_signal(
            hash,
            event::PacketSignal {
                rssi: Some(-1),
                snr: None,
                q: None,
            },
        );
    }
    assert_eq!(
        driver.packet_signals.len(),
        super::PACKET_SIGNAL_CACHE_MAXSIZE
    );
    assert_eq!(query(&mut driver, &with_readings), None);
}

#[test]
fn forced_shared_instance_bitrate_applies_to_local_clients() {
    let mut driver = new_test_driver();
    driver.forced_local_bitrate = Some(9600);
    let mut local = make_interface_info(5);
    local.is_local_client = true;
    let (writer, _sent) = MockWriter::new();
    driver.handle_interface_up_event(InterfaceId(5), Some(Box::new(writer)), Some(local));
    let mut other = make_interface_info(6);
    other.bitrate = Some(1_000);
    let (writer, _sent) = MockWriter::new();
    driver.handle_interface_up_event(InterfaceId(6), Some(Box::new(writer)), Some(other));

    assert_eq!(
        driver.interfaces.get(&InterfaceId(5)).unwrap().info.bitrate,
        Some(9600)
    );
    assert_eq!(
        driver.interfaces.get(&InterfaceId(6)).unwrap().info.bitrate,
        Some(1_000)
    );
}

// Receipts of sent packets complete only on a proof signed by the key the
// packet was sent to: the link's peer for link packets, the destination's
// identity otherwise. A proof that fails the check leaves the receipt
// pending, for the genuine proof to complete it.

/// Recorded `on_proof` calls.
type RecordedProofs = Arc<Mutex<Vec<(DestHash, PacketHash, f64)>>>;

/// A driver on interface 1 whose `on_proof` calls are recorded.
fn proof_receipt_driver() -> (Driver, RecordedProofs) {
    let (tx, rx) = event::channel();
    let (mut cbs, ..) = MockCallbacks::new();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    cbs.proofs = proofs.clone();
    let mut driver = Driver::new(make_transport_config(false), rx, tx, Box::new(cbs));
    driver.engine.register_interface(make_interface_info(1));
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    (driver, proofs)
}

/// A proof packet to `destination` carrying `data`.
fn proof_frame(destination: [u8; 16], destination_type: u8, data: &[u8]) -> Vec<u8> {
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type,
        packet_type: constants::PACKET_TYPE_PROOF,
    };
    RawPacket::pack(flags, 0, &destination, None, constants::CONTEXT_NONE, data)
        .unwrap()
        .raw
}

/// The explicit proof `prover` sends for `packet_hash` received on `link_id`.
fn link_proof_frame(
    prover: &mut crate::link_manager::LinkManager,
    link_id: &[u8; 16],
    packet_hash: &[u8; 32],
) -> Vec<u8> {
    prover
        .prove_link_packet(link_id, packet_hash)
        .into_iter()
        .find_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.to_vec()),
            _ => None,
        })
        .expect("link packet proof")
}

/// `[packet_hash][64 forged signature bytes]`.
fn forged_explicit_proof(packet_hash: &[u8; 32]) -> Vec<u8> {
    let mut data = packet_hash.to_vec();
    data.extend_from_slice(&[0xAA; 64]);
    data
}

/// A driver with an active link it sent `packet_hash` on: the driver, its
/// recorded proofs, the link's peer and the link id.
fn link_receipt_driver(
    packet_hash: [u8; 32],
) -> (
    Driver,
    RecordedProofs,
    crate::link_manager::LinkManager,
    [u8; 16],
) {
    let (mut driver, proofs) = proof_receipt_driver();
    let (peer, link_id) = establish_link(&mut driver.link_manager, [0xDD; 16], InterfaceId(1));
    driver
        .sent_packets
        .insert(packet_hash, (link_id, time::now() - 0.25));
    (driver, proofs, peer, link_id)
}

#[test]
fn link_packet_proof_from_the_link_peer_completes_the_receipt() {
    let hash = [0x51; 32];
    let (mut driver, proofs, mut peer, link_id) = link_receipt_driver(hash);

    let frame = link_proof_frame(&mut peer, &link_id, &hash);
    driver.handle_frame_event(InterfaceId(1), frame, None, None);

    let proofs = proofs.lock().unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].0, DestHash(link_id));
    assert_eq!(proofs[0].1, PacketHash(hash));
    assert!(!driver.sent_packets.contains_key(&hash));
}

#[test]
fn forged_link_packet_proof_is_rejected() {
    let hash = [0x52; 32];
    let (mut driver, proofs, _peer, link_id) = link_receipt_driver(hash);

    let frame = proof_frame(
        link_id,
        constants::DESTINATION_LINK,
        &forged_explicit_proof(&hash),
    );
    driver.handle_frame_event(InterfaceId(1), frame, None, None);

    assert!(proofs.lock().unwrap().is_empty(), "forged proof accepted");
    assert!(driver.sent_packets.contains_key(&hash), "receipt dropped");
}

#[test]
fn forged_link_packet_proof_addressed_elsewhere_is_rejected() {
    // An explicit proof names its packet itself, so it need not arrive on
    // the link: it is still checked against the link's peer.
    let hash = [0x53; 32];
    let (mut driver, proofs, _peer, _link_id) = link_receipt_driver(hash);
    let proof_destination: [u8; 16] = hash[..16].try_into().unwrap();
    driver
        .engine
        .register_destination(proof_destination, constants::DESTINATION_SINGLE);

    let frame = proof_frame(
        proof_destination,
        constants::DESTINATION_SINGLE,
        &forged_explicit_proof(&hash),
    );
    driver.handle_frame_event(InterfaceId(1), frame, None, None);

    assert!(proofs.lock().unwrap().is_empty(), "forged proof accepted");
    assert!(driver.sent_packets.contains_key(&hash), "receipt dropped");
}

#[test]
fn link_packet_proof_signed_on_another_link_is_rejected() {
    // A proof correctly signed by the peer of another link (one an attacker
    // holds) does not prove a packet sent on this one.
    let hash = [0x54; 32];
    let (mut driver, proofs, _peer, _link_id) = link_receipt_driver(hash);
    let (mut attacker, attacker_link) =
        establish_link(&mut driver.link_manager, [0xAB; 16], InterfaceId(1));

    let frame = link_proof_frame(&mut attacker, &attacker_link, &hash);
    driver.handle_frame_event(InterfaceId(1), frame, None, None);

    assert!(
        proofs.lock().unwrap().is_empty(),
        "cross-link proof accepted"
    );
    assert!(driver.sent_packets.contains_key(&hash), "receipt dropped");
}

#[test]
fn forged_link_packet_proof_does_not_suppress_the_genuine_one() {
    let hash = [0x55; 32];
    let (mut driver, proofs, mut peer, link_id) = link_receipt_driver(hash);

    let forged = proof_frame(
        link_id,
        constants::DESTINATION_LINK,
        &forged_explicit_proof(&hash),
    );
    driver.handle_frame_event(InterfaceId(1), forged, None, None);
    assert!(proofs.lock().unwrap().is_empty(), "forged proof accepted");
    let genuine = link_proof_frame(&mut peer, &link_id, &hash);
    driver.handle_frame_event(InterfaceId(1), genuine, None, None);

    let proofs = proofs.lock().unwrap();
    assert_eq!(proofs.len(), 1, "genuine proof not delivered exactly once");
    assert_eq!(proofs[0].1, PacketHash(hash));
    assert!(!driver.sent_packets.contains_key(&hash));
}

#[test]
fn link_packet_proof_after_the_link_closed_is_rejected() {
    // With the link gone there is no key left to check the proof against.
    let hash = [0x56; 32];
    let (mut driver, proofs, mut peer, link_id) = link_receipt_driver(hash);
    let frame = link_proof_frame(&mut peer, &link_id, &hash);
    driver.link_manager.teardown_link(&link_id);

    let proof = RawPacket::unpack(&frame).unwrap();
    driver.handle_inbound_proof(link_id, proof.data(), &[0; 32]);

    assert!(
        proofs.lock().unwrap().is_empty(),
        "unchecked proof accepted"
    );
}

/// A driver that sent `packet_hash` to a destination whose identity it
/// knows: the driver, its recorded proofs, that identity and destination.
fn single_receipt_driver(packet_hash: [u8; 32]) -> (Driver, RecordedProofs, Identity, [u8; 16]) {
    let (mut driver, proofs) = proof_receipt_driver();
    let identity = Identity::new(&mut OsRng);
    let destination = [0xD2; 16];
    know_identity(&mut driver, destination, &identity);
    driver
        .sent_packets
        .insert(packet_hash, (destination, time::now() - 0.25));
    let proof_destination: [u8; 16] = packet_hash[..16].try_into().unwrap();
    driver
        .engine
        .register_destination(proof_destination, constants::DESTINATION_SINGLE);
    (driver, proofs, identity, destination)
}

#[test]
fn forged_single_packet_proof_does_not_suppress_the_genuine_one() {
    let hash = [0x61; 32];
    let (mut driver, proofs, identity, destination) = single_receipt_driver(hash);
    let proof_destination: [u8; 16] = hash[..16].try_into().unwrap();

    let forged = proof_frame(
        proof_destination,
        constants::DESTINATION_SINGLE,
        &forged_explicit_proof(&hash),
    );
    driver.handle_frame_event(InterfaceId(1), forged, None, None);
    assert!(proofs.lock().unwrap().is_empty(), "forged proof accepted");
    assert!(driver.sent_packets.contains_key(&hash), "receipt dropped");

    let mut genuine = hash.to_vec();
    genuine.extend_from_slice(&identity.sign(&hash).unwrap());
    let genuine = proof_frame(proof_destination, constants::DESTINATION_SINGLE, &genuine);
    driver.handle_frame_event(InterfaceId(1), genuine, None, None);

    let proofs = proofs.lock().unwrap();
    assert_eq!(proofs.len(), 1, "genuine proof not delivered exactly once");
    assert_eq!(proofs[0].0, DestHash(destination));
    assert_eq!(proofs[0].1, PacketHash(hash));
    assert!(!driver.sent_packets.contains_key(&hash));
}

#[test]
fn forged_implicit_proof_does_not_suppress_the_genuine_one() {
    let hash = [0x62; 32];
    let (mut driver, proofs, identity, _destination) = single_receipt_driver(hash);
    let proof_destination: [u8; 16] = hash[..16].try_into().unwrap();

    let forged = proof_frame(
        proof_destination,
        constants::DESTINATION_SINGLE,
        &[0xAA; 64],
    );
    driver.handle_frame_event(InterfaceId(1), forged, None, None);
    assert!(proofs.lock().unwrap().is_empty(), "forged proof accepted");

    let signature = identity.sign(&hash).unwrap();
    let genuine = proof_frame(proof_destination, constants::DESTINATION_SINGLE, &signature);
    driver.handle_frame_event(InterfaceId(1), genuine, None, None);

    assert_eq!(proofs.lock().unwrap().len(), 1);
    assert!(!driver.sent_packets.contains_key(&hash));
}

#[test]
fn single_packet_proof_is_checked_with_the_identity_it_was_sent_to() {
    // The sender may hold an identity the driver does not know (an LXMF
    // backchannel's, or one whose announce expired): the proof is checked
    // with the identity the packet was encrypted for, as upstream's receipt.
    let (tx, rx) = event::channel();
    let (mut cbs, ..) = MockCallbacks::new();
    let proofs = Arc::new(Mutex::new(Vec::new()));
    cbs.proofs = proofs.clone();
    let mut driver = Driver::new(make_transport_config(false), rx, tx.clone(), Box::new(cbs));
    driver.engine.register_interface(make_interface_info(1));
    let (writer, _sent) = MockWriter::new();
    driver
        .interfaces
        .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
    let identity = Identity::new(&mut OsRng);
    let key: [u8; 32] = identity.get_public_key().unwrap()[32..].try_into().unwrap();
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &[0xD4; 16],
        None,
        constants::CONTEXT_NONE,
        b"for an identity the driver never saw announced",
    )
    .unwrap();
    let hash = packet.packet_hash;
    let (completion, _receipt) =
        crate::link_send::Completion::new(tx.link_send_pool().try_acquire().unwrap());
    driver.handle_confirmed_outbound(
        packet.raw,
        constants::DESTINATION_SINGLE,
        None,
        completion,
        Some(key),
    );
    assert!(driver.sent_packets.contains_key(&hash));
    let proof_destination: [u8; 16] = hash[..16].try_into().unwrap();

    driver.handle_inbound_proof(proof_destination, &forged_explicit_proof(&hash), &[0; 32]);
    assert!(proofs.lock().unwrap().is_empty(), "forged proof accepted");

    let mut genuine = hash.to_vec();
    genuine.extend_from_slice(&identity.sign(&hash).unwrap());
    driver.handle_inbound_proof(proof_destination, &genuine, &[0; 32]);
    let proofs = proofs.lock().unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].1, PacketHash(hash));
    assert!(!driver.sent_packets.contains_key(&hash));
    assert!(!driver.sent_packet_keys.contains_key(&hash));
}

#[test]
fn single_packet_proof_to_an_unknown_identity_is_rejected() {
    // Without the destination's identity the proof cannot be checked, and
    // upstream (PacketReceipt.validate_proof) does not accept it.
    let (mut driver, proofs) = proof_receipt_driver();
    let hash = [0x63; 32];
    driver.sent_packets.insert(hash, ([0xD3; 16], time::now()));

    driver.handle_inbound_proof([0xD3; 16], &forged_explicit_proof(&hash), &[0; 32]);

    assert!(
        proofs.lock().unwrap().is_empty(),
        "unchecked proof accepted"
    );
}

#[cfg(feature = "proof-pool")]
#[test]
fn proofs_checked_on_the_pool_keep_the_receipt_until_one_is_valid() {
    let hash = [0x64; 32];
    let (mut driver, proofs, identity, destination) = single_receipt_driver(hash);
    let (tx, _rx) = event::channel();
    driver.link_manager.set_receive_worker_wake(tx);
    driver
        .link_manager
        .set_proof_verify_threads(crate::ProofVerifyThreads::Fixed(2));
    // Polls for a while: the pool's verdicts arrive within it.
    let drain = |driver: &mut Driver| {
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
            driver
                .link_manager
                .poll_proof_pool(&mut OsRng)
                .expect("the pool is running");
            driver.apply_packet_proofs();
        }
    };

    driver.handle_inbound_proof(destination, &forged_explicit_proof(&hash), &[0; 32]);
    drain(&mut driver);
    assert!(proofs.lock().unwrap().is_empty(), "forged proof accepted");
    assert!(driver.sent_packets.contains_key(&hash), "receipt dropped");

    // Two genuine copies in flight at once complete the receipt once.
    let mut genuine = hash.to_vec();
    genuine.extend_from_slice(&identity.sign(&hash).unwrap());
    driver.handle_inbound_proof(destination, &genuine, &[0; 32]);
    driver.handle_inbound_proof(destination, &genuine, &[0; 32]);
    drain(&mut driver);
    assert_eq!(proofs.lock().unwrap().len(), 1);
    assert!(!driver.sent_packets.contains_key(&hash));
}

#[cfg(feature = "proof-pool")]
#[test]
fn link_packet_proofs_checked_on_the_pool_complete_only_their_own_receipt() {
    let hash = [0x57; 32];
    let (mut driver, proofs, mut peer, link_id) = link_receipt_driver(hash);
    let (mut attacker, attacker_link) =
        establish_link(&mut driver.link_manager, [0xAB; 16], InterfaceId(1));
    let (tx, _rx) = event::channel();
    driver.link_manager.set_receive_worker_wake(tx);
    driver
        .link_manager
        .set_proof_verify_threads(crate::ProofVerifyThreads::Fixed(2));
    // Polls for a while: the pool's verdicts arrive within it.
    let drain = |driver: &mut Driver| {
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
            let actions = driver
                .link_manager
                .poll_proof_pool(&mut OsRng)
                .expect("the pool is running");
            driver.dispatch_link_actions(actions);
            driver.apply_packet_proofs();
        }
    };

    let forged = proof_frame(
        link_id,
        constants::DESTINATION_LINK,
        &forged_explicit_proof(&hash),
    );
    driver.handle_frame_event(InterfaceId(1), forged, None, None);
    let cross_link = link_proof_frame(&mut attacker, &attacker_link, &hash);
    driver.handle_frame_event(InterfaceId(1), cross_link, None, None);
    drain(&mut driver);
    assert!(proofs.lock().unwrap().is_empty(), "invalid proof accepted");
    assert!(driver.sent_packets.contains_key(&hash), "receipt dropped");

    let genuine = link_proof_frame(&mut peer, &link_id, &hash);
    driver.handle_frame_event(InterfaceId(1), genuine, None, None);
    assert!(
        proofs.lock().unwrap().is_empty(),
        "checked on the pool, not inline"
    );
    drain(&mut driver);
    let proofs = proofs.lock().unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].1, PacketHash(hash));
    assert!(!driver.sent_packets.contains_key(&hash));
}

#[test]
fn interface_stats_report_upstream_display_names_and_listeners() {
    let (callbacks, ..) = MockCallbacks::new();
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));

    // A configured interface with an address in its display name, and one
    // named `{type}[{name}]`.
    let (writer, _) = MockWriter::new();
    let mut udp = make_entry(1, Box::new(writer), true);
    udp.info.name = "UDP".into();
    udp.interface_type = "UDPInterface".into();
    driver.interfaces.insert(InterfaceId(1), udp);
    driver
        .interface_display_names
        .insert(InterfaceId(1), "UDPInterface[UDP/0.0.0.0:4242]".into());
    let (writer, _) = MockWriter::new();
    let mut kiss = make_entry(2, Box::new(writer), true);
    kiss.info.name = "Radio".into();
    kiss.interface_type = "KISSInterface".into();
    driver.interfaces.insert(InterfaceId(2), kiss);

    // A TCP server and the client it spawned.
    driver.listener_stats.push(ListenerStat {
        id: InterfaceId(10),
        name: "Server".into(),
        display_name: "TCPServerInterface[Server/0.0.0.0:4242]".into(),
        interface_type: "TCPServerInterface".into(),
        mode: constants::MODE_GATEWAY,
        gravity: 3,
        announces_to_internal: None,
        bitrate: Some(10_000_000),
        mtu: 262_144,
        ifac: None,
        clients: ListenerClients::Spawned,
    });
    let (writer, _) = MockWriter::new();
    driver.handle_dynamic_interface_up_event(
        InterfaceId(11),
        Box::new(writer),
        event::DynamicInterfaceRegistration {
            info: make_interface_info(11),
            interface_type: "TCPServerClientInterface".into(),
            parent_id: InterfaceId(10),
            telemetry: event::InterfaceTelemetry::default(),
            ifac: None,
            display_name: Some("TCPInterface[Client on Server/10.0.0.2:50000]".into()),
            short_name: Some("Client on Server".into()),
            reconnecting: false,
        },
    );
    driver
        .interfaces
        .get_mut(&InterfaceId(11))
        .unwrap()
        .stats
        .rxb = 300;
    driver
        .interfaces
        .get_mut(&InterfaceId(11))
        .unwrap()
        .stats
        .txb = 400;

    // The shared instance and two programs connected to it.
    driver.register_shared_instance_listener(
        InterfaceId(20),
        crate::interface::display::LocalEndpoint::Unix("default".into()),
    );
    for id in [21, 22] {
        let mut info = make_interface_info(id);
        info.name = "LocalInterface".into();
        info.is_local_client = true;
        let (writer, _) = MockWriter::new();
        driver.handle_interface_up_event(InterfaceId(id), Some(Box::new(writer)), Some(info));
    }

    let stats = driver.interface_stats();
    let by_id = |id: u64| {
        stats
            .interfaces
            .iter()
            .find(|stat| stat.id == id)
            .unwrap_or_else(|| panic!("no stats for interface {id}"))
    };
    assert_eq!(by_id(1).display_name, "UDPInterface[UDP/0.0.0.0:4242]");
    assert_eq!(by_id(1).name, "UDP");
    assert_eq!(by_id(2).display_name, "KISSInterface[Radio]");

    let server = by_id(10);
    assert_eq!(
        server.display_name,
        "TCPServerInterface[Server/0.0.0.0:4242]"
    );
    assert_eq!(server.name, "Server");
    assert_eq!(server.interface_type, "TCPServerInterface");
    assert_eq!(server.clients, Some(1));
    assert_eq!((server.rxb, server.txb), (300, 400));
    assert_eq!(server.mode, constants::MODE_GATEWAY);
    assert_eq!(server.gravity, 3);
    assert_eq!(
        by_id(11).display_name,
        "TCPInterface[Client on Server/10.0.0.2:50000]"
    );

    let shared = by_id(20);
    assert_eq!(shared.display_name, "Shared Instance[rns/default]");
    assert_eq!(shared.name, "Reticulum");
    assert_eq!(shared.interface_type, "LocalServerInterface");
    assert_eq!(shared.clients, Some(2));
    assert_eq!(by_id(21).display_name, "LocalInterface[rns/default]");
    // Upstream names a client on the Unix socket after the number of
    // clients served before it.
    assert_eq!(by_id(21).name, "0@\0rns/default");
    assert_eq!(by_id(22).name, "1@\0rns/default");
    assert_eq!(by_id(11).name, "Client on Server");
    assert_eq!(
        by_id(21).parent_display_name.as_deref(),
        Some("Shared Instance[rns/default]")
    );
    assert_eq!(
        by_id(11).parent_display_name.as_deref(),
        Some("TCPServerInterface[Server/0.0.0.0:4242]")
    );
    assert_eq!(by_id(1).parent_display_name, None);

    // Until prioritized, in the order they were added; after upstream's
    // prioritize_interfaces, by bitrate, highest first, then that order.
    let ids: Vec<_> = stats.interfaces.iter().map(|stat| stat.id).collect();
    let mut sorted_ids = ids.clone();
    sorted_ids.sort();
    assert_eq!(ids, sorted_ids);
    driver.prioritize_interfaces();
    let stats = driver.interface_stats();
    let keys: Vec<_> = stats
        .interfaces
        .iter()
        .map(|stat| (std::cmp::Reverse(stat.bitrate.unwrap_or(0)), stat.id))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);

    // A spawned interface's display name goes with it.
    driver.handle_interface_down_event(InterfaceId(11));
    assert!(!driver
        .interface_display_names
        .contains_key(&InterfaceId(11)));
    assert!(!driver.interface_short_names.contains_key(&InterfaceId(11)));
    assert_eq!(driver.interface_stats().interfaces.len(), 6);
    let stats = driver.interface_stats();
    let server = stats.interfaces.iter().find(|stat| stat.id == 10).unwrap();
    assert_eq!(server.clients, Some(0));
}

/// Upstream lists the interfaces that spawn peers or subinterfaces as
/// interfaces of their own.
#[cfg(feature = "iface-i2p")]
#[test]
fn interface_stats_report_peer_spawning_parents() {
    let (callbacks, ..) = MockCallbacks::new();
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));
    let listener = |id: u64, name: &str, kind: &str, clients| ListenerStat {
        id: InterfaceId(id),
        name: name.into(),
        display_name: format!("{kind}[{name}]"),
        interface_type: kind.into(),
        mode: constants::MODE_FULL,
        gravity: 0,
        announces_to_internal: None,
        bitrate: Some(1000),
        mtu: 1064,
        ifac: None,
        clients,
    };
    let spawn = |driver: &mut Driver, id: u64, parent: u64, short_name: &str, rxb, txb| {
        let (writer, _) = MockWriter::new();
        driver.handle_dynamic_interface_up_event(
            InterfaceId(id),
            Box::new(writer),
            event::DynamicInterfaceRegistration {
                info: make_interface_info(id),
                interface_type: "Peer".into(),
                parent_id: InterfaceId(parent),
                telemetry: event::InterfaceTelemetry::default(),
                ifac: None,
                display_name: None,
                short_name: Some(short_name.into()),
                reconnecting: false,
            },
        );
        let stats = &mut driver.interfaces.get_mut(&InterfaceId(id)).unwrap().stats;
        stats.rxb = rxb;
        stats.txb = txb;
    };

    // An AutoInterface with two peers.
    driver.listener_stats.push(listener(
        10,
        "Auto",
        "AutoInterface",
        ListenerClients::AutoPeers,
    ));
    spawn(&mut driver, 11, 10, "None", 1, 2);
    spawn(&mut driver, 12, 10, "None", 3, 4);

    // A connectable I2PInterface with one peer it connected to and one
    // that connected to it.
    let endpoint = Arc::new(Mutex::new(crate::interface::i2p::I2pEndpoint::default()));
    driver.listener_stats.push(listener(
        20,
        "I2P",
        "I2PInterface",
        ListenerClients::I2pPeers(I2pListener {
            connectable: true,
            configured_peers: Some(1),
            endpoint: Arc::clone(&endpoint),
        }),
    ));
    spawn(&mut driver, 21, 20, "I2P to peer.b32.i2p", 10, 20);
    spawn(&mut driver, 22, 20, "Connected peer on I2P", 30, 40);
    endpoint.lock().unwrap().tunnels.insert(
        InterfaceId(21),
        Arc::new(crate::interface::i2p::tunnel::PeerTunnel::new(None)),
    );

    // An RNodeMultiInterface with two subinterfaces, one online.
    for (id, online) in [(30, true), (31, false)] {
        let (writer, _) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(id), make_entry(id, Box::new(writer), online));
    }
    driver.listener_stats.push(listener(
        40,
        "Multi",
        "RNodeMultiInterface",
        ListenerClients::Subinterfaces(vec![InterfaceId(30), InterfaceId(31)]),
    ));

    let stat = |id: u64| {
        driver
            .interface_stats()
            .interfaces
            .into_iter()
            .find(|stat| stat.id == id)
            .unwrap_or_else(|| panic!("no stats for interface {id}"))
    };

    let auto = stat(10);
    assert_eq!(auto.display_name, "AutoInterface[Auto]");
    assert_eq!((auto.clients, auto.peers), (None, Some(2)));
    assert_eq!((auto.rxb, auto.txb), (4, 6));
    assert!(auto.status);
    assert_eq!(auto.i2p, None);
    assert_eq!(
        stat(11).parent_display_name.as_deref(),
        Some("AutoInterface[Auto]")
    );
    assert_eq!(stat(11).name, "None");

    // Offline until its session accepts connections.
    let i2p = stat(20);
    assert!(!i2p.status);
    assert_eq!(
        i2p.i2p,
        Some(event::I2pEndpointStat {
            connectable: true,
            b32: None
        })
    );
    // Only the peer that connected to it is a client, and only its
    // transmitted bytes add up.
    assert_eq!((i2p.clients, i2p.peers), (Some(1), Some(1)));
    assert_eq!((i2p.rxb, i2p.txb), (40, 40));
    {
        let mut endpoint = endpoint.lock().unwrap();
        endpoint.online = true;
        endpoint.b32 = Some("abc.b32.i2p".into());
    }
    let i2p = stat(20);
    assert!(i2p.status);
    assert_eq!(i2p.i2p.unwrap().b32.as_deref(), Some("abc.b32.i2p"));
    // Only I2P peers report their tunnel state: one being created, and
    // none for a peer without a tunnel.
    assert_eq!(i2p.i2p_tunnel_state, None);
    assert_eq!(
        stat(21).i2p_tunnel_state,
        Some(Some("Creating Tunnel".to_string()))
    );
    assert_eq!(stat(22).i2p_tunnel_state, Some(None));
    assert_eq!(stat(11).i2p_tunnel_state, None);

    let multi = stat(40);
    assert_eq!(multi.display_name, "RNodeMultiInterface[Multi]");
    assert_eq!(multi.clients, Some(1));
    assert!(multi.status);
    assert_eq!(
        stat(30).parent_display_name.as_deref(),
        Some("RNodeMultiInterface[Multi]")
    );
    // As upstream, subinterfaces exist only while their device is
    // configured: the offline one is not listed.
    assert!(driver
        .interface_stats()
        .interfaces
        .iter()
        .all(|stat| stat.id != 31));
    // Without its device, the RNodeMultiInterface is listed down, alone.
    driver.interfaces.get_mut(&InterfaceId(30)).unwrap().online = false;
    let stats = driver.interface_stats().interfaces;
    let multi = stats.iter().find(|stat| stat.id == 40).unwrap();
    assert!(!multi.status);
    assert_eq!(multi.clients, Some(0));
    assert!(stats.iter().all(|stat| stat.id != 30 && stat.id != 31));
}

/// The driver runs upstream's I2P peer watchdog on its tick: the tunnel
/// state follows the peer's reads, and an idle peer gets keepalives.
#[cfg(feature = "iface-i2p")]
#[test]
fn driver_watches_i2p_peer_tunnels() {
    use crate::interface::i2p::tunnel::{PeerTunnel, TunnelState};
    use std::time::{Duration, Instant};

    let (callbacks, ..) = MockCallbacks::new();
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));
    let endpoint = Arc::new(Mutex::new(crate::interface::i2p::I2pEndpoint::default()));
    driver.listener_stats.push(ListenerStat {
        id: InterfaceId(20),
        name: "I2P".into(),
        display_name: "I2PInterface[I2P]".into(),
        interface_type: "I2PInterface".into(),
        mode: constants::MODE_FULL,
        gravity: 0,
        announces_to_internal: None,
        bitrate: Some(1000),
        mtu: 1064,
        ifac: None,
        clients: ListenerClients::I2pPeers(I2pListener {
            connectable: true,
            configured_peers: None,
            endpoint: Arc::clone(&endpoint),
        }),
    });
    let mut sent = Vec::new();
    for id in [21, 22] {
        let (writer, writes) = MockWriter::new();
        sent.push(writes);
        driver.handle_dynamic_interface_up_event(
            InterfaceId(id),
            Box::new(writer),
            event::DynamicInterfaceRegistration {
                info: make_interface_info(id),
                interface_type: "I2PInterfacePeer".into(),
                parent_id: InterfaceId(20),
                telemetry: event::InterfaceTelemetry::default(),
                ifac: None,
                display_name: None,
                short_name: Some("Connected peer on I2P".into()),
                reconnecting: false,
            },
        );
    }
    let ago = |secs| {
        Instant::now()
            .checked_sub(Duration::from_secs(secs))
            .unwrap()
    };
    // Connected 15 s ago and silent since: still active, but idle.
    let idle = Arc::new(PeerTunnel::at(ago(15), None));
    // Connected 25 s ago and silent since: unresponsive.
    let silent = Arc::new(PeerTunnel::at(ago(25), None));
    {
        let mut endpoint = endpoint.lock().unwrap();
        endpoint.tunnels.insert(InterfaceId(21), Arc::clone(&idle));
        endpoint
            .tunnels
            .insert(InterfaceId(22), Arc::clone(&silent));
    }
    // A peer that transmitted meanwhile is not idle.
    driver
        .interfaces
        .get_mut(&InterfaceId(22))
        .unwrap()
        .stats
        .txb = 100;

    driver.handle_tick_event();

    assert_eq!(idle.state(), TunnelState::Active);
    assert_eq!(silent.state(), TunnelState::Stale);
    // The keepalive is an empty frame (two HDLC flags on the wire); the
    // writer may send it from a thread of its own.
    let deadline = Instant::now() + Duration::from_secs(5);
    while sent[0].lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(*sent[0].lock().unwrap(), vec![Vec::<u8>::new()]);
    assert!(sent[1].lock().unwrap().is_empty());
    let stats = driver.interface_stats();
    let state = |id: u64| {
        stats
            .interfaces
            .iter()
            .find(|stat| stat.id == id)
            .unwrap()
            .i2p_tunnel_state
            .clone()
    };
    assert_eq!(state(21), Some(Some("Tunnel Active".into())));
    assert_eq!(state(22), Some(Some("Tunnel Unresponsive".into())));
}

/// Upstream adds an I2PInterfacePeer for each configured peer when its
/// I2P interface starts: listed, down and creating its tunnel, before it
/// connects, and kept, as the same interface and in the state its tunnel
/// was in, while it reconnects.
#[cfg(feature = "iface-i2p")]
#[test]
fn outbound_i2p_peer_is_listed_before_connecting_and_kept_across_reconnects() {
    use crate::interface::i2p::tunnel::{PeerTunnel, TunnelState};

    let (callbacks, ..) = MockCallbacks::new();
    let (tx, rx) = event::channel();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(callbacks));
    let endpoint = Arc::new(Mutex::new(crate::interface::i2p::I2pEndpoint::default()));
    driver.listener_stats.push(ListenerStat {
        id: InterfaceId(20),
        name: "I2P".into(),
        display_name: "I2PInterface[I2P]".into(),
        interface_type: "I2PInterface".into(),
        mode: constants::MODE_FULL,
        gravity: 0,
        announces_to_internal: None,
        bitrate: Some(256_000),
        mtu: 1064,
        ifac: None,
        clients: ListenerClients::I2pPeers(I2pListener {
            connectable: false,
            configured_peers: Some(1),
            endpoint: Arc::clone(&endpoint),
        }),
    });
    let tunnel = Arc::new(PeerTunnel::new(None));
    endpoint
        .lock()
        .unwrap()
        .tunnels
        .insert(InterfaceId(21), Arc::clone(&tunnel));
    let mut info = make_interface_info(21);
    info.wants_tunnel = true;
    driver.handle_dynamic_interface_up_event(
        InterfaceId(21),
        Box::new(crate::interface::UnavailableWriter),
        event::DynamicInterfaceRegistration {
            info,
            interface_type: "I2PInterfacePeer".into(),
            parent_id: InterfaceId(20),
            telemetry: event::InterfaceTelemetry::default(),
            ifac: None,
            display_name: Some("I2PInterfacePeer[I2P to peer.b32.i2p]".into()),
            short_name: Some("I2P to peer.b32.i2p".into()),
            reconnecting: true,
        },
    );
    let peer = |driver: &Driver| {
        driver
            .interface_stats()
            .interfaces
            .into_iter()
            .find(|stat| stat.id == 21)
    };
    let listed = peer(&driver).expect("listed before it connects");
    assert!(!listed.status);
    assert_eq!(listed.name, "I2P to peer.b32.i2p");
    assert_eq!(listed.interface_type, "I2PInterfacePeer");
    assert_eq!(
        listed.parent_display_name.as_deref(),
        Some("I2PInterface[I2P]")
    );
    assert_eq!(
        listed.i2p_tunnel_state,
        Some(Some("Creating Tunnel".into()))
    );
    // Not connected: no tunnel synthesized, and the watchdog leaves it be.
    assert!(driver.engine.local_tunnel_id(&InterfaceId(21)).is_none());
    driver.handle_tick_event();
    assert_eq!(tunnel.state(), TunnelState::Init);
    // An outbound peer is no client of its interface.
    let listener = |driver: &Driver| {
        driver
            .interface_stats()
            .interfaces
            .into_iter()
            .find(|stat| stat.id == 20)
            .unwrap()
    };
    assert_eq!(listener(&driver).clients, Some(0));

    // It connects, goes down, and connects again: the same interface.
    for _ in 0..2 {
        let (writer, _) = MockWriter::new();
        driver.handle_interface_up_event(InterfaceId(21), Some(Box::new(writer)), None);
        assert!(peer(&driver).unwrap().status);
        assert!(driver.interfaces[&InterfaceId(21)].online);
        driver.handle_interface_down_event(InterfaceId(21));
        let down = peer(&driver).expect("kept while it reconnects");
        assert!(!down.status);
        assert_eq!(
            down.parent_display_name.as_deref(),
            Some("I2PInterface[I2P]")
        );
        assert_eq!(down.i2p_tunnel_state, Some(Some("Creating Tunnel".into())));
        assert!(driver.engine.interface_info(&InterfaceId(21)).is_some());
    }
    assert_eq!(listener(&driver).clients, Some(0));
}

/// Upstream adds an auto-connected BackboneClientInterface whose first
/// connection fails anyway: listed, down, retrying, until its monitor
/// detaches it for having been down too long.
#[cfg(feature = "iface-backbone")]
#[test]
fn autoconnected_backbone_client_with_unreachable_target_is_kept_until_detached() {
    // A loopback port nothing listens on; 127.0.0.1 is never auto-connected to.
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.2:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.enable_upstream_autoconnect(1, Vec::new(), Vec::new());
    driver.autoconnect_discovered(&make_discovered_backbone(
        "unreachable",
        "127.0.0.2",
        Some(port),
        0x7d,
        1,
        20,
        time::now(),
    ));

    let id = driver
        .interfaces
        .iter()
        .find(|(_, entry)| entry.info.name == "unreachable")
        .map(|(id, _)| *id)
        .expect("kept although its target cannot be reached");
    assert!(driver.is_autoconnected(id));
    let stat = driver
        .interface_stats()
        .interfaces
        .into_iter()
        .find(|stat| stat.id == id.0)
        .unwrap();
    assert!(!stat.status);
    assert_eq!(stat.interface_type, "BackboneClientInterface");

    // Upstream's monitor detaches it once it was down for 12 seconds.
    let now = time::now();
    driver.tick_upstream_autoconnect(now + 5.0);
    assert!(driver.interfaces.contains_key(&id));
    driver.tick_upstream_autoconnect(now + 10.0);
    assert!(driver.interfaces.contains_key(&id));
    driver.tick_upstream_autoconnect(now + 20.0);
    assert!(!driver.interfaces.contains_key(&id));
    assert!(!driver.is_autoconnected(id));
}

/// Upstream auto-connects a discovered Backbone interface as a
/// BackboneClientInterface added with a configured bitrate of 5 Mbps,
/// which sets its hardware MTU to 8192, and which synthesizes a tunnel.
#[cfg(feature = "iface-backbone")]
#[test]
fn autoconnected_backbone_client_is_configured_as_upstream() {
    // 127.0.0.1 is never auto-connected to; the rest of 127/8 is loopback.
    let listener = std::net::TcpListener::bind("127.0.0.2:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut driver = new_test_driver();
    driver.discover_interfaces = true;
    driver.enable_upstream_autoconnect(1, Vec::new(), Vec::new());
    driver.autoconnect_discovered(&make_discovered_backbone(
        "discovered",
        "127.0.0.2",
        Some(port),
        0x7c,
        1,
        20,
        time::now(),
    ));

    let id = driver
        .interfaces
        .iter()
        .find(|(_, entry)| entry.info.name == "discovered")
        .map(|(id, _)| *id)
        .expect("the discovered interface is auto-connected");
    let entry = &driver.interfaces[&id];
    assert_eq!(entry.info.bitrate, Some(5_000_000));
    assert_eq!(entry.info.mtu, 8192);
    assert!(entry.info.wants_tunnel);
    assert_eq!(entry.interface_type, "BackboneClientInterface");
    let stat = driver
        .interface_stats()
        .interfaces
        .into_iter()
        .find(|stat| stat.id == id.0)
        .unwrap();
    assert_eq!(stat.interface_type, "BackboneClientInterface");
    assert_eq!(stat.bitrate, Some(5_000_000));
    // Upstream's configured `5E6` is a float, and reported as one.
    assert!(stat.bitrate_is_float);
    assert_eq!(stat.mtu, Some(8192));
    assert_eq!(
        stat.display_name,
        format!("BackboneInterface[discovered/127.0.0.2:{port}]")
    );
    drop(listener);
}

#[test]
fn direct_upgrade_keeps_unacknowledged_channel_messages() {
    let mut driver = new_test_driver();
    let (link_manager, link_id) = active_link_manager_with_route(InterfaceId(1));
    driver.link_manager = link_manager;
    let outstanding = |driver: &Driver| {
        driver
            .link_manager
            .link_entries()
            .into_iter()
            .find(|entry| entry.link_id == link_id)
            .and_then(|entry| entry.channel_outstanding)
    };
    let mut rng = OsRng;
    let actions = driver
        .link_manager
        .send_channel_message(&link_id, 0x0101, b"in flight", &mut rng)
        .unwrap();
    assert!(!actions.is_empty());
    assert_eq!(outstanding(&driver), Some(1));

    let (writer, _sent) = MockWriter::new();
    driver.dispatch_holepunch_actions(vec![
        crate::holepunch::orchestrator::HolePunchManagerAction::DirectConnectEstablished {
            link_id,
            session_id: [0x5E; 16],
            interface_id: InterfaceId(50_000),
            writer: Box::new(writer),
            info: Box::new(make_interface_info(50_000)),
            rtt: 0.001,
            mtu: 1400,
            peer_max_packet: None,
        },
    ]);
    // The link moved to the direct interface, and the application's
    // unacknowledged message is still there to be retransmitted.
    assert_eq!(
        driver.link_manager.direct_route_interface(&link_id),
        Some(InterfaceId(50_000))
    );
    assert_eq!(outstanding(&driver), Some(1));
}

#[test]
fn link_packet_packed_for_a_lost_direct_path_does_not_take_the_original_route() {
    let mut driver = new_test_driver();
    let (link_manager, link_id) = active_link_manager_with_route(InterfaceId(1));
    driver.link_manager = link_manager;
    let (writer, sent) = MockWriter::new();
    let entry = make_entry(1, Box::new(writer), true);
    driver.engine.register_interface(entry.info.clone());
    driver.interfaces.insert(InterfaceId(1), entry);
    let (direct_writer, _) = MockWriter::new();
    driver.dispatch_holepunch_actions(vec![
        crate::holepunch::orchestrator::HolePunchManagerAction::DirectConnectEstablished {
            link_id,
            session_id: [0x5E; 16],
            interface_id: InterfaceId(50_000),
            writer: Box::new(direct_writer),
            info: Box::new(make_interface_info(50_000)),
            rtt: 0.001,
            mtu: 1200,
            peer_max_packet: Some(rns_core::holepunch::DIRECT_MAX_PACKET),
        },
    ]);
    let mut rng = OsRng;
    let large = driver
        .link_manager
        .send_channel_message(&link_id, 0x0101, &[0x33; 1000], &mut rng)
        .unwrap();
    // The link falls back before the packet goes out.
    driver.link_manager.detach_direct_route(&link_id);
    driver.dispatch_link_actions(large);
    assert!(sent.lock().unwrap().is_empty());
    // Packets sized for the original route still take it.
    let small = driver
        .link_manager
        .try_send_on_link(&link_id, &[0x44; 100], constants::CONTEXT_NONE, &mut rng)
        .unwrap();
    driver.dispatch_link_actions(small);
    assert_eq!(sent.lock().unwrap().len(), 1);
}

/// A driver holding one end of an active link, proposing a direct
/// connection on it itself, and the peer's crossing UPGRADE_REQUEST.
fn glare_driver(link_initiator: bool) -> (Driver, [u8; 16], Vec<u8>) {
    let mut driver = new_test_driver();
    let mut initiator = crate::link_manager::LinkManager::new();
    let (responder, link_id) = establish_link(&mut initiator, [0xDD; 16], InterfaceId(1));
    driver.link_manager = if link_initiator { initiator } else { responder };
    let mut manager = crate::holepunch::orchestrator::HolePunchManager::new(
        vec!["127.0.0.1:4343".parse().unwrap()],
        rns_core::holepunch::ProbeProtocol::Rnsp,
        None,
    );
    manager.set_spawn_workers(false);
    manager.set_policy(HolePunchPolicy::AcceptAll);
    manager.set_allow_private_endpoints(true);
    driver.holepunch_manager = manager;
    let derived_key = driver.link_manager.get_derived_key(&link_id).unwrap();
    let tx = driver.get_event_sender();
    let _ = driver
        .holepunch_manager
        .propose_to_supported(link_id, &derived_key, &mut OsRng, &tx);
    assert!(driver.holepunch_manager.proposing(&link_id));

    // The peer's request, made with the same link key.
    let mut peer = rns_core::holepunch::HolePunchEngine::new(
        link_id,
        Some(rns_core::holepunch::Endpoint {
            addr: vec![10, 0, 0, 1],
            port: 4343,
        }),
        rns_core::holepunch::ProbeProtocol::Rnsp,
    );
    peer.propose(&derived_key, 1.0, &mut OsRng).unwrap();
    let request = match &peer
        .endpoints_discovered(
            rns_core::holepunch::Endpoint {
                addr: vec![10, 0, 0, 2],
                port: 41000,
            },
            2.0,
        )
        .unwrap()[0]
    {
        rns_core::holepunch::HolePunchAction::SendSignal { payload, .. } => {
            rns_core::holepunch::encode_signal(rns_core::holepunch::UPGRADE_REQUEST, payload)
        }
        other => panic!("unexpected {other:?}"),
    };
    (driver, link_id, request)
}

#[test]
fn crossing_proposals_keep_the_link_initiators() {
    let (mut driver, link_id, request) = glare_driver(true);
    driver.handle_direct_link_signal(link_id, &request);
    // The link initiator keeps its own proposal and takes up nothing.
    assert!(driver.holepunch_manager.proposing(&link_id));
    assert_eq!(driver.holepunch_manager.session_count(), 1);
}

#[test]
fn crossing_proposals_make_the_link_responder_answer() {
    let (mut driver, link_id, request) = glare_driver(false);
    driver.handle_direct_link_signal(link_id, &request);
    // The link responder drops its proposal and answers the peer's.
    assert!(!driver.holepunch_manager.proposing(&link_id));
    assert_eq!(driver.holepunch_manager.session_count(), 1);
}

#[test]
fn probe_config_keeps_the_direct_connect_settings() {
    let mut driver = new_test_driver();
    driver
        .holepunch_manager
        .set_policy(HolePunchPolicy::IdentifiedOnly);
    driver
        .holepunch_manager
        .set_allowed_identities(vec![[7; 16]]);
    driver.holepunch_manager.set_allow_private_endpoints(true);
    driver.set_probe_config(
        vec!["192.0.2.1:4343".parse().unwrap()],
        rns_core::holepunch::ProbeProtocol::Rnsp,
        None,
    );
    assert!(driver.holepunch_manager.identity_allowed(&[7; 16]));
    assert!(driver.holepunch_manager.allow_private_endpoints());
    assert_eq!(
        driver.holepunch_manager.policy(),
        HolePunchPolicy::IdentifiedOnly
    );
    assert!(driver.holepunch_manager.enabled());
}

#[test]
fn links_to_built_in_destinations_are_not_reported_to_the_application() {
    // Upstream keeps links to its management destinations inside
    // Transport; the application hears only of its own.
    let (tx, rx) = event::channel();
    let (mut cbs, established, closed, _identified) = MockCallbacks::with_link_tracking();
    let link_data = Arc::new(Mutex::new(Vec::new()));
    cbs.link_data = link_data.clone();
    let mut driver = Driver::new(make_transport_config(true), rx, tx, Box::new(cbs));
    let builtin = [0xB1; 16];
    let app_dest = [0xA1; 16];
    driver.builtin_link_destinations.insert(builtin);
    let established_link = |link_id: [u8; 16], dest_hash: [u8; 16], is_initiator: bool| {
        LinkManagerAction::LinkEstablished {
            link_id,
            dest_hash,
            hops: 1,
            rebalanced_at: None,
            rtt: 0.1,
            is_initiator,
        }
    };
    // A responder link to a built-in destination, one to an app
    // destination, and a link this node initiated to a built-in
    // destination elsewhere with the same hash.
    for (link_id, dest_hash, is_initiator) in [
        ([1; 16], builtin, false),
        ([2; 16], app_dest, false),
        ([3; 16], builtin, true),
    ] {
        driver.dispatch_link_actions(vec![
            established_link(link_id, dest_hash, is_initiator),
            LinkManagerAction::LinkDataReceived {
                link_id,
                context: 0,
                data: b"data".to_vec(),
            },
            LinkManagerAction::LinkClosed {
                link_id,
                reason: None,
            },
        ]);
    }
    let reported = |ids: Vec<TypedLinkId>| ids.into_iter().map(|id| id.0).collect::<Vec<_>>();
    assert_eq!(
        established
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.0 .0)
            .collect::<Vec<_>>(),
        vec![[2; 16], [3; 16]]
    );
    assert_eq!(
        reported(closed.lock().unwrap().clone()),
        vec![[2; 16], [3; 16]]
    );
    assert_eq!(
        link_data
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.0 .0)
            .collect::<Vec<_>>(),
        vec![[2; 16], [3; 16]]
    );
    assert!(driver.builtin_links.is_empty());
}
