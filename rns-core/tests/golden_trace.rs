//! Golden trace of the sans-io core: a behaviour-invariance gate.
//!
//! Scripted scenarios drive four transport engines (two endpoints, a
//! transport node between them and a slow leaf behind the transport node)
//! and the link, channel and resource engines on top of them. Every
//! action an engine emits is written to a trace, one line per action, with
//! the full hex of every outbound frame, together with table dumps after
//! the interesting steps. The trace is compared with the committed golden
//! file `tests/fixtures/golden/engine_trace.txt`, so a change to wire
//! output or to an engine decision fails this test.
//!
//! Everything is deterministic: fixed keys, `FixedRng` streams and a
//! scripted clock. Nothing reads the wall clock.
//!
//! When a change to the trace is intended, regenerate the golden file with
//!
//! ```text
//! RNS_GOLDEN_BLESS=1 cargo test -p rns-core --test golden_trace
//! ```
//!
//! and review the diff of the golden file before committing it. Should a
//! scenario panic part way, `RNS_GOLDEN_DUMP=<file>` saves the trace up to
//! the failure.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::path::PathBuf;

use rns_core::announce::AnnounceData;
use rns_core::buffer::types::NoopCompressor;
use rns_core::channel::{Channel, ChannelAction};
use rns_core::constants;
use rns_core::link::{LinkAction, LinkEngine, LinkMode, LinkState};
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::resource::receiver::ResourceReceiver;
use rns_core::resource::sender::ResourceSender;
use rns_core::resource::types::{ResourceAction, ResourceStatus};
use rns_core::transport::types::{
    InterfaceId, InterfaceInfo, TransportAction, TransportConfig, DEFAULT_MAX_PATH_DESTINATIONS,
};
use rns_core::transport::{InboundFrame, TransportEngine};
use rns_crypto::identity::Identity;
use rns_crypto::sha256::sha256;
use rns_crypto::x25519::X25519PrivateKey;
use rns_crypto::FixedRng;

// =============================================================================
// Determinism helpers
// =============================================================================

/// A `FixedRng` over 4096 bytes of a fixed pseudo-random stream, distinct
/// per `label`, so keys and IVs drawn from it do not repeat within a run.
fn rng(label: u8) -> FixedRng {
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ (u64::from(label) << 32 | u64::from(label));
    let bytes: Vec<u8> = (0..4096)
        .map(|_| {
            // xorshift64*
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect();
    FixedRng::new(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn short(bytes: &[u8]) -> String {
    hex(&bytes[..bytes.len().min(8)])
}

/// An announce random hash: five fixed bytes, then the emission time in
/// whole seconds, big-endian in five bytes, as upstream builds it.
fn random_hash(prefix: u8, now: f64) -> [u8; 10] {
    let mut rh = [prefix; 10];
    rh[5..].copy_from_slice(&(now as u64).to_be_bytes()[3..]);
    rh
}

// =============================================================================
// Trace formatting
// =============================================================================

fn packet_type_name(t: u8) -> &'static str {
    match t {
        constants::PACKET_TYPE_DATA => "DATA",
        constants::PACKET_TYPE_ANNOUNCE => "ANNOUNCE",
        constants::PACKET_TYPE_LINKREQUEST => "LINKREQUEST",
        _ => "PROOF",
    }
}

fn destination_type_name(t: u8) -> &'static str {
    match t {
        constants::DESTINATION_SINGLE => "SINGLE",
        constants::DESTINATION_GROUP => "GROUP",
        constants::DESTINATION_PLAIN => "PLAIN",
        _ => "LINK",
    }
}

/// A one-glance header summary of a frame, then its full bytes.
fn describe_frame(raw: &[u8]) -> String {
    let header = match RawPacket::unpack(raw) {
        Ok(p) => {
            let mut h = format!(
                "H{} {} {} ctx={:02x} cf={} hops={} dst={}",
                p.flags.header_type + 1,
                packet_type_name(p.flags.packet_type),
                destination_type_name(p.flags.destination_type),
                p.context,
                p.flags.context_flag,
                p.hops,
                short(&p.destination_hash),
            );
            if let Some(tid) = p.transport_id {
                let _ = write!(h, " tid={}", short(&tid));
            }
            h
        }
        Err(e) => format!("undecodable({e:?})"),
    };
    format!("[{header}] len={} raw={}", raw.len(), hex(raw))
}

fn iface_opt(i: Option<InterfaceId>) -> String {
    i.map_or_else(|| "-".to_string(), |i| i.0.to_string())
}

fn describe_action(a: &TransportAction) -> String {
    match a {
        TransportAction::SendOnInterface { interface, raw } => {
            format!("SendOnInterface if={} {}", interface.0, describe_frame(raw))
        }
        TransportAction::BroadcastOnAllInterfaces { raw, exclude } => format!(
            "BroadcastOnAllInterfaces exclude={} {}",
            iface_opt(*exclude),
            describe_frame(raw)
        ),
        TransportAction::DeliverLocal {
            destination_hash,
            raw,
            packet_hash,
            receiving_interface,
        } => format!(
            "DeliverLocal dst={} if={} hash={} {}",
            hex(destination_hash),
            receiving_interface.0,
            hex(packet_hash),
            describe_frame(raw)
        ),
        TransportAction::AnnounceReceived(r) => format!(
            "AnnounceReceived dst={} id={} name={} random={} ratchet={} app_data={} stamp={} \
             stamp_value={:?} lr_cost={:?} hops={} if={}",
            hex(&r.destination_hash),
            hex(&r.identity_hash),
            hex(&r.name_hash),
            hex(&r.random_hash),
            r.ratchet.map_or_else(|| "-".into(), |k| hex(&k)),
            r.app_data.as_deref().map_or_else(|| "-".into(), hex),
            r.stamp.map_or_else(|| "-".into(), |s| hex(&s)),
            r.stamp_value,
            r.lr_cost,
            r.hops,
            r.receiving_interface.0,
        ),
        TransportAction::PathUpdated {
            destination_hash,
            hops,
            next_hop,
            interface,
        } => format!(
            "PathUpdated dst={} hops={} next_hop={} if={}",
            hex(destination_hash),
            hops,
            hex(next_hop),
            interface.0
        ),
        TransportAction::ForwardToLocalClients { raw, exclude } => format!(
            "ForwardToLocalClients exclude={} {}",
            iface_opt(*exclude),
            describe_frame(raw)
        ),
        TransportAction::ForwardPlainBroadcast {
            raw,
            to_local,
            exclude,
        } => format!(
            "ForwardPlainBroadcast to_local={} exclude={} {}",
            to_local,
            iface_opt(*exclude),
            describe_frame(raw)
        ),
        TransportAction::CacheAnnounce { packet_hash, raw } => format!(
            "CacheAnnounce hash={} {}",
            hex(packet_hash),
            describe_frame(raw)
        ),
        TransportAction::TunnelSynthesize {
            interface,
            data,
            dest_hash,
        } => format!(
            "TunnelSynthesize if={} dst={} data={}",
            interface.0,
            hex(dest_hash),
            hex(data)
        ),
        TransportAction::TunnelEstablished {
            tunnel_id,
            interface,
        } => format!(
            "TunnelEstablished tunnel={} if={}",
            hex(tunnel_id),
            interface.0
        ),
        TransportAction::AnnounceRetransmit {
            destination_hash,
            hops,
            interface,
        } => format!(
            "AnnounceRetransmit dst={} hops={} if={}",
            hex(destination_hash),
            hops,
            iface_opt(*interface)
        ),
        TransportAction::LinkRequestReceived {
            link_id,
            destination_hash,
            receiving_interface,
        } => format!(
            "LinkRequestReceived link={} dst={} if={}",
            hex(link_id),
            hex(destination_hash),
            receiving_interface.0
        ),
        TransportAction::LinkEstablished { link_id, interface } => {
            format!("LinkEstablished link={} if={}", hex(link_id), interface.0)
        }
        TransportAction::LinkClosed { link_id } => format!("LinkClosed link={}", hex(link_id)),
        TransportAction::ProtocolViolation { interface } => {
            format!("ProtocolViolation if={}", interface.0)
        }
        TransportAction::AnnounceLocalPathResponse {
            destination_hash,
            tag,
            interface,
        } => format!(
            "AnnounceLocalPathResponse dst={} tag={} if={}",
            hex(destination_hash),
            hex(tag),
            interface.0
        ),
        TransportAction::StampPathRequest {
            destination_hash,
            tag,
            interface,
        } => format!(
            "StampPathRequest dst={} tag={} if={}",
            hex(destination_hash),
            hex(tag),
            interface.0
        ),
        TransportAction::RediscoverPath {
            destination_hash,
            skip_interface,
        } => format!(
            "RediscoverPath dst={} skip={}",
            hex(destination_hash),
            iface_opt(*skip_interface)
        ),
    }
}

fn describe_link_action(a: &LinkAction) -> String {
    match a {
        LinkAction::StateChanged {
            link_id,
            new_state,
            reason,
        } => format!(
            "StateChanged link={} state={:?} reason={:?}",
            hex(link_id),
            new_state,
            reason
        ),
        LinkAction::DataReceived {
            link_id,
            plaintext,
            context,
        } => format!(
            "DataReceived link={} ctx={:02x} plaintext={}",
            hex(link_id),
            context,
            hex(plaintext)
        ),
        LinkAction::RemoteIdentified {
            link_id,
            identity_hash,
            public_key,
        } => format!(
            "RemoteIdentified link={} id={} key={}",
            hex(link_id),
            hex(identity_hash),
            hex(public_key)
        ),
        LinkAction::LinkEstablished {
            link_id,
            rtt,
            is_initiator,
        } => format!(
            "LinkEstablished link={} rtt={:?} initiator={}",
            hex(link_id),
            rtt,
            is_initiator
        ),
        LinkAction::SendKeepalive { link_id } => format!("SendKeepalive link={}", hex(link_id)),
    }
}

fn describe_channel_action(a: &ChannelAction) -> String {
    match a {
        ChannelAction::SendOnLink { raw, sequence } => {
            format!("SendOnLink seq={} envelope={}", sequence, hex(raw))
        }
        ChannelAction::MessageReceived {
            msgtype,
            payload,
            sequence,
        } => format!(
            "MessageReceived type={:04x} seq={} payload={}",
            msgtype,
            sequence,
            hex(payload)
        ),
        ChannelAction::TeardownLink => "TeardownLink".to_string(),
        ChannelAction::PathFailed => "PathFailed".to_string(),
    }
}

fn describe_resource_action(a: &ResourceAction) -> String {
    match a {
        ResourceAction::SendAdvertisement(d) => format!("SendAdvertisement data={}", hex(d)),
        ResourceAction::SendPart(d) => format!("SendPart len={} data={}", d.len(), hex(d)),
        ResourceAction::SendRequest(d) => format!("SendRequest data={}", hex(d)),
        ResourceAction::SendHmu(d) => format!("SendHmu data={}", hex(d)),
        ResourceAction::SendProof(d) => format!("SendProof data={}", hex(d)),
        ResourceAction::SendCancelInitiator(d) => format!("SendCancelInitiator data={}", hex(d)),
        ResourceAction::SendCancelReceiver(d) => format!("SendCancelReceiver data={}", hex(d)),
        ResourceAction::TeardownLink => "TeardownLink".to_string(),
        ResourceAction::DataReceived {
            data,
            metadata,
            app_flag,
        } => format!(
            "DataReceived len={} sha256={} metadata={} app_flag={}",
            data.len(),
            hex(&sha256(data)),
            metadata.as_deref().map_or_else(|| "-".into(), hex),
            app_flag
        ),
        ResourceAction::Completed => "Completed".to_string(),
        ResourceAction::Failed(e) => format!("Failed {e:?}"),
        ResourceAction::ProgressUpdate { received, total } => {
            format!("ProgressUpdate {received}/{total}")
        }
    }
}

// =============================================================================
// Simulated network
// =============================================================================

fn config(identity_hash: Option<[u8; 16]>) -> TransportConfig {
    TransportConfig {
        transport_enabled: identity_hash.is_some(),
        identity_hash,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: constants::MAX_PR_TAGS,
        max_path_destinations: DEFAULT_MAX_PATH_DESTINATIONS,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    }
}

fn interface(id: u64, name: &str, bitrate: Option<u64>) -> InterfaceInfo {
    InterfaceInfo {
        stamp_costs: Default::default(),
        id: InterfaceId(id),
        name: name.to_string(),
        mode: constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: false,
        shared_medium: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: constants::MTU as u32,
        mtu_upgradable: true,
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
        ia_freq: 0.0,
        ia_samples: 0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
    }
}

fn path_request_destination() -> [u8; 16] {
    rns_core::destination::destination_hash("rnstransport", &["path", "request"], None)
}

const A: usize = 0;
const T: usize = 1;
const B: usize = 2;
const C: usize = 3;

struct Node {
    name: &'static str,
    engine: TransportEngine,
    rng: FixedRng,
    /// The node's interfaces, in id order, for broadcasts.
    interfaces: Vec<InterfaceId>,
    /// Packets delivered to local destinations, for the scripted
    /// application layer to pick up.
    delivered: VecDeque<(Vec<u8>, [u8; 32], u8)>,
    /// Path responses the engine asked the application to announce.
    path_responses: VecDeque<([u8; 16], Vec<u8>, InterfaceId)>,
}

struct Sim {
    nodes: Vec<Node>,
    /// Point-to-point wires: (node, interface) <-> (node, interface).
    wires: Vec<((usize, InterfaceId), (usize, InterfaceId))>,
    in_flight: VecDeque<(usize, InterfaceId, Vec<u8>)>,
    now: f64,
    trace: String,
}

impl Sim {
    fn new() -> Self {
        let t_identity = Identity::from_private_key(&[0x7a; 64]);
        let mut nodes = vec![
            Node::new("A", config(None), rng(0xa0)),
            Node::new("T", config(Some(*t_identity.hash())), rng(0x70)),
            Node::new("B", config(None), rng(0xb0)),
            Node::new("C", config(None), rng(0xc0)),
        ];
        nodes[A].add_interface(interface(1, "A/to-T", None));
        // Path requests from A's side search for unknown paths.
        nodes[T].add_interface(InterfaceInfo {
            recursive_prs: true,
            ..interface(1, "T/to-A", None)
        });
        nodes[T].add_interface(interface(2, "T/to-B", None));
        // A slow leaf link: announces to C are held in the announce queue.
        nodes[T].add_interface(interface(3, "T/to-C", Some(2_000)));
        nodes[B].add_interface(interface(1, "B/to-T", None));
        nodes[C].add_interface(interface(1, "C/to-T", Some(2_000)));
        Sim {
            nodes,
            wires: vec![
                ((A, InterfaceId(1)), (T, InterfaceId(1))),
                ((T, InterfaceId(2)), (B, InterfaceId(1))),
                ((T, InterfaceId(3)), (C, InterfaceId(1))),
            ],
            in_flight: VecDeque::new(),
            now: 1_000.0,
            trace: String::new(),
        }
    }

    fn scenario(&mut self, name: &str) {
        let _ = writeln!(self.trace, "\n== scenario: {name}");
    }

    fn note(&mut self, text: &str) {
        let _ = writeln!(self.trace, "  # {text}");
    }

    fn at(&mut self, now: f64) {
        assert!(now >= self.now, "the scripted clock only moves forward");
        self.now = now;
        let _ = writeln!(self.trace, "-- t={now:?}");
    }

    fn peer_of(&self, node: usize, iface: InterfaceId) -> Option<(usize, InterfaceId)> {
        self.wires.iter().find_map(|&(a, b)| {
            if a == (node, iface) {
                Some(b)
            } else if b == (node, iface) {
                Some(a)
            } else {
                None
            }
        })
    }

    fn transmit(&mut self, node: usize, iface: InterfaceId, raw: &[u8]) {
        if let Some((peer, peer_iface)) = self.peer_of(node, iface) {
            self.in_flight.push_back((peer, peer_iface, raw.to_vec()));
        }
    }

    /// Log the engine's actions and carry them out on the simulated wires.
    fn apply(&mut self, node: usize, origin: &str, actions: Vec<TransportAction>) {
        let name = self.nodes[node].name;
        if actions.is_empty() {
            let _ = writeln!(self.trace, "  {name} {origin}: (no actions)");
        }
        for action in actions {
            let _ = writeln!(
                self.trace,
                "  {name} {origin}: {}",
                describe_action(&action)
            );
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    self.transmit(node, interface, &raw);
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    for iface in self.nodes[node].interfaces.clone() {
                        if Some(iface) != exclude {
                            self.transmit(node, iface, &raw);
                        }
                    }
                }
                TransportAction::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                    receiving_interface,
                } => {
                    let packet = RawPacket::unpack(&raw).unwrap();
                    if destination_hash == path_request_destination() {
                        // The node layer hands path requests back to the engine.
                        let now = self.now;
                        let engine = &mut self.nodes[node].engine;
                        let actions = match engine.accept_path_request(
                            packet.data(),
                            receiving_interface,
                            now,
                        ) {
                            Some(request) => engine
                                .handle_accepted_path_request_with_ingress_limit(request, false),
                            None => Vec::new(),
                        };
                        self.apply(node, "path-request", actions);
                    } else if node != T {
                        // T runs no applications: what it delivers locally
                        // (proofs, for receipts it does not hold) ends here.
                        self.nodes[node].delivered.push_back((
                            raw.to_vec(),
                            packet_hash,
                            packet.hops,
                        ));
                    }
                }
                TransportAction::AnnounceLocalPathResponse {
                    destination_hash,
                    tag,
                    interface,
                } => {
                    self.nodes[node]
                        .path_responses
                        .push_back((destination_hash, tag, interface));
                }
                _ => {}
            }
        }
    }

    /// Deliver every frame in flight, and the frames those produce, in order.
    fn pump(&mut self) {
        let mut budget = 1_000;
        while let Some((node, iface, raw)) = self.in_flight.pop_front() {
            budget -= 1;
            assert!(budget > 0, "the simulated network does not settle");
            let now = self.now;
            let n = &mut self.nodes[node];
            let actions = n
                .engine
                .handle_inbound(InboundFrame::new(&raw, iface, now), &mut n.rng);
            self.apply(node, &format!("rx@if{}", iface.0), actions);
        }
    }

    /// Lose every frame in flight.
    fn drop_in_flight(&mut self) {
        let n = self.in_flight.len();
        self.in_flight.clear();
        let _ = writeln!(self.trace, "  (wire) dropped {n} frame(s)");
    }

    fn outbound(&mut self, node: usize, packet: &RawPacket, dest_type: u8, attached: Option<u64>) {
        let now = self.now;
        let actions = self.nodes[node].engine.handle_outbound(
            packet,
            dest_type,
            attached.map(InterfaceId),
            now,
        );
        let name = self.nodes[node].name;
        let _ = writeln!(
            self.trace,
            "  {name} app: send {}",
            describe_frame(&packet.raw)
        );
        self.apply(node, "outbound", actions);
        self.pump();
    }

    fn tick(&mut self, node: usize) {
        let now = self.now;
        let n = &mut self.nodes[node];
        let actions = n.engine.tick(now, &mut n.rng);
        if !actions.is_empty() {
            self.apply(node, "tick", actions);
        }
    }

    fn tick_all(&mut self) {
        for node in 0..self.nodes.len() {
            self.tick(node);
        }
        self.pump();
    }

    fn take_delivered(&mut self, node: usize) -> (RawPacket, [u8; 32]) {
        let (raw, hash, _) = self.nodes[node]
            .delivered
            .pop_front()
            .unwrap_or_else(|| panic!("{} expected a delivery", self.nodes[node].name));
        (RawPacket::unpack(&raw).unwrap(), hash)
    }

    fn dump_tables(&mut self) {
        for node in 0..self.nodes.len() {
            let n = &self.nodes[node];
            let mut rows = n.engine.get_path_table(None);
            rows.sort_by_key(|row| row.0);
            let mut out = format!(
                "  [{}] paths={} links={} reverse={} announces={} held={} queued={} \
                 hashlist={} rate={}",
                n.name,
                n.engine.path_table_count(),
                n.engine.link_table_count(),
                n.engine.reverse_table_count(),
                n.engine.announce_table_count(),
                n.engine.held_announces_count(),
                n.engine.queued_announce_count(),
                n.engine.packet_hashlist_len(),
                n.engine.rate_limiter_count(),
            );
            for (dst, timestamp, next_hop, hops, expires, used, iface) in rows {
                let _ = write!(
                    out,
                    "\n  [{}]   path dst={} hops={} next_hop={} if={} timestamp={:?} \
                     expires={:?} used={:?}",
                    n.name,
                    hex(&dst),
                    hops,
                    hex(&next_hop),
                    iface,
                    timestamp,
                    expires,
                    used
                );
            }
            let _ = writeln!(self.trace, "{out}");
        }
    }
}

/// When a scenario panics, `RNS_GOLDEN_DUMP=<file>` keeps the trace up to
/// the failure for inspection.
impl Drop for Sim {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Ok(path) = std::env::var("RNS_GOLDEN_DUMP") {
                let _ = std::fs::write(path, &self.trace);
            }
        }
    }
}

impl Node {
    fn new(name: &'static str, config: TransportConfig, rng: FixedRng) -> Self {
        // The node layer registers the transport control destinations.
        let mut engine = TransportEngine::new(config);
        engine.register_destination(path_request_destination(), constants::DESTINATION_PLAIN);
        engine.register_destination(
            rns_core::destination::destination_hash(
                "rnstransport",
                &["tunnel", "synthesize"],
                None,
            ),
            constants::DESTINATION_PLAIN,
        );
        Node {
            name,
            engine,
            rng,
            interfaces: Vec::new(),
            delivered: VecDeque::new(),
            path_responses: VecDeque::new(),
        }
    }

    fn add_interface(&mut self, info: InterfaceInfo) {
        self.interfaces.push(info.id);
        self.interfaces.sort();
        self.engine.register_interface(info);
    }
}

// =============================================================================
// Packet builders, as the node layer packs them
// =============================================================================

struct Endpoint {
    identity: Identity,
    name_hash: [u8; 10],
    hash: [u8; 16],
}

impl Endpoint {
    fn new(private_key: u8, aspect: &str) -> Self {
        let identity = Identity::from_private_key(&[private_key; 64]);
        let name_hash = rns_core::destination::name_hash("golden", &[aspect]);
        let hash =
            rns_core::destination::destination_hash("golden", &[aspect], Some(identity.hash()));
        Endpoint {
            identity,
            name_hash,
            hash,
        }
    }

    fn signing_public(&self) -> [u8; 32] {
        self.identity.get_public_key().unwrap()[32..]
            .try_into()
            .unwrap()
    }

    fn announce(
        &self,
        random_hash: &[u8; 10],
        ratchet: Option<&[u8; 32]>,
        app_data: Option<&[u8]>,
        context: u8,
    ) -> RawPacket {
        let (data, has_ratchet) = AnnounceData::pack(
            &self.identity,
            &self.hash,
            &self.name_hash,
            random_hash,
            ratchet,
            app_data,
        )
        .unwrap();
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: if has_ratchet {
                constants::FLAG_SET
            } else {
                constants::FLAG_UNSET
            },
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };
        RawPacket::pack(flags, 0, &self.hash, None, context, &data).unwrap()
    }
}

fn link_packet(link_id: &[u8; 16], packet_type: u8, context: u8, data: &[u8]) -> RawPacket {
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_LINK,
        packet_type,
    };
    RawPacket::pack(flags, 0, link_id, None, context, data).unwrap()
}

/// The explicit proof of a link packet: its hash and the link's signature.
fn link_proof(link: &LinkEngine, packet_hash: &[u8; 32]) -> RawPacket {
    let mut data = packet_hash.to_vec();
    data.extend_from_slice(&link.sign_packet_hash(packet_hash));
    link_packet(
        link.link_id(),
        constants::PACKET_TYPE_PROOF,
        constants::CONTEXT_NONE,
        &data,
    )
}

fn log_link(sim: &mut Sim, who: &str, actions: &[LinkAction]) {
    for a in actions {
        let _ = writeln!(sim.trace, "  {who} link: {}", describe_link_action(a));
    }
}

fn log_channel(sim: &mut Sim, who: &str, actions: &[ChannelAction]) {
    for a in actions {
        let _ = writeln!(sim.trace, "  {who} channel: {}", describe_channel_action(a));
    }
}

fn log_resource(sim: &mut Sim, who: &str, actions: &[ResourceAction]) {
    for a in actions {
        let _ = writeln!(
            sim.trace,
            "  {who} resource: {}",
            describe_resource_action(a)
        );
    }
}

// =============================================================================
// The scripted run
// =============================================================================

fn run_trace() -> String {
    let mut sim = Sim::new();
    let a_dest = Endpoint::new(0xa1, "sink");
    let b_dest = Endpoint::new(0xb1, "echo");
    let c_dest = Endpoint::new(0xc1, "leaf");
    sim.nodes[A]
        .engine
        .register_destination(a_dest.hash, constants::DESTINATION_SINGLE);
    sim.nodes[B]
        .engine
        .register_destination(b_dest.hash, constants::DESTINATION_SINGLE);
    sim.nodes[C]
        .engine
        .register_destination(c_dest.hash, constants::DESTINATION_SINGLE);
    let _ = writeln!(
        sim.trace,
        "# topology: A(if1) <-> (if1)T(if2) <-> (if1)B ; T(if3, 2000 bps) <-> (if1)C\n\
         # T transport id={}\n# A dest={}\n# B dest={}\n# C dest={}",
        hex(sim.nodes[T].engine.identity_hash().unwrap()),
        hex(&a_dest.hash),
        hex(&b_dest.hash),
        hex(&c_dest.hash),
    );

    // -------------------------------------------------------------------------
    sim.scenario("announce with app_data, origination and rebroadcast");
    sim.at(1_000.0);
    let announce = b_dest.announce(
        &random_hash(0xb5, sim.now),
        None,
        Some(b"golden-b app data"),
        constants::CONTEXT_NONE,
    );
    sim.outbound(B, &announce, constants::DESTINATION_SINGLE, None);
    sim.dump_tables();
    for t in [1_000.25, 1_000.5, 1_001.0] {
        sim.at(t);
        sim.tick_all();
    }
    sim.dump_tables();
    assert_eq!(sim.nodes[A].engine.hops_to(&b_dest.hash), Some(2));

    // -------------------------------------------------------------------------
    sim.scenario("announce with ratchet and app_data");
    sim.at(1_010.0);
    let ratchet = X25519PrivateKey::from_bytes(&[0x5a; 32])
        .public_key()
        .public_bytes();
    let announce = a_dest.announce(
        &random_hash(0xa5, sim.now),
        Some(&ratchet),
        Some(b"golden-a ratcheted"),
        constants::CONTEXT_NONE,
    );
    sim.outbound(A, &announce, constants::DESTINATION_SINGLE, None);
    for t in [1_010.5, 1_011.0] {
        sim.at(t);
        sim.tick_all();
    }
    sim.dump_tables();
    assert_eq!(sim.nodes[B].engine.hops_to(&a_dest.hash), Some(2));

    // -------------------------------------------------------------------------
    sim.scenario("leaf announce, then retransmit and announce queue timers");
    sim.at(1_020.0);
    let announce = c_dest.announce(
        &random_hash(0xc5, sim.now),
        None,
        None,
        constants::CONTEXT_NONE,
    );
    sim.outbound(C, &announce, constants::DESTINATION_SINGLE, None);
    let mut t = 1_020.0;
    while t < 1_200.0 {
        t += 1.0;
        sim.at(t);
        sim.tick_all();
    }
    sim.dump_tables();

    // -------------------------------------------------------------------------
    sim.scenario("path request for a path the transport node knows");
    sim.at(1_300.0);
    let dropped = sim.nodes[A].engine.drop_path(&b_dest.hash);
    sim.note(&format!("A drops its path to B: {dropped}"));
    let request = sim.nodes[A]
        .engine
        .build_path_request(&b_dest.hash, &[0x01; 16], None)
        .unwrap();
    let request = RawPacket::unpack(&request).unwrap();
    sim.outbound(A, &request, constants::DESTINATION_PLAIN, None);
    for t in [1_300.5, 1_301.0, 1_302.0] {
        sim.at(t);
        sim.tick_all();
    }
    sim.dump_tables();

    // -------------------------------------------------------------------------
    sim.scenario("path request forwarded, answered by the destination");
    // A tick past the path request gate timeout culls the earlier request.
    sim.at(1_399.0);
    sim.tick_all();
    sim.at(1_400.0);
    let dropped = sim.nodes[T].engine.drop_path(&b_dest.hash);
    sim.note(&format!("T drops its path to B: {dropped}"));
    let request = sim.nodes[A]
        .engine
        .build_path_request(&b_dest.hash, &[0x02; 16], None)
        .unwrap();
    let request = RawPacket::unpack(&request).unwrap();
    sim.outbound(A, &request, constants::DESTINATION_PLAIN, None);
    while let Some((dst, tag, iface)) = sim.nodes[B].path_responses.pop_front() {
        assert_eq!(dst, b_dest.hash);
        sim.note(&format!("B answers path request tag={}", hex(&tag)));
        let response = b_dest.announce(
            &random_hash(0xb6, sim.now),
            None,
            Some(b"golden-b app data"),
            constants::CONTEXT_PATH_RESPONSE,
        );
        sim.outbound(B, &response, constants::DESTINATION_SINGLE, Some(iface.0));
    }
    for t in [1_400.5, 1_401.0, 1_402.0, 1_405.0, 1_410.0] {
        sim.at(t);
        sim.tick_all();
    }
    sim.dump_tables();
    assert!(sim.nodes[T].engine.has_path(&b_dest.hash));

    // -------------------------------------------------------------------------
    sim.scenario("link establishment A -> B through T");
    sim.at(1_500.0);
    let hops = sim.nodes[A].engine.hops_to(&b_dest.hash).unwrap();
    let mut a_app_rng = rng(0xa9);
    let mut b_app_rng = rng(0xb9);
    let (mut initiator, request_data) = LinkEngine::new_initiator(
        &b_dest.hash,
        hops,
        LinkMode::Aes256Cbc,
        Some(constants::MTU as u32),
        sim.now,
        &mut a_app_rng,
    );
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_LINKREQUEST,
    };
    let link_request = RawPacket::pack(
        flags,
        0,
        &b_dest.hash,
        None,
        constants::CONTEXT_NONE,
        &request_data,
    )
    .unwrap();
    initiator.set_link_id_from_hashable(&link_request.get_hashable_part(), request_data.len());
    let link_id = *initiator.link_id();
    sim.note(&format!("link id {}", hex(&link_id)));
    sim.nodes[A]
        .engine
        .register_destination(link_id, constants::DESTINATION_LINK);
    sim.outbound(A, &link_request, constants::DESTINATION_SINGLE, None);

    sim.at(1_500.25);
    let (received, _) = sim.take_delivered(B);
    let (mut responder, lrproof) = LinkEngine::new_responder(
        b_dest.identity.signing_key().unwrap(),
        &b_dest.signing_public(),
        received.data(),
        &received.get_hashable_part(),
        &b_dest.hash,
        received.hops,
        sim.now,
        &mut b_app_rng,
    )
    .unwrap();
    assert_eq!(*responder.link_id(), link_id);
    sim.nodes[B]
        .engine
        .register_destination(link_id, constants::DESTINATION_LINK);
    let proof = link_packet(
        &link_id,
        constants::PACKET_TYPE_PROOF,
        constants::CONTEXT_LRPROOF,
        &lrproof,
    );
    sim.outbound(B, &proof, constants::DESTINATION_LINK, None);

    sim.at(1_500.5);
    let (received, _) = sim.take_delivered(A);
    let (lrrtt, actions) = initiator
        .handle_lrproof_with_hops(
            received.data(),
            &b_dest.signing_public(),
            Some(received.hops),
            sim.now,
            &mut a_app_rng,
        )
        .unwrap();
    log_link(&mut sim, "A", &actions);
    let rtt = link_packet(
        &link_id,
        constants::PACKET_TYPE_DATA,
        constants::CONTEXT_LRRTT,
        &lrrtt,
    );
    sim.outbound(A, &rtt, constants::DESTINATION_LINK, None);

    sim.at(1_500.75);
    let (received, _) = sim.take_delivered(B);
    let actions = responder
        .handle_lrrtt_with_hops(received.data(), Some(received.hops), sim.now)
        .unwrap();
    log_link(&mut sim, "B", &actions);
    assert_eq!(initiator.state(), LinkState::Active);
    assert_eq!(responder.state(), LinkState::Active);
    sim.dump_tables();

    // -------------------------------------------------------------------------
    sim.scenario("link packets both ways, with proofs");
    sim.at(1_510.0);
    let ciphertext = initiator.encrypt(b"ping from A", &mut a_app_rng).unwrap();
    let ping = link_packet(
        &link_id,
        constants::PACKET_TYPE_DATA,
        constants::CONTEXT_NONE,
        &ciphertext,
    );
    sim.outbound(A, &ping, constants::DESTINATION_LINK, None);
    let (received, hash) = sim.take_delivered(B);
    let plaintext = responder.decrypt(received.data()).unwrap();
    sim.note(&format!("B decrypts {}", hex(&plaintext)));
    let actions = responder.record_inbound(sim.now);
    log_link(&mut sim, "B", &actions);
    let proof = link_proof(&responder, &hash);
    sim.outbound(B, &proof, constants::DESTINATION_LINK, None);
    let (received, _) = sim.take_delivered(A);
    let valid = initiator.validate_packet_proof(
        received.data()[..32].try_into().unwrap(),
        received.data()[32..96].try_into().unwrap(),
    );
    sim.note(&format!("A validates proof of ping: {valid}"));
    assert!(valid);

    sim.at(1_511.0);
    let ciphertext = responder.encrypt(b"pong from B", &mut b_app_rng).unwrap();
    let pong = link_packet(
        &link_id,
        constants::PACKET_TYPE_DATA,
        constants::CONTEXT_NONE,
        &ciphertext,
    );
    sim.outbound(B, &pong, constants::DESTINATION_LINK, None);
    let (received, hash) = sim.take_delivered(A);
    let plaintext = initiator.decrypt(received.data()).unwrap();
    sim.note(&format!("A decrypts {}", hex(&plaintext)));
    let proof = link_proof(&initiator, &hash);
    sim.outbound(A, &proof, constants::DESTINATION_LINK, None);
    let (received, _) = sim.take_delivered(B);
    let valid = responder.validate_packet_proof(
        received.data()[..32].try_into().unwrap(),
        received.data()[32..96].try_into().unwrap(),
    );
    sim.note(&format!("B validates proof of pong: {valid}"));
    assert!(valid);

    // -------------------------------------------------------------------------
    sim.scenario("channel message, proof, and a timer-driven retransmit");
    sim.at(1_520.0);
    let mut a_channel = Channel::new(initiator.rtt().unwrap());
    let mut b_channel = Channel::new(responder.rtt().unwrap());
    let actions = a_channel
        .send(0x0101, b"hello channel", sim.now, initiator.mdu())
        .unwrap();
    log_channel(&mut sim, "A", &actions);
    let mut sent = Vec::new();
    for action in actions {
        if let ChannelAction::SendOnLink { raw, sequence } = action {
            let ciphertext = initiator.encrypt(&raw, &mut a_app_rng).unwrap();
            let packet = link_packet(
                &link_id,
                constants::PACKET_TYPE_DATA,
                constants::CONTEXT_CHANNEL,
                &ciphertext,
            );
            sent.push((packet.get_hash(), sequence));
            sim.outbound(A, &packet, constants::DESTINATION_LINK, None);
        }
    }
    let (received, hash) = sim.take_delivered(B);
    let plaintext = responder.decrypt(received.data()).unwrap();
    let actions = b_channel.receive(&plaintext, sim.now);
    log_channel(&mut sim, "B", &actions);
    let proof = link_proof(&responder, &hash);
    sim.outbound(B, &proof, constants::DESTINATION_LINK, None);
    let (received, _) = sim.take_delivered(A);
    let proved: [u8; 32] = received.data()[..32].try_into().unwrap();
    let sequence = sent.iter().find(|(h, _)| *h == proved).unwrap().1;
    let actions = a_channel.packet_delivered(sequence);
    log_channel(&mut sim, "A", &actions);

    sim.at(1_521.0);
    let actions = a_channel
        .send(0x0101, b"lost the first time", sim.now, initiator.mdu())
        .unwrap();
    log_channel(&mut sim, "A", &actions);
    for action in &actions {
        if let ChannelAction::SendOnLink { raw, .. } = action {
            let ciphertext = initiator.encrypt(raw, &mut a_app_rng).unwrap();
            let packet = link_packet(
                &link_id,
                constants::PACKET_TYPE_DATA,
                constants::CONTEXT_CHANNEL,
                &ciphertext,
            );
            let _ = writeln!(sim.trace, "  A app: send {}", describe_frame(&packet.raw));
            let now = sim.now;
            let actions = sim.nodes[A].engine.handle_outbound(
                &packet,
                constants::DESTINATION_LINK,
                None,
                now,
            );
            sim.apply(A, "outbound", actions);
            sim.drop_in_flight();
        }
    }
    let timeout = a_channel.get_packet_timeout(1);
    sim.note(&format!("channel packet timeout {timeout:?}"));
    sim.at(1_521.0 + timeout + 0.25);
    let actions = a_channel.tick(sim.now);
    log_channel(&mut sim, "A", &actions);
    assert!(!actions.is_empty(), "the channel retransmits");
    for action in actions {
        if let ChannelAction::SendOnLink { raw, .. } = action {
            let ciphertext = initiator.encrypt(&raw, &mut a_app_rng).unwrap();
            let packet = link_packet(
                &link_id,
                constants::PACKET_TYPE_DATA,
                constants::CONTEXT_CHANNEL,
                &ciphertext,
            );
            sim.outbound(A, &packet, constants::DESTINATION_LINK, None);
        }
    }
    let (received, _) = sim.take_delivered(B);
    let plaintext = responder.decrypt(received.data()).unwrap();
    let actions = b_channel.receive(&plaintext, sim.now);
    log_channel(&mut sim, "B", &actions);

    // -------------------------------------------------------------------------
    sim.scenario("multi-part resource A -> B");
    sim.at(1_600.0);
    let payload: Vec<u8> = (0..1_400u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let sdu = constants::MTU - constants::HEADER_MAXSIZE - constants::IFAC_MIN_SIZE;
    let encrypt_rng = RefCell::new(rng(0xaa));
    let encrypt = |data: &[u8]| -> Vec<u8> {
        initiator
            .encrypt(data, &mut *encrypt_rng.borrow_mut())
            .unwrap()
    };
    let mut sender = ResourceSender::new(
        &payload,
        None,
        sdu,
        &encrypt,
        &NoopCompressor,
        &mut a_app_rng,
        sim.now,
        false,
        false,
        None,
        1,
        1,
        None,
        initiator.rtt().unwrap(),
        6.0,
    )
    .unwrap();
    sim.note(&format!("resource has {} parts", sender.total_parts()));
    assert!(sender.total_parts() >= 3);
    let actions = sender.advertise(sim.now);
    log_resource(&mut sim, "A", &actions);
    let advertisement = sender.get_advertisement(0);
    let send_adv = |sim: &mut Sim, initiator: &LinkEngine, rng: &mut FixedRng| {
        let ciphertext = initiator.encrypt(&advertisement, rng).unwrap();
        let packet = link_packet(
            &link_id,
            constants::PACKET_TYPE_DATA,
            constants::CONTEXT_RESOURCE_ADV,
            &ciphertext,
        );
        let _ = writeln!(sim.trace, "  A app: send {}", describe_frame(&packet.raw));
        let now = sim.now;
        let actions =
            sim.nodes[A]
                .engine
                .handle_outbound(&packet, constants::DESTINATION_LINK, None, now);
        sim.apply(A, "outbound", actions);
    };
    send_adv(&mut sim, &initiator, &mut a_app_rng);
    sim.drop_in_flight();

    // The advertisement was lost: the sender's timer advertises again.
    let mut t = 1_600.0;
    loop {
        t += 1.0;
        sim.at(t);
        let actions = sender.tick(sim.now);
        log_resource(&mut sim, "A", &actions);
        if actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendAdvertisement(_)))
        {
            break;
        }
        assert!(t < 1_700.0, "the sender re-advertises");
    }
    send_adv(&mut sim, &initiator, &mut a_app_rng);
    sim.pump();

    let (received, _) = sim.take_delivered(B);
    let adv = responder.decrypt(received.data()).unwrap();
    let mut receiver = ResourceReceiver::from_advertisement(
        &adv,
        sdu,
        responder.rtt().unwrap(),
        sim.now,
        None,
        None,
    )
    .unwrap();
    let mut b_actions = receiver.accept(sim.now);
    let mut rounds = 0;
    while receiver.status != ResourceStatus::Complete {
        rounds += 1;
        assert!(rounds < 20, "the resource transfer completes");
        log_resource(&mut sim, "B", &b_actions);
        let mut a_actions = Vec::new();
        for action in std::mem::take(&mut b_actions) {
            match action {
                ResourceAction::SendRequest(data) => {
                    let ciphertext = responder.encrypt(&data, &mut b_app_rng).unwrap();
                    let packet = link_packet(
                        &link_id,
                        constants::PACKET_TYPE_DATA,
                        constants::CONTEXT_RESOURCE_REQ,
                        &ciphertext,
                    );
                    sim.outbound(B, &packet, constants::DESTINATION_LINK, None);
                    let (received, _) = sim.take_delivered(A);
                    let request = initiator.decrypt(received.data()).unwrap();
                    sim.at(sim.now + 0.125);
                    a_actions.extend(sender.handle_request(&request, sim.now));
                }
                ResourceAction::SendProof(data) => {
                    let packet = link_packet(
                        &link_id,
                        constants::PACKET_TYPE_PROOF,
                        constants::CONTEXT_RESOURCE_PRF,
                        &data,
                    );
                    sim.outbound(B, &packet, constants::DESTINATION_LINK, None);
                    let (received, _) = sim.take_delivered(A);
                    a_actions.extend(sender.handle_proof(received.data(), sim.now));
                }
                _ => {}
            }
        }
        log_resource(&mut sim, "A", &a_actions);
        sim.at(sim.now + 0.125);
        for action in a_actions {
            if let ResourceAction::SendPart(data) = action {
                let packet = link_packet(
                    &link_id,
                    constants::PACKET_TYPE_DATA,
                    constants::CONTEXT_RESOURCE,
                    &data,
                );
                sim.outbound(A, &packet, constants::DESTINATION_LINK, None);
                let (received, _) = sim.take_delivered(B);
                b_actions.extend(receiver.receive_part(received.data(), sim.now));
            }
        }
        if receiver.status == ResourceStatus::Transferring
            && receiver.received_count == receiver.total_parts
        {
            let decrypt = |parts: &[&[u8]], skip: usize| -> Result<Vec<u8>, ()> {
                responder.decrypt_chunks(parts, skip).map_err(|_| ())
            };
            b_actions.extend(receiver.assemble(&decrypt, &NoopCompressor));
        } else if receiver.outstanding_parts == 0 && receiver.status == ResourceStatus::Transferring
        {
            b_actions.extend(receiver.request_next(sim.now));
        }
        if sender.status == ResourceStatus::Complete && b_actions.is_empty() {
            break;
        }
    }
    log_resource(&mut sim, "B", &b_actions);
    for action in std::mem::take(&mut b_actions) {
        if let ResourceAction::SendProof(data) = action {
            let packet = link_packet(
                &link_id,
                constants::PACKET_TYPE_PROOF,
                constants::CONTEXT_RESOURCE_PRF,
                &data,
            );
            sim.outbound(B, &packet, constants::DESTINATION_LINK, None);
            let (received, _) = sim.take_delivered(A);
            let actions = sender.handle_proof(received.data(), sim.now);
            log_resource(&mut sim, "A", &actions);
        }
    }
    assert_eq!(sender.status, ResourceStatus::Complete);
    assert_eq!(receiver.status, ResourceStatus::Complete);

    // -------------------------------------------------------------------------
    sim.scenario("link keepalive and teardown");
    let keepalive_at = 1_600.0 + initiator.keepalive_interval() + 1.0;
    sim.note(&format!(
        "keepalive interval {:?}",
        initiator.keepalive_interval()
    ));
    sim.at(keepalive_at);
    let actions = initiator.tick(sim.now);
    log_link(&mut sim, "A", &actions);
    assert!(actions
        .iter()
        .any(|a| matches!(a, LinkAction::SendKeepalive { .. })));
    let keepalive = link_packet(
        &link_id,
        constants::PACKET_TYPE_DATA,
        constants::CONTEXT_KEEPALIVE,
        &[0xff],
    );
    sim.outbound(A, &keepalive, constants::DESTINATION_LINK, None);
    let (received, _) = sim.take_delivered(B);
    let reply = responder.should_reply_keepalive(received.data(), sim.now);
    sim.note(&format!("B replies to keepalive: {reply}"));
    let actions = responder.record_inbound(sim.now);
    log_link(&mut sim, "B", &actions);
    if reply {
        responder.record_outbound(sim.now, true);
        let answer = link_packet(
            &link_id,
            constants::PACKET_TYPE_DATA,
            constants::CONTEXT_KEEPALIVE,
            &[0xfe],
        );
        sim.outbound(B, &answer, constants::DESTINATION_LINK, None);
        let _ = sim.take_delivered(A);
        let actions = initiator.record_inbound(sim.now);
        log_link(&mut sim, "A", &actions);
    }

    sim.at(keepalive_at + 10.0);
    let actions = initiator.teardown();
    log_link(&mut sim, "A", &actions);
    let ciphertext = initiator.encrypt(&link_id, &mut a_app_rng).unwrap();
    let close = link_packet(
        &link_id,
        constants::PACKET_TYPE_DATA,
        constants::CONTEXT_LINKCLOSE,
        &ciphertext,
    );
    sim.outbound(A, &close, constants::DESTINATION_LINK, None);
    let (received, _) = sim.take_delivered(B);
    let closed = responder.decrypt(received.data()).unwrap();
    assert_eq!(closed, link_id);
    let actions = responder.handle_teardown();
    log_link(&mut sim, "B", &actions);
    sim.dump_tables();

    // -------------------------------------------------------------------------
    sim.scenario("link table and path expiry timers");
    for t in [
        keepalive_at + 1_000.0,
        keepalive_at + 4_000.0,
        1_000.0 + constants::DESTINATION_TIMEOUT - 1.0,
        1_000.0 + constants::DESTINATION_TIMEOUT + 10.0,
        1_000.0 + constants::DESTINATION_TIMEOUT + 4_000.0,
    ] {
        sim.at(t);
        sim.tick_all();
        sim.dump_tables();
    }

    // No frame may be left unaccounted for.
    for node in &sim.nodes {
        assert!(
            node.delivered.is_empty() && node.path_responses.is_empty(),
            "{} has unhandled deliveries",
            node.name
        );
    }
    // Keep a clock line only where something happened at that time.
    let trace = std::mem::take(&mut sim.trace);
    let lines: Vec<&str> = trace.lines().collect();
    let mut out = String::with_capacity(trace.len());
    for (i, line) in lines.iter().enumerate() {
        let next = lines.get(i + 1).copied().unwrap_or("");
        if line.starts_with("-- t=") && !next.starts_with("  ") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

// =============================================================================
// Golden check
// =============================================================================

fn golden_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("tests");
    path.push("fixtures");
    path.push("golden");
    path.push("engine_trace.txt");
    path
}

#[test]
fn golden_engine_trace() {
    let trace = run_trace();
    // The run must not depend on anything but the script.
    assert_eq!(trace, run_trace(), "two runs in one process differ");

    let path = golden_path();
    if std::env::var("RNS_GOLDEN_BLESS").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &trace).unwrap();
        eprintln!(
            "blessed {} ({} lines)",
            path.display(),
            trace.lines().count()
        );
        return;
    }

    let golden = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read golden trace {}: {e}; run with RNS_GOLDEN_BLESS=1 to create it",
            path.display()
        )
    });
    if golden == trace {
        return;
    }

    let golden_lines: Vec<&str> = golden.lines().collect();
    let trace_lines: Vec<&str> = trace.lines().collect();
    let mut report = String::new();
    let mut shown = 0;
    for i in 0..golden_lines.len().max(trace_lines.len()) {
        let expected = golden_lines.get(i).copied();
        let actual = trace_lines.get(i).copied();
        if expected == actual {
            continue;
        }
        let _ = writeln!(report, "line {}:", i + 1);
        let _ = writeln!(report, "  golden: {}", expected.unwrap_or("<end of file>"));
        let _ = writeln!(report, "  actual: {}", actual.unwrap_or("<end of file>"));
        shown += 1;
        if shown == 10 {
            let _ = writeln!(report, "  ...");
            break;
        }
    }
    // Locate the scenario of the first difference.
    let first = golden_lines
        .iter()
        .zip(trace_lines.iter())
        .position(|(g, t)| g != t)
        .unwrap_or(golden_lines.len().min(trace_lines.len()));
    let scenario = trace_lines[..first.min(trace_lines.len())]
        .iter()
        .rev()
        .find(|l| l.starts_with("== scenario:"))
        .copied()
        .unwrap_or("(before the first scenario)");
    panic!(
        "the engine trace differs from {} ({} golden lines, {} actual lines)\n\
         first difference in {scenario}\n{report}\n\
         If the change is intended, rerun with RNS_GOLDEN_BLESS=1 and review the golden diff.",
        path.display(),
        golden_lines.len(),
        trace_lines.len()
    );
}
