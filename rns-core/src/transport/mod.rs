pub mod announce_proc;
pub mod announce_queue;
pub mod announce_verify_queue;
pub mod dedup;
pub mod inbound;
pub mod ingress_control;
pub mod jobs;
pub mod outbound;
pub mod path_requests;
pub mod pathfinder;
pub mod persistence;
pub mod queries;
pub mod rate_limit;
pub mod retention;
pub mod tables;
pub mod tunnel;
pub mod types;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;

use rns_crypto::Rng;

use crate::announce::AnnounceData;
use crate::constants;
use crate::hash;
use crate::packet::RawPacket;

use self::announce_proc::compute_path_expires;
use self::announce_queue::AnnounceQueues;
use self::announce_verify_queue::{AnnounceVerifyKey, AnnounceVerifyQueue, PendingAnnounce};
use self::dedup::{AnnounceSignatureCache, PacketHashlist};
use self::inbound::{
    clamp_forwarded_link_request_mtu, create_link_entry, create_reverse_entry,
    forward_transport_packet, route_proof_via_reverse, route_via_link_table, LocalHopRewrite,
};
use self::ingress_control::IngressControl;
use self::outbound::{route_outbound_with_options, should_transmit_announce, OutboundRouteOptions};
use self::pathfinder::{
    extract_random_blob, timebase_from_random_blob, trusted_timebase_from_random_blobs,
    MultiPathDecision,
};
use self::rate_limit::AnnounceRateLimiter;
use self::tables::{AnnounceEntry, DiscoveryPathRequest, LinkEntry, PathEntry, PathSet};
use self::tunnel::TunnelTable;
use self::types::{
    BlackholeEntry, InterfaceId, InterfaceInfo, PacketBytes, StampRequirements, TransportAction,
    TransportConfig,
};

pub type PathTableRow = ([u8; 16], f64, [u8; 16], u8, f64, f64, String);
pub type RateTableRow = ([u8; 16], f64, u32, f64, Vec<f64>);
/// Parsed LRPROOF data used to rebalance an existing link route.
pub type LrproofRebalanceCandidate = ([u8; 16], [u8; 16], u8, Vec<u8>);

fn lrproof_hop_mismatch_diagnostic(packet_hops: u8, entry: &LinkEntry) -> String {
    alloc::format!(
        "Received link request proof with hop mismatch ({}/{}:{}->{}), not transporting it",
        packet_hops,
        entry.remaining_hops,
        entry.next_hop_interface.0,
        entry.received_interface.0,
    )
}

fn link_route_hops_match(
    packet_hops: u8,
    entry: &LinkEntry,
    receiving_interface: InterfaceId,
) -> bool {
    if entry.next_hop_interface == entry.received_interface {
        packet_hops == entry.remaining_hops || packet_hops == entry.taken_hops
    } else if receiving_interface == entry.next_hop_interface {
        packet_hops == entry.remaining_hops
    } else if receiving_interface == entry.received_interface {
        packet_hops == entry.taken_hops
    } else {
        // The routing failure is the interface, not a hop mismatch.
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct RxMetadata {
    pub rssi: Option<i16>,
    pub snr: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InboundFrame<'a> {
    pub raw: &'a [u8],
    pub iface: InterfaceId,
    pub now: f64,
    pub rx: RxMetadata,
}

impl<'a> InboundFrame<'a> {
    pub fn new(raw: &'a [u8], iface: InterfaceId, now: f64) -> Self {
        Self {
            raw,
            iface,
            now,
            rx: RxMetadata::default(),
        }
    }

    pub fn with_rx(mut self, rx: RxMetadata) -> Self {
        self.rx = rx;
        self
    }
}

/// A syntactically decoded packet. Routing/admission is rechecked on every use.
/// Fields are read-only so cached hashes cannot diverge from the parsed bytes.
pub struct DecodedPacket {
    packet: RawPacket,
    /// Set by [`TransportEngine::decode_inbound`] for link traffic whose hash
    /// it leaves unread; `packet.packet_hash` is then zeroed until the engine
    /// needs it.
    hash_deferred: bool,
}

impl DecodedPacket {
    pub fn unpack(raw: &[u8]) -> Result<Self, crate::packet::PacketError> {
        RawPacket::unpack(raw).map(Self::hashed)
    }

    /// Decode wire bytes the caller owns without copying them.
    pub fn unpack_owned(raw: Vec<u8>) -> Result<Self, crate::packet::PacketError> {
        RawPacket::unpack_owned(raw).map(Self::hashed)
    }

    fn hashed(packet: RawPacket) -> Self {
        Self {
            packet,
            hash_deferred: false,
        }
    }

    /// The decoded fields. Its `packet_hash` is zeroed when hashing was
    /// deferred; read the hash through [`DecodedPacket::packet_hash`].
    pub fn packet(&self) -> &RawPacket {
        &self.packet
    }

    /// The packet hash, unless [`TransportEngine::decode_inbound`] deferred it.
    pub fn packet_hash(&self) -> Option<&[u8; 32]> {
        (!self.hash_deferred).then_some(&self.packet.packet_hash)
    }
}

/// Decoded bytes plus the current receive context; no admission decision cached.
pub struct DecodedInboundFrame {
    pub decoded: DecodedPacket,
    pub iface: InterfaceId,
    pub now: f64,
    pub rx: RxMetadata,
}

struct InboundPacketCtx {
    packet: RawPacket,
    /// `packet.packet_hash` is zeroed: the packet is link traffic that is
    /// only forwarded, or a local link resource part, and nothing reads it.
    hash_deferred: bool,
    original_raw: Option<Vec<u8>>,
    iface: InterfaceId,
    now: f64,
    from_local_client: bool,
}

struct VerifiedAnnounceCtx<'a> {
    packet: &'a RawPacket,
    original_raw: &'a [u8],
    iface: InterfaceId,
    now: f64,
    validated: crate::announce::ValidatedAnnounce,
    received_from: [u8; 16],
    random_blob: [u8; 10],
    announce_emitted: u64,
}

struct TickCtx<'a> {
    now: f64,
    rng: &'a mut dyn Rng,
    actions: Vec<TransportAction>,
}

/// Validated, uniquely tagged path request awaiting ingress accounting.
///
/// This two-phase token is intended for the network driver; applications
/// should use [`TransportEngine::handle_path_request`] instead.
#[doc(hidden)]
pub struct AcceptedPathRequest {
    tag: [u8; 16],
    tag_len: usize,
    interface_id: InterfaceId,
    now: f64,
    destination_hash: [u8; 16],
    already_in_flight: bool,
    /// Stamp extension payload carried by a 64-byte path request, preserved
    /// verbatim when the request is relayed.
    ext_payload: Option<[u8; constants::PR_EXT_PAYLOAD_LENGTH]>,
    /// Value of the carried stamp over `destination_hash || tag`, when the
    /// extension carries the stamp marker.
    stamp_value: Option<u32>,
    /// Whether the carried stamp meets `PATH_REQUEST_STAMP_COST`.
    stamped: bool,
}

impl AcceptedPathRequest {
    /// Value of the stamp this request carried, if any.
    pub fn stamp_value(&self) -> Option<u32> {
        self.stamp_value
    }

    /// Whether this request carried a stamp meeting the required cost.
    pub fn stamped(&self) -> bool {
        self.stamped
    }
}

/// The core transport/routing engine.
///
/// Maintains routing tables and processes packets without performing any I/O.
/// Returns `Vec<TransportAction>` that the caller must execute.
pub struct TransportEngine {
    config: TransportConfig,
    path_table: BTreeMap<[u8; 16], PathSet>,
    announce_table: BTreeMap<[u8; 16], AnnounceEntry>,
    reverse_table: tables::ReverseTable,
    link_table: BTreeMap<[u8; 16], LinkEntry>,
    held_announces: BTreeMap<[u8; 16], AnnounceEntry>,
    packet_hashlist: PacketHashlist,
    announce_sig_cache: AnnounceSignatureCache,
    rate_limiter: AnnounceRateLimiter,
    path_states: BTreeMap<[u8; 16], u8>,
    interfaces: BTreeMap<InterfaceId, InterfaceInfo>,
    interface_hashes: BTreeMap<InterfaceId, [u8; 32]>,
    local_destinations: BTreeMap<[u8; 16], u8>,
    blackholed_identities: BTreeMap<[u8; 16], BlackholeEntry>,
    announce_queues: AnnounceQueues,
    ingress_control: IngressControl,
    tunnel_table: TunnelTable,
    discovery_pr_tags: VecDeque<[u8; 32]>,
    discovery_pr_tag_set: BTreeSet<[u8; 32]>,
    path_requests: BTreeMap<[u8; 16], f64>,
    /// Whether path requests emitted or forwarded for local clients by this
    /// node are stamped (`Transport.STAMP_PRS`). Defaults to the compile-time
    /// constant; settable so the stamping path can be exercised.
    stamp_prs: bool,
    /// Announce and path request stamp requirements (`STAMPS_ENFORCED`,
    /// `DESTINATION_COST`, `PR_COST`), configurable through `[stamps]`.
    stamp_requirements: StampRequirements,
    /// `Transport.control_hashes`: the path request and tunnel synthesis
    /// destinations, which are handled by the engine and never bridged as
    /// plain broadcasts.
    control_destinations: [[u8; 16]; 2],
    discovery_path_requests: BTreeMap<[u8; 16], DiscoveryPathRequest>,
    discovery_path_request_deadlines: BTreeMap<[u8; 16], f64>,
    /// Path requests for destinations behind a local client, by destination:
    /// the requesting interface and when it asked (Transport.py
    /// `pending_local_path_requests`).
    pending_local_path_requests: BTreeMap<[u8; 16], (InterfaceId, f64)>,
    path_destination_cap_evict_count: usize,
    // Job timing
    announces_last_checked: f64,
    tables_last_culled: f64,
}

mod engine_state;
mod inbound_engine;
mod maintenance;
mod outbound_engine;

#[cfg(test)]
mod tests;
