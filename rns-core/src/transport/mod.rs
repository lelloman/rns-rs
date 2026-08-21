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
    create_link_entry, create_reverse_entry, forward_transport_packet, route_proof_via_reverse,
    route_via_link_table, LocalHopRewrite,
};
use self::ingress_control::IngressControl;
use self::outbound::{route_outbound_with_options, should_transmit_announce, OutboundRouteOptions};
use self::pathfinder::{
    extract_random_blob, timebase_from_random_blob, timebase_from_random_blobs, MultiPathDecision,
};
use self::rate_limit::AnnounceRateLimiter;
use self::tables::{AnnounceEntry, DiscoveryPathRequest, LinkEntry, PathEntry, PathSet};
use self::tunnel::TunnelTable;
use self::types::{
    BlackholeEntry, InterfaceId, InterfaceInfo, PacketBytes, TransportAction, TransportConfig,
};

pub type PathTableRow = ([u8; 16], f64, [u8; 16], u8, f64, String);
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

struct InboundPacketCtx {
    packet: RawPacket,
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

struct PathRequestCtx<'a> {
    tag: &'a [u8],
    interface_id: InterfaceId,
    now: f64,
    destination_hash: [u8; 16],
}

/// The core transport/routing engine.
///
/// Maintains routing tables and processes packets without performing any I/O.
/// Returns `Vec<TransportAction>` that the caller must execute.
pub struct TransportEngine {
    config: TransportConfig,
    path_table: BTreeMap<[u8; 16], PathSet>,
    announce_table: BTreeMap<[u8; 16], AnnounceEntry>,
    reverse_table: BTreeMap<[u8; 16], tables::ReverseEntry>,
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
    discovery_path_requests: BTreeMap<[u8; 16], DiscoveryPathRequest>,
    discovery_path_request_deadlines: BTreeMap<[u8; 16], f64>,
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
