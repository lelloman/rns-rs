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
    route_via_link_table,
};
use self::ingress_control::IngressControl;
use self::outbound::{route_outbound, should_transmit_announce};
use self::pathfinder::{
    decide_announce_multipath, extract_random_blob, timebase_from_random_blob,
    timebase_from_random_blobs, MultiPathDecision,
};
use self::rate_limit::AnnounceRateLimiter;
use self::tables::{AnnounceEntry, DiscoveryPathRequest, LinkEntry, PathEntry, PathSet};
use self::tunnel::TunnelTable;
use self::types::{
    BlackholeEntry, InterfaceId, InterfaceInfo, PacketBytes, TransportAction, TransportConfig,
};

pub type PathTableRow = ([u8; 16], f64, [u8; 16], u8, f64, String);
pub type RateTableRow = ([u8; 16], f64, u32, f64, Vec<f64>);

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
    local_destinations: BTreeMap<[u8; 16], u8>,
    blackholed_identities: BTreeMap<[u8; 16], BlackholeEntry>,
    announce_queues: AnnounceQueues,
    ingress_control: IngressControl,
    tunnel_table: TunnelTable,
    discovery_pr_tags: VecDeque<[u8; 32]>,
    discovery_pr_tag_set: BTreeSet<[u8; 32]>,
    discovery_path_requests: BTreeMap<[u8; 16], DiscoveryPathRequest>,
    path_destination_cap_evict_count: usize,
    // Job timing
    announces_last_checked: f64,
    tables_last_culled: f64,
}

impl TransportEngine {
    pub fn new(config: TransportConfig) -> Self {
        let packet_hashlist_max_entries = config.packet_hashlist_max_entries;
        let sig_cache_max = if config.announce_sig_cache_enabled {
            config.announce_sig_cache_max_entries
        } else {
            0
        };
        let sig_cache_ttl = config.announce_sig_cache_ttl_secs;
        let announce_queue_max_interfaces = config.announce_queue_max_interfaces;
        TransportEngine {
            config,
            path_table: BTreeMap::new(),
            announce_table: BTreeMap::new(),
            reverse_table: BTreeMap::new(),
            link_table: BTreeMap::new(),
            held_announces: BTreeMap::new(),
            packet_hashlist: PacketHashlist::new(packet_hashlist_max_entries),
            announce_sig_cache: AnnounceSignatureCache::new(sig_cache_max, sig_cache_ttl),
            rate_limiter: AnnounceRateLimiter::new(),
            path_states: BTreeMap::new(),
            interfaces: BTreeMap::new(),
            local_destinations: BTreeMap::new(),
            blackholed_identities: BTreeMap::new(),
            announce_queues: AnnounceQueues::new(announce_queue_max_interfaces),
            ingress_control: IngressControl::new(),
            tunnel_table: TunnelTable::new(),
            discovery_pr_tags: VecDeque::new(),
            discovery_pr_tag_set: BTreeSet::new(),
            discovery_path_requests: BTreeMap::new(),
            path_destination_cap_evict_count: 0,
            announces_last_checked: 0.0,
            tables_last_culled: 0.0,
        }
    }

    // =========================================================================
    // Interface management
    // =========================================================================

    pub fn register_interface(&mut self, info: InterfaceInfo) {
        self.interfaces.insert(info.id, info);
    }

    pub fn deregister_interface(&mut self, id: InterfaceId) {
        self.interfaces.remove(&id);
        self.announce_queues.remove_interface(id);
        self.ingress_control.remove_interface(&id);
    }

    // =========================================================================
    // Destination management
    // =========================================================================

    pub fn register_destination(&mut self, dest_hash: [u8; 16], dest_type: u8) {
        self.local_destinations.insert(dest_hash, dest_type);
    }

    pub fn deregister_destination(&mut self, dest_hash: &[u8; 16]) {
        self.local_destinations.remove(dest_hash);
    }

    // =========================================================================
    // Path queries
    // =========================================================================

    pub fn has_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.path_table
            .get(dest_hash)
            .is_some_and(|ps| !ps.is_empty())
    }

    pub fn hops_to(&self, dest_hash: &[u8; 16]) -> Option<u8> {
        self.path_table
            .get(dest_hash)
            .and_then(|ps| ps.primary())
            .map(|e| e.hops)
    }

    pub fn next_hop(&self, dest_hash: &[u8; 16]) -> Option<[u8; 16]> {
        self.path_table
            .get(dest_hash)
            .and_then(|ps| ps.primary())
            .map(|e| e.next_hop)
    }

    pub fn next_hop_interface(&self, dest_hash: &[u8; 16]) -> Option<InterfaceId> {
        self.path_table
            .get(dest_hash)
            .and_then(|ps| ps.primary())
            .map(|e| e.receiving_interface)
    }

    // =========================================================================
    // Path state
    // =========================================================================

    /// Mark a path as unresponsive.
    ///
    /// If `receiving_interface` is provided and points to a MODE_BOUNDARY interface,
    /// the marking is skipped — boundary interfaces must not poison path tables.
    /// (Python Transport.py: mark_path_unknown/unresponsive boundary exemption)
    pub fn mark_path_unresponsive(
        &mut self,
        dest_hash: &[u8; 16],
        receiving_interface: Option<InterfaceId>,
    ) {
        if let Some(iface_id) = receiving_interface {
            if let Some(info) = self.interfaces.get(&iface_id) {
                if info.mode == constants::MODE_BOUNDARY {
                    return;
                }
            }
        }

        // Failover: if we have alternative paths, promote the next one
        if let Some(ps) = self.path_table.get_mut(dest_hash) {
            if ps.len() > 1 {
                ps.failover(false); // demote old primary to back
                                    // Clear unresponsive state since we promoted a fresh primary
                self.path_states.remove(dest_hash);
                return;
            }
        }

        self.path_states
            .insert(*dest_hash, constants::STATE_UNRESPONSIVE);
    }

    pub fn mark_path_responsive(&mut self, dest_hash: &[u8; 16]) {
        self.path_states
            .insert(*dest_hash, constants::STATE_RESPONSIVE);
    }

    pub fn path_is_unresponsive(&self, dest_hash: &[u8; 16]) -> bool {
        self.path_states.get(dest_hash) == Some(&constants::STATE_UNRESPONSIVE)
    }

    pub fn expire_path(&mut self, dest_hash: &[u8; 16]) {
        if let Some(ps) = self.path_table.get_mut(dest_hash) {
            ps.expire_all();
        }
    }

    // =========================================================================
    // Link table
    // =========================================================================

    pub fn register_link(&mut self, link_id: [u8; 16], entry: LinkEntry) {
        self.link_table.insert(link_id, entry);
    }

    pub fn validate_link(&mut self, link_id: &[u8; 16]) {
        if let Some(entry) = self.link_table.get_mut(link_id) {
            entry.validated = true;
        }
    }

    pub fn remove_link(&mut self, link_id: &[u8; 16]) {
        self.link_table.remove(link_id);
    }

    // =========================================================================
    // Blackhole management
    // =========================================================================

    /// Add an identity hash to the blackhole list.
    ///
    /// `identity_hash` is the 16-byte identity hash to blackhole. `now` is the
    /// current Unix timestamp. If `duration_hours` is `Some` and greater than
    /// zero, the entry expires after that many hours; otherwise it does not
    /// expire. `reason` is optional descriptive text retained with the entry.
    pub fn blackhole_identity(
        &mut self,
        identity_hash: [u8; 16],
        now: f64,
        duration_hours: Option<f64>,
        reason: Option<String>,
    ) {
        let expires = match duration_hours {
            Some(h) if h > 0.0 => now + h * 3600.0,
            _ => 0.0, // never expires
        };
        self.blackholed_identities.insert(
            identity_hash,
            BlackholeEntry {
                created: now,
                expires,
                reason,
            },
        );
    }

    /// Remove an identity hash from the blackhole list.
    ///
    /// Returns `true` if an entry was removed, or `false` if the identity was
    /// not blackholed.
    pub fn unblackhole_identity(&mut self, identity_hash: &[u8; 16]) -> bool {
        self.blackholed_identities.remove(identity_hash).is_some()
    }

    /// Check if an identity hash is blackholed (and not expired).
    pub fn is_blackholed(&self, identity_hash: &[u8; 16], now: f64) -> bool {
        if let Some(entry) = self.blackholed_identities.get(identity_hash) {
            if entry.expires == 0.0 || entry.expires > now {
                return true;
            }
        }
        false
    }

    /// Get all blackhole entries (for queries).
    pub fn blackholed_entries(&self) -> impl Iterator<Item = (&[u8; 16], &BlackholeEntry)> {
        self.blackholed_identities.iter()
    }

    /// Cull expired blackhole entries.
    fn cull_blackholed(&mut self, now: f64) {
        self.blackholed_identities
            .retain(|_, entry| entry.expires == 0.0 || entry.expires > now);
    }

    // =========================================================================
    // Tunnel management
    // =========================================================================

    /// Handle a validated tunnel synthesis — create new or reattach.
    ///
    /// Returns actions for any restored paths.
    pub fn handle_tunnel(
        &mut self,
        tunnel_id: [u8; 32],
        interface: InterfaceId,
        now: f64,
    ) -> Vec<TransportAction> {
        let mut actions = Vec::new();

        // Set tunnel_id on the interface
        if let Some(info) = self.interfaces.get_mut(&interface) {
            info.tunnel_id = Some(tunnel_id);
        }

        let restored_paths = self.tunnel_table.handle_tunnel(
            tunnel_id,
            interface,
            now,
            self.config.destination_timeout_secs,
        );

        // Restore paths to path table if they're better than existing
        for (dest_hash, tunnel_path) in &restored_paths {
            let should_restore = match self.path_table.get(dest_hash).and_then(|ps| ps.primary()) {
                Some(existing) => {
                    // Restore if fewer/equal hops or existing expired, but never
                    // overwrite a path learned from a more recent announce.
                    if tunnel_path.hops <= existing.hops || existing.expires < now {
                        let existing_timebase = timebase_from_random_blobs(&existing.random_blobs);
                        let tunnel_timebase = timebase_from_random_blobs(&tunnel_path.random_blobs);
                        tunnel_timebase >= existing_timebase
                    } else {
                        false
                    }
                }
                None => now < tunnel_path.expires,
            };

            if should_restore {
                let entry = PathEntry {
                    timestamp: tunnel_path.timestamp,
                    next_hop: tunnel_path.received_from,
                    hops: tunnel_path.hops,
                    expires: tunnel_path.expires,
                    random_blobs: tunnel_path.random_blobs.clone(),
                    receiving_interface: interface,
                    packet_hash: tunnel_path.packet_hash,
                    announce_raw: None,
                };
                self.upsert_path_destination(*dest_hash, entry, now);
            }
        }

        actions.push(TransportAction::TunnelEstablished {
            tunnel_id,
            interface,
        });

        actions
    }

    /// Synthesize a tunnel on an interface.
    ///
    /// `identity`: the transport identity (must have private key for signing)
    /// `interface_id`: which interface to send the synthesis on
    /// `rng`: random number generator
    ///
    /// Returns TunnelSynthesize action to send the synthesis packet.
    pub fn synthesize_tunnel(
        &self,
        identity: &rns_crypto::identity::Identity,
        interface_id: InterfaceId,
        rng: &mut dyn Rng,
    ) -> Vec<TransportAction> {
        let mut actions = Vec::new();

        // Compute interface hash from the interface name
        let interface_hash = if let Some(info) = self.interfaces.get(&interface_id) {
            hash::full_hash(info.name.as_bytes())
        } else {
            log::warn!(
                "Cannot synthesize tunnel on {:?}: unknown interface",
                interface_id
            );
            return actions;
        };

        match tunnel::build_tunnel_synthesize_data(identity, &interface_hash, rng) {
            Ok((data, _tunnel_id)) => {
                let dest_hash = crate::destination::destination_hash(
                    "rnstransport",
                    &["tunnel", "synthesize"],
                    None,
                );
                actions.push(TransportAction::TunnelSynthesize {
                    interface: interface_id,
                    data,
                    dest_hash,
                });
            }
            Err(e) => {
                log::warn!("Cannot synthesize tunnel on {:?}: {}", interface_id, e);
            }
        }

        actions
    }

    /// Void a tunnel's interface connection (tunnel disconnected).
    pub fn void_tunnel_interface(&mut self, tunnel_id: &[u8; 32]) {
        self.tunnel_table.void_tunnel_interface(tunnel_id);
    }

    /// Access the tunnel table for queries.
    pub fn tunnel_table(&self) -> &TunnelTable {
        &self.tunnel_table
    }

    // =========================================================================
    // Packet filter
    // =========================================================================

    /// Check if any local client interfaces are registered.
    fn has_local_clients(&self) -> bool {
        self.interfaces.values().any(|i| i.is_local_client)
    }

    /// Packet filter: dedup + basic validity.
    ///
    /// Transport.py:1187-1238
    fn packet_filter(&self, packet: &RawPacket) -> bool {
        // Filter packets for other transport instances
        if packet.transport_id.is_some()
            && packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE
        {
            if let Some(ref identity_hash) = self.config.identity_hash {
                if packet.transport_id.as_ref() != Some(identity_hash) {
                    return false;
                }
            }
        }

        // Allow certain contexts unconditionally
        match packet.context {
            constants::CONTEXT_KEEPALIVE
            | constants::CONTEXT_RESOURCE_REQ
            | constants::CONTEXT_RESOURCE_PRF
            | constants::CONTEXT_RESOURCE
            | constants::CONTEXT_CACHE_REQUEST
            | constants::CONTEXT_CHANNEL => return true,
            _ => {}
        }

        // PLAIN/GROUP checks
        if packet.flags.destination_type == constants::DESTINATION_PLAIN
            || packet.flags.destination_type == constants::DESTINATION_GROUP
        {
            if packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE {
                return packet.hops <= 1;
            } else {
                // PLAIN/GROUP ANNOUNCE is invalid
                return false;
            }
        }

        // Deduplication
        if !self.packet_hashlist.is_duplicate(&packet.packet_hash) {
            return true;
        }

        // Duplicate announce for SINGLE dest is allowed (path update)
        if packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
            && packet.flags.destination_type == constants::DESTINATION_SINGLE
        {
            return true;
        }

        false
    }

    // =========================================================================
    // Core API: handle_inbound
    // =========================================================================

    /// Process an inbound raw packet from a network interface.
    ///
    /// Returns a list of actions for the caller to execute.
    pub fn handle_inbound(
        &mut self,
        frame: InboundFrame<'_>,
        rng: &mut dyn Rng,
    ) -> Vec<TransportAction> {
        self.handle_inbound_with_announce_queue(frame, rng, None)
    }

    pub fn handle_inbound_with_announce_queue(
        &mut self,
        frame: InboundFrame<'_>,
        rng: &mut dyn Rng,
        announce_queue: Option<&mut AnnounceVerifyQueue>,
    ) -> Vec<TransportAction> {
        let Some(ctx) = self.prepare_inbound_packet(frame) else {
            return Vec::new();
        };
        let mut actions = Vec::new();

        self.remember_inbound_packet_hash(&ctx.packet);
        self.bridge_plain_broadcast(&ctx, &mut actions);
        self.handle_transport_forwarding(&ctx, &mut actions);
        self.handle_link_table_routing(&ctx, &mut actions);
        self.handle_inbound_announce(&ctx, rng, announce_queue, &mut actions);

        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_PROOF {
            self.process_inbound_proof(&ctx.packet, ctx.iface, ctx.now, &mut actions);
        }

        self.handle_inbound_local_delivery(&ctx, &mut actions);
        actions
    }

    fn prepare_inbound_packet(&self, frame: InboundFrame<'_>) -> Option<InboundPacketCtx> {
        let mut packet = RawPacket::unpack(frame.raw).ok()?;
        let from_local_client = self
            .interfaces
            .get(&frame.iface)
            .map(|i| i.is_local_client)
            .unwrap_or(false);
        packet.hops += 1;
        packet.rssi = frame.rx.rssi;
        packet.snr = frame.rx.snr;
        if from_local_client {
            packet.hops = packet.hops.saturating_sub(1);
        }
        if !self.packet_filter(&packet) {
            return None;
        }
        let retain_original_raw = packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE;
        Some(InboundPacketCtx {
            packet,
            original_raw: if retain_original_raw {
                Some(frame.raw.to_vec())
            } else {
                None
            },
            iface: frame.iface,
            now: frame.now,
            from_local_client,
        })
    }

    fn remember_inbound_packet_hash(&mut self, packet: &RawPacket) {
        let remember_hash = !(self.link_table.contains_key(&packet.destination_hash)
            || (packet.flags.packet_type == constants::PACKET_TYPE_PROOF
                && packet.context == constants::CONTEXT_LRPROOF));
        if remember_hash {
            self.packet_hashlist.add(packet.packet_hash);
        }
    }

    fn bridge_plain_broadcast(&self, ctx: &InboundPacketCtx, actions: &mut Vec<TransportAction>) {
        if ctx.packet.flags.destination_type != constants::DESTINATION_PLAIN
            || ctx.packet.flags.transport_type != constants::TRANSPORT_BROADCAST
            || !self.has_local_clients()
        {
            return;
        }

        if ctx.from_local_client {
            actions.push(TransportAction::ForwardPlainBroadcast {
                raw: PacketBytes::from(ctx.packet.raw.clone()),
                to_local: false,
                exclude: Some(ctx.iface),
            });
        } else {
            actions.push(TransportAction::ForwardPlainBroadcast {
                raw: PacketBytes::from(ctx.packet.raw.clone()),
                to_local: true,
                exclude: None,
            });
        }
    }

    fn handle_transport_forwarding(
        &mut self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        if !(self.config.transport_enabled || self.config.identity_hash.is_some()) {
            return;
        }
        if ctx.packet.transport_id.is_none()
            || ctx.packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
        {
            if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
                log::debug!(
                    "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. not transport-addressed header={} iface={}",
                    ctx.packet.destination_hash[0],
                    ctx.packet.destination_hash[1],
                    ctx.packet.destination_hash[2],
                    ctx.packet.destination_hash[3],
                    ctx.packet.flags.header_type,
                    ctx.iface.0
                );
            }
            return;
        }

        let Some(identity_hash) = self.config.identity_hash else {
            return;
        };
        if ctx.packet.transport_id != Some(identity_hash) {
            if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
                log::debug!(
                    "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. transport mismatch got={:02x?} own={:02x?} iface={}",
                    ctx.packet.destination_hash[0],
                    ctx.packet.destination_hash[1],
                    ctx.packet.destination_hash[2],
                    ctx.packet.destination_hash[3],
                    ctx.packet.transport_id.as_ref().map(|id| &id[..4]),
                    &identity_hash[..4],
                    ctx.iface.0
                );
            }
            return;
        }

        let Some(path_entry) = self
            .path_table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary())
        else {
            if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
                log::debug!(
                    "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. addressed to us but no path iface={}",
                    ctx.packet.destination_hash[0],
                    ctx.packet.destination_hash[1],
                    ctx.packet.destination_hash[2],
                    ctx.packet.destination_hash[3],
                    ctx.iface.0
                );
            }
            return;
        };

        let next_hop = path_entry.next_hop;
        let remaining_hops = path_entry.hops;
        let outbound_interface = path_entry.receiving_interface;
        let outbound_is_local_client = self
            .interfaces
            .get(&outbound_interface)
            .map(|info| info.is_local_client)
            .unwrap_or(false);
        let forwarded_remaining_hops = if outbound_is_local_client {
            0
        } else {
            remaining_hops
        };
        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
            log::debug!(
                "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. remaining_hops={} out_iface={} next_hop={:02x?}",
                ctx.packet.destination_hash[0],
                ctx.packet.destination_hash[1],
                ctx.packet.destination_hash[2],
                ctx.packet.destination_hash[3],
                remaining_hops,
                outbound_interface.0,
                &next_hop[..4]
            );
        }
        let new_raw = forward_transport_packet(
            &ctx.packet,
            next_hop,
            forwarded_remaining_hops,
            outbound_interface,
        );

        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST {
            let proof_timeout = ctx.now
                + constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP * (remaining_hops.max(1) as f64);
            let (link_id, link_entry) = create_link_entry(
                &ctx.packet,
                next_hop,
                outbound_interface,
                remaining_hops,
                ctx.iface,
                ctx.now,
                proof_timeout,
            );
            self.link_table.insert(link_id, link_entry);
            actions.push(TransportAction::LinkRequestReceived {
                link_id,
                destination_hash: ctx.packet.destination_hash,
                receiving_interface: ctx.iface,
            });
        } else {
            let (trunc_hash, reverse_entry) =
                create_reverse_entry(&ctx.packet, outbound_interface, ctx.iface, ctx.now);
            self.reverse_table.insert(trunc_hash, reverse_entry);
        }

        actions.push(TransportAction::SendOnInterface {
            interface: outbound_interface,
            raw: new_raw.into(),
        });

        if let Some(entry) = self
            .path_table
            .get_mut(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary_mut())
        {
            entry.timestamp = ctx.now;
        }
    }

    fn handle_link_table_routing(
        &mut self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        if !self.config.transport_enabled && self.config.identity_hash.is_none() {
            return;
        }
        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
            || ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
            || ctx.packet.context == constants::CONTEXT_LRPROOF
        {
            return;
        }

        let Some(link_entry) = self.link_table.get(&ctx.packet.destination_hash).cloned() else {
            return;
        };
        let Some((outbound_iface, new_raw)) =
            route_via_link_table(&ctx.packet, &link_entry, ctx.iface)
        else {
            return;
        };

        self.packet_hashlist.add(ctx.packet.packet_hash);
        actions.push(TransportAction::SendOnInterface {
            interface: outbound_iface,
            raw: new_raw.into(),
        });

        if let Some(entry) = self.link_table.get_mut(&ctx.packet.destination_hash) {
            entry.timestamp = ctx.now;
        }
    }

    fn handle_inbound_announce(
        &mut self,
        ctx: &InboundPacketCtx,
        rng: &mut dyn Rng,
        announce_queue: Option<&mut AnnounceVerifyQueue>,
        actions: &mut Vec<TransportAction>,
    ) {
        if ctx.packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE {
            return;
        }

        if let Some(queue) = announce_queue {
            self.try_enqueue_announce(ctx, rng, queue, actions);
        } else {
            let original_raw = ctx
                .original_raw
                .as_deref()
                .expect("announce packets retain original raw bytes");
            self.process_inbound_announce(
                &ctx.packet,
                original_raw,
                ctx.iface,
                ctx.now,
                rng,
                actions,
            );
        }
    }

    fn handle_inbound_local_delivery(
        &self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        if (ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
            || ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA)
            && self
                .local_destinations
                .contains_key(&ctx.packet.destination_hash)
        {
            actions.push(TransportAction::DeliverLocal {
                destination_hash: ctx.packet.destination_hash,
                raw: PacketBytes::from(ctx.packet.raw.clone()),
                packet_hash: ctx.packet.packet_hash,
                receiving_interface: ctx.iface,
            });
        }
    }

    // =========================================================================
    // Inbound announce processing
    // =========================================================================

    fn process_inbound_announce(
        &mut self,
        packet: &RawPacket,
        original_raw: &[u8],
        iface: InterfaceId,
        now: f64,
        rng: &mut dyn Rng,
        actions: &mut Vec<TransportAction>,
    ) {
        if packet.flags.destination_type != constants::DESTINATION_SINGLE {
            return;
        }

        let has_ratchet = packet.flags.context_flag == constants::FLAG_SET;

        // Unpack and validate announce
        let announce = match AnnounceData::unpack(&packet.data, has_ratchet) {
            Ok(a) => a,
            Err(_) => return,
        };

        if self.should_hold_announce(packet, original_raw, iface, now) {
            return;
        }

        let sig_cache_key =
            Self::announce_sig_cache_key(packet.destination_hash, &announce.signature);

        let validated = if self.announce_sig_cache.contains(&sig_cache_key) {
            announce.to_validated_unchecked()
        } else {
            match announce.validate(&packet.destination_hash) {
                Ok(v) => {
                    self.announce_sig_cache.insert(sig_cache_key, now);
                    v
                }
                Err(_) => return,
            }
        };

        let received_from = self.announce_received_from(packet, now);
        let random_blob = match extract_random_blob(&packet.data) {
            Some(b) => b,
            None => return,
        };
        let announce_emitted = timebase_from_random_blob(&random_blob);

        self.process_verified_announce(
            VerifiedAnnounceCtx {
                packet,
                original_raw,
                iface,
                now,
                validated,
                received_from,
                random_blob,
                announce_emitted,
            },
            rng,
            actions,
        );
    }

    fn announce_raw_for_local_clients(&self, packet: &RawPacket) -> PacketBytes {
        let Some(identity_hash) = self.config.identity_hash else {
            return PacketBytes::from(packet.raw.clone());
        };

        if packet.raw.len() < 2 {
            return PacketBytes::from(packet.raw.clone());
        }

        let payload_start = if packet.flags.header_type == constants::HEADER_2 {
            18usize
        } else {
            2usize
        };
        if packet.raw.len() < payload_start {
            return PacketBytes::from(packet.raw.clone());
        }

        let flags = (constants::HEADER_2 << 6)
            | (constants::TRANSPORT_TRANSPORT << 4)
            | (packet.raw[0] & 0x0F);
        let mut raw = Vec::with_capacity(18 + packet.raw.len() - payload_start);
        raw.push(flags);
        raw.push(packet.hops);
        raw.extend_from_slice(&identity_hash);
        raw.extend_from_slice(&packet.raw[payload_start..]);
        PacketBytes::from(raw)
    }

    fn announce_sig_cache_key(destination_hash: [u8; 16], signature: &[u8; 64]) -> [u8; 32] {
        let mut material = [0u8; 80];
        material[..16].copy_from_slice(&destination_hash);
        material[16..].copy_from_slice(signature);
        hash::full_hash(&material)
    }

    fn announce_received_from(&mut self, packet: &RawPacket, now: f64) -> [u8; 16] {
        if let Some(transport_id) = packet.transport_id {
            if self.config.transport_enabled {
                if let Some(announce_entry) = self.announce_table.get_mut(&packet.destination_hash)
                {
                    if packet.hops.checked_sub(1) == Some(announce_entry.hops) {
                        announce_entry.local_rebroadcasts += 1;
                        if announce_entry.retries > 0
                            && announce_entry.local_rebroadcasts
                                >= constants::LOCAL_REBROADCASTS_MAX
                        {
                            self.announce_table.remove(&packet.destination_hash);
                        }
                    }
                    if let Some(announce_entry) = self.announce_table.get(&packet.destination_hash)
                    {
                        if packet.hops.checked_sub(1) == Some(announce_entry.hops + 1)
                            && announce_entry.retries > 0
                            && now < announce_entry.retransmit_timeout
                        {
                            self.announce_table.remove(&packet.destination_hash);
                        }
                    }
                }
            }
            transport_id
        } else {
            packet.destination_hash
        }
    }

    fn should_hold_announce(
        &mut self,
        packet: &RawPacket,
        original_raw: &[u8],
        iface: InterfaceId,
        now: f64,
    ) -> bool {
        if self.has_path(&packet.destination_hash) {
            return false;
        }
        if self
            .discovery_path_requests
            .contains_key(&packet.destination_hash)
        {
            return false;
        }
        let Some(info) = self.interfaces.get(&iface) else {
            return false;
        };
        if packet.context == constants::CONTEXT_PATH_RESPONSE
            || !self.ingress_control.should_ingress_limit(
                iface,
                &info.ingress_control,
                info.ia_freq,
                info.started,
                now,
            )
        {
            return false;
        }
        self.ingress_control.hold_announce(
            iface,
            &info.ingress_control,
            packet.destination_hash,
            ingress_control::HeldAnnounce {
                raw: original_raw.to_vec(),
                hops: packet.hops,
                receiving_interface: iface,
                rx: RxMetadata {
                    rssi: packet.rssi,
                    snr: packet.snr,
                },
                timestamp: now,
            },
        );
        true
    }

    fn try_enqueue_announce(
        &mut self,
        ctx: &InboundPacketCtx,
        rng: &mut dyn Rng,
        announce_queue: &mut AnnounceVerifyQueue,
        actions: &mut Vec<TransportAction>,
    ) {
        if ctx.packet.flags.destination_type != constants::DESTINATION_SINGLE {
            return;
        }

        let has_ratchet = ctx.packet.flags.context_flag == constants::FLAG_SET;
        let announce = match AnnounceData::unpack(&ctx.packet.data, has_ratchet) {
            Ok(a) => a,
            Err(_) => return,
        };

        let received_from = self.announce_received_from(&ctx.packet, ctx.now);

        if self
            .local_destinations
            .contains_key(&ctx.packet.destination_hash)
        {
            log::debug!(
                "Announce:skipping local destination {:02x}{:02x}{:02x}{:02x}..",
                ctx.packet.destination_hash[0],
                ctx.packet.destination_hash[1],
                ctx.packet.destination_hash[2],
                ctx.packet.destination_hash[3],
            );
            return;
        }

        let original_raw = ctx
            .original_raw
            .as_deref()
            .expect("announce packets retain original raw bytes");
        if self.should_hold_announce(&ctx.packet, original_raw, ctx.iface, ctx.now) {
            return;
        }

        let sig_cache_key =
            Self::announce_sig_cache_key(ctx.packet.destination_hash, &announce.signature);
        if self.announce_sig_cache.contains(&sig_cache_key) {
            let validated = announce.to_validated_unchecked();
            let random_blob = match extract_random_blob(&ctx.packet.data) {
                Some(b) => b,
                None => return,
            };
            let announce_emitted = timebase_from_random_blob(&random_blob);
            self.process_verified_announce(
                VerifiedAnnounceCtx {
                    packet: &ctx.packet,
                    original_raw,
                    iface: ctx.iface,
                    now: ctx.now,
                    validated,
                    received_from,
                    random_blob,
                    announce_emitted,
                },
                rng,
                actions,
            );
            return;
        }

        if ctx.packet.context == constants::CONTEXT_PATH_RESPONSE {
            let Ok(validated) = announce.validate(&ctx.packet.destination_hash) else {
                return;
            };
            self.announce_sig_cache.insert(sig_cache_key, ctx.now);
            let random_blob = match extract_random_blob(&ctx.packet.data) {
                Some(b) => b,
                None => return,
            };
            let announce_emitted = timebase_from_random_blob(&random_blob);
            self.process_verified_announce(
                VerifiedAnnounceCtx {
                    packet: &ctx.packet,
                    original_raw,
                    iface: ctx.iface,
                    now: ctx.now,
                    validated,
                    received_from,
                    random_blob,
                    announce_emitted,
                },
                rng,
                actions,
            );
            return;
        }

        let random_blob = match extract_random_blob(&ctx.packet.data) {
            Some(b) => b,
            None => return,
        };
        let announce_emitted = timebase_from_random_blob(&random_blob);
        let key = AnnounceVerifyKey {
            destination_hash: ctx.packet.destination_hash,
            random_blob,
            received_from,
        };
        let pending = PendingAnnounce {
            original_raw: original_raw.to_vec(),
            packet: ctx.packet.clone(),
            interface: ctx.iface,
            received_from,
            queued_at: ctx.now,
            best_hops: ctx.packet.hops,
            emission_ts: announce_emitted,
            random_blob,
        };
        let _ = announce_queue.enqueue(key, pending);
    }

    pub fn complete_verified_announce(
        &mut self,
        pending: PendingAnnounce,
        validated: crate::announce::ValidatedAnnounce,
        sig_cache_key: [u8; 32],
        now: f64,
        rng: &mut dyn Rng,
    ) -> Vec<TransportAction> {
        self.announce_sig_cache.insert(sig_cache_key, now);
        let mut actions = Vec::new();
        self.process_verified_announce(
            VerifiedAnnounceCtx {
                packet: &pending.packet,
                original_raw: &pending.original_raw,
                iface: pending.interface,
                now,
                validated,
                received_from: pending.received_from,
                random_blob: pending.random_blob,
                announce_emitted: pending.emission_ts,
            },
            rng,
            &mut actions,
        );
        actions
    }

    pub fn clear_failed_verified_announce(&mut self, _sig_cache_key: [u8; 32], _now: f64) {}

    fn process_verified_announce(
        &mut self,
        ctx: VerifiedAnnounceCtx<'_>,
        rng: &mut dyn Rng,
        actions: &mut Vec<TransportAction>,
    ) {
        if self.is_blackholed(&ctx.validated.identity_hash, ctx.now) {
            return;
        }
        if ctx.packet.hops > constants::PATHFINDER_M {
            return;
        }

        let existing_set = self.path_table.get(&ctx.packet.destination_hash);
        let was_unknown_destination = existing_set.is_none_or(|ps| ps.is_empty());

        // Reset stale path state before first-path installation so path-state handling
        // cannot race ahead of the path table for previously unknown destinations.
        if was_unknown_destination {
            self.path_states.remove(&ctx.packet.destination_hash);
        }

        // Multi-path aware decision
        let is_unresponsive = self.path_is_unresponsive(&ctx.packet.destination_hash);

        let mp_decision = decide_announce_multipath(
            existing_set,
            ctx.packet.hops,
            ctx.announce_emitted,
            &ctx.random_blob,
            &ctx.received_from,
            is_unresponsive,
            ctx.now,
            self.config.prefer_shorter_path,
        );

        if mp_decision == MultiPathDecision::Reject {
            log::debug!(
                "Announce:path decision REJECT for dest={:02x}{:02x}{:02x}{:02x}..",
                ctx.packet.destination_hash[0],
                ctx.packet.destination_hash[1],
                ctx.packet.destination_hash[2],
                ctx.packet.destination_hash[3],
            );
            return;
        }

        // Rate limiting
        let rate_blocked = if ctx.packet.context != constants::CONTEXT_PATH_RESPONSE {
            if let Some(iface_info) = self.interfaces.get(&ctx.iface) {
                self.rate_limiter.check_and_update(
                    &ctx.packet.destination_hash,
                    ctx.now,
                    iface_info.announce_rate_target,
                    iface_info.announce_rate_grace,
                    iface_info.announce_rate_penalty,
                )
            } else {
                false
            }
        } else {
            false
        };

        // Get interface mode for expiry calculation
        let interface_mode = self
            .interfaces
            .get(&ctx.iface)
            .map(|i| i.mode)
            .unwrap_or(constants::MODE_FULL);

        let expires = compute_path_expires(ctx.now, interface_mode);

        // Get existing random blobs from the matching path (same next_hop) or empty
        let existing_blobs = self
            .path_table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.find_by_next_hop(&ctx.received_from))
            .map(|e| e.random_blobs.clone())
            .unwrap_or_default();

        // Generate RNG value for retransmit timeout
        let mut rng_bytes = [0u8; 8];
        rng.fill_bytes(&mut rng_bytes);
        let rng_value = (u64::from_le_bytes(rng_bytes) as f64) / (u64::MAX as f64);

        let is_path_response = ctx.packet.context == constants::CONTEXT_PATH_RESPONSE;

        let (path_entry, announce_entry) = announce_proc::process_validated_announce(
            ctx.packet.destination_hash,
            ctx.packet.hops,
            &ctx.packet.data,
            &ctx.packet.raw,
            ctx.packet.packet_hash,
            ctx.packet.flags.context_flag,
            ctx.received_from,
            ctx.iface,
            ctx.now,
            existing_blobs,
            ctx.random_blob,
            expires,
            rng_value,
            self.config.transport_enabled,
            is_path_response,
            rate_blocked,
            Some(ctx.original_raw.to_vec()),
        );

        // Emit CacheAnnounce for disk caching (pre-hop-increment raw)
        actions.push(TransportAction::CacheAnnounce {
            packet_hash: ctx.packet.packet_hash,
            raw: ctx.original_raw.to_vec().into(),
        });

        // Store path via upsert into PathSet
        self.upsert_path_destination(ctx.packet.destination_hash, path_entry, ctx.now);

        // If receiving interface has a tunnel_id, store path in tunnel table too
        if let Some(tunnel_id) = self.interfaces.get(&ctx.iface).and_then(|i| i.tunnel_id) {
            let blobs = self
                .path_table
                .get(&ctx.packet.destination_hash)
                .and_then(|ps| ps.find_by_next_hop(&ctx.received_from))
                .map(|e| e.random_blobs.clone())
                .unwrap_or_default();
            self.tunnel_table.store_tunnel_path(
                &tunnel_id,
                ctx.packet.destination_hash,
                tunnel::TunnelPath {
                    timestamp: ctx.now,
                    received_from: ctx.received_from,
                    hops: ctx.packet.hops,
                    expires,
                    random_blobs: blobs,
                    packet_hash: ctx.packet.packet_hash,
                },
                ctx.now,
                self.config.destination_timeout_secs,
                self.config.max_tunnel_destinations_total,
            );
        }

        // Re-apply the path-state reset after storing the path entry so any transient
        // stale state is also cleared once the destination exists in the path table.
        self.path_states.remove(&ctx.packet.destination_hash);

        // Store announce for retransmission
        if let Some(ann) = announce_entry {
            self.insert_announce_entry(ctx.packet.destination_hash, ann, ctx.now);
        }

        // Emit actions
        actions.push(TransportAction::AnnounceReceived {
            destination_hash: ctx.packet.destination_hash,
            identity_hash: ctx.validated.identity_hash,
            public_key: ctx.validated.public_key,
            name_hash: ctx.validated.name_hash,
            random_hash: ctx.validated.random_hash,
            ratchet: ctx.validated.ratchet,
            app_data: ctx.validated.app_data,
            hops: ctx.packet.hops,
            receiving_interface: ctx.iface,
            rx: RxMetadata {
                rssi: ctx.packet.rssi,
                snr: ctx.packet.snr,
            },
        });

        actions.push(TransportAction::PathUpdated {
            destination_hash: ctx.packet.destination_hash,
            hops: ctx.packet.hops,
            next_hop: ctx.received_from,
            interface: ctx.iface,
        });

        // Forward announce to local clients if any are connected
        if self.has_local_clients() {
            actions.push(TransportAction::ForwardToLocalClients {
                raw: self.announce_raw_for_local_clients(ctx.packet),
                exclude: Some(ctx.iface),
            });
        }

        // Check for discovery path requests waiting for this announce
        if let Some(pr_entry) = self.discovery_path_requests_waiting(&ctx.packet.destination_hash) {
            // Build a path response announce and queue it
            let entry = AnnounceEntry {
                timestamp: ctx.now,
                retransmit_timeout: ctx.now,
                retries: constants::PATHFINDER_R,
                received_from: ctx.received_from,
                hops: ctx.packet.hops,
                packet_raw: ctx.packet.raw.clone(),
                packet_data: ctx.packet.data.clone(),
                destination_hash: ctx.packet.destination_hash,
                context_flag: ctx.packet.flags.context_flag,
                local_rebroadcasts: 0,
                block_rebroadcasts: true,
                attached_interface: Some(pr_entry),
            };
            self.insert_announce_entry(ctx.packet.destination_hash, entry, ctx.now);
        }
    }

    pub fn announce_sig_cache_contains(&self, sig_cache_key: &[u8; 32]) -> bool {
        self.announce_sig_cache.contains(sig_cache_key)
    }

    /// Check if there's a waiting discovery path request for a destination.
    /// Consumes the request if found (one-shot: the caller queues the announce response).
    fn discovery_path_requests_waiting(&mut self, dest_hash: &[u8; 16]) -> Option<InterfaceId> {
        self.discovery_path_requests
            .remove(dest_hash)
            .map(|req| req.requesting_interface)
    }

    // =========================================================================
    // Inbound proof processing
    // =========================================================================

    fn process_inbound_proof(
        &mut self,
        packet: &RawPacket,
        iface: InterfaceId,
        _now: f64,
        actions: &mut Vec<TransportAction>,
    ) {
        if packet.context == constants::CONTEXT_LRPROOF {
            // Link request proof routing
            if (self.config.transport_enabled)
                && self.link_table.contains_key(&packet.destination_hash)
            {
                let link_entry = self.link_table.get(&packet.destination_hash).cloned();
                if let Some(entry) = link_entry {
                    if let Some((outbound_interface, new_raw)) =
                        route_via_link_table(packet, &entry, iface)
                    {
                        // Forward the proof (simplified: skip signature validation
                        // which requires Identity recall)

                        // Mark link as validated
                        if let Some(le) = self.link_table.get_mut(&packet.destination_hash) {
                            le.validated = true;
                        }

                        actions.push(TransportAction::LinkEstablished {
                            link_id: packet.destination_hash,
                            interface: outbound_interface,
                        });

                        actions.push(TransportAction::SendOnInterface {
                            interface: outbound_interface,
                            raw: new_raw.into(),
                        });
                    }
                }
            } else {
                // Could be for a local pending link - deliver locally
                actions.push(TransportAction::DeliverLocal {
                    destination_hash: packet.destination_hash,
                    raw: PacketBytes::from(packet.raw.clone()),
                    packet_hash: packet.packet_hash,
                    receiving_interface: iface,
                });
            }
        } else {
            // Regular proof: check reverse table
            if self.config.transport_enabled {
                if let Some(reverse_entry) = self.reverse_table.remove(&packet.destination_hash) {
                    if let Some(action) = route_proof_via_reverse(packet, &reverse_entry, iface) {
                        actions.push(action);
                    }
                }
            }

            // Deliver to local receipts
            actions.push(TransportAction::DeliverLocal {
                destination_hash: packet.destination_hash,
                raw: PacketBytes::from(packet.raw.clone()),
                packet_hash: packet.packet_hash,
                receiving_interface: iface,
            });
        }
    }

    // =========================================================================
    // Core API: handle_outbound
    // =========================================================================

    /// Route an outbound packet.
    pub fn handle_outbound(
        &mut self,
        packet: &RawPacket,
        dest_type: u8,
        attached_interface: Option<InterfaceId>,
        now: f64,
    ) -> Vec<TransportAction> {
        let actions = route_outbound(
            &self.path_table,
            &self.interfaces,
            &self.local_destinations,
            packet,
            dest_type,
            attached_interface,
            now,
        );

        // Add to packet hashlist for outbound packets
        self.packet_hashlist.add(packet.packet_hash);

        // Gate announces with hops > 0 through the bandwidth queue
        if packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE && packet.hops > 0 {
            self.gate_announce_actions(actions, &packet.destination_hash, packet.hops, now)
        } else {
            actions
        }
    }

    /// Gate announce SendOnInterface actions through per-interface bandwidth queues.
    fn gate_announce_actions(
        &mut self,
        actions: Vec<TransportAction>,
        dest_hash: &[u8; 16],
        hops: u8,
        now: f64,
    ) -> Vec<TransportAction> {
        let mut result = Vec::new();
        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    let (bitrate, airtime_profile, announce_cap) =
                        if let Some(info) = self.interfaces.get(&interface) {
                            (info.bitrate, info.airtime_profile, info.announce_cap)
                        } else {
                            (None, None, constants::ANNOUNCE_CAP)
                        };
                    if let Some(send_action) = self.announce_queues.gate_announce(
                        interface,
                        raw,
                        *dest_hash,
                        hops,
                        now,
                        now,
                        bitrate,
                        airtime_profile,
                        announce_cap,
                    ) {
                        result.push(send_action);
                    }
                    // If None, it was queued — no action emitted now
                }
                other => result.push(other),
            }
        }
        result
    }

    // =========================================================================
    // Core API: tick
    // =========================================================================

    /// Periodic maintenance. Call regularly (e.g., every 250ms).
    pub fn tick(&mut self, now: f64, rng: &mut dyn Rng) -> Vec<TransportAction> {
        let mut ctx = TickCtx {
            now,
            rng,
            actions: Vec::new(),
        };
        self.process_tick_pending_announces(&mut ctx);

        let mut queue_actions = self.announce_queues.process_queues(now, &self.interfaces);
        ctx.actions.append(&mut queue_actions);

        self.process_tick_ingress_release(&mut ctx);
        self.cull_tick_tables(&mut ctx);
        ctx.actions
    }

    fn process_tick_pending_announces(&mut self, ctx: &mut TickCtx<'_>) {
        if ctx.now <= self.announces_last_checked + constants::ANNOUNCES_CHECK_INTERVAL {
            return;
        }

        self.cull_expired_announce_entries(ctx.now);
        self.enforce_announce_retention_cap(ctx.now);
        if let Some(identity_hash) = self.config.identity_hash {
            let announce_actions = jobs::process_pending_announces(
                &mut self.announce_table,
                &mut self.held_announces,
                &identity_hash,
                ctx.now,
            );
            let gated = self.gate_retransmit_actions(announce_actions, ctx.now);
            ctx.actions.extend(gated);
        }
        self.cull_expired_announce_entries(ctx.now);
        self.enforce_announce_retention_cap(ctx.now);
        self.announces_last_checked = ctx.now;
    }

    fn process_tick_ingress_release(&mut self, ctx: &mut TickCtx<'_>) {
        let ic_interfaces = self.ingress_control.interfaces_with_held();
        for iface_id in ic_interfaces {
            let (ia_freq, started, ingress_config) = match self.interfaces.get(&iface_id) {
                Some(info) => (info.ia_freq, info.started, info.ingress_control),
                None => continue,
            };
            if !ingress_config.enabled {
                continue;
            }
            if let Some(held) = self.ingress_control.process_held_announces(
                iface_id,
                &ingress_config,
                ia_freq,
                started,
                ctx.now,
            ) {
                let released_actions = self.handle_inbound(
                    InboundFrame {
                        raw: &held.raw,
                        iface: held.receiving_interface,
                        now: ctx.now,
                        rx: held.rx,
                    },
                    ctx.rng,
                );
                ctx.actions.extend(released_actions);
            }
        }
    }

    fn cull_tick_tables(&mut self, ctx: &mut TickCtx<'_>) {
        if ctx.now <= self.tables_last_culled + constants::TABLES_CULL_INTERVAL {
            return;
        }

        jobs::cull_path_table(&mut self.path_table, &self.interfaces, ctx.now);
        jobs::cull_reverse_table(&mut self.reverse_table, &self.interfaces, ctx.now);
        let (_culled, link_closed_actions) =
            jobs::cull_link_table(&mut self.link_table, &self.interfaces, ctx.now);
        ctx.actions.extend(link_closed_actions);
        jobs::cull_path_states(&mut self.path_states, &self.path_table);
        self.cull_blackholed(ctx.now);
        self.discovery_path_requests
            .retain(|_, req| ctx.now - req.timestamp < constants::DISCOVERY_PATH_REQUEST_TIMEOUT);
        self.tunnel_table
            .void_missing_interfaces(|id| self.interfaces.contains_key(id));
        self.tunnel_table.cull(ctx.now);
        self.announce_sig_cache.cull(ctx.now);
        self.tables_last_culled = ctx.now;
    }

    /// Gate retransmitted announce actions through per-interface bandwidth queues.
    ///
    /// Retransmitted announces always have hops > 0.
    /// `BroadcastOnAllInterfaces` is expanded to per-interface sends gated through queues.
    fn gate_retransmit_actions(
        &mut self,
        actions: Vec<TransportAction>,
        now: f64,
    ) -> Vec<TransportAction> {
        let mut result = Vec::new();
        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    // Extract dest_hash from raw (bytes 2..18 for H1, 18..34 for H2)
                    let (dest_hash, hops) = Self::extract_announce_info(&raw);
                    let (bitrate, airtime_profile, announce_cap) =
                        if let Some(info) = self.interfaces.get(&interface) {
                            (info.bitrate, info.airtime_profile, info.announce_cap)
                        } else {
                            (None, None, constants::ANNOUNCE_CAP)
                        };
                    if let Some(send_action) = self.announce_queues.gate_announce(
                        interface,
                        raw,
                        dest_hash,
                        hops,
                        now,
                        now,
                        bitrate,
                        airtime_profile,
                        announce_cap,
                    ) {
                        result.push(send_action);
                    }
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    let (dest_hash, hops) = Self::extract_announce_info(&raw);
                    // Expand to per-interface sends gated through queues,
                    // applying mode filtering (AP blocks non-local announces, etc.)
                    let iface_ids: Vec<(
                        InterfaceId,
                        Option<u64>,
                        Option<types::AirtimeProfile>,
                        f64,
                    )> = self
                        .interfaces
                        .iter()
                        .filter(|(_, info)| info.out_capable)
                        .filter(|(id, _)| {
                            if let Some(ref ex) = exclude {
                                **id != *ex
                            } else {
                                true
                            }
                        })
                        .filter(|(_, info)| {
                            should_transmit_announce(
                                info,
                                &dest_hash,
                                hops,
                                &self.local_destinations,
                                &self.path_table,
                                &self.interfaces,
                            )
                        })
                        .map(|(id, info)| {
                            (*id, info.bitrate, info.airtime_profile, info.announce_cap)
                        })
                        .collect();

                    for (iface_id, bitrate, airtime_profile, announce_cap) in iface_ids {
                        if let Some(send_action) = self.announce_queues.gate_announce(
                            iface_id,
                            raw.clone(),
                            dest_hash,
                            hops,
                            now,
                            now,
                            bitrate,
                            airtime_profile,
                            announce_cap,
                        ) {
                            result.push(send_action);
                        }
                    }
                }
                other => result.push(other),
            }
        }
        result
    }

    /// Extract destination hash and hops from raw announce bytes.
    fn extract_announce_info(raw: &[u8]) -> ([u8; 16], u8) {
        if raw.len() < 18 {
            return ([0; 16], 0);
        }
        let header_type = (raw[0] >> 6) & 0x03;
        let hops = raw[1];
        if header_type == constants::HEADER_2 && raw.len() >= 34 {
            // H2: transport_id at [2..18], dest_hash at [18..34]
            let mut dest = [0u8; 16];
            dest.copy_from_slice(&raw[18..34]);
            (dest, hops)
        } else {
            // H1: dest_hash at [2..18]
            let mut dest = [0u8; 16];
            dest.copy_from_slice(&raw[2..18]);
            (dest, hops)
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn link_table_ref(&self) -> &BTreeMap<[u8; 16], LinkEntry> {
        &self.link_table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketFlags;

    fn make_config(transport_enabled: bool) -> TransportConfig {
        TransportConfig {
            transport_enabled,
            identity_hash: if transport_enabled {
                Some([0x42; 16])
            } else {
                None
            },
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
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

    fn make_interface(id: u64, mode: u8) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: String::from("test"),
            mode,
            recursive_prs: false,
            announces_from_internal: true,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: crate::transport::types::IngressControlConfig::disabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
        }
    }

    fn make_announce_entry(dest_hash: [u8; 16], timestamp: f64, fill_len: usize) -> AnnounceEntry {
        AnnounceEntry {
            timestamp,
            retransmit_timeout: timestamp,
            retries: 0,
            received_from: [0xAA; 16],
            hops: 2,
            packet_raw: vec![0x01; fill_len],
            packet_data: vec![0x02; fill_len],
            destination_hash: dest_hash,
            context_flag: 0,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        }
    }

    fn make_path_entry(
        timestamp: f64,
        hops: u8,
        receiving_interface: InterfaceId,
        next_hop: [u8; 16],
    ) -> PathEntry {
        PathEntry {
            timestamp,
            next_hop,
            hops,
            expires: timestamp + 10_000.0,
            random_blobs: Vec::new(),
            receiving_interface,
            packet_hash: [0; 32],
            announce_raw: None,
        }
    }

    fn make_unique_tag(dest_hash: [u8; 16], tag: &[u8]) -> [u8; 32] {
        let mut unique_tag = [0u8; 32];
        let tag_len = tag.len().min(16);
        unique_tag[..16].copy_from_slice(&dest_hash);
        unique_tag[16..16 + tag_len].copy_from_slice(&tag[..tag_len]);
        unique_tag
    }

    fn make_random_blob(timebase: u64) -> [u8; 10] {
        let mut blob = [0u8; 10];
        let bytes = timebase.to_be_bytes();
        blob[5..10].copy_from_slice(&bytes[3..8]);
        blob
    }

    #[test]
    fn test_empty_engine() {
        let engine = TransportEngine::new(make_config(false));
        assert!(!engine.has_path(&[0; 16]));
        assert!(engine.hops_to(&[0; 16]).is_none());
        assert!(engine.next_hop(&[0; 16]).is_none());
    }

    #[test]
    fn test_register_deregister_interface() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        assert!(engine.interfaces.contains_key(&InterfaceId(1)));

        engine.deregister_interface(InterfaceId(1));
        assert!(!engine.interfaces.contains_key(&InterfaceId(1)));
    }

    #[test]
    fn test_deregister_interface_removes_announce_queue_state() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let _ = engine.announce_queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            constants::ANNOUNCE_CAP,
        );
        let _ = engine.announce_queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100].into(),
            [0xBB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            None,
            constants::ANNOUNCE_CAP,
        );
        assert_eq!(engine.announce_queue_count(), 1);

        engine.deregister_interface(InterfaceId(1));
        assert_eq!(engine.announce_queue_count(), 0);
    }

    #[test]
    fn test_deregister_interface_preserves_other_announce_queues() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let _ = engine.announce_queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            constants::ANNOUNCE_CAP,
        );
        let _ = engine.announce_queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100].into(),
            [0xAB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            None,
            constants::ANNOUNCE_CAP,
        );
        let _ = engine.announce_queues.gate_announce(
            InterfaceId(2),
            vec![0x03; 100].into(),
            [0xBA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            constants::ANNOUNCE_CAP,
        );
        let _ = engine.announce_queues.gate_announce(
            InterfaceId(2),
            vec![0x04; 100].into(),
            [0xBB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            None,
            constants::ANNOUNCE_CAP,
        );

        engine.deregister_interface(InterfaceId(1));
        assert_eq!(engine.announce_queue_count(), 1);
        assert_eq!(engine.nonempty_announce_queue_count(), 1);
    }

    #[test]
    fn test_register_deregister_destination() {
        let mut engine = TransportEngine::new(make_config(false));
        let dest = [0x11; 16];
        engine.register_destination(dest, constants::DESTINATION_SINGLE);
        assert!(engine.local_destinations.contains_key(&dest));

        engine.deregister_destination(&dest);
        assert!(!engine.local_destinations.contains_key(&dest));
    }

    #[test]
    fn test_path_state() {
        let mut engine = TransportEngine::new(make_config(false));
        let dest = [0x22; 16];

        assert!(!engine.path_is_unresponsive(&dest));

        engine.mark_path_unresponsive(&dest, None);
        assert!(engine.path_is_unresponsive(&dest));

        engine.mark_path_responsive(&dest);
        assert!(!engine.path_is_unresponsive(&dest));
    }

    #[test]
    fn test_announce_clears_stale_path_state_for_unknown_destination() {
        use crate::announce::AnnounceData;
        use crate::destination::{destination_hash, name_hash};

        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x61; 32]));
        let dest_hash = destination_hash("pathfix", &["announce"], Some(identity.hash()));
        let name_h = name_hash("pathfix", &["announce"]);
        let random_hash = [0x24u8; 10];

        let (announce_data, _) =
            AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

        let packet = RawPacket::pack(
            PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            0,
            &dest_hash,
            None,
            constants::CONTEXT_NONE,
            &announce_data,
        )
        .unwrap();

        engine.mark_path_unresponsive(&dest_hash, None);
        assert!(engine.path_is_unresponsive(&dest_hash));
        assert!(!engine.has_path(&dest_hash));

        let mut rng = rns_crypto::FixedRng::new(&[0x62; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        assert!(engine.has_path(&dest_hash));
        assert!(
            !engine.path_is_unresponsive(&dest_hash),
            "stale path state should be cleared for newly installed paths"
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            TransportAction::PathUpdated {
                destination_hash,
                interface,
                ..
            } if *destination_hash == dest_hash && *interface == InterfaceId(1)
        )));
    }

    #[test]
    fn test_duplicate_announce_from_second_interface_uses_existing_path() {
        use crate::announce::AnnounceData;
        use crate::destination::{destination_hash, name_hash};

        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x63; 32]));
        let dest_hash = destination_hash("dedup", &["announce"], Some(identity.hash()));
        let name_h = name_hash("dedup", &["announce"]);
        let random_hash = [0x25u8; 10];

        let (announce_data, _) =
            AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();
        let packet = RawPacket::pack(
            PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            0,
            &dest_hash,
            None,
            constants::CONTEXT_NONE,
            &announce_data,
        )
        .unwrap();

        let mut rng = rns_crypto::FixedRng::new(&[0x64; 32]);
        let first_actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata::default(),
            },
            &mut rng,
        );
        assert!(first_actions.iter().any(|action| matches!(
            action,
            TransportAction::PathUpdated {
                destination_hash,
                interface,
                ..
            } if *destination_hash == dest_hash && *interface == InterfaceId(1)
        )));

        let second_actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(2),
                now: 1000.1,
                rx: RxMetadata::default(),
            },
            &mut rng,
        );

        assert!(!second_actions.iter().any(|action| matches!(
            action,
            TransportAction::PathUpdated {
                destination_hash,
                interface,
                ..
            } if *destination_hash == dest_hash && *interface == InterfaceId(2)
        )));
        let path = engine
            .path_table
            .get(&dest_hash)
            .and_then(|set| set.primary())
            .expect("first announce should install a path");
        assert_eq!(path.receiving_interface, InterfaceId(1));
    }

    #[test]
    fn test_boundary_exempts_unresponsive() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_BOUNDARY));
        let dest = [0xB1; 16];

        // Marking via a boundary interface should be skipped
        engine.mark_path_unresponsive(&dest, Some(InterfaceId(1)));
        assert!(!engine.path_is_unresponsive(&dest));
    }

    #[test]
    fn test_non_boundary_marks_unresponsive() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        let dest = [0xB2; 16];

        // Marking via a non-boundary interface should work
        engine.mark_path_unresponsive(&dest, Some(InterfaceId(1)));
        assert!(engine.path_is_unresponsive(&dest));
    }

    #[test]
    fn test_expire_path() {
        let mut engine = TransportEngine::new(make_config(false));
        let dest = [0x33; 16];

        engine.path_table.insert(
            dest,
            PathSet::from_single(
                PathEntry {
                    timestamp: 1000.0,
                    next_hop: [0; 16],
                    hops: 2,
                    expires: 9999.0,
                    random_blobs: Vec::new(),
                    receiving_interface: InterfaceId(1),
                    packet_hash: [0; 32],
                    announce_raw: None,
                },
                1,
            ),
        );

        assert!(engine.has_path(&dest));
        engine.expire_path(&dest);
        // Path still exists but expires = 0
        assert!(engine.has_path(&dest));
        assert_eq!(engine.path_table[&dest].primary().unwrap().expires, 0.0);
    }

    #[test]
    fn test_link_table_operations() {
        let mut engine = TransportEngine::new(make_config(false));
        let link_id = [0x44; 16];

        engine.register_link(
            link_id,
            LinkEntry {
                timestamp: 100.0,
                next_hop_transport_id: [0; 16],
                next_hop_interface: InterfaceId(1),
                remaining_hops: 3,
                received_interface: InterfaceId(2),
                taken_hops: 2,
                destination_hash: [0xAA; 16],
                validated: false,
                proof_timeout: 200.0,
            },
        );

        assert!(engine.link_table.contains_key(&link_id));
        assert!(!engine.link_table[&link_id].validated);

        engine.validate_link(&link_id);
        assert!(engine.link_table[&link_id].validated);

        engine.remove_link(&link_id);
        assert!(!engine.link_table.contains_key(&link_id));
    }

    #[test]
    fn test_lrproof_routes_from_originating_side_via_link_table() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let link_id = [0x44; 16];
        engine.register_link(
            link_id,
            LinkEntry {
                timestamp: 100.0,
                next_hop_transport_id: [0xAA; 16],
                next_hop_interface: InterfaceId(2),
                remaining_hops: 3,
                received_interface: InterfaceId(1),
                taken_hops: 1,
                destination_hash: [0xBB; 16],
                validated: false,
                proof_timeout: 200.0,
            },
        );

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet = RawPacket::pack(
            flags,
            0,
            &link_id,
            None,
            constants::CONTEXT_LRPROOF,
            &[0xCC; 64],
        )
        .unwrap();
        let mut rng = rns_crypto::FixedRng::new(&[0x33; 32]);

        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 101.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        assert!(matches!(
            engine
                .link_table_ref()
                .get(&link_id)
                .map(|entry| entry.validated),
            Some(true)
        ));
        assert!(actions.iter().any(|action| matches!(
            action,
            TransportAction::LinkEstablished {
                link_id: established,
                interface: InterfaceId(2),
            } if *established == link_id
        )));
        assert!(actions.iter().any(|action| matches!(
            action,
            TransportAction::SendOnInterface {
                interface: InterfaceId(2),
                ..
            }
        )));
    }

    #[test]
    fn test_packet_filter_drops_plain_announce() {
        let engine = TransportEngine::new(make_config(false));
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };
        let packet =
            RawPacket::pack(flags, 0, &[0; 16], None, constants::CONTEXT_NONE, b"test").unwrap();
        assert!(!engine.packet_filter(&packet));
    }

    #[test]
    fn test_packet_filter_allows_keepalive() {
        let engine = TransportEngine::new(make_config(false));
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
            &[0; 16],
            None,
            constants::CONTEXT_KEEPALIVE,
            b"test",
        )
        .unwrap();
        assert!(engine.packet_filter(&packet));
    }

    #[test]
    fn test_packet_filter_drops_high_hop_plain() {
        let engine = TransportEngine::new(make_config(false));
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let mut packet =
            RawPacket::pack(flags, 0, &[0; 16], None, constants::CONTEXT_NONE, b"test").unwrap();
        packet.hops = 2;
        assert!(!engine.packet_filter(&packet));
    }

    #[test]
    fn test_packet_filter_allows_duplicate_single_announce() {
        let mut engine = TransportEngine::new(make_config(false));
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
            &[0; 16],
            None,
            constants::CONTEXT_NONE,
            &[0xAA; 64],
        )
        .unwrap();

        // Add to hashlist
        engine.packet_hashlist.add(packet.packet_hash);

        // Should still pass filter (duplicate announce for SINGLE allowed)
        assert!(engine.packet_filter(&packet));
    }

    #[test]
    fn test_packet_filter_fifo_eviction_allows_oldest_hash_again() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.packet_hashlist = PacketHashlist::new(2);

        let make_packet = |seed: u8| {
            let flags = PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_DATA,
            };
            RawPacket::pack(
                flags,
                0,
                &[seed; 16],
                None,
                constants::CONTEXT_NONE,
                &[seed; 4],
            )
            .unwrap()
        };

        let packet1 = make_packet(1);
        let packet2 = make_packet(2);
        let packet3 = make_packet(3);

        engine.packet_hashlist.add(packet1.packet_hash);
        engine.packet_hashlist.add(packet2.packet_hash);
        assert!(!engine.packet_filter(&packet1));

        engine.packet_hashlist.add(packet3.packet_hash);

        assert!(engine.packet_filter(&packet1));
        assert!(!engine.packet_filter(&packet2));
        assert!(!engine.packet_filter(&packet3));
    }

    #[test]
    fn test_packet_filter_duplicate_does_not_refresh_recency() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.packet_hashlist = PacketHashlist::new(2);

        let make_packet = |seed: u8| {
            let flags = PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_DATA,
            };
            RawPacket::pack(
                flags,
                0,
                &[seed; 16],
                None,
                constants::CONTEXT_NONE,
                &[seed; 4],
            )
            .unwrap()
        };

        let packet1 = make_packet(1);
        let packet2 = make_packet(2);
        let packet3 = make_packet(3);

        engine.packet_hashlist.add(packet1.packet_hash);
        engine.packet_hashlist.add(packet2.packet_hash);
        engine.packet_hashlist.add(packet2.packet_hash);
        engine.packet_hashlist.add(packet3.packet_hash);

        assert!(engine.packet_filter(&packet1));
        assert!(!engine.packet_filter(&packet2));
        assert!(!engine.packet_filter(&packet3));
    }

    #[test]
    fn test_tick_retransmits_announce() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let dest = [0x55; 16];
        engine.insert_announce_entry(
            dest,
            AnnounceEntry {
                timestamp: 190.0,
                retransmit_timeout: 100.0, // ready to retransmit
                retries: 0,
                received_from: [0xAA; 16],
                hops: 2,
                packet_raw: vec![0x01, 0x02],
                packet_data: vec![0xCC; 10],
                destination_hash: dest,
                context_flag: 0,
                local_rebroadcasts: 0,
                block_rebroadcasts: false,
                attached_interface: None,
            },
            190.0,
        );

        let mut rng = rns_crypto::FixedRng::new(&[0x42; 32]);
        let actions = engine.tick(200.0, &mut rng);

        // Should have a send action for the retransmit (gated through announce queue,
        // expanded from BroadcastOnAllInterfaces to per-interface SendOnInterface)
        assert!(!actions.is_empty());
        assert!(matches!(
            &actions[0],
            TransportAction::SendOnInterface { .. }
        ));

        // Retries should have increased
        assert_eq!(engine.announce_table[&dest].retries, 1);
    }

    #[test]
    fn test_gate_retransmit_actions_expands_broadcast_to_matching_interfaces() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        engine.register_interface(make_interface(3, constants::MODE_ACCESS_POINT));

        let dest = [0x56; 16];
        let raw = make_announce_raw(&dest, &[0xAB; 32]);
        let actions = engine.gate_retransmit_actions(
            vec![TransportAction::BroadcastOnAllInterfaces {
                raw: raw.clone().into(),
                exclude: None,
            }],
            1000.0,
        );

        assert_eq!(actions.len(), 2);
        for action in &actions {
            match action {
                TransportAction::SendOnInterface {
                    interface,
                    raw: sent,
                } => {
                    assert!(*interface == InterfaceId(1) || *interface == InterfaceId(2));
                    assert_eq!(&**sent, raw.as_slice());
                }
                other => panic!("expected SendOnInterface, got {:?}", other),
            }
        }
    }

    #[test]
    fn test_tick_culls_expired_announce_entries() {
        let mut config = make_config(true);
        config.announce_table_ttl_secs = 10.0;
        let mut engine = TransportEngine::new(config);

        let dest1 = [0x61; 16];
        let dest2 = [0x62; 16];
        assert!(engine.insert_announce_entry(dest1, make_announce_entry(dest1, 100.0, 8), 100.0));
        assert!(engine.insert_held_announce(dest2, make_announce_entry(dest2, 100.0, 8), 100.0));

        let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
        let _ = engine.tick(111.0, &mut rng);

        assert!(!engine.announce_table().contains_key(&dest1));
        assert!(!engine.held_announces().contains_key(&dest2));
    }

    #[test]
    fn test_announce_retention_cap_evicts_oldest_and_prefers_held_on_tie() {
        let sample_entry = make_announce_entry([0x70; 16], 100.0, 32);
        let mut config = make_config(true);
        config.announce_table_max_bytes = TransportEngine::announce_entry_size_bytes(&sample_entry)
            * 2
            + TransportEngine::announce_entry_size_bytes(&sample_entry) / 2;
        let max_bytes = config.announce_table_max_bytes;
        let mut engine = TransportEngine::new(config);

        let held_dest = [0x71; 16];
        let active_dest = [0x72; 16];
        let newest_dest = [0x73; 16];

        assert!(engine.insert_held_announce(
            held_dest,
            make_announce_entry(held_dest, 100.0, 32),
            100.0,
        ));
        assert!(engine.insert_announce_entry(
            active_dest,
            make_announce_entry(active_dest, 100.0, 32),
            100.0,
        ));
        assert!(engine.insert_announce_entry(
            newest_dest,
            make_announce_entry(newest_dest, 101.0, 32),
            101.0,
        ));

        assert!(!engine.held_announces().contains_key(&held_dest));
        assert!(engine.announce_table().contains_key(&active_dest));
        assert!(engine.announce_table().contains_key(&newest_dest));
        assert!(engine.announce_retained_bytes() <= max_bytes);
    }

    #[test]
    fn test_oversized_announce_entry_is_not_retained() {
        let mut config = make_config(true);
        config.announce_table_max_bytes = 200;
        let mut engine = TransportEngine::new(config);
        let dest = [0x81; 16];

        assert!(!engine.insert_announce_entry(dest, make_announce_entry(dest, 100.0, 256), 100.0));
        assert!(!engine.announce_table().contains_key(&dest));
        assert_eq!(engine.announce_retained_bytes(), 0);
    }

    #[test]
    fn test_void_queues_clears_shutdown_transients() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let active_dest = [0x91; 16];
        let held_dest = [0x92; 16];
        assert!(engine.insert_announce_entry(
            active_dest,
            make_announce_entry(active_dest, 100.0, 16),
            100.0,
        ));
        assert!(engine.insert_held_announce(
            held_dest,
            make_announce_entry(held_dest, 100.0, 16),
            100.0,
        ));
        engine.reverse_table.insert(
            [0x93; 16],
            tables::ReverseEntry {
                receiving_interface: InterfaceId(1),
                outbound_interface: InterfaceId(2),
                timestamp: 100.0,
            },
        );
        let _ = engine.announce_queues.gate_announce(
            InterfaceId(1),
            vec![0xAA; 32].into(),
            [0x94; 16],
            2,
            100.0,
            100.0,
            Some(1000),
            None,
            constants::ANNOUNCE_CAP,
        );
        let _ = engine.announce_queues.gate_announce(
            InterfaceId(1),
            vec![0xBB; 32].into(),
            [0x95; 16],
            3,
            100.0,
            100.0,
            Some(1000),
            None,
            constants::ANNOUNCE_CAP,
        );

        assert_eq!(engine.announce_table_count(), 1);
        assert_eq!(engine.held_announces_count(), 1);
        assert_eq!(engine.reverse_table_count(), 1);
        assert_eq!(engine.queued_announce_count(), 1);

        engine.void_queues();

        assert_eq!(engine.announce_table_count(), 0);
        assert_eq!(engine.held_announces_count(), 0);
        assert_eq!(engine.reverse_table_count(), 0);
        assert_eq!(engine.queued_announce_count(), 0);
        assert_eq!(engine.nonempty_announce_queue_count(), 0);
        assert_eq!(engine.announce_retained_bytes(), 0);
    }

    #[test]
    fn test_blackhole_identity() {
        let mut engine = TransportEngine::new(make_config(false));
        let hash = [0xAA; 16];
        let now = 1000.0;

        assert!(!engine.is_blackholed(&hash, now));

        engine.blackhole_identity(hash, now, None, Some(String::from("test")));
        assert!(engine.is_blackholed(&hash, now));
        assert!(engine.is_blackholed(&hash, now + 999999.0)); // never expires

        assert!(engine.unblackhole_identity(&hash));
        assert!(!engine.is_blackholed(&hash, now));
        assert!(!engine.unblackhole_identity(&hash)); // already removed
    }

    #[test]
    fn test_blackhole_with_duration() {
        let mut engine = TransportEngine::new(make_config(false));
        let hash = [0xBB; 16];
        let now = 1000.0;

        engine.blackhole_identity(hash, now, Some(1.0), None); // 1 hour
        assert!(engine.is_blackholed(&hash, now));
        assert!(engine.is_blackholed(&hash, now + 3599.0)); // just before expiry
        assert!(!engine.is_blackholed(&hash, now + 3601.0)); // after expiry
    }

    #[test]
    fn test_cull_blackholed() {
        let mut engine = TransportEngine::new(make_config(false));
        let hash1 = [0xCC; 16];
        let hash2 = [0xDD; 16];
        let now = 1000.0;

        engine.blackhole_identity(hash1, now, Some(1.0), None); // 1 hour
        engine.blackhole_identity(hash2, now, None, None); // never expires

        engine.cull_blackholed(now + 4000.0); // past hash1 expiry

        assert!(!engine.blackholed_identities.contains_key(&hash1));
        assert!(engine.blackholed_identities.contains_key(&hash2));
    }

    #[test]
    fn test_blackhole_blocks_announce() {
        use crate::announce::AnnounceData;
        use crate::destination::{destination_hash, name_hash};

        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x55; 32]));
        let dest_hash = destination_hash("test", &["app"], Some(identity.hash()));
        let name_h = name_hash("test", &["app"]);
        let random_hash = [0x42u8; 10];

        let (announce_data, _) =
            AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

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

        // Blackhole the identity
        let now = 1000.0;
        engine.blackhole_identity(*identity.hash(), now, None, None);

        let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        // Should produce no AnnounceReceived or PathUpdated actions
        assert!(actions
            .iter()
            .all(|a| !matches!(a, TransportAction::AnnounceReceived { .. })));
        assert!(actions
            .iter()
            .all(|a| !matches!(a, TransportAction::PathUpdated { .. })));
    }

    #[test]
    fn test_async_announce_retransmit_cleanup_happens_before_queueing() {
        use crate::announce::AnnounceData;
        use crate::destination::{destination_hash, name_hash};
        use crate::transport::announce_verify_queue::AnnounceVerifyQueue;

        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x31; 32]));
        let dest_hash = destination_hash("async", &["announce"], Some(identity.hash()));
        let name_h = name_hash("async", &["announce"]);
        let random_hash = [0x44u8; 10];
        let (announce_data, _) =
            AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

        let packet = RawPacket::pack(
            PacketFlags {
                header_type: constants::HEADER_2,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_TRANSPORT,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            3,
            &dest_hash,
            Some(&[0xBB; 16]),
            constants::CONTEXT_NONE,
            &announce_data,
        )
        .unwrap();

        engine.announce_table.insert(
            dest_hash,
            AnnounceEntry {
                timestamp: 1000.0,
                retransmit_timeout: 2000.0,
                retries: constants::PATHFINDER_R,
                received_from: [0xBB; 16],
                hops: 2,
                packet_raw: packet.raw.clone(),
                packet_data: packet.data.clone(),
                destination_hash: dest_hash,
                context_flag: constants::FLAG_UNSET,
                local_rebroadcasts: 0,
                block_rebroadcasts: false,
                attached_interface: None,
            },
        );

        let mut queue = AnnounceVerifyQueue::new(8);
        let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
        let actions = engine.handle_inbound_with_announce_queue(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
            Some(&mut queue),
        );

        assert!(actions.is_empty());
        assert_eq!(queue.len(), 1);
        assert!(
            !engine.announce_table.contains_key(&dest_hash),
            "retransmit completion should clear announce_table before queueing"
        );
    }

    #[test]
    fn test_async_announce_completion_inserts_sig_cache_and_prevents_requeue() {
        use crate::announce::AnnounceData;
        use crate::destination::{destination_hash, name_hash};
        use crate::transport::announce_verify_queue::AnnounceVerifyQueue;

        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x52; 32]));
        let dest_hash = destination_hash("async", &["cache"], Some(identity.hash()));
        let name_h = name_hash("async", &["cache"]);
        let random_hash = [0x55u8; 10];
        let (announce_data, _) =
            AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

        let packet = RawPacket::pack(
            PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            0,
            &dest_hash,
            None,
            constants::CONTEXT_NONE,
            &announce_data,
        )
        .unwrap();

        let mut queue = AnnounceVerifyQueue::new(8);
        let mut rng = rns_crypto::FixedRng::new(&[0x77; 32]);
        let actions = engine.handle_inbound_with_announce_queue(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
            Some(&mut queue),
        );
        assert!(actions.is_empty());
        assert_eq!(queue.len(), 1);

        let mut batch = queue.take_pending(1000.0);
        assert_eq!(batch.len(), 1);
        let (key, pending) = batch.pop().unwrap();

        let announce = AnnounceData::unpack(&pending.packet.data, false).unwrap();
        let validated = announce.validate(&pending.packet.destination_hash).unwrap();
        let mut material = [0u8; 80];
        material[..16].copy_from_slice(&pending.packet.destination_hash);
        material[16..].copy_from_slice(&announce.signature);
        let sig_cache_key = hash::full_hash(&material);

        let pending = queue.complete_success(&key).unwrap();
        let actions =
            engine.complete_verified_announce(pending, validated, sig_cache_key, 1000.0, &mut rng);
        assert!(actions
            .iter()
            .any(|action| matches!(action, TransportAction::AnnounceReceived { .. })));
        assert!(engine.announce_sig_cache_contains(&sig_cache_key));

        let actions = engine.handle_inbound_with_announce_queue(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1001.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
            Some(&mut queue),
        );
        assert!(actions.is_empty());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_tick_culls_expired_path() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let dest = [0x66; 16];
        engine.path_table.insert(
            dest,
            PathSet::from_single(
                PathEntry {
                    timestamp: 100.0,
                    next_hop: [0; 16],
                    hops: 2,
                    expires: 200.0,
                    random_blobs: Vec::new(),
                    receiving_interface: InterfaceId(1),
                    packet_hash: [0; 32],
                    announce_raw: None,
                },
                1,
            ),
        );

        assert!(engine.has_path(&dest));

        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
        // Advance past cull interval and path expiry
        engine.tick(300.0, &mut rng);

        assert!(!engine.has_path(&dest));
    }

    // =========================================================================
    // Phase 7b: Local client transport tests
    // =========================================================================

    fn make_local_client_interface(id: u64) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: String::from("local_client"),
            mode: constants::MODE_FULL,
            recursive_prs: false,
            announces_from_internal: true,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: true,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: crate::transport::types::IngressControlConfig::disabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
        }
    }

    #[test]
    fn test_has_local_clients() {
        let mut engine = TransportEngine::new(make_config(false));
        assert!(!engine.has_local_clients());

        engine.register_interface(make_interface(1, constants::MODE_FULL));
        assert!(!engine.has_local_clients());

        engine.register_interface(make_local_client_interface(2));
        assert!(engine.has_local_clients());

        engine.deregister_interface(InterfaceId(2));
        assert!(!engine.has_local_clients());
    }

    #[test]
    fn test_local_client_hop_decrement() {
        // Packets from local clients should have their hops decremented
        // to cancel the standard +1 (net zero change)
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        // Register destination so we get a DeliverLocal action
        let dest = [0xAA; 16];
        engine.register_destination(dest, constants::DESTINATION_PLAIN);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        // Pack with hops=0
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        // Should have local delivery; hops should still be 0 (not 1)
        // because the local client decrement cancels the increment
        let deliver = actions
            .iter()
            .find(|a| matches!(a, TransportAction::DeliverLocal { .. }));
        assert!(deliver.is_some(), "Should deliver locally");
    }

    #[test]
    fn test_prepare_inbound_packet_only_retains_original_raw_for_announces() {
        let engine = TransportEngine::new(make_config(false));
        let dest = [0xAB; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        let ctx = engine
            .prepare_inbound_packet(InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(9),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            })
            .expect("packet should parse and pass filter");

        assert!(ctx.original_raw.is_none());
        assert_eq!(ctx.packet.raw, packet.raw);
        assert_eq!(ctx.packet.hops, 1);
        assert_eq!(ctx.iface, InterfaceId(9));

        let announce_flags = PacketFlags {
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
            ..flags
        };
        let announce = RawPacket::pack(
            announce_flags,
            0,
            &dest,
            None,
            constants::CONTEXT_NONE,
            &[0u8; 91],
        )
        .unwrap();
        let announce_ctx = engine
            .prepare_inbound_packet(InboundFrame {
                raw: &announce.raw,
                iface: InterfaceId(9),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            })
            .expect("announce should parse and pass filter");
        assert_eq!(
            announce_ctx.original_raw.as_deref(),
            Some(announce.raw.as_slice())
        );
    }

    #[test]
    fn test_deliver_local_preserves_original_raw_and_metadata() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let dest = [0xAC; 16];
        engine.register_destination(dest, constants::DESTINATION_SINGLE);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"deliver").unwrap();

        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        let deliver = actions
            .iter()
            .find_map(|action| match action {
                TransportAction::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                    receiving_interface,
                } => Some((destination_hash, raw, packet_hash, receiving_interface)),
                _ => None,
            })
            .expect("should produce DeliverLocal");

        assert_eq!(*deliver.0, dest);
        assert_eq!(&**deliver.1, packet.raw.as_slice());
        assert_eq!(*deliver.2, packet.packet_hash);
        assert_eq!(*deliver.3, InterfaceId(1));
    }

    #[test]
    fn test_plain_broadcast_from_local_client() {
        // PLAIN broadcast from local client should forward to external interfaces
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xBB; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test").unwrap();

        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        // Should have ForwardPlainBroadcast to external (to_local=false)
        let forward = actions.iter().find(|a| {
            matches!(
                a,
                TransportAction::ForwardPlainBroadcast {
                    to_local: false,
                    ..
                }
            )
        });
        assert!(forward.is_some(), "Should forward to external interfaces");
    }

    #[test]
    fn test_plain_broadcast_from_external() {
        // PLAIN broadcast from external should forward to local clients
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xCC; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test").unwrap();

        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(2),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        // Should have ForwardPlainBroadcast to local clients (to_local=true)
        let forward = actions.iter().find(|a| {
            matches!(
                a,
                TransportAction::ForwardPlainBroadcast { to_local: true, .. }
            )
        });
        assert!(forward.is_some(), "Should forward to local clients");
    }

    #[test]
    fn test_no_plain_broadcast_bridging_without_local_clients() {
        // Without local clients, no bridging should happen
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xDD; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test").unwrap();

        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        // No ForwardPlainBroadcast should be emitted
        let has_forward = actions
            .iter()
            .any(|a| matches!(a, TransportAction::ForwardPlainBroadcast { .. }));
        assert!(!has_forward, "No bridging without local clients");
    }

    #[test]
    fn test_announce_forwarded_to_local_clients() {
        use crate::announce::AnnounceData;
        use crate::destination::{destination_hash, name_hash};

        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_local_client_interface(2));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x77; 32]));
        let dest_hash = destination_hash("test", &["fwd"], Some(identity.hash()));
        let name_h = name_hash("test", &["fwd"]);
        let random_hash = [0x42u8; 10];

        let (announce_data, _) =
            AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

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

        let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        // Should have ForwardToLocalClients since we have local clients
        let forward = actions
            .iter()
            .find(|a| matches!(a, TransportAction::ForwardToLocalClients { .. }));
        assert!(
            forward.is_some(),
            "Should forward announce to local clients"
        );

        // The exclude should be the receiving interface
        match forward.unwrap() {
            TransportAction::ForwardToLocalClients { exclude, raw } => {
                assert_eq!(*exclude, Some(InterfaceId(1)));
                let flags = PacketFlags::unpack(raw[0]);
                assert_eq!(flags.header_type, constants::HEADER_2);
                assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
                assert_eq!(&raw[2..18], &[0x42; 16]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_no_announce_forward_without_local_clients() {
        use crate::announce::AnnounceData;
        use crate::destination::{destination_hash, name_hash};

        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x88; 32]));
        let dest_hash = destination_hash("test", &["nofwd"], Some(identity.hash()));
        let name_h = name_hash("test", &["nofwd"]);
        let random_hash = [0x42u8; 10];

        let (announce_data, _) =
            AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

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

        let mut rng = rns_crypto::FixedRng::new(&[0x22; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        // No ForwardToLocalClients should be emitted
        let has_forward = actions
            .iter()
            .any(|a| matches!(a, TransportAction::ForwardToLocalClients { .. }));
        assert!(!has_forward, "No forward without local clients");
    }

    #[test]
    fn test_local_client_exclude_from_forward() {
        use crate::announce::AnnounceData;
        use crate::destination::{destination_hash, name_hash};

        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_local_client_interface(2));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
        let dest_hash = destination_hash("test", &["excl"], Some(identity.hash()));
        let name_h = name_hash("test", &["excl"]);
        let random_hash = [0x42u8; 10];

        let (announce_data, _) =
            AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

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

        let mut rng = rns_crypto::FixedRng::new(&[0x33; 32]);
        // Feed announce from local client 1
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        // Should forward to local clients, excluding interface 1 (the sender)
        let forward = actions
            .iter()
            .find(|a| matches!(a, TransportAction::ForwardToLocalClients { .. }));
        assert!(forward.is_some());
        match forward.unwrap() {
            TransportAction::ForwardToLocalClients { exclude, .. } => {
                assert_eq!(*exclude, Some(InterfaceId(1)));
            }
            _ => unreachable!(),
        }
    }

    // =========================================================================
    // Phase 7d: Tunnel tests
    // =========================================================================

    fn make_tunnel_interface(id: u64) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: String::from("tunnel_iface"),
            mode: constants::MODE_FULL,
            recursive_prs: false,
            announces_from_internal: true,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: true,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: crate::transport::types::IngressControlConfig::disabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
        }
    }

    #[test]
    fn test_handle_tunnel_new() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));

        let tunnel_id = [0xAA; 32];
        let actions = engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);

        // Should emit TunnelEstablished
        assert!(actions
            .iter()
            .any(|a| matches!(a, TransportAction::TunnelEstablished { .. })));

        // Interface should now have tunnel_id set
        let info = engine.interface_info(&InterfaceId(1)).unwrap();
        assert_eq!(info.tunnel_id, Some(tunnel_id));

        // Tunnel table should have the entry
        assert_eq!(engine.tunnel_table().len(), 1);
    }

    #[test]
    fn test_announce_stores_tunnel_path() {
        use crate::announce::AnnounceData;
        use crate::destination::{destination_hash, name_hash};

        let mut engine = TransportEngine::new(make_config(false));
        let mut iface = make_tunnel_interface(1);
        let tunnel_id = [0xBB; 32];
        iface.tunnel_id = Some(tunnel_id);
        engine.register_interface(iface);

        // Create tunnel entry
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);

        // Create and send an announce
        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xCC; 32]));
        let dest_hash = destination_hash("test", &["tunnel"], Some(identity.hash()));
        let name_h = name_hash("test", &["tunnel"]);
        let random_hash = [0x42u8; 10];

        let (announce_data, _) =
            AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

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

        let mut rng = rns_crypto::FixedRng::new(&[0xDD; 32]);
        engine.handle_inbound(
            InboundFrame {
                raw: &packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        // Path should be in path table
        assert!(engine.has_path(&dest_hash));

        // Path should also be in tunnel table
        let tunnel = engine.tunnel_table().get(&tunnel_id).unwrap();
        assert_eq!(tunnel.paths.len(), 1);
        assert!(tunnel.paths.contains_key(&dest_hash));
    }

    #[test]
    fn test_tunnel_reattach_restores_paths() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));

        let tunnel_id = [0xCC; 32];
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);

        // Manually add a path to the tunnel
        let dest = [0xDD; 16];
        engine.tunnel_table.store_tunnel_path(
            &tunnel_id,
            dest,
            tunnel::TunnelPath {
                timestamp: 1000.0,
                received_from: [0xEE; 16],
                hops: 3,
                expires: 1000.0 + constants::DESTINATION_TIMEOUT,
                random_blobs: Vec::new(),
                packet_hash: [0xFF; 32],
            },
            1000.0,
            constants::DESTINATION_TIMEOUT,
            usize::MAX,
        );

        // Void the tunnel interface (disconnect)
        engine.void_tunnel_interface(&tunnel_id);

        // Remove path from path table to simulate it expiring
        engine.path_table.remove(&dest);
        assert!(!engine.has_path(&dest));

        // Reattach tunnel on new interface
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        let actions = engine.handle_tunnel(tunnel_id, InterfaceId(2), 2000.0);

        // Should restore the path
        assert!(engine.has_path(&dest));
        let path = engine.path_table.get(&dest).unwrap().primary().unwrap();
        assert_eq!(path.hops, 3);
        assert_eq!(path.receiving_interface, InterfaceId(2));

        // Should emit TunnelEstablished
        assert!(actions
            .iter()
            .any(|a| matches!(a, TransportAction::TunnelEstablished { .. })));
    }

    #[test]
    fn test_active_packet_hashes_include_detached_tunnel_paths() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));

        let tunnel_id = [0xCA; 32];
        let destination_hash = [0xDB; 16];
        let packet_hash = [0xEC; 32];
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
        engine.tunnel_table.store_tunnel_path(
            &tunnel_id,
            destination_hash,
            tunnel::TunnelPath {
                timestamp: 1000.0,
                received_from: [0xFE; 16],
                hops: 2,
                expires: 1000.0 + constants::DESTINATION_TIMEOUT,
                random_blobs: Vec::new(),
                packet_hash,
            },
            1000.0,
            constants::DESTINATION_TIMEOUT,
            usize::MAX,
        );
        engine.void_tunnel_interface(&tunnel_id);
        engine.path_table.remove(&destination_hash);

        let active_hashes = engine.active_packet_hashes();
        assert_eq!(active_hashes, vec![packet_hash]);
    }

    #[test]
    fn test_tunnel_reattach_does_not_overwrite_newer_path() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));

        let tunnel_id = [0xCD; 32];
        let dest = [0xDE; 16];
        let older_blob = make_random_blob(100);
        let newer_blob = make_random_blob(200);

        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
        engine.tunnel_table.store_tunnel_path(
            &tunnel_id,
            dest,
            tunnel::TunnelPath {
                timestamp: 1000.0,
                received_from: [0xEE; 16],
                hops: 2,
                expires: 1000.0 + constants::DESTINATION_TIMEOUT,
                random_blobs: vec![older_blob],
                packet_hash: [0x11; 32],
            },
            1000.0,
            constants::DESTINATION_TIMEOUT,
            usize::MAX,
        );
        engine.void_tunnel_interface(&tunnel_id);

        engine.path_table.insert(
            dest,
            PathSet::from_single(
                PathEntry {
                    timestamp: 1500.0,
                    next_hop: [0xAB; 16],
                    hops: 3,
                    expires: 1500.0 + constants::DESTINATION_TIMEOUT,
                    random_blobs: vec![newer_blob],
                    receiving_interface: InterfaceId(3),
                    packet_hash: [0x22; 32],
                    announce_raw: None,
                },
                1,
            ),
        );

        engine.register_interface(make_interface(2, constants::MODE_FULL));
        engine.handle_tunnel(tunnel_id, InterfaceId(2), 2000.0);

        let path = engine.path_table.get(&dest).unwrap().primary().unwrap();
        assert_eq!(path.next_hop, [0xAB; 16]);
        assert_eq!(path.hops, 3);
        assert_eq!(path.receiving_interface, InterfaceId(3));
        assert_eq!(path.random_blobs, vec![newer_blob]);
    }

    #[test]
    fn test_void_tunnel_interface() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));

        let tunnel_id = [0xDD; 32];
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);

        // Verify tunnel has interface
        assert_eq!(
            engine.tunnel_table().get(&tunnel_id).unwrap().interface,
            Some(InterfaceId(1))
        );

        engine.void_tunnel_interface(&tunnel_id);

        // Interface voided, but tunnel still exists
        assert_eq!(engine.tunnel_table().len(), 1);
        assert_eq!(
            engine.tunnel_table().get(&tunnel_id).unwrap().interface,
            None
        );
    }

    #[test]
    fn test_tick_culls_tunnels() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));

        let tunnel_id = [0xEE; 32];
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
        assert_eq!(engine.tunnel_table().len(), 1);

        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);

        // Tick past DESTINATION_TIMEOUT + TABLES_CULL_INTERVAL
        engine.tick(
            1000.0 + constants::DESTINATION_TIMEOUT + constants::TABLES_CULL_INTERVAL + 1.0,
            &mut rng,
        );

        assert_eq!(engine.tunnel_table().len(), 0);
    }

    #[test]
    fn test_synthesize_tunnel() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
        let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);

        let actions = engine.synthesize_tunnel(&identity, InterfaceId(1), &mut rng);

        // Should produce a TunnelSynthesize action
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::TunnelSynthesize {
                interface,
                data,
                dest_hash,
            } => {
                assert_eq!(*interface, InterfaceId(1));
                assert_eq!(data.len(), tunnel::TUNNEL_SYNTH_LENGTH);
                // dest_hash should be the tunnel.synthesize plain destination
                let expected_dest = crate::destination::destination_hash(
                    "rnstransport",
                    &["tunnel", "synthesize"],
                    None,
                );
                assert_eq!(*dest_hash, expected_dest);
            }
            _ => panic!("Expected TunnelSynthesize"),
        }
    }

    #[test]
    fn test_synthesize_tunnel_missing_interface_is_dropped() {
        let engine = TransportEngine::new(make_config(true));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
        let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);

        let actions = engine.synthesize_tunnel(&identity, InterfaceId(99), &mut rng);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_synthesize_tunnel_public_only_identity_is_dropped() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
        let public_key = identity.get_public_key().unwrap();
        let public_only_identity = rns_crypto::identity::Identity::from_public_key(&public_key);
        let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);

        let actions = engine.synthesize_tunnel(&public_only_identity, InterfaceId(1), &mut rng);

        assert!(actions.is_empty());
    }

    // =========================================================================
    // DISCOVER_PATHS_FOR tests
    // =========================================================================

    fn make_path_request_data(dest_hash: &[u8; 16], tag: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(dest_hash);
        data.extend_from_slice(tag);
        data
    }

    fn make_transport_path_request_data(
        dest_hash: &[u8; 16],
        requestor_transport_id: &[u8; 16],
        tag: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(dest_hash);
        data.extend_from_slice(requestor_transport_id);
        data.extend_from_slice(tag);
        data
    }

    fn assert_recursive_path_request_packet(raw: &[u8], dest: &[u8; 16], tag: &[u8]) {
        let packet = RawPacket::unpack(raw).expect("recursive path request packet");
        let path_request_dest =
            crate::destination::destination_hash("rnstransport", &["path", "request"], None);

        assert_eq!(packet.flags.header_type, constants::HEADER_1);
        assert_eq!(packet.flags.transport_type, constants::TRANSPORT_BROADCAST);
        assert_eq!(packet.flags.destination_type, constants::DESTINATION_PLAIN);
        assert_eq!(packet.flags.packet_type, constants::PACKET_TYPE_DATA);
        assert_eq!(packet.hops, 0);
        assert_eq!(packet.context, constants::CONTEXT_NONE);
        assert_eq!(packet.destination_hash, path_request_dest);

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(dest);
        expected_data.extend_from_slice(&[0x42; 16]);
        expected_data.extend_from_slice(tag);
        assert_eq!(packet.data, expected_data);
    }

    #[test]
    fn test_path_request_forwarded_on_ap() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xD1; 16];
        let tag = [0x01; 16];
        let data = make_path_request_data(&dest, &tag);

        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        // Should forward the path request on interface 2 (the other OUT interface)
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, .. } => {
                assert_eq!(*interface, InterfaceId(2));
            }
            _ => panic!("Expected SendOnInterface for forwarded path request"),
        }
        // Should have stored a discovery path request
        assert!(engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_recursive_path_request_rebuilds_transport_payload() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xD8; 16];
        let original_requestor_transport_id = [0x99; 16];
        let tag = [0x08; 16];
        let data = make_transport_path_request_data(&dest, &original_requestor_transport_id, &tag);

        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, raw } => {
                assert_eq!(*interface, InterfaceId(2));
                assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
            }
            _ => panic!("expected SendOnInterface for recursive path request"),
        }
        assert!(engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_path_request_forwarded_on_internal() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_INTERNAL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xDB; 16];
        let tag = [0x0B; 16];
        let data = make_path_request_data(&dest, &tag);

        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, raw } => {
                assert_eq!(*interface, InterfaceId(2));
                assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
            }
            _ => panic!("expected SendOnInterface for recursive path request"),
        }
        assert!(engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_path_request_not_forwarded_on_full() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xD2; 16];
        let tag = [0x02; 16];
        let data = make_path_request_data(&dest, &tag);

        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        // MODE_FULL is not in DISCOVER_PATHS_FOR, so no forwarding
        assert!(actions.is_empty());
        assert!(!engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_path_request_forwarded_on_full_with_recursive_prs() {
        let mut engine = TransportEngine::new(make_config(true));
        let mut ingress = make_interface(1, constants::MODE_FULL);
        ingress.recursive_prs = true;
        engine.register_interface(ingress);
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xD9; 16];
        let tag = [0x09; 16];
        let data = make_path_request_data(&dest, &tag);

        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, raw } => {
                assert_eq!(*interface, InterfaceId(2));
                assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
            }
            _ => panic!("expected SendOnInterface for recursive path request"),
        }
        assert!(engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_recursive_prs_still_obeys_ingress_control() {
        let mut engine = TransportEngine::new(make_config(true));
        let mut ingress = make_interface(1, constants::MODE_FULL);
        ingress.recursive_prs = true;
        let ingress_config = crate::transport::types::IngressControlConfig::enabled();
        ingress.ip_freq = ingress_config.pr_burst_freq_new + 1.0;
        ingress.ingress_control = ingress_config;
        ingress.started = 1000.0;
        engine.register_interface(ingress);
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xDA; 16];
        let tag = [0x0A; 16];
        let data = make_path_request_data(&dest, &tag);

        let actions = engine.handle_path_request(&data, InterfaceId(1), 1001.0);

        assert!(actions.is_empty());
        assert!(!engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_duplicate_discovery_path_request_is_suppressed() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xD7; 16];
        let tag = [0x07; 16];
        let data = make_path_request_data(&dest, &tag);

        let first = engine.handle_path_request(&data, InterfaceId(1), 1000.0);
        let second = engine.handle_path_request(&data, InterfaceId(1), 1001.0);

        assert_eq!(first.len(), 1);
        assert!(
            second.is_empty(),
            "duplicate discovery request should be dropped"
        );
        assert_eq!(engine.discovery_pr_tags_count(), 1);
    }

    #[test]
    fn test_path_request_ingress_burst_suppresses_recursive_discovery() {
        let mut engine = TransportEngine::new(make_config(true));
        let mut ingress = make_interface(1, constants::MODE_ACCESS_POINT);
        ingress.ingress_control.enabled = true;
        ingress.ip_freq = constants::IC_PR_BURST_FREQ + 1.0;
        engine.register_interface(ingress);
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xE1; 16];
        let tag = [0x11; 16];
        let data = make_path_request_data(&dest, &tag);

        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        assert!(actions.is_empty());
        assert!(!engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_path_request_egress_limit_skips_only_limited_interface() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));

        let mut limited = make_interface(2, constants::MODE_FULL);
        limited.ingress_control.egress_enabled = true;
        limited.op_freq = constants::EC_PR_FREQ + 1.0;
        limited.op_samples = constants::IC_BURST_MIN_SAMPLES;
        engine.register_interface(limited);

        let mut allowed = make_interface(3, constants::MODE_FULL);
        allowed.ingress_control.egress_enabled = true;
        allowed.op_freq = constants::EC_PR_FREQ - 1.0;
        allowed.op_samples = constants::IC_BURST_MIN_SAMPLES;
        engine.register_interface(allowed);

        let dest = [0xE2; 16];
        let tag = [0x12; 16];
        let data = make_path_request_data(&dest, &tag);

        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, .. } => {
                assert_eq!(*interface, InterfaceId(3))
            }
            _ => panic!("expected SendOnInterface for the unlimited egress interface"),
        }
        assert!(engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_recursive_path_request_skips_interface_with_queued_announces() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
        let mut blocked = make_interface(2, constants::MODE_FULL);
        blocked.bitrate = Some(1_000);
        engine.register_interface(blocked);
        engine.register_interface(make_interface(3, constants::MODE_FULL));

        let _ = engine.announce_queues.gate_announce(
            InterfaceId(2),
            vec![0xAA; 100].into(),
            [0xA0; 16],
            1,
            900.0,
            900.0,
            Some(1_000),
            None,
            constants::ANNOUNCE_CAP,
        );
        let _ = engine.announce_queues.gate_announce(
            InterfaceId(2),
            vec![0xBB; 100].into(),
            [0xB0; 16],
            1,
            901.0,
            901.0,
            Some(1_000),
            None,
            constants::ANNOUNCE_CAP,
        );

        let dest = [0xE3; 16];
        let tag = [0x13; 16];
        let data = make_path_request_data(&dest, &tag);
        let actions = engine.handle_path_request(&data, InterfaceId(1), 902.0);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, .. } => {
                assert_eq!(*interface, InterfaceId(3));
            }
            _ => panic!("expected SendOnInterface for the unqueued egress interface"),
        }
        assert!(engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_recursive_path_request_skips_interface_with_active_announce_cap() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
        let mut blocked = make_interface(2, constants::MODE_FULL);
        blocked.bitrate = Some(1_000);
        engine.register_interface(blocked);

        let _ = engine.announce_queues.gate_announce(
            InterfaceId(2),
            vec![0xAA; 100].into(),
            [0xA0; 16],
            1,
            900.0,
            900.0,
            Some(1_000),
            None,
            constants::ANNOUNCE_CAP,
        );

        let dest = [0xE4; 16];
        let tag = [0x14; 16];
        let data = make_path_request_data(&dest, &tag);
        let actions = engine.handle_path_request(&data, InterfaceId(1), 901.0);

        assert!(actions.is_empty());
        assert!(!engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_recursive_path_request_reserves_announce_cap_on_sent_interface() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
        let mut egress = make_interface(2, constants::MODE_FULL);
        egress.bitrate = Some(1_000);
        engine.register_interface(egress);

        let dest = [0xE5; 16];
        let tag = [0x15; 16];
        let data = make_path_request_data(&dest, &tag);
        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        assert_eq!(actions.len(), 1);
        let queue = engine
            .announce_queues
            .queue_for(&InterfaceId(2))
            .expect("sent recursive PR should create announce-cap state");
        assert!(
            queue.announce_allowed_at > 1000.0,
            "recursive PR should reserve announce-cap airtime"
        );
        assert!(queue.entries.is_empty());
    }

    #[test]
    fn test_discovery_pr_tags_fifo_eviction() {
        let mut config = make_config(true);
        config.max_discovery_pr_tags = 2;
        let mut engine = TransportEngine::new(config);

        let dest1 = [0xA1; 16];
        let dest2 = [0xA2; 16];
        let dest3 = [0xA3; 16];
        let tag1 = [0x01; 16];
        let tag2 = [0x02; 16];
        let tag3 = [0x03; 16];

        engine.handle_path_request(
            &make_path_request_data(&dest1, &tag1),
            InterfaceId(1),
            1000.0,
        );
        engine.handle_path_request(
            &make_path_request_data(&dest2, &tag2),
            InterfaceId(1),
            1001.0,
        );
        assert_eq!(engine.discovery_pr_tags_count(), 2);

        let unique1 = make_unique_tag(dest1, &tag1);
        let unique2 = make_unique_tag(dest2, &tag2);
        assert!(engine.has_discovery_pr_tag(&unique1));
        assert!(engine.has_discovery_pr_tag(&unique2));

        engine.handle_path_request(
            &make_path_request_data(&dest3, &tag3),
            InterfaceId(1),
            1002.0,
        );
        assert_eq!(engine.discovery_pr_tags_count(), 2);
        assert!(!engine.has_discovery_pr_tag(&unique1));
        assert!(engine.has_discovery_pr_tag(&unique2));

        engine.handle_path_request(
            &make_path_request_data(&dest1, &tag1),
            InterfaceId(1),
            1003.0,
        );
        assert_eq!(engine.discovery_pr_tags_count(), 2);
        assert!(engine.has_discovery_pr_tag(&unique1));
    }

    #[test]
    fn test_path_destination_cap_evicts_oldest_and_clears_state() {
        let mut config = make_config(false);
        config.max_path_destinations = 2;
        let mut engine = TransportEngine::new(config);
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let dest1 = [0xB1; 16];
        let dest2 = [0xB2; 16];
        let dest3 = [0xB3; 16];

        engine.upsert_path_destination(
            dest1,
            make_path_entry(1000.0, 1, InterfaceId(1), [0x11; 16]),
            1000.0,
        );
        engine.upsert_path_destination(
            dest2,
            make_path_entry(1001.0, 1, InterfaceId(1), [0x22; 16]),
            1001.0,
        );
        engine
            .path_states
            .insert(dest1, constants::STATE_UNRESPONSIVE);

        engine.upsert_path_destination(
            dest3,
            make_path_entry(1002.0, 1, InterfaceId(1), [0x33; 16]),
            1002.0,
        );

        assert_eq!(engine.path_table_count(), 2);
        assert!(!engine.has_path(&dest1));
        assert!(engine.has_path(&dest2));
        assert!(engine.has_path(&dest3));
        assert!(!engine.path_states.contains_key(&dest1));
        assert_eq!(engine.path_destination_cap_evict_count(), 1);
    }

    #[test]
    fn test_existing_path_destination_update_does_not_trigger_cap_eviction() {
        let mut config = make_config(false);
        config.max_path_destinations = 2;
        config.max_paths_per_destination = 2;
        let mut engine = TransportEngine::new(config);
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let dest1 = [0xC1; 16];
        let dest2 = [0xC2; 16];

        engine.upsert_path_destination(
            dest1,
            make_path_entry(1000.0, 2, InterfaceId(1), [0x11; 16]),
            1000.0,
        );
        engine.upsert_path_destination(
            dest2,
            make_path_entry(1001.0, 2, InterfaceId(1), [0x22; 16]),
            1001.0,
        );

        engine.upsert_path_destination(
            dest2,
            make_path_entry(1002.0, 1, InterfaceId(1), [0x23; 16]),
            1002.0,
        );

        assert_eq!(engine.path_table_count(), 2);
        assert!(engine.has_path(&dest1));
        assert!(engine.has_path(&dest2));
    }

    #[test]
    fn test_roaming_loop_prevention() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ROAMING));

        let dest = [0xD3; 16];
        // Path is known and routes through the same interface (1)
        engine.path_table.insert(
            dest,
            PathSet::from_single(
                PathEntry {
                    timestamp: 900.0,
                    next_hop: [0xAA; 16],
                    hops: 2,
                    expires: 9999.0,
                    random_blobs: Vec::new(),
                    receiving_interface: InterfaceId(1),
                    packet_hash: [0; 32],
                    announce_raw: None,
                },
                1,
            ),
        );

        let tag = [0x03; 16];
        let data = make_path_request_data(&dest, &tag);

        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        // ROAMING interface, path next-hop on same interface → loop prevention, no action
        assert!(actions.is_empty());
        assert!(!engine.announce_table.contains_key(&dest));
    }

    /// Build a minimal HEADER_1 announce raw packet for testing.
    fn make_announce_raw(dest_hash: &[u8; 16], payload: &[u8]) -> Vec<u8> {
        // HEADER_1: [flags:1][hops:1][dest:16][context:1][data:*]
        // flags: HEADER_1(0) << 6 | context_flag(0) << 5 | TRANSPORT_BROADCAST(0) << 4 | SINGLE(0) << 2 | ANNOUNCE(1)
        let flags: u8 = 0x01; // HEADER_1, no context, broadcast, single, announce
        let mut raw = Vec::new();
        raw.push(flags);
        raw.push(0x02); // hops
        raw.extend_from_slice(dest_hash);
        raw.push(constants::CONTEXT_NONE);
        raw.extend_from_slice(payload);
        raw
    }

    #[test]
    fn test_path_request_populates_announce_entry_from_raw() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xD5; 16];
        let payload = vec![0xAB; 32]; // simulated announce data (pubkey, sig, etc.)
        let announce_raw = make_announce_raw(&dest, &payload);

        engine.path_table.insert(
            dest,
            PathSet::from_single(
                PathEntry {
                    timestamp: 900.0,
                    next_hop: [0xBB; 16],
                    hops: 2,
                    expires: 9999.0,
                    random_blobs: Vec::new(),
                    receiving_interface: InterfaceId(2),
                    packet_hash: [0; 32],
                    announce_raw: Some(announce_raw.clone()),
                },
                1,
            ),
        );

        let tag = [0x05; 16];
        let data = make_path_request_data(&dest, &tag);
        let _actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        // The announce table should now have an entry with populated packet_raw/packet_data
        let entry = engine
            .announce_table
            .get(&dest)
            .expect("announce entry must exist");
        assert_eq!(entry.packet_raw, announce_raw);
        assert_eq!(entry.packet_data, payload);
        assert!(entry.block_rebroadcasts);
    }

    #[test]
    fn test_path_request_discovers_when_known_path_has_no_announce_raw() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
        engine.register_interface(make_interface(2, constants::MODE_FULL));

        let dest = [0xD6; 16];

        engine.path_table.insert(
            dest,
            PathSet::from_single(
                PathEntry {
                    timestamp: 900.0,
                    next_hop: [0xCC; 16],
                    hops: 1,
                    expires: 9999.0,
                    random_blobs: Vec::new(),
                    receiving_interface: InterfaceId(2),
                    packet_hash: [0; 32],
                    announce_raw: None, // no raw data available
                },
                1,
            ),
        );

        let tag = [0x06; 16];
        let data = make_path_request_data(&dest, &tag);
        let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

        assert!(!engine.announce_table.contains_key(&dest));
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, raw } => {
                assert_eq!(*interface, InterfaceId(2));
                assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
            }
            _ => panic!("expected SendOnInterface for recursive path request"),
        }
        assert!(engine.discovery_path_requests.contains_key(&dest));
    }

    #[test]
    fn test_discovery_request_consumed_on_announce() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));

        let dest = [0xD4; 16];

        // Simulate a waiting discovery request
        engine.discovery_path_requests.insert(
            dest,
            DiscoveryPathRequest {
                timestamp: 900.0,
                requesting_interface: InterfaceId(1),
            },
        );

        // Consume it
        let iface = engine.discovery_path_requests_waiting(&dest);
        assert_eq!(iface, Some(InterfaceId(1)));

        // Should be gone now
        assert!(!engine.discovery_path_requests.contains_key(&dest));
        assert_eq!(engine.discovery_path_requests_waiting(&dest), None);
    }

    #[test]
    fn test_pending_path_request_announce_bypasses_ingress_control() {
        let mut engine = TransportEngine::new(make_config(true));
        let mut inbound = make_interface(1, constants::MODE_FULL);
        inbound.ingress_control = crate::transport::types::IngressControlConfig::enabled();
        inbound.ia_freq = 10_000.0;
        inbound.started = 0.0;
        engine.register_interface(inbound);
        engine.register_interface(make_interface(2, constants::MODE_ACCESS_POINT));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
        let dest_hash = crate::destination::destination_hash(
            "ingress",
            &["path-request"],
            Some(identity.hash()),
        );
        let name_hash = crate::destination::name_hash("ingress", &["path-request"]);
        let announce_raw = build_announce_for_issue4(&dest_hash, &name_hash);

        engine.discovery_path_requests.insert(
            dest_hash,
            DiscoveryPathRequest {
                timestamp: 999.0,
                requesting_interface: InterfaceId(2),
            },
        );

        let mut rng = rns_crypto::FixedRng::new(&[0x88; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &announce_raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        assert_eq!(engine.held_announce_count(&InterfaceId(1)), 0);
        assert!(engine.has_path(&dest_hash));
        assert!(!engine.discovery_path_requests.contains_key(&dest_hash));
        assert!(actions.iter().any(|a| {
            matches!(
                a,
                TransportAction::AnnounceReceived {
                    destination_hash,
                    receiving_interface: InterfaceId(1),
                    ..
                } if *destination_hash == dest_hash
            )
        }));

        let entry = engine
            .announce_table
            .get(&dest_hash)
            .expect("path response announce should be queued");
        assert!(entry.block_rebroadcasts);
        assert_eq!(entry.attached_interface, Some(InterfaceId(2)));
    }

    // =========================================================================
    // Issue #4: Shared instance client 1-hop transport injection
    // =========================================================================

    /// Helper: build a valid announce packet for use in issue #4 tests.
    fn build_announce_for_issue4(dest_hash: &[u8; 16], name_hash: &[u8; 10]) -> Vec<u8> {
        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
        let random_hash = [0x42u8; 10];
        let (announce_data, _) = crate::announce::AnnounceData::pack(
            &identity,
            dest_hash,
            name_hash,
            &random_hash,
            None,
            None,
        )
        .unwrap();
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };
        RawPacket::pack(
            flags,
            0,
            dest_hash,
            None,
            constants::CONTEXT_NONE,
            &announce_data,
        )
        .unwrap()
        .raw
    }

    #[test]
    fn test_ingress_held_announce_preserves_rx_metadata_on_release() {
        let mut engine = TransportEngine::new(make_config(true));
        let mut inbound = make_interface(1, constants::MODE_FULL);
        inbound.ingress_control = crate::transport::types::IngressControlConfig::enabled();
        inbound.ia_freq = constants::IC_BURST_FREQ + 1.0;
        inbound.started = 0.0;
        engine.register_interface(inbound);

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
        let dest_hash =
            crate::destination::destination_hash("ingress", &["rx"], Some(identity.hash()));
        let name_hash = crate::destination::name_hash("ingress", &["rx"]);
        let announce_raw = build_announce_for_issue4(&dest_hash, &name_hash);
        let rx = RxMetadata {
            rssi: Some(-91),
            snr: Some(5.5),
        };

        let mut rng = rns_crypto::FixedRng::new(&[0x88; 32]);
        let held_actions = engine.handle_inbound(
            InboundFrame::new(&announce_raw, InterfaceId(1), 10000.0).with_rx(rx),
            &mut rng,
        );

        assert!(held_actions.is_empty());
        assert_eq!(engine.held_announce_count(&InterfaceId(1)), 1);
        assert!(!engine.has_path(&dest_hash));

        engine
            .interfaces
            .get_mut(&InterfaceId(1))
            .expect("interface must exist")
            .ia_freq = 0.0;

        let released_actions = engine.tick(10000.0 + constants::IC_BURST_PENALTY + 1.0, &mut rng);

        let released_rx = released_actions.iter().find_map(|action| match action {
            TransportAction::AnnounceReceived {
                destination_hash,
                rx: action_rx,
                ..
            } if *destination_hash == dest_hash => Some(*action_rx),
            _ => None,
        });

        assert_eq!(released_rx, Some(rx));
        assert_eq!(engine.held_announce_count(&InterfaceId(1)), 0);
        assert!(engine.has_path(&dest_hash));
    }

    #[test]
    fn test_issue4_local_client_single_data_to_1hop_rewrites_on_outbound() {
        // Shared clients learn remote paths via their local shared-instance
        // interface and must inject transport headers on outbound when the
        // destination is exactly 1 hop away behind the daemon.

        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_local_client_interface(1));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
        let dest_hash =
            crate::destination::destination_hash("issue4", &["test"], Some(identity.hash()));
        let name_hash = crate::destination::name_hash("issue4", &["test"]);
        let announce_raw = build_announce_for_issue4(&dest_hash, &name_hash);

        // Model the announce as already forwarded by the shared daemon to
        // the local client. The raw hop count is 1 so that after the local
        // client hop compensation the learned path remains 1 hop away.
        let mut announce_packet = RawPacket::unpack(&announce_raw).unwrap();
        announce_packet.raw[1] = 1;
        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
        engine.handle_inbound(
            InboundFrame {
                raw: &announce_packet.raw,
                iface: InterfaceId(1),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );
        assert!(engine.has_path(&dest_hash));
        assert_eq!(engine.hops_to(&dest_hash), Some(1));

        // Build DATA from the shared client to the 1-hop destination.
        let data_flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let data_packet = RawPacket::pack(
            data_flags,
            0,
            &dest_hash,
            None,
            constants::CONTEXT_NONE,
            b"hello",
        )
        .unwrap();

        let actions =
            engine.handle_outbound(&data_packet, constants::DESTINATION_SINGLE, None, 1001.0);

        let send = actions.iter().find_map(|a| match a {
            TransportAction::SendOnInterface { interface, raw } => Some((interface, raw)),
            _ => None,
        });
        let (interface, raw) = send.expect("shared client should emit a transport-injected packet");
        assert_eq!(*interface, InterfaceId(1));
        let flags = PacketFlags::unpack(raw[0]);
        assert_eq!(flags.header_type, constants::HEADER_2);
        assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
    }

    #[test]
    fn test_issue4_external_data_to_shared_client_strips_transport_header() {
        let daemon_id = [0x42; 16];
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_local_client_interface(2));

        let dest_hash = [0x99; 16];
        engine.upsert_path_destination(
            dest_hash,
            make_path_entry(1000.0, 1, InterfaceId(2), daemon_id),
            1000.0,
        );

        let h2_flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let mut h2_raw = Vec::new();
        h2_raw.push(h2_flags.pack());
        h2_raw.push(0);
        h2_raw.extend_from_slice(&daemon_id);
        h2_raw.extend_from_slice(&dest_hash);
        h2_raw.push(constants::CONTEXT_NONE);
        h2_raw.extend_from_slice(b"hello shared client");

        let mut rng = rns_crypto::FixedRng::new(&[0x22; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &h2_raw,
                iface: InterfaceId(1),
                now: 1001.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );

        let raw = actions.iter().find_map(|a| match a {
            TransportAction::SendOnInterface { interface, raw } if *interface == InterfaceId(2) => {
                Some(raw)
            }
            _ => None,
        });
        let raw = raw.expect("daemon should forward external DATA to shared client");
        let flags = PacketFlags::unpack(raw[0]);
        assert_eq!(flags.header_type, constants::HEADER_1);
        assert_eq!(flags.transport_type, constants::TRANSPORT_BROADCAST);
        assert_eq!(&raw[2..18], &dest_hash);
        assert_eq!(&raw[19..], b"hello shared client");
    }

    #[test]
    fn test_issue4_external_data_to_1hop_via_transport_works() {
        // Control test: when a DATA packet arrives from an external interface
        // with HEADER_2 and the daemon's transport_id, the daemon correctly
        // forwards it via step 5.  This proves the multi-hop path works;
        // it's only the 1-hop shared-client case that's broken.

        let daemon_id = [0x42; 16];
        let mut engine = TransportEngine::new(TransportConfig {
            transport_enabled: true,
            identity_hash: Some(daemon_id),
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        });
        engine.register_interface(make_interface(1, constants::MODE_FULL)); // inbound
        engine.register_interface(make_interface(2, constants::MODE_FULL)); // outbound to Bob

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
        let dest_hash =
            crate::destination::destination_hash("issue4", &["ctrl"], Some(identity.hash()));
        let name_hash = crate::destination::name_hash("issue4", &["ctrl"]);
        let announce_raw = build_announce_for_issue4(&dest_hash, &name_hash);

        // Feed announce from interface 2 (Bob's side), hops=0 → stored as hops=1
        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
        engine.handle_inbound(
            InboundFrame {
                raw: &announce_raw,
                iface: InterfaceId(2),
                now: 1000.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng,
        );
        assert_eq!(engine.hops_to(&dest_hash), Some(1));

        // Now send a HEADER_2 transport packet addressed to the daemon
        // (simulating what Alice would send in a multi-hop scenario)
        let h2_flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        // Build HEADER_2 manually: [flags, hops, transport_id(16), dest_hash(16), context, data...]
        let mut h2_raw = Vec::new();
        h2_raw.push(h2_flags.pack());
        h2_raw.push(0); // hops
        h2_raw.extend_from_slice(&daemon_id); // transport_id = daemon
        h2_raw.extend_from_slice(&dest_hash);
        h2_raw.push(constants::CONTEXT_NONE);
        h2_raw.extend_from_slice(b"hello via transport");

        let mut rng2 = rns_crypto::FixedRng::new(&[0x22; 32]);
        let actions = engine.handle_inbound(
            InboundFrame {
                raw: &h2_raw,
                iface: InterfaceId(1),
                now: 1001.0,
                rx: RxMetadata {
                    rssi: None,
                    snr: None,
                },
            },
            &mut rng2,
        );

        // This SHOULD forward via step 5 (transport forwarding)
        let has_send = actions.iter().any(|a| {
            matches!(
                a,
                TransportAction::SendOnInterface { interface, .. } if *interface == InterfaceId(2)
            )
        });
        assert!(
            has_send,
            "HEADER_2 transport packet should be forwarded (control test)"
        );
    }
}
