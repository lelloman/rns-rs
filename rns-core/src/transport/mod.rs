pub mod announce_proc;
pub mod announce_queue;
pub mod dedup;
pub mod inbound;
pub mod ingress_control;
pub mod jobs;
pub mod outbound;
pub mod pathfinder;
pub mod rate_limit;
pub mod tables;
pub mod tunnel;
pub mod types;

use alloc::collections::BTreeMap;
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
use self::dedup::{AnnounceSignatureCache, PacketHashlist};
use self::inbound::{
    create_link_entry, create_reverse_entry, forward_transport_packet, route_proof_via_reverse,
    route_via_link_table,
};
use self::ingress_control::IngressControl;
use self::outbound::{route_outbound, should_transmit_announce};
use self::pathfinder::{
    decide_announce_multipath, extract_random_blob, timebase_from_random_blob, MultiPathDecision,
};
use self::rate_limit::AnnounceRateLimiter;
use self::tables::{AnnounceEntry, DiscoveryPathRequest, LinkEntry, PathEntry, PathSet};
use self::tunnel::TunnelTable;
use self::types::{BlackholeEntry, InterfaceId, InterfaceInfo, TransportAction, TransportConfig};

pub type PathTableRow = ([u8; 16], f64, [u8; 16], u8, f64, String);
pub type RateTableRow = ([u8; 16], f64, u32, f64, Vec<f64>);

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
    discovery_pr_tags: Vec<[u8; 32]>,
    discovery_path_requests: BTreeMap<[u8; 16], DiscoveryPathRequest>,
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
            announce_queues: AnnounceQueues::new(),
            ingress_control: IngressControl::new(),
            tunnel_table: TunnelTable::new(),
            discovery_pr_tags: Vec::new(),
            discovery_path_requests: BTreeMap::new(),
            announces_last_checked: 0.0,
            tables_last_culled: 0.0,
        }
    }

    fn insert_discovery_pr_tag(&mut self, unique_tag: [u8; 32]) -> bool {
        if self.discovery_pr_tags.contains(&unique_tag) {
            return false;
        }
        if self.config.max_discovery_pr_tags != usize::MAX
            && self.discovery_pr_tags.len() >= self.config.max_discovery_pr_tags
            && !self.discovery_pr_tags.is_empty()
        {
            self.discovery_pr_tags.remove(0);
        }
        self.discovery_pr_tags.push(unique_tag);
        true
    }

    fn upsert_path_destination(&mut self, dest_hash: [u8; 16], entry: PathEntry, now: f64) {
        let max_paths = self.config.max_paths_per_destination;
        if let Some(ps) = self.path_table.get_mut(&dest_hash) {
            ps.upsert(entry);
            return;
        }
        self.enforce_path_destination_cap(now);
        self.path_table
            .insert(dest_hash, PathSet::from_single(entry, max_paths));
    }

    fn enforce_path_destination_cap(&mut self, now: f64) {
        if self.config.max_path_destinations == usize::MAX {
            return;
        }
        jobs::cull_path_table(&mut self.path_table, &self.interfaces, now);
        while self.path_table.len() >= self.config.max_path_destinations {
            let Some(dest_hash) = self.oldest_path_destination() else {
                break;
            };
            self.path_table.remove(&dest_hash);
            self.path_states.remove(&dest_hash);
        }
    }

    fn oldest_path_destination(&self) -> Option<[u8; 16]> {
        self.path_table
            .iter()
            .filter_map(|(dest_hash, path_set)| {
                path_set
                    .primary()
                    .map(|primary| (*dest_hash, primary.timestamp, primary.hops))
            })
            .min_by(|a, b| {
                a.1.partial_cmp(&b.1)
                    .unwrap_or(core::cmp::Ordering::Equal)
                    .then_with(|| b.2.cmp(&a.2))
            })
            .map(|(dest_hash, _, _)| dest_hash)
    }

    fn announce_entry_size_bytes(entry: &AnnounceEntry) -> usize {
        size_of::<AnnounceEntry>()
            + entry.packet_raw.capacity()
            + entry.packet_data.capacity()
    }

    fn announce_retained_bytes_total(&self) -> usize {
        self.announce_table
            .values()
            .chain(self.held_announces.values())
            .map(Self::announce_entry_size_bytes)
            .sum()
    }

    fn cull_expired_announce_entries(&mut self, now: f64) -> usize {
        let ttl = self.config.announce_table_ttl_secs;
        let mut removed = 0usize;

        self.announce_table.retain(|_, entry| {
            let keep = now <= entry.timestamp + ttl;
            if !keep {
                removed += 1;
            }
            keep
        });

        self.held_announces.retain(|_, entry| {
            let keep = now <= entry.timestamp + ttl;
            if !keep {
                removed += 1;
            }
            keep
        });

        removed
    }

    fn oldest_retained_announce(&self) -> Option<([u8; 16], bool)> {
        let oldest_active = self
            .announce_table
            .iter()
            .map(|(dest_hash, entry)| (*dest_hash, false, entry.timestamp))
            .min_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(core::cmp::Ordering::Equal));
        let oldest_held = self
            .held_announces
            .iter()
            .map(|(dest_hash, entry)| (*dest_hash, true, entry.timestamp))
            .min_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(core::cmp::Ordering::Equal));

        match (oldest_active, oldest_held) {
            (Some(active), Some(held)) => {
                let ordering = active
                    .2
                    .partial_cmp(&held.2)
                    .unwrap_or(core::cmp::Ordering::Equal);
                if ordering == core::cmp::Ordering::Less {
                    Some((active.0, active.1))
                } else {
                    Some((held.0, held.1))
                }
            }
            (Some(active), None) => Some((active.0, active.1)),
            (None, Some(held)) => Some((held.0, held.1)),
            (None, None) => None,
        }
    }

    fn enforce_announce_retention_cap(&mut self, now: f64) {
        self.cull_expired_announce_entries(now);
        while self.announce_retained_bytes_total() > self.config.announce_table_max_bytes {
            let Some((dest_hash, is_held)) = self.oldest_retained_announce() else {
                break;
            };
            if is_held {
                self.held_announces.remove(&dest_hash);
            } else {
                self.announce_table.remove(&dest_hash);
            }
        }
    }

    fn insert_announce_entry(&mut self, dest_hash: [u8; 16], entry: AnnounceEntry, now: f64) -> bool {
        self.cull_expired_announce_entries(now);
        if Self::announce_entry_size_bytes(&entry) > self.config.announce_table_max_bytes {
            return false;
        }
        self.announce_table.insert(dest_hash, entry);
        self.enforce_announce_retention_cap(now);
        self.announce_table.contains_key(&dest_hash)
    }

    fn insert_held_announce(&mut self, dest_hash: [u8; 16], entry: AnnounceEntry, now: f64) -> bool {
        self.cull_expired_announce_entries(now);
        if Self::announce_entry_size_bytes(&entry) > self.config.announce_table_max_bytes {
            return false;
        }
        self.held_announces.insert(dest_hash, entry);
        self.enforce_announce_retention_cap(now);
        self.held_announces.contains_key(&dest_hash)
    }

    // =========================================================================
    // Interface management
    // =========================================================================

    pub fn register_interface(&mut self, info: InterfaceInfo) {
        self.interfaces.insert(info.id, info);
    }

    pub fn deregister_interface(&mut self, id: InterfaceId) {
        self.interfaces.remove(&id);
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
                    // Restore if fewer hops or existing expired
                    tunnel_path.hops <= existing.hops || existing.expires < now
                }
                None => true,
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
                // Can't synthesize — no private key or other error
                let _ = e;
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
        raw: &[u8],
        iface: InterfaceId,
        now: f64,
        rng: &mut dyn Rng,
    ) -> Vec<TransportAction> {
        let mut actions = Vec::new();

        // 1. Unpack
        let mut packet = match RawPacket::unpack(raw) {
            Ok(p) => p,
            Err(_) => return actions, // silent drop
        };

        // Save original raw (pre-hop-increment) for announce caching
        let original_raw = raw.to_vec();

        // 2. Increment hops
        packet.hops += 1;

        // 2a. If from a local client, decrement hops to cancel the +1
        // (local clients are attached via shared instance, not a real hop)
        let from_local_client = self
            .interfaces
            .get(&iface)
            .map(|i| i.is_local_client)
            .unwrap_or(false);
        if from_local_client {
            packet.hops = packet.hops.saturating_sub(1);
        }

        // 3. Packet filter
        if !self.packet_filter(&packet) {
            return actions;
        }

        // 4. Determine whether to add to hashlist now or defer
        let mut remember_hash = true;

        if self.link_table.contains_key(&packet.destination_hash) {
            remember_hash = false;
        }
        if packet.flags.packet_type == constants::PACKET_TYPE_PROOF
            && packet.context == constants::CONTEXT_LRPROOF
        {
            remember_hash = false;
        }

        if remember_hash {
            self.packet_hashlist.add(packet.packet_hash);
        }

        // 4a. PLAIN broadcast bridging between local clients and external interfaces
        if packet.flags.destination_type == constants::DESTINATION_PLAIN
            && packet.flags.transport_type == constants::TRANSPORT_BROADCAST
            && self.has_local_clients()
        {
            if from_local_client {
                // From local client → forward to all external interfaces
                actions.push(TransportAction::ForwardPlainBroadcast {
                    raw: packet.raw.clone(),
                    to_local: false,
                    exclude: Some(iface),
                });
            } else {
                // From external → forward to all local clients
                actions.push(TransportAction::ForwardPlainBroadcast {
                    raw: packet.raw.clone(),
                    to_local: true,
                    exclude: None,
                });
            }
        }

        // 5. Transport forwarding: if we are the designated next hop
        if self.config.transport_enabled || self.config.identity_hash.is_some() {
            if packet.transport_id.is_some()
                && packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE
            {
                if let Some(ref identity_hash) = self.config.identity_hash {
                    if packet.transport_id.as_ref() == Some(identity_hash) {
                        if let Some(path_entry) = self
                            .path_table
                            .get(&packet.destination_hash)
                            .and_then(|ps| ps.primary())
                        {
                            let next_hop = path_entry.next_hop;
                            let remaining_hops = path_entry.hops;
                            let outbound_interface = path_entry.receiving_interface;

                            let new_raw = forward_transport_packet(
                                &packet,
                                next_hop,
                                remaining_hops,
                                outbound_interface,
                            );

                            // Create link table or reverse table entry
                            if packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST {
                                let proof_timeout = now
                                    + constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP
                                        * (remaining_hops.max(1) as f64);

                                let (link_id, link_entry) = create_link_entry(
                                    &packet,
                                    next_hop,
                                    outbound_interface,
                                    remaining_hops,
                                    iface,
                                    now,
                                    proof_timeout,
                                );
                                self.link_table.insert(link_id, link_entry);
                                actions.push(TransportAction::LinkRequestReceived {
                                    link_id,
                                    destination_hash: packet.destination_hash,
                                    receiving_interface: iface,
                                });
                            } else {
                                let (trunc_hash, reverse_entry) =
                                    create_reverse_entry(&packet, outbound_interface, iface, now);
                                self.reverse_table.insert(trunc_hash, reverse_entry);
                            }

                            actions.push(TransportAction::SendOnInterface {
                                interface: outbound_interface,
                                raw: new_raw,
                            });

                            // Update path timestamp
                            if let Some(entry) = self
                                .path_table
                                .get_mut(&packet.destination_hash)
                                .and_then(|ps| ps.primary_mut())
                            {
                                entry.timestamp = now;
                            }
                        }
                    }
                }
            }

            // 6. Link table routing for non-announce, non-linkrequest, non-lrproof
            if packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE
                && packet.flags.packet_type != constants::PACKET_TYPE_LINKREQUEST
                && packet.context != constants::CONTEXT_LRPROOF
            {
                if let Some(link_entry) = self.link_table.get(&packet.destination_hash).cloned() {
                    if let Some((outbound_iface, new_raw)) =
                        route_via_link_table(&packet, &link_entry, iface)
                    {
                        // Add to hashlist now that we know it's for us
                        self.packet_hashlist.add(packet.packet_hash);

                        actions.push(TransportAction::SendOnInterface {
                            interface: outbound_iface,
                            raw: new_raw,
                        });

                        // Update link timestamp
                        if let Some(entry) = self.link_table.get_mut(&packet.destination_hash) {
                            entry.timestamp = now;
                        }
                    }
                }
            }
        }

        // 7. Announce handling
        if packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE {
            self.process_inbound_announce(&packet, &original_raw, iface, now, rng, &mut actions);
        }

        // 8. Proof handling
        if packet.flags.packet_type == constants::PACKET_TYPE_PROOF {
            self.process_inbound_proof(&packet, iface, now, &mut actions);
        }

        // 9. Local delivery for LINKREQUEST and DATA
        if (packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
            || packet.flags.packet_type == constants::PACKET_TYPE_DATA)
            && self
                .local_destinations
                .contains_key(&packet.destination_hash)
        {
            actions.push(TransportAction::DeliverLocal {
                destination_hash: packet.destination_hash,
                raw: packet.raw.clone(),
                packet_hash: packet.packet_hash,
                receiving_interface: iface,
            });
        }

        actions
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

        let sig_cache_key = {
            let mut material = [0u8; 80]; // 16 + 64
            material[..16].copy_from_slice(&packet.destination_hash);
            material[16..].copy_from_slice(&announce.signature);
            hash::full_hash(&material)
        };

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

        // Skip blackholed identities
        if self.is_blackholed(&validated.identity_hash, now) {
            return;
        }

        // Skip local destinations
        if self
            .local_destinations
            .contains_key(&packet.destination_hash)
        {
            log::debug!(
                "Announce:skipping local destination {:02x}{:02x}{:02x}{:02x}..",
                packet.destination_hash[0],
                packet.destination_hash[1],
                packet.destination_hash[2],
                packet.destination_hash[3],
            );
            return;
        }

        // Ingress control: hold announces from unknown destinations during bursts
        if !self.has_path(&packet.destination_hash) {
            if let Some(info) = self.interfaces.get(&iface) {
                if packet.context != constants::CONTEXT_PATH_RESPONSE
                    && info.ingress_control
                    && self.ingress_control.should_ingress_limit(
                        iface,
                        info.ia_freq,
                        info.started,
                        now,
                    )
                {
                    self.ingress_control.hold_announce(
                        iface,
                        packet.destination_hash,
                        ingress_control::HeldAnnounce {
                            raw: original_raw.to_vec(),
                            hops: packet.hops,
                            receiving_interface: iface,
                            timestamp: now,
                        },
                    );
                    return;
                }
            }
        }

        // Detect retransmit completion
        let received_from = if let Some(transport_id) = packet.transport_id {
            // Check if this is a retransmit we can stop
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
                    // Check if our retransmit was passed on
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
        };

        // Extract random blob
        let random_blob = match extract_random_blob(&packet.data) {
            Some(b) => b,
            None => return,
        };

        // Check hop limit
        if packet.hops > constants::PATHFINDER_M {
            return;
        }

        let announce_emitted = timebase_from_random_blob(&random_blob);

        // Multi-path aware decision
        let existing_set = self.path_table.get(&packet.destination_hash);
        let is_unresponsive = self.path_is_unresponsive(&packet.destination_hash);

        let mp_decision = decide_announce_multipath(
            existing_set,
            packet.hops,
            announce_emitted,
            &random_blob,
            &received_from,
            is_unresponsive,
            now,
            self.config.prefer_shorter_path,
        );

        if mp_decision == MultiPathDecision::Reject {
            log::debug!(
                "Announce:path decision REJECT for dest={:02x}{:02x}{:02x}{:02x}..",
                packet.destination_hash[0],
                packet.destination_hash[1],
                packet.destination_hash[2],
                packet.destination_hash[3],
            );
            return;
        }

        // Rate limiting
        let rate_blocked = if packet.context != constants::CONTEXT_PATH_RESPONSE {
            if let Some(iface_info) = self.interfaces.get(&iface) {
                self.rate_limiter.check_and_update(
                    &packet.destination_hash,
                    now,
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
            .get(&iface)
            .map(|i| i.mode)
            .unwrap_or(constants::MODE_FULL);

        let expires = compute_path_expires(now, interface_mode);

        // Get existing random blobs from the matching path (same next_hop) or empty
        let existing_blobs = self
            .path_table
            .get(&packet.destination_hash)
            .and_then(|ps| ps.find_by_next_hop(&received_from))
            .map(|e| e.random_blobs.clone())
            .unwrap_or_default();

        // Generate RNG value for retransmit timeout
        let mut rng_bytes = [0u8; 8];
        rng.fill_bytes(&mut rng_bytes);
        let rng_value = (u64::from_le_bytes(rng_bytes) as f64) / (u64::MAX as f64);

        let is_path_response = packet.context == constants::CONTEXT_PATH_RESPONSE;

        let (path_entry, announce_entry) = announce_proc::process_validated_announce(
            packet.destination_hash,
            packet.hops,
            &packet.data,
            &packet.raw,
            packet.packet_hash,
            packet.flags.context_flag,
            received_from,
            iface,
            now,
            existing_blobs,
            random_blob,
            expires,
            rng_value,
            self.config.transport_enabled,
            is_path_response,
            rate_blocked,
            Some(original_raw.to_vec()),
        );

        // Emit CacheAnnounce for disk caching (pre-hop-increment raw)
        actions.push(TransportAction::CacheAnnounce {
            packet_hash: packet.packet_hash,
            raw: original_raw.to_vec(),
        });

        // Store path via upsert into PathSet
        self.upsert_path_destination(packet.destination_hash, path_entry, now);

        // If receiving interface has a tunnel_id, store path in tunnel table too
        if let Some(tunnel_id) = self.interfaces.get(&iface).and_then(|i| i.tunnel_id) {
            let blobs = self
                .path_table
                .get(&packet.destination_hash)
                .and_then(|ps| ps.find_by_next_hop(&received_from))
                .map(|e| e.random_blobs.clone())
                .unwrap_or_default();
            self.tunnel_table.store_tunnel_path(
                &tunnel_id,
                packet.destination_hash,
                tunnel::TunnelPath {
                    timestamp: now,
                    received_from,
                    hops: packet.hops,
                    expires,
                    random_blobs: blobs,
                    packet_hash: packet.packet_hash,
                },
                now,
                self.config.destination_timeout_secs,
                self.config.max_tunnel_destinations_total,
            );
        }

        // Mark path as unknown state on update
        self.path_states.remove(&packet.destination_hash);

        // Store announce for retransmission
        if let Some(ann) = announce_entry {
            self.insert_announce_entry(packet.destination_hash, ann, now);
        }

        // Emit actions
        actions.push(TransportAction::AnnounceReceived {
            destination_hash: packet.destination_hash,
            identity_hash: validated.identity_hash,
            public_key: validated.public_key,
            name_hash: validated.name_hash,
            random_hash: validated.random_hash,
            app_data: validated.app_data,
            hops: packet.hops,
            receiving_interface: iface,
        });

        actions.push(TransportAction::PathUpdated {
            destination_hash: packet.destination_hash,
            hops: packet.hops,
            next_hop: received_from,
            interface: iface,
        });

        // Forward announce to local clients if any are connected
        if self.has_local_clients() {
            actions.push(TransportAction::ForwardToLocalClients {
                raw: packet.raw.clone(),
                exclude: Some(iface),
            });
        }

        // Check for discovery path requests waiting for this announce
        if let Some(pr_entry) = self.discovery_path_requests_waiting(&packet.destination_hash) {
            // Build a path response announce and queue it
            let entry = AnnounceEntry {
                timestamp: now,
                retransmit_timeout: now,
                retries: constants::PATHFINDER_R,
                received_from,
                hops: packet.hops,
                packet_raw: packet.raw.clone(),
                packet_data: packet.data.clone(),
                destination_hash: packet.destination_hash,
                context_flag: packet.flags.context_flag,
                local_rebroadcasts: 0,
                block_rebroadcasts: true,
                attached_interface: Some(pr_entry),
            };
            self.insert_announce_entry(packet.destination_hash, entry, now);
        }
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
                    if packet.hops == entry.remaining_hops && iface == entry.next_hop_interface {
                        // Forward the proof (simplified: skip signature validation
                        // which requires Identity recall)
                        let mut new_raw = Vec::new();
                        new_raw.push(packet.raw[0]);
                        new_raw.push(packet.hops);
                        new_raw.extend_from_slice(&packet.raw[2..]);

                        // Mark link as validated
                        if let Some(le) = self.link_table.get_mut(&packet.destination_hash) {
                            le.validated = true;
                        }

                        actions.push(TransportAction::LinkEstablished {
                            link_id: packet.destination_hash,
                            interface: entry.received_interface,
                        });

                        actions.push(TransportAction::SendOnInterface {
                            interface: entry.received_interface,
                            raw: new_raw,
                        });
                    }
                }
            } else {
                // Could be for a local pending link - deliver locally
                actions.push(TransportAction::DeliverLocal {
                    destination_hash: packet.destination_hash,
                    raw: packet.raw.clone(),
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
                raw: packet.raw.clone(),
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
                    let (bitrate, announce_cap) =
                        if let Some(info) = self.interfaces.get(&interface) {
                            (info.bitrate, info.announce_cap)
                        } else {
                            (None, constants::ANNOUNCE_CAP)
                        };
                    if let Some(send_action) = self.announce_queues.gate_announce(
                        interface,
                        raw,
                        *dest_hash,
                        hops,
                        now,
                        now,
                        bitrate,
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
        let mut actions = Vec::new();

        // Process pending announces
        if now > self.announces_last_checked + constants::ANNOUNCES_CHECK_INTERVAL {
            self.cull_expired_announce_entries(now);
            self.enforce_announce_retention_cap(now);
            if let Some(ref identity_hash) = self.config.identity_hash {
                let ih = *identity_hash;
                let announce_actions = jobs::process_pending_announces(
                    &mut self.announce_table,
                    &mut self.held_announces,
                    &ih,
                    now,
                );
                // Gate retransmitted announces through bandwidth queues
                let gated = self.gate_retransmit_actions(announce_actions, now);
                actions.extend(gated);
            }
            self.cull_expired_announce_entries(now);
            self.enforce_announce_retention_cap(now);
            self.announces_last_checked = now;
        }

        // Process announce queues — dequeue waiting announces when bandwidth available
        let mut queue_actions = self.announce_queues.process_queues(now, &self.interfaces);
        actions.append(&mut queue_actions);

        // Process ingress control: release held announces
        let ic_interfaces = self.ingress_control.interfaces_with_held();
        for iface_id in ic_interfaces {
            let (ia_freq, started, ic_enabled) = match self.interfaces.get(&iface_id) {
                Some(info) => (info.ia_freq, info.started, info.ingress_control),
                None => continue,
            };
            if !ic_enabled {
                continue;
            }
            if let Some(held) = self
                .ingress_control
                .process_held_announces(iface_id, ia_freq, started, now)
            {
                let released_actions =
                    self.handle_inbound(&held.raw, held.receiving_interface, now, rng);
                actions.extend(released_actions);
            }
        }

        // Cull tables
        if now > self.tables_last_culled + constants::TABLES_CULL_INTERVAL {
            jobs::cull_path_table(&mut self.path_table, &self.interfaces, now);
            jobs::cull_reverse_table(&mut self.reverse_table, &self.interfaces, now);
            let (_culled, link_closed_actions) =
                jobs::cull_link_table(&mut self.link_table, &self.interfaces, now);
            actions.extend(link_closed_actions);
            jobs::cull_path_states(&mut self.path_states, &self.path_table);
            self.cull_blackholed(now);
            // Cull expired discovery path requests
            self.discovery_path_requests
                .retain(|_, req| now - req.timestamp < constants::DISCOVERY_PATH_REQUEST_TIMEOUT);
            // Cull tunnels: void missing interfaces, then remove expired
            self.tunnel_table
                .void_missing_interfaces(|id| self.interfaces.contains_key(id));
            self.tunnel_table.cull(now);
            self.announce_sig_cache.cull(now);
            self.tables_last_culled = now;
        }

        actions
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
                    let (bitrate, announce_cap) =
                        if let Some(info) = self.interfaces.get(&interface) {
                            (info.bitrate, info.announce_cap)
                        } else {
                            (None, constants::ANNOUNCE_CAP)
                        };
                    if let Some(send_action) = self.announce_queues.gate_announce(
                        interface,
                        raw,
                        dest_hash,
                        hops,
                        now,
                        now,
                        bitrate,
                        announce_cap,
                    ) {
                        result.push(send_action);
                    }
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    let (dest_hash, hops) = Self::extract_announce_info(&raw);
                    // Expand to per-interface sends gated through queues,
                    // applying mode filtering (AP blocks non-local announces, etc.)
                    let iface_ids: Vec<(InterfaceId, Option<u64>, f64)> = self
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
                        .map(|(id, info)| (*id, info.bitrate, info.announce_cap))
                        .collect();

                    for (iface_id, bitrate, announce_cap) in iface_ids {
                        if let Some(send_action) = self.announce_queues.gate_announce(
                            iface_id,
                            raw.clone(),
                            dest_hash,
                            hops,
                            now,
                            now,
                            bitrate,
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

    // =========================================================================
    // Path request handling
    // =========================================================================

    /// Handle an incoming path request.
    ///
    /// Transport.py path_request_handler (~line 2700):
    /// - Dedup via unique tag
    /// - If local destination, caller handles announce
    /// - If path known and transport enabled, queue retransmit (with ROAMING loop prevention)
    /// - If path unknown and receiving interface is in DISCOVER_PATHS_FOR, store a
    ///   DiscoveryPathRequest and forward the raw path request on other OUT interfaces
    pub fn handle_path_request(
        &mut self,
        data: &[u8],
        interface_id: InterfaceId,
        now: f64,
    ) -> Vec<TransportAction> {
        let mut actions = Vec::new();

        if data.len() < 16 {
            return actions;
        }

        let mut destination_hash = [0u8; 16];
        destination_hash.copy_from_slice(&data[..16]);

        // Extract requesting transport instance
        let _requesting_transport_id = if data.len() > 32 {
            let mut id = [0u8; 16];
            id.copy_from_slice(&data[16..32]);
            Some(id)
        } else {
            None
        };

        // Extract tag
        let tag_bytes = if data.len() > 32 {
            Some(&data[32..])
        } else if data.len() > 16 {
            Some(&data[16..])
        } else {
            None
        };

        if let Some(tag) = tag_bytes {
            let tag_len = tag.len().min(16);
            let mut unique_tag = [0u8; 32];
            unique_tag[..16].copy_from_slice(&destination_hash);
            unique_tag[16..16 + tag_len].copy_from_slice(&tag[..tag_len]);

            if !self.insert_discovery_pr_tag(unique_tag) {
                return actions; // Duplicate tag
            }
        } else {
            return actions; // Tagless request
        }

        // If destination is local, the caller should handle the announce
        if self.local_destinations.contains_key(&destination_hash) {
            return actions;
        }

        // If we know the path and transport is enabled, queue retransmit
        if self.config.transport_enabled && self.has_path(&destination_hash) {
            let path = self
                .path_table
                .get(&destination_hash)
                .unwrap()
                .primary()
                .unwrap()
                .clone();

            // ROAMING loop prevention (Python Transport.py:2731-2732):
            // If the receiving interface is ROAMING and the known path's next-hop
            // is on the same interface, don't answer — it would loop.
            if let Some(recv_info) = self.interfaces.get(&interface_id) {
                if recv_info.mode == constants::MODE_ROAMING
                    && path.receiving_interface == interface_id
                {
                    return actions;
                }
            }

            // We need the original announce raw bytes to build a valid retransmit.
            // Without them we can't populate packet_raw/packet_data and the response
            // would be a header-only packet that Python RNS discards.
            if let Some(ref raw) = path.announce_raw {
                // Check if there's already an announce in the table
                if let Some(existing) = self.announce_table.remove(&destination_hash) {
                    self.insert_held_announce(destination_hash, existing, now);
                }
                let retransmit_timeout =
                    if let Some(iface_info) = self.interfaces.get(&interface_id) {
                        let base = now + constants::PATH_REQUEST_GRACE;
                        if iface_info.mode == constants::MODE_ROAMING {
                            base + constants::PATH_REQUEST_RG
                        } else {
                            base
                        }
                    } else {
                        now + constants::PATH_REQUEST_GRACE
                    };

                let (packet_data, context_flag) = match RawPacket::unpack(raw) {
                    Ok(parsed) => (parsed.data, parsed.flags.context_flag),
                    Err(_) => {
                        return actions;
                    }
                };

                let entry = AnnounceEntry {
                    timestamp: now,
                    retransmit_timeout,
                    retries: constants::PATHFINDER_R,
                    received_from: path.next_hop,
                    hops: path.hops,
                    packet_raw: raw.clone(),
                    packet_data,
                    destination_hash,
                    context_flag,
                    local_rebroadcasts: 0,
                    block_rebroadcasts: true,
                    attached_interface: Some(interface_id),
                };

                self.insert_announce_entry(destination_hash, entry, now);
            }
        } else if self.config.transport_enabled {
            // Unknown path: check if receiving interface is in DISCOVER_PATHS_FOR
            let should_discover = self
                .interfaces
                .get(&interface_id)
                .map(|info| constants::DISCOVER_PATHS_FOR.contains(&info.mode))
                .unwrap_or(false);

            if should_discover {
                // Store discovery request so we can respond when the announce arrives
                self.discovery_path_requests.insert(
                    destination_hash,
                    DiscoveryPathRequest {
                        timestamp: now,
                        requesting_interface: interface_id,
                    },
                );

                // Forward the raw path request data on all other OUT-capable interfaces
                for (_, iface_info) in self.interfaces.iter() {
                    if iface_info.id != interface_id && iface_info.out_capable {
                        actions.push(TransportAction::SendOnInterface {
                            interface: iface_info.id,
                            raw: data.to_vec(),
                        });
                    }
                }
            }
        }

        actions
    }

    // =========================================================================
    // Public read accessors
    // =========================================================================

    /// Iterate over primary path entries (one per destination).
    pub fn path_table_entries(&self) -> impl Iterator<Item = (&[u8; 16], &PathEntry)> {
        self.path_table
            .iter()
            .filter_map(|(k, ps)| ps.primary().map(|e| (k, e)))
    }

    /// Iterate over all path sets (exposing alternatives).
    pub fn path_table_sets(&self) -> impl Iterator<Item = (&[u8; 16], &PathSet)> {
        self.path_table.iter()
    }

    /// Number of registered interfaces.
    pub fn interface_count(&self) -> usize {
        self.interfaces.len()
    }

    /// Number of link table entries.
    pub fn link_table_count(&self) -> usize {
        self.link_table.len()
    }

    /// Number of path table entries.
    pub fn path_table_count(&self) -> usize {
        self.path_table.len()
    }

    /// Number of announce table entries.
    pub fn announce_table_count(&self) -> usize {
        self.announce_table.len()
    }

    /// Number of reverse table entries.
    pub fn reverse_table_count(&self) -> usize {
        self.reverse_table.len()
    }

    /// Number of held announces.
    pub fn held_announces_count(&self) -> usize {
        self.held_announces.len()
    }

    /// Number of entries in the packet hashlist.
    pub fn packet_hashlist_len(&self) -> usize {
        self.packet_hashlist.len()
    }

    /// Number of entries in the announce signature verification cache.
    pub fn announce_sig_cache_len(&self) -> usize {
        self.announce_sig_cache.len()
    }

    /// Number of entries in the rate limiter.
    pub fn rate_limiter_count(&self) -> usize {
        self.rate_limiter.len()
    }

    /// Number of blackholed identities.
    pub fn blackholed_count(&self) -> usize {
        self.blackholed_identities.len()
    }

    /// Number of tunnel table entries.
    pub fn tunnel_count(&self) -> usize {
        self.tunnel_table.len()
    }

    /// Number of discovery PR tags.
    pub fn discovery_pr_tags_count(&self) -> usize {
        self.discovery_pr_tags.len()
    }

    /// Number of discovery path requests.
    pub fn discovery_path_requests_count(&self) -> usize {
        self.discovery_path_requests.len()
    }

    /// Number of local destinations.
    pub fn local_destinations_count(&self) -> usize {
        self.local_destinations.len()
    }

    /// Access the rate limiter for reading rate table entries.
    pub fn rate_limiter(&self) -> &AnnounceRateLimiter {
        &self.rate_limiter
    }

    /// Get interface info by id.
    pub fn interface_info(&self, id: &InterfaceId) -> Option<&InterfaceInfo> {
        self.interfaces.get(id)
    }

    /// Redirect a path entry to a different interface (e.g. after direct connect).
    /// If no entry exists, creates a minimal direct path (hops=1).
    pub fn redirect_path(&mut self, dest_hash: &[u8; 16], interface: InterfaceId, now: f64) {
        if let Some(entry) = self
            .path_table
            .get_mut(dest_hash)
            .and_then(|ps| ps.primary_mut())
        {
            entry.receiving_interface = interface;
            entry.hops = 1;
        } else {
            self.upsert_path_destination(
                *dest_hash,
                PathEntry {
                    timestamp: now,
                    next_hop: [0u8; 16],
                    hops: 1,
                    expires: now + 3600.0,
                    random_blobs: Vec::new(),
                    receiving_interface: interface,
                    packet_hash: [0u8; 32],
                    announce_raw: None,
                },
                now,
            );
        }
    }

    /// Inject a path entry directly into the path table (full override).
    pub fn inject_path(&mut self, dest_hash: [u8; 16], entry: PathEntry) {
        self.upsert_path_destination(dest_hash, entry.clone(), entry.timestamp);
    }

    /// Drop a path from the path table.
    pub fn drop_path(&mut self, dest_hash: &[u8; 16]) -> bool {
        self.path_table.remove(dest_hash).is_some()
    }

    /// Drop all paths that route via a given transport hash.
    ///
    /// Removes matching individual paths from each PathSet, then removes
    /// any PathSets that become empty.
    pub fn drop_all_via(&mut self, transport_hash: &[u8; 16]) -> usize {
        let mut removed = 0usize;
        for ps in self.path_table.values_mut() {
            let before = ps.len();
            ps.retain(|entry| &entry.next_hop != transport_hash);
            removed += before - ps.len();
        }
        self.path_table.retain(|_, ps| !ps.is_empty());
        removed
    }

    /// Drop all path entries learned via a given interface.
    pub fn drop_paths_for_interface(&mut self, interface: InterfaceId) -> usize {
        let mut removed = 0usize;
        let mut cleared_destinations = Vec::new();
        for (dest_hash, ps) in self.path_table.iter_mut() {
            let before = ps.len();
            ps.retain(|entry| entry.receiving_interface != interface);
            if ps.is_empty() {
                cleared_destinations.push(*dest_hash);
            }
            removed += before - ps.len();
        }
        self.path_table.retain(|_, ps| !ps.is_empty());
        for dest_hash in cleared_destinations {
            self.path_states.remove(&dest_hash);
        }
        removed
    }

    /// Drop all reverse table entries that reference a given interface.
    pub fn drop_reverse_for_interface(&mut self, interface: InterfaceId) -> usize {
        let before = self.reverse_table.len();
        self.reverse_table.retain(|_, entry| {
            entry.receiving_interface != interface && entry.outbound_interface != interface
        });
        before - self.reverse_table.len()
    }

    /// Drop all link table entries that reference a given interface.
    pub fn drop_links_for_interface(&mut self, interface: InterfaceId) -> usize {
        let before = self.link_table.len();
        self.link_table.retain(|_, entry| {
            entry.next_hop_interface != interface && entry.received_interface != interface
        });
        before - self.link_table.len()
    }

    /// Drop all pending announce retransmissions and bandwidth queues.
    pub fn drop_announce_queues(&mut self) {
        self.announce_table.clear();
        self.held_announces.clear();
        self.announce_queues = AnnounceQueues::new();
        self.ingress_control.clear();
    }

    /// Get the transport identity hash.
    pub fn identity_hash(&self) -> Option<&[u8; 16]> {
        self.config.identity_hash.as_ref()
    }

    /// Whether transport is enabled.
    pub fn transport_enabled(&self) -> bool {
        self.config.transport_enabled
    }

    /// Access the transport configuration.
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    pub fn set_packet_hashlist_max_entries(&mut self, max_entries: usize) {
        self.config.packet_hashlist_max_entries = max_entries;
        self.packet_hashlist = PacketHashlist::new(max_entries);
    }

    /// Get path table entries as tuples for management queries.
    /// Returns (dest_hash, timestamp, next_hop, hops, expires, interface_name).
    /// Reports primaries only for backward compatibility.
    pub fn get_path_table(&self, max_hops: Option<u8>) -> Vec<PathTableRow> {
        let mut result = Vec::new();
        for (dest_hash, ps) in self.path_table.iter() {
            if let Some(entry) = ps.primary() {
                if let Some(max) = max_hops {
                    if entry.hops > max {
                        continue;
                    }
                }
                let iface_name = self
                    .interfaces
                    .get(&entry.receiving_interface)
                    .map(|i| i.name.clone())
                    .unwrap_or_else(|| {
                        alloc::format!("Interface({})", entry.receiving_interface.0)
                    });
                result.push((
                    *dest_hash,
                    entry.timestamp,
                    entry.next_hop,
                    entry.hops,
                    entry.expires,
                    iface_name,
                ));
            }
        }
        result
    }

    /// Get rate table entries as tuples for management queries.
    /// Returns (dest_hash, last, rate_violations, blocked_until, timestamps).
    pub fn get_rate_table(&self) -> Vec<RateTableRow> {
        self.rate_limiter
            .entries()
            .map(|(hash, entry)| {
                (
                    *hash,
                    entry.last,
                    entry.rate_violations,
                    entry.blocked_until,
                    entry.timestamps.clone(),
                )
            })
            .collect()
    }

    /// Get blackholed identities as tuples for management queries.
    /// Returns (identity_hash, created, expires, reason).
    pub fn get_blackholed(&self) -> Vec<([u8; 16], f64, f64, Option<alloc::string::String>)> {
        self.blackholed_entries()
            .map(|(hash, entry)| (*hash, entry.created, entry.expires, entry.reason.clone()))
            .collect()
    }

    // =========================================================================
    // Cleanup
    // =========================================================================

    /// Return the set of destination hashes that currently have active paths.
    pub fn active_destination_hashes(&self) -> alloc::collections::BTreeSet<[u8; 16]> {
        self.path_table.keys().copied().collect()
    }

    /// Collect all packet hashes from active path entries (all paths, not just primaries).
    pub fn active_packet_hashes(&self) -> Vec<[u8; 32]> {
        self.path_table
            .values()
            .flat_map(|ps| ps.iter().map(|p| p.packet_hash))
            .collect()
    }

    /// Cull rate limiter entries for destinations that are neither active nor recently used.
    /// Returns the number of removed entries.
    pub fn cull_rate_limiter(
        &mut self,
        active: &alloc::collections::BTreeSet<[u8; 16]>,
        now: f64,
        ttl_secs: f64,
    ) -> usize {
        self.rate_limiter.cull_stale(active, now, ttl_secs)
    }

    // =========================================================================
    // Ingress control
    // =========================================================================

    /// Update the incoming announce frequency for an interface.
    pub fn update_interface_freq(&mut self, id: InterfaceId, ia_freq: f64) {
        if let Some(info) = self.interfaces.get_mut(&id) {
            info.ia_freq = ia_freq;
        }
    }

    /// Get the count of held announces for an interface (for management reporting).
    pub fn held_announce_count(&self, interface: &InterfaceId) -> usize {
        self.ingress_control.held_count(interface)
    }

    // =========================================================================
    // Testing helpers
    // =========================================================================

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn path_table(&self) -> &BTreeMap<[u8; 16], PathSet> {
        &self.path_table
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn announce_table(&self) -> &BTreeMap<[u8; 16], AnnounceEntry> {
        &self.announce_table
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn held_announces(&self) -> &BTreeMap<[u8; 16], AnnounceEntry> {
        &self.held_announces
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn announce_retained_bytes(&self) -> usize {
        self.announce_retained_bytes_total()
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn reverse_table(&self) -> &BTreeMap<[u8; 16], tables::ReverseEntry> {
        &self.reverse_table
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
        }
    }

    fn make_interface(id: u64, mode: u8) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: String::from("test"),
            mode,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: false,
            ia_freq: 0.0,
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
        config.announce_table_max_bytes =
            TransportEngine::announce_entry_size_bytes(&sample_entry) * 2
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
        let actions = engine.handle_inbound(&packet.raw, InterfaceId(1), now, &mut rng);

        // Should produce no AnnounceReceived or PathUpdated actions
        assert!(actions
            .iter()
            .all(|a| !matches!(a, TransportAction::AnnounceReceived { .. })));
        assert!(actions
            .iter()
            .all(|a| !matches!(a, TransportAction::PathUpdated { .. })));
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
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: true,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: false,
            ia_freq: 0.0,
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
        let actions = engine.handle_inbound(&packet.raw, InterfaceId(1), 1000.0, &mut rng);

        // Should have local delivery; hops should still be 0 (not 1)
        // because the local client decrement cancels the increment
        let deliver = actions
            .iter()
            .find(|a| matches!(a, TransportAction::DeliverLocal { .. }));
        assert!(deliver.is_some(), "Should deliver locally");
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
        let actions = engine.handle_inbound(&packet.raw, InterfaceId(1), 1000.0, &mut rng);

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
        let actions = engine.handle_inbound(&packet.raw, InterfaceId(2), 1000.0, &mut rng);

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
        let actions = engine.handle_inbound(&packet.raw, InterfaceId(1), 1000.0, &mut rng);

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

        let mut engine = TransportEngine::new(make_config(false));
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
        let actions = engine.handle_inbound(&packet.raw, InterfaceId(1), 1000.0, &mut rng);

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
            TransportAction::ForwardToLocalClients { exclude, .. } => {
                assert_eq!(*exclude, Some(InterfaceId(1)));
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
        let actions = engine.handle_inbound(&packet.raw, InterfaceId(1), 1000.0, &mut rng);

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
        let actions = engine.handle_inbound(&packet.raw, InterfaceId(1), 1000.0, &mut rng);

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
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: true,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: false,
            ia_freq: 0.0,
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
        engine.handle_inbound(&packet.raw, InterfaceId(1), 1000.0, &mut rng);

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

    // =========================================================================
    // DISCOVER_PATHS_FOR tests
    // =========================================================================

    fn make_path_request_data(dest_hash: &[u8; 16], tag: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(dest_hash);
        data.extend_from_slice(tag);
        data
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
        assert!(engine.discovery_pr_tags.contains(&unique1));
        assert!(engine.discovery_pr_tags.contains(&unique2));

        engine.handle_path_request(
            &make_path_request_data(&dest3, &tag3),
            InterfaceId(1),
            1002.0,
        );
        assert_eq!(engine.discovery_pr_tags_count(), 2);
        assert!(!engine.discovery_pr_tags.contains(&unique1));
        assert!(engine.discovery_pr_tags.contains(&unique2));

        engine.handle_path_request(
            &make_path_request_data(&dest1, &tag1),
            InterfaceId(1),
            1003.0,
        );
        assert_eq!(engine.discovery_pr_tags_count(), 2);
        assert!(engine.discovery_pr_tags.contains(&unique1));
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
    fn test_path_request_skips_when_no_announce_raw() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
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

        // Should NOT create an announce entry without raw data
        assert!(actions.is_empty());
        assert!(!engine.announce_table.contains_key(&dest));
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
        engine.handle_inbound(&announce_packet.raw, InterfaceId(1), 1000.0, &mut rng);
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
        engine.handle_inbound(&announce_raw, InterfaceId(2), 1000.0, &mut rng);
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
        let actions = engine.handle_inbound(&h2_raw, InterfaceId(1), 1001.0, &mut rng2);

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
