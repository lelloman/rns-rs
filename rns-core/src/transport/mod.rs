pub mod types;
pub mod tables;
pub mod dedup;
pub mod pathfinder;
pub mod rate_limit;
pub mod announce_proc;
pub mod outbound;
pub mod inbound;
pub mod jobs;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use rns_crypto::Rng;

use crate::announce::AnnounceData;
use crate::constants;
use crate::packet::RawPacket;

use self::announce_proc::compute_path_expires;
use self::dedup::PacketHashlist;
use self::inbound::{
    create_link_entry, create_reverse_entry, forward_transport_packet,
    route_proof_via_reverse, route_via_link_table,
};
use self::outbound::route_outbound;
use self::pathfinder::{
    extract_random_blob, should_update_path, timebase_from_random_blob, PathDecision,
};
use self::rate_limit::AnnounceRateLimiter;
use self::tables::{AnnounceEntry, LinkEntry, PathEntry};
use self::types::{InterfaceId, InterfaceInfo, TransportAction, TransportConfig};

/// The core transport/routing engine.
///
/// Maintains routing tables and processes packets without performing any I/O.
/// Returns `Vec<TransportAction>` that the caller must execute.
pub struct TransportEngine {
    config: TransportConfig,
    path_table: BTreeMap<[u8; 16], PathEntry>,
    announce_table: BTreeMap<[u8; 16], AnnounceEntry>,
    reverse_table: BTreeMap<[u8; 16], tables::ReverseEntry>,
    link_table: BTreeMap<[u8; 16], LinkEntry>,
    held_announces: BTreeMap<[u8; 16], AnnounceEntry>,
    packet_hashlist: PacketHashlist,
    rate_limiter: AnnounceRateLimiter,
    path_states: BTreeMap<[u8; 16], u8>,
    path_requests: BTreeMap<[u8; 16], f64>,
    interfaces: BTreeMap<InterfaceId, InterfaceInfo>,
    local_destinations: BTreeMap<[u8; 16], u8>,
    discovery_pr_tags: Vec<[u8; 32]>,
    // Job timing
    announces_last_checked: f64,
    tables_last_culled: f64,
    links_last_checked: f64,
}

impl TransportEngine {
    pub fn new(config: TransportConfig) -> Self {
        TransportEngine {
            config,
            path_table: BTreeMap::new(),
            announce_table: BTreeMap::new(),
            reverse_table: BTreeMap::new(),
            link_table: BTreeMap::new(),
            held_announces: BTreeMap::new(),
            packet_hashlist: PacketHashlist::new(constants::HASHLIST_MAXSIZE),
            rate_limiter: AnnounceRateLimiter::new(),
            path_states: BTreeMap::new(),
            path_requests: BTreeMap::new(),
            interfaces: BTreeMap::new(),
            local_destinations: BTreeMap::new(),
            discovery_pr_tags: Vec::new(),
            announces_last_checked: 0.0,
            tables_last_culled: 0.0,
            links_last_checked: 0.0,
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
        self.path_table.contains_key(dest_hash)
    }

    pub fn hops_to(&self, dest_hash: &[u8; 16]) -> Option<u8> {
        self.path_table.get(dest_hash).map(|e| e.hops)
    }

    pub fn next_hop(&self, dest_hash: &[u8; 16]) -> Option<[u8; 16]> {
        self.path_table.get(dest_hash).map(|e| e.next_hop)
    }

    pub fn next_hop_interface(&self, dest_hash: &[u8; 16]) -> Option<InterfaceId> {
        self.path_table.get(dest_hash).map(|e| e.receiving_interface)
    }

    // =========================================================================
    // Path state
    // =========================================================================

    pub fn mark_path_unresponsive(&mut self, dest_hash: &[u8; 16]) {
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
        if let Some(entry) = self.path_table.get_mut(dest_hash) {
            entry.timestamp = 0.0;
            entry.expires = 0.0;
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
    // Packet filter
    // =========================================================================

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

        // 2. Increment hops
        packet.hops += 1;

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

        // 5. Transport forwarding: if we are the designated next hop
        if self.config.transport_enabled || self.config.identity_hash.is_some() {
            if packet.transport_id.is_some()
                && packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE
            {
                if let Some(ref identity_hash) = self.config.identity_hash {
                    if packet.transport_id.as_ref() == Some(identity_hash) {
                        if let Some(path_entry) = self.path_table.get(&packet.destination_hash) {
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
                            } else {
                                let (trunc_hash, reverse_entry) = create_reverse_entry(
                                    &packet,
                                    outbound_interface,
                                    iface,
                                    now,
                                );
                                self.reverse_table.insert(trunc_hash, reverse_entry);
                            }

                            actions.push(TransportAction::SendOnInterface {
                                interface: outbound_interface,
                                raw: new_raw,
                            });

                            // Update path timestamp
                            if let Some(entry) = self.path_table.get_mut(&packet.destination_hash) {
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
                        if let Some(entry) =
                            self.link_table.get_mut(&packet.destination_hash)
                        {
                            entry.timestamp = now;
                        }
                    }
                }
            }
        }

        // 7. Announce handling
        if packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE {
            self.process_inbound_announce(&packet, iface, now, rng, &mut actions);
        }

        // 8. Proof handling
        if packet.flags.packet_type == constants::PACKET_TYPE_PROOF {
            self.process_inbound_proof(&packet, iface, now, &mut actions);
        }

        // 9. Local delivery for LINKREQUEST and DATA
        if packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
            || packet.flags.packet_type == constants::PACKET_TYPE_DATA
        {
            if self.local_destinations.contains_key(&packet.destination_hash) {
                actions.push(TransportAction::DeliverLocal {
                    destination_hash: packet.destination_hash,
                    raw: packet.raw.clone(),
                    packet_hash: packet.packet_hash,
                });
            }
        }

        actions
    }

    // =========================================================================
    // Inbound announce processing
    // =========================================================================

    fn process_inbound_announce(
        &mut self,
        packet: &RawPacket,
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

        let validated = match announce.validate(&packet.destination_hash) {
            Ok(v) => v,
            Err(_) => return,
        };

        // Skip local destinations
        if self.local_destinations.contains_key(&packet.destination_hash) {
            return;
        }

        // Detect retransmit completion
        let received_from = if let Some(transport_id) = packet.transport_id {
            // Check if this is a retransmit we can stop
            if self.config.transport_enabled {
                if let Some(announce_entry) = self.announce_table.get_mut(&packet.destination_hash) {
                    if packet.hops.checked_sub(1) == Some(announce_entry.hops) {
                        announce_entry.local_rebroadcasts += 1;
                        if announce_entry.retries > 0
                            && announce_entry.local_rebroadcasts >= constants::LOCAL_REBROADCASTS_MAX
                        {
                            self.announce_table.remove(&packet.destination_hash);
                        }
                    }
                    // Check if our retransmit was passed on
                    if let Some(announce_entry) = self.announce_table.get(&packet.destination_hash) {
                        if packet.hops.checked_sub(1) == Some(announce_entry.hops + 1)
                            && announce_entry.retries > 0
                        {
                            if now < announce_entry.retransmit_timeout {
                                self.announce_table.remove(&packet.destination_hash);
                            }
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
        if packet.hops >= constants::PATHFINDER_M + 1 {
            return;
        }

        let announce_emitted = timebase_from_random_blob(&random_blob);

        // Path update decision
        let existing = self.path_table.get(&packet.destination_hash);
        let is_unresponsive = self.path_is_unresponsive(&packet.destination_hash);

        let decision = should_update_path(
            existing,
            packet.hops,
            announce_emitted,
            &random_blob,
            is_unresponsive,
            now,
        );

        if decision == PathDecision::Reject {
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

        // Get existing random blobs
        let existing_blobs = self
            .path_table
            .get(&packet.destination_hash)
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
        );

        // Store path
        self.path_table
            .insert(packet.destination_hash, path_entry);

        // Mark path as unknown state on update
        self.path_states.remove(&packet.destination_hash);

        // Store announce for retransmission
        if let Some(ann) = announce_entry {
            self.announce_table.insert(packet.destination_hash, ann);
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
            self.announce_table
                .insert(packet.destination_hash, entry);
        }
    }

    /// Check if there's a waiting discovery path request for a destination.
    fn discovery_path_requests_waiting(&self, _dest_hash: &[u8; 16]) -> Option<InterfaceId> {
        // Discovery path requests are out of scope for the basic implementation.
        // This would check Transport.discovery_path_requests in Python.
        None
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
            if (self.config.transport_enabled) && self.link_table.contains_key(&packet.destination_hash)
            {
                let link_entry = self.link_table.get(&packet.destination_hash).cloned();
                if let Some(entry) = link_entry {
                    if packet.hops == entry.remaining_hops
                        && iface == entry.next_hop_interface
                    {
                        // Forward the proof (simplified: skip signature validation
                        // which requires Identity recall)
                        let mut new_raw = Vec::new();
                        new_raw.push(packet.raw[0]);
                        new_raw.push(packet.hops);
                        new_raw.extend_from_slice(&packet.raw[2..]);

                        // Mark link as validated
                        if let Some(le) =
                            self.link_table.get_mut(&packet.destination_hash)
                        {
                            le.validated = true;
                        }

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
                });
            }
        } else {
            // Regular proof: check reverse table
            if self.config.transport_enabled {
                if let Some(reverse_entry) =
                    self.reverse_table.remove(&packet.destination_hash)
                {
                    if let Some(action) =
                        route_proof_via_reverse(packet, &reverse_entry, iface)
                    {
                        actions.push(action);
                    }
                }
            }

            // Deliver to local receipts
            actions.push(TransportAction::DeliverLocal {
                destination_hash: packet.destination_hash,
                raw: packet.raw.clone(),
                packet_hash: packet.packet_hash,
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

        actions
    }

    // =========================================================================
    // Core API: tick
    // =========================================================================

    /// Periodic maintenance. Call regularly (e.g., every 250ms).
    pub fn tick(&mut self, now: f64, _rng: &mut dyn Rng) -> Vec<TransportAction> {
        let mut actions = Vec::new();

        // Process pending announces
        if now > self.announces_last_checked + constants::ANNOUNCES_CHECK_INTERVAL {
            if let Some(ref identity_hash) = self.config.identity_hash {
                let ih = *identity_hash;
                let mut announce_actions = jobs::process_pending_announces(
                    &mut self.announce_table,
                    &mut self.held_announces,
                    &ih,
                    now,
                );
                actions.append(&mut announce_actions);
            }
            self.announces_last_checked = now;
        }

        // Cull tables
        if now > self.tables_last_culled + constants::TABLES_CULL_INTERVAL {
            jobs::cull_path_table(&mut self.path_table, &self.interfaces, now);
            jobs::cull_reverse_table(&mut self.reverse_table, &self.interfaces, now);
            jobs::cull_link_table(&mut self.link_table, &self.interfaces, now);
            jobs::cull_path_states(&mut self.path_states, &self.path_table);
            self.tables_last_culled = now;
        }

        // Hashlist rotation
        self.packet_hashlist.maybe_rotate();

        // Cull PR tags if over limit
        if self.discovery_pr_tags.len() > constants::MAX_PR_TAGS {
            let start = self.discovery_pr_tags.len() - constants::MAX_PR_TAGS;
            self.discovery_pr_tags = self.discovery_pr_tags[start..].to_vec();
        }

        actions
    }

    // =========================================================================
    // Path request handling
    // =========================================================================

    /// Handle an incoming path request.
    pub fn handle_path_request(
        &mut self,
        data: &[u8],
        interface_id: InterfaceId,
        now: f64,
    ) -> Vec<TransportAction> {
        let actions = Vec::new();

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

            if self.discovery_pr_tags.contains(&unique_tag) {
                return actions; // Duplicate tag
            }
            self.discovery_pr_tags.push(unique_tag);
        } else {
            return actions; // Tagless request
        }

        // If destination is local, the caller should handle the announce
        if self.local_destinations.contains_key(&destination_hash) {
            // Caller needs to trigger local announce - we signal via PathUpdated
            // (In practice, caller would call destination.announce(path_response=True))
            return actions;
        }

        // If we know the path and transport is enabled, queue retransmit
        if (self.config.transport_enabled) && self.path_table.contains_key(&destination_hash) {
            let path = self.path_table.get(&destination_hash).unwrap();
            let received_from = path.next_hop;
            let hops = path.hops;

            // Check if there's already an announce in the table
            if let Some(existing) = self.announce_table.remove(&destination_hash) {
                self.held_announces.insert(destination_hash, existing);
            }

            let retransmit_timeout = if let Some(iface_info) = self.interfaces.get(&interface_id) {
                let base = now + constants::PATH_REQUEST_GRACE;
                if iface_info.mode == constants::MODE_ROAMING {
                    base + constants::PATH_REQUEST_RG
                } else {
                    base
                }
            } else {
                now + constants::PATH_REQUEST_GRACE
            };

            // We need the original announce packet data to retransmit.
            // Since we don't cache packets, we can only retransmit if we
            // have the data in the path entry. For now, create an entry
            // that the caller can use.
            let entry = AnnounceEntry {
                timestamp: now,
                retransmit_timeout,
                retries: constants::PATHFINDER_R,
                received_from,
                hops,
                packet_raw: Vec::new(), // Would need cached announce
                packet_data: Vec::new(),
                destination_hash,
                context_flag: 0,
                local_rebroadcasts: 0,
                block_rebroadcasts: true,
                attached_interface: Some(interface_id),
            };

            self.announce_table.insert(destination_hash, entry);
        } else if self.config.transport_enabled {
            // Unknown path: forward request on other interfaces
            for (_, iface_info) in self.interfaces.iter() {
                if iface_info.id != interface_id && iface_info.out_capable {
                    // Caller would need to send path request on this interface
                    // For now, we don't emit an action since path request forwarding
                    // requires building a new path request packet.
                }
            }
        }

        actions
    }

    // =========================================================================
    // Public read accessors
    // =========================================================================

    /// Iterate over all path table entries.
    pub fn path_table_entries(&self) -> impl Iterator<Item = (&[u8; 16], &PathEntry)> {
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

    /// Access the rate limiter for reading rate table entries.
    pub fn rate_limiter(&self) -> &AnnounceRateLimiter {
        &self.rate_limiter
    }

    /// Get interface info by id.
    pub fn interface_info(&self, id: &InterfaceId) -> Option<&InterfaceInfo> {
        self.interfaces.get(id)
    }

    /// Drop a path from the path table.
    pub fn drop_path(&mut self, dest_hash: &[u8; 16]) -> bool {
        self.path_table.remove(dest_hash).is_some()
    }

    /// Drop all paths that route via a given transport hash.
    pub fn drop_all_via(&mut self, transport_hash: &[u8; 16]) -> usize {
        let before = self.path_table.len();
        self.path_table.retain(|_, entry| &entry.next_hop != transport_hash);
        before - self.path_table.len()
    }

    /// Drop all pending announce retransmissions.
    pub fn drop_announce_queues(&mut self) {
        self.announce_table.clear();
        self.held_announces.clear();
    }

    /// Get the transport identity hash.
    pub fn identity_hash(&self) -> Option<&[u8; 16]> {
        self.config.identity_hash.as_ref()
    }

    /// Whether transport is enabled.
    pub fn transport_enabled(&self) -> bool {
        self.config.transport_enabled
    }

    // =========================================================================
    // Testing helpers
    // =========================================================================

    #[cfg(test)]
    pub(crate) fn path_table(&self) -> &BTreeMap<[u8; 16], PathEntry> {
        &self.path_table
    }

    #[cfg(test)]
    pub(crate) fn announce_table(&self) -> &BTreeMap<[u8; 16], AnnounceEntry> {
        &self.announce_table
    }

    #[cfg(test)]
    pub(crate) fn reverse_table(&self) -> &BTreeMap<[u8; 16], tables::ReverseEntry> {
        &self.reverse_table
    }

    #[cfg(test)]
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
        }
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

        engine.mark_path_unresponsive(&dest);
        assert!(engine.path_is_unresponsive(&dest));

        engine.mark_path_responsive(&dest);
        assert!(!engine.path_is_unresponsive(&dest));
    }

    #[test]
    fn test_expire_path() {
        let mut engine = TransportEngine::new(make_config(false));
        let dest = [0x33; 16];

        engine.path_table.insert(
            dest,
            PathEntry {
                timestamp: 1000.0,
                next_hop: [0; 16],
                hops: 2,
                expires: 9999.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(1),
                packet_hash: [0; 32],
            },
        );

        assert!(engine.has_path(&dest));
        engine.expire_path(&dest);
        // Path still exists but expires = 0
        assert!(engine.has_path(&dest));
        assert_eq!(engine.path_table[&dest].expires, 0.0);
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
        let packet =
            RawPacket::pack(flags, 0, &[0; 16], None, constants::CONTEXT_NONE, &[0xAA; 64])
                .unwrap();

        // Add to hashlist
        engine.packet_hashlist.add(packet.packet_hash);

        // Should still pass filter (duplicate announce for SINGLE allowed)
        assert!(engine.packet_filter(&packet));
    }

    #[test]
    fn test_tick_retransmits_announce() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let dest = [0x55; 16];
        engine.announce_table.insert(
            dest,
            AnnounceEntry {
                timestamp: 100.0,
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
        );

        let mut rng = rns_crypto::FixedRng::new(&[0x42; 32]);
        let actions = engine.tick(200.0, &mut rng);

        // Should have a broadcast action for the retransmit
        assert!(!actions.is_empty());
        assert!(matches!(
            &actions[0],
            TransportAction::BroadcastOnAllInterfaces { .. }
        ));

        // Retries should have increased
        assert_eq!(engine.announce_table[&dest].retries, 1);
    }

    #[test]
    fn test_tick_culls_expired_path() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));

        let dest = [0x66; 16];
        engine.path_table.insert(
            dest,
            PathEntry {
                timestamp: 100.0,
                next_hop: [0; 16],
                hops: 2,
                expires: 200.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(1),
                packet_hash: [0; 32],
            },
        );

        assert!(engine.has_path(&dest));

        let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
        // Advance past cull interval and path expiry
        engine.tick(300.0, &mut rng);

        assert!(!engine.has_path(&dest));
    }
}
