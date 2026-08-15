use super::*;

impl TransportEngine {
    pub fn new(config: TransportConfig) -> Self {
        let packet_hashlist_max_entries = config.packet_hashlist_max_entries;
        let packet_hashlist_allocation = config.packet_hashlist_allocation;
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
            packet_hashlist: PacketHashlist::with_allocation(
                packet_hashlist_max_entries,
                packet_hashlist_allocation,
            ),
            announce_sig_cache: AnnounceSignatureCache::new(sig_cache_max, sig_cache_ttl),
            rate_limiter: AnnounceRateLimiter::new(),
            path_states: BTreeMap::new(),
            interfaces: BTreeMap::new(),
            interface_hashes: BTreeMap::new(),
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
        self.interface_hashes
            .insert(info.id, hash::full_hash(info.name.as_bytes()));
        self.interfaces.insert(info.id, info);
    }

    pub fn deregister_interface(&mut self, id: InterfaceId) {
        self.interfaces.remove(&id);
        self.interface_hashes.remove(&id);
        self.drop_paths_for_interface(id);
        self.drop_reverse_for_interface(id);
        self.drop_links_for_interface(id);
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

    /// Return the destination whose unvalidated link route can be rebalanced
    /// by a mismatched-hop LRPROOF received from its recorded next hop.
    pub fn link_rebalance_destination(
        &self,
        link_id: &[u8; 16],
        packet_hops: u8,
        receiving_interface: InterfaceId,
    ) -> Option<[u8; 16]> {
        let entry = self.link_table.get(link_id)?;
        (self.config.transport_enabled
            && !entry.validated
            && packet_hops != entry.remaining_hops
            && receiving_interface == entry.next_hop_interface)
            .then_some(entry.destination_hash)
    }

    /// Parse and filter an inbound frame before offering it for LRPROOF path
    /// rebalancing. The returned hops are the post-ingress metric used by the
    /// normal transport pipeline.
    pub fn inbound_lrproof_rebalance_candidate(
        &self,
        raw: &[u8],
        receiving_interface: InterfaceId,
    ) -> Option<super::LrproofRebalanceCandidate> {
        let ctx = self.prepare_inbound_packet(InboundFrame {
            raw,
            iface: receiving_interface,
            now: 0.0,
            rx: RxMetadata::default(),
        })?;
        if ctx.packet.flags.packet_type != constants::PACKET_TYPE_PROOF
            || ctx.packet.context != constants::CONTEXT_LRPROOF
        {
            return None;
        }
        let link_id = ctx.packet.destination_hash;
        let destination_hash =
            self.link_rebalance_destination(&link_id, ctx.packet.hops, receiving_interface)?;
        Some((link_id, destination_hash, ctx.packet.hops, ctx.packet.data))
    }

    /// Validate a mismatched-hop LRPROOF and update the relay link route and
    /// destination path atomically enough for normal proof routing to resume.
    pub fn rebalance_link_path_from_lrproof(
        &mut self,
        link_id: &[u8; 16],
        packet_hops: u8,
        receiving_interface: InterfaceId,
        proof_data: &[u8],
        destination_sig_pub_bytes: &[u8; 32],
    ) -> bool {
        if self
            .link_rebalance_destination(link_id, packet_hops, receiving_interface)
            .is_none()
        {
            return false;
        }

        let destination_sig_pub =
            rns_crypto::ed25519::Ed25519PublicKey::from_bytes(destination_sig_pub_bytes);
        if crate::link::handshake::validate_lrproof(
            proof_data,
            link_id,
            &destination_sig_pub,
            destination_sig_pub_bytes,
        )
        .is_err()
        {
            return false;
        }

        let destination_hash = match self.link_table.get_mut(link_id) {
            Some(entry) if !entry.validated => {
                entry.remaining_hops = packet_hops;
                entry.destination_hash
            }
            _ => return false,
        };
        if let Some(paths) = self.path_table.get_mut(&destination_hash) {
            paths.update_primary_hops(packet_hops);
        }
        true
    }

    /// Update the current path metric after a terminus validates an LRPROOF.
    pub fn rebalance_destination_path_hops(
        &mut self,
        destination_hash: &[u8; 16],
        packet_hops: u8,
    ) -> bool {
        self.path_table
            .get_mut(destination_hash)
            .is_some_and(|paths| paths.update_primary_hops(packet_hops))
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
    pub(super) fn cull_blackholed(&mut self, now: f64) {
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
        let reattaching = self.tunnel_table.get(&tunnel_id).is_some();
        if reattaching {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Tunnel endpoint {:02x?} reappeared on interface {}; restoring paths",
                &tunnel_id[..4],
                interface.0,
            );
        } else {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Tunnel endpoint {:02x?} established on interface {}",
                &tunnel_id[..4],
                interface.0,
            );
        }

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
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Restored tunnel path to {:02x?}: hops={} via={:02x?} interface={}",
                    &dest_hash[..4],
                    tunnel_path.hops,
                    &tunnel_path.received_from[..4],
                    interface.0,
                );
            } else {
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Did not restore tunnel path to {:02x?}: existing path is preferred or tunnel path expired",
                    &dest_hash[..4],
                );
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

        let interface_hash = if let Some(interface_hash) = self.interface_hashes.get(&interface_id)
        {
            *interface_hash
        } else {
            log::warn!(
                "Cannot synthesize tunnel on {:?}: unknown interface or missing cached hash",
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
    pub(super) fn has_local_clients(&self) -> bool {
        self.interfaces.values().any(|i| i.is_local_client)
    }

    pub(super) fn interface_is_local_client(&self, iface: InterfaceId) -> bool {
        self.interfaces
            .get(&iface)
            .map(|i| i.is_local_client)
            .unwrap_or(false)
    }

    /// Packet filter: dedup + basic validity.
    ///
    /// Transport.py:1187-1238
    pub(super) fn packet_filter(&self, packet: &RawPacket) -> bool {
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
}
