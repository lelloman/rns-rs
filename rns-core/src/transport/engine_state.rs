use super::*;

impl TransportEngine {
    /// Engine with empty tables, configured by `config`.
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
            reverse_table: tables::ReverseTable::default(),
            link_table: tables::LinkTable::new(),
            link_rxb: 0,
            link_txb: 0,
            held_announces: BTreeMap::new(),
            packet_hashlist: PacketHashlist::with_allocation(
                packet_hashlist_max_entries,
                packet_hashlist_allocation,
            ),
            announce_sig_cache: AnnounceSignatureCache::new(sig_cache_max, sig_cache_ttl),
            rate_limiter: AnnounceRateLimiter::new(),
            path_states: BTreeMap::new(),
            lrproof_verdict: None,
            interfaces: BTreeMap::new(),
            interface_hashes: BTreeMap::new(),
            local_tunnel_ids: BTreeMap::new(),
            remote_transports: BTreeMap::new(),
            synthesis_received: BTreeSet::new(),
            synthesis_emitted: BTreeSet::new(),
            remote_transport_infos: BTreeMap::new(),
            local_destinations: BTreeMap::new(),
            blackholed_identities: BTreeMap::new(),
            announce_queues: AnnounceQueues::new(announce_queue_max_interfaces),
            ingress_control: IngressControl::new(),
            tunnel_table: TunnelTable::new(),
            discovery_pr_tags: VecDeque::new(),
            discovery_pr_tag_set: BTreeSet::new(),
            path_requests: BTreeMap::new(),
            stamp_prs: constants::STAMP_PRS,
            client_transport_id: None,
            hop_limiter: constants::HOP_LIMITER,
            inbound_filtered: false,
            inbound_filtered_announce: false,
            announce_receipts: Vec::new(),
            released_traffic: Vec::new(),
            stamp_requirements: StampRequirements::default(),
            destination_filter: Default::default(),
            control_destinations: [
                crate::destination::destination_hash("rnstransport", &["path", "request"], None),
                crate::destination::destination_hash(
                    "rnstransport",
                    &["tunnel", "synthesize"],
                    None,
                ),
            ],
            discovery_path_requests: BTreeMap::new(),
            discovery_path_request_deadlines: BTreeMap::new(),
            pending_local_path_requests: BTreeMap::new(),
            pending_discovery_prs: VecDeque::new(),
            discovery_pr_next_tx: 0.0,
            path_destination_cap_evict_count: 0,
            announces_last_checked: 0.0,
            tables_last_culled: 0.0,
        }
    }

    // =========================================================================
    // Interface management
    // =========================================================================

    /// Register an interface, or replace the info of one already registered.
    pub fn register_interface(&mut self, info: InterfaceInfo) {
        self.interface_hashes
            .insert(info.id, hash::full_hash(info.name.as_bytes()));
        self.interfaces.insert(info.id, info);
    }

    /// Remove an interface and everything that refers to it: paths, reverse and
    /// link entries, tunnel state, its announce queue, ingress control state and
    /// queued local path requests.
    pub fn deregister_interface(&mut self, id: InterfaceId) {
        self.interfaces.remove(&id);
        self.interface_hashes.remove(&id);
        self.local_tunnel_ids.remove(&id);
        self.remote_transports.remove(&id);
        self.synthesis_received.remove(&id);
        self.synthesis_emitted.remove(&id);
        self.remote_transport_infos.remove(&id);
        self.drop_paths_for_interface(id);
        self.drop_reverse_for_interface(id);
        self.drop_links_for_interface(id);
        self.announce_queues.remove_interface(id);
        self.ingress_control.remove_interface(&id);
        self.pending_local_path_requests
            .retain(|_, (interface, _)| *interface != id);
    }

    // =========================================================================
    // Destination management
    // =========================================================================

    /// Register a local destination, with its destination type (a `DESTINATION_*`
    /// constant), so packets addressed to it are delivered here.
    pub fn register_destination(&mut self, dest_hash: [u8; 16], dest_type: u8) {
        self.local_destinations.insert(dest_hash, dest_type);
    }

    /// Remove a local destination.
    pub fn deregister_destination(&mut self, dest_hash: &[u8; 16]) {
        self.local_destinations.remove(dest_hash);
    }

    // =========================================================================
    // Path queries
    // =========================================================================

    /// Whether the path table holds at least one path to `dest_hash`.
    pub fn has_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.path_table
            .get(dest_hash)
            .is_some_and(|ps| !ps.is_empty())
    }

    /// Hops to `dest_hash` on its primary path.
    pub fn hops_to(&self, dest_hash: &[u8; 16]) -> Option<u8> {
        self.path_table
            .get(dest_hash)
            .and_then(|ps| ps.primary())
            .map(|e| e.hops)
    }

    /// Next hop of the primary path to `dest_hash`.
    pub fn next_hop(&self, dest_hash: &[u8; 16]) -> Option<[u8; 16]> {
        self.path_table
            .get(dest_hash)
            .and_then(|ps| ps.primary())
            .map(|e| e.next_hop)
    }

    /// Interface of the primary path to `dest_hash`.
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

    /// `Transport.mark_path_responsive`: an event that proves the
    /// destination alive, such as a validated link request proof, refreshes
    /// its path as a fresh announce would (timestamp, expiry and use) and
    /// marks it responsive.
    pub fn mark_path_responsive(&mut self, dest_hash: &[u8; 16], now: f64) {
        if let Some(entry) = self
            .path_table
            .get_mut(dest_hash)
            .and_then(|paths| paths.primary_mut())
        {
            let mode = self
                .interfaces
                .get(&entry.receiving_interface)
                .map_or(constants::MODE_FULL, |info| info.mode);
            entry.timestamp = now;
            entry.expires = super::announce_proc::compute_path_expires(now, mode);
            entry.used = now;
        }
        self.path_states
            .insert(*dest_hash, constants::STATE_RESPONSIVE);
    }

    /// Upstream's `Transport.get_path_state` (41260ea1): the state the path
    /// to `dest_hash` is marked with, `STATE_UNKNOWN` when it has none.
    pub fn path_state(&self, dest_hash: &[u8; 16]) -> u8 {
        self.path_states
            .get(dest_hash)
            .copied()
            .unwrap_or(constants::STATE_UNKNOWN)
    }

    /// Whether the path to `dest_hash` is marked unresponsive.
    pub fn path_is_unresponsive(&self, dest_hash: &[u8; 16]) -> bool {
        self.path_states.get(dest_hash) == Some(&constants::STATE_UNRESPONSIVE)
    }

    /// Expire every path to `dest_hash`; the next table cull removes them.
    pub fn expire_path(&mut self, dest_hash: &[u8; 16]) {
        if let Some(ps) = self.path_table.get_mut(dest_hash) {
            ps.expire_all();
        }
    }

    // =========================================================================
    // Link table
    // =========================================================================

    /// Add or replace a link table entry.
    pub fn register_link(&mut self, link_id: [u8; 16], entry: LinkEntry) {
        self.link_table.insert(link_id, entry);
    }

    /// Mark a link table entry as validated.
    pub fn validate_link(&mut self, link_id: &[u8; 16]) {
        if let Some(entry) = self.link_table.get_mut(link_id) {
            entry.validated = true;
        }
    }

    /// Remove a link table entry.
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
        let decoded = DecodedPacket::unpack(raw).ok()?;
        self.decoded_lrproof_rebalance_candidate(&decoded, receiving_interface)
    }

    /// [`Self::inbound_lrproof_rebalance_candidate`] for an already decoded packet.
    pub fn decoded_lrproof_rebalance_candidate(
        &self,
        decoded: &DecodedPacket,
        receiving_interface: InterfaceId,
    ) -> Option<super::LrproofRebalanceCandidate> {
        let packet = &decoded.packet;
        let (hops, _) = self.filtered_inbound_hops(packet, receiving_interface)?;
        if packet.flags.packet_type != constants::PACKET_TYPE_PROOF
            || packet.context != constants::CONTEXT_LRPROOF
        {
            return None;
        }
        let link_id = packet.destination_hash;
        let destination_hash =
            self.link_rebalance_destination(&link_id, hops, receiving_interface)?;
        Some((link_id, destination_hash, hops, packet.data().to_vec()))
    }

    /// An LRPROOF this node would transport (`Transport.inbound`: received
    /// on the link's next-hop interface with the expected hops): its link,
    /// the link's destination, and the proof data. The caller checks the
    /// signature against the destination's identity and reports it with
    /// [`Self::set_lrproof_verdict`] before handing the packet in.
    pub fn decoded_transported_lrproof(
        &self,
        decoded: &DecodedPacket,
        receiving_interface: InterfaceId,
    ) -> Option<super::LrproofRebalanceCandidate> {
        let packet = &decoded.packet;
        if packet.flags.packet_type != constants::PACKET_TYPE_PROOF
            || packet.context != constants::CONTEXT_LRPROOF
        {
            return None;
        }
        let (hops, from_local_client) = self.filtered_inbound_hops(packet, receiving_interface)?;
        let link_id = packet.destination_hash;
        let entry = self.link_table.get(&link_id)?;
        let for_local_client_link = self.interface_is_local_client(entry.next_hop_interface)
            || self.interface_is_local_client(entry.received_interface);
        (self.config.transport_enabled || from_local_client || for_local_client_link)
            .then_some(())?;
        (hops == entry.remaining_hops && receiving_interface == entry.next_hop_interface).then(
            || {
                (
                    link_id,
                    entry.destination_hash,
                    hops,
                    packet.data().to_vec(),
                )
            },
        )
    }

    /// Whether `proof_data` is a valid LRPROOF for `link_id`, signed by the
    /// destination whose Ed25519 signing key is `destination_sig_pub_bytes`.
    pub fn lrproof_is_valid(
        link_id: &[u8; 16],
        proof_data: &[u8],
        destination_sig_pub_bytes: &[u8; 32],
    ) -> bool {
        let Ok(destination_sig_pub) =
            rns_crypto::ed25519::Ed25519PublicKey::from_bytes(destination_sig_pub_bytes)
        else {
            return false;
        };
        crate::link::handshake::validate_lrproof(
            proof_data,
            link_id,
            &destination_sig_pub,
            destination_sig_pub_bytes,
        )
        .is_ok()
    }

    /// Record whether the next LRPROOF for `link_id` is validly signed. A
    /// transported proof with a verdict is forwarded only when valid, as
    /// upstream, which also drops it when the destination's identity is
    /// unknown; without one it is routed unchecked.
    pub fn set_lrproof_verdict(&mut self, link_id: [u8; 16], valid: bool) {
        self.lrproof_verdict = Some((link_id, valid));
    }

    /// Validate a mismatched-hop LRPROOF and update the relay link route and
    /// destination path atomically enough for normal proof routing to resume.
    ///
    /// The engine is exclusively borrowed for the whole operation, so the
    /// link and path mutations need neither separate path-table locks nor
    /// repeated map lookups. A path can legitimately be absent; that does not
    /// invalidate the authenticated link-route update.
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

        let Ok(destination_sig_pub) =
            rns_crypto::ed25519::Ed25519PublicKey::from_bytes(destination_sig_pub_bytes)
        else {
            return false;
        };
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

    /// Add an identity hash to the blackhole list on this node.
    ///
    /// `identity_hash` is the 16-byte identity hash to blackhole. `now` is the
    /// current Unix timestamp. If `duration_hours` is `Some` and greater than
    /// zero, the entry expires after that many hours; otherwise it does not
    /// expire. `reason` is optional descriptive text retained with the entry.
    ///
    /// Returns `false`, leaving the entry as it is, when the identity is
    /// already blackholed (`Transport.blackhole_identity` returns `None`).
    pub fn blackhole_identity(
        &mut self,
        identity_hash: [u8; 16],
        now: f64,
        duration_hours: Option<f64>,
        reason: Option<String>,
    ) -> bool {
        let expires = match duration_hours {
            Some(h) if h > 0.0 => now + h * 3600.0,
            _ => 0.0, // never expires
        };
        self.insert_blackhole_entry(
            identity_hash,
            BlackholeEntry {
                created: now,
                expires,
                reason,
                source: None,
            },
        )
    }

    /// Add a blackhole entry unless the identity is already blackholed, as
    /// `Transport.blackhole_identity` and `reload_blackhole` do. Returns
    /// whether the entry was added.
    pub fn insert_blackhole_entry(
        &mut self,
        identity_hash: [u8; 16],
        entry: BlackholeEntry,
    ) -> bool {
        if self.blackholed_identities.contains_key(&identity_hash) {
            return false;
        }
        self.blackholed_identities.insert(identity_hash, entry);
        true
    }

    /// Remove an identity hash from the blackhole list.
    ///
    /// Returns `true` if an entry was removed, or `false` if the identity was
    /// not blackholed.
    pub fn unblackhole_identity(&mut self, identity_hash: &[u8; 16]) -> bool {
        self.blackholed_identities.remove(identity_hash).is_some()
    }

    /// Check if an identity hash is blackholed (and not expired). As
    /// upstream, an entry expires once its time has passed, not at it.
    pub fn is_blackholed(&self, identity_hash: &[u8; 16], now: f64) -> bool {
        if let Some(entry) = self.blackholed_identities.get(identity_hash) {
            if entry.expires == 0.0 || entry.expires >= now {
                return true;
            }
        }
        false
    }

    /// Get all blackhole entries (for queries).
    pub fn blackholed_entries(&self) -> impl Iterator<Item = (&[u8; 16], &BlackholeEntry)> {
        self.blackholed_identities.iter()
    }

    /// Cull expired blackhole entries: those whose time has passed, as
    /// upstream's `time.time() > until`.
    pub(super) fn cull_blackholed(&mut self, now: f64) {
        self.blackholed_identities
            .retain(|_, entry| entry.expires == 0.0 || entry.expires >= now);
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

        // Restore paths to path table if they're better than existing.
        // As upstream, a path that is not restored leaves the tunnel.
        let mut deprecated_paths = Vec::new();
        for (dest_hash, tunnel_path) in &restored_paths {
            let existing = self.path_table.get(dest_hash).and_then(|ps| ps.primary());
            let replaced = existing.map(|existing| existing.next_hop);
            let should_restore = match existing {
                Some(existing) => {
                    // Restore if fewer/equal hops or existing expired, but never
                    // overwrite a path learned from a more recent announce.
                    // With `unresponsive_path_recovery = native`,
                    // implausibly-future emission times are ignored
                    // (deliberate deviation from Python, see
                    // MAX_EMISSION_TIME_SKEW_SECS).
                    let recovery = self.config.unresponsive_path_recovery;
                    if tunnel_path.hops <= existing.hops || existing.expires < now {
                        let existing_timebase = selection_timebase_from_random_blobs(
                            &existing.random_blobs,
                            now,
                            recovery,
                        );
                        let tunnel_timebase = selection_timebase_from_random_blobs(
                            &tunnel_path.random_blobs,
                            now,
                            recovery,
                        );
                        tunnel_timebase >= existing_timebase
                    } else {
                        false
                    }
                }
                None => now < tunnel_path.expires,
            };

            if should_restore {
                // As upstream, the restored entry keeps when the path was
                // last used and drops duplicate random blobs.
                let mut random_blobs: Vec<[u8; 10]> = Vec::new();
                for blob in &tunnel_path.random_blobs {
                    if !random_blobs.contains(blob) {
                        random_blobs.push(*blob);
                    }
                }
                let entry = PathEntry {
                    timestamp: tunnel_path.timestamp,
                    next_hop: tunnel_path.received_from,
                    hops: tunnel_path.hops,
                    expires: tunnel_path.expires,
                    random_blobs,
                    receiving_interface: interface,
                    packet_hash: tunnel_path.packet_hash,
                    used: tunnel_path.used,
                    announce_raw: None,
                };
                // As upstream, the restored path takes the place of the one
                // it was judged against, even when that one ranks better.
                if let (Some(replaced), Some(paths)) =
                    (replaced, self.path_table.get_mut(dest_hash))
                {
                    paths.retain(|path| path.next_hop != replaced);
                }
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
                deprecated_paths.push(*dest_hash);
            }
        }

        if let Some(entry) = self.tunnel_table.get_mut(&tunnel_id) {
            for dest_hash in &deprecated_paths {
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Removing path to {:02x?} from tunnel {:02x?}",
                    &dest_hash[..4],
                    &tunnel_id[..4],
                );
                entry.paths.remove(dest_hash);
            }
        }

        actions.push(TransportAction::TunnelEstablished {
            tunnel_id,
            interface,
        });

        actions
    }

    /// Record that an interface received a tunnel synthesis. Returns false
    /// when it had already received one, which upstream 13b98a6b counts as
    /// a protocol violation.
    pub fn mark_synthesis_received(&mut self, interface: InterfaceId) -> bool {
        self.synthesis_received.insert(interface)
    }

    /// Record the transport node that synthesized a tunnel over an interface.
    pub fn set_remote_transport(&mut self, interface: InterfaceId, identity_hash: [u8; 16]) {
        self.remote_transports.insert(interface, identity_hash);
    }

    /// Record what the remote transport node reported about itself in its
    /// synthesis extension (upstream b7a93b9b).
    pub fn set_remote_transport_info(
        &mut self,
        interface: InterfaceId,
        info: tunnel::RemoteTransportInfo,
    ) {
        self.remote_transport_infos.insert(interface, info);
    }

    /// Forget an interface's tunnel synthesis state when it connects again:
    /// the remote transport and whether a synthesis was received or emitted.
    /// Upstream's dialing interfaces reset the remote transport and the
    /// received flag on each connect (b7a93b9b); the synthesis they then send
    /// sets the emitted flag again. What the remote reported about itself
    /// stays until its next synthesis replaces it, as upstream keeps the
    /// interface's `remote_impl`, `remote_vers` and costs.
    pub fn reset_tunnel_synthesis(&mut self, interface: InterfaceId) {
        self.remote_transports.remove(&interface);
        self.synthesis_received.remove(&interface);
        self.synthesis_emitted.remove(&interface);
    }

    /// Synthesize a tunnel on an interface.
    ///
    /// `identity`: the transport identity (must have private key for signing)
    /// `interface_id`: which interface to send the synthesis on
    /// `extension`: the signed extension after the signature (upstream
    /// b7a93b9b), empty for none
    /// `reverse`: whether this answers a synthesis received on the
    /// interface; a reverse synthesis records no local tunnel
    /// `rng`: random number generator
    ///
    /// Returns TunnelSynthesize action to send the synthesis packet.
    pub fn synthesize_tunnel(
        &mut self,
        identity: &rns_crypto::identity::Identity,
        interface_id: InterfaceId,
        extension: &[u8],
        reverse: bool,
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

        match tunnel::build_tunnel_synthesize_data(identity, &interface_hash, extension, rng) {
            Ok((data, tunnel_id)) => {
                if !reverse {
                    self.local_tunnel_ids.insert(interface_id, tunnel_id);
                }
                self.synthesis_emitted.insert(interface_id);
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

    /// Void a tunnel whose interface was removed; it waits
    /// `TUNNEL_RECONNECT_WINDOW` to be synthesized again.
    pub fn release_tunnel_interface(&mut self, tunnel_id: &[u8; 32], now: f64) {
        self.tunnel_table.release_tunnel_interface(tunnel_id, now);
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

    /// Whether `iface` is a local client this engine serves as a shared
    /// instance (Transport.py `from_local_client`). A shared client also
    /// flags its interface to the daemon as a local client, but it has no
    /// transport identity.
    pub(super) fn serves_local_client(&self, iface: InterfaceId) -> bool {
        self.config.identity_hash.is_some() && self.interface_is_local_client(iface)
    }

    pub(super) fn serves_local_clients(&self) -> bool {
        self.config.identity_hash.is_some() && self.has_local_clients()
    }

    /// Packet filter: dedup + basic validity.
    ///
    /// Transport.py:1187-1238
    #[cfg(test)]
    pub(super) fn packet_filter<B: AsRef<[u8]>>(&self, packet: &RawPacket<B>) -> bool {
        self.packet_filter_at_hops(packet, packet.hops)
    }

    pub(super) fn packet_filter_at_hops<B: AsRef<[u8]>>(
        &self,
        packet: &RawPacket<B>,
        hops: u8,
    ) -> bool {
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
                return hops <= 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketFlags;
    use crate::transport::tests::{
        make_config, make_interface, make_path_entry, make_random_blob, make_tunnel_interface,
    };
    use crate::transport::tunnel::TunnelPath;

    #[test]
    fn blackhole_lasts_through_its_expiry_time() {
        let mut engine = TransportEngine::new(make_config(true));
        let identity = [0x11; 16];
        assert!(engine.blackhole_identity(identity, 1000.0, Some(2.0), None));
        let expires = 1000.0 + 2.0 * 3600.0;
        assert!(engine.is_blackholed(&identity, expires - 100.0));
        assert!(engine.is_blackholed(&identity, expires));
        assert!(!engine.is_blackholed(&identity, expires + 1.0));

        engine.cull_blackholed(expires);
        assert_eq!(engine.blackholed_entries().count(), 1);
        engine.cull_blackholed(expires + 1.0);
        assert_eq!(engine.blackholed_entries().count(), 0);
    }

    #[test]
    fn blackhole_without_positive_duration_never_expires() {
        let mut engine = TransportEngine::new(make_config(true));
        for (n, duration) in [(1u8, None), (2, Some(0.0)), (3, Some(-1.0))] {
            let identity = [n; 16];
            assert!(engine.blackhole_identity(identity, 1000.0, duration, None));
            assert!(engine.is_blackholed(&identity, 1e12), "{duration:?}");
        }
        engine.cull_blackholed(1e12);
        assert_eq!(engine.blackholed_entries().count(), 3);
    }

    #[test]
    fn deregistering_an_interface_drops_only_its_pending_path_requests() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        engine
            .pending_local_path_requests
            .insert([1; 16], (InterfaceId(1), 10.0));
        engine
            .pending_local_path_requests
            .insert([2; 16], (InterfaceId(2), 10.0));
        engine.deregister_interface(InterfaceId(1));
        assert_eq!(
            engine
                .pending_local_path_requests
                .keys()
                .collect::<Vec<_>>(),
            [&[2; 16]]
        );
    }

    #[test]
    fn next_hop_is_the_primary_paths() {
        let mut engine = TransportEngine::new(make_config(true));
        let dest = [0xD1; 16];
        assert_eq!(engine.next_hop(&dest), None);
        engine.upsert_path_destination(
            dest,
            make_path_entry(1000.0, 2, InterfaceId(1), [0x77; 16]),
            1000.0,
        );
        assert_eq!(engine.next_hop(&dest), Some([0x77; 16]));
    }

    /// An unresponsive primary path with an alternative fails over to it
    /// instead of marking the destination unresponsive.
    #[test]
    fn unresponsive_primary_fails_over_to_alternative() {
        let mut config = make_config(true);
        config.max_paths_per_destination = 2;
        let mut engine = TransportEngine::new(config);
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        let dest = [0xD2; 16];
        let mut paths =
            PathSet::from_single(make_path_entry(1000.0, 1, InterfaceId(1), [0x01; 16]), 2);
        paths.upsert(make_path_entry(1000.0, 2, InterfaceId(1), [0x02; 16]));
        engine.path_table.insert(dest, paths);

        engine.mark_path_unresponsive(&dest, Some(InterfaceId(1)));
        assert_eq!(engine.next_hop(&dest), Some([0x02; 16]));
        assert!(!engine.path_is_unresponsive(&dest));
    }

    #[test]
    fn rebalancing_destination_hops_reports_whether_a_path_changed() {
        let mut engine = TransportEngine::new(make_config(true));
        let dest = [0xD3; 16];
        assert!(!engine.rebalance_destination_path_hops(&dest, 4));
        engine.upsert_path_destination(
            dest,
            make_path_entry(1000.0, 2, InterfaceId(1), [0x77; 16]),
            1000.0,
        );
        assert!(engine.rebalance_destination_path_hops(&dest, 4));
        assert_eq!(engine.hops_to(&dest), Some(4));
    }

    fn lrproof_frame(link_id: &[u8; 16], packet_type: u8, context: u8) -> Vec<u8> {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type,
        };
        RawPacket::pack(flags, 0, link_id, None, context, &[0x5A; 99])
            .unwrap()
            .raw
    }

    /// An LRPROOF whose hops disagree with an unvalidated relayed link,
    /// arriving from the link's next hop, is offered for rebalancing with
    /// its post-ingress hop count; other packets for the link are not.
    #[test]
    fn lrproof_rebalance_candidate_is_only_a_mismatched_lrproof() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        let link_id = [0x4C; 16];
        let dest = [0xD4; 16];
        engine.register_link(
            link_id,
            LinkEntry {
                timestamp: 1000.0,
                next_hop_transport_id: [0x33; 16],
                next_hop_interface: InterfaceId(2),
                remaining_hops: 3,
                received_interface: InterfaceId(1),
                taken_hops: 1,
                destination_hash: dest,
                validated: false,
                proof_timeout: 2000.0,
                traffic: 0,
            },
        );

        let proof = lrproof_frame(
            &link_id,
            constants::PACKET_TYPE_PROOF,
            constants::CONTEXT_LRPROOF,
        );
        let candidate = engine
            .inbound_lrproof_rebalance_candidate(&proof, InterfaceId(2))
            .expect("mismatched LRPROOF is a candidate");
        assert_eq!(candidate.0, link_id);
        assert_eq!(candidate.1, dest);
        assert_eq!(candidate.2, 1);
        assert_eq!(candidate.3, vec![0x5A; 99]);

        for (packet_type, context) in [
            (constants::PACKET_TYPE_DATA, constants::CONTEXT_LRPROOF),
            (constants::PACKET_TYPE_PROOF, constants::CONTEXT_NONE),
        ] {
            let frame = lrproof_frame(&link_id, packet_type, context);
            assert!(engine
                .inbound_lrproof_rebalance_candidate(&frame, InterfaceId(2))
                .is_none());
        }
    }

    fn tunnel_path(hops: u8, expires: f64, blob_time: u64) -> TunnelPath {
        TunnelPath {
            timestamp: 1000.0,
            received_from: TUNNEL_HOP,
            hops,
            expires,
            random_blobs: vec![make_random_blob(blob_time)],
            packet_hash: [0xFF; 32],
            used: 0.0,
        }
    }

    /// Next hop of the tunnel's path.
    const TUNNEL_HOP: [u8; 16] = [0xEE; 16];
    /// Next hop of the path already in the table.
    const EXISTING_HOP: [u8; 16] = [0xAB; 16];

    /// Reattach a tunnel holding `path` for a destination at `now`, with
    /// `existing` in the path table, and return the next hop of the
    /// resulting path and whether the tunnel still holds its path.
    fn restore(
        existing: Option<PathEntry>,
        path: TunnelPath,
        now: f64,
    ) -> (Option<[u8; 16]>, bool) {
        restore_with(
            crate::transport::types::UnresponsivePathRecovery::Native,
            existing,
            path,
            now,
        )
    }

    /// [`restore`] under `unresponsive_path_recovery = recovery`.
    fn restore_with(
        recovery: crate::transport::types::UnresponsivePathRecovery,
        existing: Option<PathEntry>,
        path: TunnelPath,
        now: f64,
    ) -> (Option<[u8; 16]>, bool) {
        let mut engine = TransportEngine::new(make_config(true));
        engine.config.unresponsive_path_recovery = recovery;
        engine.register_interface(make_tunnel_interface(1));
        let tunnel_id = [0xCC; 32];
        let dest = [0xDD; 16];
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
        engine.tunnel_table.store_tunnel_path(
            &tunnel_id,
            dest,
            path,
            1000.0,
            constants::DESTINATION_TIMEOUT,
            usize::MAX,
        );
        engine.void_tunnel_interface(&tunnel_id);
        engine.path_table.remove(&dest);
        if let Some(existing) = existing {
            engine
                .path_table
                .insert(dest, PathSet::from_single(existing, 1));
        }
        engine.handle_tunnel(tunnel_id, InterfaceId(1), now);
        let tunnel = engine.tunnel_table().get(&tunnel_id).unwrap();
        (engine.next_hop(&dest), tunnel.paths.contains_key(&dest))
    }

    /// As upstream's handle_tunnel: a tunnel path replaces an existing one
    /// with as many hops or more, or an expired one, unless the existing
    /// path is more recent; with no existing path, it is restored until it
    /// expires. A path that is not restored leaves the tunnel; a restored
    /// one stays in it.
    #[test]
    fn tunnel_reattach_restores_paths_as_upstream() {
        let now = 2000.0;
        let existing = |hops: u8, expires: f64, blob_time: u64| PathEntry {
            random_blobs: vec![make_random_blob(blob_time)],
            expires,
            ..make_path_entry(1500.0, hops, InterfaceId(3), EXISTING_HOP)
        };
        let live = 5000.0;
        let cases = [
            // Fewer or as many hops as a live path: restored.
            (Some(existing(3, live, 100)), 2, Some(TUNNEL_HOP)),
            (Some(existing(2, live, 100)), 2, Some(TUNNEL_HOP)),
            // ... unless the live path comes from a more recent announce.
            (Some(existing(2, live, 200)), 2, Some(EXISTING_HOP)),
            // More hops than a live path, or one expiring now: kept.
            (Some(existing(1, live, 100)), 2, Some(EXISTING_HOP)),
            (Some(existing(1, now, 100)), 2, Some(EXISTING_HOP)),
            // More hops than an expired path: restored.
            (Some(existing(1, now - 1.0, 100)), 2, Some(TUNNEL_HOP)),
        ];
        for (n, (existing, hops, expected)) in cases.into_iter().enumerate() {
            let kept = expected == Some(TUNNEL_HOP);
            assert_eq!(
                restore(existing, tunnel_path(hops, live, 100), now),
                (expected, kept),
                "case {n}"
            );
        }
        // No path: restored only before the tunnel path expires.
        assert_eq!(
            restore(None, tunnel_path(2, now + 1.0, 100), now),
            (Some(TUNNEL_HOP), true)
        );
        assert_eq!(restore(None, tunnel_path(2, now, 100), now), (None, false));
    }

    /// An emission time implausibly far in the future: `native` ignores it
    /// when comparing a tunnel path with the existing path
    /// (`MAX_EMISSION_TIME_SKEW_SECS`), `upstream` trusts it as upstream does.
    #[test]
    fn tunnel_reattach_emission_time_filter_only_in_native_mode() {
        use crate::transport::pathfinder::MAX_EMISSION_TIME_SKEW_SECS;
        use crate::transport::types::UnresponsivePathRecovery::{Native, Upstream};
        let now = 2000.0;
        let far_future = now as u64 + MAX_EMISSION_TIME_SKEW_SECS + 1;
        let existing = |blob_time: u64| PathEntry {
            random_blobs: vec![make_random_blob(blob_time)],
            expires: 5000.0,
            ..make_path_entry(1500.0, 2, InterfaceId(3), EXISTING_HOP)
        };
        let cases = [
            // An existing path pinned by a far-future emission time.
            (Native, far_future, 100, TUNNEL_HOP),
            (Upstream, far_future, 100, EXISTING_HOP),
            // A tunnel path carrying one.
            (Native, 100, far_future, EXISTING_HOP),
            (Upstream, 100, far_future, TUNNEL_HOP),
        ];
        for (recovery, existing_time, tunnel_time, expected) in cases {
            assert_eq!(
                restore_with(
                    recovery,
                    Some(existing(existing_time)),
                    tunnel_path(2, 5000.0, tunnel_time),
                    now
                ),
                (Some(expected), expected == TUNNEL_HOP),
                "{recovery:?} existing {existing_time} tunnel {tunnel_time}"
            );
        }
    }

    /// As upstream, a restored path keeps when it was last used and drops
    /// duplicate random blobs.
    #[test]
    fn tunnel_reattach_keeps_use_time_and_drops_duplicate_blobs() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));
        let tunnel_id = [0xCC; 32];
        let dest = [0xDD; 16];
        let (first, second) = (make_random_blob(100), make_random_blob(90));
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
        engine.tunnel_table.store_tunnel_path(
            &tunnel_id,
            dest,
            TunnelPath {
                random_blobs: vec![first, second, first, second],
                used: 1500.0,
                ..tunnel_path(2, 5000.0, 100)
            },
            1000.0,
            constants::DESTINATION_TIMEOUT,
            usize::MAX,
        );
        engine.void_tunnel_interface(&tunnel_id);
        engine.path_table.remove(&dest);
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 2000.0);
        let restored = engine.path_table[&dest].primary().unwrap();
        assert_eq!(restored.used, 1500.0);
        assert_eq!(restored.random_blobs, vec![first, second]);
    }

    /// The tunnel keeps the paths it restores and drops the others, and
    /// stays in the table even when none is left.
    #[test]
    fn tunnel_reattach_drops_only_the_paths_it_does_not_restore() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));
        let tunnel_id = [0xCC; 32];
        let restored = [0xD1; 16];
        let beaten = [0xD2; 16];
        let expired = [0xD3; 16];
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
        for (dest, path) in [
            (restored, tunnel_path(2, 5000.0, 100)),
            (beaten, tunnel_path(2, 5000.0, 100)),
            (expired, tunnel_path(2, 1500.0, 100)),
        ] {
            engine.tunnel_table.store_tunnel_path(
                &tunnel_id,
                dest,
                path,
                1000.0,
                constants::DESTINATION_TIMEOUT,
                usize::MAX,
            );
        }
        engine.void_tunnel_interface(&tunnel_id);
        for dest in [restored, beaten, expired] {
            engine.path_table.remove(&dest);
        }
        engine.path_table.insert(
            beaten,
            PathSet::from_single(
                PathEntry {
                    random_blobs: vec![make_random_blob(100)],
                    expires: 5000.0,
                    ..make_path_entry(1500.0, 1, InterfaceId(3), EXISTING_HOP)
                },
                1,
            ),
        );

        engine.handle_tunnel(tunnel_id, InterfaceId(1), 2000.0);
        let paths = &engine.tunnel_table().get(&tunnel_id).unwrap().paths;
        assert_eq!(paths.keys().copied().collect::<Vec<_>>(), vec![restored]);
        assert_eq!(engine.next_hop(&restored), Some(TUNNEL_HOP));
        assert_eq!(engine.next_hop(&beaten), Some(EXISTING_HOP));
        assert_eq!(engine.next_hop(&expired), None);

        // Reattached again with nothing to restore, the tunnel stays.
        engine.void_tunnel_interface(&tunnel_id);
        engine.path_table.remove(&restored);
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 6000.0);
        let entry = engine.tunnel_table().get(&tunnel_id).unwrap();
        assert!(entry.paths.is_empty());
        assert_eq!(entry.interface, Some(InterfaceId(1)));
    }

    #[test]
    fn synthesis_state_is_recorded_and_reset_per_interface() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));
        let iface = InterfaceId(1);
        assert!(engine.mark_synthesis_received(iface));
        assert!(!engine.mark_synthesis_received(iface));

        engine.set_remote_transport(iface, [0x77; 16]);
        assert_eq!(engine.remote_transport(&iface), Some([0x77; 16]));
        let info = tunnel::RemoteTransportInfo {
            implementation: "rns".into(),
            version: vec![1, 2, 3],
            is_transport: true,
            destination_cost: Default::default(),
            pr_cost: Default::default(),
        };
        engine.set_remote_transport_info(iface, info.clone());
        assert_eq!(engine.remote_transport_info(&iface), Some(&info));

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
        let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
        engine.synthesize_tunnel(&identity, iface, &[], false, &mut rng);
        assert!(engine.synthesis_emitted(&iface));

        engine.reset_tunnel_synthesis(iface);
        assert_eq!(engine.remote_transport(&iface), None);
        assert!(!engine.synthesis_emitted(&iface));
        assert!(engine.mark_synthesis_received(iface));
        // What the remote reported stays until its next synthesis.
        assert_eq!(engine.remote_transport_info(&iface), Some(&info));
    }

    /// A reverse synthesis answers the remote's and records no local tunnel.
    #[test]
    fn only_a_forward_synthesis_records_a_local_tunnel() {
        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
        for reverse in [false, true] {
            let mut engine = TransportEngine::new(make_config(true));
            engine.register_interface(make_tunnel_interface(1));
            let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
            engine.synthesize_tunnel(&identity, InterfaceId(1), &[], reverse, &mut rng);
            assert_eq!(engine.local_tunnel_id(&InterfaceId(1)).is_some(), !reverse);
        }
    }

    #[test]
    fn released_tunnel_waits_the_reconnect_window() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));
        let tunnel_id = [0xCE; 32];
        engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
        engine.release_tunnel_interface(&tunnel_id, 1500.0);
        let entry = engine.tunnel_table().get(&tunnel_id).unwrap();
        assert_eq!(entry.interface, None);
        assert_eq!(entry.expires, 1500.0 + constants::TUNNEL_RECONNECT_WINDOW);
    }
}
