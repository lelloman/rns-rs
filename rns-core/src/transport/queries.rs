use super::*;

impl TransportEngine {
    /// Return the slowest positive bitrate among registered interfaces.
    ///
    /// Returns `None` when no registered interface advertises a usable
    /// bitrate.
    pub fn lowest_interface_bitrate(&self) -> Option<u64> {
        super::path_requests::lowest_interface_bitrate(&self.interfaces)
    }

    /// Estimate a path-request round-trip timeout for the slowest medium.
    ///
    /// The estimate covers two MTU transmissions at the slowest registered
    /// positive bitrate plus the per-hop link-establishment allowance. It is
    /// zero when no usable interface bitrate is known.
    pub fn medium_path_timeout(&self) -> f64 {
        super::path_requests::medium_path_timeout(&self.interfaces)
    }

    pub fn path_table_entries(&self) -> impl Iterator<Item = (&[u8; 16], &PathEntry)> {
        self.path_table
            .iter()
            .filter_map(|(k, ps)| ps.primary().map(|e| (k, e)))
    }

    pub fn path_table_sets(&self) -> impl Iterator<Item = (&[u8; 16], &PathSet)> {
        self.path_table.iter()
    }

    pub fn interface_count(&self) -> usize {
        self.interfaces.len()
    }

    pub fn link_table_count(&self) -> usize {
        self.link_table.len()
    }

    pub fn active_link_count(&self) -> usize {
        self.link_table
            .values()
            .filter(|entry| entry.validated)
            .count()
    }

    pub fn is_unvalidated_link_packet<B: AsRef<[u8]>>(
        &self,
        packet: &crate::packet::RawPacket<B>,
    ) -> bool {
        packet.flags.packet_type != crate::constants::PACKET_TYPE_ANNOUNCE
            && packet.flags.packet_type != crate::constants::PACKET_TYPE_LINKREQUEST
            && packet.context != crate::constants::CONTEXT_LRPROOF
            && self
                .link_table
                .get(&packet.destination_hash)
                .is_some_and(|entry| !entry.validated)
    }

    /// Classify packet-filter rejections that are peer protocol violations.
    pub fn is_packet_filter_protocol_violation<B: AsRef<[u8]>>(
        &self,
        packet: &crate::packet::RawPacket<B>,
        interface: InterfaceId,
    ) -> bool {
        let mut hops = packet.hops.saturating_add(1);
        if self.interface_is_local_client(interface) {
            hops = hops.saturating_sub(1);
        }
        if packet.flags.packet_type == crate::constants::PACKET_TYPE_ANNOUNCE {
            return packet.flags.destination_type != crate::constants::DESTINATION_SINGLE;
        }
        (packet.flags.destination_type == crate::constants::DESTINATION_PLAIN
            || packet.flags.destination_type == crate::constants::DESTINATION_GROUP)
            && hops > 1
    }

    pub fn path_table_count(&self) -> usize {
        self.path_table.len()
    }

    pub fn announce_table_count(&self) -> usize {
        self.announce_table.len()
    }

    pub fn reverse_table_count(&self) -> usize {
        self.reverse_table.len()
    }

    pub fn held_announces_count(&self) -> usize {
        self.held_announces.len()
    }

    pub fn packet_hashlist_len(&self) -> usize {
        self.packet_hashlist.len()
    }

    /// Start loading the deduplication state for `packet_hash`, so the
    /// inbound filter's lookup of a just-decoded packet overlaps that cache
    /// miss with the driver's admission checks. It has no other effect.
    pub fn prefetch_packet_hash(&self, packet_hash: &[u8; 32]) {
        self.packet_hashlist.prefetch(packet_hash);
    }

    /// Remove a packet hash from deduplication after an interface failover race.
    ///
    /// Network drivers should call this when an active-link packet arrives on
    /// the link's former interface, allowing the same packet to be accepted
    /// later on its current route.
    #[doc(hidden)]
    pub fn forget_packet_hash(&mut self, packet_hash: &[u8; 32]) -> bool {
        self.packet_hashlist.remove(packet_hash)
    }

    pub fn announce_sig_cache_len(&self) -> usize {
        self.announce_sig_cache.len()
    }

    pub fn rate_limiter_count(&self) -> usize {
        self.rate_limiter.len()
    }

    pub fn blackholed_count(&self) -> usize {
        self.blackholed_identities.len()
    }

    pub fn tunnel_count(&self) -> usize {
        self.tunnel_table.len()
    }

    pub fn discovery_pr_tags_count(&self) -> usize {
        self.discovery_pr_tags.len()
    }

    #[cfg(test)]
    pub(crate) fn has_discovery_pr_tag(&self, unique_tag: &[u8; 32]) -> bool {
        self.discovery_pr_tag_set.contains(unique_tag)
    }

    pub fn discovery_path_requests_count(&self) -> usize {
        self.discovery_path_requests.len()
    }

    pub fn announce_queue_count(&self) -> usize {
        self.announce_queues.queue_count()
    }

    pub fn nonempty_announce_queue_count(&self) -> usize {
        self.announce_queues.nonempty_queue_count()
    }

    pub fn queued_announce_count(&self) -> usize {
        self.announce_queues.total_queued_announces()
    }

    pub fn queued_announce_bytes(&self) -> usize {
        self.announce_queues.total_queued_bytes()
    }

    pub fn announce_queue_interface_cap_drop_count(&self) -> u64 {
        self.announce_queues.interface_cap_drop_count()
    }

    pub fn local_destinations_count(&self) -> usize {
        self.local_destinations.len()
    }

    pub fn rate_limiter(&self) -> &AnnounceRateLimiter {
        &self.rate_limiter
    }

    pub fn interface_info(&self, id: &InterfaceId) -> Option<&InterfaceInfo> {
        self.interfaces.get(id)
    }

    /// The registered interfaces that can send.
    pub fn out_capable_interfaces(&self) -> impl Iterator<Item = InterfaceId> + '_ {
        self.interfaces
            .values()
            .filter(|info| info.out_capable)
            .map(|info| info.id)
    }

    pub fn redirect_path(&mut self, dest_hash: &[u8; 16], interface: InterfaceId, now: f64) {
        if let Some(entry) = self
            .path_table
            .get_mut(dest_hash)
            .and_then(|ps| ps.primary_mut())
        {
            entry.receiving_interface = interface;
            // A redirected path is a true one-hop path to the destination.
            // Retaining the previous transport as next_hop makes outbound
            // routing inject a HEADER_2 transport header for that stale peer.
            entry.next_hop = *dest_hash;
            entry.hops = 1;
            entry.timestamp = now;
            entry.expires = now + 3600.0;
        } else {
            self.upsert_path_destination(
                *dest_hash,
                PathEntry {
                    timestamp: now,
                    next_hop: *dest_hash,
                    hops: 1,
                    expires: now + 3600.0,
                    random_blobs: Vec::new(),
                    receiving_interface: interface,
                    packet_hash: [0u8; 32],
                    used: 0.0,
                    announce_raw: None,
                },
                now,
            );
        }
    }

    pub fn inject_path(&mut self, dest_hash: [u8; 16], entry: PathEntry) {
        self.upsert_path_destination(dest_hash, entry.clone(), entry.timestamp);
    }

    pub fn drop_path(&mut self, dest_hash: &[u8; 16]) -> bool {
        self.path_table.remove(dest_hash).is_some()
    }

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

    pub fn drop_reverse_for_interface(&mut self, interface: InterfaceId) -> usize {
        let before = self.reverse_table.len();
        self.reverse_table.retain(|_, entry| {
            entry.receiving_interface != interface && entry.outbound_interface != interface
        });
        before - self.reverse_table.len()
    }

    pub fn drop_links_for_interface(&mut self, interface: InterfaceId) -> usize {
        let before = self.link_table.len();
        self.link_table.retain(|_, entry| {
            entry.next_hop_interface != interface && entry.received_interface != interface
        });
        before - self.link_table.len()
    }

    pub fn drop_announce_queues(&mut self) {
        self.announce_table.clear();
        self.held_announces.clear();
        self.announce_queues = AnnounceQueues::new(self.config.announce_queue_max_interfaces);
        self.ingress_control.clear();
    }

    pub fn void_queues(&mut self) {
        self.drop_announce_queues();
        self.reverse_table.clear();
    }

    pub fn identity_hash(&self) -> Option<&[u8; 16]> {
        self.config.identity_hash.as_ref()
    }

    pub fn transport_enabled(&self) -> bool {
        self.config.transport_enabled
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    pub fn set_packet_hashlist_max_entries(&mut self, max_entries: usize) {
        self.config.packet_hashlist_max_entries = max_entries;
        let seed = self.packet_hashlist.hashing_seed();
        self.packet_hashlist =
            PacketHashlist::with_allocation(max_entries, self.config.packet_hashlist_allocation);
        if let Some(seed) = seed {
            self.packet_hashlist.seed_hashing(seed);
        }
    }

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
                    entry.used,
                    iface_name,
                ));
            }
        }
        result
    }

    /// Return (total destinations, never-used destinations) in the path pool.
    pub fn path_pool_counts(&self) -> (usize, usize) {
        let total = self.path_table.len();
        let unused = self
            .path_table
            .values()
            .filter(|paths| paths.primary().is_some_and(|path| path.used == 0.0))
            .count();
        (total, unused)
    }

    /// Count active and validated links per destination hash.
    pub fn link_distribution(&self) -> Vec<([u8; 16], usize, usize)> {
        let mut distribution: alloc::collections::BTreeMap<[u8; 16], (usize, usize)> =
            alloc::collections::BTreeMap::new();
        for entry in self.link_table.values() {
            let counts = distribution.entry(entry.destination_hash).or_default();
            counts.0 += 1;
            if entry.validated {
                counts.1 += 1;
            }
        }
        distribution
            .into_iter()
            .map(|(hash, (total, active))| (hash, total, active))
            .collect()
    }

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

    pub fn get_blackholed(&self) -> Vec<([u8; 16], f64, f64, Option<alloc::string::String>)> {
        self.blackholed_entries()
            .map(|(hash, entry)| (*hash, entry.created, entry.expires, entry.reason.clone()))
            .collect()
    }

    pub fn active_destination_hashes(&self) -> alloc::collections::BTreeSet<[u8; 16]> {
        self.path_table.keys().copied().collect()
    }

    pub fn path_destination_cap_evict_count(&self) -> usize {
        self.path_destination_cap_evict_count
    }

    pub fn active_packet_hashes(&self) -> Vec<[u8; 32]> {
        let mut hashes: Vec<[u8; 32]> = self
            .path_table
            .values()
            .flat_map(|ps| ps.iter().map(|p| p.packet_hash))
            .collect();

        hashes.extend(
            self.tunnel_table
                .iter()
                .flat_map(|(_, tunnel)| tunnel.paths.values().map(|p| p.packet_hash)),
        );
        hashes.sort_unstable();
        hashes.dedup();
        hashes
    }

    pub fn cull_rate_limiter(
        &mut self,
        active: &alloc::collections::BTreeSet<[u8; 16]>,
        now: f64,
        ttl_secs: f64,
    ) -> usize {
        self.rate_limiter.cull_stale(active, now, ttl_secs)
    }

    pub fn update_interface_freq(&mut self, id: InterfaceId, ia_freq: f64) {
        if let Some(info) = self.interfaces.get_mut(&id) {
            info.ia_freq = ia_freq;
        }
    }

    pub fn update_interface_freqs(
        &mut self,
        id: InterfaceId,
        ia_freq: f64,
        ia_samples: usize,
        ip_freq: f64,
        op_freq: f64,
        op_samples: usize,
    ) {
        if let Some(info) = self.interfaces.get_mut(&id) {
            info.ia_freq = ia_freq;
            info.ia_samples = ia_samples;
            info.ip_freq = ip_freq;
            info.op_freq = op_freq;
            info.op_samples = op_samples;
        }
    }

    /// The tunnel this node synthesized on an interface, if any (upstream
    /// 3281e283 `local_tunnel_id`).
    pub fn local_tunnel_id(&self, interface: &InterfaceId) -> Option<[u8; 32]> {
        self.local_tunnel_ids.get(interface).copied()
    }

    /// The transport identity hash of the node that synthesized a tunnel
    /// over an interface (upstream 464e7598 `remote_transport`).
    pub fn remote_transport(&self, interface: &InterfaceId) -> Option<[u8; 16]> {
        self.remote_transports.get(interface).copied()
    }

    /// What the remote transport node reported in its synthesis extension
    /// over `interface` (upstream b7a93b9b).
    pub fn remote_transport_info(
        &self,
        interface: &InterfaceId,
    ) -> Option<&tunnel::RemoteTransportInfo> {
        self.remote_transport_infos.get(interface)
    }

    /// Whether this node has sent a tunnel synthesis on `interface` since it
    /// connected (upstream b7a93b9b `synthesis_emitted`).
    pub fn synthesis_emitted(&self, interface: &InterfaceId) -> bool {
        self.synthesis_emitted.contains(interface)
    }

    /// The interface a tunnel id names: the one a remote node's tunnel is
    /// attached to, else the one this node synthesized it on (upstream
    /// 3281e283's detach by tunnel id).
    pub fn interface_for_tunnel_id(&self, tunnel_id: &[u8; 32]) -> Option<InterfaceId> {
        self.interfaces
            .iter()
            .find(|(_, info)| info.tunnel_id.as_ref() == Some(tunnel_id))
            .map(|(id, _)| *id)
            .or_else(|| {
                self.local_tunnel_ids
                    .iter()
                    .find(|(_, local)| *local == tunnel_id)
                    .map(|(id, _)| *id)
            })
    }

    pub fn held_announce_count(&self, interface: &InterfaceId) -> usize {
        self.ingress_control.held_count(interface)
    }

    /// Announces waiting in `interface`'s announce queue.
    pub fn queued_announce_count_for(&self, interface: &InterfaceId) -> usize {
        self.announce_queues.queued_for(interface)
    }

    /// Whether the inbound packet handled last was filtered: dropped where
    /// upstream's `preprocess_inbound` drops it (upstream 134dc677), by the
    /// destination type filter, an announce that does not unpack or verify,
    /// one ingress control holds (upstream 29dc449a; the release is charged
    /// through [`Self::take_released_traffic`]), drops or uses to replace a
    /// held announce, a
    /// blackholed identity, a failed stamp,
    /// or a path request that is a duplicate, fails its stamp or joins one
    /// in flight. Covers [`Self::handle_decoded_inbound_into`] and the path
    /// request it delivers, and [`Self::complete_verified_announce`];
    /// clears the flag.
    pub fn take_inbound_filtered(&mut self) -> bool {
        core::mem::take(&mut self.inbound_filtered)
    }

    /// Whether that packet was a filtered announce, counted in `afrxc`
    /// (upstream 819076c3): one ingress control drops or uses to replace a
    /// held announce, a type `required_destinations_only` rejects, a
    /// blackholed identity, or a failed stamp. Clears the flag.
    pub fn take_inbound_filtered_announce(&mut self) -> bool {
        core::mem::take(&mut self.inbound_filtered_announce)
    }

    /// Announces to count as received in `arxc`/`arxb`, as (interface,
    /// bytes): one ingress control took up (held or dropped) counts with no
    /// bytes, and a released one that was accepted with its size (upstream
    /// c850cdac). Clears the list.
    pub fn take_announce_receipts(&mut self) -> Vec<(InterfaceId, usize)> {
        core::mem::take(&mut self.announce_receipts)
    }

    /// The frames of held announces released since the last call, to charge
    /// to received or filtered bytes (upstream 29dc449a). Clears the list.
    pub fn take_released_traffic(&mut self) -> Vec<ReleasedTraffic> {
        core::mem::take(&mut self.released_traffic)
    }

    /// Paths with more hops than this are culled (`Transport.HOP_LIMITER`).
    pub fn hop_limiter(&self) -> u8 {
        self.hop_limiter
    }

    /// Set the hop limiter paths are culled against, from `[filter]
    /// hop_limiter`.
    pub fn set_hop_limiter(&mut self, hop_limiter: u8) {
        self.hop_limiter = hop_limiter;
    }

    pub fn burst_active(&self, interface: &InterfaceId) -> bool {
        self.ingress_control.burst_active(interface)
    }

    pub fn burst_activated(&self, interface: &InterfaceId) -> f64 {
        self.ingress_control.burst_activated(interface)
    }

    pub fn pr_burst_active(&self, interface: &InterfaceId) -> bool {
        self.ingress_control.pr_burst_active(interface)
    }

    pub fn pr_burst_activated(&self, interface: &InterfaceId) -> f64 {
        self.ingress_control.pr_burst_activated(interface)
    }

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

    /// Key the hashing of tables indexed by packet hashes, the reverse table
    /// and the deduplication table, with seeds drawn from `rng`. Packet hashes are chosen by whoever crafts the packets,
    /// so without a secret seed a sender could grind packets into one probe
    /// sequence and make every lookup in that table linear. Call this once
    /// with a cryptographic RNG after creating the engine; until then the
    /// tables use a fixed public seed.
    pub fn seed_table_hashing(&mut self, rng: &mut dyn Rng) {
        let mut seeds = [0u8; 16];
        rng.fill_bytes(&mut seeds);
        let (reverse_seed, dedup_seed) = seeds.split_at(8);
        let seed = |bytes: &[u8]| u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
        self.packet_hashlist.seed_hashing(seed(dedup_seed));
        let hasher = foldhash::fast::FixedState::with_seed(seed(reverse_seed));
        let mut table =
            tables::ReverseTable::with_capacity_and_hasher(self.reverse_table.len(), hasher);
        table.extend(self.reverse_table.drain());
        self.reverse_table = table;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn reverse_table(&self) -> &tables::ReverseTable {
        &self.reverse_table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketFlags, RawPacket};
    use crate::transport::tables::{RateEntry, ReverseEntry};
    use crate::transport::tests::{
        make_config, make_interface, make_local_client_interface, make_path_entry,
        make_tunnel_interface,
    };

    fn packet(
        destination_type: u8,
        packet_type: u8,
        hops: u8,
        dest: &[u8; 16],
        context: u8,
    ) -> RawPacket {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type,
            packet_type,
        };
        RawPacket::pack(flags, hops, dest, None, context, b"data").unwrap()
    }

    fn link(validated: bool, next_hop_interface: u64, received_interface: u64) -> LinkEntry {
        LinkEntry {
            timestamp: 1000.0,
            next_hop_transport_id: [0x33; 16],
            next_hop_interface: InterfaceId(next_hop_interface),
            remaining_hops: 1,
            received_interface: InterfaceId(received_interface),
            taken_hops: 1,
            destination_hash: [0xD0; 16],
            validated,
            proof_timeout: 2000.0,
        }
    }

    /// As upstream, link traffic other than announces, link requests and
    /// link request proofs is a protocol violation before its link is
    /// validated.
    #[test]
    fn unvalidated_link_packets_are_recognised_as_upstream() {
        let mut engine = TransportEngine::new(make_config(true));
        let pending = [0x01; 16];
        let validated = [0x02; 16];
        engine.register_link(pending, link(false, 1, 2));
        engine.register_link(validated, link(true, 1, 2));
        let link_type = constants::DESTINATION_LINK;
        let cases = [
            (
                packet(link_type, constants::PACKET_TYPE_DATA, 0, &pending, 0),
                true,
            ),
            (
                packet(link_type, constants::PACKET_TYPE_PROOF, 0, &pending, 0),
                true,
            ),
            (
                packet(link_type, constants::PACKET_TYPE_ANNOUNCE, 0, &pending, 0),
                false,
            ),
            (
                packet(
                    link_type,
                    constants::PACKET_TYPE_LINKREQUEST,
                    0,
                    &pending,
                    0,
                ),
                false,
            ),
            (
                packet(
                    link_type,
                    constants::PACKET_TYPE_PROOF,
                    0,
                    &pending,
                    constants::CONTEXT_LRPROOF,
                ),
                false,
            ),
            (
                packet(link_type, constants::PACKET_TYPE_DATA, 0, &validated, 0),
                false,
            ),
            (
                packet(link_type, constants::PACKET_TYPE_DATA, 0, &[0x03; 16], 0),
                false,
            ),
        ];
        for (n, (packet, expected)) in cases.iter().enumerate() {
            assert_eq!(
                engine.is_unvalidated_link_packet(packet),
                *expected,
                "case {n}"
            );
        }
    }

    /// As upstream's packet_filter: a transported PLAIN or GROUP packet,
    /// one arriving with more than one hop, and an announce for anything
    /// but a SINGLE destination are protocol violations.
    #[test]
    fn packet_filter_protocol_violations_are_classified_as_upstream() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_local_client_interface(2));
        let dest = [0x0D; 16];
        let data = constants::PACKET_TYPE_DATA;
        let announce = constants::PACKET_TYPE_ANNOUNCE;
        let cases = [
            (constants::DESTINATION_PLAIN, data, 0, 1, false),
            (constants::DESTINATION_PLAIN, data, 1, 1, true),
            (constants::DESTINATION_GROUP, data, 0, 1, false),
            (constants::DESTINATION_GROUP, data, 1, 1, true),
            // A local client's hops are not incremented.
            (constants::DESTINATION_PLAIN, data, 1, 2, false),
            (constants::DESTINATION_PLAIN, data, 2, 2, true),
            (constants::DESTINATION_SINGLE, data, 5, 1, false),
            (constants::DESTINATION_SINGLE, announce, 5, 1, false),
            (constants::DESTINATION_PLAIN, announce, 0, 1, true),
            (constants::DESTINATION_LINK, announce, 0, 1, true),
        ];
        for (n, (destination_type, packet_type, hops, iface, expected)) in
            cases.into_iter().enumerate()
        {
            let packet = packet(destination_type, packet_type, hops, &dest, 0);
            assert_eq!(
                engine.is_packet_filter_protocol_violation(&packet, InterfaceId(iface)),
                expected,
                "case {n}"
            );
        }
    }

    #[test]
    fn path_table_rows_respect_max_hops() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        for hops in 1..=3u8 {
            engine.upsert_path_destination(
                [hops; 16],
                make_path_entry(1000.0, hops, InterfaceId(1), [0x70 + hops; 16]),
                1000.0,
            );
        }
        let rows = engine.get_path_table(Some(2));
        assert_eq!(
            rows.iter().map(|row| row.0).collect::<Vec<_>>(),
            [[1; 16], [2; 16]]
        );
        let row = &rows[1];
        assert_eq!(
            (row.1, row.2, row.3, row.4, row.5, row.6.as_str()),
            (1000.0, [0x72; 16], 2, 11_000.0, 0.0, "test")
        );
        assert_eq!(engine.get_path_table(None).len(), 3);
        assert!(engine.get_path_table(Some(0)).is_empty());
    }

    #[test]
    fn path_pool_counts_never_used_paths() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.upsert_path_destination(
            [1; 16],
            make_path_entry(1000.0, 1, InterfaceId(1), [0x71; 16]),
            1000.0,
        );
        engine.upsert_path_destination(
            [2; 16],
            PathEntry {
                used: 1500.0,
                ..make_path_entry(1000.0, 1, InterfaceId(1), [0x72; 16])
            },
            1000.0,
        );
        engine.upsert_path_destination(
            [3; 16],
            make_path_entry(1000.0, 1, InterfaceId(1), [0x73; 16]),
            1000.0,
        );
        assert_eq!(engine.path_pool_counts(), (3, 2));
        assert_eq!(engine.active_destination_hashes().len(), 3);
    }

    #[test]
    fn redirected_path_is_a_fresh_one_hop_path() {
        let mut engine = TransportEngine::new(make_config(true));
        let dest = [0x0E; 16];
        engine.upsert_path_destination(
            dest,
            make_path_entry(1000.0, 4, InterfaceId(1), [0x71; 16]),
            1000.0,
        );
        // A known path is redirected, an unknown one created.
        for dest in [dest, [0x0F; 16]] {
            engine.redirect_path(&dest, InterfaceId(2), 2000.0);
            let path = engine.path_table[&dest].primary().unwrap();
            assert_eq!(
                (
                    path.hops,
                    path.next_hop,
                    path.receiving_interface,
                    path.timestamp,
                    path.expires
                ),
                (1, dest, InterfaceId(2), 2000.0, 5600.0)
            );
        }
    }

    #[test]
    fn dropping_an_interface_counts_what_it_removes() {
        let mut engine = TransportEngine::new(make_config(true));
        for (n, iface) in [(1u8, 1u64), (2, 1), (3, 2)] {
            engine.upsert_path_destination(
                [n; 16],
                make_path_entry(1000.0, 1, InterfaceId(iface), [0x70 + n; 16]),
                1000.0,
            );
        }
        assert_eq!(engine.drop_paths_for_interface(InterfaceId(1)), 2);
        assert_eq!(engine.path_table_count(), 1);

        for (n, (receiving, outbound)) in [(1, 2), (3, 1), (2, 3), (4, 5)].into_iter().enumerate() {
            engine.reverse_table.insert(
                [n as u8; 16],
                ReverseEntry {
                    receiving_interface: InterfaceId(receiving),
                    outbound_interface: InterfaceId(outbound),
                    timestamp: 1000.0,
                },
            );
        }
        assert_eq!(engine.drop_reverse_for_interface(InterfaceId(1)), 2);
        assert_eq!(engine.reverse_table_count(), 2);

        for (n, (next_hop, received)) in [(1, 2), (3, 1), (2, 3), (4, 5)].into_iter().enumerate() {
            engine.register_link([n as u8; 16], link(true, next_hop, received));
        }
        assert_eq!(engine.drop_links_for_interface(InterfaceId(1)), 2);
        assert_eq!(engine.link_table_count(), 2);
    }

    #[test]
    fn tunnel_ids_name_their_interfaces() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_tunnel_interface(1));
        engine.register_interface(make_tunnel_interface(2));
        let remote = [0xAA; 32];
        assert_eq!(engine.tunnel_count(), 0);
        engine.handle_tunnel(remote, InterfaceId(1), 1000.0);
        engine.handle_tunnel([0xAC; 32], InterfaceId(2), 1000.0);
        assert_eq!(engine.tunnel_count(), 2);
        assert_eq!(
            engine.interface_for_tunnel_id(&remote),
            Some(InterfaceId(1))
        );

        let identity =
            rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
        let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
        engine.synthesize_tunnel(&identity, InterfaceId(2), &[], false, &mut rng);
        let local = engine.local_tunnel_id(&InterfaceId(2)).unwrap();
        assert_eq!(engine.local_tunnel_id(&InterfaceId(1)), None);
        assert_eq!(engine.interface_for_tunnel_id(&local), Some(InterfaceId(2)));
        assert_eq!(engine.interface_for_tunnel_id(&[0xBB; 32]), None);
        assert!(engine.synthesis_emitted(&InterfaceId(2)));
        assert!(!engine.synthesis_emitted(&InterfaceId(1)));

        assert_eq!(engine.remote_transport(&InterfaceId(1)), None);
        engine.set_remote_transport(InterfaceId(1), [0x77; 16]);
        assert_eq!(engine.remote_transport(&InterfaceId(1)), Some([0x77; 16]));
        assert!(engine.remote_transport_info(&InterfaceId(1)).is_none());
    }

    #[test]
    fn counts_follow_the_tables() {
        let mut engine = TransportEngine::new(make_config(true));
        assert_eq!(engine.interface_count(), 0);
        assert_eq!(engine.local_destinations_count(), 0);
        assert_eq!(engine.blackholed_count(), 0);
        assert_eq!(engine.discovery_path_requests_count(), 0);
        assert_eq!(engine.path_destination_cap_evict_count(), 0);
        assert_eq!(engine.identity_hash(), Some(&[0x42; 16]));
        assert!(engine.transport_enabled());
        assert!(!TransportEngine::new(make_config(false)).transport_enabled());

        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(InterfaceInfo {
            out_capable: false,
            ..make_interface(2, constants::MODE_FULL)
        });
        engine.register_destination([1; 16], constants::DESTINATION_SINGLE);
        engine.register_destination([2; 16], constants::DESTINATION_SINGLE);
        engine.blackhole_identity([1; 16], 1000.0, None, None);
        engine.blackhole_identity([2; 16], 1000.0, Some(1.0), Some("spam".into()));
        for n in 1..=2u8 {
            engine.discovery_path_requests.insert(
                [n; 16],
                DiscoveryPathRequest {
                    timestamp: 1000.0,
                    requesting_interfaces: Vec::new(),
                    engaged: false,
                },
            );
        }
        assert_eq!(engine.interface_count(), 2);
        assert_eq!(
            engine.out_capable_interfaces().collect::<Vec<_>>(),
            [InterfaceId(1)]
        );
        assert_eq!(engine.local_destinations_count(), 2);
        assert_eq!(engine.blackholed_count(), 2);
        assert_eq!(
            engine.get_blackholed(),
            [
                ([1; 16], 1000.0, 0.0, None),
                ([2; 16], 1000.0, 4600.0, Some("spam".into()))
            ]
        );
        assert_eq!(engine.discovery_path_requests_count(), 2);
    }

    #[test]
    fn rate_table_rows_and_culling() {
        let mut engine = TransportEngine::new(make_config(true));
        assert_eq!(engine.rate_limiter_count(), 0);
        for (n, last) in [(1u8, 1000.0), (2, 1900.0)] {
            engine.rate_limiter.restore(
                [n; 16],
                RateEntry {
                    last,
                    rate_violations: u32::from(n),
                    blocked_until: 1500.0,
                    timestamps: vec![last],
                },
            );
        }
        assert_eq!(engine.rate_limiter_count(), 2);
        assert_eq!(engine.rate_limiter().len(), 2);
        assert_eq!(
            engine.get_rate_table(),
            [
                ([1; 16], 1000.0, 1, 1500.0, vec![1000.0]),
                ([2; 16], 1900.0, 2, 1500.0, vec![1900.0])
            ]
        );
        // Only the entry last seen before the horizon, and no longer
        // blocked, goes.
        let active = alloc::collections::BTreeSet::new();
        assert_eq!(engine.cull_rate_limiter(&active, 2000.0, 500.0), 1);
        assert_eq!(engine.rate_limiter_count(), 1);
    }

    #[test]
    fn announce_queue_counts() {
        let mut config = make_config(true);
        config.announce_queue_max_interfaces = 1;
        let mut engine = TransportEngine::new(config);
        let raw: PacketBytes = vec![0u8; 100].into();
        let gate = |engine: &mut TransportEngine, iface: u64, dest: u8| {
            engine.announce_queues.gate_announce(
                InterfaceId(iface),
                raw.clone(),
                [dest; 16],
                1,
                1000.0,
                1000.0,
                Some(1000),
                None,
                constants::ANNOUNCE_CAP,
            )
        };
        // The first is sent, the next two wait, and two more interfaces
        // exceed the queue cap.
        assert!(gate(&mut engine, 1, 1).is_some());
        assert!(gate(&mut engine, 1, 2).is_none());
        assert!(gate(&mut engine, 1, 3).is_none());
        assert!(gate(&mut engine, 2, 4).is_none());
        assert!(gate(&mut engine, 3, 5).is_none());
        assert_eq!(engine.queued_announce_count_for(&InterfaceId(1)), 2);
        assert_eq!(engine.queued_announce_count_for(&InterfaceId(2)), 0);
        assert_eq!(engine.queued_announce_bytes(), 200);
        assert_eq!(engine.announce_queue_interface_cap_drop_count(), 2);
    }

    #[test]
    fn interface_state_setters_and_getters() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.update_interface_freq(InterfaceId(1), 2.5);
        assert_eq!(engine.interface_info(&InterfaceId(1)).unwrap().ia_freq, 2.5);
        engine.update_interface_freqs(InterfaceId(1), 3.0, 7, 4.0, 5.0, 6);
        let info = engine.interface_info(&InterfaceId(1)).unwrap();
        assert_eq!(
            (
                info.ia_freq,
                info.ia_samples,
                info.ip_freq,
                info.op_freq,
                info.op_samples
            ),
            (3.0, 7, 4.0, 5.0, 6)
        );

        let default_limiter = engine.hop_limiter();
        engine.set_hop_limiter(default_limiter / 2);
        assert_eq!(engine.hop_limiter(), default_limiter / 2);
        engine.set_hop_limiter(7);
        assert_eq!(engine.hop_limiter(), 7);

        let config = crate::transport::types::IngressControlConfig::enabled();
        assert!(!engine.burst_active(&InterfaceId(1)));
        engine.ingress_control.should_ingress_limit(
            InterfaceId(1),
            &config,
            36.0,
            3,
            0.0,
            10_000.0,
        );
        engine.ingress_control.should_ingress_limit_pr(
            InterfaceId(1),
            &config,
            36.0,
            0.0,
            10_500.0,
        );
        assert!(engine.burst_active(&InterfaceId(1)));
        assert!(engine.pr_burst_active(&InterfaceId(1)));
        assert_eq!(engine.burst_activated(&InterfaceId(1)), 10_000.0);
        assert_eq!(engine.pr_burst_activated(&InterfaceId(1)), 10_500.0);
    }

    #[test]
    fn forgetting_a_packet_hash_reports_whether_it_was_retained() {
        let mut engine = TransportEngine::new(make_config(true));
        let hash = [0x5A; 32];
        assert!(!engine.forget_packet_hash(&hash));
        engine.packet_hashlist.add(hash);
        assert!(engine.forget_packet_hash(&hash));
        assert!(!engine.packet_hashlist.is_duplicate(&hash));
    }

    #[test]
    fn resizing_the_packet_hashlist_applies_the_new_limit() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.set_packet_hashlist_max_entries(2);
        assert_eq!(engine.config().packet_hashlist_max_entries, 2);
        for n in 1..=3u8 {
            engine.packet_hashlist.add([n; 32]);
        }
        assert_eq!(engine.packet_hashlist_len(), 2);
    }
}
