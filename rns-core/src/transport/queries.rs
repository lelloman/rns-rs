use super::*;

impl TransportEngine {
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
        self.packet_hashlist = PacketHashlist::new(max_entries);
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
                    iface_name,
                ));
            }
        }
        result
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
        self.path_table
            .values()
            .flat_map(|ps| ps.iter().map(|p| p.packet_hash))
            .collect()
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

    pub fn held_announce_count(&self, interface: &InterfaceId) -> usize {
        self.ingress_control.held_count(interface)
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

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn reverse_table(&self) -> &BTreeMap<[u8; 16], tables::ReverseEntry> {
        &self.reverse_table
    }
}
