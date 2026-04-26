use super::*;

impl TransportEngine {
    pub(crate) fn insert_discovery_pr_tag(&mut self, unique_tag: [u8; 32]) -> bool {
        if self.discovery_pr_tag_set.contains(&unique_tag) {
            return false;
        }
        if self.config.max_discovery_pr_tags != usize::MAX
            && self.discovery_pr_tags.len() >= self.config.max_discovery_pr_tags
        {
            if let Some(evicted) = self.discovery_pr_tags.pop_front() {
                self.discovery_pr_tag_set.remove(&evicted);
            }
        }
        self.discovery_pr_tags.push_back(unique_tag);
        self.discovery_pr_tag_set.insert(unique_tag);
        true
    }

    pub(crate) fn upsert_path_destination(
        &mut self,
        dest_hash: [u8; 16],
        entry: PathEntry,
        now: f64,
    ) {
        let max_paths = self.config.max_paths_per_destination;
        if let Some(ps) = self.path_table.get_mut(&dest_hash) {
            ps.upsert(entry);
            return;
        }
        self.enforce_path_destination_cap(now);
        self.path_table
            .insert(dest_hash, PathSet::from_single(entry, max_paths));
    }

    pub(crate) fn enforce_path_destination_cap(&mut self, now: f64) {
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
            self.path_destination_cap_evict_count += 1;
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

    pub(crate) fn announce_entry_size_bytes(entry: &AnnounceEntry) -> usize {
        size_of::<AnnounceEntry>() + entry.packet_raw.capacity() + entry.packet_data.capacity()
    }

    pub(crate) fn announce_retained_bytes_total(&self) -> usize {
        self.announce_table
            .values()
            .chain(self.held_announces.values())
            .map(Self::announce_entry_size_bytes)
            .sum()
    }

    pub(crate) fn cull_expired_announce_entries(&mut self, now: f64) -> usize {
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

    pub(crate) fn enforce_announce_retention_cap(&mut self, now: f64) {
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

    pub(crate) fn insert_announce_entry(
        &mut self,
        dest_hash: [u8; 16],
        entry: AnnounceEntry,
        now: f64,
    ) -> bool {
        self.cull_expired_announce_entries(now);
        if Self::announce_entry_size_bytes(&entry) > self.config.announce_table_max_bytes {
            return false;
        }
        self.announce_table.insert(dest_hash, entry);
        self.enforce_announce_retention_cap(now);
        self.announce_table.contains_key(&dest_hash)
    }

    pub(crate) fn insert_held_announce(
        &mut self,
        dest_hash: [u8; 16],
        entry: AnnounceEntry,
        now: f64,
    ) -> bool {
        self.cull_expired_announce_entries(now);
        if Self::announce_entry_size_bytes(&entry) > self.config.announce_table_max_bytes {
            return false;
        }
        self.held_announces.insert(dest_hash, entry);
        self.enforce_announce_retention_cap(now);
        self.held_announces.contains_key(&dest_hash)
    }
}
