use super::*;

/// At the path destination cap, evict down to `cap - cap / DIVISOR` (at
/// least one below the cap), so the next inserts find room without another
/// cull.
const PATH_CAP_EVICT_BATCH_DIVISOR: usize = 32;

impl TransportEngine {
    pub(crate) fn insert_discovery_pr_tag(&mut self, unique_tag: [u8; 32]) -> bool {
        self.path_requests
            .insert_discovery_tag(unique_tag, self.config.max_discovery_pr_tags)
    }

    pub(crate) fn upsert_path_destination(
        &mut self,
        dest_hash: [u8; 16],
        entry: PathEntry,
        now: f64,
    ) {
        let max_paths = self.config.max_paths_per_destination;
        if let Some(ps) = self.paths.table.get_mut(&dest_hash) {
            ps.upsert(entry);
            return;
        }
        self.enforce_path_destination_cap(now);
        self.paths
            .table
            .insert(dest_hash, PathSet::from_single(entry, max_paths));
    }

    pub(crate) fn upsert_primary_path_destination(
        &mut self,
        dest_hash: [u8; 16],
        entry: PathEntry,
        now: f64,
    ) {
        let max_paths = self.config.max_paths_per_destination;
        if let Some(path_set) = self.paths.table.get_mut(&dest_hash) {
            path_set.upsert_primary(entry);
            return;
        }
        self.enforce_path_destination_cap(now);
        self.paths
            .table
            .insert(dest_hash, PathSet::from_single(entry, max_paths));
    }

    /// Replace the primary path to `dest_hash` with `entry`, whatever its
    /// next hop (`unresponsive_path_recovery = upstream`).
    pub(crate) fn replace_primary_path_destination(
        &mut self,
        dest_hash: [u8; 16],
        entry: PathEntry,
        now: f64,
    ) {
        if let Some(path_set) = self.paths.table.get_mut(&dest_hash) {
            path_set.replace_primary(entry);
            return;
        }
        self.upsert_primary_path_destination(dest_hash, entry, now);
    }

    /// Linger time for never-used paths on this instance.
    pub(crate) fn unused_path_linger(&self) -> f64 {
        if self.config.transport_enabled {
            constants::UNUSED_PATH_LINGER
        } else {
            constants::UNUSED_PATH_LINGER_LEAF
        }
    }

    /// Make room for a new destination when the path table is at
    /// `max_path_destinations`; below the cap this does nothing, and expiry
    /// and the never-used pool trim are left to the periodic table cull.
    ///
    /// At the cap, the table is culled as the periodic job does, then, if
    /// still above the low-water mark, the oldest destinations are evicted
    /// down to it in one pass. Evicting a batch instead of a single entry
    /// keeps a flood of new destinations at the cap from culling and
    /// scanning the whole table on every insert.
    pub(crate) fn enforce_path_destination_cap(&mut self, now: f64) {
        let cap = self.config.max_path_destinations;
        if self.paths.table.len() < cap {
            return;
        }
        let unused_path_linger = self.unused_path_linger();
        // The cap is not upstream's, so neither is its cadence: trim the
        // never-used pool here whenever the cap is reached.
        jobs::cull_path_table(
            &mut self.paths.table,
            &self.interfaces,
            now,
            unused_path_linger,
            Some(jobs::UnusedPoolLimits::UPSTREAM),
            self.policy.hop_limiter,
        );
        let low_water = cap.saturating_sub((cap / PATH_CAP_EVICT_BATCH_DIVISOR).max(1));
        let excess = self.paths.table.len().saturating_sub(low_water);
        if excess == 0 {
            return;
        }
        let mut candidates: Vec<(f64, u8, [u8; 16])> = self
            .paths
            .table
            .iter()
            .filter_map(|(dest_hash, path_set)| {
                path_set
                    .primary()
                    .map(|primary| (primary.timestamp, primary.hops, *dest_hash))
            })
            .collect();
        // Oldest first; among equally old, more hops first, then hash order.
        let oldest_first = |a: &(f64, u8, [u8; 16]), b: &(f64, u8, [u8; 16])| {
            a.0.total_cmp(&b.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.cmp(&b.2))
        };
        let evict = excess.min(candidates.len());
        if evict == 0 {
            return;
        }
        if evict < candidates.len() {
            candidates.select_nth_unstable_by(evict - 1, oldest_first);
        }
        for (_, _, dest_hash) in candidates.into_iter().take(evict) {
            self.paths.table.remove(&dest_hash);
            self.paths.states.remove(&dest_hash);
            self.paths.cap_evict_count += 1;
        }
    }

    pub(crate) fn announce_entry_size_bytes(entry: &AnnounceEntry) -> usize {
        size_of::<AnnounceEntry>()
            + entry.packet_raw.capacity()
            + entry.packet_data.capacity()
            + entry.blocked_interfaces.len() * size_of::<InterfaceId>()
    }

    pub(crate) fn announce_retained_bytes_total(&self) -> usize {
        self.announces
            .table
            .values()
            .chain(self.announces.held.values())
            .map(Self::announce_entry_size_bytes)
            .sum()
    }

    pub(crate) fn cull_expired_announce_entries(&mut self, now: f64) -> usize {
        let ttl = self.config.announce_table_ttl_secs;
        let mut removed = 0usize;

        self.announces.table.retain(|_, entry| {
            let keep = now <= entry.timestamp + ttl;
            if !keep {
                removed += 1;
            }
            keep
        });

        self.announces.held.retain(|_, entry| {
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
            .announces
            .table
            .iter()
            .map(|(dest_hash, entry)| (*dest_hash, false, entry.timestamp))
            .min_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(core::cmp::Ordering::Equal));
        let oldest_held = self
            .announces
            .held
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
                self.announces.held.remove(&dest_hash);
            } else {
                self.announces.table.remove(&dest_hash);
            }
        }
    }

    pub(crate) fn insert_announce_entry(
        &mut self,
        dest_hash: [u8; 16],
        mut entry: AnnounceEntry,
        now: f64,
    ) -> bool {
        self.cull_expired_announce_entries(now);
        if Self::announce_entry_size_bytes(&entry) > self.config.announce_table_max_bytes {
            return false;
        }
        // Refresh the payload without letting incoming traffic repeatedly move
        // pending work beyond the next maintenance tick. Completed entries no
        // longer have a send to preserve; expired entries were culled above.
        if let Some(pending) = self.announces.table.get(&dest_hash) {
            if pending.retries <= constants::PATHFINDER_R {
                entry.retransmit_timeout = entry.retransmit_timeout.min(pending.retransmit_timeout);
            }
        }
        self.announces.table.insert(dest_hash, entry);
        self.enforce_announce_retention_cap(now);
        self.announces.table.contains_key(&dest_hash)
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
        self.announces.held.insert(dest_hash, entry);
        self.enforce_announce_retention_cap(now);
        self.announces.held.contains_key(&dest_hash)
    }
}

#[cfg(test)]
#[path = "retention_tests.rs"]
mod tests;
