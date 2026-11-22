use super::*;

/// At the path destination cap, evict down to `cap - cap / DIVISOR` (at
/// least one below the cap), so the next inserts find room without another
/// cull.
const PATH_CAP_EVICT_BATCH_DIVISOR: usize = 32;

/// Over the announce retention cap, evict down to
/// `max - max / DIVISOR` bytes, so the next inserts fit without another
/// cull and sort.
const ANNOUNCE_CAP_EVICT_BATCH_DIVISOR: usize = 32;

/// At the reverse table cap, evict down to `cap - cap / DIVISOR` (at least
/// one below the cap), so the next inserts find room without another pass.
const REVERSE_CAP_EVICT_BATCH_DIVISOR: usize = 32;

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
    /// At the cap, expired, unavailable, lingering and excessive-hops paths
    /// are culled as the periodic job does, without trimming the never-used
    /// pool (that keeps upstream's cadence; trimming it here dropped all but
    /// `PATH_POOL_UNUSED_MAX` never-used paths each time the cap was hit).
    /// Then, if still above the low-water mark, destinations are evicted down
    /// to it in one pass: never-used ones first, oldest first. Evicting a
    /// batch instead of a single entry keeps a flood of new destinations at
    /// the cap from culling and scanning the whole table on every insert.
    pub(crate) fn enforce_path_destination_cap(&mut self, now: f64) {
        let cap = self.config.max_path_destinations;
        if self.paths.table.len() < cap {
            return;
        }
        let unused_path_linger = self.unused_path_linger();
        jobs::cull_path_table(
            &mut self.paths.table,
            &self.interfaces,
            now,
            unused_path_linger,
            None,
            self.policy.hop_limiter,
        );
        let low_water = cap.saturating_sub((cap / PATH_CAP_EVICT_BATCH_DIVISOR).max(1));
        let excess = self.paths.table.len().saturating_sub(low_water);
        if excess == 0 {
            return;
        }
        let mut candidates: Vec<(bool, f64, u8, [u8; 16])> = self
            .paths
            .table
            .iter()
            .filter_map(|(dest_hash, path_set)| {
                path_set.primary().map(|primary| {
                    (
                        primary.used != 0.0,
                        primary.timestamp,
                        primary.hops,
                        *dest_hash,
                    )
                })
            })
            .collect();
        // Never-used first, then oldest; among equally old, more hops first,
        // then hash order.
        type Candidate = (bool, f64, u8, [u8; 16]);
        let oldest_first = |a: &Candidate, b: &Candidate| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.total_cmp(&b.1))
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| a.3.cmp(&b.3))
        };
        let evict = excess.min(candidates.len());
        if evict == 0 {
            return;
        }
        if evict < candidates.len() {
            candidates.select_nth_unstable_by(evict - 1, oldest_first);
        }
        for (_, _, _, dest_hash) in candidates.into_iter().take(evict) {
            self.paths.table.remove(&dest_hash);
            self.paths.states.remove(&dest_hash);
            self.paths.cap_evict_count += 1;
        }
    }

    /// Make room for a reverse entry for `trunc_hash` when the reverse table
    /// is at `max_reverse_entries`; below the cap, or when the entry replaces
    /// one already there, this does nothing.
    #[inline]
    pub(crate) fn enforce_reverse_table_cap(&mut self, trunc_hash: &[u8; 16], now: f64) {
        if self.routes.reverse.len() >= self.config.max_reverse_entries
            && !self.routes.reverse.contains_key(trunc_hash)
        {
            self.evict_reverse_entries(now);
        }
    }

    /// Bring a full reverse table down to its low-water mark: entries the
    /// periodic cull would remove go first, then the oldest. An entry only
    /// routes the proof of a forwarded packet back, which comes soon after
    /// the packet or not at all, so the oldest are the least likely to be
    /// needed. Evicting a batch keeps a flood of forwarded packets at the
    /// cap from scanning the whole table on every insert.
    #[cold]
    #[inline(never)]
    fn evict_reverse_entries(&mut self, now: f64) {
        let cap = self.config.max_reverse_entries;
        jobs::cull_reverse_table(&mut self.routes.reverse, &self.interfaces, now);
        let low_water = cap.saturating_sub((cap / REVERSE_CAP_EVICT_BATCH_DIVISOR).max(1));
        let excess = self.routes.reverse.len().saturating_sub(low_water);
        if excess == 0 {
            return;
        }
        let mut candidates: Vec<(f64, [u8; 16])> = self
            .routes
            .reverse
            .iter()
            .map(|(hash, entry)| (entry.timestamp, *hash))
            .collect();
        // Oldest first; among equally old, hash order.
        let oldest_first =
            |a: &(f64, [u8; 16]), b: &(f64, [u8; 16])| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1));
        if excess < candidates.len() {
            candidates.select_nth_unstable_by(excess - 1, oldest_first);
        }
        for (_, hash) in candidates.into_iter().take(excess) {
            self.routes.reverse.remove(&hash);
            self.routes.reverse_cap_evict_count += 1;
        }
    }

    pub(crate) fn announce_entry_size_bytes(entry: &AnnounceEntry) -> usize {
        entry.retained_bytes()
    }

    pub(crate) fn announce_retained_bytes_total(&self) -> usize {
        self.announces.table.retained_bytes() + self.announces.held.retained_bytes()
    }

    /// Whether an announce entry has outlived the announce table TTL.
    fn announce_expired(&self, entry: &AnnounceEntry, now: f64) -> bool {
        now > entry.timestamp + self.config.announce_table_ttl_secs
    }

    pub(crate) fn cull_expired_announce_entries(&mut self, now: f64) -> usize {
        let ttl = self.config.announce_table_ttl_secs;
        let keep = |_: &[u8; 16], entry: &AnnounceEntry| now <= entry.timestamp + ttl;
        self.announces.table.retain(keep) + self.announces.held.retain(keep)
    }

    /// Bring the bytes retained by the announce table and held announces
    /// back under `announce_table_max_bytes`; under the cap this does
    /// nothing, and expiry is left to the periodic announce job.
    ///
    /// Over the cap, expired entries are culled, then the oldest entries
    /// (held before active on a tie) are evicted until the total is at the
    /// low-water mark, so a flood at the cap culls and sorts once per batch
    /// instead of on every insert.
    pub(crate) fn enforce_announce_retention_cap(&mut self, now: f64) {
        let max_bytes = self.config.announce_table_max_bytes;
        if self.announce_retained_bytes_total() <= max_bytes {
            return;
        }
        self.cull_expired_announce_entries(now);
        let low_water = max_bytes - max_bytes / ANNOUNCE_CAP_EVICT_BATCH_DIVISOR;
        if self.announce_retained_bytes_total() <= low_water {
            return;
        }
        let mut oldest: Vec<(f64, bool, [u8; 16])> = self
            .announces
            .table
            .iter()
            .map(|(dest_hash, entry)| (entry.timestamp, false, *dest_hash))
            .chain(
                self.announces
                    .held
                    .iter()
                    .map(|(dest_hash, entry)| (entry.timestamp, true, *dest_hash)),
            )
            .collect();
        oldest.sort_unstable_by(|a, b| {
            a.0.total_cmp(&b.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.cmp(&b.2))
        });
        for (_, is_held, dest_hash) in oldest {
            if self.announce_retained_bytes_total() <= low_water {
                break;
            }
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
        if Self::announce_entry_size_bytes(&entry) > self.config.announce_table_max_bytes
            || self.announce_expired(&entry, now)
        {
            return false;
        }
        // Refresh the payload without letting incoming traffic repeatedly move
        // pending work beyond the next maintenance tick. Completed and expired
        // entries no longer have a send to preserve.
        if let Some(pending) = self.announces.table.get(&dest_hash) {
            if pending.retries <= constants::PATHFINDER_R && !self.announce_expired(pending, now) {
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
        if Self::announce_entry_size_bytes(&entry) > self.config.announce_table_max_bytes
            || self.announce_expired(&entry, now)
        {
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
