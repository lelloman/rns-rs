//! The driver's cache of known destinations.

use super::*;

/// Known destinations: the identities learned from announces, keyed by
/// destination hash, with their retention limits and cleanup progress.
pub(crate) struct KnownDestinations {
    /// Cache of known announced identities and lifecycle state.
    pub(crate) entries: HashMap<[u8; 16], KnownDestinationState>,
    /// Fingerprints of the known destinations as last flushed to storage.
    pub(crate) flushed: HashMap<[u8; 16], u64>,
    /// TTL for known destinations without an active path, in seconds.
    pub(crate) ttl: f64,
    /// Maximum number of retained known destinations.
    pub(crate) max_entries: usize,
    /// Count of cap evictions since start.
    pub(crate) cap_evict_count: usize,
    /// Runtime-configurable cleanup interval.
    pub(crate) cleanup_interval_ticks: u32,
    /// Incremental cleanup pass, if one is active.
    pub(super) cleanup: Option<KnownDestinationCleanup>,
}

impl KnownDestinations {
    pub(crate) fn new(cleanup_interval_ticks: u32) -> Self {
        Self {
            entries: HashMap::new(),
            flushed: HashMap::new(),
            ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            cap_evict_count: 0,
            cleanup_interval_ticks,
            cleanup: None,
        }
    }
}

impl KnownDestinations {
    /// Remember the identity a destination announced. A new destination
    /// first makes room under the cap, sparing the destinations with an
    /// active path in `engine` and the `local_destinations`.
    pub(crate) fn upsert(
        &mut self,
        dest_hash: [u8; 16],
        announced: crate::destination::AnnouncedIdentity,
        engine: &TransportEngine,
        local_destinations: &HashMap<[u8; 16], u8>,
    ) {
        if let Some(existing) = self.entries.get_mut(&dest_hash) {
            existing.announced = announced;
            return;
        }

        self.enforce_cap(true, engine, local_destinations);
        self.entries.insert(
            dest_hash,
            KnownDestinationState {
                packet_hash: None,
                announced,
                was_used: false,
                last_used_at: None,
                retained: false,
                stamp: None,
                stamp_value: rns_core::stamp::StampValue::ZERO,
                lr_cost: None,
            },
        );
    }

    /// Keep the hash of the announce a known destination was last heard
    /// in, as upstream's `Identity.remember` does.
    pub(crate) fn record_packet_hash(&mut self, dest_hash: [u8; 16], packet_hash: [u8; 32]) {
        if let Some(state) = self.entries.get_mut(&dest_hash) {
            state.packet_hash = Some(packet_hash);
        }
    }

    pub(crate) fn record_stamp(
        &mut self,
        dest_hash: [u8; 16],
        stamp: Option<[u8; rns_core::constants::STAMP_LENGTH]>,
        stamp_value: rns_core::stamp::StampValue,
        lr_cost: Option<rns_core::stamp::StampCost>,
    ) {
        if let Some(state) = self.entries.get_mut(&dest_hash) {
            state.stamp = stamp;
            state.stamp_value = stamp_value;
            state.lr_cost = lr_cost;
        }
    }

    /// Recall the link request stamp cost announced by a destination.
    pub(crate) fn link_cost(&self, dest_hash: &[u8; 16]) -> Option<rns_core::stamp::StampCost> {
        self.entries.get(dest_hash).and_then(|state| state.lr_cost)
    }

    pub(crate) fn stamp_value(&self, dest_hash: &[u8; 16]) -> Option<rns_core::stamp::StampValue> {
        self.entries.get(dest_hash).map(|state| state.stamp_value)
    }

    /// The known destinations that differ from their last flushed
    /// fingerprint, and the flushed ones that are gone. Only those are
    /// copied: the flush runs every ten seconds, and copying the whole table
    /// each time made a busy transport node's memory grow.
    pub(crate) fn changes(&self) -> (Vec<(KnownDestinationEntry, u64)>, Vec<[u8; 16]>) {
        let changed = self
            .entries
            .iter()
            .filter_map(|(dest_hash, state)| {
                let fingerprint = state.fingerprint();
                (self.flushed.get(dest_hash) != Some(&fingerprint))
                    .then(|| (state.entry(*dest_hash), fingerprint))
            })
            .collect();
        let removed = self
            .flushed
            .keys()
            .filter(|dest_hash| !self.entries.contains_key(*dest_hash))
            .copied()
            .collect();
        (changed, removed)
    }

    /// Record which known destinations the store now holds: `stored` added,
    /// `removed` dropped, after forgetting the rest when `seed`.
    pub(crate) fn record_flush(
        &mut self,
        stored: Vec<([u8; 16], u64)>,
        removed: Vec<[u8; 16]>,
        seed: bool,
    ) {
        if seed {
            self.flushed.clear();
        }
        self.flushed.extend(stored);
        for dest_hash in removed {
            self.flushed.remove(&dest_hash);
        }
    }

    /// Every known destination, by destination hash.
    pub(crate) fn list(&self) -> Vec<KnownDestinationEntry> {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|(dest_hash, state)| state.entry(*dest_hash))
            .collect();
        entries.sort_by_key(|a| a.dest_hash);
        entries
    }

    /// `Identity._used_destination_data`: record that a destination was
    /// used now. A retained destination is left as it is, and like upstream
    /// this then returns `false`.
    pub(crate) fn mark_used(&mut self, dest_hash: &[u8; 16]) -> bool {
        let Some(state) = self.entries.get_mut(dest_hash) else {
            return false;
        };
        if state.retained {
            return false;
        }
        state.was_used = true;
        state.last_used_at = Some(time::now());
        true
    }

    pub(crate) fn retain(&mut self, dest_hash: &[u8; 16]) -> bool {
        let Some(state) = self.entries.get_mut(dest_hash) else {
            return false;
        };
        state.retained = true;
        true
    }

    pub(crate) fn retain_identity(&mut self, identity_hash: &[u8; 16]) -> bool {
        let mut retained = false;
        for state in self.entries.values_mut() {
            if &state.announced.identity_hash.0 == identity_hash {
                state.retained = true;
                retained = true;
            }
        }
        retained
    }

    /// `Identity._unretain_destination_data`: stop retaining a destination.
    /// Like upstream, it counts as used now, so it is not cleaned up before
    /// it has gone unused for the usual time.
    pub(crate) fn unretain(&mut self, dest_hash: &[u8; 16]) -> bool {
        let Some(state) = self.entries.get_mut(dest_hash) else {
            return false;
        };
        state.retained = false;
        state.was_used = true;
        state.last_used_at = Some(time::now());
        true
    }

    pub(crate) fn announced(
        &self,
        dest_hash: &[u8; 16],
    ) -> Option<crate::destination::AnnouncedIdentity> {
        self.entries
            .get(dest_hash)
            .map(|state| state.announced.clone())
    }

    /// Evict the least relevant known destinations until the cache is
    /// within its cap, or below it `for_insert`. Destinations with an
    /// active path in `engine`, the `local_destinations` and retained ones
    /// go last. Returns how many were evicted.
    pub(crate) fn enforce_cap(
        &mut self,
        for_insert: bool,
        engine: &TransportEngine,
        local_destinations: &HashMap<[u8; 16], u8>,
    ) -> usize {
        if self.max_entries == usize::MAX {
            return 0;
        }

        let mut evicted = 0usize;
        while if for_insert {
            self.entries.len() >= self.max_entries
        } else {
            self.entries.len() > self.max_entries
        } {
            let active_dests = engine.active_destination_hashes();
            let candidate = self
                .oldest(false, &active_dests, local_destinations)
                .or_else(|| self.oldest(true, &active_dests, local_destinations));
            let Some(dest_hash) = candidate else {
                break;
            };
            if self.entries.remove(&dest_hash).is_some() {
                evicted += 1;
                self.cap_evict_count += 1;
            } else {
                break;
            }
        }
        evicted
    }

    fn oldest(
        &self,
        include_protected: bool,
        active_dests: &std::collections::BTreeSet<[u8; 16]>,
        local_destinations: &HashMap<[u8; 16], u8>,
    ) -> Option<[u8; 16]> {
        self.entries
            .iter()
            .filter(|(dest_hash, state)| {
                include_protected
                    || (!active_dests.contains(*dest_hash)
                        && !local_destinations.contains_key(*dest_hash)
                        && !state.retained)
            })
            .min_by(|a, b| {
                a.1.relevance_time()
                    .partial_cmp(&b.1.relevance_time())
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.0.cmp(b.0))
            })
            .map(|(dest_hash, _)| *dest_hash)
    }
}

impl KnownDestinationState {
    pub(crate) fn entry(&self, dest_hash: [u8; 16]) -> KnownDestinationEntry {
        KnownDestinationEntry {
            packet_hash: self.packet_hash,
            dest_hash,
            identity_hash: self.announced.identity_hash.0,
            public_key: self.announced.public_key,
            app_data: self.announced.app_data.clone(),
            hops: self.announced.hops,
            received_at: self.announced.received_at,
            receiving_interface: self.announced.receiving_interface,
            was_used: self.was_used,
            last_used_at: self.last_used_at,
            retained: self.retained,
            stamp: self.stamp,
            stamp_value: self.stamp_value,
            lr_cost: self.lr_cost,
        }
    }

    /// Fingerprint of a known destination as storage persists it.
    pub(crate) fn fingerprint(&self) -> u64 {
        crate::storage::known_destination_fingerprint(
            &self.announced.identity_hash.0,
            &self.announced.public_key,
            self.announced.app_data.as_deref(),
            self.announced.hops,
            self.announced.received_at,
            self.announced.receiving_interface.0,
            self.was_used,
            self.last_used_at,
            self.retained,
            self.stamp.as_ref().map(|stamp| &stamp[..]),
            self.stamp_value,
            self.lr_cost,
            self.packet_hash.as_ref(),
        )
    }

    /// When the destination last mattered: its last use, or its announce.
    pub(crate) fn relevance_time(&self) -> f64 {
        self.last_used_at.unwrap_or(self.announced.received_at)
    }
}
