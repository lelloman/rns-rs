//! Known destinations: recalling, retaining and persisting them.

use super::*;

/// `RNS.Transport.kd_flush_interval`.
pub(super) const KD_FLUSH_INTERVAL: Duration = Duration::from_secs(10);

/// A known destination entry as storage keeps it.
pub(super) fn stored_known_destination(
    entry: &crate::event::KnownDestinationEntry,
) -> storage::KnownDestination {
    storage::KnownDestination {
        packet_hash: entry.packet_hash,
        identity_hash: entry.identity_hash,
        public_key: entry.public_key,
        app_data: entry.app_data.clone(),
        hops: entry.hops,
        received_at: entry.received_at,
        receiving_interface: entry.receiving_interface.0,
        was_used: entry.was_used,
        last_used_at: entry.last_used_at,
        retained: entry.retained,
        stamp: entry.stamp.map(|stamp| stamp.to_vec()),
        stamp_value: entry.stamp_value,
        lr_cost: entry.lr_cost,
    }
}

/// The known destinations changed since the last recorded flush.
#[allow(clippy::type_complexity)]
pub(super) fn known_destination_changes(
    tx: &EventSender,
) -> Option<(
    Vec<(crate::event::KnownDestinationEntry, u64)>,
    Vec<[u8; 16]>,
)> {
    let (response_tx, response_rx) = std::sync::mpsc::channel();
    tx.send(Event::query(
        QueryRequest::KnownDestinationChanges,
        response_tx,
    ))
    .ok()?;
    match response_rx.recv().ok()? {
        QueryResponse::KnownDestinationChanges { changed, removed } => Some((changed, removed)),
        _ => None,
    }
}

/// Tell the driver what the flush stored (see
/// `QueryRequest::RecordKnownDestinationFlush`).
pub(super) fn record_known_destination_flush(
    tx: &EventSender,
    stored: Vec<([u8; 16], u64)>,
    removed: Vec<[u8; 16]>,
    seed: bool,
) -> Option<()> {
    let (response_tx, response_rx) = std::sync::mpsc::channel();
    tx.send(Event::query(
        QueryRequest::RecordKnownDestinationFlush {
            stored,
            removed,
            seed,
        },
        response_tx,
    ))
    .ok()?;
    matches!(
        response_rx.recv().ok()?,
        QueryResponse::KnownDestinationFlushRecorded
    )
    .then_some(())
}

/// The driver's known destinations, as storage keeps them.
pub(super) fn known_destinations_snapshot(
    tx: &EventSender,
) -> Option<std::collections::HashMap<[u8; 16], storage::KnownDestination>> {
    let (response_tx, response_rx) = std::sync::mpsc::channel();
    tx.send(Event::query(QueryRequest::KnownDestinations, response_tx))
        .ok()?;
    let QueryResponse::KnownDestinations(entries) = response_rx.recv().ok()? else {
        return None;
    };
    Some(
        entries
            .iter()
            .map(|entry| (entry.dest_hash, stored_known_destination(entry)))
            .collect(),
    )
}

impl RnsNode {
    /// Recall the identity information for a previously announced destination.
    pub fn recall_identity(
        &self,
        dest_hash: &rns_core::types::DestHash,
    ) -> Result<Option<crate::destination::AnnouncedIdentity>, SendError> {
        match self.query(QueryRequest::RecallIdentity {
            dest_hash: dest_hash.0,
        })? {
            QueryResponse::RecallIdentity(v) => Ok(v),
            _ => Ok(None),
        }
    }

    /// Stamp value and announced link request cost recorded from a known
    /// destination's last announce.
    pub fn recall_destination_stamp(
        &self,
        dest_hash: &rns_core::types::DestHash,
    ) -> Result<Option<crate::event::DestinationStampInfo>, SendError> {
        match self.query(QueryRequest::RecallDestinationStamp {
            dest_hash: dest_hash.0,
        })? {
            QueryResponse::RecallDestinationStamp(v) => Ok(v),
            _ => Ok(None),
        }
    }

    /// List known destinations and their lifecycle state.
    pub fn known_destinations(
        &self,
    ) -> Result<Vec<crate::event::KnownDestinationEntry>, SendError> {
        match self.query(QueryRequest::KnownDestinations)? {
            QueryResponse::KnownDestinations(entries) => Ok(entries),
            _ => Ok(Vec::new()),
        }
    }

    /// Mark a known destination as retained.
    pub fn retain_known_destination(
        &self,
        dest_hash: &rns_core::types::DestHash,
    ) -> Result<bool, SendError> {
        match self.query(QueryRequest::RetainKnownDestination {
            dest_hash: dest_hash.0,
        })? {
            QueryResponse::RetainKnownDestination(ok) => Ok(ok),
            _ => Ok(false),
        }
    }

    /// Mark all known destinations announced by an identity as retained.
    pub fn retain_identity(
        &self,
        identity_hash: &rns_core::types::IdentityHash,
    ) -> Result<bool, SendError> {
        // Upstream `Reticulum._retain_identity`: a shared instance client
        // asks the instance, which holds the known destinations.
        #[cfg(feature = "iface-local")]
        if self.destination_types.is_client_with_rpc() {
            use crate::pickle::PickleValue;
            let request = PickleValue::Dict(vec![
                (
                    PickleValue::String("identity_data".into()),
                    PickleValue::String("retain".into()),
                ),
                (
                    PickleValue::String("identity_hash".into()),
                    PickleValue::Bytes(identity_hash.0.to_vec()),
                ),
            ]);
            return Ok(self
                .destination_types
                .call(&request)
                .and_then(|r| r.as_bool())
                .unwrap_or(false));
        }
        match self.query(QueryRequest::RetainIdentity {
            identity_hash: identity_hash.0,
        })? {
            QueryResponse::RetainIdentity(ok) => Ok(ok),
            _ => Ok(false),
        }
    }

    /// Put known destinations loaded from storage back into the driver.
    pub(crate) fn restore_known_destinations(
        &self,
        known_destinations: impl IntoIterator<Item = ([u8; 16], storage::KnownDestination)>,
    ) {
        for (dest_hash, known) in known_destinations {
            let _ = self.query(QueryRequest::RestoreKnownDestination(
                crate::event::KnownDestinationEntry {
                    packet_hash: known.packet_hash,
                    dest_hash,
                    identity_hash: known.identity_hash,
                    public_key: known.public_key,
                    app_data: known.app_data,
                    hops: known.hops,
                    received_at: known.received_at,
                    receiving_interface: rns_core::transport::types::InterfaceId(
                        known.receiving_interface,
                    ),
                    was_used: known.was_used,
                    last_used_at: known.last_used_at,
                    retained: known.retained,
                    stamp: known
                        .stamp
                        .as_deref()
                        .and_then(|stamp| stamp.try_into().ok()),
                    stamp_value: known.stamp_value,
                    lr_cost: known.lr_cost,
                },
            ));
        }
    }

    /// Clear the retained flag on a known destination.
    pub fn unretain_known_destination(
        &self,
        dest_hash: &rns_core::types::DestHash,
    ) -> Result<bool, SendError> {
        match self.query(QueryRequest::UnretainKnownDestination {
            dest_hash: dest_hash.0,
        })? {
            QueryResponse::UnretainKnownDestination(ok) => Ok(ok),
            _ => Ok(false),
        }
    }

    /// Mark a known destination as used.
    pub fn mark_known_destination_used(
        &self,
        dest_hash: &rns_core::types::DestHash,
    ) -> Result<bool, SendError> {
        match self.query(QueryRequest::MarkKnownDestinationUsed {
            dest_hash: dest_hash.0,
        })? {
            QueryResponse::MarkKnownDestinationUsed(ok) => Ok(ok),
            _ => Ok(false),
        }
    }

    /// Save the known destinations at shutdown.
    ///
    /// Upstream 4a058544 guards `Identity.persist_data` and
    /// `Transport.exit_handler` against a missing `Transport.owner` (an exit
    /// before Reticulum was set up) before checking that the process is not
    /// a shared instance client. Neither case needs a guard here: this runs
    /// only on a constructed `RnsNode` (from its shutdown), and a shared
    /// instance client is built with `RnsNode::from_parts`, which leaves
    /// both the known destinations store and path unset, so it returns at
    /// once, as upstream's shared instance check does. The same holds for
    /// `persist_transport_state`, whose storage directory `from_parts`
    /// leaves unset.
    pub(super) fn persist_known_destinations(&self) {
        if self.known_destinations_store.is_none() && self.known_destinations_path.is_none() {
            return;
        }
        let Some(destinations) = known_destinations_snapshot(&self.tx) else {
            return;
        };
        if let Some(store) = self.known_destinations_store.as_ref() {
            if let Err(err) = store.save_all(&destinations) {
                log::warn!("failed to persist known destinations: {}", err);
            }
        } else if let Some(path) = self.known_destinations_path.as_ref() {
            if let Err(err) = storage::save_known_destinations(&destinations, path) {
                log::warn!("failed to persist known destinations: {}", err);
            }
        }
    }

    /// Write changed known destinations to the database every
    /// `KD_FLUSH_INTERVAL`, as upstream's transport jobs do, so shared
    /// instance clients, which read it, see what the instance learns. The
    /// driver keeps a fingerprint of each flushed entry and hands over only
    /// the changed ones, as upstream flushes only the destinations it marked
    /// dirty; `loaded` seeds the fingerprints with what storage holds.
    pub(super) fn start_known_destinations_flush(
        &mut self,
        loaded: std::collections::HashMap<[u8; 16], storage::KnownDestination>,
    ) {
        let Some(store) = self.known_destinations_store.clone() else {
            return;
        };
        let seed: Vec<([u8; 16], u64)> = loaded
            .iter()
            .map(|(dest_hash, entry)| (*dest_hash, entry.fingerprint()))
            .collect();
        drop(loaded);
        let tx = self.tx.clone();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let handle = thread::Builder::new()
            .name("rns-kd-flush".into())
            .spawn(move || {
                if record_known_destination_flush(&tx, seed, Vec::new(), true).is_none() {
                    return;
                }
                loop {
                    match stop_rx.recv_timeout(KD_FLUSH_INTERVAL) {
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    let Some((changed, removed)) = known_destination_changes(&tx) else {
                        break;
                    };
                    if changed.is_empty() && removed.is_empty() {
                        continue;
                    }
                    let upserts: Vec<([u8; 16], storage::KnownDestination)> = changed
                        .iter()
                        .map(|(entry, _)| (entry.dest_hash, stored_known_destination(entry)))
                        .collect();
                    let upsert_refs: Vec<([u8; 16], &storage::KnownDestination)> =
                        upserts.iter().map(|(hash, entry)| (*hash, entry)).collect();
                    match store.save_changes(&upsert_refs, &removed) {
                        Ok(()) => {
                            let stored = changed
                                .iter()
                                .map(|(entry, fingerprint)| (entry.dest_hash, *fingerprint))
                                .collect();
                            if record_known_destination_flush(&tx, stored, removed, false).is_none()
                            {
                                break;
                            }
                        }
                        // Not recorded, so the same changes come back next time.
                        Err(err) => log::warn!("failed to flush known destinations: {}", err),
                    }
                }
            });
        match handle {
            Ok(handle) => {
                self.kd_flush_handle = Some(handle);
                self.kd_flush_stop = Some(stop_tx);
            }
            Err(err) => log::warn!("could not start the known destinations flush: {}", err),
        }
    }

    pub(super) fn persist_transport_state(&self) {
        let Some(storage_dir) = self.transport_state_dir.as_ref() else {
            return;
        };
        let Ok(QueryResponse::TransportStateSnapshot(snapshot)) =
            self.query(QueryRequest::TransportStateSnapshot)
        else {
            return;
        };
        if let Err(err) = storage::save_transport_state(&snapshot, storage_dir, true) {
            log::warn!("failed to persist transport state: {}", err);
        }
    }
}
