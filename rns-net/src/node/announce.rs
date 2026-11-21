//! Announcing destinations, with their stamps.

use super::*;
use std::fmt;

/// Why a destination stamp could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DestinationStampError {
    /// The identity has no public key to bind the stamp to.
    NoPublicKey,
    /// The target cost is above what the protocol allows.
    CostAboveCap,
}

impl fmt::Display for DestinationStampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoPublicKey => "identity has no public key",
            Self::CostAboveCap => "stamp cost is above the protocol cap",
        })
    }
}

/// Make sure a destination stamp reaching the destination's target value is
/// persisted for `dest`, grinding one at that target when none is. This is
/// the stamp half of `Destination._announce`, run by the stamper off the
/// calling thread.
///
/// Since d7749b0b upstream reloads or regenerates the held stamp whenever
/// its value is below `target_value`, and both the store lookup and the
/// grind use `target_value` rather than `DESTINATION_COST` /
/// `DESTINATION_VALUE` (Destination.py:319-323). A persisted stamp that
/// still meets the announce cost but not the target is therefore replaced.
pub(crate) fn ensure_destination_stamp(
    store: &crate::stamps::DestinationStampStore,
    targets: crate::stamper::StampTargets,
    dest: &crate::destination::Destination,
    identity: &Identity,
) -> Result<(), DestinationStampError> {
    let public_key = identity
        .get_public_key()
        .ok_or(DestinationStampError::NoPublicKey)?;
    let name_hash = rns_core::destination::name_hash(
        &dest.app_name,
        &dest.aspects.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    );
    let material =
        rns_core::stamp::destination_stamp_material(&dest.hash.0, &public_key, &name_hash);
    let target = targets.destination_target(dest);
    if store.load(&dest.hash.0, &material, target).is_some() {
        return Ok(());
    }
    let started = std::time::Instant::now();
    let (stamp, value) =
        crate::stamps::generate_stamp(&material, target, rns_core::constants::STAMP_LENGTH, 0)
            .ok_or(DestinationStampError::CostAboveCap)?;
    if let Err(error) = store.store(&dest.hash.0, &stamp, value) {
        log::warn!("failed to persist destination stamp: {error}");
    }
    log::debug!(
        "Generated and persisted stamp with value {value} for {:02x?} in {:?}",
        &dest.hash.0[..4],
        started.elapsed()
    );
    Ok(())
}

/// The signing key the proof of a packet sent to `dest` is checked with:
/// the public signing key of the SINGLE destination's identity.
pub(super) fn single_proof_key(dest: &crate::destination::Destination) -> Option<[u8; 32]> {
    if dest.dest_type != rns_core::types::DestinationType::Single {
        return None;
    }
    dest.public_key
        .map(|key| rns_crypto::identity::split_key(&key).1)
}

/// Build an announce packet for `dest`, signed by `identity`.
///
/// With `stamp_destinations` the app data is extended with the destination
/// stamp from `stamp_store`, grinding one inline when none is persisted, as
/// `Destination._announce` does. The node API checks for a missing stamp
/// first and defers to the stamper, so the inline grind only runs when a
/// stamp disappeared between that check and this call.
pub(crate) fn build_announce_packet(
    tx: &EventSender,
    stamp_store: Option<&crate::stamps::DestinationStampStore>,
    stamp_destinations: bool,
    targets: crate::stamper::StampTargets,
    dest: &crate::destination::Destination,
    identity: &Identity,
    app_data: Option<&[u8]>,
) -> Result<
    (
        rns_core::packet::RawPacket,
        Option<Box<crate::common::event::AnnounceReplay>>,
    ),
    SendError,
> {
    let name_hash = rns_core::destination::name_hash(
        &dest.app_name,
        &dest.aspects.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    );

    let mut random_hash = [0u8; 10];
    OsRng.fill_bytes(&mut random_hash[..5]);
    // Bytes [5:10] must be the emission timestamp (seconds since epoch,
    // big-endian, truncated to 5 bytes) so that path table dedup can
    // compare announce freshness.  Matches Python: int(time.time()).to_bytes(5, "big")
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    random_hash[5..10].copy_from_slice(&now_secs.to_be_bytes()[3..8]);

    let owner = crate::sync::lock_or_recover(tx.local_ratchets(), "local ratchets")
        .get(&dest.hash.0)
        .cloned();
    let ratchet = if let Some(owner) = owner {
        if dest.direction != rns_core::types::Direction::In
            || owner.identity_hash() != *identity.hash()
        {
            return Err(SendError);
        }
        Some(owner.public_for_announce(now_secs).map_err(|error| {
            log::error!("local ratchet announcement failed: {error}");
            SendError
        })?)
    } else {
        None
    };
    // A node without a stamp store (a shared instance client, or one started
    // without storage) has nowhere to keep a stamp and announces unstamped,
    // as `announce_needs_stamp` already treats it; failing every announce
    // would make the 51fa8413 default unusable for it.
    let stamp_store = stamp_store.filter(|_| stamp_destinations);
    let wire_app_data: Option<Vec<u8>> = if let Some(store) = stamp_store {
        let public_key = identity.get_public_key().ok_or(SendError)?;
        let material =
            rns_core::stamp::destination_stamp_material(&dest.hash.0, &public_key, &name_hash);
        let target = targets.destination_target(dest);
        let (stamp, _value) = match store.load(&dest.hash.0, &material, target) {
            Some(entry) => entry,
            None => {
                let (stamp, value) = crate::stamps::generate_stamp(
                    &material,
                    target,
                    rns_core::constants::STAMP_LENGTH,
                    0,
                )
                .ok_or(SendError)?;
                if let Err(error) = store.store(&dest.hash.0, &stamp, value) {
                    log::warn!("failed to persist destination stamp: {error}");
                }
                (stamp, value)
            }
        };
        let mut wire = app_data.map(|data| data.to_vec()).unwrap_or_default();
        // `cost_to_bytes(self.get_link_cost())`: the destination's own cost,
        // or the default `LR_COST` when none was set, fraction included.
        wire.extend_from_slice(&rns_core::stamp::announce_ext_payload(
            &stamp,
            0,
            tx.link_request_costs().get(&dest.hash.0),
        ));
        Some(wire)
    } else {
        app_data.map(|data| data.to_vec())
    };

    let (announce_data, has_ratchet) = rns_core::announce::AnnounceData::pack(
        identity,
        &dest.hash.0,
        &name_hash,
        &random_hash,
        ratchet.as_ref(),
        wire_app_data.as_deref(),
    )
    .map_err(|_| SendError)?;

    let context_flag = if has_ratchet {
        rns_core::constants::FLAG_SET
    } else {
        rns_core::constants::FLAG_UNSET
    };

    let flags = rns_core::packet::PacketFlags {
        header_type: rns_core::constants::HEADER_1,
        context_flag,
        transport_type: rns_core::constants::TRANSPORT_BROADCAST,
        destination_type: rns_core::constants::DESTINATION_SINGLE,
        packet_type: rns_core::constants::PACKET_TYPE_ANNOUNCE,
    };

    let packet = rns_core::packet::RawPacket::pack(
        flags,
        0,
        &dest.hash.0,
        None,
        rns_core::constants::CONTEXT_NONE,
        &announce_data,
    )
    .map_err(|_| SendError)?;

    let replay = if dest.dest_type == rns_core::types::DestinationType::Single {
        identity.get_private_key().map(|identity_prv_key| {
            Box::new(crate::common::event::AnnounceReplay {
                dest_hash: dest.hash.0,
                name_hash,
                identity_prv_key,
                app_data: wire_app_data,
            })
        })
    } else {
        None
    };
    Ok((packet, replay))
}

impl RnsNode {
    /// Wait for capacity, then transmit an announcement on all selected local interfaces.
    ///
    /// Success means all selected writers accepted the complete packet, not
    /// remote delivery or subsequent relay. An error can follow partial delivery
    /// on one or more interfaces. No eligible interface returns `NoRoute`.
    /// Cancelling before admission sends nothing; after admission, transmission
    /// continues. Shared-client replay metadata travels in the same admitted
    /// event as the packet, never in a separate event from a rejected send.
    pub async fn announce(
        &self,
        dest: &crate::destination::Destination,
        identity: &Identity,
        app_data: Option<&[u8]>,
    ) -> Result<(), crate::TransmissionError> {
        let permit = self.tx.link_send_pool().acquire().await?;
        if self.announce_needs_stamp(dest, identity) {
            // Destination.announce with STAMP_DESTINATIONS and no stamp yet:
            // the stamper grinds it and submits the announce; the receipt
            // resolves when that announce has been written.
            let (completion, receipt) = crate::link_send::Completion::new(permit);
            self.enqueue_stamped_announce(dest, identity, app_data, Some(completion))
                .map_err(|_| crate::TransmissionError::QueueFull)?;
            return receipt.await;
        }
        let (packet, replay) = self
            .build_announce(dest, identity, app_data)
            .map_err(|_| crate::TransmissionError::PacketBuildFailed)?;
        let (completion, receipt) = crate::link_send::Completion::new(permit);
        self.tx
            .send_async(Event::SendOutboundTracked {
                raw: packet.raw,
                dest_type: dest.dest_type.to_wire_constant(),
                replay,
                completion,
                proof_key: None,
            })
            .await?;
        receipt.await
    }

    /// Try admission immediately; await the receipt for the exact same result
    /// as `announce`. `QueueFull` guarantees nothing was admitted.
    pub fn try_announce(
        &self,
        dest: &crate::destination::Destination,
        identity: &Identity,
        app_data: Option<&[u8]>,
    ) -> Result<crate::TransmissionReceipt, crate::TransmissionError> {
        let permit = self.tx.link_send_pool().try_acquire()?;
        if self.announce_needs_stamp(dest, identity) {
            // Deferred to the stamper; the receipt resolves once the stamped
            // announce has been written, or with `Interrupted` if a newer
            // announce for the same destination replaces this one in the
            // queue.
            let (completion, receipt) = crate::link_send::Completion::new(permit);
            self.enqueue_stamped_announce(dest, identity, app_data, Some(completion))
                .map_err(|_| crate::TransmissionError::QueueFull)?;
            return Ok(receipt);
        }
        let (packet, replay) = self
            .build_announce(dest, identity, app_data)
            .map_err(|_| crate::TransmissionError::PacketBuildFailed)?;
        let (completion, receipt) = crate::link_send::Completion::new(permit);
        self.try_confirmed_event(Event::SendOutboundTracked {
            raw: packet.raw,
            dest_type: dest.dest_type.to_wire_constant(),
            replay,
            completion,
            proof_key: None,
        })?;
        Ok(receipt)
    }

    /// Build and broadcast an announce for a destination (queue-only compatibility API).
    ///
    /// Success means driver submission, not transmission. Use `announce`
    /// or `try_announce` for confirmed local transmission.
    ///
    /// The identity is used to sign the announce. Must be the identity that
    /// owns the destination (i.e. `identity.hash()` matches `dest.identity_hash`).
    pub fn announce_queued(
        &self,
        dest: &crate::destination::Destination,
        identity: &Identity,
        app_data: Option<&[u8]>,
    ) -> Result<(), SendError> {
        self.reject_new_work_if_draining()?;
        if self.announce_needs_stamp(dest, identity) {
            // Destination.announce with STAMP_DESTINATIONS and no stamp yet
            // queues the announce for background stamping and emission.
            return self
                .enqueue_stamped_announce(dest, identity, app_data, None)
                .map_err(|_| SendError);
        }
        let (packet, replay) = self.build_announce(dest, identity, app_data)?;
        if let Some(replay) = replay {
            self.tx
                .send(Event::StoreSharedAnnounce {
                    dest_hash: replay.dest_hash,
                    name_hash: replay.name_hash,
                    identity_prv_key: replay.identity_prv_key,
                    app_data: replay.app_data,
                })
                .map_err(|_| SendError)?;
        }
        self.send_raw(packet.raw, dest.dest_type.to_wire_constant(), None)
    }

    pub(super) fn build_announce(
        &self,
        dest: &crate::destination::Destination,
        identity: &Identity,
        app_data: Option<&[u8]>,
    ) -> Result<
        (
            rns_core::packet::RawPacket,
            Option<Box<crate::common::event::AnnounceReplay>>,
        ),
        SendError,
    > {
        build_announce_packet(
            &self.tx,
            self.stamp_store.as_ref(),
            self.stamp_destinations.load(Ordering::Relaxed),
            self.stamp_targets,
            dest,
            identity,
            app_data,
        )
    }

    /// Whether `Destination.announce` would hand this announce to the
    /// stamper: destination stamping is on and no persisted stamp reaches
    /// the destination's target value (Destination.py `_announce`).
    pub(super) fn announce_needs_stamp(
        &self,
        dest: &crate::destination::Destination,
        identity: &Identity,
    ) -> bool {
        if !self.stamp_destinations.load(Ordering::Relaxed) || self.stamper.is_none() {
            return false;
        }
        let (Some(store), Some(public_key)) =
            (self.stamp_store.as_ref(), identity.get_public_key())
        else {
            return false;
        };
        let name_hash = rns_core::destination::name_hash(
            &dest.app_name,
            &dest.aspects.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        );
        let material =
            rns_core::stamp::destination_stamp_material(&dest.hash.0, &public_key, &name_hash);
        store
            .load(
                &dest.hash.0,
                &material,
                self.stamp_targets.destination_target(dest),
            )
            .is_none()
    }

    /// `Transport.enqueue_stamped_announce`: the worker grinds the stamp and
    /// emits the announce; a full queue drops it.
    pub(super) fn enqueue_stamped_announce(
        &self,
        dest: &crate::destination::Destination,
        identity: &Identity,
        app_data: Option<&[u8]>,
        completion: Option<crate::link_send::Completion>,
    ) -> Result<(), crate::stamper::QueueFull> {
        let stamper = self.stamper.as_ref().ok_or(crate::stamper::QueueFull)?;
        let identity_prv_key = identity
            .get_private_key()
            .ok_or(crate::stamper::QueueFull)?;
        let result = stamper.enqueue_announce(crate::stamper::AnnounceStampJob {
            dest: dest.clone(),
            identity_prv_key,
            app_data: app_data.map(|data| data.to_vec()),
            completion,
        });
        if result.is_err() {
            log::debug!(
                "Stamp queue full, dropping announce for {:02x?}",
                &dest.hash.0[..4]
            );
        }
        result
    }

    /// Share the driver's stamper and `STAMP_DESTINATIONS` flag, so this
    /// handle stamps announces as the driver is configured to.
    #[cfg(feature = "iface-local")]
    pub(crate) fn attach_stamper(
        &mut self,
        stamper: Arc<crate::stamper::Stamper>,
        stamp_destinations: Arc<AtomicBool>,
        targets: crate::stamper::StampTargets,
    ) {
        self.stamper = Some(stamper);
        self.stamp_destinations = stamp_destinations;
        self.stamp_targets = targets;
    }

    /// Use `store` for destination stamps, here and in the stamper.
    pub(crate) fn set_stamp_store(&mut self, store: crate::stamps::DestinationStampStore) {
        if let Some(stamper) = self.stamper.as_ref() {
            stamper.set_stamp_store(Some(store.clone()));
        }
        self.stamp_store = Some(store);
    }

    /// Override `STAMP_DESTINATIONS` and the stamp targets for this node and
    /// its stamper.
    #[doc(hidden)]
    pub fn set_destination_stamping(
        &mut self,
        enabled: bool,
        targets: crate::stamper::StampTargets,
    ) {
        self.stamp_destinations.store(enabled, Ordering::Relaxed);
        self.stamp_targets = targets;
        if let Some(stamper) = self.stamper.as_ref() {
            stamper.set_targets(targets);
        }
    }

    /// The stamper shared with the driver.
    #[doc(hidden)]
    pub fn stamper(&self) -> Option<&Arc<crate::stamper::Stamper>> {
        self.stamper.as_ref()
    }
}
