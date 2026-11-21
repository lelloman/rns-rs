//! Sending packets and asking about paths.

use super::*;

impl RnsNode {
    /// Wait for capacity and local transmission, returning the hash for proof tracking.
    ///
    /// Uses the same all-selected-writers contract as `announce` and the
    /// same admission/completion capacity as `send_on_link`. No remote delivery
    /// is promised; errors may follow partial transmission. Dropping an admitted
    /// future does not cancel its send. No async runtime is required.
    pub async fn send_packet(
        &self,
        dest: &crate::destination::Destination,
        data: &[u8],
    ) -> Result<rns_core::types::PacketHash, crate::LinkSendError> {
        let permit = self.tx.link_send_pool().acquire().await?;
        let packet = self
            .build_packet(dest, data)
            .map_err(|_| crate::LinkSendError::PacketBuildFailed)?;
        let hash = rns_core::types::PacketHash(packet.packet_hash);
        let (completion, receipt) = crate::link_send::Completion::new(permit);
        self.tx
            .send_async(Event::SendOutboundTracked {
                raw: packet.raw,
                dest_type: dest.dest_type.to_wire_constant(),
                replay: None,
                completion,
                proof_key: single_proof_key(dest),
            })
            .await?;
        receipt.await?;
        Ok(hash)
    }

    /// Try admission immediately. The receipt exposes the packet hash and
    /// resolves to the same result as `send_packet`, after local writes.
    /// `QueueFull` guarantees nothing was admitted and is safe to retry.
    pub fn try_send_packet(
        &self,
        dest: &crate::destination::Destination,
        data: &[u8],
    ) -> Result<crate::PacketSendReceipt, crate::LinkSendError> {
        let permit = self.tx.link_send_pool().try_acquire()?;
        let packet = self
            .build_packet(dest, data)
            .map_err(|_| crate::LinkSendError::PacketBuildFailed)?;
        let hash = rns_core::types::PacketHash(packet.packet_hash);
        let (completion, receipt) = crate::link_send::Completion::new(permit);
        self.try_confirmed_event(Event::SendOutboundTracked {
            raw: packet.raw,
            dest_type: dest.dest_type.to_wire_constant(),
            replay: None,
            completion,
            proof_key: single_proof_key(dest),
        })?;
        Ok(crate::PacketSendReceipt {
            completion: receipt,
            hash,
        })
    }

    pub(super) fn try_confirmed_event(&self, event: Event) -> Result<(), crate::LinkSendError> {
        self.tx.try_send(event).map_err(|error| match error {
            std::sync::mpsc::TrySendError::Full(_) => crate::LinkSendError::QueueFull,
            std::sync::mpsc::TrySendError::Disconnected(_) => crate::LinkSendError::DriverStopped,
        })
    }

    /// Queue an encrypted (SINGLE) or plaintext (PLAIN) packet to a destination.
    ///
    /// Queue-only compatibility API: use `send_packet` or `try_send_packet`
    /// for confirmed local transmission. The returned hash does not mean sent.
    ///
    /// For SINGLE destinations, `dest.public_key` must be set (OUT direction).
    /// Returns the packet hash for proof tracking.
    pub fn send_packet_queued(
        &self,
        dest: &crate::destination::Destination,
        data: &[u8],
    ) -> Result<rns_core::types::PacketHash, SendError> {
        self.reject_new_work_if_draining()?;
        let packet = self.build_packet(dest, data)?;
        let packet_hash = rns_core::types::PacketHash(packet.packet_hash);
        self.tx
            .send(Event::SendOutbound {
                raw: packet.raw,
                dest_type: dest.dest_type.to_wire_constant(),
                attached_interface: None,
            })
            .map_err(|_| SendError)?;
        Ok(packet_hash)
    }

    /// Deliver single packets addressed to `dest`, a local destination,
    /// decrypted: through [`Callbacks::on_packet_received`](crate::Callbacks::on_packet_received)
    /// in place of `on_local_delivery`, decrypted on the node's proof pool
    /// when it has one, so a receiver is not bound by decrypting on its own
    /// thread. They are decrypted with the destination's attached ratchets
    /// ([`attach_local_ratchets`](Self::attach_local_ratchets)) when it has
    /// them, else with `identity`, which must hold its private keys. Packets
    /// that do not decrypt are dropped and not proved. Deregistering the
    /// destination ends it.
    pub fn deliver_decrypted(
        &self,
        dest: &crate::destination::Destination,
        identity: &rns_crypto::identity::Identity,
    ) -> Result<(), SendError> {
        let private = identity.get_private_key().ok_or(SendError)?;
        self.tx
            .send(Event::DeliverDecrypted {
                dest_hash: dest.hash.0,
                identity: Box::new(rns_crypto::identity::Identity::from_private_key(&private)),
            })
            .map_err(|_| SendError)
    }

    /// Queue a packet for a SINGLE destination without encrypting it on this
    /// thread, unlike [`send_packet_queued`](Self::send_packet_queued): the
    /// node encrypts it (on its proof pool when it has one; on this thread
    /// when the process may use one CPU only) and reports the
    /// packet hash through [`Callbacks::on_packet_sent`](crate::Callbacks::on_packet_sent)
    /// with the returned ticket, before sending it. A sender is then not
    /// bound by its own thread's encryption, one X25519 key generation and
    /// exchange per packet.
    ///
    /// `dest.public_key` must be set (OUT direction). Like
    /// `send_packet_queued`, queueing does not mean sent.
    pub fn send_packet_deferred(
        &self,
        dest: &crate::destination::Destination,
        data: &[u8],
    ) -> Result<crate::SendTicket, SendError> {
        self.reject_new_work_if_draining()?;
        if dest.dest_type != rns_core::types::DestinationType::Single {
            return Err(SendError);
        }
        let public_key = dest.public_key.ok_or(SendError)?;
        let ticket = self.next_send_ticket.fetch_add(1, Ordering::Relaxed);
        let ratchet = self.single_ratchet(dest);
        let (data, encrypted) = if self.encrypt_deferred_inline {
            let payload = rns_crypto::identity::Identity::encrypt_for_public_key(
                &public_key,
                data,
                ratchet.as_ref(),
                &mut OsRng,
            )
            .map_err(|_| SendError)?;
            (payload, true)
        } else {
            (data.to_vec(), false)
        };
        self.tx
            .send(Event::SendDeferred(Box::new(
                crate::common::event::DeferredSend {
                    ticket,
                    destination: dest.hash.0,
                    public_key,
                    ratchet,
                    data,
                    encrypted,
                },
            )))
            .map_err(|_| SendError)?;
        Ok(crate::SendTicket(ticket))
    }

    pub(super) fn build_packet(
        &self,
        dest: &crate::destination::Destination,
        data: &[u8],
    ) -> Result<rns_core::packet::RawPacket, SendError> {
        use rns_core::types::DestinationType;

        let payload = match dest.dest_type {
            DestinationType::Single => self.encrypt_single_payload(dest, data)?,
            DestinationType::Plain => data.to_vec(),
            DestinationType::Group => dest.encrypt(data).map_err(|_| SendError)?,
        };

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: dest.dest_type.to_wire_constant(),
            packet_type: rns_core::constants::PACKET_TYPE_DATA,
        };

        let packet = rns_core::packet::RawPacket::pack(
            flags,
            0,
            &dest.hash.0,
            None,
            rns_core::constants::CONTEXT_NONE,
            &payload,
        )
        .map_err(|_| SendError)?;

        Ok(packet)
    }

    pub(super) fn encrypt_single_payload(
        &self,
        dest: &crate::destination::Destination,
        data: &[u8],
    ) -> Result<Vec<u8>, SendError> {
        let pub_key = dest.public_key.ok_or(SendError)?;
        let ratchet = self.single_ratchet(dest);
        // Encrypted straight from the key bytes: building the identity would
        // decompress its signing key on every send, and encryption does not
        // use it.
        rns_crypto::identity::Identity::encrypt_for_public_key(
            &pub_key,
            data,
            ratchet.as_ref(),
            &mut OsRng,
        )
        .map_err(|_| SendError)
    }

    /// The ratchet to encrypt a packet for `dest` with: this node's own for
    /// its destinations, else the latest one `dest` announced.
    pub(super) fn single_ratchet(
        &self,
        dest: &crate::destination::Destination,
    ) -> Option<[u8; 32]> {
        let local_ratchet =
            crate::sync::lock_or_recover(self.tx.local_ratchets(), "local ratchets")
                .get(&dest.hash.0)
                .and_then(|owner| owner.current_public());
        local_ratchet.or_else(|| {
            self.ratchet_store.as_ref().and_then(|store| {
                match store.current(&dest.hash.0, time::now(), self.ratchet_expiry.as_secs_f64()) {
                    Ok(entry) => entry.map(|entry| entry.ratchet),
                    Err(err) => {
                        log::warn!(
                            "failed to load ratchet for {:02x}{:02x}{:02x}{:02x}..: {}",
                            dest.hash.0[0],
                            dest.hash.0[1],
                            dest.hash.0[2],
                            dest.hash.0[3],
                            err
                        );
                        None
                    }
                }
            })
        })
    }

    /// Request a path to a destination from the network.
    pub fn request_path(&self, dest_hash: &rns_core::types::DestHash) -> Result<(), SendError> {
        self.reject_new_work_if_draining()?;
        self.tx
            .send(Event::RequestPath {
                dest_hash: dest_hash.0,
            })
            .map_err(|_| SendError)
    }

    /// Check if a path exists to a destination (synchronous query).
    pub fn has_path(&self, dest_hash: &rns_core::types::DestHash) -> Result<bool, SendError> {
        self.query(query::HasPath {
            dest_hash: dest_hash.0,
        })
    }

    /// The RSSI a received packet arrived with, when its interface reports
    /// it (`Reticulum.get_packet_rssi`). The latest 512 such packets are
    /// remembered.
    pub fn packet_rssi(&self, packet_hash: &[u8; 32]) -> Result<Option<i16>, SendError> {
        Ok(self.packet_signal(packet_hash)?.and_then(|s| s.rssi))
    }

    /// The SNR a received packet arrived with (`Reticulum.get_packet_snr`).
    pub fn packet_snr(&self, packet_hash: &[u8; 32]) -> Result<Option<f32>, SendError> {
        Ok(self.packet_signal(packet_hash)?.and_then(|s| s.snr))
    }

    /// The link quality, in percent, its interface reported when a packet
    /// arrived (`Reticulum.get_packet_q`).
    pub fn packet_q(&self, packet_hash: &[u8; 32]) -> Result<Option<f64>, SendError> {
        Ok(self.packet_signal(packet_hash)?.and_then(|s| s.q))
    }

    pub(super) fn packet_signal(
        &self,
        packet_hash: &[u8; 32],
    ) -> Result<Option<crate::event::PacketSignal>, SendError> {
        self.query(query::PacketSignal {
            packet_hash: *packet_hash,
        })
    }

    /// Get hop count to a destination (synchronous query).
    pub fn hops_to(&self, dest_hash: &rns_core::types::DestHash) -> Result<Option<u8>, SendError> {
        self.query(query::HopsTo {
            dest_hash: dest_hash.0,
        })
    }
}
