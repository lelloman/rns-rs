//! Sending on links.

use super::*;

impl LinkManager {
    /// Like [`try_send_on_link`](Self::try_send_on_link), returning no
    /// actions when the packet cannot be sent.
    pub fn send_on_link(
        &self,
        link_id: &LinkId,
        plaintext: &[u8],
        context: u8,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        self.try_send_on_link(link_id, plaintext, context, rng)
            .unwrap_or_default()
    }

    /// Prepare a best-effort direct Link packet and report admission failures.
    pub fn try_send_on_link(
        &self,
        link_id: &LinkId,
        plaintext: &[u8],
        context: u8,
        rng: &mut dyn Rng,
    ) -> Result<Vec<LinkManagerAction>, crate::event::LinkDatagramError> {
        self.pack_on_link(link_id, plaintext, context, rng)
    }

    /// Send Direct Link signalling on a link. Like any link packet it also
    /// goes out while the link is stale: falling back from a silent direct
    /// path is what can revive the link.
    pub fn send_direct_link_signal(
        &self,
        link_id: &LinkId,
        framed: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        self.pack_on_link(
            link_id,
            framed,
            rns_core::holepunch::CONTEXT_DIRECT_LINK,
            rng,
        )
        .unwrap_or_default()
    }

    pub(super) fn pack_on_link(
        &self,
        link_id: &LinkId,
        plaintext: &[u8],
        context: u8,
        rng: &mut dyn Rng,
    ) -> Result<Vec<LinkManagerAction>, crate::event::LinkDatagramError> {
        use crate::event::LinkDatagramError;
        let link = match self.links.get(link_id) {
            Some(l) => l,
            None => return Err(LinkDatagramError::LinkNotFound),
        };

        // Python's `Packet.send` only refuses a CLOSED link: a STALE one
        // still sends, and the peer's answer is what reactivates it.
        let sendable = matches!(link.engine.state(), LinkState::Active | LinkState::Stale);
        if !sendable {
            return Err(LinkDatagramError::LinkNotActive);
        }
        let maximum = link.engine.mdu();
        if plaintext.len() > maximum {
            return Err(LinkDatagramError::PayloadTooLarge {
                maximum,
                actual: plaintext.len(),
            });
        }

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        // As before, a link that cannot encrypt reports that first.
        if !link.engine.can_encrypt() {
            return Err(LinkDatagramError::EncryptionFailed);
        }
        // The ciphertext is written straight into the packet.
        let mut encrypted = Err(LinkDatagramError::EncryptionFailed);
        let raw = RawPacket::pack_raw_shared_filled_with_max_mtu(
            flags,
            0,
            link_id,
            None,
            context,
            link.engine.encrypted_len(plaintext.len()),
            link.engine.mtu() as usize,
            |payload| {
                encrypted = link
                    .engine
                    .encrypt_into(plaintext, rng, payload)
                    .map_err(|_| LinkDatagramError::EncryptionFailed);
            },
        )
        .map_err(|_| LinkDatagramError::PacketEncodingFailed)?;
        encrypted?;
        Ok(vec![LinkManagerAction::SendPacket {
            raw,
            dest_type: constants::DESTINATION_LINK,
            attached_interface: None,
        }])
    }

    /// Account a packed outbound action at the single driver dispatch point.
    /// LINKREQUEST is accounted when its engine is created since its wire
    /// destination is not the resulting link ID.
    ///
    /// Every packet sent on the link also refreshes its outbound timer, as
    /// Python's `Packet.send` sets `link.last_outbound`: the keepalive
    /// watchdog and the responder's choice to answer a probe both read it.
    pub fn record_outbound_packet<B: AsRef<[u8]>>(&mut self, packet: &RawPacket<B>) {
        if packet.flags.destination_type == constants::DESTINATION_LINK {
            if let Some(link) = self.links.get_mut(&packet.destination_hash) {
                link.engine.record_outbound_traffic(packet.data().len());
                let is_keepalive = packet.context == constants::CONTEXT_KEEPALIVE;
                link.engine.record_outbound(time::now(), is_keepalive);
            }
        }
    }
}
