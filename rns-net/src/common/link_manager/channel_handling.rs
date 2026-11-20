use super::*;

impl LinkManager {
    /// Send a channel message on a link.
    pub fn send_channel_message(
        &mut self,
        link_id: &LinkId,
        msgtype: u16,
        payload: &[u8],
        rng: &mut dyn Rng,
    ) -> Result<Vec<LinkManagerAction>, crate::ChannelSendError> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Err(crate::ChannelSendError::UnknownLink),
        };

        let channel = match link.channel {
            Some(ref mut ch) => ch,
            None => return Err(crate::ChannelSendError::NoChannel),
        };

        let link_mdu = link.engine.mdu();
        let now = time::now();
        let chan_actions = match channel.send(msgtype, payload, now, link_mdu) {
            Ok(a) => {
                link.channel_send_ok += 1;
                a
            }
            Err(e) => {
                log::debug!("Channel send failed: {:?}", e);
                match e {
                    rns_core::channel::ChannelError::NotReady => link.channel_send_not_ready += 1,
                    rns_core::channel::ChannelError::MessageTooBig => {
                        link.channel_send_too_big += 1;
                    }
                    rns_core::channel::ChannelError::InvalidEnvelope => {
                        link.channel_send_other_error += 1;
                    }
                }
                return Err(e.into());
            }
        };

        Ok(self.process_channel_actions(link_id, chan_actions, rng))
    }

    /// Convert ChannelActions to LinkManagerActions.
    pub(super) fn process_channel_actions(
        &mut self,
        link_id: &LinkId,
        actions: Vec<rns_core::channel::ChannelAction>,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let mut result = Vec::new();
        for action in actions {
            match action {
                rns_core::channel::ChannelAction::SendOnLink { raw, sequence } => {
                    // Encrypt and send as CHANNEL context, in a packet as
                    // large as the link MTU allows. If the packet cannot be
                    // emitted, remove the reserved channel sequence so receivers do
                    // not stall on a gap that never reached the wire.
                    let (encrypted, max_mtu) = match self.links.get(link_id) {
                        // An envelope packed for a larger MTU than the
                        // link has now (sent over a direct path the link
                        // fell back from) goes to the peer, which runs
                        // Direct Link, in parts that fit the link's
                        // packets; its receipt stands for the proof.
                        Some(link)
                            if constants::HEADER_MINSIZE + link.engine.encrypted_len(raw.len())
                                > link.engine.mtu() as usize =>
                        {
                            if link.direct_peer {
                                result
                                    .extend(self.send_channel_parts(link_id, &raw, sequence, rng));
                            } else {
                                log::debug!(
                                    "Link {:02x?}: channel message {} too large for the link MTU {}; held",
                                    &link_id[..4],
                                    sequence,
                                    link.engine.mtu()
                                );
                            }
                            continue;
                        }
                        Some(link) => match link.engine.encrypt(&raw, rng) {
                            Ok(encrypted) => (encrypted, link.engine.mtu() as usize),
                            Err(_) => {
                                if let Some(link_mut) = self.links.get_mut(link_id) {
                                    if let Some(channel) = link_mut.channel.as_mut() {
                                        channel.cancel_send(sequence);
                                    }
                                }
                                continue;
                            }
                        },
                        None => continue,
                    };
                    let flags = PacketFlags {
                        header_type: constants::HEADER_1,
                        context_flag: constants::FLAG_UNSET,
                        transport_type: constants::TRANSPORT_BROADCAST,
                        destination_type: constants::DESTINATION_LINK,
                        packet_type: constants::PACKET_TYPE_DATA,
                    };
                    match RawPacket::pack_raw_with_hash_with_max_mtu(
                        flags,
                        0,
                        link_id,
                        None,
                        constants::CONTEXT_CHANNEL,
                        &encrypted,
                        max_mtu,
                    ) {
                        Ok((raw_bytes, packet_hash)) => {
                            if let Some(link_mut) = self.links.get_mut(link_id) {
                                link_mut
                                    .pending_channel_packets
                                    .insert(packet_hash, sequence);
                            }
                            result.push(LinkManagerAction::SendPacket {
                                raw: raw_bytes.into(),
                                dest_type: constants::DESTINATION_LINK,
                                attached_interface: None,
                            });
                        }
                        Err(_) => {
                            if let Some(link_mut) = self.links.get_mut(link_id) {
                                if let Some(channel) = link_mut.channel.as_mut() {
                                    channel.cancel_send(sequence);
                                }
                            }
                        }
                    }
                }
                rns_core::channel::ChannelAction::MessageReceived {
                    msgtype, payload, ..
                } => {
                    result.push(LinkManagerAction::ChannelMessageReceived {
                        link_id: *link_id,
                        msgtype,
                        payload,
                    });
                }
                rns_core::channel::ChannelAction::PathFailed => {
                    // Retries ran out over a direct path: fall back first,
                    // then the resends that follow take the original route,
                    // packed for its MTU. The driver completes the fallback.
                    self.restore_original_route(link_id);
                    result.push(LinkManagerAction::DirectPathFailed { link_id: *link_id });
                }
                rns_core::channel::ChannelAction::TeardownLink => {
                    // Python `LinkChannelOutlet.timed_out` calls
                    // `Link.teardown()`: the link is closed, LINKCLOSE is sent
                    // to the peer and the reason is INITIATOR_CLOSED or
                    // DESTINATION_CLOSED depending on our role.
                    result.extend(self.teardown_link(link_id));
                }
            }
        }
        result
    }

    /// Send a channel envelope too large for the link's packets in
    /// `CHANNEL_PART` signalling messages that fit them.
    fn send_channel_parts(
        &self,
        link_id: &LinkId,
        raw: &[u8],
        sequence: Sequence,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        use rns_core::holepunch::channel_parts::{
            channel_part_size, encode_channel_part, ChannelPart, MAX_CHANNEL_PARTS,
        };
        let Some(link) = self.links.get(link_id) else {
            return Vec::new();
        };
        let size = channel_part_size(link.engine.mdu());
        let count = if size == 0 {
            0
        } else {
            raw.len().div_ceil(size)
        };
        if count == 0 || count > MAX_CHANNEL_PARTS as usize {
            return Vec::new();
        }
        log::debug!(
            "Link {:02x?}: channel message {} too large for the link MTU {}; sent in {} parts",
            &link_id[..4],
            sequence,
            link.engine.mtu(),
            count
        );
        let mut actions = Vec::with_capacity(count);
        for (index, data) in raw.chunks(size).enumerate() {
            let body = encode_channel_part(&ChannelPart {
                sequence,
                index: index as u8,
                count: count as u8,
                data,
            });
            let framed =
                rns_core::holepunch::encode_signal(rns_core::holepunch::CHANNEL_PART, &body);
            actions.extend(self.send_direct_link_signal(link_id, &framed, rng));
        }
        actions
    }

    /// A part of a channel message the peer sends in parts. Once all of it
    /// is in, the channel takes it as if it had come in one packet, and the
    /// peer gets its receipt, `CHANNEL_PART_ACK`, sent like the proof of a
    /// channel packet whether or not the channel had it already.
    pub(super) fn receive_channel_part(
        &mut self,
        link_id: &LinkId,
        body: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        use rns_core::holepunch::channel_parts::{decode_channel_part, encode_channel_part_ack};
        let Ok(part) = decode_channel_part(body) else {
            log::debug!("Dropping malformed Direct Link CHANNEL_PART");
            return Vec::new();
        };
        let Some(link) = self.links.get_mut(link_id) else {
            return Vec::new();
        };
        let Some(channel) = link.channel.as_mut() else {
            return Vec::new();
        };
        let Some(raw) = link.channel_parts.insert(part) else {
            return Vec::new();
        };
        let announced = rns_core::channel::envelope::unpack_envelope(&raw)
            .is_ok_and(|(_, sequence, _)| sequence == part.sequence);
        if !announced {
            log::debug!(
                "Link {:02x?}: channel message in parts is not message {}; dropped",
                &link_id[..4],
                part.sequence
            );
            return Vec::new();
        }
        let chan_actions = channel.receive(&raw, time::now());
        link.channel_messages_received += chan_actions
            .iter()
            .filter(|action| {
                matches!(
                    action,
                    rns_core::channel::ChannelAction::MessageReceived { .. }
                )
            })
            .count() as u64;
        let mut actions = self.process_channel_actions(link_id, chan_actions, rng);
        let framed = rns_core::holepunch::encode_signal(
            rns_core::holepunch::CHANNEL_PART_ACK,
            &encode_channel_part_ack(part.sequence),
        );
        actions.extend(self.send_direct_link_signal(link_id, &framed, rng));
        actions
    }

    /// The peer has every part of a channel message we sent in parts: it
    /// is delivered, as on its proof.
    pub(super) fn receive_channel_part_ack(
        &mut self,
        link_id: &LinkId,
        body: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let Ok(sequence) = rns_core::holepunch::channel_parts::decode_channel_part_ack(body) else {
            log::debug!("Dropping malformed Direct Link CHANNEL_PART_ACK");
            return Vec::new();
        };
        let Some(channel) = self
            .links
            .get_mut(link_id)
            .and_then(|link| link.channel.as_mut())
        else {
            return Vec::new();
        };
        let chan_actions = channel.packet_delivered(sequence);
        self.process_channel_actions(link_id, chan_actions, rng)
    }
}
