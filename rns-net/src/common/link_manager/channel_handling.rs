use super::*;

impl LinkManager {
    /// Flush the channel TX ring for a link, clearing outstanding messages.
    /// Called after holepunch completion where signaling messages are fire-and-forget.
    pub fn flush_channel_tx(&mut self, link_id: &LinkId) {
        if let Some(link) = self.links.get_mut(link_id) {
            if let Some(ref mut channel) = link.channel {
                channel.flush_tx();
            }
        }
    }

    /// Send a channel message on a link.
    pub fn send_channel_message(
        &mut self,
        link_id: &LinkId,
        msgtype: u16,
        payload: &[u8],
        rng: &mut dyn Rng,
    ) -> Result<Vec<LinkManagerAction>, String> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Err("unknown link".to_string()),
        };

        let channel = match link.channel {
            Some(ref mut ch) => ch,
            None => return Err("link has no active channel".to_string()),
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
                return Err(e.to_string());
            }
        };

        let _ = link;
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
                    // Encrypt and send as CHANNEL context. If the packet cannot be
                    // emitted, remove the reserved channel sequence so receivers do
                    // not stall on a gap that never reached the wire.
                    let encrypted = match self.links.get(link_id) {
                        Some(link) => match link.engine.encrypt(&raw, rng) {
                            Ok(encrypted) => encrypted,
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
                    match RawPacket::pack_raw_with_hash(
                        flags,
                        0,
                        link_id,
                        None,
                        constants::CONTEXT_CHANNEL,
                        &encrypted,
                    ) {
                        Ok((raw_bytes, packet_hash)) => {
                            if let Some(link_mut) = self.links.get_mut(link_id) {
                                link_mut
                                    .pending_channel_packets
                                    .insert(packet_hash, sequence);
                            }
                            result.push(LinkManagerAction::SendPacket {
                                raw: raw_bytes,
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
                rns_core::channel::ChannelAction::TeardownLink => {
                    result.push(LinkManagerAction::LinkClosed {
                        link_id: *link_id,
                        reason: Some(TeardownReason::Timeout),
                    });
                }
            }
        }
        result
    }
}
