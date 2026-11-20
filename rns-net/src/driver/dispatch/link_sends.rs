//! Link sends whose completion the application waits on.

use super::*;

impl Driver {
    pub(crate) fn handle_confirmed_outbound(
        &mut self,
        raw: Vec<u8>,
        dest_type: u8,
        replay: Option<Box<crate::common::event::AnnounceReplay>>,
        completion: crate::link_send::Completion,
        proof_key: Option<[u8; 32]>,
    ) {
        use crate::link_send::LinkSendError;
        if self.is_draining() {
            completion.finish(Err(LinkSendError::Draining));
            return;
        }
        let Ok(packet) = RawPacket::unpack(&raw) else {
            completion.finish(Err(LinkSendError::PacketBuildFailed));
            return;
        };
        if let Some(replay) = replay {
            let crate::common::event::AnnounceReplay {
                dest_hash,
                name_hash,
                identity_prv_key,
                app_data,
            } = *replay;
            self.shared_announces.insert(
                dest_hash,
                SharedAnnounceRecord {
                    name_hash,
                    identity_prv_key,
                    app_data,
                },
            );
        }
        let now = time::now();
        if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
            self.proofs
                .sent_packets
                .insert(packet.packet_hash, (packet.destination_hash, now));
            if let Some(key) = proof_key {
                self.proofs.sent_packet_keys.insert(packet.packet_hash, key);
            }
        }
        // These APIs originate hops=0 packets, so announcement relay bandwidth
        // queues do not apply. Retain the normal routing and per-send hooks.
        let actions = self.engine.handle_outbound(&packet, dest_type, None, now);
        let mut selected = 0;
        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    selected += 1;
                    self.tracked_link_send = Some((packet.packet_hash, completion.branch()));
                    self.dispatch_all(vec![TransportAction::SendOnInterface { interface, raw }]);
                    if let Some((_, branch)) = self.tracked_link_send.take() {
                        branch.finish(Err(LinkSendError::Rejected));
                    }
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    // Broadcast hooks still run in dispatch_broadcast_action.
                    self.tracked_link_send = Some((packet.packet_hash, completion.branch()));
                    self.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
                        raw,
                        exclude,
                    }]);
                    if let Some((_, branch)) = self.tracked_link_send.take() {
                        branch.finish(Err(LinkSendError::Rejected));
                    }
                    selected += 1;
                }
                other => self.dispatch_all(vec![other]),
            }
        }
        completion.finish(if selected == 0 {
            Err(LinkSendError::NoRoute)
        } else {
            Ok(())
        });
    }

    /// Pending frames own admission permits until actual writer completion,
    /// bounding this queue together with driver events and in-flight writes.
    pub(crate) fn flush_pending_link_frames(&mut self) {
        use crate::link_send::LinkSendError;
        // Called on every driver iteration; avoid seeding a hasher when idle.
        if self.pending_link_frames.is_empty() {
            return;
        }
        let mut blocked = std::collections::HashSet::new();
        for _ in 0..self.pending_link_frames.len() {
            let Some(mut frame) = self.pending_link_frames.pop_front() else {
                break;
            };
            if blocked.contains(&frame.interface) {
                self.pending_link_frames.push_back(frame);
                continue;
            }
            let Some(entry) = self
                .interfaces
                .get_mut(&frame.interface)
                .filter(|e| e.online && e.enabled)
            else {
                if let Some(completion) = frame.completion.take() {
                    completion.finish(Err(LinkSendError::InterfaceUnavailable));
                }
                continue;
            };
            match entry
                .writer
                .enqueue_confirmed(&frame.data, &mut frame.completion)
            {
                Ok(()) => {
                    entry.stats.txb += frame.data.len() as u64;
                    entry.stats.tx_packets += 1;
                    if frame.is_announce {
                        entry
                            .stats
                            .record_outgoing_announce_bytes(time::now(), frame.data.len());
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && frame.completion.is_some() =>
                {
                    blocked.insert(frame.interface);
                    self.pending_link_frames.push_back(frame);
                }
                Err(error) => {
                    if let Some(completion) = frame.completion.take() {
                        completion.finish(Err(LinkSendError::WriteFailed(error.to_string())));
                    }
                }
            }
        }
    }
}
