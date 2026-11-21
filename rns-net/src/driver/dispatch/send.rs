//! Sending on one interface or all of them, through the outbound hooks.

use super::*;

impl Driver {
    #[cfg(test)]
    pub(crate) fn dispatch_send_on_interface_action(
        &mut self,
        interface: InterfaceId,
        raw: rns_core::transport::types::PacketBytes,
        hook_injected: &mut Vec<TransportAction>,
    ) {
        self.dispatch_send_on_interface_action_with_hooks(interface, raw, hook_injected, true);
    }

    /// Apply an outbound packet hook outcome. Returns the bytes to send and the
    /// ratchet lease that covers them, or `None` when the packet must not be
    /// sent. A replacement takes its own ratchet lease and becomes the packet
    /// a pending confirmed link send waits for.
    pub(super) fn apply_outbound_hook_outcome(
        &mut self,
        outcome: PacketHookOutcome,
        raw: rns_core::transport::types::PacketBytes,
        ratchet_lease: Option<crate::local_ratchet::AnnouncementLease>,
    ) -> Option<(
        rns_core::transport::types::PacketBytes,
        Option<crate::local_ratchet::AnnouncementLease>,
    )> {
        match outcome {
            PacketHookOutcome::Keep => Some((raw, ratchet_lease)),
            PacketHookOutcome::Drop => None,
            PacketHookOutcome::Replace(packet) => {
                let lease = match crate::local_ratchet::AnnouncementLease::acquire(
                    self.event_tx.local_ratchets(),
                    &packet.raw,
                ) {
                    Ok(lease) => lease,
                    Err(error) => {
                        log::warn!("suppressing local announcement: {error}");
                        return None;
                    }
                };
                drop(ratchet_lease);
                self.retarget_tracked_link_send(&raw, &packet);
                Some((packet.raw.into(), lease))
            }
        }
    }

    /// Send `raw` on `interface`. When `run_hooks` is false the
    /// `SendOnInterface` hook point is skipped; this is used for actions that
    /// hooks injected themselves, so a hook cannot re-trigger itself.
    pub(super) fn dispatch_send_on_interface_action_with_hooks(
        &mut self,
        interface: InterfaceId,
        raw: rns_core::transport::types::PacketBytes,
        hook_injected: &mut Vec<TransportAction>,
        run_hooks: bool,
    ) {
        let ratchet_lease = match crate::local_ratchet::AnnouncementLease::acquire(
            self.event_tx.local_ratchets(),
            &raw,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                log::warn!("suppressing local announcement: {error}");
                return;
            }
        };

        let (raw, ratchet_lease) = if run_hooks && self.hooks.attached(HookPoint::SendOnInterface) {
            let outcome = self.run_packet_hooks(
                HookPoint::SendOnInterface,
                &HookEvent::wire_packet(&raw, interface.0),
                InjectedActions::Collect(hook_injected),
                |driver| driver.hook_packet_limit(interface),
            );
            let Some(applied) = self.apply_outbound_hook_outcome(outcome, raw, ratchet_lease)
            else {
                return;
            };
            applied
        } else {
            (raw, ratchet_lease)
        };

        let is_announce = raw.len() > 2 && raw.first().is_some_and(|flags| flags & 0x03 == 0x01);
        let is_path_request = is_outbound_path_request(&raw, &self.builtin.path_request);
        if is_path_request {
            let now = time::now();
            let live_rate = self.interfaces.get(&interface).map(|entry| {
                (
                    entry.stats.outgoing_path_request_freq(now),
                    entry.stats.outgoing_path_request_samples(),
                )
            });
            if live_rate.is_some_and(|(freq, samples)| {
                self.engine
                    .should_egress_limit_path_request(interface, freq, samples)
            }) {
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Blocking recursive path request on interface {} due to active egress limiting",
                    interface.0,
                );
                return;
            }
        }
        if is_announce {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Announce:dispatching to iface {} (len={}, online={})",
                interface.0,
                raw.len(),
                self.interfaces
                    .get(&interface)
                    .map(|e| e.online && e.enabled)
                    .unwrap_or(false)
            );
        }
        // Keep targeted-send failures interface-specific. In particular, an
        // attached interface that disappeared must not fall back to broadcast
        // or be reported as a generic inability of every interface to send.
        let Some(entry) = self.interfaces.get_mut(&interface) else {
            log::warn!("[{}] cannot send on missing interface", interface.0);
            return;
        };
        if !entry.online || !entry.enabled {
            log::debug!(
                "[{}] cannot send on unavailable interface (online={}, enabled={})",
                interface.0,
                entry.online,
                entry.enabled
            );
            return;
        }
        let Ok(tracked) = Self::take_tracked_link_send(
            &mut self.tracked_link_send,
            &self.event_tx,
            &raw,
            ratchet_lease.is_some(),
        ) else {
            return;
        };
        if let Some(mut completion) = tracked {
            let data = if let Some(ref state) = entry.ifac {
                ifac::mask_outbound(&raw, state)
            } else {
                raw.to_vec()
            };
            completion.retain_ratchet(ratchet_lease.clone());
            self.pending_link_frames.push_back(PendingLinkFrame {
                interface,
                data,
                is_announce,
                completion: Some(completion),
            });
            return;
        }
        if Self::interface_send_deferred_now(entry) {
            return;
        }
        let data = if let Some(ref ifac_state) = entry.ifac {
            ifac::mask_outbound(&raw, ifac_state)
        } else {
            Vec::new()
        };
        let send_len = if entry.ifac.is_some() {
            data.len()
        } else {
            raw.len()
        };
        Self::account_outbound(
            &mut self.engine,
            entry,
            send_len,
            is_announce,
            is_path_request,
        );
        // Forwarded frames postpone the writer wakeup; the driver wakes each
        // touched writer once before it next waits for events.
        let send_result = if entry.ifac.is_some() {
            entry.writer.send_frame_deferred(&data)
        } else {
            entry.writer.send_shared_deferred(&raw)
        };
        if self.writers_to_wake.last() != Some(&interface) {
            self.writers_to_wake.push(interface);
        }
        let sent_ok = send_result.is_ok();
        Self::record_send_result(entry, &send_result, "send", interface);
        if sent_ok && is_announce {
            let sent_slice: &[u8] = if entry.ifac.is_some() { &data } else { &raw };
            let header_type = sent_slice.first().map_or(0, |flags| (flags >> 6) & 0x03);
            let dest_start = if header_type == 1 { 18usize } else { 2usize };
            let dest_preview = match sent_slice.get(dest_start..dest_start + 4) {
                Some(prefix) => format!("{:02x?}", prefix),
                None => "??".into(),
            };
            log::debug!(
                "Announce:SENT on iface {} (len={}, h={}, dest=[{}])",
                interface.0,
                sent_slice.len(),
                header_type,
                dest_preview
            );
        }
    }

    pub(crate) fn dispatch_broadcast_action(
        &mut self,
        raw: rns_core::transport::types::PacketBytes,
        exclude: Option<InterfaceId>,
        hook_injected: &mut Vec<TransportAction>,
        run_hooks: bool,
    ) {
        let ratchet_lease = match crate::local_ratchet::AnnouncementLease::acquire(
            self.event_tx.local_ratchets(),
            &raw,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                log::warn!("suppressing local announcement: {error}");
                return;
            }
        };

        let (raw, ratchet_lease) = if run_hooks
            && self.hooks.attached(HookPoint::BroadcastOnAllInterfaces)
        {
            let outcome = self.run_packet_hooks(
                HookPoint::BroadcastOnAllInterfaces,
                &HookEvent::wire_packet(&raw, 0),
                InjectedActions::Collect(hook_injected),
                // The replacement goes out on every selected interface, so it
                // must fit the smallest of them.
                |driver| {
                    driver
                        .interfaces
                        .values()
                        .filter(|entry| entry.online && entry.enabled && Some(entry.id) != exclude)
                        .map(|entry| driver.hook_packet_limit(entry.id))
                        .min()
                        .unwrap_or(rns_core::constants::MTU)
                },
            );
            let Some(applied) = self.apply_outbound_hook_outcome(outcome, raw, ratchet_lease)
            else {
                return;
            };
            applied
        } else {
            (raw, ratchet_lease)
        };

        let is_announce = raw.len() > 2 && raw.first().is_some_and(|flags| flags & 0x03 == 0x01);
        let is_path_request = is_outbound_path_request(&raw, &self.builtin.path_request);
        let Ok(tracked) = Self::take_tracked_link_send(
            &mut self.tracked_link_send,
            &self.event_tx,
            &raw,
            ratchet_lease.is_some(),
        ) else {
            return;
        };
        if let Some(mut completion) = tracked {
            completion.retain_ratchet(ratchet_lease.clone());
            let mut selected = 0;
            for entry in self.interfaces.values() {
                if entry.online
                    && entry.enabled
                    && Some(entry.id) != exclude
                    && !self.holepunch_manager.is_direct_interface(entry.id)
                {
                    selected += 1;
                    let data = entry
                        .ifac
                        .as_ref()
                        .map_or_else(|| raw.to_vec(), |state| ifac::mask_outbound(&raw, state));
                    self.pending_link_frames.push_back(PendingLinkFrame {
                        interface: entry.id,
                        data,
                        is_announce,
                        completion: Some(completion.branch()),
                    });
                }
            }
            completion.finish(if selected == 0 {
                Err(crate::link_send::LinkSendError::NoRoute)
            } else {
                Ok(())
            });
            return;
        }
        for entry in self.interfaces.values_mut() {
            // A link's direct interface carries only that link.
            if entry.online
                && entry.enabled
                && Some(entry.id) != exclude
                && !self.holepunch_manager.is_direct_interface(entry.id)
            {
                if Self::interface_send_deferred_now(entry) {
                    continue;
                }
                let data = if let Some(ref ifac_state) = entry.ifac {
                    ifac::mask_outbound(&raw, ifac_state)
                } else {
                    Vec::new()
                };
                let send_len = if entry.ifac.is_some() {
                    data.len()
                } else {
                    raw.len()
                };
                Self::account_outbound(
                    &mut self.engine,
                    entry,
                    send_len,
                    is_announce,
                    is_path_request,
                );
                let send_result = if entry.ifac.is_some() {
                    entry.writer.send_frame(&data)
                } else {
                    entry.writer.send_frame(&raw)
                };
                Self::record_send_result(entry, &send_result, "broadcast", entry.id);
            }
        }
    }

    /// The confirmed link send `raw` completes, if it is the one tracked in
    /// `tracked_link_send`.
    /// A packet with a ratchet lease starts a tracked send when none is,
    /// which fails when the link send pool has no permit left.
    #[inline]
    fn take_tracked_link_send(
        tracked_link_send: &mut Option<([u8; 32], crate::link_send::Completion)>,
        event_tx: &crate::event::EventSender,
        raw: &[u8],
        track_new: bool,
    ) -> Result<Option<crate::link_send::Completion>, LinkSendPoolFull> {
        if track_new && tracked_link_send.is_none() {
            let Ok(permit) = event_tx.link_send_pool().try_acquire() else {
                return Err(LinkSendPoolFull);
            };
            let (completion, _receipt) = crate::link_send::Completion::new(permit);
            // The engine built `raw`, so it parses; were it not to, the send
            // would go untracked rather than fail.
            if let Ok(packet) = RawPacket::unpack(raw) {
                *tracked_link_send = Some((packet.packet_hash, completion));
            }
        }
        let tracked = if tracked_link_send.as_ref().is_some_and(|(hash, _)| {
            RawPacket::unpack(raw).is_ok_and(|packet| packet.packet_hash == *hash)
        }) {
            tracked_link_send.take()
        } else {
            None
        };
        Ok(tracked.map(|(_, completion)| completion))
    }

    /// Count `send_len` bytes sent on `entry`, and the announce and path
    /// request rates they feed, passing the new rates to the engine.
    #[inline]
    fn account_outbound(
        engine: &mut TransportEngine,
        entry: &mut InterfaceEntry,
        send_len: usize,
        is_announce: bool,
        is_path_request: bool,
    ) {
        entry.stats.txb += send_len as u64;
        entry.stats.tx_packets += 1;
        if is_announce {
            entry
                .stats
                .record_outgoing_announce_bytes(time::now(), send_len);
        }
        if is_path_request {
            let now = time::now();
            entry
                .stats
                .record_outgoing_path_request_bytes(now, send_len);
            super::sync_interface_frequencies(engine, entry.id, entry.stats.frequencies(now));
        }
    }
}

/// The link send pool had no permit for a new confirmed link send.
struct LinkSendPoolFull;
