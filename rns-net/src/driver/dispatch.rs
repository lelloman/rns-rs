use super::*;

impl Driver {
    pub(crate) fn maybe_generate_proof(&mut self, dest_hash: [u8; 16], packet_hash: &[u8; 32]) {
        use rns_core::types::ProofStrategy;

        let (strategy, identity) = match self.proof_strategies.get(&dest_hash) {
            Some((s, id)) => (*s, id.as_ref()),
            None => return,
        };

        let should_prove = match strategy {
            ProofStrategy::ProveAll => true,
            ProofStrategy::ProveApp => self.callbacks.on_proof_requested(
                rns_core::types::DestHash(dest_hash),
                rns_core::types::PacketHash(*packet_hash),
            ),
            ProofStrategy::ProveNone => false,
        };

        if !should_prove {
            return;
        }

        let identity = match identity {
            Some(id) => id,
            None => {
                log::warn!(
                    "Cannot generate proof for {:02x?}: no signing key",
                    &dest_hash[..4]
                );
                return;
            }
        };

        // Sign the packet hash to create the proof
        let signature = match identity.sign(packet_hash) {
            Ok(sig) => sig,
            Err(e) => {
                log::warn!("Failed to sign proof for {:02x?}: {:?}", &dest_hash[..4], e);
                return;
            }
        };

        // Build explicit proof: [packet_hash:32][signature:64]
        let mut proof_data = Vec::with_capacity(96);
        proof_data.extend_from_slice(packet_hash);
        proof_data.extend_from_slice(&signature);

        // Address the proof to the truncated packet hash (first 16 bytes),
        // matching Python's ProofDestination (Packet.py:390-394).
        // Transport nodes create reverse_table entries keyed by truncated
        // packet hash when forwarding data, so this allows proofs to be
        // routed back to the sender via the reverse path.
        let mut proof_dest = [0u8; 16];
        proof_dest.copy_from_slice(&packet_hash[..16]);

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_PROOF,
        };

        if let Ok(packet) = RawPacket::pack(
            flags,
            0,
            &proof_dest,
            None,
            rns_core::constants::CONTEXT_NONE,
            &proof_data,
        ) {
            let actions = self.engine.handle_outbound(
                &packet,
                rns_core::constants::DESTINATION_SINGLE,
                None,
                time::now(),
            );
            self.dispatch_all(actions);
            log::debug!(
                "Generated proof for packet on dest {:02x?}",
                &dest_hash[..4]
            );
        }
    }

    /// Handle an inbound proof packet: validate and fire on_proof callback.
    pub(crate) fn handle_inbound_proof(
        &mut self,
        dest_hash: [u8; 16],
        proof_data: &[u8],
        _raw_packet_hash: &[u8; 32],
    ) {
        // Reticulum supports both proof formats:
        // - explicit: [packet_hash:32][signature:64]
        // - implicit: [signature:64], keyed by proof destination hash
        let (tracked_hash, signature): ([u8; 32], &[u8]) = if proof_data.len() >= 96 {
            let mut tracked_hash = [0u8; 32];
            tracked_hash.copy_from_slice(&proof_data[..32]);
            (tracked_hash, &proof_data[32..96])
        } else if proof_data.len() == 64 {
            let mut candidates = self
                .sent_packets
                .iter()
                .filter_map(|(packet_hash, _)| {
                    if packet_hash[..16] == dest_hash {
                        Some(*packet_hash)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            if candidates.is_empty() {
                log::debug!(
                    "Implicit proof for unknown packet prefix {:02x?} on dest {:02x?}",
                    &dest_hash[..4],
                    &dest_hash[..4]
                );
                return;
            }

            // Multiple matches are extremely unlikely (16-byte truncated hash).
            // Use the newest tracked packet for deterministic behavior.
            if candidates.len() > 1 {
                candidates.sort_by(|a, b| {
                    let ta = self
                        .sent_packets
                        .get(a)
                        .map(|(_, t)| *t)
                        .unwrap_or_default();
                    let tb = self
                        .sent_packets
                        .get(b)
                        .map(|(_, t)| *t)
                        .unwrap_or_default();
                    tb.partial_cmp(&ta).unwrap_or(core::cmp::Ordering::Equal)
                });
                log::debug!(
                    "Implicit proof matched {} candidates for prefix {:02x?}; using newest",
                    candidates.len(),
                    &dest_hash[..4]
                );
            }

            (candidates[0], &proof_data[..64])
        } else {
            log::debug!("Unsupported proof length: {} bytes", proof_data.len());
            return;
        };

        // Look up the tracked sent packet
        if let Some((tracked_dest, sent_time)) = self.sent_packets.remove(&tracked_hash) {
            // Validate the proof signature using the destination's public key
            // (matches Python's PacketReceipt.validate_proof behavior)
            if let Some(announced) = self.known_destination_announced(&tracked_dest) {
                let identity =
                    rns_crypto::identity::Identity::from_public_key(&announced.public_key);
                let mut sig = [0u8; 64];
                sig.copy_from_slice(signature);
                if !identity.verify(&sig, &tracked_hash) {
                    log::debug!("Proof signature invalid for {:02x?}", &tracked_hash[..4],);
                    return;
                }
                let _ = self.mark_known_destination_used(&tracked_dest);
            } else {
                log::debug!(
                    "No known identity for dest {:02x?}, accepting proof without signature check",
                    &tracked_dest[..4],
                );
            }

            let now = time::now();
            let rtt = now - sent_time;
            log::debug!(
                "Proof received for {:02x?} rtt={:.3}s",
                &tracked_hash[..4],
                rtt,
            );
            self.completed_proofs.insert(tracked_hash, (rtt, now));
            self.callbacks.on_proof(
                rns_core::types::DestHash(tracked_dest),
                rns_core::types::PacketHash(tracked_hash),
                rtt,
            );
        } else {
            log::debug!(
                "Proof for unknown packet {:02x?} on dest {:02x?}",
                &tracked_hash[..4],
                &dest_hash[..4],
            );
        }
    }

    pub(crate) fn interface_send_deferred(entry: &InterfaceEntry, now: Instant) -> bool {
        matches!(entry.send_retry_at, Some(retry_at) if now < retry_at)
    }

    pub(crate) fn record_send_result(
        entry: &mut InterfaceEntry,
        result: &std::io::Result<()>,
        context: &str,
        interface_id: InterfaceId,
    ) {
        match result {
            Ok(()) => {
                entry.send_retry_at = None;
                entry.send_retry_backoff = Duration::ZERO;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let next_backoff = if entry.send_retry_backoff.is_zero() {
                    SEND_RETRY_BACKOFF_MIN
                } else {
                    (entry.send_retry_backoff * 2).min(SEND_RETRY_BACKOFF_MAX)
                };
                entry.send_retry_backoff = next_backoff;
                entry.send_retry_at = Some(Instant::now() + next_backoff);
                log::debug!(
                    "[{}] {} deferred after WouldBlock; retry in {:?}",
                    interface_id.0,
                    context,
                    next_backoff
                );
            }
            Err(e) => {
                entry.send_retry_at = None;
                entry.send_retry_backoff = Duration::ZERO;
                log::warn!("[{}] {} failed: {}", interface_id.0, context, e);
            }
        }
    }

    pub(crate) fn dispatch_send_on_interface_action(
        &mut self,
        interface: InterfaceId,
        raw: rns_core::transport::types::PacketBytes,
        _hook_injected: &mut Vec<TransportAction>,
    ) {
        #[cfg(feature = "hooks")]
        {
            let pkt_ctx = rns_hooks::PacketContext {
                flags: if raw.is_empty() { 0 } else { raw[0] },
                hops: if raw.len() > 1 { raw[1] } else { 0 },
                destination_hash: extract_dest_hash(&raw),
                context: 0,
                packet_hash: [0; 32],
                interface_id: interface.0,
                data_offset: 0,
                data_len: raw.len() as u32,
            };
            let ctx = HookContext::Packet {
                ctx: &pkt_ctx,
                raw: &raw,
            };
            let now = time::now();
            let engine_ref = EngineRef {
                engine: &self.engine,
                interfaces: &self.interfaces,
                link_manager: &self.link_manager,
                now,
            };
            let provider_events_enabled = self.provider_events_enabled();
            if let Some(ref e) = run_hook_inner(
                &mut self.hook_slots[HookPoint::SendOnInterface as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.collect_hook_side_effects("SendOnInterface", e, _hook_injected);
                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                    return;
                }
            }
        }

        let is_announce = raw.len() > 2 && (raw[0] & 0x03) == 0x01;
        if is_announce {
            log::debug!(
                "Announce:dispatching to iface {} (len={}, online={})",
                interface.0,
                raw.len(),
                self.interfaces
                    .get(&interface)
                    .map(|e| e.online && e.enabled)
                    .unwrap_or(false)
            );
        }
        if let Some(entry) = self.interfaces.get_mut(&interface) {
            if entry.online && entry.enabled {
                if Self::interface_send_deferred(entry, Instant::now()) {
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
                entry.stats.txb += send_len as u64;
                entry.stats.tx_packets += 1;
                if is_announce {
                    entry.stats.record_outgoing_announce(time::now());
                }
                let send_result = if entry.ifac.is_some() {
                    entry.writer.send_frame(&data)
                } else {
                    entry.writer.send_frame(&raw)
                };
                let sent_ok = send_result.is_ok();
                Self::record_send_result(entry, &send_result, "send", interface);
                if sent_ok && is_announce {
                    let sent_slice: &[u8] = if entry.ifac.is_some() { &data } else { &raw };
                    let header_type = (sent_slice[0] >> 6) & 0x03;
                    let dest_start = if header_type == 1 { 18usize } else { 2usize };
                    let dest_preview = if sent_slice.len() >= dest_start + 4 {
                        format!("{:02x?}", &sent_slice[dest_start..dest_start + 4])
                    } else {
                        "??".into()
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
        }
    }

    pub(crate) fn dispatch_broadcast_action(
        &mut self,
        raw: rns_core::transport::types::PacketBytes,
        exclude: Option<InterfaceId>,
        _hook_injected: &mut Vec<TransportAction>,
    ) {
        #[cfg(feature = "hooks")]
        {
            let pkt_ctx = rns_hooks::PacketContext {
                flags: if raw.is_empty() { 0 } else { raw[0] },
                hops: if raw.len() > 1 { raw[1] } else { 0 },
                destination_hash: extract_dest_hash(&raw),
                context: 0,
                packet_hash: [0; 32],
                interface_id: 0,
                data_offset: 0,
                data_len: raw.len() as u32,
            };
            let ctx = HookContext::Packet {
                ctx: &pkt_ctx,
                raw: &raw,
            };
            let now = time::now();
            let engine_ref = EngineRef {
                engine: &self.engine,
                interfaces: &self.interfaces,
                link_manager: &self.link_manager,
                now,
            };
            let provider_events_enabled = self.provider_events_enabled();
            if let Some(ref e) = run_hook_inner(
                &mut self.hook_slots[HookPoint::BroadcastOnAllInterfaces as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.collect_hook_side_effects("BroadcastOnAllInterfaces", e, _hook_injected);
                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                    return;
                }
            }
        }

        let is_announce = raw.len() > 2 && (raw[0] & 0x03) == 0x01;
        for entry in self.interfaces.values_mut() {
            if entry.online && entry.enabled && Some(entry.id) != exclude {
                if Self::interface_send_deferred(entry, Instant::now()) {
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
                entry.stats.txb += send_len as u64;
                entry.stats.tx_packets += 1;
                if is_announce {
                    entry.stats.record_outgoing_announce(time::now());
                }
                let send_result = if entry.ifac.is_some() {
                    entry.writer.send_frame(&data)
                } else {
                    entry.writer.send_frame(&raw)
                };
                Self::record_send_result(entry, &send_result, "broadcast", entry.id);
            }
        }
    }

    pub(crate) fn dispatch_deliver_local_action(
        &mut self,
        destination_hash: [u8; 16],
        raw: rns_core::transport::types::PacketBytes,
        packet_hash: [u8; 32],
        receiving_interface: InterfaceId,
        _hook_injected: &mut Vec<TransportAction>,
    ) {
        #[cfg(feature = "hooks")]
        {
            let pkt_ctx = rns_hooks::PacketContext {
                flags: 0,
                hops: 0,
                destination_hash,
                context: 0,
                packet_hash,
                interface_id: receiving_interface.0,
                data_offset: 0,
                data_len: raw.len() as u32,
            };
            let ctx = HookContext::Packet {
                ctx: &pkt_ctx,
                raw: &raw,
            };
            let now = time::now();
            let engine_ref = EngineRef {
                engine: &self.engine,
                interfaces: &self.interfaces,
                link_manager: &self.link_manager,
                now,
            };
            let provider_events_enabled = self.provider_events_enabled();
            if let Some(ref e) = run_hook_inner(
                &mut self.hook_slots[HookPoint::DeliverLocal as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.collect_hook_side_effects("DeliverLocal", e, _hook_injected);
                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                    return;
                }
            }
        }

        if destination_hash == self.tunnel_synth_dest {
            self.handle_tunnel_synth_delivery(&raw);
        } else if destination_hash == self.path_request_dest {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let actions =
                    self.engine
                        .handle_path_request(&packet.data, receiving_interface, time::now());
                self.dispatch_all(actions);
            }
        } else if self.link_manager.is_link_destination(&destination_hash) {
            let link_actions = self.link_manager.handle_local_delivery(
                destination_hash,
                &raw,
                packet_hash,
                receiving_interface,
                &mut self.rng,
            );
            if link_actions.is_empty() {
                if let Ok(packet) = RawPacket::unpack(&raw) {
                    if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_PROOF {
                        self.handle_inbound_proof(destination_hash, &packet.data, &packet_hash);
                        return;
                    }
                }
                self.maybe_generate_proof(destination_hash, &packet_hash);
                self.callbacks.on_local_delivery(
                    rns_core::types::DestHash(destination_hash),
                    raw.to_vec(),
                    rns_core::types::PacketHash(packet_hash),
                );
            } else {
                self.dispatch_link_actions(link_actions);
            }
        } else {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_PROOF {
                    self.handle_inbound_proof(destination_hash, &packet.data, &packet_hash);
                    return;
                }
            }
            self.maybe_generate_proof(destination_hash, &packet_hash);
            self.callbacks.on_local_delivery(
                rns_core::types::DestHash(destination_hash),
                raw.to_vec(),
                rns_core::types::PacketHash(packet_hash),
            );
        }
    }

    /// Dispatch a list of transport actions.
    pub(crate) fn dispatch_all(&mut self, actions: Vec<TransportAction>) {
        #[cfg(feature = "hooks")]
        let mut hook_injected: Vec<TransportAction> = Vec::new();
        #[cfg(not(feature = "hooks"))]
        let mut hook_injected: Vec<TransportAction> = Vec::new();

        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    self.dispatch_send_on_interface_action(interface, raw, &mut hook_injected);
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    self.dispatch_broadcast_action(raw, exclude, &mut hook_injected);
                }
                TransportAction::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                    receiving_interface,
                } => {
                    self.dispatch_deliver_local_action(
                        destination_hash,
                        raw,
                        packet_hash,
                        receiving_interface,
                        &mut hook_injected,
                    );
                }
                TransportAction::AnnounceReceived {
                    destination_hash,
                    identity_hash,
                    public_key,
                    name_hash,
                    ratchet,
                    app_data,
                    hops,
                    receiving_interface,
                    ..
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::AnnounceReceived as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "AnnounceReceived",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }

                    // Check if this is a discovery announce (matched by name_hash
                    // since discovery is a SINGLE destination — its dest hash varies
                    // with the sender's identity).
                    if name_hash == self.discovery_name_hash {
                        if self.discover_interfaces {
                            if let Some(ref app_data) = app_data {
                                if let Some(mut discovered) =
                                    crate::discovery::parse_interface_announce(
                                        app_data,
                                        &identity_hash,
                                        hops,
                                        self.discovery_required_value,
                                    )
                                {
                                    // Check if we already have this interface
                                    if let Ok(Some(existing)) =
                                        self.discovered_interfaces.load(&discovered.discovery_hash)
                                    {
                                        discovered.discovered = existing.discovered;
                                        discovered.heard_count = existing.heard_count + 1;
                                    }
                                    if let Err(e) = self.discovered_interfaces.store(&discovered) {
                                        log::warn!("Failed to store discovered interface: {}", e);
                                    } else {
                                        log::debug!(
                                            "Discovered interface '{}' ({}) at {}:{} [stamp={}]",
                                            discovered.name,
                                            discovered.interface_type,
                                            discovered.reachable_on.as_deref().unwrap_or("?"),
                                            discovered
                                                .port
                                                .map(|p| p.to_string())
                                                .unwrap_or_else(|| "?".into()),
                                            discovered.stamp_value,
                                        );
                                    }
                                }
                            }
                        }
                        // Still cache the identity and notify callbacks
                    }

                    if let (Some(store), Some(ratchet)) = (&self.ratchet_store, ratchet) {
                        let entry = crate::storage::RatchetEntry {
                            ratchet,
                            received_at: time::now(),
                        };
                        if let Err(err) = store.remember(destination_hash, entry) {
                            log::warn!(
                                "failed to persist ratchet for {:02x}{:02x}{:02x}{:02x}..: {}",
                                destination_hash[0],
                                destination_hash[1],
                                destination_hash[2],
                                destination_hash[3],
                                err
                            );
                        }
                    }

                    // Cache the announced identity
                    let announced = crate::destination::AnnouncedIdentity {
                        dest_hash: rns_core::types::DestHash(destination_hash),
                        identity_hash: rns_core::types::IdentityHash(identity_hash),
                        public_key,
                        app_data: app_data.clone(),
                        hops,
                        received_at: time::now(),
                        receiving_interface,
                    };
                    self.upsert_known_destination(destination_hash, announced.clone());
                    log::info!(
                        "Announce:validated dest={:02x}{:02x}{:02x}{:02x}.. hops={}",
                        destination_hash[0],
                        destination_hash[1],
                        destination_hash[2],
                        destination_hash[3],
                        hops,
                    );
                    self.callbacks.on_announce(announced);
                }
                TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    interface,
                    ..
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::PathUpdated as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("PathUpdated", e, &mut hook_injected);
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    let _ = interface;

                    let _ = self.mark_known_destination_used(&destination_hash);
                    self.callbacks
                        .on_path_updated(rns_core::types::DestHash(destination_hash), hops);
                }
                TransportAction::ForwardToLocalClients { raw, exclude } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.enabled
                            && entry.info.is_local_client
                            && Some(entry.id) != exclude
                        {
                            if Self::interface_send_deferred(entry, Instant::now()) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.to_vec()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            let send_result = entry.writer.send_frame(&data);
                            Self::record_send_result(
                                entry,
                                &send_result,
                                "forward to local client",
                                entry.id,
                            );
                        }
                    }
                }
                TransportAction::ForwardPlainBroadcast {
                    raw,
                    to_local,
                    exclude,
                } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.enabled
                            && entry.info.is_local_client == to_local
                            && Some(entry.id) != exclude
                        {
                            if Self::interface_send_deferred(entry, Instant::now()) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.to_vec()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            let send_result = entry.writer.send_frame(&data);
                            Self::record_send_result(
                                entry,
                                &send_result,
                                "forward plain broadcast",
                                entry.id,
                            );
                        }
                    }
                }
                TransportAction::CacheAnnounce { packet_hash, raw } => {
                    if let Some(ref cache) = self.announce_cache {
                        if let Err(e) = cache.store(&packet_hash, &raw, None) {
                            log::warn!("Failed to cache announce: {}", e);
                        }
                    }
                }
                TransportAction::TunnelSynthesize {
                    interface,
                    data,
                    dest_hash,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: 0,
                            hops: 0,
                            destination_hash: dest_hash,
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface.0,
                            data_offset: 0,
                            data_len: data.len() as u32,
                        };
                        let ctx = HookContext::Packet {
                            ctx: &pkt_ctx,
                            raw: &data,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::TunnelSynthesize as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "TunnelSynthesize",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }
                    // Pack as BROADCAST DATA PLAIN packet and send on interface
                    let flags = rns_core::packet::PacketFlags {
                        header_type: rns_core::constants::HEADER_1,
                        context_flag: rns_core::constants::FLAG_UNSET,
                        transport_type: rns_core::constants::TRANSPORT_BROADCAST,
                        destination_type: rns_core::constants::DESTINATION_PLAIN,
                        packet_type: rns_core::constants::PACKET_TYPE_DATA,
                    };
                    if let Ok(packet) = rns_core::packet::RawPacket::pack(
                        flags,
                        0,
                        &dest_hash,
                        None,
                        rns_core::constants::CONTEXT_NONE,
                        &data,
                    ) {
                        if let Some(entry) = self.interfaces.get_mut(&interface) {
                            if entry.online && entry.enabled {
                                let raw = if let Some(ref ifac_state) = entry.ifac {
                                    ifac::mask_outbound(&packet.raw, ifac_state)
                                } else {
                                    packet.raw
                                };
                                entry.stats.txb += raw.len() as u64;
                                entry.stats.tx_packets += 1;
                                if let Err(e) = entry.writer.send_frame(&raw) {
                                    log::warn!(
                                        "[{}] tunnel synthesize send failed: {}",
                                        entry.info.id.0,
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
                TransportAction::TunnelEstablished {
                    tunnel_id,
                    interface,
                } => {
                    log::info!(
                        "Tunnel established: {:02x?} on interface {}",
                        &tunnel_id[..4],
                        interface.0
                    );
                }
                TransportAction::AnnounceRetransmit {
                    destination_hash,
                    hops,
                    interface,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.map(|i| i.0).unwrap_or(0),
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::AnnounceRetransmit as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "AnnounceRetransmit",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (destination_hash, hops, interface);
                    }
                }
                TransportAction::LinkRequestReceived {
                    link_id,
                    destination_hash: _,
                    receiving_interface,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkRequestReceived as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkRequestReceived",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (link_id, receiving_interface);
                    }
                }
                TransportAction::LinkEstablished { link_id, interface } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkEstablished as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkEstablished",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (link_id, interface);
                    }
                }
                TransportAction::LinkClosed { link_id } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkClosed as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("LinkClosed", e, &mut hook_injected);
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = link_id;
                    }
                }
            }
        }

        // Dispatch any actions injected by hooks during action processing
        #[cfg(feature = "hooks")]
        if !hook_injected.is_empty() {
            self.dispatch_all(hook_injected);
        }
    }

    /// Dispatch link manager actions.
    pub(crate) fn dispatch_link_actions(&mut self, actions: Vec<LinkManagerAction>) {
        #[cfg(feature = "hooks")]
        let mut hook_injected: Vec<TransportAction> = Vec::new();

        for action in actions {
            match action {
                LinkManagerAction::SendPacket {
                    mut raw,
                    dest_type,
                    mut attached_interface,
                } => {
                    if dest_type == rns_core::constants::DESTINATION_LINK
                        && attached_interface.is_none()
                    {
                        if let Ok(packet) = RawPacket::unpack(&raw) {
                            let link_id = packet.destination_hash;
                            if let Some(route_hint) =
                                self.link_manager.get_link_route_hint(&link_id)
                            {
                                attached_interface = Some(route_hint.interface);
                                if packet.flags.header_type == rns_core::constants::HEADER_1 {
                                    if let Some(next_hop) = route_hint.transport_id {
                                        raw = inject_transport_header(&packet.raw, &next_hop);
                                        log::debug!(
                                            "Link SendPacket rewrite: link={:02x?} iface={} header=1->2 tid={:02x?}",
                                            &link_id[..4],
                                            route_hint.interface.0,
                                            &next_hop[..4]
                                        );
                                    } else {
                                        log::debug!(
                                            "Link SendPacket route: link={:02x?} iface={} header=1 (no transport_id)",
                                            &link_id[..4],
                                            route_hint.interface.0
                                        );
                                    }
                                }
                            } else {
                                log::debug!(
                                    "Link SendPacket no route hint: link={:02x?}",
                                    &link_id[..4]
                                );
                            }
                        }
                    }

                    // Route through the transport engine's outbound path
                    match RawPacket::unpack(&raw) {
                        Ok(packet) => {
                            if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
                                self.sent_packets.insert(
                                    packet.packet_hash,
                                    (packet.destination_hash, time::now()),
                                );
                            }
                            let transport_actions = self.engine.handle_outbound(
                                &packet,
                                dest_type,
                                attached_interface,
                                time::now(),
                            );
                            self.dispatch_all(transport_actions);
                        }
                        Err(e) => {
                            log::warn!("LinkManager SendPacket: failed to unpack: {:?}", e);
                        }
                    }
                }
                LinkManagerAction::LinkEstablished {
                    link_id,
                    dest_hash,
                    rtt,
                    is_initiator,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkEstablished as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkEstablished",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    log::info!(
                        "Link established: {:02x?} rtt={:.3}s initiator={}",
                        &link_id[..4],
                        rtt,
                        is_initiator,
                    );
                    self.callbacks.on_link_established(
                        rns_core::types::LinkId(link_id),
                        rns_core::types::DestHash(dest_hash),
                        rtt,
                        is_initiator,
                    );
                }
                LinkManagerAction::LinkClosed { link_id, reason } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkClosed as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("LinkClosed", e, &mut hook_injected);
                        }
                    }
                    log::info!("Link closed: {:02x?} reason={:?}", &link_id[..4], reason);
                    self.holepunch_manager.link_closed(&link_id);
                    self.callbacks
                        .on_link_closed(rns_core::types::LinkId(link_id), reason);
                }
                LinkManagerAction::RemoteIdentified {
                    link_id,
                    identity_hash,
                    public_key,
                } => {
                    log::debug!(
                        "Remote identified on link {:02x?}: {:02x?}",
                        &link_id[..4],
                        &identity_hash[..4],
                    );
                    self.callbacks.on_remote_identified(
                        rns_core::types::LinkId(link_id),
                        rns_core::types::IdentityHash(identity_hash),
                        public_key,
                    );
                }
                LinkManagerAction::RegisterLinkDest { link_id } => {
                    // Register the link_id as a LINK destination in the transport engine
                    self.engine
                        .register_destination(link_id, rns_core::constants::DESTINATION_LINK);
                }
                LinkManagerAction::DeregisterLinkDest { link_id } => {
                    self.engine.deregister_destination(&link_id);
                }
                LinkManagerAction::ManagementRequest {
                    link_id,
                    path_hash,
                    data,
                    request_id,
                    remote_identity,
                } => {
                    self.handle_management_request(
                        link_id,
                        path_hash,
                        data,
                        request_id,
                        remote_identity,
                    );
                }
                LinkManagerAction::ResourceReceived {
                    link_id,
                    data,
                    metadata,
                } => {
                    self.callbacks.on_resource_received(
                        rns_core::types::LinkId(link_id),
                        data,
                        metadata,
                    );
                }
                LinkManagerAction::ResourceCompleted { link_id } => {
                    self.callbacks
                        .on_resource_completed(rns_core::types::LinkId(link_id));
                }
                LinkManagerAction::ResourceFailed { link_id, error } => {
                    log::debug!("Resource failed on link {:02x?}: {}", &link_id[..4], error);
                    self.callbacks
                        .on_resource_failed(rns_core::types::LinkId(link_id), error);
                }
                LinkManagerAction::ResourceProgress {
                    link_id,
                    received,
                    total,
                } => {
                    self.callbacks.on_resource_progress(
                        rns_core::types::LinkId(link_id),
                        received,
                        total,
                    );
                }
                LinkManagerAction::ResourceAcceptQuery {
                    link_id,
                    resource_hash,
                    transfer_size,
                    has_metadata,
                } => {
                    let accept = self.callbacks.on_resource_accept_query(
                        rns_core::types::LinkId(link_id),
                        resource_hash.clone(),
                        transfer_size,
                        has_metadata,
                    );
                    let accept_actions = self.link_manager.accept_resource(
                        &link_id,
                        &resource_hash,
                        accept,
                        &mut self.rng,
                    );
                    // Re-dispatch (recursive but bounded: accept_resource won't produce more AcceptQuery)
                    self.dispatch_link_actions(accept_actions);
                }
                LinkManagerAction::ChannelMessageReceived {
                    link_id,
                    msgtype,
                    payload,
                } => {
                    // Intercept hole-punch signaling messages (0xFE00..=0xFE04)
                    if HolePunchManager::is_holepunch_message(msgtype) {
                        let derived_key = self.link_manager.get_derived_key(&link_id);
                        let tx = self.get_event_sender();
                        let (handled, hp_actions) = self.holepunch_manager.handle_signal(
                            link_id,
                            msgtype,
                            payload,
                            derived_key.as_deref(),
                            &tx,
                        );
                        if handled {
                            self.dispatch_holepunch_actions(hp_actions);
                        }
                    } else {
                        self.callbacks.on_channel_message(
                            rns_core::types::LinkId(link_id),
                            msgtype,
                            payload,
                        );
                    }
                }
                LinkManagerAction::LinkDataReceived {
                    link_id,
                    context,
                    data,
                } => {
                    self.callbacks
                        .on_link_data(rns_core::types::LinkId(link_id), context, data);
                }
                LinkManagerAction::ResponseReceived {
                    link_id,
                    request_id,
                    data,
                } => {
                    self.callbacks
                        .on_response(rns_core::types::LinkId(link_id), request_id, data);
                }
                LinkManagerAction::LinkRequestReceived {
                    link_id,
                    receiving_interface,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkRequestReceived as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkRequestReceived",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (link_id, receiving_interface);
                    }
                }
            }
        }

        // Dispatch any actions injected by hooks during action processing
        #[cfg(feature = "hooks")]
        if !hook_injected.is_empty() {
            self.dispatch_all(hook_injected);
        }
    }

    /// Dispatch hole-punch manager actions.
    pub(crate) fn dispatch_holepunch_actions(&mut self, actions: Vec<HolePunchManagerAction>) {
        for action in actions {
            match action {
                HolePunchManagerAction::SendChannelMessage {
                    link_id,
                    msgtype,
                    payload,
                } => {
                    if let Ok(link_actions) = self.link_manager.send_channel_message(
                        &link_id,
                        msgtype,
                        &payload,
                        &mut self.rng,
                    ) {
                        self.dispatch_link_actions(link_actions);
                    }
                }
                HolePunchManagerAction::DirectConnectEstablished {
                    link_id,
                    session_id,
                    interface_id,
                    rtt,
                    mtu,
                } => {
                    log::info!(
                        "Direct connection established for link {:02x?} session {:02x?} iface {} rtt={:.1}ms mtu={}",
                        &link_id[..4], &session_id[..4], interface_id.0, rtt * 1000.0, mtu
                    );
                    // Redirect the link's path to use the direct interface
                    self.engine
                        .redirect_path(&link_id, interface_id, time::now());
                    // Update the link's RTT and MTU to reflect the direct path
                    self.link_manager.set_link_rtt(&link_id, rtt);
                    self.link_manager.set_link_mtu(&link_id, mtu);
                    // Reset inbound timer — set_rtt shortens the keepalive/stale
                    // intervals, so without this the link goes stale immediately
                    self.link_manager.record_link_inbound(&link_id);
                    // Flush holepunch signaling messages from the channel window
                    self.link_manager.flush_channel_tx(&link_id);
                    self.callbacks.on_direct_connect_established(
                        rns_core::types::LinkId(link_id),
                        interface_id,
                    );
                }
                HolePunchManagerAction::DirectConnectFailed {
                    link_id,
                    session_id,
                    reason,
                } => {
                    log::debug!(
                        "Direct connection failed for link {:02x?} session {:02x?} reason={}",
                        &link_id[..4],
                        &session_id[..4],
                        reason
                    );
                    self.callbacks
                        .on_direct_connect_failed(rns_core::types::LinkId(link_id), reason);
                }
            }
        }
    }
}
