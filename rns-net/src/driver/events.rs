use super::*;

impl Driver {
    pub(crate) fn handle_frame_event(&mut self, interface_id: InterfaceId, data: Vec<u8>) {
        if data.len() > 2 && (data[0] & 0x03) == 0x01 {
            log::debug!(
                "Announce:frame from iface {} (len={}, flags=0x{:02x})",
                interface_id.0,
                data.len(),
                data[0]
            );
        }
        if let Some(entry) = self.interfaces.get(&interface_id) {
            if !entry.enabled || !entry.online {
                return;
            }
        }
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.stats.rxb += data.len() as u64;
            entry.stats.rx_packets += 1;
        }

        let packet = if let Some(entry) = self.interfaces.get(&interface_id) {
            if let Some(ref ifac_state) = entry.ifac {
                match ifac::unmask_inbound(&data, ifac_state) {
                    Some(unmasked) => unmasked,
                    None => {
                        log::debug!("[{}] IFAC rejected packet", interface_id.0);
                        return;
                    }
                }
            } else {
                if data.len() > 2 && data[0] & 0x80 == 0x80 {
                    log::debug!(
                        "[{}] dropping packet with IFAC flag on non-IFAC interface",
                        interface_id.0
                    );
                    return;
                }
                data
            }
        } else {
            data
        };

        #[cfg(feature = "rns-hooks")]
        {
            let pkt_ctx = rns_hooks::PacketContext {
                flags: if packet.is_empty() { 0 } else { packet[0] },
                hops: if packet.len() > 1 { packet[1] } else { 0 },
                destination_hash: extract_dest_hash(&packet),
                context: 0,
                packet_hash: [0; 32],
                interface_id: interface_id.0,
                data_offset: 0,
                data_len: packet.len() as u32,
            };
            let ctx = HookContext::Packet {
                ctx: &pkt_ctx,
                raw: &packet,
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
                &mut self.hook_slots[HookPoint::PreIngress as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.forward_hook_side_effects("PreIngress", e);
                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                    return;
                }
            }
        }

        if packet.len() > 2 && (packet[0] & 0x03) == 0x01 {
            let now = time::now();
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.record_incoming_announce(now);
            }
        }

        if let Some(entry) = self.interfaces.get(&interface_id) {
            self.engine
                .update_interface_freq(interface_id, entry.stats.incoming_announce_freq());
        }

        let actions = if self.async_announce_verification {
            let mut announce_queue = self
                .announce_verify_queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.engine.handle_inbound_with_announce_queue(
                &packet,
                interface_id,
                time::now(),
                &mut self.rng,
                Some(&mut announce_queue),
            )
        } else {
            self.engine
                .handle_inbound(&packet, interface_id, time::now(), &mut self.rng)
        };

        #[cfg(feature = "rns-hooks")]
        {
            let pkt_ctx = rns_hooks::PacketContext {
                flags: if packet.is_empty() { 0 } else { packet[0] },
                hops: if packet.len() > 1 { packet[1] } else { 0 },
                destination_hash: extract_dest_hash(&packet),
                context: 0,
                packet_hash: [0; 32],
                interface_id: interface_id.0,
                data_offset: 0,
                data_len: packet.len() as u32,
            };
            let ctx = HookContext::Packet {
                ctx: &pkt_ctx,
                raw: &packet,
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
                &mut self.hook_slots[HookPoint::PreDispatch as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.forward_hook_side_effects("PreDispatch", e);
            }
        }

        self.dispatch_all(actions);
    }

    pub(crate) fn handle_announce_verified_event(
        &mut self,
        key: rns_core::transport::announce_verify_queue::AnnounceVerifyKey,
        validated: rns_core::announce::ValidatedAnnounce,
        sig_cache_key: [u8; 32],
    ) {
        let pending = {
            let mut announce_queue = self
                .announce_verify_queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            announce_queue.complete_success(&key)
        };
        if let Some(pending) = pending {
            let actions = self.engine.complete_verified_announce(
                pending,
                validated,
                sig_cache_key,
                time::now(),
                &mut self.rng,
            );
            self.dispatch_all(actions);
        }
    }

    pub(crate) fn handle_tick_event(&mut self) {
        #[cfg(feature = "rns-hooks")]
        {
            let ctx = HookContext::Tick;
            let now = time::now();
            let engine_ref = EngineRef {
                engine: &self.engine,
                interfaces: &self.interfaces,
                link_manager: &self.link_manager,
                now,
            };
            let provider_events_enabled = self.provider_events_enabled();
            if let Some(ref e) = run_hook_inner(
                &mut self.hook_slots[HookPoint::Tick as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.forward_hook_side_effects("Tick", e);
            }
        }

        let now = time::now();
        for (id, entry) in &self.interfaces {
            self.engine
                .update_interface_freq(*id, entry.stats.incoming_announce_freq());
        }
        let actions = self.engine.tick(now, &mut self.rng);
        self.dispatch_all(actions);
        let link_actions = self.link_manager.tick(&mut self.rng);
        self.dispatch_link_actions(link_actions);
        self.enforce_drain_deadline();
        {
            let tx = self.get_event_sender();
            let hp_actions = self.holepunch_manager.tick(&tx);
            self.dispatch_holepunch_actions(hp_actions);
        }
        self.tick_management_announces(now);
        self.sent_packets
            .retain(|_, (_, sent_time)| now - *sent_time < 60.0);
        self.completed_proofs
            .retain(|_, (_, received)| now - *received < 120.0);

        self.tick_discovery_announcer(now);
        #[cfg(feature = "iface-backbone")]
        self.maintain_backbone_peer_pool();

        self.memory_stats_counter += 1;
        if self.memory_stats_counter >= 300 {
            self.memory_stats_counter = 0;
            self.log_memory_stats();
        }

        if self.discover_interfaces {
            self.discovery_cleanup_counter += 1;
            if self.discovery_cleanup_counter >= self.discovery_cleanup_interval_ticks {
                self.discovery_cleanup_counter = 0;
                if let Ok(removed) = self.discovered_interfaces.cleanup() {
                    if removed > 0 {
                        log::info!("Discovery cleanup: removed {} stale entries", removed);
                    }
                }
            }
        }

        self.cache_cleanup_counter += 1;
        if self.cache_cleanup_counter >= self.known_destinations_cleanup_interval_ticks {
            self.cache_cleanup_counter = 0;

            let active_dests = self.engine.active_destination_hashes();
            let ttl = self.known_destinations_ttl;
            let kd_before = self.known_destinations.len();
            self.known_destinations.retain(|k, state| {
                active_dests.contains(k)
                    || self.local_destinations.contains_key(k)
                    || state.retained
                    || now - Self::known_destination_relevance_time(state) < ttl
            });
            let kd_removed = kd_before - self.known_destinations.len();
            let kd_evicted = self.enforce_known_destination_cap(false);
            let rl_removed =
                self.engine
                    .cull_rate_limiter(&active_dests, now, self.rate_limiter_ttl_secs);

            if kd_removed > 0 || kd_evicted > 0 || rl_removed > 0 {
                log::info!(
                    "Memory cleanup: removed {} known_destinations, evicted {} known_destinations, {} rate_limiter entries",
                    kd_removed, kd_evicted, rl_removed
                );
            }
        }

        self.announce_cache_cleanup_counter += 1;
        if self.announce_cache_cleanup_counter >= self.announce_cache_cleanup_interval_ticks {
            self.announce_cache_cleanup_counter = 0;
            if self.announce_cache.is_some() && self.cache_cleanup_active_hashes.is_none() {
                self.cache_cleanup_active_hashes = Some(self.engine.active_packet_hashes());
                self.cache_cleanup_entries = None;
                self.cache_cleanup_removed = 0;
            }
        }

        if self.cache_cleanup_active_hashes.is_some() {
            if let Some(ref cache) = self.announce_cache {
                if self.cache_cleanup_entries.is_none() {
                    match cache.entries() {
                        Ok(entries) => self.cache_cleanup_entries = Some(entries),
                        Err(e) => {
                            log::warn!("Announce cache cleanup failed to open directory: {}", e);
                            self.cache_cleanup_active_hashes = None;
                            self.cache_cleanup_entries = None;
                        }
                    }
                }
            }

            if let Some(ref cache) = self.announce_cache {
                let Some(active_hashes) = self.cache_cleanup_active_hashes.as_ref() else {
                    self.cache_cleanup_entries = None;
                    return;
                };
                let entries = match self.cache_cleanup_entries.as_mut() {
                    Some(entries) => entries,
                    None => return,
                };
                match cache.clean_batch(
                    active_hashes,
                    entries,
                    self.announce_cache_cleanup_batch_size,
                ) {
                    Ok((removed, finished)) => {
                        self.cache_cleanup_removed += removed;
                        if finished {
                            if self.cache_cleanup_removed > 0 {
                                log::info!(
                                    "Announce cache cleanup complete: removed {} stale files",
                                    self.cache_cleanup_removed
                                );
                            }
                            self.cache_cleanup_active_hashes = None;
                            self.cache_cleanup_entries = None;
                        }
                    }
                    Err(e) => {
                        log::warn!("Announce cache cleanup failed: {}", e);
                        self.cache_cleanup_active_hashes = None;
                        self.cache_cleanup_entries = None;
                    }
                }
            } else {
                self.cache_cleanup_active_hashes = None;
                self.cache_cleanup_entries = None;
            }
        }
    }

    pub(crate) fn handle_interface_up_event(
        &mut self,
        id: InterfaceId,
        new_writer: Option<Box<dyn crate::interface::Writer>>,
        info: Option<rns_core::transport::types::InterfaceInfo>,
    ) {
        let wants_tunnel;
        let mut replay_shared_announces = false;
        if let Some(mut info) = info {
            log::info!("[{}] dynamic interface registered", id.0);
            wants_tunnel = info.wants_tunnel;
            let iface_type = infer_interface_type(&info.name);
            info.started = time::now();
            self.register_interface_runtime_defaults(&info);
            self.engine.register_interface(info.clone());
            if let Some(writer) = new_writer {
                let (writer, async_writer_metrics) =
                    self.wrap_interface_writer(id, &info.name, writer);
                self.interfaces.insert(
                    id,
                    InterfaceEntry {
                        id,
                        info,
                        writer,
                        async_writer_metrics: Some(async_writer_metrics),
                        enabled: true,
                        online: true,
                        dynamic: true,
                        ifac: None,
                        stats: InterfaceStats {
                            started: time::now(),
                            ..Default::default()
                        },
                        interface_type: iface_type,
                        send_retry_at: None,
                        send_retry_backoff: Duration::ZERO,
                    },
                );
            }
            self.callbacks.on_interface_up(id);
            #[cfg(feature = "rns-hooks")]
            {
                let ctx = HookContext::Interface { interface_id: id.0 };
                let now = time::now();
                let engine_ref = EngineRef {
                    engine: &self.engine,
                    interfaces: &self.interfaces,
                    link_manager: &self.link_manager,
                    now,
                };
                let provider_events_enabled = self.provider_events_enabled();
                if let Some(ref e) = run_hook_inner(
                    &mut self.hook_slots[HookPoint::InterfaceUp as usize].programs,
                    &self.hook_manager,
                    &engine_ref,
                    &ctx,
                    now,
                    provider_events_enabled,
                ) {
                    self.forward_hook_side_effects("InterfaceUp", e);
                }
            }
        } else {
            let is_local_client = self
                .interfaces
                .get(&id)
                .map(|entry| entry.info.is_local_client)
                .unwrap_or(false);
            replay_shared_announces =
                is_local_client && self.shared_reconnect_pending.remove(&id).unwrap_or(false);
            let interface_name = self
                .interfaces
                .get(&id)
                .map(|entry| entry.info.name.clone())
                .unwrap_or_else(|| format!("iface-{}", id.0));
            let wrapped_writer =
                new_writer.map(|writer| self.wrap_interface_writer(id, &interface_name, writer));
            if let Some(entry) = self.interfaces.get_mut(&id) {
                log::info!("[{}] interface online", id.0);
                wants_tunnel = entry.info.wants_tunnel;
                entry.online = true;
                if let Some((writer, async_writer_metrics)) = wrapped_writer {
                    log::info!("[{}] writer refreshed after reconnect", id.0);
                    entry.writer = writer;
                    entry.async_writer_metrics = Some(async_writer_metrics);
                }
                self.callbacks.on_interface_up(id);
                #[cfg(feature = "rns-hooks")]
                {
                    let ctx = HookContext::Interface { interface_id: id.0 };
                    let now = time::now();
                    let engine_ref = EngineRef {
                        engine: &self.engine,
                        interfaces: &self.interfaces,
                        link_manager: &self.link_manager,
                        now,
                    };
                    let provider_events_enabled = self.provider_events_enabled();
                    if let Some(ref e) = run_hook_inner(
                        &mut self.hook_slots[HookPoint::InterfaceUp as usize].programs,
                        &self.hook_manager,
                        &engine_ref,
                        &ctx,
                        now,
                        provider_events_enabled,
                    ) {
                        self.forward_hook_side_effects("InterfaceUp", e);
                    }
                }
            } else {
                wants_tunnel = false;
            }
        }

        if wants_tunnel {
            self.synthesize_tunnel_for_interface(id);
        }
        if replay_shared_announces {
            self.replay_shared_announces();
        }
    }

    pub(crate) fn handle_interface_down_event(&mut self, id: InterfaceId) {
        if let Some(entry) = self.interfaces.get(&id) {
            if let Some(tunnel_id) = entry.info.tunnel_id {
                self.engine.void_tunnel_interface(&tunnel_id);
            }
        }

        if let Some(entry) = self.interfaces.get(&id) {
            let is_dynamic = entry.dynamic;
            let is_local_client = entry.info.is_local_client;
            let interface_name = entry.info.name.clone();
            if is_dynamic {
                log::info!("[{}] dynamic interface removed", id.0);
                self.interface_runtime_defaults.remove(&interface_name);
                self.engine.deregister_interface(id);
                self.interfaces.remove(&id);
            } else {
                log::info!("[{}] interface offline", id.0);
                if let Some(entry) = self.interfaces.get_mut(&id) {
                    entry.online = false;
                } else {
                    log::warn!(
                        "interface {} disappeared while handling interface-down",
                        id.0
                    );
                    return;
                }
                if is_local_client {
                    self.handle_shared_interface_down(id);
                }
            }
            self.callbacks.on_interface_down(id);
            #[cfg(feature = "rns-hooks")]
            {
                let ctx = HookContext::Interface { interface_id: id.0 };
                let now = time::now();
                let engine_ref = EngineRef {
                    engine: &self.engine,
                    interfaces: &self.interfaces,
                    link_manager: &self.link_manager,
                    now,
                };
                let provider_events_enabled = self.provider_events_enabled();
                if let Some(ref e) = run_hook_inner(
                    &mut self.hook_slots[HookPoint::InterfaceDown as usize].programs,
                    &self.hook_manager,
                    &engine_ref,
                    &ctx,
                    now,
                    provider_events_enabled,
                ) {
                    self.forward_hook_side_effects("InterfaceDown", e);
                }
            }
        }
        #[cfg(feature = "iface-backbone")]
        self.handle_backbone_peer_pool_down(id);
    }

    pub(crate) fn known_destination_route_hint(&self, dest_hash: &[u8; 16]) -> Option<(InterfaceId, u8)> {
        let announced = &self.known_destinations.get(dest_hash)?.announced;
        let iface = announced.receiving_interface;
        if iface.0 == 0 {
            return None;
        }

        self.interfaces
            .get(&iface)
            .filter(|entry| entry.online)
            .map(|_| (iface, announced.hops))
    }

    pub(crate) fn handle_send_outbound_event(
        &mut self,
        raw: Vec<u8>,
        dest_type: u8,
        attached_interface: Option<InterfaceId>,
    ) {
        if self.is_draining() {
            self.reject_new_work("send outbound packet");
            return;
        }
        match RawPacket::unpack(&raw) {
            Ok(packet) => {
                let is_announce =
                    packet.flags.packet_type == rns_core::constants::PACKET_TYPE_ANNOUNCE;
                if is_announce {
                    log::debug!(
                        "SendOutbound: ANNOUNCE for {:02x?} (len={}, dest_type={}, attached={:?})",
                        &packet.destination_hash[..4],
                        raw.len(),
                        dest_type,
                        attached_interface
                    );
                }
                if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
                    self.sent_packets
                        .insert(packet.packet_hash, (packet.destination_hash, time::now()));
                }
                let actions = self.engine.handle_outbound(
                    &packet,
                    dest_type,
                    attached_interface,
                    time::now(),
                );
                if is_announce {
                    log::debug!(
                        "SendOutbound: announce routed to {} actions: {:?}",
                        actions.len(),
                        actions
                            .iter()
                            .map(|a| match a {
                                TransportAction::SendOnInterface { interface, .. } =>
                                    format!("SendOn({})", interface.0),
                                TransportAction::BroadcastOnAllInterfaces { .. } =>
                                    "BroadcastAll".to_string(),
                                _ => "other".to_string(),
                            })
                            .collect::<Vec<_>>()
                    );
                }
                self.dispatch_all(actions);
            }
            Err(e) => {
                log::warn!("SendOutbound: failed to unpack packet: {:?}", e);
            }
        }
    }

    /// Run the event loop. Blocks until Shutdown or all senders are dropped.
    pub fn run(&mut self) {
        loop {
            let event = match self.rx.recv() {
                Ok(e) => e,
                Err(_) => break, // all senders dropped
            };

            match event {
                Event::Frame { interface_id, data } => {
                    self.handle_frame_event(interface_id, data);
                }
                Event::AnnounceVerified {
                    key,
                    validated,
                    sig_cache_key,
                } => {
                    self.handle_announce_verified_event(key, validated, sig_cache_key);
                }
                Event::AnnounceVerifyFailed { key, .. } => {
                    let mut announce_queue = self
                        .announce_verify_queue
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let _ = announce_queue.complete_failure(&key);
                }
                Event::Tick => self.handle_tick_event(),
                Event::BeginDrain { timeout } => {
                    self.begin_drain(timeout);
                }
                Event::InterfaceUp(id, new_writer, info) => {
                    self.handle_interface_up_event(id, new_writer, info);
                }
                Event::InterfaceDown(id) => self.handle_interface_down_event(id),
                Event::SendOutbound {
                    raw,
                    dest_type,
                    attached_interface,
                } => self.handle_send_outbound_event(raw, dest_type, attached_interface),
                Event::RegisterDestination {
                    dest_hash,
                    dest_type,
                } => {
                    self.engine.register_destination(dest_hash, dest_type);
                    self.local_destinations.insert(dest_hash, dest_type);
                }
                Event::StoreSharedAnnounce {
                    dest_hash,
                    name_hash,
                    identity_prv_key,
                    app_data,
                } => {
                    self.shared_announces.insert(
                        dest_hash,
                        SharedAnnounceRecord {
                            name_hash,
                            identity_prv_key,
                            app_data,
                        },
                    );
                }
                Event::DeregisterDestination { dest_hash } => {
                    self.engine.deregister_destination(&dest_hash);
                    self.local_destinations.remove(&dest_hash);
                    self.shared_announces.remove(&dest_hash);
                }
                Event::Query(request, response_tx) => {
                    let response = self.handle_query_mut(request);
                    let _ = response_tx.send(response);
                }
                Event::DeregisterLinkDestination { dest_hash } => {
                    self.link_manager.deregister_link_destination(&dest_hash);
                }
                Event::RegisterLinkDestination {
                    dest_hash,
                    sig_prv_bytes,
                    sig_pub_bytes,
                    resource_strategy,
                } => {
                    let sig_prv =
                        rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_prv_bytes);
                    let strat = match resource_strategy {
                        1 => crate::link_manager::ResourceStrategy::AcceptAll,
                        2 => crate::link_manager::ResourceStrategy::AcceptApp,
                        _ => crate::link_manager::ResourceStrategy::AcceptNone,
                    };
                    self.link_manager.register_link_destination(
                        dest_hash,
                        sig_prv,
                        sig_pub_bytes,
                        strat,
                    );
                    // Also register in transport engine so inbound packets are delivered locally
                    self.engine
                        .register_destination(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                    self.local_destinations
                        .insert(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                }
                Event::RegisterRequestHandler {
                    path,
                    allowed_list,
                    handler,
                } => {
                    self.link_manager.register_request_handler(
                        &path,
                        allowed_list,
                        move |link_id, p, data, remote| handler(link_id, p, data, remote),
                    );
                }
                Event::CreateLink {
                    dest_hash,
                    dest_sig_pub_bytes,
                    response_tx,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("create link");
                        let _ = (dest_hash, dest_sig_pub_bytes);
                        let _ = response_tx.send([0u8; 16]);
                        continue;
                    }
                    let next_hop_interface = self.engine.next_hop_interface(&dest_hash);
                    let recalled_route_hint = if next_hop_interface.is_none() {
                        self.known_destination_route_hint(&dest_hash)
                    } else {
                        None
                    };
                    if recalled_route_hint.is_some() {
                        let _ = self.mark_known_destination_used(&dest_hash);
                    }
                    let attached_interface =
                        next_hop_interface.or(recalled_route_hint.map(|(iface, _)| iface));
                    let hops = self
                        .engine
                        .hops_to(&dest_hash)
                        .or_else(|| recalled_route_hint.map(|(_, hops)| hops))
                        .unwrap_or(0);
                    let mtu = attached_interface
                        .and_then(|iface_id| self.interfaces.get(&iface_id))
                        .map(|entry| entry.info.mtu)
                        .unwrap_or(rns_core::constants::MTU as u32);
                    let (link_id, mut link_actions) = self.link_manager.create_link(
                        &dest_hash,
                        &dest_sig_pub_bytes,
                        hops,
                        mtu,
                        &mut self.rng,
                    );
                    if next_hop_interface.is_none() {
                        if let Some(iface) = attached_interface {
                            for action in &mut link_actions {
                                if let LinkManagerAction::SendPacket {
                                    dest_type,
                                    attached_interface,
                                    ..
                                } = action
                                {
                                    if *dest_type == rns_core::constants::DESTINATION_LINK
                                        && attached_interface.is_none()
                                    {
                                        *attached_interface = Some(iface);
                                    }
                                }
                            }
                        }
                    }
                    let _ = response_tx.send(link_id);
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendRequest {
                    link_id,
                    path,
                    data,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send link request");
                        let _ = (link_id, path, data);
                        continue;
                    }
                    let link_actions =
                        self.link_manager
                            .send_request(&link_id, &path, &data, &mut self.rng);
                    self.dispatch_link_actions(link_actions);
                }
                Event::IdentifyOnLink {
                    link_id,
                    identity_prv_key,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("identify on link");
                        let _ = (link_id, identity_prv_key);
                        continue;
                    }
                    let identity =
                        rns_crypto::identity::Identity::from_private_key(&identity_prv_key);
                    let link_actions =
                        self.link_manager
                            .identify(&link_id, &identity, &mut self.rng);
                    self.dispatch_link_actions(link_actions);
                }
                Event::TeardownLink { link_id } => {
                    let link_actions = self.link_manager.teardown_link(&link_id);
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendResource {
                    link_id,
                    data,
                    metadata,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send resource");
                        let _ = (link_id, data, metadata);
                        continue;
                    }
                    let link_actions = self.link_manager.send_resource(
                        &link_id,
                        &data,
                        metadata.as_deref(),
                        &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SetResourceStrategy { link_id, strategy } => {
                    use crate::link_manager::ResourceStrategy;
                    let strat = match strategy {
                        0 => ResourceStrategy::AcceptNone,
                        1 => ResourceStrategy::AcceptAll,
                        2 => ResourceStrategy::AcceptApp,
                        _ => ResourceStrategy::AcceptNone,
                    };
                    self.link_manager.set_resource_strategy(&link_id, strat);
                }
                Event::AcceptResource {
                    link_id,
                    resource_hash,
                    accept,
                } => {
                    if self.is_draining() && accept {
                        self.reject_new_work("accept resource");
                        let _ = (link_id, resource_hash, accept);
                        continue;
                    }
                    let link_actions = self.link_manager.accept_resource(
                        &link_id,
                        &resource_hash,
                        accept,
                        &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendChannelMessage {
                    link_id,
                    msgtype,
                    payload,
                    response_tx,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send channel message");
                        let _ = response_tx.send(Err(self.drain_error("send channel message")));
                        continue;
                    }
                    match self.link_manager.send_channel_message(
                        &link_id,
                        msgtype,
                        &payload,
                        &mut self.rng,
                    ) {
                        Ok(link_actions) => {
                            self.dispatch_link_actions(link_actions);
                            let _ = response_tx.send(Ok(()));
                        }
                        Err(err) => {
                            let _ = response_tx.send(Err(err));
                        }
                    }
                }
                Event::SendOnLink {
                    link_id,
                    data,
                    context,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send link payload");
                        let _ = (link_id, data, context);
                        continue;
                    }
                    let link_actions =
                        self.link_manager
                            .send_on_link(&link_id, &data, context, &mut self.rng);
                    self.dispatch_link_actions(link_actions);
                }
                Event::RequestPath { dest_hash } => {
                    if self.is_draining() {
                        self.reject_new_work("request path");
                        let _ = dest_hash;
                        continue;
                    }
                    self.handle_request_path(dest_hash);
                }
                Event::RegisterProofStrategy {
                    dest_hash,
                    strategy,
                    signing_key,
                } => {
                    let identity = signing_key
                        .map(|key| rns_crypto::identity::Identity::from_private_key(&key));
                    self.proof_strategies
                        .insert(dest_hash, (strategy, identity));
                }
                Event::ProposeDirectConnect { link_id } => {
                    if self.is_draining() {
                        self.reject_new_work("propose direct connect");
                        let _ = link_id;
                        continue;
                    }
                    let derived_key = self.link_manager.get_derived_key(&link_id);
                    if let Some(dk) = derived_key {
                        let tx = self.get_event_sender();
                        let hp_actions =
                            self.holepunch_manager
                                .propose(link_id, &dk, &mut self.rng, &tx);
                        self.dispatch_holepunch_actions(hp_actions);
                    } else {
                        log::warn!(
                            "Cannot propose direct connect: no derived key for link {:02x?}",
                            &link_id[..4]
                        );
                    }
                }
                Event::SetDirectConnectPolicy { policy } => {
                    self.holepunch_manager.set_policy(policy);
                }
                Event::HolePunchProbeResult {
                    link_id,
                    session_id,
                    observed_addr,
                    socket,
                    probe_server,
                } => {
                    let hp_actions = self.holepunch_manager.handle_probe_result(
                        link_id,
                        session_id,
                        observed_addr,
                        socket,
                        probe_server,
                    );
                    self.dispatch_holepunch_actions(hp_actions);
                }
                Event::HolePunchProbeFailed {
                    link_id,
                    session_id,
                } => {
                    let hp_actions = self
                        .holepunch_manager
                        .handle_probe_failed(link_id, session_id);
                    self.dispatch_holepunch_actions(hp_actions);
                }
                Event::LoadHook {
                    name,
                    wasm_bytes,
                    attach_point,
                    priority,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let mgr = self
                                .hook_manager
                                .as_ref()
                                .ok_or_else(|| "hook manager not available".to_string())?;
                            let program = mgr
                                .compile(name.clone(), &wasm_bytes, priority)
                                .map_err(|e| format!("compile error: {}", e))?;
                            self.hook_slots[point_idx].attach(program);
                            log::info!(
                                "Loaded hook '{}' at point {} (priority {})",
                                name,
                                attach_point,
                                priority
                            );
                            Ok(())
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, wasm_bytes, attach_point, priority);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::UnloadHook {
                    name,
                    attach_point,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            match self.hook_slots[point_idx].detach(&name) {
                                Some(_) => {
                                    log::info!(
                                        "Unloaded hook '{}' from point {}",
                                        name,
                                        attach_point
                                    );
                                    Ok(())
                                }
                                None => Err(format!(
                                    "hook '{}' not found at point '{}'",
                                    name, attach_point
                                )),
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ReloadHook {
                    name,
                    attach_point,
                    wasm_bytes,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let old =
                                self.hook_slots[point_idx].detach(&name).ok_or_else(|| {
                                    format!("hook '{}' not found at point '{}'", name, attach_point)
                                })?;
                            let priority = old.priority;
                            let mgr = match self.hook_manager.as_ref() {
                                Some(m) => m,
                                None => {
                                    self.hook_slots[point_idx].attach(old);
                                    return Err("hook manager not available".to_string());
                                }
                            };
                            match mgr.compile(name.clone(), &wasm_bytes, priority) {
                                Ok(program) => {
                                    self.hook_slots[point_idx].attach(program);
                                    log::info!(
                                        "Reloaded hook '{}' at point {} (priority {})",
                                        name,
                                        attach_point,
                                        priority
                                    );
                                    Ok(())
                                }
                                Err(e) => {
                                    self.hook_slots[point_idx].attach(old);
                                    Err(format!("compile error: {}", e))
                                }
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point, wasm_bytes);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::SetHookEnabled {
                    name,
                    attach_point,
                    enabled,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = self.update_hook_program(&name, &attach_point, |program| {
                            program.enabled = enabled;
                        });
                        if result.is_ok() {
                            log::info!(
                                "{} hook '{}' at point {}",
                                if enabled { "Enabled" } else { "Disabled" },
                                name,
                                attach_point,
                            );
                        }
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point, enabled);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::SetHookPriority {
                    name,
                    attach_point,
                    priority,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = self.update_hook_program(&name, &attach_point, |program| {
                            program.priority = priority;
                        });
                        if result.is_ok() {
                            if let Some(point_idx) = crate::config::parse_hook_point(&attach_point)
                            {
                                self.hook_slots[point_idx]
                                    .programs
                                    .sort_by(|a, b| b.priority.cmp(&a.priority));
                                log::info!(
                                    "Updated hook '{}' at point {} to priority {}",
                                    name,
                                    attach_point,
                                    priority,
                                );
                            } else {
                                log::error!(
                                    "hook point '{}' became invalid during priority update",
                                    attach_point
                                );
                            }
                        }
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point, priority);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ListHooks { response_tx } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let hook_point_names = [
                            "PreIngress",
                            "PreDispatch",
                            "AnnounceReceived",
                            "PathUpdated",
                            "AnnounceRetransmit",
                            "LinkRequestReceived",
                            "LinkEstablished",
                            "LinkClosed",
                            "InterfaceUp",
                            "InterfaceDown",
                            "InterfaceConfigChanged",
                            "BackbonePeerConnected",
                            "BackbonePeerDisconnected",
                            "BackbonePeerIdleTimeout",
                            "BackbonePeerWriteStall",
                            "BackbonePeerPenalty",
                            "SendOnInterface",
                            "BroadcastOnAllInterfaces",
                            "DeliverLocal",
                            "TunnelSynthesize",
                            "Tick",
                        ];
                        let mut infos = Vec::new();
                        for (idx, slot) in self.hook_slots.iter().enumerate() {
                            let point_name = hook_point_names.get(idx).unwrap_or(&"Unknown");
                            for prog in &slot.programs {
                                infos.push(crate::event::HookInfo {
                                    name: prog.name.clone(),
                                    attach_point: point_name.to_string(),
                                    priority: prog.priority,
                                    enabled: prog.enabled,
                                    consecutive_traps: prog.consecutive_traps,
                                });
                            }
                        }
                        let _ = response_tx.send(infos);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = response_tx.send(Vec::new());
                    }
                }
                Event::InterfaceConfigChanged(id) => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Interface { interface_id: id.0 };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::InterfaceConfigChanged as usize]
                                .programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.forward_hook_side_effects("InterfaceConfigChanged", e);
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = id;
                }
                Event::BackbonePeerConnected {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerConnected",
                            HookPoint::BackbonePeerConnected,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for: Duration::ZERO,
                                had_received_data: false,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (server_interface_id, peer_interface_id, peer_ip, peer_port);
                }
                Event::BackbonePeerDisconnected {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                    connected_for,
                    had_received_data,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerDisconnected",
                            HookPoint::BackbonePeerDisconnected,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for,
                                had_received_data,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (
                        server_interface_id,
                        peer_interface_id,
                        peer_ip,
                        peer_port,
                        connected_for,
                        had_received_data,
                    );
                }
                Event::BackbonePeerIdleTimeout {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                    connected_for,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerIdleTimeout",
                            HookPoint::BackbonePeerIdleTimeout,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for,
                                had_received_data: false,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (
                        server_interface_id,
                        peer_interface_id,
                        peer_ip,
                        peer_port,
                        connected_for,
                    );
                }
                Event::BackbonePeerWriteStall {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                    connected_for,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerWriteStall",
                            HookPoint::BackbonePeerWriteStall,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for,
                                had_received_data: false,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (
                        server_interface_id,
                        peer_interface_id,
                        peer_ip,
                        peer_port,
                        connected_for,
                    );
                }
                Event::BackbonePeerPenalty {
                    server_interface_id,
                    peer_ip,
                    penalty_level,
                    blacklist_for,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerPenalty",
                            HookPoint::BackbonePeerPenalty,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: None,
                                peer_ip,
                                peer_port: 0,
                                connected_for: Duration::ZERO,
                                had_received_data: false,
                                penalty_level,
                                blacklist_for,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (server_interface_id, peer_ip, penalty_level, blacklist_for);
                }
                Event::Shutdown => {
                    self.lifecycle_state = LifecycleState::Stopped;
                    break;
                }
            }
        }
    }
    pub(crate) fn handle_tunnel_synth_delivery(&mut self, raw: &[u8]) {
        // Extract the data payload from the raw packet
        let packet = match RawPacket::unpack(raw) {
            Ok(p) => p,
            Err(_) => return,
        };

        match rns_core::transport::tunnel::validate_tunnel_synthesize_data(&packet.data) {
            Ok(validated) => {
                // Find the interface this tunnel belongs to by computing the expected
                // tunnel_id for each interface with wants_tunnel
                let iface_id = self
                    .interfaces
                    .iter()
                    .find(|(_, entry)| entry.info.wants_tunnel && entry.online && entry.enabled)
                    .map(|(id, _)| *id);

                if let Some(iface) = iface_id {
                    let now = time::now();
                    let tunnel_actions = self.engine.handle_tunnel(validated.tunnel_id, iface, now);
                    self.dispatch_all(tunnel_actions);
                }
            }
            Err(e) => {
                log::debug!("Tunnel synthesis validation failed: {}", e);
            }
        }
    }

    /// Synthesize a tunnel on an interface that wants it.
    ///
    /// Called when an interface with `wants_tunnel` comes up.
    pub(crate) fn synthesize_tunnel_for_interface(&mut self, interface: InterfaceId) {
        if let Some(ref identity) = self.transport_identity {
            let actions = self
                .engine
                .synthesize_tunnel(identity, interface, &mut self.rng);
            self.dispatch_all(actions);
        }
    }

    /// Build and send a path request packet for a destination.
    pub(crate) fn handle_request_path(&mut self, dest_hash: [u8; 16]) {
        // Build path request data: dest_hash(16) || [transport_id(16)] || random_tag(16)
        let mut data = Vec::with_capacity(48);
        data.extend_from_slice(&dest_hash);

        if self.engine.transport_enabled() {
            if let Some(id_hash) = self.engine.identity_hash() {
                data.extend_from_slice(id_hash);
            }
        }

        // Random tag (16 bytes)
        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);
        data.extend_from_slice(&tag);

        // Build as BROADCAST DATA PLAIN packet to rnstransport.path.request
        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_PLAIN,
            packet_type: rns_core::constants::PACKET_TYPE_DATA,
        };

        if let Ok(packet) = RawPacket::pack(
            flags,
            0,
            &self.path_request_dest,
            None,
            rns_core::constants::CONTEXT_NONE,
            &data,
        ) {
            let actions = self.engine.handle_outbound(
                &packet,
                rns_core::constants::DESTINATION_PLAIN,
                None,
                time::now(),
            );
            self.dispatch_all(actions);
        }
    }

    /// Check if we should generate a proof for a delivered packet,
    /// and if so, sign and send it.
    pub(crate) fn get_event_sender(&self) -> crate::event::EventSender {
        // The driver doesn't directly have a sender, but node.rs creates the channel
        // and passes rx to the driver. We need to store a sender clone.
        // For now we use an internal sender that was set during construction.
        self.event_tx.clone()
    }

    /// Delay before first management announce after startup.
    const MANAGEMENT_ANNOUNCE_DELAY: f64 = 5.0;

    /// Tick the discovery announcer: start stamp generation if due, send announce if ready.
    pub(crate) fn tick_discovery_announcer(&mut self, now: f64) {
        let announcer = match self.interface_announcer.as_mut() {
            Some(a) => a,
            None => return,
        };

        announcer.maybe_start(now);

        let stamp_result = match announcer.poll_ready() {
            Some(r) => r,
            None => return,
        };

        if !announcer.contains_interface(&stamp_result.interface_name) {
            log::debug!(
                "Discovery: dropping completed stamp for removed interface '{}'",
                stamp_result.interface_name
            );
            return;
        }

        let identity = match self.transport_identity.as_ref() {
            Some(id) => id,
            None => {
                log::warn!("Discovery: stamp ready but no transport identity");
                return;
            }
        };

        // Discovery is a SINGLE destination — the dest hash includes the transport identity
        let identity_hash = identity.hash();
        let disc_dest = rns_core::destination::destination_hash(
            crate::discovery::APP_NAME,
            &["discovery", "interface"],
            Some(&identity_hash),
        );
        let name_hash = self.discovery_name_hash;
        let mut random_hash = [0u8; 10];
        self.rng.fill_bytes(&mut random_hash);

        let (announce_data, _) = match rns_core::announce::AnnounceData::pack(
            identity,
            &disc_dest,
            &name_hash,
            &random_hash,
            None,
            Some(&stamp_result.app_data),
        ) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Discovery: failed to pack announce: {}", e);
                return;
            }
        };

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_ANNOUNCE,
        };

        let packet = match RawPacket::pack(
            flags,
            0,
            &disc_dest,
            None,
            rns_core::constants::CONTEXT_NONE,
            &announce_data,
        ) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Discovery: failed to pack packet: {}", e);
                return;
            }
        };

        let outbound_actions = self.engine.handle_outbound(
            &packet,
            rns_core::constants::DESTINATION_SINGLE,
            None,
            now,
        );
        log::debug!(
            "Discovery announce sent for interface '{}' ({} actions, dest={:02x?})",
            stamp_result.interface_name,
            outbound_actions.len(),
            &disc_dest[..4],
        );
        self.dispatch_all(outbound_actions);
    }

    /// Read RSS from /proc/self/statm (Linux only).
    pub(crate) fn rss_mb() -> Option<f64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(rss_pages as f64 * 4096.0 / (1024.0 * 1024.0))
    }

    pub(crate) fn parse_proc_kib(contents: &str, key: &str) -> Option<u64> {
        contents.lines().find_map(|line| {
            let value = line.strip_prefix(key)?;
            value.split_whitespace().next()?.parse().ok()
        })
    }

    pub(crate) fn proc_status_mb() -> Option<(f64, f64, f64, f64)> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let vm_rss = Self::parse_proc_kib(&status, "VmRSS:")? as f64 / 1024.0;
        let vm_hwm = Self::parse_proc_kib(&status, "VmHWM:")? as f64 / 1024.0;
        let vm_data = Self::parse_proc_kib(&status, "VmData:")? as f64 / 1024.0;
        let vm_swap = Self::parse_proc_kib(&status, "VmSwap:").unwrap_or(0) as f64 / 1024.0;
        Some((vm_rss, vm_hwm, vm_data, vm_swap))
    }

    pub(crate) fn smaps_rollup_mb() -> Option<(f64, f64, f64, f64, f64, f64, f64, f64)> {
        let smaps = std::fs::read_to_string("/proc/self/smaps_rollup").ok()?;
        let rss_kib = Self::parse_proc_kib(&smaps, "Rss:")?;
        let anon_kib = Self::parse_proc_kib(&smaps, "Anonymous:")?;
        let shared_clean_kib = Self::parse_proc_kib(&smaps, "Shared_Clean:").unwrap_or(0);
        let shared_dirty_kib = Self::parse_proc_kib(&smaps, "Shared_Dirty:").unwrap_or(0);
        let private_clean_kib = Self::parse_proc_kib(&smaps, "Private_Clean:").unwrap_or(0);
        let private_dirty_kib = Self::parse_proc_kib(&smaps, "Private_Dirty:").unwrap_or(0);
        let swap_kib = Self::parse_proc_kib(&smaps, "Swap:").unwrap_or(0);
        let file_est_kib = rss_kib.saturating_sub(anon_kib);
        Some((
            rss_kib as f64 / 1024.0,
            anon_kib as f64 / 1024.0,
            file_est_kib as f64 / 1024.0,
            shared_clean_kib as f64 / 1024.0,
            shared_dirty_kib as f64 / 1024.0,
            private_clean_kib as f64 / 1024.0,
            private_dirty_kib as f64 / 1024.0,
            swap_kib as f64 / 1024.0,
        ))
    }

    /// Log sizes of all major collections for memory growth diagnostics.
    pub(crate) fn log_memory_stats(&self) {
        let rss = Self::rss_mb()
            .map(|v| format!("{:.1}", v))
            .unwrap_or_else(|| "N/A".into());
        let (vm_rss, vm_hwm, vm_data, vm_swap) = Self::proc_status_mb()
            .map(|(rss, hwm, data, swap)| {
                (
                    format!("{rss:.1}"),
                    format!("{hwm:.1}"),
                    format!("{data:.1}"),
                    format!("{swap:.1}"),
                )
            })
            .unwrap_or_else(|| ("N/A".into(), "N/A".into(), "N/A".into(), "N/A".into()));
        let (
            smaps_rss,
            smaps_anon,
            smaps_file_est,
            smaps_shared_clean,
            smaps_shared_dirty,
            smaps_private_clean,
            smaps_private_dirty,
            smaps_swap,
        ) = Self::smaps_rollup_mb()
            .map(
                |(
                    rss,
                    anon,
                    file_est,
                    shared_clean,
                    shared_dirty,
                    private_clean,
                    private_dirty,
                    swap,
                )| {
                    (
                        format!("{rss:.1}"),
                        format!("{anon:.1}"),
                        format!("{file_est:.1}"),
                        format!("{shared_clean:.1}"),
                        format!("{shared_dirty:.1}"),
                        format!("{private_clean:.1}"),
                        format!("{private_dirty:.1}"),
                        format!("{swap:.1}"),
                    )
                },
            )
            .unwrap_or_else(|| {
                (
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                )
            });
        log::info!(
            "MEMSTATS rss_mb={} vmrss_mb={} vmhwm_mb={} vmdata_mb={} vmswap_mb={} smaps_rss_mb={} smaps_anon_mb={} smaps_file_est_mb={} smaps_shared_clean_mb={} smaps_shared_dirty_mb={} smaps_private_clean_mb={} smaps_private_dirty_mb={} smaps_swap_mb={} known_dest={} known_dest_cap_evict={} path={} path_cap_evict={} announce={} reverse={}              link={} held_ann={} hashlist={} sig_cache={} ann_verify_q={} rate_lim={} blackhole={} tunnel={} ann_q_ifaces={} ann_q_nonempty={} ann_q_entries={} ann_q_bytes={} ann_q_iface_drop={}              pr_tags={} disc_pr={} sent_pkt={} completed={} local_dest={}              shared_ann={} lm_links={} hp_sessions={} proof_strat={}",
            rss,
            vm_rss,
            vm_hwm,
            vm_data,
            vm_swap,
            smaps_rss,
            smaps_anon,
            smaps_file_est,
            smaps_shared_clean,
            smaps_shared_dirty,
            smaps_private_clean,
            smaps_private_dirty,
            smaps_swap,
            self.known_destinations.len(),
            self.known_destinations_cap_evict_count,
            self.engine.path_table_count(),
            self.engine.path_destination_cap_evict_count(),
            self.engine.announce_table_count(),
            self.engine.reverse_table_count(),
            self.engine.link_table_count(),
            self.engine.held_announces_count(),
            self.engine.packet_hashlist_len(),
            self.engine.announce_sig_cache_len(),
            self.announce_verify_queue
                .lock()
                .map(|queue| queue.len())
                .unwrap_or(0),
            self.engine.rate_limiter_count(),
            self.engine.blackholed_count(),
            self.engine.tunnel_count(),
            self.engine.announce_queue_count(),
            self.engine.nonempty_announce_queue_count(),
            self.engine.queued_announce_count(),
            self.engine.queued_announce_bytes(),
            self.engine.announce_queue_interface_cap_drop_count(),
            self.engine.discovery_pr_tags_count(),
            self.engine.discovery_path_requests_count(),
            self.sent_packets.len(),
            self.completed_proofs.len(),
            self.local_destinations.len(),
            self.shared_announces.len(),
            self.link_manager.link_count(),
            self.holepunch_manager.session_count(),
            self.proof_strategies.len(),
        );
    }

    /// Emit management and/or blackhole announces if enabled and due.
    pub(crate) fn tick_management_announces(&mut self, now: f64) {
        if self.transport_identity.is_none() {
            return;
        }

        let uptime = now - self.started;

        // Wait for initial delay
        if !self.initial_announce_sent {
            if uptime < Self::MANAGEMENT_ANNOUNCE_DELAY {
                return;
            }
            self.initial_announce_sent = true;
            self.emit_management_announces(now);
            return;
        }

        // Periodic re-announce
        if now - self.last_management_announce >= self.management_announce_interval_secs {
            self.emit_management_announces(now);
        }
    }

    /// Emit management/blackhole announce packets through the engine outbound path.
    pub(crate) fn emit_management_announces(&mut self, now: f64) {
        use crate::management;

        self.last_management_announce = now;

        let identity = match self.transport_identity {
            Some(ref id) => id,
            None => return,
        };

        // Build announce packets first (immutable borrow of identity), then dispatch
        let mgmt_raw = if self.management_config.enable_remote_management {
            management::build_management_announce(identity, &mut self.rng)
        } else {
            None
        };

        let bh_raw = if self.management_config.publish_blackhole {
            management::build_blackhole_announce(identity, &mut self.rng)
        } else {
            None
        };

        let probe_raw = if self.probe_responder_hash.is_some() {
            management::build_probe_announce(identity, &mut self.rng)
        } else {
            None
        };

        if let Some(raw) = mgmt_raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted management destination announce");
            }
        }

        if let Some(raw) = bh_raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted blackhole info announce");
            }
        }

        if let Some(raw) = probe_raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted probe responder announce");
            }
        }
    }

    /// Handle a management request by querying engine state and sending a response.
    pub(crate) fn handle_management_request(
        &mut self,
        link_id: [u8; 16],
        path_hash: [u8; 16],
        data: Vec<u8>,
        request_id: [u8; 16],
        remote_identity: Option<([u8; 16], [u8; 64])>,
    ) {
        use crate::management;

        // ACL check for /status and /path (ALLOW_LIST), /list is ALLOW_ALL
        let is_restricted = path_hash == management::status_path_hash()
            || path_hash == management::path_path_hash();

        if is_restricted && !self.management_config.remote_management_allowed.is_empty() {
            match remote_identity {
                Some((identity_hash, _)) => {
                    if !self
                        .management_config
                        .remote_management_allowed
                        .contains(&identity_hash)
                    {
                        log::debug!("Management request denied: identity not in allowed list");
                        return;
                    }
                }
                None => {
                    log::debug!("Management request denied: peer not identified");
                    return;
                }
            }
        }

        let response_data = if path_hash == management::status_path_hash() {
            {
                let views: Vec<&dyn management::InterfaceStatusView> = self
                    .interfaces
                    .values()
                    .map(|e| e as &dyn management::InterfaceStatusView)
                    .collect();
                management::handle_status_request(
                    &data,
                    &self.engine,
                    &views,
                    self.started,
                    self.probe_responder_hash,
                )
            }
        } else if path_hash == management::path_path_hash() {
            management::handle_path_request(&data, &self.engine)
        } else if path_hash == management::list_path_hash() {
            management::handle_blackhole_list_request(&self.engine)
        } else {
            log::warn!("Unknown management path_hash: {:02x?}", &path_hash[..4]);
            None
        };

        if let Some(response) = response_data {
            let actions = self.link_manager.send_management_response(
                &link_id,
                &request_id,
                &response,
                &mut self.rng,
            );
            self.dispatch_link_actions(actions);
        }
    }
}
