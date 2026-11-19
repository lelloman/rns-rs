//! The driver's event loop.

use super::*;

impl Driver {
    /// Run the event loop. Blocks until Shutdown or all senders are dropped.
    pub fn run(&mut self) {
        self.link_manager
            .set_receive_worker_wake(self.event_tx.clone());
        self.start_folded_tick();
        let mut ready = crate::poll::Events::new();
        // Events handled since driver-run writers were last flushed.
        let mut unflushed = 0usize;
        // Turns since folded timers were last checked: a busy loop checks
        // them every so many turns, an idle one before it waits.
        let mut unchecked_turns = 0u32;
        // Events handled since folded work last ran on a busy driver.
        let mut busy_events = 0u32;
        loop {
            // Each turn handles at most one event and reads the clock at most
            // once (see `time::hold`). The scope ends before the loop waits.
            let clock = time::hold();
            if crate::engine::FOLD_TIMERS && !self.folded.ticks_from_source {
                unchecked_turns += 1;
                if unchecked_turns >= FOLDED_TIMER_CHECK_TURNS {
                    unchecked_turns = 0;
                    self.run_folded_timers();
                }
            }
            self.poll_resource_preparations();
            let actions = self.link_manager.poll_receive_worker(&mut self.rng);
            self.dispatch_link_actions(actions);
            if let Some(actions) = self.link_manager.poll_proof_pool(&mut self.rng) {
                self.dispatch_link_actions(actions);
                self.apply_packet_proofs();
            }
            self.flush_pending_link_frames();
            if self
                .state_snapshot_schedule
                .needs_publish(self.link_manager.link_count())
            {
                self.publish_state_snapshot();
            }
            if !self.rx.has_prefetched() {
                self.wake_writers();
            }
            let received = match self.rx.try_recv_classified() {
                Ok(Some(e)) => e,
                Ok(None) => {
                    // Everything the last poll delivered has been handled:
                    // send this pass's output before waiting for more.
                    self.flush_writers();
                    if self.link_manager.has_idle_work() || self.has_folded_work() {
                        // Sources that are ready go before idle work: what
                        // they hold, such as the rest of a window, may be
                        // what a peer waits on.
                        ready.clear();
                        if let Err(error) = self.rx.wait(&mut ready, Some(Duration::ZERO)) {
                            log::warn!("driver poll failed: {error}");
                        }
                        if ready.iter().next().is_some() {
                            self.handle_ready_sources(&ready);
                            continue;
                        }
                        // One job per turn: events that arrive meanwhile go first.
                        if self.has_folded_work() {
                            self.run_folded_unit();
                        } else {
                            let actions = self.link_manager.run_idle_work(&mut self.rng);
                            self.dispatch_link_actions(actions);
                        }
                        continue;
                    }
                    if crate::engine::FOLD_TIMERS && !self.folded.ticks_from_source {
                        unchecked_turns = 0;
                        self.run_folded_timers();
                        if !self.folded.jobs.is_empty() {
                            continue;
                        }
                    }
                    drop(clock);
                    unflushed = 0;
                    ready.clear();
                    if let Err(error) = self.rx.wait(&mut ready, self.folded_wait()) {
                        log::warn!("driver wait failed: {error}");
                    }
                    self.handle_ready_sources(&ready);
                    continue;
                }
                Err(_) => break, // all senders dropped
            };
            // Bound output latency, and keep serving sockets, while other
            // threads keep the queue from emptying.
            unflushed += 1;
            if crate::engine::FOLD_TIMERS || crate::engine::FOLD_WORK {
                busy_events += 1;
                if busy_events >= FOLDED_WORK_BUSY_EVENTS {
                    busy_events = 0;
                    self.run_folded_unit();
                }
            }
            // A tick queued behind a long backlog would leave the snapshot
            // stale for as long as the backlog takes to drain.
            let tick_interval =
                Duration::from_millis(self.tick_interval_ms.load(Ordering::Relaxed));
            if self.state_snapshot_schedule.event_handled(tick_interval) {
                self.publish_state_snapshot();
            }
            if unflushed >= WRITER_FLUSH_EVENTS {
                self.flush_writers();
                unflushed = 0;
                ready.clear();
                match self.rx.poll_ready(&mut ready) {
                    Ok(()) => self.handle_ready_sources(&ready),
                    Err(error) => log::warn!("driver poll failed: {error}"),
                }
            }

            match received.event {
                Event::Frame {
                    interface_id,
                    data,
                    rssi,
                    snr,
                } => {
                    self.handle_classified_frame_event(
                        interface_id,
                        data,
                        rssi,
                        snr,
                        received.ingress_limited,
                    );
                }
                Event::AnnounceVerified {
                    key,
                    validated,
                    sig_cache_key,
                } => {
                    self.handle_announce_verified_event(key, *validated, sig_cache_key);
                }
                Event::AnnounceVerifyFailed { key, .. } => self.handle_announce_verify_failed(key),
                Event::Tick => self.handle_tick_event(),
                Event::BeginDrain { timeout } => {
                    self.begin_drain(timeout);
                }
                Event::InterfaceUp(id, new_writer, info) => {
                    self.handle_interface_up_event(id, new_writer, info.map(|info| *info));
                }
                Event::DynamicInterfaceUp {
                    id,
                    writer,
                    registration,
                } => self.handle_dynamic_interface_up_event(id, writer, *registration),
                Event::InterfaceNames {
                    id,
                    display_name,
                    short_name,
                } => {
                    if let Some(display_name) = display_name {
                        self.interface_display_names.insert(id, display_name);
                    }
                    if let Some(short_name) = short_name {
                        self.interface_short_names.insert(id, short_name);
                    }
                }
                Event::InterfaceTelemetry {
                    interface_id,
                    telemetry,
                } => self.handle_interface_telemetry_event(interface_id, *telemetry),
                Event::InterfaceDown(id) => self.handle_interface_down_event(id),
                Event::SendOutbound {
                    raw,
                    dest_type,
                    attached_interface,
                } => self.handle_send_outbound_event(raw, dest_type, attached_interface),
                Event::SendDeferred(encryption) => self.handle_send_deferred(encryption),
                Event::DeliverDecrypted {
                    dest_hash,
                    identity,
                } => {
                    self.decrypted_destinations
                        .insert(dest_hash, Arc::from(identity));
                }
                Event::SendOutboundTracked {
                    raw,
                    dest_type,
                    replay,
                    completion,
                    proof_key,
                } => {
                    self.handle_confirmed_outbound(raw, dest_type, replay, completion, proof_key);
                }
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
                Event::RegisterPathResponder {
                    destination,
                    identity_prv_key,
                } => {
                    let dest_hash = destination.hash.0;
                    let aspects: Vec<&str> =
                        destination.aspects.iter().map(String::as_str).collect();
                    let record = SharedAnnounceRecord {
                        name_hash: rns_core::destination::name_hash(
                            &destination.app_name,
                            &aspects,
                        ),
                        identity_prv_key,
                        app_data: None,
                    };
                    self.path_responders.insert(
                        dest_hash,
                        PathResponder {
                            record,
                            destination: *destination,
                        },
                    );
                    // Transport.register_destination: a client of a shared
                    // instance announces a new SINGLE IN destination as a
                    // path response, so the instance has a path to it and
                    // can answer, or relay its response to, path requests
                    // from other interfaces. It does so a quarter of a
                    // second later, so an announce the program makes right
                    // after creating the destination goes first: in the
                    // same second, the instance would take the path
                    // response and reject the announce as not newer, and
                    // not rebroadcast it.
                    if self.connected_to_shared_instance {
                        let tx = self.event_tx.clone();
                        let spawned = std::thread::Builder::new()
                            .name("rns-register-announce".into())
                            .spawn(move || {
                                std::thread::sleep(REGISTRATION_ANNOUNCE_DELAY);
                                let _ = tx.send(Event::AnnounceRegisteredDestination { dest_hash });
                            });
                        if spawned.is_err() {
                            self.send_path_responder_announce(dest_hash);
                        }
                    }
                }
                Event::AnnounceRegisteredDestination { dest_hash } => {
                    if self.connected_to_shared_instance {
                        self.send_path_responder_announce(dest_hash);
                    }
                }
                Event::DeregisterDestination { dest_hash } => {
                    self.path_responders.remove(&dest_hash);
                    self.stamp_waiting_path_responses.remove(&dest_hash);
                    self.decrypted_destinations.remove(&dest_hash);
                    self.engine.deregister_destination(&dest_hash);
                    self.local_destinations.remove(&dest_hash);
                    self.shared_announces.remove(&dest_hash);
                }
                Event::Query(request, response_tx) => {
                    let response = self.handle_query_mut(*request);
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
                    max_request_size,
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
                    self.link_manager
                        .set_link_destination_max_request_size(&dest_hash, max_request_size);
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
                Event::RegisterRequestHandlerResponse {
                    path,
                    allowed_list,
                    handler,
                } => {
                    self.link_manager.register_request_handler_response(
                        &path,
                        allowed_list,
                        move |link_id, p, data, remote| handler(link_id, p, data, remote),
                    );
                }
                Event::RegisterDeferredRequestHandler {
                    path,
                    allowed_list,
                    handler,
                } => {
                    self.link_manager.register_deferred_request_handler(
                        &path,
                        allowed_list,
                        move |link_id, path, request_id, data, remote| {
                            handler(link_id, path, request_id, data, remote)
                        },
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
                    self.handle_create_link(dest_hash, dest_sig_pub_bytes, response_tx);
                }
                Event::DestinationStampReady { dest_hash } => {
                    if self.is_draining() {
                        continue;
                    }
                    self.emit_builtin_announce_for(dest_hash, time::now());
                    self.send_stamp_waiting_path_responses(dest_hash);
                }
                Event::SendStampedPathRequest(request) => {
                    if self.is_draining() {
                        self.reject_new_work("send stamped path request");
                        continue;
                    }
                    let crate::stamper::StampedPathRequest {
                        destination_hash,
                        tag,
                        ext_payload,
                        target,
                    } = *request;
                    self.send_path_request(destination_hash, &tag, Some(&ext_payload), target);
                }
                Event::CompleteStampedLink(keys) => {
                    let crate::common::event::StampedLinkKeys {
                        dest_hash,
                        dest_sig_pub_bytes,
                        prv_bytes,
                        sig_prv_bytes,
                        stamp_value,
                        response_tx,
                    } = *keys;
                    if self.is_draining() {
                        self.reject_new_work("complete stamped link");
                        let _ = response_tx.send([0u8; 16]);
                        continue;
                    }
                    log::trace!(
                        "Completing stamped link request to {:02x?} with value {}",
                        &dest_hash[..4],
                        stamp_value
                    );
                    let keys = (
                        rns_crypto::x25519::X25519PrivateKey::from_bytes(&prv_bytes),
                        rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_prv_bytes),
                    );
                    self.complete_create_link(
                        dest_hash,
                        dest_sig_pub_bytes,
                        Some(keys),
                        response_tx,
                    );
                }
                Event::SendRequest {
                    link_id,
                    path,
                    data,
                    max_response_size,
                    timeout,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send link request");
                        let _ = (link_id, path, data, max_response_size, timeout);
                        continue;
                    }
                    self.finish_resource_preparations_for(&link_id);
                    let link_actions = self.link_manager.send_request_with_options(
                        &link_id,
                        &path,
                        &data,
                        max_response_size,
                        timeout,
                        &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendDeferredResponse {
                    link_id,
                    request_id,
                    data,
                } => {
                    self.finish_resource_preparations_for(&link_id);
                    let link_actions = self.link_manager.send_deferred_response(
                        &link_id,
                        &request_id,
                        &data,
                        &mut self.rng,
                    );
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
                Event::ResourcePreparationReady
                | Event::ResourceAssemblyReady
                | Event::LinkProofsVerified => {}
                Event::SendResource {
                    link_id,
                    data,
                    metadata,
                    options,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send resource");
                        let _ = (link_id, data, metadata, options);
                        continue;
                    }
                    self.prepare_resource_with_options(link_id, data, metadata, options);
                }
                Event::SendResourceStream {
                    link_id,
                    transfer_id,
                    reader,
                    declared_length,
                    metadata,
                    options,
                } => {
                    if self.is_draining() {
                        self.callbacks.on_resource_stream_failed(
                            rns_core::types::LinkId(link_id),
                            transfer_id,
                            crate::resource::ResourceTransferError::Cancelled,
                        );
                        continue;
                    }
                    self.finish_resource_preparations_for(&link_id);
                    let link_actions = self.link_manager.send_resource_stream_with_options(
                        &link_id,
                        transfer_id,
                        reader,
                        declared_length,
                        metadata,
                        options,
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
                Event::SetResourceReceiveMode { link_id, mode } => {
                    self.link_manager.set_resource_receive_mode(&link_id, mode);
                }
                Event::SetLinkDestinationResourceReceiveMode { dest_hash, mode } => {
                    self.link_manager
                        .set_link_destination_resource_receive_mode(&dest_hash, mode);
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
                Event::LinkWriterReady => {}
                Event::SendLinkTracked {
                    link_id,
                    data,
                    context,
                    completion,
                } => {
                    use crate::link_send::LinkSendError;
                    if self.is_draining() {
                        completion.finish(Err(LinkSendError::Draining));
                        continue;
                    }
                    match self.link_manager.try_send_on_link(
                        &link_id,
                        &data,
                        context,
                        &mut self.rng,
                    ) {
                        Ok(actions) => {
                            if self.link_manager.get_link_route_hint(&link_id).is_none() {
                                completion.finish(Err(LinkSendError::NoRoute));
                                continue;
                            }
                            let hash = actions.iter().find_map(|action| match action {
                                LinkManagerAction::SendPacket { raw, .. } => {
                                    RawPacket::unpack(raw).ok().map(|p| p.packet_hash)
                                }
                                _ => None,
                            });
                            if let Some(hash) = hash {
                                completion.set_packet_hash(hash);
                                self.tracked_link_send = Some((hash, completion));
                                self.dispatch_link_actions(actions);
                                if let Some((_, completion)) = self.tracked_link_send.take() {
                                    completion.finish(Err(LinkSendError::Rejected));
                                }
                            } else {
                                completion.finish(Err(LinkSendError::Rejected));
                            }
                        }
                        Err(error) => completion.finish(Err(LinkSendError::InvalidPacket(error))),
                    }
                }
                Event::SendOnLink {
                    link_id,
                    data,
                    context,
                    response_tx,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send link payload");
                        if let Some(tx) = response_tx {
                            let _ = tx.send(Err(crate::event::LinkDatagramError::DriverStopped));
                        }
                        continue;
                    }
                    let result =
                        self.link_manager
                            .try_send_on_link(&link_id, &data, context, &mut self.rng);
                    match result {
                        Ok(link_actions) => {
                            self.dispatch_link_actions(link_actions);
                            if let Some(tx) = response_tx {
                                let _ = tx.send(Ok(()));
                            }
                        }
                        Err(error) => {
                            if let Some(tx) = response_tx {
                                let _ = tx.send(Err(error));
                            }
                        }
                    }
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
                        self.callbacks.on_direct_connect_failed(
                            rns_core::types::LinkId(link_id),
                            rns_core::holepunch::types::FAIL_NOT_STARTED,
                        );
                    }
                }
                Event::BlackholeDirectPath { link_id } => {
                    if !self.holepunch_manager.blackhole_direct(&link_id) {
                        log::warn!("No direct path to blackhole on link {:02x?}", &link_id[..4]);
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
                Event::DirectPathMtu { interface_id, mtu } => {
                    self.direct_path_mtu_discovered(interface_id, mtu);
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
                event @ (Event::LoadHook { .. }
                | Event::LoadHookFile { .. }
                | Event::LoadBuiltinHook { .. }
                | Event::UnloadHook { .. }
                | Event::ReloadHook { .. }
                | Event::ReloadHookFile { .. }
                | Event::ReloadBuiltinHook { .. }
                | Event::SetHookEnabled { .. }
                | Event::SetHookPriority { .. }
                | Event::ListHooks { .. }) => self.handle_hook_event(event),
                Event::InterfaceConfigChanged(id) => {
                    #[cfg(feature = "hooks")]
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
                    #[cfg(not(feature = "hooks"))]
                    let _ = id;
                }
                Event::BackbonePeerConnected {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                } => {
                    #[cfg(feature = "hooks")]
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
                    #[cfg(not(feature = "hooks"))]
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
                    #[cfg(feature = "hooks")]
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
                    #[cfg(not(feature = "hooks"))]
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
                    #[cfg(feature = "hooks")]
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
                    #[cfg(not(feature = "hooks"))]
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
                    #[cfg(feature = "hooks")]
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
                    #[cfg(not(feature = "hooks"))]
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
                    #[cfg(feature = "hooks")]
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
                    #[cfg(not(feature = "hooks"))]
                    let _ = (server_interface_id, peer_ip, penalty_level, blacklist_for);
                }
                Event::Shutdown => {
                    self.event_tx.link_send_pool().close();
                    self.pending_link_frames.clear();
                    self.graceful_shutdown();
                    break;
                }
            }
        }
        self.link_manager.stop_receive_worker();
        self.stop_resource_preparations();
        self.event_tx.link_send_pool().close();
        self.pending_link_frames.clear();
    }

    /// Check if we should generate a proof for a delivered packet,
    /// and if so, sign and send it.
    pub(crate) fn get_event_sender(&self) -> crate::event::EventSender {
        // The driver doesn't directly have a sender, but node.rs creates the channel
        // and passes rx to the driver. We need to store a sender clone.
        // For now we use an internal sender that was set during construction.
        self.event_tx.clone()
    }
}
