//! What the driver does with each event it receives.

use super::*;

impl Driver {
    /// Handle one event from the queue. False when the event was
    /// [`Event::Shutdown`] and the loop must stop.
    pub(super) fn handle_event(&mut self, received: crate::event::ReceivedEvent) -> bool {
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
            } => self.handle_register_path_responder(*destination, identity_prv_key),
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
            } => self.handle_register_link_destination(
                dest_hash,
                sig_prv_bytes,
                sig_pub_bytes,
                resource_strategy,
                max_request_size,
            ),
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
                    return true;
                }
                self.handle_create_link(dest_hash, dest_sig_pub_bytes, response_tx);
            }
            Event::DestinationStampReady { dest_hash } => {
                if self.is_draining() {
                    return true;
                }
                self.emit_builtin_announce_for(dest_hash, time::now());
                self.send_stamp_waiting_path_responses(dest_hash);
            }
            Event::SendStampedPathRequest(request) => {
                if self.is_draining() {
                    self.reject_new_work("send stamped path request");
                    return true;
                }
                let crate::stamper::StampedPathRequest {
                    destination_hash,
                    tag,
                    ext_payload,
                    target,
                } = *request;
                self.send_path_request(destination_hash, &tag, Some(&ext_payload), target);
            }
            Event::CompleteStampedLink(keys) => self.handle_complete_stamped_link(*keys),
            Event::SendRequest {
                link_id,
                path,
                data,
                max_response_size,
                timeout,
            } => self.handle_send_request(link_id, path, data, max_response_size, timeout),
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
            } => self.handle_identify_on_link(link_id, identity_prv_key),
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
                    return true;
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
            } => self.handle_send_resource_stream(
                link_id,
                transfer_id,
                reader,
                declared_length,
                metadata,
                options,
            ),
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
            } => self.handle_accept_resource(link_id, resource_hash, accept),
            Event::SendChannelMessage {
                link_id,
                msgtype,
                payload,
                response_tx,
            } => self.handle_send_channel_message(link_id, msgtype, payload, response_tx),
            Event::LinkWriterReady => {}
            Event::SendLinkTracked {
                link_id,
                data,
                context,
                completion,
            } => self.handle_send_link_tracked(link_id, data, context, completion),
            Event::SendOnLink {
                link_id,
                data,
                context,
                response_tx,
            } => self.handle_send_on_link(link_id, data, context, response_tx),
            Event::RequestPath { dest_hash } => {
                if self.is_draining() {
                    self.reject_new_work("request path");
                    let _ = dest_hash;
                    return true;
                }
                self.handle_request_path(dest_hash);
            }
            Event::RegisterProofStrategy {
                dest_hash,
                strategy,
                signing_key,
            } => {
                let identity =
                    signing_key.map(|key| rns_crypto::identity::Identity::from_private_key(&key));
                self.proof_strategies
                    .insert(dest_hash, (strategy, identity));
            }
            Event::ProposeDirectConnect { link_id } => self.handle_propose_direct_connect(link_id),
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
            } => self.handle_hole_punch_probe_result(
                link_id,
                session_id,
                observed_addr,
                socket,
                probe_server,
            ),
            Event::DirectPathMtu { interface_id, mtu } => {
                self.direct_path_mtu_discovered(interface_id, mtu);
            }
            Event::HolePunchProbeFailed {
                link_id,
                session_id,
            } => self.handle_hole_punch_probe_failed(link_id, session_id),
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
            Event::InterfaceConfigChanged(id) => self.handle_interface_config_changed(id),
            event @ (Event::BackbonePeerConnected { .. }
            | Event::BackbonePeerDisconnected { .. }
            | Event::BackbonePeerIdleTimeout { .. }
            | Event::BackbonePeerWriteStall { .. }
            | Event::BackbonePeerPenalty { .. }) => self.handle_backbone_peer_event(&event),
            Event::Shutdown => {
                self.event_tx.link_send_pool().close();
                self.pending_link_frames.clear();
                self.graceful_shutdown();
                return false;
            }
        }
        true
    }
}
