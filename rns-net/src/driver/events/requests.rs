//! Requests from the node API that the driver handles: registrations,
//! link sends and direct connections.

use super::*;

impl Driver {
    /// Register a destination this node answers path requests for, and on a
    /// shared-instance client announce it to the instance shortly after.
    pub(super) fn handle_register_path_responder(
        &mut self,
        destination: crate::destination::Destination,
        identity_prv_key: [u8; 64],
    ) {
        let dest_hash = destination.hash.0;
        let aspects: Vec<&str> = destination.aspects.iter().map(String::as_str).collect();
        let record = SharedAnnounceRecord {
            name_hash: rns_core::destination::name_hash(&destination.app_name, &aspects),
            identity_prv_key,
            app_data: None,
        };
        self.path_responders.insert(
            dest_hash,
            PathResponder {
                record,
                destination,
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

    /// Register a destination that accepts links, in the link manager and as
    /// a local SINGLE destination in the transport engine.
    pub(super) fn handle_register_link_destination(
        &mut self,
        dest_hash: [u8; 16],
        sig_prv_bytes: [u8; 32],
        sig_pub_bytes: [u8; 32],
        resource_strategy: u8,
        max_request_size: Option<usize>,
    ) {
        let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_prv_bytes);
        let strat = match resource_strategy {
            1 => crate::link_manager::ResourceStrategy::AcceptAll,
            2 => crate::link_manager::ResourceStrategy::AcceptApp,
            _ => crate::link_manager::ResourceStrategy::AcceptNone,
        };
        self.link_manager
            .register_link_destination(dest_hash, sig_prv, sig_pub_bytes, strat);
        self.link_manager
            .set_link_destination_max_request_size(&dest_hash, max_request_size);
        // Also register in transport engine so inbound packets are delivered locally
        self.engine
            .register_destination(dest_hash, rns_core::constants::DESTINATION_SINGLE);
        self.local_destinations
            .insert(dest_hash, rns_core::constants::DESTINATION_SINGLE);
    }

    /// Send the link request whose stamped keys a stamp worker produced.
    pub(super) fn handle_complete_stamped_link(
        &mut self,
        keys: crate::common::event::StampedLinkKeys,
    ) {
        let crate::common::event::StampedLinkKeys {
            dest_hash,
            dest_sig_pub_bytes,
            prv_bytes,
            sig_prv_bytes,
            stamp_value,
            response_tx,
        } = keys;
        if self.is_draining() {
            self.reject_new_work("complete stamped link");
            let _ = response_tx.send([0u8; 16]);
            return;
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
        self.complete_create_link(dest_hash, dest_sig_pub_bytes, Some(keys), response_tx);
    }

    /// Send a request on a link.
    pub(super) fn handle_send_request(
        &mut self,
        link_id: [u8; 16],
        path: String,
        data: Vec<u8>,
        max_response_size: Option<usize>,
        timeout: Option<f64>,
    ) {
        if self.is_draining() {
            self.reject_new_work("send link request");
            let _ = (link_id, path, data, max_response_size, timeout);
            return;
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

    /// Identify this node to a link's peer.
    pub(super) fn handle_identify_on_link(
        &mut self,
        link_id: [u8; 16],
        identity_prv_key: [u8; 64],
    ) {
        if self.is_draining() {
            self.reject_new_work("identify on link");
            let _ = (link_id, identity_prv_key);
            return;
        }
        let identity = rns_crypto::identity::Identity::from_private_key(&identity_prv_key);
        let link_actions = self
            .link_manager
            .identify(&link_id, &identity, &mut self.rng);
        self.dispatch_link_actions(link_actions);
    }

    /// Start sending a resource read from a stream on a link.
    pub(super) fn handle_send_resource_stream(
        &mut self,
        link_id: [u8; 16],
        transfer_id: crate::resource::ResourceTransferId,
        reader: Box<dyn std::io::Read + Send>,
        declared_length: u64,
        metadata: Option<Vec<u8>>,
        options: crate::resource::ResourceSendOptions,
    ) {
        if self.is_draining() {
            self.callbacks.on_resource_stream_failed(
                rns_core::types::LinkId(link_id),
                transfer_id,
                crate::resource::ResourceTransferError::Cancelled,
            );
            return;
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

    /// Accept or reject an advertised resource on a link.
    pub(super) fn handle_accept_resource(
        &mut self,
        link_id: [u8; 16],
        resource_hash: Vec<u8>,
        accept: bool,
    ) {
        if self.is_draining() && accept {
            self.reject_new_work("accept resource");
            let _ = (link_id, resource_hash, accept);
            return;
        }
        let link_actions =
            self.link_manager
                .accept_resource(&link_id, &resource_hash, accept, &mut self.rng);
        self.dispatch_link_actions(link_actions);
    }

    /// Send a channel message on a link and report the outcome.
    pub(super) fn handle_send_channel_message(
        &mut self,
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
        response_tx: std::sync::mpsc::Sender<Result<(), crate::ChannelSendError>>,
    ) {
        if self.is_draining() {
            self.reject_new_work("send channel message");
            let _ = response_tx.send(Err(crate::ChannelSendError::Unavailable));
            return;
        }
        match self
            .link_manager
            .send_channel_message(&link_id, msgtype, &payload, &mut self.rng)
        {
            Ok(link_actions) => {
                self.dispatch_link_actions(link_actions);
                let _ = response_tx.send(Ok(()));
            }
            Err(err) => {
                let _ = response_tx.send(Err(err));
            }
        }
    }

    /// Send data on a link, completing `completion` once it is sent or failed.
    pub(super) fn handle_send_link_tracked(
        &mut self,
        link_id: [u8; 16],
        data: Vec<u8>,
        context: u8,
        completion: crate::link_send::Completion,
    ) {
        use crate::link_send::LinkSendError;
        if self.is_draining() {
            completion.finish(Err(LinkSendError::Draining));
            return;
        }
        match self
            .link_manager
            .try_send_on_link(&link_id, &data, context, &mut self.rng)
        {
            Ok(actions) => {
                if self.link_manager.get_link_route_hint(&link_id).is_none() {
                    completion.finish(Err(LinkSendError::NoRoute));
                    return;
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

    /// Send a datagram on a link, reporting the outcome to `response_tx` if given.
    pub(super) fn handle_send_on_link(
        &mut self,
        link_id: [u8; 16],
        data: Vec<u8>,
        context: u8,
        response_tx: Option<std::sync::mpsc::Sender<Result<(), crate::event::LinkDatagramError>>>,
    ) {
        if self.is_draining() {
            self.reject_new_work("send link payload");
            if let Some(tx) = response_tx {
                let _ = tx.send(Err(crate::event::LinkDatagramError::DriverStopped));
            }
            return;
        }
        let result = self
            .link_manager
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

    /// Propose a direct (hole-punched) connection for a link to its peer.
    pub(super) fn handle_propose_direct_connect(&mut self, link_id: [u8; 16]) {
        if self.is_draining() {
            self.reject_new_work("propose direct connect");
            let _ = link_id;
            return;
        }
        let derived_key = self.link_manager.get_derived_key(&link_id);
        if let Some(dk) = derived_key {
            let tx = self.get_event_sender();
            let hp_actions = self
                .holepunch_manager
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

    /// A probe server reported this node's public address for a direct
    /// connection session.
    pub(super) fn handle_hole_punch_probe_result(
        &mut self,
        link_id: [u8; 16],
        session_id: [u8; 16],
        observed_addr: std::net::SocketAddr,
        socket: std::net::UdpSocket,
        probe_server: std::net::SocketAddr,
    ) {
        let hp_actions = self.holepunch_manager.handle_probe_result(
            link_id,
            session_id,
            observed_addr,
            socket,
            probe_server,
        );
        self.dispatch_holepunch_actions(hp_actions);
    }

    /// A probe for a direct connection failed: tell the session.
    pub(super) fn handle_hole_punch_probe_failed(
        &mut self,
        link_id: [u8; 16],
        session_id: [u8; 16],
    ) {
        let hp_actions = self
            .holepunch_manager
            .handle_probe_failed(link_id, session_id);
        self.dispatch_holepunch_actions(hp_actions);
    }

    /// An interface's runtime configuration changed: apply it.
    pub(super) fn handle_interface_config_changed(&mut self, id: InterfaceId) {
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
                &mut self.hooks.slots[HookPoint::InterfaceConfigChanged as usize].programs,
                &self.hooks.manager,
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
}
