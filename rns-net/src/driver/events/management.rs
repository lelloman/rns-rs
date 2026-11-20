//! Management and built-in destinations: their announces and requests.

use super::*;

impl Driver {
    /// Delay before the first management announces after startup
    /// (`Transport.start` defers them by 15 seconds).
    pub(crate) const MANAGEMENT_ANNOUNCE_DELAY: f64 = 15.0;

    /// Tick the discovery announcer: start stamp generation if due, send announce if ready.
    pub(crate) fn tick_discovery_announcer(&mut self, now: f64) {
        let announcer = match self.interface_announcer.as_mut() {
            Some(a) => a,
            None => return,
        };

        announcer.set_stamp_requirements(self.engine.stamp_requirements());
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

        let app_data = match stamp_result.app_data {
            Ok(app_data) => app_data,
            Err(error) => {
                log::error!(
                    "Discovery: suppressing announce for '{}': {}",
                    stamp_result.interface_name,
                    error
                );
                return;
            }
        };

        // As upstream's `InterfaceAnnouncer`, the discovery destination
        // belongs to the network identity when one is configured, and to
        // the transport identity otherwise.
        let identity = match self
            .network_identity
            .as_ref()
            .or(self.transport_identity.as_ref())
        {
            Some(id) => id,
            None => {
                log::warn!("Discovery: stamp ready but no transport identity");
                return;
            }
        };

        // Discovery is a SINGLE destination: the dest hash includes the
        // announcing identity.
        let identity_hash = identity.hash();
        let disc_dest = rns_core::destination::destination_hash(
            crate::discovery::APP_NAME,
            &["discovery", "interface"],
            Some(identity_hash),
        );
        let name_hash = self.discovery_name_hash;
        let random_hash = crate::common::management::announce_random_blob(&mut self.rng, now);

        let (announce_data, _) = match rns_core::announce::AnnounceData::pack(
            identity,
            &disc_dest,
            &name_hash,
            &random_hash,
            None,
            Some(&app_data),
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

        self.engine.register_destination(
            packet.destination_hash,
            rns_core::constants::DESTINATION_SINGLE,
        );
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

    /// Emit the built-in destinations' announces if enabled and due.
    pub(crate) fn tick_management_announces(&mut self, now: f64) {
        if self.transport_identity.is_none() && !self.network_destinations_enabled() {
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
        self.last_management_announce = now;
        for destination in crate::management::BuiltinDestination::ALL {
            if self.builtin_destination_enabled(destination) {
                let raw = self.build_builtin_announce(destination, now, false);
                self.emit_local_management_announce(raw, now, destination.label());
            }
        }
    }

    /// Whether this node announces and answers `destination`.
    pub(super) fn builtin_destination_enabled(
        &self,
        destination: crate::management::BuiltinDestination,
    ) -> bool {
        use crate::management::BuiltinDestination;
        match destination {
            BuiltinDestination::RemoteManagement => self.management_config.enable_remote_management,
            BuiltinDestination::Blackhole => self.management_config.publish_blackhole,
            BuiltinDestination::Probe => self.probe_responder_hash.is_some(),
            BuiltinDestination::NetworkInstance | BuiltinDestination::Network => {
                self.network_destinations_enabled()
            }
        }
    }

    /// Whether this node hosts the network identity's management
    /// destinations: with a network identity, unless it is a shared
    /// instance client.
    pub(crate) fn network_destinations_enabled(&self) -> bool {
        self.network_identity.is_some() && !self.connected_to_shared_instance
    }

    /// Register the network identity's management destinations when this
    /// node hosts them: path requests for them are answered, and links to
    /// them established. They have no request handlers, so, as upstream,
    /// requests on such a link go unanswered.
    pub(crate) fn register_network_destinations(&mut self) {
        use crate::management::BuiltinDestination;
        if !self.network_destinations_enabled() {
            return;
        }
        let Some((prv_key, pub_key)) = self
            .network_identity
            .as_ref()
            .and_then(|identity| Some((identity.get_private_key()?, identity.get_public_key()?)))
        else {
            return;
        };
        let mut sig_prv = [0u8; 32];
        sig_prv.copy_from_slice(&prv_key[32..64]);
        let mut sig_pub = [0u8; 32];
        sig_pub.copy_from_slice(&pub_key[32..64]);
        for destination in [
            BuiltinDestination::NetworkInstance,
            BuiltinDestination::Network,
        ] {
            if let Some(dest_hash) = self.builtin_dest_hash(destination) {
                self.engine
                    .register_destination(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                self.local_destinations
                    .insert(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                self.builtin_link_destinations.insert(dest_hash);
                self.link_manager
                    .register_link_destination_without_requests(
                        dest_hash,
                        rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_prv),
                        sig_pub,
                    );
            }
        }
    }

    /// The identity a built-in destination belongs to.
    pub(super) fn builtin_identity(
        &self,
        destination: crate::management::BuiltinDestination,
    ) -> Option<&rns_crypto::identity::Identity> {
        if destination.uses_network_identity() {
            self.network_identity.as_ref()
        } else {
            self.transport_identity.as_ref()
        }
    }

    pub(super) fn builtin_dest_hash(
        &self,
        destination: crate::management::BuiltinDestination,
    ) -> Option<[u8; 16]> {
        self.builtin_identity(destination)
            .map(|identity| destination.dest_hash(identity.hash()))
    }

    /// The enabled built-in destination whose hash is `dest_hash`.
    pub(super) fn enabled_builtin_destination(
        &self,
        dest_hash: &[u8; 16],
    ) -> Option<crate::management::BuiltinDestination> {
        crate::management::BuiltinDestination::ALL
            .into_iter()
            .find(|destination| {
                self.builtin_dest_hash(*destination).as_ref() == Some(dest_hash)
                    && self.builtin_destination_enabled(*destination)
            })
    }

    /// Send the announce of the built-in destination whose stamp the
    /// stamper just persisted.
    pub(super) fn emit_builtin_announce_for(&mut self, dest_hash: [u8; 16], now: f64) {
        if let Some(destination) = self.enabled_builtin_destination(&dest_hash) {
            let raw = self.build_builtin_announce(destination, now, false);
            self.emit_local_management_announce(raw, now, destination.label());
        }
    }

    /// Build a built-in destination's announce, as `Destination.announce`
    /// does for upstream's management destinations.
    ///
    /// The announce is signed by the identity the destination belongs to:
    /// the network identity for the `rnstransport.network` destinations,
    /// the transport identity for the others.
    ///
    /// With `STAMP_DESTINATIONS` the announce carries the destination's
    /// persisted stamp and its link cost (`BLACKHOLE_LINK_COST` for the
    /// blackhole list, `lr_cost` for the others). Without a persisted stamp
    /// nothing is sent now: the stamper grinds one and the announce follows
    /// on `Event::DestinationStampReady`, as upstream queues the announce
    /// with `enqueue_stamped_announce`.
    pub(super) fn build_builtin_announce(
        &mut self,
        destination: crate::management::BuiltinDestination,
        now: f64,
        path_response: bool,
    ) -> Option<Vec<u8>> {
        let identity = self.builtin_identity(destination)?;
        let identity_hash = *identity.hash();
        let dest_hash = destination.dest_hash(&identity_hash);
        let mut app_data = None;
        if self.stamp_destinations.load(Ordering::Relaxed) {
            let Some(store) = self.stamper.stamp_store() else {
                log::debug!(
                    "No stamp store, {} announce emission cancelled",
                    destination.label()
                );
                return None;
            };
            let public_key = identity.get_public_key()?;
            let material = rns_core::stamp::destination_stamp_material(
                &dest_hash,
                &public_key,
                &destination.name_hash(&identity_hash),
            );
            let target = self
                .stamper
                .targets()
                .destination_target(&destination.destination(identity_hash));
            match store.load(&dest_hash, &material, target) {
                Some((stamp, _value)) => {
                    let link_cost = self.link_manager.link_request_costs().get(&dest_hash);
                    app_data = Some(rns_core::stamp::announce_ext_payload(&stamp, 0, link_cost));
                }
                None => {
                    let identity_prv_key = identity.get_private_key()?;
                    let job = crate::stamper::DestinationStampJob {
                        dest: destination.destination(identity_hash),
                        identity_prv_key,
                    };
                    if self.stamper.enqueue_destination_stamp(job).is_err() {
                        log::debug!(
                            "Stamp queue full, dropping {} announce",
                            destination.label()
                        );
                    }
                    return None;
                }
            }
        }
        // Field by field, so the rng can be borrowed alongside.
        let identity = if destination.uses_network_identity() {
            self.network_identity.as_ref()
        } else {
            self.transport_identity.as_ref()
        }?;
        crate::management::build_builtin_announce(
            destination,
            identity,
            &mut self.rng,
            now,
            path_response,
            app_data.as_deref(),
        )
    }

    pub(super) fn emit_local_management_announce(
        &mut self,
        raw: Option<Vec<u8>>,
        now: f64,
        label: &str,
    ) {
        if let Some(raw) = raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                self.engine.register_destination(
                    packet.destination_hash,
                    rns_core::constants::DESTINATION_SINGLE,
                );
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted {} announce", label);
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
            // Upstream answers with get_interface_stats(), the RPC's dict.
            management::handle_status_request(
                &data,
                crate::rpc::interface_stats_msgpack(&self.interface_stats()),
                // The RPC's get_link_count.
                self.engine.link_table_count() + self.link_manager.link_count(),
            )
        } else if path_hash == management::path_path_hash() {
            management::handle_path_request(
                &data,
                || match self.handle_path_table_query(None) {
                    QueryResponse::PathTable(entries) => crate::rpc::path_table_msgpack(&entries),
                    _ => Vec::new(),
                },
                || match self.handle_query(QueryRequest::RateTable) {
                    QueryResponse::RateTable(entries) => crate::rpc::rate_table_msgpack(&entries),
                    _ => Vec::new(),
                },
            )
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
