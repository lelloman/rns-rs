//! Queries that change the driver, runtime config among them.

use super::*;

impl Driver {
    pub(crate) fn handle_runtime_config_query(
        &self,
        request: QueryRequest,
    ) -> Option<QueryResponse> {
        match request {
            QueryRequest::ListRuntimeConfig => {
                Some(QueryResponse::RuntimeConfigList(self.list_runtime_config()))
            }
            QueryRequest::GetRuntimeConfig { key } => Some(QueryResponse::RuntimeConfigEntry(
                self.runtime_config_entry(&key),
            )),
            QueryRequest::BackbonePeerState { interface_name } => {
                Some(QueryResponse::BackbonePeerState(
                    self.list_backbone_peer_state(interface_name.as_deref()),
                ))
            }
            QueryRequest::SetRuntimeConfig { .. } => {
                Some(QueryResponse::RuntimeConfigSet(Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::Unsupported,
                    message: "mutating runtime config is handled separately".to_string(),
                })))
            }
            QueryRequest::ResetRuntimeConfig { .. } => {
                Some(QueryResponse::RuntimeConfigReset(Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::Unsupported,
                    message: "mutating runtime config is handled separately".to_string(),
                })))
            }
            QueryRequest::ClearBackbonePeerState { .. } => {
                Some(QueryResponse::ClearBackbonePeerState(false))
            }
            QueryRequest::BlacklistBackbonePeer { .. } => {
                Some(QueryResponse::BlacklistBackbonePeer(false))
            }
            _ => None,
        }
    }

    pub(crate) fn handle_mutation_query(&mut self, request: QueryRequest) -> Option<QueryResponse> {
        match request {
            QueryRequest::BlackholeIdentity {
                identity_hash,
                duration_hours,
                reason,
            } => Some(QueryResponse::BlackholeResult(
                self.blackhole_identity_local(identity_hash, duration_hours, reason),
            )),
            QueryRequest::UnblackholeIdentity { identity_hash } => Some(
                QueryResponse::UnblackholeResult(self.unblackhole_identity_local(&identity_hash)),
            ),
            QueryRequest::DropPath { dest_hash } => {
                Some(QueryResponse::DropPath(self.engine.drop_path(&dest_hash)))
            }
            QueryRequest::DropAllVia { transport_hash } => Some(QueryResponse::DropAllVia(
                self.engine.drop_all_via(&transport_hash),
            )),
            QueryRequest::DropAnnounceQueues => {
                self.engine.drop_announce_queues();
                Some(QueryResponse::DropAnnounceQueues)
            }
            QueryRequest::ClearBackbonePeerState {
                interface_name,
                peer_ip,
            } => Some(QueryResponse::ClearBackbonePeerState(
                self.clear_backbone_peer_state(&interface_name, peer_ip),
            )),
            QueryRequest::BlacklistBackbonePeer {
                interface_name,
                peer_ip,
                duration,
                reason,
                penalty_level,
            } => Some(QueryResponse::BlacklistBackbonePeer(
                self.blacklist_backbone_peer(
                    &interface_name,
                    peer_ip,
                    duration,
                    reason,
                    penalty_level,
                ),
            )),
            QueryRequest::InjectPath {
                dest_hash,
                next_hop,
                hops,
                expires,
                interface_name,
                packet_hash,
            } => {
                let iface_id = self
                    .interfaces
                    .iter()
                    .find(|(_, entry)| entry.info.name == interface_name)
                    .map(|(id, _)| *id);
                Some(match iface_id {
                    Some(id) => {
                        let entry = PathEntry {
                            timestamp: time::now(),
                            next_hop,
                            hops,
                            expires,
                            random_blobs: Vec::new(),
                            receiving_interface: id,
                            packet_hash,
                            used: 0.0,
                            announce_raw: None,
                        };
                        self.engine.inject_path(dest_hash, entry);
                        QueryResponse::InjectPath(true)
                    }
                    None => QueryResponse::InjectPath(false),
                })
            }
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash,
                public_key,
                app_data,
                hops,
                received_at,
            } => {
                self.upsert_known_destination(
                    dest_hash,
                    crate::destination::AnnouncedIdentity {
                        dest_hash: rns_core::types::DestHash(dest_hash),
                        identity_hash: rns_core::types::IdentityHash(identity_hash),
                        public_key,
                        app_data,
                        hops,
                        received_at,
                        receiving_interface: rns_core::transport::types::InterfaceId(0),
                        rssi: None,
                        snr: None,
                    },
                );
                Some(QueryResponse::InjectIdentity(true))
            }
            QueryRequest::RestoreKnownDestination(entry) => {
                self.known.entries.insert(
                    entry.dest_hash,
                    KnownDestinationState {
                        announced: crate::destination::AnnouncedIdentity {
                            dest_hash: rns_core::types::DestHash(entry.dest_hash),
                            identity_hash: rns_core::types::IdentityHash(entry.identity_hash),
                            public_key: entry.public_key,
                            app_data: entry.app_data,
                            hops: entry.hops,
                            received_at: entry.received_at,
                            receiving_interface: entry.receiving_interface,
                            rssi: None,
                            snr: None,
                        },
                        was_used: entry.was_used,
                        last_used_at: entry.last_used_at,
                        retained: entry.retained,
                        stamp: entry.stamp,
                        stamp_value: entry.stamp_value,
                        lr_cost: entry.lr_cost,
                    },
                );
                Some(QueryResponse::RestoreKnownDestination(true))
            }
            QueryRequest::RetainKnownDestination { dest_hash } => Some(
                QueryResponse::RetainKnownDestination(self.retain_known_destination(&dest_hash)),
            ),
            QueryRequest::RetainIdentity { identity_hash } => Some(QueryResponse::RetainIdentity(
                self.retain_identity(&identity_hash),
            )),
            QueryRequest::UnretainKnownDestination { dest_hash } => {
                Some(QueryResponse::UnretainKnownDestination(
                    self.unretain_known_destination(&dest_hash),
                ))
            }
            QueryRequest::MarkKnownDestinationUsed { dest_hash } => {
                Some(QueryResponse::MarkKnownDestinationUsed(
                    self.mark_known_destination_used(&dest_hash),
                ))
            }
            _ => None,
        }
    }

    pub(crate) fn runtime_config_query_fallback(request: &QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::ListRuntimeConfig => QueryResponse::RuntimeConfigList(Vec::new()),
            QueryRequest::GetRuntimeConfig { .. } => QueryResponse::RuntimeConfigEntry(None),
            QueryRequest::BackbonePeerState { .. } => QueryResponse::BackbonePeerState(Vec::new()),
            QueryRequest::SetRuntimeConfig { key, .. } => {
                QueryResponse::RuntimeConfigSet(Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::ApplyFailed,
                    message: format!(
                        "internal error: no response generated for runtime-config set '{}'",
                        key
                    ),
                }))
            }
            QueryRequest::ResetRuntimeConfig { key } => {
                QueryResponse::RuntimeConfigReset(Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::ApplyFailed,
                    message: format!(
                        "internal error: no response generated for runtime-config reset '{}'",
                        key
                    ),
                }))
            }
            QueryRequest::ClearBackbonePeerState { .. } => {
                QueryResponse::ClearBackbonePeerState(false)
            }
            QueryRequest::BlacklistBackbonePeer { .. } => {
                QueryResponse::BlacklistBackbonePeer(false)
            }
            _ => QueryResponse::RuntimeConfigEntry(None),
        }
    }

    pub(crate) fn mutation_query_fallback(request: &QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::BlackholeIdentity { .. } => QueryResponse::BlackholeResult(false),
            QueryRequest::UnblackholeIdentity { .. } => QueryResponse::UnblackholeResult(false),
            QueryRequest::DropPath { .. } => QueryResponse::DropPath(false),
            QueryRequest::DropAllVia { .. } => QueryResponse::DropAllVia(0),
            QueryRequest::DropAnnounceQueues => QueryResponse::DropAnnounceQueues,
            QueryRequest::ClearBackbonePeerState { .. } => {
                QueryResponse::ClearBackbonePeerState(false)
            }
            QueryRequest::BlacklistBackbonePeer { .. } => {
                QueryResponse::BlacklistBackbonePeer(false)
            }
            QueryRequest::InjectPath { .. } => QueryResponse::InjectPath(false),
            QueryRequest::InjectIdentity { .. } => QueryResponse::InjectIdentity(false),
            QueryRequest::RestoreKnownDestination(..) => {
                QueryResponse::RestoreKnownDestination(false)
            }
            QueryRequest::RetainKnownDestination { .. } => {
                QueryResponse::RetainKnownDestination(false)
            }
            QueryRequest::RetainIdentity { .. } => QueryResponse::RetainIdentity(false),
            QueryRequest::UnretainKnownDestination { .. } => {
                QueryResponse::UnretainKnownDestination(false)
            }
            QueryRequest::MarkKnownDestinationUsed { .. } => {
                QueryResponse::MarkKnownDestinationUsed(false)
            }
            _ => QueryResponse::InjectIdentity(false),
        }
    }

    /// Handle a mutating query request.
    pub(crate) fn handle_query_mut(&mut self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::RecordKnownDestinationFlush {
                stored,
                removed,
                seed,
            } => self.record_known_destination_flush(stored, removed, seed),
            QueryRequest::WantsDestinationType {
                full_name,
                requester,
            } => QueryResponse::DestinationTypeRegistration(
                self.wants_destination_type(&full_name, &requester),
            ),
            QueryRequest::UnwantsDestinationType {
                full_name,
                requester,
            } => QueryResponse::DestinationTypeRegistration(
                self.unwants_destination_type(&full_name, &requester),
            ),
            QueryRequest::UnwantsAllDestinationTypes { requester } => {
                self.unwant_all_destination_types(&requester)
            }
            QueryRequest::SetRequiredDestinationsOnly { enabled } => {
                self.set_required_destinations_only(enabled)
            }
            QueryRequest::ManageInterface { operation, name } => {
                QueryResponse::InterfaceManagement(self.manage_interface(operation, &name))
            }
            request @ (QueryRequest::BlackholeIdentity { .. }
            | QueryRequest::UnblackholeIdentity { .. }
            | QueryRequest::DropPath { .. }
            | QueryRequest::DropAllVia { .. }
            | QueryRequest::DropAnnounceQueues
            | QueryRequest::ClearBackbonePeerState { .. }
            | QueryRequest::BlacklistBackbonePeer { .. }
            | QueryRequest::InjectPath { .. }
            | QueryRequest::InjectIdentity { .. }
            | QueryRequest::RestoreKnownDestination(..)
            | QueryRequest::RetainKnownDestination { .. }
            | QueryRequest::RetainIdentity { .. }
            | QueryRequest::UnretainKnownDestination { .. }
            | QueryRequest::MarkKnownDestinationUsed { .. }) => {
                let fallback = Self::mutation_query_fallback(&request);
                self.handle_mutation_query(request).unwrap_or_else(|| {
                    log::error!("mutation query branch unexpectedly returned no response");
                    fallback
                })
            }
            QueryRequest::RecallDestinationStamp { dest_hash } => {
                QueryResponse::RecallDestinationStamp(self.known.entries.get(&dest_hash).map(
                    |state| crate::event::DestinationStampInfo {
                        stamp_value: state.stamp_value,
                        lr_cost: state.lr_cost,
                    },
                ))
            }
            QueryRequest::RecallIdentity { dest_hash } => self.recall_identity(&dest_hash),
            QueryRequest::DrainStatus => QueryResponse::DrainStatus(self.drain_status()),
            QueryRequest::SendProbe {
                dest_hash,
                payload_size,
            } => self.send_probe(dest_hash, payload_size),
            QueryRequest::CheckProof { packet_hash } => {
                match self.completed_proofs.remove(&packet_hash) {
                    Some((rtt, _received)) => QueryResponse::CheckProof(Some(rtt)),
                    None => QueryResponse::CheckProof(None),
                }
            }
            QueryRequest::SetRuntimeConfig { key, value } => self.set_runtime_config(key, value),
            QueryRequest::ResetRuntimeConfig { key } => self.reset_runtime_config(key),
            other => self.handle_query(other),
        }
    }

    /// Record which known destinations the store now holds: `stored` added,
    /// `removed` dropped, after forgetting the rest when `seed`.
    fn record_known_destination_flush(
        &mut self,
        stored: Vec<([u8; 16], u64)>,
        removed: Vec<[u8; 16]>,
        seed: bool,
    ) -> QueryResponse {
        if seed {
            self.known.flushed.clear();
        }
        self.known.flushed.extend(stored);
        for dest_hash in removed {
            self.known.flushed.remove(&dest_hash);
        }
        QueryResponse::KnownDestinationFlushRecorded
    }

    /// Drop every destination type requirement of `requester`.
    fn unwant_all_destination_types(&mut self, requester: &[u8]) -> QueryResponse {
        self.engine.destination_filter_mut().unwant_all(requester);
        log::debug!(
            "Deregistered all destination requirements for <{}>",
            hex(requester)
        );
        QueryResponse::DestinationTypeRegistration(true)
    }

    /// Filter announces to the required destination types only, or not.
    fn set_required_destinations_only(&mut self, enabled: bool) -> QueryResponse {
        self.engine
            .destination_filter_mut()
            .set_required_only(enabled);
        if enabled {
            log::debug!("Setting announce filtering to required only");
        } else {
            log::debug!("Setting announce filtering to all");
        }
        QueryResponse::DestinationTypeRegistration(true)
    }

    /// The identity announced for `dest_hash`, marking it used when known.
    fn recall_identity(&mut self, dest_hash: &[u8; 16]) -> QueryResponse {
        let recalled = self.known_destination_announced(dest_hash);
        if recalled.is_some() {
            let _ = self.mark_known_destination_used(dest_hash);
        }
        QueryResponse::RecallIdentity(recalled)
    }

    /// Send a probe of `payload_size` random bytes, encrypted to
    /// `dest_hash`'s identity, answering its packet hash and hop count.
    fn send_probe(&mut self, dest_hash: [u8; 16], payload_size: usize) -> QueryResponse {
        use crate::event::{SendProbeError, MAX_PROBE_PAYLOAD_SIZE};
        if payload_size > MAX_PROBE_PAYLOAD_SIZE {
            log::warn!(
                "Probe payload of {} bytes exceeds maximum of {} bytes",
                payload_size,
                MAX_PROBE_PAYLOAD_SIZE,
            );
            return QueryResponse::SendProbe(Err(SendProbeError::PayloadTooLarge {
                max: MAX_PROBE_PAYLOAD_SIZE,
            }));
        }
        // Look up the identity for this destination hash
        let announced = self.known_destination_announced(&dest_hash);
        match announced {
            Some(recalled) => {
                let _ = self.mark_known_destination_used(&dest_hash);
                // Encrypt random payload to the destination's ratchet
                // when it announced one, else to its public key.
                let ratchet = self.single_ratchet_for(&dest_hash);
                let mut payload = vec![0u8; payload_size];
                self.rng.fill_bytes(&mut payload);
                match rns_crypto::identity::Identity::encrypt_for_public_key(
                    &recalled.public_key,
                    &payload,
                    ratchet.as_ref(),
                    &mut self.rng,
                ) {
                    Ok(ciphertext) => self.send_probe_packet(dest_hash, &ciphertext, payload_size),
                    Err(e) => {
                        log::warn!("Failed to encrypt probe payload: {:?}", e);
                        QueryResponse::SendProbe(Err(SendProbeError::EncryptFailed))
                    }
                }
            }
            None => {
                log::debug!("No known identity for probe dest {:02x?}", &dest_hash[..4]);
                QueryResponse::SendProbe(Err(SendProbeError::UnknownIdentity))
            }
        }
    }

    /// Pack the encrypted probe as a DATA packet to `dest_hash`, track it
    /// for its proof and send it.
    fn send_probe_packet(
        &mut self,
        dest_hash: [u8; 16],
        ciphertext: &[u8],
        payload_size: usize,
    ) -> QueryResponse {
        // Build DATA SINGLE BROADCAST packet to dest_hash
        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_DATA,
        };
        match RawPacket::pack(
            flags,
            0,
            &dest_hash,
            None,
            rns_core::constants::CONTEXT_NONE,
            ciphertext,
        ) {
            Ok(packet) => {
                let packet_hash = packet.packet_hash;
                let hops = self.engine.hops_to(&dest_hash).unwrap_or(0);
                // Track for proof matching, and record
                // its proof for CheckProof polling.
                self.sent_packets
                    .insert(packet_hash, (dest_hash, time::now()));
                self.pending_probes.insert(packet_hash);
                // Send via engine
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    time::now(),
                );
                self.dispatch_all(actions);
                log::debug!(
                    "Sent probe ({} bytes) to {:02x?}",
                    payload_size,
                    &dest_hash[..4],
                );
                QueryResponse::SendProbe(Ok((packet_hash, hops)))
            }
            Err(e) => {
                log::warn!("Failed to pack probe packet: {:?}", e);
                QueryResponse::SendProbe(Err(crate::event::SendProbeError::PackFailed))
            }
        }
    }

    /// Set runtime-config `key` to `value`, answering its entry read back.
    fn set_runtime_config(&mut self, key: String, value: RuntimeConfigValue) -> QueryResponse {
        let result = self.apply_runtime_config_value(&key, value);
        QueryResponse::RuntimeConfigSet(match result {
            Ok(()) => self.runtime_config_entry(&key).ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::ApplyFailed,
                message: format!("failed to read back runtime-config key '{}'", key),
            }),
            Err(err) => Err(err),
        })
    }

    /// Apply `value` to runtime-config `key`.
    fn apply_runtime_config_value(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        match key {
            "global.tick_interval_ms"
            | "global.known_destinations_ttl_secs"
            | "global.rate_limiter_ttl_secs"
            | "global.known_destinations_cleanup_interval_ticks"
            | "global.announce_cache_cleanup_interval_ticks"
            | "global.announce_cache_cleanup_batch_size"
            | "global.discovery_cleanup_interval_ticks"
            | "global.management_announce_interval_secs" => self.set_timing_config(key, value),
            "global.stamp_destinations"
            | "global.stamp_path_requests"
            | "global.stamps_enforced"
            | "global.lr_stamps_enforced"
            | "global.stamp_link_requests"
            | "global.always_stamp_link_requests" => self.set_stamp_config(key, value),
            "global.direct_connect_policy" => {
                let policy = match Self::parse_holepunch_policy(&value) {
                    Some(policy) => policy,
                    None => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidValue,
                            message: format!(
                                "{} must be one of: reject, accept_all, identified_only, ask_app",
                                key
                            ),
                        })
                    }
                };
                self.holepunch_manager.set_policy(policy);
                Ok(())
            }
            #[cfg(feature = "hooks")]
            "provider.queue_max_events" | "provider.queue_max_bytes" => {
                self.set_provider_queue_limit(key, value)
            }
            _ => match Self::runtime_config_family_for_key(key) {
                Some(family) => self.set_runtime_config_family_value(family, key, value),
                None => Err(unknown_runtime_config_key(key)),
            },
        }
    }

    /// Set one of the driver's tick, TTL, cleanup and announce intervals.
    fn set_timing_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        match key {
            "global.tick_interval_ms" => match Self::expect_u64(value, key) {
                Ok(value) => {
                    let clamped = value.clamp(100, 10_000);
                    self.tick_interval_ms.store(clamped, Ordering::Relaxed);
                    Ok(())
                }
                Err(err) => Err(err),
            },
            "global.known_destinations_ttl_secs" => match Self::expect_f64(value, key) {
                Ok(value) => {
                    self.known.ttl = value;
                    Ok(())
                }
                Err(err) => Err(err),
            },
            "global.rate_limiter_ttl_secs" => match Self::expect_f64(value, key) {
                Ok(value) if value >= 0.0 => {
                    self.rate_limiter_ttl_secs = value;
                    Ok(())
                }
                Ok(_) => Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidValue,
                    message: format!("{} must be >= 0", key),
                }),
                Err(err) => Err(err),
            },
            "global.known_destinations_cleanup_interval_ticks" => {
                match Self::expect_u64(value, key) {
                    Ok(value) if value > 0 => {
                        self.known.cleanup_interval_ticks = value as u32;
                        Ok(())
                    }
                    Ok(_) => Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be >= 1", key),
                    }),
                    Err(err) => Err(err),
                }
            }
            "global.announce_cache_cleanup_interval_ticks" => match Self::expect_u64(value, key) {
                Ok(value) if value > 0 => {
                    self.housekeeping.announce_cache_cleanup_interval_ticks = value as u32;
                    Ok(())
                }
                Ok(_) => Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidValue,
                    message: format!("{} must be >= 1", key),
                }),
                Err(err) => Err(err),
            },
            "global.announce_cache_cleanup_batch_size" => match Self::expect_u64(value, key) {
                Ok(value) if value > 0 => {
                    self.housekeeping.announce_cache_cleanup_batch_size = value as usize;
                    Ok(())
                }
                Ok(_) => Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidValue,
                    message: format!("{} must be >= 1", key),
                }),
                Err(err) => Err(err),
            },
            "global.discovery_cleanup_interval_ticks" => match Self::expect_u64(value, key) {
                Ok(value) if value > 0 => {
                    self.discovery.cleanup_interval_ticks = value as u32;
                    Ok(())
                }
                Ok(_) => Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidValue,
                    message: format!("{} must be >= 1", key),
                }),
                Err(err) => Err(err),
            },
            "global.management_announce_interval_secs" => match Self::expect_f64(value, key) {
                Ok(value) => {
                    self.management_announce_interval_secs = value;
                    Ok(())
                }
                Err(err) => Err(err),
            },
            _ => Err(unknown_runtime_config_key(key)),
        }
    }

    /// Set one of the stamp settings.
    fn set_stamp_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        match key {
            "global.stamp_destinations" => match Self::expect_bool(value, key) {
                Ok(value) => {
                    self.stamp_destinations.store(value, Ordering::Relaxed);
                    Ok(())
                }
                Err(err) => Err(err),
            },
            "global.stamp_path_requests" => match Self::expect_bool(value, key) {
                Ok(value) => {
                    self.engine.set_stamp_prs(value);
                    Ok(())
                }
                Err(err) => Err(err),
            },
            "global.stamps_enforced" => match Self::expect_bool(value, key) {
                Ok(value) => {
                    self.set_stamps_enforced(value);
                    Ok(())
                }
                Err(err) => Err(err),
            },
            "global.lr_stamps_enforced" => match Self::expect_bool(value, key) {
                Ok(value) => {
                    self.link_manager.link_request_costs().set_enforced(value);
                    Ok(())
                }
                Err(err) => Err(err),
            },
            "global.stamp_link_requests" => match Self::expect_bool(value, key) {
                Ok(value) => {
                    self.stamp_settings.stamp_lrs = value;
                    Ok(())
                }
                Err(err) => Err(err),
            },
            "global.always_stamp_link_requests" => match Self::expect_bool(value, key) {
                Ok(value) => {
                    self.stamp_settings.always_stamp_lrs = value;
                    Ok(())
                }
                Err(err) => Err(err),
            },
            _ => Err(unknown_runtime_config_key(key)),
        }
    }

    /// Set one of the provider bridge's queue limits.
    #[cfg(feature = "hooks")]
    fn set_provider_queue_limit(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        match key {
            "provider.queue_max_events" => match Self::expect_u64(value, key) {
                Ok(v) if v > 0 => {
                    if let Some(ref bridge) = self.provider_bridge {
                        bridge.set_queue_max_events(v as usize);
                    }
                    Ok(())
                }
                Ok(_) => Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidValue,
                    message: format!("{} must be >= 1", key),
                }),
                Err(err) => Err(err),
            },
            "provider.queue_max_bytes" => match Self::expect_u64(value, key) {
                Ok(v) if v > 0 => {
                    if let Some(ref bridge) = self.provider_bridge {
                        bridge.set_queue_max_bytes(v as usize);
                    }
                    Ok(())
                }
                Ok(_) => Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidValue,
                    message: format!("{} must be >= 1", key),
                }),
                Err(err) => Err(err),
            },
            _ => Err(unknown_runtime_config_key(key)),
        }
    }

    /// Reset runtime-config `key` to its default, answering its entry read
    /// back.
    fn reset_runtime_config(&mut self, key: String) -> QueryResponse {
        let result = self.reset_runtime_config_value(&key);
        QueryResponse::RuntimeConfigReset(match result {
            Ok(()) => self.runtime_config_entry(&key).ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::ApplyFailed,
                message: format!("failed to read back runtime-config key '{}'", key),
            }),
            Err(err) => Err(err),
        })
    }

    /// Put runtime-config `key` back to its default.
    fn reset_runtime_config_value(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let defaults = self.runtime_config.defaults;
        match key {
            "global.tick_interval_ms" => {
                self.tick_interval_ms
                    .store(defaults.tick_interval_ms, Ordering::Relaxed);
            }
            "global.known_destinations_ttl_secs" => {
                self.known.ttl = defaults.known_destinations_ttl;
            }
            "global.rate_limiter_ttl_secs" => {
                self.rate_limiter_ttl_secs = defaults.rate_limiter_ttl_secs;
            }
            "global.known_destinations_cleanup_interval_ticks" => {
                self.known.cleanup_interval_ticks =
                    defaults.known_destinations_cleanup_interval_ticks;
            }
            "global.announce_cache_cleanup_interval_ticks" => {
                self.housekeeping.announce_cache_cleanup_interval_ticks =
                    defaults.announce_cache_cleanup_interval_ticks;
            }
            "global.announce_cache_cleanup_batch_size" => {
                self.housekeeping.announce_cache_cleanup_batch_size =
                    defaults.announce_cache_cleanup_batch_size;
            }
            "global.discovery_cleanup_interval_ticks" => {
                self.discovery.cleanup_interval_ticks = defaults.discovery_cleanup_interval_ticks;
            }
            "global.management_announce_interval_secs" => {
                self.management_announce_interval_secs = defaults.management_announce_interval_secs;
            }
            "global.stamp_destinations" => {
                self.stamp_destinations
                    .store(defaults.stamp_destinations, Ordering::Relaxed);
            }
            "global.stamp_path_requests" => {
                self.engine.set_stamp_prs(defaults.stamp_path_requests);
            }
            "global.stamps_enforced" => {
                self.set_stamps_enforced(defaults.stamps_enforced);
            }
            "global.lr_stamps_enforced" => {
                self.link_manager
                    .link_request_costs()
                    .set_enforced(defaults.lr_stamps_enforced);
            }
            "global.stamp_link_requests" => {
                self.stamp_settings.stamp_lrs = defaults.stamp_link_requests;
            }
            "global.always_stamp_link_requests" => {
                self.stamp_settings.always_stamp_lrs = defaults.always_stamp_link_requests;
            }
            "global.direct_connect_policy" => {
                self.holepunch_manager
                    .set_policy(defaults.direct_connect_policy);
            }
            #[cfg(feature = "hooks")]
            "provider.queue_max_events" => {
                if let Some(ref bridge) = self.provider_bridge {
                    bridge.set_queue_max_events(defaults.provider_queue_max_events);
                }
            }
            #[cfg(feature = "hooks")]
            "provider.queue_max_bytes" => {
                if let Some(ref bridge) = self.provider_bridge {
                    bridge.set_queue_max_bytes(defaults.provider_queue_max_bytes);
                }
            }
            _ => {
                return match Self::runtime_config_family_for_key(key) {
                    Some(family) => self.reset_runtime_config_family_value(family, key),
                    None => Err(unknown_runtime_config_key(key)),
                }
            }
        }
        Ok(())
    }
}

/// The error for a runtime-config key the driver does not have.
fn unknown_runtime_config_key(key: &str) -> RuntimeConfigError {
    RuntimeConfigError {
        code: RuntimeConfigErrorCode::UnknownKey,
        message: format!("unknown runtime-config key '{}'", key),
    }
}
