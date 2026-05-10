use super::*;

impl Driver {
    pub(crate) fn handle_interface_stats_query(&self) -> QueryResponse {
        let mut interfaces = Vec::new();
        let mut total_rxb: u64 = 0;
        let mut total_txb: u64 = 0;
        for entry in self.interfaces.values() {
            total_rxb += entry.stats.rxb;
            total_txb += entry.stats.txb;
            interfaces.push(SingleInterfaceStat {
                id: entry.info.id.0,
                name: entry.info.name.clone(),
                status: entry.online && entry.enabled,
                mode: entry.info.mode,
                rxb: entry.stats.rxb,
                txb: entry.stats.txb,
                rx_packets: entry.stats.rx_packets,
                tx_packets: entry.stats.tx_packets,
                bitrate: entry.info.bitrate,
                ifac_size: entry.ifac.as_ref().map(|s| s.size),
                started: entry.stats.started,
                ia_freq: entry.stats.incoming_announce_freq(),
                oa_freq: entry.stats.outgoing_announce_freq(),
                announce_rate_target: entry.info.announce_rate_target,
                announce_rate_grace: entry.info.announce_rate_grace,
                announce_rate_penalty: entry.info.announce_rate_penalty,
                interface_type: entry.interface_type.clone(),
            });
        }
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        QueryResponse::InterfaceStats(InterfaceStatsResponse {
            interfaces,
            transport_id: self.engine.identity_hash().copied(),
            transport_enabled: self.engine.transport_enabled(),
            transport_uptime: time::now() - self.started,
            total_rxb,
            total_txb,
            probe_responder: self.probe_responder_hash,
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: self.backbone_peer_pool_status(),
            #[cfg(not(feature = "iface-backbone"))]
            backbone_peer_pool: None,
        })
    }

    pub(crate) fn handle_path_table_query(&self, max_hops: Option<u8>) -> QueryResponse {
        let entries: Vec<PathTableEntry> = self
            .engine
            .path_table_entries()
            .filter(|(_, entry)| max_hops.is_none_or(|max| entry.hops <= max))
            .map(|(hash, entry)| {
                let iface_name = self
                    .interfaces
                    .get(&entry.receiving_interface)
                    .map(|e| e.info.name.clone())
                    .or_else(|| {
                        self.engine
                            .interface_info(&entry.receiving_interface)
                            .map(|i| i.name.clone())
                    })
                    .unwrap_or_default();
                PathTableEntry {
                    hash: *hash,
                    timestamp: entry.timestamp,
                    via: entry.next_hop,
                    hops: entry.hops,
                    expires: entry.expires,
                    interface: entry.receiving_interface,
                    interface_name: iface_name,
                }
            })
            .collect();
        QueryResponse::PathTable(entries)
    }

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
            } => {
                let now = time::now();
                self.engine
                    .blackhole_identity(identity_hash, now, duration_hours, reason);
                Some(QueryResponse::BlackholeResult(true))
            }
            QueryRequest::UnblackholeIdentity { identity_hash } => Some(
                QueryResponse::UnblackholeResult(self.engine.unblackhole_identity(&identity_hash)),
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
                self.known_destinations.insert(
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
                    },
                );
                Some(QueryResponse::RestoreKnownDestination(true))
            }
            QueryRequest::RetainKnownDestination { dest_hash } => Some(
                QueryResponse::RetainKnownDestination(self.retain_known_destination(&dest_hash)),
            ),
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
            QueryRequest::UnretainKnownDestination { .. } => {
                QueryResponse::UnretainKnownDestination(false)
            }
            QueryRequest::MarkKnownDestinationUsed { .. } => {
                QueryResponse::MarkKnownDestinationUsed(false)
            }
            _ => QueryResponse::InjectIdentity(false),
        }
    }

    /// Handle a query request and produce a response.
    pub(crate) fn handle_query(&self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::InterfaceStats => self.handle_interface_stats_query(),
            QueryRequest::BackboneInterfaces => {
                QueryResponse::BackboneInterfaces(self.list_backbone_interfaces())
            }
            QueryRequest::ProviderBridgeStats => {
                #[cfg(feature = "hooks")]
                {
                    QueryResponse::ProviderBridgeStats(
                        self.provider_bridge.as_ref().map(|bridge| bridge.stats()),
                    )
                }
                #[cfg(not(feature = "hooks"))]
                {
                    QueryResponse::ProviderBridgeStats(None::<crate::event::ProviderBridgeStats>)
                }
            }
            QueryRequest::DrainStatus => QueryResponse::DrainStatus(self.drain_status()),
            QueryRequest::PathTable { max_hops } => self.handle_path_table_query(max_hops),
            QueryRequest::RateTable => {
                let entries: Vec<RateTableEntry> = self
                    .engine
                    .rate_limiter()
                    .entries()
                    .map(|(hash, entry)| RateTableEntry {
                        hash: *hash,
                        last: entry.last,
                        rate_violations: entry.rate_violations,
                        blocked_until: entry.blocked_until,
                        timestamps: entry.timestamps.clone(),
                    })
                    .collect();
                QueryResponse::RateTable(entries)
            }
            QueryRequest::NextHop { dest_hash } => {
                let resp = self
                    .engine
                    .next_hop(&dest_hash)
                    .map(|next_hop| NextHopResponse {
                        next_hop,
                        hops: self.engine.hops_to(&dest_hash).unwrap_or(0),
                        interface: self
                            .engine
                            .next_hop_interface(&dest_hash)
                            .unwrap_or(InterfaceId(0)),
                    });
                QueryResponse::NextHop(resp)
            }
            QueryRequest::NextHopIfName { dest_hash } => {
                let name = self
                    .engine
                    .next_hop_interface(&dest_hash)
                    .and_then(|id| self.interfaces.get(&id))
                    .map(|entry| entry.info.name.clone());
                QueryResponse::NextHopIfName(name)
            }
            QueryRequest::LinkCount => QueryResponse::LinkCount(
                self.engine.link_table_count() + self.link_manager.link_count(),
            ),
            QueryRequest::DropPath { .. } => {
                // Mutating queries are handled by handle_query_mut
                QueryResponse::DropPath(false)
            }
            QueryRequest::DropAllVia { .. } => QueryResponse::DropAllVia(0),
            QueryRequest::DropAnnounceQueues => QueryResponse::DropAnnounceQueues,
            QueryRequest::TransportIdentity => {
                QueryResponse::TransportIdentity(self.engine.identity_hash().copied())
            }
            QueryRequest::GetBlackholed => {
                let now = time::now();
                let entries: Vec<BlackholeInfo> = self
                    .engine
                    .blackholed_entries()
                    .filter(|(_, e)| e.expires == 0.0 || e.expires > now)
                    .map(|(hash, entry)| BlackholeInfo {
                        identity_hash: *hash,
                        created: entry.created,
                        expires: entry.expires,
                        reason: entry.reason.clone(),
                    })
                    .collect();
                QueryResponse::Blackholed(entries)
            }
            QueryRequest::BlackholeIdentity { .. } | QueryRequest::UnblackholeIdentity { .. } => {
                // Mutating queries handled by handle_query_mut
                QueryResponse::BlackholeResult(false)
            }
            QueryRequest::InjectPath { .. } => {
                // Mutating queries handled by handle_query_mut
                QueryResponse::InjectPath(false)
            }
            QueryRequest::InjectIdentity { .. } => {
                // Mutating queries handled by handle_query_mut
                QueryResponse::InjectIdentity(false)
            }
            QueryRequest::RestoreKnownDestination(..) => {
                QueryResponse::RestoreKnownDestination(false)
            }
            QueryRequest::RetainKnownDestination { .. } => {
                QueryResponse::RetainKnownDestination(false)
            }
            QueryRequest::UnretainKnownDestination { .. } => {
                QueryResponse::UnretainKnownDestination(false)
            }
            QueryRequest::MarkKnownDestinationUsed { .. } => {
                QueryResponse::MarkKnownDestinationUsed(false)
            }
            QueryRequest::HasPath { dest_hash } => {
                QueryResponse::HasPath(self.engine.has_path(&dest_hash))
            }
            QueryRequest::HopsTo { dest_hash } => {
                QueryResponse::HopsTo(self.engine.hops_to(&dest_hash))
            }
            QueryRequest::RecallIdentity { .. } => QueryResponse::RecallIdentity(None),
            QueryRequest::KnownDestinations => {
                QueryResponse::KnownDestinations(self.known_destination_entries())
            }
            QueryRequest::LocalDestinations => {
                let entries: Vec<LocalDestinationEntry> = self
                    .local_destinations
                    .iter()
                    .map(|(hash, dest_type)| LocalDestinationEntry {
                        hash: *hash,
                        dest_type: *dest_type,
                    })
                    .collect();
                QueryResponse::LocalDestinations(entries)
            }
            QueryRequest::Links => QueryResponse::Links(self.link_manager.link_entries()),
            QueryRequest::Resources => {
                QueryResponse::Resources(self.link_manager.resource_entries())
            }
            QueryRequest::DiscoveredInterfaces {
                only_available,
                only_transport,
            } => {
                let mut interfaces = self.discovered_interfaces.list().unwrap_or_default();
                crate::discovery::filter_and_sort_interfaces(
                    &mut interfaces,
                    only_available,
                    only_transport,
                );
                QueryResponse::DiscoveredInterfaces(interfaces)
            }
            request @ (QueryRequest::ListRuntimeConfig
            | QueryRequest::GetRuntimeConfig { .. }
            | QueryRequest::BackbonePeerState { .. }
            | QueryRequest::SetRuntimeConfig { .. }
            | QueryRequest::ResetRuntimeConfig { .. }
            | QueryRequest::ClearBackbonePeerState { .. }
            | QueryRequest::BlacklistBackbonePeer { .. }) => {
                let fallback = Self::runtime_config_query_fallback(&request);
                self.handle_runtime_config_query(request)
                    .unwrap_or_else(|| {
                        log::error!(
                            "runtime-config query branch unexpectedly returned no response"
                        );
                        fallback
                    })
            }
            // Mutating queries handled by handle_query_mut
            QueryRequest::SendProbe { .. } => QueryResponse::SendProbe(None),
            QueryRequest::CheckProof { .. } => QueryResponse::CheckProof(None),
        }
    }

    /// Handle a mutating query request.
    pub(crate) fn handle_query_mut(&mut self, request: QueryRequest) -> QueryResponse {
        match request {
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
            | QueryRequest::UnretainKnownDestination { .. }
            | QueryRequest::MarkKnownDestinationUsed { .. }) => {
                let fallback = Self::mutation_query_fallback(&request);
                self.handle_mutation_query(request).unwrap_or_else(|| {
                    log::error!("mutation query branch unexpectedly returned no response");
                    fallback
                })
            }
            QueryRequest::RecallIdentity { dest_hash } => {
                let recalled = self.known_destination_announced(&dest_hash);
                if recalled.is_some() {
                    let _ = self.mark_known_destination_used(&dest_hash);
                }
                QueryResponse::RecallIdentity(recalled)
            }
            QueryRequest::DrainStatus => QueryResponse::DrainStatus(self.drain_status()),
            QueryRequest::SendProbe {
                dest_hash,
                payload_size,
            } => {
                // Look up the identity for this destination hash
                let announced = self.known_destination_announced(&dest_hash);
                match announced {
                    Some(recalled) => {
                        let _ = self.mark_known_destination_used(&dest_hash);
                        // Encrypt random payload with remote public key
                        let remote_id =
                            rns_crypto::identity::Identity::from_public_key(&recalled.public_key);
                        let mut payload = vec![0u8; payload_size];
                        self.rng.fill_bytes(&mut payload);
                        match remote_id.encrypt(&payload, &mut self.rng) {
                            Ok(ciphertext) => {
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
                                    &ciphertext,
                                ) {
                                    Ok(packet) => {
                                        let packet_hash = packet.packet_hash;
                                        let hops = self.engine.hops_to(&dest_hash).unwrap_or(0);
                                        // Track for proof matching
                                        self.sent_packets
                                            .insert(packet_hash, (dest_hash, time::now()));
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
                                        QueryResponse::SendProbe(Some((packet_hash, hops)))
                                    }
                                    Err(_) => {
                                        log::warn!("Failed to pack probe packet");
                                        QueryResponse::SendProbe(None)
                                    }
                                }
                            }
                            Err(_) => {
                                log::warn!("Failed to encrypt probe payload");
                                QueryResponse::SendProbe(None)
                            }
                        }
                    }
                    None => {
                        log::debug!("No known identity for probe dest {:02x?}", &dest_hash[..4]);
                        QueryResponse::SendProbe(None)
                    }
                }
            }
            QueryRequest::CheckProof { packet_hash } => {
                match self.completed_proofs.remove(&packet_hash) {
                    Some((rtt, _received)) => QueryResponse::CheckProof(Some(rtt)),
                    None => QueryResponse::CheckProof(None),
                }
            }
            QueryRequest::SetRuntimeConfig { key, value } => {
                let result = match key.as_str() {
                    "global.tick_interval_ms" => match Self::expect_u64(value, &key) {
                        Ok(value) => {
                            let clamped = value.clamp(100, 10_000);
                            self.tick_interval_ms.store(clamped, Ordering::Relaxed);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.known_destinations_ttl_secs" => match Self::expect_f64(value, &key) {
                        Ok(value) => {
                            self.known_destinations_ttl = value;
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.rate_limiter_ttl_secs" => match Self::expect_f64(value, &key) {
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
                        match Self::expect_u64(value, &key) {
                            Ok(value) if value > 0 => {
                                self.known_destinations_cleanup_interval_ticks = value as u32;
                                Ok(())
                            }
                            Ok(_) => Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::InvalidValue,
                                message: format!("{} must be >= 1", key),
                            }),
                            Err(err) => Err(err),
                        }
                    }
                    "global.announce_cache_cleanup_interval_ticks" => {
                        match Self::expect_u64(value, &key) {
                            Ok(value) if value > 0 => {
                                self.announce_cache_cleanup_interval_ticks = value as u32;
                                Ok(())
                            }
                            Ok(_) => Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::InvalidValue,
                                message: format!("{} must be >= 1", key),
                            }),
                            Err(err) => Err(err),
                        }
                    }
                    "global.announce_cache_cleanup_batch_size" => {
                        match Self::expect_u64(value, &key) {
                            Ok(value) if value > 0 => {
                                self.announce_cache_cleanup_batch_size = value as usize;
                                Ok(())
                            }
                            Ok(_) => Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::InvalidValue,
                                message: format!("{} must be >= 1", key),
                            }),
                            Err(err) => Err(err),
                        }
                    }
                    "global.discovery_cleanup_interval_ticks" => {
                        match Self::expect_u64(value, &key) {
                            Ok(value) if value > 0 => {
                                self.discovery_cleanup_interval_ticks = value as u32;
                                Ok(())
                            }
                            Ok(_) => Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::InvalidValue,
                                message: format!("{} must be >= 1", key),
                            }),
                            Err(err) => Err(err),
                        }
                    }
                    "global.management_announce_interval_secs" => {
                        match Self::expect_f64(value, &key) {
                            Ok(value) => {
                                self.management_announce_interval_secs = value;
                                Ok(())
                            }
                            Err(err) => Err(err),
                        }
                    }
                    "global.direct_connect_policy" => {
                        let policy = match Self::parse_holepunch_policy(&value) {
                            Some(policy) => policy,
                            None => {
                                return QueryResponse::RuntimeConfigSet(Err(RuntimeConfigError {
                                    code: RuntimeConfigErrorCode::InvalidValue,
                                    message: format!(
                                        "{} must be one of: reject, accept_all, ask_app",
                                        key
                                    ),
                                }))
                            }
                        };
                        self.holepunch_manager.set_policy(policy);
                        Ok(())
                    }
                    #[cfg(feature = "hooks")]
                    "provider.queue_max_events" => match Self::expect_u64(value, &key) {
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
                    #[cfg(feature = "hooks")]
                    "provider.queue_max_bytes" => match Self::expect_u64(value, &key) {
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
                    _ => match Self::runtime_config_family_for_key(&key) {
                        Some(family) => self.set_runtime_config_family_value(family, &key, value),
                        None => {
                            return QueryResponse::RuntimeConfigSet(Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::UnknownKey,
                                message: format!("unknown runtime-config key '{}'", key),
                            }))
                        }
                    },
                };

                QueryResponse::RuntimeConfigSet(match result {
                    Ok(()) => self.runtime_config_entry(&key).ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::ApplyFailed,
                        message: format!("failed to read back runtime-config key '{}'", key),
                    }),
                    Err(err) => Err(err),
                })
            }
            QueryRequest::ResetRuntimeConfig { key } => {
                let defaults = self.runtime_config_defaults;
                let result = match key.as_str() {
                    "global.tick_interval_ms" => {
                        self.tick_interval_ms
                            .store(defaults.tick_interval_ms, Ordering::Relaxed);
                        Ok(())
                    }
                    "global.known_destinations_ttl_secs" => {
                        self.known_destinations_ttl = defaults.known_destinations_ttl;
                        Ok(())
                    }
                    "global.rate_limiter_ttl_secs" => {
                        self.rate_limiter_ttl_secs = defaults.rate_limiter_ttl_secs;
                        Ok(())
                    }
                    "global.known_destinations_cleanup_interval_ticks" => {
                        self.known_destinations_cleanup_interval_ticks =
                            defaults.known_destinations_cleanup_interval_ticks;
                        Ok(())
                    }
                    "global.announce_cache_cleanup_interval_ticks" => {
                        self.announce_cache_cleanup_interval_ticks =
                            defaults.announce_cache_cleanup_interval_ticks;
                        Ok(())
                    }
                    "global.announce_cache_cleanup_batch_size" => {
                        self.announce_cache_cleanup_batch_size =
                            defaults.announce_cache_cleanup_batch_size;
                        Ok(())
                    }
                    "global.discovery_cleanup_interval_ticks" => {
                        self.discovery_cleanup_interval_ticks =
                            defaults.discovery_cleanup_interval_ticks;
                        Ok(())
                    }
                    "global.management_announce_interval_secs" => {
                        self.management_announce_interval_secs =
                            defaults.management_announce_interval_secs;
                        Ok(())
                    }
                    "global.direct_connect_policy" => {
                        self.holepunch_manager
                            .set_policy(defaults.direct_connect_policy);
                        Ok(())
                    }
                    #[cfg(feature = "hooks")]
                    "provider.queue_max_events" => {
                        if let Some(ref bridge) = self.provider_bridge {
                            bridge.set_queue_max_events(defaults.provider_queue_max_events);
                        }
                        Ok(())
                    }
                    #[cfg(feature = "hooks")]
                    "provider.queue_max_bytes" => {
                        if let Some(ref bridge) = self.provider_bridge {
                            bridge.set_queue_max_bytes(defaults.provider_queue_max_bytes);
                        }
                        Ok(())
                    }
                    _ => match Self::runtime_config_family_for_key(&key) {
                        Some(family) => self.reset_runtime_config_family_value(family, &key),
                        None => {
                            return QueryResponse::RuntimeConfigReset(Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::UnknownKey,
                                message: format!("unknown runtime-config key '{}'", key),
                            }))
                        }
                    },
                };

                QueryResponse::RuntimeConfigReset(match result {
                    Ok(()) => self.runtime_config_entry(&key).ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::ApplyFailed,
                        message: format!("failed to read back runtime-config key '{}'", key),
                    }),
                    Err(err) => Err(err),
                })
            }
            other => self.handle_query(other),
        }
    }
}
