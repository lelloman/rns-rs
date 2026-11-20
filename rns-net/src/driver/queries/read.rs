//! Queries that only read the driver.

use super::*;

impl Driver {
    /// Managed links with their local send backlog.
    pub(crate) fn link_info_entries(&self) -> Vec<crate::event::LinkInfoEntry> {
        let counts = self.event_tx.link_send_pool().snapshot();
        let mut links = self.link_manager.link_entries();
        for link in &mut links {
            if let Some(counts) = counts.get(&link.link_id) {
                link.pending_send_packets = counts.pending;
                link.waiting_send_packets = counts.waiting;
            }
        }
        links
    }

    pub(crate) fn handle_path_table_query(&self, max_hops: Option<u8>) -> QueryResponse {
        let entries: Vec<PathTableEntry> = self
            .engine
            .path_table_entries()
            .filter(|(_, entry)| max_hops.is_none_or(|max| entry.hops <= max))
            .map(|(hash, entry)| {
                let iface_display_name = self
                    .interfaces
                    .get(&entry.receiving_interface)
                    .map(|e| self.interface_display_name(e));
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
                let known = self.known.entries.get(hash);
                PathTableEntry {
                    hash: *hash,
                    timestamp: entry.timestamp,
                    via: entry.next_hop,
                    hops: entry.hops,
                    expires: entry.expires,
                    used: entry.used,
                    interface: entry.receiving_interface,
                    interface_display_name: iface_display_name
                        .unwrap_or_else(|| iface_name.clone()),
                    interface_name: iface_name,
                    stamp_value: known.map(|known| known.stamp_value),
                    lr_cost: known.and_then(|known| known.lr_cost),
                    state: self.engine.path_state(hash),
                }
            })
            .collect();
        QueryResponse::PathTable(entries)
    }

    /// Handle a query request and produce a response.
    pub(crate) fn handle_query(&self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::ManageInterface { .. } => QueryResponse::InterfaceManagement(Some(false)),
            QueryRequest::InterfaceStats => self.handle_interface_stats_query(),
            QueryRequest::BackboneInterfaces => {
                QueryResponse::BackboneInterfaces(self.list_backbone_interfaces())
            }
            QueryRequest::ProviderBridgeStats => {
                QueryResponse::ProviderBridgeStats(self.hooks.provider_bridge_stats())
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
            QueryRequest::LowestInterfaceBitrate => {
                QueryResponse::LowestInterfaceBitrate(self.engine.lowest_interface_bitrate())
            }
            QueryRequest::MediumPathTimeout => {
                QueryResponse::MediumPathTimeout(self.engine.medium_path_timeout())
            }
            QueryRequest::FirstHopTimeout { dest_hash } => {
                let bitrate = match self.engine.next_hop_interface(&dest_hash) {
                    Some(id) => self
                        .interfaces
                        .get(&id)
                        .and_then(|entry| entry.info.bitrate),
                    None if self.hosts_destination(&dest_hash) => self
                        .shared_instance_listener()
                        .and_then(|listener| listener.bitrate),
                    None => None,
                }
                .filter(|bitrate| *bitrate > 0);
                let timeout = rns_core::constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP
                    + bitrate
                        .map(|bitrate| rns_core::constants::MTU as f64 * 8.0 / bitrate as f64)
                        .unwrap_or(0.0);
                QueryResponse::FirstHopTimeout(timeout)
            }
            QueryRequest::NextHop { dest_hash } => {
                let resp = match self.engine.next_hop(&dest_hash) {
                    Some(next_hop) => Some(NextHopResponse {
                        next_hop,
                        hops: self.engine.hops_to(&dest_hash).unwrap_or(0),
                        interface: self
                            .engine
                            .next_hop_interface(&dest_hash)
                            .unwrap_or(InterfaceId(0)),
                    }),
                    // Upstream's `Transport.next_hop`: this node's own
                    // destinations are reached through its transport
                    // identity, on the shared instance interface, with
                    // hops unknown (`hops_to` answers PATHFINDER_M).
                    None if self.hosts_destination(&dest_hash) => self
                        .transport_identity
                        .as_ref()
                        .map(|identity| NextHopResponse {
                            next_hop: *identity.hash(),
                            hops: rns_core::constants::PATHFINDER_M,
                            interface: self
                                .shared_instance_listener()
                                .map_or(InterfaceId(0), |listener| listener.id),
                        }),
                    None => None,
                };
                QueryResponse::NextHop(resp)
            }
            QueryRequest::NextHopIfName { dest_hash } => {
                let name = match self.engine.next_hop_interface(&dest_hash) {
                    // Upstream answers with str(interface).
                    Some(id) => self
                        .interfaces
                        .get(&id)
                        .map(|entry| self.interface_display_name(entry)),
                    // Its own destinations are on the shared instance
                    // interface; without one, `str(None)`.
                    None if self.hosts_destination(&dest_hash) => self
                        .shared_instance_listener()
                        .map(|listener| listener.display_name.clone()),
                    None => None,
                };
                QueryResponse::NextHopIfName(name)
            }
            QueryRequest::LinkCount => QueryResponse::LinkCount(
                self.engine.link_table_count() + self.link_manager.link_count(),
            ),
            QueryRequest::ActiveLinkCount => QueryResponse::ActiveLinkCount(
                self.engine.active_link_count() + self.link_manager.active_link_count(),
            ),
            QueryRequest::LinkDistribution => QueryResponse::LinkDistribution(
                self.engine
                    .link_distribution()
                    .into_iter()
                    .map(|destination| {
                        let mut from_interface_hashes: Vec<[u8; 32]> = Vec::new();
                        for id in &destination.from_interfaces {
                            // Upstream's set holds `get_hash()`s, so two
                            // interfaces of the same name are one.
                            let hash = self.interface_hash(id);
                            if !from_interface_hashes.contains(&hash) {
                                from_interface_hashes.push(hash);
                            }
                        }
                        crate::event::LinkDistributionEntry {
                            destination_hash: destination.destination_hash,
                            active: destination.active,
                            pending: destination.pending,
                            traffic: destination.traffic,
                            from_interface_hashes,
                        }
                    })
                    .collect(),
            ),
            QueryRequest::DropPath { .. } => {
                // Mutating queries are handled by handle_query_mut
                QueryResponse::DropPath(false)
            }
            QueryRequest::DropAllVia { .. } => QueryResponse::DropAllVia(0),
            QueryRequest::DropAnnounceQueues => QueryResponse::DropAnnounceQueues,
            QueryRequest::WantsDestinationType { .. }
            | QueryRequest::UnwantsDestinationType { .. }
            | QueryRequest::UnwantsAllDestinationTypes { .. }
            | QueryRequest::SetRequiredDestinationsOnly { .. } => {
                // Mutating queries are handled by handle_query_mut
                QueryResponse::DestinationTypeRegistration(false)
            }
            QueryRequest::TransportIdentity => {
                QueryResponse::TransportIdentity(self.engine.identity_hash().copied())
            }
            QueryRequest::TransportStateSnapshot => {
                QueryResponse::TransportStateSnapshot(self.engine.persistence_snapshot())
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
                        source: entry.source.or(self.engine.identity_hash().copied()),
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
            QueryRequest::RetainIdentity { .. } => QueryResponse::RetainIdentity(false),
            QueryRequest::UnretainKnownDestination { .. } => {
                QueryResponse::UnretainKnownDestination(false)
            }
            QueryRequest::MarkKnownDestinationUsed { .. } => {
                QueryResponse::MarkKnownDestinationUsed(false)
            }
            QueryRequest::HasPath { dest_hash } => {
                QueryResponse::HasPath(self.engine.has_path(&dest_hash))
            }
            // Upstream looks the hash up from the oldest entry.
            QueryRequest::PacketSignal { packet_hash } => QueryResponse::PacketSignal(
                self.packet_signals
                    .iter()
                    .find(|(hash, _)| *hash == packet_hash)
                    .map(|(_, signal)| *signal),
            ),
            QueryRequest::HopsTo { dest_hash } => {
                QueryResponse::HopsTo(self.engine.hops_to(&dest_hash))
            }
            QueryRequest::RecallIdentity { .. } => QueryResponse::RecallIdentity(None),
            QueryRequest::RecallDestinationStamp { .. } => {
                QueryResponse::RecallDestinationStamp(None)
            }
            QueryRequest::KnownDestinations => {
                QueryResponse::KnownDestinations(self.known_destination_entries())
            }
            QueryRequest::KnownDestinationChanges => {
                let (changed, removed) = self.known_destination_changes();
                QueryResponse::KnownDestinationChanges { changed, removed }
            }
            // Mutating queries are handled by handle_query_mut
            QueryRequest::RecordKnownDestinationFlush { .. } => {
                QueryResponse::KnownDestinationFlushRecorded
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
            QueryRequest::Links => QueryResponse::Links(self.link_info_entries()),
            QueryRequest::DirectLinks => {
                QueryResponse::DirectLinks(self.holepunch_manager.status())
            }
            QueryRequest::Resources => {
                QueryResponse::Resources(self.link_manager.resource_entries())
            }
            QueryRequest::DiscoveredInterfaces {
                only_available,
                only_transport,
            } => {
                let mut interfaces = self.discovery.storage.list().unwrap_or_default();
                // Upstream's list_discovered_interfaces leaves out the
                // interfaces of networks that are not discovery sources.
                interfaces.retain(|iface| self.discovery_source_allowed(&iface.network_id));
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
            QueryRequest::SendProbe { .. } => {
                QueryResponse::SendProbe(Err(crate::event::SendProbeError::PackFailed))
            }
            QueryRequest::CheckProof { .. } => QueryResponse::CheckProof(None),
        }
    }
}
