use super::*;

fn traffic_detail(stats: &crate::interface::InterfaceStats) -> TrafficDetail {
    TrafficDetail {
        rxs: stats.traffic_rates.rxs,
        txs: stats.traffic_rates.txs,
        frxb: stats.frxb,
        ftxb: stats.ftxb,
        frxs: stats.traffic_rates.frxs,
        ftxs: stats.traffic_rates.ftxs,
        arxb: stats.arxb,
        atxb: stats.atxb,
        arxc: stats.arxc,
        atxc: stats.atxc,
        afrxc: stats.afrxc,
        arxs: stats.traffic_rates.arxs,
        atxs: stats.traffic_rates.atxs,
        prxb: stats.prxb,
        ptxb: stats.ptxb,
        prxc: stats.prxc,
        ptxc: stats.ptxc,
        prxs: stats.traffic_rates.prxs,
        ptxs: stats.traffic_rates.ptxs,
        arxf: stats.incoming_announce_freq(),
        atxf: stats.outgoing_announce_freq(),
        prxf: stats.incoming_path_request_freq(),
        ptxf: stats.outgoing_path_request_freq(),
    }
}

fn add_traffic(total: &mut TrafficDetail, detail: TrafficDetail) {
    total.rxs += detail.rxs;
    total.txs += detail.txs;
    total.frxb += detail.frxb;
    total.ftxb += detail.ftxb;
    total.frxs += detail.frxs;
    total.ftxs += detail.ftxs;
    total.arxb += detail.arxb;
    total.atxb += detail.atxb;
    total.arxc += detail.arxc;
    total.atxc += detail.atxc;
    total.afrxc += detail.afrxc;
    total.arxs += detail.arxs;
    total.atxs += detail.atxs;
    total.prxb += detail.prxb;
    total.ptxb += detail.ptxb;
    total.prxc += detail.prxc;
    total.ptxc += detail.ptxc;
    total.prxs += detail.prxs;
    total.ptxs += detail.ptxs;
    total.arxf += detail.arxf;
    total.atxf += detail.atxf;
    total.prxf += detail.prxf;
    total.ptxf += detail.ptxf;
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Driver {
    /// An interface announcer that encrypts `discovery_encrypt` announces
    /// to the network identity.
    pub(crate) fn new_interface_announcer(
        &self,
        transport_id: [u8; 16],
        interfaces: Vec<crate::discovery::DiscoverableInterface>,
    ) -> crate::discovery::InterfaceAnnouncer {
        let mut announcer = crate::discovery::InterfaceAnnouncer::new(transport_id, interfaces);
        announcer.set_network_public_key(
            self.network_identity
                .as_ref()
                .and_then(|identity| identity.get_public_key()),
        );
        announcer
    }

    /// Whether interfaces discovered from the network identity
    /// `network_id` are accepted: any are without
    /// `interface_discovery_sources`.
    pub(crate) fn discovery_source_allowed(&self, network_id: &[u8; 16]) -> bool {
        self.interface_discovery_sources.is_empty()
            || self.interface_discovery_sources.contains(network_id)
    }

    /// Remember a received packet's readings, keeping the newest
    /// `PACKET_SIGNAL_CACHE_MAXSIZE`.
    pub(crate) fn record_packet_signal(
        &mut self,
        packet_hash: [u8; 32],
        signal: crate::event::PacketSignal,
    ) {
        self.packet_signals.push_back((packet_hash, signal));
        while self.packet_signals.len() > super::PACKET_SIGNAL_CACHE_MAXSIZE {
            self.packet_signals.pop_front();
        }
    }

    /// `Transport._wants_destination_type`: returns `false` for a blocked
    /// type.
    pub(crate) fn wants_destination_type(&mut self, full_name: &str, requester: &[u8]) -> bool {
        use rns_core::transport::destination_filter::destination_type;
        let registered = self
            .engine
            .destination_filter_mut()
            .want(destination_type(full_name), requester);
        if registered {
            log::debug!(
                "Registered <{full_name}> destinations requirement for <{}>",
                hex_bytes(requester)
            );
        }
        registered
    }

    /// `Transport._unwants_destination_type`: returns whether the requester
    /// had registered the type.
    pub(crate) fn unwants_destination_type(&mut self, full_name: &str, requester: &[u8]) -> bool {
        use rns_core::transport::destination_filter::destination_type;
        let destination_type = destination_type(full_name);
        let filter = self.engine.destination_filter_mut();
        let was_registered = filter.unwant(destination_type, requester);
        if was_registered {
            log::debug!(
                "Deregistered <{full_name}> destinations requirement for <{}>",
                hex_bytes(requester)
            );
            if !filter.is_wanted(&destination_type) {
                log::debug!(
                    "No remaining requesters for <{full_name}> destinations, type deregistered"
                );
            }
        }
        was_registered
    }

    pub(super) fn dynamic_burst_counts(&self, parent_id: InterfaceId) -> (usize, usize) {
        self.dynamic_interface_parents
            .iter()
            .filter(|(_, candidate_parent)| **candidate_parent == parent_id)
            .fold((0, 0), |(announce_count, path_request_count), (id, _)| {
                (
                    announce_count + usize::from(self.engine.burst_active(id)),
                    path_request_count + usize::from(self.engine.pr_burst_active(id)),
                )
            })
    }

    /// Return active announce and path-request burst counts for a Backbone listener.
    #[cfg(feature = "iface-backbone")]
    pub fn backbone_burst_counts(&self, parent_id: InterfaceId) -> Option<(usize, usize)> {
        self.backbone_peer_state
            .values()
            .any(|handle| handle.interface_id == parent_id)
            .then(|| self.dynamic_burst_counts(parent_id))
    }

    /// Upstream's `str(interface)` for an interface entry.
    pub(crate) fn interface_display_name(&self, entry: &InterfaceEntry) -> String {
        if let Some(display_name) = self.interface_display_names.get(&entry.info.id) {
            return display_name.clone();
        }
        // The shared instance's clients on its Unix socket, which its
        // listener spawns unnamed: upstream names them after the socket.
        // (On TCP the listener names them after their port.)
        if entry.info.is_local_client && entry.dynamic {
            if let Some(ListenerStat {
                clients: ListenerClients::Local(endpoint),
                ..
            }) = self.shared_instance_listener()
            {
                return crate::interface::display::local_client(endpoint);
            }
        }
        crate::interface::display::typed(
            crate::rpc::upstream_interface_type(&entry.interface_type),
            &entry.info.name,
        )
    }

    /// Name a client the shared instance accepted on its abstract Unix
    /// socket, before it is added, as upstream does: `{clients}@\0rns/{instance}`,
    /// after the number of clients the instance serves (on TCP the
    /// listener names its clients after their port).
    pub(crate) fn name_local_client(&mut self, id: InterfaceId) {
        if self.interface_short_names.contains_key(&id) {
            return;
        }
        let Some(ListenerStat {
            clients:
                ListenerClients::Local(crate::interface::display::LocalEndpoint::Unix(instance)),
            ..
        }) = self.shared_instance_listener()
        else {
            return;
        };
        let clients = self
            .interfaces
            .values()
            .filter(|entry| entry.info.is_local_client && entry.dynamic && entry.info.id != id)
            .count();
        let short_name = format!("{clients}@\0rns/{instance}");
        self.interface_short_names.insert(id, short_name);
    }

    /// The display name of the listener that spawned an interface.
    fn parent_display_name(&self, entry: &InterfaceEntry) -> Option<String> {
        let parent_id = match self.dynamic_interface_parents.get(&entry.info.id) {
            Some(parent_id) => *parent_id,
            // The shared instance's clients have no registered parent.
            None if entry.info.is_local_client && entry.dynamic => {
                return self
                    .shared_instance_listener()
                    .map(|listener| listener.display_name.clone());
            }
            // Subinterfaces are configured, not spawned.
            None => {
                return self
                    .listener_stats
                    .iter()
                    .find(|listener| {
                        matches!(&listener.clients, ListenerClients::Subinterfaces(ids) if ids.contains(&entry.info.id))
                    })
                    .map(|listener| listener.display_name.clone());
            }
        };
        if let Some(listener) = self
            .listener_stats
            .iter()
            .find(|listener| listener.id == parent_id)
        {
            return Some(listener.display_name.clone());
        }
        if let Some(display_name) = self.interface_display_names.get(&parent_id) {
            return Some(display_name.clone());
        }
        self.interfaces
            .get(&parent_id)
            .map(|parent| self.interface_display_name(parent))
    }

    /// Whether this node hosts `dest_hash` itself (upstream's
    /// `Transport.destinations_map`), with no path to it in the table.
    fn hosts_destination(&self, dest_hash: &[u8; 16]) -> bool {
        self.local_destinations.contains_key(dest_hash)
    }

    fn shared_instance_listener(&self) -> Option<&ListenerStat> {
        self.listener_stats
            .iter()
            .find(|listener| matches!(listener.clients, ListenerClients::Local(_)))
    }

    /// Whether `entry` is one of the interfaces `listener` serves.
    fn listener_serves(&self, listener: &ListenerStat, entry: &InterfaceEntry) -> bool {
        match &listener.clients {
            ListenerClients::Local(_) => entry.info.is_local_client && entry.dynamic,
            ListenerClients::Subinterfaces(ids) => ids.contains(&entry.info.id),
            _ => self.dynamic_interface_parents.get(&entry.info.id) == Some(&listener.id),
        }
    }

    /// Whether `entry` is a subinterface of an RNodeMultiInterface whose
    /// device is not connected and configured: upstream creates the
    /// subinterfaces once it configured the device, and removes them when
    /// the connection fails, so it does not list them meanwhile.
    fn subinterface_without_device(&self, entry: &InterfaceEntry) -> bool {
        !entry.online
            && self.listener_stats.iter().any(|listener| {
                matches!(&listener.clients, ListenerClients::Subinterfaces(ids) if ids.contains(&entry.info.id))
            })
    }

    /// Whether an I2P peer connected to this node (upstream's `Connected
    /// peer on {interface}`), rather than this node to it.
    fn i2p_peer_accepted(&self, id: &InterfaceId) -> bool {
        self.interface_short_names
            .get(id)
            .is_some_and(|name| name.starts_with("Connected peer on "))
    }

    /// The tunnel state an I2P peer reports (upstream's `tunnelstate`);
    /// `None` for any other interface.
    #[cfg(feature = "iface-i2p")]
    fn i2p_tunnel_state(&self, entry: &InterfaceEntry) -> Option<Option<String>> {
        let parent = self.dynamic_interface_parents.get(&entry.info.id)?;
        self.listener_stats
            .iter()
            .find_map(|listener| match &listener.clients {
                ListenerClients::I2pPeers(i2p) if listener.id == *parent => Some(
                    crate::interface::lock_or_recover(&i2p.endpoint, "i2p endpoint")
                        .tunnels
                        .get(&entry.info.id)
                        .map(|tunnel| tunnel.state().description().to_string()),
                ),
                _ => None,
            })
    }

    #[cfg(not(feature = "iface-i2p"))]
    fn i2p_tunnel_state(&self, _entry: &InterfaceEntry) -> Option<Option<String>> {
        None
    }

    /// The statistics of a listener without an interface entry of its own:
    /// upstream counts its clients and adds up their bytes.
    fn listener_interface_stat(&self, listener: &ListenerStat) -> SingleInterfaceStat {
        let children: Vec<&InterfaceEntry> = self
            .interfaces
            .values()
            .filter(|entry| self.listener_serves(listener, entry))
            .collect();
        let mut status = true;
        let mut clients = Some(children.len() as u64);
        let mut peers = None;
        let mut i2p = None;
        // Whether only accepted peers' transmitted bytes add up on it.
        let mut accepted_tx_only = false;
        match &listener.clients {
            ListenerClients::Spawned | ListenerClients::Local(_) => {}
            ListenerClients::AutoPeers => {
                clients = None;
                peers = Some(children.len());
            }
            #[cfg(feature = "iface-i2p")]
            ListenerClients::I2pPeers(i2p_listener) => {
                let (online, b32) = {
                    let endpoint =
                        crate::interface::lock_or_recover(&i2p_listener.endpoint, "i2p endpoint");
                    (endpoint.online, endpoint.b32.clone())
                };
                status = online;
                clients = Some(
                    children
                        .iter()
                        .filter(|child| self.i2p_peer_accepted(&child.info.id))
                        .count() as u64,
                );
                peers = i2p_listener.configured_peers;
                i2p = Some(crate::event::I2pEndpointStat {
                    connectable: i2p_listener.connectable,
                    b32,
                });
                accepted_tx_only = true;
            }
            ListenerClients::Subinterfaces(_) => {
                // Online while its device is. As upstream, its
                // subinterfaces exist only while the device is configured.
                status = children.iter().any(|child| child.online);
                clients = Some(children.iter().filter(|child| child.online).count() as u64);
            }
        }
        let mut stat = SingleInterfaceStat {
            id: listener.id.0,
            name: listener.name.clone(),
            display_name: listener.display_name.clone(),
            parent_display_name: None,
            // A listener's tunnels belong to its spawned clients.
            tunnel_id: None,
            remote_transport_id: None,
            remote_transport_info: None,
            status,
            mode: listener.mode,
            gravity: listener.gravity,
            announces_to_internal: listener.announces_to_internal,
            rxb: 0,
            txb: 0,
            tx_drops: 0,
            tx_dropped_bytes: 0,
            tx_stalled: false,
            tx_buffered: 0,
            traffic: TrafficDetail::default(),
            protocol_violations: 0,
            ifac_violations: 0,
            packet_filter_hits: 0,
            hop_limiter_hits: 0,
            stamped_path_requests: 0,
            rx_packets: 0,
            tx_packets: 0,
            cpu_load: None,
            mem_load: None,
            switch_id: None,
            endpoint_id: None,
            via_switch_id: None,
            peers,
            rssi: None,
            snr: None,
            signal_quality: None,
            frequency: None,
            bandwidth: None,
            txpower: None,
            spreading_factor: None,
            coding_rate: None,
            channel: None,
            modulation: None,
            radio: None,
            bitrate: match listener.clients {
                ListenerClients::Local(_) => self.forced_local_bitrate.or(listener.bitrate),
                _ => listener.bitrate,
            },
            bitrate_is_float: false,
            mtu: Some(listener.mtu),
            ifac_size: listener.ifac.as_ref().map(|ifac| ifac.size),
            started: self.started,
            ia_freq: 0.0,
            oa_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            burst_active: false,
            burst_activated: 0.0,
            pr_burst_active: false,
            pr_burst_activated: 0.0,
            clients,
            blocked_ips: None,
            blocked_ip_list: None,
            i2p,
            i2p_tunnel_state: None,
            autoconnect_source: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            interface_type: listener.interface_type.clone(),
            held_announces: self.engine.held_announce_count(&listener.id),
            announce_queue: self.engine.queued_announce_count_for(&listener.id),
            ifac_netname: listener.ifac.as_ref().and_then(|ifac| ifac.netname.clone()),
            ifac_signature: listener.ifac.as_ref().map(|ifac| ifac.signature),
        };
        // As upstream, only the byte counts (and so the speeds) of the
        // clients add up on their listener; their other counters stay
        // theirs, and summing all interfaces' counters counts each once.
        for child in children {
            stat.rxb += child.stats.rxb;
            stat.traffic.rxs += child.stats.traffic_rates.rxs;
            if !accepted_tx_only || self.i2p_peer_accepted(&child.info.id) {
                stat.txb += child.stats.txb;
                stat.traffic.txs += child.stats.traffic_rates.txs;
            }
        }
        stat
    }

    pub(crate) fn handle_interface_stats_query(&self) -> QueryResponse {
        QueryResponse::InterfaceStats(self.interface_stats())
    }

    /// Upstream's `Transport.prioritize_interfaces`, run with its interface
    /// jobs every 5 seconds: a stable sort of the current order by bitrate,
    /// highest first.
    pub(crate) fn prioritize_interfaces(&mut self) {
        const INTERFACE_JOBS_INTERVAL: f64 = 5.0;
        let now = crate::time::now();
        if now < self.interface_priority_at + INTERFACE_JOBS_INTERVAL {
            return;
        }
        self.interface_priority_at = now;
        let mut order: Vec<(u64, u64)> = self
            .interface_stats()
            .interfaces
            .iter()
            .map(|i| (i.id, i.bitrate.unwrap_or(0)))
            .collect();
        order.sort_by_key(|(_, bitrate)| std::cmp::Reverse(*bitrate));
        self.interface_priority = order.into_iter().map(|(id, _)| id).collect();
    }

    pub(crate) fn interface_stats(&self) -> InterfaceStatsResponse {
        let now = time::now();
        let mut interfaces = Vec::new();
        let mut total_rxb: u64 = 0;
        let mut total_txb: u64 = 0;
        let mut total_rx_packets: u64 = 0;
        let mut total_tx_packets: u64 = 0;
        let mut total_announce_rx: u64 = 0;
        let mut total_announce_tx: u64 = 0;
        let mut total_path_request_rx: u64 = 0;
        let mut total_path_request_tx: u64 = 0;
        let mut rx_pps = 0.0;
        let mut tx_pps = 0.0;
        let mut total_traffic = TrafficDetail::default();
        for entry in self.interfaces.values() {
            let traffic = traffic_detail(&entry.stats);
            if !entry.info.is_local_client {
                total_rxb += entry.stats.rxb;
                total_txb += entry.stats.txb;
                total_rx_packets += entry.stats.rx_packets;
                total_tx_packets += entry.stats.tx_packets;
                total_announce_rx += entry.stats.arxc;
                total_announce_tx += entry.stats.atxc;
                total_path_request_rx += entry.stats.prxc;
                total_path_request_tx += entry.stats.ptxc;
                rx_pps += entry.stats.traffic_rates.rxpps;
                tx_pps += entry.stats.traffic_rates.txpps;
                add_traffic(&mut total_traffic, traffic);
            }
            if self.subinterface_without_device(entry) {
                continue;
            }
            let interface_id = entry.info.id;
            interfaces.push(SingleInterfaceStat {
                id: interface_id.0,
                name: self
                    .interface_short_names
                    .get(&interface_id)
                    .cloned()
                    .unwrap_or_else(|| entry.info.name.clone()),
                display_name: self.interface_display_name(entry),
                parent_display_name: self.parent_display_name(entry),
                tunnel_id: self
                    .engine
                    .interface_info(&interface_id)
                    .and_then(|info| info.tunnel_id)
                    // Upstream 3281e283: else the tunnel this node synthesized.
                    .or_else(|| self.engine.local_tunnel_id(&interface_id)),
                remote_transport_id: self.engine.remote_transport(&interface_id),
                remote_transport_info: (!crate::interface::shared_medium_hint(
                    &entry.interface_type,
                ))
                .then(|| self.engine.remote_transport_info(&interface_id).cloned())
                .flatten(),
                status: entry.online && entry.enabled,
                mode: entry.info.mode,
                gravity: entry.info.gravity,
                announces_to_internal: entry.info.announces_to_internal,
                rxb: entry.stats.rxb,
                txb: entry.stats.txb,
                tx_drops: entry
                    .async_writer_metrics
                    .as_ref()
                    .map(crate::interface::AsyncWriterMetrics::tx_drops)
                    .unwrap_or(0),
                tx_dropped_bytes: entry
                    .async_writer_metrics
                    .as_ref()
                    .map(crate::interface::AsyncWriterMetrics::tx_dropped_bytes)
                    .unwrap_or(0),
                tx_stalled: entry
                    .async_writer_metrics
                    .as_ref()
                    .is_some_and(crate::interface::AsyncWriterMetrics::tx_stalled),
                tx_buffered: entry
                    .async_writer_metrics
                    .as_ref()
                    .map(crate::interface::AsyncWriterMetrics::tx_buffered)
                    .unwrap_or(0),
                traffic,
                protocol_violations: entry.stats.protocol_violations,
                ifac_violations: entry.stats.ifac_violations,
                packet_filter_hits: entry.stats.packet_filter_hits,
                hop_limiter_hits: entry.stats.hop_limiter_hits,
                stamped_path_requests: entry.stats.stamped_path_requests,
                rx_packets: entry.stats.rx_packets,
                tx_packets: entry.stats.tx_packets,
                cpu_load: entry.stats.cpu_load,
                mem_load: entry.stats.mem_load,
                switch_id: entry.stats.switch_id,
                endpoint_id: entry.stats.endpoint_id,
                via_switch_id: entry.stats.via_switch_id,
                peers: entry.stats.peers,
                rssi: entry.stats.rssi,
                snr: entry.stats.snr,
                signal_quality: entry.stats.signal_quality,
                frequency: entry.stats.frequency,
                bandwidth: entry.stats.bandwidth,
                txpower: entry.stats.txpower,
                spreading_factor: entry.stats.spreading_factor,
                coding_rate: entry.stats.coding_rate,
                channel: entry.stats.channel,
                modulation: entry.stats.modulation.clone(),
                radio: entry.stats.radio,
                bitrate: entry.info.bitrate,
                bitrate_is_float: self.is_autoconnected(interface_id),
                mtu: Some(entry.info.mtu),
                ifac_size: entry.ifac.as_ref().map(|s| s.size),
                started: entry.stats.started,
                ia_freq: entry.stats.incoming_announce_freq(),
                oa_freq: entry.stats.outgoing_announce_freq(),
                ip_freq: entry.stats.incoming_path_request_freq(),
                op_freq: entry.stats.outgoing_path_request_freq(),
                op_samples: entry.stats.outgoing_path_request_samples(),
                burst_active: self.engine.burst_active(&interface_id),
                burst_activated: self.engine.burst_activated(&interface_id),
                pr_burst_active: self.engine.pr_burst_active(&interface_id),
                pr_burst_activated: self.engine.pr_burst_activated(&interface_id),
                clients: None,
                blocked_ips: None,
                blocked_ip_list: None,
                i2p: None,
                i2p_tunnel_state: self.i2p_tunnel_state(entry),
                autoconnect_source: self.autoconnect_source(interface_id),
                announce_rate_target: entry.info.announce_rate_target,
                announce_rate_grace: entry.info.announce_rate_grace,
                announce_rate_penalty: entry.info.announce_rate_penalty,
                interface_type: entry.interface_type.clone(),
                held_announces: self.engine.held_announce_count(&interface_id),
                announce_queue: self.engine.queued_announce_count_for(&interface_id),
                ifac_netname: entry.ifac.as_ref().and_then(|s| s.netname.clone()),
                ifac_signature: entry.ifac.as_ref().map(|s| s.signature),
            });
        }
        #[cfg(feature = "iface-backbone")]
        for handle in self.backbone_peer_state.values() {
            let clients = recover_mutex_guard(&handle.peer_state, "backbone peer state")
                .list(&handle.interface_name)
                .into_iter()
                .map(|entry| entry.connected_count as u64)
                .sum();
            let blocked_ip_list =
                recover_mutex_guard(&handle.fast_flap_state, "backbone fast-flap state")
                    .blocked_ip_list(&handle.fast_flap, std::time::Instant::now())
                    .into_iter()
                    .map(|peer_ip| peer_ip.to_string())
                    .collect::<Vec<_>>();
            let blocked_ips = blocked_ip_list.len() as u64;
            let mut traffic = TrafficDetail::default();
            let mut protocol_violations = 0;
            let mut ifac_violations = 0;
            let mut packet_filter_hits = 0;
            let mut hop_limiter_hits = 0;
            let mut stamped_path_requests = 0;
            let mut tx_drops = 0;
            let mut tx_dropped_bytes = 0;
            let mut tx_stalled = false;
            let mut tx_buffered = 0;
            for (child_id, parent_id) in &self.dynamic_interface_parents {
                if *parent_id == handle.interface_id {
                    if let Some(child) = self.interfaces.get(child_id) {
                        add_traffic(&mut traffic, traffic_detail(&child.stats));
                        protocol_violations += child.stats.protocol_violations;
                        ifac_violations += child.stats.ifac_violations;
                        packet_filter_hits += child.stats.packet_filter_hits;
                        hop_limiter_hits += child.stats.hop_limiter_hits;
                        stamped_path_requests += child.stats.stamped_path_requests;
                        if let Some(metrics) = &child.async_writer_metrics {
                            tx_drops += metrics.tx_drops();
                            tx_dropped_bytes += metrics.tx_dropped_bytes();
                            tx_stalled |= metrics.tx_stalled();
                            tx_buffered += metrics.tx_buffered();
                        }
                    }
                }
            }
            interfaces.push(SingleInterfaceStat {
                id: handle.interface_id.0,
                name: handle.interface_name.clone(),
                display_name: self
                    .interface_display_names
                    .get(&handle.interface_id)
                    .cloned()
                    .unwrap_or_else(|| {
                        crate::interface::display::typed(
                            "BackboneInterface",
                            &handle.interface_name,
                        )
                    }),
                parent_display_name: None,
                // A listener's tunnels belong to its spawned clients.
                tunnel_id: None,
                remote_transport_id: None,
                remote_transport_info: None,
                status: true,
                mode: handle.mode,
                gravity: handle.gravity,
                announces_to_internal: handle.announces_to_internal,
                rxb: 0,
                txb: 0,
                tx_drops,
                tx_dropped_bytes,
                tx_stalled,
                tx_buffered,
                traffic,
                protocol_violations,
                ifac_violations,
                packet_filter_hits,
                hop_limiter_hits,
                stamped_path_requests,
                rx_packets: 0,
                tx_packets: 0,
                cpu_load: None,
                mem_load: None,
                switch_id: None,
                endpoint_id: None,
                via_switch_id: None,
                peers: None,
                rssi: None,
                snr: None,
                signal_quality: None,
                frequency: None,
                bandwidth: None,
                txpower: None,
                spreading_factor: None,
                coding_rate: None,
                channel: None,
                modulation: None,
                radio: None,
                bitrate: Some(crate::interface::backbone::SERVER_BITRATE_GUESS),
                bitrate_is_float: false,
                mtu: Some(crate::interface::backbone::HW_MTU as u32),
                ifac_size: None,
                started: self.started,
                ia_freq: 0.0,
                oa_freq: 0.0,
                ip_freq: 0.0,
                op_freq: 0.0,
                op_samples: 0,
                burst_active: false,
                burst_activated: 0.0,
                pr_burst_active: false,
                pr_burst_activated: 0.0,
                clients: Some(clients),
                blocked_ips: Some(blocked_ips),
                blocked_ip_list: Some(blocked_ip_list),
                i2p: None,
                i2p_tunnel_state: None,
                autoconnect_source: None,
                announce_rate_target: None,
                announce_rate_grace: 0,
                announce_rate_penalty: 0.0,
                interface_type: "BackboneInterface".into(),
                held_announces: self.engine.held_announce_count(&handle.interface_id),
                announce_queue: self.engine.queued_announce_count_for(&handle.interface_id),
                ifac_netname: None,
                ifac_signature: None,
            });
        }
        for listener in &self.listener_stats {
            interfaces.push(self.listener_interface_stat(listener));
        }
        // In upstream's Transport.interfaces order: as last prioritized,
        // then the interfaces added since, in the order they were added
        // (ids are handed out in that order).
        interfaces.sort_by_key(|i| {
            (
                self.interface_priority
                    .iter()
                    .position(|id| *id == i.id)
                    .unwrap_or(usize::MAX),
                i.id,
            )
        });
        let (path_pool_total, path_pool_unused) = self.engine.path_pool_counts();
        let total_links = self.engine.link_table_count() + self.link_manager.link_count();
        let active_links = self.engine.active_link_count() + self.link_manager.active_link_count();
        InterfaceStatsResponse {
            interfaces,
            transport_id: self.engine.identity_hash().copied(),
            transport_enabled: self.engine.transport_enabled(),
            transport_uptime: now - self.started,
            total_rxb,
            total_txb,
            total_rx_packets,
            total_tx_packets,
            total_announce_rx,
            total_announce_tx,
            total_path_request_rx,
            total_path_request_tx,
            total_links,
            active_links,
            pending_links: total_links.saturating_sub(active_links),
            path_pool_total,
            path_pool_unused,
            path_pool_active: path_pool_total.saturating_sub(path_pool_unused),
            rx_pps,
            tx_pps,
            traffic: total_traffic,
            probe_responder: self.probe_responder_hash,
            network_id: self
                .network_identity
                .as_ref()
                .map(|identity| *identity.hash()),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: self.backbone_peer_pool_status(),
            #[cfg(not(feature = "iface-backbone"))]
            backbone_peer_pool: None,
        }
    }

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

    /// Replace the shared link and interface statistics snapshot that
    /// `RnsNode::state_snapshot` reads without a driver round trip.
    pub(crate) fn publish_state_snapshot(&mut self) {
        let links = self.link_info_entries();
        let interfaces = self.interface_stats();
        let sequence = self.state_snapshot_schedule.published(links.len());
        self.event_tx
            .state_snapshot()
            .store(crate::state_snapshot::StateSnapshot {
                sequence,
                published_at: time::now(),
                links,
                interfaces,
            });
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
                let known = self.known_destinations.get(hash);
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

    /// Handle a query request and produce a response.
    pub(crate) fn handle_query(&self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::ManageInterface { .. } => QueryResponse::InterfaceManagement(Some(false)),
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
                    .map(
                        |(destination_hash, total, active)| crate::event::LinkDistributionEntry {
                            destination_hash,
                            total,
                            active,
                        },
                    )
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
                let mut interfaces = self.discovered_interfaces.list().unwrap_or_default();
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

    /// Handle a mutating query request.
    pub(crate) fn handle_query_mut(&mut self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::RecordKnownDestinationFlush {
                stored,
                removed,
                seed,
            } => {
                if seed {
                    self.known_destinations_flushed.clear();
                }
                self.known_destinations_flushed.extend(stored);
                for dest_hash in removed {
                    self.known_destinations_flushed.remove(&dest_hash);
                }
                QueryResponse::KnownDestinationFlushRecorded
            }
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
                self.engine.destination_filter_mut().unwant_all(&requester);
                log::debug!(
                    "Deregistered all destination requirements for <{}>",
                    hex_bytes(&requester)
                );
                QueryResponse::DestinationTypeRegistration(true)
            }
            QueryRequest::SetRequiredDestinationsOnly { enabled } => {
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
                QueryResponse::RecallDestinationStamp(self.known_destinations.get(&dest_hash).map(
                    |state| crate::event::DestinationStampInfo {
                        stamp_value: state.stamp_value,
                        lr_cost: state.lr_cost,
                    },
                ))
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
                                        QueryResponse::SendProbe(Err(SendProbeError::PackFailed))
                                    }
                                }
                            }
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
                    "global.stamp_destinations" => match Self::expect_bool(value, &key) {
                        Ok(value) => {
                            self.stamp_destinations.store(value, Ordering::Relaxed);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.stamp_path_requests" => match Self::expect_bool(value, &key) {
                        Ok(value) => {
                            self.engine.set_stamp_prs(value);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.stamps_enforced" => match Self::expect_bool(value, &key) {
                        Ok(value) => {
                            self.set_stamps_enforced(value);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.lr_stamps_enforced" => match Self::expect_bool(value, &key) {
                        Ok(value) => {
                            self.link_manager.link_request_costs().set_enforced(value);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.stamp_link_requests" => match Self::expect_bool(value, &key) {
                        Ok(value) => {
                            self.stamp_settings.stamp_lrs = value;
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.always_stamp_link_requests" => match Self::expect_bool(value, &key) {
                        Ok(value) => {
                            self.stamp_settings.always_stamp_lrs = value;
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.direct_connect_policy" => {
                        let policy = match Self::parse_holepunch_policy(&value) {
                            Some(policy) => policy,
                            None => {
                                return QueryResponse::RuntimeConfigSet(Err(RuntimeConfigError {
                                    code: RuntimeConfigErrorCode::InvalidValue,
                                    message: format!(
                                        "{} must be one of: reject, accept_all, identified_only, ask_app",
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
                    "global.stamp_destinations" => {
                        self.stamp_destinations
                            .store(defaults.stamp_destinations, Ordering::Relaxed);
                        Ok(())
                    }
                    "global.stamp_path_requests" => {
                        self.engine.set_stamp_prs(defaults.stamp_path_requests);
                        Ok(())
                    }
                    "global.stamps_enforced" => {
                        self.set_stamps_enforced(defaults.stamps_enforced);
                        Ok(())
                    }
                    "global.lr_stamps_enforced" => {
                        self.link_manager
                            .link_request_costs()
                            .set_enforced(defaults.lr_stamps_enforced);
                        Ok(())
                    }
                    "global.stamp_link_requests" => {
                        self.stamp_settings.stamp_lrs = defaults.stamp_link_requests;
                        Ok(())
                    }
                    "global.always_stamp_link_requests" => {
                        self.stamp_settings.always_stamp_lrs = defaults.always_stamp_link_requests;
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
