//! Interface statistics.

use super::*;

pub(super) fn traffic_detail(stats: &crate::interface::InterfaceStats, now: f64) -> TrafficDetail {
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
        arxf: stats.incoming_announce_freq(now),
        atxf: stats.outgoing_announce_freq(now),
        prxf: stats.incoming_path_request_freq(now),
        ptxf: stats.outgoing_path_request_freq(now),
    }
}

pub(super) fn add_traffic(total: &mut TrafficDetail, detail: TrafficDetail) {
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

impl Driver {
    pub(crate) fn handle_interface_stats_query(&self) -> QueryResponse {
        QueryResponse::InterfaceStats(self.interface_stats())
    }

    /// Upstream's `Transport.prioritize_interfaces`, run with its interface
    /// jobs every 5 seconds: a stable sort of the current order by bitrate,
    /// highest first.
    pub(crate) fn prioritize_interfaces(&mut self) {
        const INTERFACE_JOBS_INTERVAL: f64 = 5.0;
        let now = crate::time::now();
        if now < self.registry.priority_at + INTERFACE_JOBS_INTERVAL {
            return;
        }
        self.registry.priority_at = now;
        let mut order: Vec<(u64, u64)> = self
            .interface_stats()
            .interfaces
            .iter()
            .map(|i| (i.id, i.bitrate.unwrap_or(0)))
            .collect();
        order.sort_by_key(|(_, bitrate)| std::cmp::Reverse(*bitrate));
        self.registry.priority = order.into_iter().map(|(id, _)| id).collect();
    }

    /// Every interface's statistics and the node's totals, as upstream's
    /// `interface_stats` reports them.
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
            let traffic = traffic_detail(&entry.stats, now);
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
            if self.registry.subinterface_without_device(entry) {
                continue;
            }
            interfaces.push(self.single_interface_stat(entry, traffic, now));
        }
        #[cfg(feature = "iface-backbone")]
        for handle in self.runtime_config.backbone_peer_state.values() {
            interfaces.push(self.backbone_listener_stat(handle, now));
        }
        for listener in &self.registry.listener_stats {
            interfaces.push(self.listener_interface_stat(listener));
        }
        // In upstream's Transport.interfaces order: as last prioritized,
        // then the interfaces added since, in the order they were added
        // (ids are handed out in that order).
        interfaces.sort_by_key(|i| {
            (
                self.registry
                    .priority
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
            link_traffic: {
                let (rxb, txb) = self.link_traffic();
                crate::event::LinkTraffic {
                    rxb,
                    txb,
                    speeds: self.registry.link_traffic.speeds,
                }
            },
            probe_responder: self.builtin.probe_responder,
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

    /// The statistics of one interface the driver runs.
    fn single_interface_stat(
        &self,
        entry: &InterfaceEntry,
        traffic: TrafficDetail,
        now: f64,
    ) -> SingleInterfaceStat {
        let interface_id = entry.info.id;
        SingleInterfaceStat {
            id: interface_id.0,
            name: self
                .registry
                .short_names
                .get(&interface_id)
                .cloned()
                .unwrap_or_else(|| entry.info.name.clone()),
            display_name: self.registry.interface_display_name(entry),
            parent_display_name: self.registry.parent_display_name(&self.interfaces, entry),
            tunnel_id: self
                .engine
                .interface_info(&interface_id)
                .and_then(|info| info.tunnel_id)
                // Upstream 3281e283: else the tunnel this node synthesized.
                .or_else(|| self.engine.local_tunnel_id(&interface_id)),
            remote_transport_id: self.engine.remote_transport(&interface_id),
            remote_transport_info: (!crate::interface::shared_medium_hint(&entry.interface_type))
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
            ia_freq: entry.stats.incoming_announce_freq(now),
            oa_freq: entry.stats.outgoing_announce_freq(now),
            ip_freq: entry.stats.incoming_path_request_freq(now),
            op_freq: entry.stats.outgoing_path_request_freq(now),
            op_samples: entry.stats.outgoing_path_request_samples(),
            burst_active: self.engine.burst_active(&interface_id),
            burst_activated: self.engine.burst_activated(&interface_id),
            pr_burst_active: self.engine.pr_burst_active(&interface_id),
            pr_burst_activated: self.engine.pr_burst_activated(&interface_id),
            clients: None,
            blocked_ips: None,
            blocked_ip_list: None,
            i2p: None,
            i2p_tunnel_state: self.registry.i2p_tunnel_state(entry),
            autoconnect_source: self.autoconnect_source(interface_id),
            announce_rate_target: entry.info.announce_rate_target,
            announce_rate_grace: entry.info.announce_rate_grace,
            announce_rate_penalty: entry.info.announce_rate_penalty,
            interface_type: entry.interface_type.clone(),
            held_announces: self.engine.held_announce_count(&interface_id),
            announce_queue: self.engine.queued_announce_count_for(&interface_id),
            ifac_netname: entry.ifac.as_ref().and_then(|s| s.netname.clone()),
            ifac_signature: entry.ifac.as_ref().map(|s| s.signature),
        }
    }

    /// The statistics of a Backbone listener: its spawned clients' traffic,
    /// counters and transmit queues summed, with its peer and blocked
    /// address counts.
    #[cfg(feature = "iface-backbone")]
    fn backbone_listener_stat(
        &self,
        handle: &BackbonePeerStateHandle,
        now: f64,
    ) -> SingleInterfaceStat {
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
        let BackboneChildTotals {
            traffic,
            protocol_violations,
            ifac_violations,
            packet_filter_hits,
            hop_limiter_hits,
            stamped_path_requests,
            tx_drops,
            tx_dropped_bytes,
            tx_stalled,
            tx_buffered,
        } = self.backbone_child_totals(handle.interface_id, now);
        SingleInterfaceStat {
            id: handle.interface_id.0,
            name: handle.interface_name.clone(),
            display_name: self
                .registry
                .display_names
                .get(&handle.interface_id)
                .cloned()
                .unwrap_or_else(|| {
                    crate::interface::display::typed("BackboneInterface", &handle.interface_name)
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
        }
    }

    /// The summed statistics of the interfaces spawned by listener `parent`.
    #[cfg(feature = "iface-backbone")]
    fn backbone_child_totals(&self, parent: InterfaceId, now: f64) -> BackboneChildTotals {
        let mut totals = BackboneChildTotals::default();
        for (child_id, parent_id) in &self.registry.dynamic_parents {
            if *parent_id == parent {
                if let Some(child) = self.interfaces.get(child_id) {
                    add_traffic(&mut totals.traffic, traffic_detail(&child.stats, now));
                    totals.protocol_violations += child.stats.protocol_violations;
                    totals.ifac_violations += child.stats.ifac_violations;
                    totals.packet_filter_hits += child.stats.packet_filter_hits;
                    totals.hop_limiter_hits += child.stats.hop_limiter_hits;
                    totals.stamped_path_requests += child.stats.stamped_path_requests;
                    if let Some(metrics) = &child.async_writer_metrics {
                        totals.tx_drops += metrics.tx_drops();
                        totals.tx_dropped_bytes += metrics.tx_dropped_bytes();
                        totals.tx_stalled |= metrics.tx_stalled();
                        totals.tx_buffered += metrics.tx_buffered();
                    }
                }
            }
        }
        totals
    }
}

/// What a Backbone listener reports for its spawned clients together.
#[cfg(feature = "iface-backbone")]
#[derive(Default)]
struct BackboneChildTotals {
    traffic: TrafficDetail,
    protocol_violations: u64,
    ifac_violations: u64,
    packet_filter_hits: u64,
    hop_limiter_hits: u64,
    stamped_path_requests: u64,
    tx_drops: u64,
    tx_dropped_bytes: u64,
    tx_stalled: bool,
    tx_buffered: usize,
}
