//! Listeners and the interfaces they serve.

use super::*;

impl Driver {
    #[cfg(feature = "iface-local")]
    pub(super) fn shared_instance_listener(&self) -> Option<&ListenerStat> {
        self.registry
            .listener_stats
            .iter()
            .find(|listener| matches!(listener.clients, ListenerClients::Local(_)))
    }

    #[cfg(not(feature = "iface-local"))]
    pub(super) fn shared_instance_listener(&self) -> Option<&ListenerStat> {
        None
    }

    /// Whether `entry` is one of the interfaces `listener` serves.
    pub(super) fn listener_serves(&self, listener: &ListenerStat, entry: &InterfaceEntry) -> bool {
        match &listener.clients {
            #[cfg(feature = "iface-local")]
            ListenerClients::Local(_) => entry.info.is_local_client && entry.dynamic,
            ListenerClients::Subinterfaces(ids) => ids.contains(&entry.info.id),
            // The others are registered as their interfaces' parent.
            #[cfg(any(feature = "iface-tcp", feature = "iface-auto", feature = "iface-i2p"))]
            _ => self.registry.dynamic_parents.get(&entry.info.id) == Some(&listener.id),
        }
    }

    /// Whether an I2P peer connected to this node (upstream's `Connected
    /// peer on {interface}`), rather than this node to it.
    pub(super) fn i2p_peer_accepted(&self, id: &InterfaceId) -> bool {
        self.registry
            .short_names
            .get(id)
            .is_some_and(|name| name.starts_with("Connected peer on "))
    }

    /// The tunnel state an I2P peer reports (upstream's `tunnelstate`);
    /// `None` for any other interface.
    #[cfg(feature = "iface-i2p")]
    pub(super) fn i2p_tunnel_state(&self, entry: &InterfaceEntry) -> Option<Option<String>> {
        let parent = self.registry.dynamic_parents.get(&entry.info.id)?;
        self.registry
            .listener_stats
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
    pub(super) fn i2p_tunnel_state(&self, _entry: &InterfaceEntry) -> Option<Option<String>> {
        None
    }

    /// The statistics of a listener without an interface entry of its own:
    /// upstream counts its clients and adds up their bytes.
    pub(super) fn listener_interface_stat(&self, listener: &ListenerStat) -> SingleInterfaceStat {
        let children: Vec<&InterfaceEntry> = self
            .interfaces
            .values()
            .filter(|entry| self.listener_serves(listener, entry))
            .collect();
        let (status, clients, peers, i2p, accepted_tx_only) = match &listener.clients {
            #[cfg(feature = "iface-tcp")]
            ListenerClients::Spawned => (true, Some(children.len() as u64), None, None, false),
            #[cfg(feature = "iface-local")]
            ListenerClients::Local(_) => (true, Some(children.len() as u64), None, None, false),
            #[cfg(feature = "iface-auto")]
            ListenerClients::AutoPeers => (true, None, Some(children.len()), None, false),
            #[cfg(feature = "iface-i2p")]
            ListenerClients::I2pPeers(i2p_listener) => {
                let (online, b32) = {
                    let endpoint =
                        crate::interface::lock_or_recover(&i2p_listener.endpoint, "i2p endpoint");
                    (endpoint.online, endpoint.b32.clone())
                };
                let accepted = children
                    .iter()
                    .filter(|child| self.i2p_peer_accepted(&child.info.id))
                    .count() as u64;
                let i2p = crate::event::I2pEndpointStat {
                    connectable: i2p_listener.connectable,
                    b32,
                };
                // Only accepted peers' transmitted bytes add up on it.
                (
                    online,
                    Some(accepted),
                    i2p_listener.configured_peers,
                    Some(i2p),
                    true,
                )
            }
            ListenerClients::Subinterfaces(_) => {
                // Online while its device is. As upstream, its
                // subinterfaces exist only while the device is configured.
                let status = children.iter().any(|child| child.online);
                let clients = children.iter().filter(|child| child.online).count() as u64;
                (status, Some(clients), None, None, false)
            }
        };
        #[cfg(feature = "iface-local")]
        let bitrate = match listener.clients {
            ListenerClients::Local(_) => self.forced_local_bitrate.or(listener.bitrate),
            _ => listener.bitrate,
        };
        #[cfg(not(feature = "iface-local"))]
        let bitrate = listener.bitrate;
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
            bitrate,
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
}
