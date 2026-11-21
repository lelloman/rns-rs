//! How a started interface is named in status output and registered with
//! the driver.

use super::*;

/// Upstream's display names of a configured interface, read from its
/// config before the factory consumes it.
#[derive(Default)]
pub(crate) struct ConfiguredDisplay {
    /// The display name of the interface a `Simple` start registers.
    pub(crate) interface: Option<String>,
    /// A listener without an interface entry of its own: its id and
    /// display name.
    pub(crate) listener: Option<(rns_core::transport::types::InterfaceId, String)>,
    /// The statistics entry of a listener: a TCP server, an interface
    /// spawning peers, or an `RNodeMultiInterface`, whose subinterfaces
    /// fill it in once started.
    pub(crate) listener_stat: Option<crate::driver::ListenerStat>,
}

impl ConfiguredDisplay {
    pub(crate) fn of(config: &InterfaceConfig, ifac: Option<&ifac::IfacState>) -> Self {
        #[cfg(any(
            feature = "iface-tcp",
            feature = "iface-auto",
            feature = "iface-rnode",
            feature = "iface-i2p"
        ))]
        use crate::interface::InterfaceKind;
        #[cfg(any(
            feature = "iface-tcp",
            feature = "iface-udp",
            feature = "iface-local",
            feature = "iface-auto",
            feature = "iface-rnode",
            feature = "iface-backbone",
            feature = "iface-i2p"
        ))]
        use crate::interface::{display, KnownConfig};
        let known = config.config_data.known();
        let name = config.name.as_str();
        // Unused when no interface feature that reads them is enabled.
        let _ = (known, name, ifac);
        #[cfg(feature = "iface-tcp")]
        if let KnownConfig::TcpClient(tcp) = known {
            return Self {
                interface: Some(display::tcp_client(name, &tcp.target_host, tcp.target_port)),
                ..Self::default()
            };
        }
        #[cfg(feature = "iface-tcp")]
        if let KnownConfig::TcpServer(tcp) = known {
            let display_name = display::tcp_server(name, &tcp.listen_ip, tcp.listen_port);
            return Self {
                listener: Some((tcp.interface_id, display_name.clone())),
                listener_stat: Some(crate::driver::ListenerStat {
                    id: tcp.interface_id,
                    name: config.name.clone(),
                    display_name,
                    interface_type: InterfaceKind::TcpServer.type_name().into(),
                    mode: config.mode,
                    gravity: config.gravity,
                    announces_to_internal: config.announces_to_internal,
                    bitrate: Some(crate::interface::tcp_bitrate(tcp.bitrate)),
                    // The MTU its clients get.
                    mtu: crate::interface::tcp_hardware_mtu(tcp.bitrate, tcp.fixed_mtu),
                    ifac: ifac.cloned(),
                    clients: crate::driver::ListenerClients::Spawned,
                }),
                ..Self::default()
            };
        }
        #[cfg(feature = "iface-auto")]
        if let KnownConfig::Auto(auto) = known {
            return Self {
                listener_stat: Some(crate::driver::ListenerStat {
                    id: auto.interface_id,
                    name: config.name.clone(),
                    display_name: display::typed(InterfaceKind::Auto.type_name(), name),
                    interface_type: InterfaceKind::Auto.type_name().into(),
                    mode: config.mode,
                    gravity: config.gravity,
                    announces_to_internal: config.announces_to_internal,
                    bitrate: Some(auto.configured_bitrate),
                    mtu: crate::interface::auto::HW_MTU as u32,
                    ifac: ifac.cloned(),
                    clients: crate::driver::ListenerClients::AutoPeers,
                }),
                ..Self::default()
            };
        }
        #[cfg(feature = "iface-i2p")]
        if let KnownConfig::I2p(i2p) = known {
            return Self {
                listener_stat: Some(crate::driver::ListenerStat {
                    id: i2p.interface_id,
                    name: config.name.clone(),
                    display_name: display::typed(InterfaceKind::I2p.type_name(), name),
                    interface_type: InterfaceKind::I2p.type_name().into(),
                    mode: config.mode,
                    gravity: config.gravity,
                    announces_to_internal: config.announces_to_internal,
                    bitrate: Some(crate::interface::i2p::BITRATE_GUESS),
                    mtu: crate::interface::i2p::HW_MTU as u32,
                    ifac: ifac.cloned(),
                    clients: crate::driver::ListenerClients::I2pPeers(crate::driver::I2pListener {
                        connectable: i2p.connectable,
                        configured_peers: (!i2p.peers.is_empty()).then_some(i2p.peers.len()),
                        endpoint: std::sync::Arc::clone(&i2p.endpoint),
                    }),
                }),
                ..Self::default()
            };
        }
        #[cfg(feature = "iface-rnode")]
        if let KnownConfig::RNode(rnode) = known {
            if rnode.multi {
                return Self {
                    listener_stat: Some(crate::driver::ListenerStat {
                        // Its subinterfaces take the ids after its own.
                        id: rnode.interface_id,
                        name: config.name.clone(),
                        display_name: display::typed(InterfaceKind::RNodeMulti.type_name(), name),
                        interface_type: InterfaceKind::RNodeMulti.type_name().into(),
                        mode: config.mode,
                        gravity: config.gravity,
                        announces_to_internal: config.announces_to_internal,
                        // Upstream's RNodeMultiInterface keeps a bitrate of 0.
                        bitrate: Some(0),
                        mtu: crate::interface::rnode::HW_MTU,
                        ifac: ifac.cloned(),
                        clients: crate::driver::ListenerClients::Subinterfaces(Vec::new()),
                    }),
                    ..Self::default()
                };
            }
        }
        #[cfg(feature = "iface-udp")]
        if let KnownConfig::Udp(udp) = known {
            return Self {
                interface: Some(display::udp(
                    name,
                    udp.listen_ip.as_deref(),
                    udp.listen_port,
                )),
                ..Self::default()
            };
        }
        #[cfg(feature = "iface-backbone")]
        if let KnownConfig::Backbone(mode) = known {
            return match mode {
                BackboneMode::Server(server) => Self {
                    listener: Some((
                        server.interface_id,
                        display::backbone(name, &server.listen_ip, server.listen_port),
                    )),
                    ..Self::default()
                },
                BackboneMode::Client(client, _) => Self {
                    interface: Some(display::backbone(
                        name,
                        &client.target_host,
                        client.target_port,
                    )),
                    ..Self::default()
                },
            };
        }
        #[cfg(feature = "iface-local")]
        if let KnownConfig::LocalClient(local) = known {
            let endpoint = display::LocalEndpoint::for_client(
                local.use_af_unix,
                &local.instance_name,
                local.port,
            );
            return Self {
                interface: Some(display::local_client(&endpoint)),
                ..Self::default()
            };
        }
        Self::default()
    }

    /// Register an interface whose subinterfaces `ids` started as a
    /// listener serving them.
    pub(crate) fn register_subinterfaces(
        &mut self,
        driver: &mut Driver,
        ids: Vec<rns_core::transport::types::InterfaceId>,
    ) {
        if let Some(listener) = self.listener_stat.as_mut() {
            listener.clients = crate::driver::ListenerClients::Subinterfaces(ids);
        }
        self.register_listener(driver);
    }

    /// Register the display names of a listener that started.
    pub(crate) fn register_listener(&mut self, driver: &mut Driver) {
        if let Some((id, display_name)) = self.listener.take() {
            driver.registry.display_names.insert(id, display_name);
        }
        if let Some(listener) = self.listener_stat.take() {
            driver
                .registry
                .listener_stats
                .retain(|candidate| candidate.id != listener.id);
            driver.registry.listener_stats.push(listener);
        }
    }
}

/// The display name of a subinterface a `Multi` start registers.
pub(crate) fn subinterface_display_name(
    config_name: &str,
    sub: &crate::interface::SubInterface,
) -> Option<String> {
    (sub.interface_type_name == crate::interface::InterfaceKind::RNodeMulti.type_name())
        .then(|| crate::interface::display::rnode_multi_sub(config_name, &sub.info.name))
}

pub(crate) struct StartedInterface<'a> {
    pub(crate) driver: &'a mut Driver,
    pub(crate) tx: &'a EventSender,
    pub(crate) queue_capacity: usize,
    pub(crate) id: rns_core::transport::types::InterfaceId,
    pub(crate) info: rns_core::transport::types::InterfaceInfo,
    pub(crate) writer: Box<dyn crate::interface::Writer>,
    pub(crate) interface_type_name: String,
    pub(crate) ifac_state: Option<crate::ifac::IfacState>,
    pub(crate) ifac_runtime: &'a crate::driver::IfacRuntimeConfig,
    pub(crate) stamp_costs: rns_core::transport::types::InterfaceStampCosts,
    /// The interface's own `hop_limiter` (upstream bb63dd44).
    pub(crate) hop_limiter: Option<u8>,
    /// Upstream's display name, when it shows more than `{type}[{name}]`.
    pub(crate) display_name: Option<String>,
}

pub(crate) fn register_started_interface(params: StartedInterface<'_>) {
    let StartedInterface {
        driver,
        tx,
        queue_capacity,
        id,
        mut info,
        writer,
        interface_type_name,
        ifac_state,
        ifac_runtime,
        stamp_costs,
        hop_limiter,
        display_name,
    } = params;
    match display_name {
        Some(display_name) => {
            driver.registry.display_names.insert(id, display_name);
        }
        None => {
            driver.registry.display_names.remove(&id);
        }
    }
    info.stamp_costs = stamp_costs;
    info.hop_limiter = hop_limiter;
    driver.apply_interface_defaults(&mut info);
    let (writer, async_writer_metrics) =
        crate::interface::wrap_async_writer(writer, id, &info.name, tx.clone(), queue_capacity);
    driver
        .runtime_config
        .register_interface_runtime_defaults(&info);
    driver
        .runtime_config
        .register_interface_ifac_runtime(&info.name, ifac_runtime.clone());
    driver.engine.register_interface(info.clone());
    driver.interfaces.insert(
        id,
        InterfaceEntry {
            id,
            info,
            writer,
            async_writer_metrics: Some(async_writer_metrics),
            enabled: true,
            online: false,
            dynamic: false,
            ifac: ifac_state,
            stats: InterfaceStats {
                started: time::now(),
                ..Default::default()
            },
            interface_type: interface_type_name,
            send_retry_at: None,
            send_retry_backoff: Duration::ZERO,
        },
    );
}
