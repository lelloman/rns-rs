//! Registering an interface's runtime settings as it starts.

use super::*;

impl RuntimeConfigHandles {
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_runtime(&mut self, handle: BackboneRuntimeConfigHandle) {
        self.backbone.insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_peer_state(&mut self, handle: BackbonePeerStateHandle) {
        self.backbone_peer_state
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_client_runtime(
        &mut self,
        handle: BackboneClientRuntimeConfigHandle,
    ) {
        self.backbone_client
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_discovery_runtime(
        &mut self,
        handle: BackboneDiscoveryRuntimeHandle,
    ) {
        self.backbone_discovery
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_runtime(&mut self, handle: TcpServerRuntimeConfigHandle) {
        self.tcp_server
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_client_runtime(&mut self, handle: TcpClientRuntimeConfigHandle) {
        self.tcp_client
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_discovery_runtime(
        &mut self,
        handle: TcpServerDiscoveryRuntimeHandle,
    ) {
        self.tcp_server_discovery
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn register_udp_runtime(&mut self, handle: UdpRuntimeConfigHandle) {
        self.udp.insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn register_auto_runtime(&mut self, handle: AutoRuntimeConfigHandle) {
        self.auto.insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn register_i2p_runtime(&mut self, handle: I2pRuntimeConfigHandle) {
        self.i2p.insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn register_pipe_runtime(&mut self, handle: PipeRuntimeConfigHandle) {
        self.pipe.insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn register_rnode_runtime(&mut self, handle: RNodeRuntimeConfigHandle) {
        self.rnode.insert(handle.interface_name.clone(), handle);
    }

    pub(crate) fn register_interface_runtime_defaults(
        &mut self,
        info: &rns_core::transport::types::InterfaceInfo,
    ) {
        self.interface_defaults
            .entry(info.name.clone())
            .or_insert_with(|| info.clone());
    }

    pub(crate) fn register_interface_ifac_runtime(
        &mut self,
        interface_name: &str,
        startup: IfacRuntimeConfig,
    ) {
        self.ifac_defaults
            .entry(interface_name.to_string())
            .or_insert_with(|| startup.clone());
        self.ifac
            .entry(interface_name.to_string())
            .or_insert(startup);
    }

    /// Register the runtime settings of a configured interface, for the
    /// interface types that have them.
    #[cfg(runtime_config_ifaces)]
    pub(crate) fn register_configured(
        &mut self,
        config: &crate::node::InterfaceConfig,
        #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))] transport_enabled: bool,
    ) {
        use crate::interface::KnownConfig;

        match config.config_data.known() {
            #[cfg(feature = "iface-backbone")]
            KnownConfig::Backbone(mode) => {
                use crate::interface::backbone::{
                    client_runtime_handle_from_mode, peer_state_handle_from_mode,
                    runtime_handle_from_mode,
                };
                if let Some(handle) = runtime_handle_from_mode(mode) {
                    self.register_backbone_runtime(handle);
                }
                if let Some(handle) = peer_state_handle_from_mode(mode, config) {
                    self.register_backbone_peer_state(handle);
                }
                if let Some(handle) = client_runtime_handle_from_mode(mode) {
                    self.register_backbone_client_runtime(handle);
                }
                if let Some(handle) = crate::node::backbone_discovery_runtime_from_interface(
                    &config.name,
                    mode,
                    config.discovery.as_ref(),
                    transport_enabled,
                    config.ifac.as_ref(),
                ) {
                    self.register_backbone_discovery_runtime(handle);
                }
            }
            #[cfg(feature = "iface-tcp")]
            KnownConfig::TcpClient(value) => {
                self.register_tcp_client_runtime(
                    crate::interface::tcp::tcp_client_runtime_handle_from_config(value),
                );
            }
            #[cfg(feature = "iface-tcp")]
            KnownConfig::TcpServer(value) => {
                self.register_tcp_server_runtime(
                    crate::interface::tcp_server::runtime_handle_from_config(value),
                );
                self.register_tcp_server_discovery_runtime(
                    crate::node::tcp_server_discovery_runtime_from_interface(
                        &config.name,
                        value,
                        config.discovery.as_ref(),
                        transport_enabled,
                        config.ifac.as_ref(),
                    ),
                );
            }
            #[cfg(feature = "iface-udp")]
            KnownConfig::Udp(value) => {
                self.register_udp_runtime(crate::interface::udp::udp_runtime_handle_from_config(
                    value,
                ));
            }
            #[cfg(feature = "iface-auto")]
            KnownConfig::Auto(value) => {
                self.register_auto_runtime(
                    crate::interface::auto::auto_runtime_handle_from_config(value),
                );
            }
            #[cfg(feature = "iface-i2p")]
            KnownConfig::I2p(value) => {
                self.register_i2p_runtime(crate::interface::i2p::i2p_runtime_handle_from_config(
                    value,
                ));
            }
            #[cfg(feature = "iface-pipe")]
            KnownConfig::Pipe(value) => {
                self.register_pipe_runtime(
                    crate::interface::pipe::pipe_runtime_handle_from_config(value),
                );
            }
            #[cfg(feature = "iface-rnode")]
            KnownConfig::RNode(value) => {
                self.register_rnode_runtime(
                    crate::interface::rnode::rnode_runtime_handle_from_config(value),
                );
            }
            _ => {}
        }
    }
}
