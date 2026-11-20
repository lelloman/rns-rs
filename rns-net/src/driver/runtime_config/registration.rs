//! Registering an interface's runtime settings as it starts.

use super::*;

impl Driver {
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_runtime(&mut self, handle: BackboneRuntimeConfigHandle) {
        self.runtime_config
            .backbone
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_peer_state(&mut self, handle: BackbonePeerStateHandle) {
        self.runtime_config
            .backbone_peer_state
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_client_runtime(
        &mut self,
        handle: BackboneClientRuntimeConfigHandle,
    ) {
        self.runtime_config
            .backbone_client
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_discovery_runtime(
        &mut self,
        handle: BackboneDiscoveryRuntimeHandle,
    ) {
        self.runtime_config
            .backbone_discovery
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_runtime(&mut self, handle: TcpServerRuntimeConfigHandle) {
        self.runtime_config
            .tcp_server
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_client_runtime(&mut self, handle: TcpClientRuntimeConfigHandle) {
        self.runtime_config
            .tcp_client
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_discovery_runtime(
        &mut self,
        handle: TcpServerDiscoveryRuntimeHandle,
    ) {
        self.runtime_config
            .tcp_server_discovery
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn register_udp_runtime(&mut self, handle: UdpRuntimeConfigHandle) {
        self.runtime_config
            .udp
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn register_auto_runtime(&mut self, handle: AutoRuntimeConfigHandle) {
        self.runtime_config
            .auto
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn register_i2p_runtime(&mut self, handle: I2pRuntimeConfigHandle) {
        self.runtime_config
            .i2p
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn register_pipe_runtime(&mut self, handle: PipeRuntimeConfigHandle) {
        self.runtime_config
            .pipe
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn register_rnode_runtime(&mut self, handle: RNodeRuntimeConfigHandle) {
        self.runtime_config
            .rnode
            .insert(handle.interface_name.clone(), handle);
    }

    pub(crate) fn register_interface_runtime_defaults(
        &mut self,
        info: &rns_core::transport::types::InterfaceInfo,
    ) {
        self.runtime_config
            .interface_defaults
            .entry(info.name.clone())
            .or_insert_with(|| info.clone());
    }

    pub(crate) fn register_interface_ifac_runtime(
        &mut self,
        interface_name: &str,
        startup: IfacRuntimeConfig,
    ) {
        self.runtime_config
            .ifac_defaults
            .entry(interface_name.to_string())
            .or_insert_with(|| startup.clone());
        self.runtime_config
            .ifac
            .entry(interface_name.to_string())
            .or_insert(startup);
    }
}
