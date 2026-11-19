//! Registering an interface's runtime settings as it starts.

use super::*;

impl Driver {
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_runtime(&mut self, handle: BackboneRuntimeConfigHandle) {
        self.backbone_runtime
            .insert(handle.interface_name.clone(), handle);
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
        self.backbone_client_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_discovery_runtime(
        &mut self,
        handle: BackboneDiscoveryRuntimeHandle,
    ) {
        self.backbone_discovery_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_runtime(&mut self, handle: TcpServerRuntimeConfigHandle) {
        self.tcp_server_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_client_runtime(&mut self, handle: TcpClientRuntimeConfigHandle) {
        self.tcp_client_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_discovery_runtime(
        &mut self,
        handle: TcpServerDiscoveryRuntimeHandle,
    ) {
        self.tcp_server_discovery_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn register_udp_runtime(&mut self, handle: UdpRuntimeConfigHandle) {
        self.udp_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn register_auto_runtime(&mut self, handle: AutoRuntimeConfigHandle) {
        self.auto_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn register_i2p_runtime(&mut self, handle: I2pRuntimeConfigHandle) {
        self.i2p_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn register_pipe_runtime(&mut self, handle: PipeRuntimeConfigHandle) {
        self.pipe_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn register_rnode_runtime(&mut self, handle: RNodeRuntimeConfigHandle) {
        self.rnode_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    pub(crate) fn register_interface_runtime_defaults(
        &mut self,
        info: &rns_core::transport::types::InterfaceInfo,
    ) {
        self.interface_runtime_defaults
            .entry(info.name.clone())
            .or_insert_with(|| info.clone());
    }

    pub(crate) fn register_interface_ifac_runtime(
        &mut self,
        interface_name: &str,
        startup: IfacRuntimeConfig,
    ) {
        self.interface_ifac_runtime_defaults
            .entry(interface_name.to_string())
            .or_insert_with(|| startup.clone());
        self.interface_ifac_runtime
            .entry(interface_name.to_string())
            .or_insert(startup);
    }
}
