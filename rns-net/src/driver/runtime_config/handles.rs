//! The handles through which runtime config reads and changes running
//! interfaces, and the startup values it resets to.

use super::*;

/// Runtime-config handles of the running interfaces, keyed by config name,
/// with the startup values runtime config resets to.
pub(crate) struct RuntimeConfigHandles {
    /// Runtime-config handles for backbone server interfaces.
    #[cfg(feature = "iface-backbone")]
    pub(crate) backbone: HashMap<String, BackboneRuntimeConfigHandle>,
    /// Live peer-state handles for backbone server interfaces.
    #[cfg(feature = "iface-backbone")]
    pub(crate) backbone_peer_state: HashMap<String, BackbonePeerStateHandle>,
    /// Runtime-config handles for backbone client interfaces.
    #[cfg(feature = "iface-backbone")]
    pub(crate) backbone_client: HashMap<String, BackboneClientRuntimeConfigHandle>,
    /// Runtime-config state for backbone discovery metadata.
    #[cfg(feature = "iface-backbone")]
    pub(crate) backbone_discovery: HashMap<String, BackboneDiscoveryRuntimeHandle>,
    /// Runtime-config handles for TCP server interfaces.
    #[cfg(feature = "iface-tcp")]
    pub(crate) tcp_server: HashMap<String, TcpServerRuntimeConfigHandle>,
    /// Runtime-config handles for TCP client interfaces.
    #[cfg(feature = "iface-tcp")]
    pub(crate) tcp_client: HashMap<String, TcpClientRuntimeConfigHandle>,
    /// Runtime-config state for TCP server discovery metadata.
    #[cfg(feature = "iface-tcp")]
    pub(crate) tcp_server_discovery: HashMap<String, TcpServerDiscoveryRuntimeHandle>,
    /// Runtime-config handles for UDP interfaces.
    #[cfg(feature = "iface-udp")]
    pub(crate) udp: HashMap<String, UdpRuntimeConfigHandle>,
    /// Runtime-config handles for Auto interfaces.
    #[cfg(feature = "iface-auto")]
    pub(crate) auto: HashMap<String, AutoRuntimeConfigHandle>,
    /// Runtime-config handles for I2P interfaces.
    #[cfg(feature = "iface-i2p")]
    pub(crate) i2p: HashMap<String, I2pRuntimeConfigHandle>,
    /// Runtime-config handles for Pipe interfaces.
    #[cfg(feature = "iface-pipe")]
    pub(crate) pipe: HashMap<String, PipeRuntimeConfigHandle>,
    /// Runtime-config handles for RNode interfaces.
    #[cfg(feature = "iface-rnode")]
    pub(crate) rnode: HashMap<String, RNodeRuntimeConfigHandle>,
    /// Startup/default interface metadata for generic cross-cutting runtime config.
    pub(crate) interface_defaults: HashMap<String, rns_core::transport::types::InterfaceInfo>,
    /// Current IFAC runtime config for static interfaces that support IFAC mutation.
    pub(crate) ifac: HashMap<String, IfacRuntimeConfig>,
    /// Startup/default IFAC runtime config for static interfaces.
    pub(crate) ifac_defaults: HashMap<String, IfacRuntimeConfig>,
    /// Startup/default runtime-config values.
    pub(crate) defaults: RuntimeConfigDefaults,
}

impl RuntimeConfigHandles {
    pub(crate) fn new(defaults: RuntimeConfigDefaults) -> Self {
        Self {
            #[cfg(feature = "iface-backbone")]
            backbone: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_state: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_client: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_discovery: HashMap::new(),
            #[cfg(feature = "iface-tcp")]
            tcp_server: HashMap::new(),
            #[cfg(feature = "iface-tcp")]
            tcp_client: HashMap::new(),
            #[cfg(feature = "iface-tcp")]
            tcp_server_discovery: HashMap::new(),
            #[cfg(feature = "iface-udp")]
            udp: HashMap::new(),
            #[cfg(feature = "iface-auto")]
            auto: HashMap::new(),
            #[cfg(feature = "iface-i2p")]
            i2p: HashMap::new(),
            #[cfg(feature = "iface-pipe")]
            pipe: HashMap::new(),
            #[cfg(feature = "iface-rnode")]
            rnode: HashMap::new(),
            interface_defaults: HashMap::new(),
            ifac: HashMap::new(),
            ifac_defaults: HashMap::new(),
            defaults,
        }
    }
}
