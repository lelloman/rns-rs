//! What the driver keeps per interface and listener.

use super::*;

/// A listener reported in interface statistics: upstream lists a TCP
/// server, the shared instance's local server and the interfaces that
/// spawn peers or subinterfaces (`AutoInterface`, `I2PInterface`,
/// `RNodeMultiInterface`) as interfaces of their own, with the interfaces
/// they serve.
#[derive(Debug, Clone)]
pub(crate) struct ListenerStat {
    pub(crate) id: InterfaceId,
    /// Upstream's `interface.name`.
    pub(crate) name: String,
    /// Upstream's `str(interface)`.
    pub(crate) display_name: String,
    pub(crate) interface_type: String,
    pub(crate) mode: u8,
    pub(crate) gravity: i64,
    pub(crate) announces_to_internal: Option<bool>,
    pub(crate) bitrate: Option<u64>,
    pub(crate) mtu: u32,
    pub(crate) ifac: Option<crate::ifac::IfacState>,
    pub(crate) clients: ListenerClients,
}

/// Which interfaces a [`ListenerStat`] serves, and how upstream reports
/// them.
#[derive(Debug, Clone)]
pub(crate) enum ListenerClients {
    /// The interfaces registered with this listener as their parent,
    /// counted as its `clients`.
    #[cfg(feature = "iface-tcp")]
    Spawned,
    /// The shared instance's local clients, on this endpoint.
    #[cfg(feature = "iface-local")]
    Local(crate::interface::display::LocalEndpoint),
    /// An `AutoInterface`'s peers, registered with it as their parent:
    /// upstream counts them as its `peers` and reports no `clients`.
    #[cfg(feature = "iface-auto")]
    AutoPeers,
    /// An `I2PInterface`'s peers, registered with it as their parent.
    #[cfg(feature = "iface-i2p")]
    I2pPeers(I2pListener),
    /// An `RNodeMultiInterface`'s subinterfaces, counted as its `clients`.
    Subinterfaces(Vec<InterfaceId>),
}

/// An `I2PInterface` as its statistics report it. Upstream counts only the
/// peers that connected to it as its `clients`, and only their transmitted
/// bytes add up on it.
#[cfg(feature = "iface-i2p")]
#[derive(Debug, Clone)]
pub(crate) struct I2pListener {
    pub(crate) connectable: bool,
    /// How many peers it is configured to connect to (`peers`).
    pub(crate) configured_peers: Option<usize>,
    pub(crate) endpoint: Arc<Mutex<crate::interface::i2p::I2pEndpoint>>,
}

/// Infer the interface type string from a dynamic interface's name.
/// Dynamic interfaces (TCP server clients, backbone peers, auto peers, local server clients)
/// include their type in the name prefix set at construction.
pub(super) fn infer_interface_type(name: &str) -> String {
    use crate::interface::InterfaceKind;

    let kind = if name.starts_with(InterfaceKind::TcpServer.type_name()) {
        InterfaceKind::TcpServerClient
    } else if name.starts_with(InterfaceKind::Backbone.type_name()) {
        InterfaceKind::Backbone
    } else if name.starts_with(InterfaceKind::Local.type_name()) {
        InterfaceKind::LocalServerClient
    } else if name.starts_with("WeaveInterfacePeer[") {
        InterfaceKind::WeavePeer
    } else {
        // AutoInterface peers use "{group_name}:{peer_addr}" format where
        // group_name is the config section name (typically "AutoInterface" or similar).
        InterfaceKind::Auto
    };
    kind.type_name().to_string()
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TrafficSample {
    pub(super) sampled_at: f64,
    pub(super) rxb: u64,
    pub(super) txb: u64,
    pub(super) rx_packets: u64,
    pub(super) tx_packets: u64,
    pub(super) arxb: u64,
    pub(super) atxb: u64,
    pub(super) prxb: u64,
    pub(super) ptxb: u64,
    pub(super) frxb: u64,
    pub(super) ftxb: u64,
}

/// Give the engine an interface's frequencies and sample counts.
pub(crate) fn sync_interface_frequencies(
    engine: &mut TransportEngine,
    id: InterfaceId,
    sample: crate::common::interface_stats::FrequencySample,
) {
    engine.update_interface_freqs(
        id,
        sample.ia_freq,
        sample.ia_samples,
        sample.ip_freq,
        sample.op_freq,
        sample.op_samples,
    );
}

impl TrafficSample {
    pub(super) fn from_stats(sampled_at: f64, stats: &crate::interface::InterfaceStats) -> Self {
        Self {
            sampled_at,
            rxb: stats.rxb,
            txb: stats.txb,
            rx_packets: stats.rx_packets,
            tx_packets: stats.tx_packets,
            arxb: stats.arxb,
            atxb: stats.atxb,
            prxb: stats.prxb,
            ptxb: stats.ptxb,
            frxb: stats.frxb,
            ftxb: stats.ftxb,
        }
    }
}

/// The driver loop. Owns the engine and all interface entries.
pub(crate) struct ManagedInterface {
    pub(crate) parent_id: InterfaceId,
    pub(crate) type_name: String,
    pub(crate) control: Option<crate::interface::ListenerControl>,
    pub(crate) static_ids: Vec<InterfaceId>,
}
