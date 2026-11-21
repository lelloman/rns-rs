//! Interface discovery: the protocol from `rns_core::discovery`, plus this
//! node's side of it: the implementation name and version it advertises,
//! per-interface discovery configuration, and wrappers reading the wall
//! clock.

pub(crate) use rns_core::discovery::*;

use rns_core::stamp::StampCost;

use super::time;

/// Short, implementation-specific identity advertised by this transport.
pub(crate) const TRANSPORT_IMPLEMENTATION_NAME: &str = "rns-rs";

/// Version of the native transport implementation in this build.
pub(crate) const TRANSPORT_IMPLEMENTATION_VERSION: &str = env!("CARGO_PKG_VERSION");

// ============================================================================
// Per-interface discovery configuration
// ============================================================================

/// Per-interface discovery configuration parsed from config file.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Human-readable name to advertise (defaults to interface name).
    pub discovery_name: String,
    /// Announce interval in seconds (default 21600 = 6h, min 300 = 5min).
    pub announce_interval: u64,
    /// Stamp cost for discovery PoW (default 16), fractional since upstream
    /// 796ef2d4 (`discovery_stamp_value`, read with `as_float`).
    pub stamp_value: StampCost,
    /// IP/hostname this interface is reachable on.
    pub reachable_on: Option<String>,
    /// Interface type string (e.g. "BackboneInterface").
    pub interface_type: String,
    /// Listen port of the discoverable interface.
    pub listen_port: Option<u16>,
    /// Executable that resolves `latitude,longitude,height` for each announce.
    pub location_cmd: Option<String>,
    /// Geographic latitude in decimal degrees.
    pub latitude: Option<f64>,
    /// Geographic longitude in decimal degrees.
    pub longitude: Option<f64>,
    /// Height/altitude in meters.
    pub height: Option<f64>,
    /// Optional 16-byte LXMF destination hash for the interface operator.
    pub operator_lxmf_address: Option<[u8; 16]>,
    /// The interface's own `destination_cost` / `pr_cost`, announced as
    /// `DST_COST` / `PR_COST` (9b464382).
    pub stamp_costs: rns_core::transport::types::InterfaceStampCosts,
    /// Announce the interface's IFAC network name and passphrase
    /// (`publish_ifac`); upstream publishes them only when asked to.
    pub publish_ifac: bool,
    /// Encrypt the announce to the network identity (`discovery_encrypt`),
    /// so only nodes holding that identity can read it.
    pub encrypt: bool,
    /// Radio parameters announced for radio interfaces.
    pub radio: DiscoveryRadio,
}

/// Radio parameters a discovery announce carries: an RNode's own settings,
/// or the `discovery_frequency`, `discovery_bandwidth` and
/// `discovery_modulation` of a KISS or Weave interface.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiscoveryRadio {
    /// Frequency, Hz.
    pub frequency: Option<u64>,
    /// Bandwidth, Hz.
    pub bandwidth: Option<u64>,
    /// LoRa spreading factor; RNode only.
    pub spreading_factor: Option<u64>,
    /// LoRa coding rate; RNode only.
    pub coding_rate: Option<u64>,
    /// Modulation name; KISS and Weave only.
    pub modulation: Option<String>,
}

/// [`rns_core::discovery::filter_and_sort_interfaces`] at the current time.
pub fn filter_and_sort_interfaces(
    interfaces: &mut Vec<DiscoveredInterface>,
    only_available: bool,
    only_transport: bool,
) {
    rns_core::discovery::filter_and_sort_interfaces(
        interfaces,
        only_available,
        only_transport,
        time::now(),
    );
}
