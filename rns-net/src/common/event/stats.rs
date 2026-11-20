//! Interface statistics.

/// Interface statistics response.
#[derive(Debug, Clone, Default)]
pub struct InterfaceStatsResponse {
    /// Statistics of each interface, in upstream's interface order.
    pub interfaces: Vec<SingleInterfaceStat>,
    /// The transport identity hash, or `None` without one.
    pub transport_id: Option<[u8; 16]>,
    /// The hash of the configured network identity (upstream `network_id`).
    pub network_id: Option<[u8; 16]>,
    /// The node is a transport node.
    pub transport_enabled: bool,
    /// Seconds since the driver started.
    pub transport_uptime: f64,
    /// Total received bytes across all interfaces.
    pub total_rxb: u64,
    /// Total transmitted bytes across all interfaces.
    pub total_txb: u64,
    /// Total received packets across all interfaces.
    pub total_rx_packets: u64,
    /// Total transmitted packets across all interfaces.
    pub total_tx_packets: u64,
    /// Total received announce packets.
    pub total_announce_rx: u64,
    /// Total transmitted announce packets.
    pub total_announce_tx: u64,
    /// Total received path-request packets.
    pub total_path_request_rx: u64,
    /// Total transmitted path-request packets.
    pub total_path_request_tx: u64,
    /// Total links (validated and pending).
    pub total_links: usize,
    /// Active (validated) links.
    pub active_links: usize,
    /// Pending links.
    pub pending_links: usize,
    /// Total path pool destinations.
    pub path_pool_total: usize,
    /// Never-used path pool destinations.
    pub path_pool_unused: usize,
    /// Path pool destinations with at least one use.
    pub path_pool_active: usize,
    /// Aggregate received packets per second, excluding local shared-instance traffic.
    pub rx_pps: f64,
    /// Aggregate transmitted packets per second, excluding local shared-instance traffic.
    pub tx_pps: f64,
    /// Aggregate byte counters and rates for total, announce and path-request traffic.
    pub traffic: TrafficDetail,
    /// Traffic relayed through the link table (upstream ef3e8086).
    pub link_traffic: LinkTraffic,
    /// Probe responder destination hash (if enabled).
    pub probe_responder: Option<[u8; 16]>,
    /// Outbound Backbone peer-pool state, if enabled.
    pub backbone_peer_pool: Option<BackbonePeerPoolStatus>,
}

/// Detailed traffic counters and average rates in bits per second.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrafficDetail {
    /// Received bits per second.
    pub rxs: f64,
    /// Transmitted bits per second.
    pub txs: f64,
    /// Received bytes dropped as filtered (upstream 134dc677).
    pub frxb: u64,
    /// Transmitted bytes counted as filtered; upstream counts none.
    pub ftxb: u64,
    /// Filtered received bits per second.
    pub frxs: f64,
    /// Filtered transmitted bits per second.
    pub ftxs: f64,
    /// Announce bytes received.
    pub arxb: u64,
    /// Announce bytes transmitted.
    pub atxb: u64,
    /// Announces received.
    pub arxc: u64,
    /// Announces transmitted.
    pub atxc: u64,
    /// Filtered announces (upstream 819076c3).
    pub afrxc: u64,
    /// Announce bits per second received.
    pub arxs: f64,
    /// Announce bits per second transmitted.
    pub atxs: f64,
    /// Path request bytes received.
    pub prxb: u64,
    /// Path request bytes transmitted.
    pub ptxb: u64,
    /// Path requests received.
    pub prxc: u64,
    /// Path requests transmitted.
    pub ptxc: u64,
    /// Path request bits per second received.
    pub prxs: f64,
    /// Path request bits per second transmitted.
    pub ptxs: f64,
    /// Incoming announce frequency, per second.
    pub arxf: f64,
    /// Outgoing announce frequency, per second.
    pub atxf: f64,
    /// Incoming path request frequency, per second.
    pub prxf: f64,
    /// Outgoing path request frequency, per second.
    pub ptxf: f64,
}

/// Upstream's link traffic totals and speeds (ef3e8086): the bytes of link
/// packets received for and relayed through the link table, local
/// clients' not counted, and those the node's own links receive and send
/// (01ffb98e).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LinkTraffic {
    /// `Transport.link_rxb`.
    pub rxb: u64,
    /// `Transport.link_txb`.
    pub txb: u64,
    /// `Transport.link_speed_rx` and `link_speed_tx`, in bits per second:
    /// `None` until upstream's traffic loop first measures them (they
    /// start as the integer 0), floats from then on.
    pub speeds: Option<(f64, f64)>,
}

/// Runtime status for the outbound Backbone peer pool.
#[derive(Debug, Clone)]
pub struct BackbonePeerPoolStatus {
    /// Most members connected at once.
    pub max_connected: usize,
    /// Members with a connection, up or still connecting.
    pub active_count: usize,
    /// Members waiting to connect.
    pub standby_count: usize,
    /// Members cooling down after too many failures within the window.
    pub cooldown_count: usize,
    /// Each member's state.
    pub members: Vec<BackbonePeerPoolMemberStatus>,
}

/// Runtime status for one outbound Backbone peer-pool member.
#[derive(Debug, Clone)]
pub struct BackbonePeerPoolMemberStatus {
    /// Name of the member's interface.
    pub name: String,
    /// The member's `host:port`.
    pub remote: String,
    /// `configured` or `discovered`.
    pub source: String,
    /// Its priority; higher is tried first.
    pub priority: u8,
    /// `active`, `connecting`, `standby` or `cooldown`.
    pub state: String,
    /// Id of its interface while it has a connection.
    pub interface_id: Option<u64>,
    /// Failures within the pool's failure window.
    pub failure_count: usize,
    /// Its last connection error.
    pub last_error: Option<String>,
    /// Seconds left of its cooldown.
    pub cooldown_remaining_seconds: Option<f64>,
}

/// What an `I2PInterface` reports about its own endpoint (upstream's
/// `i2p_connectable` and `i2p_b32`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct I2pEndpointStat {
    /// Whether it accepts connections.
    pub connectable: bool,
    /// Its address, `{base32}.b32.i2p`, once known.
    pub b32: Option<String>,
}

/// Statistics for a single interface.
#[derive(Debug, Clone)]
pub struct SingleInterfaceStat {
    /// The interface's id.
    pub id: u64,
    /// The interface's name: its config name, or the name a listener gave
    /// a spawned interface (upstream's `interface.name`, `short_name` in
    /// RPC statistics).
    pub name: String,
    /// Upstream's `str(interface)`, e.g. `TCPInterface[Peer/10.0.0.1:4242]`
    /// or `Shared Instance[rns/default]`, reported as `name` in RPC
    /// statistics.
    pub display_name: String,
    /// The display name of the listener that spawned this interface
    /// (upstream `str(interface.parent_interface)`).
    pub parent_display_name: Option<String>,
    /// The tunnel this interface carries, once one is established
    /// (upstream `interface.tunnel_id`, reported since 9b6b724b).
    pub tunnel_id: Option<[u8; 32]>,
    /// The transport identity hash of the node that synthesized a tunnel
    /// over this interface (upstream 464e7598 `remote_transport_id`).
    pub remote_transport_id: Option<[u8; 16]>,
    /// What the remote transport node reported in its synthesis extension
    /// (upstream b7a93b9b `rem_impl`, `rem_vers`, `rem_is_tn`,
    /// `rem_dst_cost`, `rem_pr_cost`); `None` on a shared medium.
    pub remote_transport_info: Option<rns_core::transport::tunnel::RemoteTransportInfo>,
    /// The interface is online and enabled.
    pub status: bool,
    /// Interface mode (`constants::MODE_*`).
    pub mode: u8,
    /// Signed interface preference used by path selection.
    pub gravity: i64,
    /// Whether boundary ingress announces may propagate to internal interfaces.
    pub announces_to_internal: Option<bool>,
    /// Bytes received.
    pub rxb: u64,
    /// Bytes transmitted.
    pub txb: u64,
    /// Frames the interface's writer dropped.
    pub tx_drops: u64,
    /// Bytes of those frames.
    pub tx_dropped_bytes: u64,
    /// The writer is stalled: what it buffered is not draining, and new frames
    /// are dropped.
    pub tx_stalled: bool,
    /// Encoded bytes waiting in the writer's queue or the writer itself.
    pub tx_buffered: usize,
    /// Byte counters and rates for total, announce and path-request traffic.
    pub traffic: TrafficDetail,
    /// Inbound packets dropped as protocol violations.
    pub protocol_violations: u64,
    /// Inbound packets dropped for failing IFAC, or for an IFAC flag on an
    /// interface without IFAC.
    pub ifac_violations: u64,
    /// Inbound packets dropped by the packet filter.
    pub packet_filter_hits: u64,
    /// Inbound packets dropped because their hop count reached `HOP_LIMITER`.
    pub hop_limiter_hits: u64,
    /// Inbound path requests whose stamp met the required cost.
    pub stamped_path_requests: u64,
    /// Packets received.
    pub rx_packets: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// CPU load of the interface's device, in percent.
    pub cpu_load: Option<f64>,
    /// Memory use of the interface's device, in percent.
    pub mem_load: Option<f64>,
    /// Switch id of a Weave device.
    pub switch_id: Option<[u8; 4]>,
    /// Endpoint id of a Weave device.
    pub endpoint_id: Option<[u8; 8]>,
    /// Switch a Weave peer is reached through.
    pub via_switch_id: Option<[u8; 4]>,
    /// Number of peers a Weave device knows.
    pub peers: Option<usize>,
    /// Last received signal strength, in dBm.
    pub rssi: Option<i16>,
    /// Last signal-to-noise ratio, in dB.
    pub snr: Option<f32>,
    /// Signal quality in percent, from SNR and spreading factor.
    pub signal_quality: Option<f64>,
    /// Radio frequency, in Hz.
    pub frequency: Option<u32>,
    /// Radio bandwidth, in Hz.
    pub bandwidth: Option<u32>,
    /// Transmit power, in dBm.
    pub txpower: Option<i8>,
    /// LoRa spreading factor.
    pub spreading_factor: Option<u8>,
    /// LoRa coding rate.
    pub coding_rate: Option<u8>,
    /// Radio channel number.
    pub channel: Option<u32>,
    /// Modulation name, such as `LoRa`.
    pub modulation: Option<String>,
    /// Channel and device state an RNode reports.
    pub radio: Option<crate::common::interface_stats::RadioStats>,
    /// Bitrate in bits per second, when known.
    pub bitrate: Option<u64>,
    /// Whether upstream holds the bitrate as a float, and so reports it as
    /// one: an auto-connected interface's, configured as `5E6`.
    pub bitrate_is_float: bool,
    /// Hardware MTU advertised for this interface, when known.
    pub mtu: Option<u32>,
    /// Size of the IFAC signature, in bytes, when the interface uses IFAC.
    pub ifac_size: Option<usize>,
    /// When the interface's statistics started, as Unix time in seconds.
    pub started: f64,
    /// Incoming announce frequency (per second).
    pub ia_freq: f64,
    /// Outgoing announce frequency (per second).
    pub oa_freq: f64,
    /// Incoming path request frequency (per second).
    pub ip_freq: f64,
    /// Outgoing path request frequency (per second).
    pub op_freq: f64,
    /// Outgoing path request samples currently retained.
    pub op_samples: usize,
    /// Whether announce ingress-control burst limiting is currently active.
    pub burst_active: bool,
    /// Timestamp when announce ingress-control burst limiting activated.
    pub burst_activated: f64,
    /// Whether path-request ingress-control burst limiting is currently active.
    pub pr_burst_active: bool,
    /// Timestamp when path-request burst limiting activated.
    pub pr_burst_activated: f64,
    /// Connected client count for aggregate server interfaces, if reported.
    pub clients: Option<u64>,
    /// Fast-flapping IPs currently blocked by an aggregate server interface.
    pub blocked_ips: Option<u64>,
    /// Sorted textual IP addresses currently blocked for fast flapping.
    pub blocked_ip_list: Option<Vec<String>>,
    /// What an I2P interface reports about its own endpoint.
    pub i2p: Option<I2pEndpointStat>,
    /// The tunnel state of an I2P peer, as upstream's `tunnelstate`
    /// describes it: `Some` on I2P peers only, which report the key, and
    /// holding `None` when the peer has no state.
    pub i2p_tunnel_state: Option<Option<String>>,
    /// The network an auto-connected interface was discovered from: the
    /// hex of the announcing network's identity hash (upstream's
    /// `autoconnect_source`).
    pub autoconnect_source: Option<String>,
    /// Target interval for outgoing announce rate control, in seconds.
    pub announce_rate_target: Option<f64>,
    /// Announce-rate control grace count.
    pub announce_rate_grace: u32,
    /// Announce-rate control penalty, in seconds.
    pub announce_rate_penalty: f64,
    /// Human-readable interface type string (e.g. "TCPClientInterface").
    pub interface_type: String,
    /// Announces held back by ingress control (upstream `held_announces`).
    pub held_announces: usize,
    /// Announces waiting in the interface's announce queue (upstream
    /// `announce_queue`).
    pub announce_queue: usize,
    /// The IFAC network name (upstream `ifac_netname`).
    pub ifac_netname: Option<String>,
    /// The IFAC signature (upstream `ifac_signature`).
    pub ifac_signature: Option<[u8; 64]>,
}
