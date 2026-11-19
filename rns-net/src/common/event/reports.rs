//! The entries and reports queries answer with.

use super::*;

/// Information about a loaded hook program.
#[derive(Debug, Clone)]
pub struct HookInfo {
    /// Name of the hook.
    pub name: String,
    /// Backend the hook runs on, such as `wasm`.
    pub hook_type: String,
    /// Name of the hook point it is attached at.
    pub attach_point: String,
    /// Order among the hooks at the point; higher runs first.
    pub priority: i32,
    /// The hook runs.
    pub enabled: bool,
    /// Traps in a row since its last successful run; at its limit the hook is
    /// disabled.
    pub consecutive_traps: u32,
}

/// Live behavioral state for a backbone peer IP.
#[derive(Debug, Clone, PartialEq)]
pub struct BackbonePeerStateEntry {
    /// Name of the backbone interface.
    pub interface_name: String,
    /// The peer's IP address.
    pub peer_ip: IpAddr,
    /// Connections from the IP open now.
    pub connected_count: usize,
    /// Seconds left on its blacklisting, while it is blacklisted.
    pub blacklisted_remaining_secs: Option<f64>,
    /// Why it was last blacklisted or blocked.
    pub blacklist_reason: Option<String>,
    /// Connections from the IP refused because it was blocked.
    pub reject_count: u64,
}

/// Hook-visible snapshot of a backbone peer lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackbonePeerHookEvent {
    /// The backbone server interface.
    pub server_interface_id: InterfaceId,
    /// The interface spawned for the peer; `None` for a penalty.
    pub peer_interface_id: Option<InterfaceId>,
    /// The peer's IP address.
    pub peer_ip: IpAddr,
    /// The peer's port; 0 for a penalty.
    pub peer_port: u16,
    /// How long the connection lasted; zero when the event has none.
    pub connected_for: Duration,
    /// The peer sent data before it disconnected; `false` for other events.
    pub had_received_data: bool,
    /// Penalty level of a penalty; 0 for other events.
    pub penalty_level: u8,
    /// How long the IP is blacklisted, for a penalty; zero for other events.
    pub blacklist_for: Duration,
}

/// A registered backbone server interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackboneInterfaceEntry {
    /// Id of the interface.
    pub interface_id: InterfaceId,
    /// Name of the interface.
    pub interface_name: String,
}

/// A known destination with its lifecycle state.
#[derive(Debug, Clone, PartialEq)]
pub struct KnownDestinationEntry {
    /// The destination's hash.
    pub dest_hash: [u8; 16],
    /// Hash of the destination's identity.
    pub identity_hash: [u8; 16],
    /// The identity's public key (X25519 then Ed25519).
    pub public_key: [u8; 64],
    /// Application data of its announce.
    pub app_data: Option<Vec<u8>>,
    /// Hops its announce came over.
    pub hops: u8,
    /// When its announce was received, as Unix time in seconds.
    pub received_at: f64,
    /// The interface its announce came in on.
    pub receiving_interface: InterfaceId,
    /// It has been used since it became known.
    pub was_used: bool,
    /// When it was last used, as Unix time in seconds.
    pub last_used_at: Option<f64>,
    /// It is kept however long it goes unused.
    pub retained: bool,
    /// The stamp its announce carried, if any.
    pub stamp: Option<[u8; rns_core::constants::STAMP_LENGTH]>,
    /// Value of its announce stamp; zero without one.
    pub stamp_value: rns_core::stamp::StampValue,
    /// Link request cost it announced, if any.
    pub lr_cost: Option<rns_core::stamp::StampCost>,
}

/// Queue state of one provider bridge consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBridgeConsumerStats {
    /// Id of the consumer.
    pub id: u64,
    /// The consumer is connected.
    pub connected: bool,
    /// Events queued for it.
    pub queue_len: usize,
    /// Bytes queued for it.
    pub queued_bytes: usize,
    /// Events dropped that it has not yet been told of.
    pub dropped_pending: u64,
    /// Events dropped for it over its life.
    pub dropped_total: u64,
    /// Most events its queue holds.
    pub queue_max_events: usize,
    /// Most bytes its queue holds.
    pub queue_max_bytes: usize,
}

/// Queue and drop state of the provider bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBridgeStats {
    /// At least one consumer is connected.
    pub connected: bool,
    /// Number of consumers.
    pub consumer_count: usize,
    /// Most events a queue holds.
    pub queue_max_events: usize,
    /// Most bytes a queue holds.
    pub queue_max_bytes: usize,
    /// Events held while no consumer is connected, for the next one.
    pub backlog_len: usize,
    /// Bytes of those events.
    pub backlog_bytes: usize,
    /// Backlog events dropped that no consumer has been told of.
    pub backlog_dropped_pending: u64,
    /// Backlog events dropped over the bridge's life.
    pub backlog_dropped_total: u64,
    /// Consumer disconnects over the bridge's life.
    pub total_disconnect_count: u64,
    /// Each consumer's queue state.
    pub consumers: Vec<ProviderBridgeConsumerStats>,
}

/// Per-destination link totals for status reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkDistributionEntry {
    /// The destination.
    pub destination_hash: [u8; 16],
    /// Links to it in the transport link table.
    pub total: usize,
    /// Those of them that are validated.
    pub active: usize,
}

/// A locally registered destination.
#[derive(Debug, Clone)]
pub struct LocalDestinationEntry {
    /// The destination's hash.
    pub hash: [u8; 16],
    /// Its type (`constants::DESTINATION_*`).
    pub dest_type: u8,
}

/// Information about an active link.
#[derive(Debug, Clone)]
pub struct LinkInfoEntry {
    /// The link's id.
    pub link_id: [u8; 16],
    /// Confirmed sends admitted locally but not yet fully written (including the current write).
    pub pending_send_packets: usize,
    /// Polled async sends waiting for local admission capacity.
    pub waiting_send_packets: usize,
    /// `pending`, `handshake`, `active`, `stale` or `closed`.
    pub state: String,
    /// This side initiated the link.
    pub is_initiator: bool,
    /// The destination the link is to.
    pub dest_hash: [u8; 16],
    /// Hash of the peer's identity, once known.
    pub remote_identity: Option<[u8; 16]>,
    /// Round trip in seconds, once measured.
    pub rtt: Option<f64>,
    /// Hops to the peer.
    pub expected_hops: u8,
    /// Maximum plaintext bytes accepted by one direct Link data packet, as
    /// of now: it follows the link's current path, so it is larger while
    /// the link runs over a Direct Link path that carries more, and back to
    /// the link's own value after a fallback. A channel message may be up
    /// to this less `CHANNEL_ENVELOPE_OVERHEAD` (6) bytes.
    pub mdu: usize,
    /// Packets sent on the link.
    pub tx_packets: u64,
    /// Packets received and accepted on the link.
    pub rx_packets: u64,
    /// Bytes of packet data sent on the link.
    pub tx_bytes: u64,
    /// Bytes of packet data received on the link.
    pub rx_bytes: u64,
    /// The channel's send window, when the link has a channel.
    pub channel_window: Option<u16>,
    /// Channel messages sent and not yet delivered, when the link has a
    /// channel.
    pub channel_outstanding: Option<usize>,
    /// Channel packets waiting for their proof.
    pub pending_channel_packets: usize,
    /// Channel messages the channel took to send.
    pub channel_send_ok: u64,
    /// Channel sends refused because the channel was not ready.
    pub channel_send_not_ready: u64,
    /// Channel sends refused because the message was too big.
    pub channel_send_too_big: u64,
    /// Channel sends refused for an invalid envelope.
    pub channel_send_other_error: u64,
    /// Channel messages received.
    pub channel_messages_received: u64,
    /// Proofs built for packets received on the link.
    pub channel_proofs_sent: u64,
    /// Proofs received for channel packets.
    pub channel_proofs_received: u64,
}

/// Information about an active resource transfer.
#[derive(Debug, Clone)]
pub struct ResourceInfoEntry {
    /// The link of the transfer.
    pub link_id: [u8; 16],
    /// `incoming` or `outgoing`.
    pub direction: String,
    /// Parts in the transfer.
    pub total_parts: usize,
    /// Parts received or sent so far.
    pub transferred_parts: usize,
    /// Every part has been transferred.
    pub complete: bool,
}

/// A single path table entry for query responses.
#[derive(Debug, Clone)]
pub struct PathTableEntry {
    /// The destination.
    pub hash: [u8; 16],
    /// When the path was learnt or last refreshed, as Unix time in seconds.
    pub timestamp: f64,
    /// Transport id of the next hop, or the destination's own hash when it is a
    /// neighbour.
    pub via: [u8; 16],
    /// Hops to the destination.
    pub hops: u8,
    /// When the path expires, as Unix time in seconds.
    pub expires: f64,
    /// When the path last carried outbound traffic, as Unix time in seconds; 0
    /// if never.
    pub used: f64,
    /// The interface the path goes out on.
    pub interface: InterfaceId,
    /// That interface's name.
    pub interface_name: String,
    /// Upstream's `str(interface)` for the receiving interface, as its RPC
    /// reports it.
    pub interface_display_name: String,
    /// Stamp value of the destination's announce, when it is a known
    /// destination (upstream `21170877` path table `value`).
    pub stamp_value: Option<rns_core::stamp::StampValue>,
    /// Link request cost the destination announced, when known (`lr_cost`).
    pub lr_cost: Option<rns_core::stamp::StampCost>,
}

/// A single rate table entry for query responses.
#[derive(Debug, Clone)]
pub struct RateTableEntry {
    /// The destination.
    pub hash: [u8; 16],
    /// When its last announce that was not blocked arrived, as Unix time in
    /// seconds.
    pub last: f64,
    /// Current count of its announces that came sooner than the rate target.
    pub rate_violations: u32,
    /// Its announces are blocked until then, as Unix time in seconds.
    pub blocked_until: f64,
    /// Arrival times of its recent announces, as Unix time in seconds.
    pub timestamps: Vec<f64>,
}

/// The physical-layer readings a packet arrived with, on an interface that
/// reports them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PacketSignal {
    /// Received signal strength, in dBm.
    pub rssi: Option<i16>,
    /// Signal-to-noise ratio, in dB.
    pub snr: Option<f32>,
    /// Link quality in percent, the interface's latest reading when the
    /// packet arrived (upstream's `packet.q`).
    pub q: Option<f64>,
}

/// A blackholed identity for query responses.
#[derive(Debug, Clone)]
pub struct BlackholeInfo {
    /// The identity's hash.
    pub identity_hash: [u8; 16],
    /// When the entry was made, as Unix time in seconds.
    pub created: f64,
    /// When it expires, as Unix time in seconds; 0 for never.
    pub expires: f64,
    /// Why the identity was blackholed.
    pub reason: Option<String>,
    /// The identity hash of the list the entry came from: this node's
    /// transport identity for its own entries, as upstream records them, or
    /// `None` on a node without one.
    pub source: Option<[u8; 16]>,
}

/// Keys for a stamped link request, ground off the driver thread, with the
/// responder of the `CreateLink` that asked for them.
pub struct StampedLinkKeys {
    /// The destination to link to.
    pub dest_hash: [u8; 16],
    /// The destination's Ed25519 public key.
    pub dest_sig_pub_bytes: [u8; 32],
    /// X25519 private key of the link request.
    pub prv_bytes: [u8; 32],
    /// Ed25519 private key of the link request.
    pub sig_prv_bytes: [u8; 32],
    /// Value of the stamp the keys make.
    pub stamp_value: rns_core::stamp::StampValue,
    /// The `CreateLink` responder, which receives the link id.
    pub response_tx: mpsc::Sender<[u8; 16]>,
}

/// Stamp information recorded from a destination's last announce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationStampInfo {
    /// Value of the announce stamp, zero when the announce carried none.
    pub stamp_value: rns_core::stamp::StampValue,
    /// Link request cost the destination announced, if any.
    pub lr_cost: Option<rns_core::stamp::StampCost>,
}

/// Next hop lookup result.
#[derive(Debug, Clone)]
pub struct NextHopResponse {
    /// Transport id of the next hop.
    pub next_hop: [u8; 16],
    /// Hops to the destination.
    pub hops: u8,
    /// The interface the next hop is reached on.
    pub interface: InterfaceId,
}
