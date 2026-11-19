//! The entries and reports queries answer with.

use super::*;

/// Information about a loaded hook program.
#[derive(Debug, Clone)]
pub struct HookInfo {
    pub name: String,
    pub hook_type: String,
    pub attach_point: String,
    pub priority: i32,
    pub enabled: bool,
    pub consecutive_traps: u32,
}

/// Live behavioral state for a backbone peer IP.
#[derive(Debug, Clone, PartialEq)]
pub struct BackbonePeerStateEntry {
    pub interface_name: String,
    pub peer_ip: IpAddr,
    pub connected_count: usize,
    pub blacklisted_remaining_secs: Option<f64>,
    pub blacklist_reason: Option<String>,
    pub reject_count: u64,
}

/// Hook-visible snapshot of a backbone peer lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackbonePeerHookEvent {
    pub server_interface_id: InterfaceId,
    pub peer_interface_id: Option<InterfaceId>,
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub connected_for: Duration,
    pub had_received_data: bool,
    pub penalty_level: u8,
    pub blacklist_for: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackboneInterfaceEntry {
    pub interface_id: InterfaceId,
    pub interface_name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KnownDestinationEntry {
    pub dest_hash: [u8; 16],
    pub identity_hash: [u8; 16],
    pub public_key: [u8; 64],
    pub app_data: Option<Vec<u8>>,
    pub hops: u8,
    pub received_at: f64,
    pub receiving_interface: InterfaceId,
    pub was_used: bool,
    pub last_used_at: Option<f64>,
    pub retained: bool,
    pub stamp: Option<[u8; rns_core::constants::STAMP_LENGTH]>,
    pub stamp_value: rns_core::stamp::StampValue,
    pub lr_cost: Option<rns_core::stamp::StampCost>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBridgeConsumerStats {
    pub id: u64,
    pub connected: bool,
    pub queue_len: usize,
    pub queued_bytes: usize,
    pub dropped_pending: u64,
    pub dropped_total: u64,
    pub queue_max_events: usize,
    pub queue_max_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBridgeStats {
    pub connected: bool,
    pub consumer_count: usize,
    pub queue_max_events: usize,
    pub queue_max_bytes: usize,
    pub backlog_len: usize,
    pub backlog_bytes: usize,
    pub backlog_dropped_pending: u64,
    pub backlog_dropped_total: u64,
    pub total_disconnect_count: u64,
    pub consumers: Vec<ProviderBridgeConsumerStats>,
}

/// Per-destination link totals for status reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkDistributionEntry {
    pub destination_hash: [u8; 16],
    pub total: usize,
    pub active: usize,
}

/// A locally registered destination.
#[derive(Debug, Clone)]
pub struct LocalDestinationEntry {
    pub hash: [u8; 16],
    pub dest_type: u8,
}

/// Information about an active link.
#[derive(Debug, Clone)]
pub struct LinkInfoEntry {
    pub link_id: [u8; 16],
    /// Confirmed sends admitted locally but not yet fully written (including the current write).
    pub pending_send_packets: usize,
    /// Polled async sends waiting for local admission capacity.
    pub waiting_send_packets: usize,
    pub state: String,
    pub is_initiator: bool,
    pub dest_hash: [u8; 16],
    pub remote_identity: Option<[u8; 16]>,
    pub rtt: Option<f64>,
    pub expected_hops: u8,
    /// Maximum plaintext bytes accepted by one direct Link data packet, as
    /// of now: it follows the link's current path, so it is larger while
    /// the link runs over a Direct Link path that carries more, and back to
    /// the link's own value after a fallback. A channel message may be up
    /// to this less `CHANNEL_ENVELOPE_OVERHEAD` (6) bytes.
    pub mdu: usize,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub channel_window: Option<u16>,
    pub channel_outstanding: Option<usize>,
    pub pending_channel_packets: usize,
    pub channel_send_ok: u64,
    pub channel_send_not_ready: u64,
    pub channel_send_too_big: u64,
    pub channel_send_other_error: u64,
    pub channel_messages_received: u64,
    pub channel_proofs_sent: u64,
    pub channel_proofs_received: u64,
}

/// Information about an active resource transfer.
#[derive(Debug, Clone)]
pub struct ResourceInfoEntry {
    pub link_id: [u8; 16],
    pub direction: String,
    pub total_parts: usize,
    pub transferred_parts: usize,
    pub complete: bool,
}

/// A single path table entry for query responses.
#[derive(Debug, Clone)]
pub struct PathTableEntry {
    pub hash: [u8; 16],
    pub timestamp: f64,
    pub via: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub used: f64,
    pub interface: InterfaceId,
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
    pub hash: [u8; 16],
    pub last: f64,
    pub rate_violations: u32,
    pub blocked_until: f64,
    pub timestamps: Vec<f64>,
}

/// The physical-layer readings a packet arrived with, on an interface that
/// reports them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PacketSignal {
    pub rssi: Option<i16>,
    pub snr: Option<f32>,
    /// Link quality in percent, the interface's latest reading when the
    /// packet arrived (upstream's `packet.q`).
    pub q: Option<f64>,
}

/// A blackholed identity for query responses.
#[derive(Debug, Clone)]
pub struct BlackholeInfo {
    pub identity_hash: [u8; 16],
    pub created: f64,
    pub expires: f64,
    pub reason: Option<String>,
    /// The identity hash of the list the entry came from: this node's
    /// transport identity for its own entries, as upstream records them, or
    /// `None` on a node without one.
    pub source: Option<[u8; 16]>,
}

/// Keys for a stamped link request, ground off the driver thread, with the
/// responder of the `CreateLink` that asked for them.
pub struct StampedLinkKeys {
    pub dest_hash: [u8; 16],
    pub dest_sig_pub_bytes: [u8; 32],
    pub prv_bytes: [u8; 32],
    pub sig_prv_bytes: [u8; 32],
    pub stamp_value: rns_core::stamp::StampValue,
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
    pub next_hop: [u8; 16],
    pub hops: u8,
    pub interface: InterfaceId,
}
