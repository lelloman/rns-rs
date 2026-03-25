use alloc::string::String;
use alloc::vec::Vec;

/// Opaque identifier for a network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceId(pub u64);

/// Metadata about a network interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub id: InterfaceId,
    pub name: String,
    pub mode: u8,
    pub out_capable: bool,
    pub in_capable: bool,
    pub bitrate: Option<u64>,
    pub announce_rate_target: Option<f64>,
    pub announce_rate_grace: u32,
    pub announce_rate_penalty: f64,
    /// Announce bandwidth cap (fraction of bitrate). Default 0.02 (2%).
    pub announce_cap: f64,
    /// Whether this interface is a local shared-instance client.
    pub is_local_client: bool,
    /// Whether this interface wants tunnel synthesis on connect.
    pub wants_tunnel: bool,
    /// Tunnel ID associated with this interface, if any.
    pub tunnel_id: Option<[u8; 32]>,
    /// Maximum transmission unit for this interface in bytes.
    pub mtu: u32,
    /// Whether ingress control is enabled for this interface.
    pub ingress_control: bool,
    /// Current incoming announce frequency (announces/sec), synced from driver.
    pub ia_freq: f64,
    /// When this interface was started (epoch seconds).
    pub started: f64,
}

/// Actions produced by TransportEngine for the caller to execute.
#[derive(Debug, Clone)]
pub enum TransportAction {
    /// Send raw bytes on a specific interface.
    SendOnInterface {
        interface: InterfaceId,
        raw: Vec<u8>,
    },
    /// Broadcast raw bytes on all OUT-capable interfaces, optionally excluding one.
    BroadcastOnAllInterfaces {
        raw: Vec<u8>,
        exclude: Option<InterfaceId>,
    },
    /// Deliver a packet to a local destination.
    DeliverLocal {
        destination_hash: [u8; 16],
        raw: Vec<u8>,
        packet_hash: [u8; 32],
        receiving_interface: InterfaceId,
    },
    /// An announce was received and validated.
    AnnounceReceived {
        destination_hash: [u8; 16],
        identity_hash: [u8; 16],
        public_key: [u8; 64],
        name_hash: [u8; 10],
        random_hash: [u8; 10],
        app_data: Option<Vec<u8>>,
        hops: u8,
        receiving_interface: InterfaceId,
    },
    /// A path was updated in the path table.
    PathUpdated {
        destination_hash: [u8; 16],
        hops: u8,
        next_hop: [u8; 16],
        interface: InterfaceId,
    },
    /// Forward raw bytes to all local client interfaces (excluding one).
    ForwardToLocalClients {
        raw: Vec<u8>,
        exclude: Option<InterfaceId>,
    },
    /// Forward a PLAIN/GROUP broadcast between local and external interfaces.
    ForwardPlainBroadcast {
        raw: Vec<u8>,
        to_local: bool,
        exclude: Option<InterfaceId>,
    },
    /// Cache an announce packet to disk.
    CacheAnnounce { packet_hash: [u8; 32], raw: Vec<u8> },
    /// Tunnel synthesis: send synthesis data on an interface.
    TunnelSynthesize {
        interface: InterfaceId,
        data: Vec<u8>,
        dest_hash: [u8; 16],
    },
    /// A tunnel was established or reattached.
    TunnelEstablished {
        tunnel_id: [u8; 32],
        interface: InterfaceId,
    },
    /// An announce is being retransmitted (for hook notification).
    AnnounceRetransmit {
        destination_hash: [u8; 16],
        hops: u8,
        interface: Option<InterfaceId>,
    },
    /// A link request was received and is being forwarded (transport relay).
    LinkRequestReceived {
        link_id: [u8; 16],
        destination_hash: [u8; 16],
        receiving_interface: InterfaceId,
    },
    /// A link was established via LRPROOF validation (transport relay).
    LinkEstablished {
        link_id: [u8; 16],
        interface: InterfaceId,
    },
    /// A link entry expired and was removed from the link table.
    LinkClosed { link_id: [u8; 16] },
}

/// A blackholed identity entry.
#[derive(Debug, Clone)]
pub struct BlackholeEntry {
    /// When this entry was created.
    pub created: f64,
    /// When this entry expires (0.0 = never).
    pub expires: f64,
    /// Optional reason for blackholing.
    pub reason: Option<String>,
}

/// Configuration for TransportEngine.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub transport_enabled: bool,
    pub identity_hash: Option<[u8; 16]>,
    /// Accept an announce with strictly fewer hops even when the random_blob
    /// is a duplicate of the existing path entry.  Default `false` preserves
    /// Python-compatible anti-replay behaviour.
    pub prefer_shorter_path: bool,
    /// Maximum number of alternative paths stored per destination.
    /// When >1, failover to the next-best path happens automatically
    /// when the primary becomes unresponsive.  Default 1 (single path,
    /// backward-compatible with Python Reticulum behaviour).
    pub max_paths_per_destination: usize,
    /// Maximum number of packet hashes retained for duplicate suppression.
    pub packet_hashlist_max_entries: usize,
    /// Maximum number of discovery path-request tags remembered for duplicate suppression.
    pub max_discovery_pr_tags: usize,
    /// Maximum number of destination hashes retained in the live path table.
    pub max_path_destinations: usize,
    /// Maximum number of destination hashes retained across all tunnel entries.
    pub max_tunnel_destinations_total: usize,
    /// Retention timeout for tunnel-known destinations, in seconds.
    pub destination_timeout_secs: f64,
    /// Retention timeout for announce retransmission state, in seconds.
    pub announce_table_ttl_secs: f64,
    /// Maximum retained bytes across announce retransmission state maps.
    pub announce_table_max_bytes: usize,
    /// Whether the announce signature verification cache is enabled.
    pub announce_sig_cache_enabled: bool,
    /// Maximum entries in the announce signature verification cache.
    pub announce_sig_cache_max_entries: usize,
    /// TTL for announce signature cache entries, in seconds.
    pub announce_sig_cache_ttl_secs: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_id_ordering() {
        let a = InterfaceId(1);
        let b = InterfaceId(2);
        assert!(a < b);
        assert_eq!(a, InterfaceId(1));
    }

    #[test]
    fn test_transport_config_defaults() {
        let cfg = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: crate::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: crate::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: crate::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: crate::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: crate::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: crate::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: crate::constants::ANNOUNCE_SIG_CACHE_TTL,
        };
        assert!(!cfg.transport_enabled);
        assert!(cfg.identity_hash.is_none());
        assert!(!cfg.prefer_shorter_path);
        assert_eq!(cfg.max_paths_per_destination, 1);
        assert_eq!(
            cfg.packet_hashlist_max_entries,
            crate::constants::HASHLIST_MAXSIZE
        );
        assert_eq!(cfg.max_discovery_pr_tags, crate::constants::MAX_PR_TAGS);
        assert_eq!(cfg.max_path_destinations, usize::MAX);
        assert_eq!(cfg.max_tunnel_destinations_total, usize::MAX);
        assert_eq!(
            cfg.destination_timeout_secs,
            crate::constants::DESTINATION_TIMEOUT
        );
        assert_eq!(
            cfg.announce_table_ttl_secs,
            crate::constants::ANNOUNCE_TABLE_TTL
        );
        assert_eq!(
            cfg.announce_table_max_bytes,
            crate::constants::ANNOUNCE_TABLE_MAX_BYTES
        );
        assert!(cfg.announce_sig_cache_enabled);
        assert_eq!(
            cfg.announce_sig_cache_max_entries,
            crate::constants::ANNOUNCE_SIG_CACHE_MAXSIZE
        );
        assert_eq!(
            cfg.announce_sig_cache_ttl_secs,
            crate::constants::ANNOUNCE_SIG_CACHE_TTL
        );
    }
}
