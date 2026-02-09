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
        };
        assert!(!cfg.transport_enabled);
        assert!(cfg.identity_hash.is_none());
    }
}
