use alloc::vec::Vec;

use super::types::InterfaceId;

/// Entry in the path table, keyed by destination_hash.
#[derive(Debug, Clone)]
pub struct PathEntry {
    pub timestamp: f64,
    pub next_hop: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<[u8; 10]>,
    pub receiving_interface: InterfaceId,
    pub packet_hash: [u8; 32],
}

/// Entry in the announce table, keyed by destination_hash.
#[derive(Debug, Clone)]
pub struct AnnounceEntry {
    pub timestamp: f64,
    pub retransmit_timeout: f64,
    pub retries: u8,
    pub received_from: [u8; 16],
    pub hops: u8,
    pub packet_raw: Vec<u8>,
    pub packet_data: Vec<u8>,
    pub destination_hash: [u8; 16],
    pub context_flag: u8,
    pub local_rebroadcasts: u8,
    pub block_rebroadcasts: bool,
    pub attached_interface: Option<InterfaceId>,
}

/// Entry in the reverse table, keyed by truncated packet hash.
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    pub receiving_interface: InterfaceId,
    pub outbound_interface: InterfaceId,
    pub timestamp: f64,
}

/// Entry in the link table, keyed by link_id.
#[derive(Debug, Clone)]
pub struct LinkEntry {
    pub timestamp: f64,
    pub next_hop_transport_id: [u8; 16],
    pub next_hop_interface: InterfaceId,
    pub remaining_hops: u8,
    pub received_interface: InterfaceId,
    pub taken_hops: u8,
    pub destination_hash: [u8; 16],
    pub validated: bool,
    pub proof_timeout: f64,
}

/// Entry in the announce rate table, keyed by destination_hash.
#[derive(Debug, Clone)]
pub struct RateEntry {
    pub last: f64,
    pub rate_violations: u32,
    pub blocked_until: f64,
    pub timestamps: Vec<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_entry_creation() {
        let entry = PathEntry {
            timestamp: 1000.0,
            next_hop: [0xAA; 16],
            hops: 3,
            expires: 2000.0,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(1),
            packet_hash: [0xBB; 32],
        };
        assert_eq!(entry.hops, 3);
        assert_eq!(entry.receiving_interface, InterfaceId(1));
    }

    #[test]
    fn test_link_entry_creation() {
        let entry = LinkEntry {
            timestamp: 100.0,
            next_hop_transport_id: [0x11; 16],
            next_hop_interface: InterfaceId(2),
            remaining_hops: 5,
            received_interface: InterfaceId(3),
            taken_hops: 2,
            destination_hash: [0x22; 16],
            validated: false,
            proof_timeout: 200.0,
        };
        assert!(!entry.validated);
        assert_eq!(entry.remaining_hops, 5);
    }

    #[test]
    fn test_rate_entry_creation() {
        let entry = RateEntry {
            last: 50.0,
            rate_violations: 0,
            blocked_until: 0.0,
            timestamps: Vec::new(),
        };
        assert_eq!(entry.rate_violations, 0);
    }
}
