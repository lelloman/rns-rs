pub const PACKET_STATS_PAYLOAD_TYPE: &str = "stats.packet.v1";
pub const PACKET_STATS_ENCODED_LEN: usize = 13;

pub const ANNOUNCE_STATS_PAYLOAD_TYPE: &str = "stats.announce.v1";
/// identity_hash:16 + destination_hash:16 + name_hash:10 + random_hash:10 + hops:1 + interface_id:8 = 61
pub const ANNOUNCE_STATS_ENCODED_LEN: usize = 61;

pub const LINK_STATS_PAYLOAD_TYPE: &str = "stats.link.v1";
/// link_id:16 + interface_id:8 = 24
pub const LINK_STATS_ENCODED_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketStatsPayload {
    pub flags: u8,
    pub packet_len: u32,
    pub interface_id: u64,
}

impl PacketStatsPayload {
    pub fn encode(&self) -> [u8; PACKET_STATS_ENCODED_LEN] {
        let mut buf = [0u8; PACKET_STATS_ENCODED_LEN];
        buf[0] = self.flags;
        buf[1..5].copy_from_slice(&self.packet_len.to_le_bytes());
        buf[5..13].copy_from_slice(&self.interface_id.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PACKET_STATS_ENCODED_LEN {
            return None;
        }
        let mut packet_len = [0u8; 4];
        packet_len.copy_from_slice(&bytes[1..5]);
        let mut interface_id = [0u8; 8];
        interface_id.copy_from_slice(&bytes[5..13]);
        Some(Self {
            flags: bytes[0],
            packet_len: u32::from_le_bytes(packet_len),
            interface_id: u64::from_le_bytes(interface_id),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceStatsPayload {
    pub identity_hash: [u8; 16],
    pub destination_hash: [u8; 16],
    pub name_hash: [u8; 10],
    pub random_hash: [u8; 10],
    pub hops: u8,
    pub interface_id: u64,
}

impl AnnounceStatsPayload {
    pub fn encode(&self) -> [u8; ANNOUNCE_STATS_ENCODED_LEN] {
        let mut buf = [0u8; ANNOUNCE_STATS_ENCODED_LEN];
        buf[0..16].copy_from_slice(&self.identity_hash);
        buf[16..32].copy_from_slice(&self.destination_hash);
        buf[32..42].copy_from_slice(&self.name_hash);
        buf[42..52].copy_from_slice(&self.random_hash);
        buf[52] = self.hops;
        buf[53..61].copy_from_slice(&self.interface_id.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ANNOUNCE_STATS_ENCODED_LEN {
            return None;
        }
        let mut identity_hash = [0u8; 16];
        identity_hash.copy_from_slice(&bytes[0..16]);
        let mut destination_hash = [0u8; 16];
        destination_hash.copy_from_slice(&bytes[16..32]);
        let mut name_hash = [0u8; 10];
        name_hash.copy_from_slice(&bytes[32..42]);
        let mut random_hash = [0u8; 10];
        random_hash.copy_from_slice(&bytes[42..52]);
        let hops = bytes[52];
        let mut iface = [0u8; 8];
        iface.copy_from_slice(&bytes[53..61]);
        Some(Self {
            identity_hash,
            destination_hash,
            name_hash,
            random_hash,
            hops,
            interface_id: u64::from_le_bytes(iface),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatsPayload {
    pub link_id: [u8; 16],
    pub interface_id: u64,
}

impl LinkStatsPayload {
    pub fn encode(&self) -> [u8; LINK_STATS_ENCODED_LEN] {
        let mut buf = [0u8; LINK_STATS_ENCODED_LEN];
        buf[0..16].copy_from_slice(&self.link_id);
        buf[16..24].copy_from_slice(&self.interface_id.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != LINK_STATS_ENCODED_LEN {
            return None;
        }
        let mut link_id = [0u8; 16];
        link_id.copy_from_slice(&bytes[0..16]);
        let mut interface_id = [0u8; 8];
        interface_id.copy_from_slice(&bytes[16..24]);
        Some(Self {
            link_id,
            interface_id: u64::from_le_bytes(interface_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_stats_roundtrip() {
        let payload = AnnounceStatsPayload {
            identity_hash: [0xAA; 16],
            destination_hash: [0xBB; 16],
            name_hash: [0xCC; 10],
            random_hash: [0xDD; 10],
            hops: 3,
            interface_id: 99,
        };
        let encoded = payload.encode();
        assert_eq!(AnnounceStatsPayload::decode(&encoded), Some(payload));
    }

    #[test]
    fn packet_stats_roundtrip() {
        let payload = PacketStatsPayload {
            flags: 0x23,
            packet_len: 1024,
            interface_id: 42,
        };
        let encoded = payload.encode();
        assert_eq!(PacketStatsPayload::decode(&encoded), Some(payload));
    }

    #[test]
    fn link_stats_roundtrip() {
        let payload = LinkStatsPayload {
            link_id: [0xAB; 16],
            interface_id: 42,
        };
        let encoded = payload.encode();
        assert_eq!(LinkStatsPayload::decode(&encoded), Some(payload));
    }
}
