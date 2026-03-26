pub const BACKBONE_PEER_PAYLOAD_TYPE: &str = "sentinel.backbone_peer.v1";
pub const BACKBONE_PEER_INTERFACE_NAME_MAX: usize = 96;

/// peer_ip_family:1 + peer_ip:16 + peer_port:2 + server_interface_id:8 +
/// peer_interface_id:8 + connected_for_secs:8 + had_received_data:1 +
/// penalty_level:1 + blacklist_for_secs:8 + event_kind:1 +
/// interface_name_len:1 + interface_name:96 = 151
pub const BACKBONE_PEER_ENCODED_LEN: usize = 151;

/// Event kind discriminants matching the 5 `BackbonePeer*` hook points.
pub const EVENT_CONNECTED: u8 = 0;
pub const EVENT_DISCONNECTED: u8 = 1;
pub const EVENT_IDLE_TIMEOUT: u8 = 2;
pub const EVENT_WRITE_STALL: u8 = 3;
pub const EVENT_PENALTY: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackbonePeerPayload {
    /// 4 = IPv4, 6 = IPv6
    pub peer_ip_family: u8,
    /// IPv4-mapped-to-16 or raw IPv6
    pub peer_ip: [u8; 16],
    pub peer_port: u16,
    pub server_interface_id: u64,
    pub peer_interface_id: u64,
    pub connected_for_secs: u64,
    pub had_received_data: bool,
    pub penalty_level: u8,
    pub blacklist_for_secs: u64,
    pub event_kind: u8,
    pub server_interface_name_len: u8,
    pub server_interface_name: [u8; BACKBONE_PEER_INTERFACE_NAME_MAX],
}

impl BackbonePeerPayload {
    pub fn encode(&self) -> [u8; BACKBONE_PEER_ENCODED_LEN] {
        let mut buf = [0u8; BACKBONE_PEER_ENCODED_LEN];
        buf[0] = self.peer_ip_family;
        buf[1..17].copy_from_slice(&self.peer_ip);
        buf[17..19].copy_from_slice(&self.peer_port.to_le_bytes());
        buf[19..27].copy_from_slice(&self.server_interface_id.to_le_bytes());
        buf[27..35].copy_from_slice(&self.peer_interface_id.to_le_bytes());
        buf[35..43].copy_from_slice(&self.connected_for_secs.to_le_bytes());
        buf[43] = self.had_received_data as u8;
        buf[44] = self.penalty_level;
        buf[45..53].copy_from_slice(&self.blacklist_for_secs.to_le_bytes());
        buf[53] = self.event_kind;
        buf[54] = self
            .server_interface_name_len
            .min(BACKBONE_PEER_INTERFACE_NAME_MAX as u8);
        buf[55..].copy_from_slice(&self.server_interface_name);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BACKBONE_PEER_ENCODED_LEN {
            return None;
        }
        let mut peer_ip = [0u8; 16];
        peer_ip.copy_from_slice(&bytes[1..17]);
        let mut peer_port = [0u8; 2];
        peer_port.copy_from_slice(&bytes[17..19]);
        let mut server_iface = [0u8; 8];
        server_iface.copy_from_slice(&bytes[19..27]);
        let mut peer_iface = [0u8; 8];
        peer_iface.copy_from_slice(&bytes[27..35]);
        let mut connected = [0u8; 8];
        connected.copy_from_slice(&bytes[35..43]);
        let mut blacklist = [0u8; 8];
        blacklist.copy_from_slice(&bytes[45..53]);
        let mut server_interface_name = [0u8; BACKBONE_PEER_INTERFACE_NAME_MAX];
        server_interface_name.copy_from_slice(&bytes[55..]);
        Some(Self {
            peer_ip_family: bytes[0],
            peer_ip,
            peer_port: u16::from_le_bytes(peer_port),
            server_interface_id: u64::from_le_bytes(server_iface),
            peer_interface_id: u64::from_le_bytes(peer_iface),
            connected_for_secs: u64::from_le_bytes(connected),
            had_received_data: bytes[43] != 0,
            penalty_level: bytes[44],
            blacklist_for_secs: u64::from_le_bytes(blacklist),
            event_kind: bytes[53],
            server_interface_name_len: bytes[54].min(BACKBONE_PEER_INTERFACE_NAME_MAX as u8),
            server_interface_name,
        })
    }

    /// Extract IPv4 address bytes if peer_ip_family == 4.
    pub fn ipv4_octets(&self) -> Option<[u8; 4]> {
        if self.peer_ip_family == 4 {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&self.peer_ip[12..16]);
            Some(octets)
        } else {
            None
        }
    }

    pub fn server_interface_name(&self) -> Option<&str> {
        let len = self.server_interface_name_len as usize;
        core::str::from_utf8(&self.server_interface_name[..len]).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backbone_peer_roundtrip() {
        let payload = BackbonePeerPayload {
            peer_ip_family: 4,
            peer_ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
            peer_port: 4242,
            server_interface_id: 100,
            peer_interface_id: 200,
            connected_for_secs: 30,
            had_received_data: true,
            penalty_level: 3,
            blacklist_for_secs: 900,
            event_kind: EVENT_WRITE_STALL,
            server_interface_name_len: 6,
            server_interface_name: {
                let mut name = [0u8; BACKBONE_PEER_INTERFACE_NAME_MAX];
                name[..6].copy_from_slice(b"public");
                name
            },
        };
        let encoded = payload.encode();
        assert_eq!(encoded.len(), BACKBONE_PEER_ENCODED_LEN);
        assert_eq!(BackbonePeerPayload::decode(&encoded), Some(payload));
    }

    #[test]
    fn decode_wrong_length_returns_none() {
        assert_eq!(BackbonePeerPayload::decode(&[0; 10]), None);
    }
}
