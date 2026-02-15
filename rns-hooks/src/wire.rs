/// Wire-format enum mirroring `TransportAction` with raw primitives.
///
/// Uses `u64` for interface IDs and `[u8; N]` for hashes so that `rns-hooks`
/// has zero dependency on `rns-core`. Conversions happen at call sites.
#[repr(C)]
#[derive(Debug, Clone)]
pub enum ActionWire {
    SendOnInterface {
        interface: u64,
        raw_offset: u32,
        raw_len: u32,
    },
    BroadcastOnAllInterfaces {
        raw_offset: u32,
        raw_len: u32,
        exclude: u64,
        has_exclude: u8,
    },
    DeliverLocal {
        destination_hash: [u8; 16],
        raw_offset: u32,
        raw_len: u32,
        packet_hash: [u8; 32],
    },
    AnnounceReceived {
        destination_hash: [u8; 16],
        identity_hash: [u8; 16],
        public_key: [u8; 64],
        name_hash: [u8; 10],
        random_hash: [u8; 10],
        app_data_offset: u32,
        /// 0 if no app_data.
        app_data_len: u32,
        hops: u8,
        receiving_interface: u64,
    },
    PathUpdated {
        destination_hash: [u8; 16],
        hops: u8,
        next_hop: [u8; 16],
        interface: u64,
    },
    ForwardToLocalClients {
        raw_offset: u32,
        raw_len: u32,
        exclude: u64,
        has_exclude: u8,
    },
    ForwardPlainBroadcast {
        raw_offset: u32,
        raw_len: u32,
        to_local: u8,
        exclude: u64,
        has_exclude: u8,
    },
    CacheAnnounce {
        packet_hash: [u8; 32],
        raw_offset: u32,
        raw_len: u32,
    },
    TunnelSynthesize {
        interface: u64,
        data_offset: u32,
        data_len: u32,
        dest_hash: [u8; 16],
    },
    TunnelEstablished {
        tunnel_id: [u8; 32],
        interface: u64,
    },
}
