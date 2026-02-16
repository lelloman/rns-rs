/// Wire-format enum mirroring `TransportAction` with raw primitives.
///
/// Uses `u64` for interface IDs and `[u8; N]` for hashes so that `rns-hooks`
/// has zero dependency on `rns-core`. Conversions happen at call sites.
///
/// Data fields use owned `Vec<u8>` — the data is copied from WASM linear memory
/// when the action is parsed, so ActionWire values remain valid after the store
/// is dropped.
#[derive(Debug, Clone)]
pub enum ActionWire {
    SendOnInterface {
        interface: u64,
        raw: Vec<u8>,
    },
    BroadcastOnAllInterfaces {
        raw: Vec<u8>,
        exclude: u64,
        has_exclude: u8,
    },
    DeliverLocal {
        destination_hash: [u8; 16],
        raw: Vec<u8>,
        packet_hash: [u8; 32],
        receiving_interface: u64,
    },
    AnnounceReceived {
        destination_hash: [u8; 16],
        identity_hash: [u8; 16],
        public_key: [u8; 64],
        name_hash: [u8; 10],
        random_hash: [u8; 10],
        app_data: Option<Vec<u8>>,
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
        raw: Vec<u8>,
        exclude: u64,
        has_exclude: u8,
    },
    ForwardPlainBroadcast {
        raw: Vec<u8>,
        to_local: u8,
        exclude: u64,
        has_exclude: u8,
    },
    CacheAnnounce {
        packet_hash: [u8; 32],
        raw: Vec<u8>,
    },
    TunnelSynthesize {
        interface: u64,
        data: Vec<u8>,
        dest_hash: [u8; 16],
    },
    TunnelEstablished {
        tunnel_id: [u8; 32],
        interface: u64,
    },
}

/// Action tag bytes used in the binary encoding.
pub const TAG_SEND_ON_INTERFACE: u8 = 0;
pub const TAG_BROADCAST: u8 = 1;
pub const TAG_DELIVER_LOCAL: u8 = 2;
pub const TAG_ANNOUNCE_RECEIVED: u8 = 3;
pub const TAG_PATH_UPDATED: u8 = 4;
pub const TAG_FORWARD_LOCAL_CLIENTS: u8 = 5;
pub const TAG_FORWARD_PLAIN_BROADCAST: u8 = 6;
pub const TAG_CACHE_ANNOUNCE: u8 = 7;
pub const TAG_TUNNEL_SYNTHESIZE: u8 = 8;
pub const TAG_TUNNEL_ESTABLISHED: u8 = 9;
