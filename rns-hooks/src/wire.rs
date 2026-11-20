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
    /// Send a packet on one interface.
    SendOnInterface {
        /// Interface to send on.
        interface: u64,
        /// Packet bytes.
        raw: Vec<u8>,
    },
    /// Broadcast a packet on every outbound interface.
    BroadcastOnAllInterfaces {
        /// Packet bytes.
        raw: Vec<u8>,
        /// Interface to skip, if `has_exclude` is non-zero.
        exclude: u64,
        /// Non-zero if `exclude` applies.
        has_exclude: u8,
    },
    /// Deliver a packet to a local destination.
    DeliverLocal {
        /// Destination the packet is addressed to.
        destination_hash: [u8; 16],
        /// Packet bytes.
        raw: Vec<u8>,
        /// Hash of the packet.
        packet_hash: [u8; 32],
        /// Interface to report the packet as received on.
        receiving_interface: u64,
    },
    /// Report a validated announce, as if the engine had received it.
    AnnounceReceived {
        /// The announced destination.
        destination_hash: [u8; 16],
        /// Hash of the announcing identity.
        identity_hash: [u8; 16],
        /// The identity's public key.
        public_key: [u8; 64],
        /// Name hash of the destination.
        name_hash: [u8; 10],
        /// The announce's random hash.
        random_hash: [u8; 10],
        /// Application data carried by the announce.
        app_data: Option<Vec<u8>>,
        /// Hop count of the announce.
        hops: u8,
        /// Interface the announce arrived on.
        receiving_interface: u64,
    },
    /// Report a path table update.
    PathUpdated {
        /// Destination whose path changed.
        destination_hash: [u8; 16],
        /// Hop count of the path.
        hops: u8,
        /// Transport identity hash of the next hop.
        next_hop: [u8; 16],
        /// Interface the path goes through.
        interface: u64,
    },
    /// Forward a packet to the local client interfaces.
    ForwardToLocalClients {
        /// Packet bytes.
        raw: Vec<u8>,
        /// Interface to skip, if `has_exclude` is non-zero.
        exclude: u64,
        /// Non-zero if `exclude` applies.
        has_exclude: u8,
    },
    /// Forward a plain or group broadcast between local clients and the
    /// other interfaces.
    ForwardPlainBroadcast {
        /// Packet bytes.
        raw: Vec<u8>,
        /// Non-zero to send to the local client interfaces, zero to send to
        /// the other interfaces.
        to_local: u8,
        /// Interface to skip, if `has_exclude` is non-zero.
        exclude: u64,
        /// Non-zero if `exclude` applies.
        has_exclude: u8,
    },
    /// Cache an announce packet.
    CacheAnnounce {
        /// Hash of the announce packet.
        packet_hash: [u8; 32],
        /// Announce packet bytes.
        raw: Vec<u8>,
    },
    /// Send tunnel synthesis data on an interface.
    TunnelSynthesize {
        /// Interface to send on.
        interface: u64,
        /// Synthesis payload.
        data: Vec<u8>,
        /// Destination hash of the tunnel synthesis destination.
        dest_hash: [u8; 16],
    },
    /// Report a tunnel as established on an interface.
    TunnelEstablished {
        /// Tunnel id.
        tunnel_id: [u8; 32],
        /// Interface attached to the tunnel.
        interface: u64,
    },
}
