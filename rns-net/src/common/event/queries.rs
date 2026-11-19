//! Queries to the driver and its answers.

use super::*;

/// Queries that can be sent to the driver.
#[derive(Debug)]
pub enum QueryRequest {
    ManageInterface {
        operation: InterfaceManagementOperation,
        name: String,
    },
    /// Get interface statistics and transport info.
    InterfaceStats,
    /// Get path table entries, optionally filtered by max hops.
    PathTable { max_hops: Option<u8> },
    /// Get rate table entries.
    RateTable,
    /// Get the slowest positive bitrate among online interfaces.
    LowestInterfaceBitrate,
    /// Estimate an MTU round trip on the slowest interface plus hop grace.
    MediumPathTimeout,
    /// Estimate the first-hop timeout for a destination using its outbound bitrate.
    FirstHopTimeout { dest_hash: [u8; 16] },
    /// Look up the next hop for a destination.
    NextHop { dest_hash: [u8; 16] },
    /// Look up the next hop interface name for a destination.
    NextHopIfName { dest_hash: [u8; 16] },
    /// Get link table entry count.
    LinkCount,
    /// Get validated or established link count.
    ActiveLinkCount,
    /// Get per-destination link totals and active counts.
    LinkDistribution,
    /// Drop a specific path.
    DropPath { dest_hash: [u8; 16] },
    /// Drop all paths that route via a given transport hash.
    DropAllVia { transport_hash: [u8; 16] },
    /// Drop all announce queues.
    DropAnnounceQueues,
    /// Get the transport identity hash.
    TransportIdentity,
    /// Snapshot restart-relevant transport routing state.
    TransportStateSnapshot,
    /// Get all blackholed identities.
    GetBlackholed,
    /// Add an identity to the blackhole list.
    BlackholeIdentity {
        identity_hash: [u8; 16],
        duration_hours: Option<f64>,
        reason: Option<String>,
    },
    /// Remove an identity from the blackhole list.
    UnblackholeIdentity { identity_hash: [u8; 16] },
    /// `wants_destination_type`: a local application needs announces of
    /// this destination type (upstream 825c2e19).
    WantsDestinationType {
        full_name: String,
        requester: Vec<u8>,
    },
    /// `unwants_destination_type`: withdraw one such need.
    UnwantsDestinationType {
        full_name: String,
        requester: Vec<u8>,
    },
    /// `unwants_all_destination_types`: withdraw every need of a requester.
    UnwantsAllDestinationTypes { requester: Vec<u8> },
    /// `Reticulum.required_announces_only`: let only required destination
    /// types through.
    SetRequiredDestinationsOnly { enabled: bool },
    /// Check if a path exists to a destination.
    HasPath { dest_hash: [u8; 16] },
    /// RSSI, SNR and link quality a received packet arrived with
    /// (`Reticulum.get_packet_rssi`, `get_packet_snr`, `get_packet_q`).
    PacketSignal { packet_hash: [u8; 32] },
    /// Get hop count to a destination.
    HopsTo { dest_hash: [u8; 16] },
    /// Recall identity info for a destination.
    RecallIdentity { dest_hash: [u8; 16] },
    /// Stamp value and announced link request cost recorded for a known
    /// destination.
    RecallDestinationStamp { dest_hash: [u8; 16] },
    /// List known-destination lifecycle state.
    KnownDestinations,
    /// The known destinations that changed or went away since the last
    /// committed flush, compared by fingerprint.
    KnownDestinationChanges,
    /// Record what the known destinations flush stored: entries with their
    /// fingerprints, and removed hashes. `seed` replaces the record, as at
    /// start with what was loaded from storage.
    RecordKnownDestinationFlush {
        stored: Vec<([u8; 16], u64)>,
        removed: Vec<[u8; 16]>,
        seed: bool,
    },
    /// Get locally registered destinations.
    LocalDestinations,
    /// Get active links.
    Links,
    /// Get the state of Direct Link: node-wide counters and each link
    /// with Direct Link activity.
    DirectLinks,
    /// Get active resource transfers.
    Resources,
    /// Inject a path entry into the path table.
    InjectPath {
        dest_hash: [u8; 16],
        next_hop: [u8; 16],
        hops: u8,
        expires: f64,
        interface_name: String,
        packet_hash: [u8; 32],
    },
    /// Inject an identity into the known destinations cache.
    InjectIdentity {
        dest_hash: [u8; 16],
        identity_hash: [u8; 16],
        public_key: [u8; 64],
        app_data: Option<Vec<u8>>,
        hops: u8,
        received_at: f64,
    },
    /// Restore a known destination with full lifecycle state.
    RestoreKnownDestination(KnownDestinationEntry),
    /// Mark a known destination as explicitly retained.
    RetainKnownDestination { dest_hash: [u8; 16] },
    /// Mark all known destinations announced by an identity as retained.
    RetainIdentity { identity_hash: [u8; 16] },
    /// Clear the retained flag on a known destination.
    UnretainKnownDestination { dest_hash: [u8; 16] },
    /// Mark a known destination as used.
    MarkKnownDestinationUsed { dest_hash: [u8; 16] },
    /// Get discovered interfaces.
    DiscoveredInterfaces {
        only_available: bool,
        only_transport: bool,
    },
    /// Send a probe packet to a destination and return (packet_hash, hops).
    SendProbe {
        dest_hash: [u8; 16],
        payload_size: usize,
    },
    /// Check if a proof was received for a probe packet.
    CheckProof { packet_hash: [u8; 32] },
    /// List runtime-config entries currently supported by the daemon.
    ListRuntimeConfig,
    /// Get a single runtime-config entry by key.
    GetRuntimeConfig { key: String },
    /// Set a runtime-config value by key.
    SetRuntimeConfig {
        key: String,
        value: RuntimeConfigValue,
    },
    /// Reset a runtime-config value to its startup/default value.
    ResetRuntimeConfig { key: String },
    /// List live backbone peer state, optionally filtered to one interface.
    BackbonePeerState { interface_name: Option<String> },
    /// List registered backbone server interfaces.
    BackboneInterfaces,
    /// Report live provider-bridge queue/drop state.
    ProviderBridgeStats,
    /// Report current lifecycle/drain status.
    DrainStatus,
    /// Clear live backbone peer state for one interface/IP pair.
    ClearBackbonePeerState {
        interface_name: String,
        peer_ip: IpAddr,
    },
    /// Blacklist a backbone peer IP for a duration.
    BlacklistBackbonePeer {
        interface_name: String,
        peer_ip: IpAddr,
        duration: Duration,
        reason: String,
        penalty_level: u8,
    },
}

/// Largest random payload a probe can carry in a single HEADER_1 DATA packet
/// to a SINGLE destination without exceeding [`rns_core::constants::MTU`].
///
/// The payload is encrypted as `ephemeral pubkey (KEYSIZE/16) || IV || AES-CBC
/// ciphertext (PKCS7-padded, so always at least one byte of padding) || HMAC`,
/// then prefixed with the HEADER_1 packet header. With MTU 500 this is 399
/// bytes, matching what Python's `rnprobe` can send before `Packet.pack()`
/// raises for exceeding the MTU.
pub const MAX_PROBE_PAYLOAD_SIZE: usize = {
    use rns_core::constants::{AES128_BLOCKSIZE, HEADER_MINSIZE, KEYSIZE, MTU, TOKEN_OVERHEAD};
    let numerator = MTU - HEADER_MINSIZE - TOKEN_OVERHEAD - KEYSIZE / 16;
    (numerator / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
};

/// Why a [`QueryRequest::SendProbe`] could not be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendProbeError {
    /// No announced identity is known for the destination.
    UnknownIdentity,
    /// The requested payload does not fit in a single packet.
    PayloadTooLarge { max: usize },
    /// Encrypting the payload to the remote identity failed.
    EncryptFailed,
    /// Packing the probe packet failed.
    PackFailed,
}

/// Responses to queries.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum QueryResponse {
    /// Python-compatible tri-state result: success, failure, or missing name.
    InterfaceManagement(Option<bool>),
    InterfaceStats(InterfaceStatsResponse),
    PathTable(Vec<PathTableEntry>),
    RateTable(Vec<RateTableEntry>),
    LowestInterfaceBitrate(Option<u64>),
    MediumPathTimeout(f64),
    FirstHopTimeout(f64),
    NextHop(Option<NextHopResponse>),
    NextHopIfName(Option<String>),
    LinkCount(usize),
    ActiveLinkCount(usize),
    LinkDistribution(Vec<LinkDistributionEntry>),
    DropPath(bool),
    DropAllVia(usize),
    DropAnnounceQueues,
    TransportIdentity(Option<[u8; 16]>),
    TransportStateSnapshot(rns_core::transport::persistence::TransportStateSnapshot),
    Blackholed(Vec<BlackholeInfo>),
    BlackholeResult(bool),
    UnblackholeResult(bool),
    DestinationTypeRegistration(bool),
    HasPath(bool),
    PacketSignal(Option<PacketSignal>),
    HopsTo(Option<u8>),
    RecallIdentity(Option<crate::common::destination::AnnouncedIdentity>),
    RecallDestinationStamp(Option<DestinationStampInfo>),
    KnownDestinations(Vec<KnownDestinationEntry>),
    KnownDestinationChanges {
        /// Changed or new entries with their fingerprints.
        changed: Vec<(KnownDestinationEntry, u64)>,
        removed: Vec<[u8; 16]>,
    },
    KnownDestinationFlushRecorded,
    LocalDestinations(Vec<LocalDestinationEntry>),
    Links(Vec<LinkInfoEntry>),
    DirectLinks(DirectLinkStatus),
    Resources(Vec<ResourceInfoEntry>),
    InjectPath(bool),
    InjectIdentity(bool),
    RestoreKnownDestination(bool),
    RetainKnownDestination(bool),
    RetainIdentity(bool),
    UnretainKnownDestination(bool),
    MarkKnownDestinationUsed(bool),
    /// List of discovered interfaces.
    DiscoveredInterfaces(Vec<crate::common::discovery::DiscoveredInterface>),
    /// Probe sent: (packet_hash, hops), or why it could not be sent.
    SendProbe(Result<([u8; 32], u8), SendProbeError>),
    /// Proof check: RTT if received, None if still pending.
    CheckProof(Option<f64>),
    /// Runtime-config entries currently supported by the daemon.
    RuntimeConfigList(Vec<RuntimeConfigEntry>),
    /// A specific runtime-config entry, or None if the key is unknown.
    RuntimeConfigEntry(Option<RuntimeConfigEntry>),
    /// Result of setting a runtime-config value.
    RuntimeConfigSet(Result<RuntimeConfigEntry, RuntimeConfigError>),
    /// Result of resetting a runtime-config value.
    RuntimeConfigReset(Result<RuntimeConfigEntry, RuntimeConfigError>),
    /// Live backbone peer state entries.
    BackbonePeerState(Vec<BackbonePeerStateEntry>),
    /// Registered backbone server interfaces.
    BackboneInterfaces(Vec<BackboneInterfaceEntry>),
    /// Live provider-bridge queue/drop state if enabled.
    ProviderBridgeStats(Option<ProviderBridgeStats>),
    /// Current lifecycle/drain status.
    DrainStatus(DrainStatus),
    /// Result of clearing one backbone peer state entry.
    ClearBackbonePeerState(bool),
    /// Result of blacklisting a backbone peer.
    BlacklistBackbonePeer(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceManagementOperation {
    Attach,
    Detach,
    Reload,
}
