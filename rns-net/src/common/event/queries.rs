//! Queries to the driver and its answers.

use super::*;

/// A query to the driver, paired with the type of its answer.
///
/// Each query is a struct in [`query`]. It goes to the driver as the
/// [`QueryRequest`] it converts into, and the driver answers with a
/// [`QueryResponse`], out of which [`Query::response`] takes the answer.
/// [`RnsNode::query`](crate::RnsNode::query) does both, so a caller gets
/// the answer's own type and never matches a response.
pub trait Query: Into<QueryRequest> {
    /// The driver's answer.
    type Response;

    /// The answer out of the driver's `response`, or `None` when it
    /// answers another query.
    fn response(response: QueryResponse) -> Option<Self::Response>;
}

/// Defines [`QueryRequest`] and, for each of its variants, the struct of the
/// same name in [`query`] with the variant's fields, and its [`Query`]
/// implementation: the type of the answer, and the pattern that takes it
/// out of a [`QueryResponse`].
macro_rules! queries {
    ($(
        $(#[$meta:meta])*
        $name:ident
        $({ $($(#[$field_meta:meta])* $field:ident: $field_ty:ty),* $(,)? })?
        $(($inner:ty))?
        => $response:ty { $pattern:pat => $answer:expr }
    ),* $(,)?) => {
        /// Queries that can be sent to the driver. Each variant has a struct
        /// of the same name in [`query`], which pairs it with the type of its
        /// answer.
        #[derive(Debug)]
        pub enum QueryRequest {
            $(
                $(#[$meta])*
                $name
                $({ $($(#[$field_meta])* $field: $field_ty),* })?
                $(($inner))?,
            )*
        }

        /// One struct per query to the driver, each a [`Query`] with the
        /// type of its answer.
        pub mod query {
            use super::*;

            $(
                query_struct! {
                    $(#[$meta])*
                    $name
                    $({ $($(#[$field_meta])* $field: $field_ty),* })?
                    $(($inner))?
                }
            )*
        }

        $(
            impl Query for query::$name {
                type Response = $response;

                fn response(response: QueryResponse) -> Option<$response> {
                    match response {
                        $pattern => Some($answer),
                        _ => None,
                    }
                }
            }
        )*
    };
}

/// One query struct of [`queries!`] and its conversion into a
/// [`QueryRequest`].
macro_rules! query_struct {
    ($(#[$meta:meta])* $name:ident { $($(#[$field_meta:meta])* $field:ident: $field_ty:ty),* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name {
            $($(#[$field_meta])* pub $field: $field_ty,)*
        }

        impl From<$name> for QueryRequest {
            fn from(query: $name) -> Self {
                let $name { $($field),* } = query;
                QueryRequest::$name { $($field),* }
            }
        }
    };
    ($(#[$meta:meta])* $name:ident ($inner:ty)) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name(pub $inner);

        impl From<$name> for QueryRequest {
            fn from(query: $name) -> Self {
                QueryRequest::$name(query.0)
            }
        }
    };
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy)]
        pub struct $name;

        impl From<$name> for QueryRequest {
            fn from(_: $name) -> Self {
                QueryRequest::$name
            }
        }
    };
}

queries! {
    /// Attach, detach or reload an interface of the config file
    /// (upstream's interface management).
    ManageInterface {
        /// What to do.
        operation: InterfaceManagementOperation,
        /// The interface's config name, or for a detach the hex id of a
        /// tunnel, naming the interface it runs on.
        name: String,
    } => Option<bool> {
        QueryResponse::InterfaceManagement(result) => result
    },
    /// Get interface statistics and transport info.
    InterfaceStats => InterfaceStatsResponse {
        QueryResponse::InterfaceStats(stats) => stats
    },
    /// Get path table entries, optionally filtered by max hops.
    PathTable {
        /// Leave out paths longer than this many hops.
        max_hops: Option<u8>,
    } => Vec<PathTableEntry> {
        QueryResponse::PathTable(entries) => entries
    },
    /// Get rate table entries.
    RateTable => Vec<RateTableEntry> {
        QueryResponse::RateTable(entries) => entries
    },
    /// Get the slowest positive bitrate among online interfaces.
    LowestInterfaceBitrate => Option<u64> {
        QueryResponse::LowestInterfaceBitrate(bitrate) => bitrate
    },
    /// Estimate an MTU round trip on the slowest interface plus hop grace.
    MediumPathTimeout => f64 {
        QueryResponse::MediumPathTimeout(timeout) => timeout
    },
    /// Estimate the first-hop timeout for a destination using its outbound bitrate.
    FirstHopTimeout {
        /// The destination.
        dest_hash: [u8; 16],
    } => f64 {
        QueryResponse::FirstHopTimeout(timeout) => timeout
    },
    /// Look up the next hop for a destination.
    NextHop {
        /// The destination.
        dest_hash: [u8; 16],
    } => Option<NextHopResponse> {
        QueryResponse::NextHop(next_hop) => next_hop
    },
    /// Look up the next hop interface name for a destination.
    NextHopIfName {
        /// The destination.
        dest_hash: [u8; 16],
    } => Option<String> {
        QueryResponse::NextHopIfName(name) => name
    },
    /// Get link table entry count.
    LinkCount => usize {
        QueryResponse::LinkCount(count) => count
    },
    /// Get validated or established link count.
    ActiveLinkCount => usize {
        QueryResponse::ActiveLinkCount(count) => count
    },
    /// Upstream's `Transport.link_distribution()`.
    LinkDistribution => Vec<LinkDistributionEntry> {
        QueryResponse::LinkDistribution(entries) => entries
    },
    /// Drop a specific path.
    DropPath {
        /// The destination.
        dest_hash: [u8; 16],
    } => bool {
        QueryResponse::DropPath(dropped) => dropped
    },
    /// Drop all paths that route via a given transport hash.
    DropAllVia {
        /// Transport id of the next hop.
        transport_hash: [u8; 16],
    } => usize {
        QueryResponse::DropAllVia(dropped) => dropped
    },
    /// Drop all announce queues.
    DropAnnounceQueues => () {
        QueryResponse::DropAnnounceQueues => ()
    },
    /// Get the transport identity hash.
    TransportIdentity => Option<[u8; 16]> {
        QueryResponse::TransportIdentity(hash) => hash
    },
    /// Snapshot restart-relevant transport routing state.
    TransportStateSnapshot => rns_core::transport::persistence::TransportStateSnapshot {
        QueryResponse::TransportStateSnapshot(snapshot) => snapshot
    },
    /// Get all blackholed identities.
    GetBlackholed => Vec<BlackholeInfo> {
        QueryResponse::Blackholed(entries) => entries
    },
    /// Add an identity to the blackhole list.
    BlackholeIdentity {
        /// The identity's hash.
        identity_hash: [u8; 16],
        /// How long the entry lasts, in hours; forever when `None` or not
        /// positive.
        duration_hours: Option<f64>,
        /// Why it is blackholed.
        reason: Option<String>,
    } => bool {
        QueryResponse::BlackholeResult(added) => added
    },
    /// Remove an identity from the blackhole list.
    UnblackholeIdentity {
        /// The identity's hash.
        identity_hash: [u8; 16],
    } => bool {
        QueryResponse::UnblackholeResult(removed) => removed
    },
    /// `wants_destination_type`: a local application needs announces of
    /// this destination type (upstream 825c2e19).
    WantsDestinationType {
        /// Full name of the destination type, such as `app.aspect`.
        full_name: String,
        /// Who needs it, so each need is withdrawn on its own.
        requester: Vec<u8>,
    } => bool {
        QueryResponse::DestinationTypeRegistration(result) => result
    },
    /// `unwants_destination_type`: withdraw one such need.
    UnwantsDestinationType {
        /// Full name of the destination type.
        full_name: String,
        /// Who registered the need.
        requester: Vec<u8>,
    } => bool {
        QueryResponse::DestinationTypeRegistration(result) => result
    },
    /// `unwants_all_destination_types`: withdraw every need of a requester.
    UnwantsAllDestinationTypes {
        /// Who registered the needs.
        requester: Vec<u8>,
    } => bool {
        QueryResponse::DestinationTypeRegistration(result) => result
    },
    /// `Reticulum.required_announces_only`: let only required destination
    /// types through.
    SetRequiredDestinationsOnly {
        /// Filter announces to required types, or let all through.
        enabled: bool,
    } => bool {
        QueryResponse::DestinationTypeRegistration(result) => result
    },
    /// Check if a path exists to a destination.
    HasPath {
        /// The destination.
        dest_hash: [u8; 16],
    } => bool {
        QueryResponse::HasPath(has_path) => has_path
    },
    /// RSSI, SNR and link quality a received packet arrived with
    /// (`Reticulum.get_packet_rssi`, `get_packet_snr`, `get_packet_q`).
    PacketSignal {
        /// Hash of the received packet.
        packet_hash: [u8; 32],
    } => Option<PacketSignal> {
        QueryResponse::PacketSignal(signal) => signal
    },
    /// Get hop count to a destination.
    HopsTo {
        /// The destination.
        dest_hash: [u8; 16],
    } => Option<u8> {
        QueryResponse::HopsTo(hops) => hops
    },
    /// Recall identity info for a destination.
    RecallIdentity {
        /// The destination.
        dest_hash: [u8; 16],
    } => Option<crate::common::destination::AnnouncedIdentity> {
        QueryResponse::RecallIdentity(identity) => identity
    },
    /// Stamp value and announced link request cost recorded for a known
    /// destination.
    RecallDestinationStamp {
        /// The destination.
        dest_hash: [u8; 16],
    } => Option<DestinationStampInfo> {
        QueryResponse::RecallDestinationStamp(stamp) => stamp
    },
    /// List known-destination lifecycle state.
    KnownDestinations => Vec<KnownDestinationEntry> {
        QueryResponse::KnownDestinations(entries) => entries
    },
    /// The known destinations that changed or went away since the last
    /// committed flush, compared by fingerprint.
    KnownDestinationChanges => (Vec<(KnownDestinationEntry, u64)>, Vec<[u8; 16]>) {
        QueryResponse::KnownDestinationChanges { changed, removed } => (changed, removed)
    },
    /// Record what the known destinations flush stored: entries with their
    /// fingerprints, and removed hashes. `seed` replaces the record, as at
    /// start with what was loaded from storage.
    RecordKnownDestinationFlush {
        /// Destination hashes stored, with their fingerprints.
        stored: Vec<([u8; 16], u64)>,
        /// Destination hashes removed from storage.
        removed: Vec<[u8; 16]>,
        /// Replace the record instead of updating it.
        seed: bool,
    } => () {
        QueryResponse::KnownDestinationFlushRecorded => ()
    },
    /// Get locally registered destinations.
    LocalDestinations => Vec<LocalDestinationEntry> {
        QueryResponse::LocalDestinations(entries) => entries
    },
    /// Get active links.
    Links => Vec<LinkInfoEntry> {
        QueryResponse::Links(links) => links
    },
    /// Get the state of Direct Link: node-wide counters and each link
    /// with Direct Link activity.
    DirectLinks => DirectLinkStatus {
        QueryResponse::DirectLinks(status) => status
    },
    /// Get active resource transfers.
    Resources => Vec<ResourceInfoEntry> {
        QueryResponse::Resources(resources) => resources
    },
    /// Inject a path entry into the path table.
    InjectPath {
        /// The destination.
        dest_hash: [u8; 16],
        /// Transport id of the next hop.
        next_hop: [u8; 16],
        /// Hops to the destination.
        hops: u8,
        /// When the path expires, as Unix time in seconds.
        expires: f64,
        /// Name of the interface the path goes out on; nothing is injected
        /// when no interface has it.
        interface_name: String,
        /// Hash recorded as that of the announce that set the path.
        packet_hash: [u8; 32],
    } => bool {
        QueryResponse::InjectPath(injected) => injected
    },
    /// Inject an identity into the known destinations cache.
    InjectIdentity {
        /// The destination.
        dest_hash: [u8; 16],
        /// Hash of the destination's identity.
        identity_hash: [u8; 16],
        /// The identity's public key (X25519 then Ed25519).
        public_key: [u8; 64],
        /// Application data, as an announce would carry it.
        app_data: Option<Vec<u8>>,
        /// Hops the announce would have come over.
        hops: u8,
        /// When it was received, as Unix time in seconds.
        received_at: f64,
    } => bool {
        QueryResponse::InjectIdentity(injected) => injected
    },
    /// Restore a known destination with full lifecycle state.
    RestoreKnownDestination(KnownDestinationEntry) => bool {
        QueryResponse::RestoreKnownDestination(restored) => restored
    },
    /// Mark a known destination as explicitly retained.
    RetainKnownDestination {
        /// The destination.
        dest_hash: [u8; 16],
    } => bool {
        QueryResponse::RetainKnownDestination(retained) => retained
    },
    /// Mark all known destinations announced by an identity as retained.
    RetainIdentity {
        /// The identity's hash.
        identity_hash: [u8; 16],
    } => bool {
        QueryResponse::RetainIdentity(retained) => retained
    },
    /// Clear the retained flag on a known destination.
    UnretainKnownDestination {
        /// The destination.
        dest_hash: [u8; 16],
    } => bool {
        QueryResponse::UnretainKnownDestination(unretained) => unretained
    },
    /// Mark a known destination as used.
    MarkKnownDestinationUsed {
        /// The destination.
        dest_hash: [u8; 16],
    } => bool {
        QueryResponse::MarkKnownDestinationUsed(marked) => marked
    },
    /// Get discovered interfaces.
    DiscoveredInterfaces {
        /// Only interfaces whose status is available.
        only_available: bool,
        /// Only interfaces of transport nodes.
        only_transport: bool,
    } => Vec<crate::common::discovery::DiscoveredInterface> {
        QueryResponse::DiscoveredInterfaces(interfaces) => interfaces
    },
    /// Send a probe packet to a destination and return (packet_hash, hops).
    SendProbe {
        /// The destination to probe.
        dest_hash: [u8; 16],
        /// Bytes of random payload, at most [`MAX_PROBE_PAYLOAD_SIZE`].
        payload_size: usize,
    } => Result<([u8; 32], u8), SendProbeError> {
        QueryResponse::SendProbe(result) => result
    },
    /// Check if a proof was received for a probe packet.
    CheckProof {
        /// Hash of the probe packet.
        packet_hash: [u8; 32],
    } => Option<f64> {
        QueryResponse::CheckProof(rtt) => rtt
    },
    /// List runtime-config entries currently supported by the daemon.
    ListRuntimeConfig => Vec<RuntimeConfigEntry> {
        QueryResponse::RuntimeConfigList(entries) => entries
    },
    /// Get a single runtime-config entry by key.
    GetRuntimeConfig {
        /// The entry's key.
        key: String,
    } => Option<RuntimeConfigEntry> {
        QueryResponse::RuntimeConfigEntry(entry) => entry
    },
    /// Set a runtime-config value by key.
    SetRuntimeConfig {
        /// The entry's key.
        key: String,
        /// The new value.
        value: RuntimeConfigValue,
    } => Result<RuntimeConfigEntry, RuntimeConfigError> {
        QueryResponse::RuntimeConfigSet(result) => result
    },
    /// Reset a runtime-config value to its startup/default value.
    ResetRuntimeConfig {
        /// The entry's key.
        key: String,
    } => Result<RuntimeConfigEntry, RuntimeConfigError> {
        QueryResponse::RuntimeConfigReset(result) => result
    },
    /// List live backbone peer state, optionally filtered to one interface.
    BackbonePeerState {
        /// Name of the backbone interface; all of them when `None`.
        interface_name: Option<String>,
    } => Vec<BackbonePeerStateEntry> {
        QueryResponse::BackbonePeerState(entries) => entries
    },
    /// List registered backbone server interfaces.
    BackboneInterfaces => Vec<BackboneInterfaceEntry> {
        QueryResponse::BackboneInterfaces(entries) => entries
    },
    /// Report live provider-bridge queue/drop state.
    ProviderBridgeStats => Option<ProviderBridgeStats> {
        QueryResponse::ProviderBridgeStats(stats) => stats
    },
    /// Report current lifecycle/drain status.
    DrainStatus => DrainStatus {
        QueryResponse::DrainStatus(status) => status
    },
    /// Clear live backbone peer state for one interface/IP pair.
    ClearBackbonePeerState {
        /// Name of the backbone interface.
        interface_name: String,
        /// The peer's IP address.
        peer_ip: IpAddr,
    } => bool {
        QueryResponse::ClearBackbonePeerState(cleared) => cleared
    },
    /// Blacklist a backbone peer IP for a duration.
    BlacklistBackbonePeer {
        /// Name of the backbone interface.
        interface_name: String,
        /// The peer's IP address.
        peer_ip: IpAddr,
        /// How long, at most the interface's maximum penalty duration.
        duration: Duration,
        /// Why the peer is blacklisted.
        reason: String,
        /// Penalty level, passed on to the `BackbonePeerPenalty` hook.
        penalty_level: u8,
    } => bool {
        QueryResponse::BlacklistBackbonePeer(blacklisted) => blacklisted
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
    PayloadTooLarge {
        /// The largest payload, in bytes.
        max: usize,
    },
    /// Encrypting the payload to the remote identity failed.
    EncryptFailed,
    /// Packing the probe packet failed.
    PackFailed,
}

/// Responses to queries.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing a variant would change this published response API; one is built per query"
)]
pub enum QueryResponse {
    /// Python-compatible tri-state result: success, failure, or missing name.
    InterfaceManagement(Option<bool>),
    /// Interface statistics and transport totals.
    InterfaceStats(InterfaceStatsResponse),
    /// Path table entries.
    PathTable(Vec<PathTableEntry>),
    /// Announce rate table entries.
    RateTable(Vec<RateTableEntry>),
    /// The slowest positive bitrate, in bits per second, if any.
    LowestInterfaceBitrate(Option<u64>),
    /// The medium path timeout, in seconds; 0 when no bitrate is known.
    MediumPathTimeout(f64),
    /// The first-hop timeout, in seconds.
    FirstHopTimeout(f64),
    /// The next hop, or `None` without a path.
    NextHop(Option<NextHopResponse>),
    /// The next hop interface's `str(interface)`, or `None` without a path.
    NextHopIfName(Option<String>),
    /// Links in the transport link table plus this node's own links.
    LinkCount(usize),
    /// Active links in the transport link table plus this node's own.
    ActiveLinkCount(usize),
    /// Link totals per destination.
    LinkDistribution(Vec<LinkDistributionEntry>),
    /// A path was dropped.
    DropPath(bool),
    /// Number of paths dropped.
    DropAllVia(usize),
    /// The announce queues were dropped.
    DropAnnounceQueues,
    /// The transport identity hash, or `None` without one.
    TransportIdentity(Option<[u8; 16]>),
    /// Transport routing state to persist.
    TransportStateSnapshot(rns_core::transport::persistence::TransportStateSnapshot),
    /// Blackholed identities whose entries have not expired.
    Blackholed(Vec<BlackholeInfo>),
    /// The identity was blackholed; `false` when it already was.
    BlackholeResult(bool),
    /// The blackhole was lifted; `false` when the identity was not
    /// blackholed.
    UnblackholeResult(bool),
    /// Answer to the destination type queries: for `WantsDestinationType`,
    /// `false` when the type is blocked; for `UnwantsDestinationType`,
    /// whether the requester had registered it; otherwise `true`.
    DestinationTypeRegistration(bool),
    /// A path to the destination exists.
    HasPath(bool),
    /// The packet's readings, or `None` when it is not among the packets
    /// recently received.
    PacketSignal(Option<PacketSignal>),
    /// Hops to the destination, or `None` without a path.
    HopsTo(Option<u8>),
    /// The destination's announced identity, if known; recalling it marks
    /// the destination used.
    RecallIdentity(Option<crate::common::destination::AnnouncedIdentity>),
    /// The destination's stamp information, if it is known.
    RecallDestinationStamp(Option<DestinationStampInfo>),
    /// All known destinations, ordered by destination hash.
    KnownDestinations(Vec<KnownDestinationEntry>),
    /// Known destinations changed or removed since the last recorded flush.
    KnownDestinationChanges {
        /// Changed or new entries with their fingerprints.
        changed: Vec<(KnownDestinationEntry, u64)>,
        /// Hashes of flushed destinations that are no longer known.
        removed: Vec<[u8; 16]>,
    },
    /// The flush was recorded.
    KnownDestinationFlushRecorded,
    /// Locally registered destinations.
    LocalDestinations(Vec<LocalDestinationEntry>),
    /// This node's links.
    Links(Vec<LinkInfoEntry>),
    /// The state of Direct Link.
    DirectLinks(DirectLinkStatus),
    /// Resource transfers on this node's links.
    Resources(Vec<ResourceInfoEntry>),
    /// The path was injected; `false` when no interface has the name.
    InjectPath(bool),
    /// The identity was injected.
    InjectIdentity(bool),
    /// The known destination was restored.
    RestoreKnownDestination(bool),
    /// The destination is retained; `false` when it is not known.
    RetainKnownDestination(bool),
    /// At least one known destination of the identity is retained.
    RetainIdentity(bool),
    /// The destination is no longer retained; `false` when it is not known.
    UnretainKnownDestination(bool),
    /// The destination was marked used; `false` when it is not known or is
    /// retained.
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

/// What [`QueryRequest::ManageInterface`] does with an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceManagementOperation {
    /// Start the interface from its section of the config file.
    Attach,
    /// Stop the interface and remove it.
    Detach,
    /// Detach the interface, then attach it again.
    Reload,
}
