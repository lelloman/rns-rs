//! Event types for the driver loop — generic over the writer type.

mod debug;
mod direct;
mod queries;
mod reports;
mod runtime;
mod stats;

pub use direct::*;
pub use queries::*;
pub use reports::*;
pub use runtime::*;
pub use stats::*;

use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::Duration;

use rns_core::announce::ValidatedAnnounce;
use rns_core::transport::announce_verify_queue::AnnounceVerifyKey;
use rns_core::transport::types::{InterfaceId, InterfaceInfo, PacketBytes};

use crate::common::link_manager::RequestResponse;

/// Identity hash and public key supplied to request callbacks.
pub type RequestRemoteIdentity = ([u8; 16], [u8; 64]);
/// Callback for an immediate byte response.
pub type ByteRequestHandler =
    dyn Fn([u8; 16], &str, &[u8], Option<&RequestRemoteIdentity>) -> Option<Vec<u8>> + Send;
/// Callback for an immediate packet or resource response.
pub type ResponseRequestHandler =
    dyn Fn([u8; 16], &str, &[u8], Option<&RequestRemoteIdentity>) -> Option<RequestResponse> + Send;
/// Callback for an application-managed deferred response.
pub type DeferredRequestHandler =
    dyn Fn([u8; 16], &str, [u8; 16], &[u8], Option<&RequestRemoteIdentity>) + Send;

/// Why loading, reloading, unloading or configuring a hook failed. It
/// displays as the message the RPC and control API report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOpError {
    /// The node was built without hooks.
    NotEnabled,
    /// The node has no hook manager.
    NoManager,
    /// No hook point has this name.
    UnknownPoint(String),
    /// No hook of this name is attached at this point.
    NotFound {
        /// Name of the hook.
        name: String,
        /// Name of the hook point.
        point: String,
    },
    /// The hook type names no backend this node has.
    Backend(String),
    /// The hook's module did not compile.
    Compile(String),
    /// The hook could not be loaded.
    Load(String),
}

impl fmt::Display for HookOpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookOpError::NotEnabled => f.write_str("hooks not enabled"),
            HookOpError::NoManager => f.write_str("hook manager not available"),
            HookOpError::UnknownPoint(point) => write!(f, "unknown hook point '{point}'"),
            HookOpError::NotFound { name, point } => {
                write!(f, "hook '{name}' not found at point '{point}'")
            }
            HookOpError::Backend(error) => f.write_str(error),
            HookOpError::Compile(error) => write!(f, "compile error: {error}"),
            HookOpError::Load(error) => write!(f, "load error: {error}"),
        }
    }
}

impl std::error::Error for HookOpError {}

/// Why a best-effort link datagram could not be admitted by the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkDatagramError {
    /// The driver's event queue was full.
    DriverQueueFull,
    /// The driver has stopped, or is draining.
    DriverStopped,
    /// The driver did not answer within the caller's timeout.
    AdmissionTimedOut,
    /// No link has this id.
    LinkNotFound,
    /// The link is neither active nor stale.
    LinkNotActive,
    /// The payload is larger than the link's MDU.
    PayloadTooLarge {
        /// The link's MDU, in bytes.
        maximum: usize,
        /// Size of the payload, in bytes.
        actual: usize,
    },
    /// Encrypting the payload for the link failed.
    EncryptionFailed,
    /// Packing the link packet failed.
    PacketEncodingFailed,
}

impl fmt::Display for LinkDatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DriverQueueFull => write!(f, "driver queue is full"),
            Self::DriverStopped => write!(f, "driver has stopped"),
            Self::AdmissionTimedOut => write!(f, "driver admission timed out"),
            Self::LinkNotFound => write!(f, "link was not found"),
            Self::LinkNotActive => write!(f, "link is not active"),
            Self::PayloadTooLarge { maximum, actual } => {
                write!(
                    f,
                    "payload is too large ({actual} bytes, maximum {maximum})"
                )
            }
            Self::EncryptionFailed => write!(f, "link encryption failed"),
            Self::PacketEncodingFailed => write!(f, "link packet encoding failed"),
        }
    }
}

impl std::error::Error for LinkDatagramError {}

/// Device and radio readings an interface reports to the driver.
///
/// `cpu_load` to `peers` replace the interface's values each time; the
/// fields after them replace its values only when set.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InterfaceTelemetry {
    /// CPU load of the interface's device, in percent.
    pub cpu_load: Option<f64>,
    /// Memory use of the interface's device, in percent.
    pub mem_load: Option<f64>,
    /// Switch id of a Weave device.
    pub switch_id: Option<[u8; 4]>,
    /// Endpoint id of a Weave device.
    pub endpoint_id: Option<[u8; 8]>,
    /// Switch a Weave peer is reached through.
    pub via_switch_id: Option<[u8; 4]>,
    /// Number of peers a Weave device knows.
    pub peers: Option<usize>,
    /// Received signal strength, in dBm.
    pub rssi: Option<i16>,
    /// Signal-to-noise ratio, in dB.
    pub snr: Option<f32>,
    /// Signal quality in percent, from SNR and spreading factor.
    pub signal_quality: Option<f64>,
    /// Radio frequency, in Hz.
    pub frequency: Option<u32>,
    /// Radio bandwidth, in Hz.
    pub bandwidth: Option<u32>,
    /// Transmit power, in dBm.
    pub txpower: Option<i8>,
    /// LoRa spreading factor.
    pub spreading_factor: Option<u8>,
    /// LoRa coding rate.
    pub coding_rate: Option<u8>,
    /// Radio channel number.
    pub channel: Option<u32>,
    /// Modulation name, such as `LoRa`.
    pub modulation: Option<String>,
    /// Channel and device state an RNode reports; replaces the previous.
    pub radio: Option<crate::common::interface_stats::RadioStats>,
}

/// A spawned interface to register, as `Event::DynamicInterfaceUp`
/// carries it.
#[derive(Debug, Clone)]
pub struct DynamicInterfaceRegistration {
    /// Transport settings of the interface. While the parent is registered,
    /// its mode, gravity, announce, ingress and stamp settings replace these.
    pub info: InterfaceInfo,
    /// Type name reported in interface statistics, such as
    /// `WeaveInterfacePeer`.
    pub interface_type: String,
    /// The interface that spawned this one.
    pub parent_id: InterfaceId,
    /// Readings to start with.
    pub telemetry: InterfaceTelemetry,
    /// IFAC state of the interface; the parent's when `None`.
    pub ifac: Option<crate::ifac::IfacState>,
    /// Upstream's `str(interface)` for this interface, reported as its
    /// `name` in interface statistics; when unset, `{type}[{name}]`.
    pub display_name: Option<String>,
    /// Upstream's `interface.name` for this interface, reported as its
    /// `short_name` in interface statistics; when unset, `info.name`.
    /// Upstream gives spawned interfaces names that need not be unique
    /// (`Client on {listener}`), so it is kept apart from `info.name`.
    pub short_name: Option<String>,
    /// Register the interface offline, and keep it while it is down: it
    /// reconnects on its own, and `InterfaceUp` brings it online each time
    /// it connects. Upstream keeps an initiating `I2PInterfacePeer` this
    /// way, from when its I2P interface starts.
    pub reconnecting: bool,
}

/// Replay metadata carried atomically with an explicit announcement.
#[doc(hidden)]
pub struct AnnounceReplay {
    pub dest_hash: [u8; 16],
    pub name_hash: [u8; 10],
    pub identity_prv_key: [u8; 64],
    pub app_data: Option<Vec<u8>>,
}

/// A single packet queued to be encrypted off the caller's thread.
pub struct DeferredSend {
    pub(crate) ticket: u64,
    pub(crate) destination: [u8; 16],
    /// The destination identity's 64-byte public key.
    pub(crate) public_key: [u8; 64],
    pub(crate) ratchet: Option<[u8; 32]>,
    /// The plaintext, or the payload when `encrypted`.
    pub(crate) data: Vec<u8>,
    /// Encrypted already by the caller: on one CPU, handing encryption to
    /// another thread only adds a context switch.
    pub(crate) encrypted: bool,
}

impl DeferredSend {
    /// The encrypted payload, or `None` when it cannot be encrypted.
    pub(crate) fn run(&self) -> Option<Vec<u8>> {
        if self.encrypted {
            return Some(self.data.clone());
        }
        rns_crypto::identity::Identity::encrypt_for_public_key(
            &self.public_key,
            &self.data,
            self.ratchet.as_ref(),
            &mut rns_crypto::OsRng,
        )
        .ok()
    }
}

/// Events sent to the driver thread.
///
/// `W` is the writer type (e.g. `Box<dyn Writer>` for sync,
/// or a channel sender for async).
// Boxing the large registration variant would change this published event API.
#[allow(clippy::large_enum_variant)]
pub enum Event<W: Send> {
    /// A decoded frame arrived from an interface. Its bytes are shared, so
    /// the packet decoded from them is delivered without copying them.
    Frame {
        /// The interface the frame arrived on.
        interface_id: InterfaceId,
        /// The frame's bytes.
        data: PacketBytes,
        /// Received signal strength in dBm, when the interface reports it.
        rssi: Option<i16>,
        /// Signal-to-noise ratio in dB, when the interface reports it.
        snr: Option<f32>,
    },
    /// (Internal) An announce was verified off-thread and is ready for driver-side processing.
    AnnounceVerified {
        /// The pending announce that was verified.
        key: AnnounceVerifyKey,
        /// The announce, validated.
        validated: Box<ValidatedAnnounce>,
        /// Key of the announce's signature in the signature cache.
        sig_cache_key: [u8; 32],
    },
    /// (Internal) An announce failed off-thread verification.
    AnnounceVerifyFailed {
        /// The pending announce that failed.
        key: AnnounceVerifyKey,
        /// Key of the announce's signature in the signature cache; the
        /// driver does not use it.
        sig_cache_key: [u8; 32],
    },
    /// An interface came online after (re)connecting.
    /// Carries a new writer if the connection was re-established.
    /// Carries InterfaceInfo if this is a new dynamic interface (e.g. TCP server client).
    InterfaceUp(InterfaceId, Option<W>, Option<Box<InterfaceInfo>>),
    /// Register a dynamic interface with an exact type and parent identity.
    DynamicInterfaceUp {
        /// Id of the new interface.
        id: InterfaceId,
        /// Writer for its outbound frames.
        writer: W,
        /// What to register it with.
        registration: Box<DynamicInterfaceRegistration>,
    },
    /// Upstream's names for an interface about to come up through
    /// `InterfaceUp`, which carries none: its `str(interface)` and its
    /// `interface.name`, reported as `name` and `short_name` in interface
    /// statistics. Each, when unset, follows from the interface.
    InterfaceNames {
        /// The interface.
        id: InterfaceId,
        /// Its `str(interface)`.
        display_name: Option<String>,
        /// Its `interface.name`.
        short_name: Option<String>,
    },
    /// Update optional device/interface telemetry without replacing counters.
    InterfaceTelemetry {
        /// The interface the readings are for.
        interface_id: InterfaceId,
        /// The readings.
        telemetry: Box<InterfaceTelemetry>,
    },
    /// An interface went offline (socket closed, error).
    InterfaceDown(InterfaceId),
    /// Periodic maintenance tick (1s interval).
    Tick,
    /// Enter drain mode and stop admitting new work.
    BeginDrain {
        /// How long to drain before the remaining links and resource
        /// transfers are torn down.
        timeout: Duration,
    },
    /// Shut down the driver loop.
    Shutdown,
    /// Send an outbound packet.
    SendOutbound {
        /// The packed packet.
        raw: Vec<u8>,
        /// Type of the packet's destination (`constants::DESTINATION_*`).
        dest_type: u8,
        /// Send on this interface only, when set.
        attached_interface: Option<InterfaceId>,
    },
    /// A single packet to encrypt off the caller's thread and send
    /// (`RnsNode::send_packet_deferred`).
    SendDeferred(Box<DeferredSend>),
    /// Deliver single packets for `dest_hash` decrypted with `identity`
    /// (`RnsNode::deliver_decrypted`).
    DeliverDecrypted {
        /// The destination.
        dest_hash: [u8; 16],
        /// Identity its packets are decrypted with.
        identity: Box<rns_crypto::identity::Identity>,
    },
    /// A locally originated packet with transmission completion tracking.
    SendOutboundTracked {
        /// The packed packet.
        raw: Vec<u8>,
        /// Type of the packet's destination (`constants::DESTINATION_*`).
        dest_type: u8,
        /// Announce to remember for shared-client replay, stored before the
        /// packet is sent.
        replay: Option<Box<AnnounceReplay>>,
        /// Finished with the outcome of the send.
        completion: crate::link_send::Completion,
        /// The signing key of the identity a SINGLE packet was encrypted
        /// for, which its proof is checked with (as upstream's receipt holds
        /// the destination's identity). Proofs of packets sent without one
        /// are checked with the destination's known identity.
        proof_key: Option<[u8; 32]>,
    },
    /// Register a local destination.
    RegisterDestination {
        /// The destination's hash.
        dest_hash: [u8; 16],
        /// Its type (`constants::DESTINATION_*`).
        dest_type: u8,
    },
    /// Remember the latest explicit SINGLE announce for shared-client replay.
    StoreSharedAnnounce {
        /// The destination's hash.
        dest_hash: [u8; 16],
        /// The destination's name hash.
        name_hash: [u8; 10],
        /// Private key of the destination's identity, to sign the replay.
        identity_prv_key: [u8; 64],
        /// Application data the announce carries.
        app_data: Option<Vec<u8>>,
    },
    /// Keep the key of a SINGLE IN destination so that a path request for it
    /// can be answered with a fresh announce before it ever announced, as
    /// upstream's `Destination.announce(path_response=True)` does.
    RegisterPathResponder {
        /// The destination.
        destination: Box<crate::destination::Destination>,
        /// Private key of its identity, to sign the announce.
        identity_prv_key: [u8; 64],
    },
    /// Announce a destination of `RegisterPathResponder` as a path
    /// response, sent a moment after its registration, as upstream's
    /// `Transport.register_destination` does on a shared instance client.
    AnnounceRegisteredDestination {
        /// The destination's hash.
        dest_hash: [u8; 16],
    },
    /// Deregister a local destination.
    DeregisterDestination {
        /// The destination's hash.
        dest_hash: [u8; 16],
    },
    /// Deregister a link destination (stop accepting incoming links).
    DeregisterLinkDestination {
        /// The destination's hash.
        dest_hash: [u8; 16],
    },
    /// Query driver state. Response is sent via the provided channel.
    Query(Box<QueryRequest>, mpsc::Sender<QueryResponse>),
    /// Register a link destination (accepts incoming LINKREQUEST).
    RegisterLinkDestination {
        /// The destination's hash.
        dest_hash: [u8; 16],
        /// The destination's Ed25519 signing key.
        sig_prv_bytes: [u8; 32],
        /// The destination's Ed25519 public key.
        sig_pub_bytes: [u8; 32],
        /// How links to it accept resources: 1 all, 2 as the application
        /// decides, any other value none.
        resource_strategy: u8,
        /// Requests larger than this many bytes are ignored; no limit when
        /// `None`.
        max_request_size: Option<usize>,
    },
    /// Register a request handler for a path on established links.
    RegisterRequestHandler {
        /// The request path it answers.
        path: String,
        /// Identity hashes allowed to make the request; anyone when `None`.
        allowed_list: Option<Vec<[u8; 16]>>,
        /// Called with the link id, path, request data and remote identity;
        /// returns the response, if any.
        handler: Box<ByteRequestHandler>,
    },
    /// Register a request handler that may return resource responses with metadata.
    RegisterRequestHandlerResponse {
        /// The request path it answers.
        path: String,
        /// Identity hashes allowed to make the request; anyone when `None`.
        allowed_list: Option<Vec<[u8; 16]>>,
        /// Called with the link id, path, request data and remote identity;
        /// returns the response, if any.
        handler: Box<ResponseRequestHandler>,
    },
    /// Register a request handler that sends its response later.
    RegisterDeferredRequestHandler {
        /// The request path it answers.
        path: String,
        /// Identity hashes allowed to make the request; anyone when `None`.
        allowed_list: Option<Vec<[u8; 16]>>,
        /// Called with the link id, path, request id, request data and
        /// remote identity; the response follows with `SendDeferredResponse`.
        handler: Box<DeferredRequestHandler>,
    },
    /// Create an outbound link. Response sends (link_id) back.
    CreateLink {
        /// The destination to link to.
        dest_hash: [u8; 16],
        /// The destination's Ed25519 public key.
        dest_sig_pub_bytes: [u8; 32],
        /// Receives the link id, all zeros when no link was created.
        response_tx: mpsc::Sender<[u8; 16]>,
    },
    /// Finish a stamped outbound link whose keys were ground on a helper
    /// thread. Internal to the driver; carries the link request keys and the
    /// original `CreateLink` responder.
    CompleteStampedLink(Box<StampedLinkKeys>),
    /// A path request stamp ground by the stamper worker; the driver builds
    /// and sends the request.
    SendStampedPathRequest(Box<crate::stamper::StampedPathRequest>),
    /// The stamper persisted the stamp of a built-in destination; the
    /// driver sends that destination's announce.
    DestinationStampReady {
        /// The destination whose stamp is ready.
        dest_hash: [u8; 16],
    },
    /// Send a request on an established link.
    SendRequest {
        /// The link to send on.
        link_id: [u8; 16],
        /// The request path.
        path: String,
        /// The request data.
        data: Vec<u8>,
        /// Fail the request when the response is larger than this many
        /// bytes; no limit when `None`.
        max_response_size: Option<usize>,
        /// Fail the request after this many seconds without a response.
        timeout: Option<f64>,
    },
    /// Complete a request previously delivered to a deferred handler.
    SendDeferredResponse {
        /// The link the request came in on.
        link_id: [u8; 16],
        /// The request id the deferred handler was given.
        request_id: [u8; 16],
        /// The response.
        data: Vec<u8>,
    },
    /// Identify on a link (send identity to remote peer).
    IdentifyOnLink {
        /// The link.
        link_id: [u8; 16],
        /// Private key of the identity to reveal.
        identity_prv_key: [u8; 64],
    },
    /// Tear down a link.
    TeardownLink {
        /// The link.
        link_id: [u8; 16],
    },
    /// Wake the driver to consume its private Resource preparation mailbox.
    ResourcePreparationReady,
    /// Internal wakeup for the bounded Resource assembly mailbox.
    ResourceAssemblyReady,
    /// Internal wakeup: link proofs were verified off the driver thread.
    LinkProofsVerified,
    /// Send a resource on a link.
    SendResource {
        /// The link to send on.
        link_id: [u8; 16],
        /// The resource's data.
        data: Vec<u8>,
        /// Metadata sent with the resource.
        metadata: Option<Vec<u8>>,
        /// How to send it.
        options: crate::resource::ResourceSendOptions,
    },
    /// Send a Resource from a sequential reader without buffering the full payload.
    SendResourceStream {
        /// The link to send on.
        link_id: [u8; 16],
        /// Id the transfer is reported under.
        transfer_id: crate::resource::ResourceTransferId,
        /// Source of the resource's data.
        reader: Box<dyn Read + Send>,
        /// Length of the data the reader yields, in bytes.
        declared_length: u64,
        /// Metadata sent with the resource.
        metadata: Option<Vec<u8>>,
        /// How to send it.
        options: crate::resource::ResourceSendOptions,
    },
    /// Set the resource acceptance strategy for a link.
    SetResourceStrategy {
        /// The link.
        link_id: [u8; 16],
        /// 0 accept none, 1 accept all, 2 as the application decides; any
        /// other value accepts none.
        strategy: u8,
    },
    /// Select in-memory or disk-backed delivery for independent Resources.
    SetResourceReceiveMode {
        /// The link.
        link_id: [u8; 16],
        /// The receive mode.
        mode: crate::resource::ResourceReceiveMode,
    },
    /// Select the receive mode links to a destination start with.
    SetLinkDestinationResourceReceiveMode {
        /// The link destination.
        dest_hash: [u8; 16],
        /// The receive mode.
        mode: crate::resource::ResourceReceiveMode,
    },
    /// Accept or reject a pending resource (for AcceptApp strategy).
    AcceptResource {
        /// The link the resource is offered on.
        link_id: [u8; 16],
        /// Hash of the pending resource.
        resource_hash: Vec<u8>,
        /// Accept it, or reject it.
        accept: bool,
    },
    /// Send a channel message on a link.
    SendChannelMessage {
        /// The link to send on.
        link_id: [u8; 16],
        /// The message type.
        msgtype: u16,
        /// The message.
        payload: Vec<u8>,
        /// Receives whether the channel took the message.
        response_tx: mpsc::Sender<Result<(), crate::ChannelSendError>>,
    },
    /// Wake the driver after outbound writer capacity changes.
    LinkWriterReady,
    /// Send generic data on a link with transmission completion.
    SendLinkTracked {
        /// The link to send on.
        link_id: [u8; 16],
        /// The plaintext to send.
        data: Vec<u8>,
        /// The packet context (`constants::CONTEXT_*`).
        context: u8,
        /// Finished with the outcome of the send.
        completion: crate::link_send::Completion,
    },
    /// Legacy best-effort datagram admission, without transmission completion.
    SendOnLink {
        /// The link to send on.
        link_id: [u8; 16],
        /// The plaintext to send.
        data: Vec<u8>,
        /// The packet context (`constants::CONTEXT_*`).
        context: u8,
        /// Present when the caller needs explicit driver-level admission.
        response_tx: Option<mpsc::Sender<Result<(), LinkDatagramError>>>,
    },
    /// Request a path to a destination from the network.
    RequestPath {
        /// The destination.
        dest_hash: [u8; 16],
    },
    /// Register a proof strategy for a destination.
    RegisterProofStrategy {
        /// The destination.
        dest_hash: [u8; 16],
        /// Which received packets to prove.
        strategy: rns_core::types::ProofStrategy,
        /// Full identity private key (64 bytes) for signing proofs.
        signing_key: Option<[u8; 64]>,
    },
    /// Propose a direct connection to a peer via hole punching.
    ProposeDirectConnect {
        /// The link to upgrade.
        link_id: [u8; 16],
    },
    /// Make the link's direct path silently drop all traffic both ways, as
    /// a network that stopped carrying it would. For tests.
    #[doc(hidden)]
    BlackholeDirectPath { link_id: [u8; 16] },
    /// Set the direct-connect policy.
    SetDirectConnectPolicy {
        /// The new policy.
        policy: HolePunchPolicy,
    },
    /// (Internal) Probe result arrived from a worker thread.
    HolePunchProbeResult {
        /// The link being upgraded.
        link_id: [u8; 16],
        /// The upgrade session the probe belongs to.
        session_id: [u8; 16],
        /// This node's address and port as the probe server saw them.
        observed_addr: std::net::SocketAddr,
        /// The UDP socket the probe was sent from.
        socket: std::net::UdpSocket,
        /// The probe server that responded successfully.
        probe_server: std::net::SocketAddr,
    },
    /// (Internal) Probe failed.
    HolePunchProbeFailed {
        /// The link being upgraded.
        link_id: [u8; 16],
        /// The upgrade session the probe belongs to.
        session_id: [u8; 16],
    },
    /// (Internal) A direct interface's path MTU discovery ended with
    /// this MTU.
    DirectPathMtu {
        /// The direct interface.
        interface_id: InterfaceId,
        /// The discovered MTU, in bytes.
        mtu: u32,
    },
    /// An interface's configuration changed (placeholder for future use).
    InterfaceConfigChanged(InterfaceId),
    /// A backbone server accepted a new inbound peer connection.
    BackbonePeerConnected {
        /// The backbone server interface.
        server_interface_id: InterfaceId,
        /// The interface spawned for the peer.
        peer_interface_id: InterfaceId,
        /// The peer's IP address.
        peer_ip: IpAddr,
        /// The peer's port.
        peer_port: u16,
    },
    /// A backbone peer connection closed for any reason.
    BackbonePeerDisconnected {
        /// The backbone server interface.
        server_interface_id: InterfaceId,
        /// The interface spawned for the peer.
        peer_interface_id: InterfaceId,
        /// The peer's IP address.
        peer_ip: IpAddr,
        /// The peer's port.
        peer_port: u16,
        /// How long the connection lasted.
        connected_for: Duration,
        /// The peer sent data before it disconnected.
        had_received_data: bool,
    },
    /// A backbone peer was disconnected for idling without sending data.
    BackbonePeerIdleTimeout {
        /// The backbone server interface.
        server_interface_id: InterfaceId,
        /// The interface spawned for the peer.
        peer_interface_id: InterfaceId,
        /// The peer's IP address.
        peer_ip: IpAddr,
        /// The peer's port.
        peer_port: u16,
        /// How long the connection lasted.
        connected_for: Duration,
    },
    /// A backbone peer was disconnected because its writer stalled.
    BackbonePeerWriteStall {
        /// The backbone server interface.
        server_interface_id: InterfaceId,
        /// The interface spawned for the peer.
        peer_interface_id: InterfaceId,
        /// The peer's IP address.
        peer_ip: IpAddr,
        /// The peer's port.
        peer_port: u16,
        /// How long the connection lasted.
        connected_for: Duration,
    },
    /// A backbone peer IP was penalized due to abusive behavior.
    BackbonePeerPenalty {
        /// The backbone server interface.
        server_interface_id: InterfaceId,
        /// The peer's IP address.
        peer_ip: IpAddr,
        /// Penalty level, passed on to the `BackbonePeerPenalty` hook.
        penalty_level: u8,
        /// How long the IP is blacklisted.
        blacklist_for: Duration,
    },
    /// Load an in-memory WASM hook at runtime.
    LoadHook {
        /// Name of the hook.
        name: String,
        /// The WASM module.
        wasm_bytes: Vec<u8>,
        /// Name of the hook point.
        attach_point: String,
        /// Order among the hooks at the point; higher runs first.
        priority: i32,
        /// Receives the outcome.
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Load a hook from a server-local filesystem path at runtime.
    LoadHookFile {
        /// Name of the hook.
        name: String,
        /// Path of the hook file on the node.
        path: String,
        /// Backend to load the file with.
        hook_type: String,
        /// Name of the hook point.
        attach_point: String,
        /// Order among the hooks at the point; higher runs first.
        priority: i32,
        /// Receives the outcome.
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Load a registered built-in hook by ID at runtime.
    LoadBuiltinHook {
        /// Name of the hook.
        name: String,
        /// Id of the built-in hook.
        builtin_id: String,
        /// Name of the hook point.
        attach_point: String,
        /// Order among the hooks at the point; higher runs first.
        priority: i32,
        /// Receives the outcome.
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Unload a hook at runtime.
    UnloadHook {
        /// Name of the hook.
        name: String,
        /// Name of the hook point.
        attach_point: String,
        /// Receives the outcome.
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Reload an in-memory WASM hook at runtime (detach + recompile + reattach with same priority).
    ReloadHook {
        /// Name of the hook.
        name: String,
        /// Name of the hook point.
        attach_point: String,
        /// The WASM module.
        wasm_bytes: Vec<u8>,
        /// Receives the outcome.
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Reload a hook from a server-local filesystem path at runtime.
    ReloadHookFile {
        /// Name of the hook.
        name: String,
        /// Name of the hook point.
        attach_point: String,
        /// Path of the hook file on the node.
        path: String,
        /// Backend to load the file with.
        hook_type: String,
        /// Receives the outcome.
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Reload a registered built-in hook by ID at runtime.
    ReloadBuiltinHook {
        /// Name of the hook.
        name: String,
        /// Name of the hook point.
        attach_point: String,
        /// Id of the built-in hook.
        builtin_id: String,
        /// Receives the outcome.
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Enable or disable a loaded hook at runtime.
    SetHookEnabled {
        /// Name of the hook.
        name: String,
        /// Name of the hook point.
        attach_point: String,
        /// Run the hook, or skip it.
        enabled: bool,
        /// Receives the outcome.
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Update the priority of a loaded hook at runtime.
    SetHookPriority {
        /// Name of the hook.
        name: String,
        /// Name of the hook point.
        attach_point: String,
        /// The new priority; higher runs first.
        priority: i32,
        /// Receives the outcome.
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// List all loaded hooks.
    ListHooks {
        /// Receives the loaded hooks.
        response_tx: mpsc::Sender<Vec<HookInfo>>,
    },
}

impl<W: Send> Event<W> {
    /// A query for the driver, answered on `response`.
    pub fn query(request: QueryRequest, response: mpsc::Sender<QueryResponse>) -> Self {
        Event::Query(Box::new(request), response)
    }

    /// The request and response channel of a query, or the event itself.
    pub fn into_query(self) -> Result<(QueryRequest, mpsc::Sender<QueryResponse>), Self> {
        match self {
            Event::Query(request, response) => Ok((*request, response)),
            other => Err(other),
        }
    }
}
