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
    NotFound { name: String, point: String },
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
    DriverQueueFull,
    DriverStopped,
    AdmissionTimedOut,
    LinkNotFound,
    LinkNotActive,
    PayloadTooLarge { maximum: usize, actual: usize },
    EncryptionFailed,
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

#[derive(Debug, Clone, Default, PartialEq)]
pub struct InterfaceTelemetry {
    pub cpu_load: Option<f64>,
    pub mem_load: Option<f64>,
    pub switch_id: Option<[u8; 4]>,
    pub endpoint_id: Option<[u8; 8]>,
    pub via_switch_id: Option<[u8; 4]>,
    pub peers: Option<usize>,
    pub rssi: Option<i16>,
    pub snr: Option<f32>,
    pub signal_quality: Option<f64>,
    pub frequency: Option<u32>,
    pub bandwidth: Option<u32>,
    pub txpower: Option<i8>,
    pub spreading_factor: Option<u8>,
    pub coding_rate: Option<u8>,
    pub channel: Option<u32>,
    pub modulation: Option<String>,
    /// Channel and device state an RNode reports; replaces the previous.
    pub radio: Option<crate::common::interface_stats::RadioStats>,
}

#[derive(Debug, Clone)]
pub struct DynamicInterfaceRegistration {
    pub info: InterfaceInfo,
    pub interface_type: String,
    pub parent_id: InterfaceId,
    pub telemetry: InterfaceTelemetry,
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
        interface_id: InterfaceId,
        data: PacketBytes,
        rssi: Option<i16>,
        snr: Option<f32>,
    },
    /// (Internal) An announce was verified off-thread and is ready for driver-side processing.
    AnnounceVerified {
        key: AnnounceVerifyKey,
        validated: Box<ValidatedAnnounce>,
        sig_cache_key: [u8; 32],
    },
    /// (Internal) An announce failed off-thread verification.
    AnnounceVerifyFailed {
        key: AnnounceVerifyKey,
        sig_cache_key: [u8; 32],
    },
    /// An interface came online after (re)connecting.
    /// Carries a new writer if the connection was re-established.
    /// Carries InterfaceInfo if this is a new dynamic interface (e.g. TCP server client).
    InterfaceUp(InterfaceId, Option<W>, Option<Box<InterfaceInfo>>),
    /// Register a dynamic interface with an exact type and parent identity.
    DynamicInterfaceUp {
        id: InterfaceId,
        writer: W,
        registration: Box<DynamicInterfaceRegistration>,
    },
    /// Upstream's names for an interface about to come up through
    /// `InterfaceUp`, which carries none: its `str(interface)` and its
    /// `interface.name`, reported as `name` and `short_name` in interface
    /// statistics. Each, when unset, follows from the interface.
    InterfaceNames {
        id: InterfaceId,
        display_name: Option<String>,
        short_name: Option<String>,
    },
    /// Update optional device/interface telemetry without replacing counters.
    InterfaceTelemetry {
        interface_id: InterfaceId,
        telemetry: Box<InterfaceTelemetry>,
    },
    /// An interface went offline (socket closed, error).
    InterfaceDown(InterfaceId),
    /// Periodic maintenance tick (1s interval).
    Tick,
    /// Enter drain mode and stop admitting new work.
    BeginDrain { timeout: Duration },
    /// Shut down the driver loop.
    Shutdown,
    /// Send an outbound packet.
    SendOutbound {
        raw: Vec<u8>,
        dest_type: u8,
        attached_interface: Option<InterfaceId>,
    },
    /// A single packet to encrypt off the caller's thread and send
    /// (`RnsNode::send_packet_deferred`).
    SendDeferred(Box<DeferredSend>),
    /// Deliver single packets for `dest_hash` decrypted with `identity`
    /// (`RnsNode::deliver_decrypted`).
    DeliverDecrypted {
        dest_hash: [u8; 16],
        identity: Box<rns_crypto::identity::Identity>,
    },
    /// A locally originated packet with transmission completion tracking.
    SendOutboundTracked {
        raw: Vec<u8>,
        dest_type: u8,
        replay: Option<Box<AnnounceReplay>>,
        completion: crate::link_send::Completion,
        /// The signing key of the identity a SINGLE packet was encrypted
        /// for, which its proof is checked with (as upstream's receipt holds
        /// the destination's identity). Proofs of packets sent without one
        /// are checked with the destination's known identity.
        proof_key: Option<[u8; 32]>,
    },
    /// Register a local destination.
    RegisterDestination { dest_hash: [u8; 16], dest_type: u8 },
    /// Remember the latest explicit SINGLE announce for shared-client replay.
    StoreSharedAnnounce {
        dest_hash: [u8; 16],
        name_hash: [u8; 10],
        identity_prv_key: [u8; 64],
        app_data: Option<Vec<u8>>,
    },
    /// Keep the key of a SINGLE IN destination so that a path request for it
    /// can be answered with a fresh announce before it ever announced, as
    /// upstream's `Destination.announce(path_response=True)` does.
    RegisterPathResponder {
        destination: Box<crate::destination::Destination>,
        identity_prv_key: [u8; 64],
    },
    /// Announce a destination of `RegisterPathResponder` as a path
    /// response, sent a moment after its registration, as upstream's
    /// `Transport.register_destination` does on a shared instance client.
    AnnounceRegisteredDestination { dest_hash: [u8; 16] },
    /// Deregister a local destination.
    DeregisterDestination { dest_hash: [u8; 16] },
    /// Deregister a link destination (stop accepting incoming links).
    DeregisterLinkDestination { dest_hash: [u8; 16] },
    /// Query driver state. Response is sent via the provided channel.
    Query(Box<QueryRequest>, mpsc::Sender<QueryResponse>),
    /// Register a link destination (accepts incoming LINKREQUEST).
    RegisterLinkDestination {
        dest_hash: [u8; 16],
        sig_prv_bytes: [u8; 32],
        sig_pub_bytes: [u8; 32],
        resource_strategy: u8,
        max_request_size: Option<usize>,
    },
    /// Register a request handler for a path on established links.
    RegisterRequestHandler {
        path: String,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: Box<ByteRequestHandler>,
    },
    /// Register a request handler that may return resource responses with metadata.
    RegisterRequestHandlerResponse {
        path: String,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: Box<ResponseRequestHandler>,
    },
    /// Register a request handler that sends its response later.
    RegisterDeferredRequestHandler {
        path: String,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: Box<DeferredRequestHandler>,
    },
    /// Create an outbound link. Response sends (link_id) back.
    CreateLink {
        dest_hash: [u8; 16],
        dest_sig_pub_bytes: [u8; 32],
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
    DestinationStampReady { dest_hash: [u8; 16] },
    /// Send a request on an established link.
    SendRequest {
        link_id: [u8; 16],
        path: String,
        data: Vec<u8>,
        max_response_size: Option<usize>,
        /// Fail the request after this many seconds without a response.
        timeout: Option<f64>,
    },
    /// Complete a request previously delivered to a deferred handler.
    SendDeferredResponse {
        link_id: [u8; 16],
        request_id: [u8; 16],
        data: Vec<u8>,
    },
    /// Identify on a link (send identity to remote peer).
    IdentifyOnLink {
        link_id: [u8; 16],
        identity_prv_key: [u8; 64],
    },
    /// Tear down a link.
    TeardownLink { link_id: [u8; 16] },
    /// Wake the driver to consume its private Resource preparation mailbox.
    ResourcePreparationReady,
    /// Internal wakeup for the bounded Resource assembly mailbox.
    ResourceAssemblyReady,
    /// Internal wakeup: link proofs were verified off the driver thread.
    LinkProofsVerified,
    /// Send a resource on a link.
    SendResource {
        link_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        options: crate::resource::ResourceSendOptions,
    },
    /// Send a Resource from a sequential reader without buffering the full payload.
    SendResourceStream {
        link_id: [u8; 16],
        transfer_id: crate::resource::ResourceTransferId,
        reader: Box<dyn Read + Send>,
        declared_length: u64,
        metadata: Option<Vec<u8>>,
        options: crate::resource::ResourceSendOptions,
    },
    /// Set the resource acceptance strategy for a link.
    SetResourceStrategy { link_id: [u8; 16], strategy: u8 },
    /// Select in-memory or disk-backed delivery for independent Resources.
    SetResourceReceiveMode {
        link_id: [u8; 16],
        mode: crate::resource::ResourceReceiveMode,
    },
    /// Select the receive mode links to a destination start with.
    SetLinkDestinationResourceReceiveMode {
        dest_hash: [u8; 16],
        mode: crate::resource::ResourceReceiveMode,
    },
    /// Accept or reject a pending resource (for AcceptApp strategy).
    AcceptResource {
        link_id: [u8; 16],
        resource_hash: Vec<u8>,
        accept: bool,
    },
    /// Send a channel message on a link.
    SendChannelMessage {
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
        response_tx: mpsc::Sender<Result<(), crate::ChannelSendError>>,
    },
    /// Wake the driver after outbound writer capacity changes.
    LinkWriterReady,
    /// Send generic data on a link with transmission completion.
    SendLinkTracked {
        link_id: [u8; 16],
        data: Vec<u8>,
        context: u8,
        completion: crate::link_send::Completion,
    },
    /// Legacy best-effort datagram admission, without transmission completion.
    SendOnLink {
        link_id: [u8; 16],
        data: Vec<u8>,
        context: u8,
        /// Present when the caller needs explicit driver-level admission.
        response_tx: Option<mpsc::Sender<Result<(), LinkDatagramError>>>,
    },
    /// Request a path to a destination from the network.
    RequestPath { dest_hash: [u8; 16] },
    /// Register a proof strategy for a destination.
    RegisterProofStrategy {
        dest_hash: [u8; 16],
        strategy: rns_core::types::ProofStrategy,
        /// Full identity private key (64 bytes) for signing proofs.
        signing_key: Option<[u8; 64]>,
    },
    /// Propose a direct connection to a peer via hole punching.
    ProposeDirectConnect { link_id: [u8; 16] },
    /// Make the link's direct path silently drop all traffic both ways, as
    /// a network that stopped carrying it would. For tests.
    #[doc(hidden)]
    BlackholeDirectPath { link_id: [u8; 16] },
    /// Set the direct-connect policy.
    SetDirectConnectPolicy { policy: HolePunchPolicy },
    /// (Internal) Probe result arrived from a worker thread.
    HolePunchProbeResult {
        link_id: [u8; 16],
        session_id: [u8; 16],
        observed_addr: std::net::SocketAddr,
        socket: std::net::UdpSocket,
        /// The probe server that responded successfully.
        probe_server: std::net::SocketAddr,
    },
    /// (Internal) Probe failed.
    HolePunchProbeFailed {
        link_id: [u8; 16],
        session_id: [u8; 16],
    },
    /// (Internal) A direct interface's path MTU discovery ended with
    /// this MTU.
    DirectPathMtu { interface_id: InterfaceId, mtu: u32 },
    /// An interface's configuration changed (placeholder for future use).
    InterfaceConfigChanged(InterfaceId),
    /// A backbone server accepted a new inbound peer connection.
    BackbonePeerConnected {
        server_interface_id: InterfaceId,
        peer_interface_id: InterfaceId,
        peer_ip: IpAddr,
        peer_port: u16,
    },
    /// A backbone peer connection closed for any reason.
    BackbonePeerDisconnected {
        server_interface_id: InterfaceId,
        peer_interface_id: InterfaceId,
        peer_ip: IpAddr,
        peer_port: u16,
        connected_for: Duration,
        had_received_data: bool,
    },
    /// A backbone peer was disconnected for idling without sending data.
    BackbonePeerIdleTimeout {
        server_interface_id: InterfaceId,
        peer_interface_id: InterfaceId,
        peer_ip: IpAddr,
        peer_port: u16,
        connected_for: Duration,
    },
    /// A backbone peer was disconnected because its writer stalled.
    BackbonePeerWriteStall {
        server_interface_id: InterfaceId,
        peer_interface_id: InterfaceId,
        peer_ip: IpAddr,
        peer_port: u16,
        connected_for: Duration,
    },
    /// A backbone peer IP was penalized due to abusive behavior.
    BackbonePeerPenalty {
        server_interface_id: InterfaceId,
        peer_ip: IpAddr,
        penalty_level: u8,
        blacklist_for: Duration,
    },
    /// Load an in-memory WASM hook at runtime.
    LoadHook {
        name: String,
        wasm_bytes: Vec<u8>,
        attach_point: String,
        priority: i32,
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Load a hook from a server-local filesystem path at runtime.
    LoadHookFile {
        name: String,
        path: String,
        hook_type: String,
        attach_point: String,
        priority: i32,
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Load a registered built-in hook by ID at runtime.
    LoadBuiltinHook {
        name: String,
        builtin_id: String,
        attach_point: String,
        priority: i32,
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Unload a hook at runtime.
    UnloadHook {
        name: String,
        attach_point: String,
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Reload an in-memory WASM hook at runtime (detach + recompile + reattach with same priority).
    ReloadHook {
        name: String,
        attach_point: String,
        wasm_bytes: Vec<u8>,
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Reload a hook from a server-local filesystem path at runtime.
    ReloadHookFile {
        name: String,
        attach_point: String,
        path: String,
        hook_type: String,
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Reload a registered built-in hook by ID at runtime.
    ReloadBuiltinHook {
        name: String,
        attach_point: String,
        builtin_id: String,
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Enable or disable a loaded hook at runtime.
    SetHookEnabled {
        name: String,
        attach_point: String,
        enabled: bool,
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// Update the priority of a loaded hook at runtime.
    SetHookPriority {
        name: String,
        attach_point: String,
        priority: i32,
        response_tx: mpsc::Sender<Result<(), HookOpError>>,
    },
    /// List all loaded hooks.
    ListHooks {
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
