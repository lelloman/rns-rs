//! Driver loop: receives events, drives the TransportEngine, dispatches actions.

mod construction;
#[cfg(any(feature = "iface-backbone", feature = "iface-tcp"))]
mod discovery_runtime;
mod folded_state;
mod hook_calls;
#[cfg(feature = "hooks")]
mod hook_support;
mod interface_state;
mod path_responses;
#[cfg(feature = "iface-backbone")]
mod peer_pool;
mod settings;

#[cfg(any(feature = "iface-backbone", feature = "iface-tcp"))]
pub(crate) use discovery_runtime::*;
pub(crate) use folded_state::*;
#[cfg(feature = "hooks")]
pub(crate) use hook_support::*;
pub(crate) use interface_state::*;
pub(crate) use path_responses::*;
#[cfg(feature = "iface-backbone")]
pub use peer_pool::*;

use std::collections::{HashMap, HashSet};
#[cfg(feature = "iface-backbone")]
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type MemoryRollup = (f64, f64, f64, f64, f64, f64, f64, f64);

use rns_core::packet::RawPacket;
use rns_core::transport::announce_verify_queue::{AnnounceVerifyQueue, OverflowPolicy};
use rns_core::transport::tables::PathEntry;
use rns_core::transport::types::{InterfaceId, ReceivedAnnounce, TransportAction, TransportConfig};
use rns_core::transport::TransportEngine;
use rns_crypto::{OsRng, Rng};

#[cfg(feature = "hooks")]
use crate::provider_bridge::ProviderBridge;
use crate::stamper::PathRequestTarget;
#[cfg(feature = "hooks")]
use rns_hooks::{create_hook_slots, EngineAccess, HookContext, HookManager, HookPoint, HookSlot};

#[cfg(feature = "hooks")]
use crate::event::BackbonePeerHookEvent;
#[cfg(feature = "iface-backbone")]
use crate::event::{BackbonePeerPoolMemberStatus, BackbonePeerPoolStatus};
use crate::event::{
    BackbonePeerStateEntry, BlackholeInfo, DrainStatus, Event, EventReceiver,
    InterfaceStatsResponse, KnownDestinationEntry, LifecycleState, LocalDestinationEntry,
    NextHopResponse, PathTableEntry, QueryRequest, QueryResponse, RateTableEntry,
    RuntimeConfigApplyMode, RuntimeConfigEntry, RuntimeConfigError, RuntimeConfigErrorCode,
    RuntimeConfigSource, RuntimeConfigValue, SingleInterfaceStat, TrafficDetail,
};
use crate::holepunch::orchestrator::{HolePunchManager, HolePunchManagerAction};
use crate::ifac;
#[cfg(all(feature = "iface-auto", test))]
use crate::interface::auto::AutoRuntime;
#[cfg(feature = "iface-auto")]
use crate::interface::auto::AutoRuntimeConfigHandle;
#[cfg(feature = "iface-backbone")]
use crate::interface::backbone::{
    start_client_with_ifac, start_retrying_client, BackboneClientConfig, BackboneClientRuntime,
    BackboneClientRuntimeConfigHandle, BackbonePeerStateHandle, BackboneRuntimeConfigHandle,
};
#[cfg(all(feature = "iface-backbone", test))]
use crate::interface::backbone::{BackboneAbuseConfig, BackboneServerRuntime};
#[cfg(all(feature = "iface-i2p", test))]
use crate::interface::i2p::I2pRuntime;
#[cfg(feature = "iface-i2p")]
use crate::interface::i2p::I2pRuntimeConfigHandle;
#[cfg(all(feature = "iface-pipe", test))]
use crate::interface::pipe::PipeRuntime;
#[cfg(feature = "iface-pipe")]
use crate::interface::pipe::PipeRuntimeConfigHandle;
#[cfg(feature = "iface-rnode")]
use crate::interface::rnode::{
    validate_sub_config, RNodeRuntime, RNodeRuntimeConfigHandle, RNodeSubConfig,
};
#[cfg(feature = "iface-tcp")]
use crate::interface::tcp::TcpClientRuntimeConfigHandle;
#[cfg(all(feature = "iface-tcp", test))]
use crate::interface::tcp_server::TcpServerRuntime;
#[cfg(feature = "iface-tcp")]
use crate::interface::tcp_server::TcpServerRuntimeConfigHandle;
#[cfg(all(feature = "iface-udp", test))]
use crate::interface::udp::UdpRuntime;
#[cfg(feature = "iface-udp")]
use crate::interface::udp::UdpRuntimeConfigHandle;
use crate::interface::{InterfaceEntry, InterfaceStats};
use crate::link_manager::{LinkManager, LinkManagerAction};
use crate::time;

const DEFAULT_KNOWN_DESTINATIONS_TTL: f64 = 48.0 * 60.0 * 60.0;
const DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES: usize = 8192;
const DEFAULT_RATE_LIMITER_TTL_SECS: f64 = 48.0 * 60.0 * 60.0;
const DEFAULT_TICK_INTERVAL_MS: u64 = 1000;
const DEFAULT_KNOWN_DESTINATIONS_CLEANUP_INTERVAL_TICKS: u32 = 3600;
const KNOWN_DESTINATION_CLEANUP_BATCH_SIZE: usize = 64;
const DEFAULT_ANNOUNCE_CACHE_CLEANUP_INTERVAL_TICKS: u32 = 3600;
const DEFAULT_ANNOUNCE_CACHE_CLEANUP_BATCH_SIZE: usize = 10_000;
const DEFAULT_DISCOVERY_CLEANUP_INTERVAL_TICKS: u32 = 3600;
const DEFAULT_MANAGEMENT_ANNOUNCE_INTERVAL_SECS: f64 = 3600.0;
const DEFAULT_LINK_TEARDOWN_FLUSH: Duration = Duration::from_millis(150);
const SEND_RETRY_BACKOFF_MIN: Duration = Duration::from_millis(25);
const SEND_RETRY_BACKOFF_MAX: Duration = Duration::from_millis(1000);

/// Default announce-rate controls applied to transport-node interfaces.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AnnounceRateDefaults {
    /// Minimum time between announces from one destination, in seconds; `None` applies no default.
    pub target: Option<f64>,
    /// Extra block time once a destination is blocked, in seconds; used when the interface sets none.
    pub penalty: f64,
    /// Rate violations tolerated before blocking; used when the interface sets none.
    pub grace: u32,
}

impl Default for AnnounceRateDefaults {
    fn default() -> Self {
        Self {
            target: Some(3600.0),
            penalty: 0.0,
            grace: 5,
        }
    }
}

mod announce_check;
mod autoconnect;
mod blackhole;
mod blackhole_updater;
pub(crate) use announce_check::{check_pending_announce, AnnounceCheck};
mod dispatch;
mod events;
mod hook_events;
mod interface_management;
mod lifecycle;
mod link_stamps;
mod queries;
mod resource_preparation;
mod rpc_service;
pub(crate) use rpc_service::{RpcListener, RpcService};
mod runtime_config;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod tick_source;

#[cfg(test)]
pub(crate) mod tests;

fn inject_transport_header(raw: &[u8], next_hop: &[u8; 16]) -> Vec<u8> {
    if raw.len() < 18 {
        return raw.to_vec();
    }

    let new_flags = (rns_core::constants::HEADER_2 << 6)
        | (rns_core::constants::TRANSPORT_TRANSPORT << 4)
        | (raw[0] & 0x0F);

    let mut new_raw = Vec::with_capacity(raw.len() + 16);
    new_raw.push(new_flags);
    new_raw.push(raw[1]);
    new_raw.extend_from_slice(next_hop);
    new_raw.extend_from_slice(&raw[2..]);
    new_raw
}

#[cfg(runtime_config_ifaces)]
fn recover_mutex_guard<'a, T>(mutex: &'a Mutex<T>, label: &str) -> std::sync::MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned mutex: {}", label);
            poisoned.into_inner()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeConfigDefaults {
    pub(crate) tick_interval_ms: u64,
    pub(crate) known_destinations_ttl: f64,
    pub(crate) rate_limiter_ttl_secs: f64,
    pub(crate) known_destinations_cleanup_interval_ticks: u32,
    pub(crate) announce_cache_cleanup_interval_ticks: u32,
    pub(crate) announce_cache_cleanup_batch_size: usize,
    pub(crate) discovery_cleanup_interval_ticks: u32,
    pub(crate) management_announce_interval_secs: f64,
    pub(crate) direct_connect_policy: crate::event::HolePunchPolicy,
    /// `Transport.STAMP_DESTINATIONS` default.
    pub(crate) stamp_destinations: bool,
    /// `Transport.STAMP_PRS` default.
    pub(crate) stamp_path_requests: bool,
    /// `Transport.STAMPS_ENFORCED` default.
    pub(crate) stamps_enforced: bool,
    /// `Transport.LR_STAMPS_ENFORCED` default.
    pub(crate) lr_stamps_enforced: bool,
    /// `Transport.STAMP_LRS` default.
    pub(crate) stamp_link_requests: bool,
    /// `Transport.ALWAYS_STAMP_LRS` default.
    pub(crate) always_stamp_link_requests: bool,
    #[cfg(feature = "hooks")]
    pub(crate) provider_queue_max_events: usize,
    #[cfg(feature = "hooks")]
    pub(crate) provider_queue_max_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IfacRuntimeConfig {
    pub(crate) netname: Option<String>,
    pub(crate) netkey: Option<String>,
    pub(crate) size: usize,
}

impl IfacRuntimeConfig {
    pub(crate) fn from_parts(netname: Option<String>, netkey: Option<String>, size: usize) -> Self {
        Self {
            netname,
            netkey,
            size,
        }
    }
}

/// Packets whose physical-layer readings are kept for queries
/// (`Transport.LOCAL_CLIENT_CACHE_MAXSIZE`).
pub(crate) const PACKET_SIGNAL_CACHE_MAXSIZE: usize = 512;

/// Extract the 16-byte destination hash from a raw packet header.
///
/// HEADER_1 (raw[0] & 0x40 == 0): dest at bytes 2..18
/// HEADER_2 (raw[0] & 0x40 != 0): dest at bytes 18..34 (after transport ID)
#[cfg(any(test, feature = "hooks"))]
fn extract_dest_hash(raw: &[u8]) -> [u8; 16] {
    let mut dest = [0u8; 16];
    if raw.is_empty() {
        return dest;
    }
    let is_header2 = raw[0] & 0x40 != 0;
    let start = if is_header2 { 18 } else { 2 };
    let end = start + 16;
    if raw.len() >= end {
        dest.copy_from_slice(&raw[start..end]);
    }
    dest
}

pub use crate::common::callbacks::Callbacks;

#[derive(Debug, Clone)]
pub(crate) struct KnownDestinationState {
    announced: crate::destination::AnnouncedIdentity,
    was_used: bool,
    last_used_at: Option<f64>,
    retained: bool,
    stamp: Option<[u8; rns_core::constants::STAMP_LENGTH]>,
    stamp_value: rns_core::stamp::StampValue,
    lr_cost: Option<rns_core::stamp::StampCost>,
}

struct KnownDestinationCleanup {
    candidates: Vec<[u8; 16]>,
    cursor: usize,
    started_at: Instant,
    removed: usize,
}

/// Interval of the transport-state snapshot, as the persistence thread keeps.
pub(crate) const TRANSPORT_STATE_PERSIST_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

/// The node's event loop: owns the transport engine and the interfaces,
/// handles each incoming event and carries out the resulting actions.
pub struct Driver {
    resource_preparation: Option<resource_preparation::Worker>,
    pub(crate) tracked_link_send: Option<([u8; 32], crate::link_send::Completion)>,
    pub(crate) pending_link_frames: std::collections::VecDeque<PendingLinkFrame>,
    pub(crate) engine: TransportEngine,
    pub(crate) interfaces: crate::interface::InterfaceMap<InterfaceEntry>,
    /// Parent listener for dynamically spawned interfaces.
    pub(crate) dynamic_interface_parents: HashMap<InterfaceId, InterfaceId>,
    /// Upstream's display names (`str(interface)`) of interfaces whose
    /// name shows more than `{type}[{name}]`: addresses, parents.
    pub(crate) interface_display_names: HashMap<InterfaceId, String>,
    /// Upstream's `interface.name` of spawned interfaces whose upstream
    /// name differs from their own (`Client on {listener}`), reported as
    /// their `short_name`.
    pub(crate) interface_short_names: HashMap<InterfaceId, String>,
    /// Listeners with no interface entry of their own, reported in
    /// interface statistics as upstream lists them.
    pub(crate) listener_stats: Vec<ListenerStat>,
    /// Upstream's `Transport.interfaces` order: by bitrate, recomputed
    /// every `INTERFACE_JOBS_INTERVAL`; interfaces added since are listed
    /// after it.
    pub(crate) interface_priority: Vec<u64>,
    pub(crate) interface_priority_at: f64,
    /// Previous cumulative counters used to calculate current one-second rates.
    pub(crate) traffic_samples: HashMap<InterfaceId, TrafficSample>,
    pub(crate) rng: OsRng,
    pub(crate) rx: EventReceiver,
    pub(crate) callbacks: Box<dyn Callbacks>,
    pub(crate) started: f64,
    pub(crate) lifecycle_state: LifecycleState,
    /// Whether `lifecycle_state` is still `Active`, shared with the node
    /// handle so that each API call can check it without a driver query.
    pub(crate) accepting_work: Arc<AtomicBool>,
    /// This node is a client of a shared instance, which sends the path
    /// requests that rediscover paths for it
    /// (`Transport.owner.is_connected_to_shared_instance`).
    pub(crate) connected_to_shared_instance: bool,
    pub(crate) drain_started_at: Option<Instant>,
    pub(crate) drain_deadline: Option<Instant>,
    pub(crate) listener_controls: Vec<crate::interface::ListenerControl>,
    pub(crate) interface_management: Option<crate::node::InterfaceManagementConfig>,
    pub(crate) managed_interfaces: HashMap<String, ManagedInterface>,
    /// Static interfaces started without interface management, with their
    /// stop controls, so transport can still detach one as upstream's
    /// `_detach_interface(.., internal_forced=True)` does.
    pub(crate) unmanaged_static_interfaces:
        HashMap<InterfaceId, Option<crate::interface::ListenerControl>>,
    pub(crate) retired_interface_parents: HashSet<InterfaceId>,
    /// Writers that may hold frames queued without a wakeup.
    pub(crate) writers_to_wake: Vec<InterfaceId>,
    /// Ingress burst state last published to the event queue, per interface.
    pub(crate) published_ingress_bursts: crate::interface::InterfaceMap<(Option<f64>, Option<f64>)>,
    pub(crate) announce_cache: Option<crate::announce_cache::AnnounceCache>,
    /// Destination hash for rnstransport.tunnel.synthesize (PLAIN).
    pub(crate) tunnel_synth_dest: [u8; 16],
    /// Transport identity (optional, needed for tunnel synthesis).
    pub(crate) transport_identity: Option<rns_crypto::identity::Identity>,
    /// Link manager: handles link lifecycle, request/response.
    pub(crate) link_manager: LinkManager,
    /// Management configuration for ACL checks.
    pub(crate) management_config: crate::management::ManagementConfig,
    /// Last time management announces were emitted.
    pub(crate) last_management_announce: f64,
    /// Whether initial management announce has been sent (delayed 5s after start).
    pub(crate) initial_announce_sent: bool,
    /// Cache of known announced identities and lifecycle state, keyed by destination hash.
    pub(crate) known_destinations: HashMap<[u8; 16], KnownDestinationState>,
    /// Fingerprints of the known destinations as last flushed to storage.
    pub(crate) known_destinations_flushed: HashMap<[u8; 16], u64>,
    /// RSSI, SNR and link quality of the latest packets received on
    /// interfaces that report them (`Transport.local_client_rssi_cache` and
    /// its SNR and Q siblings), oldest first.
    pub(crate) packet_signals: std::collections::VecDeque<([u8; 32], crate::event::PacketSignal)>,
    /// `storage/blackhole`, where the blackhole lists persist; `None` keeps
    /// them in memory only.
    pub(crate) blackhole_dir: Option<std::path::PathBuf>,
    /// Identity hashes of the remote blackhole lists this node subscribes to.
    pub(crate) blackhole_sources: Vec<[u8; 16]>,
    /// Fetches the lists of `blackhole_sources`, when enabled.
    pub(crate) blackhole_updater: Option<blackhole_updater::BlackholeUpdater>,
    /// Network identities whose discovered interfaces are accepted; empty
    /// accepts any (`interface_discovery_sources`).
    pub(crate) interface_discovery_sources: Vec<[u8; 16]>,
    /// The network identity, when one is configured, kept apart from the
    /// transport identity: it signs this node's discovery announces,
    /// decrypts `discovery_encrypt` announces and their own are encrypted
    /// to it. Unless this node is a shared instance client, it also owns
    /// the `rnstransport.network` management destinations.
    pub(crate) network_identity: Option<rns_crypto::identity::Identity>,
    /// The bitrate the shared instance's client interfaces report
    /// (`force_shared_instance_bitrate`).
    pub(crate) forced_local_bitrate: Option<u64>,
    /// Upstream's auto-connecting of discovered interfaces, when
    /// `autoconnect_discovered_interfaces` is set under the upstream policy.
    pub(crate) upstream_autoconnect: Option<autoconnect::UpstreamAutoconnect>,
    /// Store for received remote ratchets, if persistence/use is enabled.
    pub(crate) ratchet_store: Option<Arc<dyn crate::storage::RatchetStore>>,
    /// TTL for received ratchets, in seconds.
    pub(crate) ratchet_expiry_secs: f64,
    /// TTL for known destinations without an active path, in seconds.
    pub(crate) known_destinations_ttl: f64,
    /// Maximum number of retained known destinations.
    pub(crate) known_destinations_max_entries: usize,
    /// TTL for announce rate-limiter entries without an active path, in seconds.
    pub(crate) rate_limiter_ttl_secs: f64,
    /// Destination hash for rnstransport.path.request (PLAIN).
    pub(crate) path_request_dest: [u8; 16],
    /// Proof strategies per destination hash.
    /// Maps dest_hash → (strategy, optional signing identity for generating proofs).
    pub(crate) proof_strategies: HashMap<
        [u8; 16],
        (
            rns_core::types::ProofStrategy,
            Option<rns_crypto::identity::Identity>,
        ),
    >,
    /// Tracked sent packets for proof matching: packet_hash → (dest_hash, sent_time).
    pub(crate) sent_packets: HashMap<[u8; 32], ([u8; 16], f64)>,
    /// The signing keys proofs of tracked sent packets are checked with,
    /// for packets sent with the identity they were encrypted for:
    /// packet_hash → Ed25519 public key bytes.
    pub(crate) sent_packet_keys: HashMap<[u8; 32], [u8; 32]>,
    /// Local destinations whose single packets are delivered decrypted, with
    /// the identity they are decrypted with when they have no ratchets.
    pub(crate) decrypted_destinations: HashMap<[u8; 16], Arc<rns_crypto::identity::Identity>>,
    /// Reused buffer for single-packet proofs the proof pool finished.
    pub(crate) packet_proofs: Vec<crate::common::link_manager::ProofOutcome>,
    /// Reused transport action buffers (see [`crate::action_pool`]).
    pub(crate) transport_actions: crate::action_pool::ActionPool<TransportAction>,
    /// Reused link manager action buffers.
    pub(crate) link_actions: crate::action_pool::ActionPool<LinkManagerAction>,
    /// Completed proofs for probe polling: packet_hash → (rtt_seconds, received_time).
    /// Only probes ([`QueryRequest::SendProbe`]) are recorded: a proof for
    /// every other packet would be kept two minutes for nobody to poll.
    pub(crate) completed_proofs: HashMap<[u8; 32], (f64, f64)>,
    /// Probes sent and not yet proved, whose proofs `completed_proofs`
    /// records.
    pub(crate) pending_probes: std::collections::HashSet<[u8; 32]>,
    /// Parsed signing keys of destinations whose packet proofs were checked.
    /// A destination's hash follows from its identity, so its key never
    /// changes.
    pub(crate) proof_keys: HashMap<[u8; 16], rns_crypto::ed25519::Ed25519PublicKey>,
    /// Locally registered destinations: hash → dest_type.
    pub(crate) local_destinations: HashMap<[u8; 16], u8>,
    /// The built-in destinations links are accepted to (remote management,
    /// the blackhole list, the network identity's): upstream keeps them
    /// inside Transport, so the application never hears of those links.
    pub(crate) builtin_link_destinations: HashSet<[u8; 16]>,
    /// Links established to `builtin_link_destinations`, whose events are
    /// not reported to the callbacks.
    pub(crate) builtin_links: HashSet<[u8; 16]>,
    /// Latest explicit SINGLE announces to replay after shared-client reconnect.
    shared_announces: HashMap<[u8; 16], SharedAnnounceRecord>,
    /// Keys of SINGLE IN destinations registered with their identity, to
    /// answer path requests for them before they announce. A shared client
    /// announces one as a path response when it is registered and again on
    /// reconnect, unless `shared_announces` holds a newer record for it.
    path_responders: HashMap<[u8; 16], PathResponder>,
    /// Path responses of `path_responders` waiting for the stamper to grind
    /// their destination's stamp, sent on `Event::DestinationStampReady`.
    stamp_waiting_path_responses: HashMap<[u8; 16], Vec<WaitingPathResponse>>,
    /// Shared local interfaces that went down and should replay announces on reconnect.
    shared_reconnect_pending: HashMap<InterfaceId, bool>,
    /// Path-response announces recently sent for local destinations, keyed by
    /// (destination, path-request tag), replayed byte-for-byte for a repeated
    /// tag within `LOCAL_PATH_RESPONSE_WINDOW`: (created, raw announce).
    pub(crate) local_path_responses: LocalPathResponseCache,
    /// Hole-punch manager for direct P2P connections.
    pub(crate) holepunch_manager: HolePunchManager,
    /// Event sender for worker threads to send results back to the driver loop.
    pub(crate) event_tx: crate::event::EventSender,
    /// Grinds own path request and announce stamps off the driver thread.
    /// Replaced by the node's shared instance at startup.
    pub(crate) stamper: Arc<crate::stamper::Stamper>,
    /// `Transport.STAMP_DESTINATIONS`, shared with the node handle whose
    /// announce API reads it; settable as `global.stamp_destinations`.
    pub(crate) stamp_destinations: Arc<AtomicBool>,
    /// The `[stamps]` config section this node started with. Link request
    /// stamping reads `stamp_lrs`, `always_stamp_lrs` and `lr_stamp_timeout`
    /// from it; the other
    /// options are applied to the engine, the stamper and the node handle at
    /// startup.
    pub(crate) stamp_settings: crate::config::StampsSection,
    /// Inbound packets whose hop count reaches this limit are dropped and
    /// counted as `hop_limiter_hits` (`Transport.HOP_LIMITER`, set from
    /// `[filter] hop_limiter`).
    pub(crate) hop_limiter: u8,
    /// Maximum queued outbound frames per interface writer worker.
    pub(crate) interface_writer_queue_capacity: usize,
    /// Linux mark inherited by dynamically created IP underlay sockets.
    pub(crate) underlay_mark: Option<u32>,
    /// Default announce-rate controls for interfaces on transport nodes.
    pub(crate) announce_rate_defaults: AnnounceRateDefaults,
    /// Announce rate and cap options from configured interface sections,
    /// by interface name, applied when the interface registers.
    pub(crate) interface_announce_limits: HashMap<String, crate::node::InterfaceAnnounceLimits>,
    /// Default ingress/egress controls for interfaces on transport nodes.
    pub(crate) ingress_control_defaults: rns_core::transport::types::IngressControlConfig,
    /// Shared timer interval used by the node timer thread.
    pub(crate) tick_interval_ms: Arc<AtomicU64>,
    /// Runtime-config handles for backbone server interfaces, keyed by config name.
    #[cfg(feature = "iface-backbone")]
    pub(crate) backbone_runtime: HashMap<String, BackboneRuntimeConfigHandle>,
    /// Live peer-state handles for backbone server interfaces, keyed by config name.
    #[cfg(feature = "iface-backbone")]
    pub(crate) backbone_peer_state: HashMap<String, BackbonePeerStateHandle>,
    /// Runtime-config handles for backbone client interfaces, keyed by config name.
    #[cfg(feature = "iface-backbone")]
    pub(crate) backbone_client_runtime: HashMap<String, BackboneClientRuntimeConfigHandle>,
    /// Runtime-config state for backbone discovery metadata, keyed by config name.
    #[cfg(feature = "iface-backbone")]
    pub(crate) backbone_discovery_runtime: HashMap<String, BackboneDiscoveryRuntimeHandle>,
    /// Ordered outbound Backbone peer pool, if enabled.
    #[cfg(feature = "iface-backbone")]
    backbone_peer_pool: Option<BackbonePeerPool>,
    /// Shared allocator for listener-created and discovery-created dynamic interfaces.
    pub(crate) next_dynamic_interface_id: Arc<AtomicU64>,
    /// Runtime-config handles for TCP server interfaces, keyed by config name.
    #[cfg(feature = "iface-tcp")]
    pub(crate) tcp_server_runtime: HashMap<String, TcpServerRuntimeConfigHandle>,
    /// Runtime-config handles for TCP client interfaces, keyed by config name.
    #[cfg(feature = "iface-tcp")]
    pub(crate) tcp_client_runtime: HashMap<String, TcpClientRuntimeConfigHandle>,
    /// Runtime-config state for TCP server discovery metadata, keyed by config name.
    #[cfg(feature = "iface-tcp")]
    pub(crate) tcp_server_discovery_runtime: HashMap<String, TcpServerDiscoveryRuntimeHandle>,
    /// Runtime-config handles for UDP interfaces, keyed by config name.
    #[cfg(feature = "iface-udp")]
    pub(crate) udp_runtime: HashMap<String, UdpRuntimeConfigHandle>,
    /// Runtime-config handles for Auto interfaces, keyed by config name.
    #[cfg(feature = "iface-auto")]
    pub(crate) auto_runtime: HashMap<String, AutoRuntimeConfigHandle>,
    /// Runtime-config handles for I2P interfaces, keyed by config name.
    #[cfg(feature = "iface-i2p")]
    pub(crate) i2p_runtime: HashMap<String, I2pRuntimeConfigHandle>,
    /// Runtime-config handles for Pipe interfaces, keyed by config name.
    #[cfg(feature = "iface-pipe")]
    pub(crate) pipe_runtime: HashMap<String, PipeRuntimeConfigHandle>,
    /// Runtime-config handles for RNode interfaces, keyed by config name.
    #[cfg(feature = "iface-rnode")]
    pub(crate) rnode_runtime: HashMap<String, RNodeRuntimeConfigHandle>,
    /// Startup/default interface metadata for generic cross-cutting runtime config.
    pub(crate) interface_runtime_defaults:
        HashMap<String, rns_core::transport::types::InterfaceInfo>,
    /// Current IFAC runtime config for static interfaces that support IFAC mutation.
    pub(crate) interface_ifac_runtime: HashMap<String, IfacRuntimeConfig>,
    /// Startup/default IFAC runtime config for static interfaces.
    pub(crate) interface_ifac_runtime_defaults: HashMap<String, IfacRuntimeConfig>,
    /// Storage for discovered interfaces.
    pub(crate) discovered_interfaces: crate::discovery::DiscoveredInterfaceStorage,
    /// Required stamp value for accepting discovered interfaces.
    pub(crate) discovery_required_value: rns_core::stamp::StampCost,
    /// Bounded cache of discovery payloads with previously rejected stamps.
    pub(crate) discovery_stamp_cache: crate::discovery::DiscoveryStampCache,
    /// Name hash for interface discovery announces ("rnstransport.discovery.interface").
    pub(crate) discovery_name_hash: [u8; 10],
    /// Destination hash for the probe responder (if respond_to_probes is enabled).
    pub(crate) probe_responder_hash: Option<[u8; 16]>,
    /// Whether interface discovery is enabled.
    pub(crate) discover_interfaces: bool,
    /// Explicit mode for interfaces created from discovery announces.
    pub(crate) autoconnect_interface_mode: Option<u8>,
    /// Gravity for interfaces created from discovery announces.
    pub(crate) autoconnect_interface_gravity: i64,
    /// Internal announce propagation override for discovered interfaces.
    pub(crate) autoconnect_announces_to_internal: Option<bool>,
    /// Allow auto-connecting discovered interfaces from unverified implementations.
    pub(crate) autoconnect_unverified_implementations: bool,
    /// Announcer for discoverable interfaces (None if nothing to announce).
    pub(crate) interface_announcer: Option<crate::discovery::InterfaceAnnouncer>,
    /// Shared async announce verification queue.
    pub(crate) announce_verify_queue: Arc<Mutex<AnnounceVerifyQueue>>,
    /// Wakes the verification thread when announces are queued.
    pub(crate) announce_verify_signal: Arc<WorkSignal>,
    /// Whether inbound announces should be verified off the driver thread.
    pub(crate) async_announce_verification: bool,
    /// Tick counter for periodic discovery cleanup (every ~3600 ticks = ~1 hour).
    pub(crate) discovery_cleanup_counter: u32,
    /// Runtime-configurable discovery cleanup interval.
    pub(crate) discovery_cleanup_interval_ticks: u32,
    /// Tick counter for periodic MEMSTATS logging (every 300 ticks = ~5 min).
    pub(crate) memory_stats_counter: u32,
    /// When to republish the link/interface statistics snapshot.
    pub(crate) state_snapshot_schedule: crate::state_snapshot::PublishSchedule,
    /// Tick counter for periodic memory/cache cleanup (every ~3600 ticks = ~1 hour).
    pub(crate) cache_cleanup_counter: u32,
    /// Tick counter for incremental announce-cache cleanup scheduling.
    pub(crate) announce_cache_cleanup_counter: u32,
    /// Runtime-configurable cleanup interval for known destinations.
    pub(crate) known_destinations_cleanup_interval_ticks: u32,
    /// Incremental known-destination cleanup pass, if one is active.
    known_destination_cleanup: Option<KnownDestinationCleanup>,
    /// Low-priority ratchet filesystem cleanup associated with the last pass.
    ratchet_cleanup_handle: Option<std::thread::JoinHandle<()>>,
    /// Timers and housekeeping the driver runs itself when they are folded
    /// (see [`crate::engine::FOLD_TIMERS`]).
    pub(crate) folded: FoldedTimers,
    /// The RPC servers, when the driver serves them itself (see
    /// [`crate::engine::FOLD_SERVICES`]).
    pub(crate) rpc_service: Option<rpc_service::RpcService>,
    /// The probe server, when it runs on the driver loop (with services
    /// folded); otherwise the node runs it on a thread of its own.
    pub(crate) probe_server: Option<crate::holepunch::probe::FoldedProbeServer>,
    /// Count of known-destination cap evictions since start.
    pub(crate) known_destinations_cap_evict_count: usize,
    /// Runtime-configurable interval for starting announce cache cleanup.
    pub(crate) announce_cache_cleanup_interval_ticks: u32,
    /// When set, announce cache cleanup is in progress (contains active packet hashes).
    /// Directory iterator for incremental announce cache cleanup.
    /// Running total of files removed during current cache cleanup cycle.
    /// Runtime-configurable announce cache cleanup batch size.
    pub(crate) announce_cache_cleanup_batch_size: usize,
    /// Runtime-configurable management announce interval.
    pub(crate) management_announce_interval_secs: f64,
    /// Startup/default runtime-config values.
    pub(crate) runtime_config_defaults: RuntimeConfigDefaults,
    /// Hook slots for the programmable hook system (one per HookPoint).
    #[cfg(feature = "hooks")]
    pub(crate) hook_slots: [HookSlot; HookPoint::COUNT],
    /// Hook manager. None if initialization failed.
    #[cfg(feature = "hooks")]
    pub(crate) hook_manager: Option<HookManager>,
    #[cfg(feature = "hooks")]
    pub(crate) provider_bridge: Option<ProviderBridge>,
    /// Per hook point count of `Modify` replacements that failed validation
    /// and were therefore treated as `Drop`.
    #[cfg(feature = "hooks")]
    pub(crate) hook_rejected_modifications: [u64; HookPoint::COUNT],
}

pub(crate) struct PendingLinkFrame {
    interface: InterfaceId,
    data: Vec<u8>,
    is_announce: bool,
    completion: Option<crate::link_send::Completion>,
}

/// Wakes a worker thread when there is work for it, or when it should
/// stop, so it sleeps until then instead of polling.
#[derive(Default)]
pub(crate) struct WorkSignal {
    /// Work is pending; the worker is stopped.
    state: Mutex<(bool, bool)>,
    condvar: std::sync::Condvar,
}

impl WorkSignal {
    fn lock(&self) -> std::sync::MutexGuard<'_, (bool, bool)> {
        crate::sync::lock_or_recover(&self.state, "driver state")
    }

    /// There is work.
    pub(crate) fn notify(&self) {
        self.lock().0 = true;
        self.condvar.notify_one();
    }

    /// The worker should stop.
    pub(crate) fn stop(&self) {
        self.lock().1 = true;
        self.condvar.notify_all();
    }

    pub(crate) fn stopped(&self) -> bool {
        self.lock().1
    }

    /// Wait until there is work or the worker should stop, consuming the
    /// notification. Returns `false` once stopped.
    pub(crate) fn wait(&self) -> bool {
        let mut state = self.lock();
        while !state.0 && !state.1 {
            state = self
                .condvar
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        state.0 = false;
        !state.1
    }
}
