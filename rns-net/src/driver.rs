//! Driver loop: receives events, drives the TransportEngine, dispatches actions.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rns_core::packet::RawPacket;
use rns_core::transport::announce_verify_queue::{AnnounceVerifyQueue, OverflowPolicy};
use rns_core::transport::tables::PathEntry;
use rns_core::transport::types::{InterfaceId, TransportAction, TransportConfig};
use rns_core::transport::TransportEngine;
use rns_crypto::{OsRng, Rng};

#[cfg(feature = "hooks")]
use crate::provider_bridge::ProviderBridge;
#[cfg(feature = "hooks")]
use rns_hooks::{create_hook_slots, EngineAccess, HookContext, HookManager, HookPoint, HookSlot};

#[cfg(feature = "hooks")]
use crate::event::BackbonePeerHookEvent;
use crate::event::{
    BackbonePeerPoolMemberStatus, BackbonePeerPoolStatus, BackbonePeerStateEntry, BlackholeInfo,
    DrainStatus, Event, EventReceiver, InterfaceStatsResponse, KnownDestinationEntry,
    LifecycleState, LocalDestinationEntry, NextHopResponse, PathTableEntry, QueryRequest,
    QueryResponse, RateTableEntry, RuntimeConfigApplyMode, RuntimeConfigEntry, RuntimeConfigError,
    RuntimeConfigErrorCode, RuntimeConfigSource, RuntimeConfigValue, SingleInterfaceStat,
};
use crate::holepunch::orchestrator::{HolePunchManager, HolePunchManagerAction};
use crate::ifac;
#[cfg(all(feature = "iface-auto", test))]
use crate::interface::auto::AutoRuntime;
#[cfg(feature = "iface-auto")]
use crate::interface::auto::AutoRuntimeConfigHandle;
#[cfg(feature = "iface-backbone")]
use crate::interface::backbone::{
    start_client, BackboneClientConfig, BackboneClientRuntime, BackboneClientRuntimeConfigHandle,
    BackbonePeerStateHandle, BackboneRuntimeConfigHandle,
};
#[cfg(all(feature = "iface-backbone", target_os = "linux", test))]
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
const DEFAULT_ANNOUNCE_CACHE_CLEANUP_INTERVAL_TICKS: u32 = 3600;
const DEFAULT_ANNOUNCE_CACHE_CLEANUP_BATCH_SIZE: usize = 10_000;
const DEFAULT_DISCOVERY_CLEANUP_INTERVAL_TICKS: u32 = 3600;
const DEFAULT_MANAGEMENT_ANNOUNCE_INTERVAL_SECS: f64 = 300.0;
const DEFAULT_LINK_TEARDOWN_FLUSH: Duration = Duration::from_millis(150);
const SEND_RETRY_BACKOFF_MIN: Duration = Duration::from_millis(25);
const SEND_RETRY_BACKOFF_MAX: Duration = Duration::from_millis(1000);

mod dispatch;
mod events;
mod lifecycle;
mod queries;
mod runtime_config;

#[cfg(test)]
mod tests;

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
    #[cfg(feature = "hooks")]
    pub(crate) provider_queue_max_events: usize,
    #[cfg(feature = "hooks")]
    pub(crate) provider_queue_max_bytes: usize,
}

#[cfg(feature = "iface-backbone")]
#[derive(Debug, Clone)]
pub(crate) struct BackboneDiscoveryRuntime {
    pub(crate) discoverable: bool,
    pub(crate) config: crate::discovery::DiscoveryConfig,
    pub(crate) transport_enabled: bool,
    pub(crate) ifac_netname: Option<String>,
    pub(crate) ifac_netkey: Option<String>,
}

#[cfg(feature = "iface-backbone")]
#[derive(Debug, Clone)]
pub(crate) struct BackboneDiscoveryRuntimeHandle {
    pub(crate) interface_name: String,
    pub(crate) current: BackboneDiscoveryRuntime,
    pub(crate) startup: BackboneDiscoveryRuntime,
}

#[cfg(feature = "iface-tcp")]
#[derive(Debug, Clone)]
pub(crate) struct TcpServerDiscoveryRuntime {
    pub(crate) discoverable: bool,
    pub(crate) config: crate::discovery::DiscoveryConfig,
    pub(crate) transport_enabled: bool,
    pub(crate) ifac_netname: Option<String>,
    pub(crate) ifac_netkey: Option<String>,
}

#[cfg(feature = "iface-tcp")]
#[derive(Debug, Clone)]
pub(crate) struct TcpServerDiscoveryRuntimeHandle {
    pub(crate) interface_name: String,
    pub(crate) current: TcpServerDiscoveryRuntime,
    pub(crate) startup: TcpServerDiscoveryRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IfacRuntimeConfig {
    pub(crate) netname: Option<String>,
    pub(crate) netkey: Option<String>,
    pub(crate) size: usize,
}

#[cfg(feature = "iface-backbone")]
impl BackboneDiscoveryRuntimeHandle {
    pub(crate) fn from_parts(
        interface_name: String,
        startup_config: crate::discovery::DiscoveryConfig,
        transport_enabled: bool,
        ifac_netname: Option<String>,
        ifac_netkey: Option<String>,
        discoverable: bool,
    ) -> Self {
        let startup = BackboneDiscoveryRuntime {
            discoverable,
            config: startup_config,
            transport_enabled,
            ifac_netname,
            ifac_netkey,
        };
        Self {
            interface_name,
            current: startup.clone(),
            startup,
        }
    }
}

#[cfg(feature = "iface-tcp")]
impl TcpServerDiscoveryRuntimeHandle {
    pub(crate) fn from_parts(
        interface_name: String,
        startup_config: crate::discovery::DiscoveryConfig,
        transport_enabled: bool,
        ifac_netname: Option<String>,
        ifac_netkey: Option<String>,
        discoverable: bool,
    ) -> Self {
        let startup = TcpServerDiscoveryRuntime {
            discoverable,
            config: startup_config,
            transport_enabled,
            ifac_netname,
            ifac_netkey,
        };
        Self {
            interface_name,
            current: startup.clone(),
            startup,
        }
    }
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

#[cfg(feature = "iface-backbone")]
#[derive(Debug, Clone)]
pub struct BackbonePeerPoolSettings {
    pub max_connected: usize,
    pub failure_threshold: usize,
    pub failure_window: Duration,
    pub cooldown: Duration,
}

#[cfg(feature = "iface-backbone")]
pub(crate) struct BackbonePeerPoolCandidateConfig {
    pub(crate) client: BackboneClientConfig,
    pub(crate) mode: u8,
    pub(crate) ingress_control: rns_core::transport::types::IngressControlConfig,
    pub(crate) ifac_runtime: IfacRuntimeConfig,
    pub(crate) ifac_enabled: bool,
    pub(crate) interface_type_name: String,
}

#[cfg(feature = "iface-backbone")]
struct BackbonePeerPool {
    settings: BackbonePeerPoolSettings,
    candidates: Vec<BackbonePeerPoolCandidate>,
}

#[cfg(feature = "iface-backbone")]
struct BackbonePeerPoolCandidate {
    config: BackbonePeerPoolCandidateConfig,
    active_id: Option<InterfaceId>,
    failures: Vec<f64>,
    retry_after: Option<f64>,
    cooldown_until: Option<f64>,
    last_error: Option<String>,
}

/// Thin wrapper providing `EngineAccess` for a `TransportEngine` + Driver interfaces.
#[cfg(feature = "hooks")]
struct EngineRef<'a> {
    engine: &'a TransportEngine,
    interfaces: &'a HashMap<InterfaceId, InterfaceEntry>,
    link_manager: &'a LinkManager,
    now: f64,
}

#[cfg(feature = "hooks")]
impl<'a> EngineAccess for EngineRef<'a> {
    fn has_path(&self, dest: &[u8; 16]) -> bool {
        self.engine.has_path(dest)
    }
    fn hops_to(&self, dest: &[u8; 16]) -> Option<u8> {
        self.engine.hops_to(dest)
    }
    fn next_hop(&self, dest: &[u8; 16]) -> Option<[u8; 16]> {
        self.engine.next_hop(dest)
    }
    fn is_blackholed(&self, identity: &[u8; 16]) -> bool {
        self.engine.is_blackholed(identity, self.now)
    }
    fn interface_name(&self, id: u64) -> Option<String> {
        self.interfaces
            .get(&InterfaceId(id))
            .map(|e| e.info.name.clone())
    }
    fn interface_mode(&self, id: u64) -> Option<u8> {
        self.interfaces.get(&InterfaceId(id)).map(|e| e.info.mode)
    }
    fn identity_hash(&self) -> Option<[u8; 16]> {
        self.engine.identity_hash().copied()
    }
    fn announce_rate(&self, id: u64) -> Option<i32> {
        self.interfaces
            .get(&InterfaceId(id))
            .map(|e| (e.stats.outgoing_announce_freq() * 1000.0) as i32)
    }
    fn link_state(&self, link_hash: &[u8; 16]) -> Option<u8> {
        use rns_core::link::types::LinkState;
        self.link_manager.link_state(link_hash).map(|s| match s {
            LinkState::Pending => 0,
            LinkState::Handshake => 1,
            LinkState::Active => 2,
            LinkState::Stale => 3,
            LinkState::Closed => 4,
        })
    }
}

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

/// Execute a hook chain on disjoint Driver fields (avoids &mut self borrow conflict).
#[cfg(feature = "hooks")]
fn run_hook_inner(
    programs: &mut [rns_hooks::LoadedProgram],
    hook_manager: &Option<HookManager>,
    engine_access: &dyn EngineAccess,
    ctx: &HookContext,
    now: f64,
    provider_events_enabled: bool,
) -> Option<rns_hooks::ExecuteResult> {
    if programs.is_empty() {
        return None;
    }
    let mgr = hook_manager.as_ref()?;
    mgr.run_chain_with_provider_events(programs, ctx, engine_access, now, provider_events_enabled)
}

#[cfg(feature = "hooks")]
fn backbone_peer_hook_context(event: &BackbonePeerHookEvent) -> HookContext<'_> {
    HookContext::BackbonePeer {
        server_interface_id: event.server_interface_id.0,
        peer_interface_id: event.peer_interface_id.map(|id| id.0),
        peer_ip: event.peer_ip,
        peer_port: event.peer_port,
        connected_for: event.connected_for,
        had_received_data: event.had_received_data,
        penalty_level: event.penalty_level,
        blacklist_for: event.blacklist_for,
    }
}

/// Convert a Vec of ActionWire into TransportActions for dispatch.
#[cfg(feature = "hooks")]
fn convert_injected_actions(actions: Vec<rns_hooks::ActionWire>) -> Vec<TransportAction> {
    actions
        .into_iter()
        .map(|a| {
            use rns_hooks::ActionWire;
            match a {
                ActionWire::SendOnInterface { interface, raw } => {
                    TransportAction::SendOnInterface {
                        interface: InterfaceId(interface),
                        raw: raw.into(),
                    }
                }
                ActionWire::BroadcastOnAllInterfaces {
                    raw,
                    exclude,
                    has_exclude,
                } => TransportAction::BroadcastOnAllInterfaces {
                    raw: raw.into(),
                    exclude: if has_exclude != 0 {
                        Some(InterfaceId(exclude))
                    } else {
                        None
                    },
                },
                ActionWire::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                    receiving_interface,
                } => TransportAction::DeliverLocal {
                    destination_hash,
                    raw: raw.into(),
                    packet_hash,
                    receiving_interface: InterfaceId(receiving_interface),
                },
                ActionWire::PathUpdated {
                    destination_hash,
                    hops,
                    next_hop,
                    interface,
                } => TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    next_hop,
                    interface: InterfaceId(interface),
                },
                ActionWire::CacheAnnounce { packet_hash, raw } => TransportAction::CacheAnnounce {
                    packet_hash,
                    raw: raw.into(),
                },
                ActionWire::TunnelEstablished {
                    tunnel_id,
                    interface,
                } => TransportAction::TunnelEstablished {
                    tunnel_id,
                    interface: InterfaceId(interface),
                },
                ActionWire::TunnelSynthesize {
                    interface,
                    data,
                    dest_hash,
                } => TransportAction::TunnelSynthesize {
                    interface: InterfaceId(interface),
                    data,
                    dest_hash,
                },
                ActionWire::ForwardToLocalClients {
                    raw,
                    exclude,
                    has_exclude,
                } => TransportAction::ForwardToLocalClients {
                    raw: raw.into(),
                    exclude: if has_exclude != 0 {
                        Some(InterfaceId(exclude))
                    } else {
                        None
                    },
                },
                ActionWire::ForwardPlainBroadcast {
                    raw,
                    to_local,
                    exclude,
                    has_exclude,
                } => TransportAction::ForwardPlainBroadcast {
                    raw: raw.into(),
                    to_local: to_local != 0,
                    exclude: if has_exclude != 0 {
                        Some(InterfaceId(exclude))
                    } else {
                        None
                    },
                },
                ActionWire::AnnounceReceived {
                    destination_hash,
                    identity_hash,
                    public_key,
                    name_hash,
                    random_hash,
                    app_data,
                    hops,
                    receiving_interface,
                } => TransportAction::AnnounceReceived {
                    destination_hash,
                    identity_hash,
                    public_key,
                    name_hash,
                    random_hash,
                    ratchet: None,
                    app_data,
                    hops,
                    receiving_interface: InterfaceId(receiving_interface),
                },
            }
        })
        .collect()
}

/// Infer the interface type string from a dynamic interface's name.
/// Dynamic interfaces (TCP server clients, backbone peers, auto peers, local server clients)
/// include their type in the name prefix set at construction.
fn infer_interface_type(name: &str) -> String {
    if name.starts_with("TCPServerInterface") {
        "TCPServerClientInterface".to_string()
    } else if name.starts_with("BackboneInterface") {
        "BackboneInterface".to_string()
    } else if name.starts_with("LocalInterface") {
        "LocalServerClientInterface".to_string()
    } else {
        // AutoInterface peers use "{group_name}:{peer_addr}" format where
        // group_name is the config section name (typically "AutoInterface" or similar).
        "AutoInterface".to_string()
    }
}

pub use crate::common::callbacks::Callbacks;

#[derive(Clone)]
struct SharedAnnounceRecord {
    name_hash: [u8; 10],
    identity_prv_key: [u8; 64],
    app_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(crate) struct KnownDestinationState {
    announced: crate::destination::AnnouncedIdentity,
    was_used: bool,
    last_used_at: Option<f64>,
    retained: bool,
}

/// The driver loop. Owns the engine and all interface entries.
pub struct Driver {
    pub(crate) engine: TransportEngine,
    pub(crate) interfaces: HashMap<InterfaceId, InterfaceEntry>,
    pub(crate) rng: OsRng,
    pub(crate) rx: EventReceiver,
    pub(crate) callbacks: Box<dyn Callbacks>,
    pub(crate) started: f64,
    pub(crate) lifecycle_state: LifecycleState,
    pub(crate) drain_started_at: Option<Instant>,
    pub(crate) drain_deadline: Option<Instant>,
    pub(crate) listener_controls: Vec<crate::interface::ListenerControl>,
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
    /// Store for received remote ratchets, if persistence/use is enabled.
    pub(crate) ratchet_store: Option<Arc<dyn crate::storage::RatchetStore>>,
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
    /// Completed proofs for probe polling: packet_hash → (rtt_seconds, received_time).
    pub(crate) completed_proofs: HashMap<[u8; 32], (f64, f64)>,
    /// Locally registered destinations: hash → dest_type.
    pub(crate) local_destinations: HashMap<[u8; 16], u8>,
    /// Latest explicit SINGLE announces to replay after shared-client reconnect.
    shared_announces: HashMap<[u8; 16], SharedAnnounceRecord>,
    /// Shared local interfaces that went down and should replay announces on reconnect.
    shared_reconnect_pending: HashMap<InterfaceId, bool>,
    /// Hole-punch manager for direct P2P connections.
    pub(crate) holepunch_manager: HolePunchManager,
    /// Event sender for worker threads to send results back to the driver loop.
    pub(crate) event_tx: crate::event::EventSender,
    /// Maximum queued outbound frames per interface writer worker.
    pub(crate) interface_writer_queue_capacity: usize,
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
    pub(crate) discovery_required_value: u8,
    /// Name hash for interface discovery announces ("rnstransport.discovery.interface").
    pub(crate) discovery_name_hash: [u8; 10],
    /// Destination hash for the probe responder (if respond_to_probes is enabled).
    pub(crate) probe_responder_hash: Option<[u8; 16]>,
    /// Whether interface discovery is enabled.
    pub(crate) discover_interfaces: bool,
    /// Announcer for discoverable interfaces (None if nothing to announce).
    pub(crate) interface_announcer: Option<crate::discovery::InterfaceAnnouncer>,
    /// Shared async announce verification queue.
    pub(crate) announce_verify_queue: Arc<Mutex<AnnounceVerifyQueue>>,
    /// Whether inbound announces should be verified off the driver thread.
    pub(crate) async_announce_verification: bool,
    /// Tick counter for periodic discovery cleanup (every ~3600 ticks = ~1 hour).
    pub(crate) discovery_cleanup_counter: u32,
    /// Runtime-configurable discovery cleanup interval.
    pub(crate) discovery_cleanup_interval_ticks: u32,
    /// Tick counter for periodic MEMSTATS logging (every 300 ticks = ~5 min).
    pub(crate) memory_stats_counter: u32,
    /// Tick counter for periodic memory/cache cleanup (every ~3600 ticks = ~1 hour).
    pub(crate) cache_cleanup_counter: u32,
    /// Tick counter for incremental announce-cache cleanup scheduling.
    pub(crate) announce_cache_cleanup_counter: u32,
    /// Runtime-configurable cleanup interval for known destinations.
    pub(crate) known_destinations_cleanup_interval_ticks: u32,
    /// Count of known-destination cap evictions since start.
    pub(crate) known_destinations_cap_evict_count: usize,
    /// Runtime-configurable interval for starting announce cache cleanup.
    pub(crate) announce_cache_cleanup_interval_ticks: u32,
    /// When set, announce cache cleanup is in progress (contains active packet hashes).
    pub(crate) cache_cleanup_active_hashes: Option<Vec<[u8; 32]>>,
    /// Directory iterator for incremental announce cache cleanup.
    pub(crate) cache_cleanup_entries: Option<std::fs::ReadDir>,
    /// Running total of files removed during current cache cleanup cycle.
    pub(crate) cache_cleanup_removed: usize,
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
}

impl Driver {
    /// Create a new driver.
    pub fn new(
        config: TransportConfig,
        rx: EventReceiver,
        tx: crate::event::EventSender,
        callbacks: Box<dyn Callbacks>,
    ) -> Self {
        let announce_queue_max_entries = config.announce_queue_max_entries;
        let tunnel_synth_dest = rns_core::destination::destination_hash(
            "rnstransport",
            &["tunnel", "synthesize"],
            None,
        );
        let path_request_dest =
            rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
        let discovery_name_hash = crate::discovery::discovery_name_hash();
        let mut engine = TransportEngine::new(config);
        engine.register_destination(tunnel_synth_dest, rns_core::constants::DESTINATION_PLAIN);
        // Register path request destination so inbound path requests are delivered locally
        engine.register_destination(path_request_dest, rns_core::constants::DESTINATION_PLAIN);
        // Note: discovery destination is NOT registered as local — it's a SINGLE destination
        // whose hash depends on the sender's identity. We match it by name_hash instead.
        let mut local_destinations = HashMap::new();
        local_destinations.insert(tunnel_synth_dest, rns_core::constants::DESTINATION_PLAIN);
        local_destinations.insert(path_request_dest, rns_core::constants::DESTINATION_PLAIN);
        let runtime_config_defaults = RuntimeConfigDefaults {
            tick_interval_ms: DEFAULT_TICK_INTERVAL_MS,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            rate_limiter_ttl_secs: DEFAULT_RATE_LIMITER_TTL_SECS,
            known_destinations_cleanup_interval_ticks:
                DEFAULT_KNOWN_DESTINATIONS_CLEANUP_INTERVAL_TICKS,
            announce_cache_cleanup_interval_ticks: DEFAULT_ANNOUNCE_CACHE_CLEANUP_INTERVAL_TICKS,
            announce_cache_cleanup_batch_size: DEFAULT_ANNOUNCE_CACHE_CLEANUP_BATCH_SIZE,
            discovery_cleanup_interval_ticks: DEFAULT_DISCOVERY_CLEANUP_INTERVAL_TICKS,
            management_announce_interval_secs: DEFAULT_MANAGEMENT_ANNOUNCE_INTERVAL_SECS,
            direct_connect_policy: crate::event::HolePunchPolicy::default(),
            #[cfg(feature = "hooks")]
            provider_queue_max_events: crate::provider_bridge::ProviderBridgeConfig::default()
                .queue_max_events,
            #[cfg(feature = "hooks")]
            provider_queue_max_bytes: crate::provider_bridge::ProviderBridgeConfig::default()
                .queue_max_bytes,
        };
        Driver {
            engine,
            interfaces: HashMap::new(),
            rng: OsRng,
            rx,
            callbacks,
            started: time::now(),
            lifecycle_state: LifecycleState::Active,
            drain_started_at: None,
            drain_deadline: None,
            listener_controls: Vec::new(),
            announce_cache: None,
            tunnel_synth_dest,
            transport_identity: None,
            link_manager: LinkManager::new(),
            management_config: Default::default(),
            last_management_announce: 0.0,
            initial_announce_sent: false,
            known_destinations: HashMap::new(),
            ratchet_store: None,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            rate_limiter_ttl_secs: DEFAULT_RATE_LIMITER_TTL_SECS,
            path_request_dest,
            proof_strategies: HashMap::new(),
            sent_packets: HashMap::new(),
            completed_proofs: HashMap::new(),
            local_destinations,
            shared_announces: HashMap::new(),
            shared_reconnect_pending: HashMap::new(),
            holepunch_manager: HolePunchManager::new(
                vec![],
                rns_core::holepunch::ProbeProtocol::Rnsp,
                None,
            ),
            event_tx: tx,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            tick_interval_ms: Arc::new(AtomicU64::new(DEFAULT_TICK_INTERVAL_MS)),
            #[cfg(feature = "iface-backbone")]
            backbone_runtime: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_state: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_client_runtime: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_discovery_runtime: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            #[cfg(feature = "iface-tcp")]
            tcp_server_runtime: HashMap::new(),
            #[cfg(feature = "iface-tcp")]
            tcp_client_runtime: HashMap::new(),
            #[cfg(feature = "iface-tcp")]
            tcp_server_discovery_runtime: HashMap::new(),
            #[cfg(feature = "iface-udp")]
            udp_runtime: HashMap::new(),
            #[cfg(feature = "iface-auto")]
            auto_runtime: HashMap::new(),
            #[cfg(feature = "iface-i2p")]
            i2p_runtime: HashMap::new(),
            #[cfg(feature = "iface-pipe")]
            pipe_runtime: HashMap::new(),
            #[cfg(feature = "iface-rnode")]
            rnode_runtime: HashMap::new(),
            interface_runtime_defaults: HashMap::new(),
            interface_ifac_runtime: HashMap::new(),
            interface_ifac_runtime_defaults: HashMap::new(),
            discovered_interfaces: crate::discovery::DiscoveredInterfaceStorage::new(
                std::env::temp_dir().join("rns-discovered-interfaces"),
            ),
            discovery_required_value: crate::discovery::DEFAULT_STAMP_VALUE,
            discovery_name_hash,
            probe_responder_hash: None,
            discover_interfaces: false,
            interface_announcer: None,
            announce_verify_queue: Arc::new(Mutex::new(AnnounceVerifyQueue::new(
                announce_queue_max_entries,
            ))),
            async_announce_verification: false,
            discovery_cleanup_counter: 0,
            discovery_cleanup_interval_ticks: runtime_config_defaults
                .discovery_cleanup_interval_ticks,
            memory_stats_counter: 0,
            cache_cleanup_counter: 0,
            announce_cache_cleanup_counter: 0,
            known_destinations_cleanup_interval_ticks: runtime_config_defaults
                .known_destinations_cleanup_interval_ticks,
            known_destinations_cap_evict_count: 0,
            announce_cache_cleanup_interval_ticks: runtime_config_defaults
                .announce_cache_cleanup_interval_ticks,
            cache_cleanup_active_hashes: None,
            cache_cleanup_entries: None,
            cache_cleanup_removed: 0,
            announce_cache_cleanup_batch_size: runtime_config_defaults
                .announce_cache_cleanup_batch_size,
            management_announce_interval_secs: runtime_config_defaults
                .management_announce_interval_secs,
            runtime_config_defaults,
            #[cfg(feature = "hooks")]
            hook_slots: create_hook_slots(),
            #[cfg(feature = "hooks")]
            hook_manager: HookManager::new().ok(),
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        }
    }

    pub fn set_announce_verify_queue_config(
        &mut self,
        max_entries: usize,
        max_bytes: usize,
        max_stale_secs: f64,
        overflow_policy: OverflowPolicy,
    ) {
        self.announce_verify_queue = Arc::new(Mutex::new(AnnounceVerifyQueue::with_limits(
            max_entries,
            max_bytes,
            max_stale_secs,
            overflow_policy,
        )));
    }

    fn wrap_interface_writer(
        &self,
        interface_id: InterfaceId,
        interface_name: &str,
        writer: Box<dyn crate::interface::Writer>,
    ) -> (
        Box<dyn crate::interface::Writer>,
        crate::interface::AsyncWriterMetrics,
    ) {
        crate::interface::wrap_async_writer(
            writer,
            interface_id,
            interface_name,
            self.event_tx.clone(),
            self.interface_writer_queue_capacity,
        )
    }

    #[cfg(feature = "hooks")]
    fn provider_events_enabled(&self) -> bool {
        self.provider_bridge.is_some()
    }

    #[cfg(feature = "hooks")]
    fn run_backbone_peer_hook(
        &mut self,
        attach_point: &str,
        point: HookPoint,
        event: &BackbonePeerHookEvent,
    ) {
        let ctx = backbone_peer_hook_context(event);
        let now = time::now();
        let engine_ref = EngineRef {
            engine: &self.engine,
            interfaces: &self.interfaces,
            link_manager: &self.link_manager,
            now,
        };
        let provider_events_enabled = self.provider_events_enabled();
        if let Some(ref e) = run_hook_inner(
            &mut self.hook_slots[point as usize].programs,
            &self.hook_manager,
            &engine_ref,
            &ctx,
            now,
            provider_events_enabled,
        ) {
            self.forward_hook_side_effects(attach_point, e);
        }
    }

    #[cfg(feature = "iface-backbone")]
    fn make_discoverable_interface(
        runtime: &BackboneDiscoveryRuntimeHandle,
    ) -> crate::discovery::DiscoverableInterface {
        crate::discovery::DiscoverableInterface {
            interface_name: runtime.interface_name.clone(),
            config: runtime.current.config.clone(),
            transport_enabled: runtime.current.transport_enabled,
            ifac_netname: runtime.current.ifac_netname.clone(),
            ifac_netkey: runtime.current.ifac_netkey.clone(),
        }
    }

    #[cfg(feature = "iface-backbone")]
    fn sync_backbone_discovery_runtime(
        &mut self,
        interface_name: &str,
    ) -> Result<(), RuntimeConfigError> {
        let handle = self
            .backbone_discovery_runtime
            .get(interface_name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone interface '{}' not found", interface_name),
            })?
            .clone();

        if handle.current.discoverable {
            let iface = Self::make_discoverable_interface(&handle);
            if let Some(announcer) = self.interface_announcer.as_mut() {
                announcer.upsert_interface(iface);
            } else if let Some(identity) = self.transport_identity.as_ref() {
                self.interface_announcer = Some(crate::discovery::InterfaceAnnouncer::new(
                    *identity.hash(),
                    vec![iface],
                ));
            }
        } else if let Some(announcer) = self.interface_announcer.as_mut() {
            announcer.remove_interface(interface_name);
            if announcer.is_empty() {
                self.interface_announcer = None;
            }
        }

        Ok(())
    }

    #[cfg(feature = "iface-tcp")]
    fn make_tcp_server_discoverable_interface(
        runtime: &TcpServerDiscoveryRuntimeHandle,
    ) -> crate::discovery::DiscoverableInterface {
        crate::discovery::DiscoverableInterface {
            interface_name: runtime.interface_name.clone(),
            config: runtime.current.config.clone(),
            transport_enabled: runtime.current.transport_enabled,
            ifac_netname: runtime.current.ifac_netname.clone(),
            ifac_netkey: runtime.current.ifac_netkey.clone(),
        }
    }

    #[cfg(feature = "iface-tcp")]
    fn sync_tcp_server_discovery_runtime(
        &mut self,
        interface_name: &str,
    ) -> Result<(), RuntimeConfigError> {
        let handle = self
            .tcp_server_discovery_runtime
            .get(interface_name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", interface_name),
            })?
            .clone();

        if handle.current.discoverable {
            let iface = Self::make_tcp_server_discoverable_interface(&handle);
            if let Some(announcer) = self.interface_announcer.as_mut() {
                announcer.upsert_interface(iface);
            } else if let Some(identity) = self.transport_identity.as_ref() {
                self.interface_announcer = Some(crate::discovery::InterfaceAnnouncer::new(
                    *identity.hash(),
                    vec![iface],
                ));
            }
        } else if let Some(announcer) = self.interface_announcer.as_mut() {
            announcer.remove_interface(interface_name);
            if announcer.is_empty() {
                self.interface_announcer = None;
            }
        }

        Ok(())
    }

    #[cfg(feature = "hooks")]
    fn update_hook_program<F>(
        &mut self,
        name: &str,
        attach_point: &str,
        mut update: F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut rns_hooks::LoadedProgram),
    {
        let point_idx = crate::config::parse_hook_point(attach_point)
            .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
        let program = self.hook_slots[point_idx]
            .programs
            .iter_mut()
            .find(|program| program.name == name)
            .ok_or_else(|| format!("hook '{}' not found at point '{}'", name, attach_point))?;
        update(program);
        Ok(())
    }

    pub(crate) fn set_tick_interval_handle(&mut self, tick_interval_ms: Arc<AtomicU64>) {
        self.tick_interval_ms = tick_interval_ms;
    }

    pub(crate) fn set_packet_hashlist_max_entries(&mut self, max_entries: usize) {
        self.engine.set_packet_hashlist_max_entries(max_entries);
    }

    #[cfg(feature = "hooks")]
    fn forward_hook_side_effects(&mut self, attach_point: &str, exec: &rns_hooks::ExecuteResult) {
        if !exec.injected_actions.is_empty() {
            self.dispatch_all(convert_injected_actions(exec.injected_actions.clone()));
        }
        if let Some(ref bridge) = self.provider_bridge {
            for event in &exec.provider_events {
                bridge.emit_event(
                    attach_point,
                    event.hook_name.clone(),
                    event.payload_type.clone(),
                    event.payload.clone(),
                );
            }
        }
    }

    #[cfg(feature = "hooks")]
    fn collect_hook_side_effects(
        &mut self,
        attach_point: &str,
        exec: &rns_hooks::ExecuteResult,
        out: &mut Vec<TransportAction>,
    ) {
        if !exec.injected_actions.is_empty() {
            out.extend(convert_injected_actions(exec.injected_actions.clone()));
        }
        if let Some(ref bridge) = self.provider_bridge {
            for event in &exec.provider_events {
                bridge.emit_event(
                    attach_point,
                    event.hook_name.clone(),
                    event.payload_type.clone(),
                    event.payload.clone(),
                );
            }
        }
    }

    /// Set the probe addresses, protocol, and optional device for hole punching.
    pub fn set_probe_config(
        &mut self,
        addrs: Vec<std::net::SocketAddr>,
        protocol: rns_core::holepunch::ProbeProtocol,
        device: Option<String>,
    ) {
        self.holepunch_manager = HolePunchManager::new(addrs, protocol, device);
    }
}
