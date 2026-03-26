//! Driver loop: receives events, drives the TransportEngine, dispatches actions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rns_core::packet::RawPacket;
use rns_core::transport::announce_verify_queue::{AnnounceVerifyQueue, OverflowPolicy};
use rns_core::transport::tables::PathEntry;
use rns_core::transport::types::{InterfaceId, TransportAction, TransportConfig};
use rns_core::transport::TransportEngine;
use rns_crypto::{OsRng, Rng};

#[cfg(feature = "rns-hooks")]
use crate::provider_bridge::ProviderBridge;
#[cfg(feature = "rns-hooks")]
use rns_hooks::{create_hook_slots, EngineAccess, HookContext, HookManager, HookPoint, HookSlot};

#[cfg(feature = "rns-hooks")]
use crate::event::BackbonePeerHookEvent;
use crate::event::{
    BackbonePeerStateEntry, BlackholeInfo, Event, EventReceiver, InterfaceStatsResponse,
    LocalDestinationEntry, NextHopResponse, PathTableEntry, QueryRequest, QueryResponse,
    RateTableEntry, RuntimeConfigApplyMode, RuntimeConfigEntry, RuntimeConfigError,
    RuntimeConfigErrorCode, RuntimeConfigSource, RuntimeConfigValue, SingleInterfaceStat,
};
use crate::holepunch::orchestrator::{HolePunchManager, HolePunchManagerAction};
use crate::ifac;
#[cfg(all(feature = "iface-auto", test))]
use crate::interface::auto::AutoRuntime;
#[cfg(feature = "iface-auto")]
use crate::interface::auto::AutoRuntimeConfigHandle;
#[cfg(all(feature = "iface-backbone", target_os = "linux", test))]
use crate::interface::backbone::{
    BackboneAbuseConfig, BackboneClientRuntime, BackboneServerRuntime,
};
#[cfg(feature = "iface-backbone")]
use crate::interface::backbone::{
    BackboneClientRuntimeConfigHandle, BackbonePeerStateHandle, BackboneRuntimeConfigHandle,
};
#[cfg(all(feature = "iface-i2p", test))]
use crate::interface::i2p::I2pRuntime;
#[cfg(feature = "iface-i2p")]
use crate::interface::i2p::I2pRuntimeConfigHandle;
#[cfg(all(feature = "iface-pipe", test))]
use crate::interface::pipe::PipeRuntime;
#[cfg(feature = "iface-pipe")]
use crate::interface::pipe::PipeRuntimeConfigHandle;
#[cfg(all(feature = "iface-rnode", test))]
use crate::interface::rnode::RNodeSubConfig;
#[cfg(feature = "iface-rnode")]
use crate::interface::rnode::{validate_sub_config, RNodeRuntime, RNodeRuntimeConfigHandle};
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
const DEFAULT_RATE_LIMITER_TTL_SECS: f64 = 48.0 * 60.0 * 60.0;
const DEFAULT_TICK_INTERVAL_MS: u64 = 1000;
const DEFAULT_KNOWN_DESTINATIONS_CLEANUP_INTERVAL_TICKS: u32 = 3600;
const DEFAULT_ANNOUNCE_CACHE_CLEANUP_INTERVAL_TICKS: u32 = 3600;
const DEFAULT_ANNOUNCE_CACHE_CLEANUP_BATCH_SIZE: usize = 10_000;
const DEFAULT_DISCOVERY_CLEANUP_INTERVAL_TICKS: u32 = 3600;
const DEFAULT_MANAGEMENT_ANNOUNCE_INTERVAL_SECS: f64 = 300.0;
const SEND_RETRY_BACKOFF_MIN: Duration = Duration::from_millis(25);
const SEND_RETRY_BACKOFF_MAX: Duration = Duration::from_millis(1000);

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
    #[cfg(feature = "rns-hooks")]
    pub(crate) provider_queue_max_events: usize,
    #[cfg(feature = "rns-hooks")]
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

/// Thin wrapper providing `EngineAccess` for a `TransportEngine` + Driver interfaces.
#[cfg(feature = "rns-hooks")]
struct EngineRef<'a> {
    engine: &'a TransportEngine,
    interfaces: &'a HashMap<InterfaceId, InterfaceEntry>,
    link_manager: &'a LinkManager,
    now: f64,
}

#[cfg(feature = "rns-hooks")]
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
#[cfg(any(test, feature = "rns-hooks"))]
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
#[cfg(feature = "rns-hooks")]
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

#[cfg(feature = "rns-hooks")]
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
#[cfg(feature = "rns-hooks")]
fn convert_injected_actions(actions: Vec<rns_hooks::ActionWire>) -> Vec<TransportAction> {
    actions
        .into_iter()
        .map(|a| {
            use rns_hooks::ActionWire;
            match a {
                ActionWire::SendOnInterface { interface, raw } => {
                    TransportAction::SendOnInterface {
                        interface: InterfaceId(interface),
                        raw,
                    }
                }
                ActionWire::BroadcastOnAllInterfaces {
                    raw,
                    exclude,
                    has_exclude,
                } => TransportAction::BroadcastOnAllInterfaces {
                    raw,
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
                    raw,
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
                ActionWire::CacheAnnounce { packet_hash, raw } => {
                    TransportAction::CacheAnnounce { packet_hash, raw }
                }
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
                    raw,
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
                    raw,
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

/// The driver loop. Owns the engine and all interface entries.
pub struct Driver {
    pub(crate) engine: TransportEngine,
    pub(crate) interfaces: HashMap<InterfaceId, InterfaceEntry>,
    pub(crate) rng: OsRng,
    pub(crate) rx: EventReceiver,
    pub(crate) callbacks: Box<dyn Callbacks>,
    pub(crate) started: f64,
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
    /// Cache of known announced identities, keyed by destination hash.
    pub(crate) known_destinations: HashMap<[u8; 16], crate::destination::AnnouncedIdentity>,
    /// TTL for known destinations without an active path, in seconds.
    pub(crate) known_destinations_ttl: f64,
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
    /// Hook slots for the WASM hook system (one per HookPoint).
    #[cfg(feature = "rns-hooks")]
    pub(crate) hook_slots: [HookSlot; HookPoint::COUNT],
    /// WASM hook manager (runtime + linker). None if initialization failed.
    #[cfg(feature = "rns-hooks")]
    pub(crate) hook_manager: Option<HookManager>,
    #[cfg(feature = "rns-hooks")]
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
            #[cfg(feature = "rns-hooks")]
            provider_queue_max_events: crate::provider_bridge::ProviderBridgeConfig::default()
                .queue_max_events,
            #[cfg(feature = "rns-hooks")]
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
            announce_cache: None,
            tunnel_synth_dest,
            transport_identity: None,
            link_manager: LinkManager::new(),
            management_config: Default::default(),
            last_management_announce: 0.0,
            initial_announce_sent: false,
            known_destinations: HashMap::new(),
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
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
            tick_interval_ms: Arc::new(AtomicU64::new(DEFAULT_TICK_INTERVAL_MS)),
            #[cfg(feature = "iface-backbone")]
            backbone_runtime: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_state: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_client_runtime: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_discovery_runtime: HashMap::new(),
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
            #[cfg(feature = "rns-hooks")]
            hook_slots: create_hook_slots(),
            #[cfg(feature = "rns-hooks")]
            hook_manager: HookManager::new().ok(),
            #[cfg(feature = "rns-hooks")]
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

    #[cfg(feature = "rns-hooks")]
    fn provider_events_enabled(&self) -> bool {
        self.provider_bridge.is_some()
    }

    #[cfg(feature = "rns-hooks")]
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

    #[cfg(feature = "rns-hooks")]
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

    fn build_shared_announce_raw(
        &mut self,
        dest_hash: &[u8; 16],
        record: &SharedAnnounceRecord,
        path_response: bool,
    ) -> Option<Vec<u8>> {
        let identity = rns_crypto::identity::Identity::from_private_key(&record.identity_prv_key);

        let mut random_hash = [0u8; 10];
        self.rng.fill_bytes(&mut random_hash[..5]);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        random_hash[5..10].copy_from_slice(&now_secs.to_be_bytes()[3..8]);

        let (announce_data, _has_ratchet) = rns_core::announce::AnnounceData::pack(
            &identity,
            dest_hash,
            &record.name_hash,
            &random_hash,
            None,
            record.app_data.as_deref(),
        )
        .ok()?;

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_ANNOUNCE,
        };
        let context = if path_response {
            rns_core::constants::CONTEXT_PATH_RESPONSE
        } else {
            rns_core::constants::CONTEXT_NONE
        };

        rns_core::packet::RawPacket::pack(flags, 0, dest_hash, None, context, &announce_data)
            .ok()
            .map(|packet| packet.raw)
    }

    fn replay_shared_announces(&mut self) {
        let records: Vec<([u8; 16], SharedAnnounceRecord)> = self
            .shared_announces
            .iter()
            .map(|(dest_hash, record)| (*dest_hash, record.clone()))
            .collect();
        for (dest_hash, record) in records {
            if let Some(raw) = self.build_shared_announce_raw(&dest_hash, &record, true) {
                let event = Event::SendOutbound {
                    raw,
                    dest_type: rns_core::constants::DESTINATION_SINGLE,
                    attached_interface: None,
                };
                match event {
                    Event::SendOutbound {
                        raw,
                        dest_type,
                        attached_interface,
                    } => match RawPacket::unpack(&raw) {
                        Ok(packet) => {
                            let actions = self.engine.handle_outbound(
                                &packet,
                                dest_type,
                                attached_interface,
                                time::now(),
                            );
                            self.dispatch_all(actions);
                        }
                        Err(e) => {
                            log::warn!(
                                "Shared announce replay failed for {:02x?}: {:?}",
                                &dest_hash[..4],
                                e
                            );
                        }
                    },
                    _ => unreachable!(),
                }
            }
        }
    }

    fn handle_shared_interface_down(&mut self, id: InterfaceId) {
        let dropped_paths = self.engine.drop_paths_for_interface(id);
        let dropped_reverse = self.engine.drop_reverse_for_interface(id);
        let dropped_links = self.engine.drop_links_for_interface(id);
        self.engine.drop_announce_queues();
        let link_actions = self.link_manager.teardown_all_links();
        self.dispatch_link_actions(link_actions);
        self.shared_reconnect_pending.insert(id, true);
        log::info!(
            "[{}] cleared shared state: {} paths, {} reverse entries, {} transport links",
            id.0,
            dropped_paths,
            dropped_reverse,
            dropped_links
        );
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_runtime(&mut self, handle: BackboneRuntimeConfigHandle) {
        self.backbone_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_peer_state(&mut self, handle: BackbonePeerStateHandle) {
        self.backbone_peer_state
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_client_runtime(
        &mut self,
        handle: BackboneClientRuntimeConfigHandle,
    ) {
        self.backbone_client_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_discovery_runtime(
        &mut self,
        handle: BackboneDiscoveryRuntimeHandle,
    ) {
        self.backbone_discovery_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    fn list_backbone_peer_state(
        &self,
        interface_name: Option<&str>,
    ) -> Vec<BackbonePeerStateEntry> {
        let mut names: Vec<&String> = match interface_name {
            Some(name) => self
                .backbone_peer_state
                .keys()
                .filter(|candidate| candidate.as_str() == name)
                .collect(),
            None => self.backbone_peer_state.keys().collect(),
        };
        names.sort();

        let mut entries = Vec::new();
        for name in names {
            if let Some(handle) = self.backbone_peer_state.get(name) {
                entries.extend(handle.peer_state.lock().unwrap().list(name));
            }
        }
        entries.sort_by(|a, b| {
            a.interface_name
                .cmp(&b.interface_name)
                .then_with(|| a.peer_ip.cmp(&b.peer_ip))
        });
        entries
    }

    #[cfg(feature = "iface-backbone")]
    fn list_backbone_interfaces(&self) -> Vec<crate::event::BackboneInterfaceEntry> {
        let mut entries: Vec<_> = self
            .backbone_peer_state
            .values()
            .map(|handle| crate::event::BackboneInterfaceEntry {
                interface_id: handle.interface_id,
                interface_name: handle.interface_name.clone(),
            })
            .collect();
        entries.sort_by(|a, b| a.interface_name.cmp(&b.interface_name));
        entries
    }

    #[cfg(feature = "iface-backbone")]
    fn clear_backbone_peer_state(
        &mut self,
        interface_name: &str,
        peer_ip: std::net::IpAddr,
    ) -> bool {
        self.backbone_peer_state
            .get(interface_name)
            .map(|handle| handle.peer_state.lock().unwrap().clear(peer_ip))
            .unwrap_or(false)
    }

    fn blacklist_backbone_peer(
        &mut self,
        interface_name: &str,
        peer_ip: std::net::IpAddr,
        duration: std::time::Duration,
        reason: String,
        penalty_level: u8,
    ) -> bool {
        let capped_duration = self
            .backbone_runtime
            .get(interface_name)
            .and_then(|handle| {
                handle
                    .runtime
                    .lock()
                    .ok()
                    .map(|runtime| runtime.abuse.max_penalty_duration)
            })
            .flatten()
            .map(|max| duration.min(max))
            .unwrap_or(duration);
        let Some(handle) = self.backbone_peer_state.get(interface_name) else {
            return false;
        };
        let ok = handle
            .peer_state
            .lock()
            .unwrap()
            .blacklist(peer_ip, capped_duration, reason);
        if ok {
            #[cfg(feature = "rns-hooks")]
            self.run_backbone_peer_hook(
                "BackbonePeerPenalty",
                HookPoint::BackbonePeerPenalty,
                &BackbonePeerHookEvent {
                    server_interface_id: self
                        .interfaces
                        .iter()
                        .find(|(_, entry)| entry.info.name == interface_name)
                        .map(|(id, _)| *id)
                        .unwrap_or(InterfaceId(0)),
                    peer_interface_id: None,
                    peer_ip,
                    peer_port: 0,
                    connected_for: Duration::ZERO,
                    had_received_data: false,
                    penalty_level,
                    blacklist_for: capped_duration,
                },
            );
            #[cfg(not(feature = "rns-hooks"))]
            let _ = (peer_ip, capped_duration, penalty_level);
        }
        ok
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_runtime(&mut self, handle: TcpServerRuntimeConfigHandle) {
        self.tcp_server_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_client_runtime(&mut self, handle: TcpClientRuntimeConfigHandle) {
        self.tcp_client_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_discovery_runtime(
        &mut self,
        handle: TcpServerDiscoveryRuntimeHandle,
    ) {
        self.tcp_server_discovery_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn register_udp_runtime(&mut self, handle: UdpRuntimeConfigHandle) {
        self.udp_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn register_auto_runtime(&mut self, handle: AutoRuntimeConfigHandle) {
        self.auto_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn register_i2p_runtime(&mut self, handle: I2pRuntimeConfigHandle) {
        self.i2p_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn register_pipe_runtime(&mut self, handle: PipeRuntimeConfigHandle) {
        self.pipe_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn register_rnode_runtime(&mut self, handle: RNodeRuntimeConfigHandle) {
        self.rnode_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    pub(crate) fn register_interface_runtime_defaults(
        &mut self,
        info: &rns_core::transport::types::InterfaceInfo,
    ) {
        self.interface_runtime_defaults
            .entry(info.name.clone())
            .or_insert_with(|| info.clone());
    }

    pub(crate) fn register_interface_ifac_runtime(
        &mut self,
        interface_name: &str,
        startup: IfacRuntimeConfig,
    ) {
        self.interface_ifac_runtime_defaults
            .entry(interface_name.to_string())
            .or_insert_with(|| startup.clone());
        self.interface_ifac_runtime
            .entry(interface_name.to_string())
            .or_insert(startup);
    }

    fn runtime_config_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let defaults = self.runtime_config_defaults;
        let make_entry = |key: &str,
                          value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          apply_mode: RuntimeConfigApplyMode,
                          description: &str| RuntimeConfigEntry {
            key: key.to_string(),
            source: if value == default {
                RuntimeConfigSource::Startup
            } else {
                RuntimeConfigSource::RuntimeOverride
            },
            value,
            default,
            apply_mode,
            description: Some(description.to_string()),
        };

        match key {
            "global.tick_interval_ms" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.tick_interval_ms.load(Ordering::Relaxed) as i64),
                RuntimeConfigValue::Int(defaults.tick_interval_ms as i64),
                RuntimeConfigApplyMode::Immediate,
                "Driver tick interval in milliseconds.",
            )),
            "global.known_destinations_ttl_secs" => Some(make_entry(
                key,
                RuntimeConfigValue::Float(self.known_destinations_ttl),
                RuntimeConfigValue::Float(defaults.known_destinations_ttl),
                RuntimeConfigApplyMode::Immediate,
                "TTL for known destinations without an active path.",
            )),
            "global.rate_limiter_ttl_secs" => Some(make_entry(
                key,
                RuntimeConfigValue::Float(self.rate_limiter_ttl_secs),
                RuntimeConfigValue::Float(defaults.rate_limiter_ttl_secs),
                RuntimeConfigApplyMode::Immediate,
                "TTL for announce rate-limiter entries without an active path.",
            )),
            "global.known_destinations_cleanup_interval_ticks" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.known_destinations_cleanup_interval_ticks as i64),
                RuntimeConfigValue::Int(defaults.known_destinations_cleanup_interval_ticks as i64),
                RuntimeConfigApplyMode::Immediate,
                "Tick interval between known-destinations cleanup passes.",
            )),
            "global.announce_cache_cleanup_interval_ticks" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.announce_cache_cleanup_interval_ticks as i64),
                RuntimeConfigValue::Int(defaults.announce_cache_cleanup_interval_ticks as i64),
                RuntimeConfigApplyMode::Immediate,
                "Tick interval between announce-cache cleanup cycles.",
            )),
            "global.announce_cache_cleanup_batch_size" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.announce_cache_cleanup_batch_size as i64),
                RuntimeConfigValue::Int(defaults.announce_cache_cleanup_batch_size as i64),
                RuntimeConfigApplyMode::Immediate,
                "Number of announce-cache entries processed per cleanup tick.",
            )),
            "global.discovery_cleanup_interval_ticks" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.discovery_cleanup_interval_ticks as i64),
                RuntimeConfigValue::Int(defaults.discovery_cleanup_interval_ticks as i64),
                RuntimeConfigApplyMode::Immediate,
                "Tick interval between discovered-interface cleanup passes.",
            )),
            "global.management_announce_interval_secs" => Some(make_entry(
                key,
                RuntimeConfigValue::Float(self.management_announce_interval_secs),
                RuntimeConfigValue::Float(defaults.management_announce_interval_secs),
                RuntimeConfigApplyMode::Immediate,
                "Interval between management announces in seconds.",
            )),
            "global.direct_connect_policy" => Some(make_entry(
                key,
                RuntimeConfigValue::String(Self::holepunch_policy_name(
                    self.holepunch_manager.policy(),
                )),
                RuntimeConfigValue::String(Self::holepunch_policy_name(
                    defaults.direct_connect_policy,
                )),
                RuntimeConfigApplyMode::Immediate,
                "Policy for incoming direct-connect proposals.",
            )),
            #[cfg(feature = "rns-hooks")]
            "provider.queue_max_events" => {
                let value = self
                    .provider_bridge
                    .as_ref()
                    .map(|b| b.queue_max_events())
                    .unwrap_or(defaults.provider_queue_max_events);
                Some(make_entry(
                    key,
                    RuntimeConfigValue::Int(value as i64),
                    RuntimeConfigValue::Int(defaults.provider_queue_max_events as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Max queued events in the provider bridge.",
                ))
            }
            #[cfg(feature = "rns-hooks")]
            "provider.queue_max_bytes" => {
                let value = self
                    .provider_bridge
                    .as_ref()
                    .map(|b| b.queue_max_bytes())
                    .unwrap_or(defaults.provider_queue_max_bytes);
                Some(make_entry(
                    key,
                    RuntimeConfigValue::Int(value as i64),
                    RuntimeConfigValue::Int(defaults.provider_queue_max_bytes as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Max queued bytes in the provider bridge.",
                ))
            }
            _ => {
                #[cfg(feature = "iface-backbone")]
                if let Some(entry) = self.backbone_runtime_entry(key) {
                    return Some(entry);
                }
                #[cfg(feature = "iface-backbone")]
                if let Some(entry) = self.backbone_client_runtime_entry(key) {
                    return Some(entry);
                }
                #[cfg(feature = "iface-tcp")]
                if let Some(entry) = self.tcp_server_runtime_entry(key) {
                    return Some(entry);
                }
                #[cfg(feature = "iface-tcp")]
                if let Some(entry) = self.tcp_client_runtime_entry(key) {
                    return Some(entry);
                }
                #[cfg(feature = "iface-udp")]
                if let Some(entry) = self.udp_runtime_entry(key) {
                    return Some(entry);
                }
                #[cfg(feature = "iface-auto")]
                if let Some(entry) = self.auto_runtime_entry(key) {
                    return Some(entry);
                }
                #[cfg(feature = "iface-i2p")]
                if let Some(entry) = self.i2p_runtime_entry(key) {
                    return Some(entry);
                }
                #[cfg(feature = "iface-pipe")]
                if let Some(entry) = self.pipe_runtime_entry(key) {
                    return Some(entry);
                }
                #[cfg(feature = "iface-rnode")]
                if let Some(entry) = self.rnode_runtime_entry(key) {
                    return Some(entry);
                }
                if let Some(entry) = self.generic_interface_runtime_entry(key) {
                    return Some(entry);
                }
                None
            }
        }
    }

    fn list_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries: Vec<RuntimeConfigEntry> = [
            "global.tick_interval_ms",
            "global.known_destinations_ttl_secs",
            "global.rate_limiter_ttl_secs",
            "global.known_destinations_cleanup_interval_ticks",
            "global.announce_cache_cleanup_interval_ticks",
            "global.announce_cache_cleanup_batch_size",
            "global.discovery_cleanup_interval_ticks",
            "global.management_announce_interval_secs",
            "global.direct_connect_policy",
        ]
        .into_iter()
        .filter_map(|key| self.runtime_config_entry(key))
        .collect();

        #[cfg(feature = "rns-hooks")]
        {
            entries.extend(
                ["provider.queue_max_events", "provider.queue_max_bytes"]
                    .into_iter()
                    .filter_map(|key| self.runtime_config_entry(key)),
            );
        }
        #[cfg(feature = "iface-backbone")]
        {
            entries.extend(self.list_backbone_runtime_config());
            entries.extend(self.list_backbone_client_runtime_config());
        }
        #[cfg(feature = "iface-tcp")]
        {
            entries.extend(self.list_tcp_server_runtime_config());
            entries.extend(self.list_tcp_client_runtime_config());
        }
        #[cfg(feature = "iface-udp")]
        {
            entries.extend(self.list_udp_runtime_config());
        }
        #[cfg(feature = "iface-auto")]
        {
            entries.extend(self.list_auto_runtime_config());
        }
        #[cfg(feature = "iface-i2p")]
        {
            entries.extend(self.list_i2p_runtime_config());
        }
        #[cfg(feature = "iface-pipe")]
        {
            entries.extend(self.list_pipe_runtime_config());
        }
        #[cfg(feature = "iface-rnode")]
        {
            entries.extend(self.list_rnode_runtime_config());
        }
        entries.extend(self.list_generic_interface_runtime_config());

        entries
    }

    fn holepunch_policy_name(policy: crate::event::HolePunchPolicy) -> String {
        match policy {
            crate::event::HolePunchPolicy::Reject => "reject".to_string(),
            crate::event::HolePunchPolicy::AcceptAll => "accept_all".to_string(),
            crate::event::HolePunchPolicy::AskApp => "ask_app".to_string(),
        }
    }

    fn parse_holepunch_policy(value: &RuntimeConfigValue) -> Option<crate::event::HolePunchPolicy> {
        match value {
            RuntimeConfigValue::String(s) => match s.to_ascii_lowercase().as_str() {
                "reject" => Some(crate::event::HolePunchPolicy::Reject),
                "accept_all" | "acceptall" => Some(crate::event::HolePunchPolicy::AcceptAll),
                "ask_app" | "askapp" => Some(crate::event::HolePunchPolicy::AskApp),
                _ => None,
            },
            _ => None,
        }
    }

    fn expect_u64(value: RuntimeConfigValue, key: &str) -> Result<u64, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Int(v) if v >= 0 => Ok(v as u64),
            RuntimeConfigValue::Int(_) => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: format!("{} must be >= 0", key),
            }),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects an integer", key),
            }),
        }
    }

    fn expect_f64(value: RuntimeConfigValue, key: &str) -> Result<f64, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Float(v) if v >= 0.0 => Ok(v),
            RuntimeConfigValue::Int(v) if v >= 0 => Ok(v as f64),
            RuntimeConfigValue::Float(_) | RuntimeConfigValue::Int(_) => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: format!("{} must be >= 0", key),
            }),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a numeric value", key),
            }),
        }
    }

    fn expect_i64(value: RuntimeConfigValue, key: &str) -> Result<i64, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Int(v) => Ok(v),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects an integer", key),
            }),
        }
    }

    fn expect_bool(value: RuntimeConfigValue, key: &str) -> Result<bool, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Bool(v) => Ok(v),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a boolean", key),
            }),
        }
    }

    fn expect_string(value: RuntimeConfigValue, key: &str) -> Result<String, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::String(v) => Ok(v),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a string", key),
            }),
        }
    }

    fn expect_optional_f64(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<f64>, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Null => Ok(None),
            RuntimeConfigValue::Float(v) => Ok(Some(v)),
            RuntimeConfigValue::Int(v) => Ok(Some(v as f64)),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a numeric value or null", key),
            }),
        }
    }

    fn expect_optional_string(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<String>, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Null => Ok(None),
            RuntimeConfigValue::String(v) => Ok(Some(v)),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a string or null", key),
            }),
        }
    }

    #[cfg(feature = "iface-backbone")]
    fn split_backbone_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("backbone.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-backbone")]
    fn set_optional_duration(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<Duration>, RuntimeConfigError> {
        let secs = Self::expect_f64(value, key)?;
        if secs == 0.0 {
            Ok(None)
        } else {
            Ok(Some(Duration::from_secs_f64(secs)))
        }
    }

    #[cfg(feature = "iface-backbone")]
    fn set_optional_usize(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<usize>, RuntimeConfigError> {
        let raw = Self::expect_u64(value, key)?;
        if raw == 0 {
            Ok(None)
        } else {
            Ok(Some(raw as usize))
        }
    }

    #[cfg(feature = "iface-backbone")]
    fn set_backbone_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self.set_backbone_discovery_runtime_config(key, value);
        }
        let handle = self.backbone_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("backbone interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        match setting {
            "idle_timeout_secs" => {
                runtime.idle_timeout = Self::set_optional_duration(value, key)?;
                Ok(())
            }
            "write_stall_timeout_secs" => {
                runtime.write_stall_timeout = Self::set_optional_duration(value, key)?;
                Ok(())
            }
            "max_penalty_duration_secs" => {
                runtime.abuse.max_penalty_duration = Self::set_optional_duration(value, key)?;
                Ok(())
            }
            "max_connections" => {
                runtime.max_connections = Self::set_optional_usize(value, key)?;
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-backbone")]
    fn split_backbone_discovery_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("backbone.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-backbone")]
    fn set_backbone_discovery_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_discovery_runtime_key(key)?;
        let handle = self
            .backbone_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => {
                handle.current.discoverable = Self::expect_bool(value, key)?;
            }
            "discovery_name" => {
                handle.current.config.discovery_name = Self::expect_string(value, key)?;
            }
            "announce_interval_secs" => {
                let secs = Self::expect_u64(value, key)?;
                if secs < 300 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be >= 300", key),
                    });
                }
                handle.current.config.announce_interval = secs;
            }
            "reachable_on" => {
                handle.current.config.reachable_on = Self::expect_optional_string(value, key)?;
            }
            "stamp_value" => {
                let raw = Self::expect_u64(value, key)?;
                if raw > u8::MAX as u64 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be <= {}", key, u8::MAX),
                    });
                }
                handle.current.config.stamp_value = raw as u8;
            }
            "latitude" => {
                handle.current.config.latitude = Self::expect_optional_f64(value, key)?;
            }
            "longitude" => {
                handle.current.config.longitude = Self::expect_optional_f64(value, key)?;
            }
            "height" => {
                handle.current.config.height = Self::expect_optional_f64(value, key)?;
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        self.sync_backbone_discovery_runtime(name)
    }

    #[cfg(feature = "iface-backbone")]
    fn reset_backbone_discovery_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_discovery_runtime_key(key)?;
        let handle = self
            .backbone_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => handle.current.discoverable = handle.startup.discoverable,
            "discovery_name" => {
                handle.current.config.discovery_name = handle.startup.config.discovery_name.clone()
            }
            "announce_interval_secs" => {
                handle.current.config.announce_interval = handle.startup.config.announce_interval
            }
            "reachable_on" => {
                handle.current.config.reachable_on = handle.startup.config.reachable_on.clone()
            }
            "stamp_value" => handle.current.config.stamp_value = handle.startup.config.stamp_value,
            "latitude" => handle.current.config.latitude = handle.startup.config.latitude,
            "longitude" => handle.current.config.longitude = handle.startup.config.longitude,
            "height" => handle.current.config.height = handle.startup.config.height,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        self.sync_backbone_discovery_runtime(name)
    }

    #[cfg(feature = "iface-backbone")]
    fn reset_backbone_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self.reset_backbone_discovery_runtime_config(key);
        }
        let handle = self.backbone_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("backbone interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let startup = handle.startup.clone();
        match setting {
            "idle_timeout_secs" => runtime.idle_timeout = startup.idle_timeout,
            "write_stall_timeout_secs" => runtime.write_stall_timeout = startup.write_stall_timeout,
            "max_penalty_duration_secs" => {
                runtime.abuse.max_penalty_duration = startup.abuse.max_penalty_duration
            }
            "max_connections" => runtime.max_connections = startup.max_connections,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-backbone")]
    fn list_backbone_client_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.backbone_client_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "connect_timeout_secs",
                "reconnect_wait_secs",
                "max_reconnect_tries",
            ] {
                let key = format!("backbone_client.{}.{}", name, suffix);
                if let Some(entry) = self.backbone_client_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-backbone")]
    fn backbone_client_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("backbone_client.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.backbone_client_runtime.get(name)?;
        let current = handle.runtime.lock().unwrap().clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "connect_timeout_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.connect_timeout.as_secs_f64()),
                RuntimeConfigValue::Float(startup.connect_timeout.as_secs_f64()),
                "Backbone client connect timeout in seconds; applies on the next reconnect.",
            )),
            "reconnect_wait_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.reconnect_wait.as_secs_f64()),
                RuntimeConfigValue::Float(startup.reconnect_wait.as_secs_f64()),
                "Delay between backbone client reconnect attempts in seconds.",
            )),
            "max_reconnect_tries" => Some(make_entry(
                RuntimeConfigValue::Int(current.max_reconnect_tries.unwrap_or(0) as i64),
                RuntimeConfigValue::Int(startup.max_reconnect_tries.unwrap_or(0) as i64),
                "Maximum backbone client reconnect attempts; 0 disables the cap.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-backbone")]
    fn split_backbone_client_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key
            .strip_prefix("backbone_client.")
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-backbone")]
    fn set_backbone_client_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_client_runtime_key(key)?;
        let handle = self
            .backbone_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone client interface '{}' not found", name),
            })?;
        let mut runtime = handle.runtime.lock().unwrap();
        match setting {
            "connect_timeout_secs" => {
                runtime.connect_timeout = Duration::from_secs_f64(Self::expect_f64(value, key)?);
                Ok(())
            }
            "reconnect_wait_secs" => {
                runtime.reconnect_wait = Duration::from_secs_f64(Self::expect_f64(value, key)?);
                Ok(())
            }
            "max_reconnect_tries" => {
                runtime.max_reconnect_tries = match Self::expect_u64(value, key)? {
                    0 => None,
                    raw => Some(raw as u32),
                };
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-backbone")]
    fn reset_backbone_client_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_client_runtime_key(key)?;
        let handle = self
            .backbone_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone client interface '{}' not found", name),
            })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let startup = handle.startup.clone();
        match setting {
            "connect_timeout_secs" => runtime.connect_timeout = startup.connect_timeout,
            "reconnect_wait_secs" => runtime.reconnect_wait = startup.reconnect_wait,
            "max_reconnect_tries" => runtime.max_reconnect_tries = startup.max_reconnect_tries,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-tcp")]
    fn list_tcp_server_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.tcp_server_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "max_connections",
                "discoverable",
                "discovery_name",
                "announce_interval_secs",
                "reachable_on",
                "stamp_value",
                "latitude",
                "longitude",
                "height",
            ] {
                let key = format!("tcp_server.{}.{}", name, suffix);
                if let Some(entry) = self.tcp_server_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-tcp")]
    fn list_tcp_client_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.tcp_client_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "connect_timeout_secs",
                "reconnect_wait_secs",
                "max_reconnect_tries",
            ] {
                let key = format!("tcp_client.{}.{}", name, suffix);
                if let Some(entry) = self.tcp_client_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-tcp")]
    fn tcp_client_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("tcp_client.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.tcp_client_runtime.get(name)?;
        let current = handle.runtime.lock().unwrap().clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "connect_timeout_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.connect_timeout.as_secs_f64()),
                RuntimeConfigValue::Float(startup.connect_timeout.as_secs_f64()),
                "TCP client connect timeout in seconds; applies on the next reconnect.",
            )),
            "reconnect_wait_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.reconnect_wait.as_secs_f64()),
                RuntimeConfigValue::Float(startup.reconnect_wait.as_secs_f64()),
                "Delay between TCP client reconnect attempts in seconds.",
            )),
            "max_reconnect_tries" => Some(make_entry(
                RuntimeConfigValue::Int(current.max_reconnect_tries.unwrap_or(0) as i64),
                RuntimeConfigValue::Int(startup.max_reconnect_tries.unwrap_or(0) as i64),
                "Maximum TCP client reconnect attempts; 0 disables the cap.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-tcp")]
    fn split_tcp_client_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("tcp_client.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-tcp")]
    fn set_tcp_client_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_client_runtime_key(key)?;
        let handle = self
            .tcp_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp client interface '{}' not found", name),
            })?;
        let mut runtime = handle.runtime.lock().unwrap();
        match setting {
            "connect_timeout_secs" => {
                runtime.connect_timeout = Duration::from_secs_f64(Self::expect_f64(value, key)?);
                Ok(())
            }
            "reconnect_wait_secs" => {
                runtime.reconnect_wait = Duration::from_secs_f64(Self::expect_f64(value, key)?);
                Ok(())
            }
            "max_reconnect_tries" => {
                runtime.max_reconnect_tries = match Self::expect_u64(value, key)? {
                    0 => None,
                    raw => Some(raw as u32),
                };
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-tcp")]
    fn reset_tcp_client_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_client_runtime_key(key)?;
        let handle = self
            .tcp_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp client interface '{}' not found", name),
            })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let startup = handle.startup.clone();
        match setting {
            "connect_timeout_secs" => runtime.connect_timeout = startup.connect_timeout,
            "reconnect_wait_secs" => runtime.reconnect_wait = startup.reconnect_wait,
            "max_reconnect_tries" => runtime.max_reconnect_tries = startup.max_reconnect_tries,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-udp")]
    fn list_udp_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.udp_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in ["forward_ip", "forward_port"] {
                let key = format!("udp.{}.{}", name, suffix);
                if let Some(entry) = self.udp_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-udp")]
    fn udp_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("udp.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.udp_runtime.get(name)?;
        let current = handle.runtime.lock().unwrap().clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::Immediate,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "forward_ip" => Some(make_entry(
                current
                    .forward_ip
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .forward_ip
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                "Outbound UDP destination IP or hostname; null clears it.",
            )),
            "forward_port" => Some(make_entry(
                current
                    .forward_port
                    .map(|value| RuntimeConfigValue::Int(value as i64))
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .forward_port
                    .map(|value| RuntimeConfigValue::Int(value as i64))
                    .unwrap_or(RuntimeConfigValue::Null),
                "Outbound UDP destination port; null clears it.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-udp")]
    fn split_udp_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("udp.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-udp")]
    fn set_udp_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_udp_runtime_key(key)?;
        let handle = self.udp_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("udp interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        match setting {
            "forward_ip" => {
                runtime.forward_ip = Self::expect_optional_string(value, key)?;
                Ok(())
            }
            "forward_port" => {
                runtime.forward_port = match value {
                    RuntimeConfigValue::Null => None,
                    other => Some(Self::expect_u64(other, key)? as u16),
                };
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-udp")]
    fn reset_udp_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_udp_runtime_key(key)?;
        let handle = self.udp_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("udp interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let startup = handle.startup.clone();
        match setting {
            "forward_ip" => runtime.forward_ip = startup.forward_ip,
            "forward_port" => runtime.forward_port = startup.forward_port,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-auto")]
    fn list_auto_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.auto_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "announce_interval_secs",
                "peer_timeout_secs",
                "peer_job_interval_secs",
            ] {
                let key = format!("auto.{}.{}", name, suffix);
                if let Some(entry) = self.auto_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-auto")]
    fn auto_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("auto.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.auto_runtime.get(name)?;
        let current = handle.runtime.lock().unwrap().clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::Immediate,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "announce_interval_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.announce_interval_secs),
                RuntimeConfigValue::Float(startup.announce_interval_secs),
                "Interval between multicast discovery announces in seconds.",
            )),
            "peer_timeout_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.peer_timeout_secs),
                RuntimeConfigValue::Float(startup.peer_timeout_secs),
                "How long an Auto peer may stay quiet before being culled.",
            )),
            "peer_job_interval_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.peer_job_interval_secs),
                RuntimeConfigValue::Float(startup.peer_job_interval_secs),
                "Interval between Auto peer maintenance passes.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-auto")]
    fn split_auto_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("auto.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-auto")]
    fn set_auto_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_auto_runtime_key(key)?;
        let handle = self.auto_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("auto interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        match setting {
            "announce_interval_secs" => {
                runtime.announce_interval_secs = Self::expect_f64(value, key)?.max(0.1)
            }
            "peer_timeout_secs" => {
                runtime.peer_timeout_secs = Self::expect_f64(value, key)?.max(0.1)
            }
            "peer_job_interval_secs" => {
                runtime.peer_job_interval_secs = Self::expect_f64(value, key)?.max(0.1)
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-auto")]
    fn reset_auto_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_auto_runtime_key(key)?;
        let handle = self.auto_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("auto interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let startup = handle.startup.clone();
        match setting {
            "announce_interval_secs" => {
                runtime.announce_interval_secs = startup.announce_interval_secs
            }
            "peer_timeout_secs" => runtime.peer_timeout_secs = startup.peer_timeout_secs,
            "peer_job_interval_secs" => {
                runtime.peer_job_interval_secs = startup.peer_job_interval_secs
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-i2p")]
    fn list_i2p_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.i2p_runtime.keys().collect();
        names.sort();
        for name in names {
            let key = format!("i2p.{}.reconnect_wait_secs", name);
            if let Some(entry) = self.i2p_runtime_entry(&key) {
                entries.push(entry);
            }
        }
        entries
    }

    #[cfg(feature = "iface-i2p")]
    fn i2p_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("i2p.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.i2p_runtime.get(name)?;
        let current = handle.runtime.lock().unwrap().clone();
        let startup = handle.startup.clone();
        match setting {
            "reconnect_wait_secs" => Some(RuntimeConfigEntry {
                key: key.to_string(),
                source: if current.reconnect_wait == startup.reconnect_wait {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value: RuntimeConfigValue::Float(current.reconnect_wait.as_secs_f64()),
                default: RuntimeConfigValue::Float(startup.reconnect_wait.as_secs_f64()),
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(
                    "Delay before retrying outbound I2P peer connections.".to_string(),
                ),
            }),
            _ => None,
        }
    }

    #[cfg(feature = "iface-i2p")]
    fn split_i2p_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("i2p.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-i2p")]
    fn set_i2p_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_i2p_runtime_key(key)?;
        let handle = self.i2p_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("i2p interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        match setting {
            "reconnect_wait_secs" => {
                runtime.reconnect_wait =
                    Duration::from_secs_f64(Self::expect_f64(value, key)?.max(0.1));
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-i2p")]
    fn reset_i2p_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_i2p_runtime_key(key)?;
        let handle = self.i2p_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("i2p interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let startup = handle.startup.clone();
        match setting {
            "reconnect_wait_secs" => runtime.reconnect_wait = startup.reconnect_wait,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-pipe")]
    fn list_pipe_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.pipe_runtime.keys().collect();
        names.sort();
        for name in names {
            let key = format!("pipe.{}.respawn_delay_secs", name);
            if let Some(entry) = self.pipe_runtime_entry(&key) {
                entries.push(entry);
            }
        }
        entries
    }

    #[cfg(feature = "iface-pipe")]
    fn pipe_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("pipe.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.pipe_runtime.get(name)?;
        let current = handle.runtime.lock().unwrap().clone();
        let startup = handle.startup.clone();
        match setting {
            "respawn_delay_secs" => Some(RuntimeConfigEntry {
                key: key.to_string(),
                source: if current.respawn_delay == startup.respawn_delay {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value: RuntimeConfigValue::Float(current.respawn_delay.as_secs_f64()),
                default: RuntimeConfigValue::Float(startup.respawn_delay.as_secs_f64()),
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(
                    "Delay before respawning the pipe subprocess after exit.".to_string(),
                ),
            }),
            _ => None,
        }
    }

    #[cfg(feature = "iface-pipe")]
    fn split_pipe_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("pipe.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-pipe")]
    fn set_pipe_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_pipe_runtime_key(key)?;
        let handle = self.pipe_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("pipe interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        match setting {
            "respawn_delay_secs" => {
                runtime.respawn_delay =
                    Duration::from_secs_f64(Self::expect_f64(value, key)?.max(0.1));
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-pipe")]
    fn reset_pipe_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_pipe_runtime_key(key)?;
        let handle = self.pipe_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("pipe interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let startup = handle.startup.clone();
        match setting {
            "respawn_delay_secs" => runtime.respawn_delay = startup.respawn_delay,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    fn list_rnode_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.rnode_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "frequency_hz",
                "bandwidth_hz",
                "txpower_dbm",
                "spreading_factor",
                "coding_rate",
                "st_alock_pct",
                "lt_alock_pct",
            ] {
                let key = format!("rnode.{}.{}", name, suffix);
                if let Some(entry) = self.rnode_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-rnode")]
    fn rnode_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("rnode.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.rnode_runtime.get(name)?;
        let current = handle.runtime.lock().unwrap().clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::Immediate,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "frequency_hz" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.frequency as i64),
                RuntimeConfigValue::Int(startup.sub.frequency as i64),
                "RNode radio frequency in Hz.",
            )),
            "bandwidth_hz" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.bandwidth as i64),
                RuntimeConfigValue::Int(startup.sub.bandwidth as i64),
                "RNode radio bandwidth in Hz.",
            )),
            "txpower_dbm" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.txpower as i64),
                RuntimeConfigValue::Int(startup.sub.txpower as i64),
                "RNode transmit power in dBm.",
            )),
            "spreading_factor" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.spreading_factor as i64),
                RuntimeConfigValue::Int(startup.sub.spreading_factor as i64),
                "RNode LoRa spreading factor.",
            )),
            "coding_rate" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.coding_rate as i64),
                RuntimeConfigValue::Int(startup.sub.coding_rate as i64),
                "RNode LoRa coding rate.",
            )),
            "st_alock_pct" => Some(make_entry(
                current
                    .sub
                    .st_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .sub
                    .st_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                "RNode short-term airtime lock percent; null clears it.",
            )),
            "lt_alock_pct" => Some(make_entry(
                current
                    .sub
                    .lt_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .sub
                    .lt_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                "RNode long-term airtime lock percent; null clears it.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-rnode")]
    fn split_rnode_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("rnode.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-rnode")]
    fn apply_rnode_runtime(runtime: &mut RNodeRuntime) -> Result<(), RuntimeConfigError> {
        if let Some(err) = validate_sub_config(&runtime.sub) {
            return Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: err,
            });
        }
        if let Some(writer) = runtime.writer.clone() {
            crate::interface::rnode::configure_subinterface(&writer, 0, &runtime.sub, false)
                .map_err(|e| RuntimeConfigError {
                    code: RuntimeConfigErrorCode::ApplyFailed,
                    message: format!("failed to apply RNode config: {}", e),
                })?;
        }
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    fn set_rnode_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_rnode_runtime_key(key)?;
        let handle = self.rnode_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("rnode interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let old = runtime.sub.clone();
        match setting {
            "frequency_hz" => runtime.sub.frequency = Self::expect_u64(value, key)? as u32,
            "bandwidth_hz" => runtime.sub.bandwidth = Self::expect_u64(value, key)? as u32,
            "txpower_dbm" => runtime.sub.txpower = Self::expect_i64(value, key)? as i8,
            "spreading_factor" => {
                runtime.sub.spreading_factor = Self::expect_u64(value, key)? as u8
            }
            "coding_rate" => runtime.sub.coding_rate = Self::expect_u64(value, key)? as u8,
            "st_alock_pct" => {
                runtime.sub.st_alock = match value {
                    RuntimeConfigValue::Null => None,
                    other => Some(Self::expect_f64(other, key)? as f32),
                };
            }
            "lt_alock_pct" => {
                runtime.sub.lt_alock = match value {
                    RuntimeConfigValue::Null => None,
                    other => Some(Self::expect_f64(other, key)? as f32),
                };
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        if let Err(err) = Self::apply_rnode_runtime(&mut runtime) {
            runtime.sub = old;
            return Err(err);
        }
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    fn reset_rnode_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_rnode_runtime_key(key)?;
        let handle = self.rnode_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("rnode interface '{}' not found", name),
        })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let old = runtime.sub.clone();
        let startup = handle.startup.clone();
        match setting {
            "frequency_hz" => runtime.sub.frequency = startup.sub.frequency,
            "bandwidth_hz" => runtime.sub.bandwidth = startup.sub.bandwidth,
            "txpower_dbm" => runtime.sub.txpower = startup.sub.txpower,
            "spreading_factor" => runtime.sub.spreading_factor = startup.sub.spreading_factor,
            "coding_rate" => runtime.sub.coding_rate = startup.sub.coding_rate,
            "st_alock_pct" => runtime.sub.st_alock = startup.sub.st_alock,
            "lt_alock_pct" => runtime.sub.lt_alock = startup.sub.lt_alock,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        if let Err(err) = Self::apply_rnode_runtime(&mut runtime) {
            runtime.sub = old;
            return Err(err);
        }
        Ok(())
    }

    fn list_generic_interface_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<String> = self
            .interfaces
            .values()
            .map(|entry| entry.info.name.clone())
            .collect();
        names.sort();
        names.dedup();
        for name in names {
            for suffix in [
                "enabled",
                "mode",
                "announce_rate_target",
                "announce_rate_grace",
                "announce_rate_penalty",
                "announce_cap",
                "ingress_control",
            ] {
                let key = format!("interface.{}.{}", name, suffix);
                if let Some(entry) = self.generic_interface_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
            if self.interface_ifac_runtime.contains_key(&name) {
                for suffix in ["ifac_netname", "ifac_passphrase", "ifac_size_bytes"] {
                    let key = format!("interface.{}.{}", name, suffix);
                    if let Some(entry) = self.generic_interface_runtime_entry(&key) {
                        entries.push(entry);
                    }
                }
            }
        }
        entries
    }

    fn generic_interface_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("interface.")?;
        let (name, setting) = rest.rsplit_once('.')?;
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          apply_mode: RuntimeConfigApplyMode,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "enabled" => {
                let entry = self
                    .interfaces
                    .values()
                    .find(|entry| entry.info.name == name)?;
                Some(make_entry(
                    RuntimeConfigValue::Bool(entry.enabled),
                    RuntimeConfigValue::Bool(true),
                    RuntimeConfigApplyMode::Immediate,
                    "Administrative enable/disable state for this interface.",
                ))
            }
            "ifac_netname" => {
                let current = self.interface_ifac_runtime.get(name)?;
                let startup = self.interface_ifac_runtime_defaults.get(name)?;
                Some(make_entry(
                    current
                        .netname
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .netname
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "IFAC network name for this interface; null clears it.",
                ))
            }
            "ifac_passphrase" => {
                let current = self.interface_ifac_runtime.get(name)?;
                let startup = self.interface_ifac_runtime_defaults.get(name)?;
                let current_value = current
                    .netkey
                    .as_ref()
                    .map(|_| RuntimeConfigValue::String("<redacted>".to_string()))
                    .unwrap_or(RuntimeConfigValue::Null);
                let default_value = startup
                    .netkey
                    .as_ref()
                    .map(|_| RuntimeConfigValue::String("<redacted>".to_string()))
                    .unwrap_or(RuntimeConfigValue::Null);
                Some(RuntimeConfigEntry {
                    key: key.to_string(),
                    source: if current.netkey == startup.netkey {
                        RuntimeConfigSource::Startup
                    } else {
                        RuntimeConfigSource::RuntimeOverride
                    },
                    value: current_value,
                    default: default_value,
                    apply_mode: RuntimeConfigApplyMode::Immediate,
                    description: Some(
                        "IFAC passphrase for this interface; write-only, set a string to change it or null to clear it."
                            .to_string(),
                    ),
                })
            }
            "ifac_size_bytes" => {
                let current = self.interface_ifac_runtime.get(name)?;
                let startup = self.interface_ifac_runtime_defaults.get(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Int(current.size as i64),
                    RuntimeConfigValue::Int(startup.size as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "IFAC size in bytes; applies when IFAC is enabled.",
                ))
            }
            "mode" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::String(Self::interface_mode_name(current.mode)),
                    RuntimeConfigValue::String(Self::interface_mode_name(startup.mode)),
                    RuntimeConfigApplyMode::Immediate,
                    "Routing mode for this interface.",
                ))
            }
            "announce_rate_target" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    current
                        .announce_rate_target
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .announce_rate_target
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Optional announce rate target in announces/sec; null disables it.",
                ))
            }
            "announce_rate_grace" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Int(current.announce_rate_grace as i64),
                    RuntimeConfigValue::Int(startup.announce_rate_grace as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce rate grace period in announces.",
                ))
            }
            "announce_rate_penalty" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.announce_rate_penalty),
                    RuntimeConfigValue::Float(startup.announce_rate_penalty),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce rate penalty multiplier.",
                ))
            }
            "announce_cap" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.announce_cap),
                    RuntimeConfigValue::Float(startup.announce_cap),
                    RuntimeConfigApplyMode::Immediate,
                    "Fraction of bitrate reserved for announces.",
                ))
            }
            "ingress_control" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Bool(current.ingress_control),
                    RuntimeConfigValue::Bool(startup.ingress_control),
                    RuntimeConfigApplyMode::Immediate,
                    "Whether ingress control is enabled for this interface.",
                ))
            }
            _ => None,
        }
    }

    fn split_generic_interface_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("interface.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.rsplit_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    fn interface_runtime_infos_by_name(
        &self,
        name: &str,
    ) -> Option<(
        rns_core::transport::types::InterfaceId,
        &rns_core::transport::types::InterfaceInfo,
        &rns_core::transport::types::InterfaceInfo,
    )> {
        let (id, entry) = self
            .interfaces
            .iter()
            .find(|(_, entry)| entry.info.name == name)?;
        let startup = self.interface_runtime_defaults.get(name)?;
        Some((*id, &entry.info, startup))
    }

    fn interface_mode_name(mode: u8) -> String {
        match mode {
            rns_core::constants::MODE_FULL => "full".to_string(),
            rns_core::constants::MODE_ACCESS_POINT => "access_point".to_string(),
            rns_core::constants::MODE_POINT_TO_POINT => "point_to_point".to_string(),
            rns_core::constants::MODE_ROAMING => "roaming".to_string(),
            rns_core::constants::MODE_BOUNDARY => "boundary".to_string(),
            rns_core::constants::MODE_GATEWAY => "gateway".to_string(),
            _ => mode.to_string(),
        }
    }

    fn parse_interface_mode(value: &RuntimeConfigValue) -> Option<u8> {
        match value {
            RuntimeConfigValue::Int(v) if *v >= 0 && *v <= u8::MAX as i64 => Some(*v as u8),
            RuntimeConfigValue::String(s) => match s.to_ascii_lowercase().as_str() {
                "full" => Some(rns_core::constants::MODE_FULL),
                "access_point" | "accesspoint" | "ap" => {
                    Some(rns_core::constants::MODE_ACCESS_POINT)
                }
                "point_to_point" | "pointtopoint" | "ptp" => {
                    Some(rns_core::constants::MODE_POINT_TO_POINT)
                }
                "roaming" => Some(rns_core::constants::MODE_ROAMING),
                "boundary" => Some(rns_core::constants::MODE_BOUNDARY),
                "gateway" | "gw" => Some(rns_core::constants::MODE_GATEWAY),
                _ => None,
            },
            _ => None,
        }
    }

    fn apply_interface_ifac_runtime(entry: &mut InterfaceEntry, config: &IfacRuntimeConfig) {
        entry.ifac = if config.netname.is_some() || config.netkey.is_some() {
            Some(ifac::derive_ifac(
                config.netname.as_deref(),
                config.netkey.as_deref(),
                config.size,
            ))
        } else {
            None
        };
    }

    fn set_generic_interface_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_generic_interface_runtime_key(key)?;
        let (id, _) = self
            .interfaces
            .iter()
            .find(|(_, entry)| entry.info.name == name)
            .map(|(id, entry)| (*id, entry))
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("interface '{}' not found", name),
            })?;
        let entry = self.interfaces.get_mut(&id).unwrap();
        match setting {
            "enabled" => {
                entry.enabled = Self::expect_bool(value, key)?;
            }
            "ifac_netname" => {
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.netname = match value {
                    RuntimeConfigValue::Null => None,
                    RuntimeConfigValue::String(value) => Some(value),
                    _ => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidType,
                            message: format!("{} expects a string or null", key),
                        })
                    }
                };
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_passphrase" => {
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.netkey = match value {
                    RuntimeConfigValue::Null => None,
                    RuntimeConfigValue::String(value) => Some(value),
                    _ => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidType,
                            message: format!("{} expects a string or null", key),
                        })
                    }
                };
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_size_bytes" => {
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.size =
                    (Self::expect_u64(value, key)? as usize).max(crate::ifac::IFAC_MIN_SIZE);
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "mode" => {
                entry.info.mode = Self::parse_interface_mode(&value).ok_or(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidValue,
                    message: format!("{} must be a valid interface mode", key),
                })?;
            }
            "announce_rate_target" => {
                entry.info.announce_rate_target = match value {
                    RuntimeConfigValue::Null => None,
                    RuntimeConfigValue::Float(v) if v >= 0.0 => Some(v),
                    RuntimeConfigValue::Int(v) if v >= 0 => Some(v as f64),
                    RuntimeConfigValue::Float(_) | RuntimeConfigValue::Int(_) => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidValue,
                            message: format!("{} must be >= 0", key),
                        })
                    }
                    _ => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidType,
                            message: format!("{} expects a numeric value or null", key),
                        })
                    }
                };
            }
            "announce_rate_grace" => {
                entry.info.announce_rate_grace = Self::expect_u64(value, key)? as u32
            }
            "announce_rate_penalty" => {
                entry.info.announce_rate_penalty = Self::expect_f64(value, key)?
            }
            "announce_cap" => entry.info.announce_cap = Self::expect_f64(value, key)?,
            "ingress_control" => entry.info.ingress_control = Self::expect_bool(value, key)?,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        let info = entry.info.clone();
        self.engine.register_interface(info);
        Ok(())
    }

    fn reset_generic_interface_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_generic_interface_runtime_key(key)?;
        let startup =
            self.interface_runtime_defaults
                .get(name)
                .cloned()
                .ok_or(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::NotFound,
                    message: format!("interface '{}' not found", name),
                })?;
        let entry = self
            .interfaces
            .values_mut()
            .find(|entry| entry.info.name == name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("interface '{}' not found", name),
            })?;
        match setting {
            "enabled" => entry.enabled = true,
            "ifac_netname" => {
                let startup_ifac =
                    self.interface_ifac_runtime_defaults
                        .get(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.netname = startup_ifac.netname.clone();
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_passphrase" => {
                let startup_ifac =
                    self.interface_ifac_runtime_defaults
                        .get(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.netkey = startup_ifac.netkey.clone();
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_size_bytes" => {
                let startup_ifac =
                    self.interface_ifac_runtime_defaults
                        .get(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.size = startup_ifac.size;
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "mode" => entry.info.mode = startup.mode,
            "announce_rate_target" => {
                entry.info.announce_rate_target = startup.announce_rate_target
            }
            "announce_rate_grace" => entry.info.announce_rate_grace = startup.announce_rate_grace,
            "announce_rate_penalty" => {
                entry.info.announce_rate_penalty = startup.announce_rate_penalty
            }
            "announce_cap" => entry.info.announce_cap = startup.announce_cap,
            "ingress_control" => entry.info.ingress_control = startup.ingress_control,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        let info = entry.info.clone();
        self.engine.register_interface(info);
        Ok(())
    }

    #[cfg(feature = "iface-tcp")]
    fn tcp_server_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("tcp_server.")?;
        let (name, setting) = rest.split_once('.')?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            let handle = self.tcp_server_discovery_runtime.get(name)?;
            let current = &handle.current;
            let startup = &handle.startup;
            let make_entry = |value: RuntimeConfigValue,
                              default: RuntimeConfigValue,
                              apply_mode: RuntimeConfigApplyMode,
                              description: &str|
             -> RuntimeConfigEntry {
                RuntimeConfigEntry {
                    key: key.to_string(),
                    source: if value == default {
                        RuntimeConfigSource::Startup
                    } else {
                        RuntimeConfigSource::RuntimeOverride
                    },
                    value,
                    default,
                    apply_mode,
                    description: Some(description.to_string()),
                }
            };
            return match setting {
                "discoverable" => Some(make_entry(
                    RuntimeConfigValue::Bool(current.discoverable),
                    RuntimeConfigValue::Bool(startup.discoverable),
                    RuntimeConfigApplyMode::Immediate,
                    "Whether this TCP server interface is advertised through interface discovery.",
                )),
                "discovery_name" => Some(make_entry(
                    RuntimeConfigValue::String(current.config.discovery_name.clone()),
                    RuntimeConfigValue::String(startup.config.discovery_name.clone()),
                    RuntimeConfigApplyMode::Immediate,
                    "Human-readable discovery name advertised for this TCP server interface.",
                )),
                "announce_interval_secs" => Some(make_entry(
                    RuntimeConfigValue::Int(current.config.announce_interval as i64),
                    RuntimeConfigValue::Int(startup.config.announce_interval as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Discovery announce interval for this TCP server interface in seconds.",
                )),
                "reachable_on" => Some(make_entry(
                    current
                        .config
                        .reachable_on
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .config
                        .reachable_on
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Reachable hostname or IP advertised for this TCP server interface; null clears it.",
                )),
                "stamp_value" => Some(make_entry(
                    RuntimeConfigValue::Int(current.config.stamp_value as i64),
                    RuntimeConfigValue::Int(startup.config.stamp_value as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Discovery proof-of-work stamp cost for this TCP server interface.",
                )),
                "latitude" => Some(make_entry(
                    current
                        .config
                        .latitude
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .config
                        .latitude
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Latitude advertised for this TCP server interface; null clears it.",
                )),
                "longitude" => Some(make_entry(
                    current
                        .config
                        .longitude
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .config
                        .longitude
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Longitude advertised for this TCP server interface; null clears it.",
                )),
                "height" => Some(make_entry(
                    current
                        .config
                        .height
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .config
                        .height
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Height advertised for this TCP server interface; null clears it.",
                )),
                _ => None,
            };
        }

        let handle = self.tcp_server_runtime.get(name)?;
        let current = handle.runtime.lock().unwrap().clone();
        let startup = handle.startup.clone();
        match setting {
            "max_connections" => Some(RuntimeConfigEntry {
                key: key.to_string(),
                value: RuntimeConfigValue::Int(current.max_connections.unwrap_or(0) as i64),
                default: RuntimeConfigValue::Int(startup.max_connections.unwrap_or(0) as i64),
                source: if current.max_connections == startup.max_connections {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                apply_mode: RuntimeConfigApplyMode::NewConnectionsOnly,
                description: Some(
                    "Maximum simultaneous inbound TCP server connections; 0 disables the cap."
                        .to_string(),
                ),
            }),
            _ => None,
        }
    }

    #[cfg(feature = "iface-tcp")]
    fn split_tcp_server_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("tcp_server.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-tcp")]
    fn set_tcp_server_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self.set_tcp_server_discovery_runtime_config(key, value);
        }
        let handle = self
            .tcp_server_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        let mut runtime = handle.runtime.lock().unwrap();
        match setting {
            "max_connections" => {
                runtime.max_connections = Self::set_optional_usize(value, key)?;
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-tcp")]
    fn reset_tcp_server_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self.reset_tcp_server_discovery_runtime_config(key);
        }
        let handle = self
            .tcp_server_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        let mut runtime = handle.runtime.lock().unwrap();
        let startup = handle.startup.clone();
        match setting {
            "max_connections" => runtime.max_connections = startup.max_connections,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-tcp")]
    fn set_tcp_server_discovery_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        let handle = self
            .tcp_server_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => handle.current.discoverable = Self::expect_bool(value, key)?,
            "discovery_name" => {
                handle.current.config.discovery_name = Self::expect_string(value, key)?
            }
            "announce_interval_secs" => {
                let secs = Self::expect_u64(value, key)?;
                if secs < 300 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be >= 300", key),
                    });
                }
                handle.current.config.announce_interval = secs;
            }
            "reachable_on" => {
                handle.current.config.reachable_on = Self::expect_optional_string(value, key)?
            }
            "stamp_value" => {
                let raw = Self::expect_u64(value, key)?;
                if raw > u8::MAX as u64 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be <= {}", key, u8::MAX),
                    });
                }
                handle.current.config.stamp_value = raw as u8;
            }
            "latitude" => handle.current.config.latitude = Self::expect_optional_f64(value, key)?,
            "longitude" => handle.current.config.longitude = Self::expect_optional_f64(value, key)?,
            "height" => handle.current.config.height = Self::expect_optional_f64(value, key)?,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        self.sync_tcp_server_discovery_runtime(name)
    }

    #[cfg(feature = "iface-tcp")]
    fn reset_tcp_server_discovery_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        let handle = self
            .tcp_server_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => handle.current.discoverable = handle.startup.discoverable,
            "discovery_name" => {
                handle.current.config.discovery_name = handle.startup.config.discovery_name.clone()
            }
            "announce_interval_secs" => {
                handle.current.config.announce_interval = handle.startup.config.announce_interval
            }
            "reachable_on" => {
                handle.current.config.reachable_on = handle.startup.config.reachable_on.clone()
            }
            "stamp_value" => handle.current.config.stamp_value = handle.startup.config.stamp_value,
            "latitude" => handle.current.config.latitude = handle.startup.config.latitude,
            "longitude" => handle.current.config.longitude = handle.startup.config.longitude,
            "height" => handle.current.config.height = handle.startup.config.height,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        self.sync_tcp_server_discovery_runtime(name)
    }

    #[cfg(feature = "iface-backbone")]
    fn list_backbone_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.backbone_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "idle_timeout_secs",
                "write_stall_timeout_secs",
                "max_penalty_duration_secs",
                "max_connections",
            ] {
                let key = format!("backbone.{}.{}", name, suffix);
                if let Some(entry) = self.backbone_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
            for suffix in [
                "discoverable",
                "discovery_name",
                "announce_interval_secs",
                "reachable_on",
                "stamp_value",
                "latitude",
                "longitude",
                "height",
            ] {
                let key = format!("backbone.{}.{}", name, suffix);
                if let Some(entry) = self.backbone_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-backbone")]
    fn backbone_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("backbone.")?;
        let (name, setting) = rest.split_once('.')?;

        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          apply_mode: RuntimeConfigApplyMode,
                          description: &str| RuntimeConfigEntry {
            key: key.to_string(),
            source: if value == default {
                RuntimeConfigSource::Startup
            } else {
                RuntimeConfigSource::RuntimeOverride
            },
            value,
            default,
            apply_mode,
            description: Some(description.to_string()),
        };

        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            let handle = self.backbone_discovery_runtime.get(name)?;
            let current = &handle.current;
            let startup = &handle.startup;
            return match setting {
                "discoverable" => Some(make_entry(
                    RuntimeConfigValue::Bool(current.discoverable),
                    RuntimeConfigValue::Bool(startup.discoverable),
                    RuntimeConfigApplyMode::Immediate,
                    "Whether this backbone interface is advertised through interface discovery.",
                )),
                "discovery_name" => Some(make_entry(
                    RuntimeConfigValue::String(current.config.discovery_name.clone()),
                    RuntimeConfigValue::String(startup.config.discovery_name.clone()),
                    RuntimeConfigApplyMode::Immediate,
                    "Human-readable discovery name advertised for this backbone interface.",
                )),
                "announce_interval_secs" => Some(make_entry(
                    RuntimeConfigValue::Int(current.config.announce_interval as i64),
                    RuntimeConfigValue::Int(startup.config.announce_interval as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Discovery announce interval for this backbone interface in seconds.",
                )),
                "reachable_on" => Some(make_entry(
                    current
                        .config
                        .reachable_on
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .config
                        .reachable_on
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Reachable hostname or IP advertised for this backbone interface; null clears it.",
                )),
                "stamp_value" => Some(make_entry(
                    RuntimeConfigValue::Int(current.config.stamp_value as i64),
                    RuntimeConfigValue::Int(startup.config.stamp_value as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Discovery proof-of-work stamp cost for this backbone interface.",
                )),
                "latitude" => Some(make_entry(
                    current
                        .config
                        .latitude
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .config
                        .latitude
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Latitude advertised for this backbone interface; null clears it.",
                )),
                "longitude" => Some(make_entry(
                    current
                        .config
                        .longitude
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .config
                        .longitude
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Longitude advertised for this backbone interface; null clears it.",
                )),
                "height" => Some(make_entry(
                    current
                        .config
                        .height
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .config
                        .height
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Height advertised for this backbone interface; null clears it.",
                )),
                _ => None,
            };
        }

        if let Some(handle) = self.backbone_runtime.get(name) {
            let current = handle.runtime.lock().unwrap().clone();
            let startup = handle.startup.clone();
            return match setting {
                "idle_timeout_secs" => Some(make_entry(
                    RuntimeConfigValue::Float(current.idle_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigValue::Float(startup.idle_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigApplyMode::Immediate,
                    "Disconnect silent inbound peers after this many seconds; 0 disables the timeout.",
                )),
                "write_stall_timeout_secs" => Some(make_entry(
                    RuntimeConfigValue::Float(current.write_stall_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigValue::Float(startup.write_stall_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigApplyMode::Immediate,
                    "Disconnect peers whose send buffer remains unwritable for this many seconds; 0 disables the timeout.",
                )),
                "max_penalty_duration_secs" => Some(make_entry(
                    RuntimeConfigValue::Float(current.abuse.max_penalty_duration.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigValue::Float(startup.abuse.max_penalty_duration.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigApplyMode::Immediate,
                    "Maximum accepted backbone blacklist duration; 0 means no cap.",
                )),
                "max_connections" => Some(make_entry(
                    RuntimeConfigValue::Int(current.max_connections.unwrap_or(0) as i64),
                    RuntimeConfigValue::Int(startup.max_connections.unwrap_or(0) as i64),
                    RuntimeConfigApplyMode::NewConnectionsOnly,
                    "Maximum simultaneous inbound backbone connections; 0 disables the cap.",
                )),
                _ => None,
            };
        }

        None
    }

    #[cfg(feature = "rns-hooks")]
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

    #[cfg(feature = "rns-hooks")]
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

    /// Run the event loop. Blocks until Shutdown or all senders are dropped.
    pub fn run(&mut self) {
        loop {
            let event = match self.rx.recv() {
                Ok(e) => e,
                Err(_) => break, // all senders dropped
            };

            match event {
                Event::Frame { interface_id, data } => {
                    // Log incoming announces
                    if data.len() > 2 && (data[0] & 0x03) == 0x01 {
                        log::debug!(
                            "Announce:frame from iface {} (len={}, flags=0x{:02x})",
                            interface_id.0,
                            data.len(),
                            data[0]
                        );
                    }
                    if let Some(entry) = self.interfaces.get(&interface_id) {
                        if !entry.enabled || !entry.online {
                            continue;
                        }
                    }
                    // Update rx stats
                    if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                        entry.stats.rxb += data.len() as u64;
                        entry.stats.rx_packets += 1;
                    }

                    // IFAC inbound processing
                    let packet = if let Some(entry) = self.interfaces.get(&interface_id) {
                        if let Some(ref ifac_state) = entry.ifac {
                            // Interface has IFAC enabled — unmask
                            match ifac::unmask_inbound(&data, ifac_state) {
                                Some(unmasked) => unmasked,
                                None => {
                                    log::debug!("[{}] IFAC rejected packet", interface_id.0);
                                    continue;
                                }
                            }
                        } else {
                            // No IFAC — drop if IFAC flag is set
                            if data.len() > 2 && data[0] & 0x80 == 0x80 {
                                log::debug!(
                                    "[{}] dropping packet with IFAC flag on non-IFAC interface",
                                    interface_id.0
                                );
                                continue;
                            }
                            data
                        }
                    } else {
                        data
                    };

                    // PreIngress hook: after IFAC, before engine processing
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: if packet.is_empty() { 0 } else { packet[0] },
                            hops: if packet.len() > 1 { packet[1] } else { 0 },
                            destination_hash: extract_dest_hash(&packet),
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface_id.0,
                            data_offset: 0,
                            data_len: packet.len() as u32,
                        };
                        let ctx = HookContext::Packet {
                            ctx: &pkt_ctx,
                            raw: &packet,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::PreIngress as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.forward_hook_side_effects("PreIngress", e);
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }

                    // Record incoming announce for frequency tracking (before engine processing)
                    if packet.len() > 2 && (packet[0] & 0x03) == 0x01 {
                        let now = time::now();
                        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                            entry.stats.record_incoming_announce(now);
                        }
                    }

                    // Sync announce frequency to engine before processing
                    if let Some(entry) = self.interfaces.get(&interface_id) {
                        self.engine.update_interface_freq(
                            interface_id,
                            entry.stats.incoming_announce_freq(),
                        );
                    }

                    let actions = if self.async_announce_verification {
                        let mut announce_queue = self
                            .announce_verify_queue
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        self.engine.handle_inbound_with_announce_queue(
                            &packet,
                            interface_id,
                            time::now(),
                            &mut self.rng,
                            Some(&mut announce_queue),
                        )
                    } else {
                        self.engine.handle_inbound(
                            &packet,
                            interface_id,
                            time::now(),
                            &mut self.rng,
                        )
                    };

                    // PreDispatch hook: after engine, before action dispatch
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx2 = rns_hooks::PacketContext {
                            flags: if packet.is_empty() { 0 } else { packet[0] },
                            hops: if packet.len() > 1 { packet[1] } else { 0 },
                            destination_hash: extract_dest_hash(&packet),
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface_id.0,
                            data_offset: 0,
                            data_len: packet.len() as u32,
                        };
                        let ctx = HookContext::Packet {
                            ctx: &pkt_ctx2,
                            raw: &packet,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::PreDispatch as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.forward_hook_side_effects("PreDispatch", e);
                        }
                    }

                    self.dispatch_all(actions);
                }
                Event::AnnounceVerified {
                    key,
                    validated,
                    sig_cache_key,
                } => {
                    let pending = {
                        let mut announce_queue = self
                            .announce_verify_queue
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        announce_queue.complete_success(&key)
                    };
                    if let Some(pending) = pending {
                        let actions = self.engine.complete_verified_announce(
                            pending,
                            validated,
                            sig_cache_key,
                            time::now(),
                            &mut self.rng,
                        );
                        self.dispatch_all(actions);
                    }
                }
                Event::AnnounceVerifyFailed { key, .. } => {
                    let mut announce_queue = self
                        .announce_verify_queue
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let _ = announce_queue.complete_failure(&key);
                }
                Event::Tick => {
                    // Tick hook
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Tick;
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::Tick as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.forward_hook_side_effects("Tick", e);
                        }
                    }

                    let now = time::now();
                    // Sync announce frequency to engine for all interfaces before tick
                    for (id, entry) in &self.interfaces {
                        self.engine
                            .update_interface_freq(*id, entry.stats.incoming_announce_freq());
                    }
                    let actions = self.engine.tick(now, &mut self.rng);
                    self.dispatch_all(actions);
                    // Tick link manager (keepalive, stale, timeout)
                    let link_actions = self.link_manager.tick(&mut self.rng);
                    self.dispatch_link_actions(link_actions);
                    // Tick hole-punch manager
                    {
                        let tx = self.get_event_sender();
                        let hp_actions = self.holepunch_manager.tick(&tx);
                        self.dispatch_holepunch_actions(hp_actions);
                    }
                    // Emit management announces
                    self.tick_management_announces(now);
                    // Cull expired sent packet tracking entries (no proof received within 60s)
                    self.sent_packets
                        .retain(|_, (_, sent_time)| now - *sent_time < 60.0);
                    // Cull old completed proof entries (older than 120s)
                    self.completed_proofs
                        .retain(|_, (_, received)| now - *received < 120.0);

                    self.tick_discovery_announcer(now);

                    // Periodic MEMSTATS logging (~every 5 min / 300 ticks)
                    self.memory_stats_counter += 1;
                    if self.memory_stats_counter >= 300 {
                        self.memory_stats_counter = 0;
                        self.log_memory_stats();
                    }

                    // Periodic discovery cleanup
                    if self.discover_interfaces {
                        self.discovery_cleanup_counter += 1;
                        if self.discovery_cleanup_counter >= self.discovery_cleanup_interval_ticks {
                            self.discovery_cleanup_counter = 0;
                            if let Ok(removed) = self.discovered_interfaces.cleanup() {
                                if removed > 0 {
                                    log::info!(
                                        "Discovery cleanup: removed {} stale entries",
                                        removed
                                    );
                                }
                            }
                        }
                    }

                    // Periodic known-destinations cleanup
                    self.cache_cleanup_counter += 1;
                    if self.cache_cleanup_counter >= self.known_destinations_cleanup_interval_ticks
                    {
                        self.cache_cleanup_counter = 0;

                        let active_dests = self.engine.active_destination_hashes();

                        // Retain known destinations while their path is active, while they are
                        // locally registered, or until their configured TTL expires.
                        let now = time::now();
                        let ttl = self.known_destinations_ttl;
                        let kd_before = self.known_destinations.len();
                        self.known_destinations.retain(|k, announced| {
                            active_dests.contains(k)
                                || self.local_destinations.contains_key(k)
                                || now - announced.received_at < ttl
                        });
                        let kd_removed = kd_before - self.known_destinations.len();

                        // Cull rate limiter entries while keeping active or recently used ones.
                        let rl_removed = self.engine.cull_rate_limiter(
                            &active_dests,
                            now,
                            self.rate_limiter_ttl_secs,
                        );

                        if kd_removed > 0 || rl_removed > 0 {
                            log::info!(
                                "Memory cleanup: removed {} known_destinations, {} rate_limiter entries",
                                kd_removed, rl_removed
                            );
                        }
                    }

                    // Periodic announce-cache cleanup scheduling
                    self.announce_cache_cleanup_counter += 1;
                    if self.announce_cache_cleanup_counter
                        >= self.announce_cache_cleanup_interval_ticks
                    {
                        self.announce_cache_cleanup_counter = 0;
                        if self.announce_cache.is_some()
                            && self.cache_cleanup_active_hashes.is_none()
                        {
                            self.cache_cleanup_active_hashes =
                                Some(self.engine.active_packet_hashes());
                            self.cache_cleanup_entries = None;
                            self.cache_cleanup_removed = 0;
                        }
                    }

                    // Incremental announce cache cleanup
                    if self.cache_cleanup_active_hashes.is_some() {
                        if let Some(ref cache) = self.announce_cache {
                            if self.cache_cleanup_entries.is_none() {
                                match cache.entries() {
                                    Ok(entries) => self.cache_cleanup_entries = Some(entries),
                                    Err(e) => {
                                        log::warn!(
                                            "Announce cache cleanup failed to open directory: {}",
                                            e
                                        );
                                        self.cache_cleanup_active_hashes = None;
                                        self.cache_cleanup_entries = None;
                                    }
                                }
                            }
                        }

                        if let Some(ref cache) = self.announce_cache {
                            let active_hashes = self.cache_cleanup_active_hashes.as_ref().unwrap();
                            let entries = match self.cache_cleanup_entries.as_mut() {
                                Some(entries) => entries,
                                None => continue,
                            };
                            match cache.clean_batch(
                                active_hashes,
                                entries,
                                self.announce_cache_cleanup_batch_size,
                            ) {
                                Ok((removed, finished)) => {
                                    self.cache_cleanup_removed += removed;
                                    if finished {
                                        if self.cache_cleanup_removed > 0 {
                                            log::info!(
                                                "Announce cache cleanup complete: removed {} stale files",
                                                self.cache_cleanup_removed
                                            );
                                        }
                                        self.cache_cleanup_active_hashes = None;
                                        self.cache_cleanup_entries = None;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Announce cache cleanup failed: {}", e);
                                    self.cache_cleanup_active_hashes = None;
                                    self.cache_cleanup_entries = None;
                                }
                            }
                        } else {
                            self.cache_cleanup_active_hashes = None;
                            self.cache_cleanup_entries = None;
                        }
                    }
                }
                Event::InterfaceUp(id, new_writer, info) => {
                    let wants_tunnel;
                    let mut replay_shared_announces = false;
                    if let Some(mut info) = info {
                        // New dynamic interface (e.g., TCP server client connection)
                        log::info!("[{}] dynamic interface registered", id.0);
                        wants_tunnel = info.wants_tunnel;
                        let iface_type = infer_interface_type(&info.name);
                        // Set started time for ingress control age tracking
                        info.started = time::now();
                        self.register_interface_runtime_defaults(&info);
                        self.engine.register_interface(info.clone());
                        if let Some(writer) = new_writer {
                            self.interfaces.insert(
                                id,
                                InterfaceEntry {
                                    id,
                                    info,
                                    writer,
                                    enabled: true,
                                    online: true,
                                    dynamic: true,
                                    ifac: None,
                                    stats: InterfaceStats {
                                        started: time::now(),
                                        ..Default::default()
                                    },
                                    interface_type: iface_type,
                                    send_retry_at: None,
                                    send_retry_backoff: Duration::ZERO,
                                },
                            );
                        }
                        self.callbacks.on_interface_up(id);
                        #[cfg(feature = "rns-hooks")]
                        {
                            let ctx = HookContext::Interface { interface_id: id.0 };
                            let now = time::now();
                            let engine_ref = EngineRef {
                                engine: &self.engine,
                                interfaces: &self.interfaces,
                                link_manager: &self.link_manager,
                                now,
                            };
                            let provider_events_enabled = self.provider_events_enabled();
                            if let Some(ref e) = run_hook_inner(
                                &mut self.hook_slots[HookPoint::InterfaceUp as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            ) {
                                self.forward_hook_side_effects("InterfaceUp", e);
                            }
                        }
                    } else {
                        // Existing interface reconnected
                        let is_local_client = self
                            .interfaces
                            .get(&id)
                            .map(|entry| entry.info.is_local_client)
                            .unwrap_or(false);
                        replay_shared_announces = is_local_client
                            && self.shared_reconnect_pending.remove(&id).unwrap_or(false);
                        if let Some(entry) = self.interfaces.get_mut(&id) {
                            log::info!("[{}] interface online", id.0);
                            wants_tunnel = entry.info.wants_tunnel;
                            entry.online = true;
                            if let Some(writer) = new_writer {
                                log::info!("[{}] writer refreshed after reconnect", id.0);
                                entry.writer = writer;
                            }
                            self.callbacks.on_interface_up(id);
                            #[cfg(feature = "rns-hooks")]
                            {
                                let ctx = HookContext::Interface { interface_id: id.0 };
                                let now = time::now();
                                let engine_ref = EngineRef {
                                    engine: &self.engine,
                                    interfaces: &self.interfaces,
                                    link_manager: &self.link_manager,
                                    now,
                                };
                                let provider_events_enabled = self.provider_events_enabled();
                                if let Some(ref e) = run_hook_inner(
                                    &mut self.hook_slots[HookPoint::InterfaceUp as usize].programs,
                                    &self.hook_manager,
                                    &engine_ref,
                                    &ctx,
                                    now,
                                    provider_events_enabled,
                                ) {
                                    self.forward_hook_side_effects("InterfaceUp", e);
                                }
                            }
                        } else {
                            wants_tunnel = false;
                        }
                    }

                    // Trigger tunnel synthesis if the interface wants it
                    if wants_tunnel {
                        self.synthesize_tunnel_for_interface(id);
                    }
                    if replay_shared_announces {
                        self.replay_shared_announces();
                    }
                }
                Event::InterfaceDown(id) => {
                    // Void tunnel if interface had one
                    if let Some(entry) = self.interfaces.get(&id) {
                        if let Some(tunnel_id) = entry.info.tunnel_id {
                            self.engine.void_tunnel_interface(&tunnel_id);
                        }
                    }

                    if let Some(entry) = self.interfaces.get(&id) {
                        let is_dynamic = entry.dynamic;
                        let is_local_client = entry.info.is_local_client;
                        let interface_name = entry.info.name.clone();
                        if is_dynamic {
                            // Dynamic interfaces are removed entirely
                            log::info!("[{}] dynamic interface removed", id.0);
                            self.interface_runtime_defaults.remove(&interface_name);
                            self.engine.deregister_interface(id);
                            self.interfaces.remove(&id);
                        } else {
                            // Static interfaces are just marked offline
                            log::info!("[{}] interface offline", id.0);
                            self.interfaces.get_mut(&id).unwrap().online = false;
                            if is_local_client {
                                self.handle_shared_interface_down(id);
                            }
                        }
                        self.callbacks.on_interface_down(id);
                        #[cfg(feature = "rns-hooks")]
                        {
                            let ctx = HookContext::Interface { interface_id: id.0 };
                            let now = time::now();
                            let engine_ref = EngineRef {
                                engine: &self.engine,
                                interfaces: &self.interfaces,
                                link_manager: &self.link_manager,
                                now,
                            };
                            let provider_events_enabled = self.provider_events_enabled();
                            if let Some(ref e) = run_hook_inner(
                                &mut self.hook_slots[HookPoint::InterfaceDown as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            ) {
                                self.forward_hook_side_effects("InterfaceDown", e);
                            }
                        }
                    }
                }
                Event::SendOutbound {
                    raw,
                    dest_type,
                    attached_interface,
                } => {
                    match RawPacket::unpack(&raw) {
                        Ok(packet) => {
                            let is_announce = packet.flags.packet_type
                                == rns_core::constants::PACKET_TYPE_ANNOUNCE;
                            if is_announce {
                                log::debug!("SendOutbound: ANNOUNCE for {:02x?} (len={}, dest_type={}, attached={:?})",
                                    &packet.destination_hash[..4], raw.len(), dest_type, attached_interface);
                            }
                            // Track sent DATA packets for proof matching
                            if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
                                self.sent_packets.insert(
                                    packet.packet_hash,
                                    (packet.destination_hash, time::now()),
                                );
                            }
                            let actions = self.engine.handle_outbound(
                                &packet,
                                dest_type,
                                attached_interface,
                                time::now(),
                            );
                            if is_announce {
                                log::debug!(
                                    "SendOutbound: announce routed to {} actions: {:?}",
                                    actions.len(),
                                    actions
                                        .iter()
                                        .map(|a| match a {
                                            TransportAction::SendOnInterface {
                                                interface, ..
                                            } => format!("SendOn({})", interface.0),
                                            TransportAction::BroadcastOnAllInterfaces {
                                                ..
                                            } => "BroadcastAll".to_string(),
                                            _ => "other".to_string(),
                                        })
                                        .collect::<Vec<_>>()
                                );
                            }
                            self.dispatch_all(actions);
                        }
                        Err(e) => {
                            log::warn!("SendOutbound: failed to unpack packet: {:?}", e);
                        }
                    }
                }
                Event::RegisterDestination {
                    dest_hash,
                    dest_type,
                } => {
                    self.engine.register_destination(dest_hash, dest_type);
                    self.local_destinations.insert(dest_hash, dest_type);
                }
                Event::StoreSharedAnnounce {
                    dest_hash,
                    name_hash,
                    identity_prv_key,
                    app_data,
                } => {
                    self.shared_announces.insert(
                        dest_hash,
                        SharedAnnounceRecord {
                            name_hash,
                            identity_prv_key,
                            app_data,
                        },
                    );
                }
                Event::DeregisterDestination { dest_hash } => {
                    self.engine.deregister_destination(&dest_hash);
                    self.local_destinations.remove(&dest_hash);
                    self.shared_announces.remove(&dest_hash);
                }
                Event::Query(request, response_tx) => {
                    let response = self.handle_query_mut(request);
                    let _ = response_tx.send(response);
                }
                Event::DeregisterLinkDestination { dest_hash } => {
                    self.link_manager.deregister_link_destination(&dest_hash);
                }
                Event::RegisterLinkDestination {
                    dest_hash,
                    sig_prv_bytes,
                    sig_pub_bytes,
                    resource_strategy,
                } => {
                    let sig_prv =
                        rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_prv_bytes);
                    let strat = match resource_strategy {
                        1 => crate::link_manager::ResourceStrategy::AcceptAll,
                        2 => crate::link_manager::ResourceStrategy::AcceptApp,
                        _ => crate::link_manager::ResourceStrategy::AcceptNone,
                    };
                    self.link_manager.register_link_destination(
                        dest_hash,
                        sig_prv,
                        sig_pub_bytes,
                        strat,
                    );
                    // Also register in transport engine so inbound packets are delivered locally
                    self.engine
                        .register_destination(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                    self.local_destinations
                        .insert(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                }
                Event::RegisterRequestHandler {
                    path,
                    allowed_list,
                    handler,
                } => {
                    self.link_manager.register_request_handler(
                        &path,
                        allowed_list,
                        move |link_id, p, data, remote| handler(link_id, p, data, remote),
                    );
                }
                Event::CreateLink {
                    dest_hash,
                    dest_sig_pub_bytes,
                    response_tx,
                } => {
                    let hops = self.engine.hops_to(&dest_hash).unwrap_or(0);
                    let mtu = self
                        .engine
                        .next_hop_interface(&dest_hash)
                        .and_then(|iface_id| self.interfaces.get(&iface_id))
                        .map(|entry| entry.info.mtu)
                        .unwrap_or(rns_core::constants::MTU as u32);
                    let (link_id, link_actions) = self.link_manager.create_link(
                        &dest_hash,
                        &dest_sig_pub_bytes,
                        hops,
                        mtu,
                        &mut self.rng,
                    );
                    let _ = response_tx.send(link_id);
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendRequest {
                    link_id,
                    path,
                    data,
                } => {
                    let link_actions =
                        self.link_manager
                            .send_request(&link_id, &path, &data, &mut self.rng);
                    self.dispatch_link_actions(link_actions);
                }
                Event::IdentifyOnLink {
                    link_id,
                    identity_prv_key,
                } => {
                    let identity =
                        rns_crypto::identity::Identity::from_private_key(&identity_prv_key);
                    let link_actions =
                        self.link_manager
                            .identify(&link_id, &identity, &mut self.rng);
                    self.dispatch_link_actions(link_actions);
                }
                Event::TeardownLink { link_id } => {
                    let link_actions = self.link_manager.teardown_link(&link_id);
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendResource {
                    link_id,
                    data,
                    metadata,
                } => {
                    let link_actions = self.link_manager.send_resource(
                        &link_id,
                        &data,
                        metadata.as_deref(),
                        &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SetResourceStrategy { link_id, strategy } => {
                    use crate::link_manager::ResourceStrategy;
                    let strat = match strategy {
                        0 => ResourceStrategy::AcceptNone,
                        1 => ResourceStrategy::AcceptAll,
                        2 => ResourceStrategy::AcceptApp,
                        _ => ResourceStrategy::AcceptNone,
                    };
                    self.link_manager.set_resource_strategy(&link_id, strat);
                }
                Event::AcceptResource {
                    link_id,
                    resource_hash,
                    accept,
                } => {
                    let link_actions = self.link_manager.accept_resource(
                        &link_id,
                        &resource_hash,
                        accept,
                        &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendChannelMessage {
                    link_id,
                    msgtype,
                    payload,
                    response_tx,
                } => {
                    match self.link_manager.send_channel_message(
                        &link_id,
                        msgtype,
                        &payload,
                        &mut self.rng,
                    ) {
                        Ok(link_actions) => {
                            self.dispatch_link_actions(link_actions);
                            let _ = response_tx.send(Ok(()));
                        }
                        Err(err) => {
                            let _ = response_tx.send(Err(err));
                        }
                    }
                }
                Event::SendOnLink {
                    link_id,
                    data,
                    context,
                } => {
                    let link_actions =
                        self.link_manager
                            .send_on_link(&link_id, &data, context, &mut self.rng);
                    self.dispatch_link_actions(link_actions);
                }
                Event::RequestPath { dest_hash } => {
                    self.handle_request_path(dest_hash);
                }
                Event::RegisterProofStrategy {
                    dest_hash,
                    strategy,
                    signing_key,
                } => {
                    let identity = signing_key
                        .map(|key| rns_crypto::identity::Identity::from_private_key(&key));
                    self.proof_strategies
                        .insert(dest_hash, (strategy, identity));
                }
                Event::ProposeDirectConnect { link_id } => {
                    let derived_key = self.link_manager.get_derived_key(&link_id);
                    if let Some(dk) = derived_key {
                        let tx = self.get_event_sender();
                        let hp_actions =
                            self.holepunch_manager
                                .propose(link_id, &dk, &mut self.rng, &tx);
                        self.dispatch_holepunch_actions(hp_actions);
                    } else {
                        log::warn!(
                            "Cannot propose direct connect: no derived key for link {:02x?}",
                            &link_id[..4]
                        );
                    }
                }
                Event::SetDirectConnectPolicy { policy } => {
                    self.holepunch_manager.set_policy(policy);
                }
                Event::HolePunchProbeResult {
                    link_id,
                    session_id,
                    observed_addr,
                    socket,
                    probe_server,
                } => {
                    let hp_actions = self.holepunch_manager.handle_probe_result(
                        link_id,
                        session_id,
                        observed_addr,
                        socket,
                        probe_server,
                    );
                    self.dispatch_holepunch_actions(hp_actions);
                }
                Event::HolePunchProbeFailed {
                    link_id,
                    session_id,
                } => {
                    let hp_actions = self
                        .holepunch_manager
                        .handle_probe_failed(link_id, session_id);
                    self.dispatch_holepunch_actions(hp_actions);
                }
                Event::LoadHook {
                    name,
                    wasm_bytes,
                    attach_point,
                    priority,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let mgr = self
                                .hook_manager
                                .as_ref()
                                .ok_or_else(|| "hook manager not available".to_string())?;
                            let program = mgr
                                .compile(name.clone(), &wasm_bytes, priority)
                                .map_err(|e| format!("compile error: {}", e))?;
                            self.hook_slots[point_idx].attach(program);
                            log::info!(
                                "Loaded hook '{}' at point {} (priority {})",
                                name,
                                attach_point,
                                priority
                            );
                            Ok(())
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, wasm_bytes, attach_point, priority);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::UnloadHook {
                    name,
                    attach_point,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            match self.hook_slots[point_idx].detach(&name) {
                                Some(_) => {
                                    log::info!(
                                        "Unloaded hook '{}' from point {}",
                                        name,
                                        attach_point
                                    );
                                    Ok(())
                                }
                                None => Err(format!(
                                    "hook '{}' not found at point '{}'",
                                    name, attach_point
                                )),
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ReloadHook {
                    name,
                    attach_point,
                    wasm_bytes,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let old =
                                self.hook_slots[point_idx].detach(&name).ok_or_else(|| {
                                    format!("hook '{}' not found at point '{}'", name, attach_point)
                                })?;
                            let priority = old.priority;
                            let mgr = match self.hook_manager.as_ref() {
                                Some(m) => m,
                                None => {
                                    self.hook_slots[point_idx].attach(old);
                                    return Err("hook manager not available".to_string());
                                }
                            };
                            match mgr.compile(name.clone(), &wasm_bytes, priority) {
                                Ok(program) => {
                                    self.hook_slots[point_idx].attach(program);
                                    log::info!(
                                        "Reloaded hook '{}' at point {} (priority {})",
                                        name,
                                        attach_point,
                                        priority
                                    );
                                    Ok(())
                                }
                                Err(e) => {
                                    self.hook_slots[point_idx].attach(old);
                                    Err(format!("compile error: {}", e))
                                }
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point, wasm_bytes);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::SetHookEnabled {
                    name,
                    attach_point,
                    enabled,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = self.update_hook_program(&name, &attach_point, |program| {
                            program.enabled = enabled;
                        });
                        if result.is_ok() {
                            log::info!(
                                "{} hook '{}' at point {}",
                                if enabled { "Enabled" } else { "Disabled" },
                                name,
                                attach_point,
                            );
                        }
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point, enabled);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::SetHookPriority {
                    name,
                    attach_point,
                    priority,
                    response_tx,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = self.update_hook_program(&name, &attach_point, |program| {
                            program.priority = priority;
                        });
                        if result.is_ok() {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .expect("validated hook point");
                            self.hook_slots[point_idx]
                                .programs
                                .sort_by(|a, b| b.priority.cmp(&a.priority));
                            log::info!(
                                "Updated hook '{}' at point {} to priority {}",
                                name,
                                attach_point,
                                priority,
                            );
                        }
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point, priority);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ListHooks { response_tx } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let hook_point_names = [
                            "PreIngress",
                            "PreDispatch",
                            "AnnounceReceived",
                            "PathUpdated",
                            "AnnounceRetransmit",
                            "LinkRequestReceived",
                            "LinkEstablished",
                            "LinkClosed",
                            "InterfaceUp",
                            "InterfaceDown",
                            "InterfaceConfigChanged",
                            "BackbonePeerConnected",
                            "BackbonePeerDisconnected",
                            "BackbonePeerIdleTimeout",
                            "BackbonePeerWriteStall",
                            "BackbonePeerPenalty",
                            "SendOnInterface",
                            "BroadcastOnAllInterfaces",
                            "DeliverLocal",
                            "TunnelSynthesize",
                            "Tick",
                        ];
                        let mut infos = Vec::new();
                        for (idx, slot) in self.hook_slots.iter().enumerate() {
                            let point_name = hook_point_names.get(idx).unwrap_or(&"Unknown");
                            for prog in &slot.programs {
                                infos.push(crate::event::HookInfo {
                                    name: prog.name.clone(),
                                    attach_point: point_name.to_string(),
                                    priority: prog.priority,
                                    enabled: prog.enabled,
                                    consecutive_traps: prog.consecutive_traps,
                                });
                            }
                        }
                        let _ = response_tx.send(infos);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = response_tx.send(Vec::new());
                    }
                }
                Event::InterfaceConfigChanged(id) => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Interface { interface_id: id.0 };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::InterfaceConfigChanged as usize]
                                .programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.forward_hook_side_effects("InterfaceConfigChanged", e);
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = id;
                }
                Event::BackbonePeerConnected {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerConnected",
                            HookPoint::BackbonePeerConnected,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for: Duration::ZERO,
                                had_received_data: false,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (server_interface_id, peer_interface_id, peer_ip, peer_port);
                }
                Event::BackbonePeerDisconnected {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                    connected_for,
                    had_received_data,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerDisconnected",
                            HookPoint::BackbonePeerDisconnected,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for,
                                had_received_data,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (
                        server_interface_id,
                        peer_interface_id,
                        peer_ip,
                        peer_port,
                        connected_for,
                        had_received_data,
                    );
                }
                Event::BackbonePeerIdleTimeout {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                    connected_for,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerIdleTimeout",
                            HookPoint::BackbonePeerIdleTimeout,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for,
                                had_received_data: false,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (
                        server_interface_id,
                        peer_interface_id,
                        peer_ip,
                        peer_port,
                        connected_for,
                    );
                }
                Event::BackbonePeerWriteStall {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                    connected_for,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerWriteStall",
                            HookPoint::BackbonePeerWriteStall,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for,
                                had_received_data: false,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (
                        server_interface_id,
                        peer_interface_id,
                        peer_ip,
                        peer_port,
                        connected_for,
                    );
                }
                Event::BackbonePeerPenalty {
                    server_interface_id,
                    peer_ip,
                    penalty_level,
                    blacklist_for,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerPenalty",
                            HookPoint::BackbonePeerPenalty,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: None,
                                peer_ip,
                                peer_port: 0,
                                connected_for: Duration::ZERO,
                                had_received_data: false,
                                penalty_level,
                                blacklist_for,
                            },
                        );
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = (server_interface_id, peer_ip, penalty_level, blacklist_for);
                }
                Event::Shutdown => break,
            }
        }
    }

    /// Handle a query request and produce a response.
    fn handle_query(&self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::InterfaceStats => {
                let mut interfaces = Vec::new();
                let mut total_rxb: u64 = 0;
                let mut total_txb: u64 = 0;
                for entry in self.interfaces.values() {
                    total_rxb += entry.stats.rxb;
                    total_txb += entry.stats.txb;
                    interfaces.push(SingleInterfaceStat {
                        id: entry.info.id.0,
                        name: entry.info.name.clone(),
                        status: entry.online && entry.enabled,
                        mode: entry.info.mode,
                        rxb: entry.stats.rxb,
                        txb: entry.stats.txb,
                        rx_packets: entry.stats.rx_packets,
                        tx_packets: entry.stats.tx_packets,
                        bitrate: entry.info.bitrate,
                        ifac_size: entry.ifac.as_ref().map(|s| s.size),
                        started: entry.stats.started,
                        ia_freq: entry.stats.incoming_announce_freq(),
                        oa_freq: entry.stats.outgoing_announce_freq(),
                        interface_type: entry.interface_type.clone(),
                    });
                }
                // Sort by name for consistent output
                interfaces.sort_by(|a, b| a.name.cmp(&b.name));
                QueryResponse::InterfaceStats(InterfaceStatsResponse {
                    interfaces,
                    transport_id: self.engine.identity_hash().copied(),
                    transport_enabled: self.engine.transport_enabled(),
                    transport_uptime: time::now() - self.started,
                    total_rxb,
                    total_txb,
                    probe_responder: self.probe_responder_hash,
                })
            }
            QueryRequest::BackboneInterfaces => {
                QueryResponse::BackboneInterfaces(self.list_backbone_interfaces())
            }
            QueryRequest::PathTable { max_hops } => {
                let entries: Vec<PathTableEntry> = self
                    .engine
                    .path_table_entries()
                    .filter(|(_, entry)| max_hops.map_or(true, |max| entry.hops <= max))
                    .map(|(hash, entry)| {
                        let iface_name = self
                            .interfaces
                            .get(&entry.receiving_interface)
                            .map(|e| e.info.name.clone())
                            .or_else(|| {
                                self.engine
                                    .interface_info(&entry.receiving_interface)
                                    .map(|i| i.name.clone())
                            })
                            .unwrap_or_default();
                        PathTableEntry {
                            hash: *hash,
                            timestamp: entry.timestamp,
                            via: entry.next_hop,
                            hops: entry.hops,
                            expires: entry.expires,
                            interface: entry.receiving_interface,
                            interface_name: iface_name,
                        }
                    })
                    .collect();
                QueryResponse::PathTable(entries)
            }
            QueryRequest::RateTable => {
                let entries: Vec<RateTableEntry> = self
                    .engine
                    .rate_limiter()
                    .entries()
                    .map(|(hash, entry)| RateTableEntry {
                        hash: *hash,
                        last: entry.last,
                        rate_violations: entry.rate_violations,
                        blocked_until: entry.blocked_until,
                        timestamps: entry.timestamps.clone(),
                    })
                    .collect();
                QueryResponse::RateTable(entries)
            }
            QueryRequest::NextHop { dest_hash } => {
                let resp = self
                    .engine
                    .next_hop(&dest_hash)
                    .map(|next_hop| NextHopResponse {
                        next_hop,
                        hops: self.engine.hops_to(&dest_hash).unwrap_or(0),
                        interface: self
                            .engine
                            .next_hop_interface(&dest_hash)
                            .unwrap_or(InterfaceId(0)),
                    });
                QueryResponse::NextHop(resp)
            }
            QueryRequest::NextHopIfName { dest_hash } => {
                let name = self
                    .engine
                    .next_hop_interface(&dest_hash)
                    .and_then(|id| self.interfaces.get(&id))
                    .map(|entry| entry.info.name.clone());
                QueryResponse::NextHopIfName(name)
            }
            QueryRequest::LinkCount => QueryResponse::LinkCount(
                self.engine.link_table_count() + self.link_manager.link_count(),
            ),
            QueryRequest::DropPath { .. } => {
                // Mutating queries are handled by handle_query_mut
                QueryResponse::DropPath(false)
            }
            QueryRequest::DropAllVia { .. } => QueryResponse::DropAllVia(0),
            QueryRequest::DropAnnounceQueues => QueryResponse::DropAnnounceQueues,
            QueryRequest::TransportIdentity => {
                QueryResponse::TransportIdentity(self.engine.identity_hash().copied())
            }
            QueryRequest::GetBlackholed => {
                let now = time::now();
                let entries: Vec<BlackholeInfo> = self
                    .engine
                    .blackholed_entries()
                    .filter(|(_, e)| e.expires == 0.0 || e.expires > now)
                    .map(|(hash, entry)| BlackholeInfo {
                        identity_hash: *hash,
                        created: entry.created,
                        expires: entry.expires,
                        reason: entry.reason.clone(),
                    })
                    .collect();
                QueryResponse::Blackholed(entries)
            }
            QueryRequest::BlackholeIdentity { .. } | QueryRequest::UnblackholeIdentity { .. } => {
                // Mutating queries handled by handle_query_mut
                QueryResponse::BlackholeResult(false)
            }
            QueryRequest::InjectPath { .. } => {
                // Mutating queries handled by handle_query_mut
                QueryResponse::InjectPath(false)
            }
            QueryRequest::InjectIdentity { .. } => {
                // Mutating queries handled by handle_query_mut
                QueryResponse::InjectIdentity(false)
            }
            QueryRequest::HasPath { dest_hash } => {
                QueryResponse::HasPath(self.engine.has_path(&dest_hash))
            }
            QueryRequest::HopsTo { dest_hash } => {
                QueryResponse::HopsTo(self.engine.hops_to(&dest_hash))
            }
            QueryRequest::RecallIdentity { dest_hash } => {
                QueryResponse::RecallIdentity(self.known_destinations.get(&dest_hash).cloned())
            }
            QueryRequest::LocalDestinations => {
                let entries: Vec<LocalDestinationEntry> = self
                    .local_destinations
                    .iter()
                    .map(|(hash, dest_type)| LocalDestinationEntry {
                        hash: *hash,
                        dest_type: *dest_type,
                    })
                    .collect();
                QueryResponse::LocalDestinations(entries)
            }
            QueryRequest::Links => QueryResponse::Links(self.link_manager.link_entries()),
            QueryRequest::Resources => {
                QueryResponse::Resources(self.link_manager.resource_entries())
            }
            QueryRequest::DiscoveredInterfaces {
                only_available,
                only_transport,
            } => {
                let mut interfaces = self.discovered_interfaces.list().unwrap_or_default();
                crate::discovery::filter_and_sort_interfaces(
                    &mut interfaces,
                    only_available,
                    only_transport,
                );
                QueryResponse::DiscoveredInterfaces(interfaces)
            }
            QueryRequest::ListRuntimeConfig => {
                QueryResponse::RuntimeConfigList(self.list_runtime_config())
            }
            QueryRequest::GetRuntimeConfig { key } => {
                QueryResponse::RuntimeConfigEntry(self.runtime_config_entry(&key))
            }
            QueryRequest::BackbonePeerState { interface_name } => QueryResponse::BackbonePeerState(
                self.list_backbone_peer_state(interface_name.as_deref()),
            ),
            // Mutating queries handled by handle_query_mut
            QueryRequest::SendProbe { .. } => QueryResponse::SendProbe(None),
            QueryRequest::CheckProof { .. } => QueryResponse::CheckProof(None),
            QueryRequest::SetRuntimeConfig { .. } => {
                QueryResponse::RuntimeConfigSet(Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::Unsupported,
                    message: "mutating runtime config is handled separately".to_string(),
                }))
            }
            QueryRequest::ResetRuntimeConfig { .. } => {
                QueryResponse::RuntimeConfigReset(Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::Unsupported,
                    message: "mutating runtime config is handled separately".to_string(),
                }))
            }
            QueryRequest::ClearBackbonePeerState { .. } => {
                QueryResponse::ClearBackbonePeerState(false)
            }
            QueryRequest::BlacklistBackbonePeer { .. } => {
                QueryResponse::BlacklistBackbonePeer(false)
            }
        }
    }

    /// Handle a mutating query request.
    fn handle_query_mut(&mut self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::BlackholeIdentity {
                identity_hash,
                duration_hours,
                reason,
            } => {
                let now = time::now();
                self.engine
                    .blackhole_identity(identity_hash, now, duration_hours, reason);
                QueryResponse::BlackholeResult(true)
            }
            QueryRequest::UnblackholeIdentity { identity_hash } => {
                let result = self.engine.unblackhole_identity(&identity_hash);
                QueryResponse::UnblackholeResult(result)
            }
            QueryRequest::DropPath { dest_hash } => {
                QueryResponse::DropPath(self.engine.drop_path(&dest_hash))
            }
            QueryRequest::DropAllVia { transport_hash } => {
                QueryResponse::DropAllVia(self.engine.drop_all_via(&transport_hash))
            }
            QueryRequest::DropAnnounceQueues => {
                self.engine.drop_announce_queues();
                QueryResponse::DropAnnounceQueues
            }
            QueryRequest::ClearBackbonePeerState {
                interface_name,
                peer_ip,
            } => QueryResponse::ClearBackbonePeerState(
                self.clear_backbone_peer_state(&interface_name, peer_ip),
            ),
            QueryRequest::BlacklistBackbonePeer {
                interface_name,
                peer_ip,
                duration,
                reason,
                penalty_level,
            } => QueryResponse::BlacklistBackbonePeer(self.blacklist_backbone_peer(
                &interface_name,
                peer_ip,
                duration,
                reason,
                penalty_level,
            )),
            QueryRequest::InjectPath {
                dest_hash,
                next_hop,
                hops,
                expires,
                interface_name,
                packet_hash,
            } => {
                // Resolve interface_name → InterfaceId
                let iface_id = self
                    .interfaces
                    .iter()
                    .find(|(_, entry)| entry.info.name == interface_name)
                    .map(|(id, _)| *id);
                match iface_id {
                    Some(id) => {
                        let entry = PathEntry {
                            timestamp: time::now(),
                            next_hop,
                            hops,
                            expires,
                            random_blobs: Vec::new(),
                            receiving_interface: id,
                            packet_hash,
                            announce_raw: None,
                        };
                        self.engine.inject_path(dest_hash, entry);
                        QueryResponse::InjectPath(true)
                    }
                    None => QueryResponse::InjectPath(false),
                }
            }
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash,
                public_key,
                app_data,
                hops,
                received_at,
            } => {
                self.known_destinations.insert(
                    dest_hash,
                    crate::destination::AnnouncedIdentity {
                        dest_hash: rns_core::types::DestHash(dest_hash),
                        identity_hash: rns_core::types::IdentityHash(identity_hash),
                        public_key,
                        app_data,
                        hops,
                        received_at,
                        receiving_interface: rns_core::transport::types::InterfaceId(0),
                    },
                );
                QueryResponse::InjectIdentity(true)
            }
            QueryRequest::SendProbe {
                dest_hash,
                payload_size,
            } => {
                // Look up the identity for this destination hash
                let announced = self.known_destinations.get(&dest_hash).cloned();
                match announced {
                    Some(recalled) => {
                        // Encrypt random payload with remote public key
                        let remote_id =
                            rns_crypto::identity::Identity::from_public_key(&recalled.public_key);
                        let mut payload = vec![0u8; payload_size];
                        self.rng.fill_bytes(&mut payload);
                        match remote_id.encrypt(&payload, &mut self.rng) {
                            Ok(ciphertext) => {
                                // Build DATA SINGLE BROADCAST packet to dest_hash
                                let flags = rns_core::packet::PacketFlags {
                                    header_type: rns_core::constants::HEADER_1,
                                    context_flag: rns_core::constants::FLAG_UNSET,
                                    transport_type: rns_core::constants::TRANSPORT_BROADCAST,
                                    destination_type: rns_core::constants::DESTINATION_SINGLE,
                                    packet_type: rns_core::constants::PACKET_TYPE_DATA,
                                };
                                match RawPacket::pack(
                                    flags,
                                    0,
                                    &dest_hash,
                                    None,
                                    rns_core::constants::CONTEXT_NONE,
                                    &ciphertext,
                                ) {
                                    Ok(packet) => {
                                        let packet_hash = packet.packet_hash;
                                        let hops = self.engine.hops_to(&dest_hash).unwrap_or(0);
                                        // Track for proof matching
                                        self.sent_packets
                                            .insert(packet_hash, (dest_hash, time::now()));
                                        // Send via engine
                                        let actions = self.engine.handle_outbound(
                                            &packet,
                                            rns_core::constants::DESTINATION_SINGLE,
                                            None,
                                            time::now(),
                                        );
                                        self.dispatch_all(actions);
                                        log::debug!(
                                            "Sent probe ({} bytes) to {:02x?}",
                                            payload_size,
                                            &dest_hash[..4],
                                        );
                                        QueryResponse::SendProbe(Some((packet_hash, hops)))
                                    }
                                    Err(_) => {
                                        log::warn!("Failed to pack probe packet");
                                        QueryResponse::SendProbe(None)
                                    }
                                }
                            }
                            Err(_) => {
                                log::warn!("Failed to encrypt probe payload");
                                QueryResponse::SendProbe(None)
                            }
                        }
                    }
                    None => {
                        log::debug!("No known identity for probe dest {:02x?}", &dest_hash[..4]);
                        QueryResponse::SendProbe(None)
                    }
                }
            }
            QueryRequest::CheckProof { packet_hash } => {
                match self.completed_proofs.remove(&packet_hash) {
                    Some((rtt, _received)) => QueryResponse::CheckProof(Some(rtt)),
                    None => QueryResponse::CheckProof(None),
                }
            }
            QueryRequest::SetRuntimeConfig { key, value } => {
                let result = match key.as_str() {
                    "global.tick_interval_ms" => match Self::expect_u64(value, &key) {
                        Ok(value) => {
                            let clamped = value.clamp(100, 10_000);
                            self.tick_interval_ms.store(clamped, Ordering::Relaxed);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.known_destinations_ttl_secs" => match Self::expect_f64(value, &key) {
                        Ok(value) => {
                            self.known_destinations_ttl = value;
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    "global.rate_limiter_ttl_secs" => match Self::expect_f64(value, &key) {
                        Ok(value) if value >= 0.0 => {
                            self.rate_limiter_ttl_secs = value;
                            Ok(())
                        }
                        Ok(_) => Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidValue,
                            message: format!("{} must be >= 0", key),
                        }),
                        Err(err) => Err(err),
                    },
                    "global.known_destinations_cleanup_interval_ticks" => {
                        match Self::expect_u64(value, &key) {
                            Ok(value) if value > 0 => {
                                self.known_destinations_cleanup_interval_ticks = value as u32;
                                Ok(())
                            }
                            Ok(_) => Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::InvalidValue,
                                message: format!("{} must be >= 1", key),
                            }),
                            Err(err) => Err(err),
                        }
                    }
                    "global.announce_cache_cleanup_interval_ticks" => {
                        match Self::expect_u64(value, &key) {
                            Ok(value) if value > 0 => {
                                self.announce_cache_cleanup_interval_ticks = value as u32;
                                Ok(())
                            }
                            Ok(_) => Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::InvalidValue,
                                message: format!("{} must be >= 1", key),
                            }),
                            Err(err) => Err(err),
                        }
                    }
                    "global.announce_cache_cleanup_batch_size" => {
                        match Self::expect_u64(value, &key) {
                            Ok(value) if value > 0 => {
                                self.announce_cache_cleanup_batch_size = value as usize;
                                Ok(())
                            }
                            Ok(_) => Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::InvalidValue,
                                message: format!("{} must be >= 1", key),
                            }),
                            Err(err) => Err(err),
                        }
                    }
                    "global.discovery_cleanup_interval_ticks" => {
                        match Self::expect_u64(value, &key) {
                            Ok(value) if value > 0 => {
                                self.discovery_cleanup_interval_ticks = value as u32;
                                Ok(())
                            }
                            Ok(_) => Err(RuntimeConfigError {
                                code: RuntimeConfigErrorCode::InvalidValue,
                                message: format!("{} must be >= 1", key),
                            }),
                            Err(err) => Err(err),
                        }
                    }
                    "global.management_announce_interval_secs" => {
                        match Self::expect_f64(value, &key) {
                            Ok(value) => {
                                self.management_announce_interval_secs = value;
                                Ok(())
                            }
                            Err(err) => Err(err),
                        }
                    }
                    "global.direct_connect_policy" => {
                        let policy = match Self::parse_holepunch_policy(&value) {
                            Some(policy) => policy,
                            None => {
                                return QueryResponse::RuntimeConfigSet(Err(RuntimeConfigError {
                                    code: RuntimeConfigErrorCode::InvalidValue,
                                    message: format!(
                                        "{} must be one of: reject, accept_all, ask_app",
                                        key
                                    ),
                                }))
                            }
                        };
                        self.holepunch_manager.set_policy(policy);
                        Ok(())
                    }
                    #[cfg(feature = "rns-hooks")]
                    "provider.queue_max_events" => match Self::expect_u64(value, &key) {
                        Ok(v) if v > 0 => {
                            if let Some(ref bridge) = self.provider_bridge {
                                bridge.set_queue_max_events(v as usize);
                            }
                            Ok(())
                        }
                        Ok(_) => Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidValue,
                            message: format!("{} must be >= 1", key),
                        }),
                        Err(err) => Err(err),
                    },
                    #[cfg(feature = "rns-hooks")]
                    "provider.queue_max_bytes" => match Self::expect_u64(value, &key) {
                        Ok(v) if v > 0 => {
                            if let Some(ref bridge) = self.provider_bridge {
                                bridge.set_queue_max_bytes(v as usize);
                            }
                            Ok(())
                        }
                        Ok(_) => Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidValue,
                            message: format!("{} must be >= 1", key),
                        }),
                        Err(err) => Err(err),
                    },
                    #[cfg(feature = "iface-backbone")]
                    _ if key.starts_with("backbone.") => {
                        self.set_backbone_runtime_config(&key, value)
                    }
                    #[cfg(feature = "iface-backbone")]
                    _ if key.starts_with("backbone_client.") => {
                        self.set_backbone_client_runtime_config(&key, value)
                    }
                    #[cfg(feature = "iface-tcp")]
                    _ if key.starts_with("tcp_server.") => {
                        self.set_tcp_server_runtime_config(&key, value)
                    }
                    #[cfg(feature = "iface-tcp")]
                    _ if key.starts_with("tcp_client.") => {
                        self.set_tcp_client_runtime_config(&key, value)
                    }
                    #[cfg(feature = "iface-udp")]
                    _ if key.starts_with("udp.") => self.set_udp_runtime_config(&key, value),
                    #[cfg(feature = "iface-auto")]
                    _ if key.starts_with("auto.") => self.set_auto_runtime_config(&key, value),
                    #[cfg(feature = "iface-i2p")]
                    _ if key.starts_with("i2p.") => self.set_i2p_runtime_config(&key, value),
                    #[cfg(feature = "iface-pipe")]
                    _ if key.starts_with("pipe.") => self.set_pipe_runtime_config(&key, value),
                    #[cfg(feature = "iface-rnode")]
                    _ if key.starts_with("rnode.") => self.set_rnode_runtime_config(&key, value),
                    _ if key.starts_with("interface.") => {
                        self.set_generic_interface_runtime_config(&key, value)
                    }
                    _ => {
                        return QueryResponse::RuntimeConfigSet(Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        }))
                    }
                };

                QueryResponse::RuntimeConfigSet(match result {
                    Ok(()) => self.runtime_config_entry(&key).ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::ApplyFailed,
                        message: format!("failed to read back runtime-config key '{}'", key),
                    }),
                    Err(err) => Err(err),
                })
            }
            QueryRequest::ResetRuntimeConfig { key } => {
                let defaults = self.runtime_config_defaults;
                let result = match key.as_str() {
                    "global.tick_interval_ms" => {
                        self.tick_interval_ms
                            .store(defaults.tick_interval_ms, Ordering::Relaxed);
                        Ok(())
                    }
                    "global.known_destinations_ttl_secs" => {
                        self.known_destinations_ttl = defaults.known_destinations_ttl;
                        Ok(())
                    }
                    "global.rate_limiter_ttl_secs" => {
                        self.rate_limiter_ttl_secs = defaults.rate_limiter_ttl_secs;
                        Ok(())
                    }
                    "global.known_destinations_cleanup_interval_ticks" => {
                        self.known_destinations_cleanup_interval_ticks =
                            defaults.known_destinations_cleanup_interval_ticks;
                        Ok(())
                    }
                    "global.announce_cache_cleanup_interval_ticks" => {
                        self.announce_cache_cleanup_interval_ticks =
                            defaults.announce_cache_cleanup_interval_ticks;
                        Ok(())
                    }
                    "global.announce_cache_cleanup_batch_size" => {
                        self.announce_cache_cleanup_batch_size =
                            defaults.announce_cache_cleanup_batch_size;
                        Ok(())
                    }
                    "global.discovery_cleanup_interval_ticks" => {
                        self.discovery_cleanup_interval_ticks =
                            defaults.discovery_cleanup_interval_ticks;
                        Ok(())
                    }
                    "global.management_announce_interval_secs" => {
                        self.management_announce_interval_secs =
                            defaults.management_announce_interval_secs;
                        Ok(())
                    }
                    "global.direct_connect_policy" => {
                        self.holepunch_manager
                            .set_policy(defaults.direct_connect_policy);
                        Ok(())
                    }
                    #[cfg(feature = "rns-hooks")]
                    "provider.queue_max_events" => {
                        if let Some(ref bridge) = self.provider_bridge {
                            bridge.set_queue_max_events(defaults.provider_queue_max_events);
                        }
                        Ok(())
                    }
                    #[cfg(feature = "rns-hooks")]
                    "provider.queue_max_bytes" => {
                        if let Some(ref bridge) = self.provider_bridge {
                            bridge.set_queue_max_bytes(defaults.provider_queue_max_bytes);
                        }
                        Ok(())
                    }
                    #[cfg(feature = "iface-backbone")]
                    _ if key.starts_with("backbone.") => self.reset_backbone_runtime_config(&key),
                    #[cfg(feature = "iface-backbone")]
                    _ if key.starts_with("backbone_client.") => {
                        self.reset_backbone_client_runtime_config(&key)
                    }
                    #[cfg(feature = "iface-tcp")]
                    _ if key.starts_with("tcp_server.") => {
                        self.reset_tcp_server_runtime_config(&key)
                    }
                    #[cfg(feature = "iface-tcp")]
                    _ if key.starts_with("tcp_client.") => {
                        self.reset_tcp_client_runtime_config(&key)
                    }
                    #[cfg(feature = "iface-udp")]
                    _ if key.starts_with("udp.") => self.reset_udp_runtime_config(&key),
                    #[cfg(feature = "iface-auto")]
                    _ if key.starts_with("auto.") => self.reset_auto_runtime_config(&key),
                    #[cfg(feature = "iface-i2p")]
                    _ if key.starts_with("i2p.") => self.reset_i2p_runtime_config(&key),
                    #[cfg(feature = "iface-pipe")]
                    _ if key.starts_with("pipe.") => self.reset_pipe_runtime_config(&key),
                    #[cfg(feature = "iface-rnode")]
                    _ if key.starts_with("rnode.") => self.reset_rnode_runtime_config(&key),
                    _ if key.starts_with("interface.") => {
                        self.reset_generic_interface_runtime_config(&key)
                    }
                    _ => {
                        return QueryResponse::RuntimeConfigReset(Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        }))
                    }
                };

                QueryResponse::RuntimeConfigReset(match result {
                    Ok(()) => self.runtime_config_entry(&key).ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::ApplyFailed,
                        message: format!("failed to read back runtime-config key '{}'", key),
                    }),
                    Err(err) => Err(err),
                })
            }
            other => self.handle_query(other),
        }
    }

    /// Handle a tunnel synthesis packet delivered locally.
    fn handle_tunnel_synth_delivery(&mut self, raw: &[u8]) {
        // Extract the data payload from the raw packet
        let packet = match RawPacket::unpack(raw) {
            Ok(p) => p,
            Err(_) => return,
        };

        match rns_core::transport::tunnel::validate_tunnel_synthesize_data(&packet.data) {
            Ok(validated) => {
                // Find the interface this tunnel belongs to by computing the expected
                // tunnel_id for each interface with wants_tunnel
                let iface_id = self
                    .interfaces
                    .iter()
                    .find(|(_, entry)| entry.info.wants_tunnel && entry.online && entry.enabled)
                    .map(|(id, _)| *id);

                if let Some(iface) = iface_id {
                    let now = time::now();
                    let tunnel_actions = self.engine.handle_tunnel(validated.tunnel_id, iface, now);
                    self.dispatch_all(tunnel_actions);
                }
            }
            Err(e) => {
                log::debug!("Tunnel synthesis validation failed: {}", e);
            }
        }
    }

    /// Synthesize a tunnel on an interface that wants it.
    ///
    /// Called when an interface with `wants_tunnel` comes up.
    fn synthesize_tunnel_for_interface(&mut self, interface: InterfaceId) {
        if let Some(ref identity) = self.transport_identity {
            let actions = self
                .engine
                .synthesize_tunnel(identity, interface, &mut self.rng);
            self.dispatch_all(actions);
        }
    }

    /// Build and send a path request packet for a destination.
    fn handle_request_path(&mut self, dest_hash: [u8; 16]) {
        // Build path request data: dest_hash(16) || [transport_id(16)] || random_tag(16)
        let mut data = Vec::with_capacity(48);
        data.extend_from_slice(&dest_hash);

        if self.engine.transport_enabled() {
            if let Some(id_hash) = self.engine.identity_hash() {
                data.extend_from_slice(id_hash);
            }
        }

        // Random tag (16 bytes)
        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);
        data.extend_from_slice(&tag);

        // Build as BROADCAST DATA PLAIN packet to rnstransport.path.request
        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_PLAIN,
            packet_type: rns_core::constants::PACKET_TYPE_DATA,
        };

        if let Ok(packet) = RawPacket::pack(
            flags,
            0,
            &self.path_request_dest,
            None,
            rns_core::constants::CONTEXT_NONE,
            &data,
        ) {
            let actions = self.engine.handle_outbound(
                &packet,
                rns_core::constants::DESTINATION_PLAIN,
                None,
                time::now(),
            );
            self.dispatch_all(actions);
        }
    }

    /// Check if we should generate a proof for a delivered packet,
    /// and if so, sign and send it.
    fn maybe_generate_proof(&mut self, dest_hash: [u8; 16], packet_hash: &[u8; 32]) {
        use rns_core::types::ProofStrategy;

        let (strategy, identity) = match self.proof_strategies.get(&dest_hash) {
            Some((s, id)) => (*s, id.as_ref()),
            None => return,
        };

        let should_prove = match strategy {
            ProofStrategy::ProveAll => true,
            ProofStrategy::ProveApp => self.callbacks.on_proof_requested(
                rns_core::types::DestHash(dest_hash),
                rns_core::types::PacketHash(*packet_hash),
            ),
            ProofStrategy::ProveNone => false,
        };

        if !should_prove {
            return;
        }

        let identity = match identity {
            Some(id) => id,
            None => {
                log::warn!(
                    "Cannot generate proof for {:02x?}: no signing key",
                    &dest_hash[..4]
                );
                return;
            }
        };

        // Sign the packet hash to create the proof
        let signature = match identity.sign(packet_hash) {
            Ok(sig) => sig,
            Err(e) => {
                log::warn!("Failed to sign proof for {:02x?}: {:?}", &dest_hash[..4], e);
                return;
            }
        };

        // Build explicit proof: [packet_hash:32][signature:64]
        let mut proof_data = Vec::with_capacity(96);
        proof_data.extend_from_slice(packet_hash);
        proof_data.extend_from_slice(&signature);

        // Address the proof to the truncated packet hash (first 16 bytes),
        // matching Python's ProofDestination (Packet.py:390-394).
        // Transport nodes create reverse_table entries keyed by truncated
        // packet hash when forwarding data, so this allows proofs to be
        // routed back to the sender via the reverse path.
        let mut proof_dest = [0u8; 16];
        proof_dest.copy_from_slice(&packet_hash[..16]);

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_PROOF,
        };

        if let Ok(packet) = RawPacket::pack(
            flags,
            0,
            &proof_dest,
            None,
            rns_core::constants::CONTEXT_NONE,
            &proof_data,
        ) {
            let actions = self.engine.handle_outbound(
                &packet,
                rns_core::constants::DESTINATION_SINGLE,
                None,
                time::now(),
            );
            self.dispatch_all(actions);
            log::debug!(
                "Generated proof for packet on dest {:02x?}",
                &dest_hash[..4]
            );
        }
    }

    /// Handle an inbound proof packet: validate and fire on_proof callback.
    fn handle_inbound_proof(
        &mut self,
        dest_hash: [u8; 16],
        proof_data: &[u8],
        _raw_packet_hash: &[u8; 32],
    ) {
        // Explicit proof format: [packet_hash:32][signature:64] = 96 bytes
        if proof_data.len() < 96 {
            log::debug!(
                "Proof too short for explicit proof: {} bytes",
                proof_data.len()
            );
            return;
        }

        let mut tracked_hash = [0u8; 32];
        tracked_hash.copy_from_slice(&proof_data[..32]);

        let signature = &proof_data[32..96];

        // Look up the tracked sent packet
        if let Some((tracked_dest, sent_time)) = self.sent_packets.remove(&tracked_hash) {
            // Validate the proof signature using the destination's public key
            // (matches Python's PacketReceipt.validate_proof behavior)
            if let Some(announced) = self.known_destinations.get(&tracked_dest) {
                let identity =
                    rns_crypto::identity::Identity::from_public_key(&announced.public_key);
                let mut sig = [0u8; 64];
                sig.copy_from_slice(signature);
                if !identity.verify(&sig, &tracked_hash) {
                    log::debug!("Proof signature invalid for {:02x?}", &tracked_hash[..4],);
                    return;
                }
            } else {
                log::debug!(
                    "No known identity for dest {:02x?}, accepting proof without signature check",
                    &tracked_dest[..4],
                );
            }

            let now = time::now();
            let rtt = now - sent_time;
            log::debug!(
                "Proof received for {:02x?} rtt={:.3}s",
                &tracked_hash[..4],
                rtt,
            );
            self.completed_proofs.insert(tracked_hash, (rtt, now));
            self.callbacks.on_proof(
                rns_core::types::DestHash(tracked_dest),
                rns_core::types::PacketHash(tracked_hash),
                rtt,
            );
        } else {
            log::debug!(
                "Proof for unknown packet {:02x?} on dest {:02x?}",
                &tracked_hash[..4],
                &dest_hash[..4],
            );
        }
    }

    fn interface_send_deferred(entry: &InterfaceEntry, now: Instant) -> bool {
        matches!(entry.send_retry_at, Some(retry_at) if now < retry_at)
    }

    fn record_send_result(
        entry: &mut InterfaceEntry,
        result: &std::io::Result<()>,
        context: &str,
        interface_id: InterfaceId,
    ) {
        match result {
            Ok(()) => {
                entry.send_retry_at = None;
                entry.send_retry_backoff = Duration::ZERO;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let next_backoff = if entry.send_retry_backoff.is_zero() {
                    SEND_RETRY_BACKOFF_MIN
                } else {
                    (entry.send_retry_backoff * 2).min(SEND_RETRY_BACKOFF_MAX)
                };
                entry.send_retry_backoff = next_backoff;
                entry.send_retry_at = Some(Instant::now() + next_backoff);
                log::debug!(
                    "[{}] {} deferred after WouldBlock; retry in {:?}",
                    interface_id.0,
                    context,
                    next_backoff
                );
            }
            Err(e) => {
                entry.send_retry_at = None;
                entry.send_retry_backoff = Duration::ZERO;
                log::warn!("[{}] {} failed: {}", interface_id.0, context, e);
            }
        }
    }

    /// Dispatch a list of transport actions.
    fn dispatch_all(&mut self, actions: Vec<TransportAction>) {
        #[cfg(feature = "rns-hooks")]
        let mut hook_injected: Vec<TransportAction> = Vec::new();

        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: if raw.is_empty() { 0 } else { raw[0] },
                            hops: if raw.len() > 1 { raw[1] } else { 0 },
                            destination_hash: extract_dest_hash(&raw),
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface.0,
                            data_offset: 0,
                            data_len: raw.len() as u32,
                        };
                        let ctx = HookContext::Packet {
                            ctx: &pkt_ctx,
                            raw: &raw,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::SendOnInterface as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "SendOnInterface",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }
                    let is_announce = raw.len() > 2 && (raw[0] & 0x03) == 0x01;
                    if is_announce {
                        log::debug!(
                            "Announce:dispatching to iface {} (len={}, online={})",
                            interface.0,
                            raw.len(),
                            self.interfaces
                                .get(&interface)
                                .map(|e| e.online && e.enabled)
                                .unwrap_or(false)
                        );
                    }
                    if let Some(entry) = self.interfaces.get_mut(&interface) {
                        if entry.online && entry.enabled {
                            if Self::interface_send_deferred(entry, Instant::now()) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw
                            };
                            // Update tx stats
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            if is_announce {
                                entry.stats.record_outgoing_announce(time::now());
                            }
                            let send_result = entry.writer.send_frame(&data);
                            let sent_ok = send_result.is_ok();
                            Self::record_send_result(entry, &send_result, "send", interface);
                            if sent_ok && is_announce {
                                // For HEADER_2 (transported), dest hash is at bytes 18-33
                                // For HEADER_1 (original), dest hash is at bytes 2-17
                                let header_type = (data[0] >> 6) & 0x03;
                                let dest_start = if header_type == 1 { 18usize } else { 2usize };
                                let dest_preview = if data.len() >= dest_start + 4 {
                                    format!("{:02x?}", &data[dest_start..dest_start + 4])
                                } else {
                                    "??".into()
                                };
                                log::debug!(
                                    "Announce:SENT on iface {} (len={}, h={}, dest=[{}])",
                                    interface.0,
                                    data.len(),
                                    header_type,
                                    dest_preview
                                );
                            }
                        }
                    }
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: if raw.is_empty() { 0 } else { raw[0] },
                            hops: if raw.len() > 1 { raw[1] } else { 0 },
                            destination_hash: extract_dest_hash(&raw),
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: 0,
                            data_offset: 0,
                            data_len: raw.len() as u32,
                        };
                        let ctx = HookContext::Packet {
                            ctx: &pkt_ctx,
                            raw: &raw,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::BroadcastOnAllInterfaces as usize]
                                    .programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "BroadcastOnAllInterfaces",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }
                    let is_announce = raw.len() > 2 && (raw[0] & 0x03) == 0x01;
                    for entry in self.interfaces.values_mut() {
                        if entry.online && entry.enabled && Some(entry.id) != exclude {
                            if Self::interface_send_deferred(entry, Instant::now()) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.clone()
                            };
                            // Update tx stats
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            if is_announce {
                                entry.stats.record_outgoing_announce(time::now());
                            }
                            let send_result = entry.writer.send_frame(&data);
                            Self::record_send_result(entry, &send_result, "broadcast", entry.id);
                        }
                    }
                }
                TransportAction::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                    receiving_interface,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: 0,
                            hops: 0,
                            destination_hash,
                            context: 0,
                            packet_hash,
                            interface_id: receiving_interface.0,
                            data_offset: 0,
                            data_len: raw.len() as u32,
                        };
                        let ctx = HookContext::Packet {
                            ctx: &pkt_ctx,
                            raw: &raw,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::DeliverLocal as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "DeliverLocal",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }
                    if destination_hash == self.tunnel_synth_dest {
                        // Tunnel synthesis packet — validate and handle
                        self.handle_tunnel_synth_delivery(&raw);
                    } else if destination_hash == self.path_request_dest {
                        // Path request packet — extract data and handle
                        if let Ok(packet) = RawPacket::unpack(&raw) {
                            let actions = self.engine.handle_path_request(
                                &packet.data,
                                receiving_interface,
                                time::now(),
                            );
                            self.dispatch_all(actions);
                        }
                    } else if self.link_manager.is_link_destination(&destination_hash) {
                        // Link-related packet — route to link manager
                        let link_actions = self.link_manager.handle_local_delivery(
                            destination_hash,
                            &raw,
                            packet_hash,
                            receiving_interface,
                            &mut self.rng,
                        );
                        if link_actions.is_empty() {
                            // Link manager couldn't handle (e.g. opportunistic DATA
                            // for a registered link destination). Fall back to
                            // regular delivery.
                            if let Ok(packet) = RawPacket::unpack(&raw) {
                                if packet.flags.packet_type
                                    == rns_core::constants::PACKET_TYPE_PROOF
                                {
                                    self.handle_inbound_proof(
                                        destination_hash,
                                        &packet.data,
                                        &packet_hash,
                                    );
                                    continue;
                                }
                            }
                            self.maybe_generate_proof(destination_hash, &packet_hash);
                            self.callbacks.on_local_delivery(
                                rns_core::types::DestHash(destination_hash),
                                raw,
                                rns_core::types::PacketHash(packet_hash),
                            );
                        } else {
                            self.dispatch_link_actions(link_actions);
                        }
                    } else {
                        // Check if this is a PROOF packet for a packet we sent
                        if let Ok(packet) = RawPacket::unpack(&raw) {
                            if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_PROOF {
                                self.handle_inbound_proof(
                                    destination_hash,
                                    &packet.data,
                                    &packet_hash,
                                );
                                continue;
                            }
                        }

                        // Check if destination has a proof strategy — generate proof if needed
                        self.maybe_generate_proof(destination_hash, &packet_hash);

                        self.callbacks.on_local_delivery(
                            rns_core::types::DestHash(destination_hash),
                            raw,
                            rns_core::types::PacketHash(packet_hash),
                        );
                    }
                }
                TransportAction::AnnounceReceived {
                    destination_hash,
                    identity_hash,
                    public_key,
                    name_hash,
                    app_data,
                    hops,
                    receiving_interface,
                    ..
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::AnnounceReceived as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "AnnounceReceived",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }

                    // Check if this is a discovery announce (matched by name_hash
                    // since discovery is a SINGLE destination — its dest hash varies
                    // with the sender's identity).
                    if name_hash == self.discovery_name_hash {
                        if self.discover_interfaces {
                            if let Some(ref app_data) = app_data {
                                if let Some(mut discovered) =
                                    crate::discovery::parse_interface_announce(
                                        app_data,
                                        &identity_hash,
                                        hops,
                                        self.discovery_required_value,
                                    )
                                {
                                    // Check if we already have this interface
                                    if let Ok(Some(existing)) =
                                        self.discovered_interfaces.load(&discovered.discovery_hash)
                                    {
                                        discovered.discovered = existing.discovered;
                                        discovered.heard_count = existing.heard_count + 1;
                                    }
                                    if let Err(e) = self.discovered_interfaces.store(&discovered) {
                                        log::warn!("Failed to store discovered interface: {}", e);
                                    } else {
                                        log::debug!(
                                            "Discovered interface '{}' ({}) at {}:{} [stamp={}]",
                                            discovered.name,
                                            discovered.interface_type,
                                            discovered.reachable_on.as_deref().unwrap_or("?"),
                                            discovered
                                                .port
                                                .map(|p| p.to_string())
                                                .unwrap_or_else(|| "?".into()),
                                            discovered.stamp_value,
                                        );
                                    }
                                }
                            }
                        }
                        // Still cache the identity and notify callbacks
                    }

                    // Cache the announced identity
                    let announced = crate::destination::AnnouncedIdentity {
                        dest_hash: rns_core::types::DestHash(destination_hash),
                        identity_hash: rns_core::types::IdentityHash(identity_hash),
                        public_key,
                        app_data: app_data.clone(),
                        hops,
                        received_at: time::now(),
                        receiving_interface,
                    };
                    self.known_destinations
                        .insert(destination_hash, announced.clone());
                    log::info!(
                        "Announce:validated dest={:02x}{:02x}{:02x}{:02x}.. hops={}",
                        destination_hash[0],
                        destination_hash[1],
                        destination_hash[2],
                        destination_hash[3],
                        hops,
                    );
                    self.callbacks.on_announce(announced);
                }
                TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    interface,
                    ..
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::PathUpdated as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("PathUpdated", e, &mut hook_injected);
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = interface;

                    self.callbacks
                        .on_path_updated(rns_core::types::DestHash(destination_hash), hops);
                }
                TransportAction::ForwardToLocalClients { raw, exclude } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.enabled
                            && entry.info.is_local_client
                            && Some(entry.id) != exclude
                        {
                            if Self::interface_send_deferred(entry, Instant::now()) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.clone()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            let send_result = entry.writer.send_frame(&data);
                            Self::record_send_result(
                                entry,
                                &send_result,
                                "forward to local client",
                                entry.id,
                            );
                        }
                    }
                }
                TransportAction::ForwardPlainBroadcast {
                    raw,
                    to_local,
                    exclude,
                } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.enabled
                            && entry.info.is_local_client == to_local
                            && Some(entry.id) != exclude
                        {
                            if Self::interface_send_deferred(entry, Instant::now()) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.clone()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            let send_result = entry.writer.send_frame(&data);
                            Self::record_send_result(
                                entry,
                                &send_result,
                                "forward plain broadcast",
                                entry.id,
                            );
                        }
                    }
                }
                TransportAction::CacheAnnounce { packet_hash, raw } => {
                    if let Some(ref cache) = self.announce_cache {
                        if let Err(e) = cache.store(&packet_hash, &raw, None) {
                            log::warn!("Failed to cache announce: {}", e);
                        }
                    }
                }
                TransportAction::TunnelSynthesize {
                    interface,
                    data,
                    dest_hash,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: 0,
                            hops: 0,
                            destination_hash: dest_hash,
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface.0,
                            data_offset: 0,
                            data_len: data.len() as u32,
                        };
                        let ctx = HookContext::Packet {
                            ctx: &pkt_ctx,
                            raw: &data,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::TunnelSynthesize as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "TunnelSynthesize",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }
                    // Pack as BROADCAST DATA PLAIN packet and send on interface
                    let flags = rns_core::packet::PacketFlags {
                        header_type: rns_core::constants::HEADER_1,
                        context_flag: rns_core::constants::FLAG_UNSET,
                        transport_type: rns_core::constants::TRANSPORT_BROADCAST,
                        destination_type: rns_core::constants::DESTINATION_PLAIN,
                        packet_type: rns_core::constants::PACKET_TYPE_DATA,
                    };
                    if let Ok(packet) = rns_core::packet::RawPacket::pack(
                        flags,
                        0,
                        &dest_hash,
                        None,
                        rns_core::constants::CONTEXT_NONE,
                        &data,
                    ) {
                        if let Some(entry) = self.interfaces.get_mut(&interface) {
                            if entry.online && entry.enabled {
                                let raw = if let Some(ref ifac_state) = entry.ifac {
                                    ifac::mask_outbound(&packet.raw, ifac_state)
                                } else {
                                    packet.raw
                                };
                                entry.stats.txb += raw.len() as u64;
                                entry.stats.tx_packets += 1;
                                if let Err(e) = entry.writer.send_frame(&raw) {
                                    log::warn!(
                                        "[{}] tunnel synthesize send failed: {}",
                                        entry.info.id.0,
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
                TransportAction::TunnelEstablished {
                    tunnel_id,
                    interface,
                } => {
                    log::info!(
                        "Tunnel established: {:02x?} on interface {}",
                        &tunnel_id[..4],
                        interface.0
                    );
                }
                TransportAction::AnnounceRetransmit {
                    destination_hash,
                    hops,
                    interface,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.map(|i| i.0).unwrap_or(0),
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::AnnounceRetransmit as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "AnnounceRetransmit",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (destination_hash, hops, interface);
                    }
                }
                TransportAction::LinkRequestReceived {
                    link_id,
                    destination_hash: _,
                    receiving_interface,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkRequestReceived as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkRequestReceived",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (link_id, receiving_interface);
                    }
                }
                TransportAction::LinkEstablished { link_id, interface } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkEstablished as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkEstablished",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (link_id, interface);
                    }
                }
                TransportAction::LinkClosed { link_id } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkClosed as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("LinkClosed", e, &mut hook_injected);
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = link_id;
                    }
                }
            }
        }

        // Dispatch any actions injected by hooks during action processing
        #[cfg(feature = "rns-hooks")]
        if !hook_injected.is_empty() {
            self.dispatch_all(hook_injected);
        }
    }

    /// Dispatch link manager actions.
    fn dispatch_link_actions(&mut self, actions: Vec<LinkManagerAction>) {
        #[cfg(feature = "rns-hooks")]
        let mut hook_injected: Vec<TransportAction> = Vec::new();

        for action in actions {
            match action {
                LinkManagerAction::SendPacket {
                    raw,
                    dest_type,
                    attached_interface,
                } => {
                    // Route through the transport engine's outbound path
                    match RawPacket::unpack(&raw) {
                        Ok(packet) => {
                            let transport_actions = self.engine.handle_outbound(
                                &packet,
                                dest_type,
                                attached_interface,
                                time::now(),
                            );
                            self.dispatch_all(transport_actions);
                        }
                        Err(e) => {
                            log::warn!("LinkManager SendPacket: failed to unpack: {:?}", e);
                        }
                    }
                }
                LinkManagerAction::LinkEstablished {
                    link_id,
                    dest_hash,
                    rtt,
                    is_initiator,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkEstablished as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkEstablished",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    log::info!(
                        "Link established: {:02x?} rtt={:.3}s initiator={}",
                        &link_id[..4],
                        rtt,
                        is_initiator,
                    );
                    self.callbacks.on_link_established(
                        rns_core::types::LinkId(link_id),
                        rns_core::types::DestHash(dest_hash),
                        rtt,
                        is_initiator,
                    );
                }
                LinkManagerAction::LinkClosed { link_id, reason } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkClosed as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("LinkClosed", e, &mut hook_injected);
                        }
                    }
                    log::info!("Link closed: {:02x?} reason={:?}", &link_id[..4], reason);
                    self.holepunch_manager.link_closed(&link_id);
                    self.callbacks
                        .on_link_closed(rns_core::types::LinkId(link_id), reason);
                }
                LinkManagerAction::RemoteIdentified {
                    link_id,
                    identity_hash,
                    public_key,
                } => {
                    log::debug!(
                        "Remote identified on link {:02x?}: {:02x?}",
                        &link_id[..4],
                        &identity_hash[..4],
                    );
                    self.callbacks.on_remote_identified(
                        rns_core::types::LinkId(link_id),
                        rns_core::types::IdentityHash(identity_hash),
                        public_key,
                    );
                }
                LinkManagerAction::RegisterLinkDest { link_id } => {
                    // Register the link_id as a LINK destination in the transport engine
                    self.engine
                        .register_destination(link_id, rns_core::constants::DESTINATION_LINK);
                }
                LinkManagerAction::DeregisterLinkDest { link_id } => {
                    self.engine.deregister_destination(&link_id);
                }
                LinkManagerAction::ManagementRequest {
                    link_id,
                    path_hash,
                    data,
                    request_id,
                    remote_identity,
                } => {
                    self.handle_management_request(
                        link_id,
                        path_hash,
                        data,
                        request_id,
                        remote_identity,
                    );
                }
                LinkManagerAction::ResourceReceived {
                    link_id,
                    data,
                    metadata,
                } => {
                    self.callbacks.on_resource_received(
                        rns_core::types::LinkId(link_id),
                        data,
                        metadata,
                    );
                }
                LinkManagerAction::ResourceCompleted { link_id } => {
                    self.callbacks
                        .on_resource_completed(rns_core::types::LinkId(link_id));
                }
                LinkManagerAction::ResourceFailed { link_id, error } => {
                    log::debug!("Resource failed on link {:02x?}: {}", &link_id[..4], error);
                    self.callbacks
                        .on_resource_failed(rns_core::types::LinkId(link_id), error);
                }
                LinkManagerAction::ResourceProgress {
                    link_id,
                    received,
                    total,
                } => {
                    self.callbacks.on_resource_progress(
                        rns_core::types::LinkId(link_id),
                        received,
                        total,
                    );
                }
                LinkManagerAction::ResourceAcceptQuery {
                    link_id,
                    resource_hash,
                    transfer_size,
                    has_metadata,
                } => {
                    let accept = self.callbacks.on_resource_accept_query(
                        rns_core::types::LinkId(link_id),
                        resource_hash.clone(),
                        transfer_size,
                        has_metadata,
                    );
                    let accept_actions = self.link_manager.accept_resource(
                        &link_id,
                        &resource_hash,
                        accept,
                        &mut self.rng,
                    );
                    // Re-dispatch (recursive but bounded: accept_resource won't produce more AcceptQuery)
                    self.dispatch_link_actions(accept_actions);
                }
                LinkManagerAction::ChannelMessageReceived {
                    link_id,
                    msgtype,
                    payload,
                } => {
                    // Intercept hole-punch signaling messages (0xFE00..=0xFE04)
                    if HolePunchManager::is_holepunch_message(msgtype) {
                        let derived_key = self.link_manager.get_derived_key(&link_id);
                        let tx = self.get_event_sender();
                        let (handled, hp_actions) = self.holepunch_manager.handle_signal(
                            link_id,
                            msgtype,
                            payload,
                            derived_key.as_deref(),
                            &tx,
                        );
                        if handled {
                            self.dispatch_holepunch_actions(hp_actions);
                        }
                    } else {
                        self.callbacks.on_channel_message(
                            rns_core::types::LinkId(link_id),
                            msgtype,
                            payload,
                        );
                    }
                }
                LinkManagerAction::LinkDataReceived {
                    link_id,
                    context,
                    data,
                } => {
                    self.callbacks
                        .on_link_data(rns_core::types::LinkId(link_id), context, data);
                }
                LinkManagerAction::ResponseReceived {
                    link_id,
                    request_id,
                    data,
                } => {
                    self.callbacks
                        .on_response(rns_core::types::LinkId(link_id), request_id, data);
                }
                LinkManagerAction::LinkRequestReceived {
                    link_id,
                    receiving_interface,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkRequestReceived as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkRequestReceived",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (link_id, receiving_interface);
                    }
                }
            }
        }

        // Dispatch any actions injected by hooks during action processing
        #[cfg(feature = "rns-hooks")]
        if !hook_injected.is_empty() {
            self.dispatch_all(hook_injected);
        }
    }

    /// Dispatch hole-punch manager actions.
    fn dispatch_holepunch_actions(&mut self, actions: Vec<HolePunchManagerAction>) {
        for action in actions {
            match action {
                HolePunchManagerAction::SendChannelMessage {
                    link_id,
                    msgtype,
                    payload,
                } => {
                    if let Ok(link_actions) = self.link_manager.send_channel_message(
                        &link_id,
                        msgtype,
                        &payload,
                        &mut self.rng,
                    ) {
                        self.dispatch_link_actions(link_actions);
                    }
                }
                HolePunchManagerAction::DirectConnectEstablished {
                    link_id,
                    session_id,
                    interface_id,
                    rtt,
                    mtu,
                } => {
                    log::info!(
                        "Direct connection established for link {:02x?} session {:02x?} iface {} rtt={:.1}ms mtu={}",
                        &link_id[..4], &session_id[..4], interface_id.0, rtt * 1000.0, mtu
                    );
                    // Redirect the link's path to use the direct interface
                    self.engine
                        .redirect_path(&link_id, interface_id, time::now());
                    // Update the link's RTT and MTU to reflect the direct path
                    self.link_manager.set_link_rtt(&link_id, rtt);
                    self.link_manager.set_link_mtu(&link_id, mtu);
                    // Reset inbound timer — set_rtt shortens the keepalive/stale
                    // intervals, so without this the link goes stale immediately
                    self.link_manager.record_link_inbound(&link_id);
                    // Flush holepunch signaling messages from the channel window
                    self.link_manager.flush_channel_tx(&link_id);
                    self.callbacks.on_direct_connect_established(
                        rns_core::types::LinkId(link_id),
                        interface_id,
                    );
                }
                HolePunchManagerAction::DirectConnectFailed {
                    link_id,
                    session_id,
                    reason,
                } => {
                    log::debug!(
                        "Direct connection failed for link {:02x?} session {:02x?} reason={}",
                        &link_id[..4],
                        &session_id[..4],
                        reason
                    );
                    self.callbacks
                        .on_direct_connect_failed(rns_core::types::LinkId(link_id), reason);
                }
            }
        }
    }

    /// Get an event sender for worker threads to send results back to the driver.
    ///
    /// This is a bit of a workaround since the driver owns the receiver.
    /// We store a clone of the sender when the driver is created.
    fn get_event_sender(&self) -> crate::event::EventSender {
        // The driver doesn't directly have a sender, but node.rs creates the channel
        // and passes rx to the driver. We need to store a sender clone.
        // For now we use an internal sender that was set during construction.
        self.event_tx.clone()
    }

    /// Delay before first management announce after startup.
    const MANAGEMENT_ANNOUNCE_DELAY: f64 = 5.0;

    /// Tick the discovery announcer: start stamp generation if due, send announce if ready.
    fn tick_discovery_announcer(&mut self, now: f64) {
        let announcer = match self.interface_announcer.as_mut() {
            Some(a) => a,
            None => return,
        };

        announcer.maybe_start(now);

        let stamp_result = match announcer.poll_ready() {
            Some(r) => r,
            None => return,
        };

        if !announcer.contains_interface(&stamp_result.interface_name) {
            log::debug!(
                "Discovery: dropping completed stamp for removed interface '{}'",
                stamp_result.interface_name
            );
            return;
        }

        let identity = match self.transport_identity.as_ref() {
            Some(id) => id,
            None => {
                log::warn!("Discovery: stamp ready but no transport identity");
                return;
            }
        };

        // Discovery is a SINGLE destination — the dest hash includes the transport identity
        let identity_hash = identity.hash();
        let disc_dest = rns_core::destination::destination_hash(
            crate::discovery::APP_NAME,
            &["discovery", "interface"],
            Some(&identity_hash),
        );
        let name_hash = self.discovery_name_hash;
        let mut random_hash = [0u8; 10];
        self.rng.fill_bytes(&mut random_hash);

        let (announce_data, _) = match rns_core::announce::AnnounceData::pack(
            identity,
            &disc_dest,
            &name_hash,
            &random_hash,
            None,
            Some(&stamp_result.app_data),
        ) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Discovery: failed to pack announce: {}", e);
                return;
            }
        };

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_ANNOUNCE,
        };

        let packet = match RawPacket::pack(
            flags,
            0,
            &disc_dest,
            None,
            rns_core::constants::CONTEXT_NONE,
            &announce_data,
        ) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Discovery: failed to pack packet: {}", e);
                return;
            }
        };

        let outbound_actions = self.engine.handle_outbound(
            &packet,
            rns_core::constants::DESTINATION_SINGLE,
            None,
            now,
        );
        log::debug!(
            "Discovery announce sent for interface '{}' ({} actions, dest={:02x?})",
            stamp_result.interface_name,
            outbound_actions.len(),
            &disc_dest[..4],
        );
        self.dispatch_all(outbound_actions);
    }

    /// Read RSS from /proc/self/statm (Linux only).
    fn rss_mb() -> Option<f64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(rss_pages as f64 * 4096.0 / (1024.0 * 1024.0))
    }

    /// Log sizes of all major collections for memory growth diagnostics.
    fn log_memory_stats(&self) {
        let rss = Self::rss_mb()
            .map(|v| format!("{:.1}", v))
            .unwrap_or_else(|| "N/A".into());
        log::info!(
            "MEMSTATS rss_mb={} known_dest={} path={} announce={} reverse={} \
             link={} held_ann={} hashlist={} sig_cache={} ann_verify_q={} rate_lim={} blackhole={} tunnel={} \
             pr_tags={} disc_pr={} sent_pkt={} completed={} local_dest={} \
             shared_ann={} lm_links={} hp_sessions={} proof_strat={}",
            rss,
            self.known_destinations.len(),
            self.engine.path_table_count(),
            self.engine.announce_table_count(),
            self.engine.reverse_table_count(),
            self.engine.link_table_count(),
            self.engine.held_announces_count(),
            self.engine.packet_hashlist_len(),
            self.engine.announce_sig_cache_len(),
            self.announce_verify_queue
                .lock()
                .map(|queue| queue.len())
                .unwrap_or(0),
            self.engine.rate_limiter_count(),
            self.engine.blackholed_count(),
            self.engine.tunnel_count(),
            self.engine.discovery_pr_tags_count(),
            self.engine.discovery_path_requests_count(),
            self.sent_packets.len(),
            self.completed_proofs.len(),
            self.local_destinations.len(),
            self.shared_announces.len(),
            self.link_manager.link_count(),
            self.holepunch_manager.session_count(),
            self.proof_strategies.len(),
        );
    }

    /// Emit management and/or blackhole announces if enabled and due.
    fn tick_management_announces(&mut self, now: f64) {
        if self.transport_identity.is_none() {
            return;
        }

        let uptime = now - self.started;

        // Wait for initial delay
        if !self.initial_announce_sent {
            if uptime < Self::MANAGEMENT_ANNOUNCE_DELAY {
                return;
            }
            self.initial_announce_sent = true;
            self.emit_management_announces(now);
            return;
        }

        // Periodic re-announce
        if now - self.last_management_announce >= self.management_announce_interval_secs {
            self.emit_management_announces(now);
        }
    }

    /// Emit management/blackhole announce packets through the engine outbound path.
    fn emit_management_announces(&mut self, now: f64) {
        use crate::management;

        self.last_management_announce = now;

        let identity = match self.transport_identity {
            Some(ref id) => id,
            None => return,
        };

        // Build announce packets first (immutable borrow of identity), then dispatch
        let mgmt_raw = if self.management_config.enable_remote_management {
            management::build_management_announce(identity, &mut self.rng)
        } else {
            None
        };

        let bh_raw = if self.management_config.publish_blackhole {
            management::build_blackhole_announce(identity, &mut self.rng)
        } else {
            None
        };

        let probe_raw = if self.probe_responder_hash.is_some() {
            management::build_probe_announce(identity, &mut self.rng)
        } else {
            None
        };

        if let Some(raw) = mgmt_raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted management destination announce");
            }
        }

        if let Some(raw) = bh_raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted blackhole info announce");
            }
        }

        if let Some(raw) = probe_raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted probe responder announce");
            }
        }
    }

    /// Handle a management request by querying engine state and sending a response.
    fn handle_management_request(
        &mut self,
        link_id: [u8; 16],
        path_hash: [u8; 16],
        data: Vec<u8>,
        request_id: [u8; 16],
        remote_identity: Option<([u8; 16], [u8; 64])>,
    ) {
        use crate::management;

        // ACL check for /status and /path (ALLOW_LIST), /list is ALLOW_ALL
        let is_restricted = path_hash == management::status_path_hash()
            || path_hash == management::path_path_hash();

        if is_restricted && !self.management_config.remote_management_allowed.is_empty() {
            match remote_identity {
                Some((identity_hash, _)) => {
                    if !self
                        .management_config
                        .remote_management_allowed
                        .contains(&identity_hash)
                    {
                        log::debug!("Management request denied: identity not in allowed list");
                        return;
                    }
                }
                None => {
                    log::debug!("Management request denied: peer not identified");
                    return;
                }
            }
        }

        let response_data = if path_hash == management::status_path_hash() {
            {
                let views: Vec<&dyn management::InterfaceStatusView> = self
                    .interfaces
                    .values()
                    .map(|e| e as &dyn management::InterfaceStatusView)
                    .collect();
                management::handle_status_request(
                    &data,
                    &self.engine,
                    &views,
                    self.started,
                    self.probe_responder_hash,
                )
            }
        } else if path_hash == management::path_path_hash() {
            management::handle_path_request(&data, &self.engine)
        } else if path_hash == management::list_path_hash() {
            management::handle_blackhole_list_request(&self.engine)
        } else {
            log::warn!("Unknown management path_hash: {:02x?}", &path_hash[..4]);
            None
        };

        if let Some(response) = response_data {
            let actions = self.link_manager.send_management_response(
                &link_id,
                &request_id,
                &response,
                &mut self.rng,
            );
            self.dispatch_link_actions(actions);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event;
    use crate::interface::Writer;
    use rns_core::announce::AnnounceData;
    use rns_core::constants;
    use rns_core::packet::PacketFlags;
    use rns_core::transport::types::InterfaceInfo;
    use rns_crypto::identity::Identity;
    use std::io;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    struct MockWriter {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockWriter {
        fn new() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (MockWriter { sent: sent.clone() }, sent)
        }
    }

    impl Writer for MockWriter {
        fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
            self.sent.lock().unwrap().push(data.to_vec());
            Ok(())
        }
    }

    struct WouldBlockWriter {
        attempts: Arc<Mutex<usize>>,
    }

    impl WouldBlockWriter {
        fn new() -> (Self, Arc<Mutex<usize>>) {
            let attempts = Arc::new(Mutex::new(0));
            (
                WouldBlockWriter {
                    attempts: attempts.clone(),
                },
                attempts,
            )
        }
    }

    impl Writer for WouldBlockWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            *self.attempts.lock().unwrap() += 1;
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "intentional stall",
            ))
        }
    }

    use rns_core::types::{DestHash, IdentityHash, LinkId as TypedLinkId, PacketHash};

    struct MockCallbacks {
        announces: Arc<Mutex<Vec<(DestHash, u8)>>>,
        paths: Arc<Mutex<Vec<(DestHash, u8)>>>,
        deliveries: Arc<Mutex<Vec<DestHash>>>,
        iface_ups: Arc<Mutex<Vec<InterfaceId>>>,
        iface_downs: Arc<Mutex<Vec<InterfaceId>>>,
        link_established: Arc<Mutex<Vec<(TypedLinkId, f64, bool)>>>,
        link_closed: Arc<Mutex<Vec<TypedLinkId>>>,
        remote_identified: Arc<Mutex<Vec<(TypedLinkId, IdentityHash)>>>,
        resources_received: Arc<Mutex<Vec<(TypedLinkId, Vec<u8>)>>>,
        resource_completed: Arc<Mutex<Vec<TypedLinkId>>>,
        resource_failed: Arc<Mutex<Vec<(TypedLinkId, String)>>>,
        channel_messages: Arc<Mutex<Vec<(TypedLinkId, u16, Vec<u8>)>>>,
        link_data: Arc<Mutex<Vec<(TypedLinkId, u8, Vec<u8>)>>>,
        responses: Arc<Mutex<Vec<(TypedLinkId, [u8; 16], Vec<u8>)>>>,
        proofs: Arc<Mutex<Vec<(DestHash, PacketHash, f64)>>>,
        proof_requested: Arc<Mutex<Vec<(DestHash, PacketHash)>>>,
    }

    impl MockCallbacks {
        fn new() -> (
            Self,
            Arc<Mutex<Vec<(DestHash, u8)>>>,
            Arc<Mutex<Vec<(DestHash, u8)>>>,
            Arc<Mutex<Vec<DestHash>>>,
            Arc<Mutex<Vec<InterfaceId>>>,
            Arc<Mutex<Vec<InterfaceId>>>,
        ) {
            let announces = Arc::new(Mutex::new(Vec::new()));
            let paths = Arc::new(Mutex::new(Vec::new()));
            let deliveries = Arc::new(Mutex::new(Vec::new()));
            let iface_ups = Arc::new(Mutex::new(Vec::new()));
            let iface_downs = Arc::new(Mutex::new(Vec::new()));
            (
                MockCallbacks {
                    announces: announces.clone(),
                    paths: paths.clone(),
                    deliveries: deliveries.clone(),
                    iface_ups: iface_ups.clone(),
                    iface_downs: iface_downs.clone(),
                    link_established: Arc::new(Mutex::new(Vec::new())),
                    link_closed: Arc::new(Mutex::new(Vec::new())),
                    remote_identified: Arc::new(Mutex::new(Vec::new())),
                    resources_received: Arc::new(Mutex::new(Vec::new())),
                    resource_completed: Arc::new(Mutex::new(Vec::new())),
                    resource_failed: Arc::new(Mutex::new(Vec::new())),
                    channel_messages: Arc::new(Mutex::new(Vec::new())),
                    link_data: Arc::new(Mutex::new(Vec::new())),
                    responses: Arc::new(Mutex::new(Vec::new())),
                    proofs: Arc::new(Mutex::new(Vec::new())),
                    proof_requested: Arc::new(Mutex::new(Vec::new())),
                },
                announces,
                paths,
                deliveries,
                iface_ups,
                iface_downs,
            )
        }

        fn with_link_tracking() -> (
            Self,
            Arc<Mutex<Vec<(TypedLinkId, f64, bool)>>>,
            Arc<Mutex<Vec<TypedLinkId>>>,
            Arc<Mutex<Vec<(TypedLinkId, IdentityHash)>>>,
        ) {
            let link_established = Arc::new(Mutex::new(Vec::new()));
            let link_closed = Arc::new(Mutex::new(Vec::new()));
            let remote_identified = Arc::new(Mutex::new(Vec::new()));
            (
                MockCallbacks {
                    announces: Arc::new(Mutex::new(Vec::new())),
                    paths: Arc::new(Mutex::new(Vec::new())),
                    deliveries: Arc::new(Mutex::new(Vec::new())),
                    iface_ups: Arc::new(Mutex::new(Vec::new())),
                    iface_downs: Arc::new(Mutex::new(Vec::new())),
                    link_established: link_established.clone(),
                    link_closed: link_closed.clone(),
                    remote_identified: remote_identified.clone(),
                    resources_received: Arc::new(Mutex::new(Vec::new())),
                    resource_completed: Arc::new(Mutex::new(Vec::new())),
                    resource_failed: Arc::new(Mutex::new(Vec::new())),
                    channel_messages: Arc::new(Mutex::new(Vec::new())),
                    link_data: Arc::new(Mutex::new(Vec::new())),
                    responses: Arc::new(Mutex::new(Vec::new())),
                    proofs: Arc::new(Mutex::new(Vec::new())),
                    proof_requested: Arc::new(Mutex::new(Vec::new())),
                },
                link_established,
                link_closed,
                remote_identified,
            )
        }
    }

    fn new_test_driver() -> Driver {
        let transport_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
        };
        let (callbacks, _, _, _, _, _) = MockCallbacks::new();
        let (tx, rx) = event::channel();
        let mut driver = Driver::new(transport_config, rx, tx, Box::new(callbacks));
        driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
        driver
    }

    #[cfg(feature = "iface-backbone")]
    fn register_test_backbone(driver: &mut Driver, name: &str) {
        let startup = BackboneServerRuntime {
            max_connections: Some(8),
            idle_timeout: Some(Duration::from_secs(10)),
            write_stall_timeout: Some(Duration::from_secs(30)),
            abuse: BackboneAbuseConfig {
                max_penalty_duration: Some(Duration::from_secs(3600)),
            },
        };
        let peer_state = Arc::new(std::sync::Mutex::new(
            crate::interface::backbone::BackbonePeerMonitor::new(),
        ));
        driver.register_backbone_runtime(BackboneRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
        driver.register_backbone_peer_state(BackbonePeerStateHandle {
            interface_id: InterfaceId(1),
            interface_name: name.to_string(),
            peer_state,
        });
    }

    #[cfg(feature = "iface-backbone")]
    fn register_test_backbone_client(driver: &mut Driver, name: &str) {
        let startup = BackboneClientRuntime {
            reconnect_wait: Duration::from_secs(5),
            max_reconnect_tries: Some(3),
            connect_timeout: Duration::from_secs(5),
        };
        driver.register_backbone_client_runtime(BackboneClientRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-backbone")]
    fn register_test_backbone_discovery(driver: &mut Driver, name: &str, discoverable: bool) {
        let startup = BackboneDiscoveryRuntime {
            discoverable,
            config: crate::discovery::DiscoveryConfig {
                discovery_name: name.to_string(),
                announce_interval: 3600,
                stamp_value: crate::discovery::DEFAULT_STAMP_VALUE,
                reachable_on: None,
                interface_type: "BackboneInterface".to_string(),
                listen_port: Some(4242),
                latitude: None,
                longitude: None,
                height: None,
            },
            transport_enabled: true,
            ifac_netname: None,
            ifac_netkey: None,
        };
        driver.register_backbone_discovery_runtime(BackboneDiscoveryRuntimeHandle {
            interface_name: name.to_string(),
            current: startup.clone(),
            startup,
        });
    }

    #[cfg(feature = "iface-tcp")]
    fn register_test_tcp_server(driver: &mut Driver, name: &str) {
        let startup = TcpServerRuntime {
            max_connections: Some(4),
        };
        driver.register_tcp_server_runtime(TcpServerRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-tcp")]
    fn register_test_tcp_server_discovery(driver: &mut Driver, name: &str, discoverable: bool) {
        let startup = TcpServerDiscoveryRuntime {
            discoverable,
            config: crate::discovery::DiscoveryConfig {
                discovery_name: name.to_string(),
                announce_interval: 3600,
                stamp_value: crate::discovery::DEFAULT_STAMP_VALUE,
                reachable_on: None,
                interface_type: "TCPServerInterface".to_string(),
                listen_port: Some(4242),
                latitude: None,
                longitude: None,
                height: None,
            },
            transport_enabled: true,
            ifac_netname: None,
            ifac_netkey: None,
        };
        driver.register_tcp_server_discovery_runtime(TcpServerDiscoveryRuntimeHandle {
            interface_name: name.to_string(),
            current: startup.clone(),
            startup,
        });
    }

    #[cfg(feature = "iface-tcp")]
    fn register_test_tcp_client(driver: &mut Driver, name: &str) {
        let startup = crate::interface::tcp::TcpClientRuntime {
            target_host: "127.0.0.1".into(),
            target_port: 4242,
            reconnect_wait: Duration::from_secs(5),
            max_reconnect_tries: Some(3),
            connect_timeout: Duration::from_secs(5),
        };
        driver.register_tcp_client_runtime(crate::interface::tcp::TcpClientRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-udp")]
    fn register_test_udp(driver: &mut Driver, name: &str) {
        let startup = UdpRuntime {
            forward_ip: Some("127.0.0.1".into()),
            forward_port: Some(4242),
        };
        driver.register_udp_runtime(UdpRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    fn register_test_generic_interface(driver: &mut Driver, id: u64, name: &str) {
        let mut info = make_interface_info(id);
        info.name = name.to_string();
        info.mode = rns_core::constants::MODE_FULL;
        info.announce_rate_target = Some(1.5);
        info.announce_rate_grace = 2;
        info.announce_rate_penalty = 0.25;
        info.announce_cap = 0.05;
        info.ingress_control = true;
        driver.register_interface_runtime_defaults(&info);
        driver.register_interface_ifac_runtime(
            &info.name,
            IfacRuntimeConfig {
                netname: None,
                netkey: None,
                size: 16,
            },
        );
        driver.engine.register_interface(info.clone());
        let (writer, _) = MockWriter::new();
        driver.interfaces.insert(
            InterfaceId(id),
            InterfaceEntry {
                id: InterfaceId(id),
                info,
                writer: Box::new(writer),
                enabled: true,
                online: true,
                dynamic: false,
                ifac: None,
                stats: InterfaceStats {
                    started: time::now(),
                    ..Default::default()
                },
                interface_type: "TestInterface".to_string(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );
    }

    #[cfg(feature = "iface-auto")]
    fn register_test_auto(driver: &mut Driver, name: &str) {
        let startup = AutoRuntime {
            announce_interval_secs: 1.6,
            peer_timeout_secs: 22.0,
            peer_job_interval_secs: 4.0,
        };
        driver.register_auto_runtime(AutoRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-i2p")]
    fn register_test_i2p(driver: &mut Driver, name: &str) {
        let startup = I2pRuntime {
            reconnect_wait: Duration::from_secs(15),
        };
        driver.register_i2p_runtime(I2pRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-pipe")]
    fn register_test_pipe(driver: &mut Driver, name: &str) {
        let startup = PipeRuntime {
            respawn_delay: Duration::from_secs(5),
        };
        driver.register_pipe_runtime(PipeRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-rnode")]
    fn register_test_rnode(driver: &mut Driver, name: &str) {
        let startup = RNodeRuntime {
            sub: RNodeSubConfig {
                name: name.to_string(),
                frequency: 868_000_000,
                bandwidth: 125_000,
                txpower: 7,
                spreading_factor: 8,
                coding_rate: 5,
                flow_control: false,
                st_alock: None,
                lt_alock: None,
            },
            writer: None,
        };
        driver.register_rnode_runtime(RNodeRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    impl Callbacks for MockCallbacks {
        fn on_announce(&mut self, announced: crate::destination::AnnouncedIdentity) {
            self.announces
                .lock()
                .unwrap()
                .push((announced.dest_hash, announced.hops));
        }

        fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
            self.paths.lock().unwrap().push((dest_hash, hops));
        }

        fn on_local_delivery(
            &mut self,
            dest_hash: DestHash,
            _raw: Vec<u8>,
            _packet_hash: PacketHash,
        ) {
            self.deliveries.lock().unwrap().push(dest_hash);
        }

        fn on_interface_up(&mut self, id: InterfaceId) {
            self.iface_ups.lock().unwrap().push(id);
        }

        fn on_interface_down(&mut self, id: InterfaceId) {
            self.iface_downs.lock().unwrap().push(id);
        }

        fn on_link_established(
            &mut self,
            link_id: TypedLinkId,
            _dest_hash: DestHash,
            rtt: f64,
            is_initiator: bool,
        ) {
            self.link_established
                .lock()
                .unwrap()
                .push((link_id, rtt, is_initiator));
        }

        fn on_link_closed(
            &mut self,
            link_id: TypedLinkId,
            _reason: Option<rns_core::link::TeardownReason>,
        ) {
            self.link_closed.lock().unwrap().push(link_id);
        }

        fn on_remote_identified(
            &mut self,
            link_id: TypedLinkId,
            identity_hash: IdentityHash,
            _public_key: [u8; 64],
        ) {
            self.remote_identified
                .lock()
                .unwrap()
                .push((link_id, identity_hash));
        }

        fn on_resource_received(
            &mut self,
            link_id: TypedLinkId,
            data: Vec<u8>,
            _metadata: Option<Vec<u8>>,
        ) {
            self.resources_received
                .lock()
                .unwrap()
                .push((link_id, data));
        }

        fn on_resource_completed(&mut self, link_id: TypedLinkId) {
            self.resource_completed.lock().unwrap().push(link_id);
        }

        fn on_resource_failed(&mut self, link_id: TypedLinkId, error: String) {
            self.resource_failed.lock().unwrap().push((link_id, error));
        }

        fn on_channel_message(&mut self, link_id: TypedLinkId, msgtype: u16, payload: Vec<u8>) {
            self.channel_messages
                .lock()
                .unwrap()
                .push((link_id, msgtype, payload));
        }

        fn on_link_data(&mut self, link_id: TypedLinkId, context: u8, data: Vec<u8>) {
            self.link_data
                .lock()
                .unwrap()
                .push((link_id, context, data));
        }

        fn on_response(&mut self, link_id: TypedLinkId, request_id: [u8; 16], data: Vec<u8>) {
            self.responses
                .lock()
                .unwrap()
                .push((link_id, request_id, data));
        }

        fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
            self.proofs
                .lock()
                .unwrap()
                .push((dest_hash, packet_hash, rtt));
        }

        fn on_proof_requested(&mut self, dest_hash: DestHash, packet_hash: PacketHash) -> bool {
            self.proof_requested
                .lock()
                .unwrap()
                .push((dest_hash, packet_hash));
            true
        }
    }

    fn make_interface_info(id: u64) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: format!("test-{}", id),
            mode: constants::MODE_FULL,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ia_freq: 0.0,
            started: 0.0,
            ingress_control: false,
        }
    }

    fn make_entry(id: u64, writer: Box<dyn Writer>, online: bool) -> InterfaceEntry {
        InterfaceEntry {
            id: InterfaceId(id),
            info: make_interface_info(id),
            writer,
            enabled: true,
            online,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats::default(),
            interface_type: String::new(),
            send_retry_at: None,
            send_retry_backoff: Duration::ZERO,
        }
    }

    /// Build a valid announce packet that the engine will accept.
    fn build_announce_packet(identity: &Identity) -> Vec<u8> {
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));
        let name_hash = rns_core::destination::name_hash("test", &["app"]);
        let random_hash = [0x42u8; 10];

        let (announce_data, _has_ratchet) =
            AnnounceData::pack(identity, &dest_hash, &name_hash, &random_hash, None, None).unwrap();

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };

        let packet = RawPacket::pack(
            flags,
            0,
            &dest_hash,
            None,
            constants::CONTEXT_NONE,
            &announce_data,
        )
        .unwrap();
        packet.raw
    }

    #[test]
    fn process_inbound_frame() {
        let (tx, rx) = event::channel();
        let (cbs, announces, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        // Send frame then shutdown
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(announces.lock().unwrap().len(), 1);
    }

    #[test]
    fn dispatch_send() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x01, 0x02, 0x03],
        }]);

        assert_eq!(sent.lock().unwrap().len(), 1);
        assert_eq!(sent.lock().unwrap()[0], vec![0x01, 0x02, 0x03]);

        drop(tx);
    }

    #[test]
    fn dispatch_broadcast() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0xAA],
            exclude: None,
        }]);

        assert_eq!(sent1.lock().unwrap().len(), 1);
        assert_eq!(sent2.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn dispatch_broadcast_exclude() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0xBB],
            exclude: Some(InterfaceId(1)),
        }]);

        assert_eq!(sent1.lock().unwrap().len(), 0); // excluded
        assert_eq!(sent2.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn tick_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0x42; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Send Tick then Shutdown
        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();
        // No crash = tick was processed successfully
    }

    #[test]
    fn shutdown_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        tx.send(Event::Shutdown).unwrap();
        driver.run(); // Should return immediately
    }

    #[test]
    fn announce_callback() {
        let (tx, rx) = event::channel();
        let (cbs, announces, paths, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let ann = announces.lock().unwrap();
        assert_eq!(ann.len(), 1);
        // Hops should be 1 (incremented from 0 by handle_inbound)
        assert_eq!(ann[0].1, 1);

        let p = paths.lock().unwrap();
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn dispatch_skips_offline_interface() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w1), false)); // offline
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        // Direct send to offline interface: should be skipped
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x01],
        }]);
        assert_eq!(sent1.lock().unwrap().len(), 0);

        // Broadcast: only online interface should receive
        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0x02],
            exclude: None,
        }]);
        assert_eq!(sent1.lock().unwrap().len(), 0); // still offline
        assert_eq!(sent2.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn interface_up_refreshes_writer() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (w_old, sent_old) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w_old), false));

        // Simulate reconnect: InterfaceUp with new writer
        let (w_new, sent_new) = MockWriter::new();
        tx.send(Event::InterfaceUp(
            InterfaceId(1),
            Some(Box::new(w_new)),
            None,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Interface should be online now
        assert!(driver.interfaces[&InterfaceId(1)].online);

        // Send via the (now-refreshed) interface
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0xFF],
        }]);

        // Old writer should not have received anything
        assert_eq!(sent_old.lock().unwrap().len(), 0);
        // New writer should have received the data
        assert_eq!(sent_new.lock().unwrap().len(), 1);
        assert_eq!(sent_new.lock().unwrap()[0], vec![0xFF]);

        drop(tx);
    }

    #[test]
    fn dynamic_interface_register() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, iface_ups, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let info = make_interface_info(100);
        let (writer, sent) = MockWriter::new();

        // InterfaceUp with InterfaceInfo = new dynamic interface
        tx.send(Event::InterfaceUp(
            InterfaceId(100),
            Some(Box::new(writer)),
            Some(info),
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should be registered and online
        assert!(driver.interfaces.contains_key(&InterfaceId(100)));
        assert!(driver.interfaces[&InterfaceId(100)].online);
        assert!(driver.interfaces[&InterfaceId(100)].dynamic);

        // Callback should have fired
        assert_eq!(iface_ups.lock().unwrap().len(), 1);
        assert_eq!(iface_ups.lock().unwrap()[0], InterfaceId(100));

        // Can send to it
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(100),
            raw: vec![0x42],
        }]);
        assert_eq!(sent.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn dynamic_interface_deregister() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, iface_downs) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // Register a dynamic interface
        let info = make_interface_info(200);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(
            InterfaceId(200),
            InterfaceEntry {
                id: InterfaceId(200),
                info,
                writer: Box::new(writer),
                enabled: true,
                online: true,
                dynamic: true,
                ifac: None,
                stats: InterfaceStats::default(),
                interface_type: String::new(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );

        // InterfaceDown for dynamic → should be removed entirely
        tx.send(Event::InterfaceDown(InterfaceId(200))).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(!driver.interfaces.contains_key(&InterfaceId(200)));
        assert_eq!(iface_downs.lock().unwrap().len(), 1);
        assert_eq!(iface_downs.lock().unwrap()[0], InterfaceId(200));
    }

    #[test]
    fn send_wouldblock_is_backed_off_between_dispatches() {
        let (tx, rx) = event::channel();
        let (cbs, ..) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx,
            Box::new(cbs),
        );
        let (writer, attempts) = WouldBlockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(7), make_entry(7, Box::new(writer), true));

        let action = TransportAction::SendOnInterface {
            interface: InterfaceId(7),
            raw: vec![0x01, 0x00, 0x42],
        };
        driver.dispatch_all(vec![action.clone()]);
        assert_eq!(*attempts.lock().unwrap(), 1);

        driver.dispatch_all(vec![action.clone()]);
        assert_eq!(
            *attempts.lock().unwrap(),
            1,
            "second dispatch should be deferred during backoff"
        );

        let entry = driver.interfaces.get_mut(&InterfaceId(7)).unwrap();
        entry.send_retry_at = Some(Instant::now() - Duration::from_millis(1));
        driver.dispatch_all(vec![action]);
        assert_eq!(*attempts.lock().unwrap(), 2);
    }

    #[test]
    fn interface_callbacks_fire() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, iface_ups, iface_downs) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // Static interface
        let (writer, _) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), false));

        tx.send(Event::InterfaceUp(InterfaceId(1), None, None))
            .unwrap();
        tx.send(Event::InterfaceDown(InterfaceId(1))).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(iface_ups.lock().unwrap().len(), 1);
        assert_eq!(iface_downs.lock().unwrap().len(), 1);
        // Static interface should still exist but be offline
        assert!(driver.interfaces.contains_key(&InterfaceId(1)));
        assert!(!driver.interfaces[&InterfaceId(1)].online);
    }

    // =========================================================================
    // New tests for Phase 6a
    // =========================================================================

    #[test]
    fn frame_updates_rx_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let announce_len = announce_raw.len() as u64;

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.rxb, announce_len);
        assert_eq!(stats.rx_packets, 1);
    }

    #[test]
    fn send_updates_tx_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x01, 0x02, 0x03],
        }]);

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.txb, 3);
        assert_eq!(stats.tx_packets, 1);

        drop(tx);
    }

    #[test]
    fn broadcast_updates_tx_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (w1, _s1) = MockWriter::new();
        let (w2, _s2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0xAA, 0xBB],
            exclude: None,
        }]);

        // Both interfaces should have tx stats updated
        assert_eq!(driver.interfaces[&InterfaceId(1)].stats.txb, 2);
        assert_eq!(driver.interfaces[&InterfaceId(1)].stats.tx_packets, 1);
        assert_eq!(driver.interfaces[&InterfaceId(2)].stats.txb, 2);
        assert_eq!(driver.interfaces[&InterfaceId(2)].stats.tx_packets, 1);

        drop(tx);
    }

    #[test]
    fn query_interface_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0x42; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::InterfaceStats, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let resp = resp_rx.recv().unwrap();
        match resp {
            QueryResponse::InterfaceStats(stats) => {
                assert_eq!(stats.interfaces.len(), 1);
                assert_eq!(stats.interfaces[0].name, "test-1");
                assert!(stats.interfaces[0].status);
                assert_eq!(stats.transport_id, Some([0x42; 16]));
                assert!(stats.transport_enabled);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_path_table() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Feed an announce to create a path entry
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::PathTable { max_hops: None },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let resp = resp_rx.recv().unwrap();
        match resp {
            QueryResponse::PathTable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].hops, 1);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_drop_path() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Feed an announce to create a path entry
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::DropPath { dest_hash }, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let resp = resp_rx.recv().unwrap();
        match resp {
            QueryResponse::DropPath(dropped) => {
                assert!(dropped);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn send_outbound_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, sent) = MockWriter::new();
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Build a DATA packet to a destination
        let dest = [0xAA; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::SendOutbound {
            raw: packet.raw,
            dest_type: constants::DESTINATION_PLAIN,
            attached_interface: None,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // PLAIN packet should be broadcast on all interfaces
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn register_destination_and_deliver() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xBB; 16];

        // Register destination then send a data packet to it
        tx.send(Event::RegisterDestination {
            dest_hash: dest,
            dest_type: constants::DESTINATION_SINGLE,
        })
        .unwrap();

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"data").unwrap();
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(deliveries.lock().unwrap().len(), 1);
        assert_eq!(deliveries.lock().unwrap()[0], DestHash(dest));
    }

    #[test]
    fn query_transport_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0xAA; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::TransportIdentity, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::TransportIdentity(Some(hash)) => {
                assert_eq!(hash, [0xAA; 16]);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_link_count() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LinkCount, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LinkCount(count) => assert_eq!(count, 0),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_rate_table() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::RateTable, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::RateTable(entries) => assert!(entries.is_empty()),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_next_hop() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xBB; 16];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::NextHop { dest_hash: dest },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::NextHop(None) => {}
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_next_hop_if_name() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xCC; 16];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::NextHopIfName { dest_hash: dest },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::NextHopIfName(None) => {}
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_drop_all_via() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let transport = [0xDD; 16];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::DropAllVia {
                transport_hash: transport,
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::DropAllVia(count) => assert_eq!(count, 0),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_drop_announce_queues() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::DropAnnounceQueues, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::DropAnnounceQueues => {}
            _ => panic!("unexpected response"),
        }
    }

    // =========================================================================
    // Phase 7e: Link wiring integration tests
    // =========================================================================

    #[test]
    fn register_link_dest_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let mut rng = OsRng;
        let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
        let sig_pub_bytes = sig_prv.public_key().public_bytes();
        let sig_prv_bytes = sig_prv.private_bytes();
        let dest_hash = [0xDD; 16];

        tx.send(Event::RegisterLinkDestination {
            dest_hash,
            sig_prv_bytes,
            sig_pub_bytes,
            resource_strategy: 0,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Link manager should know about the destination
        assert!(driver.link_manager.is_link_destination(&dest_hash));
    }

    #[test]
    fn create_link_event() {
        let (tx, rx) = event::channel();
        let (cbs, _link_established, _, _) = MockCallbacks::with_link_tracking();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest_hash = [0xDD; 16];
        let dummy_sig_pub = [0xAA; 32];

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::CreateLink {
            dest_hash,
            dest_sig_pub_bytes: dummy_sig_pub,
            response_tx: resp_tx,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have received a link_id
        let link_id = resp_rx.recv().unwrap();
        assert_ne!(link_id, [0u8; 16]);

        // Link should be in pending state in the manager
        assert_eq!(driver.link_manager.link_count(), 1);

        // The LINKREQUEST packet won't be sent on the wire without a path
        // to the destination (DESTINATION_LINK requires a known path or
        // attached_interface). In a real scenario, the path would exist from
        // an announce received earlier.
    }

    #[test]
    fn deliver_local_routes_to_link_manager() {
        // Verify that DeliverLocal for a registered link destination goes to
        // the link manager instead of the callbacks.
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a link destination
        let mut rng = OsRng;
        let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
        let sig_pub_bytes = sig_prv.public_key().public_bytes();
        let dest_hash = [0xEE; 16];
        driver.link_manager.register_link_destination(
            dest_hash,
            sig_prv,
            sig_pub_bytes,
            crate::link_manager::ResourceStrategy::AcceptNone,
        );

        // dispatch_all with a DeliverLocal for that dest should route to link_manager
        // (not to callbacks). We can't easily test this via run() since we need
        // a valid LINKREQUEST, but we can check is_link_destination works.
        assert!(driver.link_manager.is_link_destination(&dest_hash));

        // Non-link destination should go to callbacks
        assert!(!driver.link_manager.is_link_destination(&[0xFF; 16]));

        drop(tx);
    }

    #[test]
    fn teardown_link_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, link_closed, _) = MockCallbacks::with_link_tracking();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Create a link first
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::CreateLink {
            dest_hash: [0xDD; 16],
            dest_sig_pub_bytes: [0xAA; 32],
            response_tx: resp_tx,
        })
        .unwrap();
        // Then tear it down
        // We can't receive resp_rx yet since driver.run() hasn't started,
        // but we know the link_id will be created. Send teardown after CreateLink.
        // Actually, we need to get the link_id first. Let's use a two-phase approach.
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let link_id = resp_rx.recv().unwrap();
        assert_ne!(link_id, [0u8; 16]);
        assert_eq!(driver.link_manager.link_count(), 1);

        // Now restart with same driver (just use events directly since driver loop exited)
        let teardown_actions = driver.link_manager.teardown_link(&link_id);
        driver.dispatch_link_actions(teardown_actions);

        // Callback should have been called
        assert_eq!(link_closed.lock().unwrap().len(), 1);
        assert_eq!(link_closed.lock().unwrap()[0], TypedLinkId(link_id));
    }

    #[test]
    fn link_count_includes_link_manager() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Create a link via link_manager directly
        let mut rng = OsRng;
        let dummy_sig = [0xAA; 32];
        driver.link_manager.create_link(
            &[0xDD; 16],
            &dummy_sig,
            1,
            constants::MTU as u32,
            &mut rng,
        );

        // Query link count — should include link_manager links
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LinkCount, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LinkCount(count) => assert_eq!(count, 1),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn register_request_handler_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        tx.send(Event::RegisterRequestHandler {
            path: "/status".to_string(),
            allowed_list: None,
            handler: Box::new(|_link_id, _path, _data, _remote| Some(b"OK".to_vec())),
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Handler should be registered (we can't directly query the count,
        // but at least verify no crash)
    }

    // Phase 8c: Management announce timing tests

    #[test]
    fn management_announces_emitted_after_delay() {
        let (tx, rx) = event::channel();
        let (cbs, _announces, _, _, _, _) = MockCallbacks::new();
        let identity = Identity::new(&mut OsRng);
        let identity_hash = *identity.hash();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some(identity_hash),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // Register interface so announces can be sent
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Enable management announces
        driver.management_config.enable_remote_management = true;
        driver.transport_identity = Some(identity);

        // Set started time to 10 seconds ago so the 5s delay has passed
        driver.started = time::now() - 10.0;

        // Send Tick then Shutdown
        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have sent at least one packet (the management announce)
        let sent_packets = sent.lock().unwrap();
        assert!(
            !sent_packets.is_empty(),
            "Management announce should be sent after startup delay"
        );
    }

    #[test]
    fn runtime_config_list_contains_global_keys() {
        let driver = new_test_driver();
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"global.tick_interval_ms".to_string()));
        assert!(keys.contains(&"global.known_destinations_ttl_secs".to_string()));
        assert!(keys.contains(&"global.rate_limiter_ttl_secs".to_string()));
        assert!(keys.contains(&"global.direct_connect_policy".to_string()));
    }

    #[test]
    fn runtime_config_set_and_reset_tick_interval() {
        let mut driver = new_test_driver();

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "global.tick_interval_ms".into(),
            value: RuntimeConfigValue::Int(250),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.key, "global.tick_interval_ms");
        assert_eq!(entry.value, RuntimeConfigValue::Int(250));
        assert_eq!(driver.tick_interval_ms.load(Ordering::Relaxed), 250);

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "global.tick_interval_ms".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(1000));
        assert_eq!(driver.tick_interval_ms.load(Ordering::Relaxed), 1000);
    }

    #[test]
    fn runtime_config_rejects_invalid_policy() {
        let mut driver = new_test_driver();
        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "global.direct_connect_policy".into(),
            value: RuntimeConfigValue::String("bogus".into()),
        });
        let QueryResponse::RuntimeConfigSet(Err(err)) = response else {
            panic!("expected runtime config set failure");
        };
        assert_eq!(err.code, RuntimeConfigErrorCode::InvalidValue);
    }

    #[test]
    fn runtime_config_set_and_reset_rate_limiter_ttl() {
        let mut driver = new_test_driver();

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "global.rate_limiter_ttl_secs".into(),
            value: RuntimeConfigValue::Float(600.0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(600.0));
        assert_eq!(driver.rate_limiter_ttl_secs, 600.0);

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "global.rate_limiter_ttl_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(
            entry.value,
            RuntimeConfigValue::Float(DEFAULT_RATE_LIMITER_TTL_SECS)
        );
        assert_eq!(driver.rate_limiter_ttl_secs, DEFAULT_RATE_LIMITER_TTL_SECS);
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn runtime_config_lists_backbone_keys() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        register_test_backbone_client(&mut driver, "uplink");
        register_test_backbone_discovery(&mut driver, "public", false);
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"backbone.public.idle_timeout_secs".to_string()));
        assert!(keys.contains(&"backbone.public.write_stall_timeout_secs".to_string()));
        assert!(keys.contains(&"backbone.public.max_connections".to_string()));
        assert!(keys.contains(&"backbone.public.discoverable".to_string()));
        assert!(keys.contains(&"backbone.public.discovery_name".to_string()));
        assert!(keys.contains(&"backbone.public.latitude".to_string()));
        assert!(keys.contains(&"backbone.public.longitude".to_string()));
        assert!(keys.contains(&"backbone.public.height".to_string()));
        assert!(keys.contains(&"backbone_client.uplink.connect_timeout_secs".to_string()));
        assert!(keys.contains(&"backbone_client.uplink.reconnect_wait_secs".to_string()));
        assert!(keys.contains(&"backbone_client.uplink.max_reconnect_tries".to_string()));
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn runtime_config_sets_backbone_values() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        register_test_backbone_discovery(&mut driver, "public", false);
        driver.transport_identity = Some(rns_crypto::identity::Identity::new(&mut OsRng));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.idle_timeout_secs".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.write_stall_timeout_secs".into(),
            value: RuntimeConfigValue::Float(15.0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(15.0));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.max_connections".into(),
            value: RuntimeConfigValue::Int(0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone.public.max_connections".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(8));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone.public.write_stall_timeout_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(30.0));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.discoverable".into(),
            value: RuntimeConfigValue::Bool(true),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(true));
        assert!(driver
            .interface_announcer
            .as_ref()
            .map(|announcer| announcer.contains_interface("public"))
            .unwrap_or(false));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.discovery_name".into(),
            value: RuntimeConfigValue::String("Public Backbone".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(
            entry.value,
            RuntimeConfigValue::String("Public Backbone".into())
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.latitude".into(),
            value: RuntimeConfigValue::Float(45.4642),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(45.4642));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.longitude".into(),
            value: RuntimeConfigValue::Float(9.19),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(9.19));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.height".into(),
            value: RuntimeConfigValue::Int(120),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(120.0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone.public.discoverable".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(false));
        assert!(driver.interface_announcer.is_none());

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone.public.latitude".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn runtime_config_sets_backbone_client_values() {
        let mut driver = new_test_driver();
        register_test_backbone_client(&mut driver, "uplink");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone_client.uplink.connect_timeout_secs".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone_client.uplink.max_reconnect_tries".into(),
            value: RuntimeConfigValue::Int(0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone_client.uplink.connect_timeout_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(5.0));
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_state_query_lists_entries() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        driver
            .backbone_peer_state
            .get("public")
            .unwrap()
            .peer_state
            .lock()
            .unwrap()
            .seed_entry(BackbonePeerStateEntry {
                interface_name: "public".into(),
                peer_ip: "203.0.113.10".parse().unwrap(),
                connected_count: 1,
                blacklisted_remaining_secs: Some(120.0),
                blacklist_reason: Some("repeated idle timeouts".into()),
                reject_count: 7,
            });

        let response = driver.handle_query(QueryRequest::BackbonePeerState {
            interface_name: Some("public".into()),
        });
        let QueryResponse::BackbonePeerState(entries) = response else {
            panic!("expected backbone peer state list");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].peer_ip.to_string(), "203.0.113.10");
        assert_eq!(entries[0].connected_count, 1);
        assert_eq!(entries[0].reject_count, 7);
        assert_eq!(
            entries[0].blacklist_reason.as_deref(),
            Some("repeated idle timeouts")
        );
        assert!(entries[0].blacklisted_remaining_secs.unwrap() > 0.0);
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_state_clear_removes_entry() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        driver
            .backbone_peer_state
            .get("public")
            .unwrap()
            .peer_state
            .lock()
            .unwrap()
            .seed_entry(BackbonePeerStateEntry {
                interface_name: "public".into(),
                peer_ip: "203.0.113.11".parse().unwrap(),
                connected_count: 0,
                blacklisted_remaining_secs: None,
                blacklist_reason: None,
                reject_count: 0,
            });

        let response = driver.handle_query_mut(QueryRequest::ClearBackbonePeerState {
            interface_name: "public".into(),
            peer_ip: "203.0.113.11".parse().unwrap(),
        });
        let QueryResponse::ClearBackbonePeerState(true) = response else {
            panic!("expected successful peer-state clear");
        };

        let response = driver.handle_query(QueryRequest::BackbonePeerState {
            interface_name: Some("public".into()),
        });
        let QueryResponse::BackbonePeerState(entries) = response else {
            panic!("expected backbone peer state list");
        };
        assert!(entries.is_empty());
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_blacklist_sets_blacklist() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        driver
            .backbone_peer_state
            .get("public")
            .unwrap()
            .peer_state
            .lock()
            .unwrap()
            .seed_entry(BackbonePeerStateEntry {
                interface_name: "public".into(),
                peer_ip: "203.0.113.50".parse().unwrap(),
                connected_count: 1,
                blacklisted_remaining_secs: None,
                blacklist_reason: None,
                reject_count: 0,
            });

        let response = driver.handle_query_mut(QueryRequest::BlacklistBackbonePeer {
            interface_name: "public".into(),
            peer_ip: "203.0.113.50".parse().unwrap(),
            duration: Duration::from_secs(300),
            reason: "sentinel blacklist".into(),
            penalty_level: 2,
        });
        let QueryResponse::BlacklistBackbonePeer(true) = response else {
            panic!("expected successful blacklist");
        };

        // Verify the peer is now blacklisted
        let response = driver.handle_query(QueryRequest::BackbonePeerState {
            interface_name: Some("public".into()),
        });
        let QueryResponse::BackbonePeerState(entries) = response else {
            panic!("expected backbone peer state list");
        };
        let entry = entries
            .iter()
            .find(|e| e.peer_ip == "203.0.113.50".parse::<std::net::IpAddr>().unwrap())
            .expect("expected entry for blacklisted peer");
        assert!(entry.blacklisted_remaining_secs.is_some());
        let remaining = entry.blacklisted_remaining_secs.unwrap();
        assert!(remaining > 290.0 && remaining <= 300.0);
        assert_eq!(
            entry.blacklist_reason.as_deref(),
            Some("sentinel blacklist")
        );
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_blacklist_unknown_interface_returns_false() {
        let mut driver = new_test_driver();
        let response = driver.handle_query_mut(QueryRequest::BlacklistBackbonePeer {
            interface_name: "nonexistent".into(),
            peer_ip: "203.0.113.50".parse().unwrap(),
            duration: Duration::from_secs(60),
            reason: "sentinel blacklist".into(),
            penalty_level: 1,
        });
        let QueryResponse::BlacklistBackbonePeer(false) = response else {
            panic!("expected false for unknown interface");
        };
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_blacklist_creates_entry_for_unknown_ip() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");

        // Blacklist an IP that has no existing peer state
        let response = driver.handle_query_mut(QueryRequest::BlacklistBackbonePeer {
            interface_name: "public".into(),
            peer_ip: "198.51.100.1".parse().unwrap(),
            duration: Duration::from_secs(120),
            reason: "sentinel blacklist".into(),
            penalty_level: 1,
        });
        let QueryResponse::BlacklistBackbonePeer(true) = response else {
            panic!("expected successful blacklist for new IP");
        };

        let response = driver.handle_query(QueryRequest::BackbonePeerState {
            interface_name: Some("public".into()),
        });
        let QueryResponse::BackbonePeerState(entries) = response else {
            panic!("expected backbone peer state list");
        };
        let entry = entries
            .iter()
            .find(|e| e.peer_ip == "198.51.100.1".parse::<std::net::IpAddr>().unwrap())
            .expect("expected entry for newly blacklisted IP");
        assert!(entry.blacklisted_remaining_secs.is_some());
    }

    #[cfg(feature = "iface-tcp")]
    #[test]
    fn runtime_config_lists_tcp_server_keys() {
        let mut driver = new_test_driver();
        register_test_tcp_server(&mut driver, "public");
        register_test_tcp_server_discovery(&mut driver, "public", false);
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"tcp_server.public.max_connections".to_string()));
        assert!(keys.contains(&"tcp_server.public.discoverable".to_string()));
        assert!(keys.contains(&"tcp_server.public.discovery_name".to_string()));
    }

    #[cfg(feature = "iface-tcp")]
    #[test]
    fn runtime_config_sets_tcp_server_values() {
        let mut driver = new_test_driver();
        register_test_tcp_server(&mut driver, "public");
        register_test_tcp_server_discovery(&mut driver, "public", false);
        driver.transport_identity = Some(rns_crypto::identity::Identity::new(&mut OsRng));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_server.public.max_connections".into(),
            value: RuntimeConfigValue::Int(0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "tcp_server.public.max_connections".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(4));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_server.public.discoverable".into(),
            value: RuntimeConfigValue::Bool(true),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(true));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_server.public.latitude".into(),
            value: RuntimeConfigValue::Float(41.9028),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(41.9028));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "tcp_server.public.latitude".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);
    }

    #[cfg(feature = "iface-tcp")]
    #[test]
    fn runtime_config_lists_tcp_client_keys() {
        let mut driver = new_test_driver();
        register_test_tcp_client(&mut driver, "uplink");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"tcp_client.uplink.connect_timeout_secs".to_string()));
        assert!(keys.contains(&"tcp_client.uplink.reconnect_wait_secs".to_string()));
        assert!(keys.contains(&"tcp_client.uplink.max_reconnect_tries".to_string()));
    }

    #[cfg(feature = "iface-tcp")]
    #[test]
    fn runtime_config_sets_tcp_client_values() {
        let mut driver = new_test_driver();
        register_test_tcp_client(&mut driver, "uplink");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_client.uplink.connect_timeout_secs".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_client.uplink.max_reconnect_tries".into(),
            value: RuntimeConfigValue::Int(0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "tcp_client.uplink.connect_timeout_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(5.0));
    }

    #[cfg(feature = "iface-udp")]
    #[test]
    fn runtime_config_lists_udp_keys() {
        let mut driver = new_test_driver();
        register_test_udp(&mut driver, "lan");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"udp.lan.forward_ip".to_string()));
        assert!(keys.contains(&"udp.lan.forward_port".to_string()));
    }

    #[cfg(feature = "iface-udp")]
    #[test]
    fn runtime_config_sets_udp_values() {
        let mut driver = new_test_driver();
        register_test_udp(&mut driver, "lan");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "udp.lan.forward_ip".into(),
            value: RuntimeConfigValue::String("192.168.1.10".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(
            entry.value,
            RuntimeConfigValue::String("192.168.1.10".into())
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "udp.lan.forward_port".into(),
            value: RuntimeConfigValue::Null,
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "udp.lan.forward_port".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(4242));
    }

    #[cfg(feature = "iface-auto")]
    #[test]
    fn runtime_config_lists_auto_keys() {
        let mut driver = new_test_driver();
        register_test_auto(&mut driver, "lan");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"auto.lan.announce_interval_secs".to_string()));
        assert!(keys.contains(&"auto.lan.peer_timeout_secs".to_string()));
        assert!(keys.contains(&"auto.lan.peer_job_interval_secs".to_string()));
    }

    #[cfg(feature = "iface-auto")]
    #[test]
    fn runtime_config_sets_auto_values() {
        let mut driver = new_test_driver();
        register_test_auto(&mut driver, "lan");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "auto.lan.announce_interval_secs".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "auto.lan.peer_timeout_secs".into(),
            value: RuntimeConfigValue::Float(30.0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(30.0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "auto.lan.peer_job_interval_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(4.0));
    }

    #[cfg(feature = "iface-i2p")]
    #[test]
    fn runtime_config_lists_i2p_keys() {
        let mut driver = new_test_driver();
        register_test_i2p(&mut driver, "anon");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"i2p.anon.reconnect_wait_secs".to_string()));
    }

    #[cfg(feature = "iface-i2p")]
    #[test]
    fn runtime_config_sets_i2p_values() {
        let mut driver = new_test_driver();
        register_test_i2p(&mut driver, "anon");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "i2p.anon.reconnect_wait_secs".into(),
            value: RuntimeConfigValue::Float(3.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(3.5));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "i2p.anon.reconnect_wait_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(15.0));
    }

    #[cfg(feature = "iface-pipe")]
    #[test]
    fn runtime_config_lists_pipe_keys() {
        let mut driver = new_test_driver();
        register_test_pipe(&mut driver, "worker");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"pipe.worker.respawn_delay_secs".to_string()));
    }

    #[cfg(feature = "iface-pipe")]
    #[test]
    fn runtime_config_sets_pipe_values() {
        let mut driver = new_test_driver();
        register_test_pipe(&mut driver, "worker");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "pipe.worker.respawn_delay_secs".into(),
            value: RuntimeConfigValue::Float(2.0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "pipe.worker.respawn_delay_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(5.0));
    }

    #[cfg(feature = "iface-rnode")]
    #[test]
    fn runtime_config_lists_rnode_keys() {
        let mut driver = new_test_driver();
        register_test_rnode(&mut driver, "radio");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"rnode.radio.frequency_hz".to_string()));
        assert!(keys.contains(&"rnode.radio.bandwidth_hz".to_string()));
        assert!(keys.contains(&"rnode.radio.txpower_dbm".to_string()));
        assert!(keys.contains(&"rnode.radio.spreading_factor".to_string()));
        assert!(keys.contains(&"rnode.radio.coding_rate".to_string()));
        assert!(keys.contains(&"rnode.radio.st_alock_pct".to_string()));
        assert!(keys.contains(&"rnode.radio.lt_alock_pct".to_string()));
    }

    #[cfg(feature = "iface-rnode")]
    #[test]
    fn runtime_config_sets_rnode_values() {
        let mut driver = new_test_driver();
        register_test_rnode(&mut driver, "radio");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "rnode.radio.frequency_hz".into(),
            value: RuntimeConfigValue::Int(915_000_000),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(915_000_000));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "rnode.radio.st_alock_pct".into(),
            value: RuntimeConfigValue::Float(12.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(12.5));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "rnode.radio.frequency_hz".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(868_000_000));
    }

    #[test]
    fn runtime_config_lists_generic_interface_keys() {
        let mut driver = new_test_driver();
        register_test_generic_interface(&mut driver, 1, "public");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"interface.public.enabled".to_string()));
        assert!(keys.contains(&"interface.public.mode".to_string()));
        assert!(keys.contains(&"interface.public.announce_rate_target".to_string()));
        assert!(keys.contains(&"interface.public.announce_rate_grace".to_string()));
        assert!(keys.contains(&"interface.public.announce_rate_penalty".to_string()));
        assert!(keys.contains(&"interface.public.announce_cap".to_string()));
        assert!(keys.contains(&"interface.public.ingress_control".to_string()));
        assert!(keys.contains(&"interface.public.ifac_netname".to_string()));
        assert!(keys.contains(&"interface.public.ifac_passphrase".to_string()));
        assert!(keys.contains(&"interface.public.ifac_size_bytes".to_string()));
    }

    #[test]
    fn runtime_config_sets_generic_interface_values() {
        let mut driver = new_test_driver();
        register_test_generic_interface(&mut driver, 1, "public");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.enabled".into(),
            value: RuntimeConfigValue::Bool(false),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(false));
        assert!(!driver.interfaces.get(&InterfaceId(1)).unwrap().enabled);

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.announce_cap".into(),
            value: RuntimeConfigValue::Float(0.15),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(0.15));
        assert_eq!(
            driver
                .engine
                .interface_info(&InterfaceId(1))
                .unwrap()
                .announce_cap,
            0.15
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.mode".into(),
            value: RuntimeConfigValue::String("gateway".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("gateway".into()));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "interface.public.mode".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("full".into()));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "interface.public.enabled".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(true));
        assert!(driver.interfaces.get(&InterfaceId(1)).unwrap().enabled);

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ifac_netname".into(),
            value: RuntimeConfigValue::String("mesh".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("mesh".into()));
        assert_eq!(
            driver
                .interfaces
                .get(&InterfaceId(1))
                .unwrap()
                .ifac
                .as_ref()
                .unwrap()
                .size,
            16
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ifac_passphrase".into(),
            value: RuntimeConfigValue::String("secret".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("<redacted>".into()));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ifac_size_bytes".into(),
            value: RuntimeConfigValue::Int(24),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(24));
        let ifac = driver
            .interfaces
            .get(&InterfaceId(1))
            .unwrap()
            .ifac
            .as_ref()
            .unwrap();
        assert_eq!(ifac.size, 24);

        let response = driver.handle_query(QueryRequest::GetRuntimeConfig {
            key: "interface.public.ifac_passphrase".into(),
        });
        let QueryResponse::RuntimeConfigEntry(Some(entry)) = response else {
            panic!("expected runtime config entry");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("<redacted>".into()));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "interface.public.ifac_netname".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);
        assert!(driver
            .interfaces
            .get(&InterfaceId(1))
            .unwrap()
            .ifac
            .is_some());

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "interface.public.ifac_passphrase".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);
        assert!(driver
            .interfaces
            .get(&InterfaceId(1))
            .unwrap()
            .ifac
            .is_none());
    }

    #[cfg(feature = "rns-hooks")]
    #[test]
    fn runtime_config_sets_provider_bridge_values() {
        let mut driver = new_test_driver();

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("provider.sock");
        let bridge = crate::provider_bridge::ProviderBridge::start(
            crate::provider_bridge::ProviderBridgeConfig {
                enabled: true,
                socket_path,
                queue_max_events: 1024,
                queue_max_bytes: 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        driver.runtime_config_defaults.provider_queue_max_events = 1024;
        driver.runtime_config_defaults.provider_queue_max_bytes = 1024 * 1024;
        driver.provider_bridge = Some(bridge);

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "provider.queue_max_events".into(),
            value: RuntimeConfigValue::Int(4096),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(4096));
        assert_eq!(entry.source, RuntimeConfigSource::RuntimeOverride,);

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "provider.queue_max_bytes".into(),
            value: RuntimeConfigValue::Int(2 * 1024 * 1024),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(2 * 1024 * 1024));

        // Reject zero values
        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "provider.queue_max_events".into(),
            value: RuntimeConfigValue::Int(0),
        });
        assert!(matches!(response, QueryResponse::RuntimeConfigSet(Err(_))));

        // Reset
        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "provider.queue_max_events".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(1024));
        assert_eq!(entry.source, RuntimeConfigSource::Startup);

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "provider.queue_max_bytes".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(1024 * 1024));
    }

    #[test]
    fn disabled_interface_drops_ingress_and_egress() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.register_interface_runtime_defaults(&info);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(
            InterfaceId(1),
            InterfaceEntry {
                id: InterfaceId(1),
                info,
                writer: Box::new(writer),
                enabled: false,
                online: true,
                dynamic: false,
                ifac: None,
                stats: InterfaceStats::default(),
                interface_type: String::new(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x00, 0x01, 0x42],
        }]);
        assert!(sent.lock().unwrap().is_empty());

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: vec![0x00, 0x01, 0x42],
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let entry = driver.interfaces.get(&InterfaceId(1)).unwrap();
        assert_eq!(entry.stats.rxb, 0);
        assert_eq!(entry.stats.rx_packets, 0);
    }

    #[test]
    fn management_announces_not_emitted_when_disabled() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let identity = Identity::new(&mut OsRng);
        let identity_hash = *identity.hash();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some(identity_hash),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Management announces disabled (default)
        driver.transport_identity = Some(identity);
        driver.started = time::now() - 10.0;

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should NOT have sent any packets
        let sent_packets = sent.lock().unwrap();
        assert!(
            sent_packets.is_empty(),
            "No announces should be sent when management is disabled"
        );
    }

    #[test]
    fn management_announces_not_emitted_before_delay() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let identity = Identity::new(&mut OsRng);
        let identity_hash = *identity.hash();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some(identity_hash),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        driver.management_config.enable_remote_management = true;
        driver.transport_identity = Some(identity);
        // Started just now - delay hasn't passed
        driver.started = time::now();

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let sent_packets = sent.lock().unwrap();
        assert!(sent_packets.is_empty(), "No announces before startup delay");
    }

    // =========================================================================
    // Phase 9c: Announce + Discovery tests
    // =========================================================================

    #[test]
    fn announce_received_populates_known_destinations() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // known_destinations should be populated
        assert!(driver.known_destinations.contains_key(&dest_hash));
        let recalled = &driver.known_destinations[&dest_hash];
        assert_eq!(recalled.dest_hash.0, dest_hash);
        assert_eq!(recalled.identity_hash.0, *identity.hash());
        assert_eq!(&recalled.public_key, &identity.get_public_key().unwrap());
        assert_eq!(recalled.hops, 1);
    }

    #[test]
    fn known_destinations_cleanup_respects_ttl() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        driver.known_destinations_ttl = 10.0;
        driver.cache_cleanup_counter = 3599;

        let stale_dest = [0x11; 16];
        let fresh_dest = [0x22; 16];
        driver.known_destinations.insert(
            stale_dest,
            crate::destination::AnnouncedIdentity {
                dest_hash: rns_core::types::DestHash(stale_dest),
                identity_hash: rns_core::types::IdentityHash([0x33; 16]),
                public_key: [0x44; 64],
                app_data: None,
                hops: 1,
                received_at: time::now() - 20.0,
                receiving_interface: InterfaceId(1),
            },
        );
        driver.known_destinations.insert(
            fresh_dest,
            crate::destination::AnnouncedIdentity {
                dest_hash: rns_core::types::DestHash(fresh_dest),
                identity_hash: rns_core::types::IdentityHash([0x55; 16]),
                public_key: [0x66; 64],
                app_data: None,
                hops: 1,
                received_at: time::now() - 5.0,
                receiving_interface: InterfaceId(1),
            },
        );

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(!driver.known_destinations.contains_key(&stale_dest));
        assert!(driver.known_destinations.contains_key(&fresh_dest));
    }

    #[test]
    fn query_has_path() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // No path yet
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::HasPath {
                dest_hash: [0xAA; 16],
            },
            resp_tx,
        ))
        .unwrap();

        // Feed an announce to create a path
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        let (resp_tx2, resp_rx2) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::HasPath { dest_hash }, resp_tx2))
            .unwrap();

        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // First query — no path
        match resp_rx.recv().unwrap() {
            QueryResponse::HasPath(false) => {}
            other => panic!("expected HasPath(false), got {:?}", other),
        }

        // Second query — path exists
        match resp_rx2.recv().unwrap() {
            QueryResponse::HasPath(true) => {}
            other => panic!("expected HasPath(true), got {:?}", other),
        }
    }

    #[test]
    fn query_hops_to() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Feed an announce
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::HopsTo { dest_hash }, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::HopsTo(Some(1)) => {}
            other => panic!("expected HopsTo(Some(1)), got {:?}", other),
        }
    }

    #[test]
    fn query_recall_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        // Recall identity
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::RecallIdentity { dest_hash },
            resp_tx,
        ))
        .unwrap();

        // Also recall unknown destination
        let (resp_tx2, resp_rx2) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::RecallIdentity {
                dest_hash: [0xFF; 16],
            },
            resp_tx2,
        ))
        .unwrap();

        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::RecallIdentity(Some(recalled)) => {
                assert_eq!(recalled.dest_hash.0, dest_hash);
                assert_eq!(recalled.identity_hash.0, *identity.hash());
                assert_eq!(recalled.public_key, identity.get_public_key().unwrap());
                assert_eq!(recalled.hops, 1);
            }
            other => panic!("expected RecallIdentity(Some(..)), got {:?}", other),
        }

        match resp_rx2.recv().unwrap() {
            QueryResponse::RecallIdentity(None) => {}
            other => panic!("expected RecallIdentity(None), got {:?}", other),
        }
    }

    #[test]
    fn request_path_sends_packet() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Send path request
        tx.send(Event::RequestPath {
            dest_hash: [0xAA; 16],
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have sent a packet on the wire (broadcast)
        let sent_packets = sent.lock().unwrap();
        assert!(
            !sent_packets.is_empty(),
            "Path request should be sent on wire"
        );

        // Verify the sent packet is a DATA PLAIN BROADCAST packet
        let raw = &sent_packets[0];
        let flags = rns_core::packet::PacketFlags::unpack(raw[0] & 0x7F);
        assert_eq!(flags.packet_type, constants::PACKET_TYPE_DATA);
        assert_eq!(flags.destination_type, constants::DESTINATION_PLAIN);
        assert_eq!(flags.transport_type, constants::TRANSPORT_BROADCAST);
    }

    #[test]
    fn request_path_includes_transport_id() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0xBB; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        tx.send(Event::RequestPath {
            dest_hash: [0xAA; 16],
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let sent_packets = sent.lock().unwrap();
        assert!(!sent_packets.is_empty());

        // Unpack the packet to check data length includes transport_id
        let raw = &sent_packets[0];
        if let Ok(packet) = RawPacket::unpack(raw) {
            // Data: dest_hash(16) + transport_id(16) + random_tag(16) = 48 bytes
            assert_eq!(
                packet.data.len(),
                48,
                "Path request data should be 48 bytes with transport_id"
            );
            assert_eq!(
                &packet.data[..16],
                &[0xAA; 16],
                "First 16 bytes should be dest_hash"
            );
            assert_eq!(
                &packet.data[16..32],
                &[0xBB; 16],
                "Next 16 bytes should be transport_id"
            );
        } else {
            panic!("Could not unpack sent packet");
        }
    }

    #[test]
    fn path_request_dest_registered() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // The path request dest should be registered as a local PLAIN destination
        let expected_dest =
            rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
        assert_eq!(driver.path_request_dest, expected_dest);

        drop(tx);
    }

    // =========================================================================
    // Phase 9d: send_packet + proofs tests
    // =========================================================================

    #[test]
    fn register_proof_strategy_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xAA; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();

        tx.send(Event::RegisterProofStrategy {
            dest_hash: dest,
            strategy: rns_core::types::ProofStrategy::ProveAll,
            signing_key: Some(prv_key),
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(driver.proof_strategies.contains_key(&dest));
        let (strategy, ref id_opt) = driver.proof_strategies[&dest];
        assert_eq!(strategy, rns_core::types::ProofStrategy::ProveAll);
        assert!(id_opt.is_some());
    }

    #[test]
    fn register_proof_strategy_prove_none_no_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xBB; 16];
        tx.send(Event::RegisterProofStrategy {
            dest_hash: dest,
            strategy: rns_core::types::ProofStrategy::ProveNone,
            signing_key: None,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(driver.proof_strategies.contains_key(&dest));
        let (strategy, ref id_opt) = driver.proof_strategies[&dest];
        assert_eq!(strategy, rns_core::types::ProofStrategy::ProveNone);
        assert!(id_opt.is_none());
    }

    #[test]
    fn send_outbound_tracks_sent_packets() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Build a DATA packet
        let dest = [0xCC; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test data").unwrap();
        let expected_hash = packet.packet_hash;

        tx.send(Event::SendOutbound {
            raw: packet.raw,
            dest_type: constants::DESTINATION_PLAIN,
            attached_interface: None,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should be tracking the sent packet
        assert!(driver.sent_packets.contains_key(&expected_hash));
        let (tracked_dest, _sent_time) = &driver.sent_packets[&expected_hash];
        assert_eq!(tracked_dest, &dest);
    }

    #[test]
    fn prove_all_generates_proof_on_delivery() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination with ProveAll
        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(
            dest,
            (
                rns_core::types::ProofStrategy::ProveAll,
                Some(Identity::from_private_key(&prv_key)),
            ),
        );

        // Send a DATA packet to that destination
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have delivered the packet
        assert_eq!(deliveries.lock().unwrap().len(), 1);

        // Should have sent at least one proof packet on the wire
        let sent_packets = sent.lock().unwrap();
        // The original DATA is not sent out (it was delivered locally), but a PROOF should be
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(
            has_proof,
            "ProveAll should generate a proof packet: sent {} packets",
            sent_packets.len()
        );
    }

    #[test]
    fn prove_none_does_not_generate_proof() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination with ProveNone
        let dest = [0xDD; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver
            .proof_strategies
            .insert(dest, (rns_core::types::ProofStrategy::ProveNone, None));

        // Send a DATA packet to that destination
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have delivered the packet
        assert_eq!(deliveries.lock().unwrap().len(), 1);

        // Should NOT have sent any proof
        let sent_packets = sent.lock().unwrap();
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(!has_proof, "ProveNone should not generate a proof packet");
    }

    #[test]
    fn no_proof_strategy_does_not_generate_proof() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register destination but NO proof strategy
        let dest = [0xDD; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(deliveries.lock().unwrap().len(), 1);

        let sent_packets = sent.lock().unwrap();
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(!has_proof, "No proof strategy means no proof generated");
    }

    #[test]
    fn prove_app_calls_callback() {
        let (tx, rx) = event::channel();
        let proof_requested = Arc::new(Mutex::new(Vec::new()));
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: deliveries.clone(),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: Arc::new(Mutex::new(Vec::new())),
            proof_requested: proof_requested.clone(),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register dest with ProveApp
        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(
            dest,
            (
                rns_core::types::ProofStrategy::ProveApp,
                Some(Identity::from_private_key(&prv_key)),
            ),
        );

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"app test").unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // on_proof_requested should have been called
        let prs = proof_requested.lock().unwrap();
        assert_eq!(prs.len(), 1);
        assert_eq!(prs[0].0, DestHash(dest));

        // Since our mock returns true, a proof should also have been sent
        let sent_packets = sent.lock().unwrap();
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(
            has_proof,
            "ProveApp (callback returns true) should generate a proof"
        );
    }

    #[test]
    fn inbound_proof_fires_callback() {
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination so proof packets can be delivered locally
        let dest = [0xEE; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        // Simulate a sent packet that we're tracking
        let tracked_hash = [0x42u8; 32];
        let sent_time = time::now() - 0.5; // 500ms ago
        driver.sent_packets.insert(tracked_hash, (dest, sent_time));

        // Build a PROOF packet with the tracked hash + dummy signature
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&tracked_hash);
        proof_data.extend_from_slice(&[0xAA; 64]); // dummy signature

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // on_proof callback should have been fired
        let proof_list = proofs.lock().unwrap();
        assert_eq!(proof_list.len(), 1);
        assert_eq!(proof_list[0].0, DestHash(dest));
        assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
        assert!(
            proof_list[0].2 >= 0.4,
            "RTT should be approximately 0.5s, got {}",
            proof_list[0].2
        );

        // Tracked packet should be removed
        assert!(!driver.sent_packets.contains_key(&tracked_hash));
    }

    #[test]
    fn inbound_proof_for_unknown_packet_is_ignored() {
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xEE; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        // Build a PROOF packet for an untracked hash
        let unknown_hash = [0xFF; 32];
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&unknown_hash);
        proof_data.extend_from_slice(&[0xAA; 64]);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // on_proof should NOT have been called
        assert!(proofs.lock().unwrap().is_empty());
    }

    #[test]
    fn inbound_proof_with_valid_signature_fires_callback() {
        // When the destination IS in known_destinations, the proof signature is verified
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xEE; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        // Create real identity and add to known_destinations
        let identity = Identity::new(&mut OsRng);
        let pub_key = identity.get_public_key();
        driver.known_destinations.insert(
            dest,
            crate::destination::AnnouncedIdentity {
                dest_hash: DestHash(dest),
                identity_hash: IdentityHash(*identity.hash()),
                public_key: pub_key.unwrap(),
                app_data: None,
                hops: 0,
                received_at: time::now(),
                receiving_interface: InterfaceId(0),
            },
        );

        // Sign a packet hash with the identity
        let tracked_hash = [0x42u8; 32];
        let sent_time = time::now() - 0.5;
        driver.sent_packets.insert(tracked_hash, (dest, sent_time));

        let signature = identity.sign(&tracked_hash).unwrap();
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&tracked_hash);
        proof_data.extend_from_slice(&signature);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Valid signature: on_proof should fire
        let proof_list = proofs.lock().unwrap();
        assert_eq!(proof_list.len(), 1);
        assert_eq!(proof_list[0].0, DestHash(dest));
        assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
    }

    #[test]
    fn inbound_proof_with_invalid_signature_rejected() {
        // When known_destinations has the public key, bad signatures are rejected
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xEE; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        // Create identity and add to known_destinations
        let identity = Identity::new(&mut OsRng);
        let pub_key = identity.get_public_key();
        driver.known_destinations.insert(
            dest,
            crate::destination::AnnouncedIdentity {
                dest_hash: DestHash(dest),
                identity_hash: IdentityHash(*identity.hash()),
                public_key: pub_key.unwrap(),
                app_data: None,
                hops: 0,
                received_at: time::now(),
                receiving_interface: InterfaceId(0),
            },
        );

        // Track a sent packet
        let tracked_hash = [0x42u8; 32];
        let sent_time = time::now() - 0.5;
        driver.sent_packets.insert(tracked_hash, (dest, sent_time));

        // Use WRONG signature (all 0xAA — invalid for this identity)
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&tracked_hash);
        proof_data.extend_from_slice(&[0xAA; 64]);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Invalid signature: on_proof should NOT fire
        assert!(proofs.lock().unwrap().is_empty());
    }

    #[test]
    fn proof_data_is_valid_explicit_proof() {
        // Verify that the proof generated by ProveAll is a valid explicit proof
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(
            dest,
            (
                rns_core::types::ProofStrategy::ProveAll,
                Some(Identity::from_private_key(&prv_key)),
            ),
        );

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let data_packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"verify me").unwrap();
        let data_packet_hash = data_packet.packet_hash;

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: data_packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Find the proof packet in sent
        let sent_packets = sent.lock().unwrap();
        let proof_raw = sent_packets.iter().find(|raw| {
            let f = PacketFlags::unpack(raw[0] & 0x7F);
            f.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(proof_raw.is_some(), "Should have sent a proof");

        let proof_packet = RawPacket::unpack(proof_raw.unwrap()).unwrap();
        // Proof data should be 96 bytes: packet_hash(32) + signature(64)
        assert_eq!(
            proof_packet.data.len(),
            96,
            "Explicit proof should be 96 bytes"
        );

        // Validate using rns-core's receipt module
        let result = rns_core::receipt::validate_proof(
            &proof_packet.data,
            &data_packet_hash,
            &Identity::from_private_key(&prv_key), // same identity
        );
        assert_eq!(result, rns_core::receipt::ProofResult::Valid);
    }

    #[test]
    fn query_local_destinations_empty() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LocalDestinations, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LocalDestinations(entries) => {
                // Should contain the two internal destinations (tunnel_synth + path_request)
                assert_eq!(entries.len(), 2);
                for entry in &entries {
                    assert_eq!(entry.dest_type, rns_core::constants::DESTINATION_PLAIN);
                }
            }
            other => panic!("expected LocalDestinations, got {:?}", other),
        }
    }

    #[test]
    fn query_local_destinations_with_registered() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let dest_hash = [0xAA; 16];
        tx.send(Event::RegisterDestination {
            dest_hash,
            dest_type: rns_core::constants::DESTINATION_SINGLE,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LocalDestinations, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LocalDestinations(entries) => {
                // 2 internal + 1 registered
                assert_eq!(entries.len(), 3);
                assert!(entries.iter().any(|e| e.hash == dest_hash
                    && e.dest_type == rns_core::constants::DESTINATION_SINGLE));
            }
            other => panic!("expected LocalDestinations, got {:?}", other),
        }
    }

    #[test]
    fn query_local_destinations_tracks_link_dest() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let dest_hash = [0xBB; 16];
        tx.send(Event::RegisterLinkDestination {
            dest_hash,
            sig_prv_bytes: [0x11; 32],
            sig_pub_bytes: [0x22; 32],
            resource_strategy: 0,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LocalDestinations, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LocalDestinations(entries) => {
                // 2 internal + 1 link destination
                assert_eq!(entries.len(), 3);
                assert!(entries.iter().any(|e| e.hash == dest_hash
                    && e.dest_type == rns_core::constants::DESTINATION_SINGLE));
            }
            other => panic!("expected LocalDestinations, got {:?}", other),
        }
    }

    #[test]
    fn query_links_empty() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::Links, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::Links(entries) => {
                assert!(entries.is_empty());
            }
            other => panic!("expected Links, got {:?}", other),
        }
    }

    #[test]
    fn query_resources_empty() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::Resources, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::Resources(entries) => {
                assert!(entries.is_empty());
            }
            other => panic!("expected Resources, got {:?}", other),
        }
    }

    #[test]
    fn infer_interface_type_from_name() {
        assert_eq!(
            super::infer_interface_type("TCPServerInterface/Client-1234"),
            "TCPServerClientInterface"
        );
        assert_eq!(
            super::infer_interface_type("BackboneInterface/5"),
            "BackboneInterface"
        );
        assert_eq!(
            super::infer_interface_type("LocalInterface"),
            "LocalServerClientInterface"
        );
        assert_eq!(
            super::infer_interface_type("MyAutoGroup:fe80::1"),
            "AutoInterface"
        );
    }

    // ---- extract_dest_hash tests ----

    #[test]
    fn test_extract_dest_hash_empty() {
        assert_eq!(super::extract_dest_hash(&[]), [0u8; 16]);
    }

    // =========================================================================
    // Probe tests: SendProbe, CheckProof, completed_proofs, probe_responder
    // =========================================================================

    #[test]
    fn send_probe_unknown_dest_returns_none() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // SendProbe for a dest_hash with no known identity should return None
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::SendProbe {
                dest_hash: [0xAA; 16],
                payload_size: 16,
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::SendProbe(None) => {}
            other => panic!("expected SendProbe(None), got {:?}", other),
        }
    }

    #[test]
    fn send_probe_known_dest_returns_packet_hash() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Inject a known identity so SendProbe can encrypt to it
        let remote_identity = Identity::new(&mut OsRng);
        let dest_hash = rns_core::destination::destination_hash(
            "rnstransport",
            &["probe"],
            Some(remote_identity.hash()),
        );

        // First inject the identity via announce
        let (inject_tx, inject_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash: *remote_identity.hash(),
                public_key: remote_identity.get_public_key().unwrap(),
                app_data: None,
                hops: 1,
                received_at: 0.0,
            },
            inject_tx,
        ))
        .unwrap();

        // Now send the probe
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::SendProbe {
                dest_hash,
                payload_size: 16,
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Verify injection succeeded
        match inject_rx.recv().unwrap() {
            QueryResponse::InjectIdentity(true) => {}
            other => panic!("expected InjectIdentity(true), got {:?}", other),
        }

        // Verify probe sent
        match resp_rx.recv().unwrap() {
            QueryResponse::SendProbe(Some((packet_hash, _hops))) => {
                // Packet hash should be non-zero
                assert_ne!(packet_hash, [0u8; 32]);
                // Should be tracked in sent_packets
                assert!(driver.sent_packets.contains_key(&packet_hash));
                // Should have sent a DATA packet on the wire
                let sent_data = sent.lock().unwrap();
                assert!(!sent_data.is_empty(), "Probe packet should be sent on wire");
                // Verify it's a DATA SINGLE packet
                let raw = &sent_data[0];
                let flags = PacketFlags::unpack(raw[0] & 0x7F);
                assert_eq!(flags.packet_type, constants::PACKET_TYPE_DATA);
                assert_eq!(flags.destination_type, constants::DESTINATION_SINGLE);
            }
            other => panic!("expected SendProbe(Some(..)), got {:?}", other),
        }
    }

    #[test]
    fn check_proof_not_found_returns_none() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::CheckProof {
                packet_hash: [0xBB; 32],
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::CheckProof(None) => {}
            other => panic!("expected CheckProof(None), got {:?}", other),
        }
    }

    #[test]
    fn check_proof_found_returns_rtt() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // Pre-populate completed_proofs
        let packet_hash = [0xCC; 32];
        driver
            .completed_proofs
            .insert(packet_hash, (0.123, time::now()));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::CheckProof { packet_hash },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::CheckProof(Some(rtt)) => {
                assert!(
                    (rtt - 0.123).abs() < 0.001,
                    "RTT should be ~0.123, got {}",
                    rtt
                );
            }
            other => panic!("expected CheckProof(Some(..)), got {:?}", other),
        }
        // Should be consumed (removed) after checking
        assert!(!driver.completed_proofs.contains_key(&packet_hash));
    }

    #[test]
    fn inbound_proof_populates_completed_proofs() {
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination with ProveAll so we can get a proof back
        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(
            dest,
            (
                rns_core::types::ProofStrategy::ProveAll,
                Some(Identity::from_private_key(&prv_key)),
            ),
        );

        // Build and send a DATA packet to the dest (this creates a sent_packet + proof)
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let data_packet = RawPacket::pack(
            flags,
            0,
            &dest,
            None,
            constants::CONTEXT_NONE,
            b"probe data",
        )
        .unwrap();
        let data_packet_hash = data_packet.packet_hash;

        // Track it as a sent packet so the proof handler recognizes it
        driver
            .sent_packets
            .insert(data_packet_hash, (dest, time::now()));

        // Deliver the frame — this generates a proof which gets sent on wire
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: data_packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // The proof was generated and sent on the wire
        let sent_packets = sent.lock().unwrap();
        let proof_packets: Vec<_> = sent_packets
            .iter()
            .filter(|raw| {
                let flags = PacketFlags::unpack(raw[0] & 0x7F);
                flags.packet_type == constants::PACKET_TYPE_PROOF
            })
            .collect();
        assert!(!proof_packets.is_empty(), "Should have sent a proof packet");

        // Now feed the proof packet back to the driver so handle_inbound_proof fires.
        // We need a fresh driver run since the previous one shut down.
        // Instead, verify the data flow: the proof was sent on wire, and when
        // handle_inbound_proof processes a matching proof, completed_proofs gets populated.
        // Since our DATA packet was both delivered locally AND tracked in sent_packets,
        // the proof was generated on delivery. But the proof is for the *sender* to verify --
        // the proof gets sent back to the sender. So in this test (same driver = both sides),
        // the proof was sent on wire but not yet received back.
        //
        // Let's verify handle_inbound_proof directly by feeding the proof frame back.
        let proof_raw = proof_packets[0].clone();
        drop(sent_packets); // release lock

        // Create a new event loop to handle the proof frame
        let (tx2, rx2) = event::channel();
        let proofs2 = Arc::new(Mutex::new(Vec::new()));
        let cbs2 = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs2.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };
        let mut driver2 = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx2,
            tx2.clone(),
            Box::new(cbs2),
        );
        let info2 = make_interface_info(1);
        driver2.engine.register_interface(info2);
        let (writer2, _sent2) = MockWriter::new();
        driver2
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer2), true));

        // Track the original sent packet in driver2 so it recognizes the proof
        driver2
            .sent_packets
            .insert(data_packet_hash, (dest, time::now()));

        // Feed the proof frame
        tx2.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: proof_raw,
        })
        .unwrap();
        tx2.send(Event::Shutdown).unwrap();
        driver2.run();

        // The on_proof callback should have fired
        let proof_events = proofs2.lock().unwrap();
        assert_eq!(proof_events.len(), 1, "on_proof callback should fire once");
        assert_eq!(
            proof_events[0].1 .0, data_packet_hash,
            "proof should match original packet hash"
        );
        assert!(proof_events[0].2 >= 0.0, "RTT should be non-negative");

        // completed_proofs should contain the entry
        assert!(
            driver2.completed_proofs.contains_key(&data_packet_hash),
            "completed_proofs should contain the packet hash"
        );
        let (rtt, _received) = driver2.completed_proofs[&data_packet_hash];
        assert!(rtt >= 0.0, "RTT should be non-negative");
    }

    #[test]
    fn interface_stats_includes_probe_responder() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0x42; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Set probe_responder_hash
        driver.probe_responder_hash = Some([0xEE; 16]);

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::InterfaceStats, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::InterfaceStats(stats) => {
                assert_eq!(stats.probe_responder, Some([0xEE; 16]));
            }
            other => panic!("expected InterfaceStats, got {:?}", other),
        }
    }

    #[test]
    fn interface_stats_probe_responder_none_when_disabled() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::InterfaceStats, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::InterfaceStats(stats) => {
                assert_eq!(stats.probe_responder, None);
            }
            other => panic!("expected InterfaceStats, got {:?}", other),
        }
    }

    #[test]
    fn test_extract_dest_hash_too_short() {
        // Packet too short to contain a full dest hash
        assert_eq!(super::extract_dest_hash(&[0x00, 0x00, 0xAA]), [0u8; 16]);
    }

    #[test]
    fn test_extract_dest_hash_header1() {
        // HEADER_1: bit 6 = 0, dest at bytes 2..18
        let mut raw = vec![0x00, 0x00]; // flags (header_type=0), hops
        let dest = [0x11; 16];
        raw.extend_from_slice(&dest);
        raw.extend_from_slice(&[0xFF; 10]); // trailing data
        assert_eq!(super::extract_dest_hash(&raw), dest);
    }

    #[test]
    fn test_extract_dest_hash_header2() {
        // HEADER_2: bit 6 = 1, transport_id at 2..18, dest at 18..34
        let mut raw = vec![0x40, 0x00]; // flags (header_type=1), hops
        raw.extend_from_slice(&[0xAA; 16]); // transport_id (bytes 2..18)
        let dest = [0x22; 16];
        raw.extend_from_slice(&dest); // dest (bytes 18..34)
        raw.extend_from_slice(&[0xFF; 10]); // trailing data
        assert_eq!(super::extract_dest_hash(&raw), dest);
    }

    #[test]
    fn test_extract_dest_hash_header2_too_short() {
        // HEADER_2 packet that's too short for the dest portion
        let mut raw = vec![0x40, 0x00];
        raw.extend_from_slice(&[0xAA; 16]); // transport_id only, no dest
        assert_eq!(super::extract_dest_hash(&raw), [0u8; 16]);
    }

    #[test]
    fn announce_stores_receiving_interface_in_known_destinations() {
        // When an announce arrives on interface 1, the AnnouncedIdentity
        // stored in known_destinations must have receiving_interface == InterfaceId(1).
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // The identity should be cached with the correct receiving interface
        assert_eq!(driver.known_destinations.len(), 1);
        let (_, announced) = driver.known_destinations.iter().next().unwrap();
        assert_eq!(
            announced.receiving_interface,
            InterfaceId(1),
            "receiving_interface should match the interface the announce arrived on"
        );
    }

    #[test]
    fn announce_on_different_interfaces_stores_correct_id() {
        // Announces arriving on interface 2 should store InterfaceId(2).
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        // Register two interfaces
        for id in [1, 2] {
            driver.engine.register_interface(make_interface_info(id));
            let (writer, _) = MockWriter::new();
            driver
                .interfaces
                .insert(InterfaceId(id), make_entry(id, Box::new(writer), true));
        }

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        // Send on interface 2
        tx.send(Event::Frame {
            interface_id: InterfaceId(2),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(driver.known_destinations.len(), 1);
        let (_, announced) = driver.known_destinations.iter().next().unwrap();
        assert_eq!(announced.receiving_interface, InterfaceId(2));
    }

    #[test]
    fn inject_identity_stores_sentinel_interface() {
        // InjectIdentity (used for persistence restore) should store InterfaceId(0)
        // because the identity wasn't received from a real interface.
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let identity = Identity::new(&mut OsRng);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: Some(b"restored".to_vec()),
                hops: 2,
                received_at: 99.0,
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::InjectIdentity(true) => {}
            other => panic!("expected InjectIdentity(true), got {:?}", other),
        }

        let announced = driver
            .known_destinations
            .get(&dest_hash)
            .expect("identity should be cached");
        assert_eq!(
            announced.receiving_interface,
            InterfaceId(0),
            "injected identity should have sentinel InterfaceId(0)"
        );
        assert_eq!(announced.dest_hash.0, dest_hash);
        assert_eq!(announced.identity_hash.0, *identity.hash());
        assert_eq!(announced.public_key, identity.get_public_key().unwrap());
        assert_eq!(announced.app_data, Some(b"restored".to_vec()));
        assert_eq!(announced.hops, 2);
        assert_eq!(announced.received_at, 99.0);
    }

    #[test]
    fn inject_identity_overwrites_previous_entry() {
        // A second InjectIdentity for the same dest_hash should overwrite the first.
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let identity = Identity::new(&mut OsRng);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        // First injection
        let (resp_tx1, resp_rx1) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: Some(b"first".to_vec()),
                hops: 1,
                received_at: 10.0,
            },
            resp_tx1,
        ))
        .unwrap();

        // Second injection with different app_data
        let (resp_tx2, resp_rx2) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: Some(b"second".to_vec()),
                hops: 3,
                received_at: 20.0,
            },
            resp_tx2,
        ))
        .unwrap();

        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(matches!(
            resp_rx1.recv().unwrap(),
            QueryResponse::InjectIdentity(true)
        ));
        assert!(matches!(
            resp_rx2.recv().unwrap(),
            QueryResponse::InjectIdentity(true)
        ));

        // Should have the second injection's data
        let announced = driver.known_destinations.get(&dest_hash).unwrap();
        assert_eq!(announced.app_data, Some(b"second".to_vec()));
        assert_eq!(announced.hops, 3);
        assert_eq!(announced.received_at, 20.0);
    }

    #[test]
    fn re_announce_updates_receiving_interface() {
        // If we get two announces for the same dest from different interfaces,
        // the latest should win (known_destinations is a HashMap keyed by dest_hash).
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
                max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
                max_path_destinations: usize::MAX,
                max_tunnel_destinations_total: usize::MAX,
                destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
                announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
                announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
                announce_sig_cache_enabled: true,
                announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
                announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
                announce_queue_max_entries: 256,
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        for id in [1, 2] {
            driver.engine.register_interface(make_interface_info(id));
            let (writer, _) = MockWriter::new();
            driver
                .interfaces
                .insert(InterfaceId(id), make_entry(id, Box::new(writer), true));
        }

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        // Same announce on interface 1, then interface 2
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw.clone(),
        })
        .unwrap();
        // The second announce of the same identity will be dropped by the transport
        // engine's deduplication (same random_hash). Build a second identity instead
        // to verify the field is correctly set per-announce.
        let identity2 = Identity::new(&mut OsRng);
        let announce_raw2 = build_announce_packet(&identity2);
        tx.send(Event::Frame {
            interface_id: InterfaceId(2),
            data: announce_raw2,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Both should be cached with their respective interface IDs
        assert_eq!(driver.known_destinations.len(), 2);
        for (_, announced) in &driver.known_destinations {
            // We can't predict ordering, but each should have a valid non-zero interface
            assert!(
                announced.receiving_interface == InterfaceId(1)
                    || announced.receiving_interface == InterfaceId(2)
            );
        }
        // Verify we actually got both interfaces represented
        let ifaces: Vec<_> = driver
            .known_destinations
            .values()
            .map(|a| a.receiving_interface)
            .collect();
        assert!(ifaces.contains(&InterfaceId(1)));
        assert!(ifaces.contains(&InterfaceId(2)));
    }

    #[test]
    fn test_extract_dest_hash_other_flags_preserved() {
        // Ensure other flag bits don't affect header type detection
        // 0x3F = all bits set except bit 6 -> still HEADER_1
        let mut raw = vec![0x3F, 0x00];
        let dest = [0x33; 16];
        raw.extend_from_slice(&dest);
        raw.extend_from_slice(&[0xFF; 10]);
        assert_eq!(super::extract_dest_hash(&raw), dest);

        // 0xFF = all bits set including bit 6 -> HEADER_2
        let mut raw2 = vec![0xFF, 0x00];
        raw2.extend_from_slice(&[0xBB; 16]); // transport_id
        let dest2 = [0x44; 16];
        raw2.extend_from_slice(&dest2);
        raw2.extend_from_slice(&[0xFF; 10]);
        assert_eq!(super::extract_dest_hash(&raw2), dest2);
    }
}
