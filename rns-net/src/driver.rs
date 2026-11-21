//! Driver loop: receives events, drives the TransportEngine, dispatches actions.

mod construction;
#[cfg(any(feature = "iface-backbone", feature = "iface-tcp"))]
mod discovery_runtime;
mod folded_state;
mod hook_calls;
mod hook_host;
mod interface_state;
mod path_responses;
#[cfg(feature = "iface-backbone")]
mod peer_pool;
mod settings;

#[cfg(any(feature = "iface-backbone", feature = "iface-tcp"))]
pub(crate) use discovery_runtime::*;
pub(crate) use folded_state::*;
pub(crate) use hook_host::{
    HookEnv, HookEvent, HookHost, HookPoint, HookRun, InjectedActions, PacketHookOutcome,
};
pub(crate) use interface_state::*;
pub(crate) use path_responses::*;
#[cfg(feature = "iface-backbone")]
pub use peer_pool::*;
pub(crate) use settings::InterfaceSettings;

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

use crate::stamper::PathRequestTarget;

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

/// The interface entries the driver owns, by interface id.
pub(crate) type Interfaces = crate::interface::InterfaceMap<InterfaceEntry>;
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
mod announce_verification;
mod autoconnect;
mod blackhole;
mod blackhole_updater;
mod builtin_destinations;
pub(crate) use announce_check::{check_pending_announce, AnnounceCheck};
mod dispatch;
mod events;
mod hook_events;
mod housekeeping;
mod interface_discovery;
mod interface_management;
mod interface_registry;
mod known_destinations;
mod lifecycle;
mod link_stamps;
mod management_state;
mod packet_proofs;
mod queries;
mod resource_preparation;
mod rpc_service;
pub(crate) use rpc_service::{RpcListener, RpcService};
mod runtime_config;
use runtime_config::values::*;
mod stamps;
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
    /// The provider bridge's queue limits; unused without hooks.
    pub(crate) provider_queue_max_events: usize,
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
    /// Hash of the last announce heard, upstream's `packet_hash` element.
    packet_hash: Option<[u8; 32]>,
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
    pub(crate) engine: TransportEngine,
    pub(crate) interfaces: crate::interface::InterfaceMap<InterfaceEntry>,
    /// Link manager: handles link lifecycle, request/response.
    pub(crate) link_manager: LinkManager,
    pub(crate) rx: EventReceiver,
    /// Event sender for worker threads to send results back to the driver loop.
    pub(crate) event_tx: crate::event::EventSender,
    pub(crate) callbacks: Box<dyn Callbacks>,
    pub(crate) rng: OsRng,
    pub(crate) started: f64,
    /// This node is a client of a shared instance, which sends the path
    /// requests that rediscover paths for it
    /// (`Transport.owner.is_connected_to_shared_instance`).
    pub(crate) connected_to_shared_instance: bool,
    /// Names of destination types, for log lines
    /// (`Transport.destination_type_map`).
    pub(crate) destination_type_names: crate::destination_types::DestinationTypeNames,
    /// Transport identity (optional, needed for tunnel synthesis).
    pub(crate) transport_identity: Option<rns_crypto::identity::Identity>,
    /// The network identity, when one is configured, kept apart from the
    /// transport identity: it signs this node's discovery announces,
    /// decrypts `discovery_encrypt` announces and their own are encrypted
    /// to it. Unless this node is a shared instance client, it also owns
    /// the `rnstransport.network` management destinations.
    pub(crate) network_identity: Option<rns_crypto::identity::Identity>,
    /// Inbound packets whose hop count reaches this limit are dropped and
    /// counted as `hop_limiter_hits` (`Transport.HOP_LIMITER`, set from
    /// `[filter] hop_limiter`).
    pub(crate) hop_limiter: u8,
    /// TTL for announce rate-limiter entries without an active path, in seconds.
    pub(crate) rate_limiter_ttl_secs: f64,
    /// Shared timer interval used by the node timer thread.
    pub(crate) tick_interval_ms: Arc<AtomicU64>,
    /// Reused transport action buffers (see [`crate::action_pool`]).
    pub(crate) transport_actions: crate::action_pool::ActionPool<TransportAction>,
    /// Reused link manager action buffers.
    pub(crate) link_actions: crate::action_pool::ActionPool<LinkManagerAction>,
    pub(crate) tracked_link_send: Option<([u8; 32], crate::link_send::Completion)>,
    pub(crate) pending_link_frames: std::collections::VecDeque<PendingLinkFrame>,
    /// Writers that may hold frames queued without a wakeup.
    pub(crate) writers_to_wake: Vec<InterfaceId>,
    /// Ingress burst state last published to the event queue, per interface.
    pub(crate) published_ingress_bursts: crate::interface::InterfaceMap<(Option<f64>, Option<f64>)>,
    /// RSSI, SNR and link quality of the latest packets received on
    /// interfaces that report them (`Transport.local_client_rssi_cache` and
    /// its SNR and Q siblings), oldest first.
    pub(crate) packet_signals: std::collections::VecDeque<([u8; 32], crate::event::PacketSignal)>,
    /// Locally registered destinations: hash → dest_type.
    pub(crate) local_destinations: HashMap<[u8; 16], u8>,
    /// Local destinations whose single packets are delivered decrypted, with
    /// the identity they are decrypted with when they have no ratchets.
    pub(crate) decrypted_destinations: HashMap<[u8; 16], Arc<rns_crypto::identity::Identity>>,
    /// Store for received remote ratchets, if persistence/use is enabled.
    pub(crate) ratchet_store: Option<Arc<dyn crate::storage::RatchetStore>>,
    /// TTL for received ratchets, in seconds.
    pub(crate) ratchet_expiry_secs: f64,
    pub(crate) announce_cache: Option<crate::announce_cache::AnnounceCache>,
    /// The destinations transport itself serves, and links to them.
    pub(crate) builtin: builtin_destinations::BuiltinDestinations,
    /// Packet proofs: tracked sent packets, the proofs they await and how
    /// local destinations prove the packets they receive.
    pub(crate) proofs: packet_proofs::PacketProofs,
    /// Path responses for local destinations, and the announces a shared
    /// client replays to its instance.
    path_responses: PathResponses,
    /// Known destinations: announced identities and their retention policy.
    pub(crate) known: known_destinations::KnownDestinations,
    /// Verification of inbound announce signatures off the driver thread.
    pub(crate) announce_verify: announce_verification::AnnounceVerification,
    /// Stamping of this node's announces, path requests and link requests.
    pub(crate) stamps: stamps::Stamps,
    /// Bookkeeping about the interfaces beyond their entries: naming,
    /// listeners, management and statistics.
    pub(crate) registry: interface_registry::InterfaceRegistry,
    /// Settings applied to interfaces as they register.
    pub(crate) interface_settings: InterfaceSettings,
    /// Runtime-config handles of the interfaces and the defaults they reset to.
    pub(crate) runtime_config: runtime_config::RuntimeConfigHandles,
    /// Interface discovery: received discovered interfaces, this node's
    /// discovery announces and auto-connecting.
    pub(crate) discovery: interface_discovery::InterfaceDiscovery,
    /// Ordered outbound Backbone peer pool, if enabled.
    #[cfg(feature = "iface-backbone")]
    backbone_peer_pool: Option<BackbonePeerPool>,
    /// Hole-punch manager for direct P2P connections.
    pub(crate) holepunch_manager: HolePunchManager,
    /// Where the node is in its lifecycle, and its drain progress.
    pub(crate) lifecycle: lifecycle::Lifecycle,
    /// Schedules and progress of the periodic housekeeping jobs.
    pub(crate) housekeeping: housekeeping::Housekeeping,
    /// Timers and housekeeping the driver runs itself when they are folded
    /// (see [`crate::engine::FOLD_TIMERS`]).
    pub(crate) folded: FoldedTimers,
    resource_preparation: Option<resource_preparation::Worker>,
    /// The RPC servers, when the driver serves them itself (see
    /// [`crate::engine::FOLD_SERVICES`]).
    pub(crate) rpc_service: Option<rpc_service::RpcService>,
    /// The probe server, when it runs on the driver loop (with services
    /// folded); otherwise the node runs it on a thread of its own.
    pub(crate) probe_server: Option<crate::holepunch::probe::FoldedProbeServer>,
    /// Remote management: its access configuration and announce schedule.
    pub(crate) management: management_state::ManagementState,
    /// The blackhole lists' storage and remote sources.
    pub(crate) blackhole: blackhole::BlackholeState,
    /// The programmable hook system: hook slots, their manager and the
    /// provider bridge.
    pub(crate) hooks: HookHost,
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
