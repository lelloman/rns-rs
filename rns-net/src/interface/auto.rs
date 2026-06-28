//! AutoInterface: Zero-configuration LAN auto-discovery via IPv6 multicast.
//!
//! Matches Python `AutoInterface` from `RNS/Interfaces/AutoInterface.py`.
//!
//! Thread model (per adopted network interface):
//!   - Discovery sender: periodically sends discovery token via multicast
//!   - Discovery receiver (multicast): validates tokens, adds peers
//!   - Discovery receiver (unicast): validates reverse-peering tokens
//!   - Data receiver: UDP server receiving unicast data from peers
//!
//! Additionally one shared thread:
//!   - Peer jobs: periodically culls timed-out peers

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender};
use crate::interface::{lock_or_recover, Writer};

// ── Constants (matching Python AutoInterface) ──────────────────────────────

/// Default UDP port for multicast discovery.
pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;

/// Default UDP port for unicast data exchange.
pub const DEFAULT_DATA_PORT: u16 = 42671;

/// Default group identifier.
pub const DEFAULT_GROUP_ID: &[u8] = b"reticulum";

/// Default IFAC size for AutoInterface (bytes).
pub const DEFAULT_IFAC_SIZE: usize = 16;

/// Hardware MTU for AutoInterface packets.
pub const HW_MTU: usize = 1196;

/// Multicast scope: link-local.
pub const SCOPE_LINK: &str = "2";
/// Multicast scope: admin-local.
pub const SCOPE_ADMIN: &str = "4";
/// Multicast scope: site-local.
pub const SCOPE_SITE: &str = "5";
/// Multicast scope: organization-local.
pub const SCOPE_ORGANISATION: &str = "8";
/// Multicast scope: global.
pub const SCOPE_GLOBAL: &str = "e";

/// Permanent multicast address type.
pub const MULTICAST_PERMANENT_ADDRESS_TYPE: &str = "0";
/// Temporary multicast address type.
pub const MULTICAST_TEMPORARY_ADDRESS_TYPE: &str = "1";

/// How long before a peer is considered timed out (seconds).
pub const PEERING_TIMEOUT: f64 = 22.0;

/// How often to send multicast discovery announcements (seconds).
pub const ANNOUNCE_INTERVAL: f64 = 1.6;

/// How often to run peer maintenance jobs (seconds).
pub const PEER_JOB_INTERVAL: f64 = 4.0;

/// Multicast echo timeout (seconds). Used for carrier detection.
pub const MCAST_ECHO_TIMEOUT: f64 = 6.5;

/// Default bitrate guess for AutoInterface (10 Mbps).
pub const BITRATE_GUESS: u64 = 10_000_000;

/// Deduplication deque size.
pub const MULTI_IF_DEQUE_LEN: usize = 48;

/// Deduplication deque entry TTL (seconds).
pub const MULTI_IF_DEQUE_TTL: f64 = 0.75;

/// Reverse peering interval multiplier (announce_interval * 3.25).
pub const REVERSE_PEERING_MULTIPLIER: f64 = 3.25;

/// How often AutoInterface rescans local link-local interfaces.
pub const AUTO_RESCAN_INTERVAL: f64 = 1.25;

/// Interfaces always ignored.
pub const ALL_IGNORE_IFS: &[&str] = &["lo0"];

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
const ANDROID_IGNORE_IFS: &[&str] = &[
    "dummy0", "lo", "tun0", "rmnet0", "rmnet1", "rmnet2", "rmnet3", "rmnet4", "rmnet5", "rmnet6",
    "rmnet7",
];

// ── Configuration ──────────────────────────────────────────────────────────

/// Configuration for an AutoInterface.
#[derive(Debug, Clone)]
pub struct AutoConfig {
    pub name: String,
    pub group_id: Vec<u8>,
    pub discovery_scope: String,
    pub discovery_port: u16,
    pub data_port: u16,
    pub multicast_address_type: String,
    pub allowed_interfaces: Vec<String>,
    pub ignored_interfaces: Vec<String>,
    pub configured_bitrate: u64,
    /// Base interface ID. Per-peer IDs will be assigned dynamically.
    pub interface_id: InterfaceId,
    pub ingress_control: rns_core::transport::types::IngressControlConfig,
    pub runtime: Arc<Mutex<AutoRuntime>>,
}

#[derive(Debug, Clone)]
pub struct AutoRuntime {
    pub announce_interval_secs: f64,
    pub peer_timeout_secs: f64,
    pub peer_job_interval_secs: f64,
}

impl AutoRuntime {
    pub fn from_config(_config: &AutoConfig) -> Self {
        Self {
            announce_interval_secs: ANNOUNCE_INTERVAL,
            peer_timeout_secs: PEERING_TIMEOUT,
            peer_job_interval_secs: PEER_JOB_INTERVAL,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AutoRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<AutoRuntime>>,
    pub startup: AutoRuntime,
}

impl Default for AutoConfig {
    fn default() -> Self {
        let mut config = AutoConfig {
            name: String::new(),
            group_id: DEFAULT_GROUP_ID.to_vec(),
            discovery_scope: SCOPE_LINK.to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT,
            data_port: DEFAULT_DATA_PORT,
            multicast_address_type: MULTICAST_TEMPORARY_ADDRESS_TYPE.to_string(),
            allowed_interfaces: Vec::new(),
            ignored_interfaces: Vec::new(),
            configured_bitrate: BITRATE_GUESS,
            interface_id: InterfaceId(0),
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            runtime: Arc::new(Mutex::new(AutoRuntime {
                announce_interval_secs: ANNOUNCE_INTERVAL,
                peer_timeout_secs: PEERING_TIMEOUT,
                peer_job_interval_secs: PEER_JOB_INTERVAL,
            })),
        };
        let startup = AutoRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

// ── Multicast address derivation ───────────────────────────────────────────

/// Derive the IPv6 multicast discovery address from group_id, scope, and address type.
///
/// Algorithm (matching Python):
///   1. group_hash = SHA-256(group_id)
///   2. Build suffix from hash bytes 2..14 as 6 little-endian 16-bit words
///   3. First word is hardcoded "0"
///   4. Prefix = "ff" + address_type + scope
pub fn derive_multicast_address(group_id: &[u8], address_type: &str, scope: &str) -> String {
    let group_hash = rns_crypto::sha256::sha256(group_id);
    let g = &group_hash;

    // Build 6 LE 16-bit words from bytes 2..14
    let w1 = (g[2] as u16) << 8 | g[3] as u16;
    let w2 = (g[4] as u16) << 8 | g[5] as u16;
    let w3 = (g[6] as u16) << 8 | g[7] as u16;
    let w4 = (g[8] as u16) << 8 | g[9] as u16;
    let w5 = (g[10] as u16) << 8 | g[11] as u16;
    let w6 = (g[12] as u16) << 8 | g[13] as u16;

    format!(
        "ff{}{}:0:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        address_type, scope, w1, w2, w3, w4, w5, w6
    )
}

/// Parse a multicast address string into an Ipv6Addr.
pub fn parse_multicast_addr(addr: &str) -> Option<Ipv6Addr> {
    addr.parse::<Ipv6Addr>().ok()
}

// ── Discovery token ────────────────────────────────────────────────────────

/// Compute the discovery token: SHA-256(group_id + link_local_address_string).
pub fn compute_discovery_token(group_id: &[u8], link_local_addr: &str) -> [u8; 32] {
    let mut input = group_id.to_vec();
    input.extend_from_slice(link_local_addr.as_bytes());
    rns_crypto::sha256::sha256(&input)
}

// ── Network interface enumeration ──────────────────────────────────────────

/// Information about a local network interface with an IPv6 link-local address.
#[derive(Debug, Clone)]
pub struct LocalInterface {
    pub name: String,
    pub link_local_addr: String,
    pub index: u32,
}

#[cfg(target_os = "android")]
fn platform_ignored_interfaces() -> &'static [&'static str] {
    ANDROID_IGNORE_IFS
}

#[cfg(not(target_os = "android"))]
fn platform_ignored_interfaces() -> &'static [&'static str] {
    &[]
}

fn should_adopt_interface_name(
    name: &str,
    allowed: &[String],
    ignored: &[String],
    platform_ignored: &[&str],
) -> bool {
    let is_allowed = allowed.iter().any(|a| a == name);
    let is_system_ignored = ALL_IGNORE_IFS.iter().any(|&ig| ig == name)
        || platform_ignored.iter().any(|&ig| ig == name);

    if is_system_ignored && !is_allowed {
        return false;
    }

    if ignored.iter().any(|ig| ig == name) {
        return false;
    }

    if !allowed.is_empty() && !is_allowed {
        return false;
    }

    true
}

/// Enumerate network interfaces that have IPv6 link-local addresses (fe80::/10).
///
/// Uses `libc::getifaddrs()`. Filters by allowed/ignored interface lists.
pub fn enumerate_interfaces(allowed: &[String], ignored: &[String]) -> Vec<LocalInterface> {
    let mut result = Vec::new();
    let platform_ignored = platform_ignored_interfaces();

    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return result;
        }

        let mut current = ifaddrs;
        while !current.is_null() {
            let ifa = &*current;
            current = ifa.ifa_next;

            // Must have an address
            if ifa.ifa_addr.is_null() {
                continue;
            }

            // Must be AF_INET6
            if (*ifa.ifa_addr).sa_family as i32 != libc::AF_INET6 {
                continue;
            }

            // Get interface name
            let name = match std::ffi::CStr::from_ptr(ifa.ifa_name).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            if !should_adopt_interface_name(&name, allowed, ignored, platform_ignored) {
                continue;
            }

            // Extract IPv6 address
            let sa6 = ifa.ifa_addr as *const libc::sockaddr_in6;
            let addr_bytes = (*sa6).sin6_addr.s6_addr;
            let ipv6 = Ipv6Addr::from(addr_bytes);

            // Must be link-local (fe80::/10)
            let octets = ipv6.octets();
            if octets[0] != 0xfe || (octets[1] & 0xc0) != 0x80 {
                continue;
            }

            // Format the address (drop scope ID, matching Python's descope_linklocal)
            let addr_str = format!("{}", ipv6);

            // Get interface index
            let index = libc::if_nametoindex(ifa.ifa_name);
            if index == 0 {
                continue;
            }

            // Avoid duplicates (same interface may appear multiple times)
            if result.iter().any(|li: &LocalInterface| li.name == name) {
                continue;
            }

            result.push(LocalInterface {
                name,
                link_local_addr: addr_str,
                index,
            });
        }

        libc::freeifaddrs(ifaddrs);
    }

    result
}

// ── Peer and worker tracking ───────────────────────────────────────────────

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AutoWorkerKey {
    ifname: String,
    if_index: u32,
    link_local_addr: String,
}

#[allow(dead_code)]
impl AutoWorkerKey {
    fn from_local_interface(local: &LocalInterface) -> Self {
        Self {
            ifname: local.name.clone(),
            if_index: local.index,
            link_local_addr: local.link_local_addr.clone(),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkerReconcileAction {
    Add(AutoWorkerKey),
    Remove(AutoWorkerKey),
}

#[cfg_attr(not(test), allow(dead_code))]
fn reconcile_worker_keys(
    active: impl IntoIterator<Item = AutoWorkerKey>,
    desired: impl IntoIterator<Item = AutoWorkerKey>,
) -> Vec<WorkerReconcileAction> {
    let active = active.into_iter().collect::<HashSet<_>>();
    let desired = desired.into_iter().collect::<HashSet<_>>();
    let mut actions = Vec::new();

    for key in active.difference(&desired) {
        actions.push(WorkerReconcileAction::Remove(key.clone()));
    }
    for key in desired.difference(&active) {
        actions.push(WorkerReconcileAction::Add(key.clone()));
    }

    actions.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    actions
}

struct RunningAutoWorker {
    running: Arc<AtomicBool>,
}

impl RunningAutoWorker {
    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

enum AutoWorkerEntry {
    Running(RunningAutoWorker),
    Pending,
}

impl AutoWorkerEntry {
    fn stop(&self) {
        if let AutoWorkerEntry::Running(worker) = self {
            worker.stop();
        }
    }
}

fn reconcile_auto_workers<F>(
    workers: &mut HashMap<AutoWorkerKey, AutoWorkerEntry>,
    desired: Vec<AutoWorkerKey>,
    mut start_worker: F,
) where
    F: FnMut(&AutoWorkerKey) -> io::Result<RunningAutoWorker>,
{
    let mut desired_keys = desired.into_iter().collect::<HashSet<_>>();
    let active_keys = workers.keys().cloned().collect::<Vec<_>>();

    for key in active_keys {
        if !desired_keys.contains(&key) {
            if let Some(worker) = workers.remove(&key) {
                worker.stop();
            }
        }
    }

    let mut desired = desired_keys.drain().collect::<Vec<_>>();
    desired.sort_by(|a, b| a.ifname.cmp(&b.ifname).then(a.if_index.cmp(&b.if_index)));

    for key in desired {
        if matches!(workers.get(&key), Some(AutoWorkerEntry::Running(_))) {
            continue;
        }

        let entry = match start_worker(&key) {
            Ok(worker) => AutoWorkerEntry::Running(worker),
            Err(e) => {
                log::warn!(
                    "AutoInterface worker {} failed to start on {}%{}: {}",
                    key.ifname,
                    key.link_local_addr,
                    key.if_index,
                    e
                );
                AutoWorkerEntry::Pending
            }
        };
        workers.insert(key, entry);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PeerKey {
    link_local_addr: String,
    if_index: u32,
}

/// A discovered peer.
struct AutoPeer {
    interface_id: InterfaceId,
    #[allow(dead_code)]
    link_local_addr: String,
    #[allow(dead_code)]
    ifname: String,
    #[allow(dead_code)]
    if_index: u32,
    last_heard: f64,
}

/// Writer that sends UDP unicast data to a peer.
struct UdpWriter {
    socket: UdpSocket,
    target: SocketAddrV6,
}

impl Writer for UdpWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.socket.send_to(data, self.target)?;
        Ok(())
    }
}

/// Shared state for the AutoInterface across all threads.
struct SharedState {
    /// Known peers, scoped by link-local address and interface index.
    peers: HashMap<PeerKey, AutoPeer>,
    /// Our own scoped link-local addresses (for echo detection).
    link_local_addresses: HashSet<PeerKey>,
    /// Deduplication deque: (hash, timestamp)
    dedup_deque: VecDeque<([u8; 32], f64)>,
    /// Flag set when final_init is done
    online: bool,
    /// Next dynamic interface ID
    next_id: Arc<AtomicU64>,
}

impl SharedState {
    fn new(next_id: Arc<AtomicU64>) -> Self {
        SharedState {
            peers: HashMap::new(),
            link_local_addresses: HashSet::new(),
            dedup_deque: VecDeque::new(),
            online: false,
            next_id,
        }
    }

    /// Check dedup deque for a data hash.
    fn is_duplicate(&self, hash: &[u8; 32], now: f64) -> bool {
        for (h, ts) in &self.dedup_deque {
            if h == hash && now < *ts + MULTI_IF_DEQUE_TTL {
                return true;
            }
        }
        false
    }

    /// Add to dedup deque, trimming to max length.
    fn add_dedup(&mut self, hash: [u8; 32], now: f64) {
        self.dedup_deque.push_back((hash, now));
        while self.dedup_deque.len() > MULTI_IF_DEQUE_LEN {
            self.dedup_deque.pop_front();
        }
    }

    /// Refresh a peer's last_heard timestamp.
    fn refresh_peer(&mut self, key: &PeerKey, now: f64) {
        if let Some(peer) = self.peers.get_mut(key) {
            peer.last_heard = now;
        }
    }
}

fn peer_key_from_src(src_addr: &SocketAddrV6, fallback_if_index: u32) -> PeerKey {
    let if_index = match src_addr.scope_id() {
        0 => fallback_if_index,
        scope_id => scope_id,
    };

    PeerKey {
        link_local_addr: src_addr.ip().to_string(),
        if_index,
    }
}

fn peer_target_addr(peer_key: &PeerKey, data_port: u16) -> io::Result<SocketAddrV6> {
    let peer_ip = peer_key.link_local_addr.parse::<Ipv6Addr>().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad peer IPv6: {}", e))
    })?;

    Ok(SocketAddrV6::new(peer_ip, data_port, 0, peer_key.if_index))
}

fn remove_peers_for_worker(
    shared: &Arc<Mutex<SharedState>>,
    tx: &EventSender,
    key: &AutoWorkerKey,
) {
    let removed = {
        let mut state = lock_or_recover(shared, "auto shared state");
        let removed = state
            .peers
            .iter()
            .filter_map(|(peer_key, peer)| {
                if peer.if_index == key.if_index && peer.ifname == key.ifname {
                    Some((peer_key.clone(), peer.interface_id))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for (peer_key, _) in &removed {
            state.peers.remove(peer_key);
        }

        removed
    };

    for (_, iface_id) in removed {
        let _ = tx.send(Event::InterfaceDown(iface_id));
    }
}

// ── Start function ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct AutoWorkerContext {
    group_id: Vec<u8>,
    mcast_ip: Ipv6Addr,
    discovery_port: u16,
    unicast_discovery_port: u16,
    data_port: u16,
    name: String,
    configured_bitrate: u64,
    ingress_control: rns_core::transport::types::IngressControlConfig,
    runtime: Arc<Mutex<AutoRuntime>>,
    shared: Arc<Mutex<SharedState>>,
    tx: EventSender,
}

/// Start an AutoInterface. Discovers local IPv6 link-local interfaces,
/// sets up multicast discovery, and creates UDP data servers.
///
/// Returns a vec of (InterfaceId, Writer) for each initial peer (typically empty
/// since peers are discovered dynamically via InterfaceUp events).
pub fn start(
    config: AutoConfig,
    tx: EventSender,
    next_dynamic_id: Arc<AtomicU64>,
) -> io::Result<()> {
    let group_id = config.group_id.clone();
    let mcast_addr_str = derive_multicast_address(
        &group_id,
        &config.multicast_address_type,
        &config.discovery_scope,
    );

    let mcast_ip = match parse_multicast_addr(&mcast_addr_str) {
        Some(ip) => ip,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid multicast address: {}", mcast_addr_str),
            ));
        }
    };

    {
        let startup = AutoRuntime::from_config(&config);
        *lock_or_recover(&config.runtime, "auto runtime") = startup;
    }
    let runtime = Arc::clone(&config.runtime);
    let shared = Arc::new(Mutex::new(SharedState::new(next_dynamic_id)));
    let running = Arc::new(AtomicBool::new(true));

    let worker_context = AutoWorkerContext {
        group_id,
        mcast_ip,
        discovery_port: config.discovery_port,
        unicast_discovery_port: config.discovery_port + 1,
        data_port: config.data_port,
        name: config.name.clone(),
        configured_bitrate: config.configured_bitrate,
        ingress_control: config.ingress_control,
        runtime: runtime.clone(),
        shared: shared.clone(),
        tx: tx.clone(),
    };

    {
        let allowed = config.allowed_interfaces.clone();
        let ignored = config.ignored_interfaces.clone();
        let running = running.clone();
        let name = config.name.clone();
        thread::Builder::new()
            .name(format!("auto-supervisor-{}", name))
            .spawn(move || {
                auto_supervisor_loop(allowed, ignored, worker_context, running, &name);
            })?;
    }

    {
        let shared = shared.clone();
        let tx = tx.clone();
        let running = running.clone();
        let name = config.name.clone();
        let runtime = runtime.clone();

        thread::Builder::new()
            .name(format!("auto-peer-jobs-{}", name))
            .spawn(move || {
                peer_jobs_loop(shared, tx, runtime, &running, &name);
            })?;
    }

    let announce_interval = lock_or_recover(&runtime, "auto runtime").announce_interval_secs;
    let peering_wait = Duration::from_secs_f64(announce_interval * 1.2);
    thread::sleep(peering_wait);

    {
        let mut state = lock_or_recover(&shared, "auto shared state");
        state.online = true;
    }

    log::info!("[{}] AutoInterface online", config.name);

    Ok(())
}

fn auto_supervisor_loop(
    allowed_interfaces: Vec<String>,
    ignored_interfaces: Vec<String>,
    context: AutoWorkerContext,
    running: Arc<AtomicBool>,
    name: &str,
) {
    let mut workers: HashMap<AutoWorkerKey, AutoWorkerEntry> = HashMap::new();

    while running.load(Ordering::Relaxed) {
        let interfaces = enumerate_interfaces(&allowed_interfaces, &ignored_interfaces);
        let desired = interfaces
            .iter()
            .map(AutoWorkerKey::from_local_interface)
            .collect::<Vec<_>>();

        {
            let mut state = lock_or_recover(&context.shared, "auto shared state");
            state.link_local_addresses = desired
                .iter()
                .map(|key| PeerKey {
                    link_local_addr: key.link_local_addr.clone(),
                    if_index: key.if_index,
                })
                .collect();
        }

        let removed_workers = reconcile_worker_keys(workers.keys().cloned(), desired.clone())
            .into_iter()
            .filter_map(|action| match action {
                WorkerReconcileAction::Remove(key) => Some(key),
                WorkerReconcileAction::Add(_) => None,
            })
            .collect::<Vec<_>>();
        for key in &removed_workers {
            remove_peers_for_worker(&context.shared, &context.tx, key);
        }

        if desired.is_empty() && workers.is_empty() {
            log::warn!("[{}] No suitable IPv6 link-local interfaces found", name);
        }

        reconcile_auto_workers(&mut workers, desired, |key| {
            start_auto_worker(key, &context)
        });

        thread::sleep(Duration::from_secs_f64(AUTO_RESCAN_INTERVAL));
    }

    for (key, worker) in workers {
        remove_peers_for_worker(&context.shared, &context.tx, &key);
        worker.stop();
    }
}

fn start_auto_worker(
    key: &AutoWorkerKey,
    context: &AutoWorkerContext,
) -> io::Result<RunningAutoWorker> {
    let mcast_socket =
        create_multicast_recv_socket(&context.mcast_ip, context.discovery_port, key.if_index)?;
    let unicast_socket = create_unicast_recv_socket(
        &key.link_local_addr,
        context.unicast_discovery_port,
        key.if_index,
    )?;
    let data_socket =
        create_data_recv_socket(&key.link_local_addr, context.data_port, key.if_index)?;

    let worker_running = Arc::new(AtomicBool::new(true));

    {
        let group_id = context.group_id.clone();
        let link_local = key.link_local_addr.clone();
        let running = worker_running.clone();
        let name = context.name.clone();
        let runtime = context.runtime.clone();
        let mcast_ip = context.mcast_ip;
        let discovery_port = context.discovery_port;
        let if_index = key.if_index;
        thread::Builder::new()
            .name(format!("auto-disc-tx-{}", key.ifname))
            .spawn(move || {
                discovery_sender_loop(
                    &group_id,
                    &link_local,
                    &mcast_ip,
                    discovery_port,
                    if_index,
                    runtime,
                    &running,
                    &name,
                );
            })?;
    }

    {
        let group_id = context.group_id.clone();
        let shared = context.shared.clone();
        let tx = context.tx.clone();
        let running = worker_running.clone();
        let name = context.name.clone();
        let ifname = key.ifname.clone();
        let if_index = key.if_index;
        let runtime = context.runtime.clone();
        let data_port = context.data_port;
        let configured_bitrate = context.configured_bitrate;
        let ingress_control = context.ingress_control;
        thread::Builder::new()
            .name(format!("auto-disc-rx-{}", key.ifname))
            .spawn(move || {
                discovery_receiver_loop(
                    mcast_socket,
                    &group_id,
                    shared,
                    tx,
                    &running,
                    &name,
                    &ifname,
                    if_index,
                    data_port,
                    configured_bitrate,
                    ingress_control,
                    runtime,
                );
            })?;
    }

    {
        let group_id = context.group_id.clone();
        let shared = context.shared.clone();
        let tx = context.tx.clone();
        let running = worker_running.clone();
        let name = context.name.clone();
        let ifname = key.ifname.clone();
        let if_index = key.if_index;
        let runtime = context.runtime.clone();
        let data_port = context.data_port;
        let configured_bitrate = context.configured_bitrate;
        let ingress_control = context.ingress_control;
        thread::Builder::new()
            .name(format!("auto-udisc-rx-{}", key.ifname))
            .spawn(move || {
                discovery_receiver_loop(
                    unicast_socket,
                    &group_id,
                    shared,
                    tx,
                    &running,
                    &name,
                    &ifname,
                    if_index,
                    data_port,
                    configured_bitrate,
                    ingress_control,
                    runtime,
                );
            })?;
    }

    {
        let shared = context.shared.clone();
        let tx = context.tx.clone();
        let running = worker_running.clone();
        let name = context.name.clone();
        let if_index = key.if_index;
        thread::Builder::new()
            .name(format!("auto-data-rx-{}", key.ifname))
            .spawn(move || {
                data_receiver_loop(data_socket, shared, tx, &running, &name, if_index);
            })?;
    }

    log::info!(
        "[{}] AutoInterface worker online on {} {}%{}",
        context.name,
        key.ifname,
        key.link_local_addr,
        key.if_index
    );

    Ok(RunningAutoWorker {
        running: worker_running,
    })
}

// ── Socket creation helpers ────────────────────────────────────────────────

fn create_multicast_recv_socket(
    mcast_ip: &Ipv6Addr,
    port: u16,
    if_index: u32,
) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;

    // Bind to [::]:port on the specific interface
    let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, if_index);
    socket.bind(&bind_addr.into())?;

    // Join multicast group on the specific interface
    socket.join_multicast_v6(mcast_ip, if_index)?;

    socket.set_nonblocking(false)?;
    let std_socket: UdpSocket = socket.into();
    std_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(std_socket)
}

fn create_unicast_recv_socket(link_local: &str, port: u16, if_index: u32) -> io::Result<UdpSocket> {
    let ip: Ipv6Addr = link_local
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad IPv6: {}", e)))?;

    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;

    let bind_addr = SocketAddrV6::new(ip, port, 0, if_index);
    socket.bind(&bind_addr.into())?;

    socket.set_nonblocking(false)?;
    let std_socket: UdpSocket = socket.into();
    std_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(std_socket)
}

fn create_data_recv_socket(link_local: &str, port: u16, if_index: u32) -> io::Result<UdpSocket> {
    let ip: Ipv6Addr = link_local
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad IPv6: {}", e)))?;

    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;

    let bind_addr = SocketAddrV6::new(ip, port, 0, if_index);
    socket.bind(&bind_addr.into())?;

    socket.set_nonblocking(false)?;
    let std_socket: UdpSocket = socket.into();
    std_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(std_socket)
}

// ── Thread loops ───────────────────────────────────────────────────────────

/// Discovery sender: periodically sends discovery token via multicast.
fn discovery_sender_loop(
    group_id: &[u8],
    link_local_addr: &str,
    mcast_ip: &Ipv6Addr,
    discovery_port: u16,
    if_index: u32,
    runtime: Arc<Mutex<AutoRuntime>>,
    running: &AtomicBool,
    name: &str,
) {
    let token = compute_discovery_token(group_id, link_local_addr);

    while running.load(Ordering::Relaxed) {
        // Create a fresh socket for each send (matches Python)
        if let Ok(socket) = UdpSocket::bind("[::]:0") {
            // Set multicast interface
            let if_bytes = if_index.to_ne_bytes();
            unsafe {
                libc::setsockopt(
                    socket_fd(&socket),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MULTICAST_IF,
                    if_bytes.as_ptr() as *const libc::c_void,
                    4,
                );
            }

            let target = SocketAddrV6::new(*mcast_ip, discovery_port, 0, 0);
            if let Err(e) = socket.send_to(&token, target) {
                log::debug!("[{}] multicast send error: {}", name, e);
            }
        }

        let sleep_dur = Duration::from_secs_f64(
            lock_or_recover(&runtime, "auto runtime")
                .announce_interval_secs
                .max(0.1),
        );
        thread::sleep(sleep_dur);
    }
}

/// Discovery receiver: listens for discovery tokens and adds peers.
fn discovery_receiver_loop(
    socket: UdpSocket,
    group_id: &[u8],
    shared: Arc<Mutex<SharedState>>,
    tx: EventSender,
    running: &AtomicBool,
    name: &str,
    ifname: &str,
    if_index: u32,
    data_port: u16,
    configured_bitrate: u64,
    ingress_control: rns_core::transport::types::IngressControlConfig,
    runtime: Arc<Mutex<AutoRuntime>>,
) {
    let mut buf = [0u8; 1024];

    while running.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if n < 32 {
                    continue;
                }

                // Extract source IPv6 address
                let src_addr = match src {
                    std::net::SocketAddr::V6(v6) => v6,
                    _ => continue,
                };
                let peer_key = peer_key_from_src(&src_addr, if_index);
                let src_ip = peer_key.link_local_addr.clone();

                let peering_hash = &buf[..32];
                let expected = compute_discovery_token(group_id, &src_ip);

                if peering_hash != expected {
                    log::debug!("[{}] invalid peering hash from {}", name, src_ip);
                    continue;
                }

                // Check if online
                let state = lock_or_recover(&shared, "auto shared state");
                if !state.online {
                    // Not fully initialized yet, but still accept for initial peering
                    // (Python processes after final_init_done)
                }

                // Check if it's our own echo
                if state.link_local_addresses.contains(&peer_key) {
                    // Multicast echo from ourselves — just record it
                    drop(state);
                    continue;
                }

                // Check if already known
                if state.peers.contains_key(&peer_key) {
                    let now = crate::time::now();
                    drop(state);
                    let mut state = lock_or_recover(&shared, "auto shared state");
                    state.refresh_peer(&peer_key, now);
                    continue;
                }
                drop(state);

                // New peer! Create a data writer to send to them.
                add_peer(
                    &shared,
                    &tx,
                    &peer_key,
                    data_port,
                    name,
                    ifname,
                    configured_bitrate,
                    ingress_control,
                    &runtime,
                );
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout, loop again
                continue;
            }
            Err(e) => {
                log::warn!("[{}] discovery recv error: {}", name, e);
                if !running.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Add a new peer, creating a writer and emitting InterfaceUp.
fn add_peer(
    shared: &Arc<Mutex<SharedState>>,
    tx: &EventSender,
    peer_key: &PeerKey,
    data_port: u16,
    name: &str,
    ifname: &str,
    configured_bitrate: u64,
    ingress_control: rns_core::transport::types::IngressControlConfig,
    _runtime: &Arc<Mutex<AutoRuntime>>,
) {
    // Create UDP writer to send data to this peer
    let send_socket = match UdpSocket::bind("[::]:0") {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "[{}] failed to create writer for peer {}: {}",
                name,
                peer_key.link_local_addr,
                e
            );
            return;
        }
    };

    let target = match peer_target_addr(peer_key, data_port) {
        Ok(target) => target,
        Err(e) => {
            log::warn!(
                "[{}] failed to create target for peer {}%{}: {}",
                name,
                peer_key.link_local_addr,
                peer_key.if_index,
                e
            );
            return;
        }
    };

    let mut state = lock_or_recover(shared, "auto shared state");

    // Double-check not already added (race)
    if state.peers.contains_key(peer_key) {
        state.refresh_peer(peer_key, crate::time::now());
        return;
    }

    let peer_id = InterfaceId(state.next_id.fetch_add(1, Ordering::Relaxed));

    // Create a boxed writer for the driver
    let driver_writer: Box<dyn Writer> = Box::new(UdpWriter {
        socket: send_socket,
        target,
    });

    let peer_info = rns_core::transport::types::InterfaceInfo {
        id: peer_id,
        name: format!(
            "{}:{}%{}",
            name, peer_key.link_local_addr, peer_key.if_index
        ),
        mode: rns_core::constants::MODE_FULL,
        recursive_prs: false,
        announces_from_internal: true,
        out_capable: true,
        in_capable: true,
        bitrate: Some(configured_bitrate),
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: rns_core::constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: false,
        tunnel_id: None,
        mtu: 1400,
        ia_freq: 0.0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
        ingress_control,
    };

    let now = crate::time::now();
    state.peers.insert(
        peer_key.clone(),
        AutoPeer {
            interface_id: peer_id,
            link_local_addr: peer_key.link_local_addr.clone(),
            ifname: ifname.to_string(),
            if_index: peer_key.if_index,
            last_heard: now,
        },
    );

    log::info!(
        "[{}] Peer discovered: {} (id={})",
        name,
        peer_key.link_local_addr,
        peer_id.0
    );

    // Notify driver of new dynamic interface
    let _ = tx.send(Event::InterfaceUp(
        peer_id,
        Some(driver_writer),
        Some(peer_info),
    ));
}

/// Data receiver: receives unicast UDP data from peers and dispatches as frames.
fn data_receiver_loop(
    socket: UdpSocket,
    shared: Arc<Mutex<SharedState>>,
    tx: EventSender,
    running: &AtomicBool,
    name: &str,
    if_index: u32,
) {
    let mut buf = [0u8; HW_MTU + 64]; // a bit extra

    while running.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if n == 0 {
                    continue;
                }

                let src_addr = match src {
                    std::net::SocketAddr::V6(v6) => v6,
                    _ => continue,
                };
                let peer_key = peer_key_from_src(&src_addr, if_index);
                let data = &buf[..n];

                let now = crate::time::now();
                let data_hash = rns_crypto::sha256::sha256(data);

                let mut state = lock_or_recover(&shared, "auto shared state");

                if !state.online {
                    continue;
                }

                // Deduplication
                if state.is_duplicate(&data_hash, now) {
                    continue;
                }
                state.add_dedup(data_hash, now);

                // Refresh peer
                state.refresh_peer(&peer_key, now);

                // Find the interface ID for this peer
                let iface_id = match state.peers.get(&peer_key) {
                    Some(peer) => peer.interface_id,
                    None => {
                        // Unknown peer, skip
                        continue;
                    }
                };

                drop(state);

                if tx
                    .send(Event::Frame {
                        interface_id: iface_id,
                        data: data.to_vec(),
                        rssi: None,
                        snr: None,
                    })
                    .is_err()
                {
                    return;
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                log::warn!("[{}] data recv error: {}", name, e);
                if !running.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Peer jobs: periodically cull timed-out peers.
fn peer_jobs_loop(
    shared: Arc<Mutex<SharedState>>,
    tx: EventSender,
    runtime: Arc<Mutex<AutoRuntime>>,
    running: &AtomicBool,
    name: &str,
) {
    while running.load(Ordering::Relaxed) {
        let interval = Duration::from_secs_f64(
            lock_or_recover(&runtime, "auto runtime")
                .peer_job_interval_secs
                .max(0.1),
        );
        thread::sleep(interval);

        let now = crate::time::now();
        let mut timed_out = Vec::new();
        let peer_timeout_secs = lock_or_recover(&runtime, "auto runtime").peer_timeout_secs;

        {
            let state = lock_or_recover(&shared, "auto shared state");
            for (peer_key, peer) in &state.peers {
                if now > peer.last_heard + peer_timeout_secs {
                    timed_out.push((peer_key.clone(), peer.interface_id));
                }
            }
        }

        for (peer_key, iface_id) in &timed_out {
            log::info!(
                "[{}] Peer timed out: {}%{}",
                name,
                peer_key.link_local_addr,
                peer_key.if_index
            );
            let mut state = lock_or_recover(&shared, "auto shared state");
            state.peers.remove(peer_key);
            let _ = tx.send(Event::InterfaceDown(*iface_id));
        }
    }
}

// ── Helper ─────────────────────────────────────────────────────────────────

/// Get the raw file descriptor from a UdpSocket (for setsockopt).
#[cfg(unix)]
fn socket_fd(socket: &UdpSocket) -> i32 {
    use std::os::unix::io::AsRawFd;
    socket.as_raw_fd()
}

#[cfg(not(unix))]
fn socket_fd(_socket: &UdpSocket) -> i32 {
    0
}

// ── Factory implementation ─────────────────────────────────────────────────

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};

/// Factory for `AutoInterface`.
pub struct AutoFactory;

impl InterfaceFactory for AutoFactory {
    fn type_name(&self) -> &str {
        "AutoInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let group_id = params
            .get("group_id")
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_else(|| DEFAULT_GROUP_ID.to_vec());

        let discovery_scope = params
            .get("discovery_scope")
            .map(|v| match v.to_lowercase().as_str() {
                "link" => SCOPE_LINK.to_string(),
                "admin" => SCOPE_ADMIN.to_string(),
                "site" => SCOPE_SITE.to_string(),
                "organisation" | "organization" => SCOPE_ORGANISATION.to_string(),
                "global" => SCOPE_GLOBAL.to_string(),
                _ => v.clone(),
            })
            .unwrap_or_else(|| SCOPE_LINK.to_string());

        let discovery_port = params
            .get("discovery_port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_DISCOVERY_PORT);

        let data_port = params
            .get("data_port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_DATA_PORT);

        let multicast_address_type = params
            .get("multicast_address_type")
            .map(|v| match v.to_lowercase().as_str() {
                "permanent" => MULTICAST_PERMANENT_ADDRESS_TYPE.to_string(),
                "temporary" => MULTICAST_TEMPORARY_ADDRESS_TYPE.to_string(),
                _ => v.clone(),
            })
            .unwrap_or_else(|| MULTICAST_TEMPORARY_ADDRESS_TYPE.to_string());

        let configured_bitrate = params
            .get("configured_bitrate")
            .or_else(|| params.get("bitrate"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(BITRATE_GUESS);

        let allowed_interfaces = params
            .get("devices")
            .or_else(|| params.get("allowed_interfaces"))
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let ignored_interfaces = params
            .get("ignored_devices")
            .or_else(|| params.get("ignored_interfaces"))
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Box::new(AutoConfig {
            name: name.to_string(),
            group_id,
            discovery_scope,
            discovery_port,
            data_port,
            multicast_address_type,
            allowed_interfaces,
            ignored_interfaces,
            configured_bitrate,
            interface_id: id,
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            runtime: Arc::new(Mutex::new(AutoRuntime {
                announce_interval_secs: ANNOUNCE_INTERVAL,
                peer_timeout_secs: PEERING_TIMEOUT,
                peer_job_interval_secs: PEER_JOB_INTERVAL,
            })),
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> std::io::Result<StartResult> {
        let mut auto_config = *config.into_any().downcast::<AutoConfig>().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong config type")
        })?;

        auto_config.ingress_control = ctx.ingress_control;
        start(auto_config, ctx.tx, ctx.next_dynamic_id)?;
        Ok(StartResult::Listener { control: None })
    }
}

pub(crate) fn auto_runtime_handle_from_config(config: &AutoConfig) -> AutoRuntimeConfigHandle {
    AutoRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: AutoRuntime::from_config(config),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Multicast address derivation ──────────────────────────────────

    #[test]
    fn multicast_address_default_group() {
        // Python vector: ff12:0:d70b:fb1c:16e4:5e39:485e:31e1
        let addr = derive_multicast_address(
            DEFAULT_GROUP_ID,
            MULTICAST_TEMPORARY_ADDRESS_TYPE,
            SCOPE_LINK,
        );
        assert_eq!(addr, "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1");
    }

    #[test]
    fn multicast_address_custom_group() {
        let addr =
            derive_multicast_address(b"testgroup", MULTICAST_TEMPORARY_ADDRESS_TYPE, SCOPE_LINK);
        // Just verify format
        assert!(addr.starts_with("ff12:0:"));
        // Must be different from default
        assert_ne!(addr, "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1");
    }

    #[test]
    fn multicast_address_scope_admin() {
        let addr = derive_multicast_address(
            DEFAULT_GROUP_ID,
            MULTICAST_TEMPORARY_ADDRESS_TYPE,
            SCOPE_ADMIN,
        );
        assert!(addr.starts_with("ff14:0:"));
    }

    #[test]
    fn multicast_address_permanent_type() {
        let addr = derive_multicast_address(
            DEFAULT_GROUP_ID,
            MULTICAST_PERMANENT_ADDRESS_TYPE,
            SCOPE_LINK,
        );
        assert!(addr.starts_with("ff02:0:"));
    }

    #[test]
    fn multicast_address_parseable() {
        let addr = derive_multicast_address(
            DEFAULT_GROUP_ID,
            MULTICAST_TEMPORARY_ADDRESS_TYPE,
            SCOPE_LINK,
        );
        let ip = parse_multicast_addr(&addr);
        assert!(ip.is_some());
        assert!(ip.unwrap().is_multicast());
    }

    // ── Discovery token ──────────────────────────────────────────────

    #[test]
    fn discovery_token_interop() {
        // Python vector: fe80::1 → 97b25576749ea936b0d8a8536ffaf442d157cf47d460dcf13c48b7bd18b6c163
        let token = compute_discovery_token(DEFAULT_GROUP_ID, "fe80::1");
        let expected = "97b25576749ea936b0d8a8536ffaf442d157cf47d460dcf13c48b7bd18b6c163";
        let got = token
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        assert_eq!(got, expected);
    }

    #[test]
    fn discovery_token_interop_2() {
        // Python vector: fe80::dead:beef:1234:5678
        let token = compute_discovery_token(DEFAULT_GROUP_ID, "fe80::dead:beef:1234:5678");
        let expected = "46b6ec7595504b6a35f06bd4bfff71567fb82fcf2706cd361bab20409c42d072";
        let got = token
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        assert_eq!(got, expected);
    }

    #[test]
    fn discovery_token_different_groups() {
        let t1 = compute_discovery_token(b"reticulum", "fe80::1");
        let t2 = compute_discovery_token(b"othergroup", "fe80::1");
        assert_ne!(t1, t2);
    }

    #[test]
    fn discovery_token_different_addrs() {
        let t1 = compute_discovery_token(DEFAULT_GROUP_ID, "fe80::1");
        let t2 = compute_discovery_token(DEFAULT_GROUP_ID, "fe80::2");
        assert_ne!(t1, t2);
    }

    // ── Deduplication ────────────────────────────────────────────────

    #[test]
    fn dedup_basic() {
        let next_id = Arc::new(AtomicU64::new(1));
        let mut state = SharedState::new(next_id);

        let hash = [0xAA; 32];
        let now = 1000.0;

        assert!(!state.is_duplicate(&hash, now));
        state.add_dedup(hash, now);
        assert!(state.is_duplicate(&hash, now));
    }

    #[test]
    fn dedup_expired() {
        let next_id = Arc::new(AtomicU64::new(1));
        let mut state = SharedState::new(next_id);

        let hash = [0xBB; 32];
        state.add_dedup(hash, 1000.0);

        // Within TTL
        assert!(state.is_duplicate(&hash, 1000.5));
        // Expired
        assert!(!state.is_duplicate(&hash, 1001.0));
    }

    #[test]
    fn dedup_max_length() {
        let next_id = Arc::new(AtomicU64::new(1));
        let mut state = SharedState::new(next_id);

        // Fill beyond max
        for i in 0..MULTI_IF_DEQUE_LEN + 10 {
            let mut hash = [0u8; 32];
            hash[0] = (i & 0xFF) as u8;
            hash[1] = ((i >> 8) & 0xFF) as u8;
            state.add_dedup(hash, 1000.0);
        }

        assert_eq!(state.dedup_deque.len(), MULTI_IF_DEQUE_LEN);
    }

    // ── Peer tracking ────────────────────────────────────────────────

    #[test]
    fn peer_refresh() {
        let next_id = Arc::new(AtomicU64::new(100));
        let mut state = SharedState::new(next_id);
        let key = peer_key("fe80::1", 2);

        state.peers.insert(
            key.clone(),
            AutoPeer {
                interface_id: InterfaceId(100),
                link_local_addr: key.link_local_addr.clone(),
                ifname: "eth0".to_string(),
                if_index: key.if_index,
                last_heard: 1000.0,
            },
        );

        state.refresh_peer(&key, 2000.0);
        assert_eq!(state.peers[&key].last_heard, 2000.0);
    }

    #[test]
    fn peer_not_found_refresh() {
        let next_id = Arc::new(AtomicU64::new(100));
        let mut state = SharedState::new(next_id);
        // Should not panic
        state.refresh_peer(&peer_key("fe80::999", 4), 1000.0);
    }

    fn peer_key(addr: &str, if_index: u32) -> PeerKey {
        PeerKey {
            link_local_addr: addr.to_string(),
            if_index,
        }
    }

    #[test]
    fn peer_key_distinguishes_same_link_local_on_different_interfaces() {
        let next_id = Arc::new(AtomicU64::new(100));
        let mut state = SharedState::new(next_id);
        let eth = peer_key("fe80::1", 2);
        let wlan = peer_key("fe80::1", 4);

        state.peers.insert(
            eth.clone(),
            AutoPeer {
                interface_id: InterfaceId(100),
                link_local_addr: eth.link_local_addr.clone(),
                ifname: "eth0".to_string(),
                if_index: eth.if_index,
                last_heard: 1000.0,
            },
        );
        state.peers.insert(
            wlan.clone(),
            AutoPeer {
                interface_id: InterfaceId(101),
                link_local_addr: wlan.link_local_addr.clone(),
                ifname: "wlan0".to_string(),
                if_index: wlan.if_index,
                last_heard: 1000.0,
            },
        );

        assert_eq!(state.peers.len(), 2);
        assert_eq!(state.peers[&eth].interface_id, InterfaceId(100));
        assert_eq!(state.peers[&wlan].interface_id, InterfaceId(101));
    }

    #[test]
    fn peer_target_addr_uses_scope_id() {
        let target = peer_target_addr(&peer_key("fe80::1", 7), 42671).unwrap();

        assert_eq!(target.port(), 42671);
        assert_eq!(target.scope_id(), 7);
    }

    #[test]
    fn remove_peers_for_worker_emits_interface_down() {
        let next_id = Arc::new(AtomicU64::new(100));
        let shared = Arc::new(Mutex::new(SharedState::new(next_id)));
        let worker = worker_key("wlan0", 4, "fe80::abcd");
        let removed = peer_key("fe80::1", 4);
        let kept = peer_key("fe80::1", 5);
        let (tx, rx) = crate::event::channel_with_capacity(4);

        {
            let mut state = lock_or_recover(&shared, "test auto shared state");
            state.peers.insert(
                removed.clone(),
                AutoPeer {
                    interface_id: InterfaceId(100),
                    link_local_addr: removed.link_local_addr.clone(),
                    ifname: "wlan0".to_string(),
                    if_index: removed.if_index,
                    last_heard: 1000.0,
                },
            );
            state.peers.insert(
                kept.clone(),
                AutoPeer {
                    interface_id: InterfaceId(101),
                    link_local_addr: kept.link_local_addr.clone(),
                    ifname: "wlan1".to_string(),
                    if_index: kept.if_index,
                    last_heard: 1000.0,
                },
            );
        }

        remove_peers_for_worker(&shared, &tx, &worker);

        let state = lock_or_recover(&shared, "test auto shared state");
        assert!(!state.peers.contains_key(&removed));
        assert!(state.peers.contains_key(&kept));
        drop(state);

        assert!(matches!(
            rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap(),
            Event::InterfaceDown(InterfaceId(100))
        ));
        assert!(rx.try_recv().is_err());
    }

    // ── Network interface enumeration ────────────────────────────────

    #[test]
    fn enumerate_returns_vec() {
        // This test just verifies the function runs without crashing.
        // Results depend on the system's network configuration.
        let interfaces = enumerate_interfaces(&[], &[]);
        // On CI/test machines, we may or may not have IPv6 link-local
        for iface in &interfaces {
            assert!(!iface.name.is_empty());
            assert!(iface.link_local_addr.starts_with("fe80"));
            assert!(iface.index > 0);
        }
    }

    #[test]
    fn enumerate_with_ignored() {
        // Ignore everything
        let interfaces = enumerate_interfaces(
            &[],
            &[
                "lo".to_string(),
                "eth0".to_string(),
                "wlan0".to_string(),
                "enp0s3".to_string(),
                "docker0".to_string(),
            ],
        );
        // May still have some interfaces, but known ones should be filtered
        for iface in &interfaces {
            assert_ne!(iface.name, "lo");
            assert_ne!(iface.name, "eth0");
            assert_ne!(iface.name, "wlan0");
        }
    }

    #[test]
    fn enumerate_with_allowed_nonexistent() {
        // Only allow an interface that doesn't exist
        let interfaces = enumerate_interfaces(&["nonexistent_if_12345".to_string()], &[]);
        assert!(interfaces.is_empty());
    }

    fn worker_key(name: &str, index: u32, addr: &str) -> AutoWorkerKey {
        AutoWorkerKey {
            ifname: name.to_string(),
            if_index: index,
            link_local_addr: addr.to_string(),
        }
    }

    #[test]
    fn reconcile_worker_keys_adds_new_interface() {
        let desired = vec![worker_key("wlan0", 4, "fe80::1")];

        assert_eq!(
            reconcile_worker_keys(Vec::new(), desired.clone()),
            vec![WorkerReconcileAction::Add(desired[0].clone())]
        );
    }

    #[test]
    fn reconcile_worker_keys_keeps_unchanged_interface() {
        let key = worker_key("wlan0", 4, "fe80::1");

        assert!(reconcile_worker_keys(vec![key.clone()], vec![key]).is_empty());
    }

    #[test]
    fn reconcile_worker_keys_removes_missing_interface() {
        let active = vec![worker_key("wlan0", 4, "fe80::1")];

        assert_eq!(
            reconcile_worker_keys(active.clone(), Vec::new()),
            vec![WorkerReconcileAction::Remove(active[0].clone())]
        );
    }

    #[test]
    fn reconcile_worker_keys_replaces_changed_interface_identity() {
        let old = worker_key("wlan0", 4, "fe80::1");
        let new = worker_key("wlan0", 9, "fe80::2");
        let actions = reconcile_worker_keys(vec![old.clone()], vec![new.clone()]);

        assert!(actions.contains(&WorkerReconcileAction::Remove(old)));
        assert!(actions.contains(&WorkerReconcileAction::Add(new)));
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn reconcile_auto_workers_starts_new_worker() {
        let key = worker_key("wlan0", 4, "fe80::1");
        let mut workers = HashMap::new();
        let mut starts = Vec::new();

        reconcile_auto_workers(&mut workers, vec![key.clone()], |key| {
            starts.push(key.clone());
            Ok(RunningAutoWorker {
                running: Arc::new(AtomicBool::new(true)),
            })
        });

        assert_eq!(starts, vec![key.clone()]);
        assert!(matches!(
            workers.get(&key),
            Some(AutoWorkerEntry::Running(_))
        ));
    }

    #[test]
    fn reconcile_auto_workers_stops_removed_worker() {
        let key = worker_key("wlan0", 4, "fe80::1");
        let running = Arc::new(AtomicBool::new(true));
        let mut workers = HashMap::from([(
            key.clone(),
            AutoWorkerEntry::Running(RunningAutoWorker {
                running: running.clone(),
            }),
        )]);

        reconcile_auto_workers(&mut workers, Vec::new(), |_| unreachable!());

        assert!(!running.load(Ordering::Relaxed));
        assert!(!workers.contains_key(&key));
    }

    #[test]
    fn reconcile_auto_workers_leaves_unchanged_worker_running() {
        let key = worker_key("wlan0", 4, "fe80::1");
        let running = Arc::new(AtomicBool::new(true));
        let mut workers = HashMap::from([(
            key.clone(),
            AutoWorkerEntry::Running(RunningAutoWorker {
                running: running.clone(),
            }),
        )]);
        let mut starts = 0;

        reconcile_auto_workers(&mut workers, vec![key.clone()], |_| {
            starts += 1;
            unreachable!()
        });

        assert_eq!(starts, 0);
        assert!(running.load(Ordering::Relaxed));
        assert!(workers.contains_key(&key));
    }

    #[test]
    fn reconcile_auto_workers_records_pending_start_failure() {
        let key = worker_key("wlan0", 4, "fe80::1");
        let mut workers = HashMap::new();

        reconcile_auto_workers(&mut workers, vec![key.clone()], |_| {
            Err(io::Error::new(io::ErrorKind::AddrInUse, "busy"))
        });

        assert!(matches!(workers.get(&key), Some(AutoWorkerEntry::Pending)));
    }

    #[test]
    fn reconcile_auto_workers_retries_pending_worker() {
        let key = worker_key("wlan0", 4, "fe80::1");
        let running = Arc::new(AtomicBool::new(true));
        let mut workers = HashMap::from([(key.clone(), AutoWorkerEntry::Pending)]);
        let mut starts = 0;

        reconcile_auto_workers(&mut workers, vec![key.clone()], |_| {
            starts += 1;
            Ok(RunningAutoWorker {
                running: running.clone(),
            })
        });

        assert_eq!(starts, 1);
        assert!(matches!(
            workers.get(&key),
            Some(AutoWorkerEntry::Running(_))
        ));
    }

    #[test]
    fn reconcile_auto_workers_keeps_pending_worker_on_retry_failure() {
        let key = worker_key("wlan0", 4, "fe80::1");
        let mut workers = HashMap::from([(key.clone(), AutoWorkerEntry::Pending)]);
        let mut starts = 0;

        reconcile_auto_workers(&mut workers, vec![key.clone()], |_| {
            starts += 1;
            Err(io::Error::new(io::ErrorKind::AddrInUse, "busy"))
        });

        assert_eq!(starts, 1);
        assert!(matches!(workers.get(&key), Some(AutoWorkerEntry::Pending)));
    }

    #[test]
    fn reconcile_auto_workers_removes_pending_worker() {
        let key = worker_key("wlan0", 4, "fe80::1");
        let mut workers = HashMap::from([(key.clone(), AutoWorkerEntry::Pending)]);

        reconcile_auto_workers(&mut workers, Vec::new(), |_| unreachable!());

        assert!(!workers.contains_key(&key));
    }

    #[test]
    fn filter_skips_android_system_interfaces() {
        let allowed = Vec::new();
        let ignored = Vec::new();

        for name in ["dummy0", "lo", "tun0", "rmnet0", "rmnet7"] {
            assert!(
                !should_adopt_interface_name(name, &allowed, &ignored, ANDROID_IGNORE_IFS),
                "{name} should be skipped by Android AutoInterface defaults"
            );
        }
    }

    #[test]
    fn filter_does_not_skip_rmnet8_by_android_defaults() {
        assert!(should_adopt_interface_name(
            "rmnet8",
            &[],
            &[],
            ANDROID_IGNORE_IFS
        ));
    }

    #[test]
    fn filter_allowed_overrides_system_ignored_interface() {
        assert!(should_adopt_interface_name(
            "rmnet0",
            &["rmnet0".to_string()],
            &[],
            ANDROID_IGNORE_IFS
        ));

        assert!(should_adopt_interface_name(
            "lo0",
            &["lo0".to_string()],
            &[],
            &[]
        ));
    }

    #[test]
    fn filter_ignored_wins_over_allowed_interface() {
        assert!(!should_adopt_interface_name(
            "rmnet0",
            &["rmnet0".to_string()],
            &["rmnet0".to_string()],
            ANDROID_IGNORE_IFS
        ));
    }

    #[test]
    fn filter_allowed_list_excludes_unlisted_interfaces() {
        assert!(!should_adopt_interface_name(
            "wlan0",
            &["eth0".to_string()],
            &[],
            ANDROID_IGNORE_IFS
        ));

        assert!(should_adopt_interface_name(
            "wlan0",
            &["wlan0".to_string()],
            &[],
            ANDROID_IGNORE_IFS
        ));
    }

    // ── Config defaults ──────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let config = AutoConfig::default();
        assert_eq!(config.group_id, DEFAULT_GROUP_ID);
        assert_eq!(config.discovery_scope, SCOPE_LINK);
        assert_eq!(config.discovery_port, DEFAULT_DISCOVERY_PORT);
        assert_eq!(config.data_port, DEFAULT_DATA_PORT);
        assert_eq!(
            config.multicast_address_type,
            MULTICAST_TEMPORARY_ADDRESS_TYPE
        );
        assert_eq!(config.configured_bitrate, BITRATE_GUESS);
        assert!(config.allowed_interfaces.is_empty());
        assert!(config.ignored_interfaces.is_empty());
    }

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn constants_match_python() {
        assert_eq!(DEFAULT_DISCOVERY_PORT, 29716);
        assert_eq!(DEFAULT_DATA_PORT, 42671);
        assert_eq!(HW_MTU, 1196);
        assert_eq!(MULTI_IF_DEQUE_LEN, 48);
        assert!((MULTI_IF_DEQUE_TTL - 0.75).abs() < f64::EPSILON);
        assert!((PEERING_TIMEOUT - 22.0).abs() < f64::EPSILON);
        assert!((ANNOUNCE_INTERVAL - 1.6).abs() < f64::EPSILON);
        assert!((PEER_JOB_INTERVAL - 4.0).abs() < f64::EPSILON);
        assert!((MCAST_ECHO_TIMEOUT - 6.5).abs() < f64::EPSILON);
        assert_eq!(BITRATE_GUESS, 10_000_000);
    }

    #[test]
    fn unicast_discovery_port() {
        // Python: unicast_discovery_port = discovery_port + 1
        let unicast_port = DEFAULT_DISCOVERY_PORT + 1;
        assert_eq!(unicast_port, 29717);
    }

    #[test]
    fn reverse_peering_interval() {
        let interval = ANNOUNCE_INTERVAL * REVERSE_PEERING_MULTIPLIER;
        assert!((interval - 5.2).abs() < 0.01);
    }
}
