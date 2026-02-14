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

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender};
use crate::interface::Writer;

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

/// Interfaces always ignored.
pub const ALL_IGNORE_IFS: &[&str] = &["lo0"];

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
}

impl Default for AutoConfig {
    fn default() -> Self {
        AutoConfig {
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
        }
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
pub fn derive_multicast_address(
    group_id: &[u8],
    address_type: &str,
    scope: &str,
) -> String {
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

/// Enumerate network interfaces that have IPv6 link-local addresses (fe80::/10).
///
/// Uses `libc::getifaddrs()`. Filters by allowed/ignored interface lists.
pub fn enumerate_interfaces(
    allowed: &[String],
    ignored: &[String],
) -> Vec<LocalInterface> {
    let mut result = Vec::new();

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

            // Check global ignore list
            if ALL_IGNORE_IFS.iter().any(|&ig| ig == name) {
                if !allowed.iter().any(|a| a == &name) {
                    continue;
                }
            }

            // Check ignored interfaces
            if ignored.iter().any(|ig| ig == &name) {
                continue;
            }

            // Check allowed interfaces (if non-empty, only allow those)
            if !allowed.is_empty() && !allowed.iter().any(|a| a == &name) {
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

// ── Peer tracking ──────────────────────────────────────────────────────────

/// A discovered peer.
struct AutoPeer {
    interface_id: InterfaceId,
    #[allow(dead_code)]
    link_local_addr: String,
    #[allow(dead_code)]
    ifname: String,
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
    /// Known peers: link_local_addr → AutoPeer
    peers: HashMap<String, AutoPeer>,
    /// Our own link-local addresses (for echo detection)
    link_local_addresses: Vec<String>,
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
            link_local_addresses: Vec::new(),
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
    fn refresh_peer(&mut self, addr: &str, now: f64) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.last_heard = now;
        }
    }
}

// ── Start function ─────────────────────────────────────────────────────────

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
    let interfaces = enumerate_interfaces(
        &config.allowed_interfaces,
        &config.ignored_interfaces,
    );

    if interfaces.is_empty() {
        log::warn!(
            "[{}] No suitable IPv6 link-local interfaces found",
            config.name,
        );
        return Ok(());
    }

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

    let discovery_port = config.discovery_port;
    let unicast_discovery_port = config.discovery_port + 1;
    let data_port = config.data_port;
    let name = config.name.clone();
    let announce_interval = ANNOUNCE_INTERVAL;
    let configured_bitrate = config.configured_bitrate;

    let shared = Arc::new(Mutex::new(SharedState::new(next_dynamic_id)));
    let running = Arc::new(AtomicBool::new(true));

    // Record our own link-local addresses
    {
        let mut state = shared.lock().unwrap();
        for iface in &interfaces {
            state.link_local_addresses.push(iface.link_local_addr.clone());
        }
    }

    log::info!(
        "[{}] AutoInterface starting with {} local interfaces, multicast {}",
        name,
        interfaces.len(),
        mcast_addr_str,
    );

    // Per-interface: set up discovery sockets and threads
    for local_iface in &interfaces {
        let ifname = local_iface.name.clone();
        let link_local = local_iface.link_local_addr.clone();
        let if_index = local_iface.index;

        // ─── Multicast discovery socket ───────────────────────────────
        let mcast_socket = create_multicast_recv_socket(
            &mcast_ip,
            discovery_port,
            if_index,
        )?;

        // ─── Unicast discovery socket ─────────────────────────────────
        let unicast_socket = create_unicast_recv_socket(
            &link_local,
            unicast_discovery_port,
            if_index,
        )?;

        // ─── Discovery sender thread ──────────────────────────────────
        {
            let group_id = group_id.clone();
            let link_local = link_local.clone();
            let running = running.clone();
            let name = name.clone();

            thread::Builder::new()
                .name(format!("auto-disc-tx-{}", ifname))
                .spawn(move || {
                    discovery_sender_loop(
                        &group_id,
                        &link_local,
                        &mcast_ip,
                        discovery_port,
                        if_index,
                        announce_interval,
                        &running,
                        &name,
                    );
                })?;
        }

        // ─── Multicast discovery receiver thread ──────────────────────
        {
            let group_id = group_id.clone();
            let shared = shared.clone();
            let tx = tx.clone();
            let running = running.clone();
            let name = name.clone();

            thread::Builder::new()
                .name(format!("auto-disc-rx-{}", ifname))
                .spawn(move || {
                    discovery_receiver_loop(
                        mcast_socket,
                        &group_id,
                        shared,
                        tx,
                        &running,
                        &name,
                        data_port,
                        configured_bitrate,
                    );
                })?;
        }

        // ─── Unicast discovery receiver thread ────────────────────────
        {
            let group_id = group_id.clone();
            let shared = shared.clone();
            let tx = tx.clone();
            let running = running.clone();
            let name = name.clone();

            thread::Builder::new()
                .name(format!("auto-udisc-rx-{}", ifname))
                .spawn(move || {
                    discovery_receiver_loop(
                        unicast_socket,
                        &group_id,
                        shared,
                        tx,
                        &running,
                        &name,
                        data_port,
                        configured_bitrate,
                    );
                })?;
        }

        // ─── Data receiver thread ─────────────────────────────────────
        {
            let link_local = local_iface.link_local_addr.clone();
            let shared = shared.clone();
            let tx = tx.clone();
            let running = running.clone();
            let name = name.clone();

            let data_socket = create_data_recv_socket(
                &link_local,
                data_port,
                if_index,
            )?;

            thread::Builder::new()
                .name(format!("auto-data-rx-{}", local_iface.name))
                .spawn(move || {
                    data_receiver_loop(
                        data_socket,
                        shared,
                        tx,
                        &running,
                        &name,
                    );
                })?;
        }
    }

    // ─── Peer jobs thread ─────────────────────────────────────────────
    {
        let shared = shared.clone();
        let tx = tx.clone();
        let running = running.clone();
        let name = name.clone();

        thread::Builder::new()
            .name(format!("auto-peer-jobs-{}", name))
            .spawn(move || {
                peer_jobs_loop(shared, tx, &running, &name);
            })?;
    }

    // Wait for initial peering
    let peering_wait = Duration::from_secs_f64(announce_interval * 1.2);
    thread::sleep(peering_wait);

    // Mark as online
    {
        let mut state = shared.lock().unwrap();
        state.online = true;
    }

    log::info!("[{}] AutoInterface online", config.name);

    Ok(())
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

fn create_unicast_recv_socket(
    link_local: &str,
    port: u16,
    if_index: u32,
) -> io::Result<UdpSocket> {
    let ip: Ipv6Addr = link_local.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad IPv6: {}", e))
    })?;

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

fn create_data_recv_socket(
    link_local: &str,
    port: u16,
    if_index: u32,
) -> io::Result<UdpSocket> {
    let ip: Ipv6Addr = link_local.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad IPv6: {}", e))
    })?;

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
    interval: f64,
    running: &AtomicBool,
    name: &str,
) {
    let token = compute_discovery_token(group_id, link_local_addr);
    let sleep_dur = Duration::from_secs_f64(interval);

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
    data_port: u16,
    configured_bitrate: u64,
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
                let src_ip = format!("{}", src_addr.ip());

                let peering_hash = &buf[..32];
                let expected = compute_discovery_token(group_id, &src_ip);

                if peering_hash != expected {
                    log::debug!(
                        "[{}] invalid peering hash from {}",
                        name, src_ip
                    );
                    continue;
                }

                // Check if online
                let state = shared.lock().unwrap();
                if !state.online {
                    // Not fully initialized yet, but still accept for initial peering
                    // (Python processes after final_init_done)
                }

                // Check if it's our own echo
                if state.link_local_addresses.contains(&src_ip) {
                    // Multicast echo from ourselves — just record it
                    drop(state);
                    continue;
                }

                // Check if already known
                if state.peers.contains_key(&src_ip) {
                    let now = crate::time::now();
                    drop(state);
                    let mut state = shared.lock().unwrap();
                    state.refresh_peer(&src_ip, now);
                    continue;
                }
                drop(state);

                // New peer! Create a data writer to send to them.
                add_peer(
                    &shared,
                    &tx,
                    &src_ip,
                    data_port,
                    name,
                    configured_bitrate,
                );
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut =>
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
    peer_addr: &str,
    data_port: u16,
    name: &str,
    configured_bitrate: u64,
) {
    let peer_ip: Ipv6Addr = match peer_addr.parse() {
        Ok(ip) => ip,
        Err(_) => return,
    };

    // Create UDP writer to send data to this peer
    let send_socket = match UdpSocket::bind("[::]:0") {
        Ok(s) => s,
        Err(e) => {
            log::warn!("[{}] failed to create writer for peer {}: {}", name, peer_addr, e);
            return;
        }
    };

    let target = SocketAddrV6::new(peer_ip, data_port, 0, 0);

    let mut state = shared.lock().unwrap();

    // Double-check not already added (race)
    if state.peers.contains_key(peer_addr) {
        state.refresh_peer(peer_addr, crate::time::now());
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
        name: format!("{}:{}", name, peer_addr),
        mode: rns_core::constants::MODE_FULL,
        out_capable: true,
        in_capable: true,
        bitrate: Some(configured_bitrate),
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: rns_core::constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: false,
        tunnel_id: None,
        mtu: 1400,
    };

    let now = crate::time::now();
    state.peers.insert(
        peer_addr.to_string(),
        AutoPeer {
            interface_id: peer_id,
            link_local_addr: peer_addr.to_string(),
            ifname: String::new(),
            last_heard: now,
        },
    );

    log::info!("[{}] Peer discovered: {} (id={})", name, peer_addr, peer_id.0);

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
                let src_ip = format!("{}", src_addr.ip());
                let data = &buf[..n];

                let now = crate::time::now();
                let data_hash = rns_crypto::sha256::sha256(data);

                let mut state = shared.lock().unwrap();

                if !state.online {
                    continue;
                }

                // Deduplication
                if state.is_duplicate(&data_hash, now) {
                    continue;
                }
                state.add_dedup(data_hash, now);

                // Refresh peer
                state.refresh_peer(&src_ip, now);

                // Find the interface ID for this peer
                let iface_id = match state.peers.get(&src_ip) {
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
                    })
                    .is_err()
                {
                    return;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut =>
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
    running: &AtomicBool,
    name: &str,
) {
    let interval = Duration::from_secs_f64(PEER_JOB_INTERVAL);

    while running.load(Ordering::Relaxed) {
        thread::sleep(interval);

        let now = crate::time::now();
        let mut timed_out = Vec::new();

        {
            let state = shared.lock().unwrap();
            for (addr, peer) in &state.peers {
                if now > peer.last_heard + PEERING_TIMEOUT {
                    timed_out.push((addr.clone(), peer.interface_id));
                }
            }
        }

        for (addr, iface_id) in &timed_out {
            log::info!("[{}] Peer timed out: {}", name, addr);
            let mut state = shared.lock().unwrap();
            state.peers.remove(addr.as_str());
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
        let addr = derive_multicast_address(
            b"testgroup",
            MULTICAST_TEMPORARY_ADDRESS_TYPE,
            SCOPE_LINK,
        );
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
        let got = token.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(got, expected);
    }

    #[test]
    fn discovery_token_interop_2() {
        // Python vector: fe80::dead:beef:1234:5678
        let token = compute_discovery_token(
            DEFAULT_GROUP_ID,
            "fe80::dead:beef:1234:5678",
        );
        let expected = "46b6ec7595504b6a35f06bd4bfff71567fb82fcf2706cd361bab20409c42d072";
        let got = token.iter().map(|b| format!("{:02x}", b)).collect::<String>();
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

        state.peers.insert("fe80::1".to_string(), AutoPeer {
            interface_id: InterfaceId(100),
            link_local_addr: "fe80::1".to_string(),
            ifname: "eth0".to_string(),
            last_heard: 1000.0,
        });

        state.refresh_peer("fe80::1", 2000.0);
        assert_eq!(state.peers["fe80::1"].last_heard, 2000.0);
    }

    #[test]
    fn peer_not_found_refresh() {
        let next_id = Arc::new(AtomicU64::new(100));
        let mut state = SharedState::new(next_id);
        // Should not panic
        state.refresh_peer("fe80::999", 1000.0);
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
        let interfaces = enumerate_interfaces(&[], &["lo".to_string(), "eth0".to_string(), "wlan0".to_string(), "enp0s3".to_string(), "docker0".to_string()]);
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
        let interfaces = enumerate_interfaces(
            &["nonexistent_if_12345".to_string()],
            &[],
        );
        assert!(interfaces.is_empty());
    }

    // ── Config defaults ──────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let config = AutoConfig::default();
        assert_eq!(config.group_id, DEFAULT_GROUP_ID);
        assert_eq!(config.discovery_scope, SCOPE_LINK);
        assert_eq!(config.discovery_port, DEFAULT_DISCOVERY_PORT);
        assert_eq!(config.data_port, DEFAULT_DATA_PORT);
        assert_eq!(config.multicast_address_type, MULTICAST_TEMPORARY_ADDRESS_TYPE);
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
