//! Backbone TCP mesh interface using cross-platform polling.
//!
//! Server mode: listens on a TCP port, accepts peer connections, spawns
//! dynamic per-peer interfaces. Uses a single poll thread to multiplex
//! all client sockets. HDLC framing for packet boundaries.
//!
//! Client mode: connects to a remote backbone server, single TCP connection
//! with HDLC framing. Reconnects on disconnect.
//!
//! Matches Python `BackboneInterface.py`.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use polling::{Event as PollEvent, Events, Poller};
use socket2::{SockRef, TcpKeepalive};

use rns_core::constants;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult, Writer};
use crate::BackbonePeerStateEntry;

/// HW_MTU: 1 MB (matches Python BackboneInterface.HW_MTU)
#[allow(dead_code)]
const HW_MTU: usize = 1_048_576;

/// Configuration for a backbone interface.
#[derive(Debug, Clone)]
pub struct BackboneConfig {
    pub name: String,
    pub listen_ip: String,
    pub listen_port: u16,
    pub interface_id: InterfaceId,
    pub max_connections: Option<usize>,
    pub idle_timeout: Option<Duration>,
    pub write_stall_timeout: Option<Duration>,
    pub abuse: BackboneAbuseConfig,
    pub runtime: Arc<Mutex<BackboneServerRuntime>>,
    pub peer_state: Arc<Mutex<BackbonePeerMonitor>>,
}

/// Configurable behavior-based abuse detection for inbound peers.
#[derive(Debug, Clone, Default)]
pub struct BackboneAbuseConfig {
    pub max_penalty_duration: Option<Duration>,
}

/// Live runtime state for a backbone server interface.
#[derive(Debug, Clone)]
pub struct BackboneServerRuntime {
    pub max_connections: Option<usize>,
    pub idle_timeout: Option<Duration>,
    pub write_stall_timeout: Option<Duration>,
    pub abuse: BackboneAbuseConfig,
}

impl BackboneServerRuntime {
    pub fn from_config(config: &BackboneConfig) -> Self {
        Self {
            max_connections: config.max_connections,
            idle_timeout: config.idle_timeout,
            write_stall_timeout: config.write_stall_timeout,
            abuse: config.abuse.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackboneRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<BackboneServerRuntime>>,
    pub startup: BackboneServerRuntime,
}

#[derive(Debug, Clone)]
pub struct BackbonePeerStateHandle {
    pub interface_id: InterfaceId,
    pub interface_name: String,
    pub peer_state: Arc<Mutex<BackbonePeerMonitor>>,
}

impl Default for BackboneConfig {
    fn default() -> Self {
        let mut config = BackboneConfig {
            name: String::new(),
            listen_ip: "0.0.0.0".into(),
            listen_port: 0,
            interface_id: InterfaceId(0),
            max_connections: None,
            idle_timeout: None,
            write_stall_timeout: None,
            abuse: BackboneAbuseConfig::default(),
            runtime: Arc::new(Mutex::new(BackboneServerRuntime {
                max_connections: None,
                idle_timeout: None,
                write_stall_timeout: None,
                abuse: BackboneAbuseConfig::default(),
            })),
            peer_state: Arc::new(Mutex::new(BackbonePeerMonitor::new())),
        };
        let startup = BackboneServerRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

/// Maximum pending buffer size per client (512 KB). Clients exceeding this are
/// disconnected to prevent unbounded memory growth from slow readers.
const MAX_PENDING_BYTES: usize = 512 * 1024;

/// Writer that sends HDLC-framed data over a cloned TCP stream (server mode).
struct BackboneWriter {
    stream: TcpStream,
    runtime: Arc<Mutex<BackboneServerRuntime>>,
    interface_name: String,
    interface_id: InterfaceId,
    event_tx: EventSender,
    pending: Vec<u8>,
    stall_started: Option<Instant>,
    disconnect_notified: bool,
    write_stall_flag: Arc<AtomicBool>,
}

impl Writer for BackboneWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let write_stall_timeout = self.runtime.lock().unwrap().write_stall_timeout;
        if !self.pending.is_empty() {
            self.flush_pending(write_stall_timeout)?;
            if !self.pending.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "backbone writer still stalled",
                ));
            }
        }

        let frame = hdlc::frame(data);
        self.write_buffer(&frame, write_stall_timeout)
    }
}

impl BackboneWriter {
    fn write_buffer(
        &mut self,
        data: &[u8],
        write_stall_timeout: Option<Duration>,
    ) -> io::Result<()> {
        let mut written = 0usize;
        while written < data.len() {
            match self.stream.write(&data[written..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "backbone writer wrote zero bytes",
                    ))
                }
                Ok(n) => {
                    written += n;
                    self.stall_started = None;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let now = Instant::now();
                    let started = self.stall_started.get_or_insert(now);
                    if let Some(timeout) = write_stall_timeout {
                        if now.duration_since(*started) >= timeout {
                            return Err(self.disconnect_for_write_stall(timeout));
                        }
                    }
                    if self.pending.len() + data[written..].len() > MAX_PENDING_BYTES {
                        return Err(self.disconnect_for_write_stall(
                            write_stall_timeout.unwrap_or(Duration::from_secs(30)),
                        ));
                    }
                    self.pending.extend_from_slice(&data[written..]);
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "backbone writer would block",
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn flush_pending(&mut self, write_stall_timeout: Option<Duration>) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }

        let pending = std::mem::take(&mut self.pending);
        match self.write_buffer(&pending, write_stall_timeout) {
            Ok(()) => Ok(()),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn disconnect_for_write_stall(&mut self, timeout: Duration) -> io::Error {
        if !self.disconnect_notified {
            log::warn!(
                "[{}] backbone client {} disconnected due to write stall timeout ({:?})",
                self.interface_name,
                self.interface_id.0,
                timeout
            );
            self.write_stall_flag.store(true, Ordering::Relaxed);
            let _ = self.stream.shutdown(Shutdown::Both);
            let _ = self.event_tx.send(Event::InterfaceDown(self.interface_id));
            self.disconnect_notified = true;
        }
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("backbone writer stalled for {:?}", timeout),
        )
    }
}

/// Start a backbone interface. Binds TCP listener, spawns poll thread.
pub fn start(config: BackboneConfig, tx: EventSender, next_id: Arc<AtomicU64>) -> io::Result<()> {
    let addr = format!("{}:{}", config.listen_ip, config.listen_port);
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;

    log::info!(
        "[{}] backbone server listening on {}",
        config.name,
        listener.local_addr().unwrap_or(addr.parse().unwrap())
    );

    let name = config.name.clone();
    let server_interface_id = config.interface_id;
    let runtime = Arc::clone(&config.runtime);
    let peer_state = Arc::clone(&config.peer_state);
    thread::Builder::new()
        .name(format!("backbone-poll-{}", config.interface_id.0))
        .spawn(move || {
            if let Err(e) = poll_loop(
                listener,
                name,
                server_interface_id,
                tx,
                next_id,
                runtime,
                peer_state,
            ) {
                log::error!("backbone poll loop error: {}", e);
            }
        })?;

    Ok(())
}

/// Per-client tracking state.
struct ClientState {
    id: InterfaceId,
    peer_ip: IpAddr,
    peer_port: u16,
    stream: TcpStream,
    decoder: hdlc::Decoder,
    connected_at: Instant,
    has_received_data: bool,
    write_stall_flag: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct PeerBehaviorState {
    blacklisted_until: Option<Instant>,
    blacklist_reason: Option<String>,
    reject_count: u64,
    connected_count: usize,
}

impl PeerBehaviorState {
    fn new() -> Self {
        Self {
            blacklisted_until: None,
            blacklist_reason: None,
            reject_count: 0,
            connected_count: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BackbonePeerMonitor {
    peers: HashMap<IpAddr, PeerBehaviorState>,
}

impl BackbonePeerMonitor {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    fn upsert_snapshot(&mut self, peers: &HashMap<IpAddr, PeerBehaviorState>) {
        let mut merged = self.peers.clone();

        for (peer_ip, state) in peers {
            let entry = merged
                .entry(*peer_ip)
                .or_insert_with(PeerBehaviorState::new);
            entry.connected_count = state.connected_count;
            entry.reject_count = state.reject_count;
            if state.blacklisted_until.is_some() {
                entry.blacklisted_until = state.blacklisted_until;
                entry.blacklist_reason = state.blacklist_reason.clone();
            }
        }

        merged.retain(|peer_ip, state| {
            peers.contains_key(peer_ip)
                || state.blacklisted_until.is_some()
                || state.reject_count > 0
        });
        self.peers = merged;
    }

    fn sync_into(&self, peers: &mut HashMap<IpAddr, PeerBehaviorState>) {
        for (peer_ip, state) in &self.peers {
            let entry = peers.entry(*peer_ip).or_insert_with(PeerBehaviorState::new);
            entry.blacklisted_until = state.blacklisted_until;
            entry.blacklist_reason = state.blacklist_reason.clone();
            entry.reject_count = state.reject_count;
        }

        peers.retain(|peer_ip, state| {
            if state.connected_count > 0 {
                return true;
            }
            self.peers.contains_key(peer_ip)
        });
    }

    pub fn list(&self, interface_name: &str) -> Vec<BackbonePeerStateEntry> {
        let now = Instant::now();
        let mut entries: Vec<BackbonePeerStateEntry> = self
            .peers
            .iter()
            .map(|(peer_ip, state)| BackbonePeerStateEntry {
                interface_name: interface_name.to_string(),
                peer_ip: *peer_ip,
                connected_count: state.connected_count,
                blacklisted_remaining_secs: state
                    .blacklisted_until
                    .and_then(|until| (until > now).then(|| (until - now).as_secs_f64())),
                blacklist_reason: state.blacklist_reason.clone(),
                reject_count: state.reject_count,
            })
            .collect();
        entries.sort_by(|a, b| a.peer_ip.cmp(&b.peer_ip));
        entries
    }

    pub fn clear(&mut self, peer_ip: IpAddr) -> bool {
        self.peers.remove(&peer_ip).is_some()
    }

    pub fn blacklist(&mut self, peer_ip: IpAddr, duration: Duration, reason: String) -> bool {
        let state = self
            .peers
            .entry(peer_ip)
            .or_insert_with(PeerBehaviorState::new);
        state.blacklisted_until = Some(Instant::now() + duration);
        state.blacklist_reason = Some(reason);
        true
    }

    #[cfg(test)]
    pub fn seed_entry(&mut self, entry: BackbonePeerStateEntry) {
        let mut state = PeerBehaviorState::new();
        state.connected_count = entry.connected_count;
        state.reject_count = entry.reject_count;
        state.blacklist_reason = entry.blacklist_reason;
        if let Some(remaining) = entry.blacklisted_remaining_secs {
            state.blacklisted_until = Some(Instant::now() + Duration::from_secs_f64(remaining));
        }
        self.peers.insert(entry.peer_ip, state);
    }
}

#[derive(Clone, Copy)]
enum DisconnectReason {
    RemoteClosed,
    IdleTimeout,
    WriteStall,
}

/// Main poll event loop.
fn poll_loop(
    listener: TcpListener,
    name: String,
    server_interface_id: InterfaceId,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    runtime: Arc<Mutex<BackboneServerRuntime>>,
    peer_state: Arc<Mutex<BackbonePeerMonitor>>,
) -> io::Result<()> {
    let poller = Poller::new()?;

    const LISTENER_KEY: usize = 0;

    // SAFETY: listener outlives its registration in the poller.
    unsafe { poller.add(&listener, PollEvent::readable(LISTENER_KEY))? };

    let mut clients: HashMap<usize, ClientState> = HashMap::new();
    let mut peers: HashMap<IpAddr, PeerBehaviorState> = HashMap::new();
    let mut events = Events::new();
    let mut next_key: usize = 1;

    loop {
        let runtime_snapshot = runtime.lock().unwrap().clone();
        let max_connections = runtime_snapshot.max_connections;
        let idle_timeout = runtime_snapshot.idle_timeout;
        cleanup_peer_state(&mut peers);
        {
            let mut monitor = peer_state.lock().unwrap();
            monitor.sync_into(&mut peers);
            monitor.upsert_snapshot(&peers);
        }

        events.clear();
        poller.wait(&mut events, Some(Duration::from_secs(1)))?;

        for ev in events.iter() {
            if ev.key == LISTENER_KEY {
                // Accept new connections
                loop {
                    match listener.accept() {
                        Ok((stream, peer_addr)) => {
                            let peer_ip = peer_addr.ip();
                            let peer_port = peer_addr.port();

                            if is_ip_blacklisted(&mut peers, peer_ip) {
                                if let Some(state) = peers.get_mut(&peer_ip) {
                                    state.reject_count = state.reject_count.saturating_add(1);
                                }
                                peer_state.lock().unwrap().upsert_snapshot(&peers);
                                log::debug!("[{}] rejecting blacklisted peer {}", name, peer_addr);
                                drop(stream);
                                continue;
                            }

                            if let Some(max) = max_connections {
                                if clients.len() >= max {
                                    log::warn!(
                                        "[{}] max connections ({}) reached, rejecting {}",
                                        name,
                                        max,
                                        peer_addr
                                    );
                                    drop(stream);
                                    continue;
                                }
                            }

                            stream.set_nonblocking(true).ok();
                            stream.set_nodelay(true).ok();
                            set_tcp_keepalive(&stream).ok();

                            // Prevent SIGPIPE on macOS when writing to broken pipes
                            #[cfg(target_os = "macos")]
                            {
                                let sock = SockRef::from(&stream);
                                sock.set_nosigpipe(true).ok();
                            }

                            let key = next_key;
                            next_key += 1;
                            let client_id = InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));

                            log::info!(
                                "[{}] backbone client connected: {} → id {}",
                                name,
                                peer_addr,
                                client_id.0
                            );

                            // Register client with poller
                            // SAFETY: stream is stored in ClientState and outlives registration.
                            if let Err(e) = unsafe { poller.add(&stream, PollEvent::readable(key)) }
                            {
                                log::warn!("[{}] failed to add client to poller: {}", name, e);
                                continue; // stream drops, closing socket
                            }

                            // Create writer via try_clone (cross-platform dup)
                            let writer_stream = match stream.try_clone() {
                                Ok(s) => s,
                                Err(e) => {
                                    log::warn!("[{}] failed to clone client stream: {}", name, e);
                                    let _ = poller.delete(&stream);
                                    continue; // stream drops
                                }
                            };
                            let write_stall_flag = Arc::new(AtomicBool::new(false));
                            let writer: Box<dyn Writer> = Box::new(BackboneWriter {
                                stream: writer_stream,
                                runtime: Arc::clone(&runtime),
                                interface_name: name.clone(),
                                interface_id: client_id,
                                event_tx: tx.clone(),
                                pending: Vec::new(),
                                stall_started: None,
                                disconnect_notified: false,
                                write_stall_flag: Arc::clone(&write_stall_flag),
                            });

                            clients.insert(
                                key,
                                ClientState {
                                    id: client_id,
                                    peer_ip,
                                    peer_port,
                                    stream,
                                    decoder: hdlc::Decoder::new(),
                                    connected_at: Instant::now(),
                                    has_received_data: false,
                                    write_stall_flag,
                                },
                            );
                            peers
                                .entry(peer_ip)
                                .or_insert_with(PeerBehaviorState::new)
                                .connected_count += 1;
                            peer_state.lock().unwrap().upsert_snapshot(&peers);
                            let _ = tx.send(Event::BackbonePeerConnected {
                                server_interface_id,
                                peer_interface_id: client_id,
                                peer_ip,
                                peer_port,
                            });

                            let info = InterfaceInfo {
                                id: client_id,
                                name: format!("BackboneInterface/{}", client_id.0),
                                mode: constants::MODE_FULL,
                                out_capable: true,
                                in_capable: true,
                                bitrate: Some(1_000_000_000), // 1 Gbps guess
                                announce_rate_target: None,
                                announce_rate_grace: 0,
                                announce_rate_penalty: 0.0,
                                announce_cap: constants::ANNOUNCE_CAP,
                                is_local_client: false,
                                wants_tunnel: false,
                                tunnel_id: None,
                                mtu: 65535,
                                ia_freq: 0.0,
                                started: 0.0,
                                ingress_control: true,
                            };

                            if tx
                                .send(Event::InterfaceUp(client_id, Some(writer), Some(info)))
                                .is_err()
                            {
                                // Driver shut down
                                cleanup(&poller, &clients, &listener);
                                return Ok(());
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            log::warn!("[{}] accept error: {}", name, e);
                            break;
                        }
                    }
                }
                // Re-arm listener (oneshot semantics)
                poller.modify(&listener, PollEvent::readable(LISTENER_KEY))?;
            } else if clients.contains_key(&ev.key) {
                let key = ev.key;
                let mut should_remove = false;
                let mut client_id = InterfaceId(0);

                let mut buf = [0u8; 4096];
                let read_result = {
                    let client = clients.get_mut(&key).unwrap();
                    client.stream.read(&mut buf)
                };

                match read_result {
                    Ok(0) | Err(_) => {
                        if let Some(c) = clients.get(&key) {
                            client_id = c.id;
                        }
                        should_remove = true;
                    }
                    Ok(n) => {
                        let client = clients.get_mut(&key).unwrap();
                        client_id = client.id;
                        client.has_received_data = true;
                        for frame in client.decoder.feed(&buf[..n]) {
                            if tx
                                .send(Event::Frame {
                                    interface_id: client_id,
                                    data: frame,
                                })
                                .is_err()
                            {
                                cleanup(&poller, &clients, &listener);
                                return Ok(());
                            }
                        }
                    }
                }

                if should_remove {
                    let reason = if clients
                        .get(&key)
                        .is_some_and(|c| c.write_stall_flag.load(Ordering::Relaxed))
                    {
                        DisconnectReason::WriteStall
                    } else {
                        DisconnectReason::RemoteClosed
                    };
                    disconnect_client(
                        &poller,
                        &mut clients,
                        &mut peers,
                        &name,
                        server_interface_id,
                        &tx,
                        &peer_state,
                        key,
                        client_id,
                        reason,
                    );
                } else if let Some(client) = clients.get(&key) {
                    // Re-arm client (oneshot semantics)
                    poller.modify(&client.stream, PollEvent::readable(key))?;
                }
            }
        }

        if let Some(timeout) = idle_timeout {
            let now = Instant::now();
            let timed_out: Vec<(usize, InterfaceId)> = clients
                .iter()
                .filter_map(|(&key, client)| {
                    if client.has_received_data || now.duration_since(client.connected_at) < timeout
                    {
                        None
                    } else {
                        Some((key, client.id))
                    }
                })
                .collect();

            for (key, client_id) in timed_out {
                disconnect_client(
                    &poller,
                    &mut clients,
                    &mut peers,
                    &name,
                    server_interface_id,
                    &tx,
                    &peer_state,
                    key,
                    client_id,
                    DisconnectReason::IdleTimeout,
                );
            }
        }
    }
}

fn cleanup_peer_state(peers: &mut HashMap<IpAddr, PeerBehaviorState>) {
    let now = Instant::now();
    peers.retain(|_, state| {
        if matches!(state.blacklisted_until, Some(until) if now >= until) {
            state.blacklisted_until = None;
            state.blacklist_reason = None;
        }
        state.blacklisted_until.is_some() || state.connected_count > 0 || state.reject_count > 0
    });
}

fn is_ip_blacklisted(peers: &mut HashMap<IpAddr, PeerBehaviorState>, peer_ip: IpAddr) -> bool {
    let now = Instant::now();
    if let Some(state) = peers.get_mut(&peer_ip) {
        if let Some(until) = state.blacklisted_until {
            if now < until {
                return true;
            }
            state.blacklisted_until = None;
        }
    }
    false
}

fn disconnect_client(
    poller: &Poller,
    clients: &mut HashMap<usize, ClientState>,
    peers: &mut HashMap<IpAddr, PeerBehaviorState>,
    name: &str,
    server_interface_id: InterfaceId,
    tx: &EventSender,
    peer_state: &Arc<Mutex<BackbonePeerMonitor>>,
    key: usize,
    client_id: InterfaceId,
    reason: DisconnectReason,
) {
    let Some(client) = clients.remove(&key) else {
        return;
    };

    match reason {
        DisconnectReason::RemoteClosed => {
            log::info!("[{}] backbone client {} disconnected", name, client_id.0);
        }
        DisconnectReason::IdleTimeout => {
            log::info!(
                "[{}] backbone client {} disconnected due to idle timeout",
                name,
                client_id.0
            );
        }
        DisconnectReason::WriteStall => {
            // Already logged by BackboneWriter::disconnect_for_write_stall
        }
    }

    let _ = poller.delete(&client.stream);
    // client.stream closes on drop
    let connected_for = client.connected_at.elapsed();
    let _ = tx.send(Event::BackbonePeerDisconnected {
        server_interface_id,
        peer_interface_id: client.id,
        peer_ip: client.peer_ip,
        peer_port: client.peer_port,
        connected_for,
        had_received_data: client.has_received_data,
    });
    match reason {
        DisconnectReason::IdleTimeout => {
            let _ = tx.send(Event::BackbonePeerIdleTimeout {
                server_interface_id,
                peer_interface_id: client.id,
                peer_ip: client.peer_ip,
                peer_port: client.peer_port,
                connected_for,
            });
        }
        DisconnectReason::WriteStall => {
            let _ = tx.send(Event::BackbonePeerWriteStall {
                server_interface_id,
                peer_interface_id: client.id,
                peer_ip: client.peer_ip,
                peer_port: client.peer_port,
                connected_for,
            });
        }
        DisconnectReason::RemoteClosed => {}
    }

    if let Some(state) = peers.get_mut(&client.peer_ip) {
        state.connected_count = state.connected_count.saturating_sub(1);
    }
    peer_state.lock().unwrap().upsert_snapshot(peers);
    // Writer already sent InterfaceDown for write stalls; avoid duplicate.
    if !matches!(reason, DisconnectReason::WriteStall) {
        let _ = tx.send(Event::InterfaceDown(client_id));
    }
}

fn set_tcp_keepalive(stream: &TcpStream) -> io::Result<()> {
    let sock = SockRef::from(stream);
    let mut keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(5))
        .with_interval(Duration::from_secs(2));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        keepalive = keepalive.with_retries(12);
    }
    sock.set_tcp_keepalive(&keepalive)
}

fn cleanup(poller: &Poller, clients: &HashMap<usize, ClientState>, listener: &TcpListener) {
    for (_, client) in clients {
        let _ = poller.delete(&client.stream);
    }
    let _ = poller.delete(listener);
}

// ---------------------------------------------------------------------------
// Client mode
// ---------------------------------------------------------------------------

/// Configuration for a backbone client interface.
#[derive(Debug, Clone)]
pub struct BackboneClientConfig {
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub interface_id: InterfaceId,
    pub reconnect_wait: Duration,
    pub max_reconnect_tries: Option<u32>,
    pub connect_timeout: Duration,
    pub transport_identity: Option<String>,
    pub runtime: Arc<Mutex<BackboneClientRuntime>>,
}

#[derive(Debug, Clone)]
pub struct BackboneClientRuntime {
    pub reconnect_wait: Duration,
    pub max_reconnect_tries: Option<u32>,
    pub connect_timeout: Duration,
}

impl BackboneClientRuntime {
    pub fn from_config(config: &BackboneClientConfig) -> Self {
        Self {
            reconnect_wait: config.reconnect_wait,
            max_reconnect_tries: config.max_reconnect_tries,
            connect_timeout: config.connect_timeout,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackboneClientRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<BackboneClientRuntime>>,
    pub startup: BackboneClientRuntime,
}

impl Default for BackboneClientConfig {
    fn default() -> Self {
        let mut config = BackboneClientConfig {
            name: String::new(),
            target_host: "127.0.0.1".into(),
            target_port: 4242,
            interface_id: InterfaceId(0),
            reconnect_wait: Duration::from_secs(5),
            max_reconnect_tries: None,
            connect_timeout: Duration::from_secs(5),
            transport_identity: None,
            runtime: Arc::new(Mutex::new(BackboneClientRuntime {
                reconnect_wait: Duration::from_secs(5),
                max_reconnect_tries: None,
                connect_timeout: Duration::from_secs(5),
            })),
        };
        let startup = BackboneClientRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

/// Writer that sends HDLC-framed data over a TCP stream (client mode).
struct BackboneClientWriter {
    stream: TcpStream,
}

impl Writer for BackboneClientWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }
}

/// Try to connect to the target host:port with timeout.
fn try_connect_client(config: &BackboneClientConfig) -> io::Result<TcpStream> {
    let runtime = config.runtime.lock().unwrap().clone();
    let addr_str = format!("{}:{}", config.target_host, config.target_port);
    let addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved"))?;

    let stream = TcpStream::connect_timeout(&addr, runtime.connect_timeout)?;
    stream.set_nodelay(true)?;
    set_tcp_keepalive(&stream).ok();

    // Prevent SIGPIPE on macOS when writing to broken pipes
    #[cfg(target_os = "macos")]
    {
        let sock = SockRef::from(&stream);
        sock.set_nosigpipe(true).ok();
    }

    Ok(stream)
}

/// Connect and start the reader thread. Returns the writer for the driver.
pub fn start_client(config: BackboneClientConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    let stream = try_connect_client(&config)?;
    let reader_stream = stream.try_clone()?;
    let writer_stream = stream.try_clone()?;

    let id = config.interface_id;
    log::info!(
        "[{}] backbone client connected to {}:{}",
        config.name,
        config.target_host,
        config.target_port
    );

    // Initial connect: writer is None because it's returned directly to the caller
    let _ = tx.send(Event::InterfaceUp(id, None, None));

    thread::Builder::new()
        .name(format!("backbone-client-{}", id.0))
        .spawn(move || {
            client_reader_loop(reader_stream, config, tx);
        })?;

    Ok(Box::new(BackboneClientWriter {
        stream: writer_stream,
    }))
}

/// Reader thread: reads from socket, HDLC-decodes, sends frames to driver.
/// On disconnect, attempts reconnection.
fn client_reader_loop(mut stream: TcpStream, config: BackboneClientConfig, tx: EventSender) {
    let id = config.interface_id;
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log::warn!("[{}] connection closed", config.name);
                let _ = tx.send(Event::InterfaceDown(id));
                match client_reconnect(&config, &tx) {
                    Some(new_stream) => {
                        stream = new_stream;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => {
                        log::error!("[{}] reconnection failed, giving up", config.name);
                        return;
                    }
                }
            }
            Ok(n) => {
                for frame in decoder.feed(&buf[..n]) {
                    if tx
                        .send(Event::Frame {
                            interface_id: id,
                            data: frame,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] read error: {}", config.name, e);
                let _ = tx.send(Event::InterfaceDown(id));
                match client_reconnect(&config, &tx) {
                    Some(new_stream) => {
                        stream = new_stream;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => {
                        log::error!("[{}] reconnection failed, giving up", config.name);
                        return;
                    }
                }
            }
        }
    }
}

/// Maximum backoff multiplier: `base_delay * 2^MAX_BACKOFF_SHIFT`.
/// With a 5 s base this caps at 5 × 2^6 = 320 s ≈ 5 min.
const MAX_BACKOFF_SHIFT: u32 = 6;

/// Attempt to reconnect with exponential backoff and jitter.
/// Returns the new reader stream on success.
/// Sends the new writer to the driver via InterfaceUp event.
fn client_reconnect(config: &BackboneClientConfig, tx: &EventSender) -> Option<TcpStream> {
    let mut attempts = 0u32;
    loop {
        let runtime = config.runtime.lock().unwrap().clone();

        let shift = attempts.min(MAX_BACKOFF_SHIFT);
        let backoff = runtime.reconnect_wait * 2u32.pow(shift);
        // Add ±25 % jitter to avoid thundering-herd reconnects.
        let jitter_range = backoff / 4;
        let jitter = if jitter_range.as_nanos() > 0 {
            let offset = Duration::from_nanos(
                (std::hash::RandomState::new().build_hasher().finish()
                    % jitter_range.as_nanos() as u64)
                    * 2,
            );
            if offset > jitter_range {
                backoff + (offset - jitter_range)
            } else {
                backoff - (jitter_range - offset)
            }
        } else {
            backoff
        };
        thread::sleep(jitter);

        attempts += 1;

        if let Some(max) = runtime.max_reconnect_tries {
            if attempts > max {
                let _ = tx.send(Event::InterfaceDown(config.interface_id));
                return None;
            }
        }

        log::info!(
            "[{}] reconnect attempt {} (backoff {:.1}s) ...",
            config.name,
            attempts,
            jitter.as_secs_f64(),
        );

        match try_connect_client(config) {
            Ok(new_stream) => {
                let writer_stream = match new_stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("[{}] failed to clone stream: {}", config.name, e);
                        continue;
                    }
                };
                log::info!(
                    "[{}] reconnected after {} attempt(s)",
                    config.name,
                    attempts
                );
                let new_writer: Box<dyn Writer> = Box::new(BackboneClientWriter {
                    stream: writer_stream,
                });
                let _ = tx.send(Event::InterfaceUp(
                    config.interface_id,
                    Some(new_writer),
                    None,
                ));
                return Some(new_stream);
            }
            Err(e) => {
                log::warn!("[{}] reconnect failed: {}", config.name, e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Internal enum used by [`BackboneInterfaceFactory`] to carry either a
/// server or client config through the opaque `InterfaceConfigData` channel.
pub(crate) enum BackboneMode {
    Server(BackboneConfig),
    Client(BackboneClientConfig),
}

/// Factory for `BackboneInterface`.
///
/// If the config params contain `"remote"` or `"target_host"` the interface
/// is started in client mode; otherwise it is started as a TCP listener
/// (server mode).
pub struct BackboneInterfaceFactory;

fn parse_positive_duration_secs(params: &HashMap<String, String>, key: &str) -> Option<Duration> {
    params
        .get(key)
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .map(Duration::from_secs_f64)
}

impl InterfaceFactory for BackboneInterfaceFactory {
    fn type_name(&self) -> &str {
        "BackboneInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        if let Some(target_host) = params.get("remote").or_else(|| params.get("target_host")) {
            // Client mode
            let target_host = target_host.clone();
            let target_port = params
                .get("target_port")
                .or_else(|| params.get("port"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(4242);
            let transport_identity = params.get("transport_identity").cloned();
            Ok(Box::new(BackboneMode::Client(BackboneClientConfig {
                name: name.to_string(),
                target_host,
                target_port,
                interface_id: id,
                transport_identity,
                ..BackboneClientConfig::default()
            })))
        } else {
            // Server mode
            let listen_ip = params
                .get("listen_ip")
                .or_else(|| params.get("device"))
                .cloned()
                .unwrap_or_else(|| "0.0.0.0".into());
            let listen_port = params
                .get("listen_port")
                .or_else(|| params.get("port"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(4242);
            let max_connections = params.get("max_connections").and_then(|v| v.parse().ok());
            let idle_timeout = parse_positive_duration_secs(params, "idle_timeout");
            let write_stall_timeout = parse_positive_duration_secs(params, "write_stall_timeout");
            let abuse = BackboneAbuseConfig {
                max_penalty_duration: parse_positive_duration_secs(params, "max_penalty_duration"),
            };
            let mut config = BackboneConfig {
                name: name.to_string(),
                listen_ip,
                listen_port,
                interface_id: id,
                max_connections,
                idle_timeout,
                write_stall_timeout,
                abuse,
                runtime: Arc::new(Mutex::new(BackboneServerRuntime {
                    max_connections: None,
                    idle_timeout: None,
                    write_stall_timeout: None,
                    abuse: BackboneAbuseConfig::default(),
                })),
                peer_state: Arc::new(Mutex::new(BackbonePeerMonitor::new())),
            };
            let startup = BackboneServerRuntime::from_config(&config);
            config.runtime = Arc::new(Mutex::new(startup));
            Ok(Box::new(BackboneMode::Server(config)))
        }
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let mode = *config.into_any().downcast::<BackboneMode>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "wrong config type for BackboneInterface",
            )
        })?;

        match mode {
            BackboneMode::Client(cfg) => {
                let id = cfg.interface_id;
                let name = cfg.name.clone();
                let info = InterfaceInfo {
                    id,
                    name,
                    mode: ctx.mode,
                    out_capable: true,
                    in_capable: true,
                    bitrate: Some(1_000_000_000),
                    announce_rate_target: None,
                    announce_rate_grace: 0,
                    announce_rate_penalty: 0.0,
                    announce_cap: constants::ANNOUNCE_CAP,
                    is_local_client: false,
                    wants_tunnel: false,
                    tunnel_id: None,
                    mtu: 65535,
                    ingress_control: true,
                    ia_freq: 0.0,
                    started: crate::time::now(),
                };
                let writer = start_client(cfg, ctx.tx)?;
                Ok(StartResult::Simple {
                    id,
                    info,
                    writer,
                    interface_type_name: "BackboneInterface".to_string(),
                })
            }
            BackboneMode::Server(cfg) => {
                start(cfg, ctx.tx, ctx.next_dynamic_id)?;
                Ok(StartResult::Listener { control: None })
            }
        }
    }
}

pub(crate) fn runtime_handle_from_mode(mode: &BackboneMode) -> Option<BackboneRuntimeConfigHandle> {
    match mode {
        BackboneMode::Server(config) => Some(BackboneRuntimeConfigHandle {
            interface_name: config.name.clone(),
            runtime: Arc::clone(&config.runtime),
            startup: BackboneServerRuntime::from_config(config),
        }),
        BackboneMode::Client(_) => None,
    }
}

pub(crate) fn peer_state_handle_from_mode(mode: &BackboneMode) -> Option<BackbonePeerStateHandle> {
    match mode {
        BackboneMode::Server(config) => Some(BackbonePeerStateHandle {
            interface_id: config.interface_id,
            interface_name: config.name.clone(),
            peer_state: Arc::clone(&config.peer_state),
        }),
        BackboneMode::Client(_) => None,
    }
}

pub(crate) fn client_runtime_handle_from_mode(
    mode: &BackboneMode,
) -> Option<BackboneClientRuntimeConfigHandle> {
    match mode {
        BackboneMode::Client(config) => Some(BackboneClientRuntimeConfigHandle {
            interface_name: config.name.clone(),
            runtime: Arc::clone(&config.runtime),
            startup: BackboneClientRuntime::from_config(config),
        }),
        BackboneMode::Server(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn find_free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn recv_non_peer_event(
        rx: &mpsc::Receiver<Event>,
        timeout: Duration,
    ) -> Result<Event, mpsc::RecvTimeoutError> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(mpsc::RecvTimeoutError::Timeout);
            }
            let event = rx.recv_timeout(remaining)?;
            match event {
                Event::BackbonePeerConnected { .. }
                | Event::BackbonePeerDisconnected { .. }
                | Event::BackbonePeerIdleTimeout { .. }
                | Event::BackbonePeerWriteStall { .. }
                | Event::BackbonePeerPenalty { .. } => continue,
                other => return Ok(other),
            }
        }
    }

    fn make_server_config(
        port: u16,
        interface_id: u64,
        max_connections: Option<usize>,
        idle_timeout: Option<Duration>,
        write_stall_timeout: Option<Duration>,
        abuse: BackboneAbuseConfig,
    ) -> BackboneConfig {
        let mut config = BackboneConfig {
            name: "test-backbone".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(interface_id),
            max_connections,
            idle_timeout,
            write_stall_timeout,
            abuse,
            runtime: Arc::new(Mutex::new(BackboneServerRuntime {
                max_connections: None,
                idle_timeout: None,
                write_stall_timeout: None,
                abuse: BackboneAbuseConfig::default(),
            })),
            peer_state: Arc::new(Mutex::new(BackbonePeerMonitor::new())),
        };
        let startup = BackboneServerRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }

    #[test]
    fn backbone_accept_connection() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8000));

        let config = make_server_config(port, 80, None, None, None, BackboneAbuseConfig::default());

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        match event {
            Event::InterfaceUp(id, writer, info) => {
                assert_eq!(id, InterfaceId(8000));
                assert!(writer.is_some());
                assert!(info.is_some());
                let info = info.unwrap();
                assert!(info.out_capable);
                assert!(info.in_capable);
            }
            other => panic!("expected InterfaceUp, got {:?}", other),
        }
    }

    #[test]
    fn backbone_receive_frame() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8100));

        let config = make_server_config(port, 81, None, None, None, BackboneAbuseConfig::default());

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain InterfaceUp
        let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

        // Send HDLC frame (>= 19 bytes)
        let payload: Vec<u8> = (0..32).collect();
        client.write_all(&hdlc::frame(&payload)).unwrap();

        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { interface_id, data } => {
                assert_eq!(interface_id, InterfaceId(8100));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn backbone_send_to_client() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8200));

        let config = make_server_config(port, 82, None, None, None, BackboneAbuseConfig::default());

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Get writer from InterfaceUp
        let event = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();
        let mut writer = match event {
            Event::InterfaceUp(_, Some(w), _) => w,
            other => panic!("expected InterfaceUp with writer, got {:?}", other),
        };

        // Send frame via writer
        let payload: Vec<u8> = (0..24).collect();
        writer.send_frame(&payload).unwrap();

        // Read from client
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).unwrap();
        let expected = hdlc::frame(&payload);
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn backbone_multiple_clients() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8300));

        let config = make_server_config(port, 83, None, None, None, BackboneAbuseConfig::default());

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        let mut ids = Vec::new();
        for _ in 0..2 {
            let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
            match event {
                Event::InterfaceUp(id, _, _) => ids.push(id),
                other => panic!("expected InterfaceUp, got {:?}", other),
            }
        }

        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn backbone_client_disconnect() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8400));

        let config = make_server_config(port, 84, None, None, None, BackboneAbuseConfig::default());

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain InterfaceUp
        let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

        // Disconnect
        drop(client);

        // Should receive InterfaceDown
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(
            matches!(event, Event::InterfaceDown(InterfaceId(8400))),
            "expected InterfaceDown(8400), got {:?}",
            event
        );
    }

    #[test]
    fn backbone_epoll_multiplexing() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8500));

        let config = make_server_config(port, 85, None, None, None, BackboneAbuseConfig::default());

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let mut client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain both InterfaceUp events
        let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();
        let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

        // Both clients send data simultaneously
        let payload1: Vec<u8> = (0..24).collect();
        let payload2: Vec<u8> = (100..130).collect();
        client1.write_all(&hdlc::frame(&payload1)).unwrap();
        client2.write_all(&hdlc::frame(&payload2)).unwrap();

        // Should receive both Frame events
        let mut received = Vec::new();
        for _ in 0..2 {
            let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
            match event {
                Event::Frame { data, .. } => received.push(data),
                other => panic!("expected Frame, got {:?}", other),
            }
        }
        assert!(received.contains(&payload1));
        assert!(received.contains(&payload2));
    }

    #[test]
    fn backbone_bind_port() {
        let port = find_free_port();
        let (tx, _rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8600));

        let config = make_server_config(port, 86, None, None, None, BackboneAbuseConfig::default());

        // Should not error
        start(config, tx, next_id).unwrap();
    }

    #[test]
    fn backbone_hdlc_fragmented() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8700));

        let config = make_server_config(port, 87, None, None, None, BackboneAbuseConfig::default());

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_nodelay(true).unwrap();

        // Drain InterfaceUp
        let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

        // Send HDLC frame in two fragments
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        let mid = framed.len() / 2;

        client.write_all(&framed[..mid]).unwrap();
        thread::sleep(Duration::from_millis(50));
        client.write_all(&framed[mid..]).unwrap();

        // Should receive reassembled frame
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => {
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Client mode tests
    // -----------------------------------------------------------------------

    fn make_client_config(port: u16, id: u64) -> BackboneClientConfig {
        BackboneClientConfig {
            name: format!("test-bb-client-{}", port),
            target_host: "127.0.0.1".into(),
            target_port: port,
            interface_id: InterfaceId(id),
            reconnect_wait: Duration::from_millis(100),
            max_reconnect_tries: Some(2),
            connect_timeout: Duration::from_secs(2),
            transport_identity: None,
            runtime: Arc::new(Mutex::new(BackboneClientRuntime {
                reconnect_wait: Duration::from_millis(100),
                max_reconnect_tries: Some(2),
                connect_timeout: Duration::from_secs(2),
            })),
        }
    }

    #[test]
    fn backbone_client_connect() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = crate::event::channel();

        let config = make_client_config(port, 9000);
        let _writer = start_client(config, tx).unwrap();

        let _server_stream = listener.accept().unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(9000), _, _)));
    }

    #[test]
    fn backbone_client_receive_frame() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = crate::event::channel();

        let config = make_client_config(port, 9100);
        let _writer = start_client(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send HDLC frame from server side (>= 19 bytes payload)
        let payload: Vec<u8> = (0..32).collect();
        server_stream.write_all(&hdlc::frame(&payload)).unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { interface_id, data } => {
                assert_eq!(interface_id, InterfaceId(9100));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn backbone_client_send_frame() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, _rx) = crate::event::channel();

        let config = make_client_config(port, 9200);
        let mut writer = start_client(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();
        server_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let payload: Vec<u8> = (0..24).collect();
        writer.send_frame(&payload).unwrap();

        let mut buf = [0u8; 256];
        let n = server_stream.read(&mut buf).unwrap();
        let expected = hdlc::frame(&payload);
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn backbone_max_connections_rejects_excess() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8800));

        let config = make_server_config(
            port,
            88,
            Some(2),
            None,
            None,
            BackboneAbuseConfig::default(),
        );

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect two clients (at limit)
        let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain both InterfaceUp events
        for _ in 0..2 {
            let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
            assert!(matches!(event, Event::InterfaceUp(_, _, _)));
        }

        // Third connection should be accepted at TCP level but immediately dropped
        let client3 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client3
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        // Give server time to reject
        thread::sleep(Duration::from_millis(100));

        // Should NOT receive a third InterfaceUp
        let result = recv_non_peer_event(&rx, Duration::from_millis(500));
        assert!(
            result.is_err(),
            "expected no InterfaceUp for rejected connection, got {:?}",
            result
        );
    }

    #[test]
    fn backbone_max_connections_allows_after_disconnect() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(8900));

        let config = make_server_config(
            port,
            89,
            Some(1),
            None,
            None,
            BackboneAbuseConfig::default(),
        );

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect first client
        let client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(_, _, _)));

        // Disconnect first client
        drop(client1);

        // Wait for InterfaceDown
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(_)));

        // Now a new connection should be accepted
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(
            matches!(event, Event::InterfaceUp(_, _, _)),
            "expected InterfaceUp after slot freed, got {:?}",
            event
        );
    }

    #[test]
    fn backbone_client_reconnect() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        listener.set_nonblocking(false).unwrap();
        let (tx, rx) = crate::event::channel();

        let config = make_client_config(port, 9300);
        let _writer = start_client(config, tx).unwrap();

        // Accept first connection and immediately close it
        let (server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        drop(server_stream);

        // Should get InterfaceDown
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(InterfaceId(9300))));

        // Accept the reconnection
        let _server_stream2 = listener.accept().unwrap();

        // Should get InterfaceUp again
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(9300), _, _)));
    }

    #[test]
    fn backbone_idle_timeout_disconnects_silent_client() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(9400));

        let config = make_server_config(
            port,
            94,
            None,
            Some(Duration::from_millis(150)),
            None,
            BackboneAbuseConfig::default(),
        );

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        let client_id = match event {
            Event::InterfaceUp(id, _, _) => id,
            other => panic!("expected InterfaceUp, got {:?}", other),
        };

        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(id) if id == client_id));
    }

    #[test]
    fn backbone_idle_timeout_ignores_client_after_data() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(9500));

        let config = make_server_config(
            port,
            95,
            None,
            Some(Duration::from_millis(200)),
            None,
            BackboneAbuseConfig::default(),
        );

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        let client_id = match event {
            Event::InterfaceUp(id, _, _) => id,
            other => panic!("expected InterfaceUp, got {:?}", other),
        };

        client.write_all(&hdlc::frame(&[1u8; 24])).unwrap();

        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { interface_id, data } => {
                assert_eq!(interface_id, client_id);
                assert_eq!(data, vec![1u8; 24]);
            }
            other => panic!("expected Frame, got {:?}", other),
        }

        let result = recv_non_peer_event(&rx, Duration::from_millis(500));
        assert!(
            result.is_err(),
            "expected no InterfaceDown after client sent data, got {:?}",
            result
        );
    }

    #[test]
    fn backbone_runtime_idle_timeout_updates_live() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(9650));

        let config = make_server_config(port, 97, None, None, None, BackboneAbuseConfig::default());
        let runtime = Arc::clone(&config.runtime);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        let client_id = match event {
            Event::InterfaceUp(id, _, _) => id,
            other => panic!("expected InterfaceUp, got {:?}", other),
        };

        {
            let mut runtime = runtime.lock().unwrap();
            runtime.idle_timeout = Some(Duration::from_millis(150));
        }

        let event = recv_non_peer_event(&rx, Duration::from_secs(4)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(id) if id == client_id));
    }

    #[test]
    fn backbone_write_stall_timeout_disconnects_unwritable_client() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(9660));

        let config = make_server_config(
            port,
            98,
            None,
            None,
            Some(Duration::from_millis(50)),
            BackboneAbuseConfig::default(),
        );

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let sock = SockRef::from(&client);
        sock.set_recv_buffer_size(4096).ok();

        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        let (client_id, mut writer) = match event {
            Event::InterfaceUp(id, Some(writer), _) => (id, writer),
            other => panic!("expected InterfaceUp with writer, got {:?}", other),
        };

        let payload = vec![0x55; 512 * 1024];
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stalled = false;
        while Instant::now() < deadline {
            match writer.send_frame(&payload) {
                Ok(()) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    stalled = true;
                    break;
                }
                Err(e) => panic!("unexpected send error: {}", e),
            }
        }

        assert!(stalled, "expected writer to time out on persistent stall");
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(id) if id == client_id));
    }

    /// Drain events matching a predicate, return the first match.
    fn wait_for<F>(rx: &mpsc::Receiver<Event>, timeout: Duration, mut pred: F) -> Option<Event>
    where
        F: FnMut(&Event) -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match rx.recv_timeout(remaining) {
                Ok(event) if pred(&event) => return Some(event),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    }

    #[test]
    fn backbone_write_stall_emits_peer_events() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(9700));

        let config = make_server_config(
            port,
            97,
            None,
            None,
            Some(Duration::from_millis(50)), // 50ms stall timeout
            BackboneAbuseConfig::default(),
        );

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect a client that won't read (will cause write stall)
        let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let sock = SockRef::from(&client);
        sock.set_recv_buffer_size(4096).ok();

        // Wait for InterfaceUp and grab writer
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        let mut writer = match event {
            Event::InterfaceUp(_, Some(w), _) => w,
            other => panic!("expected InterfaceUp with writer, got {:?}", other),
        };

        // Flood until stall
        let payload = vec![0x55; 512 * 1024];
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            match writer.send_frame(&payload) {
                Ok(()) | Err(_) => {
                    if Instant::now() + Duration::from_millis(10) > deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }

        // Should see BackbonePeerWriteStall event
        let stall_event = wait_for(&rx, Duration::from_secs(3), |e| {
            matches!(e, Event::BackbonePeerWriteStall { .. })
        });
        assert!(
            stall_event.is_some(),
            "expected BackbonePeerWriteStall event"
        );
    }

    #[test]
    fn backbone_blacklisted_peer_rejected_on_connect() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(9800));

        let config = make_server_config(port, 98, None, None, None, BackboneAbuseConfig::default());
        let peer_state = config.peer_state.clone();

        start(config, tx.clone(), next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // First connection should succeed
        let client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(
            matches!(event, Event::InterfaceUp(_, _, _)),
            "first connection should succeed"
        );
        drop(client1);

        // Drain disconnect events
        thread::sleep(Duration::from_millis(100));
        while rx.try_recv().is_ok() {}

        // Blacklist 127.0.0.1 via the peer monitor
        peer_state.lock().unwrap().blacklist(
            "127.0.0.1".parse().unwrap(),
            Duration::from_secs(60),
            "test blacklist".into(),
        );

        // Second connection from same IP should be rejected (no InterfaceUp)
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        // Give poll loop time to reject
        thread::sleep(Duration::from_millis(200));

        // Should NOT get an InterfaceUp — connection should have been rejected
        let event = rx.try_recv();
        match event {
            Ok(Event::InterfaceUp(_, _, _)) => {
                panic!("blacklisted peer should not get InterfaceUp")
            }
            _ => {} // Expected: no InterfaceUp
        }
    }

    #[test]
    fn backbone_parse_config_reads_abuse_settings() {
        let factory = BackboneInterfaceFactory;
        let mut params = HashMap::new();
        params.insert("listen_ip".into(), "127.0.0.1".into());
        params.insert("listen_port".into(), "4242".into());
        params.insert("idle_timeout".into(), "15".into());
        params.insert("write_stall_timeout".into(), "45".into());
        params.insert("max_penalty_duration".into(), "3600".into());

        let config = factory
            .parse_config("test-backbone", InterfaceId(97), &params)
            .unwrap();
        let mode = *config.into_any().downcast::<BackboneMode>().unwrap();

        match mode {
            BackboneMode::Server(config) => {
                assert_eq!(config.listen_ip, "127.0.0.1");
                assert_eq!(config.listen_port, 4242);
                assert_eq!(config.idle_timeout, Some(Duration::from_secs(15)));
                assert_eq!(config.write_stall_timeout, Some(Duration::from_secs(45)));
                assert_eq!(
                    config.abuse.max_penalty_duration,
                    Some(Duration::from_secs(3600))
                );
            }
            BackboneMode::Client(_) => panic!("expected server config"),
        }
    }
}
