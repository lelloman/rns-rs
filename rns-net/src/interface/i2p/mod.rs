//! I2P interface using the SAM v3.1 protocol.
//!
//! Provides anonymous transport over the I2P network. The interface manages
//! both outbound peer connections and inbound connection acceptance.
//! Each peer connection becomes a dynamic interface with HDLC framing,
//! similar to TCP server client connections.
//!
//! Matches Python `I2PInterface` from `I2PInterface.py`.

mod folded;
pub mod sam;
pub mod tunnel;

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_core::constants;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::{lock_or_recover, Writer};

use self::sam::{Destination, SamError};

/// Hardware MTU for I2P streams (matches Python I2PInterface).
pub(crate) const HW_MTU: usize = 1064;

/// Estimated bitrate for I2P tunnels (256 kbps, matches Python).
pub(crate) const BITRATE_GUESS: u64 = 256_000;

/// Wait time before reconnecting to an outbound peer.
const RECONNECT_WAIT: Duration = Duration::from_secs(15);

/// Configuration for the I2P interface.
#[derive(Debug, Clone)]
pub struct I2pConfig {
    pub name: String,
    pub interface_id: InterfaceId,
    /// SAM bridge host (default "127.0.0.1").
    pub sam_host: String,
    /// SAM bridge port (default 7656).
    pub sam_port: u16,
    /// List of .b32.i2p peer addresses (or full base64 destinations) to connect to.
    pub peers: Vec<String>,
    /// Whether to accept inbound connections.
    pub connectable: bool,
    /// Directory for key persistence (typically `{config_dir}/storage`).
    pub storage_dir: PathBuf,
    pub ingress_control: rns_core::transport::types::IngressControlConfig,
    pub underlay_mark: Option<u32>,
    pub runtime: Arc<Mutex<I2pRuntime>>,
    /// The state of this interface's own endpoint, which interface
    /// statistics report.
    pub endpoint: Arc<Mutex<I2pEndpoint>>,
}

/// The state of an I2P interface's own endpoint, as upstream's
/// `I2PInterface` keeps it: a connectable interface learns its address
/// (`b32`) from its keys and is online once its session accepts
/// connections; one that is not connectable stays offline.
#[derive(Debug, Clone, Default)]
pub struct I2pEndpoint {
    pub online: bool,
    /// `{base32}.b32.i2p`.
    pub b32: Option<String>,
    /// The tunnels of the peers, by their interface: of each connected
    /// peer, and of each outbound peer from when the interface starts.
    pub tunnels: std::collections::HashMap<InterfaceId, Arc<tunnel::PeerTunnel>>,
}

impl I2pEndpoint {
    /// Record the session's own address, which upstream knows only for a
    /// connectable interface.
    fn set_address(endpoint: &Mutex<I2pEndpoint>, connectable: bool, b32: String) {
        if connectable {
            lock_or_recover(endpoint, "i2p endpoint").b32 = Some(b32);
        }
    }

    /// Record that the session accepts connections.
    fn set_accepting(endpoint: &Mutex<I2pEndpoint>) {
        lock_or_recover(endpoint, "i2p endpoint").online = true;
    }

    /// Start watching the tunnel of peer `id`, connected over `stream`. An
    /// outbound peer reconnecting keeps the state its tunnel was in.
    fn add_tunnel(
        endpoint: &Mutex<I2pEndpoint>,
        id: InterfaceId,
        stream: Option<&std::net::TcpStream>,
    ) -> Arc<tunnel::PeerTunnel> {
        let tunnel = Arc::new(tunnel::PeerTunnel::new(
            stream.and_then(|stream| stream.try_clone().ok()),
        ));
        let mut endpoint = lock_or_recover(endpoint, "i2p endpoint");
        if let Some(previous) = endpoint.tunnels.get(&id) {
            tunnel.resume(previous.state());
        }
        endpoint.tunnels.insert(id, Arc::clone(&tunnel));
        tunnel
    }

    /// Stop watching the tunnel of accepted peer `id`, which disconnected.
    /// An outbound peer's tunnel stays, as the peer does while it
    /// reconnects.
    fn remove_tunnel(endpoint: &Mutex<I2pEndpoint>, id: InterfaceId) {
        lock_or_recover(endpoint, "i2p endpoint")
            .tunnels
            .remove(&id);
    }
}

#[derive(Debug, Clone)]
pub struct I2pRuntime {
    pub reconnect_wait: Duration,
}

impl I2pRuntime {
    pub fn from_config(_config: &I2pConfig) -> Self {
        Self {
            reconnect_wait: RECONNECT_WAIT,
        }
    }
}

#[derive(Debug, Clone)]
pub struct I2pRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<I2pRuntime>>,
    pub startup: I2pRuntime,
}

impl Default for I2pConfig {
    fn default() -> Self {
        let mut config = I2pConfig {
            name: String::new(),
            interface_id: InterfaceId(0),
            sam_host: "127.0.0.1".into(),
            sam_port: 7656,
            peers: Vec::new(),
            connectable: false,
            storage_dir: PathBuf::from("."),
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            underlay_mark: None,
            runtime: Arc::new(Mutex::new(I2pRuntime {
                reconnect_wait: RECONNECT_WAIT,
            })),
            endpoint: Arc::default(),
        };
        let startup = I2pRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

/// Writer that sends HDLC-framed data over an I2P SAM stream.
struct I2pWriter {
    stream: std::net::TcpStream,
    /// Set when the driver detaches the peer, so an outbound peer is not
    /// reconnected, as upstream's detached `I2PInterfacePeer` stays down.
    detached: Arc<AtomicBool>,
}

impl I2pWriter {
    fn new(stream: std::net::TcpStream) -> (Self, Arc<AtomicBool>) {
        let detached = Arc::new(AtomicBool::new(false));
        (
            I2pWriter {
                stream,
                detached: Arc::clone(&detached),
            },
            detached,
        )
    }
}

impl Writer for I2pWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }

    fn loop_socket(&self) -> Option<std::os::fd::RawFd> {
        // With interface I/O folded the driver writes the stream itself.
        use std::os::fd::AsRawFd;
        crate::engine::FOLD_IO.then(|| self.stream.as_raw_fd())
    }

    fn shutdown(&mut self) {
        // Only a detach shuts a writer down; the peer stays down after it.
        self.detached.store(true, Ordering::Relaxed);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// The interface a connected peer gets, named after `remote`.
/// Outbound peers synthesize a tunnel on each connect, as upstream's
/// initiating `I2PInterfacePeer` does; accepted peers do not.
fn peer_info(
    client_id: InterfaceId,
    remote: &str,
    ingress_control: rns_core::transport::types::IngressControlConfig,
    outbound: bool,
) -> InterfaceInfo {
    InterfaceInfo {
        stamp_costs: Default::default(),
        id: client_id,
        name: format!("I2PInterface/{}", remote),
        mode: constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate: Some(BITRATE_GUESS),
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: outbound,
        hop_limiter: None,
        tunnel_id: None,
        // Upstream's I2PInterfacePeer HW_MTU, which the HDLC decoder also
        // enforces: a larger one would let links negotiate packets that
        // the receiving peer then drops as oversized frames.
        mtu: HW_MTU as u32,
        mtu_upgradable: false,
        ia_freq: 0.0,
        ia_samples: 0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
        ingress_control,
    }
}

/// A peer's interface, under upstream's peer name `name` (see
/// [`super::display::i2p_peer_name`]).
fn peer_registration(
    template: &super::DynamicInterfaceTemplate,
    info: InterfaceInfo,
    name: String,
) -> crate::event::DynamicInterfaceRegistration {
    let mut registration = template.registration(info);
    registration.display_name = Some(format!("I2PInterfacePeer[{name}]"));
    registration.short_name = Some(name);
    registration
}

/// The event that brings up a connected peer's interface, reported under
/// upstream's peer name `name`. An outbound peer's interface was registered
/// when the interface started (see [`register_outbound_peers`]), and only
/// comes online.
fn peer_up(
    client_id: InterfaceId,
    writer: Box<dyn Writer>,
    info: InterfaceInfo,
    template: Option<&super::DynamicInterfaceTemplate>,
    name: String,
) -> Event {
    match template {
        // Only outbound peers want a tunnel (see `peer_info`). Each connect
        // brings the peer up here, and the driver sends the synthesis as its
        // first frame (upstream ad6c709e writes it while connecting).
        Some(_) if info.wants_tunnel => Event::InterfaceUp(client_id, Some(writer), None),
        Some(template) => Event::DynamicInterfaceUp {
            id: client_id,
            writer,
            registration: Box::new(peer_registration(template, info, name)),
        },
        None => Event::InterfaceUp(client_id, Some(writer), Some(Box::new(info))),
    }
}

/// A configured outbound peer: the address it connects to and its
/// interface, which it keeps across reconnects.
#[derive(Debug, Clone)]
struct OutboundPeer {
    address: String,
    id: InterfaceId,
}

/// Give each configured peer its interface, as upstream adds an
/// `I2PInterfacePeer` for each when the interface starts: listed, offline
/// and creating its tunnel, before it connects, and kept, under the same
/// interface, while it reconnects. Without a template the peers' interfaces
/// are registered as they connect.
fn register_outbound_peers(
    config: &I2pConfig,
    tx: &EventSender,
    next_id: &AtomicU64,
    template: Option<&super::DynamicInterfaceTemplate>,
) -> Vec<OutboundPeer> {
    config
        .peers
        .iter()
        .map(|address| address.trim())
        .filter(|address| !address.is_empty())
        .map(|address| {
            let id = InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));
            I2pEndpoint::add_tunnel(&config.endpoint, id, None);
            if let Some(template) = template {
                let mut registration = peer_registration(
                    template,
                    peer_info(id, address, config.ingress_control, true),
                    crate::interface::display::i2p_peer_name(&config.name, address, true),
                );
                registration.reconnecting = true;
                let _ = tx.send(Event::DynamicInterfaceUp {
                    id,
                    writer: Box::new(crate::interface::UnavailableWriter),
                    registration: Box::new(registration),
                });
            }
            OutboundPeer {
                address: address.to_string(),
                id,
            }
        })
        .collect()
}

/// Sanitize a name for use in filenames and SAM session IDs.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Key file path for the given interface name.
fn key_file_path(storage_dir: &Path, name: &str) -> PathBuf {
    storage_dir.join(format!("i2p_{}.key", sanitize_name(name)))
}

/// Load or generate an I2P keypair. Persists the private key to disk
/// so the node keeps a stable I2P address across restarts.
fn load_or_generate_keypair(
    sam_addr: &SocketAddr,
    storage_dir: &Path,
    name: &str,
    underlay_mark: Option<u32>,
) -> Result<sam::KeyPair, SamError> {
    let key_path = key_file_path(storage_dir, name);

    if key_path.exists() {
        // Load existing private key
        let priv_data = std::fs::read(&key_path).map_err(SamError::Io)?;

        // We need the public destination too. Create a temporary session to extract it,
        // or we can derive it by creating a session and reading back the destination.
        // Simpler: store the full keypair. Let's re-generate from the private key
        // by creating a session (the destination is embedded in the private key).
        // Actually, the I2P private key blob contains the destination as a prefix.
        // We can extract the destination from the private key.
        // The destination is the first portion of the private key blob.
        // For simplicity, store the full PRIV blob (which includes the destination).

        // The PRIV blob from DEST GENERATE contains both the destination and private keys.
        // The destination is extractable as the first ~387 bytes, but the exact size
        // depends on the key type. For Ed25519 (sig type 7), the destination is:
        //   256 bytes (encryption public key) + 128 bytes (signing public key) + 3 bytes (certificate)
        // = 387 bytes. But this can vary with certificate content.

        // Rather than parsing, we pass the full PRIV to SESSION CREATE (which accepts it)
        // and then do a NAMING LOOKUP on "ME" to get our destination.

        Ok(sam::KeyPair {
            destination: Destination { data: Vec::new() }, // filled in later
            private_key: priv_data,
        })
    } else {
        // Generate new keypair
        log::info!("[{}] generating new I2P destination keypair", name);
        let keypair = sam::dest_generate_with_mark(sam_addr, underlay_mark)?;

        // Save private key to disk
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).map_err(SamError::Io)?;
        }
        std::fs::write(&key_path, &keypair.private_key).map_err(SamError::Io)?;
        log::info!("[{}] saved I2P key to {:?}", name, key_path);

        Ok(keypair)
    }
}

/// How long upstream waits before setting a tunnel up again after the SAM
/// bridge failed (or could not be reached): an outbound peer's tunnel job
/// retries after 8 seconds.
const PEER_TUNNEL_RETRY_WAIT: Duration = Duration::from_secs(8);

/// How long upstream waits before setting the interface's own server
/// tunnel up again after the SAM bridge failed.
const SERVER_TUNNEL_RETRY_WAIT: Duration = Duration::from_secs(15);

impl I2pConfig {
    /// How long to wait before trying the SAM bridge again. One session
    /// serves every stream here, so it is retried as often as the first of
    /// upstream's tunnel jobs that needs it would retry: the outbound
    /// peers', if there are any.
    fn sam_retry_wait(&self) -> Duration {
        if self.peers.iter().any(|peer| !peer.trim().is_empty()) {
            PEER_TUNNEL_RETRY_WAIT
        } else {
            SERVER_TUNNEL_RETRY_WAIT
        }
    }
}

/// Open the interface's SAM session: load (or generate) its keys, create
/// the session, which lasts as long as the returned control socket stays
/// open, and learn its own address. Returns the control socket and the
/// session id.
fn open_session(
    config: &I2pConfig,
    sam_addr: &SocketAddr,
) -> Result<(std::net::TcpStream, String), SamError> {
    let keypair = load_or_generate_keypair(
        sam_addr,
        &config.storage_dir,
        &config.name,
        config.underlay_mark,
    )?;
    let priv_b64 = sam::i2p_base64_encode(&keypair.private_key);

    // We use a single session for all streams (outbound + inbound).
    // Session ID must be unique; use the interface name sanitized.
    let session_id = sanitize_name(&config.name);

    log::info!("[{}] creating SAM session (id={})", config.name, session_id);
    let mut control_socket =
        sam::session_create_with_mark(sam_addr, &session_id, &priv_b64, config.underlay_mark)?;

    // Look up our own destination via NAMING LOOKUP "ME" on the session control socket.
    // "ME" requires a session context on the same connection.
    match sam::naming_lookup_on(&mut control_socket, "ME") {
        Ok(our_dest) => {
            let b32 = our_dest.base32_address();
            log::info!("[{}] I2P address: {}", config.name, b32);
            I2pEndpoint::set_address(&config.endpoint, config.connectable, b32);
        }
        Err(e) => {
            log::warn!("[{}] could not look up own destination: {}", config.name, e);
        }
    }
    Ok((control_socket, session_id))
}

/// [`open_session`], tried again every `wait` until it succeeds: upstream
/// keeps retrying its tunnels while the SAM bridge is unavailable, so the
/// interface comes up once the bridge does.
fn open_session_retrying(
    config: &I2pConfig,
    sam_addr: &SocketAddr,
    wait: Duration,
) -> (std::net::TcpStream, String) {
    loop {
        match open_session(config, sam_addr) {
            Ok(session) => return session,
            Err(e) => {
                log::error!(
                    "Error while while configuring I2PInterface[{}]: {}",
                    config.name,
                    e
                );
                log::error!(
                    "Check that I2P is installed and running, and that SAM is enabled. Retrying tunnel setup later."
                );
                thread::sleep(wait);
            }
        }
    }
}

/// Start the I2P interface coordinator. All peer connections are registered
/// as dynamic interfaces via InterfaceUp events.
pub fn start(config: I2pConfig, tx: EventSender, next_id: Arc<AtomicU64>) -> io::Result<()> {
    start_with_template(config, tx, next_id, None)
}

fn start_with_template(
    config: I2pConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    dynamic_template: Option<super::DynamicInterfaceTemplate>,
) -> io::Result<()> {
    let name = config.name.clone();
    let peers = register_outbound_peers(&config, &tx, &next_id, dynamic_template.as_ref());

    if crate::engine::FOLD_IO {
        thread::Builder::new()
            .name(format!("i2p-setup-{}", config.interface_id.0))
            .spawn(move || {
                if let Err(e) = folded::setup(config, peers, tx, next_id, dynamic_template) {
                    log::error!("[{}] I2P setup failed: {}", name, e);
                }
            })?;
        return Ok(());
    }

    thread::Builder::new()
        .name(format!("i2p-coord-{}", config.interface_id.0))
        .spawn(move || {
            if let Err(e) = coordinator(config, peers, tx, next_id, dynamic_template) {
                log::error!("[{}] I2P coordinator failed: {}", name, e);
            }
        })?;

    Ok(())
}

/// Coordinator thread: sets up SAM sessions and spawns peer threads.
fn coordinator(
    config: I2pConfig,
    peers: Vec<OutboundPeer>,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    dynamic_template: Option<super::DynamicInterfaceTemplate>,
) -> Result<(), SamError> {
    let ingress_control = config.ingress_control;
    let sam_addr: SocketAddr = format!("{}:{}", config.sam_host, config.sam_port)
        .parse()
        .map_err(|e| SamError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;

    let (control_socket, session_id) =
        open_session_retrying(&config, &sam_addr, config.sam_retry_wait());

    // Spawn outbound peer threads
    for peer in peers {
        let tx2 = tx.clone();
        let sam_addr2 = sam_addr;
        let session_id2 = session_id.clone();
        let iface_name = config.name.clone();
        let runtime = Arc::clone(&config.runtime);
        let dynamic_template = dynamic_template.clone();
        let endpoint = Arc::clone(&config.endpoint);

        thread::Builder::new()
            .name(format!("i2p-out-{}", peer.address))
            .spawn(move || {
                outbound_peer_loop(OutboundPeerContext {
                    sam_addr: sam_addr2,
                    session_id: session_id2,
                    peer,
                    iface_name,
                    tx2,
                    runtime,
                    ingress_control,
                    dynamic_template,
                    underlay_mark: config.underlay_mark,
                    endpoint,
                });
            })
            .ok();
    }

    // Spawn acceptor thread if connectable
    if config.connectable {
        I2pEndpoint::set_accepting(&config.endpoint);
        let tx2 = tx.clone();
        let next_id2 = next_id.clone();
        let sam_addr2 = sam_addr;
        let session_id2 = session_id.clone();
        let iface_name = config.name.clone();
        let dynamic_template = dynamic_template.clone();
        let endpoint = Arc::clone(&config.endpoint);

        thread::Builder::new()
            .name("i2p-acceptor".into())
            .spawn(move || {
                acceptor_loop(AcceptorContext {
                    sam_addr: sam_addr2,
                    session_id: session_id2,
                    iface_name,
                    tx: tx2,
                    next_id: next_id2,
                    ingress_control,
                    dynamic_template,
                    underlay_mark: config.underlay_mark,
                    endpoint,
                });
            })
            .ok();
    }

    // The session lasts as long as its control socket stays open: serve it
    // here, and open the session again whenever the bridge closes it. The
    // peers and the acceptor retry meanwhile, under the same session id.
    let mut control_socket = control_socket;
    loop {
        watch_session(&mut control_socket, &config.name);
        control_socket = reopen_session(&config, &sam_addr, config.sam_retry_wait());
    }
}

/// What to answer a line the bridge sent on the session's control socket:
/// a `PING` keeps the session alive with its `PONG`.
fn control_reply(line: &str) -> Option<String> {
    line.strip_prefix("PING")
        .map(|rest| format!("PONG{}\n", rest))
}

/// Serve the session's control socket until the bridge closes it.
fn watch_session(control: &mut std::net::TcpStream, name: &str) {
    let _ = control.set_read_timeout(None);
    let mut line = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match control.read(&mut buf) {
            Ok(0) => {
                log::warn!("[{}] the SAM bridge closed the I2P session", name);
                return;
            }
            Ok(n) => {
                for &byte in &buf[..n] {
                    if byte != b'\n' {
                        if line.len() < 4096 {
                            line.push(byte);
                        }
                        continue;
                    }
                    let text = String::from_utf8_lossy(&line).into_owned();
                    line.clear();
                    if let Some(reply) = control_reply(&text) {
                        let _ = control.write_all(reply.as_bytes());
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                log::warn!("[{}] I2P session socket failed: {}", name, e);
                return;
            }
        }
    }
}

/// Open the session again after the bridge closed it: the interface is
/// offline meanwhile, as upstream's is while its tunnels are set up again,
/// and the first attempt waits `wait`, as upstream's tunnel jobs wait
/// before they retry. Returns the new control socket.
fn reopen_session(
    config: &I2pConfig,
    sam_addr: &SocketAddr,
    wait: Duration,
) -> std::net::TcpStream {
    lock_or_recover(&config.endpoint, "i2p endpoint").online = false;
    log::warn!(
        "[{}] reopening the I2P session in {}s",
        config.name,
        wait.as_secs_f64()
    );
    thread::sleep(wait);
    let (control, _) = open_session_retrying(config, sam_addr, wait);
    if config.connectable {
        I2pEndpoint::set_accepting(&config.endpoint);
    }
    control
}

/// Outbound peer thread: connects to a remote I2P destination, runs HDLC reader loop.
/// Reconnects on failure.
struct OutboundPeerContext {
    sam_addr: SocketAddr,
    session_id: String,
    peer: OutboundPeer,
    iface_name: String,
    tx2: EventSender,
    runtime: Arc<Mutex<I2pRuntime>>,
    ingress_control: rns_core::transport::types::IngressControlConfig,
    dynamic_template: Option<super::DynamicInterfaceTemplate>,
    underlay_mark: Option<u32>,
    endpoint: Arc<Mutex<I2pEndpoint>>,
}

fn outbound_peer_loop(context: OutboundPeerContext) {
    let OutboundPeerContext {
        sam_addr,
        session_id,
        peer: OutboundPeer {
            address: peer_addr,
            id: client_id,
        },
        iface_name,
        tx2: tx,
        runtime,
        ingress_control,
        dynamic_template,
        underlay_mark,
        endpoint,
    } = context;
    loop {
        log::info!("[{}] connecting to I2P peer {}", iface_name, peer_addr);

        // Resolve .b32.i2p address if needed
        let destination = if peer_addr.ends_with(".i2p") {
            match sam::naming_lookup_with_mark(&sam_addr, &peer_addr, underlay_mark) {
                Ok(dest) => dest.to_i2p_base64(),
                Err(e) => {
                    log::warn!("[{}] failed to resolve {}: {}", iface_name, peer_addr, e);
                    thread::sleep(lock_or_recover(&runtime, "i2p runtime").reconnect_wait);
                    continue;
                }
            }
        } else {
            // Assume it's already a full base64 destination
            peer_addr.to_string()
        };

        // Connect via SAM
        match sam::stream_connect_with_mark(&sam_addr, &session_id, &destination, underlay_mark) {
            Ok(stream) => {
                log::info!(
                    "[{}] connected to I2P peer {} → id {}",
                    iface_name,
                    peer_addr,
                    client_id.0
                );

                // Clone stream for writer/reader split
                let writer_stream = match stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("[{}] failed to clone stream: {}", iface_name, e);
                        thread::sleep(lock_or_recover(&runtime, "i2p runtime").reconnect_wait);
                        continue;
                    }
                };

                let (writer, detached) = I2pWriter::new(writer_stream);
                let writer: Box<dyn Writer> = Box::new(writer);

                let tunnel = I2pEndpoint::add_tunnel(&endpoint, client_id, Some(&stream));
                let event = peer_up(
                    client_id,
                    writer,
                    peer_info(client_id, &peer_addr, ingress_control, true),
                    dynamic_template.as_ref(),
                    crate::interface::display::i2p_peer_name(&iface_name, &peer_addr, true),
                );
                if tx.send(event).is_err() {
                    return; // Driver shut down
                }

                // Run HDLC reader loop (blocks until disconnect)
                peer_reader_loop(
                    stream,
                    client_id,
                    &iface_name,
                    &tx,
                    template_ifac_size(dynamic_template.as_ref()),
                    &tunnel,
                );

                // Disconnected
                let _ = tx.send(Event::InterfaceDown(client_id));
                if detached.load(Ordering::Relaxed) {
                    log::info!(
                        "[{}] I2P peer {} was detached, not reconnecting",
                        iface_name,
                        peer_addr
                    );
                    I2pEndpoint::remove_tunnel(&endpoint, client_id);
                    return;
                }
                log::warn!(
                    "[{}] I2P peer {} disconnected, reconnecting in {}s",
                    iface_name,
                    peer_addr,
                    lock_or_recover(&runtime, "i2p runtime")
                        .reconnect_wait
                        .as_secs()
                );
            }
            Err(e) => {
                log::warn!(
                    "[{}] failed to connect to I2P peer {}: {}",
                    iface_name,
                    peer_addr,
                    e
                );
            }
        }

        thread::sleep(lock_or_recover(&runtime, "i2p runtime").reconnect_wait);
    }
}

/// Acceptor thread: loops accepting inbound connections on the session.
struct AcceptorContext {
    sam_addr: SocketAddr,
    session_id: String,
    iface_name: String,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    ingress_control: rns_core::transport::types::IngressControlConfig,
    dynamic_template: Option<super::DynamicInterfaceTemplate>,
    underlay_mark: Option<u32>,
    endpoint: Arc<Mutex<I2pEndpoint>>,
}

fn acceptor_loop(context: AcceptorContext) {
    let AcceptorContext {
        sam_addr,
        session_id,
        iface_name,
        tx,
        next_id,
        ingress_control,
        dynamic_template,
        underlay_mark,
        endpoint,
    } = context;

    loop {
        match sam::stream_accept_with_mark(&sam_addr, &session_id, underlay_mark) {
            Ok((stream, remote_dest)) => {
                let client_id = InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));
                let remote_b32 = remote_dest.base32_address();

                log::info!(
                    "[{}] accepted I2P connection from {} → id {}",
                    iface_name,
                    remote_b32,
                    client_id.0
                );

                // Clone stream for writer/reader split
                let writer_stream = match stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("[{}] failed to clone accepted stream: {}", iface_name, e);
                        continue;
                    }
                };

                let writer: Box<dyn Writer> = Box::new(I2pWriter::new(writer_stream).0);

                let tunnel = I2pEndpoint::add_tunnel(&endpoint, client_id, Some(&stream));
                let event = peer_up(
                    client_id,
                    writer,
                    peer_info(client_id, &remote_b32, ingress_control, false),
                    dynamic_template.as_ref(),
                    crate::interface::display::i2p_peer_name(&iface_name, &remote_b32, false),
                );
                if tx.send(event).is_err() {
                    return; // Driver shut down
                }

                // Spawn per-client reader thread (accepted peers don't reconnect)
                let client_tx = tx.clone();
                let client_name = iface_name.to_string();
                let ifac_size = template_ifac_size(dynamic_template.as_ref());
                let client_endpoint = Arc::clone(&endpoint);
                thread::Builder::new()
                    .name(format!("i2p-client-{}", client_id.0))
                    .spawn(move || {
                        peer_reader_loop(
                            stream,
                            client_id,
                            &client_name,
                            &client_tx,
                            ifac_size,
                            &tunnel,
                        );
                        I2pEndpoint::remove_tunnel(&client_endpoint, client_id);
                        let _ = client_tx.send(Event::InterfaceDown(client_id));
                    })
                    .ok();
            }
            Err(e) => {
                log::warn!("[{}] I2P accept failed: {}, retrying", iface_name, e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// IFAC bytes a spawned peer connection may carry on the wire.
fn template_ifac_size(template: Option<&super::DynamicInterfaceTemplate>) -> usize {
    template
        .and_then(|template| template.ifac.as_ref())
        .map_or(0, |ifac| ifac.size)
}

/// HDLC decoder bounded by the I2P hardware MTU plus on-wire IFAC bytes.
fn frame_decoder(ifac_size: usize) -> hdlc::Decoder {
    hdlc::Decoder::reticulum(HW_MTU, ifac_size)
}

/// Per-peer HDLC reader loop. Reads from the SAM data stream, decodes HDLC
/// frames, and sends them to the driver. Returns when the stream is closed.
fn peer_reader_loop(
    mut stream: std::net::TcpStream,
    id: InterfaceId,
    name: &str,
    tx: &EventSender,
    ifac_size: usize,
    tunnel: &tunnel::PeerTunnel,
) {
    let mut decoder = frame_decoder(ifac_size);
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log::info!("[{}] I2P peer {} disconnected", name, id.0);
                return;
            }
            Ok(n) => {
                tunnel.note_read();
                for frame in decoder.feed(&buf[..n]) {
                    if tx
                        .send(Event::Frame {
                            interface_id: id,
                            data: frame.into(),
                            rssi: None,
                            snr: None,
                        })
                        .is_err()
                    {
                        return; // Driver shut down
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] I2P peer {} read error: {}", name, id.0, e);
                return;
            }
        }
    }
}

// --- Factory implementation ---

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};
use std::collections::HashMap;

/// Factory for `I2PInterface`.
pub struct I2pFactory;

impl InterfaceFactory for I2pFactory {
    fn type_name(&self) -> &str {
        "I2PInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let sam_host = params
            .get("sam_host")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".into());

        let sam_port = params
            .get("sam_port")
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(7656);

        let connectable = params
            .get("connectable")
            .and_then(|v| crate::config::parse_bool_pub(v))
            .unwrap_or(false);

        let peers = params
            .get("peers")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        let storage_dir = params
            .get("storage_dir")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/rns-i2p"));

        Ok(Box::new(I2pConfig {
            name: name.to_string(),
            interface_id: id,
            sam_host,
            sam_port,
            connectable,
            peers,
            storage_dir,
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            underlay_mark: None,
            runtime: Arc::new(Mutex::new(I2pRuntime {
                reconnect_wait: RECONNECT_WAIT,
            })),
            endpoint: Arc::default(),
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let mut cfg = *config
            .into_any()
            .downcast::<I2pConfig>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong config type"))?;
        cfg.ingress_control = ctx.ingress_control;
        cfg.underlay_mark = ctx.underlay_mark;
        let parent_id = cfg.interface_id;
        start_with_template(
            cfg,
            ctx.tx,
            ctx.next_dynamic_id,
            Some(super::DynamicInterfaceTemplate {
                parent_id,
                interface_type: "I2PInterfacePeer".into(),
                ifac: ctx.ifac,
                mode: ctx.mode,
                gravity: ctx.gravity,
                hop_limiter: ctx.hop_limiter,
                recursive_prs: ctx.recursive_prs,
                announces_from_internal: ctx.announces_from_internal,
                announces_to_internal: ctx.announces_to_internal,
                stamp_costs: ctx.stamp_costs,
                announce_limits: ctx.announce_limits,
            }),
        )?;
        Ok(StartResult::Listener { control: None })
    }
}

pub(crate) fn i2p_runtime_handle_from_config(config: &I2pConfig) -> I2pRuntimeConfigHandle {
    I2pRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: I2pRuntime::from_config(config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_decoder_accepts_frames_up_to_hw_mtu_plus_ifac() {
        let ifac_size = 16;
        let mut decoder = frame_decoder(ifac_size);
        let payload = vec![0x5a; HW_MTU + ifac_size];
        let decoded = decoder.feed_with_diagnostics(&hdlc::frame(&payload));
        assert_eq!(decoded.frames, vec![payload]);
        assert!(decoded.invalid_frame_lengths.is_empty());
    }

    #[test]
    fn frame_decoder_drops_frame_above_hw_mtu_as_invalid() {
        let mut decoder = frame_decoder(0);
        let decoded = decoder.feed_with_diagnostics(&hdlc::frame(&vec![0x5a; HW_MTU + 1]));
        assert!(decoded.frames.is_empty());
        assert_eq!(decoded.invalid_frame_lengths, vec![HW_MTU + 1]);
    }

    #[test]
    fn only_outbound_i2p_peers_want_a_tunnel() {
        // Upstream's initiating I2PInterfacePeer synthesizes a tunnel.
        let ic = rns_core::transport::types::IngressControlConfig::enabled();
        assert!(peer_info(InterfaceId(1), "peer.b32.i2p", ic, true).wants_tunnel);
        assert_eq!(
            peer_info(InterfaceId(1), "peer.b32.i2p", ic, true).mtu,
            1064,
            "upstream I2PInterfacePeer.HW_MTU, and what the decoder accepts"
        );
        assert!(!peer_info(InterfaceId(2), "peer.b32.i2p", ic, false).wants_tunnel);
    }

    #[test]
    fn sam_bridge_is_retried_as_often_as_upstream_retries_tunnels() {
        let mut config = I2pConfig::default();
        assert_eq!(config.sam_retry_wait(), Duration::from_secs(15));
        config.peers = vec!["a.b32.i2p".into()];
        assert_eq!(config.sam_retry_wait(), Duration::from_secs(8));
    }

    fn read_command(stream: &mut std::net::TcpStream) -> String {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            line.push(byte[0]);
        }
        String::from_utf8(line).unwrap()
    }

    #[test]
    fn session_is_opened_once_the_sam_bridge_appears() {
        // Upstream keeps retrying its tunnels while the bridge is down.
        let port = free_port();
        // Existing keys: the session is all the bridge is asked for.
        let config = config_with_keys("I2P test", port);
        let storage_dir = config.storage_dir.clone();
        let sam_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (opened_tx, opened) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let session = open_session_retrying(&config, &sam_addr, Duration::from_millis(100));
            let _ = opened_tx.send(session);
        });

        // The bridge cannot be reached: the setup keeps waiting.
        assert!(opened.recv_timeout(Duration::from_millis(500)).is_err());

        let bridge = std::net::TcpListener::bind(sam_addr).unwrap();
        let _session = answer_session(&bridge, "I2P_test");
        let (_control, session_id) = opened.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(session_id, "I2P_test");
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    /// Answer, as a SAM bridge, the opening of session `id` on `bridge`,
    /// returning the session's control socket.
    pub(super) fn answer_session(bridge: &std::net::TcpListener, id: &str) -> std::net::TcpStream {
        let (mut stream, _) = bridge.accept().unwrap();
        assert!(read_command(&mut stream).starts_with("HELLO VERSION"));
        stream
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
            .unwrap();
        assert!(
            read_command(&mut stream).starts_with(&format!("SESSION CREATE STYLE=STREAM ID={id} "))
        );
        stream.write_all(b"SESSION STATUS RESULT=OK\n").unwrap();
        assert!(read_command(&mut stream).starts_with("NAMING LOOKUP NAME=ME"));
        stream
            .write_all(b"NAMING REPLY RESULT=KEY_NOT_FOUND NAME=ME\n")
            .unwrap();
        stream
    }

    /// An interface whose keys exist, so opening its session only asks the
    /// bridge at `port` for the session. Returns it with its storage.
    pub(super) fn config_with_keys(name: &str, port: u16) -> I2pConfig {
        let storage_dir =
            std::env::temp_dir().join(format!("rns-i2p-{}-{}", std::process::id(), port));
        std::fs::create_dir_all(&storage_dir).unwrap();
        std::fs::write(key_file_path(&storage_dir, name), [7u8; 64]).unwrap();
        I2pConfig {
            name: name.into(),
            sam_port: port,
            storage_dir,
            connectable: true,
            ..I2pConfig::default()
        }
    }

    pub(super) fn free_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    }

    #[test]
    fn session_closed_by_the_bridge_is_opened_again() {
        let port = free_port();
        let config = config_with_keys("I2P lost", port);
        let sam_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let bridge = std::net::TcpListener::bind(sam_addr).unwrap();
        let (watched_tx, watched) = std::sync::mpsc::channel();
        let (reopened_tx, reopened) = std::sync::mpsc::channel();
        {
            let config = config.clone();
            thread::spawn(move || {
                let (mut control, _) =
                    open_session_retrying(&config, &sam_addr, Duration::from_millis(100));
                I2pEndpoint::set_accepting(&config.endpoint);
                watch_session(&mut control, &config.name);
                let _ = watched_tx.send(());
                let _control = reopen_session(&config, &sam_addr, Duration::from_millis(200));
                let _ = reopened_tx.send(());
            });
        }
        let mut control = answer_session(&bridge, "I2P_lost");
        // The session is kept alive while the bridge checks on it.
        control.write_all(b"PING 42\n").unwrap();
        assert_eq!(read_command(&mut control), "PONG 42");
        assert!(watched.recv_timeout(Duration::from_millis(200)).is_err());

        // The bridge goes away: the interface is offline until it is back.
        drop(control);
        drop(bridge);
        watched.recv_timeout(Duration::from_secs(2)).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert!(!lock_or_recover(&config.endpoint, "test").online);
        assert!(reopened.recv_timeout(Duration::from_millis(500)).is_err());
        let bridge = std::net::TcpListener::bind(sam_addr).unwrap();
        let _control = answer_session(&bridge, "I2P_lost");
        reopened.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(lock_or_recover(&config.endpoint, "test").online);
        let _ = std::fs::remove_dir_all(&config.storage_dir);
    }

    /// Answer an outbound peer's STREAM CONNECT on the fake bridge and
    /// return its data stream.
    fn answer_stream_connect(bridge: &std::net::TcpListener) -> std::net::TcpStream {
        let (mut stream, _) = bridge.accept().unwrap();
        assert!(read_command(&mut stream).starts_with("HELLO VERSION"));
        stream
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
            .unwrap();
        assert!(read_command(&mut stream).starts_with("STREAM CONNECT ID=I2P_peer "));
        stream.write_all(b"STREAM STATUS RESULT=OK\n").unwrap();
        stream
    }

    #[test]
    fn a_detached_outbound_peer_is_not_reconnected() {
        // Upstream's detached I2PInterfacePeer stays down; a peer whose
        // connection drops reconnects.
        let bridge = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let sam_addr = bridge.local_addr().unwrap();
        let config = I2pConfig::default();
        lock_or_recover(&config.runtime, "test").reconnect_wait = Duration::from_millis(50);
        let (tx, rx) = crate::event::channel();
        let (done_tx, done) = std::sync::mpsc::channel();
        {
            let context = OutboundPeerContext {
                sam_addr,
                session_id: "I2P_peer".into(),
                peer: OutboundPeer {
                    address: "peer-destination".into(),
                    id: InterfaceId(7),
                },
                iface_name: "I2P".into(),
                tx2: tx,
                runtime: Arc::clone(&config.runtime),
                ingress_control: config.ingress_control,
                dynamic_template: None,
                underlay_mark: None,
                endpoint: Arc::clone(&config.endpoint),
            };
            thread::spawn(move || {
                outbound_peer_loop(context);
                let _ = done_tx.send(());
            });
        }
        let writer_of = |rx: &crate::event::EventReceiver| loop {
            match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
                Event::InterfaceUp(InterfaceId(7), Some(writer), _) => return writer,
                Event::DynamicInterfaceUp { writer, .. } => return writer,
                _ => {}
            }
        };

        // The bridge drops the connection: the peer reconnects.
        let first = answer_stream_connect(&bridge);
        let _writer = writer_of(&rx);
        drop(first);
        let _second = answer_stream_connect(&bridge);
        let mut writer = writer_of(&rx);

        // The driver detaches it: the loop ends instead of reconnecting.
        writer.shutdown();
        done.recv_timeout(Duration::from_secs(2))
            .expect("the detached peer's loop should end");
        bridge.set_nonblocking(true).unwrap();
        thread::sleep(Duration::from_millis(200));
        assert!(bridge.accept().is_err(), "a detached peer reconnected");
        assert!(!lock_or_recover(&config.endpoint, "test")
            .tunnels
            .contains_key(&InterfaceId(7)));
    }

    fn template() -> crate::interface::DynamicInterfaceTemplate {
        crate::interface::DynamicInterfaceTemplate {
            parent_id: InterfaceId(5),
            interface_type: "I2PInterfacePeer".into(),
            ifac: None,
            mode: constants::MODE_FULL,
            gravity: 0,
            hop_limiter: None,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            stamp_costs: Default::default(),
            announce_limits: Default::default(),
        }
    }

    #[test]
    fn configured_peers_are_registered_offline_when_the_interface_starts() {
        // Upstream adds each configured peer's I2PInterfacePeer at start,
        // creating its tunnel, and keeps it across reconnects.
        let config = I2pConfig {
            name: "I2P".into(),
            peers: vec!["a.b32.i2p".into(), " ".into(), " b.b32.i2p ".into()],
            ..I2pConfig::default()
        };
        let (tx, rx) = crate::event::channel();
        let next_id = AtomicU64::new(40);
        let peers = register_outbound_peers(&config, &tx, &next_id, Some(&template()));
        let registered: Vec<_> = peers
            .iter()
            .map(|peer| (peer.address.as_str(), peer.id))
            .collect();
        assert_eq!(
            registered,
            vec![
                ("a.b32.i2p", InterfaceId(40)),
                ("b.b32.i2p", InterfaceId(41))
            ]
        );
        for (address, id) in registered {
            match rx.recv_timeout(Duration::from_secs(1)).unwrap() {
                Event::DynamicInterfaceUp {
                    id: up,
                    mut writer,
                    registration,
                } => {
                    assert_eq!(up, id);
                    assert!(registration.reconnecting);
                    assert!(registration.info.wants_tunnel);
                    assert_eq!(registration.parent_id, InterfaceId(5));
                    assert_eq!(registration.interface_type, "I2PInterfacePeer");
                    assert_eq!(
                        registration.short_name.as_deref(),
                        Some(format!("I2P to {address}").as_str())
                    );
                    assert_eq!(
                        writer.send_frame(b"x").unwrap_err().kind(),
                        io::ErrorKind::NotConnected
                    );
                }
                other => panic!("expected the peer's registration, got {other:?}"),
            }
            assert_eq!(
                lock_or_recover(&config.endpoint, "test").tunnels[&id].state(),
                tunnel::TunnelState::Init
            );
        }

        // Once connected, the registered peer only comes online.
        let stream_pair = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(stream_pair.local_addr().unwrap()).unwrap();
        let up = peer_up(
            InterfaceId(40),
            Box::new(I2pWriter::new(stream).0),
            peer_info(InterfaceId(40), "a.b32.i2p", config.ingress_control, true),
            Some(&template()),
            "I2P to a.b32.i2p".into(),
        );
        assert!(matches!(
            up,
            Event::InterfaceUp(InterfaceId(40), Some(_), None)
        ));
    }
}
