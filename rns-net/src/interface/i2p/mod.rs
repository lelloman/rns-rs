//! I2P interface using the SAM v3.1 protocol.
//!
//! Provides anonymous transport over the I2P network. The interface manages
//! both outbound peer connections and inbound connection acceptance.
//! Each peer connection becomes a dynamic interface with HDLC framing,
//! similar to TCP server client connections.
//!
//! Matches Python `I2PInterface` from `I2PInterface.py`.

pub mod sam;

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rns_core::constants;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::Writer;

use self::sam::{Destination, SamError};

/// Hardware MTU for I2P streams (matches Python I2PInterface).
#[allow(dead_code)]
const HW_MTU: usize = 1064;

/// Estimated bitrate for I2P tunnels (256 kbps, matches Python).
const BITRATE_GUESS: u64 = 256_000;

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
}

impl Default for I2pConfig {
    fn default() -> Self {
        I2pConfig {
            name: String::new(),
            interface_id: InterfaceId(0),
            sam_host: "127.0.0.1".into(),
            sam_port: 7656,
            peers: Vec::new(),
            connectable: false,
            storage_dir: PathBuf::from("."),
        }
    }
}

/// Writer that sends HDLC-framed data over an I2P SAM stream.
struct I2pWriter {
    stream: std::net::TcpStream,
}

impl Writer for I2pWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }
}

/// Sanitize a name for use in filenames and SAM session IDs.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// Key file path for the given interface name.
fn key_file_path(storage_dir: &PathBuf, name: &str) -> PathBuf {
    storage_dir.join(format!("i2p_{}.key", sanitize_name(name)))
}

/// Load or generate an I2P keypair. Persists the private key to disk
/// so the node keeps a stable I2P address across restarts.
fn load_or_generate_keypair(
    sam_addr: &SocketAddr,
    storage_dir: &PathBuf,
    name: &str,
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
        let keypair = sam::dest_generate(sam_addr)?;

        // Save private key to disk
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).map_err(SamError::Io)?;
        }
        std::fs::write(&key_path, &keypair.private_key).map_err(SamError::Io)?;
        log::info!("[{}] saved I2P key to {:?}", name, key_path);

        Ok(keypair)
    }
}

/// Start the I2P interface coordinator. All peer connections are registered
/// as dynamic interfaces via InterfaceUp events.
pub fn start(
    config: I2pConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
) -> io::Result<()> {
    let name = config.name.clone();

    thread::Builder::new()
        .name(format!("i2p-coord-{}", config.interface_id.0))
        .spawn(move || {
            if let Err(e) = coordinator(config, tx, next_id) {
                log::error!("[{}] I2P coordinator failed: {}", name, e);
            }
        })?;

    Ok(())
}

/// Coordinator thread: sets up SAM sessions and spawns peer threads.
fn coordinator(
    config: I2pConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
) -> Result<(), SamError> {
    let sam_addr: SocketAddr = format!("{}:{}", config.sam_host, config.sam_port)
        .parse()
        .map_err(|e| SamError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;

    // Load or generate keypair
    let keypair = load_or_generate_keypair(&sam_addr, &config.storage_dir, &config.name)?;
    let priv_b64 = sam::i2p_base64_encode(&keypair.private_key);

    // We use a single session for all streams (outbound + inbound).
    // Session ID must be unique; use the interface name sanitized.
    let session_id = sanitize_name(&config.name);

    log::info!("[{}] creating SAM session (id={})", config.name, session_id);
    let mut control_socket = sam::session_create(&sam_addr, &session_id, &priv_b64)?;

    // Look up our own destination via NAMING LOOKUP "ME" on the session control socket.
    // "ME" requires a session context on the same connection.
    match sam::naming_lookup_on(&mut control_socket, "ME") {
        Ok(our_dest) => {
            let b32 = our_dest.base32_address();
            log::info!("[{}] I2P address: {}", config.name, b32);
        }
        Err(e) => {
            log::warn!("[{}] could not look up own destination: {}", config.name, e);
        }
    }

    // Spawn outbound peer threads
    for peer_addr in &config.peers {
        let peer_addr = peer_addr.trim().to_string();
        if peer_addr.is_empty() {
            continue;
        }

        let tx2 = tx.clone();
        let next_id2 = next_id.clone();
        let sam_addr2 = sam_addr;
        let session_id2 = session_id.clone();
        let iface_name = config.name.clone();

        thread::Builder::new()
            .name(format!("i2p-out-{}", peer_addr))
            .spawn(move || {
                outbound_peer_loop(
                    sam_addr2,
                    &session_id2,
                    &peer_addr,
                    &iface_name,
                    tx2,
                    next_id2,
                );
            })
            .ok();
    }

    // Spawn acceptor thread if connectable
    if config.connectable {
        let tx2 = tx.clone();
        let next_id2 = next_id.clone();
        let sam_addr2 = sam_addr;
        let session_id2 = session_id.clone();
        let iface_name = config.name.clone();

        thread::Builder::new()
            .name("i2p-acceptor".into())
            .spawn(move || {
                acceptor_loop(sam_addr2, &session_id2, &iface_name, tx2, next_id2);
            })
            .ok();
    }

    // The control socket (and this thread) must remain alive for the session's lifetime.
    // We park the coordinator thread here. If control_socket drops, the session ends.
    let _keep_alive = control_socket;
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

/// Outbound peer thread: connects to a remote I2P destination, runs HDLC reader loop.
/// Reconnects on failure.
fn outbound_peer_loop(
    sam_addr: SocketAddr,
    session_id: &str,
    peer_addr: &str,
    iface_name: &str,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
) {
    loop {
        log::info!("[{}] connecting to I2P peer {}", iface_name, peer_addr);

        // Resolve .b32.i2p address if needed
        let destination = if peer_addr.ends_with(".i2p") {
            match sam::naming_lookup(&sam_addr, peer_addr) {
                Ok(dest) => dest.to_i2p_base64(),
                Err(e) => {
                    log::warn!(
                        "[{}] failed to resolve {}: {}",
                        iface_name, peer_addr, e
                    );
                    thread::sleep(RECONNECT_WAIT);
                    continue;
                }
            }
        } else {
            // Assume it's already a full base64 destination
            peer_addr.to_string()
        };

        // Connect via SAM
        match sam::stream_connect(&sam_addr, session_id, &destination) {
            Ok(stream) => {
                let client_id = InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));

                log::info!(
                    "[{}] connected to I2P peer {} → id {}",
                    iface_name, peer_addr, client_id.0
                );

                // Clone stream for writer/reader split
                let writer_stream = match stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("[{}] failed to clone stream: {}", iface_name, e);
                        thread::sleep(RECONNECT_WAIT);
                        continue;
                    }
                };

                let writer: Box<dyn Writer> = Box::new(I2pWriter { stream: writer_stream });

                let info = InterfaceInfo {
                    id: client_id,
                    name: format!("I2PInterface/{}", peer_addr),
                    mode: constants::MODE_FULL,
                    out_capable: true,
                    in_capable: true,
                    bitrate: Some(BITRATE_GUESS),
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

                // Register dynamic interface
                if tx
                    .send(Event::InterfaceUp(client_id, Some(writer), Some(info)))
                    .is_err()
                {
                    return; // Driver shut down
                }

                // Run HDLC reader loop (blocks until disconnect)
                peer_reader_loop(stream, client_id, iface_name, &tx);

                // Disconnected
                let _ = tx.send(Event::InterfaceDown(client_id));
                log::warn!(
                    "[{}] I2P peer {} disconnected, reconnecting in {}s",
                    iface_name,
                    peer_addr,
                    RECONNECT_WAIT.as_secs()
                );
            }
            Err(e) => {
                log::warn!(
                    "[{}] failed to connect to I2P peer {}: {}",
                    iface_name, peer_addr, e
                );
            }
        }

        thread::sleep(RECONNECT_WAIT);
    }
}

/// Acceptor thread: loops accepting inbound connections on the session.
fn acceptor_loop(
    sam_addr: SocketAddr,
    session_id: &str,
    iface_name: &str,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
) {
    loop {
        match sam::stream_accept(&sam_addr, session_id) {
            Ok((stream, remote_dest)) => {
                let client_id = InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));
                let remote_b32 = remote_dest.base32_address();

                log::info!(
                    "[{}] accepted I2P connection from {} → id {}",
                    iface_name, remote_b32, client_id.0
                );

                // Clone stream for writer/reader split
                let writer_stream = match stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("[{}] failed to clone accepted stream: {}", iface_name, e);
                        continue;
                    }
                };

                let writer: Box<dyn Writer> = Box::new(I2pWriter { stream: writer_stream });

                let info = InterfaceInfo {
                    id: client_id,
                    name: format!("I2PInterface/{}", remote_b32),
                    mode: constants::MODE_FULL,
                    out_capable: true,
                    in_capable: true,
                    bitrate: Some(BITRATE_GUESS),
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

                // Register dynamic interface
                if tx
                    .send(Event::InterfaceUp(client_id, Some(writer), Some(info)))
                    .is_err()
                {
                    return; // Driver shut down
                }

                // Spawn per-client reader thread (accepted peers don't reconnect)
                let client_tx = tx.clone();
                let client_name = iface_name.to_string();
                thread::Builder::new()
                    .name(format!("i2p-client-{}", client_id.0))
                    .spawn(move || {
                        peer_reader_loop(stream, client_id, &client_name, &client_tx);
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

/// Per-peer HDLC reader loop. Reads from the SAM data stream, decodes HDLC
/// frames, and sends them to the driver. Returns when the stream is closed.
fn peer_reader_loop(
    mut stream: std::net::TcpStream,
    id: InterfaceId,
    name: &str,
    tx: &EventSender,
) {
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log::info!("[{}] I2P peer {} disconnected", name, id.0);
                return;
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
