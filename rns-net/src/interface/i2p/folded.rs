//! An I2P interface on the compact engine's driver loop.
//!
//! With interface I/O folded (see [`crate::engine::FOLD_IO`]) every SAM
//! stream is a loop source read on the driver thread: the session's control
//! socket, each peer's data stream, and the pending accept, which becomes
//! the accepted peer's stream once the bridge names the peer. Peers'
//! writers are written by the driver (see `I2pWriter::loop_socket`).
//!
//! Talking to the SAM bridge before a stream carries data blocks, for up to
//! tens of seconds while I2P builds tunnels, so it runs on short-lived
//! threads: one sets the session up, one connects (or reconnects) each
//! outbound peer, and one asks for the next incoming connection. Each exits
//! once its stream is served on the driver.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use super::sam::{self, Destination, SamError};
use super::{
    frame_decoder, load_or_generate_keypair, peer_info, peer_up, sanitize_name, template_ifac_size,
    I2pConfig, I2pRuntime, I2pWriter,
};
use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::hdlc;
use crate::interface::lock_or_recover;
use crate::interface::loop_writer::read_key;
use crate::interface::stream_read::{read_stream_frames, StreamRead};

/// How long to wait before asking the bridge again after an accept failed.
const ACCEPT_RETRY_WAIT: Duration = Duration::from_secs(1);

/// Longest line the bridge may send ahead of an accepted stream's data: a
/// destination in I2P base64 is well under this.
const MAX_ACCEPT_LINE: usize = 4096;

/// What the interface's streams share.
struct Session {
    sam_addr: SocketAddr,
    session_id: String,
    name: String,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    runtime: Arc<Mutex<I2pRuntime>>,
    ingress_control: rns_core::transport::types::IngressControlConfig,
    dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
    underlay_mark: Option<u32>,
}

/// Set the SAM session up and serve it on the driver loop. Runs on a setup
/// thread, which ends once the first accept is armed.
pub(super) fn setup(
    config: I2pConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
) -> Result<(), SamError> {
    let sam_addr: SocketAddr = format!("{}:{}", config.sam_host, config.sam_port)
        .parse()
        .map_err(|e| SamError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
    let keypair = load_or_generate_keypair(
        &sam_addr,
        &config.storage_dir,
        &config.name,
        config.underlay_mark,
    )?;
    let priv_b64 = sam::i2p_base64_encode(&keypair.private_key);
    // One session carries every stream, outbound and inbound.
    let session_id = sanitize_name(&config.name);
    log::info!("[{}] creating SAM session (id={})", config.name, session_id);
    let mut control =
        sam::session_create_with_mark(&sam_addr, &session_id, &priv_b64, config.underlay_mark)?;
    match sam::naming_lookup_on(&mut control, "ME") {
        Ok(our_dest) => {
            log::info!(
                "[{}] I2P address: {}",
                config.name,
                our_dest.base32_address()
            );
        }
        Err(e) => {
            log::warn!("[{}] could not look up own destination: {}", config.name, e);
        }
    }

    let session = Arc::new(Session {
        sam_addr,
        session_id,
        name: config.name.clone(),
        tx,
        next_id,
        runtime: Arc::clone(&config.runtime),
        ingress_control: config.ingress_control,
        dynamic_template,
        underlay_mark: config.underlay_mark,
    });

    // The session lasts as long as its control socket stays open.
    control.set_nonblocking(true).map_err(SamError::Io)?;
    session
        .tx
        .register_source(
            read_key(config.interface_id),
            Box::new(ControlSource {
                stream: control,
                line: Vec::new(),
                session: Arc::clone(&session),
            }),
        )
        .map_err(SamError::Io)?;

    for peer in &config.peers {
        let peer = peer.trim().to_string();
        if peer.is_empty() {
            continue;
        }
        let session = Arc::clone(&session);
        thread::Builder::new()
            .name(format!("i2p-out-{}", peer))
            .spawn(move || session.connect(peer, false))
            .map_err(SamError::Io)?;
    }

    if config.connectable {
        session.arm_accept();
    }
    Ok(())
}

impl Session {
    fn reconnect_wait(&self) -> Duration {
        lock_or_recover(&self.runtime, "i2p runtime").reconnect_wait
    }

    fn allocate_id(&self) -> InterfaceId {
        InterfaceId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Connect to an outbound peer until it is served on the driver,
    /// waiting between attempts (and first, when `wait_first`).
    fn connect(self: Arc<Self>, peer: String, wait_first: bool) {
        let mut wait = wait_first;
        loop {
            if wait {
                thread::sleep(self.reconnect_wait());
            }
            wait = true;
            log::info!("[{}] connecting to I2P peer {}", self.name, peer);
            let destination = if peer.ends_with(".i2p") {
                match sam::naming_lookup_with_mark(&self.sam_addr, &peer, self.underlay_mark) {
                    Ok(dest) => dest.to_i2p_base64(),
                    Err(e) => {
                        log::warn!("[{}] failed to resolve {}: {}", self.name, peer, e);
                        continue;
                    }
                }
            } else {
                // Assume it's already a full base64 destination
                peer.clone()
            };
            let stream = match sam::stream_connect_with_mark(
                &self.sam_addr,
                &self.session_id,
                &destination,
                self.underlay_mark,
            ) {
                Ok(stream) => stream,
                Err(e) => {
                    log::warn!(
                        "[{}] failed to connect to I2P peer {}: {}",
                        self.name,
                        peer,
                        e
                    );
                    continue;
                }
            };
            let id = self.allocate_id();
            log::info!(
                "[{}] connected to I2P peer {} → id {}",
                self.name,
                peer,
                id.0
            );
            let event = match self.writer(&stream, id, &peer) {
                Ok(event) => event,
                Err(e) => {
                    log::warn!("[{}] failed to clone stream: {}", self.name, e);
                    continue;
                }
            };
            if self.tx.send(event).is_err() {
                return; // Driver shut down
            }
            let source = StreamSource {
                stream,
                state: State::Peer(self.peer(id, Some(peer.clone()))),
                session: Arc::clone(&self),
            };
            match self.tx.register_source(read_key(id), Box::new(source)) {
                Ok(()) => return,
                Err(e) => {
                    log::warn!("[{}] cannot read I2P peer {}: {}", self.name, peer, e);
                    let _ = self.tx.send(Event::InterfaceDown(id));
                }
            }
        }
    }

    /// The event bringing up a peer whose writer writes `stream`.
    fn writer(&self, stream: &TcpStream, id: InterfaceId, remote: &str) -> io::Result<Event> {
        let writer = Box::new(I2pWriter {
            stream: stream.try_clone()?,
        });
        Ok(peer_up(
            id,
            writer,
            peer_info(id, remote, self.ingress_control),
            self.dynamic_template.as_ref(),
        ))
    }

    fn peer(&self, id: InterfaceId, outbound: Option<String>) -> Peer {
        Peer {
            id,
            decoder: frame_decoder(template_ifac_size(self.dynamic_template.as_ref())),
            outbound,
        }
    }

    /// Ask the bridge for the next incoming connection and wait for it on
    /// the driver loop. Blocks until the bridge agreed.
    fn arm_accept(self: &Arc<Self>) {
        loop {
            match sam::stream_accept_begin(&self.sam_addr, &self.session_id, self.underlay_mark) {
                Ok(stream) => {
                    let id = self.allocate_id();
                    let source = StreamSource {
                        stream,
                        state: State::Accepting {
                            id,
                            line: Vec::new(),
                        },
                        session: Arc::clone(self),
                    };
                    match self.tx.register_source(read_key(id), Box::new(source)) {
                        Ok(()) => return,
                        Err(e) => log::warn!("[{}] cannot wait for I2P peers: {}", self.name, e),
                    }
                }
                Err(e) => log::warn!("[{}] I2P accept failed: {}, retrying", self.name, e),
            }
            thread::sleep(ACCEPT_RETRY_WAIT);
        }
    }

    /// [`Session::arm_accept`] on a thread of its own, after `wait`.
    fn arm_accept_later(self: &Arc<Self>, wait: Duration) {
        let session = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name("i2p-accept".into())
            .spawn(move || {
                thread::sleep(wait);
                session.arm_accept();
            });
        if let Err(e) = spawned {
            log::error!("[{}] cannot accept I2P peers any more: {}", self.name, e);
        }
    }
}

/// The session's control socket, read on the driver thread.
struct ControlSource {
    stream: TcpStream,
    line: Vec<u8>,
    session: Arc<Session>,
}

impl LoopSource for ControlSource {
    fn fd(&self) -> std::os::fd::RawFd {
        self.stream.as_raw_fd()
    }

    fn on_ready(&mut self, _cx: &mut LoopContext<'_>) -> SourceStatus {
        let mut buf = [0u8; 512];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    log::warn!(
                        "[{}] the SAM bridge closed the I2P session",
                        self.session.name
                    );
                    return SourceStatus::Remove;
                }
                Ok(n) => {
                    for &byte in &buf[..n] {
                        if byte != b'\n' {
                            if self.line.len() < MAX_ACCEPT_LINE {
                                self.line.push(byte);
                            }
                            continue;
                        }
                        let line = String::from_utf8_lossy(&self.line).into_owned();
                        self.line.clear();
                        // Keep the session alive when the bridge checks on it.
                        if let Some(rest) = line.strip_prefix("PING") {
                            let _ = self.stream.write_all(format!("PONG{}\n", rest).as_bytes());
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return SourceStatus::Rearm,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log::warn!("[{}] I2P session socket failed: {}", self.session.name, e);
                    return SourceStatus::Remove;
                }
            }
        }
    }
}

struct Peer {
    id: InterfaceId,
    decoder: hdlc::Decoder,
    /// The address an outbound peer is reconnected to.
    outbound: Option<String>,
}

enum State {
    /// Waiting for the bridge to name an incoming peer; the stream then
    /// carries that peer's data, as interface `id`.
    Accepting {
        id: InterfaceId,
        line: Vec<u8>,
    },
    Peer(Peer),
}

/// A SAM data stream, read on the driver thread.
struct StreamSource {
    stream: TcpStream,
    state: State,
    session: Arc<Session>,
}

impl StreamSource {
    /// Read the accepted peer's destination; once it is complete, become
    /// that peer's stream. Returns `Some` when the source is done.
    fn accept(&mut self, cx: &mut LoopContext<'_>) -> Option<SourceStatus> {
        let session = Arc::clone(&self.session);
        let State::Accepting { id, line } = &mut self.state else {
            return None;
        };
        let id = *id;
        // SAFETY: `cx.buf` is a valid writable buffer for the call.
        let n = unsafe {
            libc::recv(
                self.stream.as_raw_fd(),
                cx.buf.as_mut_ptr().cast(),
                cx.buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        let read = match n {
            n if n > 0 => &cx.buf[..n as usize],
            0 => {
                log::warn!("[{}] I2P accept closed by the bridge", session.name);
                session.arm_accept_later(ACCEPT_RETRY_WAIT);
                return Some(SourceStatus::Remove);
            }
            _ => {
                let e = io::Error::last_os_error();
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    return Some(SourceStatus::Rearm);
                }
                log::warn!("[{}] I2P accept failed: {}, retrying", session.name, e);
                session.arm_accept_later(ACCEPT_RETRY_WAIT);
                return Some(SourceStatus::Remove);
            }
        };
        let Some(end) = read.iter().position(|&byte| byte == b'\n') else {
            line.extend_from_slice(read);
            if line.len() > MAX_ACCEPT_LINE {
                log::warn!("[{}] I2P accept sent no destination", session.name);
                session.arm_accept_later(ACCEPT_RETRY_WAIT);
                return Some(SourceStatus::Remove);
            }
            return Some(SourceStatus::Rearm);
        };
        line.extend_from_slice(&read[..end]);
        let data = read[end + 1..].to_vec();
        let remote = match std::str::from_utf8(line)
            .map_err(|e| SamError::InvalidResponse(e.to_string()))
            .and_then(|text| Destination::from_i2p_base64(text.trim()))
        {
            Ok(dest) => dest.base32_address(),
            Err(e) => {
                log::warn!("[{}] I2P accept failed: {}, retrying", session.name, e);
                session.arm_accept_later(ACCEPT_RETRY_WAIT);
                return Some(SourceStatus::Remove);
            }
        };
        // The next peer may arrive meanwhile: ask for it at once.
        session.arm_accept_later(Duration::ZERO);
        log::info!(
            "[{}] accepted I2P connection from {} → id {}",
            session.name,
            remote,
            id.0
        );
        let up = match session.writer(&self.stream, id, &remote) {
            Ok(up) => up,
            Err(e) => {
                log::warn!("[{}] failed to clone accepted stream: {}", session.name, e);
                return Some(SourceStatus::Remove);
            }
        };
        let mut peer = session.peer(id, None);
        let frames = peer
            .decoder
            .feed(&data)
            .into_iter()
            .map(|frame| Event::Frame {
                interface_id: id,
                data: frame.into(),
                rssi: None,
                snr: None,
            });
        if session
            .tx
            .push_from_loop(std::iter::once(up).chain(frames))
            .is_err()
        {
            return Some(SourceStatus::Remove);
        }
        self.state = State::Peer(peer);
        None
    }

    fn peer_lost(&self, peer: &Peer) {
        let session = &self.session;
        let _ = session.tx.push_from_loop([Event::InterfaceDown(peer.id)]);
        let Some(address) = peer.outbound.clone() else {
            // Accepted peers are not reconnected.
            return;
        };
        log::warn!(
            "[{}] I2P peer {} disconnected, reconnecting in {}s",
            session.name,
            address,
            session.reconnect_wait().as_secs()
        );
        let session = Arc::clone(session);
        let spawned = thread::Builder::new()
            .name(format!("i2p-out-{}", address))
            .spawn(move || session.connect(address, true));
        if let Err(e) = spawned {
            log::error!(
                "[{}] cannot reconnect to I2P peer, giving up: {}",
                self.session.name,
                e
            );
        }
    }
}

impl LoopSource for StreamSource {
    fn fd(&self) -> std::os::fd::RawFd {
        self.stream.as_raw_fd()
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if let Some(status) = self.accept(cx) {
            return status;
        }
        let State::Peer(peer) = &mut self.state else {
            return SourceStatus::Rearm;
        };
        let session = &self.session;
        match read_stream_frames(
            self.stream.as_raw_fd(),
            &mut peer.decoder,
            cx,
            &session.tx,
            peer.id,
            &session.name,
            |_, _| {},
        ) {
            StreamRead::Rearm => SourceStatus::Rearm,
            StreamRead::Suspend => SourceStatus::Suspend,
            StreamRead::DriverGone => SourceStatus::Remove,
            StreamRead::Closed => {
                log::info!("[{}] I2P peer {} disconnected", session.name, peer.id.0);
                let State::Peer(peer) = &self.state else {
                    unreachable!()
                };
                self.peer_lost(peer);
                SourceStatus::Remove
            }
            StreamRead::Failed(e) => {
                log::warn!(
                    "[{}] I2P peer {} read error: {}",
                    session.name,
                    peer.id.0,
                    e
                );
                let State::Peer(peer) = &self.state else {
                    unreachable!()
                };
                self.peer_lost(peer);
                SourceStatus::Remove
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn read_command(stream: &mut TcpStream) -> String {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            line.push(byte[0]);
        }
        String::from_utf8(line).unwrap()
    }

    /// Answer one SAM connection's HELLO and STREAM ACCEPT, returning it.
    fn agree_to_accept(listener: &TcpListener) -> TcpStream {
        let (mut stream, _) = listener.accept().unwrap();
        assert!(read_command(&mut stream).starts_with("HELLO VERSION"));
        stream
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
            .unwrap();
        assert!(read_command(&mut stream).starts_with("STREAM ACCEPT ID=test"));
        stream.write_all(b"STREAM STATUS RESULT=OK\n").unwrap();
        stream
    }

    #[test]
    fn accepted_peer_is_served_on_the_driver_loop() {
        if !crate::engine::FOLD_IO {
            return;
        }
        let bridge = TcpListener::bind("127.0.0.1:0").unwrap();
        let (tx, rx) = crate::event::channel();
        let session = Arc::new(Session {
            sam_addr: bridge.local_addr().unwrap(),
            session_id: "test".into(),
            name: "i2p-test".into(),
            tx: tx.clone(),
            next_id: Arc::new(AtomicU64::new(700)),
            runtime: Arc::new(Mutex::new(I2pRuntime {
                reconnect_wait: Duration::from_secs(1),
            })),
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
            dynamic_template: None,
            underlay_mark: None,
        });
        let (accepts_tx, accepts) = mpsc::channel();
        thread::spawn(move || {
            for _ in 0..2 {
                if accepts_tx.send(agree_to_accept(&bridge)).is_err() {
                    return;
                }
            }
        });
        session.arm_accept();
        let mut first = accepts.recv_timeout(Duration::from_secs(2)).unwrap();

        // A peer arrives: its destination, then its first frame, together.
        let remote = Destination {
            data: (0..=255).collect(),
        };
        let payload: Vec<u8> = (0..32).collect();
        let mut wire = remote.to_i2p_base64().into_bytes();
        wire.push(b'\n');
        wire.extend_from_slice(&hdlc::frame(&payload));
        first.write_all(&wire).unwrap();

        let writer = match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::InterfaceUp(InterfaceId(700), Some(writer), Some(info)) => {
                assert_eq!(
                    info.name,
                    format!("I2PInterface/{}", remote.base32_address())
                );
                writer
            }
            other => panic!("expected the peer's InterfaceUp, got {other:?}"),
        };
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Frame {
                interface_id, data, ..
            } => {
                assert_eq!(interface_id, InterfaceId(700));
                assert_eq!(&*data, &payload[..]);
            }
            other => panic!("expected Frame, got {other:?}"),
        }
        // The next incoming connection was asked for.
        let _second = accepts.recv_timeout(Duration::from_secs(2)).unwrap();

        // Outbound, written by the driver.
        assert!(writer.loop_socket().is_some());
        let (mut writer, _) =
            crate::interface::wrap_async_writer(writer, InterfaceId(700), "i2p", tx, 16);
        writer.send_frame(&payload).unwrap();
        writer.flush_pending();
        let mut sent = vec![0u8; hdlc::frame(&payload).len()];
        first.read_exact(&mut sent).unwrap();
        assert_eq!(sent, hdlc::frame(&payload));

        // The peer leaving is reported; accepted peers are not reconnected.
        drop(first);
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::InterfaceDown(InterfaceId(700)) => {}
            other => panic!("expected InterfaceDown, got {other:?}"),
        }
    }

    #[test]
    fn outbound_peer_is_served_on_the_driver_loop_and_reconnected() {
        if !crate::engine::FOLD_IO {
            return;
        }
        let bridge = TcpListener::bind("127.0.0.1:0").unwrap();
        let (tx, rx) = crate::event::channel();
        let session = Arc::new(Session {
            sam_addr: bridge.local_addr().unwrap(),
            session_id: "test".into(),
            name: "i2p-test".into(),
            tx,
            next_id: Arc::new(AtomicU64::new(800)),
            runtime: Arc::new(Mutex::new(I2pRuntime {
                reconnect_wait: Duration::from_millis(100),
            })),
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
            dynamic_template: None,
            underlay_mark: None,
        });
        let (connections_tx, connections) = mpsc::channel();
        thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = bridge.accept().unwrap();
                assert!(read_command(&mut stream).starts_with("HELLO VERSION"));
                stream
                    .write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
                    .unwrap();
                assert!(read_command(&mut stream).starts_with("STREAM CONNECT ID=test"));
                stream.write_all(b"STREAM STATUS RESULT=OK\n").unwrap();
                if connections_tx.send(stream).is_err() {
                    return;
                }
            }
        });
        let peer = "AAAA".to_string();
        {
            let session = Arc::clone(&session);
            thread::spawn(move || session.connect(peer, false));
        }
        let mut stream = connections.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::InterfaceUp(InterfaceId(800), Some(_), Some(_))
        ));
        let payload: Vec<u8> = (0..32).collect();
        stream.write_all(&hdlc::frame(&payload)).unwrap();
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Frame {
                interface_id, data, ..
            } => {
                assert_eq!(interface_id, InterfaceId(800));
                assert_eq!(&*data, &payload[..]);
            }
            other => panic!("expected Frame, got {other:?}"),
        }

        // The peer dropping brings it down, and it is connected again.
        drop(stream);
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::InterfaceDown(InterfaceId(800))
        ));
        let _again = connections.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::InterfaceUp(InterfaceId(801), Some(_), Some(_))
        ));
    }
}
