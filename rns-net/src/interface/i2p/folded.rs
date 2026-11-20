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
use std::net::TcpStream;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use super::sam::{self, Destination, SamError};
use super::session::{ControlLines, Session, ACCEPT_RETRY_WAIT, MAX_SAM_LINE};
use super::tunnel::PeerTunnel;
use super::{
    frame_decoder, reopen_session, template_ifac_size, I2pConfig, I2pEndpoint, OutboundPeer,
};
use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::hdlc;
use crate::interface::loop_writer::read_key;
use crate::interface::stream_read::{read_stream_frames, StreamRead};

/// Set the SAM session up and serve it on the driver loop. Runs on a setup
/// thread, which ends once the first accept is armed.
pub(super) fn setup(
    config: I2pConfig,
    peers: Vec<OutboundPeer>,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
) -> Result<(), SamError> {
    let (session, control) = Session::open(config, tx, next_id, dynamic_template)?;

    // The session lasts as long as its control socket stays open.
    serve_control(&session, control).map_err(SamError::Io)?;

    for peer in peers {
        let session = Arc::clone(&session);
        thread::Builder::new()
            .name(format!("i2p-out-{}", peer.address))
            .spawn(move || connect(session, peer, false))
            .map_err(SamError::Io)?;
    }

    if session.config.connectable {
        arm_accept(&session);
        super::I2pEndpoint::set_accepting(&session.endpoint);
    }
    Ok(())
}

/// Open the session again, on a thread of its own, after the bridge
/// closed it, and serve its new control socket on the driver loop. Peers
/// reconnect and accepts are asked for again meanwhile, under the same
/// session id.
fn reopen_later(session: &Arc<Session>) {
    let session = Arc::clone(session);
    let name = session.name.clone();
    let spawned = thread::Builder::new()
        .name(format!("i2p-session-{}", session.config.interface_id.0))
        .spawn(move || {
            let control =
                reopen_session(&session.config, &session.sam_addr, session.sam_retry_wait);
            if let Err(e) = serve_control(&session, control) {
                log::error!("[{}] cannot serve the I2P session: {}", session.name, e);
            }
        });
    if let Err(e) = spawned {
        log::error!("[{}] cannot reopen the I2P session: {}", name, e);
    }
}

/// Serve the session's control socket on the driver loop.
fn serve_control(session: &Arc<Session>, control: TcpStream) -> io::Result<()> {
    control.set_nonblocking(true)?;
    session.tx.register_source(
        read_key(session.config.interface_id),
        Box::new(ControlSource {
            stream: control,
            lines: ControlLines::default(),
            session: Arc::clone(session),
        }),
    )
}

/// Connect to an outbound peer until it is served on the driver, waiting
/// between attempts (and first, when `wait_first`).
fn connect(session: Arc<Session>, peer: OutboundPeer, wait_first: bool) {
    let mut wait = wait_first;
    loop {
        if wait {
            thread::sleep(session.reconnect_wait());
        }
        wait = true;
        let Some((stream, up)) = session.connect_once(&peer) else {
            continue;
        };
        if session.tx.send(up.event).is_err() {
            return; // Driver shut down
        }
        let source = StreamSource {
            stream,
            state: State::Peer(new_peer(
                &session,
                peer.id,
                Some(peer.clone()),
                up.tunnel,
                up.detached,
            )),
            session: Arc::clone(&session),
        };
        match session
            .tx
            .register_source(read_key(peer.id), Box::new(source))
        {
            Ok(()) => return,
            Err(e) => {
                log::warn!(
                    "[{}] cannot read I2P peer {}: {}",
                    session.name,
                    peer.address,
                    e
                );
                let _ = session.tx.send(Event::InterfaceDown(peer.id));
            }
        }
    }
}

fn new_peer(
    session: &Session,
    id: InterfaceId,
    outbound: Option<OutboundPeer>,
    tunnel: Arc<PeerTunnel>,
    detached: Arc<AtomicBool>,
) -> Peer {
    Peer {
        id,
        decoder: frame_decoder(template_ifac_size(session.dynamic_template.as_ref())),
        outbound,
        tunnel,
        detached,
    }
}

/// Ask the bridge for the next incoming connection and wait for it on the
/// driver loop. Blocks until the bridge agreed.
fn arm_accept(session: &Arc<Session>) {
    loop {
        match sam::stream_accept_begin(
            &session.sam_addr,
            &session.session_id,
            session.underlay_mark,
        ) {
            Ok(stream) => {
                let id = session.allocate_id();
                let source = StreamSource {
                    stream,
                    state: State::Accepting {
                        id,
                        line: Vec::new(),
                    },
                    session: Arc::clone(session),
                };
                match session.tx.register_source(read_key(id), Box::new(source)) {
                    Ok(()) => return,
                    Err(e) => log::warn!("[{}] cannot wait for I2P peers: {}", session.name, e),
                }
            }
            Err(e) => log::warn!("[{}] I2P accept failed: {}, retrying", session.name, e),
        }
        thread::sleep(ACCEPT_RETRY_WAIT);
    }
}

/// [`arm_accept`] on a thread of its own, after `wait`.
fn arm_accept_later(session: &Arc<Session>, wait: Duration) {
    let session = Arc::clone(session);
    let name = session.name.clone();
    let spawned = thread::Builder::new()
        .name("i2p-accept".into())
        .spawn(move || {
            thread::sleep(wait);
            arm_accept(&session);
        });
    if let Err(e) = spawned {
        log::error!("[{}] cannot accept I2P peers any more: {}", name, e);
    }
}

/// The session's control socket, read on the driver thread.
struct ControlSource {
    stream: TcpStream,
    lines: ControlLines,
    session: Arc<Session>,
}

impl LoopSource for ControlSource {
    fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.stream.as_fd()
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
                    reopen_later(&self.session);
                    return SourceStatus::Remove;
                }
                Ok(n) => {
                    let stream = &mut self.stream;
                    self.lines.feed(&buf[..n], |reply| {
                        let _ = stream.write_all(reply.as_bytes());
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return SourceStatus::Rearm,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log::warn!("[{}] I2P session socket failed: {}", self.session.name, e);
                    reopen_later(&self.session);
                    return SourceStatus::Remove;
                }
            }
        }
    }
}

struct Peer {
    id: InterfaceId,
    decoder: hdlc::Decoder,
    /// The outbound peer, reconnected when its stream ends.
    outbound: Option<OutboundPeer>,
    tunnel: Arc<PeerTunnel>,
    /// Set when the driver detaches the peer, which is then not reconnected.
    detached: Arc<AtomicBool>,
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
        let n = crate::sys::recv(self.stream.as_raw_fd(), cx.buf, libc::MSG_DONTWAIT);
        let read = match n {
            n if n > 0 => &cx.buf[..n as usize],
            0 => {
                log::warn!("[{}] I2P accept closed by the bridge", session.name);
                arm_accept_later(&session, ACCEPT_RETRY_WAIT);
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
                arm_accept_later(&session, ACCEPT_RETRY_WAIT);
                return Some(SourceStatus::Remove);
            }
        };
        let Some(end) = read.iter().position(|&byte| byte == b'\n') else {
            line.extend_from_slice(read);
            if line.len() > MAX_SAM_LINE {
                log::warn!("[{}] I2P accept sent no destination", session.name);
                arm_accept_later(&session, ACCEPT_RETRY_WAIT);
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
                arm_accept_later(&session, ACCEPT_RETRY_WAIT);
                return Some(SourceStatus::Remove);
            }
        };
        // The next peer may arrive meanwhile: ask for it at once.
        arm_accept_later(&session, Duration::ZERO);
        let Some(up) = session.accepted(&self.stream, id, &remote) else {
            return Some(SourceStatus::Remove);
        };
        let mut peer = new_peer(&session, id, None, up.tunnel, up.detached);
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
            .push_from_loop(std::iter::once(up.event).chain(frames))
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
        let Some(outbound) = peer.outbound.clone() else {
            // Accepted peers are not reconnected.
            I2pEndpoint::remove_tunnel(&session.endpoint, peer.id);
            return;
        };
        if !session.outbound_lost(&outbound, &peer.detached) {
            return;
        }
        let session = Arc::clone(session);
        let spawned = thread::Builder::new()
            .name(format!("i2p-out-{}", outbound.address))
            .spawn(move || connect(session, outbound, true));
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
    fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.stream.as_fd()
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
            |_, _| peer.tunnel.note_read(),
        ) {
            StreamRead::Rearm => return SourceStatus::Rearm,
            StreamRead::Suspend => return SourceStatus::Suspend,
            StreamRead::DriverGone => return SourceStatus::Remove,
            StreamRead::Closed => {
                log::info!("[{}] I2P peer {} disconnected", session.name, peer.id.0);
            }
            StreamRead::Failed(e) => {
                log::warn!(
                    "[{}] I2P peer {} read error: {}",
                    session.name,
                    peer.id.0,
                    e
                );
            }
        }
        if let State::Peer(peer) = &self.state {
            self.peer_lost(peer);
        }
        SourceStatus::Remove
    }
}

#[cfg(test)]
mod tests {
    use super::super::I2pRuntime;
    use super::*;
    use crate::interface::lock_or_recover;
    use std::net::SocketAddr;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::sync::Mutex;

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
    fn session_closed_by_the_bridge_is_opened_again_on_the_driver_loop() {
        if !crate::engine::FOLD_IO {
            return;
        }
        use super::super::tests::{answer_session, config_with_keys, free_port};
        let port = free_port();
        let mut config = config_with_keys("I2P folded", port);
        config.interface_id = InterfaceId(42);
        let sam_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let bridge = TcpListener::bind(sam_addr).unwrap();
        let (tx, rx) = crate::event::channel();
        let session = Arc::new(Session {
            sam_addr,
            session_id: "I2P_folded".into(),
            name: config.name.clone(),
            tx,
            next_id: Arc::new(AtomicU64::new(900)),
            runtime: Arc::clone(&config.runtime),
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
            dynamic_template: None,
            underlay_mark: None,
            endpoint: Arc::clone(&config.endpoint),
            config: config.clone(),
            sam_retry_wait: Duration::from_millis(200),
        });
        // The session's first control socket, served on the driver loop.
        let control_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let control = TcpStream::connect(control_listener.local_addr().unwrap()).unwrap();
        let (first, _) = control_listener.accept().unwrap();
        serve_control(&session, control).unwrap();
        I2pEndpoint::set_accepting(&config.endpoint);

        // The bridge answers the session opened again, and checks on it.
        let (done_tx, done) = mpsc::channel();
        thread::spawn(move || {
            let mut control = answer_session(&bridge, "I2P_folded");
            control.write_all(b"PING 7\n").unwrap();
            let _ = done_tx.send(read_command(&mut control));
            thread::sleep(Duration::from_secs(1));
        });
        drop(first);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let pong = loop {
            let _ = rx.recv_timeout(Duration::from_millis(50));
            if let Ok(pong) = done.try_recv() {
                break pong;
            }
            assert!(std::time::Instant::now() < deadline, "session not reopened");
        };
        // The new control socket is served on the driver loop.
        assert_eq!(pong, "PONG 7");
        assert!(lock_or_recover(&config.endpoint, "test").online);
        let _ = std::fs::remove_dir_all(&config.storage_dir);
    }

    #[test]
    fn accepted_peer_is_served_on_the_driver_loop() {
        if !crate::engine::FOLD_IO {
            return;
        }
        let bridge = TcpListener::bind("127.0.0.1:0").unwrap();
        let (tx, rx) = crate::event::channel();
        let endpoint: Arc<Mutex<I2pEndpoint>> = Arc::default();
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
            endpoint: Arc::clone(&endpoint),
            config: I2pConfig::default(),
            sam_retry_wait: Duration::from_secs(1),
        });
        let (accepts_tx, accepts) = mpsc::channel();
        thread::spawn(move || {
            for _ in 0..2 {
                if accepts_tx.send(agree_to_accept(&bridge)).is_err() {
                    return;
                }
            }
        });
        arm_accept(&session);
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
        // Its tunnel is watched, being created until the driver checks it.
        let tunnel = Arc::clone(&lock_or_recover(&endpoint, "test").tunnels[&InterfaceId(700)]);
        assert_eq!(tunnel.state(), super::super::tunnel::TunnelState::Init);
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
        assert!(lock_or_recover(&endpoint, "test").tunnels.is_empty());
    }

    #[test]
    fn outbound_peer_is_served_on_the_driver_loop_and_reconnected() {
        if !crate::engine::FOLD_IO {
            return;
        }
        let bridge = TcpListener::bind("127.0.0.1:0").unwrap();
        let (tx, rx) = crate::event::channel();
        let endpoint: Arc<Mutex<I2pEndpoint>> = Arc::default();
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
            endpoint: Arc::clone(&endpoint),
            config: I2pConfig::default(),
            sam_retry_wait: Duration::from_secs(1),
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
        let peer = OutboundPeer {
            address: "AAAA".to_string(),
            id: InterfaceId(800),
        };
        {
            let session = Arc::clone(&session);
            thread::spawn(move || connect(session, peer, false));
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
        assert!(lock_or_recover(&endpoint, "test")
            .tunnels
            .contains_key(&InterfaceId(800)));

        // The peer dropping brings it down, and it is connected again as
        // the same interface, its tunnel keeping its state meanwhile.
        let tunnel = Arc::clone(&lock_or_recover(&endpoint, "test").tunnels[&InterfaceId(800)]);
        tunnel.resume(super::super::tunnel::TunnelState::Stale);
        drop(stream);
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::InterfaceDown(InterfaceId(800))
        ));
        assert!(Arc::ptr_eq(
            &tunnel,
            &lock_or_recover(&endpoint, "test").tunnels[&InterfaceId(800)]
        ));
        let _again = connections.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::InterfaceUp(InterfaceId(800), Some(_), Some(_))
        ));
        let resumed = Arc::clone(&lock_or_recover(&endpoint, "test").tunnels[&InterfaceId(800)]);
        assert!(!Arc::ptr_eq(&tunnel, &resumed));
        assert_eq!(resumed.state(), super::super::tunnel::TunnelState::Stale);
    }
}
