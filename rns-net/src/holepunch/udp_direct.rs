//! Point-to-point UDP direct interface.
//!
//! After hole punching succeeds, this module wraps the punched UDP socket
//! as a Reticulum interface (implementing Writer + reader thread).
//! No HDLC framing needed — one datagram = one packet (same as UdpInterface).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::interface::Writer;

use super::puncher;

/// Keepalive interval for maintaining NAT mappings.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Timeout for considering the direct connection dead.
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(120);

/// Writer for a direct UDP peer-to-peer connection.
///
/// When dropped, signals the reader thread to stop.
pub struct UdpDirectWriter {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    running: Arc<AtomicBool>,
    /// Called by the driver directly on a non-blocking socket, with
    /// interface I/O folded (see [`crate::engine::FOLD_IO`]).
    inline: bool,
}

impl Writer for UdpDirectWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        match self.socket.send_to(data, self.peer_addr) {
            // A datagram the socket buffer cannot take is dropped, as the
            // network may drop it.
            Err(e) if self.inline && e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            result => result.map(|_| ()),
        }
    }

    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
        self.socket.send_to(data, self.peer_addr).map(|_| ())
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        // A full buffer returns WouldBlock with the completion untouched,
        // and the driver retries the frame.
        self.socket.send_to(data, self.peer_addr)?;
        if let Some(completion) = completion.take() {
            completion.finish(Ok(()));
        }
        Ok(())
    }

    fn sends_inline(&self) -> bool {
        self.inline
    }
}

impl Drop for UdpDirectWriter {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Start a direct UDP interface from a punched socket.
///
/// Returns `(interface_id, writer, InterfaceInfo)` and spawns a reader thread.
/// The reader thread sends `Event::Frame` for incoming packets and
/// `Event::InterfaceDown` if the connection times out.
pub fn start_direct_interface(
    socket: UdpSocket,
    peer_addr: SocketAddr,
    interface_id: InterfaceId,
    session_id: [u8; 16],
    punch_token: [u8; 32],
    tx: EventSender,
) -> io::Result<(Box<dyn Writer>, InterfaceInfo)> {
    let socket = Arc::new(socket);
    let inline = crate::engine::FOLD_IO;
    if inline {
        socket.set_nonblocking(true)?;
    } else {
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    }

    let running = Arc::new(AtomicBool::new(true));

    let writer = UdpDirectWriter {
        socket: socket.clone(),
        peer_addr,
        running: running.clone(),
        inline,
    };

    let name = format!(
        "DirectPeer/{:02x}{:02x}{:02x}{:02x}",
        session_id[0], session_id[1], session_id[2], session_id[3]
    );

    let info = InterfaceInfo {
        stamp_costs: Default::default(),
        id: interface_id,
        name: name.clone(),
        mode: rns_core::constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate: None,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: 1.0,
        is_local_client: false,
        wants_tunnel: false,
        tunnel_id: None,
        mtu: 1400,
        ia_freq: 0.0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
    };

    if inline {
        let now = std::time::Instant::now();
        tx.register_source(
            crate::interface::loop_writer::read_key(interface_id),
            Box::new(DirectSource {
                socket,
                peer_addr,
                interface_id,
                keepalive: puncher::build_keepalive_packet(&session_id, &punch_token),
                last_inbound: now,
                last_keepalive: now,
                tx: tx.clone(),
                running,
            }),
        )?;
        return Ok((Box::new(writer), info));
    }

    let running_clone = running.clone();

    // Spawn reader + keepalive thread
    thread::Builder::new()
        .name(format!("direct-udp-{}", &name))
        .spawn(move || {
            run_reader(
                socket,
                peer_addr,
                interface_id,
                session_id,
                punch_token,
                tx,
                running_clone,
            );
        })?;

    Ok((Box::new(writer), info))
}

fn run_reader(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    interface_id: InterfaceId,
    session_id: [u8; 16],
    punch_token: [u8; 32],
    tx: EventSender,
    running: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 2048];
    let mut last_inbound = std::time::Instant::now();
    let mut last_keepalive = std::time::Instant::now();
    let keepalive_pkt = puncher::build_keepalive_packet(&session_id, &punch_token);

    while running.load(Ordering::Relaxed) {
        // Send keepalive if due
        if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
            let _ = socket.send_to(&keepalive_pkt, peer_addr);
            last_keepalive = std::time::Instant::now();
        }

        // Check inactivity timeout
        if last_inbound.elapsed() >= INACTIVITY_TIMEOUT {
            log::info!("[{}] Direct UDP interface timed out", interface_id.0);
            let _ = tx.send(Event::InterfaceDown(interface_id));
            break;
        }

        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                // Only accept packets from our verified peer
                if src != peer_addr {
                    continue;
                }
                last_inbound = std::time::Instant::now();

                // Skip keepalive/punch packets (they have RNSH/RNSA magic)
                if len >= 4 && (buf[..4] == *b"RNSH" || buf[..4] == *b"RNSA") {
                    continue;
                }

                // Deliver as Reticulum frame
                if len > 0 {
                    let _ = tx.send(Event::Frame {
                        interface_id,
                        data: buf[..len].into(),
                        rssi: None,
                        snr: None,
                    });
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                log::warn!("[{}] Direct UDP recv error: {}", interface_id.0, e);
                let _ = tx.send(Event::InterfaceDown(interface_id));
                break;
            }
        }
    }
}

/// Datagrams read per readiness before other sources get a turn.
const READ_BUDGET: usize = 64;

/// A direct UDP link, read on the driver thread, with its keepalive and
/// inactivity timeout on timers.
struct DirectSource {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    interface_id: InterfaceId,
    keepalive: Vec<u8>,
    last_inbound: std::time::Instant,
    last_keepalive: std::time::Instant,
    tx: EventSender,
    /// Cleared when the writer is dropped with the interface.
    running: Arc<AtomicBool>,
}

impl LoopSource for DirectSource {
    fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.socket.as_raw_fd()
    }

    fn stopped(&self) -> bool {
        !self.running.load(Ordering::Relaxed)
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if self.stopped() {
            return SourceStatus::Remove;
        }
        if !self.tx.inbound_data_has_room() {
            return SourceStatus::Suspend;
        }
        let mut frames = Vec::new();
        for _ in 0..READ_BUDGET {
            let (len, src) = match self.socket.recv_from(cx.buf) {
                Ok(received) => received,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::warn!("[{}] Direct UDP recv error: {}", self.interface_id.0, e);
                    let _ = self.tx.push_from_loop(frames);
                    let _ = self
                        .tx
                        .push_from_loop([Event::InterfaceDown(self.interface_id)]);
                    return SourceStatus::Remove;
                }
            };
            // Only accept packets from our verified peer
            if src != self.peer_addr {
                continue;
            }
            self.last_inbound = std::time::Instant::now();
            // Skip keepalive/punch packets (they have RNSH/RNSA magic)
            if len >= 4 && (cx.buf[..4] == *b"RNSH" || cx.buf[..4] == *b"RNSA") {
                continue;
            }
            if len > 0 {
                frames.push(Event::Frame {
                    interface_id: self.interface_id,
                    data: cx.buf[..len].into(),
                    rssi: None,
                    snr: None,
                });
            }
        }
        match self.tx.push_from_loop(frames) {
            Ok(true) => SourceStatus::Rearm,
            Ok(false) => SourceStatus::Suspend,
            Err(_) => SourceStatus::Remove,
        }
    }

    fn deadline(&self) -> Option<std::time::Instant> {
        Some((self.last_keepalive + KEEPALIVE_INTERVAL).min(self.last_inbound + INACTIVITY_TIMEOUT))
    }

    fn on_timer(&mut self, _cx: &mut LoopContext<'_>) -> SourceStatus {
        if self.stopped() {
            return SourceStatus::Remove;
        }
        let now = std::time::Instant::now();
        if now >= self.last_inbound + INACTIVITY_TIMEOUT {
            log::info!("[{}] Direct UDP interface timed out", self.interface_id.0);
            let _ = self
                .tx
                .push_from_loop([Event::InterfaceDown(self.interface_id)]);
            return SourceStatus::Remove;
        }
        if now >= self.last_keepalive + KEEPALIVE_INTERVAL {
            let _ = self.socket.send_to(&self.keepalive, self.peer_addr);
            self.last_keepalive = now;
        }
        SourceStatus::Rearm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_direct_writer() {
        // Create a pair of sockets
        let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        sock_b
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let mut writer = UdpDirectWriter {
            socket: Arc::new(sock_a),
            peer_addr: addr_b,
            running: Arc::new(AtomicBool::new(true)),
            inline: false,
        };

        // Send a frame
        let data = b"hello direct peer";
        writer.send_frame(data).unwrap();

        // Receive on other end
        let mut buf = [0u8; 64];
        let (len, _src) = sock_b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], data);
    }

    #[test]
    fn folded_direct_link_runs_on_the_driver_loop() {
        if !crate::engine::FOLD_IO {
            return;
        }
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let local_addr = local.local_addr().unwrap();
        let (tx, rx) = crate::event::channel();
        let (writer, _info) = start_direct_interface(
            local,
            peer_addr,
            InterfaceId(910),
            [1; 16],
            [2; 32],
            tx.clone(),
        )
        .unwrap();
        assert!(writer.sends_inline());
        // Served on the driver loop: no reader thread.
        assert!(!std::fs::read_dir("/proc/self/task").unwrap().any(|task| {
            std::fs::read_to_string(task.unwrap().path().join("comm"))
                .is_ok_and(|comm| comm.starts_with("direct-udp-"))
        }));
        let (mut writer, _) =
            crate::interface::wrap_async_writer(writer, InterfaceId(910), "direct", tx, 16);

        // Inbound from the peer; keepalives and strangers are skipped.
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        stranger.send_to(b"not from the peer", local_addr).unwrap();
        peer.send_to(b"RNSH keepalive", local_addr).unwrap();
        peer.send_to(b"from the peer", local_addr).unwrap();
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Frame {
                interface_id, data, ..
            } => {
                assert_eq!(interface_id, InterfaceId(910));
                assert_eq!(&*data, b"from the peer");
            }
            other => panic!("expected Frame, got {other:?}"),
        }
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());

        // Outbound, sent by the driver directly.
        writer.send_frame(b"to the peer").unwrap();
        let mut buf = [0u8; 64];
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"to the peer");
    }
}
