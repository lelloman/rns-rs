//! Point-to-point UDP direct interface.
//!
//! After hole punching succeeds, this module wraps the punched UDP socket
//! as a Reticulum interface (implementing Writer + reader thread).
//! No HDLC framing needed — one datagram = one packet (same as UdpInterface).
//!
//! The interface belongs to one link and carries only that link's packets:
//! it is not an outbound interface for the transport engine (no announces,
//! path requests or broadcasts are routed to it), and its reader and writer
//! drop any frame that is not a link DATA or PROOF packet addressed to the
//! link. Nothing else can reach the peer through it, or the node through it.

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

/// Whether `frame` is a packet of the link the direct interface belongs to:
/// a HEADER_1 link DATA or PROOF packet whose destination is `link_id`.
pub(crate) fn carries_link(frame: &[u8], link_id: &[u8; 16]) -> bool {
    use rns_core::constants::{DESTINATION_LINK, HEADER_1, PACKET_TYPE_DATA, PACKET_TYPE_PROOF};
    let Some(flags) = frame.first() else {
        return false;
    };
    let header_type = (flags >> 6) & 0x01;
    let destination_type = (flags >> 2) & 0x03;
    let packet_type = flags & 0x03;
    header_type == HEADER_1
        && destination_type == DESTINATION_LINK
        && (packet_type == PACKET_TYPE_DATA || packet_type == PACKET_TYPE_PROOF)
        && frame.get(2..18) == Some(&link_id[..])
}

/// Writer for a direct UDP peer-to-peer connection.
///
/// When dropped, signals the reader thread to stop.
pub struct UdpDirectWriter {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    /// The link this interface belongs to; other frames are not sent.
    link_id: [u8; 16],
    running: Arc<AtomicBool>,
    /// Called by the driver directly on a non-blocking socket, with
    /// interface I/O folded (see [`crate::engine::FOLD_IO`]).
    inline: bool,
}

impl UdpDirectWriter {
    /// Frames of other traffic are dropped, as a link that cannot carry
    /// them would.
    fn admits(&self, data: &[u8]) -> bool {
        let ok = carries_link(data, &self.link_id);
        if !ok {
            log::trace!("Direct UDP interface dropped a frame not of its link");
        }
        ok
    }
}

impl Writer for UdpDirectWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.admits(data) {
            return Ok(());
        }
        match self.socket.send_to(data, self.peer_addr) {
            // A datagram the socket buffer cannot take is dropped, as the
            // network may drop it.
            Err(e) if self.inline && e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            result => result.map(|_| ()),
        }
    }

    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.admits(data) {
            return Ok(());
        }
        self.socket.send_to(data, self.peer_addr).map(|_| ())
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        // A full buffer returns WouldBlock with the completion untouched,
        // and the driver retries the frame.
        if self.admits(data) {
            self.socket.send_to(data, self.peer_addr)?;
        }
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
    link_id: [u8; 16],
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
        link_id,
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
        // Only its link's packets, sent to it by the link's route, go out
        // on it: the engine never picks it for announces, path requests
        // or broadcasts.
        out_capable: false,
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
        mtu_upgradable: false,
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
                link_id,
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
                link_id,
                session_id,
                punch_token,
                tx,
                running_clone,
            );
        })?;

    Ok((Box::new(writer), info))
}

#[allow(clippy::too_many_arguments)]
fn run_reader(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    interface_id: InterfaceId,
    link_id: [u8; 16],
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

                // Deliver as Reticulum frame, if it belongs to the link
                if carries_link(&buf[..len], &link_id) {
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
    link_id: [u8; 16],
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
            if carries_link(&cx.buf[..len], &self.link_id) {
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
    use rns_core::constants;

    const LINK: [u8; 16] = [0x4C; 16];

    /// A HEADER_1 packet with the given destination type, packet type and
    /// destination.
    fn frame(destination_type: u8, packet_type: u8, destination: &[u8; 16]) -> Vec<u8> {
        let mut frame = vec![(destination_type << 2) | packet_type, 0];
        frame.extend_from_slice(destination);
        frame.push(constants::CONTEXT_NONE);
        frame.extend_from_slice(b"payload");
        frame
    }

    fn link_data(destination: &[u8; 16], text: &[u8]) -> Vec<u8> {
        let mut frame = frame(
            constants::DESTINATION_LINK,
            constants::PACKET_TYPE_DATA,
            destination,
        );
        frame.extend_from_slice(text);
        frame
    }

    #[test]
    fn only_packets_of_its_link_are_carried() {
        assert!(carries_link(
            &frame(
                constants::DESTINATION_LINK,
                constants::PACKET_TYPE_DATA,
                &LINK
            ),
            &LINK
        ));
        assert!(carries_link(
            &frame(
                constants::DESTINATION_LINK,
                constants::PACKET_TYPE_PROOF,
                &LINK
            ),
            &LINK
        ));
        // Another link, announces, link requests, path requests (plain
        // data), single-destination data: not carried.
        assert!(!carries_link(&link_data(&[0x11; 16], b""), &LINK));
        for (destination_type, packet_type) in [
            (
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_ANNOUNCE,
            ),
            (
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_LINKREQUEST,
            ),
            (constants::DESTINATION_PLAIN, constants::PACKET_TYPE_DATA),
            (constants::DESTINATION_SINGLE, constants::PACKET_TYPE_DATA),
            (constants::DESTINATION_LINK, constants::PACKET_TYPE_ANNOUNCE),
        ] {
            assert!(!carries_link(
                &frame(destination_type, packet_type, &LINK),
                &LINK
            ));
        }
        // A transported (HEADER_2) packet is never for a direct path.
        let mut transported = vec![0x40 | 0x0C, 1];
        transported.extend_from_slice(&[0x99; 16]);
        transported.extend_from_slice(&LINK);
        transported.push(0);
        assert!(!carries_link(&transported, &LINK));
        assert!(!carries_link(&[], &LINK));
        assert!(!carries_link(&[0x0C, 0, 0x4C], &LINK));
    }

    #[test]
    fn test_udp_direct_writer() {
        // Create a pair of sockets
        let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        sock_b
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();

        let mut writer = UdpDirectWriter {
            socket: Arc::new(sock_a),
            peer_addr: addr_b,
            link_id: LINK,
            running: Arc::new(AtomicBool::new(true)),
            inline: false,
        };

        // Frames of other traffic are dropped without an error.
        let announce = frame(
            constants::DESTINATION_SINGLE,
            constants::PACKET_TYPE_ANNOUNCE,
            &[0x22; 16],
        );
        writer.send_frame(&announce).unwrap();
        writer.send_frame_confirmed(&announce).unwrap();

        // A frame of the link goes out.
        let data = link_data(&LINK, b"hello direct peer");
        writer.send_frame(&data).unwrap();

        // Receive on other end: only the link's frame.
        let mut buf = [0u8; 128];
        let (len, _src) = sock_b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], &data[..]);
        assert!(sock_b.recv_from(&mut buf).is_err());
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
        let (writer, info) = start_direct_interface(
            local,
            peer_addr,
            InterfaceId(910),
            LINK,
            [1; 16],
            [2; 32],
            tx.clone(),
        )
        .unwrap();
        assert!(!info.out_capable);
        assert!(writer.sends_inline());
        // Served on the driver loop: no reader thread.
        assert!(!std::fs::read_dir("/proc/self/task").unwrap().any(|task| {
            std::fs::read_to_string(task.unwrap().path().join("comm"))
                .is_ok_and(|comm| comm.starts_with("direct-udp-"))
        }));
        let (mut writer, _) =
            crate::interface::wrap_async_writer(writer, InterfaceId(910), "direct", tx, 16);

        // Inbound from the peer; keepalives, strangers and other traffic
        // are skipped.
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        stranger
            .send_to(&link_data(&LINK, b"not from the peer"), local_addr)
            .unwrap();
        peer.send_to(b"RNSH keepalive", local_addr).unwrap();
        peer.send_to(
            &frame(
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_ANNOUNCE,
                &[0x22; 16],
            ),
            local_addr,
        )
        .unwrap();
        let from_peer = link_data(&LINK, b"from the peer");
        peer.send_to(&from_peer, local_addr).unwrap();
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Frame {
                interface_id, data, ..
            } => {
                assert_eq!(interface_id, InterfaceId(910));
                assert_eq!(&*data, &from_peer[..]);
            }
            other => panic!("expected Frame, got {other:?}"),
        }
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());

        // Outbound, sent by the driver directly.
        let to_peer = link_data(&LINK, b"to the peer");
        writer.send_frame(&to_peer).unwrap();
        let mut buf = [0u8; 64];
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], &to_peer[..]);
    }
}
