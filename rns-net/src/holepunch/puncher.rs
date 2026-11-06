//! UDP hole punch execution.
//!
//! Sends punch packets to peer endpoints and listens for valid replies.
//! Punch packet: [MAGIC:"RNSH" 4B] [SESSION_ID:16B] [PUNCH_TOKEN:32B] [SEQ:4B] = 56 bytes
//! ACK packet:   [MAGIC:"RNSA" 4B] [SESSION_ID:16B] [PUNCH_TOKEN:32B] [SEQ:4B] = 56 bytes

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const PUNCH_MAGIC: &[u8; 4] = b"RNSH";
const ACK_MAGIC: &[u8; 4] = b"RNSA";
const PUNCH_PACKET_LEN: usize = 56; // 4 + 16 + 32 + 4
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const PUNCH_DURATION: Duration = Duration::from_secs(10);
/// Upper bound on punch packets sent per session (over all endpoints).
pub const MAX_PUNCH_PACKETS: u32 = 128;
/// Upper bound on ACK packets sent per session.
pub const MAX_ACK_PACKETS: u32 = 128;

/// Timing and packet budget for one punch session.
#[derive(Debug, Clone, Copy)]
struct PunchLimits {
    duration: Duration,
    interval: Duration,
    max_punch_packets: u32,
    max_ack_packets: u32,
}

const DEFAULT_LIMITS: PunchLimits = PunchLimits {
    duration: PUNCH_DURATION,
    interval: PUNCH_INTERVAL,
    max_punch_packets: MAX_PUNCH_PACKETS,
    max_ack_packets: MAX_ACK_PACKETS,
};

/// Result of a completed hole punch.
pub struct PunchResult {
    /// The socket used for punching (same NAT mapping as the probe).
    pub socket: UdpSocket,
    /// The peer address that responded.
    pub peer_addr: SocketAddr,
    /// Measured RTT: time from first punch send to first valid ACK received.
    pub rtt: Duration,
}

/// Status values for the atomic state.
const STATUS_RUNNING: u8 = 0;
const STATUS_SUCCEEDED: u8 = 1;
const STATUS_FAILED: u8 = 2;
const STATUS_CANCELLED: u8 = 3;

/// Handle to a running punch operation.
pub struct PunchHandle {
    status: Arc<AtomicU8>,
    cancel: Arc<AtomicBool>,
    outcome: Outcome,
}

/// Where a punch's result comes from.
enum Outcome {
    /// The punch thread returns it.
    Thread(Option<thread::JoinHandle<Option<PunchResult>>>),
    /// A punch on the driver loop leaves it here before it reports success.
    Loop(Arc<std::sync::Mutex<Option<PunchResult>>>),
}

impl PunchHandle {
    /// Check if the punch is still running.
    pub fn is_running(&self) -> bool {
        self.status.load(Ordering::Relaxed) == STATUS_RUNNING
    }

    /// Check if the punch succeeded.
    pub fn succeeded(&self) -> bool {
        self.status.load(Ordering::Relaxed) == STATUS_SUCCEEDED
    }

    /// Cancel the punch.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Wait for the punch to complete and return the result.
    pub fn join(self) -> Option<PunchResult> {
        match self.outcome {
            Outcome::Thread(mut thread) => thread.take().and_then(|h| h.join().ok().flatten()),
            Outcome::Loop(slot) => slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take(),
        }
    }
}

/// Start UDP hole punching in a background thread.
///
/// `socket` should be the same socket used for the probe (to preserve NAT mapping).
/// `peer_endpoints` are the peer's public endpoints discovered via probe.
/// `local_endpoints` are the peer's LAN endpoints for direct-network fallback.
/// `session_id` and `punch_token` are used for packet authentication.
///
/// Punch and ACK packets are only exchanged with sources whose IP matches one
/// of the given endpoints (the port may differ), and the number of packets
/// sent per session is capped by [`MAX_PUNCH_PACKETS`] and [`MAX_ACK_PACKETS`].
pub fn start_udp_punch(
    socket: UdpSocket,
    peer_endpoints: Vec<SocketAddr>,
    local_endpoints: Vec<SocketAddr>,
    session_id: [u8; 16],
    punch_token: [u8; 32],
) -> io::Result<PunchHandle> {
    start_udp_punch_with_limits(
        socket,
        peer_endpoints,
        local_endpoints,
        session_id,
        punch_token,
        DEFAULT_LIMITS,
    )
}

fn start_udp_punch_with_limits(
    socket: UdpSocket,
    peer_endpoints: Vec<SocketAddr>,
    local_endpoints: Vec<SocketAddr>,
    session_id: [u8; 16],
    punch_token: [u8; 32],
    limits: PunchLimits,
) -> io::Result<PunchHandle> {
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_nonblocking(false)?;

    let status = Arc::new(AtomicU8::new(STATUS_RUNNING));
    let cancel = Arc::new(AtomicBool::new(false));
    let status_clone = status.clone();
    let cancel_clone = cancel.clone();
    let all_endpoints: Vec<SocketAddr> =
        peer_endpoints.into_iter().chain(local_endpoints).collect();

    let handle = thread::Builder::new()
        .name("udp-punch".into())
        .spawn(move || {
            run_udp_punch(
                socket,
                all_endpoints,
                session_id,
                punch_token,
                status_clone,
                cancel_clone,
                limits,
            )
        })?;

    Ok(PunchHandle {
        status,
        cancel,
        outcome: Outcome::Thread(Some(handle)),
    })
}

/// [`start_udp_punch`] on the driver loop that `tx` feeds, instead of a
/// thread of its own (see [`crate::engine::FOLD_SERVICES`]).
pub(crate) fn start_udp_punch_on_loop(
    socket: UdpSocket,
    peer_endpoints: Vec<SocketAddr>,
    local_endpoints: Vec<SocketAddr>,
    session_id: [u8; 16],
    punch_token: [u8; 32],
    tx: &crate::event::EventSender,
) -> io::Result<PunchHandle> {
    start_udp_punch_on_loop_with_limits(
        socket,
        peer_endpoints.into_iter().chain(local_endpoints).collect(),
        session_id,
        punch_token,
        tx,
        DEFAULT_LIMITS,
    )
}

fn start_udp_punch_on_loop_with_limits(
    socket: UdpSocket,
    endpoints: Vec<SocketAddr>,
    session_id: [u8; 16],
    punch_token: [u8; 32],
    tx: &crate::event::EventSender,
    limits: PunchLimits,
) -> io::Result<PunchHandle> {
    use std::os::fd::AsRawFd;
    socket.set_nonblocking(true)?;
    let status = Arc::new(AtomicU8::new(STATUS_RUNNING));
    let cancel = Arc::new(AtomicBool::new(false));
    let slot = Arc::new(std::sync::Mutex::new(None));
    let now = Instant::now();
    tx.register_source(
        super::next_loop_key(),
        Box::new(PunchSource {
            fd: socket.as_raw_fd(),
            socket: Some(socket),
            punch: PunchState::new(endpoints, session_id, punch_token, limits),
            next_send: now,
            status: status.clone(),
            cancel: cancel.clone(),
            slot: slot.clone(),
        }),
    )?;
    Ok(PunchHandle {
        status,
        cancel,
        outcome: Outcome::Loop(slot),
    })
}

/// One punch session's progress: what was sent, and what the peer
/// confirmed.
struct PunchState {
    endpoints: Vec<SocketAddr>,
    session_id: [u8; 16],
    punch_token: [u8; 32],
    limits: PunchLimits,
    start: Instant,
    seq: u32,
    punch_packets_sent: u32,
    ack_packets_sent: u32,
    we_got_ack: bool,
    they_got_ack: bool,
    verified_peer: Option<SocketAddr>,
    first_ack_time: Option<Instant>,
}

impl PunchState {
    fn new(
        endpoints: Vec<SocketAddr>,
        session_id: [u8; 16],
        punch_token: [u8; 32],
        limits: PunchLimits,
    ) -> Self {
        Self {
            endpoints,
            session_id,
            punch_token,
            limits,
            start: Instant::now(),
            seq: 0,
            punch_packets_sent: 0,
            ack_packets_sent: 0,
            we_got_ack: false,
            they_got_ack: false,
            verified_peer: None,
            first_ack_time: None,
        }
    }

    fn end(&self) -> Instant {
        self.start + self.limits.duration
    }

    /// Send a punch packet to every peer endpoint, within the budget.
    fn send_round(&mut self, socket: &UdpSocket) {
        let punch_pkt = build_punch_packet(&self.session_id, &self.punch_token, self.seq);
        for ep in &self.endpoints {
            if self.punch_packets_sent >= self.limits.max_punch_packets {
                break;
            }
            let _ = socket.send_to(&punch_pkt, ep);
            self.punch_packets_sent += 1;
        }
        self.seq = self.seq.wrapping_add(1);
    }

    /// Handle one received datagram, answering a valid punch. Returns the
    /// verified peer and the round trip once both sides confirmed.
    fn receive(
        &mut self,
        socket: &UdpSocket,
        data: &[u8],
        src: SocketAddr,
    ) -> Option<(SocketAddr, Duration)> {
        if data.len() != PUNCH_PACKET_LEN || !self.endpoints.iter().any(|ep| ep.ip() == src.ip()) {
            return None;
        }
        if &data[..4] == PUNCH_MAGIC {
            // Received a punch from peer — verify token
            if verify_punch_packet(data, &self.session_id, &self.punch_token) {
                // Send ACK back
                let peer_seq = u32::from_be_bytes([data[52], data[53], data[54], data[55]]);
                if self.ack_packets_sent < self.limits.max_ack_packets {
                    let ack = build_ack_packet(&self.session_id, &self.punch_token, peer_seq);
                    let _ = socket.send_to(&ack, src);
                    self.ack_packets_sent += 1;
                }
                self.they_got_ack = true;
                self.verified_peer = Some(src);
            }
        } else if &data[..4] == ACK_MAGIC {
            // Received ACK for our punch
            if verify_ack_packet(data, &self.session_id, &self.punch_token) {
                self.we_got_ack = true;
                self.first_ack_time.get_or_insert_with(Instant::now);
                if self.verified_peer.is_none() {
                    self.verified_peer = Some(src);
                }
            }
        }
        // Both sides confirmed → success
        if self.we_got_ack && self.they_got_ack {
            let rtt = self
                .first_ack_time
                .map(|t| t - self.start)
                .unwrap_or(self.start.elapsed());
            return self.verified_peer.map(|peer| (peer, rtt));
        }
        None
    }
}

/// A punch on the driver loop: the socket is read when readable, and a
/// timer sends each round and ends the punch.
struct PunchSource {
    /// The socket's descriptor, kept for deregistering after the socket
    /// was handed over with the result.
    fd: std::os::fd::RawFd,
    socket: Option<UdpSocket>,
    punch: PunchState,
    next_send: Instant,
    status: Arc<AtomicU8>,
    cancel: Arc<AtomicBool>,
    slot: Arc<std::sync::Mutex<Option<PunchResult>>>,
}

impl PunchSource {
    fn finish(&mut self, outcome: u8) -> crate::event::SourceStatus {
        if self.status.load(Ordering::Relaxed) == STATUS_RUNNING {
            self.status.store(outcome, Ordering::Relaxed);
        }
        crate::event::SourceStatus::Remove
    }
}

impl crate::event::LoopSource for PunchSource {
    fn fd(&self) -> std::os::fd::RawFd {
        self.fd
    }

    fn stopped(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn on_ready(&mut self, cx: &mut crate::event::LoopContext<'_>) -> crate::event::SourceStatus {
        if self.cancel.load(Ordering::Relaxed) {
            return self.finish(STATUS_CANCELLED);
        }
        let Some(socket) = self.socket.as_ref() else {
            return crate::event::SourceStatus::Remove;
        };
        loop {
            let (len, src) = match socket.recv_from(cx.buf) {
                Ok(received) => received,
                // An ICMP error from an earlier send surfaces here.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(_) => return crate::event::SourceStatus::Rearm,
            };
            if let Some((peer_addr, rtt)) = self.punch.receive(socket, &cx.buf[..len], src) {
                // The result is in place before success is reported.
                let socket = self.socket.take().expect("checked above");
                *self
                    .slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(PunchResult {
                    socket,
                    peer_addr,
                    rtt,
                });
                return self.finish(STATUS_SUCCEEDED);
            }
        }
    }

    fn on_removed(&mut self) {
        // Swept as cancelled, or the driver is going away.
        self.finish(if self.cancel.load(Ordering::Relaxed) {
            STATUS_CANCELLED
        } else {
            STATUS_FAILED
        });
    }

    fn deadline(&self) -> Option<Instant> {
        Some(self.next_send.min(self.punch.end()))
    }

    fn on_timer(&mut self, _cx: &mut crate::event::LoopContext<'_>) -> crate::event::SourceStatus {
        if self.cancel.load(Ordering::Relaxed) {
            return self.finish(STATUS_CANCELLED);
        }
        let now = Instant::now();
        if now >= self.punch.end() {
            return self.finish(STATUS_FAILED);
        }
        if now >= self.next_send {
            if let Some(socket) = self.socket.as_ref() {
                self.punch.send_round(socket);
            }
            self.next_send = now + self.punch.limits.interval;
        }
        crate::event::SourceStatus::Rearm
    }
}

fn run_udp_punch(
    socket: UdpSocket,
    all_endpoints: Vec<SocketAddr>,
    session_id: [u8; 16],
    punch_token: [u8; 32],
    status: Arc<AtomicU8>,
    cancel: Arc<AtomicBool>,
    limits: PunchLimits,
) -> Option<PunchResult> {
    let mut punch = PunchState::new(all_endpoints, session_id, punch_token, limits);

    while Instant::now() < punch.end() {
        if cancel.load(Ordering::Relaxed) {
            status.store(STATUS_CANCELLED, Ordering::Relaxed);
            return None;
        }

        punch.send_round(&socket);

        // Listen for replies
        let recv_deadline = Instant::now() + limits.interval;
        let mut buf = [0u8; 128];
        while Instant::now() < recv_deadline {
            let remaining = recv_deadline.duration_since(Instant::now());
            let _ = socket.set_read_timeout(Some(remaining.max(Duration::from_millis(1))));

            let (len, src) = match socket.recv_from(&mut buf) {
                Ok(r) => r,
                // An ICMP error from an earlier send surfaces here; keep
                // listening until the interval ends instead of sending again.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    continue
                }
                Err(_) => break,
            };

            if let Some((peer_addr, rtt)) = punch.receive(&socket, &buf[..len], src) {
                status.store(STATUS_SUCCEEDED, Ordering::Relaxed);
                // Set socket back to blocking with a reasonable timeout
                let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));
                return Some(PunchResult {
                    socket,
                    peer_addr,
                    rtt,
                });
            }
        }
    }

    status.store(STATUS_FAILED, Ordering::Relaxed);
    None
}

fn build_punch_packet(session_id: &[u8; 16], punch_token: &[u8; 32], seq: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(PUNCH_PACKET_LEN);
    pkt.extend_from_slice(PUNCH_MAGIC);
    pkt.extend_from_slice(session_id);
    pkt.extend_from_slice(punch_token);
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt
}

fn build_ack_packet(session_id: &[u8; 16], punch_token: &[u8; 32], seq: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(PUNCH_PACKET_LEN);
    pkt.extend_from_slice(ACK_MAGIC);
    pkt.extend_from_slice(session_id);
    pkt.extend_from_slice(punch_token);
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt
}

fn verify_punch_packet(data: &[u8], session_id: &[u8; 16], punch_token: &[u8; 32]) -> bool {
    if data.len() != PUNCH_PACKET_LEN {
        return false;
    }
    if &data[..4] != PUNCH_MAGIC {
        return false;
    }
    &data[4..20] == session_id && &data[20..52] == punch_token
}

fn verify_ack_packet(data: &[u8], session_id: &[u8; 16], punch_token: &[u8; 32]) -> bool {
    if data.len() != PUNCH_PACKET_LEN {
        return false;
    }
    if &data[..4] != ACK_MAGIC {
        return false;
    }
    &data[4..20] == session_id && &data[20..52] == punch_token
}

/// Build a keepalive punch packet (empty payload, just the punch header).
/// Used to maintain NAT mappings on the direct UDP interface.
pub fn build_keepalive_packet(session_id: &[u8; 16], punch_token: &[u8; 32]) -> Vec<u8> {
    build_punch_packet(session_id, punch_token, u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_punch_packet_roundtrip() {
        let session_id = [0xAA; 16];
        let token = [0xBB; 32];
        let pkt = build_punch_packet(&session_id, &token, 42);
        assert_eq!(pkt.len(), PUNCH_PACKET_LEN);
        assert!(verify_punch_packet(&pkt, &session_id, &token));
    }

    #[test]
    fn test_ack_packet_roundtrip() {
        let session_id = [0xCC; 16];
        let token = [0xDD; 32];
        let pkt = build_ack_packet(&session_id, &token, 7);
        assert_eq!(pkt.len(), PUNCH_PACKET_LEN);
        assert!(verify_ack_packet(&pkt, &session_id, &token));
    }

    #[test]
    fn test_wrong_token_rejected() {
        let session_id = [0xAA; 16];
        let token = [0xBB; 32];
        let wrong_token = [0xFF; 32];
        let pkt = build_punch_packet(&session_id, &token, 0);
        assert!(!verify_punch_packet(&pkt, &session_id, &wrong_token));
    }

    #[test]
    fn test_localhost_punch() {
        // Two sockets on localhost simulate a punch
        let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let session_id = [0x11; 16];
        let token = [0x22; 32];

        let handle_a = start_udp_punch(sock_a, vec![addr_b], vec![], session_id, token).unwrap();

        let handle_b = start_udp_punch(sock_b, vec![addr_a], vec![], session_id, token).unwrap();

        let result_a = handle_a.join();
        let result_b = handle_b.join();

        assert!(result_a.is_some(), "Punch A should succeed");
        assert!(result_b.is_some(), "Punch B should succeed");

        let result_a = result_a.unwrap();
        let result_b = result_b.unwrap();
        assert_eq!(result_a.peer_addr, addr_b);
        assert_eq!(result_b.peer_addr, addr_a);
    }

    fn short_limits(max_punch_packets: u32) -> PunchLimits {
        PunchLimits {
            duration: Duration::from_millis(600),
            interval: Duration::from_millis(5),
            max_punch_packets,
            max_ack_packets: MAX_ACK_PACKETS,
        }
    }

    #[test]
    fn punch_packet_count_is_capped_per_session() {
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target_addr = target.local_addr().unwrap();

        let handle = start_udp_punch_with_limits(
            sender,
            vec![target_addr],
            vec![],
            [0x11; 16],
            [0x22; 32],
            short_limits(5),
        )
        .unwrap();
        assert!(handle.join().is_none());

        target
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buf = [0u8; 128];
        let mut received = 0;
        while target.recv_from(&mut buf).is_ok() {
            received += 1;
        }
        assert_eq!(received, 5);
    }

    #[test]
    fn punch_from_other_source_ip_is_ignored() {
        // The puncher targets 127.0.0.1; a valid punch from 127.0.0.2 must
        // not be acknowledged or accepted as the peer.
        let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target_addr = target.local_addr().unwrap();
        let other = match UdpSocket::bind("127.0.0.2:0") {
            Ok(s) => s,
            Err(_) => return, // loopback alias not available on this host
        };
        other
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();

        let session_id = [0x33; 16];
        let token = [0x44; 32];
        let handle = start_udp_punch_with_limits(
            sock_a,
            vec![target_addr],
            vec![],
            session_id,
            token,
            short_limits(MAX_PUNCH_PACKETS),
        )
        .unwrap();

        other
            .send_to(&build_punch_packet(&session_id, &token, 0), addr_a)
            .unwrap();
        other
            .send_to(&build_ack_packet(&session_id, &token, 0), addr_a)
            .unwrap();
        let mut buf = [0u8; 128];
        assert!(other.recv_from(&mut buf).is_err(), "no ACK expected");
        assert!(handle.join().is_none());
    }

    #[test]
    fn localhost_punch_on_the_driver_loop() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let session_id = [0x42; 16];
        let token = [0x99; 32];
        let (tx, rx) = crate::event::channel();

        let handle_a =
            start_udp_punch_on_loop(sock_a, vec![addr_b], vec![], session_id, token, &tx).unwrap();
        let handle_b =
            start_udp_punch_on_loop(sock_b, vec![addr_a], vec![], session_id, token, &tx).unwrap();
        // Both are served by the receiver while it waits.
        let deadline = Instant::now() + Duration::from_secs(5);
        while (handle_a.is_running() || handle_b.is_running()) && Instant::now() < deadline {
            let _ = rx.recv_timeout(Duration::from_millis(20));
        }
        assert!(handle_a.succeeded());
        assert!(handle_b.succeeded());
        let result_a = handle_a.join().unwrap();
        let result_b = handle_b.join().unwrap();
        assert_eq!(result_a.peer_addr, addr_b);
        assert_eq!(result_b.peer_addr, addr_a);
        assert_eq!(result_a.socket.local_addr().unwrap(), addr_a);
    }

    #[test]
    fn punch_on_the_driver_loop_fails_and_cancels() {
        let silent_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (tx, rx) = crate::event::channel();
        let limits = PunchLimits {
            duration: Duration::from_millis(300),
            ..short_limits(MAX_PUNCH_PACKETS)
        };
        let failing = start_udp_punch_on_loop_with_limits(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            vec![silent_peer.local_addr().unwrap()],
            [1; 16],
            [2; 32],
            &tx,
            limits,
        )
        .unwrap();
        let cancelled = start_udp_punch_on_loop_with_limits(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            vec![silent_peer.local_addr().unwrap()],
            [3; 16],
            [4; 32],
            &tx,
            DEFAULT_LIMITS,
        )
        .unwrap();
        cancelled.cancel();
        let deadline = Instant::now() + Duration::from_secs(3);
        while (failing.is_running() || cancelled.is_running()) && Instant::now() < deadline {
            let _ = rx.recv_timeout(Duration::from_millis(20));
        }
        assert!(!failing.is_running() && !failing.succeeded());
        assert!(failing.join().is_none());
        assert_eq!(cancelled.status.load(Ordering::Relaxed), STATUS_CANCELLED);
    }
}
