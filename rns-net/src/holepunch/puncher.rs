//! UDP hole punch execution.
//!
//! Sends punch packets to peer endpoints and listens for valid replies.
//! Punch packet: [MAGIC:"RNSH" 4B] [SESSION_ID:16B] [NONCE:16B] [TAG:16B] = 52 bytes
//! ACK packet:   [MAGIC:"RNSA" 4B] [SESSION_ID:16B] [NONCE:16B] [TAG:16B] = 52 bytes
//!
//! The nonce of a punch is random; an ACK echoes the nonce of the punch it
//! answers. The tag is the first 16 bytes of HMAC-SHA256 over the preceding
//! 36 bytes, keyed with the session's punch token, which never appears on
//! the wire. An ACK counts only if it echoes a nonce this side sent to the
//! IP it comes from.
//!
//! The candidates are the peer's public (reflexive) endpoint and its host
//! candidates, addresses of its own interfaces for a peer on the same
//! network. A host candidate that is acknowledged is preferred: once the
//! punch has succeeded over another candidate, it waits up to
//! [`HOST_GRACE`] for a host candidate still unanswered.
//!
//! A fresh, authenticated punch from a port of a candidate's IP that is
//! not a candidate itself (a NAT that maps each destination to its own
//! port) makes that address a peer-reflexive candidate, punched like the
//! others (see [`MAX_PEER_REFLEXIVE`]).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const PUNCH_MAGIC: &[u8; 4] = b"RNSH";
const ACK_MAGIC: &[u8; 4] = b"RNSA";
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;
const PUNCH_PACKET_LEN: usize = 4 + 16 + NONCE_LEN + TAG_LEN;
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const PUNCH_DURATION: Duration = Duration::from_secs(10);
/// Upper bound on punch packets sent per session (over all endpoints).
pub const MAX_PUNCH_PACKETS: u32 = 128;
/// Upper bound on ACK packets sent per session.
pub const MAX_ACK_PACKETS: u32 = 128;
/// Most candidate endpoints one punch session sends to; any beyond are
/// dropped.
pub const MAX_PUNCH_CANDIDATES: usize = 4;
/// Punch packets sent at the full rate to an endpoint that has not shown
/// it is the peer (by sending a valid punch or acknowledgement).
pub const UNVERIFIED_BURST: u32 = 16;
/// After its burst, an endpoint that has not answered gets one punch
/// packet per this interval, enough to keep a NAT mapping toward it open.
const UNVERIFIED_INTERVAL: Duration = Duration::from_secs(1);
/// Most peer-reflexive candidates one punch session learns.
pub const MAX_PEER_REFLEXIVE: usize = 2;
/// Punch nonces remembered per session, so that a replayed punch does not
/// teach a peer-reflexive candidate.
const MAX_SEEN_NONCES: usize = 256;
/// How long a punch that succeeded over its public endpoint waits for a
/// host candidate to answer as well, so that peers on the same network use
/// it.
pub const HOST_GRACE: Duration = Duration::from_millis(500);

/// Timing and packet budget for one punch session.
#[derive(Debug, Clone, Copy)]
struct PunchLimits {
    duration: Duration,
    interval: Duration,
    max_punch_packets: u32,
    max_ack_packets: u32,
    unverified_burst: u32,
    unverified_interval: Duration,
    host_grace: Duration,
}

const DEFAULT_LIMITS: PunchLimits = PunchLimits {
    duration: PUNCH_DURATION,
    interval: PUNCH_INTERVAL,
    max_punch_packets: MAX_PUNCH_PACKETS,
    max_ack_packets: MAX_ACK_PACKETS,
    unverified_burst: UNVERIFIED_BURST,
    unverified_interval: UNVERIFIED_INTERVAL,
    host_grace: HOST_GRACE,
};

/// Whether `addr` can be a punch target at all: a unicast address with a
/// port. Which unicast ranges a peer may name is decided before the punch
/// starts (see [`super::admission`]).
fn plausible_target(addr: &SocketAddr) -> bool {
    let ip = match addr.ip() {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(v6),
        },
        ip => ip,
    };
    let unicast = match ip {
        std::net::IpAddr::V4(v4) => !v4.is_broadcast() && !v4.is_multicast(),
        std::net::IpAddr::V6(v6) => !v6.is_multicast(),
    };
    addr.port() != 0 && !ip.is_unspecified() && unicast
}

/// The endpoints a punch sends to, each with whether it is a host
/// candidate: plausible targets, the peer's public ones first, without
/// repeats, at most [`MAX_PUNCH_CANDIDATES`].
fn punch_candidates(
    peer_endpoints: Vec<SocketAddr>,
    host_endpoints: Vec<SocketAddr>,
) -> io::Result<Vec<(SocketAddr, bool)>> {
    let mut candidates: Vec<(SocketAddr, bool)> = Vec::new();
    let tagged = peer_endpoints
        .into_iter()
        .map(|ep| (ep, false))
        .chain(host_endpoints.into_iter().map(|ep| (ep, true)));
    for (ep, host) in tagged {
        if plausible_target(&ep) && !candidates.iter().any(|(c, _)| *c == ep) {
            candidates.push((ep, host));
        }
    }
    candidates.truncate(MAX_PUNCH_CANDIDATES);
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no endpoint to punch toward",
        ));
    }
    Ok(candidates)
}

/// Result of a completed hole punch.
pub struct PunchResult {
    /// The socket used for punching (same NAT mapping as the probe).
    pub socket: UdpSocket,
    /// The peer address that responded.
    pub peer_addr: SocketAddr,
    /// Peer-reflexive candidates the punch learned.
    pub learned: Vec<SocketAddr>,
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
/// `local_endpoints` are the peer's host candidates, addresses on a network
/// this node shares with it, preferred when they answer (see
/// [`HOST_GRACE`]).
/// `session_id` and `punch_token` are used for packet authentication.
///
/// Punch and ACK packets are only exchanged with sources whose IP matches one
/// of the given endpoints (the port may differ), and the number of packets
/// sent per session is capped by [`MAX_PUNCH_PACKETS`] and [`MAX_ACK_PACKETS`].
/// At most [`MAX_PUNCH_CANDIDATES`] endpoints are used, and an endpoint gets
/// only [`UNVERIFIED_BURST`] packets, then one a second, until a valid punch
/// or acknowledgement from its IP shows the peer is there. Unspecified,
/// multicast and broadcast endpoints are never sent to.
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
    let all_endpoints = punch_candidates(peer_endpoints, local_endpoints)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_nonblocking(false)?;

    let status = Arc::new(AtomicU8::new(STATUS_RUNNING));
    let cancel = Arc::new(AtomicBool::new(false));
    let status_clone = status.clone();
    let cancel_clone = cancel.clone();

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
        peer_endpoints,
        local_endpoints,
        session_id,
        punch_token,
        tx,
        DEFAULT_LIMITS,
    )
}

#[allow(clippy::too_many_arguments)]
fn start_udp_punch_on_loop_with_limits(
    socket: UdpSocket,
    peer_endpoints: Vec<SocketAddr>,
    host_endpoints: Vec<SocketAddr>,
    session_id: [u8; 16],
    punch_token: [u8; 32],
    tx: &crate::event::EventSender,
    limits: PunchLimits,
) -> io::Result<PunchHandle> {
    use std::os::fd::AsRawFd;
    let endpoints = punch_candidates(peer_endpoints, host_endpoints)?;
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
    endpoints: Vec<Candidate>,
    session_id: [u8; 16],
    punch_token: [u8; 32],
    limits: PunchLimits,
    start: Instant,
    /// The nonce of every punch sent, with the IP it went to.
    sent_nonces: Vec<([u8; NONCE_LEN], std::net::IpAddr)>,
    punch_packets_sent: u32,
    ack_packets_sent: u32,
    we_got_ack: bool,
    they_got_ack: bool,
    verified_peer: Option<SocketAddr>,
    /// Where acknowledgements of our punches came from, in order: each
    /// carries traffic both ways.
    acked_from: Vec<SocketAddr>,
    first_ack_time: Option<Instant>,
    /// When both sides had first confirmed.
    succeeded_at: Option<Instant>,
    /// Nonces of the punches received, for telling a replay.
    seen_nonces: Vec<[u8; NONCE_LEN]>,
    /// Peer-reflexive candidates learned, in order.
    learned: Vec<SocketAddr>,
}

/// One endpoint a punch sends to.
struct Candidate {
    addr: SocketAddr,
    /// A host candidate of the peer, rather than its public endpoint.
    host: bool,
    /// A valid punch or acknowledgement came from its IP.
    verified: bool,
    /// An acknowledgement of our punch came from this very address.
    acked: bool,
    sent: u32,
    last_sent: Option<Instant>,
}

impl Candidate {
    /// Whether a punch packet to it is due in the round at `now`.
    fn due(&self, now: Instant, limits: &PunchLimits) -> bool {
        self.verified
            || self.sent < limits.unverified_burst
            || self.last_sent.is_none_or(|last| {
                now.saturating_duration_since(last) >= limits.unverified_interval
            })
    }
}

impl PunchState {
    fn new(
        endpoints: Vec<(SocketAddr, bool)>,
        session_id: [u8; 16],
        punch_token: [u8; 32],
        limits: PunchLimits,
    ) -> Self {
        Self {
            endpoints: endpoints
                .into_iter()
                .map(|(addr, host)| Candidate {
                    addr,
                    host,
                    verified: false,
                    acked: false,
                    sent: 0,
                    last_sent: None,
                })
                .collect(),
            session_id,
            punch_token,
            limits,
            start: Instant::now(),
            sent_nonces: Vec::new(),
            punch_packets_sent: 0,
            ack_packets_sent: 0,
            we_got_ack: false,
            they_got_ack: false,
            verified_peer: None,
            acked_from: Vec::new(),
            first_ack_time: None,
            succeeded_at: None,
            seen_nonces: Vec::new(),
            learned: Vec::new(),
        }
    }

    /// A fresh, authenticated punch came from `src`, at the IP of a
    /// candidate: if that address is no candidate, punch it too, as a
    /// peer-reflexive candidate (verified, since the peer is there).
    fn learn_peer_reflexive(&mut self, src: SocketAddr) {
        if self.endpoints.iter().any(|ep| ep.addr == src)
            || self.learned.len() >= MAX_PEER_REFLEXIVE
            || self.endpoints.len() >= MAX_PUNCH_CANDIDATES
            || !plausible_target(&src)
        {
            return;
        }
        self.endpoints.push(Candidate {
            addr: src,
            host: false,
            verified: true,
            acked: false,
            sent: 0,
            last_sent: None,
        });
        self.learned.push(src);
    }

    fn end(&self) -> Instant {
        self.start + self.limits.duration
    }

    /// Send a punch packet to every peer endpoint that is due one, within
    /// the budget.
    fn send_round(&mut self, socket: &UdpSocket) {
        use rns_crypto::Rng;
        let now = Instant::now();
        for ep in &mut self.endpoints {
            if self.punch_packets_sent >= self.limits.max_punch_packets {
                break;
            }
            if !ep.due(now, &self.limits) {
                continue;
            }
            let mut nonce = [0u8; NONCE_LEN];
            rns_crypto::OsRng.fill_bytes(&mut nonce);
            let punch_pkt = build_punch_packet(&self.session_id, &self.punch_token, &nonce);
            self.sent_nonces.push((nonce, ep.addr.ip()));
            let _ = socket.send_to(&punch_pkt, ep.addr);
            ep.sent += 1;
            ep.last_sent = Some(now);
            self.punch_packets_sent += 1;
        }
    }

    /// A valid packet came from `src`: the endpoints at its IP are the peer.
    fn verify_source(&mut self, src: SocketAddr) {
        for ep in &mut self.endpoints {
            if ep.addr.ip() == src.ip() {
                ep.verified = true;
            }
        }
    }

    /// Handle one received datagram, answering a valid punch. Returns the
    /// verified peer and the round trip once both sides confirmed.
    fn receive(
        &mut self,
        socket: &UdpSocket,
        data: &[u8],
        src: SocketAddr,
    ) -> Option<(SocketAddr, Duration)> {
        if data.len() != PUNCH_PACKET_LEN
            || !self.endpoints.iter().any(|ep| ep.addr.ip() == src.ip())
        {
            return None;
        }
        if let Some(nonce) = open_control(data, PUNCH_MAGIC, &self.session_id, &self.punch_token) {
            let fresh = !self.seen_nonces.contains(&nonce);
            if fresh {
                if self.seen_nonces.len() >= MAX_SEEN_NONCES {
                    self.seen_nonces.remove(0);
                }
                self.seen_nonces.push(nonce);
                self.learn_peer_reflexive(src);
            }
            // A punch from the peer: acknowledge it, echoing its nonce.
            if self.ack_packets_sent < self.limits.max_ack_packets {
                let ack = build_ack_packet(&self.session_id, &self.punch_token, &nonce);
                let _ = socket.send_to(&ack, src);
                self.ack_packets_sent += 1;
            }
            self.they_got_ack = true;
            self.verified_peer = Some(src);
            self.verify_source(src);
        } else if let Some(nonce) =
            open_control(data, ACK_MAGIC, &self.session_id, &self.punch_token)
        {
            // An ACK counts only for a punch we sent to where it came from.
            let ours = self
                .sent_nonces
                .iter()
                .any(|(sent, ip)| *sent == nonce && *ip == src.ip());
            if ours {
                self.we_got_ack = true;
                self.first_ack_time.get_or_insert_with(Instant::now);
                if self.verified_peer.is_none() {
                    self.verified_peer = Some(src);
                }
                if !self.acked_from.contains(&src) {
                    self.acked_from.push(src);
                }
                for ep in &mut self.endpoints {
                    if ep.addr == src {
                        ep.acked = true;
                    }
                }
                self.verify_source(src);
            }
        }
        self.ready(Instant::now())
    }

    /// The peer address and round trip, once both sides have confirmed:
    /// an acknowledged host candidate if there is one, otherwise (after
    /// waiting [`HOST_GRACE`] for a host candidate still unanswered) where
    /// the first acknowledgement came from.
    fn ready(&mut self, now: Instant) -> Option<(SocketAddr, Duration)> {
        if !(self.we_got_ack && self.they_got_ack) {
            return None;
        }
        let succeeded_at = *self.succeeded_at.get_or_insert(now);
        let rtt = self
            .first_ack_time
            .map(|t| t - self.start)
            .unwrap_or(self.start.elapsed());
        if let Some(host) = self.endpoints.iter().find(|ep| ep.host && ep.acked) {
            return Some((host.addr, rtt));
        }
        let host_pending = self.endpoints.iter().any(|ep| ep.host && !ep.acked);
        if host_pending && now < succeeded_at + self.limits.host_grace && now < self.end() {
            return None;
        }
        self.acked_from
            .first()
            .copied()
            .or(self.verified_peer)
            .map(|peer| (peer, rtt))
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
    /// Hand over the socket with the result, then report success.
    fn succeed(&mut self, peer_addr: SocketAddr, rtt: Duration) -> crate::event::SourceStatus {
        let Some(socket) = self.socket.take() else {
            return crate::event::SourceStatus::Remove;
        };
        *self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(PunchResult {
            socket,
            peer_addr,
            learned: self.punch.learned.clone(),
            rtt,
        });
        self.finish(STATUS_SUCCEEDED)
    }

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
                return self.succeed(peer_addr, rtt);
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
        if let Some((peer_addr, rtt)) = self.punch.ready(now) {
            return self.succeed(peer_addr, rtt);
        }
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
    all_endpoints: Vec<(SocketAddr, bool)>,
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
                    learned: punch.learned.clone(),
                    rtt,
                });
            }
        }
        if let Some((peer_addr, rtt)) = punch.ready(Instant::now()) {
            status.store(STATUS_SUCCEEDED, Ordering::Relaxed);
            let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));
            return Some(PunchResult {
                socket,
                peer_addr,
                learned: punch.learned.clone(),
                rtt,
            });
        }
    }

    status.store(STATUS_FAILED, Ordering::Relaxed);
    None
}

fn build_control(
    magic: &[u8; 4],
    session_id: &[u8; 16],
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(PUNCH_PACKET_LEN);
    pkt.extend_from_slice(magic);
    pkt.extend_from_slice(session_id);
    pkt.extend_from_slice(nonce);
    let tag = rns_crypto::hmac::hmac_sha256(key, &pkt);
    pkt.extend_from_slice(&tag[..TAG_LEN]);
    pkt
}

/// The nonce of `data`, if it is a `magic` packet of the session with a
/// valid tag.
fn open_control(
    data: &[u8],
    magic: &[u8; 4],
    session_id: &[u8; 16],
    key: &[u8; 32],
) -> Option<[u8; NONCE_LEN]> {
    if data.len() != PUNCH_PACKET_LEN || &data[..4] != magic || data[4..20] != session_id[..] {
        return None;
    }
    let signed = &data[..PUNCH_PACKET_LEN - TAG_LEN];
    let tag = rns_crypto::hmac::hmac_sha256(key, signed);
    if !super::constant_time_eq(&tag[..TAG_LEN], &data[signed.len()..]) {
        return None;
    }
    data[20..20 + NONCE_LEN].try_into().ok()
}

fn build_punch_packet(session_id: &[u8; 16], punch_token: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    build_control(PUNCH_MAGIC, session_id, punch_token, nonce)
}

fn build_ack_packet(session_id: &[u8; 16], punch_token: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    build_control(ACK_MAGIC, session_id, punch_token, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_punch_packet_roundtrip() {
        let session_id = [0xAA; 16];
        let token = [0xBB; 32];
        let pkt = build_punch_packet(&session_id, &token, &[42; 16]);
        assert_eq!(pkt.len(), PUNCH_PACKET_LEN);
        assert_eq!(
            open_control(&pkt, PUNCH_MAGIC, &session_id, &token),
            Some([42; 16])
        );
        // The key never appears on the wire.
        assert!(!pkt.windows(32).any(|w| w == token));
        assert_eq!(open_control(&pkt, ACK_MAGIC, &session_id, &token), None);
    }

    #[test]
    fn test_ack_packet_roundtrip() {
        let session_id = [0xCC; 16];
        let token = [0xDD; 32];
        let pkt = build_ack_packet(&session_id, &token, &[7; 16]);
        assert_eq!(pkt.len(), PUNCH_PACKET_LEN);
        assert_eq!(
            open_control(&pkt, ACK_MAGIC, &session_id, &token),
            Some([7; 16])
        );
    }

    #[test]
    fn test_wrong_token_or_session_or_tampering_rejected() {
        let session_id = [0xAA; 16];
        let token = [0xBB; 32];
        let pkt = build_punch_packet(&session_id, &token, &[1; 16]);
        assert!(open_control(&pkt, PUNCH_MAGIC, &session_id, &[0xFF; 32]).is_none());
        assert!(open_control(&pkt, PUNCH_MAGIC, &[0xAB; 16], &token).is_none());
        let mut tampered = pkt.clone();
        tampered[25] ^= 1;
        assert!(open_control(&tampered, PUNCH_MAGIC, &session_id, &token).is_none());
        assert!(open_control(&pkt[..51], PUNCH_MAGIC, &session_id, &token).is_none());
    }

    #[test]
    fn punch_nonces_are_random() {
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut punch = PunchState::new(
            vec![(target.local_addr().unwrap(), false)],
            [1; 16],
            [2; 32],
            DEFAULT_LIMITS,
        );
        punch.send_round(&sender);
        punch.send_round(&sender);
        assert_eq!(punch.sent_nonces.len(), 2);
        assert_ne!(punch.sent_nonces[0].0, punch.sent_nonces[1].0);
        assert_ne!(punch.sent_nonces[0].0, [0; 16]);
    }

    #[test]
    fn ack_counts_only_with_a_nonce_sent_to_its_source() {
        let session_id = [3; 16];
        let token = [4; 32];
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let mut punch = PunchState::new(vec![(target, false)], session_id, token, DEFAULT_LIMITS);
        punch.send_round(&sender);
        let sent = punch.sent_nonces[0].0;

        // A well-formed ACK echoing a nonce never sent.
        let forged = build_ack_packet(&session_id, &token, &[9; 16]);
        punch.receive(&sender, &forged, target);
        assert!(!punch.we_got_ack);
        // The right nonce from an IP it was not sent to.
        let ack = build_ack_packet(&session_id, &token, &sent);
        punch.receive(&sender, &ack, "127.0.0.2:40000".parse().unwrap());
        assert!(!punch.we_got_ack);
        // The right nonce from where it was sent (the port may differ).
        punch.receive(&sender, &ack, "127.0.0.1:40001".parse().unwrap());
        assert!(punch.we_got_ack);
    }

    /// A punch toward a public endpoint and a host candidate, both real
    /// sockets, with its first round sent: the punch, the public socket,
    /// the host socket.
    fn punch_with_host_candidate(limits: PunchLimits) -> (PunchState, UdpSocket, UdpSocket) {
        let public = UdpSocket::bind("127.0.0.1:0").unwrap();
        let host = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut punch = PunchState::new(
            vec![
                (public.local_addr().unwrap(), false),
                (host.local_addr().unwrap(), true),
            ],
            [5; 16],
            [6; 32],
            limits,
        );
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        punch.send_round(&sender);
        (punch, public, host)
    }

    #[test]
    fn an_answering_host_candidate_is_preferred() {
        let (mut punch, public, host) = punch_with_host_candidate(DEFAULT_LIMITS);
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (session_id, token) = ([5; 16], [6; 32]);
        let public_addr = public.local_addr().unwrap();
        let host_addr = host.local_addr().unwrap();
        // The peer's punch and acknowledgement arrive from its public
        // endpoint first: the punch has succeeded, but waits for the host
        // candidate.
        let nonce = punch.sent_nonces[0].0;
        let punch_pkt = build_punch_packet(&session_id, &token, &[1; 16]);
        assert!(punch.receive(&sender, &punch_pkt, public_addr).is_none());
        let ack = build_ack_packet(&session_id, &token, &nonce);
        assert!(punch.receive(&sender, &ack, public_addr).is_none());
        // Then the host candidate answers: it is the peer's address.
        let host_nonce = punch.sent_nonces[1].0;
        let ack = build_ack_packet(&session_id, &token, &host_nonce);
        let (peer, _) = punch.receive(&sender, &ack, host_addr).unwrap();
        assert_eq!(peer, host_addr);
    }

    #[test]
    fn a_silent_host_candidate_is_given_up_after_the_grace() {
        let limits = PunchLimits {
            host_grace: Duration::from_millis(50),
            ..DEFAULT_LIMITS
        };
        let (mut punch, public, _host) = punch_with_host_candidate(limits);
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (session_id, token) = ([5; 16], [6; 32]);
        let public_addr = public.local_addr().unwrap();
        let nonce = punch.sent_nonces[0].0;
        let punch_pkt = build_punch_packet(&session_id, &token, &[1; 16]);
        punch.receive(&sender, &punch_pkt, public_addr);
        let ack = build_ack_packet(&session_id, &token, &nonce);
        assert!(punch.receive(&sender, &ack, public_addr).is_none());
        assert!(punch.ready(Instant::now()).is_none());
        let later = Instant::now() + Duration::from_millis(60);
        assert_eq!(punch.ready(later).map(|r| r.0), Some(public_addr));
    }

    #[test]
    fn host_candidates_come_after_public_ones_within_the_cap() {
        let public: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        let hosts: Vec<SocketAddr> = vec![
            "192.168.1.5:4000".parse().unwrap(),
            "203.0.113.5:4000".parse().unwrap(),
            "192.168.1.6:4000".parse().unwrap(),
            "192.168.1.7:4000".parse().unwrap(),
            "192.168.1.8:4000".parse().unwrap(),
        ];
        let candidates = punch_candidates(vec![public], hosts).unwrap();
        assert_eq!(
            candidates,
            vec![
                (public, false),
                ("192.168.1.5:4000".parse().unwrap(), true),
                ("192.168.1.6:4000".parse().unwrap(), true),
                ("192.168.1.7:4000".parse().unwrap(), true),
            ]
        );
    }

    #[test]
    fn a_punch_from_an_unsignalled_port_is_learned_and_punched() {
        let (session_id, token) = ([7; 16], [8; 32]);
        let signalled = UdpSocket::bind("127.0.0.1:0").unwrap();
        let actual = UdpSocket::bind("127.0.0.1:0").unwrap();
        let actual_addr = actual.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut punch = PunchState::new(
            vec![(signalled.local_addr().unwrap(), false)],
            session_id,
            token,
            DEFAULT_LIMITS,
        );
        // A punch from another port of the candidate's IP is answered and
        // that address becomes a candidate.
        let pkt = build_punch_packet(&session_id, &token, &[1; 16]);
        punch.receive(&sender, &pkt, actual_addr);
        assert_eq!(punch.learned, vec![actual_addr]);
        assert!(punch
            .endpoints
            .iter()
            .any(|ep| ep.addr == actual_addr && ep.verified));
        // Its replay from yet another port teaches nothing.
        let elsewhere: SocketAddr = "127.0.0.1:9".parse().unwrap();
        punch.receive(&sender, &pkt, elsewhere);
        assert_eq!(punch.learned, vec![actual_addr]);
        // A forged punch teaches nothing either.
        let forged = build_punch_packet(&session_id, &[0; 32], &[2; 16]);
        punch.receive(&sender, &forged, elsewhere);
        assert_eq!(punch.learned.len(), 1);
        // The next round punches the learned address at full rate.
        drain(&actual);
        punch.send_round(&sender);
        let mut buf = [0u8; 128];
        actual
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let (n, _) = actual.recv_from(&mut buf).unwrap();
        assert!(open_control(&buf[..n], PUNCH_MAGIC, &session_id, &token).is_some());
    }

    #[test]
    fn peer_reflexive_candidates_are_bounded() {
        let (session_id, token) = ([7; 16], [8; 32]);
        let signalled: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut punch =
            PunchState::new(vec![(signalled, false)], session_id, token, DEFAULT_LIMITS);
        for port in 0..5u16 {
            let pkt = build_punch_packet(&session_id, &token, &[port as u8 + 1; 16]);
            punch.receive(
                &sender,
                &pkt,
                SocketAddr::from(([127, 0, 0, 1], 41000 + port)),
            );
        }
        assert_eq!(punch.learned.len(), MAX_PEER_REFLEXIVE);
        // Never from another IP than a candidate's.
        let pkt = build_punch_packet(&session_id, &token, &[99; 16]);
        let mut punch =
            PunchState::new(vec![(signalled, false)], session_id, token, DEFAULT_LIMITS);
        punch.receive(&sender, &pkt, "127.0.0.2:41000".parse().unwrap());
        assert!(punch.learned.is_empty());
    }

    #[test]
    fn a_peer_behind_a_port_changing_nat_is_reached_over_its_learned_port() {
        // B's punches leave from another socket (another NAT port) than
        // the one A was told about, and only that socket is reachable.
        let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let told = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let session_id = [0x21; 16];
        let token = [0x31; 32];
        let handle_a = start_udp_punch(
            sock_a,
            vec![told.local_addr().unwrap()],
            vec![],
            session_id,
            token,
        )
        .unwrap();
        let handle_b = start_udp_punch(sock_b, vec![addr_a], vec![], session_id, token).unwrap();
        let a = handle_a.join().expect("A connects");
        let b = handle_b.join().expect("B connects");
        assert_eq!(a.peer_addr, addr_b);
        assert_eq!(a.learned, vec![addr_b]);
        assert_eq!(b.peer_addr, addr_a);
        assert!(b.learned.is_empty());
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
            unverified_burst: MAX_PUNCH_PACKETS,
            unverified_interval: Duration::from_millis(5),
            host_grace: HOST_GRACE,
        }
    }

    /// Datagrams waiting on `socket`.
    fn drain(socket: &UdpSocket) -> usize {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buf = [0u8; 128];
        let mut received = 0;
        while socket.recv_from(&mut buf).is_ok() {
            received += 1;
        }
        received
    }

    #[test]
    fn silent_endpoint_gets_a_burst_then_one_packet_per_interval() {
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        let limits = PunchLimits {
            duration: Duration::from_millis(700),
            unverified_burst: 4,
            unverified_interval: Duration::from_millis(200),
            ..short_limits(MAX_PUNCH_PACKETS)
        };
        let handle = start_udp_punch_with_limits(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            vec![target.local_addr().unwrap()],
            vec![],
            [0x11; 16],
            [0x22; 32],
            limits,
        )
        .unwrap();
        assert!(handle.join().is_none());
        // The burst of 4 at the full rate (5 ms apart), then one about
        // every 200 ms: well under the ~140 rounds the punch ran.
        let received = drain(&target);
        assert!((5..=8).contains(&received), "{received} packets");
    }

    #[test]
    fn candidates_are_capped_and_implausible_targets_dropped() {
        let targets: Vec<UdpSocket> = (0..MAX_PUNCH_CANDIDATES + 2)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let mut endpoints: Vec<SocketAddr> = vec![
            "0.0.0.0:4000".parse().unwrap(),
            "224.0.0.1:4000".parse().unwrap(),
            "255.255.255.255:4000".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        ];
        endpoints.extend(targets.iter().map(|t| t.local_addr().unwrap()));
        // A repeat is sent to once.
        endpoints.insert(5, targets[0].local_addr().unwrap());
        let limits = PunchLimits {
            duration: Duration::from_millis(100),
            interval: Duration::from_millis(50),
            ..short_limits(MAX_PUNCH_PACKETS)
        };
        let handle = start_udp_punch_with_limits(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            endpoints,
            vec![],
            [0x11; 16],
            [0x22; 32],
            limits,
        )
        .unwrap();
        assert!(handle.join().is_none());
        let counts: Vec<usize> = targets.iter().map(drain).collect();
        assert!(
            counts[..MAX_PUNCH_CANDIDATES].iter().all(|&c| c > 0),
            "{counts:?}"
        );
        assert!(
            counts[MAX_PUNCH_CANDIDATES..].iter().all(|&c| c == 0),
            "{counts:?}"
        );
    }

    #[test]
    fn punch_with_no_plausible_target_does_not_start() {
        for endpoints in [
            vec!["0.0.0.0:4000".parse().unwrap()],
            vec!["[ff02::1]:4000".parse().unwrap()],
            vec!["[::ffff:255.255.255.255]:4000".parse().unwrap()],
            vec![],
        ] {
            let started = start_udp_punch(
                UdpSocket::bind("127.0.0.1:0").unwrap(),
                endpoints.clone(),
                vec![],
                [0x11; 16],
                [0x22; 32],
            );
            assert!(started.is_err(), "{endpoints:?}");
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
        assert_eq!(drain(&target), 5);
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
            .send_to(&build_punch_packet(&session_id, &token, &[0; 16]), addr_a)
            .unwrap();
        other
            .send_to(&build_ack_packet(&session_id, &token, &[0; 16]), addr_a)
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
            vec![],
            [1; 16],
            [2; 32],
            &tx,
            limits,
        )
        .unwrap();
        let cancelled = start_udp_punch_on_loop_with_limits(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            vec![silent_peer.local_addr().unwrap()],
            vec![],
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
