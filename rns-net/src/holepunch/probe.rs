//! STUN-like probe service for endpoint discovery.
//!
//! Wire format (raw UDP, outside Reticulum framing):
//!
//! Request:  [MAGIC:"RNSP" 4B] [VERSION:1B] [NONCE:16B]          = 21 bytes
//! Response: [MAGIC:"RNSP" 4B] [VERSION:1B] [NONCE:16B (echo)]
//!           [ADDR_TYPE:1B (4=IPv4,6=IPv6)] [ADDR:4|16B] [PORT:2B] = 24 or 36 bytes
//!
//! The server answers each source within the limits of a
//! [`ProbeRateLimit`] and drops what is over them (see [`ProbeLimiter`]).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub use crate::event::ProbeRateLimit;

use crate::engine::service_keys::PROBE_SERVER as PROBE_SERVER_KEY;
use crate::poll::{Event as Interest, Events, Poller};

const PROBE_MAGIC: &[u8; 4] = b"RNSP";
const PROBE_VERSION: u8 = 1;
const PROBE_REQUEST_LEN: usize = 21; // 4 + 1 + 16
const ADDR_TYPE_IPV4: u8 = 4;
const ADDR_TYPE_IPV6: u8 = 6;

/// Start a probe server on the given address. Runs in a background thread.
///
/// Returns a handle to stop the server.
pub fn start_probe_server(listen_addr: SocketAddr) -> io::Result<ProbeServerHandle> {
    start_probe_server_with_mark(listen_addr, None, ProbeRateLimit::default())
}

pub fn start_probe_server_with_mark(
    listen_addr: SocketAddr,
    underlay_mark: Option<u32>,
    limit: ProbeRateLimit,
) -> io::Result<ProbeServerHandle> {
    let socket = bind_server_socket(listen_addr)?;
    crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;
    socket.set_nonblocking(true)?;
    let local_addr = socket.local_addr()?;
    let (socket, wake) = crate::listen::Listener::new(socket)?;

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    let limiter = ProbeLimiter::new(limit);
    let counters = limiter.counters();

    let handle = thread::Builder::new()
        .name("probe-server".into())
        .spawn(move || {
            run_probe_server(socket, running_clone, limiter);
        })?;

    Ok(ProbeServerHandle {
        running,
        wake,
        local_addr,
        thread: Some(handle),
        counters,
    })
}

/// Answer probes on a non-blocking socket, waiting in its poller between
/// them, until `running` is cleared and the poller woken.
fn run_probe_server(
    mut socket: crate::listen::Listener<UdpSocket>,
    running: Arc<AtomicBool>,
    mut limiter: ProbeLimiter,
) {
    let mut buf = [0u8; 64];
    while running.load(Ordering::Relaxed) {
        let (len, src) = match socket.get().recv_from(&mut buf) {
            Ok(r) => r,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = socket.wait() {
                    log::warn!("Probe server cannot wait for probes: {}", e);
                    thread::sleep(Duration::from_secs(1));
                }
                continue;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                log::warn!("Probe server recv error: {}", e);
                continue;
            }
        };
        let socket = socket.get();

        if let Some(response) = limiter.answer(&buf[..len], &src, Instant::now()) {
            if let Err(e) = socket.send_to(&response, src) {
                log::debug!("Probe server send error: {}", e);
            }
        }
    }
}

/// The response to a probe request from `src`, or `None` if `request` is
/// not one.
fn answer_probe(request: &[u8], src: &SocketAddr) -> Option<Vec<u8>> {
    if !is_probe_request(request) {
        return None;
    }
    Some(build_probe_response(&request[5..21], src))
}

/// Whether `data` is a probe request.
fn is_probe_request(data: &[u8]) -> bool {
    data.len() == PROBE_REQUEST_LEN && &data[..4] == PROBE_MAGIC && data[4] == PROBE_VERSION
}

/// Most sources a [`ProbeLimiter`] tracks at once.
const MAX_TRACKED_SOURCES: usize = 4096;

/// Seconds between log lines about refused requests.
const REFUSAL_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// A token bucket: up to `capacity` tokens, refilled at `rate` a second.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(capacity: f64, now: Instant) -> Self {
        Bucket {
            tokens: capacity,
            at: now,
        }
    }

    fn refill(&mut self, capacity: f64, rate: f64, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(capacity);
        self.at = now;
    }

    /// Take a token if there is one.
    fn take(&mut self, capacity: f64, rate: f64, now: Instant) -> bool {
        self.refill(capacity, rate, now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Counts of a probe server's work over its life, shared with the node's
/// status report.
#[derive(Debug, Default)]
pub struct ProbeServerCounters {
    answered: AtomicU64,
    rate_limited: AtomicU64,
}

impl ProbeServerCounters {
    /// Probe requests answered.
    pub fn answered(&self) -> u64 {
        self.answered.load(Ordering::Relaxed)
    }

    /// Probe requests dropped over the rate limits.
    pub fn rate_limited(&self) -> u64 {
        self.rate_limited.load(Ordering::Relaxed)
    }
}

/// The rate limits of a probe server (see [`ProbeRateLimit`]): a token
/// bucket per source (an IPv4 address, or an IPv6 /64) and one over all
/// of them. At most [`MAX_TRACKED_SOURCES`] sources are tracked; when the
/// table is full, sources whose bucket has refilled are forgotten, and a
/// new source is refused while every tracked one is still limited.
pub(crate) struct ProbeLimiter {
    limit: ProbeRateLimit,
    sources: HashMap<IpAddr, Bucket>,
    total: Option<Bucket>,
    refused: u64,
    last_report: Option<Instant>,
    counters: Arc<ProbeServerCounters>,
}

impl ProbeLimiter {
    pub(crate) fn new(limit: ProbeRateLimit) -> Self {
        ProbeLimiter {
            limit,
            sources: HashMap::new(),
            total: None,
            refused: 0,
            last_report: None,
            counters: Arc::new(ProbeServerCounters::default()),
        }
    }

    /// The counters this limiter keeps.
    pub(crate) fn counters(&self) -> Arc<ProbeServerCounters> {
        Arc::clone(&self.counters)
    }

    /// The source a request from `src` counts against.
    fn source_key(src: &SocketAddr) -> IpAddr {
        match super::canonical(*src).ip() {
            IpAddr::V6(v6) => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
            v4 => v4,
        }
    }

    fn per_source_limited(&self) -> bool {
        self.limit.per_source_rate > 0.0 && self.limit.per_source_rate.is_finite()
    }

    /// Whether a request from `src` at `now` may be answered; takes its
    /// tokens if so.
    pub(crate) fn allow(&mut self, src: &SocketAddr, now: Instant) -> bool {
        let allowed = self.check(src, now);
        if !allowed {
            self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            self.refused += 1;
            if self
                .last_report
                .is_none_or(|last| now.saturating_duration_since(last) >= REFUSAL_REPORT_INTERVAL)
            {
                log::info!(
                    "Probe server dropped {} request(s) over its rate limits (latest from {})",
                    self.refused,
                    src.ip()
                );
                self.refused = 0;
                self.last_report = Some(now);
            }
        }
        allowed
    }

    fn check(&mut self, src: &SocketAddr, now: Instant) -> bool {
        let rate = self.limit.per_source_rate;
        let burst = f64::from(self.limit.per_source_burst.max(1));
        let key = Self::source_key(src);
        if self.per_source_limited() {
            if !self.sources.contains_key(&key) && self.sources.len() >= MAX_TRACKED_SOURCES {
                self.sources.retain(|_, bucket| {
                    bucket.refill(burst, rate, now);
                    bucket.tokens < burst
                });
                if self.sources.len() >= MAX_TRACKED_SOURCES {
                    return false;
                }
            }
            let bucket = self
                .sources
                .entry(key)
                .or_insert_with(|| Bucket::full(burst, now));
            // Look before taking: a request refused overall does not use
            // up the source's allowance.
            bucket.refill(burst, rate, now);
            if bucket.tokens < 1.0 {
                return false;
            }
        }
        if self.limit.total_rate > 0 {
            let total_rate = f64::from(self.limit.total_rate);
            let total = self
                .total
                .get_or_insert_with(|| Bucket::full(total_rate, now));
            if !total.take(total_rate, total_rate, now) {
                return false;
            }
        }
        if let Some(bucket) = self.sources.get_mut(&key) {
            bucket.tokens -= 1.0;
        }
        true
    }

    /// The response to `request` from `src`, if it is a probe request
    /// within the limits.
    pub(crate) fn answer(
        &mut self,
        request: &[u8],
        src: &SocketAddr,
        now: Instant,
    ) -> Option<Vec<u8>> {
        // Datagrams that are not probe requests cost no tokens.
        if !is_probe_request(request) || !self.allow(src, now) {
            return None;
        }
        let response = answer_probe(request, src);
        if response.is_some() {
            self.counters.answered.fetch_add(1, Ordering::Relaxed);
        }
        response
    }
}

/// Datagrams answered per wake-up, so that a flood of probes cannot hold
/// the driver loop; the rest are answered on the next pass.
const FOLDED_PROBES_PER_WAKE: usize = 64;

/// The probe server on the compact engine's driver loop (see
/// [`crate::engine::FOLD_SERVICES`]): its socket is watched by the driver's
/// poller and requests are answered when they arrive, with no thread.
pub(crate) struct FoldedProbeServer {
    socket: UdpSocket,
    poller: Arc<Poller>,
    limiter: ProbeLimiter,
}

impl FoldedProbeServer {
    /// What the server has answered and dropped so far.
    pub(crate) fn counters(&self) -> Arc<ProbeServerCounters> {
        self.limiter.counters()
    }

    pub(crate) fn bind(
        listen_addr: SocketAddr,
        underlay_mark: Option<u32>,
        limit: ProbeRateLimit,
        poller: Arc<Poller>,
    ) -> io::Result<Self> {
        let socket = bind_server_socket(listen_addr)?;
        crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;
        socket.set_nonblocking(true)?;
        // SAFETY: the socket is kept, open, until `Drop` removes the
        // registration.
        unsafe { poller.add(socket.as_raw_fd(), Interest::readable(PROBE_SERVER_KEY))? };
        Ok(Self {
            socket,
            poller,
            limiter: ProbeLimiter::new(limit),
        })
    }

    /// Answer pending requests if `ready` holds the server's key.
    pub(crate) fn serve(&mut self, ready: &Events) {
        if !ready.iter().any(|event| event.key == PROBE_SERVER_KEY) {
            return;
        }
        let mut buf = [0u8; 64];
        for _ in 0..FOLDED_PROBES_PER_WAKE {
            let (len, src) = match self.socket.recv_from(&mut buf) {
                Ok(received) => received,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                // An ICMP error for an earlier response, or a signal.
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
                Err(e) => {
                    log::warn!("Probe server recv error: {}", e);
                    break;
                }
            };
            let response = self.limiter.answer(&buf[..len], &src, Instant::now());
            if let Some(response) = response {
                // A response the socket cannot take now is dropped, as a
                // lost datagram would be; the client asks again.
                if let Err(e) = self.socket.send_to(&response, src) {
                    log::debug!("Probe server send error: {}", e);
                }
            }
        }
        if let Err(e) = self
            .poller
            .modify(self.socket.as_fd(), Interest::readable(PROBE_SERVER_KEY))
        {
            log::error!("Probe server cannot watch its socket again: {}", e);
        }
    }

    #[cfg(test)]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl Drop for FoldedProbeServer {
    fn drop(&mut self) {
        let _ = self.poller.delete(self.socket.as_fd());
    }
}

/// Bind a probe server's socket. An unspecified IPv6 address (`[::]`)
/// serves IPv4 too, where the host allows it (dual stack).
fn bind_server_socket(listen_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(listen_addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if let SocketAddr::V6(v6) = listen_addr {
        if v6.ip().is_unspecified() {
            // Not fatal: a host with IPv4 off serves IPv6 alone.
            let _ = socket.set_only_v6(false);
        }
    }
    socket.bind(&listen_addr.into())?;
    Ok(socket.into())
}

/// The address a probe server listens on for `port`: every IPv6 and IPv4
/// address when the host has IPv6, else every IPv4 address.
pub fn probe_server_listen_addrs(port: u16) -> [SocketAddr; 2] {
    [
        SocketAddr::from(([0u16; 8], port)),
        SocketAddr::from(([0, 0, 0, 0], port)),
    ]
}

/// The response to a probe from `src`. An IPv4 client of a dual-stack
/// server is reported as IPv4, not as an IPv4-mapped IPv6 address.
fn build_probe_response(nonce: &[u8], src: &SocketAddr) -> Vec<u8> {
    let src = &super::canonical(*src);
    let mut resp = Vec::with_capacity(36);
    resp.extend_from_slice(PROBE_MAGIC);
    resp.push(PROBE_VERSION);
    resp.extend_from_slice(nonce);

    match src {
        SocketAddr::V4(addr) => {
            resp.push(ADDR_TYPE_IPV4);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            resp.push(ADDR_TYPE_IPV6);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    resp
}

/// Handle to a running probe server. Stops the server when dropped.
pub struct ProbeServerHandle {
    running: Arc<AtomicBool>,
    wake: crate::listen::ListenerWake,
    local_addr: SocketAddr,
    thread: Option<thread::JoinHandle<()>>,
    counters: Arc<ProbeServerCounters>,
}

impl ProbeServerHandle {
    /// The address the server answers on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// What the server has answered and dropped so far.
    pub fn counters(&self) -> Arc<ProbeServerCounters> {
        Arc::clone(&self.counters)
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.wake.wake();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ProbeServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Probe client: discover our public endpoint by sending a probe to a server.
///
/// Binds a new UDP socket (or uses an existing one), sends a probe request,
/// and returns the observed public endpoint.
///
/// The socket is returned so it can be reused for hole punching (same NAT mapping).
pub fn probe_endpoint(
    probe_server: SocketAddr,
    existing_socket: Option<UdpSocket>,
    timeout: Duration,
    device: Option<&str>,
) -> io::Result<(SocketAddr, UdpSocket)> {
    probe_endpoint_with_mark(probe_server, existing_socket, timeout, device, None)
}

pub fn probe_endpoint_with_mark(
    probe_server: SocketAddr,
    existing_socket: Option<UdpSocket>,
    timeout: Duration,
    device: Option<&str>,
    underlay_mark: Option<u32>,
) -> io::Result<(SocketAddr, UdpSocket)> {
    let socket = match existing_socket {
        Some(s) => s,
        None => {
            let bind_addr: SocketAddr = if probe_server.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0u16; 8], 0))
            };
            let sock = UdpSocket::bind(bind_addr)?;
            #[cfg(target_os = "linux")]
            if let Some(dev) = device {
                use std::os::unix::io::AsRawFd;
                crate::interface::bind_to_device(sock.as_raw_fd(), dev)?;
            }
            sock
        }
    };
    crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;
    socket.set_read_timeout(Some(timeout))?;

    let observed = ask_and_wait(
        &socket,
        probe_server,
        rns_core::holepunch::ProbeProtocol::Rnsp,
        timeout,
    )?;
    Ok((observed, socket))
}

/// Send a fresh request to `server` and wait up to `timeout` for its
/// reply: a datagram from `server` that echoes the request's random nonce
/// (or STUN transaction id). Anything else is ignored.
fn ask_and_wait(
    socket: &UdpSocket,
    server: SocketAddr,
    protocol: rns_core::holepunch::ProbeProtocol,
    timeout: Duration,
) -> io::Result<SocketAddr> {
    let request = ProbeRequest::new(protocol);
    socket.send_to(request.bytes(), server)?;
    let deadline = std::time::Instant::now() + timeout;
    let mut buf = [0u8; 256];
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "no probe reply"))?;
        socket.set_read_timeout(Some(remaining))?;
        let (len, src) = socket.recv_from(&mut buf)?;
        if let Some(observed) = request.reply_from(&buf[..len], src, server) {
            return Ok(observed);
        }
        log::debug!(
            "Ignoring a datagram from {} that is not the probe reply",
            src
        );
    }
}

// --- STUN client (RFC 5389) ---

/// STUN magic cookie (RFC 5389).
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
/// STUN Binding Request message type.
const STUN_BINDING_REQUEST: u16 = 0x0001;
/// STUN Binding Response (success) message type.
const STUN_BINDING_RESPONSE: u16 = 0x0101;
/// STUN Binding Error Response message type.
const STUN_BINDING_ERROR: u16 = 0x0111;
/// STUN header length.
const STUN_HEADER_LEN: usize = 20;
/// XOR-MAPPED-ADDRESS attribute type.
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// MAPPED-ADDRESS attribute type (fallback for older servers).
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// IPv4 address family in STUN attributes.
const STUN_FAMILY_IPV4: u8 = 0x01;
/// IPv6 address family in STUN attributes.
const STUN_FAMILY_IPV6: u8 = 0x02;

/// Discover our public endpoint using a STUN Binding Request (RFC 5389).
///
/// Same contract as `probe_endpoint`: returns `(observed_addr, socket)`.
pub fn stun_probe_endpoint(
    stun_server: SocketAddr,
    existing_socket: Option<UdpSocket>,
    timeout: Duration,
    device: Option<&str>,
) -> io::Result<(SocketAddr, UdpSocket)> {
    stun_probe_endpoint_with_mark(stun_server, existing_socket, timeout, device, None)
}

pub fn stun_probe_endpoint_with_mark(
    stun_server: SocketAddr,
    existing_socket: Option<UdpSocket>,
    timeout: Duration,
    device: Option<&str>,
    underlay_mark: Option<u32>,
) -> io::Result<(SocketAddr, UdpSocket)> {
    let socket = match existing_socket {
        Some(s) => s,
        None => {
            let bind_addr: SocketAddr = if stun_server.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0u16; 8], 0))
            };
            let sock = UdpSocket::bind(bind_addr)?;
            #[cfg(target_os = "linux")]
            if let Some(dev) = device {
                use std::os::unix::io::AsRawFd;
                crate::interface::bind_to_device(sock.as_raw_fd(), dev)?;
            }
            sock
        }
    };
    crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;
    socket.set_read_timeout(Some(timeout))?;

    let observed = ask_and_wait(
        &socket,
        stun_server,
        rns_core::holepunch::ProbeProtocol::Stun,
        timeout,
    )?;
    Ok((observed, socket))
}

/// Build a minimal STUN Binding Request (header only, no attributes).
fn build_stun_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(STUN_HEADER_LEN);
    pkt.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes()); // type
    pkt.extend_from_slice(&0u16.to_be_bytes()); // length (no attributes)
    pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes()); // magic cookie
    pkt.extend_from_slice(txn_id); // transaction ID
    pkt
}

/// Parse a STUN Binding Response and extract the reflexive address.
fn parse_stun_binding_response(data: &[u8], expected_txn_id: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < STUN_HEADER_LEN {
        return None;
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    if cookie != STUN_MAGIC_COOKIE {
        return None;
    }
    if &data[8..20] != expected_txn_id {
        return None;
    }

    // Error response — treat as probe failure
    if msg_type == STUN_BINDING_ERROR {
        return None;
    }
    if msg_type != STUN_BINDING_RESPONSE {
        return None;
    }

    // Ensure payload fits
    if data.len() < STUN_HEADER_LEN + msg_len {
        return None;
    }

    let attrs = &data[STUN_HEADER_LEN..STUN_HEADER_LEN + msg_len];

    // First try XOR-MAPPED-ADDRESS, then fall back to MAPPED-ADDRESS
    if let Some(addr) = find_stun_attribute(attrs, STUN_ATTR_XOR_MAPPED_ADDRESS) {
        return parse_xor_mapped_address(addr, expected_txn_id);
    }
    if let Some(addr) = find_stun_attribute(attrs, STUN_ATTR_MAPPED_ADDRESS) {
        return parse_mapped_address(addr);
    }

    None
}

/// Find a STUN attribute by type, returning the attribute value bytes.
fn find_stun_attribute(mut attrs: &[u8], target_type: u16) -> Option<&[u8]> {
    while attrs.len() >= 4 {
        let attr_type = u16::from_be_bytes([attrs[0], attrs[1]]);
        let attr_len = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        if attrs.len() < 4 + attr_len {
            return None;
        }
        if attr_type == target_type {
            return Some(&attrs[4..4 + attr_len]);
        }
        // Attributes are padded to 4-byte boundaries
        let padded_len = (attr_len + 3) & !3;
        let advance = 4 + padded_len;
        if advance > attrs.len() {
            return None;
        }
        attrs = &attrs[advance..];
    }
    None
}

/// Parse XOR-MAPPED-ADDRESS attribute value.
fn parse_xor_mapped_address(value: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        STUN_FAMILY_IPV4 => {
            if value.len() < 8 {
                return None;
            }
            let xaddr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let addr = xaddr ^ STUN_MAGIC_COOKIE;
            let ip = std::net::Ipv4Addr::from(addr.to_be_bytes());
            Some(SocketAddr::new(ip.into(), port))
        }
        STUN_FAMILY_IPV6 => {
            if value.len() < 20 {
                return None;
            }
            // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(txn_id);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = value[4 + i] ^ xor_key[i];
            }
            let ip = std::net::Ipv6Addr::from(octets);
            Some(SocketAddr::new(ip.into(), port))
        }
        _ => None,
    }
}

/// Parse MAPPED-ADDRESS attribute value (no XOR, for older servers).
fn parse_mapped_address(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);

    match family {
        STUN_FAMILY_IPV4 => {
            if value.len() < 8 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(value[4], value[5], value[6], value[7]);
            Some(SocketAddr::new(ip.into(), port))
        }
        STUN_FAMILY_IPV6 => {
            if value.len() < 20 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            Some(SocketAddr::new(ip.into(), port))
        }
        _ => None,
    }
}

/// Unified probe dispatcher: calls RNSP or STUN based on the protocol.
pub fn probe_endpoint_with_protocol(
    server: SocketAddr,
    protocol: rns_core::holepunch::ProbeProtocol,
    existing_socket: Option<UdpSocket>,
    timeout: Duration,
    device: Option<&str>,
) -> io::Result<(SocketAddr, UdpSocket)> {
    probe_endpoint_with_protocol_and_mark(server, protocol, existing_socket, timeout, device, None)
}

pub fn probe_endpoint_with_protocol_and_mark(
    server: SocketAddr,
    protocol: rns_core::holepunch::ProbeProtocol,
    existing_socket: Option<UdpSocket>,
    timeout: Duration,
    device: Option<&str>,
    underlay_mark: Option<u32>,
) -> io::Result<(SocketAddr, UdpSocket)> {
    match protocol {
        rns_core::holepunch::ProbeProtocol::Rnsp => {
            probe_endpoint_with_mark(server, existing_socket, timeout, device, underlay_mark)
        }
        rns_core::holepunch::ProbeProtocol::Stun => {
            stun_probe_endpoint_with_mark(server, existing_socket, timeout, device, underlay_mark)
        }
    }
}

/// Try multiple probe servers sequentially, returning the first successful result.
///
/// Returns `(observed_addr, socket, server_that_worked)`.
/// All servers fail → returns the last error.
pub fn probe_endpoint_failover(
    servers: &[SocketAddr],
    protocol: rns_core::holepunch::ProbeProtocol,
    timeout_per_server: Duration,
    device: Option<&str>,
) -> io::Result<(SocketAddr, UdpSocket, SocketAddr)> {
    probe_endpoint_failover_with_mark(servers, protocol, timeout_per_server, device, None)
}

pub fn probe_endpoint_failover_with_mark(
    servers: &[SocketAddr],
    protocol: rns_core::holepunch::ProbeProtocol,
    timeout_per_server: Duration,
    device: Option<&str>,
    underlay_mark: Option<u32>,
) -> io::Result<(SocketAddr, UdpSocket, SocketAddr)> {
    let mut last_err = io::Error::new(io::ErrorKind::InvalidInput, "no probe servers configured");
    for &server in servers {
        match probe_endpoint_with_protocol_and_mark(
            server,
            protocol,
            None,
            timeout_per_server,
            device,
            underlay_mark,
        ) {
            Ok((observed, socket)) => return Ok((observed, socket, server)),
            Err(e) => {
                log::debug!("Probe server {} failed: {}", server, e);
                last_err = e;
            }
        }
    }
    Err(last_err)
}

/// A probe request, and how to recognise the reply to it.
pub(crate) struct ProbeRequest {
    bytes: Vec<u8>,
    id: ProbeId,
}

enum ProbeId {
    Rnsp([u8; 16]),
    Stun([u8; 12]),
}

impl ProbeRequest {
    /// A request with a fresh random nonce (or STUN transaction id), so
    /// that a reply cannot be forged by anyone who has not seen the
    /// request.
    pub(crate) fn new(protocol: rns_core::holepunch::ProbeProtocol) -> Self {
        use rns_crypto::Rng;
        let mut nonce = [0u8; 16];
        rns_crypto::OsRng.fill_bytes(&mut nonce);
        match protocol {
            rns_core::holepunch::ProbeProtocol::Rnsp => {
                let mut bytes = Vec::with_capacity(PROBE_REQUEST_LEN);
                bytes.extend_from_slice(PROBE_MAGIC);
                bytes.push(PROBE_VERSION);
                bytes.extend_from_slice(&nonce);
                Self {
                    bytes,
                    id: ProbeId::Rnsp(nonce),
                }
            }
            rns_core::holepunch::ProbeProtocol::Stun => {
                let txn_id: [u8; 12] = nonce[..12].try_into().expect("12 of 16 bytes");
                Self {
                    bytes: build_stun_binding_request(&txn_id),
                    id: ProbeId::Stun(txn_id),
                }
            }
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The observed address, if `data`, received from `src`, is the reply
    /// to this request sent to `server`.
    pub(crate) fn reply_from(
        &self,
        data: &[u8],
        src: SocketAddr,
        server: SocketAddr,
    ) -> Option<SocketAddr> {
        if super::canonical(src) != super::canonical(server) {
            return None;
        }
        self.reply(data)
    }

    /// The observed address, if `data` is the reply to this request.
    fn reply(&self, data: &[u8]) -> Option<SocketAddr> {
        match &self.id {
            ProbeId::Rnsp(nonce) => parse_probe_response(data, nonce),
            ProbeId::Stun(txn_id) => parse_stun_binding_response(data, txn_id),
        }
    }
}

/// A fresh socket for probing `server`, bound like the blocking probes
/// bind theirs.
pub(crate) fn open_probe_socket(
    server: SocketAddr,
    device: Option<&str>,
    underlay_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let bind_addr: SocketAddr = if server.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind_addr)?;
    #[cfg(target_os = "linux")]
    if let Some(dev) = device {
        crate::interface::bind_to_device(socket.as_raw_fd(), dev)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = device;
    crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;
    Ok(socket)
}

fn parse_probe_response(data: &[u8], expected_nonce: &[u8; 16]) -> Option<SocketAddr> {
    if data.len() < 24 {
        return None;
    }
    if &data[..4] != PROBE_MAGIC {
        return None;
    }
    if data[4] != PROBE_VERSION {
        return None;
    }
    if &data[5..21] != expected_nonce {
        return None;
    }

    let addr_type = data[21];
    match addr_type {
        ADDR_TYPE_IPV4 => {
            if data.len() < 28 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(data[22], data[23], data[24], data[25]);
            let port = u16::from_be_bytes([data[26], data[27]]);
            Some(SocketAddr::new(ip.into(), port))
        }
        ADDR_TYPE_IPV6 => {
            if data.len() < 40 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[22..38]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[38], data[39]]);
            Some(SocketAddr::new(ip.into(), port))
        }
        _ => None,
    }
}

/// Take `data` as a probe request at a rate-limited server, and as a
/// reply to an RNSP and a STUN request, with fixed ids and with ids taken
/// from `data`. For fuzzing.
pub(crate) fn fuzz_request(data: &[u8]) {
    let mut limiter = ProbeLimiter::new(ProbeRateLimit::default());
    let src: SocketAddr = ([198, 51, 100, 1], 4000).into();
    let _ = limiter.answer(data, &src, Instant::now());
    let mapped: SocketAddr = "[::ffff:198.51.100.1]:4000".parse().expect("valid");
    let _ = answer_probe(data, &mapped);
}

/// See [`fuzz_request`].
pub(crate) fn fuzz_reply(data: &[u8]) {
    let _ = parse_probe_response(data, &[0x11; 16]);
    let _ = parse_stun_binding_response(data, &[0x22; 12]);
    if let Some(nonce) = data.get(5..21).and_then(|n| <&[u8; 16]>::try_from(n).ok()) {
        let _ = parse_probe_response(data, nonce);
    }
    if let Some(txn) = data.get(8..20).and_then(|t| <&[u8; 12]>::try_from(t).ok()) {
        let _ = parse_stun_binding_response(data, txn);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_probe_server_and_client() {
        // Start probe server on a random port
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(server_addr).unwrap();
        let actual_addr = socket.local_addr().unwrap();
        socket.set_nonblocking(true).unwrap();
        let (socket, wake) = crate::listen::Listener::new(socket).unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let server_thread = thread::spawn(move || {
            run_probe_server(
                socket,
                running_clone,
                ProbeLimiter::new(ProbeRateLimit::default()),
            );
        });

        // Give server a moment to start
        thread::sleep(Duration::from_millis(50));

        // Probe from client
        let (observed, _socket) =
            probe_endpoint(actual_addr, None, Duration::from_secs(3), None).unwrap();

        // Since we're on localhost, the observed address should be 127.0.0.1
        assert_eq!(observed.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert!(observed.port() > 0);

        // Stop server: waking it ends its wait at once.
        running.store(false, Ordering::Relaxed);
        wake.wake();
        let _ = server_thread.join();
    }

    /// Answer the probe that arrives at `server` with a reply from another
    /// socket, a reply with another id, and then the reply, which observed
    /// 3.3.3.3:3. `id` picks the request's id out of it, and `respond`
    /// builds a reply echoing an id.
    pub(crate) fn answer_with_decoys(
        server: &UdpSocket,
        id: impl Fn(&[u8]) -> Vec<u8>,
        respond: impl Fn(&[u8], &SocketAddr) -> Vec<u8>,
    ) {
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut buf = [0u8; 64];
        let (len, client) = server.recv_from(&mut buf).unwrap();
        let id = id(&buf[..len]);
        let mut other_id = id.clone();
        other_id[0] ^= 0xff;
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        other
            .send_to(&respond(&id, &"1.1.1.1:1".parse().unwrap()), client)
            .unwrap();
        server
            .send_to(&respond(&other_id, &"2.2.2.2:2".parse().unwrap()), client)
            .unwrap();
        server
            .send_to(&respond(&id, &"3.3.3.3:3".parse().unwrap()), client)
            .unwrap();
    }

    pub(crate) fn rnsp_id(request: &[u8]) -> Vec<u8> {
        assert_eq!(request.len(), PROBE_REQUEST_LEN);
        request[5..21].to_vec()
    }

    pub(crate) fn rnsp_reply(id: &[u8], observed: &SocketAddr) -> Vec<u8> {
        build_probe_response(id, observed)
    }

    #[test]
    fn probe_reply_must_come_from_the_server_and_echo_the_nonce() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client =
            thread::spawn(move || probe_endpoint(server_addr, None, Duration::from_secs(3), None));
        answer_with_decoys(&server, rnsp_id, rnsp_reply);
        let (observed, _) = client.join().unwrap().unwrap();
        assert_eq!(observed, "3.3.3.3:3".parse().unwrap());
    }

    #[test]
    fn stun_reply_must_come_from_the_server_and_echo_the_transaction_id() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = thread::spawn(move || {
            stun_probe_endpoint(server_addr, None, Duration::from_secs(3), None)
        });
        answer_with_decoys(
            &server,
            |request| request[8..20].to_vec(),
            |id, observed| build_stun_response_xor_mapped(id.try_into().unwrap(), observed),
        );
        let (observed, _) = client.join().unwrap().unwrap();
        assert_eq!(observed, "3.3.3.3:3".parse().unwrap());
    }

    #[test]
    fn probe_without_its_reply_times_out() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = thread::spawn(move || {
            probe_endpoint(server_addr, None, Duration::from_millis(500), None)
        });
        let mut buf = [0u8; 64];
        let (len, client_addr) = server.recv_from(&mut buf).unwrap();
        let nonce = rnsp_id(&buf[..len]);
        let mut wrong = nonce.clone();
        wrong[15] ^= 1;
        server
            .send_to(
                &rnsp_reply(&wrong, &"2.2.2.2:2".parse().unwrap()),
                client_addr,
            )
            .unwrap();
        assert!(client.join().unwrap().is_err());
    }

    #[test]
    fn probe_ids_are_random() {
        use rns_core::holepunch::ProbeProtocol;
        for protocol in [ProbeProtocol::Rnsp, ProbeProtocol::Stun] {
            let a = ProbeRequest::new(protocol);
            let b = ProbeRequest::new(protocol);
            assert_ne!(a.bytes(), b.bytes());
        }
    }

    fn request() -> Vec<u8> {
        ProbeRequest::new(rns_core::holepunch::ProbeProtocol::Rnsp)
            .bytes()
            .to_vec()
    }

    #[test]
    fn counters_track_answered_and_rate_limited_requests() {
        let mut limiter = ProbeLimiter::new(ProbeRateLimit {
            per_source_rate: 1.0,
            per_source_burst: 2,
            total_rate: 0,
        });
        let counters = limiter.counters();
        let t0 = Instant::now();
        let a: SocketAddr = "198.51.100.1:4000".parse().unwrap();
        for _ in 0..5 {
            limiter.answer(&request(), &a, t0);
        }
        // Junk is neither answered nor counted against the limits.
        assert!(limiter.answer(b"junk", &a, t0).is_none());
        assert_eq!(counters.answered(), 2);
        assert_eq!(counters.rate_limited(), 3);
    }

    #[test]
    fn each_source_gets_its_burst_then_its_rate() {
        let mut limiter = ProbeLimiter::new(ProbeRateLimit {
            per_source_rate: 2.0,
            per_source_burst: 3,
            total_rate: 0,
        });
        let t0 = Instant::now();
        let a: SocketAddr = "198.51.100.1:4000".parse().unwrap();
        let b: SocketAddr = "198.51.100.2:4000".parse().unwrap();
        for _ in 0..3 {
            assert!(limiter.answer(&request(), &a, t0).is_some());
        }
        assert!(limiter.answer(&request(), &a, t0).is_none());
        // Another port of the same address is the same source.
        let a2: SocketAddr = "198.51.100.1:4001".parse().unwrap();
        assert!(limiter.answer(&request(), &a2, t0).is_none());
        // Another address has a bucket of its own.
        assert!(limiter.answer(&request(), &b, t0).is_some());
        // Half a second refills one request at two a second.
        let t1 = t0 + Duration::from_millis(500);
        assert!(limiter.answer(&request(), &a, t1).is_some());
        assert!(limiter.answer(&request(), &a, t1).is_none());
        // A refill never exceeds the burst.
        let t2 = t1 + Duration::from_secs(60);
        for _ in 0..3 {
            assert!(limiter.allow(&a, t2));
        }
        assert!(!limiter.allow(&a, t2));
    }

    #[test]
    fn junk_costs_no_tokens() {
        let mut limiter = ProbeLimiter::new(ProbeRateLimit {
            per_source_rate: 1.0,
            per_source_burst: 1,
            total_rate: 1,
        });
        let now = Instant::now();
        let src: SocketAddr = "198.51.100.1:4000".parse().unwrap();
        for _ in 0..10 {
            assert!(limiter.answer(b"not a probe", &src, now).is_none());
        }
        assert!(limiter.answer(&request(), &src, now).is_some());
    }

    #[test]
    fn an_ipv6_slash_64_is_one_source() {
        let mut limiter = ProbeLimiter::new(ProbeRateLimit {
            per_source_rate: 1.0,
            per_source_burst: 1,
            total_rate: 0,
        });
        let now = Instant::now();
        let a: SocketAddr = "[2001:db8:1:2::1]:4000".parse().unwrap();
        let same_64: SocketAddr = "[2001:db8:1:2:ffff::9]:4000".parse().unwrap();
        let other_64: SocketAddr = "[2001:db8:1:3::1]:4000".parse().unwrap();
        assert!(limiter.allow(&a, now));
        assert!(!limiter.allow(&same_64, now));
        assert!(limiter.allow(&other_64, now));
        // An IPv4-mapped address counts as its IPv4 form.
        let v4: SocketAddr = "198.51.100.7:1".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:198.51.100.7]:2".parse().unwrap();
        assert!(limiter.allow(&v4, now));
        assert!(!limiter.allow(&mapped, now));
    }

    #[test]
    fn the_total_rate_bounds_all_sources_together() {
        let mut limiter = ProbeLimiter::new(ProbeRateLimit {
            per_source_rate: 1.0,
            per_source_burst: 5,
            total_rate: 4,
        });
        let now = Instant::now();
        let answered = (0..10u8)
            .filter(|i| {
                let src = SocketAddr::from(([198, 51, 100, *i], 4000));
                limiter.allow(&src, now)
            })
            .count();
        assert_eq!(answered, 4);
        // A source refused overall kept its own allowance.
        let later = now + Duration::from_secs(1);
        let src = SocketAddr::from(([198, 51, 100, 9], 4000));
        for _ in 0..4 {
            assert!(limiter.allow(&src, later));
        }
    }

    #[test]
    fn zero_rates_turn_the_limits_off() {
        let mut limiter = ProbeLimiter::new(ProbeRateLimit {
            per_source_rate: 0.0,
            per_source_burst: 1,
            total_rate: 0,
        });
        let now = Instant::now();
        let src: SocketAddr = "198.51.100.1:4000".parse().unwrap();
        for _ in 0..1000 {
            assert!(limiter.allow(&src, now));
        }
        assert!(limiter.sources.is_empty());
    }

    #[test]
    fn a_full_source_table_forgets_refilled_sources_and_refuses_the_rest() {
        let mut limiter = ProbeLimiter::new(ProbeRateLimit {
            per_source_rate: 1.0,
            per_source_burst: 2,
            total_rate: 0,
        });
        let t0 = Instant::now();
        let src = |i: usize| SocketAddr::from(([10, (i >> 16) as u8, (i >> 8) as u8, i as u8], 1));
        for i in 0..MAX_TRACKED_SOURCES {
            assert!(limiter.allow(&src(i), t0));
        }
        // Every tracked source is still short of its burst: a new one is
        // refused rather than evicting one.
        let newcomer = src(MAX_TRACKED_SOURCES);
        assert!(!limiter.allow(&newcomer, t0));
        // Once they have refilled they are forgotten and it gets in.
        let t1 = t0 + Duration::from_secs(2);
        assert!(limiter.allow(&newcomer, t1));
        assert_eq!(limiter.sources.len(), 1);
    }

    #[test]
    fn threaded_probe_server_drops_requests_over_the_limit() {
        let mut server = start_probe_server_with_mark(
            "127.0.0.1:0".parse().unwrap(),
            None,
            ProbeRateLimit {
                per_source_rate: 0.001,
                per_source_burst: 2,
                total_rate: 0,
            },
        )
        .unwrap();
        let addr = server.local_addr();
        assert!(probe_endpoint(addr, None, Duration::from_secs(3), None).is_ok());
        assert!(probe_endpoint(addr, None, Duration::from_secs(3), None).is_ok());
        // Unanswered: the probe times out (WouldBlock from the socket's
        // read timeout on some platforms).
        assert!(probe_endpoint(addr, None, Duration::from_millis(300), None).is_err());
        server.stop();
    }

    #[test]
    fn dual_stack_server_reflects_ipv4_and_ipv6_clients_in_their_family() {
        let Ok(mut server) = start_probe_server("[::]:0".parse().unwrap()) else {
            return; // no IPv6 on this host
        };
        let port = server.local_addr().port();
        let (v4, _) = probe_endpoint(
            SocketAddr::from(([127, 0, 0, 1], port)),
            None,
            Duration::from_secs(3),
            None,
        )
        .expect("IPv4 client answered");
        assert_eq!(v4.ip(), std::net::Ipv4Addr::LOCALHOST);
        if let Ok((v6, _)) = probe_endpoint(
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
            None,
            Duration::from_secs(3),
            None,
        ) {
            assert_eq!(v6.ip(), std::net::Ipv6Addr::LOCALHOST);
        }
        server.stop();
    }

    #[test]
    fn mapped_sources_are_reported_as_ipv4() {
        let src: SocketAddr = "[::ffff:198.51.100.7]:4000".parse().unwrap();
        let response = build_probe_response(&[3; 16], &src);
        assert_eq!(
            parse_probe_response(&response, &[3; 16]),
            Some("198.51.100.7:4000".parse().unwrap())
        );
        assert_eq!(response.len(), 28);
    }

    #[test]
    fn folded_probe_server_answers_on_its_poller_and_ignores_junk() {
        let poller = Arc::new(Poller::new().unwrap());
        let mut server = FoldedProbeServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            ProbeRateLimit::default(),
            poller.clone(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();

        let client = thread::spawn(move || {
            let junk = UdpSocket::bind("127.0.0.1:0").unwrap();
            junk.send_to(b"not a probe", addr).unwrap();
            let first = probe_endpoint(addr, None, Duration::from_secs(3), None).unwrap();
            let second = probe_endpoint(addr, None, Duration::from_secs(3), None).unwrap();
            (first.0, second.0)
        });
        let mut ready = Events::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !client.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "client did not finish"
            );
            ready.clear();
            poller
                .wait(&mut ready, Some(Duration::from_millis(10)))
                .unwrap();
            server.serve(&ready);
        }
        let (first, second) = client.join().unwrap();
        assert_eq!(first.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(second.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_ne!(first.port(), second.port());
    }

    #[test]
    fn test_probe_response_roundtrip() {
        let nonce = [0x42u8; 16];
        let addr: SocketAddr = "1.2.3.4:41000".parse().unwrap();
        let response = build_probe_response(&nonce, &addr);
        let parsed = parse_probe_response(&response, &nonce).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_probe_response_ipv6() {
        let nonce = [0x42u8; 16];
        let addr: SocketAddr = "[::1]:52000".parse().unwrap();
        let response = build_probe_response(&nonce, &addr);
        let parsed = parse_probe_response(&response, &nonce).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_probe_response_bad_nonce() {
        let nonce = [0x42u8; 16];
        let addr: SocketAddr = "1.2.3.4:41000".parse().unwrap();
        let response = build_probe_response(&nonce, &addr);
        let wrong_nonce = [0x99u8; 16];
        assert!(parse_probe_response(&response, &wrong_nonce).is_none());
    }

    // --- STUN tests ---

    /// Build a synthetic STUN Binding Response with XOR-MAPPED-ADDRESS.
    fn build_stun_response_xor_mapped(txn_id: &[u8; 12], addr: &SocketAddr) -> Vec<u8> {
        let mut attr_value = Vec::new();
        attr_value.push(0x00); // reserved
        match addr {
            SocketAddr::V4(v4) => {
                attr_value.push(STUN_FAMILY_IPV4);
                let xport = v4.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16;
                attr_value.extend_from_slice(&xport.to_be_bytes());
                let xaddr = u32::from_be_bytes(v4.ip().octets()) ^ STUN_MAGIC_COOKIE;
                attr_value.extend_from_slice(&xaddr.to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                attr_value.push(STUN_FAMILY_IPV6);
                let xport = v6.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16;
                attr_value.extend_from_slice(&xport.to_be_bytes());
                let mut xor_key = [0u8; 16];
                xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                xor_key[4..16].copy_from_slice(txn_id);
                let octets = v6.ip().octets();
                for i in 0..16 {
                    attr_value.push(octets[i] ^ xor_key[i]);
                }
            }
        }

        let attr_len = attr_value.len() as u16;
        let mut attr = Vec::new();
        attr.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&attr_len.to_be_bytes());
        attr.extend_from_slice(&attr_value);

        let msg_len = attr.len() as u16;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        pkt.extend_from_slice(&msg_len.to_be_bytes());
        pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(txn_id);
        pkt.extend_from_slice(&attr);
        pkt
    }

    /// Build a synthetic STUN Binding Response with MAPPED-ADDRESS (no XOR).
    fn build_stun_response_mapped(txn_id: &[u8; 12], addr: &SocketAddr) -> Vec<u8> {
        let mut attr_value = Vec::new();
        attr_value.push(0x00); // reserved
        match addr {
            SocketAddr::V4(v4) => {
                attr_value.push(STUN_FAMILY_IPV4);
                attr_value.extend_from_slice(&v4.port().to_be_bytes());
                attr_value.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                attr_value.push(STUN_FAMILY_IPV6);
                attr_value.extend_from_slice(&v6.port().to_be_bytes());
                attr_value.extend_from_slice(&v6.ip().octets());
            }
        }

        let attr_len = attr_value.len() as u16;
        let mut attr = Vec::new();
        attr.extend_from_slice(&STUN_ATTR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&attr_len.to_be_bytes());
        attr.extend_from_slice(&attr_value);

        let msg_len = attr.len() as u16;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        pkt.extend_from_slice(&msg_len.to_be_bytes());
        pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(txn_id);
        pkt.extend_from_slice(&attr);
        pkt
    }

    #[test]
    fn test_stun_binding_request_format() {
        let txn_id = [0x42u8; 12];
        let req = build_stun_binding_request(&txn_id);
        assert_eq!(req.len(), STUN_HEADER_LEN);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0); // no attributes
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &txn_id);
    }

    #[test]
    fn test_stun_xor_mapped_address_ipv4_roundtrip() {
        let txn_id = [0xAB; 12];
        let addr: SocketAddr = "203.0.113.42:54321".parse().unwrap();
        let response = build_stun_response_xor_mapped(&txn_id, &addr);
        let parsed = parse_stun_binding_response(&response, &txn_id).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_stun_xor_mapped_address_ipv6_roundtrip() {
        let txn_id = [0xCD; 12];
        let addr: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
        let response = build_stun_response_xor_mapped(&txn_id, &addr);
        let parsed = parse_stun_binding_response(&response, &txn_id).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_stun_mapped_address_fallback() {
        let txn_id = [0xEF; 12];
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let response = build_stun_response_mapped(&txn_id, &addr);
        let parsed = parse_stun_binding_response(&response, &txn_id).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_stun_error_response_returns_none() {
        let txn_id = [0x11; 12];
        // Build an error response
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&STUN_BINDING_ERROR.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // no attributes
        pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(&txn_id);
        assert!(parse_stun_binding_response(&pkt, &txn_id).is_none());
    }

    #[test]
    fn test_stun_wrong_txn_id_returns_none() {
        let txn_id = [0xAB; 12];
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let response = build_stun_response_xor_mapped(&txn_id, &addr);
        let wrong_txn = [0xFF; 12];
        assert!(parse_stun_binding_response(&response, &wrong_txn).is_none());
    }

    #[test]
    fn test_stun_truncated_response_returns_none() {
        let txn_id = [0xAB; 12];
        // Too short for a valid STUN header
        assert!(parse_stun_binding_response(&[0; 10], &txn_id).is_none());
    }
}
