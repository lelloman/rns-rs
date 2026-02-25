//! STUN-like probe service for endpoint discovery.
//!
//! Wire format (raw UDP, outside Reticulum framing):
//!
//! Request:  [MAGIC:"RNSP" 4B] [VERSION:1B] [NONCE:16B]          = 21 bytes
//! Response: [MAGIC:"RNSP" 4B] [VERSION:1B] [NONCE:16B (echo)]
//!           [ADDR_TYPE:1B (4=IPv4,6=IPv6)] [ADDR:4|16B] [PORT:2B] = 24 or 36 bytes

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const PROBE_MAGIC: &[u8; 4] = b"RNSP";
const PROBE_VERSION: u8 = 1;
const PROBE_REQUEST_LEN: usize = 21;  // 4 + 1 + 16
const ADDR_TYPE_IPV4: u8 = 4;
const ADDR_TYPE_IPV6: u8 = 6;

/// Start a probe server on the given address. Runs in a background thread.
///
/// Returns a handle to stop the server.
pub fn start_probe_server(listen_addr: SocketAddr) -> io::Result<ProbeServerHandle> {
    let socket = UdpSocket::bind(listen_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    let handle = thread::Builder::new()
        .name("probe-server".into())
        .spawn(move || {
            run_probe_server(socket, running_clone);
        })?;

    Ok(ProbeServerHandle {
        running,
        thread: Some(handle),
    })
}

fn run_probe_server(socket: UdpSocket, running: Arc<AtomicBool>) {
    let mut buf = [0u8; 64];
    while running.load(Ordering::Relaxed) {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                log::warn!("Probe server recv error: {}", e);
                continue;
            }
        };

        if len != PROBE_REQUEST_LEN {
            continue;
        }
        if &buf[..4] != PROBE_MAGIC {
            continue;
        }
        if buf[4] != PROBE_VERSION {
            continue;
        }

        let nonce = &buf[5..21];
        let response = build_probe_response(nonce, &src);
        if let Err(e) = socket.send_to(&response, src) {
            log::debug!("Probe server send error: {}", e);
        }
    }
}

fn build_probe_response(nonce: &[u8], src: &SocketAddr) -> Vec<u8> {
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
    thread: Option<thread::JoinHandle<()>>,
}

impl ProbeServerHandle {
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
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
    let socket = match existing_socket {
        Some(s) => s,
        None => {
            let bind_addr: SocketAddr = if probe_server.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
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
    socket.set_read_timeout(Some(timeout))?;

    // Build request with a nonce for response matching
    let mut nonce = [0u8; 16];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();
    nonce[..8].copy_from_slice(&nanos.to_le_bytes()[..8]);
    // Fill remaining bytes: local port + thread ID bits + subsec nanos (reversed)
    let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    nonce[8..10].copy_from_slice(&local_port.to_be_bytes());
    let thread_id = std::thread::current().id();
    let thread_hash = format!("{:?}", thread_id);
    for (i, b) in thread_hash.bytes().enumerate() {
        if 10 + i >= 16 { break; }
        nonce[10 + i] = b;
    }

    let mut request = Vec::with_capacity(PROBE_REQUEST_LEN);
    request.extend_from_slice(PROBE_MAGIC);
    request.push(PROBE_VERSION);
    request.extend_from_slice(&nonce);

    socket.send_to(&request, probe_server)?;

    // Wait for response
    let mut buf = [0u8; 64];
    let (len, _) = socket.recv_from(&mut buf)?;

    parse_probe_response(&buf[..len], &nonce)
        .map(|addr| (addr, socket))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid probe response"))
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
    let socket = match existing_socket {
        Some(s) => s,
        None => {
            let bind_addr: SocketAddr = if stun_server.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
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
    socket.set_read_timeout(Some(timeout))?;

    // Build transaction ID (12 bytes) from timestamp + port + thread bits
    let mut txn_id = [0u8; 12];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();
    txn_id[..8].copy_from_slice(&nanos.to_le_bytes()[..8]);
    let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    txn_id[8..10].copy_from_slice(&local_port.to_be_bytes());
    let thread_id = std::thread::current().id();
    let thread_hash = format!("{:?}", thread_id);
    for (i, b) in thread_hash.bytes().enumerate() {
        if 10 + i >= 12 { break; }
        txn_id[10 + i] = b;
    }

    let request = build_stun_binding_request(&txn_id);
    socket.send_to(&request, stun_server)?;

    let mut buf = [0u8; 256];
    let (len, _) = socket.recv_from(&mut buf)?;

    parse_stun_binding_response(&buf[..len], &txn_id)
        .map(|addr| (addr, socket))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid STUN response"))
}

/// Build a minimal STUN Binding Request (header only, no attributes).
fn build_stun_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(STUN_HEADER_LEN);
    pkt.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes()); // type
    pkt.extend_from_slice(&0u16.to_be_bytes());                 // length (no attributes)
    pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());    // magic cookie
    pkt.extend_from_slice(txn_id);                               // transaction ID
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
    match protocol {
        rns_core::holepunch::ProbeProtocol::Rnsp => probe_endpoint(server, existing_socket, timeout, device),
        rns_core::holepunch::ProbeProtocol::Stun => stun_probe_endpoint(server, existing_socket, timeout, device),
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
    let mut last_err = io::Error::new(io::ErrorKind::InvalidInput, "no probe servers configured");
    for &server in servers {
        match probe_endpoint_with_protocol(server, protocol, None, timeout_per_server, device) {
            Ok((observed, socket)) => return Ok((observed, socket, server)),
            Err(e) => {
                log::debug!("Probe server {} failed: {}", server, e);
                last_err = e;
            }
        }
    }
    Err(last_err)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_server_and_client() {
        // Start probe server on a random port
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(server_addr).unwrap();
        let actual_addr = socket.local_addr().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let server_thread = thread::spawn(move || {
            run_probe_server(socket, running_clone);
        });

        // Give server a moment to start
        thread::sleep(Duration::from_millis(50));

        // Probe from client
        let (observed, _socket) = probe_endpoint(
            actual_addr,
            None,
            Duration::from_secs(3),
            None,
        ).unwrap();

        // Since we're on localhost, the observed address should be 127.0.0.1
        assert_eq!(observed.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert!(observed.port() > 0);

        // Stop server
        running.store(false, Ordering::Relaxed);
        let _ = server_thread.join();
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
        assert_eq!(u32::from_be_bytes([req[4], req[5], req[6], req[7]]), STUN_MAGIC_COOKIE);
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
