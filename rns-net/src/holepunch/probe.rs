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
) -> io::Result<(SocketAddr, UdpSocket)> {
    let socket = match existing_socket {
        Some(s) => s,
        None => {
            let bind_addr: SocketAddr = if probe_server.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            UdpSocket::bind(bind_addr)?
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
}
