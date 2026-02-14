//! Point-to-point UDP direct interface.
//!
//! After hole punching succeeds, this module wraps the punched UDP socket
//! as a Reticulum interface (implementing Writer + reader thread).
//! No HDLC framing needed — one datagram = one packet (same as UdpInterface).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender};
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
}

impl Writer for UdpDirectWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.socket.send_to(data, self.peer_addr)?;
        Ok(())
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
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    let running = Arc::new(AtomicBool::new(true));

    let writer = UdpDirectWriter {
        socket: socket.clone(),
        peer_addr,
        running: running.clone(),
    };

    let name = format!(
        "DirectPeer/{:02x}{:02x}{:02x}{:02x}",
        session_id[0], session_id[1], session_id[2], session_id[3]
    );

    let info = InterfaceInfo {
        id: interface_id,
        name: name.clone(),
        mode: rns_core::constants::MODE_FULL,
        out_capable: true,
        in_capable: true,
        bitrate: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: 1.0,
        is_local_client: false,
        wants_tunnel: false,
        tunnel_id: None,
        mtu: 1400,
        ia_freq: 0.0,
        started: 0.0,
        ingress_control: false,
    };

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
                        data: buf[..len].to_vec(),
                    });
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_direct_writer() {
        // Create a pair of sockets
        let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        sock_b.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

        let mut writer = UdpDirectWriter {
            socket: Arc::new(sock_a),
            peer_addr: addr_b,
            running: Arc::new(AtomicBool::new(true)),
        };

        // Send a frame
        let data = b"hello direct peer";
        writer.send_frame(data).unwrap();

        // Receive on other end
        let mut buf = [0u8; 64];
        let (len, _src) = sock_b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], data);
    }
}
