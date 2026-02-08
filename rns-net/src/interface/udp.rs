//! UDP broadcast interface.
//!
//! Connectionless, no HDLC framing — each UDP datagram is one packet.
//! Matches Python `UDPInterface` from `UDPInterface.py`.

use std::io::{self};
use std::net::{SocketAddr, UdpSocket};
use std::thread;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender};
use crate::interface::Writer;

/// Configuration for a UDP interface.
#[derive(Debug, Clone)]
pub struct UdpConfig {
    pub name: String,
    pub listen_ip: Option<String>,
    pub listen_port: Option<u16>,
    pub forward_ip: Option<String>,
    pub forward_port: Option<u16>,
    pub interface_id: InterfaceId,
}

impl Default for UdpConfig {
    fn default() -> Self {
        UdpConfig {
            name: String::new(),
            listen_ip: None,
            listen_port: None,
            forward_ip: None,
            forward_port: None,
            interface_id: InterfaceId(0),
        }
    }
}

/// Writer that sends raw data via UDP to a target address.
struct UdpWriter {
    socket: UdpSocket,
    target: SocketAddr,
}

impl Writer for UdpWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.socket.send_to(data, self.target)?;
        Ok(())
    }
}

/// Start a UDP interface. Spawns a reader thread if listen_ip/port are set.
/// Returns a writer if forward_ip/port are set.
pub fn start(config: UdpConfig, tx: EventSender) -> io::Result<Option<Box<dyn Writer>>> {
    let id = config.interface_id;
    let mut writer: Option<Box<dyn Writer>> = None;

    // Create writer socket if forward params are set
    if let (Some(ref fwd_ip), Some(fwd_port)) = (&config.forward_ip, config.forward_port) {
        let target: SocketAddr = format!("{}:{}", fwd_ip, fwd_port)
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let send_socket = UdpSocket::bind("0.0.0.0:0")?;
        send_socket.set_broadcast(true)?;

        writer = Some(Box::new(UdpWriter {
            socket: send_socket,
            target,
        }));
    }

    // Create reader socket if listen params are set
    if let (Some(ref bind_ip), Some(bind_port)) = (&config.listen_ip, config.listen_port) {
        let bind_addr = format!("{}:{}", bind_ip, bind_port);
        let recv_socket = UdpSocket::bind(&bind_addr)?;

        log::info!("[{}] UDP listening on {}", config.name, bind_addr);

        // Signal interface is up
        let _ = tx.send(Event::InterfaceUp(id, None, None));

        let name = config.name.clone();
        thread::Builder::new()
            .name(format!("udp-reader-{}", id.0))
            .spawn(move || {
                udp_reader_loop(recv_socket, id, name, tx);
            })?;
    }

    Ok(writer)
}

/// Reader thread: receives UDP datagrams and sends them as frames.
fn udp_reader_loop(socket: UdpSocket, id: InterfaceId, name: String, tx: EventSender) {
    let mut buf = [0u8; 2048];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, _src)) => {
                if tx
                    .send(Event::Frame {
                        interface_id: id,
                        data: buf[..n].to_vec(),
                    })
                    .is_err()
                {
                    // Driver shut down
                    return;
                }
            }
            Err(e) => {
                log::warn!("[{}] recv error: {}", name, e);
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::time::Duration;

    fn find_free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn bind_and_receive() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();

        let config = UdpConfig {
            name: "test-udp".into(),
            listen_ip: Some("127.0.0.1".into()),
            listen_port: Some(port),
            forward_ip: None,
            forward_port: None,
            interface_id: InterfaceId(10),
        };

        let _writer = start(config, tx).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send a UDP packet to the listener
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let payload = b"hello udp";
        sender
            .send_to(payload, format!("127.0.0.1:{}", port))
            .unwrap();

        // Should receive Frame event
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { interface_id, data } => {
                assert_eq!(interface_id, InterfaceId(10));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn send_broadcast() {
        let recv_port = find_free_port();
        let (tx, _rx) = mpsc::channel();

        let config = UdpConfig {
            name: "test-udp-send".into(),
            listen_ip: None,
            listen_port: None,
            forward_ip: Some("127.0.0.1".into()),
            forward_port: Some(recv_port),
            interface_id: InterfaceId(11),
        };

        let writer = start(config, tx).unwrap();
        let mut writer = writer.unwrap();

        // Bind a receiver
        let receiver = UdpSocket::bind(format!("127.0.0.1:{}", recv_port)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Send via writer
        let payload = b"broadcast data";
        writer.send_frame(payload).unwrap();

        // Receive on the other socket
        let mut buf = [0u8; 256];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn round_trip() {
        let listen_port = find_free_port();
        let forward_port = find_free_port();
        let (tx, rx) = mpsc::channel();

        let config = UdpConfig {
            name: "test-udp-rt".into(),
            listen_ip: Some("127.0.0.1".into()),
            listen_port: Some(listen_port),
            forward_ip: Some("127.0.0.1".into()),
            forward_port: Some(forward_port),
            interface_id: InterfaceId(12),
        };

        let writer = start(config, tx).unwrap();
        assert!(writer.is_some());

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send to the listener
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"ping", format!("127.0.0.1:{}", listen_port))
            .unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => assert_eq!(data, b"ping"),
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn multiple_datagrams() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();

        let config = UdpConfig {
            name: "test-udp-multi".into(),
            listen_ip: Some("127.0.0.1".into()),
            listen_port: Some(port),
            forward_ip: None,
            forward_port: None,
            interface_id: InterfaceId(13),
        };

        let _writer = start(config, tx).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..5u8 {
            sender
                .send_to(&[i], format!("127.0.0.1:{}", port))
                .unwrap();
        }

        for i in 0..5u8 {
            let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            match event {
                Event::Frame { data, .. } => assert_eq!(data, vec![i]),
                other => panic!("expected Frame, got {:?}", other),
            }
        }
    }

    #[test]
    fn writer_send_to() {
        let recv_port = find_free_port();

        // Bind receiver first
        let receiver = UdpSocket::bind(format!("127.0.0.1:{}", recv_port)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Create writer directly
        let send_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        send_socket.set_broadcast(true).unwrap();
        let target: SocketAddr = format!("127.0.0.1:{}", recv_port).parse().unwrap();
        let mut writer = UdpWriter {
            socket: send_socket,
            target,
        };

        let payload = vec![0xAA, 0xBB, 0xCC];
        writer.send_frame(&payload).unwrap();

        let mut buf = [0u8; 256];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], &payload);
    }
}
