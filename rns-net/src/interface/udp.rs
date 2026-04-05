//! UDP broadcast interface.
//!
//! Connectionless, no HDLC framing — each UDP datagram is one packet.
//! Matches Python `UDPInterface` from `UDPInterface.py`.

use std::io::{self};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
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
    pub runtime: Arc<Mutex<UdpRuntime>>,
}

#[derive(Debug, Clone)]
pub struct UdpRuntime {
    pub forward_ip: Option<String>,
    pub forward_port: Option<u16>,
}

impl UdpRuntime {
    pub fn from_config(config: &UdpConfig) -> Self {
        Self {
            forward_ip: config.forward_ip.clone(),
            forward_port: config.forward_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<UdpRuntime>>,
    pub startup: UdpRuntime,
}

impl Default for UdpConfig {
    fn default() -> Self {
        let mut config = UdpConfig {
            name: String::new(),
            listen_ip: None,
            listen_port: None,
            forward_ip: None,
            forward_port: None,
            interface_id: InterfaceId(0),
            runtime: Arc::new(Mutex::new(UdpRuntime {
                forward_ip: None,
                forward_port: None,
            })),
        };
        let startup = UdpRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

/// Writer that sends raw data via UDP to a target address.
struct UdpWriter {
    socket: UdpSocket,
    runtime: Arc<Mutex<UdpRuntime>>,
}

impl Writer for UdpWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let runtime = self.runtime.lock().unwrap().clone();
        let target = match (runtime.forward_ip, runtime.forward_port) {
            (Some(ip), Some(port)) => format!("{}:{}", ip, port)
                .parse::<SocketAddr>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "UDP interface has no forward target configured",
                ))
            }
        };
        self.socket.send_to(data, target)?;
        Ok(())
    }
}

/// Start a UDP interface. Spawns a reader thread if listen_ip/port are set.
/// Returns a writer if forward_ip/port are set.
pub fn start(config: UdpConfig, tx: EventSender) -> io::Result<Option<Box<dyn Writer>>> {
    let id = config.interface_id;
    {
        let startup = UdpRuntime::from_config(&config);
        *config.runtime.lock().unwrap() = startup;
    }
    let send_socket = UdpSocket::bind("0.0.0.0:0")?;
    send_socket.set_broadcast(true)?;
    let writer: Option<Box<dyn Writer>> = Some(Box::new(UdpWriter {
        socket: send_socket,
        runtime: Arc::clone(&config.runtime),
    }));

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

// --- Factory implementation ---

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};
use rns_core::transport::types::InterfaceInfo;
use std::collections::HashMap;

/// Factory for `UDPInterface`.
pub struct UdpFactory;

impl InterfaceFactory for UdpFactory {
    fn type_name(&self) -> &str {
        "UDPInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let listen_ip = params.get("listen_ip").cloned();

        // 'port' is a shorthand that sets both listen_port and forward_port
        let port_shorthand: Option<u16> = params.get("port").and_then(|v| v.parse().ok());

        let listen_port: Option<u16> = params
            .get("listen_port")
            .and_then(|v| v.parse().ok())
            .or(port_shorthand);

        let forward_ip = params.get("forward_ip").cloned();

        let forward_port: Option<u16> = params
            .get("forward_port")
            .and_then(|v| v.parse().ok())
            .or(port_shorthand);

        let mut config = UdpConfig {
            name: name.to_string(),
            listen_ip,
            listen_port,
            forward_ip,
            forward_port,
            interface_id: id,
            runtime: Arc::new(Mutex::new(UdpRuntime {
                forward_ip: None,
                forward_port: None,
            })),
        };
        let startup = UdpRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        Ok(Box::new(config))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let udp_config = *config
            .into_any()
            .downcast::<UdpConfig>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong config type"))?;

        let id = udp_config.interface_id;
        let name = udp_config.name.clone();
        let out_capable = udp_config.forward_ip.is_some();
        let in_capable = udp_config.listen_ip.is_some();

        let info = InterfaceInfo {
            id,
            name,
            mode: ctx.mode,
            out_capable,
            in_capable,
            bitrate: Some(10_000_000),
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: 1400,
            ingress_control: true,
            ia_freq: 0.0,
            started: crate::time::now(),
        };

        let maybe_writer = start(udp_config, ctx.tx)?;

        let writer: Box<dyn Writer> = maybe_writer.unwrap();

        Ok(StartResult::Simple {
            id,
            info,
            writer,
            interface_type_name: "UDPInterface".to_string(),
        })
    }
}

pub(crate) fn udp_runtime_handle_from_config(config: &UdpConfig) -> UdpRuntimeConfigHandle {
    UdpRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: UdpRuntime::from_config(config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
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
        let (tx, rx) = crate::event::channel();

        let config = UdpConfig {
            name: "test-udp".into(),
            listen_ip: Some("127.0.0.1".into()),
            listen_port: Some(port),
            forward_ip: None,
            forward_port: None,
            interface_id: InterfaceId(10),
            ..UdpConfig::default()
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
        let (tx, _rx) = crate::event::channel();

        let config = UdpConfig {
            name: "test-udp-send".into(),
            listen_ip: None,
            listen_port: None,
            forward_ip: Some("127.0.0.1".into()),
            forward_port: Some(recv_port),
            interface_id: InterfaceId(11),
            ..UdpConfig::default()
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
        let (tx, rx) = crate::event::channel();

        let config = UdpConfig {
            name: "test-udp-rt".into(),
            listen_ip: Some("127.0.0.1".into()),
            listen_port: Some(listen_port),
            forward_ip: Some("127.0.0.1".into()),
            forward_port: Some(forward_port),
            interface_id: InterfaceId(12),
            ..UdpConfig::default()
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
        let (tx, rx) = crate::event::channel();

        let config = UdpConfig {
            name: "test-udp-multi".into(),
            listen_ip: Some("127.0.0.1".into()),
            listen_port: Some(port),
            forward_ip: None,
            forward_port: None,
            interface_id: InterfaceId(13),
            ..UdpConfig::default()
        };

        let _writer = start(config, tx).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..5u8 {
            sender.send_to(&[i], format!("127.0.0.1:{}", port)).unwrap();
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
        let mut writer = UdpWriter {
            socket: send_socket,
            runtime: Arc::new(Mutex::new(UdpRuntime {
                forward_ip: Some("127.0.0.1".into()),
                forward_port: Some(recv_port),
            })),
        };

        let payload = vec![0xAA, 0xBB, 0xCC];
        writer.send_frame(&payload).unwrap();

        let mut buf = [0u8; 256];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], &payload);
    }
}
