//! UDP broadcast interface.
//!
//! Connectionless, no HDLC framing — each UDP datagram is one packet.
//! Matches Python `UDPInterface` from `UDPInterface.py`.

use std::io::{self};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::interface::{lock_or_recover, ListenerControl, Writer};

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

/// Datagrams read per wake-up by a reader on the driver loop, so that one
/// busy interface cannot hold the loop; the rest are read on the next pass.
const LOOP_READ_BUDGET: usize = 64;

/// The largest datagram read, as the reader thread reads.
const MAX_DATAGRAM: usize = 2048;

/// Writer that sends raw data via UDP to a target address.
struct UdpWriter {
    socket: UdpSocket,
    runtime: Arc<Mutex<UdpRuntime>>,
    /// Called by the driver directly, on a non-blocking socket.
    inline: bool,
}

impl UdpWriter {
    fn target(&self) -> io::Result<SocketAddr> {
        let runtime = lock_or_recover(&self.runtime, "udp runtime");
        match (runtime.forward_ip.as_deref(), runtime.forward_port) {
            (Some(ip), Some(port)) => ip
                .parse::<std::net::IpAddr>()
                .map(|ip| SocketAddr::new(ip, port))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e)),
            _ => Err(io::Error::other(
                "UDP interface has no forward target configured",
            )),
        }
    }

    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let target = self.target()?;
        self.socket.send_to(data, target)?;
        Ok(())
    }
}

impl Writer for UdpWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        match self.send(data) {
            // The socket's buffer is full: the datagram is dropped, as the
            // network may drop it, rather than blocking the driver.
            Err(e) if self.inline && e.kind() == io::ErrorKind::WouldBlock => {
                log::debug!("UDP send buffer full, datagram dropped");
                Ok(())
            }
            result => result,
        }
    }

    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
        self.send(data)
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        // A full buffer returns WouldBlock with the completion untouched,
        // and the driver retries the frame.
        self.send(data)?;
        if let Some(completion) = completion.take() {
            completion.finish(Ok(()));
        }
        Ok(())
    }

    fn sends_inline(&self) -> bool {
        self.inline
    }
}

/// Start a UDP interface. Spawns a reader thread if listen_ip/port are set.
/// Returns a writer if forward_ip/port are set.
pub fn start(config: UdpConfig, tx: EventSender) -> io::Result<Option<Box<dyn Writer>>> {
    start_with_mark(config, tx, None).map(|(writer, _)| writer)
}

fn start_with_mark(
    config: UdpConfig,
    tx: EventSender,
    underlay_mark: Option<u32>,
) -> io::Result<(Option<Box<dyn Writer>>, ListenerControl)> {
    let id = config.interface_id;
    let control = ListenerControl::new();
    {
        let startup = UdpRuntime::from_config(&config);
        *lock_or_recover(&config.runtime, "udp runtime") = startup;
    }
    let inline = crate::engine::FOLD_IO;
    let send_socket = UdpSocket::bind("0.0.0.0:0")?;
    super::apply_underlay_mark(send_socket.as_raw_fd(), underlay_mark)?;
    send_socket.set_broadcast(true)?;
    send_socket.set_nonblocking(inline)?;
    let writer: Option<Box<dyn Writer>> = Some(Box::new(UdpWriter {
        socket: send_socket,
        runtime: Arc::clone(&config.runtime),
        inline,
    }));

    // Create reader socket if listen params are set
    if let (Some(ref bind_ip), Some(bind_port)) = (&config.listen_ip, config.listen_port) {
        let bind_addr = format!("{}:{}", bind_ip, bind_port);
        let recv_socket = UdpSocket::bind(&bind_addr)?;
        super::apply_underlay_mark(recv_socket.as_raw_fd(), underlay_mark)?;
        log::info!("[{}] UDP listening on {}", config.name, bind_addr);

        // Signal interface is up
        let _ = tx.send(Event::InterfaceUp(id, None, None));

        if inline {
            recv_socket.set_nonblocking(true)?;
            let source = UdpSource {
                socket: recv_socket,
                id,
                name: config.name.clone(),
                tx: tx.clone(),
                control: control.clone(),
            };
            tx.register_source(
                crate::interface::loop_writer::read_key(id),
                Box::new(source),
            )?;
            return Ok((writer, control));
        }
        recv_socket.set_read_timeout(Some(Duration::from_millis(200)))?;

        let name = config.name.clone();
        let reader_control = control.clone();
        thread::Builder::new()
            .name(format!("udp-reader-{}", id.0))
            .spawn(move || {
                udp_reader_loop(recv_socket, id, name, tx, reader_control);
            })?;
    }

    Ok((writer, control))
}

/// Reader thread: receives UDP datagrams and sends them as frames.
fn udp_reader_loop(
    socket: UdpSocket,
    id: InterfaceId,
    name: String,
    tx: EventSender,
    control: ListenerControl,
) {
    let mut buf = [0u8; 2048];

    loop {
        if control.should_stop() {
            return;
        }
        match socket.recv_from(&mut buf) {
            Ok((n, _src)) => {
                if n == 0 {
                    continue;
                }
                if tx
                    .send(Event::Frame {
                        interface_id: id,
                        data: buf[..n].into(),
                        rssi: None,
                        snr: None,
                    })
                    .is_err()
                {
                    // Driver shut down
                    return;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => {
                if control.should_stop() {
                    return;
                }
                log::warn!("[{}] recv error: {}", name, e);
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
        }
    }
}

/// The listening socket, read on the driver loop (see
/// [`crate::engine::FOLD_IO`]).
struct UdpSource {
    socket: UdpSocket,
    id: InterfaceId,
    name: String,
    tx: EventSender,
    control: ListenerControl,
}

impl LoopSource for UdpSource {
    fn fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }

    fn stopped(&self) -> bool {
        self.control.should_stop()
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if self.control.should_stop() {
            return SourceStatus::Remove;
        }
        if !self.tx.inbound_data_has_room() {
            return SourceStatus::Suspend;
        }
        let buf = &mut cx.buf[..MAX_DATAGRAM];
        let mut frames = Vec::new();
        let mut status = SourceStatus::Rearm;
        for _ in 0..LOOP_READ_BUDGET {
            match self.socket.recv_from(buf) {
                Ok((0, _)) => {}
                Ok((n, _)) => frames.push(Event::Frame {
                    interface_id: self.id,
                    data: buf[..n].into(),
                    rssi: None,
                    snr: None,
                }),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log::warn!("[{}] recv error: {}", self.name, e);
                    frames.push(Event::InterfaceDown(self.id));
                    status = SourceStatus::Remove;
                    break;
                }
            }
        }
        match self.tx.push_from_loop(frames) {
            Ok(true) => status,
            Ok(false) if status == SourceStatus::Rearm => SourceStatus::Suspend,
            Ok(false) => status,
            Err(_) => SourceStatus::Remove,
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
            stamp_costs: Default::default(),
            id,
            name,
            mode: ctx.mode,
            gravity: ctx.gravity,
            recursive_prs: ctx.recursive_prs,
            announces_from_internal: ctx.announces_from_internal,
            announces_to_internal: ctx.announces_to_internal,
            out_capable,
            in_capable,
            bitrate: Some(10_000_000),
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: 1400,
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: crate::time::now(),
        };

        let (maybe_writer, control) = start_with_mark(udp_config, ctx.tx, ctx.underlay_mark)?;

        let writer: Box<dyn Writer> = maybe_writer
            .ok_or_else(|| io::Error::other("UDPInterface did not provide a writer"))?;

        Ok(StartResult::Simple {
            control: Some(control),
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

    #[test]
    fn detach_stops_idle_udp_listener() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let (tx, rx) = crate::event::channel();
        let control = ListenerControl::new();
        let reader_control = control.clone();

        let reader = thread::spawn(move || {
            udp_reader_loop(
                socket,
                InterfaceId(76),
                "detach-test".into(),
                tx,
                reader_control,
            )
        });
        thread::sleep(Duration::from_millis(50));
        control.request_stop();
        reader.join().unwrap();
        assert!(rx.try_recv().is_err());
    }
    use std::net::UdpSocket;
    use std::time::Duration;

    fn find_free_port() -> u16 {
        crate::test_support::port()
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
            Event::Frame {
                interface_id,
                data,
                rssi: _,
                snr: _,
            } => {
                assert_eq!(interface_id, InterfaceId(10));
                assert_eq!(&*data, &payload[..]);
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
            Event::Frame { data, .. } => assert_eq!(&*data, b"ping"),
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
                Event::Frame { data, .. } => assert_eq!(data, vec![i].into()),
                other => panic!("expected Frame, got {:?}", other),
            }
        }
    }

    #[test]
    fn empty_datagram_is_ignored_before_transport_ingress() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let config = UdpConfig {
            name: "test-udp-empty".into(),
            listen_ip: Some("127.0.0.1".into()),
            listen_port: Some(port),
            interface_id: InterfaceId(14),
            ..UdpConfig::default()
        };
        let _writer = start(config, tx).unwrap();
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = format!("127.0.0.1:{port}");
        sender.send_to(&[], &target).unwrap();
        sender.send_to(b"after-empty", &target).unwrap();

        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Frame { data, .. } => assert_eq!(&*data, b"after-empty"),
            other => panic!("expected non-empty Frame, got {other:?}"),
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
            inline: false,
        };

        let payload = vec![0xAA, 0xBB, 0xCC];
        writer.send_frame(&payload).unwrap();

        let mut buf = [0u8; 256];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], &payload);
    }

    fn thread_named(name: &str) -> bool {
        std::fs::read_dir("/proc/self/task").unwrap().any(|task| {
            let comm = task.unwrap().path().join("comm");
            std::fs::read_to_string(comm).is_ok_and(|comm| comm.trim() == name)
        })
    }

    #[test]
    fn folded_udp_interface_runs_on_the_driver_loop() {
        if !crate::engine::FOLD_IO {
            return;
        }
        let listen_port = find_free_port();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (tx, rx) = crate::event::channel();
        let config = UdpConfig {
            name: "test-udp-folded".into(),
            listen_ip: Some("127.0.0.1".into()),
            listen_port: Some(listen_port),
            forward_ip: Some("127.0.0.1".into()),
            forward_port: Some(receiver.local_addr().unwrap().port()),
            interface_id: InterfaceId(77),
            ..UdpConfig::default()
        };
        let writer = start(config, tx.clone()).unwrap().unwrap();
        assert!(writer.sends_inline());
        let (mut writer, _) =
            crate::interface::wrap_async_writer(writer, InterfaceId(77), "folded", tx, 16);
        assert!(!thread_named("udp-reader-77"));
        assert!(!thread_named("iface-writer-77"));

        // Inbound, read by the receiver's wait.
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"in", format!("127.0.0.1:{listen_port}"))
            .unwrap();
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Frame { data, .. } => assert_eq!(&*data, b"in"),
            other => panic!("expected Frame, got {other:?}"),
        }

        // Outbound, plain and confirmed.
        let mut buf = [0u8; 64];
        writer.send_frame(b"plain").unwrap();
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"plain");

        let pool = crate::link_send::SendPool::new(1);
        let (completion, receipt) = crate::link_send::Completion::new(pool.try_acquire().unwrap());
        let mut completion = Some(completion);
        writer
            .enqueue_confirmed(b"confirmed", &mut completion)
            .unwrap();
        assert!(completion.is_none());
        receipt.wait().unwrap();
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"confirmed");
    }

    #[test]
    fn writer_sends_to_an_ipv6_target() {
        let receiver = UdpSocket::bind("[::1]:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut writer = UdpWriter {
            socket: UdpSocket::bind("[::1]:0").unwrap(),
            runtime: Arc::new(Mutex::new(UdpRuntime {
                forward_ip: Some("::1".into()),
                forward_port: Some(receiver.local_addr().unwrap().port()),
            })),
            inline: false,
        };
        writer.send_frame(b"v6").unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"v6");
    }
}
