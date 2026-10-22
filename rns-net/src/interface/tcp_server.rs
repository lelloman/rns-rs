//! TCP server interface with HDLC framing.
//!
//! Accepts client connections and spawns per-client reader threads.
//! Each client gets a dynamically allocated InterfaceId.
//! Matches Python `TCPServerInterface` from `TCPInterface.py`.

use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rns_core::constants;
use rns_core::transport::types::{IngressControlConfig, InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::hdlc;
use crate::interface::tcp::{read_stream_frames, StreamRead};
use crate::interface::{lock_or_recover, ListenerControl, Writer};

/// Upstream `TCPInterface.HW_MTU` inherited by spawned server clients.
const HW_MTU: usize = 262_144;

/// Configuration for a TCP server interface.
#[derive(Debug, Clone)]
pub struct TcpServerConfig {
    pub name: String,
    pub listen_ip: String,
    pub listen_port: u16,
    pub interface_id: InterfaceId,
    pub max_connections: Option<usize>,
    pub ingress_control: IngressControlConfig,
    /// Bitrate of accepted clients; it also selects their hardware MTU tier.
    pub bitrate: Option<u64>,
    /// Hardware MTU of accepted clients, overriding the bitrate tier.
    pub fixed_mtu: Option<u32>,
    pub runtime: Arc<Mutex<TcpServerRuntime>>,
}

#[derive(Debug, Clone)]
pub struct TcpServerRuntime {
    pub max_connections: Option<usize>,
}

impl TcpServerRuntime {
    pub fn from_config(config: &TcpServerConfig) -> Self {
        Self {
            max_connections: config.max_connections,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpServerRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<TcpServerRuntime>>,
    pub startup: TcpServerRuntime,
}

impl Default for TcpServerConfig {
    fn default() -> Self {
        let mut config = TcpServerConfig {
            name: String::new(),
            listen_ip: "0.0.0.0".into(),
            listen_port: 4242,
            interface_id: InterfaceId(0),
            max_connections: None,
            ingress_control: IngressControlConfig::enabled(),
            bitrate: None,
            fixed_mtu: None,
            runtime: Arc::new(Mutex::new(TcpServerRuntime {
                max_connections: None,
            })),
        };
        let startup = TcpServerRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

/// Writer that sends HDLC-framed data over a TCP stream.
struct TcpServerWriter {
    stream: TcpStream,
    /// Reused encoding buffer for coalesced writes.
    scratch: Vec<u8>,
}

impl Writer for TcpServerWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }

    fn send_frames(&mut self, frames: &[crate::interface::FrameBytes]) -> io::Result<()> {
        hdlc::write_frames(&mut self.stream, frames, &mut self.scratch)
    }

    fn loop_socket(&self) -> Option<std::os::fd::RawFd> {
        Some(self.stream.as_raw_fd())
    }
}

/// Start a TCP server. Spawns a listener thread that accepts connections
/// and per-client reader threads. Returns immediately.
///
/// `next_id` is shared with the node for allocating unique InterfaceIds
/// for each connected client.
pub fn start(
    config: TcpServerConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
) -> io::Result<ListenerControl> {
    start_with_template(config, tx, next_id, None, None)
}

fn start_with_template(
    config: TcpServerConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    dynamic_template: Option<super::DynamicInterfaceTemplate>,
    underlay_mark: Option<u32>,
) -> io::Result<ListenerControl> {
    let addr = format!("{}:{}", config.listen_ip, config.listen_port);
    let listener = TcpListener::bind(&addr)?;
    super::apply_underlay_mark(listener.as_raw_fd(), underlay_mark)?;
    listener.set_nonblocking(true)?;

    log::info!("[{}] TCP server listening on {}", config.name, addr);

    let name = config.name.clone();
    let ifac_size = dynamic_template
        .as_ref()
        .and_then(|template| template.ifac.as_ref())
        .map(|ifac| ifac.size)
        .unwrap_or(0);
    let runtime = Arc::clone(&config.runtime);
    let ingress_control = config.ingress_control;
    let bitrate = config.bitrate;
    let mtu = super::tcp_hardware_mtu(config.bitrate, config.fixed_mtu);
    let active_connections = Arc::new(AtomicUsize::new(0));
    let control = ListenerControl::new();
    let listener_key = crate::interface::loop_writer::read_key(config.interface_id);
    tx.register_source(
        listener_key,
        Box::new(ListenerSource {
            listener,
            name,
            tx: tx.clone(),
            next_id,
            runtime,
            ingress_control,
            bitrate,
            mtu,
            active_connections,
            control: control.clone(),
            dynamic_template,
            ifac_size,
            underlay_mark,
        }),
    )?;

    Ok(control)
}

/// Connections accepted per readiness before other sources get a turn.
const ACCEPT_BURST: usize = 64;

/// The listening socket, served on the driver thread: accepts clients,
/// registers them with the driver and adds a source per client.
struct ListenerSource {
    listener: TcpListener,
    name: String,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    runtime: Arc<Mutex<TcpServerRuntime>>,
    ingress_control: IngressControlConfig,
    bitrate: Option<u64>,
    mtu: u32,
    active_connections: Arc<AtomicUsize>,
    control: ListenerControl,
    dynamic_template: Option<super::DynamicInterfaceTemplate>,
    ifac_size: usize,
    underlay_mark: Option<u32>,
}

impl LoopSource for ListenerSource {
    fn fd(&self) -> std::os::fd::RawFd {
        self.listener.as_raw_fd()
    }

    fn stopped(&self) -> bool {
        self.control.should_stop()
    }

    fn on_removed(&mut self) {
        log::info!("[{}] listener stopping", self.name);
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if self.control.should_stop() {
            return SourceStatus::Remove;
        }
        for _ in 0..ACCEPT_BURST {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) => match accept_error_step(&e) {
                    AcceptStep::Drained => break,
                    AcceptStep::Next => {
                        log::debug!("[{}] accept failed: {}", self.name, e);
                        continue;
                    }
                    AcceptStep::Pause => {
                        // The pending connection stays queued, so the
                        // listener would be ready again at once.
                        log::warn!(
                            "[{}] accept failed: {}; accepting resumes on the next tick",
                            self.name,
                            e
                        );
                        return SourceStatus::Pause;
                    }
                },
            };
            match self.admit(stream) {
                Admitted::Client(id, source) => {
                    cx.add_source(crate::interface::loop_writer::read_key(id), source)
                }
                Admitted::Rejected => {}
                Admitted::DriverGone => return SourceStatus::Remove,
            }
        }
        SourceStatus::Rearm
    }
}

/// What the accept loop does after `accept` returns an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptStep {
    /// No connection is pending: wait for readiness.
    Drained,
    /// The error concerned one pending connection only: try the next one.
    Next,
    /// The error is likely to persist (e.g. out of descriptors or memory):
    /// stop watching the listener until the next tick.
    Pause,
}

pub(crate) fn accept_error_step(error: &io::Error) -> AcceptStep {
    match error.kind() {
        io::ErrorKind::WouldBlock => AcceptStep::Drained,
        io::ErrorKind::Interrupted
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable => AcceptStep::Next,
        // Linux reports some network errors of a pending connection
        // through accept; they concern that connection only.
        _ if error.raw_os_error() == Some(libc::EPROTO) => AcceptStep::Next,
        _ => AcceptStep::Pause,
    }
}

enum Admitted {
    Client(InterfaceId, Box<dyn LoopSource>),
    Rejected,
    DriverGone,
}

impl ListenerSource {
    fn admit(&self, stream: TcpStream) -> Admitted {
        let name = &self.name;
        if let Err(error) = super::apply_underlay_mark(stream.as_raw_fd(), self.underlay_mark) {
            log::error!(
                "[{}] failed to mark accepted underlay socket: {}",
                name,
                error
            );
            return Admitted::Rejected;
        }

        // Keepalive and user timeout notice a peer that went silent or
        // stopped reading; both descriptors of the client share them.
        if let Err(error) = super::tcp::set_socket_options(&stream) {
            log::warn!(
                "[{}] failed to set socket options for {:?}: {}",
                name,
                stream.peer_addr().ok(),
                error
            );
        }

        let max_connections = lock_or_recover(&self.runtime, "tcp server runtime").max_connections;
        if let Some(max) = max_connections {
            if self.active_connections.load(Ordering::Relaxed) >= max {
                let peer = stream.peer_addr().ok();
                log::warn!(
                    "[{}] max connections ({}) reached, rejecting {:?}",
                    name,
                    max,
                    peer
                );
                return Admitted::Rejected;
            }
        }

        let client_id = InterfaceId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let peer_addr = stream.peer_addr().ok();

        log::info!(
            "[{}] client connected: {:?} → id {}",
            name,
            peer_addr,
            client_id.0
        );

        // Clone stream for writer
        let writer_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[{}] failed to clone stream: {}", name, e);
                return Admitted::Rejected;
            }
        };

        let writer: Box<dyn Writer> = Box::new(TcpServerWriter {
            stream: writer_stream,
            scratch: Vec::new(),
        });

        let info = InterfaceInfo {
            id: client_id,
            name: format!("TCPServerInterface/Client-{}", client_id.0),
            mode: constants::MODE_FULL,
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            out_capable: true,
            in_capable: true,
            bitrate: self.bitrate,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: self.mtu,
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
            ingress_control: self.ingress_control,
        };

        // Register the client with the driver before any of its frames: the
        // queue never delivers a frame ahead of an older control event.
        let registration = if let Some(template) = &self.dynamic_template {
            Event::DynamicInterfaceUp {
                id: client_id,
                writer,
                registration: Box::new(template.registration(info)),
            }
        } else {
            Event::InterfaceUp(client_id, Some(writer), Some(Box::new(info)))
        };
        if self.tx.push_from_loop([registration]).is_err() {
            return Admitted::DriverGone;
        }

        self.active_connections.fetch_add(1, Ordering::Relaxed);
        Admitted::Client(
            client_id,
            Box::new(ClientSource {
                stream,
                id: client_id,
                name: name.clone(),
                tx: self.tx.clone(),
                active_connections: Arc::clone(&self.active_connections),
                decoder: hdlc::Decoder::reticulum(HW_MTU, self.ifac_size),
                control: self.control.clone(),
            }),
        )
    }
}

/// One accepted client, read on the driver thread.
struct ClientSource {
    stream: TcpStream,
    id: InterfaceId,
    name: String,
    tx: EventSender,
    active_connections: Arc<AtomicUsize>,
    decoder: hdlc::Decoder,
    control: ListenerControl,
}

impl LoopSource for ClientSource {
    fn fd(&self) -> std::os::fd::RawFd {
        self.stream.as_raw_fd()
    }

    fn stopped(&self) -> bool {
        self.control.should_stop()
    }

    fn on_removed(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    fn on_abandoned(&mut self) {
        // The driver was told about this client; it will never be read.
        let _ = self.tx.push_from_loop([Event::InterfaceDown(self.id)]);
        self.on_removed();
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if self.control.should_stop() {
            return SourceStatus::Remove;
        }
        match read_stream_frames(
            self.stream.as_raw_fd(),
            &mut self.decoder,
            cx,
            &self.tx,
            self.id,
            &self.name,
            |_, _| {},
        ) {
            StreamRead::Rearm => SourceStatus::Rearm,
            StreamRead::Suspend => SourceStatus::Suspend,
            StreamRead::Closed => {
                log::info!("[{}] client {} disconnected", self.name, self.id.0);
                let _ = self.tx.push_from_loop([Event::InterfaceDown(self.id)]);
                SourceStatus::Remove
            }
            StreamRead::Failed(e) => {
                log::warn!("[{}] client {} read error: {}", self.name, self.id.0, e);
                let _ = self.tx.push_from_loop([Event::InterfaceDown(self.id)]);
                SourceStatus::Remove
            }
            StreamRead::DriverGone => SourceStatus::Remove,
        }
    }
}

// --- Factory implementation ---

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};
use std::collections::HashMap;

/// Factory for `TCPServerInterface`.
pub struct TcpServerFactory;

impl InterfaceFactory for TcpServerFactory {
    fn type_name(&self) -> &str {
        "TCPServerInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let listen_ip = params
            .get("listen_ip")
            .cloned()
            .unwrap_or_else(|| "0.0.0.0".into());
        let listen_port = params
            .get("listen_port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(4242);
        let max_connections = params.get("max_connections").and_then(|v| v.parse().ok());
        let (bitrate, fixed_mtu) = super::parse_tcp_rate_params(params)?;
        let mut config = TcpServerConfig {
            name: name.to_string(),
            listen_ip,
            listen_port,
            interface_id: id,
            max_connections,
            ingress_control: IngressControlConfig::enabled(),
            bitrate,
            fixed_mtu,
            runtime: Arc::new(Mutex::new(TcpServerRuntime {
                max_connections: None,
            })),
        };
        let startup = TcpServerRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        Ok(Box::new(config))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let mut cfg = *config
            .into_any()
            .downcast::<TcpServerConfig>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong config type"))?;
        cfg.ingress_control = ctx.ingress_control;
        let parent_id = cfg.interface_id;
        let control = start_with_template(
            cfg,
            ctx.tx,
            ctx.next_dynamic_id,
            Some(super::DynamicInterfaceTemplate {
                parent_id,
                interface_type: "TCPServerClientInterface".into(),
                ifac: ctx.ifac,
                mode: ctx.mode,
                gravity: ctx.gravity,
                recursive_prs: ctx.recursive_prs,
                announces_from_internal: ctx.announces_from_internal,
                announces_to_internal: ctx.announces_to_internal,
            }),
            ctx.underlay_mark,
        )?;
        Ok(StartResult::Listener {
            control: Some(control),
        })
    }
}

pub(crate) fn runtime_handle_from_config(config: &TcpServerConfig) -> TcpServerRuntimeConfigHandle {
    TcpServerRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: TcpServerRuntime::from_config(config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpStream;
    use std::sync::mpsc::RecvTimeoutError;
    use std::thread;
    use std::time::Duration;

    fn find_free_port() -> u16 {
        crate::test_support::port()
    }

    fn make_server_config(
        port: u16,
        interface_id: u64,
        max_connections: Option<usize>,
    ) -> TcpServerConfig {
        let mut config = TcpServerConfig {
            name: "test-server".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(interface_id),
            max_connections,
            bitrate: None,
            fixed_mtu: None,
            ingress_control: IngressControlConfig::enabled(),
            runtime: Arc::new(Mutex::new(TcpServerRuntime {
                max_connections: None,
            })),
        };
        let startup = TcpServerRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stop_resume_preserves_partial_server_frame() {
        use std::io::{BufRead, BufReader};
        use std::process::{Child, Command, Stdio};
        use std::sync::mpsc;

        const CHILD_PORT: &str = "RNS_TEST_INTERRUPTED_TCP_SERVER_PORT";
        const ROUNDS: usize = 3;
        let payload = vec![0x7e; constants::HEADER_MINSIZE + 16];
        if let Ok(port) = std::env::var(CHILD_PORT) {
            let (tx, rx) = crate::event::channel();
            let control = start(
                make_server_config(port.parse().unwrap(), 1, None),
                tx,
                Arc::new(AtomicU64::new(1200)),
            )
            .unwrap();
            println!("EINTR_READY");
            let registration = rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(matches!(
                registration,
                Event::InterfaceUp(InterfaceId(1200), _, _)
            ));
            println!("EINTR_CONNECTED");
            for round in 0..ROUNDS {
                let event = rx.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(
                    matches!(event, Event::Frame { interface_id: InterfaceId(1200), data, .. } if data == payload),
                    "read interruption must preserve the connection and partial frame"
                );
                println!("EINTR_FRAME_{round}");
            }
            control.request_stop();
            return;
        }

        // Signals affect only the isolated child, never the parallel test runner.
        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                if matches!(self.0.try_wait(), Ok(None)) {
                    unsafe { libc::kill(self.0.id() as i32, libc::SIGCONT) };
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        let port = find_free_port();
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "interface::tcp_server::tests::stop_resume_preserves_partial_server_frame",
                    "--exact",
                    "--nocapture",
                ])
                .env(CHILD_PORT, port.to_string())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (lines_tx, lines_rx) = mpsc::channel();
        let output = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if lines_tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let wait_for = |expected: &str| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let line = lines_rx
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                    .unwrap_or_else(|error| panic!("waiting for {expected}: {error}"));
                if line == expected {
                    break;
                }
            }
        };
        wait_for("EINTR_READY");
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        wait_for("EINTR_CONNECTED");
        let frame = hdlc::frame(&payload);
        // Interrupt with an escape byte pending in the HDLC decoder.
        let split = frame.iter().position(|b| *b == 0x7d).unwrap() + 1;
        for round in 0..ROUNDS {
            client.write_all(&frame[..split]).unwrap();
            thread::sleep(Duration::from_millis(30));
            assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGSTOP) }, 0);
            thread::sleep(Duration::from_millis(200));
            assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGCONT) }, 0);
            client.write_all(&frame[split..]).unwrap();
            wait_for(&format!("EINTR_FRAME_{round}"));
        }
        assert!(child.0.wait().unwrap().success());
        output.join().unwrap();
    }

    #[test]
    fn accept_connection() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(1000));

        let config = make_server_config(port, 1, None);

        start(config, tx, next_id).unwrap();

        // Give server time to start listening
        thread::sleep(Duration::from_millis(50));

        // Connect a client
        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Should receive InterfaceUp with InterfaceInfo (dynamic)
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::InterfaceUp(id, writer, info) => {
                assert_eq!(id, InterfaceId(1000));
                assert!(writer.is_some());
                assert!(info.is_some());
            }
            other => panic!("expected InterfaceUp, got {:?}", other),
        }
    }

    #[test]
    fn spawned_client_drops_exact_header_minimum_and_recovers() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(1100));
        start(make_server_config(port, 1, None), tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::InterfaceUp(InterfaceId(1100), _, _)
        ));
        client
            .write_all(&hdlc::frame(&[0x11; rns_core::constants::HEADER_MINSIZE]))
            .unwrap();
        let valid = vec![0x22; rns_core::constants::HEADER_MINSIZE + 1];
        client.write_all(&hdlc::frame(&valid)).unwrap();

        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::Frame { interface_id: InterfaceId(1100), data, .. } if data == valid
        ));
    }

    #[test]
    fn typed_registration_carries_exact_type_mode_parent_and_ifac() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let ifac = crate::ifac::derive_ifac(Some("network"), Some("key"), 8).unwrap();
        let template = crate::interface::DynamicInterfaceTemplate {
            parent_id: InterfaceId(77),
            interface_type: "TCPServerClientInterface".into(),
            ifac: Some(ifac),
            mode: constants::MODE_GATEWAY,
            gravity: -6,
            recursive_prs: true,
            announces_from_internal: false,
            announces_to_internal: None,
        };
        start_with_template(
            make_server_config(port, 77, None),
            tx,
            Arc::new(AtomicU64::new(1200)),
            Some(template),
            None,
        )
        .unwrap();
        thread::sleep(Duration::from_millis(50));
        let _client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::DynamicInterfaceUp { registration, .. } => {
                assert_eq!(registration.parent_id, InterfaceId(77));
                assert_eq!(registration.interface_type, "TCPServerClientInterface");
                assert_eq!(registration.info.mode, constants::MODE_GATEWAY);
                assert_eq!(registration.info.gravity, -6);
                assert!(registration.info.recursive_prs);
                assert!(!registration.info.announces_from_internal);
                assert_eq!(registration.ifac.as_ref().map(|state| state.size), Some(8));
            }
            other => panic!("expected typed dynamic registration, got {other:?}"),
        }
    }

    #[test]
    fn spawned_client_inherits_ingress_control_config() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(1100));

        let mut config = make_server_config(port, 11, None);
        config.ingress_control = IngressControlConfig::disabled();
        config.ingress_control.max_held_announces = 17;
        config.ingress_control.burst_hold = 1.5;
        config.ingress_control.burst_freq_new = 2.5;
        config.ingress_control.burst_freq = 3.5;
        config.ingress_control.new_time = 4.5;
        config.ingress_control.burst_penalty = 5.5;
        config.ingress_control.held_release_interval = 6.5;

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::InterfaceUp(_, _, Some(info)) => {
                assert!(!info.ingress_control.enabled);
                assert_eq!(info.ingress_control.max_held_announces, 17);
                assert_eq!(info.ingress_control.burst_hold, 1.5);
                assert_eq!(info.ingress_control.burst_freq_new, 2.5);
                assert_eq!(info.ingress_control.burst_freq, 3.5);
                assert_eq!(info.ingress_control.new_time, 4.5);
                assert_eq!(info.ingress_control.burst_penalty, 5.5);
                assert_eq!(info.ingress_control.held_release_interval, 6.5);
            }
            other => panic!("expected InterfaceUp with InterfaceInfo, got {:?}", other),
        }
    }

    #[test]
    fn listener_stop_prevents_new_accepts() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(1500));

        let config = make_server_config(port, 15, None);
        let control = start(config, tx, next_id).unwrap();

        thread::sleep(Duration::from_millis(50));
        control.request_stop();
        thread::sleep(Duration::from_millis(120));

        let connect_result = TcpStream::connect(format!("127.0.0.1:{}", port));
        if let Ok(stream) = connect_result {
            drop(stream);
        }

        match rx.recv_timeout(Duration::from_millis(200)) {
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {}
            other => panic!(
                "expected no InterfaceUp after listener stop, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn receive_frame_from_client() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(2000));

        let config = make_server_config(port, 2, None);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send an HDLC frame (>= 19 bytes)
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        client.write_all(&framed).unwrap();

        // Should receive Frame event
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame {
                interface_id,
                data,
                rssi: _,
                snr: _,
            } => {
                assert_eq!(interface_id, InterfaceId(2000));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn a_flood_into_a_small_queue_suspends_reading_without_losing_frames() {
        const FRAMES: u32 = 3000;
        let port = find_free_port();
        let (tx, rx) = crate::event::channel_with_capacity(4);
        let snapshot_tx = tx.clone();
        start(
            make_server_config(port, 4, None),
            tx,
            Arc::new(AtomicU64::new(4000)),
        )
        .unwrap();
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::InterfaceUp(InterfaceId(4000), _, _)
        ));

        let writer = thread::spawn(move || {
            let mut wire = Vec::new();
            for seq in 0..FRAMES {
                let mut payload = vec![0u8; 32];
                payload[2..18].copy_from_slice(&[0x5A; 16]);
                payload[20..24].copy_from_slice(&seq.to_be_bytes());
                wire.extend(hdlc::frame(&payload));
            }
            client.write_all(&wire).unwrap();
            client
        });

        for expected in 0..FRAMES {
            match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Frame {
                    interface_id, data, ..
                } => {
                    assert_eq!(interface_id, InterfaceId(4000));
                    let seq = u32::from_be_bytes(data[20..24].try_into().unwrap());
                    assert_eq!(seq, expected, "frames lost or reordered");
                }
                other => panic!("expected Frame, got {:?}", other),
            }
        }
        let _client = writer.join().unwrap();
        assert_eq!(snapshot_tx.inbound_queue_snapshot().dropped, [0, 0, 0, 0]);
    }

    #[test]
    fn dropping_the_receiver_closes_the_listener() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        start(
            make_server_config(port, 6, None),
            tx,
            Arc::new(AtomicU64::new(6000)),
        )
        .unwrap();
        drop(rx);
        let refused = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn a_stopped_listener_is_closed_at_the_next_sweep() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let control = start(
            make_server_config(port, 5, None),
            tx,
            Arc::new(AtomicU64::new(5000)),
        )
        .unwrap();
        control.request_stop();
        rx.sweep_stopped_sources();
        let refused = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn accept_errors_map_to_drain_next_or_pause() {
        use io::ErrorKind;
        let step = |kind: ErrorKind| accept_error_step(&io::Error::from(kind));
        assert_eq!(step(ErrorKind::WouldBlock), AcceptStep::Drained);
        for kind in [
            ErrorKind::Interrupted,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::NetworkDown,
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
        ] {
            assert_eq!(step(kind), AcceptStep::Next, "{kind:?}");
        }
        assert_eq!(
            accept_error_step(&io::Error::from_raw_os_error(libc::ECONNABORTED)),
            AcceptStep::Next
        );
        assert_eq!(
            accept_error_step(&io::Error::from_raw_os_error(libc::EPROTO)),
            AcceptStep::Next
        );
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(
                accept_error_step(&io::Error::from_raw_os_error(errno)),
                AcceptStep::Pause,
                "errno {errno}"
            );
        }
    }

    /// Pauses on its first pass without accepting, as the listener does
    /// after an accept error, then serves the real listener.
    struct PauseOnce {
        inner: ListenerSource,
        paused: bool,
    }

    impl LoopSource for PauseOnce {
        fn fd(&self) -> std::os::fd::RawFd {
            self.inner.fd()
        }
        fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
            if !std::mem::replace(&mut self.paused, true) {
                return SourceStatus::Pause;
            }
            self.inner.on_ready(cx)
        }
    }

    fn serve_pass(rx: &crate::event::EventReceiver) {
        let mut ready = polling::Events::new();
        rx.wait(&mut ready, Some(Duration::from_millis(50)))
            .unwrap();
        rx.serve_sources(&ready);
    }

    #[test]
    fn connections_made_while_the_listener_is_paused_are_accepted_after_the_resume() {
        let (tx, rx) = crate::event::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let config = make_server_config(addr.port(), 8, None);
        let inner = ListenerSource {
            listener,
            name: config.name.clone(),
            tx: tx.clone(),
            next_id: Arc::new(AtomicU64::new(8000)),
            runtime: Arc::clone(&config.runtime),
            ingress_control: config.ingress_control,
            bitrate: None,
            mtu: crate::interface::TCP_DEFAULT_MTU,
            active_connections: Arc::new(AtomicUsize::new(0)),
            control: ListenerControl::new(),
            dynamic_template: None,
            ifac_size: 0,
            underlay_mark: None,
        };
        tx.register_source(
            crate::interface::loop_writer::read_key(config.interface_id),
            Box::new(PauseOnce {
                inner,
                paused: false,
            }),
        )
        .unwrap();

        let _first = TcpStream::connect(addr).unwrap();
        serve_pass(&rx);
        let _second = TcpStream::connect(addr).unwrap();
        for _ in 0..3 {
            serve_pass(&rx);
        }
        assert!(
            rx.try_recv().is_err(),
            "a paused listener accepted a connection"
        );

        rx.resume_paused_sources();
        let mut up = Vec::new();
        for _ in 0..20 {
            serve_pass(&rx);
            while let Ok(event) = rx.try_recv() {
                match event {
                    Event::InterfaceUp(id, _, _) => up.push(id),
                    other => panic!("expected InterfaceUp, got {:?}", other),
                }
            }
            if up.len() == 2 {
                break;
            }
        }
        assert_eq!(up, [InterfaceId(8000), InterfaceId(8001)]);
    }

    fn sockopt_int(fd: std::os::fd::RawFd, level: libc::c_int, name: libc::c_int) -> libc::c_int {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `value` and `len` are valid for the call and sized for an int.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                &mut value as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt: {}", io::Error::last_os_error());
        value
    }

    #[test]
    fn accepted_sockets_get_keepalive_and_timeout_options() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        start(
            make_server_config(port, 9, None),
            tx,
            Arc::new(AtomicU64::new(9000)),
        )
        .unwrap();
        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let writer = match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::InterfaceUp(_, Some(writer), _) => writer,
            other => panic!("expected InterfaceUp with writer, got {:?}", other),
        };
        let fd = writer
            .loop_socket()
            .expect("server writer exposes its socket");
        assert_eq!(sockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
        assert_eq!(sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY), 1);
        #[cfg(target_os = "linux")]
        assert_eq!(
            sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT),
            24_000
        );
    }

    #[test]
    fn send_frame_to_client() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(3000));

        let config = make_server_config(port, 3, None);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Get the writer from InterfaceUp
        let event = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let mut writer = match event {
            Event::InterfaceUp(_, Some(w), _) => w,
            other => panic!("expected InterfaceUp with writer, got {:?}", other),
        };

        // Send a frame via writer
        let payload: Vec<u8> = (0..24).collect();
        writer.send_frame(&payload).unwrap();

        // Read from client side
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).unwrap();
        let expected = hdlc::frame(&payload);
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn multiple_clients() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(4000));

        let config = make_server_config(port, 4, None);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect two clients
        let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Collect InterfaceUp events
        let mut ids = Vec::new();
        for _ in 0..2 {
            let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            match event {
                Event::InterfaceUp(id, _, _) => ids.push(id),
                other => panic!("expected InterfaceUp, got {:?}", other),
            }
        }

        // Should have unique IDs
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn client_disconnect() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(5000));

        let config = make_server_config(port, 5, None);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Disconnect
        drop(client);

        // Should receive InterfaceDown
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            matches!(event, Event::InterfaceDown(InterfaceId(5000))),
            "expected InterfaceDown(5000), got {:?}",
            event
        );
    }

    #[test]
    fn server_bind_port() {
        let port = find_free_port();
        let (tx, _rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(6000));

        let config = make_server_config(port, 6, None);

        // Should not error
        start(config, tx, next_id).unwrap();
    }

    #[test]
    fn max_connections_rejects_excess() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7000));

        let config = make_server_config(port, 7, Some(2));

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect two clients (at limit)
        let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain both InterfaceUp events
        for _ in 0..2 {
            let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(matches!(event, Event::InterfaceUp(_, _, _)));
        }

        // Third connection should be accepted at TCP level but immediately dropped by server
        let client3 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client3
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        // Give server time to reject
        thread::sleep(Duration::from_millis(100));

        // Should NOT receive a third InterfaceUp
        let result = rx.recv_timeout(Duration::from_millis(500));
        assert!(
            result.is_err(),
            "expected no InterfaceUp for rejected connection, got {:?}",
            result
        );
    }

    #[test]
    fn max_connections_allows_after_disconnect() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7100));

        let config = make_server_config(port, 71, Some(1));

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect first client
        let client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(_, _, _)));

        // Disconnect first client
        drop(client1);

        // Wait for InterfaceDown
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(_)));

        // Now a new connection should be accepted
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            matches!(event, Event::InterfaceUp(_, _, _)),
            "expected InterfaceUp after slot freed, got {:?}",
            event
        );
    }

    #[test]
    fn runtime_max_connections_updates_live() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7200));

        let config = make_server_config(port, 72, None);
        let runtime = Arc::clone(&config.runtime);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(_, _, _)));

        {
            let mut runtime = runtime.lock().unwrap();
            runtime.max_connections = Some(1);
        }

        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let result = rx.recv_timeout(Duration::from_millis(400));
        assert!(
            result.is_err(),
            "expected no InterfaceUp after lowering max_connections, got {:?}",
            result
        );
    }
}
