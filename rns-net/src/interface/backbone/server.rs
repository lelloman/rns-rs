//! Server mode: the listener and the poll thread serving its peers,
//! and the ingress pressure it watches.

#![allow(
    unsafe_code,
    reason = "descriptors registered with the poller and OS calls through libc"
)]

use super::*;
use std::os::fd::AsFd;

/// Concurrent clients a Backbone listener accepts unless configured
/// otherwise (upstream `BackboneInterface.CLIENT_LIMIT`, rgit `3c4b271f`).
pub const BACKBONE_CLIENT_LIMIT: usize = 500;

/// Writer that sends HDLC-framed data over a cloned TCP stream (server mode).
///
/// The server poller owns only readable interest on the original stream. This
/// independent writer therefore never enables or re-arms writable poll events;
/// an already-pending buffer is retried directly before accepting another
/// frame.
pub(super) struct BackboneWriter {
    stream: TcpStream,
    runtime: Arc<Mutex<BackboneServerRuntime>>,
    interface_name: String,
    interface_id: InterfaceId,
    event_tx: EventSender,
    transmit_buffer: TransmitBuffer,
    egress_controller: EgressController,
    egress_control: EgressControl,
    egress_started: Instant,
    stall_started: Option<Instant>,
    disconnect_notified: bool,
    write_stall_flag: Arc<AtomicBool>,
}

impl Writer for BackboneWriter {
    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
        // The async writer has already reserved this frame's byte budget.
        // Once admitted, retain it even if the egress gate subsequently closes.
        if !self
            .transmit_buffer
            .append_with_limit(hdlc::frame(data), Some(EGRESS_HIGH_WATERMARK))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "confirmed frame exceeds backbone buffer",
            ));
        }
        self.transmit_buffer.flush();
        let timeout = lock_or_recover(&self.runtime, "backbone runtime").write_stall_timeout;
        self.drain_transmit(timeout)
    }
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.send_frames(&[crate::interface::FrameBytes::Owned(data.to_vec())])
    }

    fn send_frames(&mut self, frames: &[crate::interface::FrameBytes]) -> io::Result<()> {
        let write_stall_timeout =
            lock_or_recover(&self.runtime, "backbone runtime").write_stall_timeout;
        if self.transmit_buffer.buffered_bytes() > 0 {
            self.drain_transmit(write_stall_timeout)?;
            if self.transmit_buffer.buffered_bytes() > 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "backbone writer still stalled",
                ));
            }
        }

        let elapsed = self.egress_started.elapsed();
        let _ = self.egress_controller.evaluate(
            elapsed,
            self.transmit_buffer.buffered_bytes(),
            self.transmit_buffer.sendable_bytes(),
            self.transmit_buffer.total_sent_bytes(),
        );
        self.egress_control
            .set_stalled(self.egress_controller.stalled());
        for frame in frames {
            let encoded = hdlc::frame(frame);
            let encoded_len = encoded.len();
            if self.egress_control.stalled()
                || !self
                    .transmit_buffer
                    .append_with_limit(encoded, Some(EGRESS_HIGH_WATERMARK))
            {
                self.egress_control.record_drop(encoded_len);
                log::debug!(
                    "[{}:{}] egress control dropped outbound frame of {} bytes",
                    self.interface_name,
                    self.interface_id.0,
                    encoded_len
                );
            }
        }
        self.transmit_buffer.flush();
        self.drain_transmit(write_stall_timeout)
    }

    fn flush(&mut self) -> io::Result<()> {
        let timeout = lock_or_recover(&self.runtime, "backbone runtime").write_stall_timeout;
        self.drain_transmit(timeout)
    }

    fn egress_control(&self) -> Option<EgressControl> {
        Some(self.egress_control.clone())
    }

    fn loop_socket(&self) -> Option<std::os::fd::RawFd> {
        Some(self.stream.as_raw_fd())
    }

    fn loop_egress(&mut self) -> Option<LoopEgress> {
        let runtime = Arc::clone(&self.runtime);
        Some(
            LoopEgress::budget(self.egress_control.clone()).with_stall_watch(
                move || lock_or_recover(&runtime, "backbone runtime").write_stall_timeout,
                Arc::clone(&self.write_stall_flag),
            ),
        )
    }

    fn shutdown(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl BackboneWriter {
    pub(super) fn drain_transmit(
        &mut self,
        write_stall_timeout: Option<Duration>,
    ) -> io::Result<()> {
        if self.transmit_buffer.buffered_bytes() == 0 {
            return Ok(());
        }

        let written = self.transmit_buffer.drain_to(&mut self.stream)?;
        if written > 0 {
            self.stall_started = None;
        }
        let elapsed = self.egress_started.elapsed();
        let dead_time = write_stall_timeout.unwrap_or(EGRESS_DEAD_TIME);
        let dead = self.egress_controller.evaluate_with(
            elapsed,
            self.transmit_buffer.buffered_bytes(),
            self.transmit_buffer.sendable_bytes(),
            self.transmit_buffer.total_sent_bytes(),
            dead_time,
        );
        self.egress_control
            .set_stalled(self.egress_controller.stalled());
        if dead {
            return Err(self.disconnect_for_write_stall(dead_time));
        }
        if self.transmit_buffer.buffered_bytes() == 0 {
            return Ok(());
        }

        let now = Instant::now();
        let started = self.stall_started.get_or_insert(now);
        let timeout = write_stall_timeout.unwrap_or(EGRESS_DEAD_TIME);
        if now.duration_since(*started) >= timeout {
            return Err(self.disconnect_for_write_stall(timeout));
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "backbone writer would block",
        ))
    }

    pub(super) fn disconnect_for_write_stall(&mut self, timeout: Duration) -> io::Error {
        if !self.disconnect_notified {
            log::warn!(
                "[{}] backbone client {} disconnected due to write stall timeout ({:?})",
                self.interface_name,
                self.interface_id.0,
                timeout
            );
            self.write_stall_flag.store(true, Ordering::Relaxed);
            let _ = self.stream.shutdown(Shutdown::Both);
            let _ = self.event_tx.send(Event::InterfaceDown(self.interface_id));
            self.disconnect_notified = true;
        }
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("backbone writer stalled for {:?}", timeout),
        )
    }
}

/// Start a backbone interface. Binds the TCP listener, which is served
/// with its peers on the receiving (driver) thread.
pub fn start(config: BackboneConfig, tx: EventSender, next_id: Arc<AtomicU64>) -> io::Result<()> {
    start_with_template(config, tx, next_id, None, None)
}

pub(super) fn start_with_template(
    config: BackboneConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    dynamic_template: Option<DynamicInterfaceTemplate>,
    underlay_mark: Option<u32>,
) -> io::Result<()> {
    let addr = format!("{}:{}", config.listen_ip, config.listen_port);
    // std listens with a backlog of 128 (Rust 1.96.0,
    // library/std/src/sys/net/connection/socket/mod.rs), above the 16
    // upstream's BackboneInterface listeners use since 52898683 (1 before).
    let listener = TcpListener::bind(&addr)?;
    crate::interface::apply_underlay_mark(listener.as_fd(), underlay_mark)?;
    listener.set_nonblocking(true)?;

    log::info!(
        "[{}] backbone server listening on {}",
        config.name,
        listener
            .local_addr()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], config.listen_port)))
    );

    let ifac_size = dynamic_template
        .as_ref()
        .and_then(|template| template.ifac.as_ref())
        .map(|ifac| ifac.size)
        .unwrap_or(0);
    // Queue capacities are finalized before interfaces start. Derive the
    // ingress controller's watermarks once, before any listener can read.
    let ingress_thresholds = ingress_thresholds(tx.inbound_queue_snapshot().capacities[0]);
    let server = Arc::new(Server {
        name: config.name.clone(),
        server_interface_id: config.interface_id,
        tx: tx.clone(),
        next_id,
        runtime: Arc::clone(&config.runtime),
        peer_state: Arc::clone(&config.peer_state),
        fast_flap: config.fast_flap,
        fast_flap_state: Arc::clone(&config.fast_flap_state),
        ingress_control: config.ingress_control,
        accepted_peer_mode: config.mode,
        accepted_peer_gravity: config.gravity,
        accepted_peer_recursive_prs: config.recursive_prs,
        accepted_peer_announces_from_internal: config.announces_from_internal,
        accepted_peer_announces_to_internal: config.announces_to_internal,
        dynamic_template,
        ifac_size,
        underlay_mark,
        ingress_thresholds,
        state: Mutex::new(ServerState {
            clients: HashMap::new(),
            peers: HashMap::new(),
            ingress_snapshot_at: Instant::now(),
        }),
    });
    tx.register_source(
        crate::interface::loop_writer::read_key(config.interface_id),
        Box::new(ListenerSource {
            listener,
            server,
            next_interval: Instant::now() + DP_IC_INTERVAL,
        }),
    )
}

/// Connections accepted per readiness before other sources get a turn.
pub(super) const ACCEPT_BURST: usize = 64;

/// A listener's configuration and the state its peers share. The listener
/// and all its peers are served on the same thread, so `state` is never
/// contended.
pub(super) struct Server {
    name: String,
    server_interface_id: InterfaceId,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    runtime: Arc<Mutex<BackboneServerRuntime>>,
    peer_state: Arc<Mutex<BackbonePeerMonitor>>,
    fast_flap: BackboneFastFlapConfig,
    fast_flap_state: Arc<Mutex<BackboneFastFlapMonitor>>,
    ingress_control: IngressControlConfig,
    accepted_peer_mode: u8,
    accepted_peer_gravity: i64,
    accepted_peer_recursive_prs: bool,
    accepted_peer_announces_from_internal: bool,
    accepted_peer_announces_to_internal: Option<bool>,
    dynamic_template: Option<DynamicInterfaceTemplate>,
    ifac_size: usize,
    underlay_mark: Option<u32>,
    ingress_thresholds: IngressThresholds,
    state: Mutex<ServerState>,
}

pub(super) struct ServerState {
    /// Connected peers by poller key.
    clients: HashMap<usize, ClientState>,
    peers: HashMap<IpAddr, PeerBehaviorState>,
    ingress_snapshot_at: Instant,
}

/// Per-client tracking state.
pub(super) struct ClientState {
    id: InterfaceId,
    peer_ip: IpAddr,
    peer_port: u16,
    /// The peer's socket, owned by its source, which removes this entry
    /// before the socket is closed.
    fd: std::os::fd::RawFd,
    connected_at: Instant,
    has_received_data: bool,
    write_stall_flag: Arc<AtomicBool>,
    /// The idle timeout shut the socket down; the peer source reports it
    /// once it reads the end of the stream.
    idle_timed_out: bool,
    dp_ingress_bytes: u64,
    dp_ingress_packets: u64,
    dp_ingress_hold: Option<Instant>,
    dp_ingress_gated: bool,
    dp_ingress_throttle_count: u64,
}

impl Server {
    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, ServerState> {
        lock_or_recover(&self.state, "backbone server state")
    }

    /// Take blacklist changes made through management and expire what is
    /// due, then publish the merged view.
    pub(super) fn sync_peer_state(&self, state: &mut ServerState) {
        let mut monitor = lock_or_recover(&self.peer_state, "backbone peer state");
        monitor.sync_into(&mut state.peers);
        cleanup_peer_state(&mut state.peers);
        monitor.upsert_snapshot(&state.peers);
    }

    /// Watch a peer for readability again, or stop watching it.
    pub(super) fn set_readable(&self, key: usize, fd: std::os::fd::RawFd, readable: bool) {
        // SAFETY: `fd` belongs to a registered peer source (see `ClientState`).
        let source = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        if let Err(error) = self.tx.set_source_readable(source, key, readable) {
            log::warn!(
                "[{}] cannot update peer read interest: {}",
                self.name,
                error
            );
        }
    }

    /// Stop reading the peer that produced the most packets this sample
    /// for a hold proportional to the sample span. Returns its key.
    pub(super) fn throttle_busiest_ingress(&self, state: &mut ServerState) -> Option<usize> {
        let key = busiest_ingress_key(
            state
                .clients
                .iter()
                .map(|(key, client)| (*key, client.dp_ingress_packets)),
        )?;
        let allocation_divisor = state.clients.len().max(DP_IC_IF_HEADROOM) as f64 * DP_IC_PENALTY;
        let sample_span = state.ingress_snapshot_at.elapsed();
        let client = state.clients.get_mut(&key)?;
        if client.dp_ingress_gated {
            return None;
        }
        let hold = Duration::from_secs_f64(
            (sample_span.as_secs_f64().max(0.001) * allocation_divisor).max(0.001),
        );
        client.dp_ingress_gated = true;
        client.dp_ingress_hold = Some(Instant::now() + hold);
        client.dp_ingress_throttle_count = client.dp_ingress_throttle_count.saturating_add(1);
        log::info!(
            "ingress throttled on BackboneInterface/{} for {:.3}s",
            client.id.0,
            hold.as_secs_f64(),
        );
        Some(key)
    }

    /// Resume reading one gated peer whose hold has passed.
    pub(super) fn release_one_ingress(&self, state: &mut ServerState, now: Instant) {
        let Some((key, client)) = state.clients.iter_mut().find(|(_, client)| {
            client.dp_ingress_gated
                && client
                    .dp_ingress_hold
                    .is_none_or(|hold_until| now >= hold_until)
        }) else {
            return;
        };
        client.dp_ingress_gated = false;
        client.dp_ingress_hold = None;
        log::info!(
            "released ingress throttle on BackboneInterface/{}",
            client.id.0
        );
        self.set_readable(*key, client.fd, true);
    }

    /// The listener's periodic work: ingress throttling and idle timeouts.
    pub(super) fn interval(&self) {
        let mut state = self.lock();
        let state = &mut *state;
        self.sync_peer_state(state);
        let now = Instant::now();
        if now.duration_since(state.ingress_snapshot_at) >= DP_IC_INTERVAL {
            let height = self.tx.inbound_queue_snapshot().heights[0];
            if height > self.ingress_thresholds.mid {
                if let Some(key) = self.throttle_busiest_ingress(state) {
                    self.set_readable(key, state.clients[&key].fd, false);
                }
            } else if height < self.ingress_thresholds.low {
                self.release_one_ingress(state, now);
            }
            for client in state.clients.values_mut() {
                client.dp_ingress_bytes = 0;
                client.dp_ingress_packets = 0;
            }
            state.ingress_snapshot_at = now;
        }

        let idle_timeout = lock_or_recover(&self.runtime, "backbone runtime").idle_timeout;
        if let Some(timeout) = idle_timeout {
            for (key, client) in state.clients.iter_mut() {
                if client.has_received_data
                    || client.idle_timed_out
                    || now.duration_since(client.connected_at) < timeout
                {
                    continue;
                }
                // The peer source reports the disconnect when it reads the
                // end of the stream, gated or not.
                client.idle_timed_out = true;
                // SAFETY: the descriptor is open (see `ClientState`).
                unsafe { libc::shutdown(client.fd, libc::SHUT_RDWR) };
                self.set_readable(*key, client.fd, true);
            }
        }
    }

    /// Accept one connection; returns `false` once the driver is gone.
    pub(super) fn admit(
        self: &Arc<Self>,
        state: &mut ServerState,
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        cx: &mut LoopContext<'_>,
    ) -> bool {
        let name = &self.name;
        if let Err(error) =
            crate::interface::apply_underlay_mark(stream.as_fd(), self.underlay_mark)
        {
            log::error!(
                "[{}] failed to mark accepted underlay socket: {}",
                name,
                error
            );
            return true;
        }
        let peer_ip = peer_addr.ip();
        let peer_port = peer_addr.port();

        // Upstream checks the client limit first, without logging; it counts
        // every client of this listener, whatever its address.
        let max_connections = lock_or_recover(&self.runtime, "backbone runtime").max_connections;
        if let Some(max) = max_connections {
            if state.clients.len() >= max {
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "[{}] client limit ({}) reached, rejecting {}",
                    name,
                    max,
                    peer_addr,
                );
                return true;
            }
        }

        let (file_blocked, fast_flap_blocked_until) = {
            let mut monitor = lock_or_recover(&self.fast_flap_state, "backbone fast-flap state");
            (
                monitor.is_statically_blocked(peer_ip, &self.fast_flap),
                monitor.blocked_until(peer_ip, &self.fast_flap, Instant::now()),
            )
        };
        if file_blocked {
            let peer = state
                .peers
                .entry(peer_ip)
                .or_insert_with(PeerBehaviorState::new);
            peer.blacklist_reason = Some("blocked_ips file".into());
            peer.reject_count = peer.reject_count.saturating_add(1);
            lock_or_recover(&self.peer_state, "backbone peer state").upsert_snapshot(&state.peers);
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "[{}] rejecting peer {} from the blocked_ips file",
                name,
                peer_addr,
            );
            return true;
        }
        if is_ip_blacklisted(&mut state.peers, peer_ip) || fast_flap_blocked_until.is_some() {
            let peer = state
                .peers
                .entry(peer_ip)
                .or_insert_with(PeerBehaviorState::new);
            if let Some(blocked_until) = fast_flap_blocked_until {
                peer.blacklisted_until = Some(blocked_until);
                peer.blacklist_reason = Some("fast flapping".into());
            }
            peer.reject_count = peer.reject_count.saturating_add(1);
            lock_or_recover(&self.peer_state, "backbone peer state").upsert_snapshot(&state.peers);
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "[{}] rejecting blocked peer {}",
                name,
                peer_addr,
            );
            return true;
        }

        stream.set_nonblocking(true).ok();
        stream.set_nodelay(true).ok();
        set_tcp_keepalive(&stream).ok();
        SockRef::from(&stream)
            .set_recv_buffer_size(DP_IC_RCVBUF)
            .ok();

        // Prevent SIGPIPE on macOS when writing to broken pipes
        #[cfg(target_os = "macos")]
        {
            let sock = SockRef::from(&stream);
            sock.set_nosigpipe(true).ok();
        }

        // Create writer via try_clone (cross-platform dup)
        let writer_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[{}] failed to clone client stream: {}", name, e);
                return true;
            }
        };
        let client_id = InterfaceId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let key = crate::interface::loop_writer::read_key(client_id);

        log::trace!(target: crate::logging::PATHING_LOG_TARGET,
            "[{}] backbone client connected: {} → id {}",
            name,
            peer_addr,
            client_id.0
        );

        let write_stall_flag = Arc::new(AtomicBool::new(false));
        let writer: Box<dyn Writer> = Box::new(BackboneWriter {
            stream: writer_stream,
            runtime: Arc::clone(&self.runtime),
            interface_name: name.clone(),
            interface_id: client_id,
            event_tx: self.tx.clone(),
            transmit_buffer: TransmitBuffer::new(),
            egress_controller: EgressController::default(),
            egress_control: EgressControl::new(EGRESS_HIGH_WATERMARK),
            egress_started: Instant::now(),
            stall_started: None,
            disconnect_notified: false,
            write_stall_flag: Arc::clone(&write_stall_flag),
        });

        state.clients.insert(
            key,
            ClientState {
                id: client_id,
                peer_ip,
                peer_port,
                fd: stream.as_raw_fd(),
                connected_at: Instant::now(),
                has_received_data: false,
                write_stall_flag,
                idle_timed_out: false,
                dp_ingress_bytes: 0,
                dp_ingress_packets: 0,
                dp_ingress_hold: None,
                dp_ingress_gated: false,
                dp_ingress_throttle_count: 0,
            },
        );
        state
            .peers
            .entry(peer_ip)
            .or_insert_with(PeerBehaviorState::new)
            .connected_count += 1;
        lock_or_recover(&self.peer_state, "backbone peer state").upsert_snapshot(&state.peers);

        let info = InterfaceInfo {
            stamp_costs: Default::default(),
            id: client_id,
            name: format!("BackboneInterface/{}", client_id.0),
            mode: self.accepted_peer_mode,
            gravity: self.accepted_peer_gravity,
            recursive_prs: self.accepted_peer_recursive_prs,
            announces_from_internal: self.accepted_peer_announces_from_internal,
            announces_to_internal: self.accepted_peer_announces_to_internal,
            out_capable: true,
            in_capable: true,
            bitrate: Some(SERVER_BITRATE_GUESS),
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            shared_medium: false,
            hop_limiter: None,
            tunnel_id: None,
            mtu: SERVER_PEER_MTU,
            mtu_upgradable: true,
            ia_freq: 0.0,
            ia_samples: 0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
            ingress_control: self.ingress_control,
        };
        let up = if let Some(template) = &self.dynamic_template {
            let mut registration = template.registration(info);
            registration.display_name = Some(crate::interface::display::backbone_server_client(
                name, peer_ip, peer_port,
            ));
            registration.short_name = Some(crate::interface::display::spawned_client_name(name));
            Event::DynamicInterfaceUp {
                id: client_id,
                writer,
                registration: Box::new(registration),
            }
        } else {
            Event::InterfaceUp(client_id, Some(writer), Some(Box::new(info)))
        };
        let connected = Event::BackbonePeerConnected {
            server_interface_id: self.server_interface_id,
            peer_interface_id: client_id,
            peer_ip,
            peer_port,
        };
        if self.tx.push_from_loop([connected, up]).is_err() {
            state.clients.remove(&key);
            return false;
        }
        cx.add_source(
            key,
            Box::new(PeerSource {
                stream,
                decoder: hdlc::Decoder::reticulum(HW_MTU, self.ifac_size),
                key,
                id: client_id,
                server: Arc::clone(self),
            }),
        );
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IngressThresholds {
    pub(super) high: usize,
    pub(super) immediate: usize,
    pub(super) mid: usize,
    pub(super) low: usize,
}

pub(super) fn ingress_thresholds(data_capacity: usize) -> IngressThresholds {
    // Keep initialization silent; only actual throttle/release transitions are
    // operational events. Upstream removed its accidental critical HWM log.
    let high = ((DP_IC_HIGH_WM_PCT * data_capacity) / 100).max(4);
    IngressThresholds {
        high,
        immediate: high.max(128),
        mid: ((DP_IC_MID_WM_PCT * data_capacity) / 100).max(2),
        low: (DP_IC_LOW_WM_PCT * data_capacity) / 100,
    }
}

pub(super) fn busiest_ingress_key(producers: impl Iterator<Item = (usize, u64)>) -> Option<usize> {
    producers
        .filter(|(_, packets)| *packets > 0)
        .max_by_key(|(_, packets)| *packets)
        .map(|(key, _)| key)
}

/// The listening socket, served on the driver thread: accepts peers and
/// runs the server's periodic work from its timer.
pub(super) struct ListenerSource {
    listener: TcpListener,
    server: Arc<Server>,
    next_interval: Instant,
}

impl LoopSource for ListenerSource {
    fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.listener.as_fd()
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        let server = &self.server;
        let mut state = server.lock();
        server.sync_peer_state(&mut state);
        for _ in 0..ACCEPT_BURST {
            match self.listener.accept() {
                Ok((stream, peer_addr)) => {
                    if !server.admit(&mut state, stream, peer_addr, cx) {
                        return SourceStatus::Remove;
                    }
                }
                Err(error) => match crate::interface::stream_read::accept_error_step(&error) {
                    crate::interface::stream_read::AcceptStep::Drained => {
                        return SourceStatus::Rearm
                    }
                    crate::interface::stream_read::AcceptStep::Next => {}
                    crate::interface::stream_read::AcceptStep::Pause => {
                        log::warn!("[{}] accept error, pausing accepts: {}", server.name, error);
                        return SourceStatus::Pause;
                    }
                },
            }
        }
        SourceStatus::Rearm
    }

    fn deadline(&self) -> Option<Instant> {
        Some(self.next_interval)
    }

    fn on_timer(&mut self, _cx: &mut LoopContext<'_>) -> SourceStatus {
        self.server.interval();
        self.next_interval = Instant::now() + DP_IC_INTERVAL;
        SourceStatus::Rearm
    }
}

/// One accepted peer, read on the driver thread.
pub(super) struct PeerSource {
    stream: TcpStream,
    decoder: hdlc::Decoder,
    key: usize,
    id: InterfaceId,
    server: Arc<Server>,
}

impl LoopSource for PeerSource {
    fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.stream.as_fd()
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        let server = Arc::clone(&self.server);
        if server
            .lock()
            .clients
            .get(&self.key)
            .is_some_and(|client| client.dp_ingress_gated)
            // A hung-up socket stays ready even unwatched (epoll always
            // reports hang-ups and errors): holding it would serve it again
            // on every pass for as long as the hold lasts. Read it instead,
            // which finds the end of the stream.
            && !crate::interface::stream_read::socket_hung_up(self.stream.as_raw_fd())
        {
            // Throttled: the server re-arms it when the hold ends.
            return SourceStatus::Hold;
        }
        let (mut bytes, mut frames) = (0u64, 0u64);
        let read = read_stream_frames(
            self.stream.as_raw_fd(),
            &mut self.decoder,
            cx,
            &server.tx,
            self.id,
            &server.name,
            |read_bytes, read_frames| {
                bytes += read_bytes as u64;
                frames += read_frames as u64;
            },
        );
        let mut state = server.lock();
        if bytes > 0 {
            if let Some(client) = state.clients.get_mut(&self.key) {
                client.has_received_data = true;
                client.dp_ingress_bytes = client.dp_ingress_bytes.saturating_add(bytes);
                client.dp_ingress_packets = client.dp_ingress_packets.saturating_add(frames);
            }
        }
        let status = match read {
            StreamRead::Rearm => SourceStatus::Rearm,
            StreamRead::Suspend => SourceStatus::Suspend,
            StreamRead::Closed | StreamRead::Failed(_) => {
                let reason = match state.clients.get(&self.key) {
                    Some(client) if client.idle_timed_out => DisconnectReason::IdleTimeout,
                    Some(client) if client.write_stall_flag.load(Ordering::Relaxed) => {
                        DisconnectReason::WriteStall
                    }
                    _ => DisconnectReason::RemoteClosed,
                };
                self.disconnect(&mut state, reason);
                return SourceStatus::Remove;
            }
            StreamRead::DriverGone => return SourceStatus::Remove,
        };
        if bytes > 0
            && server.tx.inbound_queue_snapshot().heights[0] >= server.ingress_thresholds.immediate
        {
            if let Some(key) = server.throttle_busiest_ingress(&mut state) {
                if key == self.key {
                    return SourceStatus::Hold;
                }
                server.set_readable(key, state.clients[&key].fd, false);
            }
        }
        status
    }

    fn on_removed(&mut self) {
        // Closed without a disconnect (the receiver went away): forget it so
        // nothing touches the descriptor once it is closed.
        self.server.lock().clients.remove(&self.key);
    }

    fn on_abandoned(&mut self) {
        // The driver was told about this peer; it will never be read.
        let server = Arc::clone(&self.server);
        let mut state = server.lock();
        self.disconnect(&mut state, DisconnectReason::RemoteClosed);
    }
}

impl PeerSource {
    pub(super) fn disconnect(&self, state: &mut ServerState, reason: DisconnectReason) {
        let server = &self.server;
        let name = &server.name;
        let Some(client) = state.clients.remove(&self.key) else {
            return;
        };
        let client_id = client.id;

        match reason {
            DisconnectReason::RemoteClosed => {
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "[{}] backbone client {} disconnected",
                    name,
                    client_id.0,
                );
            }
            DisconnectReason::IdleTimeout => {
                log::info!(
                    "[{}] backbone client {} disconnected due to idle timeout",
                    name,
                    client_id.0
                );
            }
            DisconnectReason::WriteStall => {
                // Already logged by the writer that detected the stall.
            }
        }

        let connected_for = client.connected_at.elapsed();
        let mut penalty = None;
        if let Some(record) = lock_or_recover(&server.fast_flap_state, "backbone fast-flap state")
            .record_disconnect(
                client.peer_ip,
                connected_for,
                &server.fast_flap,
                Instant::now(),
            )
        {
            let frequency = if record.elapsed_since_first.is_zero() {
                None
            } else {
                Some(record.flap_count as f64 / record.elapsed_since_first.as_secs_f64())
            };
            log::debug!(
                "[{}] peer {} fast flapped after {:.3}s ({} flaps{})",
                name,
                client.peer_ip,
                connected_for.as_secs_f64(),
                record.flap_count,
                frequency
                    .map(|value| format!(", {:.3} Hz", value))
                    .unwrap_or_default(),
            );
            if record.blocked {
                let peer = state
                    .peers
                    .entry(client.peer_ip)
                    .or_insert_with(PeerBehaviorState::new);
                peer.blacklisted_until = record.blocked_until;
                peer.blacklist_reason = Some("fast flapping".into());
                if record.newly_blocked {
                    log::warn!(
                        "[{}] blocking further connections from {} due to fast flapping",
                        name,
                        client.peer_ip,
                    );
                    // A block is a penalty: report it to the
                    // `BackbonePeerPenalty` hook. Fast flapping has no levels.
                    penalty = Some(Event::BackbonePeerPenalty {
                        server_interface_id: server.server_interface_id,
                        peer_ip: client.peer_ip,
                        penalty_level: 0,
                        blacklist_for: server.fast_flap.block_duration,
                    });
                }
            }
        }
        let mut events = vec![Event::BackbonePeerDisconnected {
            server_interface_id: server.server_interface_id,
            peer_interface_id: client.id,
            peer_ip: client.peer_ip,
            peer_port: client.peer_port,
            connected_for,
            had_received_data: client.has_received_data,
        }];
        match reason {
            DisconnectReason::IdleTimeout => events.push(Event::BackbonePeerIdleTimeout {
                server_interface_id: server.server_interface_id,
                peer_interface_id: client.id,
                peer_ip: client.peer_ip,
                peer_port: client.peer_port,
                connected_for,
            }),
            DisconnectReason::WriteStall => events.push(Event::BackbonePeerWriteStall {
                server_interface_id: server.server_interface_id,
                peer_interface_id: client.id,
                peer_ip: client.peer_ip,
                peer_port: client.peer_port,
                connected_for,
            }),
            DisconnectReason::RemoteClosed => {}
        }
        events.extend(penalty);

        if let Some(peer) = state.peers.get_mut(&client.peer_ip) {
            peer.connected_count = peer.connected_count.saturating_sub(1);
        }
        lock_or_recover(&server.peer_state, "backbone peer state").upsert_snapshot(&state.peers);
        // The writer already reported a write stall's interface down.
        if !matches!(reason, DisconnectReason::WriteStall) {
            events.push(Event::InterfaceDown(client_id));
        }
        let _ = server.tx.push_from_loop(events);
    }
}

/// Upstream `BackboneClientInterface.set_timeouts_linux`, for connected and
/// accepted peers alike: keepalive probes after 5 s idle, and on Linux a
/// `TCP_USER_TIMEOUT` of 24 s. Keepalive only probes an idle connection; with
/// data waiting to be sent, only the user timeout drops a peer that stopped
/// acknowledging, where retransmission would keep it "up" for many minutes.
pub(super) fn set_tcp_keepalive(stream: &TcpStream) -> io::Result<()> {
    let sock = SockRef::from(stream);
    let mut keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(5))
        .with_interval(Duration::from_secs(2));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        keepalive = keepalive.with_retries(12);
    }
    sock.set_tcp_keepalive(&keepalive)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    sock.set_tcp_user_timeout(Some(TCP_USER_TIMEOUT))?;
    Ok(())
}

/// Upstream `BackboneClientInterface.TCP_USER_TIMEOUT`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) const TCP_USER_TIMEOUT: Duration = Duration::from_secs(24);
