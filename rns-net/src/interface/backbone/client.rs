//! Client mode: one connection to a server, reconnecting with backoff.

use super::*;

/// Configuration for a backbone client interface.
#[derive(Debug, Clone)]
pub struct BackboneClientConfig {
    /// Interface name.
    pub name: String,
    /// Host to connect to (`remote` or `target_host`).
    pub target_host: String,
    /// TCP port to connect to (`target_port` or `port`); default 4242.
    pub target_port: u16,
    /// ID of the interface.
    pub interface_id: InterfaceId,
    /// Startup limit on reconnection attempts (`max_reconnect_tries`); `None`
    /// retries forever.
    pub max_reconnect_tries: Option<u32>,
    /// The `transport_identity` config value (hex), as upstream writes it in
    /// the config entries of discovered interfaces; upstream's interfaces
    /// ignore it. The Backbone peer pool matches a discovered peer to this
    /// candidate by it, so a peer is not connected twice.
    pub transport_identity: Option<String>,
    /// The client's bitrate, which sets its hardware MTU as upstream's
    /// `optimise_mtu` does: [`CLIENT_BITRATE_GUESS`] unless it was
    /// configured, as for an auto-connected client.
    pub bitrate: u64,
    /// Live settings the client reads, which can be changed while it runs.
    pub runtime: Arc<Mutex<BackboneClientRuntime>>,
}

impl BackboneClientConfig {
    /// The hardware MTU upstream selects for the client's bitrate.
    pub(crate) fn hw_mtu(&self) -> usize {
        auto_mtu_for_bitrate(self.bitrate).map_or(1_048_576, |mtu| mtu as usize)
    }
}

/// Upstream's `RECONNECT_WAIT`: the wait between connection attempts, and
/// the base of the backoff after a lost connection. Not configurable.
pub(crate) const RECONNECT_WAIT: Duration = Duration::from_secs(5);

/// Upstream's `INITIAL_CONNECT_TIMEOUT`, the TCP connect timeout. Upstream
/// parses a `connect_timeout` option but connects with this constant.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

impl Default for BackboneClientConfig {
    fn default() -> Self {
        BackboneClientConfig {
            name: String::new(),
            target_host: "127.0.0.1".into(),
            target_port: 4242,
            interface_id: InterfaceId(0),
            max_reconnect_tries: None,
            transport_identity: None,
            bitrate: CLIENT_BITRATE_GUESS,
            runtime: Arc::new(Mutex::new(BackboneClientRuntime {
                reconnect_wait: RECONNECT_WAIT,
                max_reconnect_tries: None,
                connect_timeout: CONNECT_TIMEOUT,
            })),
        }
    }
}

/// Writer that sends HDLC-framed data over a TCP stream (client mode).
///
/// A fresh writer is constructed for every connection: the initial connect in
/// [`start_client`] and each reconnect in [`ClientLink::reconnect_loop`]. Its
/// [`TransmitBuffer`] and [`EgressController`] therefore always start empty and
/// unstalled, and the stalled writer is dropped together with its socket on
/// teardown, so no egress drain/stall state can survive into the next
/// connection. This structurally covers upstream's `BackboneInterface._dp_ec_reset`
/// (rgit `f0875ac4`), which resets the same counters on a persistent Python
/// initiator instance, and its call on every initiator reconnect (rgit
/// `0bc5c37c`): there is no persistent instance here to reset.
pub(super) struct BackboneClientWriter {
    stream: TcpStream,
    transmit_buffer: TransmitBuffer,
    egress_control: EgressControl,
}

impl Writer for BackboneClientWriter {
    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
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
        while self.transmit_buffer.sendable_bytes() > 0 {
            if self.transmit_buffer.drain_to(&mut self.stream)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "backbone writer made no progress",
                ));
            }
        }
        Ok(())
    }
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.send_frames(&[crate::interface::FrameBytes::Owned(data.to_vec())])
    }

    fn send_frames(&mut self, frames: &[crate::interface::FrameBytes]) -> io::Result<()> {
        for frame in frames {
            let encoded = hdlc::frame(frame);
            let encoded_len = encoded.len();
            if !self
                .transmit_buffer
                .append_with_limit(encoded, Some(EGRESS_HIGH_WATERMARK))
            {
                self.egress_control.record_drop(encoded_len);
            }
        }
        self.transmit_buffer.flush();
        while self.transmit_buffer.sendable_bytes() > 0 {
            if self.transmit_buffer.drain_to(&mut self.stream)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "backbone client writer made no progress",
                ));
            }
        }
        Ok(())
    }

    fn egress_control(&self) -> Option<EgressControl> {
        Some(self.egress_control.clone())
    }

    fn loop_socket(&self) -> Option<std::os::fd::RawFd> {
        Some(self.stream.as_raw_fd())
    }

    fn loop_egress(&mut self) -> Option<LoopEgress> {
        Some(LoopEgress::budget(self.egress_control.clone()))
    }
}

/// Try to connect to the target host:port with timeout.
pub(super) fn try_connect_client(
    config: &BackboneClientConfig,
    underlay_mark: Option<u32>,
) -> io::Result<TcpStream> {
    let runtime = lock_or_recover(&config.runtime, "backbone runtime").clone();
    let addr_str = format!("{}:{}", config.target_host, config.target_port);
    let addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved"))?;

    #[cfg(target_os = "linux")]
    let stream = if underlay_mark.is_some() {
        crate::interface::connect_tcp_with_options(
            &addr,
            None,
            underlay_mark,
            runtime.connect_timeout,
        )?
    } else {
        TcpStream::connect_timeout(&addr, runtime.connect_timeout)?
    };
    #[cfg(not(target_os = "linux"))]
    let stream = TcpStream::connect_timeout(&addr, runtime.connect_timeout)?;
    stream.set_nodelay(true)?;
    set_tcp_keepalive(&stream).ok();

    // Prevent SIGPIPE on macOS when writing to broken pipes
    #[cfg(target_os = "macos")]
    {
        let sock = SockRef::from(&stream);
        sock.set_nosigpipe(true).ok();
    }

    Ok(stream)
}

/// Connect and start the reader thread. Returns the writer for the driver.
#[cfg(test)]
pub(crate) fn start_client(
    config: BackboneClientConfig,
    tx: EventSender,
) -> io::Result<Box<dyn Writer>> {
    start_client_with_ifac(config, tx, 0, None, ListenerControl::new())
}

pub(crate) fn start_client_with_ifac(
    config: BackboneClientConfig,
    tx: EventSender,
    ifac_size: usize,
    underlay_mark: Option<u32>,
    control: ListenerControl,
) -> io::Result<Box<dyn Writer>> {
    let stream = try_connect_client(&config, underlay_mark)?;
    serve_client(config, tx, ifac_size, underlay_mark, control, stream)
}

/// Start a client that reconnects on its own, as a configured or an
/// auto-connected one does. As upstream's `BackboneClientInterface`, one
/// whose target cannot be reached yet is left unconnected, reported down,
/// and tried again every `reconnect_wait` (upstream's `RECONNECT_WAIT`, 5
/// seconds) until it connects or runs out of `max_reconnect_tries`; the
/// connection brings its writer in with its `InterfaceUp`.
pub(crate) fn start_retrying_client(
    config: BackboneClientConfig,
    tx: EventSender,
    ifac_size: usize,
    underlay_mark: Option<u32>,
    control: ListenerControl,
) -> io::Result<Box<dyn Writer>> {
    let stream = match try_connect_client(&config, underlay_mark) {
        Ok(stream) => stream,
        Err(error) => {
            log::warn!(
                "Initial connection for {} could not be established: {}",
                crate::interface::display::backbone(
                    &config.name,
                    &config.target_host,
                    config.target_port
                ),
                error
            );
            let wait = lock_or_recover(&config.runtime, "backbone runtime").reconnect_wait;
            log::warn!(
                "Leaving unconnected and retrying connection in {} seconds.",
                wait.as_secs_f64()
            );
            let link = Arc::new(ClientLink {
                config,
                tx,
                ifac_size,
                underlay_mark,
                control,
            });
            thread::Builder::new()
                .name(format!("bb-reconn-{}", link.config.interface_id.0))
                .spawn(move || link.reconnect_loop(Retry::Steady))?;
            return Ok(Box::new(crate::interface::UnavailableWriter));
        }
    };
    serve_client(config, tx, ifac_size, underlay_mark, control, stream)
}

/// Serve a client's first connection, over `stream`.
pub(super) fn serve_client(
    config: BackboneClientConfig,
    tx: EventSender,
    ifac_size: usize,
    underlay_mark: Option<u32>,
    control: ListenerControl,
    stream: TcpStream,
) -> io::Result<Box<dyn Writer>> {
    let writer_stream = stream.try_clone()?;

    let id = config.interface_id;
    log::info!(
        "[{}] backbone client connected to {}:{}",
        config.name,
        config.target_host,
        config.target_port
    );

    // Initial connect: writer is None because it's returned directly to the caller
    let _ = tx.send(Event::InterfaceUp(id, None, None));

    let link = Arc::new(ClientLink {
        config,
        tx,
        ifac_size,
        underlay_mark,
        control,
    });
    if let Err(error) = link.serve(stream) {
        let _ = link.tx.send(Event::InterfaceDown(id));
        return Err(error);
    }

    Ok(Box::new(BackboneClientWriter {
        stream: writer_stream,
        transmit_buffer: TransmitBuffer::new(),
        egress_control: EgressControl::new(EGRESS_HIGH_WATERMARK),
    }))
}

/// What a client connection needs across reconnects.
pub(super) struct ClientLink {
    config: BackboneClientConfig,
    tx: EventSender,
    ifac_size: usize,
    underlay_mark: Option<u32>,
    control: ListenerControl,
}

impl ClientLink {
    /// Read `stream` on the driver thread from now on.
    pub(super) fn serve(self: &Arc<Self>, stream: TcpStream) -> io::Result<()> {
        let source = ClientSource {
            stream,
            decoder: hdlc::Decoder::reticulum(self.config.hw_mtu(), self.ifac_size),
            link: Arc::clone(self),
        };
        self.tx.register_source(
            crate::interface::loop_writer::read_key(self.config.interface_id),
            Box::new(source),
        )
    }

    /// Report the connection down and reconnect on a thread of its own,
    /// which exits once the new connection is served on the driver (or
    /// reconnecting gives up or is stopped).
    pub(super) fn connection_lost(self: &Arc<Self>) {
        let id = self.config.interface_id;
        let _ = self.tx.push_from_loop([Event::InterfaceDown(id)]);
        let max_tries =
            lock_or_recover(&self.config.runtime, "backbone runtime").max_reconnect_tries;
        if max_tries == Some(0) {
            // Whoever owns this client (the backbone peer pool) reconnects
            // it. A reconnect thread would only wait out a backoff and then
            // report the interface down again, possibly after the owner has
            // already brought it back up under the same id.
            log::debug!(
                "[{}] not reconnecting (max_reconnect_tries = 0)",
                self.config.name
            );
            return;
        }
        let link = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name(format!("bb-reconn-{}", id.0))
            .spawn(move || link.reconnect_loop(Retry::Backoff));
        if let Err(error) = spawned {
            log::error!(
                "[{}] cannot start reconnecting, giving up: {}",
                self.config.name,
                error
            );
        }
    }

    pub(super) fn reconnect_loop(self: Arc<Self>, retry: Retry) {
        loop {
            let Some(stream) = client_reconnect(
                &self.config,
                &self.tx,
                self.underlay_mark,
                &self.control,
                retry,
            ) else {
                if !self.control.should_stop() {
                    log::error!("[{}] reconnection failed, giving up", self.config.name);
                }
                return;
            };
            match self.serve(stream) {
                Ok(()) => return,
                Err(error) => {
                    log::warn!(
                        "[{}] cannot read the new connection: {}",
                        self.config.name,
                        error
                    );
                    let _ = self.tx.send(Event::InterfaceDown(self.config.interface_id));
                }
            }
        }
    }
}

/// The connected client socket, read on the driver thread.
pub(super) struct ClientSource {
    stream: TcpStream,
    decoder: hdlc::Decoder,
    link: Arc<ClientLink>,
}

impl LoopSource for ClientSource {
    fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.stream.as_fd()
    }

    fn stopped(&self) -> bool {
        self.link.control.should_stop()
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        let link = &self.link;
        if link.control.should_stop() {
            return SourceStatus::Remove;
        }
        let name = &link.config.name;
        match read_stream_frames(
            self.stream.as_raw_fd(),
            &mut self.decoder,
            cx,
            &link.tx,
            link.config.interface_id,
            name,
            |_, _| {},
        ) {
            StreamRead::Rearm => SourceStatus::Rearm,
            StreamRead::Suspend => SourceStatus::Suspend,
            StreamRead::Closed => {
                log::warn!("[{}] connection closed", name);
                link.connection_lost();
                SourceStatus::Remove
            }
            StreamRead::Failed(error) => {
                log::warn!("[{}] read error: {}", name, error);
                link.connection_lost();
                SourceStatus::Remove
            }
            StreamRead::DriverGone => SourceStatus::Remove,
        }
    }
}

/// Maximum backoff multiplier: `base_delay * 2^MAX_BACKOFF_SHIFT`.
/// With a 5 s base this caps at 5 × 2^6 = 320 s ≈ 5 min.
pub(crate) const MAX_BACKOFF_SHIFT: u32 = 6;

/// Delay before reconnect attempt number `attempt` (0-based): `base`
/// doubled per attempt up to `base * 2^MAX_BACKOFF_SHIFT`, with ±25 %
/// jitter to avoid thundering-herd reconnects.
pub(crate) fn reconnect_backoff(base: Duration, attempt: u32) -> Duration {
    let backoff = base * 2u32.pow(attempt.min(MAX_BACKOFF_SHIFT));
    let jitter_range = backoff / 4;
    if jitter_range.as_nanos() == 0 {
        return backoff;
    }
    let offset = Duration::from_nanos(
        (std::hash::RandomState::new().build_hasher().finish() % jitter_range.as_nanos() as u64)
            * 2,
    );
    if offset > jitter_range {
        backoff + (offset - jitter_range)
    } else {
        backoff - (jitter_range - offset)
    }
}

/// How a client waits between connection attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Retry {
    /// `reconnect_wait` before every attempt, as upstream's reconnect does;
    /// for a client that has not connected yet.
    Steady,
    /// Exponential backoff with jitter (see [`reconnect_backoff`]), for a
    /// client that lost its connection.
    Backoff,
}

impl Retry {
    pub(super) fn wait(self, base: Duration, attempt: u32) -> Duration {
        match self {
            Retry::Steady => base,
            Retry::Backoff => reconnect_backoff(base, attempt),
        }
    }
}

/// Attempt to (re)connect, waiting between attempts as `retry` says.
/// Returns the new reader stream on success.
/// Sends the new writer to the driver via InterfaceUp event.
pub(super) fn client_reconnect(
    config: &BackboneClientConfig,
    tx: &EventSender,
    underlay_mark: Option<u32>,
    control: &ListenerControl,
    retry: Retry,
) -> Option<TcpStream> {
    let mut attempts = 0u32;
    loop {
        let runtime = lock_or_recover(&config.runtime, "backbone runtime").clone();

        let jitter = retry.wait(runtime.reconnect_wait, attempts);
        if !wait_while_active(control, jitter) {
            return None;
        }

        attempts += 1;

        if let Some(max) = runtime.max_reconnect_tries {
            if attempts > max {
                let _ = tx.send(Event::InterfaceDown(config.interface_id));
                return None;
            }
        }

        log::info!(
            "[{}] reconnect attempt {} (backoff {:.1}s) ...",
            config.name,
            attempts,
            jitter.as_secs_f64(),
        );

        match try_connect_client(config, underlay_mark) {
            Ok(new_stream) => {
                if control.should_stop() {
                    return None;
                }
                let writer_stream = match new_stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("[{}] failed to clone stream: {}", config.name, e);
                        continue;
                    }
                };
                log::info!(
                    "[{}] reconnected after {} attempt(s)",
                    config.name,
                    attempts
                );
                let new_writer: Box<dyn Writer> = Box::new(BackboneClientWriter {
                    stream: writer_stream,
                    transmit_buffer: TransmitBuffer::new(),
                    egress_control: EgressControl::new(EGRESS_HIGH_WATERMARK),
                });
                let _ = tx.send(Event::InterfaceUp(
                    config.interface_id,
                    Some(new_writer),
                    None,
                ));
                return Some(new_stream);
            }
            Err(e) => {
                log::warn!("[{}] reconnect failed: {}", config.name, e);
            }
        }
    }
}
