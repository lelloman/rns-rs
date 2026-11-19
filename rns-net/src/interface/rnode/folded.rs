//! An RNode on the compact engine's driver loop.
//!
//! With interface I/O folded (see [`crate::engine::FOLD_IO`]) the RNode's
//! connection is read as a loop source on the driver thread, which also
//! sends the keepalive, and the subinterfaces' writers write the shared
//! [`DeviceWriter`] without blocking, called by the driver directly.
//! Detecting and configuring the device waits on its replies, so it runs
//! on a thread of its own, at start and after the connection is lost, which
//! exits once the configured device is served on the driver.

use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rns_core::transport::types::InterfaceId;

use super::setup;
use super::transport::Transport;
use super::DeviceWriter;
use super::{
    first_ble_open, open_until_configured, reopen_connection, reset_flow_states,
    signal_interface_up, wait_while_running, RNodeConfig, RNodeReceiver, SubFlowState,
};
use super::{identify_station, station_id_due};
use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::interface::lock_or_recover;
use crate::interface::stream_read::{set_nonblocking, STREAM_READ_BUDGET};
use crate::rnode_kiss;

/// How often a detect request keeps the device's host bridge awake (ESP32
/// RNodes revert to standalone after 30 seconds idle).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

const RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(200);
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(2);

/// What serving an RNode on the driver loop needs across reconnects.
pub(super) struct RNodeLink {
    config: RNodeConfig,
    tx: EventSender,
    writer: Arc<Mutex<DeviceWriter>>,
    flow_states: Vec<Arc<Mutex<SubFlowState>>>,
    running: Arc<AtomicBool>,
}

impl RNodeLink {
    pub(super) fn new(
        config: RNodeConfig,
        tx: EventSender,
        writer: Arc<Mutex<DeviceWriter>>,
        flow_states: Vec<Arc<Mutex<SubFlowState>>>,
        running: Arc<AtomicBool>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            tx,
            writer,
            flow_states,
            running,
        })
    }

    fn running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Detect and configure the device on a setup thread, then serve it.
    /// Without a connection (the device could not be opened), keep trying
    /// to open it first.
    pub(super) fn start(self: Arc<Self>, reader: Option<Transport>) -> io::Result<()> {
        thread::Builder::new()
            .name(format!("rnode-setup-{}", self.config.base_interface_id.0))
            .spawn(move || {
                let reader = reader.or_else(|| {
                    setup::is_ble(&self.config)
                        .then(|| first_ble_open(&self.config, &self.writer))
                        .flatten()
                });
                let configured = reader.and_then(|mut reader| {
                    match setup::setup_device(
                        &mut reader,
                        &self.writer,
                        &self.config,
                        &self.running,
                    ) {
                        Ok(()) => Some(reader),
                        Err(e) => {
                            log::debug!("[{}] initial RNode setup failed: {}", self.config.name, e);
                            None
                        }
                    }
                });
                let (reader, reopened) = match configured {
                    Some(reader) => (reader, false),
                    // As upstream, keep trying to bring the device up.
                    None => match open_until_configured(
                        &self.config,
                        &self.writer,
                        &self.flow_states,
                        &self.running,
                    ) {
                        Some(reader) => (reader, true),
                        None => return,
                    },
                };
                signal_interface_up(
                    &self.tx,
                    &self.config,
                    &self.writer,
                    &self.flow_states,
                    reopened,
                );
                self.serve_or_reconnect(reader);
            })?;
        Ok(())
    }

    /// Read `reader` on the driver thread from now on, or reopen the
    /// connection if it cannot be.
    fn serve_or_reconnect(self: &Arc<Self>, reader: Transport) {
        if let Err(e) = self.serve(reader) {
            log::warn!(
                "[{}] cannot read the RNode connection: {}",
                self.config.name,
                e
            );
            self.report_down(|event| {
                let _ = self.tx.send(event);
            });
            self.reconnect();
        }
    }

    fn serve(self: &Arc<Self>, reader: Transport) -> io::Result<()> {
        // Reader and writer share one open file, so this makes both
        // non-blocking.
        set_nonblocking(reader.as_raw_fd())?;
        self.tx.register_source(
            crate::interface::loop_writer::read_key(self.config.base_interface_id),
            Box::new(RNodeSource {
                reader,
                receiver: RNodeReceiver::new(&self.config),
                keepalive_at: Instant::now() + KEEPALIVE_INTERVAL,
                link: Arc::clone(self),
            }),
        )
    }

    fn report_down(&self, mut send: impl FnMut(Event)) {
        for i in 0..self.config.subinterfaces.len() {
            send(Event::InterfaceDown(InterfaceId(
                self.config.base_interface_id.0 + i as u64,
            )));
        }
    }

    /// Reopen and reconfigure the connection until it is served again or
    /// the interface stops. Runs on a reconnect thread.
    fn reconnect(self: &Arc<Self>) {
        if setup::is_ble(&self.config) {
            // As upstream: wait, then try again, until the device is back.
            if let Some(reader) =
                open_until_configured(&self.config, &self.writer, &self.flow_states, &self.running)
            {
                signal_interface_up(
                    &self.tx,
                    &self.config,
                    &self.writer,
                    &self.flow_states,
                    true,
                );
                self.serve_or_reconnect(reader);
            }
            return;
        }
        let mut backoff = RECONNECT_INITIAL_DELAY;
        while self.running() {
            match reopen_connection(&self.config, &self.writer) {
                Ok(mut reader) => {
                    reset_flow_states(&self.flow_states);
                    if let Err(e) =
                        setup::setup_device(&mut reader, &self.writer, &self.config, &self.running)
                    {
                        log::warn!("[{}] reconnect configure failed: {}", self.config.name, e);
                    } else {
                        signal_interface_up(
                            &self.tx,
                            &self.config,
                            &self.writer,
                            &self.flow_states,
                            true,
                        );
                        self.serve_or_reconnect(reader);
                        return;
                    }
                }
                Err(e) => {
                    log::warn!("[{}] reconnect open failed: {}", self.config.name, e);
                }
            }
            if !wait_while_running(&self.running, backoff) {
                return;
            }
            backoff = std::cmp::min(backoff.saturating_mul(2), RECONNECT_MAX_DELAY);
        }
    }

    /// Report the subinterfaces down and, unless the connection was handed
    /// over pre-opened, reconnect on a thread of its own.
    fn connection_lost(self: &Arc<Self>) {
        let mut events = Vec::new();
        self.report_down(|event| events.push(event));
        let _ = self.tx.push_from_loop(events);
        if self.config.pre_opened_fd.is_some() {
            return;
        }
        let link = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name(format!(
                "rnode-reconnect-{}",
                self.config.base_interface_id.0
            ))
            .spawn(move || link.reconnect());
        if let Err(e) = spawned {
            log::error!(
                "[{}] cannot start reconnecting, giving up: {}",
                self.config.name,
                e
            );
        }
    }
}

/// The RNode connection, read on the driver thread.
struct RNodeSource {
    reader: Transport,
    receiver: RNodeReceiver,
    keepalive_at: Instant,
    link: Arc<RNodeLink>,
}

enum Read {
    Rearm,
    Suspend,
    Lost(Option<io::Error>),
    DriverGone,
}

impl RNodeSource {
    fn read(&mut self, cx: &mut LoopContext<'_>) -> Read {
        let link = Arc::clone(&self.link);
        if !link.tx.inbound_data_has_room() {
            return Read::Suspend;
        }
        let config = &link.config;
        let mut read = 0;
        while read < STREAM_READ_BUDGET {
            // The connection is non-blocking.
            let n = crate::sys::read(self.reader.as_raw_fd(), cx.buf);
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock => return Read::Rearm,
                    io::ErrorKind::Interrupted => continue,
                    _ => return Read::Lost(Some(e)),
                }
            }
            if n == 0 {
                return Read::Lost(None);
            }
            let n = n as usize;
            read += n;
            let mut events = Vec::new();
            self.receiver.feed(
                &cx.buf[..n],
                config,
                &link.flow_states,
                &link.writer,
                &mut events,
            );
            match link.tx.push_from_loop(events) {
                Ok(true) => {}
                Ok(false) => return Read::Suspend,
                Err(_) => return Read::DriverGone,
            }
            if n < cx.buf.len() {
                break;
            }
        }
        Read::Rearm
    }
}

impl LoopSource for RNodeSource {
    fn fd(&self) -> std::os::fd::RawFd {
        self.reader.as_raw_fd()
    }

    fn stopped(&self) -> bool {
        !self.link.running()
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if !self.link.running() {
            return SourceStatus::Remove;
        }
        match self.read(cx) {
            Read::Rearm => SourceStatus::Rearm,
            Read::Suspend => SourceStatus::Suspend,
            Read::Lost(error) => {
                if !self.link.running() {
                    return SourceStatus::Remove;
                }
                let name = &self.link.config.name;
                if setup::is_ble(&self.link.config) {
                    // Upstream's disconnect callback says so.
                    self.reader.lost();
                } else {
                    match error {
                        Some(e) => log::error!("[{}] serial read error: {}", name, e),
                        None => log::warn!("[{}] serial port closed", name),
                    }
                }
                self.link.connection_lost();
                SourceStatus::Remove
            }
            Read::DriverGone => SourceStatus::Remove,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        let id_due = station_id_due(&self.link.config, &self.link.flow_states);
        Some(id_due.map_or(self.keepalive_at, |due| due.min(self.keepalive_at)))
    }

    fn on_timer(&mut self, _cx: &mut LoopContext<'_>) -> SourceStatus {
        if !self.link.running() {
            return SourceStatus::Remove;
        }
        identify_station(&self.link.config, &self.link.flow_states, &self.link.writer);
        if Instant::now() < self.keepalive_at {
            return SourceStatus::Rearm;
        }
        self.keepalive_at = Instant::now() + KEEPALIVE_INTERVAL;
        if let Err(e) = lock_or_recover(&self.link.writer, "rnode shared writer")
            .write_all(&rnode_kiss::detect_request())
        {
            // Not while the device is away: that was said already.
            if e.kind() != io::ErrorKind::NotConnected {
                log::debug!("[{}] keepalive write failed: {}", self.link.config.name, e);
            }
        }
        SourceStatus::Rearm
    }
}
