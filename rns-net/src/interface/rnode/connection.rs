//! Opening the device, keeping it open and reconnecting.

use super::*;

pub(super) fn start_with_control(
    config: RNodeConfig,
    tx: EventSender,
) -> io::Result<(RNodeWriters, crate::interface::ListenerControl)> {
    // Validate all subinterface configs upfront
    for sub in &config.subinterfaces {
        if let Some(err) = validate_sub_config(sub) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, err));
        }
    }

    if config.subinterfaces.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No subinterfaces configured",
        ));
    }

    let (reader_file, writer_transport) = if let Some(fd) = config.pre_opened_fd {
        // Pre-opened fd from USB bridge — dup for independent reader/writer handles
        let (reader, writer) = Transport::open_from_fd(fd)?;
        (Some(reader), writer)
    } else if setup::is_ble(&config) {
        // Finding and connecting a BLE device takes seconds: the setup
        // thread opens it.
        (None, Transport::Offline)
    } else {
        match open_device(&config) {
            Ok((reader, writer)) => (Some(reader), writer),
            // As upstream, the interface still comes up, offline, and
            // keeps trying to open its device.
            Err(e) => {
                log_open_failure(&config, &e);
                (None, Transport::Offline)
            }
        }
    };
    let shared_writer = Arc::new(Mutex::new(if crate::engine::FOLD_IO {
        DeviceWriter::driven(
            writer_transport,
            Arc::clone(tx.poller()),
            crate::interface::loop_writer::write_key(config.base_interface_id),
            &config.name,
        )
    } else {
        DeviceWriter::new(writer_transport)
    }));

    // Build per-subinterface writers and IDs
    let num_subs = config.subinterfaces.len();
    let mut writers: Vec<(InterfaceId, Box<dyn Writer>)> = Vec::with_capacity(num_subs);
    let mut flow_states: Vec<Arc<Mutex<SubFlowState>>> = Vec::with_capacity(num_subs);

    let station_id: Option<Arc<[u8]>> = config
        .id_interval
        .and(config.id_callsign.as_deref())
        .map(Arc::from);
    for (i, sub) in config.subinterfaces.iter().enumerate() {
        let sub_id = InterfaceId(config.base_interface_id.0 + i as u64);
        let flow_state = Arc::new(Mutex::new(SubFlowState::new(station_id.clone())));
        flow_states.push(flow_state.clone());
        let sub_writer = make_sub_writer(
            shared_writer.clone(),
            sub.vport,
            sub.flow_control,
            flow_state,
            config.multi,
        );
        writers.push((sub_id, sub_writer));
    }

    // Spawn reader thread
    let reader_shared_writer = shared_writer.clone();
    {
        let mut runtime = lock_or_recover(&config.runtime, "rnode runtime");
        runtime.writer = Some(shared_writer.clone());
        runtime.sub = config
            .subinterfaces
            .first()
            .cloned()
            .unwrap_or(runtime.sub.clone());
    }
    let running = Arc::new(AtomicBool::new(true));
    let shared_writer_for_leave = Arc::clone(&shared_writer);
    let finish_config = config.clone();
    if crate::engine::FOLD_IO {
        folded::RNodeLink::new(config, tx, shared_writer, flow_states, Arc::clone(&running))
            .start(reader_file)?;
        let control = crate::interface::ListenerControl::with_running_flag(running);
        return Ok((
            writers,
            with_leave_on_finish(control, shared_writer_for_leave, &finish_config),
        ));
    }
    let reader_config = config.clone();
    let reader_flow_states = flow_states;
    let reader_running = Arc::clone(&running);
    thread::Builder::new()
        .name(format!("rnode-reader-{}", config.base_interface_id.0))
        .spawn(move || {
            reader_loop(
                reader_file,
                reader_shared_writer,
                reader_config,
                tx,
                reader_flow_states,
                reader_running,
            );
        })?;

    // Spawn keepalive thread — sends periodic DETECT to prevent firmware
    // bridge idle timeout (ESP32 RNode reverts to standalone after 30s idle).
    let keepalive_writer = shared_writer.clone();
    let keepalive_name = config.name.clone();
    let keepalive_running = Arc::clone(&running);
    thread::Builder::new()
        .name(format!("rnode-keepalive-{}", config.base_interface_id.0))
        .spawn(move || {
            while keepalive_running.load(Ordering::Relaxed) {
                if !wait_while_running(&keepalive_running, KEEPALIVE_INTERVAL) {
                    break;
                }
                send_keepalive(&keepalive_writer, &keepalive_name);
            }
        })?;

    let control = crate::interface::ListenerControl::with_running_flag(running);
    Ok((
        writers,
        with_leave_on_finish(control, shared_writer_for_leave, &finish_config),
    ))
}

/// Turn the radios off and send LEAVE when the interface finishes, as
/// upstream's `detach()`: the device can then stop bridging instead of
/// waiting for the host.
pub(super) fn with_leave_on_finish(
    control: crate::interface::ListenerControl,
    writer: Arc<Mutex<DeviceWriter>>,
    config: &RNodeConfig,
) -> crate::interface::ListenerControl {
    let multi = config.multi;
    let vports: Vec<u8> = config.subinterfaces.iter().map(|sub| sub.vport).collect();
    let config = config.clone();
    control.with_on_finish(move || {
        let mut writer = lock_or_recover(&writer, "rnode shared writer");
        let off = [rnode_kiss::RADIO_STATE_OFF];
        let mut commands = Vec::new();
        if multi {
            for &vport in &vports {
                commands.push(rnode_kiss::rnode_select_command(
                    vport,
                    rnode_kiss::CMD_RADIO_STATE,
                    &off,
                ));
            }
        } else {
            commands.push(rnode_kiss::rnode_command(rnode_kiss::CMD_RADIO_STATE, &off));
        }
        commands.push(rnode_kiss::leave_request());
        // The device may already be gone: there is nothing left to do then.
        if let Err(e) = commands.iter().try_for_each(|c| writer.write_all(c)) {
            log::debug!("[{}] radio off and leave not sent: {e}", config.name);
        }
        // Nothing serves a driven writer any more: send what it holds.
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while writer.holds_unwritten() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
            writer.drain();
        }
        // A BLE device is disconnected, as upstream's detach does, and
        // what it answers meanwhile is read, as upstream's reader keeps
        // reading until the connection is gone: the radio reporting it is
        // off.
        writer.transport().close_reading(|notify| {
            setup::read_closing_answer(
                notify,
                &config,
                std::time::Instant::now() + setup::CLOSING_ANSWER_WAIT,
            )
        });
    })
}

pub(super) fn wait_while_running(running: &AtomicBool, duration: Duration) -> bool {
    let deadline = std::time::Instant::now() + duration;
    while running.load(Ordering::Relaxed) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return true;
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
    false
}

/// Upstream `RNodeInterface.RECONNECT_WAIT`: how long to wait before each
/// attempt to open a device that could not be opened at start.
pub(super) const OPEN_RETRY_WAIT: Duration = Duration::from_secs(5);

/// Open and configure a device that could not be opened at start, as
/// upstream's `reconnect_port` does: wait, then try, until it works or the
/// interface stops. Returns the configured connection.
pub(super) fn open_until_configured(
    config: &RNodeConfig,
    writer: &Arc<Mutex<DeviceWriter>>,
    flow_states: &[Arc<Mutex<SubFlowState>>],
    running: &AtomicBool,
) -> Option<Transport> {
    loop {
        let attempt_at = std::time::Instant::now() + OPEN_RETRY_WAIT;
        let early = if setup::is_ble(config) {
            connect_ble_meanwhile(config, running, attempt_at)
        } else {
            None
        };
        if !wait_while_running(
            running,
            attempt_at.saturating_duration_since(std::time::Instant::now()),
        ) {
            return None;
        }
        if config.multi {
            log::debug!(
                "[{}] attempting to reconnect serial port {}",
                config.name,
                config.port
            );
        } else {
            log::info!(
                "Attempting to reconnect serial port {} for {}...",
                setup::port_display(config),
                setup::display_name(config)
            );
        }
        let opened = match early {
            // Connected while waiting: upstream's attempt finds it open.
            Some((reader, new_writer)) => {
                setup::log_opening(config);
                lock_or_recover(writer, "rnode shared writer").replace(new_writer);
                Ok(reader)
            }
            None => reopen_connection(config, writer),
        };
        match opened {
            Ok(mut reader) => {
                reset_flow_states(flow_states);
                match setup::setup_device(&mut reader, writer, config, running) {
                    Ok(()) => {
                        if config.multi {
                            log::info!("[{}] reconnected serial port {}", config.name, config.port);
                        } else {
                            log::info!(
                                target: crate::logging::NOTICE_TARGET,
                                "Reconnected port for {}",
                                setup::display_name(config)
                            );
                        }
                        return Some(reader);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => return None,
                    // Upstream logs why the device did not come up while
                    // setting it up.
                    Err(e) if !config.multi && setup_error_logged(&e) => {}
                    Err(e) => log_reconnect_error(config, &e),
                }
            }
            Err(e) => log_reconnect_error(config, &e),
        }
    }
}

/// Look for and connect a BLE device while waiting for the next attempt
/// at `attempt_at`, as upstream's connection job keeps doing between
/// attempts (unless looking for it failed outright, which ends the job).
pub(super) fn connect_ble_meanwhile(
    config: &RNodeConfig,
    running: &AtomicBool,
    attempt_at: std::time::Instant,
) -> Option<(Transport, Transport)> {
    if ble::job_ended(&config.ble) || !wait_while_running(running, ble::JOB_INTERVAL) {
        return None;
    }
    let budget = attempt_at.saturating_duration_since(std::time::Instant::now());
    if budget.is_zero() {
        return None;
    }
    let target = ble::Target::parse(&config.port).unwrap_or_default();
    Transport::open_ble(&target, &setup::display_name(config), &config.ble, budget).ok()
}

/// Whether setting a single RNode up already said why it failed.
pub(super) fn setup_error_logged(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::InvalidData
    )
}

pub(super) fn log_reconnect_error(config: &RNodeConfig, error: &io::Error) {
    if config.multi {
        log::error!(
            "[{}] error while reconnecting port, the contained exception was: {}",
            config.name,
            error
        );
    } else {
        log::error!(
            "Error while reconnecting port, the contained exception was: {}",
            error
        );
    }
}

/// Open the device's connection, saying so as upstream does.
pub(super) fn open_device(config: &RNodeConfig) -> io::Result<(Transport, Transport)> {
    setup::log_opening(config);
    if setup::is_ble(config) {
        let target = ble::Target::parse(&config.port).unwrap_or_default();
        return Transport::open_ble(
            &target,
            &setup::display_name(config),
            &config.ble,
            ble::CONNECT_TIMEOUT,
        );
    }
    let serial_config = SerialConfig {
        path: config.port.clone(),
        baud: config.speed,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: 1,
    };
    Transport::open(&serial_config, config.underlay_mark)
}

/// Upstream's lines when the device cannot be opened at start.
pub(super) fn log_open_failure(config: &RNodeConfig, error: &io::Error) {
    let kind = if config.multi {
        "RNodeMultiInterface"
    } else {
        "RNodeInterface"
    };
    log::error!(
        "Could not open serial port for interface {}[{}]",
        kind,
        config.name
    );
    log::error!("The contained exception was: {}", error);
    log::error!("Reticulum will attempt to bring up this interface periodically");
}

/// Open a BLE device the interface just started with, as upstream opens
/// it at start.
pub(super) fn first_ble_open(
    config: &RNodeConfig,
    writer: &Arc<Mutex<DeviceWriter>>,
) -> Option<Transport> {
    match reopen_connection(config, writer) {
        Ok(reader) => Some(reader),
        Err(e) => {
            log_open_failure(config, &e);
            None
        }
    }
}

pub(super) fn reopen_connection(
    config: &RNodeConfig,
    writer: &Arc<Mutex<DeviceWriter>>,
) -> io::Result<Transport> {
    let (reader, new_writer) = open_device(config)?;
    lock_or_recover(writer, "rnode shared writer").replace(new_writer);
    Ok(reader)
}
