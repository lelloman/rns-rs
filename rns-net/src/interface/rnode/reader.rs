//! Reading the device's frames and reporting the interface up or down.

use super::*;

/// Reader loop: detect device, configure radios, then relay data frames.
pub(super) fn reader_loop(
    reader: Option<Transport>,
    writer: Arc<Mutex<DeviceWriter>>,
    config: RNodeConfig,
    tx: EventSender,
    flow_states: Vec<Arc<Mutex<SubFlowState>>>,
    running: Arc<AtomicBool>,
) {
    let Some(reader) = bring_up(reader, &config, &tx, &writer, &flow_states, &running) else {
        return;
    };
    reader_loop_connected(reader, writer, config, tx, flow_states, running);
}

/// Bring the device up for the first time, for either I/O engine: open
/// it (a BLE device is opened here), detect and configure it, and, as
/// upstream, keep reopening it until it is configured. Reports the
/// interface up. `None` once the interface stops.
pub(super) fn bring_up(
    reader: Option<Transport>,
    config: &RNodeConfig,
    tx: &EventSender,
    writer: &Arc<Mutex<DeviceWriter>>,
    flow_states: &[Arc<Mutex<SubFlowState>>],
    running: &Arc<AtomicBool>,
) -> Option<Transport> {
    let reader = reader.or_else(|| {
        setup::is_ble(config)
            .then(|| first_ble_open(config, writer))
            .flatten()
    });
    let configured = reader.and_then(|mut reader| {
        match setup::setup_device(&mut reader, writer, config, running) {
            Ok(()) => Some(reader),
            Err(e) => {
                log::debug!("[{}] initial RNode setup failed: {}", config.name, e);
                None
            }
        }
    });
    let (reader, reopened) = match configured {
        Some(reader) => (reader, false),
        // As upstream, keep trying to bring the device up.
        None => (
            open_until_configured(config, writer, flow_states, running)?,
            true,
        ),
    };
    signal_interface_up(tx, config, writer, flow_states, reopened);
    Some(reader)
}

/// Reopen a lost connection and configure the device again, for either
/// I/O engine, until it works or the interface stops: a BLE device is
/// waited for as upstream does, a serial or TCP one is retried with a
/// backoff from 200 ms to 2 s. Reports the interface up again.
pub(super) fn reconnect_until_configured(
    config: &RNodeConfig,
    tx: &EventSender,
    writer: &Arc<Mutex<DeviceWriter>>,
    flow_states: &[Arc<Mutex<SubFlowState>>],
    running: &Arc<AtomicBool>,
) -> Option<Transport> {
    const RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(200);
    const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(2);
    if setup::is_ble(config) {
        // As upstream: wait, then try again, until the device is back.
        let reader = open_until_configured(config, writer, flow_states, running)?;
        signal_interface_up(tx, config, writer, flow_states, true);
        return Some(reader);
    }
    let mut backoff = RECONNECT_INITIAL_DELAY;
    while running.load(Ordering::Relaxed) {
        match reopen_connection(config, writer) {
            Ok(mut reader) => {
                reset_flow_states(flow_states);
                match setup::setup_device(&mut reader, writer, config, running) {
                    Ok(()) => {
                        signal_interface_up(tx, config, writer, flow_states, true);
                        return Some(reader);
                    }
                    Err(e) => log::warn!("[{}] reconnect configure failed: {}", config.name, e),
                }
            }
            Err(e) => log::warn!("[{}] reconnect open failed: {}", config.name, e),
        }
        if !wait_while_running(running, backoff) {
            return None;
        }
        backoff = std::cmp::min(backoff.saturating_mul(2), RECONNECT_MAX_DELAY);
    }
    None
}

/// Read a configured device until the interface stops, reconnecting when
/// the connection is lost.
pub(super) fn reader_loop_connected(
    mut reader: Transport,
    writer: Arc<Mutex<DeviceWriter>>,
    config: RNodeConfig,
    tx: EventSender,
    flow_states: Vec<Arc<Mutex<SubFlowState>>>,
    running: Arc<AtomicBool>,
) {
    while running.load(Ordering::Relaxed) {
        // A fresh receiver for each connection: no report of the last one
        // can be attached to a frame of this one.
        let mut receiver = RNodeReceiver::new(&config);
        let mut events = Vec::new();
        let mut buf = [0u8; 4096];
        let disconnected = loop {
            if !running.load(Ordering::Relaxed) {
                return;
            }
            if !reader_ready(&reader, Duration::from_millis(200)) {
                identify_station(&config, &flow_states, &writer);
                continue;
            }
            // Once stopped, nothing more is read here: a BLE connection
            // reads the device's last answers while it closes.
            if !running.load(Ordering::Relaxed) {
                return;
            }
            match reader.read(&mut buf) {
                Ok(0) => {
                    if !running.load(Ordering::Relaxed) {
                        return;
                    }
                    if setup::is_ble(&config) {
                        reader.lost();
                    } else {
                        log::warn!("[{}] serial port closed", config.name);
                    }
                    signal_interface_down(&tx, &config);
                    break true;
                }
                Ok(n) => {
                    receiver.feed(&buf[..n], &config, &flow_states, &writer, &mut events);
                    for event in events.drain(..) {
                        if tx.send(event).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    if !running.load(Ordering::Relaxed) {
                        return;
                    }
                    if setup::is_ble(&config) {
                        reader.lost();
                    } else {
                        log::error!("[{}] serial read error: {}", config.name, e);
                    }
                    signal_interface_down(&tx, &config);
                    break true;
                }
            }
        };

        if !running.load(Ordering::Relaxed) || !disconnected || config.pre_opened_fd.is_some() {
            return;
        }

        match reconnect_until_configured(&config, &tx, &writer, &flow_states, &running) {
            Some(new_reader) => reader = new_reader,
            None => return,
        }
    }
}

pub(super) fn reader_ready(reader: &impl AsRawFd, timeout: Duration) -> bool {
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    matches!(crate::sys::poll_in(reader.as_raw_fd(), timeout_ms), Ok(revents) if revents != 0)
}

pub(super) fn signal_interface_down(tx: &EventSender, config: &RNodeConfig) {
    for i in 0..config.subinterfaces.len() {
        let sub_id = InterfaceId(config.base_interface_id.0 + i as u64);
        let _ = tx.send(Event::InterfaceDown(sub_id));
    }
}

pub(super) fn update_pending_rx_metadata(
    event: &rnode_kiss::RNodeEvent,
    last_rssi: &mut Option<i16>,
    last_snr: &mut Option<f32>,
) -> bool {
    match event {
        rnode_kiss::RNodeEvent::StatRssi(rssi) => {
            *last_rssi = Some(*rssi as i16 - 157);
            true
        }
        rnode_kiss::RNodeEvent::StatSnr(snr) => {
            *last_snr = Some(*snr as f32 * 0.25);
            true
        }
        _ => false,
    }
}

pub(super) fn signal_interface_up(
    tx: &EventSender,
    config: &RNodeConfig,
    writer: &Arc<Mutex<DeviceWriter>>,
    flow_states: &[Arc<Mutex<SubFlowState>>],
    reconnected: bool,
) {
    for (i, flow_state) in flow_states.iter().enumerate() {
        let sub_id = InterfaceId(config.base_interface_id.0 + i as u64);
        let new_writer = reconnected.then(|| {
            make_sub_writer(
                writer.clone(),
                config.subinterfaces[i].vport,
                config.subinterfaces[i].flow_control,
                flow_state.clone(),
                config.multi,
            )
        });
        let _ = tx.send(Event::InterfaceUp(sub_id, new_writer, None));
    }
    // A device just (re)connected has reported nothing yet; upstream starts
    // from zero airtime and load and an unknown noise floor.
    for event in phy_telemetry(config, None, None, Some(RadioStats::default())) {
        let _ = tx.send(event);
    }
}

pub(super) fn clear_pending_rx_metadata(last_rssi: &mut Option<i16>, last_snr: &mut Option<f32>) {
    *last_rssi = None;
    *last_snr = None;
}
