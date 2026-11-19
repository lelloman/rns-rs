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
    let reader = reader.or_else(|| {
        setup::is_ble(&config)
            .then(|| first_ble_open(&config, &writer))
            .flatten()
    });
    let configured = reader.and_then(|mut reader| {
        match setup::setup_device(&mut reader, &writer, &config, &running) {
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
        None => match open_until_configured(&config, &writer, &flow_states, &running) {
            Some(reader) => (reader, true),
            None => return,
        },
    };
    signal_interface_up(&tx, &config, &writer, &flow_states, reopened);
    reader_loop_connected(reader, writer, config, tx, flow_states, running);
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
    const RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(200);
    const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(2);
    // RNode is the PHY-stat-capable interface: retain each modem report until
    // the matching frame is enqueued, attach it to that frame, then clear it
    // so later frames cannot inherit stale RSSI or SNR.
    let mut last_rssi: Option<i16> = None;
    let mut last_snr: Option<f32> = None;
    // What the device reports about its channel and itself.
    let mut radio = RadioStats::default();
    let name = setup::display_name(&config);
    while running.load(Ordering::Relaxed) {
        let mut decoder = rnode_kiss::RNodeDecoder::new();
        let mut reports = setup::RadioReports::new(&config);
        let mut buf = [0u8; 4096];
        let disconnected = loop {
            if !running.load(Ordering::Relaxed) {
                return;
            }
            if !reader_ready(&reader, Duration::from_millis(200)) {
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
                    for event in decoder.feed(&buf[..n]) {
                        if config.multi {
                            log_multi_radio_report(&event, &config.name);
                        } else {
                            reports.apply(&event, &name);
                        }
                        if update_radio_stats(&event, &mut radio, crate::time::now()) {
                            publish_radio_telemetry(&tx, &config, &radio);
                            continue;
                        }
                        let phy_stat = matches!(
                            &event,
                            rnode_kiss::RNodeEvent::StatRssi(_)
                                | rnode_kiss::RNodeEvent::StatSnr(_)
                        );
                        if update_pending_rx_metadata(&event, &mut last_rssi, &mut last_snr) {
                            if phy_stat {
                                publish_phy_telemetry(&tx, &config, last_rssi, last_snr);
                            }
                            continue;
                        }
                        match event {
                            rnode_kiss::RNodeEvent::DataFrame { index, data } => {
                                let Some(position) = config
                                    .subinterfaces
                                    .iter()
                                    .position(|sub| usize::from(sub.vport) == index)
                                else {
                                    continue;
                                };
                                let sub_id =
                                    InterfaceId(config.base_interface_id.0 + position as u64);
                                if tx
                                    .send(Event::Frame {
                                        interface_id: sub_id,
                                        data: data.into(),
                                        rssi: last_rssi,
                                        snr: last_snr,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                                last_rssi = None;
                                last_snr = None;
                            }
                            rnode_kiss::RNodeEvent::Ready => {
                                // Flow control: unlock all subinterfaces that have flow_control
                                for (i, fs) in flow_states.iter().enumerate() {
                                    if config.subinterfaces[i].flow_control {
                                        process_flow_queue(
                                            fs,
                                            &writer,
                                            config.subinterfaces[i].vport,
                                            config.multi,
                                        );
                                    }
                                }
                            }
                            rnode_kiss::RNodeEvent::Error(code) if config.multi => {
                                log::error!("[{}] RNode error: 0x{:02X}", config.name, code);
                            }
                            _ => {
                                // Status updates logged but not acted on
                            }
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

        clear_pending_rx_metadata(&mut last_rssi, &mut last_snr);
        radio = RadioStats::default();

        if !running.load(Ordering::Relaxed) || !disconnected || config.pre_opened_fd.is_some() {
            return;
        }

        if setup::is_ble(&config) {
            // As upstream: wait, then try again, until the device is back.
            match open_until_configured(&config, &writer, &flow_states, &running) {
                Some(new_reader) => {
                    reader = new_reader;
                    signal_interface_up(&tx, &config, &writer, &flow_states, true);
                    continue;
                }
                None => return,
            }
        }

        let mut backoff = RECONNECT_INITIAL_DELAY;
        while running.load(Ordering::Relaxed) {
            match reopen_connection(&config, &writer) {
                Ok(new_reader) => {
                    reset_flow_states(&flow_states);
                    reader = new_reader;
                    if let Err(e) = setup::setup_device(&mut reader, &writer, &config, &running) {
                        log::warn!("[{}] reconnect configure failed: {}", config.name, e);
                        if !wait_while_running(&running, backoff) {
                            return;
                        }
                        backoff = std::cmp::min(backoff.saturating_mul(2), RECONNECT_MAX_DELAY);
                        continue;
                    }
                    signal_interface_up(&tx, &config, &writer, &flow_states, true);
                    break;
                }
                Err(e) => {
                    log::warn!("[{}] reconnect open failed: {}", config.name, e);
                    if !wait_while_running(&running, backoff) {
                        return;
                    }
                    backoff = std::cmp::min(backoff.saturating_mul(2), RECONNECT_MAX_DELAY);
                }
            }
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
