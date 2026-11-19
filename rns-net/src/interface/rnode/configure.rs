//! Detecting the RNode and configuring its radios.

use super::*;

pub(super) fn detect_and_configure(
    reader: &mut Transport,
    writer: &Arc<Mutex<DeviceWriter>>,
    config: &RNodeConfig,
) -> io::Result<()> {
    let detect_cmd = rnode_kiss::detect_request();
    let mut cmd = detect_cmd;
    cmd.extend_from_slice(&rnode_kiss::rnode_command(
        rnode_kiss::CMD_FW_VERSION,
        &[0x00],
    ));
    cmd.extend_from_slice(&rnode_kiss::rnode_command(
        rnode_kiss::CMD_FW_DETAIL,
        &[0x00],
    ));
    cmd.extend_from_slice(&rnode_kiss::rnode_command(
        rnode_kiss::CMD_PLATFORM,
        &[0x00],
    ));
    cmd.extend_from_slice(&rnode_kiss::rnode_command(rnode_kiss::CMD_MCU, &[0x00]));

    lock_or_recover(writer, "rnode shared writer").write_all(&cmd)?;

    let mut decoder = rnode_kiss::RNodeDecoder::new();
    let mut buf = [0u8; 4096];
    let mut detected = false;
    let detect_start = std::time::Instant::now();
    let detect_timeout = Duration::from_secs(5);

    while !detected && detect_start.elapsed() < detect_timeout {
        match reader.read(&mut buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "serial port closed during detect",
                ));
            }
            Ok(n) => {
                for event in decoder.feed(&buf[..n]) {
                    match event {
                        rnode_kiss::RNodeEvent::Detected(true) => {
                            detected = true;
                            log::info!("[{}] RNode device detected", config.name);
                        }
                        rnode_kiss::RNodeEvent::FirmwareVersion { major, minor } => {
                            log::info!("[{}] firmware version {}.{}", config.name, major, minor);
                        }
                        rnode_kiss::RNodeEvent::FirmwareDetail(ref detail) => {
                            log::info!("[{}] firmware detail: {}", config.name, detail);
                        }
                        rnode_kiss::RNodeEvent::Platform(p) => {
                            log::info!("[{}] platform: 0x{:02X}", config.name, p);
                        }
                        rnode_kiss::RNodeEvent::Mcu(m) => {
                            log::info!("[{}] MCU: 0x{:02X}", config.name, m);
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("serial read error during detect: {}", e),
                ));
            }
        }
    }

    if !detected {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RNode detection timed out",
        ));
    }

    for sub in &config.subinterfaces {
        configure_subinterface(writer, sub.vport, sub, config.multi)?;
    }

    thread::sleep(Duration::from_millis(300));
    log::info!(
        "[{}] RNode configured with {} subinterface(s)",
        config.name,
        config.subinterfaces.len()
    );
    Ok(())
}

/// Configure a single subinterface on the RNode device.
pub(crate) fn configure_subinterface(
    writer: &Arc<Mutex<DeviceWriter>>,
    index: u8,
    sub: &RNodeSubConfig,
    multi: bool,
) -> io::Result<()> {
    let mut w = lock_or_recover(writer, "rnode shared writer");

    // For multi-radio, send select command before each parameter
    let freq_bytes = [
        (sub.frequency >> 24) as u8,
        (sub.frequency >> 16) as u8,
        (sub.frequency >> 8) as u8,
        (sub.frequency & 0xFF) as u8,
    ];
    let bw_bytes = [
        (sub.bandwidth >> 24) as u8,
        (sub.bandwidth >> 16) as u8,
        (sub.bandwidth >> 8) as u8,
        (sub.bandwidth & 0xFF) as u8,
    ];
    let txp = if sub.txpower < 0 {
        (sub.txpower as i16 + 256) as u8
    } else {
        sub.txpower as u8
    };

    if multi {
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_FREQUENCY,
            &freq_bytes,
        ))?;
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_BANDWIDTH,
            &bw_bytes,
        ))?;
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_TXPOWER,
            &[txp],
        ))?;
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_SF,
            &[sub.spreading_factor],
        ))?;
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_CR,
            &[sub.coding_rate],
        ))?;
    } else {
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_FREQUENCY,
            &freq_bytes,
        ))?;
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_BANDWIDTH,
            &bw_bytes,
        ))?;
        w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_TXPOWER, &[txp]))?;
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_SF,
            &[sub.spreading_factor],
        ))?;
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_CR,
            &[sub.coding_rate],
        ))?;
    }

    // Airtime locks
    if let Some(st) = sub.st_alock {
        let st_val = (st * 100.0) as u16;
        let st_bytes = [(st_val >> 8) as u8, (st_val & 0xFF) as u8];
        if multi {
            w.write_all(&rnode_kiss::rnode_select_command(
                index,
                rnode_kiss::CMD_ST_ALOCK,
                &st_bytes,
            ))?;
        } else {
            w.write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_ST_ALOCK,
                &st_bytes,
            ))?;
        }
    }
    if let Some(lt) = sub.lt_alock {
        let lt_val = (lt * 100.0) as u16;
        let lt_bytes = [(lt_val >> 8) as u8, (lt_val & 0xFF) as u8];
        if multi {
            w.write_all(&rnode_kiss::rnode_select_command(
                index,
                rnode_kiss::CMD_LT_ALOCK,
                &lt_bytes,
            ))?;
        } else {
            w.write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_LT_ALOCK,
                &lt_bytes,
            ))?;
        }
    }

    // Turn on radio
    if multi {
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_RADIO_STATE,
            &[rnode_kiss::RADIO_STATE_ON],
        ))?;
    } else {
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_RADIO_STATE,
            &[rnode_kiss::RADIO_STATE_ON],
        ))?;
    }

    Ok(())
}
