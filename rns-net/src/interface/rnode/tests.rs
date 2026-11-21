use super::*;
use crate::event;
use crate::kiss;
use crate::serial::open_pty_pair;
use crate::test_support::logged;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;
use tempfile::tempdir;
/// Helper: poll an fd for reading with timeout (ms).
fn poll_read(fd: i32, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    ret > 0
}

/// Read all available bytes from an fd.
fn read_available(file: &mut Transport) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    while poll_read(file.as_raw_fd(), 100) {
        match file.read(&mut buf) {
            Ok(n) if n > 0 => all.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    all
}

fn slave_tty_path(fd: i32) -> PathBuf {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(rc, 0, "ttyname_r failed for fd {}", fd);
    let nul = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    PathBuf::from(std::str::from_utf8(&buf[..nul]).unwrap())
}

unsafe fn transport_from_raw_fd(fd: i32) -> Transport {
    // SAFETY: the caller hands over an open fd it no longer uses.
    Transport::Serial(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn wait_for_interface_event<F>(
    rx: &crate::event::EventReceiver,
    timeout: Duration,
    predicate: F,
) -> Event
where
    F: Fn(&Event) -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(event) if predicate(&event) => return event,
            Ok(_) => continue,
            Err(RecvTimeoutError::Timeout) => panic!("timed out waiting for interface event"),
            Err(RecvTimeoutError::Disconnected) => panic!("event channel disconnected"),
        }
    }
}

/// Mock RNode: respond to detect with DETECT_RESP, FW version, platform
fn mock_respond_detect(master: &mut Transport) {
    // Respond: DETECT_RESP
    master
        .write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_DETECT,
            &[rnode_kiss::DETECT_RESP],
        ))
        .unwrap();
    // FW version 1.74
    master
        .write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_FW_VERSION,
            &[0x01, 0x4A],
        ))
        .unwrap();
    // Platform ESP32
    master
        .write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_PLATFORM,
            &[0x80],
        ))
        .unwrap();
    // MCU
    master
        .write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_MCU, &[0x01]))
        .unwrap();
    master.flush().unwrap();
}

/// Mock RNode: report the radio configured as `sub`, as the firmware
/// answers each setting.
fn mock_report_configured(master: &mut Transport, sub: &RNodeSubConfig) {
    for (command, data) in [
        (
            rnode_kiss::CMD_FREQUENCY,
            sub.frequency.to_be_bytes().to_vec(),
        ),
        (
            rnode_kiss::CMD_BANDWIDTH,
            sub.bandwidth.to_be_bytes().to_vec(),
        ),
        (rnode_kiss::CMD_TXPOWER, vec![sub.txpower as u8]),
        (rnode_kiss::CMD_SF, vec![sub.spreading_factor]),
        (rnode_kiss::CMD_CR, vec![sub.coding_rate]),
        (
            rnode_kiss::CMD_RADIO_STATE,
            vec![rnode_kiss::RADIO_STATE_ON],
        ),
    ] {
        master
            .write_all(&rnode_kiss::rnode_command(command, &data))
            .unwrap();
    }
    master.flush().unwrap();
}

#[test]
fn rnode_detect_over_pty() {
    // Test that the RNode decoder can parse detect responses from a PTY
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    let mut master = unsafe { transport_from_raw_fd(master_fd) };
    let mut slave = unsafe { transport_from_raw_fd(slave_fd) };

    // Write detect response to master
    mock_respond_detect(&mut master);

    let mut decoder = rnode_kiss::RNodeDecoder::new();
    let mut events = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);

    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        if !poll_read(slave.as_raw_fd(), timeout_ms) {
            break;
        }

        let chunk = read_available(&mut slave);
        if chunk.is_empty() {
            continue;
        }

        events.extend(decoder.feed(&chunk));

        let saw_detect = events
            .iter()
            .any(|e| matches!(e, rnode_kiss::RNodeEvent::Detected(true)));
        let saw_firmware = events
            .iter()
            .any(|e| matches!(e, rnode_kiss::RNodeEvent::FirmwareVersion { .. }));
        if saw_detect && saw_firmware {
            break;
        }
    }

    assert!(
        events
            .iter()
            .any(|e| matches!(e, rnode_kiss::RNodeEvent::Detected(true))),
        "should detect device"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, rnode_kiss::RNodeEvent::FirmwareVersion { .. })),
        "should get firmware version"
    );
}

#[test]
fn rnode_configure_commands() {
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    let mut master = unsafe { transport_from_raw_fd(master_fd) };
    let writer_file = unsafe { transport_from_raw_fd(libc::dup(slave_fd)) };
    let writer = Arc::new(Mutex::new(DeviceWriter::new(writer_file)));

    let sub = RNodeSubConfig {
        name: "test".into(),
        vport: 0,
        outgoing: true,
        frequency: 868_000_000,
        bandwidth: 125_000,
        txpower: 7,
        spreading_factor: 8,
        coding_rate: 5,
        flow_control: false,
        st_alock: None,
        lt_alock: None,
    };

    configure_subinterface(&writer, 0, &sub, false).unwrap();

    // Read what was sent
    let data = read_available(&mut master);

    // Should contain frequency command
    assert!(
        data.windows(2)
            .any(|w| w[0] == kiss::FEND && w[1] == rnode_kiss::CMD_FREQUENCY),
        "should contain FREQUENCY command"
    );
    // Should contain bandwidth command
    assert!(
        data.windows(2)
            .any(|w| w[0] == kiss::FEND && w[1] == rnode_kiss::CMD_BANDWIDTH),
        "should contain BANDWIDTH command"
    );
    // Should contain RADIO_STATE ON
    assert!(
        data.windows(3).any(|w| w[0] == kiss::FEND
            && w[1] == rnode_kiss::CMD_RADIO_STATE
            && w[2] == rnode_kiss::RADIO_STATE_ON),
        "should contain RADIO_STATE ON command"
    );

    unsafe { libc::close(slave_fd) };
}

#[test]
fn rnode_data_roundtrip() {
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    let mut master = unsafe { transport_from_raw_fd(master_fd) };
    let slave = unsafe { transport_from_raw_fd(slave_fd) };

    // Write a data frame (subinterface 0) to master
    let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let frame = rnode_kiss::rnode_data_frame(0, &payload);
    master.write_all(&frame).unwrap();
    master.flush().unwrap();

    // Read from slave with RNode decoder
    assert!(poll_read(slave.as_raw_fd(), 2000));
    let mut decoder = rnode_kiss::RNodeDecoder::new();
    let mut buf = [0u8; 4096];
    let mut slave_file = slave;
    let n = slave_file.read(&mut buf).unwrap();
    let events = decoder.feed(&buf[..n]);

    assert_eq!(events.len(), 1);
    match &events[0] {
        rnode_kiss::RNodeEvent::DataFrame { index, data } => {
            assert_eq!(*index, 0);
            assert_eq!(data, &payload);
        }
        other => panic!("expected DataFrame, got {:?}", other),
    }
}

#[test]
fn rnode_flow_control() {
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    let writer_file = unsafe { transport_from_raw_fd(slave_fd) };
    let shared_writer = Arc::new(Mutex::new(DeviceWriter::new(writer_file)));

    let flow_state = Arc::new(Mutex::new(SubFlowState {
        ready: true,
        queue: std::collections::VecDeque::new(),
        first_tx: None,
        station_id: None,
    }));

    let mut sub_writer = RNodeSubWriter {
        confirmed_pending: None,
        writer: shared_writer.clone(),
        index: 0,
        flow_control: true,
        flow_state: flow_state.clone(),
        multi: false,
    };

    // First send: should go through (ready=true) and set ready=false
    sub_writer.send_frame(b"hello").unwrap();
    assert!(!flow_state.lock().unwrap().ready);

    // Second send: should be queued
    sub_writer.send_frame(b"world").unwrap();
    assert_eq!(flow_state.lock().unwrap().queue.len(), 1);

    // Process flow queue (simulates CMD_READY)
    process_flow_queue(&flow_state, &shared_writer, 0, false);
    assert_eq!(flow_state.lock().unwrap().queue.len(), 0);
    assert!(!flow_state.lock().unwrap().ready); // sent queued, still locked

    // Process again with empty queue: sets ready=true
    process_flow_queue(&flow_state, &shared_writer, 0, false);
    assert!(flow_state.lock().unwrap().ready);

    unsafe { libc::close(master_fd) };
}

#[test]
fn device_reports_update_radio_stats_as_upstream() {
    let mut radio = RadioStats::default();
    let channel = rnode_kiss::RNodeEvent::ChannelStats {
        airtime_short: 697,
        airtime_long: 2,
        channel_load_short: 1113,
        channel_load_long: 4,
        current_rssi: 47,
        noise_floor: 58,
        interference: 0xFF,
    };
    assert!(update_radio_stats(&channel, &mut radio, 100.0));
    assert_eq!(radio.airtime_short, 6.97);
    assert_eq!(radio.airtime_long, 0.02);
    assert_eq!(radio.channel_load_short, 11.13);
    assert_eq!(radio.channel_load_long, 0.04);
    assert_eq!(radio.current_rssi, Some(-110));
    assert_eq!(radio.noise_floor, Some(-99));
    assert_eq!(radio.interference, None);
    assert_eq!(radio.interference_last, None);

    let busy = rnode_kiss::RNodeEvent::ChannelStats {
        airtime_short: 0,
        airtime_long: 0,
        channel_load_short: 0,
        channel_load_long: 0,
        current_rssi: 77,
        noise_floor: 58,
        interference: 77,
    };
    assert!(update_radio_stats(&busy, &mut radio, 200.0));
    assert_eq!(radio.interference, Some(-80));
    assert_eq!(radio.interference_last, Some((200.0, -80)));
    // Cleared now, but the last sighting stays.
    assert!(update_radio_stats(&channel, &mut radio, 300.0));
    assert_eq!(radio.interference, None);
    assert_eq!(radio.interference_last, Some((200.0, -80)));

    let battery = rnode_kiss::RNodeEvent::Battery {
        state: 2,
        percent: 140,
    };
    assert!(update_radio_stats(&battery, &mut radio, 0.0));
    assert_eq!(radio.battery_state_name(), "charging");
    assert_eq!(radio.battery_percent, 100);

    // Temperature is offset by 120 and kept only between -30 and 90.
    let temp = |raw| rnode_kiss::RNodeEvent::Temperature(raw);
    assert!(update_radio_stats(&temp(178), &mut radio, 0.0));
    assert_eq!(radio.temperature, Some(58));
    assert!(update_radio_stats(&temp(250), &mut radio, 0.0));
    assert_eq!(radio.temperature, None);

    let phy = rnode_kiss::RNodeEvent::PhyStats {
        symbol_time_us: 2048,
        symbol_rate: 488,
        preamble_symbols: 18,
        preamble_ms: 37,
        csma_slot_ms: 24,
        difs_ms: 48,
    };
    assert!(!update_radio_stats(&phy, &mut radio, 0.0));
    assert!(!update_radio_stats(
        &rnode_kiss::RNodeEvent::Ready,
        &mut radio,
        0.0
    ));
}

#[test]
fn signal_quality_matches_python_mapping_and_clamps() {
    assert_eq!(signal_quality(8, -11.0), 0.0);
    assert_eq!(signal_quality(8, -2.5), 50.0);
    assert_eq!(signal_quality(8, 6.0), 100.0);
    assert_eq!(signal_quality(8, 30.0), 100.0);
    assert_eq!(signal_quality(8, -40.0), 0.0);
    assert_eq!(signal_quality(10, -2.5), 59.5);
}

#[test]
fn rnode_reset_clears_pending_rx_metadata() {
    let mut last_rssi = Some(-101);
    let mut last_snr = Some(7.25);

    clear_pending_rx_metadata(&mut last_rssi, &mut last_snr);

    assert_eq!(last_rssi, None);
    assert_eq!(last_snr, None);
}

#[test]
fn confirmed_rnode_frame_waits_for_ready_and_flushes_once() {
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    let mut master = unsafe { transport_from_raw_fd(master_fd) };
    let state = Arc::new(Mutex::new(SubFlowState {
        ready: false,
        queue: std::collections::VecDeque::new(),
        first_tx: None,
        station_id: None,
    }));
    let mut writer = RNodeSubWriter {
        confirmed_pending: None,
        writer: Arc::new(Mutex::new(DeviceWriter::new(unsafe {
            transport_from_raw_fd(slave_fd)
        }))),
        index: 0,
        flow_control: true,
        flow_state: state.clone(),
        multi: false,
    };
    assert_eq!(
        writer
            .send_frame_confirmed(b"confirmed")
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(state.lock().unwrap().queue.is_empty());
    assert!(!poll_read(master.as_raw_fd(), 20));
    state.lock().unwrap().ready = true;
    Writer::flush(&mut writer).unwrap();
    let expected = rnode_kiss::rnode_data_frame(0, b"confirmed");
    let mut actual = vec![0; expected.len()];
    master.read_exact(&mut actual).unwrap();
    assert_eq!(actual, expected);
    Writer::flush(&mut writer).unwrap();
    assert!(!poll_read(master.as_raw_fd(), 20));
}

#[test]
fn rnode_snr_metadata_does_not_depend_on_rssi() {
    let mut last_rssi = None;
    let mut last_snr = None;

    assert!(update_pending_rx_metadata(
        &rnode_kiss::RNodeEvent::StatSnr(-12),
        &mut last_rssi,
        &mut last_snr,
    ));

    assert_eq!(last_rssi, None);
    assert_eq!(last_snr, Some(-3.0));
}

#[test]
fn rnode_rx_metadata_reports_rssi_and_snr() {
    let mut last_rssi = None;
    let mut last_snr = None;

    assert!(update_pending_rx_metadata(
        &rnode_kiss::RNodeEvent::StatRssi(57),
        &mut last_rssi,
        &mut last_snr,
    ));
    assert!(update_pending_rx_metadata(
        &rnode_kiss::RNodeEvent::StatSnr(-12),
        &mut last_rssi,
        &mut last_snr,
    ));

    assert_eq!(last_rssi, Some(-100));
    assert_eq!(last_snr, Some(-3.0));
}

#[test]
fn rnode_sub_writer_format() {
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    let mut master = unsafe { transport_from_raw_fd(master_fd) };
    let writer_file = unsafe { transport_from_raw_fd(slave_fd) };
    let shared_writer = Arc::new(Mutex::new(DeviceWriter::new(writer_file)));

    let flow_state = Arc::new(Mutex::new(SubFlowState {
        ready: true,
        queue: std::collections::VecDeque::new(),
        first_tx: None,
        station_id: None,
    }));

    let mut sub_writer = RNodeSubWriter {
        confirmed_pending: None,
        writer: shared_writer,
        index: 1, // subinterface 1
        flow_control: false,
        flow_state,
        multi: false,
    };

    let payload = vec![0xAA, 0xBB, 0xCC];
    sub_writer.send_frame(&payload).unwrap();

    // Read from master
    assert!(poll_read(master.as_raw_fd(), 2000));
    let mut buf = [0u8; 256];
    let n = master.read(&mut buf).unwrap();

    // Should start with FEND, CMD_INT1_DATA (0x10)
    assert_eq!(buf[0], kiss::FEND);
    assert_eq!(buf[1], 0x10); // CMD_INT1_DATA
    assert_eq!(buf[n - 1], kiss::FEND);
}

#[test]
fn rnode_multi_sub_routing() {
    // Test that data frames on different CMD_INTn route to different indices
    let mut decoder = rnode_kiss::RNodeDecoder::new();

    let payload0 = vec![0x01, 0x02];
    let frame0 = rnode_kiss::rnode_data_frame(0, &payload0);
    let events0 = decoder.feed(&frame0);
    assert_eq!(events0.len(), 1);
    assert_eq!(
        events0[0],
        rnode_kiss::RNodeEvent::DataFrame {
            index: 0,
            data: payload0
        }
    );

    let payload1 = vec![0x03, 0x04];
    let frame1 = rnode_kiss::rnode_data_frame(1, &payload1);
    let events1 = decoder.feed(&frame1);
    assert_eq!(events1.len(), 1);
    assert_eq!(
        events1[0],
        rnode_kiss::RNodeEvent::DataFrame {
            index: 1,
            data: payload1
        }
    );
}

#[test]
fn rnode_error_handling() {
    // NOTE: CMD_ERROR (0x90) == CMD_INT5_DATA (0x90) — they share the same
    // byte value. In multi-radio mode, 0x90 is treated as INT5_DATA.
    // Error events only appear on single-radio devices where there's no
    // INT5_DATA. The decoder treats 0x90 as INT5_DATA (data wins).
    // For real error detection, we rely on the data frame being invalid
    // or the device sending a different error indicator.
    // Test that cmd 0x90 is correctly handled as a data frame.
    let mut decoder = rnode_kiss::RNodeDecoder::new();
    let frame = rnode_kiss::rnode_command(rnode_kiss::CMD_ERROR, &[0x02]);
    let events = decoder.feed(&frame);
    assert_eq!(events.len(), 1);
    // 0x90 = CMD_INT5_DATA, so it's a DataFrame with index 5
    assert_eq!(
        events[0],
        rnode_kiss::RNodeEvent::DataFrame {
            index: 5,
            data: vec![0x02]
        }
    );
}

#[test]
fn rnode_config_validation() {
    let good = RNodeSubConfig {
        name: "test".into(),
        vport: 0,
        outgoing: true,
        frequency: 868_000_000,
        bandwidth: 125_000,
        txpower: 7,
        spreading_factor: 8,
        coding_rate: 5,
        flow_control: false,
        st_alock: None,
        lt_alock: None,
    };
    assert!(validate_sub_config(&good).is_none());

    // Bad frequency
    let mut bad = good.clone();
    bad.frequency = 100;
    assert!(validate_sub_config(&bad).is_some());

    // Bad SF
    bad = good.clone();
    bad.spreading_factor = 13;
    assert!(validate_sub_config(&bad).is_some());

    // Bad CR
    bad = good.clone();
    bad.coding_rate = 9;
    assert!(validate_sub_config(&bad).is_some());

    // Bad BW
    bad = good.clone();
    bad.bandwidth = 5;
    assert!(validate_sub_config(&bad).is_some());

    // Bad TX power
    bad = good.clone();
    bad.txpower = 50;
    assert!(validate_sub_config(&bad).is_some());
}

#[test]
fn multi_factory_preserves_nonsequential_virtual_ports_and_disabled_children() {
    let parent = HashMap::from([
        ("port".to_string(), "/dev/ttyUSB0".to_string()),
        ("speed".to_string(), "115200".to_string()),
    ]);
    let children = vec![
        crate::config::ParsedSubinterface {
            name: "disabled".into(),
            params: HashMap::from([
                ("interface_enabled".into(), "no".into()),
                ("vport".into(), "2".into()),
            ]),
        },
        crate::config::ParsedSubinterface {
            name: "high".into(),
            params: HashMap::from([
                ("interface_enabled".into(), "yes".into()),
                ("vport".into(), "7".into()),
                ("frequency".into(), "915000000".into()),
                ("airtime_limit_short".into(), "12.5".into()),
                ("outgoing".into(), "no".into()),
            ]),
        },
        crate::config::ParsedSubinterface {
            name: "low".into(),
            params: HashMap::from([
                ("enabled".into(), "yes".into()),
                ("vport".into(), "1".into()),
            ]),
        },
    ];
    let parsed = RNodeMultiFactory
        .parse_config_section(
            "multi",
            InterfaceId(40),
            ConfigSection {
                params: &parent,
                children: &children,
            },
        )
        .unwrap();
    let config = parsed.into_any().downcast::<RNodeConfig>().unwrap();
    assert_eq!(config.subinterfaces.len(), 2);
    assert_eq!(config.subinterfaces[0].vport, 7);
    assert_eq!(config.subinterfaces[1].vport, 1);
    assert!(!config.subinterfaces[0].outgoing);
    assert_eq!(config.subinterfaces[0].st_alock, Some(12.5));
}

#[test]
fn rnode_factory_reads_upstream_airtime_limit_keys() {
    let parse = |params: &[(&str, &str)]| {
        let params: HashMap<String, String> = params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let parsed = RNodeFactory
            .parse_config("radio", InterfaceId(41), &params)
            .unwrap();
        let config = parsed.into_any().downcast::<RNodeConfig>().unwrap();
        (
            config.subinterfaces[0].st_alock,
            config.subinterfaces[0].lt_alock,
        )
    };
    // Upstream RNodeInterface reads airtime_limit_short / _long.
    assert_eq!(
        parse(&[
            ("port", "/dev/ttyUSB0"),
            ("airtime_limit_short", "25"),
            ("airtime_limit_long", "3.5"),
        ]),
        (Some(25.0), Some(3.5))
    );
    // The earlier Rust names still work.
    assert_eq!(
        parse(&[
            ("port", "/dev/ttyUSB0"),
            ("st_alock", "10"),
            ("lt_alock", "1")
        ]),
        (Some(10.0), Some(1.0))
    );
    assert_eq!(parse(&[("port", "/dev/ttyUSB0")]), (None, None));
}

#[test]
fn rnode_lora_bitrate_estimate_uses_radio_params() {
    let mut sub = RNodeSubConfig {
        name: "test".into(),
        vport: 0,
        outgoing: true,
        frequency: 868_000_000,
        bandwidth: 125_000,
        txpower: 7,
        spreading_factor: 8,
        coding_rate: 5,
        flow_control: false,
        st_alock: None,
        lt_alock: None,
    };

    assert_eq!(estimate_lora_bitrate_bps(&sub), 3125);

    sub.spreading_factor = 12;
    assert_eq!(estimate_lora_bitrate_bps(&sub), 293);

    sub.bandwidth = 250_000;
    assert_eq!(estimate_lora_bitrate_bps(&sub), 586);
}

#[test]
fn rnode_lora_airtime_profile_uses_radio_params() {
    let sub = RNodeSubConfig {
        name: "test".into(),
        vport: 0,
        outgoing: true,
        frequency: 868_000_000,
        bandwidth: 125_000,
        txpower: 7,
        spreading_factor: 8,
        coding_rate: 5,
        flow_control: false,
        st_alock: None,
        lt_alock: None,
    };

    let profile = lora_airtime_profile(&sub);
    assert!((profile.transmit_time_secs(100) - 0.307712).abs() < 0.000001);
    assert_eq!(
        profile,
        AirtimeProfile::Lora {
            bandwidth: 125_000,
            spreading_factor: 8,
            coding_rate: 5,
            preamble_symbols: LORA_PREAMBLE_SYMBOLS,
            explicit_header: LORA_EXPLICIT_HEADER,
            crc: LORA_CRC,
        }
    );
}

fn thread_named(prefix: &str) -> bool {
    std::fs::read_dir("/proc/self/task").unwrap().any(|task| {
        let comm = task.unwrap().path().join("comm");
        std::fs::read_to_string(comm).is_ok_and(|comm| comm.trim().starts_with(prefix))
    })
}

/// Data frames the device side reads within `timeout_ms`, past the
/// host's commands.
fn device_reads(master: &mut Transport, want: usize, timeout_ms: i32) -> Vec<Vec<u8>> {
    let mut decoder = rnode_kiss::RNodeDecoder::new();
    let mut frames = Vec::new();
    let mut buf = [0u8; 1024];
    while frames.len() < want && poll_read(master.as_raw_fd(), timeout_ms) {
        let n = master.read(&mut buf).unwrap();
        for event in decoder.feed(&buf[..n]) {
            if let rnode_kiss::RNodeEvent::DataFrame { data, .. } = event {
                frames.push(data);
            }
        }
    }
    frames
}

#[test]
fn folded_rnode_runs_on_the_driver_loop() {
    if !crate::engine::FOLD_IO {
        return;
    }
    let tempdir = tempdir().unwrap();
    let port_path = tempdir.path().join("rnode-port");
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    std::os::unix::fs::symlink(slave_tty_path(slave_fd), &port_path).unwrap();
    let mut master = unsafe { transport_from_raw_fd(master_fd) };
    let slave = unsafe { transport_from_raw_fd(slave_fd) };

    let (tx, rx) = event::channel();
    let mut config = RNodeConfig {
        name: "folded-rnode".into(),
        port: port_path.display().to_string(),
        subinterfaces: vec![RNodeSubConfig {
            name: "folded-rnode".into(),
            vport: 0,
            outgoing: true,
            frequency: 868_000_000,
            bandwidth: 125_000,
            txpower: 7,
            spreading_factor: 8,
            coding_rate: 5,
            flow_control: true,
            st_alock: None,
            lt_alock: None,
        }],
        interface_id: InterfaceId(43),
        base_interface_id: InterfaceId(43),
        ..Default::default()
    };
    config.runtime = Arc::new(Mutex::new(RNodeRuntime::from_config(&config)));
    let sub = config.subinterfaces[0].clone();
    let (mut writers, control) = start_with_control(config, tx.clone()).unwrap();
    let (_, writer) = writers.remove(0);
    assert!(writer.sends_inline());
    let (mut writer, _) =
        crate::interface::wrap_async_writer(writer, InterfaceId(43), "rnode", tx, 16);

    thread::sleep(Duration::from_millis(2500));
    mock_respond_detect(&mut master);
    mock_report_configured(&mut master, &sub);
    wait_for_interface_event(&rx, Duration::from_secs(4), |event| {
        matches!(event, Event::InterfaceUp(InterfaceId(43), None, None))
    });
    // Setup is done: only the driver serves the device now.
    thread::sleep(Duration::from_millis(100));
    assert!(!thread_named("rnode-setup-43"));
    assert!(!thread_named("rnode-reader-43"));
    assert!(!thread_named("rnode-keepaliv"));
    assert!(!thread_named("iface-writer-43"));

    // Inbound, with the modem's report attached.
    master
        .write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_STAT_RSSI,
            &[100],
        ))
        .unwrap();
    let payload: Vec<u8> = (0..32).collect();
    master
        .write_all(&rnode_kiss::rnode_data_frame(0, &payload))
        .unwrap();
    match wait_for_interface_event(&rx, Duration::from_secs(2), |event| {
        matches!(event, Event::Frame { .. })
    }) {
        Event::Frame {
            interface_id,
            data,
            rssi,
            ..
        } => {
            assert_eq!(interface_id, InterfaceId(43));
            assert_eq!(&*data, &payload[..]);
            assert_eq!(rssi, Some(-57));
        }
        _ => unreachable!(),
    }

    // Outbound: the second frame waits for the device to report ready.
    writer.send_frame(b"first frame").unwrap();
    writer.send_frame(b"second frame").unwrap();
    writer.flush_pending();
    assert_eq!(
        device_reads(&mut master, 2, 200),
        vec![b"first frame".to_vec()]
    );
    master
        .write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_READY, &[0x01]))
        .unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    assert_eq!(
        device_reads(&mut master, 1, 2000),
        vec![b"second frame".to_vec()]
    );

    // The device going away is reported.
    drop(master);
    drop(slave);
    wait_for_interface_event(&rx, Duration::from_secs(2), |event| {
        matches!(event, Event::InterfaceDown(InterfaceId(43)))
    });
    control.request_stop();
}

/// As upstream, an RNodeMultiInterface whose device cannot be opened
/// still starts, offline, and tries to open it every five seconds.
#[test]
fn rnode_multi_starts_without_its_device_and_opens_it_later() {
    let tempdir = tempdir().unwrap();
    let port_path = tempdir.path().join("rnode-port");
    let sub = |name: &str, vport: u8| RNodeSubConfig {
        name: name.into(),
        vport,
        outgoing: true,
        frequency: 868_000_000,
        bandwidth: 125_000,
        txpower: 7,
        spreading_factor: 8,
        coding_rate: 5,
        flow_control: false,
        st_alock: None,
        lt_alock: None,
    };
    let mut config = RNodeConfig {
        name: "test-multi".into(),
        port: port_path.display().to_string(),
        subinterfaces: vec![sub("a", 0), sub("b", 1)],
        multi: true,
        base_interface_id: InterfaceId(51),
        ..RNodeConfig::default()
    };
    config.runtime = Arc::new(Mutex::new(RNodeRuntime::from_config(&config)));
    let (tx, rx) = event::channel();

    let started = std::time::Instant::now();
    let (writers, control) = start_with_control(config, tx).unwrap();
    // Both subinterfaces have writers, which cannot write yet.
    assert_eq!(writers.len(), 2);

    // The device appears after start.
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    std::os::unix::fs::symlink(slave_tty_path(slave_fd), &port_path).unwrap();
    let mut master = unsafe { transport_from_raw_fd(master_fd) };
    let _slave = unsafe { transport_from_raw_fd(slave_fd) };
    // Nothing comes up before the first attempt, five seconds in.
    assert!(rx.recv_timeout(Duration::from_secs(4)).is_err());
    // The device answers once the port was opened (and the hardware
    // given its two seconds).
    thread::sleep(Duration::from_millis(3500));
    mock_respond_detect(&mut master);
    for id in [51, 52] {
        let up = wait_for_interface_event(
            &rx,
            Duration::from_secs(5),
            |event| matches!(event, Event::InterfaceUp(InterfaceId(i), _, _) if *i == id),
        );
        // With a writer on the connection now open.
        assert!(matches!(up, Event::InterfaceUp(_, Some(_), None)));
    }
    assert!(started.elapsed() >= OPEN_RETRY_WAIT);
    control.request_stop();
}

#[test]
fn rnode_reconnects_after_serial_disconnect() {
    let tempdir = tempdir().unwrap();
    let port_path = tempdir.path().join("rnode-port");

    let (master1_fd, slave1_fd) = open_pty_pair().unwrap();
    let slave1_path = slave_tty_path(slave1_fd);
    std::os::unix::fs::symlink(&slave1_path, &port_path).unwrap();

    let mut master1 = unsafe { transport_from_raw_fd(master1_fd) };
    let slave1 = unsafe { transport_from_raw_fd(slave1_fd) };

    let (tx, rx) = event::channel();
    let sub = RNodeSubConfig {
        name: "test-rnode".into(),
        vport: 0,
        outgoing: true,
        frequency: 868_000_000,
        bandwidth: 125_000,
        txpower: 7,
        spreading_factor: 8,
        coding_rate: 5,
        flow_control: false,
        st_alock: None,
        lt_alock: None,
    };
    let mut config = RNodeConfig {
        name: "test-rnode".into(),
        port: port_path.display().to_string(),
        speed: 115200,
        subinterfaces: vec![sub],
        multi: false,
        id_interval: None,
        id_callsign: None,
        interface_id: InterfaceId(41),
        base_interface_id: InterfaceId(41),
        pre_opened_fd: None,
        underlay_mark: None,
        runtime: Arc::new(Mutex::new(RNodeRuntime {
            sub: RNodeSubConfig {
                name: String::new(),
                vport: 0,
                outgoing: true,
                frequency: 868_000_000,
                bandwidth: 125_000,
                txpower: 7,
                spreading_factor: 8,
                coding_rate: 5,
                flow_control: false,
                st_alock: None,
                lt_alock: None,
            },
            writer: None,
        })),
        ble: Default::default(),
        reported_phy: Default::default(),
    };
    config.runtime = Arc::new(Mutex::new(RNodeRuntime::from_config(&config)));

    let sub = config.subinterfaces[0].clone();
    let (_writers, control) = start_with_control(config, tx).unwrap();

    thread::sleep(Duration::from_secs(3));
    mock_respond_detect(&mut master1);
    mock_report_configured(&mut master1, &sub);
    let up = wait_for_interface_event(&rx, Duration::from_secs(4), |event| {
        matches!(event, Event::InterfaceUp(InterfaceId(41), _, _))
    });
    assert!(matches!(
        up,
        Event::InterfaceUp(InterfaceId(41), None, None)
    ));

    drop(master1);
    drop(slave1);

    let down = wait_for_interface_event(&rx, Duration::from_secs(4), |event| {
        matches!(event, Event::InterfaceDown(InterfaceId(41)))
    });
    assert!(matches!(down, Event::InterfaceDown(InterfaceId(41))));

    let (master2_fd, slave2_fd) = open_pty_pair().unwrap();
    let slave2_path = slave_tty_path(slave2_fd);
    std::fs::remove_file(&port_path).unwrap();
    std::os::unix::fs::symlink(&slave2_path, &port_path).unwrap();

    let mut master2 = unsafe { transport_from_raw_fd(master2_fd) };
    let _slave2 = unsafe { transport_from_raw_fd(slave2_fd) };

    thread::sleep(Duration::from_secs(3));
    mock_respond_detect(&mut master2);
    mock_report_configured(&mut master2, &sub);
    let up = wait_for_interface_event(&rx, Duration::from_secs(4), |event| {
        matches!(event, Event::InterfaceUp(InterfaceId(41), _, _))
    });
    assert!(matches!(
        up,
        Event::InterfaceUp(InterfaceId(41), Some(_), None)
    ));

    // signal_interface_up publishes telemetry right after InterfaceUp;
    // wait for it so it cannot land in the post-stop silence window.
    let telemetry = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(matches!(
        telemetry,
        Event::InterfaceTelemetry {
            interface_id: InterfaceId(41),
            ..
        }
    ));

    control.request_stop();
    assert!(control.should_stop());
    // A stopped reader must not report the intentional serial close as a
    // hardware failure or start another reconnect attempt.
    drop(master2);
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
}

/// The lines logged so far about `iface` reporting on its radio.
fn radio_lines(iface: &str) -> Vec<(log::Level, String)> {
    logged()
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, line)| {
            line.starts_with(iface)
                && (line.contains(" Radio reporting ") || line.contains(" On-air bitrate "))
        })
        .map(|(_, level, line)| (*level, line.clone()))
        .collect()
}

/// The radio timing the mock firmware reports for 125 kHz, SF8.
const MOCK_PHY: [u16; 6] = [2048, 488, 18, 37, 24, 48];

/// A mock RNode answering the host as the firmware does, including
/// where it reports its radio timing: only while the radio is on, each
/// time bandwidth, spreading factor or coding rate change and when the
/// radio starts. Returns the commands it got.
fn mock_firmware(
    mut master: Transport,
    radio_on: bool,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<Vec<(u8, Vec<u8>)>> {
    thread::spawn(move || {
        let mut online = radio_on;
        let mut got = Vec::new();
        let mut pending = Vec::new();
        let mut buf = [0u8; 1024];
        let phy: Vec<u8> = MOCK_PHY.iter().flat_map(|v| v.to_be_bytes()).collect();
        let answer = |master: &mut Transport, command: u8, data: &[u8]| {
            master
                .write_all(&rnode_kiss::rnode_command(command, data))
                .unwrap();
        };
        while !stop.load(Ordering::Relaxed) {
            if !poll_read(master.as_raw_fd(), 50) {
                continue;
            }
            let n = match master.read(&mut buf) {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            pending.extend_from_slice(&buf[..n]);
            while let Some(end) = pending.iter().skip(1).position(|b| *b == kiss::FEND) {
                let frame: Vec<u8> = pending.drain(..=end).collect();
                let frame = kiss::unescape(&frame[1..]);
                let Some((&command, data)) = frame.split_first() else {
                    continue;
                };
                got.push((command, data.to_vec()));
                match command {
                    rnode_kiss::CMD_DETECT => mock_respond_detect(&mut master),
                    rnode_kiss::CMD_FREQUENCY | rnode_kiss::CMD_TXPOWER => {
                        answer(&mut master, command, data)
                    }
                    rnode_kiss::CMD_BANDWIDTH | rnode_kiss::CMD_SF | rnode_kiss::CMD_CR => {
                        if online {
                            answer(&mut master, rnode_kiss::CMD_STAT_PHYPRM, &phy);
                        }
                        answer(&mut master, command, data);
                    }
                    rnode_kiss::CMD_RADIO_STATE => {
                        if data == [rnode_kiss::RADIO_STATE_ON] && !online {
                            online = true;
                            for _ in 0..3 {
                                answer(&mut master, rnode_kiss::CMD_STAT_PHYPRM, &phy);
                            }
                        } else if data == [rnode_kiss::RADIO_STATE_OFF] {
                            online = false;
                        }
                        answer(&mut master, command, &[u8::from(online)]);
                    }
                    _ => {}
                }
            }
        }
        got
    })
}

/// A single RNode interface up on a pty, served by the mock firmware.
struct MockRNode {
    rx: crate::event::EventReceiver,
    control: super::super::ListenerControl,
    stop: Arc<AtomicBool>,
    firmware: thread::JoinHandle<Vec<(u8, Vec<u8>)>>,
    _slave: Transport,
    _dir: tempfile::TempDir,
}

impl MockRNode {
    fn start(name: &str, id: u64, radio_on: bool) -> MockRNode {
        // Capture from the start.
        logged();
        let dir = tempdir().unwrap();
        let port_path = dir.path().join("rnode-port");
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        std::os::unix::fs::symlink(slave_tty_path(slave_fd), &port_path).unwrap();
        let master = unsafe { transport_from_raw_fd(master_fd) };
        // Kept open so the pty does not hang up.
        let slave = unsafe { transport_from_raw_fd(slave_fd) };
        let mut config = RNodeConfig {
            name: name.into(),
            port: port_path.display().to_string(),
            subinterfaces: vec![RNodeSubConfig {
                name: name.into(),
                vport: 0,
                outgoing: true,
                frequency: 868_000_000,
                bandwidth: 125_000,
                txpower: 14,
                spreading_factor: 8,
                coding_rate: 5,
                flow_control: false,
                st_alock: None,
                lt_alock: None,
            }],
            interface_id: InterfaceId(id),
            base_interface_id: InterfaceId(id),
            ..Default::default()
        };
        config.runtime = Arc::new(Mutex::new(RNodeRuntime::from_config(&config)));
        let stop = Arc::new(AtomicBool::new(false));
        let firmware = mock_firmware(master, radio_on, Arc::clone(&stop));
        let (tx, rx) = event::channel();
        let (_writers, control) = start_with_control(config, tx).unwrap();
        wait_for_interface_event(
            &rx,
            Duration::from_secs(6),
            |event| matches!(event, Event::InterfaceUp(InterfaceId(i), _, _) if *i == id),
        );
        MockRNode {
            rx,
            control,
            stop,
            firmware,
            _slave: slave,
            _dir: dir,
        }
    }

    /// Shut the interface down as the driver does, and return the
    /// commands the device got.
    fn shut_down(self) -> Vec<(u8, Vec<u8>)> {
        // The device is being read when the stop comes.
        let _ = self.rx.recv_timeout(Duration::from_millis(300));
        self.control.request_stop();
        self.control.finish();
        // Whatever the device still answers has time to be read.
        let _ = self.rx.recv_timeout(Duration::from_millis(300));
        self.stop.store(true, Ordering::Relaxed);
        self.firmware.join().unwrap()
    }
}

fn debug_lines(iface: &str, lines: &[&str]) -> Vec<(log::Level, String)> {
    lines
        .iter()
        .map(|line| {
            let level = if line.starts_with("On-air") {
                log::Level::Info
            } else {
                log::Level::Debug
            };
            (level, format!("{} {}", iface, line))
        })
        .collect()
}

const TIMING_LINES: [&str; 4] = [
    "Radio reporting symbol time is 2.05ms (488 baud)",
    "Radio reporting preamble is 18 symbols (37ms)",
    "Radio reporting CSMA slot time is 24ms",
    "Radio reporting DIFS time is 48ms",
];

/// The radio timing is logged where the device reports it: a radio
/// still off reports it once started, after the settings are
/// answered; a radio left on reports it with the first setting that
/// changes its timing, the bandwidth.
#[test]
fn rnode_logs_radio_timing_where_the_device_reports_it() {
    let settings = [
        "Radio reporting bandwidth is 125.0 KHz",
        "Radio reporting TX power is 14 dBm",
        "Radio reporting spreading factor is 8",
        "Radio reporting coding rate is 5",
        "On-air bitrate is now 3.12 kbps",
    ];
    let frequency = "Radio reporting frequency is 868.0 MHz";

    let iface = "RNodeInterface[timing-radio-off]";
    let rnode = MockRNode::start("timing-radio-off", 61, false);
    let mut want = vec![frequency];
    want.extend(settings);
    want.extend(TIMING_LINES);
    assert_eq!(radio_lines(iface), debug_lines(iface, &want));
    rnode.shut_down();

    let iface = "RNodeInterface[timing-radio-on]";
    let rnode = MockRNode::start("timing-radio-on", 62, true);
    let mut want = vec![frequency];
    want.extend(TIMING_LINES);
    want.extend(settings);
    assert_eq!(radio_lines(iface), debug_lines(iface, &want));
    rnode.shut_down();
}

/// On shutdown the radio is turned off before the host leaves, as
/// upstream's detach. A serial port closes right after, before the
/// device's answer is read, so nothing more is logged, as upstream.
#[test]
fn rnode_turns_its_radio_off_on_shutdown() {
    let iface = "RNodeInterface[shutdown-serial]";
    let rnode = MockRNode::start("shutdown-serial", 63, false);
    let got = rnode.shut_down();
    let tail: Vec<_> = got.iter().rev().take(2).rev().cloned().collect();
    assert_eq!(
        tail,
        vec![
            (
                rnode_kiss::CMD_RADIO_STATE,
                vec![rnode_kiss::RADIO_STATE_OFF]
            ),
            (rnode_kiss::CMD_LEAVE, vec![0xFF]),
        ]
    );
    assert!(!radio_lines(iface)
        .iter()
        .any(|(_, line)| line.ends_with("Radio reporting state is offline")));
}

/// What a BLE device answers while its connection closes is read up
/// to the radio's state, which is logged as upstream's reader does.
#[test]
fn closing_answer_is_read_up_to_the_radio_state() {
    logged();
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    let mut master = unsafe { transport_from_raw_fd(master_fd) };
    let mut slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
    let config = RNodeConfig {
        name: "closing-answer".into(),
        ..Default::default()
    };
    master
        .write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_RADIO_STATE,
            &[rnode_kiss::RADIO_STATE_OFF],
        ))
        .unwrap();
    let started = std::time::Instant::now();
    setup::read_closing_answer(&mut slave, &config, started + setup::CLOSING_ANSWER_WAIT);
    assert!(started.elapsed() < setup::CLOSING_ANSWER_WAIT);
    assert_eq!(
        radio_lines("RNodeInterface[closing-answer]"),
        vec![(
            log::Level::Debug,
            "RNodeInterface[closing-answer] Radio reporting state is offline".to_string()
        )]
    );

    // A device that does not answer is waited for no longer than the
    // deadline.
    let started = std::time::Instant::now();
    setup::read_closing_answer(&mut slave, &config, started + Duration::from_millis(200));
    assert!(started.elapsed() < Duration::from_millis(700));
}

fn station_id_config(flow_control: bool) -> RNodeConfig {
    RNodeConfig {
        name: "id".into(),
        subinterfaces: vec![RNodeSubConfig {
            name: "id".into(),
            vport: 0,
            outgoing: true,
            frequency: 868_000_000,
            bandwidth: 125_000,
            txpower: 7,
            spreading_factor: 8,
            coding_rate: 5,
            flow_control,
            st_alock: None,
            lt_alock: None,
        }],
        id_interval: Some(0),
        id_callsign: Some(b"N0CALL".to_vec()),
        ..RNodeConfig::default()
    }
}

/// As upstream: the callsign goes out `id_interval` after the first frame
/// sent since the last identification, and not while nothing is sent.
#[test]
fn station_id_follows_traffic_as_upstream() {
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    crate::sys::set_nonblocking(master_fd).unwrap();
    let writer = Arc::new(Mutex::new(DeviceWriter::new(unsafe {
        transport_from_raw_fd(slave_fd)
    })));
    let config = station_id_config(false);
    let flow = Arc::new(Mutex::new(SubFlowState::new(Some(Arc::from(
        &b"N0CALL"[..],
    )))));
    let flows = [flow.clone()];

    assert_eq!(station_id_due(&config, &flows), None);
    assert_eq!(identify_station(&config, &flows, &writer), None);

    let mut sub = RNodeSubWriter {
        confirmed_pending: None,
        writer: writer.clone(),
        index: 0,
        flow_control: false,
        flow_state: flow.clone(),
        multi: false,
    };
    sub.send_frame(b"traffic").unwrap();
    assert!(station_id_due(&config, &flows).is_some());
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(identify_station(&config, &flows, &writer), None);
    assert_eq!(flow.lock().unwrap().first_tx, None);

    let mut buf = [0u8; 256];
    let mut n = 0isize;
    while let read @ 1.. = crate::sys::read(master_fd, &mut buf[n as usize..]) {
        n += read;
    }
    assert!(n > 0);
    let id_frame = rnode_kiss::rnode_data_frame(0, b"N0CALL");
    assert!(
        buf[..n as usize]
            .windows(id_frame.len())
            .any(|w| w == id_frame),
        "{:02x?} in {:02x?}",
        id_frame,
        &buf[..n as usize]
    );
    unsafe { libc::close(master_fd) };
}

/// With flow control, a station ID waiting behind traffic is queued, and
/// sending it from the queue restarts the interval, as upstream.
#[test]
fn queued_station_id_restarts_the_interval() {
    let (master_fd, slave_fd) = open_pty_pair().unwrap();
    let writer = Arc::new(Mutex::new(DeviceWriter::new(unsafe {
        transport_from_raw_fd(slave_fd)
    })));
    let config = station_id_config(true);
    let flow = Arc::new(Mutex::new(SubFlowState::new(Some(Arc::from(
        &b"N0CALL"[..],
    )))));
    let flows = [flow.clone()];
    let mut sub = RNodeSubWriter {
        confirmed_pending: None,
        writer: writer.clone(),
        index: 0,
        flow_control: true,
        flow_state: flow.clone(),
        multi: false,
    };
    sub.send_frame(b"traffic").unwrap();
    std::thread::sleep(Duration::from_millis(5));
    identify_station(&config, &flows, &writer);
    assert_eq!(flow.lock().unwrap().queue.len(), 1);
    // Traffic queued after it starts a new interval...
    sub.send_frame(b"more").unwrap();
    // ...which the ID, sent from the queue first, does not end.
    process_flow_queue(&flow, &writer, 0, false);
    assert_eq!(flow.lock().unwrap().first_tx, None);
    process_flow_queue(&flow, &writer, 0, false);
    assert!(flow.lock().unwrap().first_tx.is_some());
    unsafe { libc::close(master_fd) };
}

#[test]
fn station_id_callsign_longer_than_32_bytes_is_refused() {
    let params: std::collections::HashMap<String, String> = [
        ("port", "/dev/ttyUSB0"),
        ("frequency", "868000000"),
        ("bandwidth", "125000"),
        ("txpower", "7"),
        ("spreadingfactor", "8"),
        ("codingrate", "5"),
        ("id_interval", "600"),
        ("id_callsign", "A123456789012345678901234567890123"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let error = RNodeFactory
        .parse_config("radio", InterfaceId(1), &params)
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("exceeds the max length of 32 bytes"),
        "{error}"
    );
}
