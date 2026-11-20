//! Configuration directories and the serial connection to a device.

use super::*;

pub(super) fn config_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".config").join("rnodeconf")
}

/// upstream creates its working directories on startup.
pub(super) fn ensure_config_dirs() {
    let base = config_dir();
    for sub in [
        "",
        "update",
        "firmware",
        "extracted",
        "trusted_keys",
        "eeprom",
    ] {
        if let Err(e) = std::fs::create_dir_all(base.join(sub)) {
            println!(
                "No access to directory {}. This utility needs file system access to store firmware and data files. Cannot continue.",
                base.display()
            );
            println!("The contained exception was:");
            println!("{e}");
            graceful_exit(99);
        }
    }
}

pub(super) fn open_serial(port: &str) -> std::io::Result<(std::fs::File, std::fs::File)> {
    let serial = rns_net::serial::SerialPort::open(&rns_net::serial::SerialConfig {
        path: port.to_string(),
        baud: RNODE_BAUDRATE,
        data_bits: 8,
        parity: rns_net::serial::Parity::None,
        stop_bits: 1,
    })?;
    let reader = serial.reader()?;
    let writer = serial.writer()?;
    // The duplicated descriptors keep the port open.
    drop(serial);
    Ok((reader, writer))
}

/// What upstream logs when it cannot open a serial port.
pub(super) fn log_open_failure(port: &str, e: &std::io::Error) {
    log("Could not open the specified serial port. The contained exception was:");
    log(&format!(
        "[Errno {}] could not open port {port}: {e}",
        e.raw_os_error().unwrap_or(0)
    ));
}

/// upstream's search for an NRF52 board's port once the board has reset,
/// which can bring it back under another name: the first listed port with
/// the board's USB serial number. A port that is not listed, such as a
/// pseudo-terminal, is the first candidate when it is the one in use.
pub(super) fn find_port_after_reset(port: &str, usb_serial_id: &Option<String>) -> Option<String> {
    let listed = ports::comports();
    let unlisted = (!listed.iter().any(|p| p.device == port)).then(|| ports::PortInfo {
        device: port.to_string(),
        product: None,
        serial_number: None,
    });
    unlisted
        .into_iter()
        .chain(listed)
        .find(|p| &p.serial_number == usb_serial_id)
        .map(|p| p.device)
}

/// Open `port` and probe the device, as upstream does before each use:
/// the device, what it reported, and its platform (AVR when it does not
/// say).
pub(super) fn connect(port: &str) -> (RNode, device::Reported, u8) {
    log(&format!("Opening serial port {port}..."));
    let opened = open_serial(port).and_then(|(reader, writer)| RNode::new(reader, writer));
    let mut rnode = match opened {
        Ok(rnode) => rnode,
        Err(e) => {
            log_open_failure(port, &e);
            graceful_exit(0);
        }
    };
    rnode.usb_serial_id = ports::comports()
        .into_iter()
        .find(|listed| listed.device == port)
        .and_then(|listed| listed.serial_number);
    if let Err(e) = rnode.device_probe() {
        log("Serial port opened, but RNode did not respond. Is a valid firmware installed?");
        println!("{e}");
        graceful_exit(0);
    }
    let reported = rnode.reported();
    log("Device connected");
    log(&format!(
        "Current firmware version: {}",
        reported.version().unwrap_or_else(|| "None".into())
    ));
    let platform = match (reported.platform, reported.mcu) {
        (Some(platform), Some(_)) => platform,
        _ => rom::PLATFORM_AVR,
    };
    (rnode, reported, platform)
}

/// upstream's serial port menu: the detected ports, newest first, and the
/// one chosen by number, exiting when none is.
pub(super) fn select_port() -> ports::PortInfo {
    let mut ports = ports::comports();
    ports.reverse();
    println!("Detected serial ports:");
    for (i, port) in ports.iter().enumerate() {
        println!(
            "  [{}] {} ({}, {})",
            i + 1,
            port.device,
            ports::py_str(&port.product),
            ports::py_str(&port.serial_number)
        );
    }
    print!("\nEnter the number of the serial port your device is connected to:\n? ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    match py_int(&line) {
        Some(n) if n >= 1 && (n as usize) <= ports.len() => ports.swap_remove(n as usize - 1),
        _ => {
            println!("That port does not exist, exiting now.");
            graceful_exit(0);
        }
    }
}
