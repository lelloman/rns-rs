//! A device's radio, TNC mode and peripheral settings.

use super::*;

/// upstream `set_wifi_ip` and `set_wifi_nm`: a dotted quad as four bytes.
pub(super) fn ip_bytes(text: &str) -> Result<[u8; 4], String> {
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return Err("Invalid IP address length".into());
    }
    let mut bytes = [0u8; 4];
    for (byte, octet) in bytes.iter_mut().zip(&octets) {
        let value = py_int(octet).ok_or_else(|| {
            format!("Could not decode IP address octet: invalid literal for int() with base 10: '{octet}'")
        })?;
        if !(0..=255).contains(&value) {
            return Err("Could not decode IP address octet: Invalid IP octet value".into());
        }
        *byte = value as u8;
    }
    Ok(bytes)
}

/// A WiFi string setting: UTF-8 with a closing NUL, or a lone NUL to
/// delete it.
pub(super) fn wifi_string(value: Option<&str>) -> Vec<u8> {
    match value {
        None => vec![0x00],
        Some(text) => {
            let mut data = text.as_bytes().to_vec();
            data.push(0x00);
            data
        }
    }
}

/// The display, NeoPixel, interference avoidance, Bluetooth and WiFi
/// settings, in upstream's order. Each is sent to the device as given;
/// the device stores it.
pub(super) fn configure_peripherals(rnode: &mut RNode, args: &Args) {
    let sent = |result: std::io::Result<()>| {
        if let Err(e) = result {
            println!("{e}");
            graceful_exit(1);
        }
    };
    let byte = |value: i64, max: i64| value.clamp(0, max) as u8;

    if let Some(intensity) = args.int("--display") {
        let intensity = byte(intensity, 255);
        log(&format!("Setting display intensity to {intensity}"));
        sent(rnode.send(
            kiss::CMD_DISP_INT,
            &[intensity],
            "sending display intensity command to device",
        ));
    }
    if let Some(timeout) = args.int("--timeout") {
        let timeout = byte(timeout, 255);
        if timeout == 0 {
            log("Disabling display blanking");
        } else {
            log(&format!("Setting display timeout to {timeout}"));
        }
        sent(rnode.send(
            kiss::CMD_DISP_BLNK,
            &[timeout],
            "sending display blanking timeout command to device",
        ));
    }
    if let Some(rotation) = args.int("--rotation") {
        let rotation = byte(rotation, 3);
        log(&format!("Setting display rotation to {rotation}"));
        sent(rnode.send(
            kiss::CMD_DISP_ROT,
            &[rotation],
            "sending display rotation command to device",
        ));
    }
    if args.has("--recondition-display") {
        log("Starting display reconditioning");
        sent(rnode.send(
            kiss::CMD_DISP_RCND,
            &[0x01],
            "sending display recondition command to device",
        ));
    }
    for (option, disabled, message) in [
        ("--ia-enable", 0x00, "Enabling interference avoidance"),
        ("--ia-disable", 0x01, "Disabling interference avoidance"),
    ] {
        if args.has(option) {
            log(message);
            sent(rnode.send(
                kiss::CMD_DIS_IA,
                &[disabled],
                "sending interference avoidance configuration command to device",
            ));
        }
    }
    if let Some(intensity) = args.int("--np") {
        let intensity = byte(intensity, 255);
        log(&format!("Setting NeoPixel intensity to {intensity}"));
        sent(rnode.send(
            kiss::CMD_NP_INT,
            &[intensity],
            "sending NeoPixel intensity command to device",
        ));
    }
    if let Some(address) = args.value("--display-addr") {
        let address = address.strip_prefix("0x").unwrap_or(address);
        match signature::unhex(address).as_deref() {
            Some([address]) => {
                log(&format!("Setting display address to {address:02x}"));
                sent(rnode.send(
                    kiss::CMD_DISP_ADR,
                    &[*address],
                    "sending display address command to device",
                ));
                let _ = rnode.hard_reset();
                graceful_exit(0);
            }
            _ => log("Invalid display address specified"),
        }
    }

    for (option, control, message) in [
        ("--bluetooth-on", 0x01, "Enabling Bluetooth..."),
        ("--bluetooth-off", 0x00, "Disabling Bluetooth..."),
        (
            "--bluetooth-pair",
            0x02,
            "Putting device into Bluetooth pairing mode. Press enter to exit when done.",
        ),
    ] {
        if args.has(option) {
            log(message);
            sent(rnode.send(
                kiss::CMD_BT_CTRL,
                &[control],
                "sending bluetooth command to device",
            ));
            if control == 0x02 {
                let mut line = String::new();
                let _ = std::io::stdin().lock().read_line(&mut line);
            }
            sent(rnode.leave());
        }
    }

    // A WiFi setting the device refuses ends the run, as upstream's does.
    let refused = |what: &str, error: String| -> ! {
        println!("Could not set WiFi {what}: {error}");
        graceful_exit(0);
    };
    if let Some(channel) = args.value("--channel").filter(|v| !v.is_empty()) {
        log(&format!("Setting WiFi channel to {channel}"));
        match py_int(channel).filter(|ch| (1..=14).contains(ch)) {
            Some(ch) => sent(rnode.send(
                kiss::CMD_WIFI_CHN,
                &[ch as u8],
                "sending wifi channel to device",
            )),
            None => refused("channel", "Invalid WiFi channel".into()),
        }
    }
    if let Some(ssid) = args.value("--ssid").filter(|v| !v.is_empty()) {
        let ssid = if ssid.to_lowercase() == "none" {
            log("Deleting WiFi SSID");
            None
        } else {
            log(&format!("Setting WiFi SSID to: {ssid}"));
            Some(ssid)
        };
        let data = wifi_string(ssid);
        if ssid.is_some() && data.len() > 33 {
            refused("SSID", "Invalid SSID length".into());
        }
        sent(rnode.send(kiss::CMD_WIFI_SSID, &data, "sending wifi SSID to device"));
    }
    if let Some(psk) = args.value("--psk").filter(|v| !v.is_empty()) {
        let psk = if psk.to_lowercase() == "none" {
            log("Deleting WiFi PSK");
            None
        } else {
            log("Setting WiFi PSK");
            Some(psk)
        };
        let data = wifi_string(psk);
        // Upstream counts the closing NUL, so a 7-character PSK passes.
        if psk.is_some() && !(8..=33).contains(&data.len()) {
            refused("PSK", "Invalid psk length".into());
        }
        sent(rnode.send(kiss::CMD_WIFI_PSK, &data, "sending wifi SSID to device"));
    }
    for (option, what, command, dhcp, set) in [
        (
            "--ip",
            "IP",
            kiss::CMD_WIFI_IP,
            "Setting WiFi IP to DHCP...",
            "Setting WiFi static IP to: ",
        ),
        (
            "--nm",
            "netmask",
            kiss::CMD_WIFI_NM,
            "Deleting WiFi static netmask configuration...",
            "Setting WiFi static netmask to: ",
        ),
    ] {
        let Some(value) = args.value(option).filter(|v| !v.is_empty()) else {
            continue;
        };
        let bytes = if value.to_lowercase() == "none" {
            log(dhcp);
            [0u8; 4]
        } else {
            log(&format!("{set}{value}"));
            match ip_bytes(value) {
                Ok(bytes) => bytes,
                Err(e) => refused(what, e),
            }
        };
        let described = if command == kiss::CMD_WIFI_IP {
            "sending wifi IP address to device"
        } else {
            "sending wifi netmask to device"
        };
        sent(rnode.send(command, &bytes, described));
    }
    if let Some(mode) = args.value("--wifi").filter(|v| !v.is_empty()) {
        let mode = mode.to_lowercase();
        let mode = if mode.starts_with("sta") {
            log("Setting WiFi to station mode");
            0x01
        } else if mode.starts_with("ap") {
            log("Setting WiFi to AP mode");
            0x02
        } else {
            log("Disabling WiFi...");
            0x00
        };
        sent(rnode.send(
            kiss::CMD_WIFI_MODE,
            &[mode],
            "sending wifi mode command to device",
        ));
    }
}

/// `-c`.
pub(super) fn show_config(rnode: &mut RNode, image: &[u8], _platform: u8, show_psk: bool) {
    let cfg_sector = rnode.download_cfg_sector().ok().flatten();
    let at = |addr: u8| image.get(addr as usize).copied().unwrap_or(0xFF);
    let ec_bt = at(rom::ADDR_CONF_BT);
    let ec_dint = at(rom::ADDR_CONF_DINT);
    let ec_dadr = at(rom::ADDR_CONF_DADR);
    let ec_dblk = at(rom::ADDR_CONF_DBLK);
    let ec_drot = at(rom::ADDR_CONF_DROT);
    let ec_pset = at(rom::ADDR_CONF_PSET);
    let ec_pint = at(rom::ADDR_CONF_PINT);
    let ec_bset = at(rom::ADDR_CONF_BSET);
    let ec_dia = at(rom::ADDR_CONF_DIA);
    let ec_wifi = at(rom::ADDR_CONF_WIFI);
    let mut ec_wchn = at(rom::ADDR_CONF_WCHN);
    let mut ec_ssid: Option<String> = None;
    let mut ec_psk: Option<String> = None;
    let mut ec_ip: Option<String> = None;
    let mut ec_nm: Option<String> = None;
    if !(1..=14).contains(&ec_wchn) {
        ec_wchn = 1;
    }
    if let Some(sector) = cfg_sector.as_ref() {
        let text = |start: u8| -> Vec<u8> {
            let mut bytes = Vec::new();
            for i in 0..32 {
                let byte = sector.get(start as usize + i).copied().unwrap_or(0);
                let byte = if byte == 0xFF { 0 } else { byte };
                if byte == 0 {
                    break;
                }
                bytes.push(byte);
            }
            bytes
        };
        let address = |start: u8| -> Option<String> {
            let &[a, b, c, d] = sector.get(start as usize..start as usize + 4)? else {
                return None;
            };
            let ip = format!("{a}.{b}.{c}.{d}");
            (ip != "255.255.255.255" && ip != "0.0.0.0").then_some(ip)
        };
        match String::from_utf8(text(rom::ADDR_CONF_SSID)) {
            Ok(ssid) => ec_ssid = Some(ssid),
            Err(_) => println!("Error: Could not decode WiFi SSID read from device"),
        }
        let psk_bytes = text(rom::ADDR_CONF_PSK);
        ec_ip = address(rom::ADDR_CONF_IP);
        ec_nm = address(rom::ADDR_CONF_NM);
        if ec_wifi == 0x02 {
            ec_ip = Some("10.0.0.1".into());
            ec_nm = Some("255.255.255.0".into());
        }
        match String::from_utf8(psk_bytes) {
            Ok(psk) => ec_psk = Some(psk),
            Err(_) => println!("Error: Could not decode WiFi PSK read from device"),
        }
        if !show_psk {
            if let Some(psk) = ec_psk.as_mut().filter(|psk| !psk.is_empty()) {
                *psk = "*".repeat(psk.chars().count());
            }
        }
    }
    let set = |value: &Option<String>| value.as_ref().filter(|v| !v.is_empty()).cloned();

    println!("\nDevice configuration:");
    if ec_bt == 0x73 {
        println!("  Bluetooth              : Enabled");
    } else {
        println!("  Bluetooth              : Disabled");
    }
    match ec_wifi {
        0x01 => println!("  WiFi                   : Enabled (Station)"),
        0x02 => println!("  WiFi                   : Enabled (AP)"),
        _ => println!("  WiFi                   : Disabled"),
    }
    if ec_wifi == 0x01 || ec_wifi == 0x02 {
        println!("    Channel              : {ec_wchn}");
        match set(&ec_ssid) {
            None => println!("    SSID                 : Not set"),
            Some(ssid) => println!("    SSID                 : {ssid}"),
        }
        match set(&ec_psk) {
            None => println!("    PSK                  : Not set"),
            Some(psk) => println!("    PSK                  : {psk}"),
        }
        match &ec_ip {
            None => println!("    IP Address           : DHCP"),
            Some(ip) => println!("    IP Address           : {ip}"),
        }
        if let (Some(_), Some(nm)) = (&ec_ip, &ec_nm) {
            println!("    Network Mask         : {nm}");
        }
    }
    if ec_dia == 0x00 {
        println!("  Interference avoidance : Enabled");
    } else {
        println!("  Interference avoidance : Disabled");
    }
    println!("  Display brightness     : {ec_dint}");
    if ec_dadr == 0xFF {
        println!("  Display address        : Default");
    } else {
        println!("  Display address        : {ec_dadr:02x}");
    }
    if ec_bset == 0x73 && ec_dblk != 0x00 {
        println!("  Display blanking       : {ec_dblk}s");
    } else {
        println!("  Display blanking       : Disabled");
    }
    if ec_drot != 0xFF {
        let rotation = match ec_drot {
            0x00 => "Landscape",
            0x01 => "Portrait",
            0x02 => "Landscape 180",
            0x03 => "Portrait 180",
            _ => "Unknown",
        };
        println!("  Display rotation       : {rotation}");
    } else {
        println!("  Display rotation       : Default");
    }
    if ec_pset == 0x73 {
        println!("  Neopixel Intensity     : {ec_pint}");
    }
    println!();
}

/// `-T`: store the TNC radio parameters and switch to TNC mode, asking for
/// the ones not given.
pub(super) fn set_tnc_mode(rnode: &mut RNode, args: &Args, platform: u8) {
    let freq = args.int("--freq").filter(|v| *v != 0);
    let bw = args.int("--bw").filter(|v| *v != 0);
    let txp = args.int("--txp");
    let sf = args.int("--sf").filter(|v| *v != 0);
    let cr = args.int("--cr").filter(|v| *v != 0);
    if !(freq.is_some()
        && bw.is_some()
        && txp.is_some_and(|v| v != 0)
        && sf.is_some()
        && cr.is_some())
    {
        log("Please input startup configuration:");
    }
    println!();
    let frequency = freq.unwrap_or_else(|| prompt_int("Frequency in Hz:\t"));
    let bandwidth = bw.unwrap_or_else(|| prompt_int("Bandwidth in Hz:\t"));
    let txpower = match txp {
        Some(v) if (0..=17).contains(&v) => v,
        _ => prompt_int("TX Power in dBm:\t"),
    };
    let sf = sf.unwrap_or_else(|| prompt_int("Spreading factor:\t"));
    let cr = cr.unwrap_or_else(|| prompt_int("Coding rate:\t\t"));
    println!();
    let radio = RadioConfig {
        frequency: frequency as u32,
        bandwidth: bandwidth as u32,
        txpower: txpower as u8,
        sf: sf as u8,
        cr: cr as u8,
    };
    if rnode.init_radio(&radio).is_err() {
        graceful_exit(1);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    if rnode.set_tnc_mode(platform).is_err() {
        graceful_exit(1);
    }
    log("Device set to TNC operating mode");
    std::thread::sleep(std::time::Duration::from_secs(1));
}
