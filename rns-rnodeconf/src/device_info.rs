//! What a connected device reports about itself.

use super::*;

/// `-i`.
pub(super) fn show_info(info: &eeprom::DeviceInfo, reported: &device::Reported) {
    let timestamp = u32::from_be_bytes(info.made) as i64;
    let timestring = local_time("%Y-%m-%d %H:%M:%S", timestamp);
    let sigstring = if info.signature_valid {
        if info.locally_signed {
            "Validated - Local signature".to_string()
        } else {
            format!(
                "Genuine board, vendor is {}",
                info.vendor.clone().unwrap_or_default()
            )
        }
    } else {
        "Unverified".to_string()
    };
    let board_string = reported
        .board
        .map_or(String::new(), |board| format!(":{board:02x}"));
    let model = rom::model(info.model);
    log("");
    log("Device info:");
    log(&format!(
        "\tProduct            : {} {} ({:02x}:{:02x}{board_string})",
        rom::product_name(info.product).unwrap_or("Unknown product"),
        model.as_ref().map_or("(Unknown model)", |m| m.band),
        info.product,
        info.model
    ));
    log(&format!("\tDevice signature   : {sigstring}"));
    log(&format!(
        "\tFirmware version   : {}",
        reported.version().unwrap_or_else(|| "None".into())
    ));
    log(&format!("\tHardware revision  : {}", info.hw_rev));
    log(&format!(
        "\tSerial number      : {}",
        hexrep(&info.serialno)
    ));
    log(&format!(
        "\tModem chip         : {}",
        model.as_ref().map_or("Unknown", |m| m.modem)
    ));
    log(&format!(
        "\tFrequency range    : {} MHz - {} MHz",
        py_float(info.min_freq as f64 / 1e6),
        py_float(info.max_freq as f64 / 1e6)
    ));
    log(&format!("\tMax TX power       : {} dBm", info.max_output));
    log(&format!("\tManufactured       : {timestring}"));
    match info.tnc {
        Some(tnc) => {
            let bitrate = tnc.sf as f64
                * ((4.0 / tnc.cr as f64)
                    / (2f64.powi(tnc.sf as i32) / (tnc.bandwidth as f64 / 1000.0)))
                * 1000.0;
            let txp_mw = py_round(10f64.powf(tnc.txpower as f64 / 10.0), 3);
            log("");
            log("\tDevice mode        : TNC");
            log(&format!(
                "\t  Frequency        : {} MHz",
                py_float(tnc.frequency as f64 / 1_000_000.0)
            ));
            log(&format!(
                "\t  Bandwidth        : {} KHz",
                py_float(tnc.bandwidth as f64 / 1000.0)
            ));
            log(&format!(
                "\t  TX power         : {} dBm ({} mW)",
                tnc.txpower,
                py_float(txp_mw)
            ));
            log(&format!("\t  Spreading factor : {}", tnc.sf));
            log(&format!("\t  Coding rate      : {}", tnc.cr));
            log(&format!(
                "\t  On-air bitrate   : {} kbps",
                py_float(py_round(bitrate / 1000.0, 2))
            ));
        }
        None => log("\tDevice mode        : Normal (host-controlled)"),
    }
    println!();
}
