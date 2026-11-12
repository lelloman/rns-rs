//! Serial ports as pyserial's `list_ports.comports()` finds them on Linux:
//! the usual device name patterns, with the USB product and serial number
//! from sysfs, leaving out built-in ports with no hardware behind them.

use std::path::{Path, PathBuf};

pub struct PortInfo {
    pub device: String,
    pub product: Option<String>,
    pub serial_number: Option<String>,
}

/// The device name patterns pyserial looks for, in its order.
const PATTERNS: &[&str] = &[
    "ttyS", "ttyUSB", "ttyXRUSB", "ttyACM", "ttyAMA", "rfcomm", "ttyAP",
];

pub fn comports() -> Vec<PortInfo> {
    let names: Vec<String> = std::fs::read_dir("/dev")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut ports = Vec::new();
    for pattern in PATTERNS {
        let mut matching: Vec<&String> = names.iter().filter(|n| n.starts_with(pattern)).collect();
        matching.sort();
        for name in matching {
            if let Some(info) = sysfs_info(name) {
                ports.push(info);
            }
        }
    }
    ports
}

/// pyserial's `SysFS`; `None` for a port its subsystem marks as absent.
fn sysfs_info(name: &str) -> Option<PortInfo> {
    let device_link = PathBuf::from(format!("/sys/class/tty/{name}/device"));
    let (device_path, subsystem) = if device_link.exists() {
        let device_path = std::fs::canonicalize(&device_link).ok()?;
        let subsystem = std::fs::canonicalize(device_path.join("subsystem"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        (Some(device_path), subsystem)
    } else {
        (None, None)
    };
    if subsystem.as_deref() == Some("platform") {
        return None;
    }
    let interface_path = match (subsystem.as_deref(), &device_path) {
        (Some("usb-serial"), Some(path)) => path.parent().map(Path::to_path_buf),
        (Some("usb"), Some(path)) => Some(path.clone()),
        _ => None,
    };
    let usb_device = interface_path.as_deref().and_then(Path::parent);
    let read = |file: &str| -> Option<String> {
        let text = std::fs::read_to_string(usb_device?.join(file)).ok()?;
        Some(text.lines().next().unwrap_or_default().trim().to_string())
    };
    Some(PortInfo {
        device: format!("/dev/{name}"),
        product: read("product"),
        serial_number: read("serial"),
    })
}

/// Python's `str()` of an optional string.
pub fn py_str(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("None")
}
