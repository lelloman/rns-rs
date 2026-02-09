//! Formatting utilities matching Python RNS output style.

/// Format a byte count as a human-readable string.
/// Matches Python's `RNS.prettysize()`.
pub fn size_str(num: u64) -> String {
    if num < 1000 {
        return format!("{} B", num);
    }
    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut val = num as f64;
    let mut unit_idx = 0;
    while val >= 1000.0 && unit_idx < units.len() - 1 {
        val /= 1000.0;
        unit_idx += 1;
    }
    format!("{:.2} {}", val, units[unit_idx])
}

/// Format a bitrate as a human-readable string.
/// Matches Python's `RNS.prettyspeed()`.
pub fn speed_str(bps: u64) -> String {
    if bps < 1000 {
        return format!("{} b/s", bps);
    }
    let units = ["b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"];
    let mut val = bps as f64;
    let mut unit_idx = 0;
    while val >= 1000.0 && unit_idx < units.len() - 1 {
        val /= 1000.0;
        unit_idx += 1;
    }
    format!("{:.2} {}", val, units[unit_idx])
}

/// Format a destination hash as a hex string.
/// Matches Python's `RNS.prettyhexrep()`.
pub fn prettyhexrep(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Format a duration in seconds as a human-readable string.
/// Matches Python's `RNS.prettytime()`.
pub fn prettytime(secs: f64) -> String {
    if secs < 0.0 {
        return "now".into();
    }
    let total_secs = secs as u64;
    if total_secs == 0 {
        return "now".into();
    }

    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if secs > 0 && days == 0 {
        parts.push(format!("{}s", secs));
    }

    if parts.is_empty() {
        "now".into()
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_str() {
        assert_eq!(size_str(0), "0 B");
        assert_eq!(size_str(500), "500 B");
        assert_eq!(size_str(1234), "1.23 KB");
        assert_eq!(size_str(1234567), "1.23 MB");
        assert_eq!(size_str(1234567890), "1.23 GB");
    }

    #[test]
    fn test_speed_str() {
        assert_eq!(speed_str(500), "500 b/s");
        assert_eq!(speed_str(10_000_000), "10.00 Mb/s");
        assert_eq!(speed_str(1_000_000), "1.00 Mb/s");
    }

    #[test]
    fn test_prettyhexrep() {
        assert_eq!(prettyhexrep(&[0xab, 0xcd, 0xef]), "abcdef");
        assert_eq!(prettyhexrep(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn test_prettytime() {
        assert_eq!(prettytime(0.0), "now");
        assert_eq!(prettytime(30.0), "30s");
        assert_eq!(prettytime(90.0), "1m 30s");
        assert_eq!(prettytime(3661.0), "1h 1m 1s");
        assert_eq!(prettytime(86400.0), "1d");
        assert_eq!(prettytime(90061.0), "1d 1h 1m");
    }
}
