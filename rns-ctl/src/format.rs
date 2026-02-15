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

/// Format a frequency as a human-readable string.
/// E.g., 3.5 per hour, 0.2 per minute, etc.
pub fn prettyfrequency(freq: f64) -> String {
    if freq <= 0.0 {
        return "none".into();
    }
    // freq is in per-second
    let per_minute = freq * 60.0;
    let per_hour = freq * 3600.0;

    if per_hour < 1.0 {
        format!("{:.2}/h", per_hour)
    } else if per_minute < 1.0 {
        format!("{:.1}/h", per_hour)
    } else {
        format!("{:.1}/m", per_minute)
    }
}

/// RFC 4648 Base32 encoding (standard alphabet, with padding).
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut bits: u32 = 0;
    let mut num_bits: u32 = 0;

    for &byte in data {
        bits = (bits << 8) | byte as u32;
        num_bits += 8;
        while num_bits >= 5 {
            num_bits -= 5;
            result.push(ALPHABET[((bits >> num_bits) & 0x1F) as usize] as char);
        }
    }
    if num_bits > 0 {
        result.push(ALPHABET[((bits << (5 - num_bits)) & 0x1F) as usize] as char);
    }
    // Pad to multiple of 8
    while result.len() % 8 != 0 {
        result.push('=');
    }
    result
}

/// RFC 4648 Base32 decoding (standard alphabet, with padding).
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut result = Vec::new();
    let mut bits: u32 = 0;
    let mut num_bits: u32 = 0;

    for c in s.chars() {
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        bits = (bits << 5) | val;
        num_bits += 5;
        if num_bits >= 8 {
            num_bits -= 8;
            result.push((bits >> num_bits) as u8);
        }
    }
    Some(result)
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

    #[test]
    fn test_prettyfrequency() {
        assert_eq!(prettyfrequency(0.0), "none");
        assert_eq!(prettyfrequency(-1.0), "none");
        // 1 per hour = 1/3600 per second
        assert_eq!(prettyfrequency(1.0 / 3600.0), "1.0/h");
        // 10 per minute = 10/60 per second
        assert_eq!(prettyfrequency(10.0 / 60.0), "10.0/m");
    }

    #[test]
    fn test_base32_encode() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY======");
        assert_eq!(base32_encode(b"fo"), "MZXQ====");
        assert_eq!(base32_encode(b"foo"), "MZXW6===");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ=");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI======");
    }

    #[test]
    fn test_base32_decode() {
        assert_eq!(base32_decode("").unwrap(), b"");
        assert_eq!(base32_decode("MY======").unwrap(), b"f");
        assert_eq!(base32_decode("MZXQ====").unwrap(), b"fo");
        assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(base32_decode("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
        // Case insensitive
        assert_eq!(base32_decode("mzxw6===").unwrap(), b"foo");
        // Invalid char
        assert!(base32_decode("!!!").is_none());
    }

    #[test]
    fn test_base32_roundtrip() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let encoded = base32_encode(&data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
