//! Formatting utilities matching Python RNS output style.

pub use rns_core::display::{b256_rep, b256_to_bytes, b256rep, prettyb256rep};

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

/// upstream's `RNS.prettytime(time)`: days, hours and minutes, and seconds
/// rounded to two decimals as Python writes them (`1m and 5.5s`, `2h`,
/// `0s`).
pub fn upstream_prettytime(time: f64) -> String {
    prettytime_with(time, false)
}

/// upstream's `RNS.prettytime(time, compact=True)`: whole seconds and at
/// most the two largest units (`1d and 2h`).
pub fn upstream_prettytime_compact(time: f64) -> String {
    prettytime_with(time, true)
}

fn prettytime_with(time: f64, compact: bool) -> String {
    let neg = time < 0.0;
    let mut time = time.abs();
    let days = (time / 86400.0).floor();
    time %= 86400.0;
    let hours = (time / 3600.0).floor();
    time %= 3600.0;
    let minutes = (time / 60.0).floor();
    time %= 60.0;
    // Python: int(time) when compact, else round(time, 2).
    let seconds = if compact {
        time.trunc()
    } else {
        format!("{time:.2}").parse::<f64>().unwrap_or(0.0)
    };

    let mut components = Vec::new();
    for (value, unit) in [(days, "d"), (hours, "h"), (minutes, "m")] {
        if value > 0.0 && (!compact || components.len() < 2) {
            components.push(format!("{value}{unit}"));
        }
    }
    if seconds > 0.0 && (!compact || components.len() < 2) {
        let seconds = if compact {
            format!("{seconds}")
        } else {
            python_float(seconds)
        };
        components.push(format!("{seconds}s"));
    }

    let mut text = String::new();
    let count = components.len();
    for (i, component) in components.iter().enumerate() {
        if i > 0 {
            text.push_str(if i + 1 < count { ", " } else { " and " });
        }
        text.push_str(component);
    }
    match (text.is_empty(), neg) {
        (true, _) => "0s".into(),
        (false, true) => format!("-{text}"),
        (false, false) => text,
    }
}

/// A float as Python's `repr()` and `str()` write it: the shortest form
/// that reads back the same, with `.0` on whole numbers and an exponent
/// below 1e-4 and from 1e16 (`1e+16`, `1.5e-07`).
pub fn python_float(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.into();
    }
    let sci = format!("{:e}", value.abs());
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if (-4..16).contains(&exponent) {
        let point = exponent + 1;
        let text = if point <= 0 {
            format!("0.{}{digits}", "0".repeat((-point) as usize))
        } else if point as usize >= digits.len() {
            format!("{digits}{}.0", "0".repeat(point as usize - digits.len()))
        } else {
            let (whole, fraction) = digits.split_at(point as usize);
            format!("{whole}.{fraction}")
        };
        format!("{sign}{text}")
    } else {
        let (first, rest) = digits.split_at(1);
        let rest = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!("{sign}{first}{rest}e{exp_sign}{:02}", exponent.abs())
    }
}

/// A value as Python's `json.dumps` writes it, bytes as plain hex (as
/// upstream's rnpath converts them first).
pub fn python_json(value: &rns_net::pickle::PickleValue) -> String {
    use rns_net::pickle::PickleValue;
    match value {
        PickleValue::None => "null".into(),
        PickleValue::Bool(b) => if *b { "true" } else { "false" }.into(),
        PickleValue::Int(n) => n.to_string(),
        PickleValue::Float(f) if f.is_nan() => "NaN".into(),
        PickleValue::Float(f) if f.is_infinite() => {
            if *f > 0.0 { "Infinity" } else { "-Infinity" }.into()
        }
        PickleValue::Float(f) => python_float(*f),
        PickleValue::String(s) => json_string(s),
        PickleValue::Bytes(b) => format!("\"{}\"", prettyhexrep(b)),
        PickleValue::List(items) => {
            let inner: Vec<String> = items.iter().map(python_json).collect();
            format!("[{}]", inner.join(", "))
        }
        PickleValue::Dict(pairs) => {
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        PickleValue::String(s) => json_string(s),
                        other => json_string(&python_json(other)),
                    };
                    format!("{key}: {}", python_json(v))
                })
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// A JSON string as Python's `json.dumps` writes it (`ensure_ascii`).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
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

/// Format a stamp value or cost as upstream's `RNS.prettycost` does
/// (rgit `21170877`): quantized to the 1/256 cost grid and clamped to
/// `STAMP_COST_CAP`, with three decimals, or `n` when there is none (`?`
/// before rgit `d5891fde`).
pub fn prettycost(value: Option<f64>) -> String {
    match value {
        Some(value) => rns_crypto::stamp_value::pretty_cost(value),
        None => "n".into(),
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
    while !result.len().is_multiple_of(8) {
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
    fn prettycost_quantizes_clamps_and_rounds_like_upstream() {
        assert_eq!(prettycost(None), "n");
        assert_eq!(prettycost(Some(23.5)), "23.500");
        assert_eq!(prettycost(Some(24.734375)), "24.734");
        // Rounded onto the 1/256 grid first: 19.2 is 4915/256.
        assert_eq!(prettycost(Some(19.2)), "19.199");
        // Exact ties round to even, as Python's format does.
        assert_eq!(prettycost(Some(0.0625)), "0.062");
        assert_eq!(prettycost(Some(0.1875)), "0.188");
        // Clamped to the cost cap, as quantize_cost is.
        assert_eq!(prettycost(Some(256.0)), "100.000");
        assert_eq!(prettycost(Some(-1.0)), "0.000");
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
    fn prettytime_matches_upstream() {
        // Python: RNS.prettytime(t) and RNS.prettytime(t, compact=True).
        let cases = [
            (0.0, "0s", "0s"),
            (0.004, "0s", "0s"),
            (1.0, "1.0s", "1s"),
            (30.0, "30.0s", "30s"),
            (65.5, "1m and 5.5s", "1m and 5s"),
            (90.0, "1m and 30.0s", "1m and 30s"),
            (120.0, "2m", "2m"),
            (3661.0, "1h, 1m and 1.0s", "1h and 1m"),
            (86400.0, "1d", "1d"),
            (90061.25, "1d, 1h, 1m and 1.25s", "1d and 1h"),
            (604799.999, "6d, 23h, 59m and 60.0s", "6d and 23h"),
            (-125.0, "-2m and 5.0s", "-2m and 5s"),
            (59.996, "60.0s", "59s"),
        ];
        for (time, full, compact) in cases {
            assert_eq!(upstream_prettytime(time), full, "{time}");
            assert_eq!(upstream_prettytime_compact(time), compact, "{time}");
        }
    }

    #[test]
    fn python_float_matches_repr() {
        let cases = [
            (0.0, "0.0"),
            (5.0, "5.0"),
            (-1.5, "-1.5"),
            (1234.5, "1234.5"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1.2345e20, "1.2345e+20"),
            (1763112345.123456, "1763112345.123456"),
            (0.1 + 0.2, "0.30000000000000004"),
        ];
        for (value, repr) in cases {
            assert_eq!(python_float(value), repr);
        }
    }

    #[test]
    fn python_json_matches_json_dumps() {
        use rns_net::pickle::PickleValue as P;
        let value = P::List(vec![P::Dict(vec![
            (P::String("hash".into()), P::Bytes(vec![0xab, 0x01])),
            (P::String("hops".into()), P::Int(2)),
            (P::String("expires".into()), P::Float(1.5)),
            (P::String("value".into()), P::None),
            (P::String("ok".into()), P::Bool(true)),
            (
                P::String("interface".into()),
                P::String("If \"x\"\\ é\n😀".into()),
            ),
            (
                P::String("ts".into()),
                P::List(vec![P::Float(2.0), P::Float(1e16)]),
            ),
        ])]);
        // Python: json.dumps of the same list.
        assert_eq!(
            python_json(&value),
            r#"[{"hash": "ab01", "hops": 2, "expires": 1.5, "value": null, "ok": true, "interface": "If \"x\"\\ \u00e9\n\ud83d\ude00", "ts": [2.0, 1e+16]}]"#
        );
        assert_eq!(python_json(&P::List(Vec::new())), "[]");
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
