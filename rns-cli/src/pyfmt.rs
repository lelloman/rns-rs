//! Python's value formatting and upstream's `RNS.pretty*` helpers, exactly,
//! for output that must match upstream's utilities byte for byte.
//!
//! Python keeps ints and floats apart (`str(round(5, 1))` is `5`, of a float
//! `5.0`), so the helpers that can see either take a [`Num`].

use rns_net::pickle::PickleValue;

use crate::format::python_float;

/// A Python number: `int` or `float` (`bool` reads as an int).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num {
    /// A Python `int`.
    Int(i64),
    /// A Python `float`.
    Float(f64),
}

impl Num {
    /// The number in a pickled value; `None` for anything but an int, a float
    /// or a bool.
    pub fn of(value: &PickleValue) -> Option<Num> {
        match value {
            PickleValue::Int(n) => Some(Num::Int(*n)),
            PickleValue::Float(f) => Some(Num::Float(*f)),
            PickleValue::Bool(b) => Some(Num::Int(*b as i64)),
            _ => None,
        }
    }

    /// The value as an `f64`; large ints lose precision.
    pub fn f(self) -> f64 {
        match self {
            Num::Int(n) => n as f64,
            Num::Float(f) => f,
        }
    }

    /// Python's `str()`.
    pub fn str(self) -> String {
        match self {
            Num::Int(n) => n.to_string(),
            Num::Float(f) => python_float(f),
        }
    }

    /// Whether the value is zero, of either type.
    pub fn is_zero(self) -> bool {
        self.f() == 0.0
    }
}

/// Python's truthiness of a dict lookup (`d.get(key)`): missing, `None`,
/// zero, and empty values are false.
pub fn truthy(value: Option<&PickleValue>) -> bool {
    match value {
        None | Some(PickleValue::None) => false,
        Some(PickleValue::Bool(b)) => *b,
        Some(PickleValue::Int(n)) => *n != 0,
        Some(PickleValue::Float(f)) => *f != 0.0,
        Some(PickleValue::String(s)) => !s.is_empty(),
        Some(PickleValue::Bytes(b)) => !b.is_empty(),
        Some(PickleValue::List(l)) => !l.is_empty(),
        Some(PickleValue::Dict(d)) => !d.is_empty(),
    }
}

/// Python's `str()` of a value.
pub fn str_of(value: &PickleValue) -> String {
    match value {
        PickleValue::None => "None".into(),
        PickleValue::Bool(true) => "True".into(),
        PickleValue::Bool(false) => "False".into(),
        PickleValue::Int(n) => n.to_string(),
        PickleValue::Float(f) => python_float(*f),
        PickleValue::String(s) => s.clone(),
        PickleValue::Bytes(b) => bytes_repr(b),
        PickleValue::List(items) => {
            let inner: Vec<String> = items.iter().map(repr_of).collect();
            format!("[{}]", inner.join(", "))
        }
        PickleValue::Dict(pairs) => {
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", repr_of(k), repr_of(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

fn repr_of(value: &PickleValue) -> String {
    match value {
        PickleValue::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
        other => str_of(other),
    }
}

fn bytes_repr(bytes: &[u8]) -> String {
    let mut out = String::from("b'");
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push('\'');
    out
}

/// Python's `len()` of a string: code points, not bytes.
pub fn len(s: &str) -> usize {
    s.chars().count()
}

/// `s += (width - len(s)) * " "`.
pub fn pad(s: &mut String, width: usize) {
    for _ in len(s)..width {
        s.push(' ');
    }
}

/// Python's `round(x, digits)` of a float.
pub fn round_float(x: f64, digits: usize) -> f64 {
    if !x.is_finite() {
        return x;
    }
    format!("{x:.digits$}").parse().unwrap_or(x)
}

/// Python's `round(x, digits)`: an int stays an int.
pub fn round(x: Num, digits: usize) -> Num {
    match x {
        Num::Int(n) => Num::Int(n),
        Num::Float(f) => Num::Float(round_float(f, digits)),
    }
}

/// Python's float `a // b`.
fn floordiv(a: f64, b: f64) -> f64 {
    let rem = a % b;
    let mut div = (a - rem) / b;
    if rem != 0.0 && ((b < 0.0) != (rem < 0.0)) {
        div -= 1.0;
    }
    if div == 0.0 {
        return 0.0f64.copysign(a / b);
    }
    let floor = div.floor();
    if div - floor > 0.5 {
        floor + 1.0
    } else {
        floor
    }
}

/// Python's float `a % b`.
fn pymod(a: f64, b: f64) -> f64 {
    let rem = a % b;
    if rem != 0.0 && ((b < 0.0) != (rem < 0.0)) {
        rem + b
    } else {
        rem
    }
}

/// `RNS.prettysize(num, suffix)`.
pub fn prettysize(num: f64, suffix: &str) -> String {
    let mut num = num;
    if suffix == "b" {
        num *= 8.0;
    }
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"] {
        if num.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{num:.0} {unit}{suffix}")
            } else {
                format!("{num:.2} {unit}{suffix}")
            };
        }
        num /= 1000.0;
    }
    format!("{num:.2}Y{suffix}")
}

/// `RNS.prettyspeed(num)`.
pub fn prettyspeed(num: f64) -> String {
    prettysize(num / 8.0, "b") + "ps"
}

/// `RNS.prettyfrequency(hz, d=d, lpf=lpf)` with the default `Hz` suffix.
pub fn prettyfrequency(hz: Num, d: usize, lpf: bool) -> String {
    if hz.is_zero() {
        return "0 Hz".into();
    }
    let mut num = if lpf { hz } else { Num::Float(hz.f() * 1e6) };
    let units: &[&str] = if lpf {
        &["", "K", "M", "G", "T", "P", "E", "Z"]
    } else {
        &["µ", "m", "", "K", "M", "G", "T", "P", "E", "Z"]
    };
    for unit in units {
        if num.f().abs() < 1000.0 {
            return if d == 2 {
                format!("{:.2} {unit}Hz", num.f())
            } else {
                format!("{} {unit}Hz", round(num, d).str())
            };
        }
        num = Num::Float(num.f() / 1000.0);
    }
    format!("{:.2}YHz", num.f())
}

/// `RNS.prettytime(time)` (`compact=False`) or `RNS.prettytime(time,
/// compact=True)`.
pub fn prettytime(time: Num, compact: bool) -> String {
    let neg = time.f() < 0.0;
    let (days, hours, minutes, seconds) = match time {
        Num::Int(t) => {
            let t = t.unsigned_abs();
            let days = t / 86400;
            let t = t % 86400;
            (
                days as f64,
                (t / 3600) as f64,
                (t % 3600 / 60) as f64,
                Num::Int((t % 60) as i64),
            )
        }
        Num::Float(t) => {
            let t = t.abs();
            let days = floordiv(t, 86400.0).trunc();
            let t = pymod(t, 86400.0);
            let hours = floordiv(t, 3600.0).trunc();
            let t = pymod(t, 3600.0);
            let minutes = floordiv(t, 60.0).trunc();
            let t = pymod(t, 60.0);
            let seconds = if compact {
                Num::Int(t.trunc() as i64)
            } else {
                Num::Float(round_float(t, 2))
            };
            (days, hours, minutes, seconds)
        }
    };

    let mut components = Vec::new();
    for (value, unit) in [(days, "d"), (hours, "h"), (minutes, "m")] {
        if value > 0.0 && (!compact || components.len() < 2) {
            components.push(format!("{}{unit}", value as i64));
        }
    }
    if seconds.f() > 0.0 && (!compact || components.len() < 2) {
        components.push(format!("{}s", seconds.str()));
    }
    let text = join_components(&components, ", ", " and ");
    if text.is_empty() {
        "0s".into()
    } else if neg {
        format!("-{text}")
    } else {
        text
    }
}

/// `RNS.prettyshorttime(time, tight=True)`.
pub fn prettyshorttime_tight(time: f64) -> String {
    let mut time = time * 1e6;
    let neg = time < 0.0;
    if neg {
        time = time.abs();
    }
    let seconds = floordiv(time, 1e6).trunc() as i64;
    time = pymod(time, 1e6);
    let milliseconds = floordiv(time, 1e3).trunc() as i64;
    time = pymod(time, 1e3);
    let microseconds = round_float(time, 2);

    let mut components = Vec::new();
    if seconds > 0 {
        components.push(format!("{seconds}s"));
    }
    if milliseconds > 0 {
        components.push(format!("{milliseconds}ms"));
    }
    if microseconds > 0.0 {
        components.push(format!("{}µs", python_float(microseconds)));
    }
    let text = join_components(&components, " ", " ");
    if text.is_empty() {
        "0us".into()
    } else if neg {
        format!("-{text}")
    } else {
        text
    }
}

fn join_components(components: &[String], sep: &str, last_sep: &str) -> String {
    let mut text = String::new();
    for (i, component) in components.iter().enumerate() {
        if i > 0 {
            text.push_str(if i + 1 < components.len() {
                sep
            } else {
                last_sep
            });
        }
        text.push_str(component);
    }
    text
}

/// `RNS.prettyhexrep(data)`: `<hex>`.
pub fn prettyhexrep(data: &[u8]) -> String {
    format!("<{}>", hexrep(data))
}

/// `RNS.hexrep(data, delimit=False)`.
pub fn hexrep(data: &[u8]) -> String {
    rns_core::encoding::hex(data)
}

// Upstream f7b54ccc adds `RNS.prettynamehash(name_hash)`, which is
// `f"<{RNS.Transport.destination_type_name(name_hash)}>"`: a type's name,
// flagged name or bare hex from the calling process's own destination type
// maps, in angle brackets. Nothing upstream calls it up to `cff4d03f`, so no
// utility prints it and it has no counterpart here. The lookup it wraps is
// `rns_net::destination_types::DestinationTypeNames::type_name`; a utility
// that comes to print it would format that name as `prettyhexrep` does.

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values are Python 3 / RNS 1.6.0 output for the same calls.

    #[test]
    fn prettysize_and_prettyspeed() {
        assert_eq!(prettysize(0.0, "B"), "0 B");
        assert_eq!(prettysize(999.0, "B"), "999 B");
        assert_eq!(prettysize(1000.0, "B"), "1.00 KB");
        assert_eq!(prettysize(1234567.0, "B"), "1.23 MB");
        assert_eq!(prettysize(12.0, "pps"), "12 pps");
        assert_eq!(prettysize(2.5, "B"), "2 B");
        assert_eq!(prettysize(1e30, "B"), "1000000.00YB");
        assert_eq!(prettyspeed(0.0), "0 bps");
        assert_eq!(prettyspeed(10_000_000.0), "10.00 Mbps");
        assert_eq!(prettyspeed(1234.0), "1.23 Kbps");
    }

    #[test]
    fn prettyfrequency_keeps_python_number_types() {
        assert_eq!(prettyfrequency(Num::Int(0), 1, true), "0 Hz");
        assert_eq!(prettyfrequency(Num::Float(0.0), 2, false), "0 Hz");
        assert_eq!(prettyfrequency(Num::Int(5), 1, true), "5 Hz");
        assert_eq!(prettyfrequency(Num::Float(5.0), 1, true), "5.0 Hz");
        assert_eq!(prettyfrequency(Num::Float(0.123456), 1, true), "0.1 Hz");
        assert_eq!(prettyfrequency(Num::Int(1500), 1, true), "1.5 KHz");
        assert_eq!(prettyfrequency(Num::Float(0.0123), 2, false), "12.30 mHz");
        assert_eq!(prettyfrequency(Num::Float(2.5e-7), 2, false), "0.25 µHz");
        assert_eq!(prettyfrequency(Num::Int(3), 2, false), "3.00 Hz");
    }

    #[test]
    fn prettytime_keeps_python_number_types() {
        assert_eq!(prettytime(Num::Int(5), false), "5s");
        assert_eq!(prettytime(Num::Float(5.0), false), "5.0s");
        assert_eq!(prettytime(Num::Int(3600), false), "1h");
        assert_eq!(prettytime(Num::Int(3725), false), "1h, 2m and 5s");
        assert_eq!(
            prettytime(Num::Float(90061.25), false),
            "1d, 1h, 1m and 1.25s"
        );
        assert_eq!(prettytime(Num::Float(90061.25), true), "1d and 1h");
        assert_eq!(prettytime(Num::Float(0.004), false), "0s");
        assert_eq!(prettytime(Num::Float(59.996), false), "60.0s");
        assert_eq!(prettytime(Num::Float(-125.0), false), "-2m and 5.0s");
        assert_eq!(prettytime(Num::Int(0), true), "0s");
    }

    #[test]
    fn prettyshorttime_tight_matches() {
        assert_eq!(prettyshorttime_tight(0.0), "0us");
        assert_eq!(prettyshorttime_tight(0.000012), "12.0µs");
        assert_eq!(prettyshorttime_tight(0.0015), "1ms 500.0µs");
        assert_eq!(prettyshorttime_tight(1.25), "1s 250ms");
        assert_eq!(prettyshorttime_tight(0.0000125), "12.5µs");
    }

    #[test]
    fn values_print_as_python_str() {
        assert_eq!(str_of(&PickleValue::Int(-99)), "-99");
        assert_eq!(str_of(&PickleValue::Float(12.5)), "12.5");
        assert_eq!(str_of(&PickleValue::Float(3.0)), "3.0");
        assert_eq!(str_of(&PickleValue::None), "None");
        assert_eq!(str_of(&PickleValue::Bool(true)), "True");
        assert_eq!(prettyhexrep(&[0xab, 0x01]), "<ab01>");
        assert_eq!(len("↓1.23 KB"), 8);
    }
}
