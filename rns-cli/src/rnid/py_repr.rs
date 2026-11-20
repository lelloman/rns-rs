//! Values printed as Python prints them.

use super::*;

/// Python's `str()` of a msgpack value.
pub(super) fn py_str(value: &Value) -> String {
    match value {
        Value::Str(s) => s.clone(),
        other => py_repr(other),
    }
}

/// Python's `repr()` of a msgpack value.
pub(super) fn py_repr(value: &Value) -> String {
    match value {
        Value::Nil => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::UInt(n) => n.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => crate::format::python_float(*f),
        Value::Str(s) => crate::argparse::repr(s),
        Value::Bin(b) => crate::pyfmt::str_of(&rns_net::pickle::PickleValue::Bytes(b.clone())),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(py_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Map(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The `--meta` view of one metadata entry.
pub(super) fn recurse(entry: &Value, key: &str, level: usize) {
    let indent = "  ".repeat(level);
    if let Value::Map(entries) = entry {
        println!("d{indent}{key}:");
        for (k, v) in entries {
            recurse(v, &py_str(k), level + 1);
        }
        return;
    }
    let etype = match entry {
        Value::Str(_) => 's',
        Value::Bin(_) => 'b',
        Value::Array(_) => 'l',
        Value::UInt(_) | Value::Int(_) => 'i',
        Value::Float(_) => 'f',
        Value::Nil => 'N',
        _ => 'u',
    };
    if key == "note" && *entry == Value::Nil {
        return;
    }
    let text = match entry {
        Value::Bin(bytes) => hexrep(bytes),
        other => py_str(other),
    };
    let leadin = format!("{etype}{indent}{key}=");
    let leadln = leadin.chars().count();
    let chars: Vec<char> = text.chars().collect();
    let mut chunks = chars.chunks(64);
    let first: String = chunks
        .next()
        .map(|c| c.iter().collect())
        .unwrap_or_default();
    println!("{leadin}{first}");
    for chunk in chunks {
        println!("{}{}", " ".repeat(leadln), chunk.iter().collect::<String>());
    }
}

/// Python's message for bytes that are not UTF-8.
pub(super) fn utf8_error(bytes: &[u8], e: std::str::Utf8Error) -> String {
    let at = e.valid_up_to();
    let byte = bytes.get(at).copied().unwrap_or(0);
    let reason = match e.error_len() {
        None => "unexpected end of data",
        Some(_) if (0x80..0xc2).contains(&byte) || byte >= 0xf5 => "invalid start byte",
        Some(_) => "invalid continuation byte",
    };
    format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {at}: {reason}")
}

pub(super) fn decode_utf8(bytes: &[u8]) -> Result<String, String> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|e| utf8_error(bytes, e))
}
