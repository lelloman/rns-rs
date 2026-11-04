//! Minimal msgpack encoder/decoder for Resource advertisements and HMU packets.
//!
//! Supports the subset needed by Reticulum's Resource protocol:
//! - Nil, Bool, positive/negative fixint, uint8-64, int8-32
//! - fixstr, str8
//! - bin8, bin16, bin32
//! - fixarray, array16
//! - fixmap, map16

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// A msgpack value.
#[derive(Debug, Clone)]
pub enum Value {
    Nil,
    Bool(bool),
    UInt(u64),
    Int(i64),
    Float(f64),
    Bin(Vec<u8>),
    Str(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Nil, Value::Nil) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::UInt(a), Value::UInt(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a.to_bits() == b.to_bits(),
            (Value::Bin(a), Value::Bin(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Map(a), Value::Map(b)) => a == b,
            _ => false,
        }
    }
}

impl Value {
    /// Get as u64 if this is a UInt.
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::UInt(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as i64 if this is an Int.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as integer (works for both UInt and Int).
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::UInt(v) => {
                if *v <= i64::MAX as u64 {
                    Some(*v as i64)
                } else {
                    None
                }
            }
            Value::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as f64 if Float.
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Float(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as f64, accepting Float, UInt, or Int.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            Value::Float(v) => Some(*v),
            Value::UInt(v) => Some(*v as f64),
            Value::Int(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Get as byte slice if Bin.
    pub fn as_bin(&self) -> Option<&[u8]> {
        match self {
            Value::Bin(v) => Some(v),
            _ => None,
        }
    }

    /// Get as string slice if Str.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(v) => Some(v),
            _ => None,
        }
    }

    /// Get as array slice.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(v) => Some(v),
            _ => None,
        }
    }

    /// Get as map slice.
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(v) => Some(v),
            _ => None,
        }
    }

    /// Check if nil.
    pub fn is_nil(&self) -> bool {
        matches!(self, Value::Nil)
    }

    /// Look up a string key in a map.
    pub fn map_get(&self, key: &str) -> Option<&Value> {
        self.as_map().and_then(|entries| {
            entries.iter().find_map(|(k, v)| {
                if let Value::Str(s) = k {
                    if s == key {
                        return Some(v);
                    }
                }
                None
            })
        })
    }
}

/// Maximum nesting depth for msgpack decoding.
const MAX_DEPTH: usize = 32;

/// Msgpack error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnexpectedEof,
    UnsupportedFormat(u8),
    InvalidUtf8,
    TrailingData,
    MaxDepthExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof => write!(f, "Unexpected end of msgpack data"),
            Error::UnsupportedFormat(b) => write!(f, "Unsupported msgpack format: 0x{:02x}", b),
            Error::InvalidUtf8 => write!(f, "Invalid UTF-8 in msgpack string"),
            Error::TrailingData => write!(f, "Trailing data after msgpack value"),
            Error::MaxDepthExceeded => write!(f, "Maximum nesting depth exceeded"),
        }
    }
}

// ============================================================================
// Encoder
// ============================================================================

/// Encode a Value to msgpack bytes.
pub fn pack(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    pack_into(value, &mut buf);
    buf
}

fn pack_into(value: &Value, buf: &mut Vec<u8>) {
    match value {
        Value::Nil => buf.push(0xc0),
        Value::Bool(true) => buf.push(0xc3),
        Value::Bool(false) => buf.push(0xc2),
        Value::UInt(v) => pack_uint(*v, buf),
        Value::Int(v) => pack_int(*v, buf),
        Value::Float(v) => {
            buf.push(0xcb);
            buf.extend_from_slice(&v.to_bits().to_be_bytes());
        }
        Value::Bin(data) => pack_bin(data, buf),
        Value::Str(s) => pack_str(s, buf),
        Value::Array(items) => pack_array(items, buf),
        Value::Map(entries) => pack_map(entries, buf),
    }
}

pub(crate) fn pack_uint(v: u64, buf: &mut Vec<u8>) {
    if v <= 127 {
        buf.push(v as u8);
    } else if v <= 0xFF {
        buf.push(0xcc);
        buf.push(v as u8);
    } else if v <= 0xFFFF {
        buf.push(0xcd);
        buf.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xFFFF_FFFF {
        buf.push(0xce);
        buf.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        buf.push(0xcf);
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

fn pack_int(v: i64, buf: &mut Vec<u8>) {
    if v >= 0 {
        pack_uint(v as u64, buf);
    } else if v >= -32 {
        buf.push(v as u8); // negative fixint: 0xe0..0xff
    } else if v >= -128 {
        buf.push(0xd0);
        buf.push(v as i8 as u8);
    } else if v >= -32768 {
        buf.push(0xd1);
        buf.extend_from_slice(&(v as i16).to_be_bytes());
    } else if v >= -2_147_483_648 {
        buf.push(0xd2);
        buf.extend_from_slice(&(v as i32).to_be_bytes());
    } else {
        buf.push(0xd3);
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

pub(crate) fn pack_bin(data: &[u8], buf: &mut Vec<u8>) {
    let len = data.len();
    if len <= 0xFF {
        buf.push(0xc4);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xc5);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xc6);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buf.extend_from_slice(data);
}

pub(crate) fn pack_str(s: &str, buf: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len <= 31 {
        buf.push(0xa0 | len as u8);
    } else if len <= 0xFF {
        buf.push(0xd9);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xda);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdb);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buf.extend_from_slice(bytes);
}

/// Append the header of an array of `len` items, as [`pack`] writes it.
pub fn pack_array_header(len: usize, buf: &mut Vec<u8>) {
    if len <= 15 {
        buf.push(0x90 | len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xdc);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdd);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn pack_map_header(len: usize, buf: &mut Vec<u8>) {
    if len <= 15 {
        buf.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xde);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdf);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

/// Append binary data, as [`pack`] writes [`Value::Bin`].
pub fn pack_bin_into(data: &[u8], buf: &mut Vec<u8>) {
    pack_bin(data, buf);
}

/// Append a value decoded by [`unpack_ref`] exactly as [`pack`] writes the
/// [`Value`] that [`unpack`] decodes from the same bytes.
pub fn pack_ref_into(value: ValueRef<'_>, buf: &mut Vec<u8>) {
    match value {
        ValueRef::Nil => buf.push(0xc0),
        ValueRef::Bool(true) => buf.push(0xc3),
        ValueRef::Bool(false) => buf.push(0xc2),
        ValueRef::UInt(v) => pack_uint(v, buf),
        ValueRef::Int(v) => pack_int(v, buf),
        ValueRef::Float(v) => {
            buf.push(0xcb);
            buf.extend_from_slice(&v.to_bits().to_be_bytes());
        }
        ValueRef::Bin(data) => pack_bin(data, buf),
        ValueRef::Str(s) => pack_str(s, buf),
        ValueRef::Array { len, .. } => {
            pack_array_header(len, buf);
            for item in value.array_items().into_iter().flatten() {
                pack_ref_into(item, buf);
            }
        }
        ValueRef::Map { len, .. } => {
            pack_map_header(len, buf);
            for (k, v) in value.map_entries().into_iter().flatten() {
                pack_ref_into(k, buf);
                pack_ref_into(v, buf);
            }
        }
    }
}

fn pack_array(items: &[Value], buf: &mut Vec<u8>) {
    pack_array_header(items.len(), buf);
    for item in items {
        pack_into(item, buf);
    }
}

fn pack_map(entries: &[(Value, Value)], buf: &mut Vec<u8>) {
    pack_map_header(entries.len(), buf);
    for (k, v) in entries {
        pack_into(k, buf);
        pack_into(v, buf);
    }
}

/// Convenience: pack a map from string keys.
pub fn pack_str_map(entries: &[(&str, Value)]) -> Vec<u8> {
    let map: Vec<(Value, Value)> = entries
        .iter()
        .map(|(k, v)| (Value::Str(String::from(*k)), v.clone()))
        .collect();
    pack(&Value::Map(map))
}

// ============================================================================
// Decoder
// ============================================================================

/// Decode a single msgpack value from the start of `data`.
/// Returns (value, bytes_consumed).
pub fn unpack(data: &[u8]) -> Result<(Value, usize), Error> {
    unpack_depth(data, 0)
}

fn unpack_depth(data: &[u8], depth: usize) -> Result<(Value, usize), Error> {
    let (value, consumed) = unpack_ref(data, depth)?;
    Ok((value.to_owned_value()?, consumed))
}

/// Decode a complete msgpack value, ensuring no trailing data.
pub fn unpack_exact(data: &[u8]) -> Result<Value, Error> {
    let (value, consumed) = unpack(data)?;
    if consumed != data.len() {
        return Err(Error::TrailingData);
    }
    Ok(value)
}

/// Decode a complete msgpack value without copying it, ensuring no trailing
/// data. Accepts and rejects exactly the inputs [`unpack_exact`] does.
pub fn unpack_exact_ref(data: &[u8]) -> Result<ValueRef<'_>, Error> {
    let (value, consumed) = unpack_ref(data, 0)?;
    if consumed != data.len() {
        return Err(Error::TrailingData);
    }
    Ok(value)
}

fn ensure_len(data: &[u8], needed: usize) -> Result<(), Error> {
    if data.len() < needed {
        Err(Error::UnexpectedEof)
    } else {
        Ok(())
    }
}

/// A decoded msgpack value borrowing from its input. Arrays and maps are
/// validated when decoded (formats, nesting depth, UTF-8) and keep their
/// encoded items, which [`ValueRef::array_items`] and [`ValueRef::map_entries`]
/// decode on demand.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ValueRef<'a> {
    Nil,
    Bool(bool),
    UInt(u64),
    Int(i64),
    Float(f64),
    Bin(&'a [u8]),
    Str(&'a str),
    Array {
        len: usize,
        items: &'a [u8],
        depth: usize,
    },
    Map {
        len: usize,
        entries: &'a [u8],
        depth: usize,
    },
}

impl<'a> ValueRef<'a> {
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            ValueRef::UInt(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bin(&self) -> Option<&'a [u8]> {
        match self {
            ValueRef::Bin(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            ValueRef::Str(v) => Some(v),
            _ => None,
        }
    }

    pub fn is_nil(&self) -> bool {
        matches!(self, ValueRef::Nil)
    }

    /// The items of an array, or `None` for any other value.
    pub fn array_items(&self) -> Option<Items<'a>> {
        match *self {
            ValueRef::Array { len, items, depth } => Some(Items {
                rest: items,
                remaining: len,
                depth: depth + 1,
            }),
            _ => None,
        }
    }

    /// The (key, value) entries of a map, or `None` for any other value.
    pub fn map_entries(&self) -> Option<Entries<'a>> {
        match *self {
            ValueRef::Map {
                len,
                entries,
                depth,
            } => Some(Entries(Items {
                rest: entries,
                remaining: len * 2,
                depth: depth + 1,
            })),
            _ => None,
        }
    }

    /// Look up a string key in a map: the first entry with that key, as
    /// [`Value::map_get`] does.
    pub fn map_get(&self, key: &str) -> Option<ValueRef<'a>> {
        self.map_entries()?
            .find_map(|(k, v)| (k.as_str() == Some(key)).then_some(v))
    }

    fn to_owned_value(self) -> Result<Value, Error> {
        Ok(match self {
            ValueRef::Nil => Value::Nil,
            ValueRef::Bool(b) => Value::Bool(b),
            ValueRef::UInt(v) => Value::UInt(v),
            ValueRef::Int(v) => Value::Int(v),
            ValueRef::Float(v) => Value::Float(v),
            ValueRef::Bin(b) => Value::Bin(b.to_vec()),
            ValueRef::Str(s) => Value::Str(String::from(s)),
            ValueRef::Array { len, .. } => {
                let mut items = Vec::with_capacity(len);
                for item in self.array_items().into_iter().flatten() {
                    items.push(item.to_owned_value()?);
                }
                Value::Array(items)
            }
            ValueRef::Map { len, .. } => {
                let mut entries = Vec::with_capacity(len);
                for (k, v) in self.map_entries().into_iter().flatten() {
                    entries.push((k.to_owned_value()?, v.to_owned_value()?));
                }
                Value::Map(entries)
            }
        })
    }
}

/// Items of a validated array (or keys and values of a map, in order).
#[derive(Debug, Clone)]
pub struct Items<'a> {
    rest: &'a [u8],
    remaining: usize,
    depth: usize,
}

impl<'a> Iterator for Items<'a> {
    type Item = ValueRef<'a>;

    fn next(&mut self) -> Option<ValueRef<'a>> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        // Validated when the container was decoded, so this cannot fail.
        let (value, consumed) = unpack_ref(self.rest, self.depth).ok()?;
        self.rest = &self.rest[consumed..];
        Some(value)
    }
}

/// Entries of a validated map.
#[derive(Debug, Clone)]
pub struct Entries<'a>(Items<'a>);

impl<'a> Iterator for Entries<'a> {
    type Item = (ValueRef<'a>, ValueRef<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        Some((self.0.next()?, self.0.next()?))
    }
}

/// Decode one value from the start of `data` without copying, returning it
/// and the bytes consumed. Nested arrays and maps are validated in full.
pub fn unpack_ref(data: &[u8], depth: usize) -> Result<(ValueRef<'_>, usize), Error> {
    if data.is_empty() {
        return Err(Error::UnexpectedEof);
    }
    if depth > MAX_DEPTH {
        return Err(Error::MaxDepthExceeded);
    }
    let b = data[0];
    match b {
        // positive fixint: 0x00..0x7f
        0x00..=0x7f => Ok((ValueRef::UInt(b as u64), 1)),

        // fixmap: 0x80..0x8f
        0x80..=0x8f => unpack_map_ref(data, 1, (b & 0x0f) as usize, depth),

        // fixarray: 0x90..0x9f
        0x90..=0x9f => unpack_array_ref(data, 1, (b & 0x0f) as usize, depth),

        // fixstr: 0xa0..0xbf
        0xa0..=0xbf => unpack_str_ref(data, 1, (b & 0x1f) as usize),

        // nil
        0xc0 => Ok((ValueRef::Nil, 1)),

        // (unused)
        0xc1 => Err(Error::UnsupportedFormat(b)),

        // bool
        0xc2 => Ok((ValueRef::Bool(false), 1)),
        0xc3 => Ok((ValueRef::Bool(true), 1)),

        // float32
        0xca => {
            ensure_len(data, 5)?;
            let bits = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            Ok((ValueRef::Float(f32::from_bits(bits) as f64), 5))
        }

        // float64
        0xcb => {
            ensure_len(data, 9)?;
            let bits = u64::from_be_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            Ok((ValueRef::Float(f64::from_bits(bits)), 9))
        }

        // bin8, bin16, bin32
        0xc4 => {
            ensure_len(data, 2)?;
            unpack_bin_ref(data, 2, data[1] as usize)
        }
        0xc5 => {
            ensure_len(data, 3)?;
            unpack_bin_ref(data, 3, u16::from_be_bytes([data[1], data[2]]) as usize)
        }
        0xc6 => {
            ensure_len(data, 5)?;
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            unpack_bin_ref(data, 5, len)
        }

        // uint8
        0xcc => {
            ensure_len(data, 2)?;
            Ok((ValueRef::UInt(data[1] as u64), 2))
        }

        // uint16
        0xcd => {
            ensure_len(data, 3)?;
            let v = u16::from_be_bytes([data[1], data[2]]);
            Ok((ValueRef::UInt(v as u64), 3))
        }

        // uint32
        0xce => {
            ensure_len(data, 5)?;
            let v = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            Ok((ValueRef::UInt(v as u64), 5))
        }

        // uint64
        0xcf => {
            ensure_len(data, 9)?;
            let v = u64::from_be_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            Ok((ValueRef::UInt(v), 9))
        }

        // int8
        0xd0 => {
            ensure_len(data, 2)?;
            Ok((ValueRef::Int(data[1] as i8 as i64), 2))
        }

        // int16
        0xd1 => {
            ensure_len(data, 3)?;
            let v = i16::from_be_bytes([data[1], data[2]]);
            Ok((ValueRef::Int(v as i64), 3))
        }

        // int32
        0xd2 => {
            ensure_len(data, 5)?;
            let v = i32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            Ok((ValueRef::Int(v as i64), 5))
        }

        // int64
        0xd3 => {
            ensure_len(data, 9)?;
            let v = i64::from_be_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            Ok((ValueRef::Int(v), 9))
        }

        // str8, str16, str32
        0xd9 => {
            ensure_len(data, 2)?;
            unpack_str_ref(data, 2, data[1] as usize)
        }
        0xda => {
            ensure_len(data, 3)?;
            unpack_str_ref(data, 3, u16::from_be_bytes([data[1], data[2]]) as usize)
        }
        0xdb => {
            ensure_len(data, 5)?;
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            unpack_str_ref(data, 5, len)
        }

        // array16, array32
        0xdc => {
            ensure_len(data, 3)?;
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            unpack_array_ref(data, 3, len, depth)
        }
        0xdd => {
            ensure_len(data, 5)?;
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            unpack_array_ref(data, 5, len, depth)
        }

        // map16, map32
        0xde => {
            ensure_len(data, 3)?;
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            unpack_map_ref(data, 3, len, depth)
        }
        0xdf => {
            ensure_len(data, 5)?;
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            unpack_map_ref(data, 5, len, depth)
        }

        // negative fixint: 0xe0..0xff
        0xe0..=0xff => Ok((ValueRef::Int(b as i8 as i64), 1)),

        _ => Err(Error::UnsupportedFormat(b)),
    }
}

fn unpack_bin_ref(data: &[u8], offset: usize, len: usize) -> Result<(ValueRef<'_>, usize), Error> {
    let end = offset.checked_add(len).ok_or(Error::UnexpectedEof)?;
    ensure_len(data, end)?;
    Ok((ValueRef::Bin(&data[offset..end]), end))
}

fn unpack_str_ref(data: &[u8], offset: usize, len: usize) -> Result<(ValueRef<'_>, usize), Error> {
    let end = offset.checked_add(len).ok_or(Error::UnexpectedEof)?;
    ensure_len(data, end)?;
    let s = core::str::from_utf8(&data[offset..end]).map_err(|_| Error::InvalidUtf8)?;
    Ok((ValueRef::Str(s), end))
}

/// Validate `count` values after `start` at `depth + 1`; returns the offset
/// after them.
fn skip_items(data: &[u8], start: usize, count: usize, depth: usize) -> Result<usize, Error> {
    let mut offset = start;
    for _ in 0..count {
        let (_, consumed) = unpack_ref(&data[offset..], depth + 1)?;
        offset += consumed;
    }
    Ok(offset)
}

fn unpack_array_ref(
    data: &[u8],
    start: usize,
    count: usize,
    depth: usize,
) -> Result<(ValueRef<'_>, usize), Error> {
    if count > data.len().saturating_sub(start) {
        return Err(Error::UnexpectedEof);
    }
    let end = skip_items(data, start, count, depth)?;
    Ok((
        ValueRef::Array {
            len: count,
            items: &data[start..end],
            depth,
        },
        end,
    ))
}

fn unpack_map_ref(
    data: &[u8],
    start: usize,
    count: usize,
    depth: usize,
) -> Result<(ValueRef<'_>, usize), Error> {
    let items = count
        .checked_mul(2)
        .filter(|items| *items <= data.len().saturating_sub(start))
        .ok_or(Error::UnexpectedEof)?;
    let end = skip_items(data, start, items, depth)?;
    Ok((
        ValueRef::Map {
            len: count,
            entries: &data[start..end],
            depth,
        },
        end,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoded values that exercise every format, including encodings
    /// [`pack`] never writes (float32, non-minimal integers and lengths).
    fn encoded_corpus() -> Vec<Vec<u8>> {
        let mut corpus: Vec<Vec<u8>> = vec![
            vec![0xc0],
            vec![0xc2],
            vec![0xc3],
            vec![0x7f],
            vec![0xe0],
            vec![0xcc, 0x05],
            vec![0xcd, 0x00, 0x05],
            vec![0xcf, 0, 0, 0, 0, 0, 0, 0, 1],
            vec![0xd0, 0x05],
            vec![0xd3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
            vec![0xca, 0x3f, 0x80, 0x00, 0x00],
            vec![0xcb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18],
            vec![0xc4, 0x02, 0xaa, 0xbb],
            vec![0xc5, 0x00, 0x01, 0xaa],
            vec![0xa3, b'a', b'b', b'c'],
            vec![0xd9, 0x01, b'x'],
            vec![0x93, 0x01, 0xc4, 0x01, 0xff, 0x92, 0xc0, 0xa1, b'k'],
            vec![0xdc, 0x00, 0x02, 0xc3, 0xc2],
            vec![
                0x82, 0xa1, b'a', 0x01, 0xa1, b'a', 0x92, 0x02, 0xca, 0, 0, 0, 0,
            ],
            vec![0xde, 0x00, 0x01, 0x01, 0x80],
        ];
        corpus.push(pack(&Value::Array(vec![
            Value::Float(1.5),
            Value::Bin(vec![7; 300]),
            Value::Str("s".repeat(40)),
            Value::Array((0..20).map(Value::UInt).collect()),
            Value::Map((0..20).map(|i| (Value::Int(-i), Value::Nil)).collect()),
        ])));
        corpus
    }

    #[test]
    fn packing_a_borrowed_value_matches_packing_its_owned_form() {
        let mut inputs = encoded_corpus();
        // Plus every prefix and one-byte corruption of the corpus, so the
        // accepted set is wide and the rejected one is checked to agree.
        let mut extra = Vec::new();
        for input in &inputs {
            for end in 0..input.len() {
                extra.push(input[..end].to_vec());
            }
            for i in 0..input.len() {
                for byte in [0x00, 0x7f, 0x90, 0xc4, 0xca, 0xdc, 0xff] {
                    let mut corrupt = input.clone();
                    corrupt[i] = byte;
                    extra.push(corrupt);
                }
            }
        }
        inputs.extend(extra);
        let mut accepted = 0;
        for input in &inputs {
            let owned = unpack_exact(input);
            let borrowed = unpack_exact_ref(input);
            assert_eq!(owned.is_ok(), borrowed.is_ok(), "{input:02x?}");
            if let (Ok(owned), Ok(borrowed)) = (owned, borrowed) {
                let mut packed = Vec::new();
                pack_ref_into(borrowed, &mut packed);
                assert_eq!(packed, pack(&owned), "{input:02x?}");
                accepted += 1;
            }
        }
        assert!(accepted > 100);
    }

    fn roundtrip(v: &Value) -> Value {
        let packed = pack(v);
        let (unpacked, consumed) = unpack(&packed).unwrap();
        assert_eq!(consumed, packed.len(), "all bytes consumed");
        unpacked
    }

    #[test]
    fn test_nil() {
        let packed = pack(&Value::Nil);
        assert_eq!(packed, vec![0xc0]);
        assert_eq!(roundtrip(&Value::Nil), Value::Nil);
    }

    #[test]
    fn test_bool() {
        assert_eq!(pack(&Value::Bool(true)), vec![0xc3]);
        assert_eq!(pack(&Value::Bool(false)), vec![0xc2]);
        assert_eq!(roundtrip(&Value::Bool(true)), Value::Bool(true));
        assert_eq!(roundtrip(&Value::Bool(false)), Value::Bool(false));
    }

    #[test]
    fn test_positive_fixint() {
        assert_eq!(pack(&Value::UInt(0)), vec![0x00]);
        assert_eq!(pack(&Value::UInt(127)), vec![0x7f]);
        assert_eq!(roundtrip(&Value::UInt(0)), Value::UInt(0));
        assert_eq!(roundtrip(&Value::UInt(42)), Value::UInt(42));
        assert_eq!(roundtrip(&Value::UInt(127)), Value::UInt(127));
    }

    #[test]
    fn test_uint8() {
        assert_eq!(pack(&Value::UInt(128)), vec![0xcc, 0x80]);
        assert_eq!(pack(&Value::UInt(255)), vec![0xcc, 0xff]);
        assert_eq!(roundtrip(&Value::UInt(128)), Value::UInt(128));
        assert_eq!(roundtrip(&Value::UInt(255)), Value::UInt(255));
    }

    #[test]
    fn test_uint16() {
        assert_eq!(pack(&Value::UInt(256)), vec![0xcd, 0x01, 0x00]);
        assert_eq!(roundtrip(&Value::UInt(256)), Value::UInt(256));
        assert_eq!(roundtrip(&Value::UInt(0xFFFF)), Value::UInt(0xFFFF));
    }

    #[test]
    fn test_uint32() {
        assert_eq!(
            pack(&Value::UInt(0x10000)),
            vec![0xce, 0x00, 0x01, 0x00, 0x00]
        );
        assert_eq!(roundtrip(&Value::UInt(0x10000)), Value::UInt(0x10000));
        assert_eq!(roundtrip(&Value::UInt(0xFFFFFFFF)), Value::UInt(0xFFFFFFFF));
    }

    #[test]
    fn test_uint64() {
        let big = 0x1_0000_0000u64;
        assert_eq!(roundtrip(&Value::UInt(big)), Value::UInt(big));
        let huge = u64::MAX;
        assert_eq!(roundtrip(&Value::UInt(huge)), Value::UInt(huge));
    }

    #[test]
    fn test_negative_fixint() {
        // -1 = 0xff, -32 = 0xe0
        assert_eq!(pack(&Value::Int(-1)), vec![0xff]);
        assert_eq!(pack(&Value::Int(-32)), vec![0xe0]);
        assert_eq!(roundtrip(&Value::Int(-1)), Value::Int(-1));
        assert_eq!(roundtrip(&Value::Int(-32)), Value::Int(-32));
    }

    #[test]
    fn test_int8() {
        assert_eq!(pack(&Value::Int(-33)), vec![0xd0, 0xdf]);
        assert_eq!(roundtrip(&Value::Int(-33)), Value::Int(-33));
        assert_eq!(roundtrip(&Value::Int(-128)), Value::Int(-128));
    }

    #[test]
    fn test_int16() {
        assert_eq!(roundtrip(&Value::Int(-129)), Value::Int(-129));
        assert_eq!(roundtrip(&Value::Int(-32768)), Value::Int(-32768));
    }

    #[test]
    fn test_int32() {
        assert_eq!(roundtrip(&Value::Int(-32769)), Value::Int(-32769));
    }

    #[test]
    fn test_positive_int_packed_as_uint() {
        // Positive values always encode as uint format
        let packed = pack(&Value::Int(42));
        assert_eq!(packed, vec![42]); // positive fixint
    }

    #[test]
    fn test_fixstr() {
        let v = Value::Str(String::from("t"));
        let packed = pack(&v);
        assert_eq!(packed[0], 0xa1); // fixstr len=1
        assert_eq!(roundtrip(&v), v);

        let v = Value::Str(String::from("hello"));
        assert_eq!(roundtrip(&v), v);

        // Empty string
        let v = Value::Str(String::new());
        assert_eq!(pack(&v), vec![0xa0]);
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_str8() {
        let s: String = "a".repeat(32);
        let v = Value::Str(s);
        let packed = pack(&v);
        assert_eq!(packed[0], 0xd9);
        assert_eq!(packed[1], 32);
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_bin8() {
        let v = Value::Bin(vec![1, 2, 3]);
        let packed = pack(&v);
        assert_eq!(packed[0], 0xc4);
        assert_eq!(packed[1], 3);
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_bin16() {
        let data = vec![0xAB; 300];
        let v = Value::Bin(data);
        let packed = pack(&v);
        assert_eq!(packed[0], 0xc5);
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_bin32() {
        // bin32 threshold is > 65535 bytes, skip actual large allocation but
        // test the format byte by manually checking a 0-length edge
        let data = vec![0xCD; 70000];
        let v = Value::Bin(data);
        let packed = pack(&v);
        assert_eq!(packed[0], 0xc6);
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_fixarray() {
        let v = Value::Array(vec![Value::UInt(1), Value::UInt(2), Value::UInt(3)]);
        let packed = pack(&v);
        assert_eq!(packed[0], 0x93); // fixarray len=3
        assert_eq!(roundtrip(&v), v);

        // Empty array
        let v = Value::Array(vec![]);
        assert_eq!(pack(&v), vec![0x90]);
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_fixmap() {
        let v = Value::Map(vec![
            (Value::Str(String::from("a")), Value::UInt(1)),
            (Value::Str(String::from("b")), Value::UInt(2)),
        ]);
        let packed = pack(&v);
        assert_eq!(packed[0], 0x82); // fixmap len=2
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_nested_structure() {
        let v = Value::Map(vec![
            (Value::Str(String::from("t")), Value::UInt(1000)),
            (Value::Str(String::from("m")), Value::Bin(vec![0xAA; 10])),
            (Value::Str(String::from("q")), Value::Nil),
        ]);
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_pack_str_map() {
        let packed = pack_str_map(&[("x", Value::UInt(42)), ("y", Value::Bool(true))]);
        let (v, _) = unpack(&packed).unwrap();
        assert_eq!(v.map_get("x").unwrap().as_uint(), Some(42));
        assert_eq!(v.map_get("y").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn test_map_get_missing_key() {
        let v = Value::Map(vec![(Value::Str(String::from("a")), Value::UInt(1))]);
        assert!(v.map_get("b").is_none());
    }

    #[test]
    fn test_hmu_array_format() {
        // HMU format: [segment_int, hashmap_bytes]
        let v = Value::Array(vec![
            Value::UInt(2),
            Value::Bin(vec![0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD]),
        ]);
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_decode_error_eof() {
        assert_eq!(unpack(&[]), Err(Error::UnexpectedEof));
        // bin8 with length but no data
        assert_eq!(unpack(&[0xc4, 0x05]), Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_declared_array_length_cannot_force_large_allocation() {
        let data = [0xdd, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(unpack(&data), Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_declared_map_length_cannot_force_large_allocation() {
        let data = [0xdf, 0x7f, 0xff, 0xff, 0xff];
        assert_eq!(unpack(&data), Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_unpack_exact_trailing() {
        let packed = pack(&Value::UInt(42));
        let mut with_extra = packed.clone();
        with_extra.push(0x00);
        assert!(unpack_exact(&with_extra).is_err());
        assert!(unpack_exact(&packed).is_ok());
    }

    #[test]
    fn test_value_accessors() {
        assert_eq!(Value::UInt(42).as_uint(), Some(42));
        assert_eq!(Value::UInt(42).as_int(), None);
        assert_eq!(Value::UInt(42).as_integer(), Some(42));
        assert_eq!(Value::Int(-5).as_integer(), Some(-5));
        assert_eq!(Value::Bool(true).as_bool(), Some(true));
        assert_eq!(Value::Bin(vec![1]).as_bin(), Some(&[1u8][..]));
        assert_eq!(Value::Str(String::from("x")).as_str(), Some("x"));
        assert!(Value::Nil.is_nil());
    }

    #[test]
    fn test_max_depth_exceeded() {
        // Build deeply nested arrays: [[[[...]]]] beyond MAX_DEPTH
        let mut data = Vec::new();
        data.extend(core::iter::repeat_n(0x91, MAX_DEPTH + 2)); // fixarray of length 1
        data.push(0x01); // innermost value: uint 1
        assert_eq!(unpack(&data), Err(Error::MaxDepthExceeded));
    }

    #[test]
    fn test_depth_within_limit() {
        // Build nested arrays within limit (depth 5)
        let mut data = Vec::new();
        data.extend(core::iter::repeat_n(0x91, 5)); // fixarray of length 1
        data.push(0x01); // innermost value
        let (val, _) = unpack(&data).unwrap();
        // Should be Array([Array([Array([Array([Array([UInt(1)])])])])])
        let mut current = &val;
        for _ in 0..5 {
            current = &current.as_array().unwrap()[0];
        }
        assert_eq!(current.as_uint(), Some(1));
    }

    #[test]
    fn test_int64_roundtrip() {
        let v = Value::Int(i64::MIN);
        assert_eq!(roundtrip(&v), v);
        let v = Value::Int(-2_147_483_649); // beyond i32 range
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_str16_roundtrip() {
        let s: String = "x".repeat(256);
        let v = Value::Str(s);
        let packed = pack(&v);
        assert_eq!(packed[0], 0xda); // str16
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_array16_roundtrip() {
        let items: Vec<Value> = (0..16).map(Value::UInt).collect();
        let v = Value::Array(items);
        let packed = pack(&v);
        assert_eq!(packed[0], 0xdc); // array16
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_map16_roundtrip() {
        let entries: Vec<(Value, Value)> = (0..16)
            .map(|i| (Value::UInt(i), Value::Bool(i % 2 == 0)))
            .collect();
        let v = Value::Map(entries);
        let packed = pack(&v);
        assert_eq!(packed[0], 0xde); // map16
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn test_unsupported_format() {
        // 0xc1 is unused/never valid
        assert_eq!(unpack(&[0xc1]), Err(Error::UnsupportedFormat(0xc1)));
    }
}
