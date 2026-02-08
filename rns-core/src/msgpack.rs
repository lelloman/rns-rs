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
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    UInt(u64),
    Int(i64),
    Bin(Vec<u8>),
    Str(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
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
        Value::Bin(data) => pack_bin(data, buf),
        Value::Str(s) => pack_str(s, buf),
        Value::Array(items) => pack_array(items, buf),
        Value::Map(entries) => pack_map(entries, buf),
    }
}

fn pack_uint(v: u64, buf: &mut Vec<u8>) {
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

fn pack_bin(data: &[u8], buf: &mut Vec<u8>) {
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

fn pack_str(s: &str, buf: &mut Vec<u8>) {
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

fn pack_array(items: &[Value], buf: &mut Vec<u8>) {
    let len = items.len();
    if len <= 15 {
        buf.push(0x90 | len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xdc);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdd);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    for item in items {
        pack_into(item, buf);
    }
}

fn pack_map(entries: &[(Value, Value)], buf: &mut Vec<u8>) {
    let len = entries.len();
    if len <= 15 {
        buf.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xde);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdf);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
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
    if data.is_empty() {
        return Err(Error::UnexpectedEof);
    }
    if depth > MAX_DEPTH {
        return Err(Error::MaxDepthExceeded);
    }
    let b = data[0];
    match b {
        // positive fixint: 0x00..0x7f
        0x00..=0x7f => Ok((Value::UInt(b as u64), 1)),

        // fixmap: 0x80..0x8f
        0x80..=0x8f => {
            let len = (b & 0x0f) as usize;
            unpack_map_entries(data, 1, len, depth)
        }

        // fixarray: 0x90..0x9f
        0x90..=0x9f => {
            let len = (b & 0x0f) as usize;
            unpack_array_entries(data, 1, len, depth)
        }

        // fixstr: 0xa0..0xbf
        0xa0..=0xbf => {
            let len = (b & 0x1f) as usize;
            unpack_str_bytes(data, 1, len)
        }

        // nil
        0xc0 => Ok((Value::Nil, 1)),

        // (unused)
        0xc1 => Err(Error::UnsupportedFormat(b)),

        // bool
        0xc2 => Ok((Value::Bool(false), 1)),
        0xc3 => Ok((Value::Bool(true), 1)),

        // bin8
        0xc4 => {
            ensure_len(data, 2)?;
            let len = data[1] as usize;
            ensure_len(data, 2 + len)?;
            Ok((Value::Bin(data[2..2 + len].to_vec()), 2 + len))
        }

        // bin16
        0xc5 => {
            ensure_len(data, 3)?;
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            ensure_len(data, 3 + len)?;
            Ok((Value::Bin(data[3..3 + len].to_vec()), 3 + len))
        }

        // bin32
        0xc6 => {
            ensure_len(data, 5)?;
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            ensure_len(data, 5 + len)?;
            Ok((Value::Bin(data[5..5 + len].to_vec()), 5 + len))
        }

        // uint8
        0xcc => {
            ensure_len(data, 2)?;
            Ok((Value::UInt(data[1] as u64), 2))
        }

        // uint16
        0xcd => {
            ensure_len(data, 3)?;
            let v = u16::from_be_bytes([data[1], data[2]]);
            Ok((Value::UInt(v as u64), 3))
        }

        // uint32
        0xce => {
            ensure_len(data, 5)?;
            let v = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            Ok((Value::UInt(v as u64), 5))
        }

        // uint64
        0xcf => {
            ensure_len(data, 9)?;
            let v = u64::from_be_bytes([
                data[1], data[2], data[3], data[4],
                data[5], data[6], data[7], data[8],
            ]);
            Ok((Value::UInt(v), 9))
        }

        // int8
        0xd0 => {
            ensure_len(data, 2)?;
            Ok((Value::Int(data[1] as i8 as i64), 2))
        }

        // int16
        0xd1 => {
            ensure_len(data, 3)?;
            let v = i16::from_be_bytes([data[1], data[2]]);
            Ok((Value::Int(v as i64), 3))
        }

        // int32
        0xd2 => {
            ensure_len(data, 5)?;
            let v = i32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            Ok((Value::Int(v as i64), 5))
        }

        // int64
        0xd3 => {
            ensure_len(data, 9)?;
            let v = i64::from_be_bytes([
                data[1], data[2], data[3], data[4],
                data[5], data[6], data[7], data[8],
            ]);
            Ok((Value::Int(v), 9))
        }

        // str8
        0xd9 => {
            ensure_len(data, 2)?;
            let len = data[1] as usize;
            unpack_str_bytes(data, 2, len)
        }

        // str16
        0xda => {
            ensure_len(data, 3)?;
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            unpack_str_bytes(data, 3, len)
        }

        // str32
        0xdb => {
            ensure_len(data, 5)?;
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            unpack_str_bytes(data, 5, len)
        }

        // array16
        0xdc => {
            ensure_len(data, 3)?;
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            unpack_array_entries(data, 3, len, depth)
        }

        // array32
        0xdd => {
            ensure_len(data, 5)?;
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            unpack_array_entries(data, 5, len, depth)
        }

        // map16
        0xde => {
            ensure_len(data, 3)?;
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            unpack_map_entries(data, 3, len, depth)
        }

        // map32
        0xdf => {
            ensure_len(data, 5)?;
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            unpack_map_entries(data, 5, len, depth)
        }

        // negative fixint: 0xe0..0xff
        0xe0..=0xff => Ok((Value::Int(b as i8 as i64), 1)),

        _ => Err(Error::UnsupportedFormat(b)),
    }
}

/// Decode a complete msgpack value, ensuring no trailing data.
pub fn unpack_exact(data: &[u8]) -> Result<Value, Error> {
    let (value, consumed) = unpack(data)?;
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

fn unpack_str_bytes(data: &[u8], offset: usize, len: usize) -> Result<(Value, usize), Error> {
    ensure_len(data, offset + len)?;
    let bytes = &data[offset..offset + len];
    let s = core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
    Ok((Value::Str(String::from(s)), offset + len))
}

fn unpack_array_entries(data: &[u8], start: usize, count: usize, depth: usize) -> Result<(Value, usize), Error> {
    let mut offset = start;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let (v, consumed) = unpack_depth(&data[offset..], depth + 1)?;
        items.push(v);
        offset += consumed;
    }
    Ok((Value::Array(items), offset))
}

fn unpack_map_entries(data: &[u8], start: usize, count: usize, depth: usize) -> Result<(Value, usize), Error> {
    let mut offset = start;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let (k, kc) = unpack_depth(&data[offset..], depth + 1)?;
        offset += kc;
        let (v, vc) = unpack_depth(&data[offset..], depth + 1)?;
        offset += vc;
        entries.push((k, v));
    }
    Ok((Value::Map(entries), offset))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(pack(&Value::UInt(0x10000)), vec![0xce, 0x00, 0x01, 0x00, 0x00]);
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
        let packed = pack_str_map(&[
            ("x", Value::UInt(42)),
            ("y", Value::Bool(true)),
        ]);
        let (v, _) = unpack(&packed).unwrap();
        assert_eq!(v.map_get("x").unwrap().as_uint(), Some(42));
        assert_eq!(v.map_get("y").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn test_map_get_missing_key() {
        let v = Value::Map(vec![
            (Value::Str(String::from("a")), Value::UInt(1)),
        ]);
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
        for _ in 0..MAX_DEPTH + 2 {
            data.push(0x91); // fixarray of length 1
        }
        data.push(0x01); // innermost value: uint 1
        assert_eq!(unpack(&data), Err(Error::MaxDepthExceeded));
    }

    #[test]
    fn test_depth_within_limit() {
        // Build nested arrays within limit (depth 5)
        let mut data = Vec::new();
        for _ in 0..5 {
            data.push(0x91); // fixarray of length 1
        }
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
        let items: Vec<Value> = (0..16).map(|i| Value::UInt(i)).collect();
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
