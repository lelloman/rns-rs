//! Minimal pickle codec (protocols 2-5).
//!
//! Supports a subset of pickle opcodes sufficient for RPC serialization
//! compatible with Python's `multiprocessing.connection`.
//!
//! Encoder always produces protocol 2 (maximum compatibility).
//! Decoder accepts protocols 2-5 (Python 3.8+ defaults to protocol 4/5).
//!
//! Security: rejects unknown opcodes (no arbitrary code execution).

use std::collections::HashMap;

// Pickle opcodes (protocol 2)
const PROTO: u8 = 0x80;
const STOP: u8 = b'.';
const NONE: u8 = b'N';
const NEWTRUE: u8 = 0x88;
const NEWFALSE: u8 = 0x89;
const BININT1: u8 = b'K';
const BININT2: u8 = b'M';
const BININT4: u8 = b'J';
const BINFLOAT: u8 = b'G';
const SHORT_BINUNICODE: u8 = 0x8c;
const BINUNICODE: u8 = b'X';
const BINBYTES: u8 = b'B'; // protocol 3+
const SHORT_BINBYTES: u8 = b'C'; // protocol 3+
const EMPTY_LIST: u8 = b']';
const EMPTY_DICT: u8 = b'}';
const APPENDS: u8 = b'e';
const APPEND: u8 = b'a';
const SETITEM: u8 = b's';
const SETITEMS: u8 = b'u';
const MARK: u8 = b'(';
const BINPUT: u8 = b'q';
const LONG_BINPUT: u8 = b'r';
const BINGET: u8 = b'h';
const LONG_BINGET: u8 = b'j';
const GLOBAL: u8 = b'c';
const REDUCE: u8 = b'R';
const TUPLE1: u8 = 0x85;
const TUPLE2: u8 = 0x86;
const TUPLE3: u8 = 0x87;
const EMPTY_TUPLE: u8 = b')';
const LONG1: u8 = 0x8a;
const SHORT_BINSTRING: u8 = b'U'; // protocol 0/1 but appears in some pickles
const BINSTRING: u8 = b'T'; // protocol 0/1
// Protocol 4+ opcodes
const FRAME: u8 = 0x95;
const MEMOIZE: u8 = 0x94;
const SHORT_BINBYTES8: u8 = 0x8e; // protocol 4: 8-byte length bytes
const BINUNICODE8: u8 = 0x8d; // protocol 4: 8-byte length unicode
const BYTEARRAY8: u8 = 0x96; // protocol 5: bytearray

/// A pickle value.
#[derive(Debug, Clone, PartialEq)]
pub enum PickleValue {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<PickleValue>),
    Dict(Vec<(PickleValue, PickleValue)>),
}

impl PickleValue {
    /// Get as string reference if this is a String variant.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PickleValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as i64 if this is an Int variant.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            PickleValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Get as f64 if this is a Float variant.
    pub fn as_float(&self) -> Option<f64> {
        match self {
            PickleValue::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Get as bool if this is a Bool variant.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PickleValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as bytes reference if this is a Bytes variant.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            PickleValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Get as list reference if this is a List variant.
    pub fn as_list(&self) -> Option<&[PickleValue]> {
        match self {
            PickleValue::List(l) => Some(l),
            _ => None,
        }
    }

    /// Look up a key in a Dict by string key.
    pub fn get(&self, key: &str) -> Option<&PickleValue> {
        match self {
            PickleValue::Dict(pairs) => {
                for (k, v) in pairs {
                    if let PickleValue::String(s) = k {
                        if s == key {
                            return Some(v);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }
}

/// Encode a PickleValue as pickle protocol 2 bytes.
pub fn encode(value: &PickleValue) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(PROTO);
    buf.push(2); // protocol 2
    encode_value(&mut buf, value);
    buf.push(STOP);
    buf
}

fn encode_value(buf: &mut Vec<u8>, value: &PickleValue) {
    match value {
        PickleValue::None => buf.push(NONE),
        PickleValue::Bool(true) => buf.push(NEWTRUE),
        PickleValue::Bool(false) => buf.push(NEWFALSE),
        PickleValue::Int(n) => encode_int(buf, *n),
        PickleValue::Float(f) => {
            buf.push(BINFLOAT);
            buf.extend_from_slice(&f.to_be_bytes());
        }
        PickleValue::String(s) => {
            let bytes = s.as_bytes();
            if bytes.len() < 256 {
                buf.push(SHORT_BINUNICODE);
                buf.push(bytes.len() as u8);
            } else {
                buf.push(BINUNICODE);
                buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            }
            buf.extend_from_slice(bytes);
        }
        PickleValue::Bytes(data) => {
            // Protocol 2 encodes bytes via _codecs.encode trick:
            // GLOBAL _codecs.encode, then two args, TUPLE2, REDUCE
            // No MARK needed since TUPLE2 takes exactly 2 items from stack.
            buf.extend_from_slice(b"c_codecs\nencode\n");
            // Encode the bytes as a latin-1 unicode string
            // Bytes 0x00-0x7F map to same UTF-8; 0x80-0xFF need 2-byte UTF-8
            let mut latin1_utf8 = Vec::with_capacity(data.len() * 2);
            for &b in data.iter() {
                if b < 0x80 {
                    latin1_utf8.push(b);
                } else {
                    // UTF-8 encode U+0080..U+00FF
                    latin1_utf8.push(0xC0 | (b >> 6));
                    latin1_utf8.push(0x80 | (b & 0x3F));
                }
            }
            if latin1_utf8.len() < 256 {
                buf.push(SHORT_BINUNICODE);
                buf.push(latin1_utf8.len() as u8);
            } else {
                buf.push(BINUNICODE);
                buf.extend_from_slice(&(latin1_utf8.len() as u32).to_le_bytes());
            }
            buf.extend_from_slice(&latin1_utf8);
            // encoding name
            buf.push(SHORT_BINUNICODE);
            buf.push(7); // "latin-1"
            buf.extend_from_slice(b"latin-1");
            buf.push(TUPLE2);
            buf.push(REDUCE);
        }
        PickleValue::List(items) => {
            buf.push(EMPTY_LIST);
            if !items.is_empty() {
                buf.push(MARK);
                for item in items {
                    encode_value(buf, item);
                }
                buf.push(APPENDS);
            }
        }
        PickleValue::Dict(pairs) => {
            buf.push(EMPTY_DICT);
            if !pairs.is_empty() {
                buf.push(MARK);
                for (k, v) in pairs {
                    encode_value(buf, k);
                    encode_value(buf, v);
                }
                buf.push(SETITEMS);
            }
        }
    }
}

fn encode_int(buf: &mut Vec<u8>, n: i64) {
    if n >= 0 && n < 256 {
        buf.push(BININT1);
        buf.push(n as u8);
    } else if n >= 0 && n < 65536 {
        buf.push(BININT2);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n >= i32::MIN as i64 && n <= i32::MAX as i64 {
        buf.push(BININT4);
        buf.extend_from_slice(&(n as i32).to_le_bytes());
    } else {
        // Use LONG1 for values that don't fit in i32
        buf.push(LONG1);
        let bytes = long_to_bytes(n);
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(&bytes);
    }
}

fn long_to_bytes(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let bytes = n.to_le_bytes();
    // Trim trailing 0x00 (positive) or 0xFF (negative) bytes
    let mut len = 8;
    if n > 0 {
        while len > 1 && bytes[len - 1] == 0x00 {
            len -= 1;
        }
        // If high bit is set, add a 0x00 byte
        if bytes[len - 1] & 0x80 != 0 {
            let mut result = bytes[..len].to_vec();
            result.push(0x00);
            return result;
        }
    } else {
        while len > 1 && bytes[len - 1] == 0xFF {
            len -= 1;
        }
        // If high bit is not set, add a 0xFF byte
        if bytes[len - 1] & 0x80 == 0 {
            let mut result = bytes[..len].to_vec();
            result.push(0xFF);
            return result;
        }
    }
    bytes[..len].to_vec()
}

/// Decode error.
#[derive(Debug)]
pub enum DecodeError {
    UnexpectedEnd,
    UnknownOpcode(u8),
    InvalidUtf8,
    StackUnderflow,
    NoMarkFound,
    NoStop,
    UnsupportedGlobal(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::UnexpectedEnd => write!(f, "unexpected end of pickle data"),
            DecodeError::UnknownOpcode(op) => write!(f, "unknown pickle opcode: 0x{:02x}", op),
            DecodeError::InvalidUtf8 => write!(f, "invalid UTF-8 in pickle string"),
            DecodeError::StackUnderflow => write!(f, "stack underflow"),
            DecodeError::NoMarkFound => write!(f, "no mark found on stack"),
            DecodeError::NoStop => write!(f, "no STOP opcode found"),
            DecodeError::UnsupportedGlobal(name) => {
                write!(f, "unsupported global: {}", name)
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode pickle protocol 2 bytes into a PickleValue.
pub fn decode(data: &[u8]) -> Result<PickleValue, DecodeError> {
    let mut stack: Vec<PickleValue> = Vec::new();
    let mut memo: HashMap<u32, PickleValue> = HashMap::new();
    let mut memo_counter: u32 = 0;
    let mut pos = 0;

    // Skip protocol header if present
    if pos < data.len() && data[pos] == PROTO {
        pos += 2; // skip PROTO + version byte
    }

    loop {
        if pos >= data.len() {
            return Err(DecodeError::NoStop);
        }

        let op = data[pos];
        pos += 1;

        match op {
            STOP => {
                return stack.pop().ok_or(DecodeError::StackUnderflow);
            }
            NONE => stack.push(PickleValue::None),
            NEWTRUE => stack.push(PickleValue::Bool(true)),
            NEWFALSE => stack.push(PickleValue::Bool(false)),
            BININT1 => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(PickleValue::Int(data[pos] as i64));
                pos += 1;
            }
            BININT2 => {
                if pos + 2 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let val = u16::from_le_bytes([data[pos], data[pos + 1]]);
                stack.push(PickleValue::Int(val as i64));
                pos += 2;
            }
            BININT4 => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let val = i32::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]);
                stack.push(PickleValue::Int(val as i64));
                pos += 4;
            }
            LONG1 => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let n = data[pos] as usize;
                pos += 1;
                if pos + n > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let val = bytes_to_long(&data[pos..pos + n]);
                stack.push(PickleValue::Int(val));
                pos += n;
            }
            BINFLOAT => {
                if pos + 8 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let val = f64::from_be_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]);
                stack.push(PickleValue::Float(val));
                pos += 8;
            }
            SHORT_BINUNICODE => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = data[pos] as usize;
                pos += 1;
                if pos + len > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let s = std::str::from_utf8(&data[pos..pos + len])
                    .map_err(|_| DecodeError::InvalidUtf8)?;
                stack.push(PickleValue::String(s.to_string()));
                pos += len;
            }
            BINUNICODE => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = u32::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]) as usize;
                pos += 4;
                if pos + len > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let s = std::str::from_utf8(&data[pos..pos + len])
                    .map_err(|_| DecodeError::InvalidUtf8)?;
                stack.push(PickleValue::String(s.to_string()));
                pos += len;
            }
            SHORT_BINSTRING => {
                // Protocol 0/1 short binary string (used as bytes in some pickles)
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = data[pos] as usize;
                pos += 1;
                if pos + len > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(PickleValue::Bytes(data[pos..pos + len].to_vec()));
                pos += len;
            }
            BINSTRING => {
                // Protocol 0/1 binary string
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = i32::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]) as usize;
                pos += 4;
                if pos + len > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(PickleValue::Bytes(data[pos..pos + len].to_vec()));
                pos += len;
            }
            SHORT_BINBYTES => {
                // SHORT_BINBYTES is actually opcode 'B' = 0x42
                // Wait, Python pickle docs say:
                // SHORT_BINBYTES = b'B' (no, that's wrong)
                // Actually: BINBYTES = b'B', SHORT_BINBYTES = b'C'
                // Let me just handle both...
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = data[pos] as usize;
                pos += 1;
                if pos + len > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(PickleValue::Bytes(data[pos..pos + len].to_vec()));
                pos += len;
            }
            BINBYTES => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = u32::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]) as usize;
                pos += 4;
                if pos + len > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(PickleValue::Bytes(data[pos..pos + len].to_vec()));
                pos += len;
            }
            EMPTY_LIST => stack.push(PickleValue::List(Vec::new())),
            EMPTY_DICT => stack.push(PickleValue::Dict(Vec::new())),
            EMPTY_TUPLE => stack.push(PickleValue::List(Vec::new())), // treat tuple as list
            MARK => stack.push(PickleValue::String("__mark__".into())),
            FRAME => {
                // Protocol 4: 8-byte frame length prefix. We just skip it
                // since we already have the full data.
                if pos + 8 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                pos += 8;
            }
            MEMOIZE => {
                // Protocol 4: implicit memo, auto-assigns next index
                if let Some(val) = stack.last() {
                    memo.insert(memo_counter, val.clone());
                }
                memo_counter += 1;
            }
            APPEND => {
                // Pop item, append to list on top of stack
                let item = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                if let Some(PickleValue::List(ref mut list)) = stack.last_mut() {
                    list.push(item);
                } else {
                    return Err(DecodeError::StackUnderflow);
                }
            }
            APPENDS => {
                // Pop items until mark, then append them to the list before the mark
                let mark_pos = find_mark(&stack)?;
                let items: Vec<PickleValue> = stack.drain(mark_pos + 1..).collect();
                stack.pop(); // remove mark
                if let Some(PickleValue::List(ref mut list)) = stack.last_mut() {
                    list.extend(items);
                } else {
                    return Err(DecodeError::StackUnderflow);
                }
            }
            SETITEM => {
                // Pop value, pop key, set on dict at top of stack
                let value = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                let key = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                if let Some(PickleValue::Dict(ref mut dict)) = stack.last_mut() {
                    dict.push((key, value));
                } else {
                    return Err(DecodeError::StackUnderflow);
                }
            }
            SETITEMS => {
                // Pop key-value pairs until mark, then set them on the dict before the mark
                let mark_pos = find_mark(&stack)?;
                let items: Vec<PickleValue> = stack.drain(mark_pos + 1..).collect();
                stack.pop(); // remove mark
                if let Some(PickleValue::Dict(ref mut dict)) = stack.last_mut() {
                    for pair in items.chunks_exact(2) {
                        dict.push((pair[0].clone(), pair[1].clone()));
                    }
                } else {
                    return Err(DecodeError::StackUnderflow);
                }
            }
            TUPLE1 => {
                let a = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                stack.push(PickleValue::List(vec![a]));
            }
            TUPLE2 => {
                let b = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                let a = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                stack.push(PickleValue::List(vec![a, b]));
            }
            TUPLE3 => {
                let c = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                let b = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                let a = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                stack.push(PickleValue::List(vec![a, b, c]));
            }
            SHORT_BINBYTES8 => {
                // Protocol 4: 8-byte length bytes
                if pos + 8 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = u64::from_le_bytes([
                    data[pos], data[pos+1], data[pos+2], data[pos+3],
                    data[pos+4], data[pos+5], data[pos+6], data[pos+7],
                ]) as usize;
                pos += 8;
                if pos + len > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(PickleValue::Bytes(data[pos..pos + len].to_vec()));
                pos += len;
            }
            BINUNICODE8 => {
                // Protocol 4: 8-byte length unicode
                if pos + 8 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = u64::from_le_bytes([
                    data[pos], data[pos+1], data[pos+2], data[pos+3],
                    data[pos+4], data[pos+5], data[pos+6], data[pos+7],
                ]) as usize;
                pos += 8;
                if pos + len > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let s = std::str::from_utf8(&data[pos..pos + len])
                    .map_err(|_| DecodeError::InvalidUtf8)?;
                stack.push(PickleValue::String(s.to_string()));
                pos += len;
            }
            BYTEARRAY8 => {
                // Protocol 5: 8-byte length bytearray (treat as bytes)
                if pos + 8 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = u64::from_le_bytes([
                    data[pos], data[pos+1], data[pos+2], data[pos+3],
                    data[pos+4], data[pos+5], data[pos+6], data[pos+7],
                ]) as usize;
                pos += 8;
                if pos + len > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(PickleValue::Bytes(data[pos..pos + len].to_vec()));
                pos += len;
            }
            BINPUT => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let idx = data[pos] as u32;
                pos += 1;
                if let Some(val) = stack.last() {
                    memo.insert(idx, val.clone());
                }
            }
            LONG_BINPUT => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let idx = u32::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]);
                pos += 4;
                if let Some(val) = stack.last() {
                    memo.insert(idx, val.clone());
                }
            }
            BINGET => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let idx = data[pos] as u32;
                pos += 1;
                let val = memo
                    .get(&idx)
                    .cloned()
                    .ok_or(DecodeError::StackUnderflow)?;
                stack.push(val);
            }
            LONG_BINGET => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let idx = u32::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]);
                pos += 4;
                let val = memo
                    .get(&idx)
                    .cloned()
                    .ok_or(DecodeError::StackUnderflow)?;
                stack.push(val);
            }
            GLOBAL => {
                // Read module\nname\n
                let nl1 = data[pos..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .ok_or(DecodeError::UnexpectedEnd)?;
                let module =
                    std::str::from_utf8(&data[pos..pos + nl1]).map_err(|_| DecodeError::InvalidUtf8)?;
                pos += nl1 + 1;
                let nl2 = data[pos..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .ok_or(DecodeError::UnexpectedEnd)?;
                let name =
                    std::str::from_utf8(&data[pos..pos + nl2]).map_err(|_| DecodeError::InvalidUtf8)?;
                pos += nl2 + 1;

                // Only allow _codecs.encode (for bytes encoding)
                if module == "_codecs" && name == "encode" {
                    stack.push(PickleValue::String("__codecs_encode__".into()));
                } else {
                    return Err(DecodeError::UnsupportedGlobal(format!(
                        "{}.{}",
                        module, name
                    )));
                }
            }
            REDUCE => {
                // Pop args tuple and callable, apply
                let args = stack.pop().ok_or(DecodeError::StackUnderflow)?;
                let callable = stack.pop().ok_or(DecodeError::StackUnderflow)?;

                if let PickleValue::String(ref s) = callable {
                    if s == "__codecs_encode__" {
                        // args should be a tuple (string, encoding)
                        if let PickleValue::List(ref items) = args {
                            if let Some(PickleValue::String(ref text)) = items.first() {
                                // Convert latin-1 string back to bytes
                                let bytes: Vec<u8> =
                                    text.chars().map(|c| c as u8).collect();
                                stack.push(PickleValue::Bytes(bytes));
                            } else {
                                stack.push(PickleValue::None);
                            }
                        } else {
                            stack.push(PickleValue::None);
                        }
                    } else {
                        return Err(DecodeError::UnsupportedGlobal(s.clone()));
                    }
                } else {
                    return Err(DecodeError::StackUnderflow);
                }
            }
            other => {
                return Err(DecodeError::UnknownOpcode(other));
            }
        }
    }
}

fn bytes_to_long(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    let negative = bytes[bytes.len() - 1] & 0x80 != 0;
    let mut result: i64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= (b as i64) << (i * 8);
    }
    if negative {
        // Sign-extend
        let bits = bytes.len() * 8;
        if bits < 64 {
            result |= !0i64 << bits;
        }
    }
    result
}

fn find_mark(stack: &[PickleValue]) -> Result<usize, DecodeError> {
    for i in (0..stack.len()).rev() {
        if let PickleValue::String(ref s) = stack[i] {
            if s == "__mark__" {
                return Ok(i);
            }
        }
    }
    Err(DecodeError::NoMarkFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_none() {
        let val = PickleValue::None;
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_bool_true() {
        let val = PickleValue::Bool(true);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_bool_false() {
        let val = PickleValue::Bool(false);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_int_small() {
        let val = PickleValue::Int(42);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_int_medium() {
        let val = PickleValue::Int(1000);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_int_large() {
        let val = PickleValue::Int(100000);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_int_negative() {
        let val = PickleValue::Int(-42);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_float() {
        let val = PickleValue::Float(3.14159);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_string_short() {
        let val = PickleValue::String("hello".into());
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_string_long() {
        let val = PickleValue::String("x".repeat(300));
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_bytes() {
        let val = PickleValue::Bytes(vec![0, 1, 2, 3, 255]);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_empty_list() {
        let val = PickleValue::List(vec![]);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_list() {
        let val = PickleValue::List(vec![
            PickleValue::Int(1),
            PickleValue::String("two".into()),
            PickleValue::Bool(true),
        ]);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_empty_dict() {
        let val = PickleValue::Dict(vec![]);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_dict() {
        let val = PickleValue::Dict(vec![
            (
                PickleValue::String("key".into()),
                PickleValue::Int(42),
            ),
            (
                PickleValue::String("flag".into()),
                PickleValue::Bool(false),
            ),
        ]);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_nested() {
        let val = PickleValue::Dict(vec![
            (
                PickleValue::String("list".into()),
                PickleValue::List(vec![
                    PickleValue::Int(1),
                    PickleValue::Dict(vec![(
                        PickleValue::String("inner".into()),
                        PickleValue::None,
                    )]),
                ]),
            ),
            (
                PickleValue::String("bytes".into()),
                PickleValue::Bytes(vec![0xDE, 0xAD]),
            ),
        ]);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn reject_unknown_opcode() {
        // 0x80 0x02 = protocol 2, then 0xFF = unknown
        let data = vec![0x80, 0x02, 0xFF];
        assert!(decode(&data).is_err());
    }

    #[test]
    fn dict_get_helper() {
        let val = PickleValue::Dict(vec![
            (PickleValue::String("get".into()), PickleValue::String("interface_stats".into())),
        ]);
        assert_eq!(
            val.get("get").unwrap().as_str().unwrap(),
            "interface_stats"
        );
        assert!(val.get("missing").is_none());
    }

    #[test]
    fn roundtrip_int_zero() {
        let val = PickleValue::Int(0);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_int_255() {
        let val = PickleValue::Int(255);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_bytes_empty() {
        let val = PickleValue::Bytes(vec![]);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_large_int() {
        let val = PickleValue::Int(i64::MAX);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_negative_large_int() {
        let val = PickleValue::Int(i64::MIN);
        let encoded = encode(&val);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn decode_python_dict() {
        // Manually constructed protocol 2 pickle of {"get": "stats"}
        // PROTO 2, EMPTY_DICT, MARK, SHORT_BINUNICODE 3 "get", SHORT_BINUNICODE 5 "stats", SETITEMS, STOP
        let data = vec![
            0x80, 0x02, // PROTO 2
            b'}',       // EMPTY_DICT
            b'(',       // MARK
            0x8c, 3, b'g', b'e', b't', // SHORT_BINUNICODE "get"
            0x8c, 5, b's', b't', b'a', b't', b's', // SHORT_BINUNICODE "stats"
            b'u',       // SETITEMS
            b'.',       // STOP
        ];
        let val = decode(&data).unwrap();
        assert_eq!(val.get("get").unwrap().as_str().unwrap(), "stats");
    }

    #[test]
    fn decode_protocol4_dict() {
        // Protocol 4 pickle of {"get": "interface_stats"} (from Python 3.8+)
        // Generated by: pickle.dumps({"get": "interface_stats"})
        let data = vec![
            0x80, 0x04,  // PROTO 4
            0x95, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // FRAME (28 bytes)
            b'}',        // EMPTY_DICT
            0x94,        // MEMOIZE
            0x8c, 0x03, b'g', b'e', b't', // SHORT_BINUNICODE "get"
            0x94,        // MEMOIZE
            0x8c, 0x0f,  // SHORT_BINUNICODE (15 bytes)
            b'i', b'n', b't', b'e', b'r', b'f', b'a', b'c', b'e',
            b'_', b's', b't', b'a', b't', b's',
            0x94,        // MEMOIZE
            b's',        // SETITEM
            b'.',        // STOP
        ];
        let val = decode(&data).unwrap();
        assert_eq!(val.get("get").unwrap().as_str().unwrap(), "interface_stats");
    }

    #[test]
    fn decode_protocol4_with_bytes() {
        // Protocol 4 pickle of {"drop": "path", "destination_hash": b"\x01\x02\x03"}
        let data = vec![
            0x80, 0x04,  // PROTO 4
            0x95, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // FRAME
            b'}',        // EMPTY_DICT
            0x94,        // MEMOIZE
            b'(',        // MARK
            0x8c, 0x04, b'd', b'r', b'o', b'p', // SHORT_BINUNICODE "drop"
            0x94,        // MEMOIZE
            0x8c, 0x04, b'p', b'a', b't', b'h', // SHORT_BINUNICODE "path"
            0x94,        // MEMOIZE
            0x8c, 0x10, b'd', b'e', b's', b't', b'i', b'n', b'a', b't',
            b'i', b'o', b'n', b'_', b'h', b'a', b's', b'h',
            0x94,        // MEMOIZE
            b'C', 0x03, 0x01, 0x02, 0x03, // SHORT_BINBYTES 3 bytes
            0x94,        // MEMOIZE
            b'u',        // SETITEMS
            b'.',        // STOP
        ];
        let val = decode(&data).unwrap();
        assert_eq!(val.get("drop").unwrap().as_str().unwrap(), "path");
        assert_eq!(val.get("destination_hash").unwrap().as_bytes().unwrap(), &[1, 2, 3]);
    }
}
