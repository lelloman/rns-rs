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
    /// Python `None`.
    None,
    /// Python `bool`.
    Bool(bool),
    /// Python `int` that fits in `i64`.
    Int(i64),
    /// Python `float`.
    Float(f64),
    /// Python `str`.
    String(String),
    /// Python `bytes`; `bytearray` and protocol 0/1 binary strings also decode to this.
    Bytes(Vec<u8>),
    /// Python `list`; tuples also decode to this.
    List(Vec<PickleValue>),
    /// Python `dict`, as key/value pairs in pickle order.
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

    /// Get a number, float or int, as `f64`: upstream sends some values as
    /// either, depending on how they were last set.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            PickleValue::Float(f) => Some(*f),
            PickleValue::Int(i) => Some(*i as f64),
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
    if (0..256).contains(&n) {
        buf.push(BININT1);
        buf.push(n as u8);
    } else if (0..65536).contains(&n) {
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
    /// The data ended in the middle of an opcode's argument.
    UnexpectedEnd,
    /// An opcode this decoder does not handle.
    UnknownOpcode(u8),
    /// A string or global name that is not valid UTF-8.
    InvalidUtf8,
    /// An opcode needed more stack entries than there were.
    StackUnderflow,
    /// An opcode needed a MARK and none was on the stack.
    NoMarkFound,
    /// The data ended without a STOP opcode.
    NoStop,
    /// A global other than `_codecs.encode`, or that callable left where a
    /// value was expected; holds the `module.name`.
    UnsupportedGlobal(String),
    /// A pickled integer outside the range of `i64`.
    IntegerOutOfRange,
    /// The memo would copy more than [`MAX_MEMO_COPY`] in all: a pickle
    /// that refers back to its own containers can describe a value
    /// exponentially larger than itself.
    TooLarge,
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
            DecodeError::IntegerOutOfRange => write!(f, "pickled integer out of range"),
            DecodeError::TooLarge => write!(f, "pickle expands beyond the decode limit"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Most the memo may copy while decoding one pickle, in [`Item::weight`]
/// units (about one per value plus one per string or bytes byte). Values
/// are copied in and out of the memo rather than shared, so a few bytes
/// that store a container and fetch it back into itself again and again
/// would otherwise grow without bound. The RPC's largest real messages
/// copy a small fraction of this.
pub const MAX_MEMO_COPY: usize = 16 * 1024 * 1024;

/// Charge `item`'s weight against the memo copy `budget`.
fn charge_copy(budget: &mut usize, item: &Item) -> Result<(), DecodeError> {
    let weight = item.weight(*budget).ok_or(DecodeError::TooLarge)?;
    *budget -= weight;
    Ok(())
}

/// Decode pickle protocol 2 bytes into a PickleValue.
pub fn decode(data: &[u8]) -> Result<PickleValue, DecodeError> {
    let mut stack: Vec<Item> = Vec::new();
    // Stack heights at each MARK, kept apart from the values (as CPython's
    // metastack): a value can never be taken for a mark, and no opcode may
    // pop below the innermost mark.
    let mut marks: Vec<usize> = Vec::new();
    let mut memo: HashMap<u32, Item> = HashMap::new();
    let mut memo_counter: u32 = 0;
    let mut copy_budget = MAX_MEMO_COPY;
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
                return pop_value(&mut stack, &marks);
            }
            NONE => stack.push(Item::Value(PickleValue::None)),
            NEWTRUE => stack.push(Item::Value(PickleValue::Bool(true))),
            NEWFALSE => stack.push(Item::Value(PickleValue::Bool(false))),
            BININT1 => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(Item::Value(PickleValue::Int(data[pos] as i64)));
                pos += 1;
            }
            BININT2 => {
                if pos + 2 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let val = u16::from_le_bytes([data[pos], data[pos + 1]]);
                stack.push(Item::Value(PickleValue::Int(val as i64)));
                pos += 2;
            }
            BININT4 => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let val =
                    i32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                stack.push(Item::Value(PickleValue::Int(val as i64)));
                pos += 4;
            }
            LONG1 => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let n = data[pos] as usize;
                pos += 1;
                if n > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let val =
                    bytes_to_long(&data[pos..pos + n]).ok_or(DecodeError::IntegerOutOfRange)?;
                stack.push(Item::Value(PickleValue::Int(val)));
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
                stack.push(Item::Value(PickleValue::Float(val)));
                pos += 8;
            }
            SHORT_BINUNICODE => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = data[pos] as usize;
                pos += 1;
                if len > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let s = std::str::from_utf8(&data[pos..pos + len])
                    .map_err(|_| DecodeError::InvalidUtf8)?;
                stack.push(Item::Value(PickleValue::String(s.to_string())));
                pos += len;
            }
            BINUNICODE => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len =
                    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                        as usize;
                pos += 4;
                if len > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let s = std::str::from_utf8(&data[pos..pos + len])
                    .map_err(|_| DecodeError::InvalidUtf8)?;
                stack.push(Item::Value(PickleValue::String(s.to_string())));
                pos += len;
            }
            SHORT_BINSTRING => {
                // Protocol 0/1 short binary string (used as bytes in some pickles)
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = data[pos] as usize;
                pos += 1;
                if len > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(Item::Value(PickleValue::Bytes(
                    data[pos..pos + len].to_vec(),
                )));
                pos += len;
            }
            BINSTRING => {
                // Protocol 0/1 binary string
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len =
                    i32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                        as usize;
                pos += 4;
                if len > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(Item::Value(PickleValue::Bytes(
                    data[pos..pos + len].to_vec(),
                )));
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
                if len > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(Item::Value(PickleValue::Bytes(
                    data[pos..pos + len].to_vec(),
                )));
                pos += len;
            }
            BINBYTES => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len =
                    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                        as usize;
                pos += 4;
                if len > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(Item::Value(PickleValue::Bytes(
                    data[pos..pos + len].to_vec(),
                )));
                pos += len;
            }
            EMPTY_LIST => stack.push(Item::Value(PickleValue::List(Vec::new()))),
            EMPTY_DICT => stack.push(Item::Value(PickleValue::Dict(Vec::new()))),
            EMPTY_TUPLE => stack.push(Item::Value(PickleValue::List(Vec::new()))), // treat tuple as list
            MARK => marks.push(stack.len()),
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
                    charge_copy(&mut copy_budget, val)?;
                    memo.insert(memo_counter, val.clone());
                }
                memo_counter += 1;
            }
            APPEND => {
                // Pop item, append to list on top of stack
                let item = pop_value(&mut stack, &marks)?;
                if let Some(PickleValue::List(ref mut list)) = top_mut(&mut stack, &marks) {
                    list.push(item);
                } else {
                    return Err(DecodeError::StackUnderflow);
                }
            }
            APPENDS => {
                // Pop items until mark, then append them to the list before the mark
                let items = pop_mark(&mut stack, &mut marks)?;
                if let Some(PickleValue::List(ref mut list)) = top_mut(&mut stack, &marks) {
                    list.extend(items);
                } else {
                    return Err(DecodeError::StackUnderflow);
                }
            }
            SETITEM => {
                // Pop value, pop key, set on dict at top of stack
                let value = pop_value(&mut stack, &marks)?;
                let key = pop_value(&mut stack, &marks)?;
                if let Some(PickleValue::Dict(ref mut dict)) = top_mut(&mut stack, &marks) {
                    dict.push((key, value));
                } else {
                    return Err(DecodeError::StackUnderflow);
                }
            }
            SETITEMS => {
                // Pop key-value pairs until mark, then set them on the dict before the mark
                let items = pop_mark(&mut stack, &mut marks)?;
                if items.len() % 2 != 0 {
                    return Err(DecodeError::StackUnderflow);
                }
                if let Some(PickleValue::Dict(ref mut dict)) = top_mut(&mut stack, &marks) {
                    for pair in items.chunks_exact(2) {
                        dict.push((pair[0].clone(), pair[1].clone()));
                    }
                } else {
                    return Err(DecodeError::StackUnderflow);
                }
            }
            TUPLE1 => {
                let a = pop_value(&mut stack, &marks)?;
                stack.push(Item::Value(PickleValue::List(vec![a])));
            }
            TUPLE2 => {
                let b = pop_value(&mut stack, &marks)?;
                let a = pop_value(&mut stack, &marks)?;
                stack.push(Item::Value(PickleValue::List(vec![a, b])));
            }
            TUPLE3 => {
                let c = pop_value(&mut stack, &marks)?;
                let b = pop_value(&mut stack, &marks)?;
                let a = pop_value(&mut stack, &marks)?;
                stack.push(Item::Value(PickleValue::List(vec![a, b, c])));
            }
            SHORT_BINBYTES8 => {
                // Protocol 4: 8-byte length bytes
                if pos + 8 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = u64::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]) as usize;
                pos += 8;
                if len > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(Item::Value(PickleValue::Bytes(
                    data[pos..pos + len].to_vec(),
                )));
                pos += len;
            }
            BINUNICODE8 => {
                // Protocol 4: 8-byte length unicode
                if pos + 8 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = u64::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]) as usize;
                pos += 8;
                if len > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let s = std::str::from_utf8(&data[pos..pos + len])
                    .map_err(|_| DecodeError::InvalidUtf8)?;
                stack.push(Item::Value(PickleValue::String(s.to_string())));
                pos += len;
            }
            BYTEARRAY8 => {
                // Protocol 5: 8-byte length bytearray (treat as bytes)
                if pos + 8 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let len = u64::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]) as usize;
                pos += 8;
                if len > data.len() - pos {
                    return Err(DecodeError::UnexpectedEnd);
                }
                stack.push(Item::Value(PickleValue::Bytes(
                    data[pos..pos + len].to_vec(),
                )));
                pos += len;
            }
            BINPUT => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let idx = data[pos] as u32;
                pos += 1;
                if let Some(val) = stack.last() {
                    charge_copy(&mut copy_budget, val)?;
                    memo.insert(idx, val.clone());
                }
            }
            LONG_BINPUT => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let idx =
                    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                pos += 4;
                if let Some(val) = stack.last() {
                    charge_copy(&mut copy_budget, val)?;
                    memo.insert(idx, val.clone());
                }
            }
            BINGET => {
                if pos >= data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let idx = data[pos] as u32;
                pos += 1;
                let val = memo.get(&idx).ok_or(DecodeError::StackUnderflow)?;
                charge_copy(&mut copy_budget, val)?;
                stack.push(val.clone());
            }
            LONG_BINGET => {
                if pos + 4 > data.len() {
                    return Err(DecodeError::UnexpectedEnd);
                }
                let idx =
                    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                pos += 4;
                let val = memo.get(&idx).ok_or(DecodeError::StackUnderflow)?;
                charge_copy(&mut copy_budget, val)?;
                stack.push(val.clone());
            }
            GLOBAL => {
                // Read module\nname\n
                let nl1 = data[pos..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .ok_or(DecodeError::UnexpectedEnd)?;
                let module = std::str::from_utf8(&data[pos..pos + nl1])
                    .map_err(|_| DecodeError::InvalidUtf8)?;
                pos += nl1 + 1;
                let nl2 = data[pos..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .ok_or(DecodeError::UnexpectedEnd)?;
                let name = std::str::from_utf8(&data[pos..pos + nl2])
                    .map_err(|_| DecodeError::InvalidUtf8)?;
                pos += nl2 + 1;

                // Only allow _codecs.encode (for bytes encoding)
                if module == "_codecs" && name == "encode" {
                    stack.push(Item::CodecsEncode);
                } else {
                    return Err(DecodeError::UnsupportedGlobal(format!(
                        "{}.{}",
                        module, name
                    )));
                }
            }
            REDUCE => {
                // Pop args tuple and callable, apply
                let args = pop_value(&mut stack, &marks)?;
                let callable = pop(&mut stack, &marks)?;

                match callable {
                    Item::CodecsEncode => {
                        // args should be a tuple (string, encoding)
                        if let PickleValue::List(ref items) = args {
                            if let Some(PickleValue::String(ref text)) = items.first() {
                                // Convert latin-1 string back to bytes
                                let bytes: Vec<u8> = text.chars().map(|c| c as u8).collect();
                                stack.push(Item::Value(PickleValue::Bytes(bytes)));
                            } else {
                                stack.push(Item::Value(PickleValue::None));
                            }
                        } else {
                            stack.push(Item::Value(PickleValue::None));
                        }
                    }
                    Item::Value(_) => return Err(DecodeError::StackUnderflow),
                }
            }
            other => {
                return Err(DecodeError::UnknownOpcode(other));
            }
        }
    }
}

/// A little-endian two's complement integer (pickle's LONG1), or `None`
/// when it does not fit an `i64`: bytes past the eighth may only repeat the
/// sign.
fn bytes_to_long(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() {
        return Some(0);
    }
    let negative = bytes[bytes.len() - 1] & 0x80 != 0;
    let (low, high) = bytes.split_at(bytes.len().min(8));
    let sign_byte = if negative { 0xff } else { 0x00 };
    if high.iter().any(|&b| b != sign_byte) {
        return None;
    }
    let mut buf = [sign_byte; 8];
    buf[..low.len()].copy_from_slice(low);
    let value = i64::from_le_bytes(buf);
    // With more than eight bytes, the eighth must carry the same sign.
    if !high.is_empty() && (value < 0) != negative {
        return None;
    }
    Some(value)
}

/// An entry on the decoder's stack. The callables a GLOBAL may name are kept
/// apart from decoded data, so no pickled value can stand in for one.
#[derive(Clone)]
enum Item {
    Value(PickleValue),
    /// `_codecs.encode`, the only global allowed.
    CodecsEncode,
}

impl Item {
    /// The cost of copying this item: one per value, plus the length of
    /// each string and bytes value. `None` once it passes `limit`, which
    /// bounds the walk as well.
    fn weight(&self, limit: usize) -> Option<usize> {
        fn walk(value: &PickleValue, total: &mut usize, limit: usize) -> Option<()> {
            *total += 1;
            match value {
                PickleValue::String(s) => *total += s.len(),
                PickleValue::Bytes(b) => *total += b.len(),
                PickleValue::List(items) => {
                    for item in items {
                        walk(item, total, limit)?;
                    }
                }
                PickleValue::Dict(pairs) => {
                    for (key, value) in pairs {
                        walk(key, total, limit)?;
                        walk(value, total, limit)?;
                    }
                }
                _ => {}
            }
            (*total <= limit).then_some(())
        }
        match self {
            Item::Value(value) => {
                let mut total = 0;
                walk(value, &mut total, limit)?;
                Some(total)
            }
            Item::CodecsEncode => (limit >= 1).then_some(1),
        }
    }

    /// The decoded value, or an error for a callable found where data is
    /// expected (it has no `PickleValue` form).
    fn into_value(self) -> Result<PickleValue, DecodeError> {
        match self {
            Item::Value(value) => Ok(value),
            Item::CodecsEncode => Err(DecodeError::UnsupportedGlobal("_codecs.encode".into())),
        }
    }
}

/// Pop an entry, refusing to reach below the innermost MARK.
fn pop(stack: &mut Vec<Item>, marks: &[usize]) -> Result<Item, DecodeError> {
    if stack.len() <= marks.last().copied().unwrap_or(0) {
        return Err(DecodeError::StackUnderflow);
    }
    stack.pop().ok_or(DecodeError::StackUnderflow)
}

/// Pop a decoded value, refusing to reach below the innermost MARK.
fn pop_value(stack: &mut Vec<Item>, marks: &[usize]) -> Result<PickleValue, DecodeError> {
    pop(stack, marks)?.into_value()
}

/// The value on top of the stack, if it is a value above the innermost MARK.
fn top_mut<'a>(stack: &'a mut [Item], marks: &[usize]) -> Option<&'a mut PickleValue> {
    if stack.len() <= marks.last().copied().unwrap_or(0) {
        return None;
    }
    match stack.last_mut() {
        Some(Item::Value(value)) => Some(value),
        _ => None,
    }
}

/// Pop the innermost MARK and the values pushed since it.
fn pop_mark(
    stack: &mut Vec<Item>,
    marks: &mut Vec<usize>,
) -> Result<Vec<PickleValue>, DecodeError> {
    let mark = marks.pop().ok_or(DecodeError::NoMarkFound)?;
    if mark > stack.len() {
        return Err(DecodeError::StackUnderflow);
    }
    stack.drain(mark..).map(Item::into_value).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_pickle_that_doubles_itself_through_the_memo_is_refused() {
        // [] put 0, then 40 times: a new list holding memo 0 twice, put
        // back as memo 0, so the value doubles each round.
        let mut data = vec![PROTO, 2, EMPTY_LIST, BINPUT, 0];
        for _ in 0..40 {
            data.extend_from_slice(&[EMPTY_LIST, BINGET, 0, APPEND, BINGET, 0, APPEND, BINPUT, 0]);
        }
        data.push(STOP);
        assert!(matches!(decode(&data), Err(DecodeError::TooLarge)));

        // A few rounds stay within the limit and decode in full.
        let mut data = vec![PROTO, 2, EMPTY_LIST, BINPUT, 0];
        for _ in 0..4 {
            data.extend_from_slice(&[EMPTY_LIST, BINGET, 0, APPEND, BINGET, 0, APPEND, BINPUT, 0]);
        }
        data.push(STOP);
        fn leaves(value: &PickleValue) -> usize {
            match value {
                PickleValue::List(items) if items.is_empty() => 1,
                PickleValue::List(items) => items.iter().map(leaves).sum(),
                _ => 0,
            }
        }
        assert_eq!(leaves(&decode(&data).unwrap()), 16);
    }

    #[test]
    fn the_fuzzed_memo_bomb_is_refused_without_exhausting_memory() {
        // Found by the pickle_decode fuzz target: it went past 2 GB.
        let data = include_bytes!("../../tests/fixtures/pickle/memo_bomb_oom.bin");
        assert!(decode(data).is_err());
    }

    /// Lengths read from the stream are checked without overflowing: a
    /// negative BINSTRING length (an i32) or a huge 8-byte length used to
    /// overflow `pos + len` (found by fuzzing the RPC decoder).
    /// MARK used to be the string "__mark__" on the value stack: a pickled
    /// "__mark__" was then taken for a mark, and a mark could leak out as a
    /// value (found by fuzzing).
    #[test]
    fn marks_are_not_values() {
        let value = PickleValue::Dict(vec![(
            PickleValue::String("__mark__".into()),
            PickleValue::List(vec![PickleValue::String("__mark__".into())]),
        )]);
        assert_eq!(decode(&encode(&value)).unwrap(), value);
        // PROTO 2, EMPTY_DICT, MARK, SETITEM (would pop the mark), STOP.
        assert!(decode(&[0x80, 0x02, b'}', b'(', b's', b'.']).is_err());
        // A leftover MARK never comes out as a value: MARK, STOP.
        assert!(decode(&[0x80, 0x02, b'(', b'.']).is_err());
    }

    #[test]
    fn long_integers_beyond_i64_are_errors() {
        assert_eq!(bytes_to_long(&[]), Some(0));
        assert_eq!(bytes_to_long(&[0xff]), Some(-1));
        assert_eq!(bytes_to_long(&[0x00, 0x80]), Some(-32768));
        assert_eq!(bytes_to_long(&[0x00, 0x80, 0x00]), Some(32768));
        assert_eq!(
            bytes_to_long(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
            Some(i64::MAX)
        );
        // Redundant sign bytes past the eighth are fine.
        assert_eq!(bytes_to_long(&[0xff; 12]), Some(-1));
        assert_eq!(bytes_to_long(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Some(1));
        // 2**63 and wider values do not fit.
        assert_eq!(bytes_to_long(&[0, 0, 0, 0, 0, 0, 0, 0x80, 0]), None);
        assert_eq!(bytes_to_long(&[0, 0, 0, 0, 0, 0, 0, 0, 1]), None);
        // PROTO 2, LONG1 of nine bytes holding 2**64, STOP.
        let mut data = vec![0x80, 0x02, 0x8a, 9];
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.push(b'.');
        assert!(matches!(decode(&data), Err(DecodeError::IntegerOutOfRange)));
    }

    #[test]
    fn oversized_and_negative_lengths_are_errors_not_panics() {
        // PROTO 2, BINSTRING with length -1.
        assert!(decode(&[0x80, 0x02, b'T', 0xff, 0xff, 0xff, 0xff]).is_err());
        // PROTO 4, BINBYTES8 / BINUNICODE8 with length u64::MAX.
        for opcode in [0x8e, 0x8d] {
            let mut data = vec![0x80, 0x04, opcode];
            data.extend_from_slice(&u64::MAX.to_le_bytes());
            assert!(decode(&data).is_err(), "opcode {opcode:#x}");
        }
    }

    use super::*;

    /// `_codecs.encode` used to be the string "__codecs_encode__" on the
    /// stack: a pickled string with that value could then be called by
    /// REDUCE as if it were the global.
    #[test]
    fn codecs_encode_is_not_a_string() {
        // pickle.dumps(['__codecs_encode__', b'ab',
        //               {'__codecs_encode__': '__codecs_encode__'}], protocol=2)
        let data = b"\x80\x02]q\x00(X\x11\x00\x00\x00__codecs_encode__q\x01c_codecs\nencode\n\
                     q\x02X\x02\x00\x00\x00abq\x03X\x06\x00\x00\x00latin1q\x04\x86q\x05Rq\x06\
                     }q\x07h\x01h\x01se.";
        let s = || PickleValue::String("__codecs_encode__".into());
        assert_eq!(
            decode(data).unwrap(),
            PickleValue::List(vec![
                s(),
                PickleValue::Bytes(b"ab".to_vec()),
                PickleValue::Dict(vec![(s(), s())]),
            ])
        );

        // pickle.dumps({'k': '__codecs_encode__'}, protocol=2)
        let data =
            b"\x80\x02}q\x00X\x01\x00\x00\x00kq\x01X\x11\x00\x00\x00__codecs_encode__q\x02s.";
        assert_eq!(
            decode(data).unwrap(),
            PickleValue::Dict(vec![(PickleValue::String("k".into()), s())])
        );

        // pickle.dumps(b'\x00\xe9\xff', protocol=2)
        let data = b"\x80\x02c_codecs\nencode\nq\x00X\x05\x00\x00\x00\x00\xc3\xa9\xc3\xbfq\x01\
                     X\x06\x00\x00\x00latin1q\x02\x86q\x03Rq\x04.";
        assert_eq!(
            decode(data).unwrap(),
            PickleValue::Bytes(vec![0x00, 0xe9, 0xff])
        );

        // The string called as a function: ('__codecs_encode__', ('ab',)) REDUCE.
        let data = b"\x80\x02X\x11\x00\x00\x00__codecs_encode__X\x02\x00\x00\x00ab\x85R.";
        assert!(decode(data).is_err());

        // The global itself has no value form.
        assert!(decode(b"\x80\x02c_codecs\nencode\n.").is_err());
        assert!(decode(b"\x80\x02]c_codecs\nencode\na.").is_err());
    }

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
        let val = PickleValue::Float(std::f64::consts::PI);
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
            (PickleValue::String("key".into()), PickleValue::Int(42)),
            (PickleValue::String("flag".into()), PickleValue::Bool(false)),
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
        let val = PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("interface_stats".into()),
        )]);
        assert_eq!(val.get("get").unwrap().as_str().unwrap(), "interface_stats");
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
            b'}', // EMPTY_DICT
            b'(', // MARK
            0x8c, 3, b'g', b'e', b't', // SHORT_BINUNICODE "get"
            0x8c, 5, b's', b't', b'a', b't', b's', // SHORT_BINUNICODE "stats"
            b'u', // SETITEMS
            b'.', // STOP
        ];
        let val = decode(&data).unwrap();
        assert_eq!(val.get("get").unwrap().as_str().unwrap(), "stats");
    }

    #[test]
    fn decode_protocol4_dict() {
        // Protocol 4 pickle of {"get": "interface_stats"} (from Python 3.8+)
        // Generated by: pickle.dumps({"get": "interface_stats"})
        let data = vec![
            0x80, 0x04, // PROTO 4
            0x95, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // FRAME (28 bytes)
            b'}', // EMPTY_DICT
            0x94, // MEMOIZE
            0x8c, 0x03, b'g', b'e', b't', // SHORT_BINUNICODE "get"
            0x94, // MEMOIZE
            0x8c, 0x0f, // SHORT_BINUNICODE (15 bytes)
            b'i', b'n', b't', b'e', b'r', b'f', b'a', b'c', b'e', b'_', b's', b't', b'a', b't',
            b's', 0x94, // MEMOIZE
            b's', // SETITEM
            b'.', // STOP
        ];
        let val = decode(&data).unwrap();
        assert_eq!(val.get("get").unwrap().as_str().unwrap(), "interface_stats");
    }

    #[test]
    fn decode_protocol4_with_bytes() {
        // Protocol 4 pickle of {"drop": "path", "destination_hash": b"\x01\x02\x03"}
        let data = vec![
            0x80, 0x04, // PROTO 4
            0x95, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // FRAME
            b'}', // EMPTY_DICT
            0x94, // MEMOIZE
            b'(', // MARK
            0x8c, 0x04, b'd', b'r', b'o', b'p', // SHORT_BINUNICODE "drop"
            0x94, // MEMOIZE
            0x8c, 0x04, b'p', b'a', b't', b'h', // SHORT_BINUNICODE "path"
            0x94, // MEMOIZE
            0x8c, 0x10, b'd', b'e', b's', b't', b'i', b'n', b'a', b't', b'i', b'o', b'n', b'_',
            b'h', b'a', b's', b'h', 0x94, // MEMOIZE
            b'C', 0x03, 0x01, 0x02, 0x03, // SHORT_BINBYTES 3 bytes
            0x94, // MEMOIZE
            b'u', // SETITEMS
            b'.', // STOP
        ];
        let val = decode(&data).unwrap();
        assert_eq!(val.get("drop").unwrap().as_str().unwrap(), "path");
        assert_eq!(
            val.get("destination_hash").unwrap().as_bytes().unwrap(),
            &[1, 2, 3]
        );
    }
}
