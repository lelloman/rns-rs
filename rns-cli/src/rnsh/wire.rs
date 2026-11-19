//! rnsh's messages and the msgpack they travel in.

use super::*;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum MsgValue {
    Nil,
    Bool(bool),
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<MsgValue>),
    Map(Vec<(MsgValue, MsgValue)>),
}

pub(super) fn msgpack_pack(value: &MsgValue, out: &mut Vec<u8>) {
    match value {
        MsgValue::Nil => out.push(0xc0),
        MsgValue::Bool(false) => out.push(0xc2),
        MsgValue::Bool(true) => out.push(0xc3),
        MsgValue::Int(v) if *v >= 0 && *v <= 0x7f => out.push(*v as u8),
        MsgValue::Int(v) if *v >= -32 && *v < 0 => out.push((*v as i8) as u8),
        MsgValue::Int(v) if *v >= i8::MIN as i64 && *v <= i8::MAX as i64 => {
            out.extend_from_slice(&[0xd0, *v as i8 as u8]);
        }
        MsgValue::Int(v) if *v >= i16::MIN as i64 && *v <= i16::MAX as i64 => {
            out.push(0xd1);
            out.extend_from_slice(&(*v as i16).to_be_bytes());
        }
        MsgValue::Int(v) if *v >= i32::MIN as i64 && *v <= i32::MAX as i64 => {
            out.push(0xd2);
            out.extend_from_slice(&(*v as i32).to_be_bytes());
        }
        MsgValue::Int(v) => {
            out.push(0xd3);
            out.extend_from_slice(&v.to_be_bytes());
        }
        MsgValue::String(s) => pack_msgpack_str(s.as_bytes(), out, true),
        MsgValue::Bytes(bytes) => pack_msgpack_str(bytes, out, false),
        MsgValue::Array(items) => {
            if items.len() < 16 {
                out.push(0x90 | items.len() as u8);
            } else if items.len() <= u16::MAX as usize {
                out.push(0xdc);
                out.extend_from_slice(&(items.len() as u16).to_be_bytes());
            } else {
                out.push(0xdd);
                out.extend_from_slice(&(items.len() as u32).to_be_bytes());
            }
            for item in items {
                msgpack_pack(item, out);
            }
        }
        MsgValue::Map(items) => {
            if items.len() < 16 {
                out.push(0x80 | items.len() as u8);
            } else {
                out.push(0xde);
                out.extend_from_slice(&(items.len() as u16).to_be_bytes());
            }
            for (key, value) in items {
                msgpack_pack(key, out);
                msgpack_pack(value, out);
            }
        }
    }
}

pub(super) fn pack_msgpack_str(bytes: &[u8], out: &mut Vec<u8>, utf8: bool) {
    if utf8 {
        if bytes.len() < 32 {
            out.push(0xa0 | bytes.len() as u8);
        } else if bytes.len() <= u8::MAX as usize {
            out.extend_from_slice(&[0xd9, bytes.len() as u8]);
        } else if bytes.len() <= u16::MAX as usize {
            out.push(0xda);
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        } else {
            out.push(0xdb);
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        }
    } else if bytes.len() <= u8::MAX as usize {
        out.extend_from_slice(&[0xc4, bytes.len() as u8]);
    } else if bytes.len() <= u16::MAX as usize {
        out.push(0xc5);
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    } else {
        out.push(0xc6);
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

pub(super) fn msgpack_unpack(raw: &[u8]) -> Result<MsgValue, RnshError> {
    let (value, consumed) = unpack_at(raw, 0)?;
    if consumed != raw.len() {
        return Err(RnshError::Protocol("trailing msgpack data".into()));
    }
    Ok(value)
}

pub(super) fn unpack_at(raw: &[u8], mut pos: usize) -> Result<(MsgValue, usize), RnshError> {
    let tag = *raw
        .get(pos)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack".into()))?;
    pos += 1;
    match tag {
        0x00..=0x7f => Ok((MsgValue::Int(tag as i64), pos)),
        0x80..=0x8f => unpack_map(raw, pos, (tag & 0x0f) as usize),
        0x90..=0x9f => unpack_array(raw, pos, (tag & 0x0f) as usize),
        0xa0..=0xbf => unpack_string(raw, pos, (tag & 0x1f) as usize),
        0xc0 => Ok((MsgValue::Nil, pos)),
        0xc2 => Ok((MsgValue::Bool(false), pos)),
        0xc3 => Ok((MsgValue::Bool(true), pos)),
        0xc4 => {
            let len = read_u8(raw, &mut pos)? as usize;
            unpack_bytes(raw, pos, len)
        }
        0xc5 => {
            let len = read_u16(raw, &mut pos)? as usize;
            unpack_bytes(raw, pos, len)
        }
        0xc6 => {
            let len = read_u32(raw, &mut pos)? as usize;
            unpack_bytes(raw, pos, len)
        }
        0xcc => Ok((MsgValue::Int(read_u8(raw, &mut pos)? as i64), pos)),
        0xcd => Ok((MsgValue::Int(read_u16(raw, &mut pos)? as i64), pos)),
        0xce => Ok((MsgValue::Int(read_u32(raw, &mut pos)? as i64), pos)),
        0xcf => Ok((MsgValue::Int(read_u64(raw, &mut pos)? as i64), pos)),
        0xd0 => Ok((MsgValue::Int(read_u8(raw, &mut pos)? as i8 as i64), pos)),
        0xd1 => Ok((MsgValue::Int(read_u16(raw, &mut pos)? as i16 as i64), pos)),
        0xd2 => Ok((MsgValue::Int(read_u32(raw, &mut pos)? as i32 as i64), pos)),
        0xd3 => Ok((MsgValue::Int(read_u64(raw, &mut pos)? as i64), pos)),
        0xd9 => {
            let len = read_u8(raw, &mut pos)? as usize;
            unpack_string(raw, pos, len)
        }
        0xda => {
            let len = read_u16(raw, &mut pos)? as usize;
            unpack_string(raw, pos, len)
        }
        0xdb => {
            let len = read_u32(raw, &mut pos)? as usize;
            unpack_string(raw, pos, len)
        }
        0xdc => {
            let len = read_u16(raw, &mut pos)? as usize;
            unpack_array(raw, pos, len)
        }
        0xdd => {
            let len = read_u32(raw, &mut pos)? as usize;
            unpack_array(raw, pos, len)
        }
        0xde => {
            let len = read_u16(raw, &mut pos)? as usize;
            unpack_map(raw, pos, len)
        }
        0xdf => {
            let len = read_u32(raw, &mut pos)? as usize;
            unpack_map(raw, pos, len)
        }
        0xe0..=0xff => Ok((MsgValue::Int((tag as i8) as i64), pos)),
        _ => Err(RnshError::Protocol(format!(
            "unsupported msgpack tag 0x{tag:02x}"
        ))),
    }
}

pub(super) fn unpack_array(
    raw: &[u8],
    mut pos: usize,
    len: usize,
) -> Result<(MsgValue, usize), RnshError> {
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let (value, next) = unpack_at(raw, pos)?;
        values.push(value);
        pos = next;
    }
    Ok((MsgValue::Array(values), pos))
}

pub(super) fn unpack_map(
    raw: &[u8],
    mut pos: usize,
    len: usize,
) -> Result<(MsgValue, usize), RnshError> {
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let (key, next) = unpack_at(raw, pos)?;
        let (value, next) = unpack_at(raw, next)?;
        values.push((key, value));
        pos = next;
    }
    Ok((MsgValue::Map(values), pos))
}

pub(super) fn unpack_string(
    raw: &[u8],
    pos: usize,
    len: usize,
) -> Result<(MsgValue, usize), RnshError> {
    let bytes = raw
        .get(pos..pos + len)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack string".into()))?;
    let s = std::str::from_utf8(bytes)
        .map_err(|_| RnshError::Protocol("invalid msgpack utf8".into()))?;
    Ok((MsgValue::String(s.to_string()), pos + len))
}

pub(super) fn unpack_bytes(
    raw: &[u8],
    pos: usize,
    len: usize,
) -> Result<(MsgValue, usize), RnshError> {
    let bytes = raw
        .get(pos..pos + len)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack bytes".into()))?;
    Ok((MsgValue::Bytes(bytes.to_vec()), pos + len))
}

pub(super) fn read_u8(raw: &[u8], pos: &mut usize) -> Result<u8, RnshError> {
    let v = *raw
        .get(*pos)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack integer".into()))?;
    *pos += 1;
    Ok(v)
}

pub(super) fn read_u16(raw: &[u8], pos: &mut usize) -> Result<u16, RnshError> {
    let bytes = raw
        .get(*pos..*pos + 2)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack integer".into()))?;
    *pos += 2;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(super) fn read_u32(raw: &[u8], pos: &mut usize) -> Result<u32, RnshError> {
    let bytes = raw
        .get(*pos..*pos + 4)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack integer".into()))?;
    *pos += 4;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) fn read_u64(raw: &[u8], pos: &mut usize) -> Result<u64, RnshError> {
    let bytes = raw
        .get(*pos..*pos + 8)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack integer".into()))?;
    *pos += 8;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct WindowSize {
    pub(super) rows: Option<u16>,
    pub(super) cols: Option<u16>,
    pub(super) hpix: Option<u16>,
    pub(super) vpix: Option<u16>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct ExecuteCommand {
    pub(super) cmdline: Vec<String>,
    pub(super) pipe_stdin: bool,
    pub(super) pipe_stdout: bool,
    pub(super) pipe_stderr: bool,
    pub(super) term: Option<String>,
    pub(super) rows: Option<u16>,
    pub(super) cols: Option<u16>,
    pub(super) hpix: Option<u16>,
    pub(super) vpix: Option<u16>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum RnshMessage {
    Noop,
    WindowSize(WindowSize),
    ExecuteCommand(ExecuteCommand),
    StreamData(StreamDataMessage),
    VersionInfo {
        sw_version: String,
        protocol_version: u64,
    },
    Error {
        msg: String,
        fatal: bool,
    },
    CommandExited(i32),
}

impl RnshMessage {
    pub(super) fn msgtype(&self) -> u16 {
        match self {
            RnshMessage::Noop => MSG_NOOP,
            RnshMessage::WindowSize(_) => MSG_WINDOW_SIZE,
            RnshMessage::ExecuteCommand(_) => MSG_EXECUTE_COMMAND,
            RnshMessage::StreamData(_) => MSG_STREAM_DATA,
            RnshMessage::VersionInfo { .. } => MSG_VERSION_INFO,
            RnshMessage::Error { .. } => MSG_ERROR,
            RnshMessage::CommandExited(_) => MSG_COMMAND_EXITED,
        }
    }

    pub(super) fn pack(&self) -> Vec<u8> {
        match self {
            RnshMessage::Noop => Vec::new(),
            RnshMessage::StreamData(msg) => msg.pack(),
            RnshMessage::VersionInfo {
                sw_version,
                protocol_version,
            } => pack_msgpack_array(vec![
                MsgValue::String(sw_version.clone()),
                MsgValue::Int(*protocol_version as i64),
            ]),
            RnshMessage::WindowSize(size) => pack_msgpack_array(vec![
                opt_u16(size.rows),
                opt_u16(size.cols),
                opt_u16(size.hpix),
                opt_u16(size.vpix),
            ]),
            RnshMessage::ExecuteCommand(cmd) => pack_msgpack_array(vec![
                MsgValue::Array(
                    cmd.cmdline
                        .iter()
                        .map(|s| MsgValue::String(s.clone()))
                        .collect(),
                ),
                MsgValue::Bool(cmd.pipe_stdin),
                MsgValue::Bool(cmd.pipe_stdout),
                MsgValue::Bool(cmd.pipe_stderr),
                MsgValue::Nil,
                cmd.term
                    .as_ref()
                    .map(|s| MsgValue::String(s.clone()))
                    .unwrap_or(MsgValue::Nil),
                opt_u16(cmd.rows),
                opt_u16(cmd.cols),
                opt_u16(cmd.hpix),
                opt_u16(cmd.vpix),
            ]),
            RnshMessage::Error { msg, fatal } => pack_msgpack_array(vec![
                MsgValue::String(msg.clone()),
                MsgValue::Bool(*fatal),
                MsgValue::Nil,
            ]),
            RnshMessage::CommandExited(code) => {
                let mut out = Vec::new();
                msgpack_pack(&MsgValue::Int(*code as i64), &mut out);
                out
            }
        }
    }

    pub(super) fn unpack(msgtype: u16, payload: &[u8]) -> Result<Self, RnshError> {
        match msgtype {
            MSG_NOOP => Ok(RnshMessage::Noop),
            MSG_STREAM_DATA => Ok(RnshMessage::StreamData(
                StreamDataMessage::unpack_bounded(
                    payload,
                    &Bzip2Compressor,
                    MAX_DECOMPRESSED_STREAM_CHUNK,
                )
                .map_err(|_| RnshError::Protocol("invalid stream data message".into()))?,
            )),
            MSG_VERSION_INFO => {
                let values = expect_array(msgpack_unpack(payload)?, 2)?;
                Ok(RnshMessage::VersionInfo {
                    sw_version: expect_string(&values[0])?,
                    protocol_version: expect_int(&values[1])? as u64,
                })
            }
            MSG_WINDOW_SIZE => {
                let values = expect_array(msgpack_unpack(payload)?, 4)?;
                Ok(RnshMessage::WindowSize(WindowSize {
                    rows: opt_int_u16(&values[0])?,
                    cols: opt_int_u16(&values[1])?,
                    hpix: opt_int_u16(&values[2])?,
                    vpix: opt_int_u16(&values[3])?,
                }))
            }
            MSG_EXECUTE_COMMAND => {
                let values = expect_array(msgpack_unpack(payload)?, 10)?;
                let cmdline = expect_array_value(&values[0])?
                    .iter()
                    .map(expect_string)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(RnshMessage::ExecuteCommand(ExecuteCommand {
                    cmdline,
                    pipe_stdin: expect_bool(&values[1])?,
                    pipe_stdout: expect_bool(&values[2])?,
                    pipe_stderr: expect_bool(&values[3])?,
                    term: opt_string(&values[5])?,
                    rows: opt_int_u16(&values[6])?,
                    cols: opt_int_u16(&values[7])?,
                    hpix: opt_int_u16(&values[8])?,
                    vpix: opt_int_u16(&values[9])?,
                }))
            }
            MSG_ERROR => {
                let values = expect_array(msgpack_unpack(payload)?, 3)?;
                Ok(RnshMessage::Error {
                    msg: expect_string(&values[0])?,
                    fatal: expect_bool(&values[1])?,
                })
            }
            MSG_COMMAND_EXITED => Ok(RnshMessage::CommandExited(expect_int(&msgpack_unpack(
                payload,
            )?)? as i32)),
            _ => Err(RnshError::Protocol(format!(
                "unknown rnsh message type 0x{msgtype:04x}"
            ))),
        }
    }
}

pub(super) fn pack_msgpack_array(values: Vec<MsgValue>) -> Vec<u8> {
    let mut out = Vec::new();
    msgpack_pack(&MsgValue::Array(values), &mut out);
    out
}

pub(super) fn opt_u16(value: Option<u16>) -> MsgValue {
    value
        .map(|v| MsgValue::Int(v as i64))
        .unwrap_or(MsgValue::Nil)
}

pub(super) fn expect_array(value: MsgValue, len: usize) -> Result<Vec<MsgValue>, RnshError> {
    match value {
        MsgValue::Array(values) if values.len() == len => Ok(values),
        _ => Err(RnshError::Protocol("unexpected msgpack array".into())),
    }
}

pub(super) fn expect_array_value(value: &MsgValue) -> Result<&[MsgValue], RnshError> {
    match value {
        MsgValue::Array(values) => Ok(values),
        _ => Err(RnshError::Protocol("expected msgpack array".into())),
    }
}

pub(super) fn expect_string(value: &MsgValue) -> Result<String, RnshError> {
    match value {
        MsgValue::String(s) => Ok(s.clone()),
        _ => Err(RnshError::Protocol("expected msgpack string".into())),
    }
}

pub(super) fn opt_string(value: &MsgValue) -> Result<Option<String>, RnshError> {
    match value {
        MsgValue::Nil => Ok(None),
        MsgValue::String(s) => Ok(Some(s.clone())),
        _ => Err(RnshError::Protocol(
            "expected optional msgpack string".into(),
        )),
    }
}

pub(super) fn expect_bool(value: &MsgValue) -> Result<bool, RnshError> {
    match value {
        MsgValue::Bool(v) => Ok(*v),
        _ => Err(RnshError::Protocol("expected msgpack bool".into())),
    }
}

pub(super) fn expect_int(value: &MsgValue) -> Result<i64, RnshError> {
    match value {
        MsgValue::Int(v) => Ok(*v),
        _ => Err(RnshError::Protocol("expected msgpack int".into())),
    }
}

pub(super) fn opt_int_u16(value: &MsgValue) -> Result<Option<u16>, RnshError> {
    match value {
        MsgValue::Nil => Ok(None),
        MsgValue::Int(v) if *v >= 0 && *v <= u16::MAX as i64 => Ok(Some(*v as u16)),
        _ => Err(RnshError::Protocol("expected optional u16".into())),
    }
}
