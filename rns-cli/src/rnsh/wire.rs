//! rnsh's messages and the msgpack they travel in.

use super::*;

use rns_core::msgpack::{self, Value};

/// The single msgpack value `raw` holds.
pub(super) fn msgpack_unpack(raw: &[u8]) -> Result<Value, RnshError> {
    msgpack::unpack_exact(raw).map_err(|e| RnshError::Protocol(format!("invalid msgpack: {e:?}")))
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
                Value::Str(sw_version.clone()),
                Value::UInt(*protocol_version),
            ]),
            RnshMessage::WindowSize(size) => pack_msgpack_array(vec![
                opt_u16(size.rows),
                opt_u16(size.cols),
                opt_u16(size.hpix),
                opt_u16(size.vpix),
            ]),
            RnshMessage::ExecuteCommand(cmd) => pack_msgpack_array(vec![
                Value::Array(cmd.cmdline.iter().map(|s| Value::Str(s.clone())).collect()),
                Value::Bool(cmd.pipe_stdin),
                Value::Bool(cmd.pipe_stdout),
                Value::Bool(cmd.pipe_stderr),
                Value::Nil,
                cmd.term
                    .as_ref()
                    .map(|s| Value::Str(s.clone()))
                    .unwrap_or(Value::Nil),
                opt_u16(cmd.rows),
                opt_u16(cmd.cols),
                opt_u16(cmd.hpix),
                opt_u16(cmd.vpix),
            ]),
            RnshMessage::Error { msg, fatal } => pack_msgpack_array(vec![
                Value::Str(msg.clone()),
                Value::Bool(*fatal),
                Value::Nil,
            ]),
            RnshMessage::CommandExited(code) => msgpack::pack(&Value::Int(i64::from(*code))),
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

pub(super) fn pack_msgpack_array(values: Vec<Value>) -> Vec<u8> {
    msgpack::pack(&Value::Array(values))
}

pub(super) fn opt_u16(value: Option<u16>) -> Value {
    value.map(|v| Value::UInt(v.into())).unwrap_or(Value::Nil)
}

pub(super) fn expect_array(value: Value, len: usize) -> Result<Vec<Value>, RnshError> {
    match value {
        Value::Array(values) if values.len() == len => Ok(values),
        _ => Err(RnshError::Protocol("unexpected msgpack array".into())),
    }
}

pub(super) fn expect_array_value(value: &Value) -> Result<&[Value], RnshError> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(RnshError::Protocol("expected msgpack array".into())),
    }
}

pub(super) fn expect_string(value: &Value) -> Result<String, RnshError> {
    match value {
        Value::Str(s) => Ok(s.clone()),
        _ => Err(RnshError::Protocol("expected msgpack string".into())),
    }
}

pub(super) fn opt_string(value: &Value) -> Result<Option<String>, RnshError> {
    match value {
        Value::Nil => Ok(None),
        Value::Str(s) => Ok(Some(s.clone())),
        _ => Err(RnshError::Protocol(
            "expected optional msgpack string".into(),
        )),
    }
}

pub(super) fn expect_bool(value: &Value) -> Result<bool, RnshError> {
    match value {
        Value::Bool(v) => Ok(*v),
        _ => Err(RnshError::Protocol("expected msgpack bool".into())),
    }
}

pub(super) fn expect_int(value: &Value) -> Result<i64, RnshError> {
    match value {
        Value::Int(v) => Ok(*v),
        Value::UInt(v) => {
            i64::try_from(*v).map_err(|_| RnshError::Protocol("msgpack int out of range".into()))
        }
        _ => Err(RnshError::Protocol("expected msgpack int".into())),
    }
}

pub(super) fn opt_int_u16(value: &Value) -> Result<Option<u16>, RnshError> {
    match value {
        Value::Nil => Ok(None),
        _ => expect_int(value)
            .ok()
            .and_then(|v| u16::try_from(v).ok())
            .map(Some)
            .ok_or_else(|| RnshError::Protocol("expected optional u16".into())),
    }
}
