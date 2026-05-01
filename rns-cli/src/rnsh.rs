//! Reticulum Remote Shell Utility.
//!
//! Protocol and behaviour are based on the first-party Python `rnsh` utility,
//! which itself credits Aaron Heise's original `rnsh` program.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rns_core::buffer::StreamDataMessage;
use rns_core::types::{DestHash, IdentityHash};
use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::compressor::Bzip2Compressor;
use rns_net::destination::Destination;
use rns_net::{Callbacks, RnsNode, SendError};

use crate::format::prettyhexrep;

const APP_NAME: &str = "rnsh";
const DEFAULT_SERVICE_NAME: &str = "default";
const VERSION: &str = env!("FULL_VERSION");

const MSG_MAGIC: u16 = 0xac;
const PROTOCOL_VERSION: u64 = 1;

const MSG_NOOP: u16 = (MSG_MAGIC << 8) | 0;
const MSG_WINDOW_SIZE: u16 = (MSG_MAGIC << 8) | 2;
const MSG_EXECUTE_COMMAND: u16 = (MSG_MAGIC << 8) | 3;
const MSG_STREAM_DATA: u16 = (MSG_MAGIC << 8) | 4;
const MSG_VERSION_INFO: u16 = (MSG_MAGIC << 8) | 5;
const MSG_ERROR: u16 = (MSG_MAGIC << 8) | 6;
const MSG_COMMAND_EXITED: u16 = (MSG_MAGIC << 8) | 7;

const STREAM_STDIN: u16 = 0;
const STREAM_STDOUT: u16 = 1;
const STREAM_STDERR: u16 = 2;

const CHANNEL_PAYLOAD_MAX: usize =
    rns_core::constants::LINK_MDU - rns_core::constants::CHANNEL_ENVELOPE_OVERHEAD;
const STREAM_CHUNK_MAX: usize = CHANNEL_PAYLOAD_MAX - 2;
const MAX_DECOMPRESSED_STREAM_CHUNK: usize = 64 * 1024;

static SIGWINCH_SEEN: AtomicBool = AtomicBool::new(false);

extern "C" fn sigwinch_handler(_: libc::c_int) {
    SIGWINCH_SEEN.store(true, Ordering::SeqCst);
}

#[derive(Debug)]
enum RnshError {
    Io(io::Error),
    Protocol(String),
    Send,
}

impl From<io::Error> for RnshError {
    fn from(value: io::Error) -> Self {
        RnshError::Io(value)
    }
}

impl From<SendError> for RnshError {
    fn from(_: SendError) -> Self {
        RnshError::Send
    }
}

impl std::fmt::Display for RnshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RnshError::Io(err) => write!(f, "{err}"),
            RnshError::Protocol(err) => write!(f, "{err}"),
            RnshError::Send => write!(f, "RNS send failed"),
        }
    }
}

pub fn main() -> i32 {
    match CliOptions::parse(std::env::args().skip(1).collect()) {
        Ok(opts) => {
            if opts.help {
                print_usage();
                return 0;
            }
            if opts.version {
                println!("rnsh {} (protocol {})", VERSION, PROTOCOL_VERSION);
                return 0;
            }
            if opts.print_identity {
                return match print_identity(&opts) {
                    Ok(()) => 0,
                    Err(err) => {
                        eprintln!("{err}");
                        1
                    }
                };
            }
            let result = if opts.listen {
                listen(opts).map(|_| 0)
            } else if opts.destination.is_some() {
                let mirror = opts.mirror_exit;
                initiate(opts).map(|code| if mirror { code } else { 0 })
            } else {
                print_usage();
                Ok(1)
            };
            match result {
                Ok(code) => code,
                Err(err) => {
                    eprintln!("{err}");
                    1
                }
            }
        }
        Err(err) => {
            eprintln!("{err}");
            print_usage();
            1
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CliOptions {
    config: Option<String>,
    identity: Option<String>,
    verbose: u8,
    quiet: u8,
    print_identity: bool,
    version: bool,
    help: bool,
    listen: bool,
    service: Option<String>,
    announce_period: Option<u64>,
    allowed: Vec<String>,
    no_auth: bool,
    remote_command_as_args: bool,
    no_remote_command: bool,
    no_id: bool,
    mirror_exit: bool,
    timeout: Option<f64>,
    destination: Option<String>,
    command: Vec<String>,
}

impl CliOptions {
    fn parse(argv: Vec<String>) -> Result<Self, String> {
        let mut opts = CliOptions::default();
        let (rnsh_argv, command) = match argv.iter().position(|arg| arg == "--") {
            Some(idx) => (argv[..idx].to_vec(), argv[idx + 1..].to_vec()),
            None => (argv, Vec::new()),
        };
        opts.command = command;

        let mut i = 0;
        while i < rnsh_argv.len() {
            let arg = &rnsh_argv[i];
            if !arg.starts_with('-') || arg == "-" {
                if opts.destination.is_some() {
                    return Err(format!("unexpected positional argument: {arg}"));
                }
                opts.destination = Some(arg.clone());
                i += 1;
                continue;
            }

            if let Some(name) = arg.strip_prefix("--") {
                match name {
                    "config" | "identity" | "service" | "announce" | "allowed" | "timeout" => {
                        i += 1;
                        let value = rnsh_argv
                            .get(i)
                            .ok_or_else(|| format!("--{name} requires a value"))?
                            .clone();
                        match name {
                            "config" => opts.config = Some(value),
                            "identity" => opts.identity = Some(value),
                            "service" => opts.service = Some(value),
                            "announce" => {
                                opts.announce_period = Some(value.parse().map_err(|_| {
                                    "--announce requires an integer period".to_string()
                                })?)
                            }
                            "allowed" => opts.allowed.push(value),
                            "timeout" => {
                                opts.timeout = Some(value.parse().map_err(|_| {
                                    "--timeout requires a numeric value".to_string()
                                })?)
                            }
                            _ => {}
                        }
                    }
                    "verbose" => opts.verbose = opts.verbose.saturating_add(1),
                    "quiet" => opts.quiet = opts.quiet.saturating_add(1),
                    "print-identity" => opts.print_identity = true,
                    "version" => opts.version = true,
                    "help" => opts.help = true,
                    "listen" => opts.listen = true,
                    "no-auth" => opts.no_auth = true,
                    "remote-command-as-args" => opts.remote_command_as_args = true,
                    "no-remote-command" => opts.no_remote_command = true,
                    "no-id" => opts.no_id = true,
                    "mirror" => opts.mirror_exit = true,
                    _ => return Err(format!("unknown option --{name}")),
                }
                i += 1;
                continue;
            }

            let chars: Vec<char> = arg[1..].chars().collect();
            let mut pos = 0;
            while pos < chars.len() {
                match chars[pos] {
                    'c' | 'i' | 's' | 'b' | 'a' | 'w' => {
                        let key = chars[pos];
                        let value = if pos + 1 < chars.len() {
                            chars[pos + 1..].iter().collect::<String>()
                        } else {
                            i += 1;
                            rnsh_argv
                                .get(i)
                                .ok_or_else(|| format!("-{key} requires a value"))?
                                .clone()
                        };
                        match key {
                            'c' => opts.config = Some(value),
                            'i' => opts.identity = Some(value),
                            's' => opts.service = Some(value),
                            'b' => {
                                opts.announce_period = Some(
                                    value
                                        .parse()
                                        .map_err(|_| "-b requires an integer".to_string())?,
                                )
                            }
                            'a' => opts.allowed.push(value),
                            'w' => {
                                opts.timeout = Some(
                                    value
                                        .parse()
                                        .map_err(|_| "-w requires a number".to_string())?,
                                )
                            }
                            _ => {}
                        }
                        break;
                    }
                    'v' => opts.verbose = opts.verbose.saturating_add(1),
                    'q' => opts.quiet = opts.quiet.saturating_add(1),
                    'p' => opts.print_identity = true,
                    'l' => opts.listen = true,
                    'n' => opts.no_auth = true,
                    'A' => opts.remote_command_as_args = true,
                    'C' => opts.no_remote_command = true,
                    'N' => opts.no_id = true,
                    'm' => opts.mirror_exit = true,
                    'h' => opts.help = true,
                    other => return Err(format!("unknown option -{other}")),
                }
                pos += 1;
            }
            i += 1;
        }

        if opts.listen && opts.service.is_none() {
            opts.service = Some(DEFAULT_SERVICE_NAME.to_string());
        }
        Ok(opts)
    }
}

fn print_usage() {
    eprintln!(
        "Usage:\n  rnsh -l [options] [-- command...]\n  rnsh [options] <destination> [-- command...]\n\nOptions:\n  -c, --config PATH        Reticulum config directory\n  -i, --identity PATH      Identity file to use\n  -p, --print-identity     Print identity and destination info\n  -l, --listen             Listen for remote shell links\n  -s, --service NAME       Listener identity service name\n  -b, --announce PERIOD    Announce on startup and every PERIOD seconds (0 = once)\n  -a, --allowed HASH       Allow initiator identity hash (repeatable)\n  -n, --no-auth            Allow any initiator identity\n  -A, --remote-command-as-args\n  -C, --no-remote-command\n  -N, --no-id              Do not identify to the listener\n  -m, --mirror             Return remote command exit code\n  -w, --timeout SECONDS    Path/link/protocol timeout"
    );
}

#[derive(Debug, Clone, PartialEq)]
enum MsgValue {
    Nil,
    Bool(bool),
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<MsgValue>),
    Map(Vec<(MsgValue, MsgValue)>),
}

fn msgpack_pack(value: &MsgValue, out: &mut Vec<u8>) {
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

fn pack_msgpack_str(bytes: &[u8], out: &mut Vec<u8>, utf8: bool) {
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

fn msgpack_unpack(raw: &[u8]) -> Result<MsgValue, RnshError> {
    let (value, consumed) = unpack_at(raw, 0)?;
    if consumed != raw.len() {
        return Err(RnshError::Protocol("trailing msgpack data".into()));
    }
    Ok(value)
}

fn unpack_at(raw: &[u8], mut pos: usize) -> Result<(MsgValue, usize), RnshError> {
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

fn unpack_array(raw: &[u8], mut pos: usize, len: usize) -> Result<(MsgValue, usize), RnshError> {
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let (value, next) = unpack_at(raw, pos)?;
        values.push(value);
        pos = next;
    }
    Ok((MsgValue::Array(values), pos))
}

fn unpack_map(raw: &[u8], mut pos: usize, len: usize) -> Result<(MsgValue, usize), RnshError> {
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let (key, next) = unpack_at(raw, pos)?;
        let (value, next) = unpack_at(raw, next)?;
        values.push((key, value));
        pos = next;
    }
    Ok((MsgValue::Map(values), pos))
}

fn unpack_string(raw: &[u8], pos: usize, len: usize) -> Result<(MsgValue, usize), RnshError> {
    let bytes = raw
        .get(pos..pos + len)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack string".into()))?;
    let s = std::str::from_utf8(bytes)
        .map_err(|_| RnshError::Protocol("invalid msgpack utf8".into()))?;
    Ok((MsgValue::String(s.to_string()), pos + len))
}

fn unpack_bytes(raw: &[u8], pos: usize, len: usize) -> Result<(MsgValue, usize), RnshError> {
    let bytes = raw
        .get(pos..pos + len)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack bytes".into()))?;
    Ok((MsgValue::Bytes(bytes.to_vec()), pos + len))
}

fn read_u8(raw: &[u8], pos: &mut usize) -> Result<u8, RnshError> {
    let v = *raw
        .get(*pos)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack integer".into()))?;
    *pos += 1;
    Ok(v)
}

fn read_u16(raw: &[u8], pos: &mut usize) -> Result<u16, RnshError> {
    let bytes = raw
        .get(*pos..*pos + 2)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack integer".into()))?;
    *pos += 2;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(raw: &[u8], pos: &mut usize) -> Result<u32, RnshError> {
    let bytes = raw
        .get(*pos..*pos + 4)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack integer".into()))?;
    *pos += 4;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(raw: &[u8], pos: &mut usize) -> Result<u64, RnshError> {
    let bytes = raw
        .get(*pos..*pos + 8)
        .ok_or_else(|| RnshError::Protocol("truncated msgpack integer".into()))?;
    *pos += 8;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[derive(Debug, Clone, PartialEq)]
struct WindowSize {
    rows: Option<u16>,
    cols: Option<u16>,
    hpix: Option<u16>,
    vpix: Option<u16>,
}

#[derive(Debug, Clone, PartialEq)]
struct ExecuteCommand {
    cmdline: Vec<String>,
    pipe_stdin: bool,
    pipe_stdout: bool,
    pipe_stderr: bool,
    term: Option<String>,
    rows: Option<u16>,
    cols: Option<u16>,
    hpix: Option<u16>,
    vpix: Option<u16>,
}

#[derive(Debug, Clone, PartialEq)]
enum RnshMessage {
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
    fn msgtype(&self) -> u16 {
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

    fn pack(&self) -> Vec<u8> {
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

    fn unpack(msgtype: u16, payload: &[u8]) -> Result<Self, RnshError> {
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

fn pack_msgpack_array(values: Vec<MsgValue>) -> Vec<u8> {
    let mut out = Vec::new();
    msgpack_pack(&MsgValue::Array(values), &mut out);
    out
}

fn opt_u16(value: Option<u16>) -> MsgValue {
    value
        .map(|v| MsgValue::Int(v as i64))
        .unwrap_or(MsgValue::Nil)
}

fn expect_array(value: MsgValue, len: usize) -> Result<Vec<MsgValue>, RnshError> {
    match value {
        MsgValue::Array(values) if values.len() == len => Ok(values),
        _ => Err(RnshError::Protocol("unexpected msgpack array".into())),
    }
}

fn expect_array_value(value: &MsgValue) -> Result<&[MsgValue], RnshError> {
    match value {
        MsgValue::Array(values) => Ok(values),
        _ => Err(RnshError::Protocol("expected msgpack array".into())),
    }
}

fn expect_string(value: &MsgValue) -> Result<String, RnshError> {
    match value {
        MsgValue::String(s) => Ok(s.clone()),
        _ => Err(RnshError::Protocol("expected msgpack string".into())),
    }
}

fn opt_string(value: &MsgValue) -> Result<Option<String>, RnshError> {
    match value {
        MsgValue::Nil => Ok(None),
        MsgValue::String(s) => Ok(Some(s.clone())),
        _ => Err(RnshError::Protocol(
            "expected optional msgpack string".into(),
        )),
    }
}

fn expect_bool(value: &MsgValue) -> Result<bool, RnshError> {
    match value {
        MsgValue::Bool(v) => Ok(*v),
        _ => Err(RnshError::Protocol("expected msgpack bool".into())),
    }
}

fn expect_int(value: &MsgValue) -> Result<i64, RnshError> {
    match value {
        MsgValue::Int(v) => Ok(*v),
        _ => Err(RnshError::Protocol("expected msgpack int".into())),
    }
}

fn opt_int_u16(value: &MsgValue) -> Result<Option<u16>, RnshError> {
    match value {
        MsgValue::Nil => Ok(None),
        MsgValue::Int(v) if *v >= 0 && *v <= u16::MAX as i64 => Ok(Some(*v as u16)),
        _ => Err(RnshError::Protocol("expected optional u16".into())),
    }
}

#[derive(Debug)]
enum RnshEvent {
    Announce(rns_net::AnnouncedIdentity),
    LinkEstablished {
        link_id: [u8; 16],
        is_initiator: bool,
    },
    LinkClosed([u8; 16]),
    RemoteIdentified {
        link_id: [u8; 16],
        identity_hash: IdentityHash,
    },
    ChannelMessage {
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
    },
    ProcessOutput {
        link_id: [u8; 16],
        stream_id: u16,
        data: Vec<u8>,
    },
    ProcessExited {
        link_id: [u8; 16],
        code: i32,
    },
    LocalStdin(Vec<u8>),
    LocalStdinEof,
}

struct RnshCallbacks {
    tx: mpsc::Sender<RnshEvent>,
}

impl Callbacks for RnshCallbacks {
    fn on_announce(&mut self, announced: rns_net::AnnouncedIdentity) {
        let _ = self.tx.send(RnshEvent::Announce(announced));
    }

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(
        &mut self,
        _dest_hash: DestHash,
        _raw: Vec<u8>,
        _packet_hash: rns_net::PacketHash,
    ) {
    }

    fn on_link_established(
        &mut self,
        link_id: rns_net::LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        is_initiator: bool,
    ) {
        let _ = self.tx.send(RnshEvent::LinkEstablished {
            link_id: link_id.0,
            is_initiator,
        });
    }

    fn on_link_closed(
        &mut self,
        link_id: rns_net::LinkId,
        _reason: Option<rns_net::TeardownReason>,
    ) {
        let _ = self.tx.send(RnshEvent::LinkClosed(link_id.0));
    }

    fn on_remote_identified(
        &mut self,
        link_id: rns_net::LinkId,
        identity_hash: IdentityHash,
        _public_key: [u8; 64],
    ) {
        let _ = self.tx.send(RnshEvent::RemoteIdentified {
            link_id: link_id.0,
            identity_hash,
        });
    }

    fn on_channel_message(&mut self, link_id: rns_net::LinkId, msgtype: u16, payload: Vec<u8>) {
        let _ = self.tx.send(RnshEvent::ChannelMessage {
            link_id: link_id.0,
            msgtype,
            payload,
        });
    }
}

trait RnshTransport {
    fn send_rnsh_message(&self, link_id: [u8; 16], message: &RnshMessage) -> Result<(), RnshError>;

    fn teardown_rnsh_link(&self, link_id: [u8; 16]) -> Result<(), RnshError>;
}

impl RnshTransport for RnsNode {
    fn send_rnsh_message(&self, link_id: [u8; 16], message: &RnshMessage) -> Result<(), RnshError> {
        self.send_channel_message(link_id, message.msgtype(), message.pack())?;
        Ok(())
    }

    fn teardown_rnsh_link(&self, link_id: [u8; 16]) -> Result<(), RnshError> {
        self.teardown_link(link_id)?;
        Ok(())
    }
}

struct ChildProcess {
    pid: libc::pid_t,
    stdin_fd: Option<RawFd>,
    stdout_fd: Option<RawFd>,
    stderr_fd: Option<RawFd>,
}

impl ChildProcess {
    fn spawn(
        link_id: [u8; 16],
        argv: &[String],
        env_overrides: &[(&str, String)],
        flags: &ExecuteCommand,
        event_tx: mpsc::Sender<RnshEvent>,
    ) -> io::Result<Self> {
        if argv.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty command"));
        }

        let use_pty = !(flags.pipe_stdin && flags.pipe_stdout && flags.pipe_stderr);
        let mut pty_master = None;
        let mut pty_child = None;
        if use_pty {
            let mut master: libc::c_int = -1;
            let mut child: libc::c_int = -1;
            let rc = unsafe {
                libc::openpty(
                    &mut master,
                    &mut child,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            pty_master = Some(master);
            pty_child = Some(child);
        }

        let stdin_pipe = if flags.pipe_stdin {
            Some(pipe_pair()?)
        } else {
            None
        };
        let stdout_pipe = if flags.pipe_stdout {
            Some(pipe_pair()?)
        } else {
            None
        };
        let stderr_pipe = if flags.pipe_stderr {
            Some(pipe_pair()?)
        } else {
            None
        };

        let child_stdin = stdin_pipe.map(|p| p.0).or(pty_child).unwrap_or(-1);
        let parent_stdin = stdin_pipe.map(|p| p.1).or(pty_master).unwrap_or(-1);
        let parent_stdout = stdout_pipe.map(|p| p.0).or(pty_master).unwrap_or(-1);
        let child_stdout = stdout_pipe.map(|p| p.1).or(pty_child).unwrap_or(-1);
        let parent_stderr = stderr_pipe.map(|p| p.0).or(pty_master).unwrap_or(-1);
        let child_stderr = stderr_pipe.map(|p| p.1).or(pty_child).unwrap_or(-1);

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            unsafe {
                if use_pty {
                    libc::setsid();
                }
                libc::dup2(child_stdin, 0);
                libc::dup2(child_stdout, 1);
                libc::dup2(child_stderr, 2);
                if use_pty {
                    let tty_fd = if !flags.pipe_stdin {
                        0
                    } else if !flags.pipe_stdout {
                        1
                    } else {
                        2
                    };
                    libc::ioctl(tty_fd, libc::TIOCSCTTY, 0);
                }
                for fd in 3..1024 {
                    libc::close(fd);
                }
                for (key, value) in env_overrides {
                    if let (Ok(k), Ok(v)) = (CString::new(*key), CString::new(value.as_str())) {
                        libc::setenv(k.as_ptr(), v.as_ptr(), 1);
                    }
                }
                let c_args = argv
                    .iter()
                    .map(|arg| CString::new(arg.as_str()))
                    .collect::<Result<Vec<_>, _>>();
                if let Ok(c_args) = c_args {
                    let mut ptrs = c_args.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
                    ptrs.push(std::ptr::null());
                    libc::execvp(ptrs[0], ptrs.as_ptr());
                }
                libc::_exit(255);
            }
        }

        close_unique(&[
            pty_child,
            stdin_pipe.map(|p| p.0),
            stdout_pipe.map(|p| p.1),
            stderr_pipe.map(|p| p.1),
        ]);

        let stdout_fd = if parent_stdout >= 0 {
            Some(parent_stdout)
        } else {
            None
        };
        let stderr_fd = if parent_stderr >= 0 && Some(parent_stderr) != stdout_fd {
            Some(parent_stderr)
        } else {
            None
        };

        if let Some(fd) = stdout_fd {
            spawn_reader(link_id, STREAM_STDOUT, fd, event_tx.clone());
        }
        if let Some(fd) = stderr_fd {
            spawn_reader(link_id, STREAM_STDERR, fd, event_tx.clone());
        }
        spawn_waiter(link_id, pid, event_tx);

        Ok(ChildProcess {
            pid,
            stdin_fd: (parent_stdin >= 0).then_some(parent_stdin),
            stdout_fd,
            stderr_fd,
        })
    }

    fn write_stdin(&self, data: &[u8]) {
        if let Some(fd) = self.stdin_fd {
            let _ = write_all_fd(fd, data);
        }
    }

    fn close_stdin(&mut self) {
        if let Some(fd) = self.stdin_fd.take() {
            if Some(fd) == self.stdout_fd || Some(fd) == self.stderr_fd {
                let _ = write_all_fd(fd, b"\x04");
                self.stdin_fd = Some(fd);
            } else {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }

    fn set_winsize(&self, size: &WindowSize) {
        let Some(fd) = self.stdout_fd.or(self.stdin_fd) else {
            return;
        };
        let ws = libc::winsize {
            ws_row: size.rows.unwrap_or(0),
            ws_col: size.cols.unwrap_or(0),
            ws_xpixel: size.hpix.unwrap_or(0),
            ws_ypixel: size.vpix.unwrap_or(0),
        };
        unsafe {
            libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
        }
    }

    fn terminate(&mut self) {
        unsafe {
            libc::kill(self.pid, libc::SIGTERM);
        }
        self.close_stdin();
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        close_unique(&[
            self.stdin_fd.take(),
            self.stdout_fd.take(),
            self.stderr_fd.take(),
        ]);
    }
}

fn pipe_pair() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn close_unique(fds: &[Option<RawFd>]) {
    let mut seen = HashSet::new();
    for fd in fds.iter().flatten().copied() {
        if fd >= 0 && seen.insert(fd) {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

fn spawn_reader(link_id: [u8; 16], stream_id: u16, fd: RawFd, event_tx: mpsc::Sender<RnshEvent>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                let _ = event_tx.send(RnshEvent::ProcessOutput {
                    link_id,
                    stream_id,
                    data: buf[..n as usize].to_vec(),
                });
            } else {
                break;
            }
        }
    });
}

fn spawn_waiter(link_id: [u8; 16], pid: libc::pid_t, event_tx: mpsc::Sender<RnshEvent>) {
    std::thread::spawn(move || {
        let mut status = 0;
        let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            255
        };
        let _ = event_tx.send(RnshEvent::ProcessExited { link_id, code });
    });
}

fn write_all_fd(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        data = &data[n as usize..];
    }
    Ok(())
}

struct TtyRestorer {
    fd: RawFd,
    original: Option<libc::termios>,
}

impl TtyRestorer {
    fn new(fd: RawFd) -> Self {
        let mut original = unsafe { std::mem::zeroed() };
        let original = if unsafe { libc::tcgetattr(fd, &mut original) } == 0 {
            Some(original)
        } else {
            None
        };
        TtyRestorer { fd, original }
    }

    fn raw(&self) {
        let Some(mut raw) = self.original else {
            return;
        };
        unsafe {
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(self.fd, libc::TCSANOW, &raw);
        }
    }
}

impl Drop for TtyRestorer {
    fn drop(&mut self) {
        if let Some(original) = self.original {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSADRAIN, &original);
            }
        }
    }
}

fn current_winsize(fd: RawFd) -> WindowSize {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 {
        WindowSize {
            rows: nonzero_u16(ws.ws_row),
            cols: nonzero_u16(ws.ws_col),
            hpix: nonzero_u16(ws.ws_xpixel),
            vpix: nonzero_u16(ws.ws_ypixel),
        }
    } else {
        WindowSize {
            rows: None,
            cols: None,
            hpix: None,
            vpix: None,
        }
    }
}

fn nonzero_u16(value: u16) -> Option<u16> {
    (value != 0).then_some(value)
}

#[derive(Clone)]
struct ListenerConfig {
    default_command: Vec<String>,
    allow_all: bool,
    allowed: HashSet<[u8; 16]>,
    allow_remote_command: bool,
    remote_command_as_args: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerState {
    WaitIdent,
    WaitVersion,
    WaitCommand,
    Running,
    Closed,
}

struct ListenerSession {
    link_id: [u8; 16],
    state: ListenerState,
    remote_identity: Option<IdentityHash>,
    config: ListenerConfig,
    process: Option<ChildProcess>,
}

impl ListenerSession {
    fn new(link_id: [u8; 16], config: ListenerConfig) -> Self {
        let state = if config.allow_all {
            ListenerState::WaitVersion
        } else {
            ListenerState::WaitIdent
        };
        ListenerSession {
            link_id,
            state,
            remote_identity: None,
            config,
            process: None,
        }
    }

    fn remote_identified(&mut self, transport: &dyn RnshTransport, identity_hash: IdentityHash) {
        if !self.config.allow_all && !self.config.allowed.contains(&identity_hash.0) {
            let _ = send_message(
                transport,
                self.link_id,
                &RnshMessage::Error {
                    msg: "Identity is not allowed.".into(),
                    fatal: true,
                },
            );
            let _ = transport.teardown_rnsh_link(self.link_id);
            self.state = ListenerState::Closed;
            return;
        }
        self.remote_identity = Some(identity_hash);
        if self.state == ListenerState::WaitIdent {
            self.state = ListenerState::WaitVersion;
        }
    }

    fn handle_message(
        &mut self,
        transport: &dyn RnshTransport,
        event_tx: &mpsc::Sender<RnshEvent>,
        msgtype: u16,
        payload: Vec<u8>,
    ) {
        if self.state == ListenerState::WaitIdent {
            return;
        }
        let message = match RnshMessage::unpack(msgtype, &payload) {
            Ok(message) => message,
            Err(err) => {
                self.protocol_error(transport, &err.to_string());
                return;
            }
        };
        match self.state {
            ListenerState::WaitVersion => match message {
                RnshMessage::VersionInfo {
                    protocol_version, ..
                } if protocol_version == PROTOCOL_VERSION => {
                    let _ = send_message(transport, self.link_id, &version_message());
                    self.state = ListenerState::WaitCommand;
                }
                RnshMessage::VersionInfo { .. } => {
                    self.protocol_error(transport, "Incompatible protocol");
                }
                _ => self.protocol_error(transport, "expected version info"),
            },
            ListenerState::WaitCommand => match message {
                RnshMessage::ExecuteCommand(command) => {
                    if let Err(err) = self.start_command(transport, event_tx, command) {
                        self.protocol_error(transport, &format!("Unable to start process: {err}"));
                    } else {
                        self.state = ListenerState::Running;
                    }
                }
                _ => self.protocol_error(transport, "expected execute command"),
            },
            ListenerState::Running => match message {
                RnshMessage::WindowSize(size) => {
                    if let Some(process) = &self.process {
                        process.set_winsize(&size);
                    }
                }
                RnshMessage::StreamData(data) if data.stream_id == STREAM_STDIN => {
                    if let Some(process) = &mut self.process {
                        if !data.data.is_empty() {
                            process.write_stdin(&data.data);
                        }
                        if data.eof {
                            process.close_stdin();
                        }
                    }
                }
                RnshMessage::Noop => {
                    let _ = send_message(transport, self.link_id, &RnshMessage::Noop);
                }
                _ => self.protocol_error(transport, "unexpected message while running"),
            },
            ListenerState::WaitIdent | ListenerState::Closed => {}
        }
    }

    fn start_command(
        &mut self,
        transport: &dyn RnshTransport,
        event_tx: &mpsc::Sender<RnshEvent>,
        command: ExecuteCommand,
    ) -> Result<(), RnshError> {
        if !self.config.allow_remote_command && !command.cmdline.is_empty() {
            let _ = send_message(
                transport,
                self.link_id,
                &RnshMessage::Error {
                    msg: "Remote command line not allowed by listener".into(),
                    fatal: true,
                },
            );
            return Err(RnshError::Protocol(
                "remote command line not allowed by listener".into(),
            ));
        }

        let mut argv = self.config.default_command.clone();
        if self.config.remote_command_as_args && !command.cmdline.is_empty() {
            argv.extend(command.cmdline.clone());
        } else if !command.cmdline.is_empty() {
            argv = command.cmdline.clone();
        }

        let remote_identity = self
            .remote_identity
            .as_ref()
            .map(|ih| prettyhexrep(&ih.0))
            .unwrap_or_default();
        let env = [
            (
                "TERM",
                command
                    .term
                    .clone()
                    .or_else(|| std::env::var("TERM").ok())
                    .unwrap_or_else(|| "xterm".into()),
            ),
            ("RNS_REMOTE_IDENTITY", remote_identity),
        ];
        let process = ChildProcess::spawn(self.link_id, &argv, &env, &command, event_tx.clone())?;
        process.set_winsize(&WindowSize {
            rows: command.rows,
            cols: command.cols,
            hpix: command.hpix,
            vpix: command.vpix,
        });
        self.process = Some(process);
        Ok(())
    }

    fn protocol_error(&mut self, transport: &dyn RnshTransport, message: &str) {
        let _ = send_message(
            transport,
            self.link_id,
            &RnshMessage::Error {
                msg: message.into(),
                fatal: true,
            },
        );
        let _ = transport.teardown_rnsh_link(self.link_id);
        if let Some(process) = &mut self.process {
            process.terminate();
        }
        self.state = ListenerState::Closed;
    }
}

fn listen(opts: CliOptions) -> Result<(), RnshError> {
    let (event_tx, event_rx) = mpsc::channel();
    let node = RnsNode::connect_shared_from_config(
        opts.config.as_deref().map(Path::new),
        Box::new(RnshCallbacks {
            tx: event_tx.clone(),
        }),
    )?;

    let service = opts.service.as_deref().unwrap_or(DEFAULT_SERVICE_NAME);
    let identity = prepare_identity(
        opts.config.as_deref(),
        opts.identity.as_deref(),
        Some(service),
    )?;
    let identity_hash = IdentityHash(*identity.hash());
    let dest = Destination::single_in(APP_NAME, &[], identity_hash);
    let (sig_prv, sig_pub) = extract_sig_keys(&identity)?;
    node.register_destination_with_proof(
        &dest,
        Some(
            identity.get_private_key().ok_or_else(|| {
                RnshError::Protocol("listener identity has no private key".into())
            })?,
        ),
    )?;
    node.register_link_destination(dest.hash.0, sig_prv, sig_pub, 0)?;

    eprintln!("rnsh listening on {}", prettyhexrep(&dest.hash.0));

    let allowed = load_allowed_identities(&opts)?;
    if allowed.is_empty() && !opts.no_auth {
        eprintln!("warning: no allowed identities configured; no initiators will be accepted");
    }

    let default_command = if opts.command.is_empty() {
        vec![std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())]
    } else {
        opts.command.clone()
    };
    let config = ListenerConfig {
        default_command,
        allow_all: opts.no_auth,
        allowed,
        allow_remote_command: !opts.no_remote_command,
        remote_command_as_args: opts.remote_command_as_args,
    };

    let mut sessions: HashMap<[u8; 16], ListenerSession> = HashMap::new();
    let mut last_announce = Instant::now() - Duration::from_secs(24 * 60 * 60);
    let mut announced_once = false;

    loop {
        if let Some(period) = opts.announce_period {
            let due = period == 0 && !announced_once
                || period > 0 && last_announce.elapsed() >= Duration::from_secs(period);
            if due {
                node.announce(&dest, &identity, None)?;
                last_announce = Instant::now();
                announced_once = true;
            }
        }

        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::LinkEstablished {
                link_id,
                is_initiator: false,
                ..
            }) => {
                sessions
                    .entry(link_id)
                    .or_insert_with(|| ListenerSession::new(link_id, config.clone()));
            }
            Ok(RnshEvent::RemoteIdentified {
                link_id,
                identity_hash,
            }) => {
                if let Some(session) = sessions.get_mut(&link_id) {
                    session.remote_identified(&node, identity_hash);
                }
            }
            Ok(RnshEvent::ChannelMessage {
                link_id,
                msgtype,
                payload,
            }) => {
                if let Some(session) = sessions.get_mut(&link_id) {
                    session.handle_message(&node, &event_tx, msgtype, payload);
                }
            }
            Ok(RnshEvent::ProcessOutput {
                link_id,
                stream_id,
                data,
            }) => {
                send_stream_chunks(&node, link_id, stream_id, &data, false)?;
            }
            Ok(RnshEvent::ProcessExited { link_id, code }) => {
                send_stream_chunks(&node, link_id, STREAM_STDOUT, &[], true)?;
                let _ = send_message(&node, link_id, &RnshMessage::CommandExited(code));
                sessions.remove(&link_id);
            }
            Ok(RnshEvent::LinkClosed(link_id)) => {
                if let Some(mut session) = sessions.remove(&link_id) {
                    if let Some(process) = &mut session.process {
                        process.terminate();
                    }
                }
            }
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

fn initiate(opts: CliOptions) -> Result<i32, RnshError> {
    let dest_hash = parse_hash_16(
        opts.destination
            .as_deref()
            .ok_or_else(|| RnshError::Protocol("missing destination".into()))?,
    )
    .ok_or_else(|| RnshError::Protocol("destination must be 32 hexadecimal characters".into()))?;
    let timeout = Duration::from_secs_f64(opts.timeout.unwrap_or(15.0));
    let (event_tx, event_rx) = mpsc::channel();
    let node = RnsNode::connect_shared_from_config(
        opts.config.as_deref().map(Path::new),
        Box::new(RnshCallbacks {
            tx: event_tx.clone(),
        }),
    )?;
    let identity = prepare_identity(opts.config.as_deref(), opts.identity.as_deref(), None)?;

    wait_for_path(&node, dest_hash, &event_rx, timeout)?;
    let recalled = node
        .recall_identity(&DestHash(dest_hash))?
        .ok_or_else(|| RnshError::Protocol("destination identity was not recalled".into()))?;
    let mut sig_pub = [0u8; 32];
    sig_pub.copy_from_slice(&recalled.public_key[32..64]);

    let link_id = node.create_link(dest_hash, sig_pub)?;
    wait_for_link(&event_rx, link_id, timeout)?;
    if !opts.no_id {
        node.identify_on_link(
            link_id,
            identity
                .get_private_key()
                .ok_or_else(|| RnshError::Protocol("identity has no private key".into()))?,
        )?;
    }

    send_message(&node, link_id, &version_message())?;
    wait_for_version(&event_rx, timeout)?;

    let stdin_is_tty = io::stdin().is_terminal();
    let stdout_is_tty = io::stdout().is_terminal();
    let stderr_is_tty = io::stderr().is_terminal();
    let size = current_winsize(0);
    let execute = ExecuteCommand {
        cmdline: opts.command.clone(),
        pipe_stdin: !stdin_is_tty,
        pipe_stdout: !stdout_is_tty,
        pipe_stderr: !stderr_is_tty,
        term: std::env::var("TERM").ok(),
        rows: size.rows,
        cols: size.cols,
        hpix: size.hpix,
        vpix: size.vpix,
    };
    send_message(&node, link_id, &RnshMessage::ExecuteCommand(execute))?;

    let tty = stdin_is_tty.then(|| {
        let restorer = TtyRestorer::new(0);
        restorer.raw();
        unsafe {
            libc::signal(libc::SIGWINCH, sigwinch_handler as *const () as usize);
        }
        restorer
    });
    let _keep_tty = tty;
    spawn_stdin_reader(event_tx);

    loop {
        if SIGWINCH_SEEN.swap(false, Ordering::SeqCst) {
            let _ = send_message(&node, link_id, &RnshMessage::WindowSize(current_winsize(0)));
        }
        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::ChannelMessage {
                msgtype, payload, ..
            }) => match RnshMessage::unpack(msgtype, &payload)? {
                RnshMessage::StreamData(data) if data.stream_id == STREAM_STDOUT => {
                    io::stdout().write_all(&data.data)?;
                    io::stdout().flush()?;
                }
                RnshMessage::StreamData(data) if data.stream_id == STREAM_STDERR => {
                    io::stderr().write_all(&data.data)?;
                    io::stderr().flush()?;
                }
                RnshMessage::CommandExited(code) => return Ok(code),
                RnshMessage::Error { msg, fatal } => {
                    eprintln!("remote error: {msg}");
                    if fatal {
                        return Ok(200);
                    }
                }
                _ => {}
            },
            Ok(RnshEvent::LocalStdin(data)) => {
                send_stream_chunks(&node, link_id, STREAM_STDIN, &data, false)?;
            }
            Ok(RnshEvent::LocalStdinEof) => {
                send_stream_chunks(&node, link_id, STREAM_STDIN, &[], true)?;
            }
            Ok(RnshEvent::LinkClosed(_)) => return Ok(0),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
        }
    }
}

fn send_message(
    transport: &dyn RnshTransport,
    link_id: [u8; 16],
    message: &RnshMessage,
) -> Result<(), RnshError> {
    transport.send_rnsh_message(link_id, message)
}

fn send_stream_chunks(
    transport: &dyn RnshTransport,
    link_id: [u8; 16],
    stream_id: u16,
    data: &[u8],
    eof: bool,
) -> Result<(), RnshError> {
    for chunk in data.chunks(STREAM_CHUNK_MAX) {
        let msg = RnshMessage::StreamData(StreamDataMessage::new(
            stream_id,
            chunk.to_vec(),
            false,
            false,
        ));
        send_message(transport, link_id, &msg)?;
    }
    if eof {
        let msg =
            RnshMessage::StreamData(StreamDataMessage::new(stream_id, Vec::new(), true, false));
        send_message(transport, link_id, &msg)?;
    }
    Ok(())
}

fn version_message() -> RnshMessage {
    RnshMessage::VersionInfo {
        sw_version: VERSION.into(),
        protocol_version: PROTOCOL_VERSION,
    }
}

fn wait_for_path(
    node: &RnsNode,
    dest_hash: [u8; 16],
    event_rx: &mpsc::Receiver<RnshEvent>,
    timeout: Duration,
) -> Result<(), RnshError> {
    let started = Instant::now();
    if !node.has_path(&DestHash(dest_hash))? {
        node.request_path(&DestHash(dest_hash))?;
    }
    while started.elapsed() < timeout {
        if node.has_path(&DestHash(dest_hash))? {
            return Ok(());
        }
        if let Ok(RnshEvent::Announce(announced)) =
            event_rx.recv_timeout(Duration::from_millis(250))
        {
            if announced.dest_hash.0 == dest_hash {
                return Ok(());
            }
        }
    }
    Err(RnshError::Protocol("path not found".into()))
}

fn wait_for_link(
    event_rx: &mpsc::Receiver<RnshEvent>,
    expected_link: [u8; 16],
    timeout: Duration,
) -> Result<(), RnshError> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::LinkEstablished {
                link_id,
                is_initiator: true,
                ..
            }) if link_id == expected_link => return Ok(()),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Err(RnshError::Protocol("link establishment timed out".into()))
}

fn wait_for_version(
    event_rx: &mpsc::Receiver<RnshEvent>,
    timeout: Duration,
) -> Result<(), RnshError> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::ChannelMessage {
                msgtype, payload, ..
            }) => match RnshMessage::unpack(msgtype, &payload)? {
                RnshMessage::VersionInfo {
                    protocol_version, ..
                } if protocol_version == PROTOCOL_VERSION => return Ok(()),
                RnshMessage::Error { msg, .. } => return Err(RnshError::Protocol(msg)),
                _ => {}
            },
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Err(RnshError::Protocol(
        "protocol version exchange timed out".into(),
    ))
}

fn spawn_stdin_reader(event_tx: mpsc::Sender<RnshEvent>) {
    std::thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = event_tx.send(RnshEvent::LocalStdinEof);
                    break;
                }
                Ok(n) => {
                    let _ = event_tx.send(RnshEvent::LocalStdin(buf[..n].to_vec()));
                }
                Err(_) => {
                    let _ = event_tx.send(RnshEvent::LocalStdinEof);
                    break;
                }
            }
        }
    });
}

fn prepare_identity(
    config: Option<&str>,
    explicit_path: Option<&str>,
    service: Option<&str>,
) -> Result<Identity, RnshError> {
    let path = if let Some(path) = explicit_path {
        PathBuf::from(path)
    } else {
        let config_dir = rns_net::storage::resolve_config_dir(config.map(Path::new));
        let paths = rns_net::storage::ensure_storage_dirs(&config_dir)?;
        let suffix = service.map(sanitize_service_name).unwrap_or_default();
        let filename = if suffix.is_empty() {
            APP_NAME.to_string()
        } else {
            format!("{APP_NAME}.{suffix}")
        };
        paths.identities.join(filename)
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        Ok(rns_net::storage::load_identity(&path)?)
    } else {
        let identity = Identity::new(&mut OsRng);
        rns_net::storage::save_identity(&identity, &path)?;
        Ok(identity)
    }
}

fn print_identity(opts: &CliOptions) -> Result<(), RnshError> {
    let identity = prepare_identity(
        opts.config.as_deref(),
        opts.identity.as_deref(),
        opts.service.as_deref(),
    )?;
    println!("Identity     : {}", prettyhexrep(identity.hash()));
    if opts.listen {
        let dest = Destination::single_in(APP_NAME, &[], IdentityHash(*identity.hash()));
        println!("Listening on : {}", prettyhexrep(&dest.hash.0));
    }
    Ok(())
}

fn load_allowed_identities(opts: &CliOptions) -> Result<HashSet<[u8; 16]>, RnshError> {
    let mut allowed = HashSet::new();
    for entry in &opts.allowed {
        if let Some(hash) = parse_hash_16(entry) {
            allowed.insert(hash);
        } else {
            return Err(RnshError::Protocol(format!(
                "invalid allowed identity hash: {entry}"
            )));
        }
    }
    for path in allowed_identity_files() {
        if !path.exists() {
            continue;
        }
        let contents = fs::read_to_string(path)?;
        for line in contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if let Some(hash) = parse_hash_16(line) {
                allowed.insert(hash);
            }
        }
    }
    Ok(allowed)
}

fn allowed_identity_files() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    vec![
        PathBuf::from(&home)
            .join(".config")
            .join("rnsh")
            .join("allowed_identities"),
        PathBuf::from(home).join(".rnsh").join("allowed_identities"),
    ]
}

fn sanitize_service_name(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

fn parse_hash_16(value: &str) -> Option<[u8; 16]> {
    let s = value.trim();
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn extract_sig_keys(identity: &Identity) -> Result<([u8; 32], [u8; 32]), RnshError> {
    let private = identity
        .get_private_key()
        .ok_or_else(|| RnshError::Protocol("identity has no private key".into()))?;
    let public = identity
        .get_public_key()
        .ok_or_else(|| RnshError::Protocol("identity has no public key".into()))?;
    let mut sig_prv = [0u8; 32];
    let mut sig_pub = [0u8; 32];
    sig_prv.copy_from_slice(&private[32..64]);
    sig_pub.copy_from_slice(&public[32..64]);
    Ok((sig_prv, sig_pub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const TEST_LINK: [u8; 16] = [0x42; 16];

    #[derive(Default)]
    struct FakeTransport {
        sent: Mutex<Vec<([u8; 16], u16, Vec<u8>)>>,
        teardowns: Mutex<Vec<[u8; 16]>>,
    }

    impl FakeTransport {
        fn sent_messages(&self) -> Vec<([u8; 16], RnshMessage)> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .map(|(link_id, msgtype, payload)| {
                    (
                        *link_id,
                        RnshMessage::unpack(*msgtype, payload)
                            .expect("fake transport stored decodable message"),
                    )
                })
                .collect()
        }
    }

    impl RnshTransport for FakeTransport {
        fn send_rnsh_message(
            &self,
            link_id: [u8; 16],
            message: &RnshMessage,
        ) -> Result<(), RnshError> {
            self.sent
                .lock()
                .unwrap()
                .push((link_id, message.msgtype(), message.pack()));
            Ok(())
        }

        fn teardown_rnsh_link(&self, link_id: [u8; 16]) -> Result<(), RnshError> {
            self.teardowns.lock().unwrap().push(link_id);
            Ok(())
        }
    }

    fn test_config() -> ListenerConfig {
        ListenerConfig {
            default_command: vec!["/bin/cat".into()],
            allow_all: true,
            allowed: HashSet::new(),
            allow_remote_command: true,
            remote_command_as_args: false,
        }
    }

    fn exec_msg(cmdline: Vec<&str>) -> RnshMessage {
        RnshMessage::ExecuteCommand(ExecuteCommand {
            cmdline: cmdline.into_iter().map(str::to_string).collect(),
            pipe_stdin: true,
            pipe_stdout: true,
            pipe_stderr: true,
            term: Some("xterm".into()),
            rows: Some(24),
            cols: Some(80),
            hpix: None,
            vpix: None,
        })
    }

    #[test]
    fn msgpack_version_matches_upstream_shape() {
        let msg = RnshMessage::VersionInfo {
            sw_version: "1.2.0".into(),
            protocol_version: 1,
        };
        let packed = msg.pack();
        assert_eq!(packed, b"\x92\xa51.2.0\x01");
        assert_eq!(RnshMessage::unpack(MSG_VERSION_INFO, &packed).unwrap(), msg);
    }

    #[test]
    fn execute_command_roundtrips() {
        let msg = RnshMessage::ExecuteCommand(ExecuteCommand {
            cmdline: vec!["/bin/sh".into(), "-lc".into(), "echo hi".into()],
            pipe_stdin: true,
            pipe_stdout: true,
            pipe_stderr: false,
            term: Some("xterm-256color".into()),
            rows: Some(24),
            cols: Some(80),
            hpix: None,
            vpix: None,
        });
        let packed = msg.pack();
        assert_eq!(
            RnshMessage::unpack(MSG_EXECUTE_COMMAND, &packed).unwrap(),
            msg
        );
    }

    #[test]
    fn stream_data_uses_upstream_header_bits() {
        let msg = RnshMessage::StreamData(StreamDataMessage::new(2, b"err".to_vec(), true, false));
        let packed = msg.pack();
        assert_eq!(&packed[..2], &0x8002u16.to_be_bytes());
        assert_eq!(RnshMessage::unpack(MSG_STREAM_DATA, &packed).unwrap(), msg);
    }

    #[test]
    fn cli_splits_command_after_double_dash() {
        let args = CliOptions::parse(vec![
            "-l".into(),
            "-s".into(),
            "ops".into(),
            "--".into(),
            "/bin/sh".into(),
            "-l".into(),
        ])
        .unwrap();
        assert!(args.listen);
        assert_eq!(args.service.as_deref(), Some("ops"));
        assert_eq!(args.command, vec!["/bin/sh", "-l"]);
    }

    #[test]
    fn service_name_is_sanitized_like_upstream() {
        assert_eq!(sanitize_service_name("dev-shell_1!"), "devshell1");
    }

    #[test]
    fn listener_rejects_unallowed_identity_and_tears_down() {
        let mut allowed = HashSet::new();
        allowed.insert([0x11; 16]);
        let config = ListenerConfig {
            allow_all: false,
            allowed,
            ..test_config()
        };
        let fake = FakeTransport::default();
        let mut session = ListenerSession::new(TEST_LINK, config);

        assert_eq!(session.state, ListenerState::WaitIdent);
        session.remote_identified(&fake, IdentityHash([0x22; 16]));

        assert_eq!(session.state, ListenerState::Closed);
        assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
        let messages = fake.sent_messages();
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            &messages[0].1,
            RnshMessage::Error { msg, fatal: true } if msg == "Identity is not allowed."
        ));
    }

    #[test]
    fn listener_accepts_allowed_identity_and_completes_version_handshake() {
        let mut allowed = HashSet::new();
        allowed.insert([0x11; 16]);
        let config = ListenerConfig {
            allow_all: false,
            allowed,
            ..test_config()
        };
        let fake = FakeTransport::default();
        let (tx, _rx) = mpsc::channel();
        let mut session = ListenerSession::new(TEST_LINK, config);

        session.remote_identified(&fake, IdentityHash([0x11; 16]));
        assert_eq!(session.state, ListenerState::WaitVersion);
        let version = version_message();
        session.handle_message(&fake, &tx, version.msgtype(), version.pack());

        assert_eq!(session.state, ListenerState::WaitCommand);
        let messages = fake.sent_messages();
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            &messages[0].1,
            RnshMessage::VersionInfo {
                protocol_version: PROTOCOL_VERSION,
                ..
            }
        ));
    }

    #[test]
    fn listener_rejects_incompatible_protocol_version() {
        let fake = FakeTransport::default();
        let (tx, _rx) = mpsc::channel();
        let mut session = ListenerSession::new(TEST_LINK, test_config());
        let msg = RnshMessage::VersionInfo {
            sw_version: "future".into(),
            protocol_version: PROTOCOL_VERSION + 1,
        };

        session.handle_message(&fake, &tx, msg.msgtype(), msg.pack());

        assert_eq!(session.state, ListenerState::Closed);
        assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
        assert!(matches!(
            &fake.sent_messages()[0].1,
            RnshMessage::Error { msg, fatal: true } if msg == "Incompatible protocol"
        ));
    }

    #[test]
    fn listener_rejects_remote_command_when_disabled() {
        let fake = FakeTransport::default();
        let (tx, _rx) = mpsc::channel();
        let config = ListenerConfig {
            allow_remote_command: false,
            ..test_config()
        };
        let mut session = ListenerSession::new(TEST_LINK, config);
        let version = version_message();
        session.handle_message(&fake, &tx, version.msgtype(), version.pack());
        let exec = exec_msg(vec!["/bin/echo", "nope"]);

        session.handle_message(&fake, &tx, exec.msgtype(), exec.pack());

        assert_eq!(session.state, ListenerState::Closed);
        assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
        assert!(fake.sent_messages().iter().any(|(_, msg)| matches!(
            msg,
            RnshMessage::Error { msg, fatal: true }
                if msg.contains("Remote command line not allowed")
        )));
    }

    #[test]
    fn listener_executes_default_command_and_forwards_stdin_to_process() {
        let fake = FakeTransport::default();
        let (tx, rx) = mpsc::channel();
        let mut session = ListenerSession::new(TEST_LINK, test_config());
        let version = version_message();
        session.handle_message(&fake, &tx, version.msgtype(), version.pack());
        let exec = exec_msg(Vec::new());
        session.handle_message(&fake, &tx, exec.msgtype(), exec.pack());
        assert_eq!(session.state, ListenerState::Running);

        let stdin = RnshMessage::StreamData(StreamDataMessage::new(
            STREAM_STDIN,
            b"hello over stdin".to_vec(),
            true,
            false,
        ));
        session.handle_message(&fake, &tx, stdin.msgtype(), stdin.pack());

        let started = Instant::now();
        let mut stdout = Vec::new();
        let mut exit = None;
        while started.elapsed() < Duration::from_secs(5) && exit.is_none() {
            match rx.recv_timeout(Duration::from_millis(100)).unwrap() {
                RnshEvent::ProcessOutput {
                    stream_id: STREAM_STDOUT,
                    data,
                    ..
                } => stdout.extend(data),
                RnshEvent::ProcessExited { code, .. } => exit = Some(code),
                _ => {}
            }
        }

        assert_eq!(stdout, b"hello over stdin");
        assert_eq!(exit, Some(0));
    }

    #[test]
    fn send_stream_chunks_splits_large_payload_and_appends_eof() {
        let fake = FakeTransport::default();
        let data = vec![0x55; STREAM_CHUNK_MAX * 2 + 3];

        send_stream_chunks(&fake, TEST_LINK, STREAM_STDOUT, &data, true).unwrap();

        let messages = fake.sent_messages();
        assert_eq!(messages.len(), 4);
        let mut payload = Vec::new();
        for (_, message) in &messages[..3] {
            match message {
                RnshMessage::StreamData(stream) => {
                    assert_eq!(stream.stream_id, STREAM_STDOUT);
                    assert!(!stream.eof);
                    payload.extend_from_slice(&stream.data);
                }
                other => panic!("expected stream data, got {other:?}"),
            }
        }
        assert_eq!(payload, data);
        assert!(matches!(
            messages.last().unwrap().1,
            RnshMessage::StreamData(ref stream)
                if stream.stream_id == STREAM_STDOUT && stream.eof && stream.data.is_empty()
        ));
    }

    #[test]
    fn process_pipe_mode_reports_stdout_stderr_and_exit() {
        let (tx, rx) = mpsc::channel();
        let link_id = [7u8; 16];
        let command = ExecuteCommand {
            cmdline: Vec::new(),
            pipe_stdin: true,
            pipe_stdout: true,
            pipe_stderr: true,
            term: None,
            rows: None,
            cols: None,
            hpix: None,
            vpix: None,
        };
        let _process = ChildProcess::spawn(
            link_id,
            &[
                "/bin/sh".into(),
                "-c".into(),
                "printf out; printf err >&2; exit 13".into(),
            ],
            &[],
            &command,
            tx,
        )
        .unwrap();

        let started = Instant::now();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit = None;
        while started.elapsed() < Duration::from_secs(5) && exit.is_none() {
            match rx.recv_timeout(Duration::from_millis(100)).unwrap() {
                RnshEvent::ProcessOutput {
                    stream_id: STREAM_STDOUT,
                    data,
                    ..
                } => stdout.extend(data),
                RnshEvent::ProcessOutput {
                    stream_id: STREAM_STDERR,
                    data,
                    ..
                } => stderr.extend(data),
                RnshEvent::ProcessExited { code, .. } => exit = Some(code),
                _ => {}
            }
        }
        assert_eq!(stdout, b"out");
        assert_eq!(stderr, b"err");
        assert_eq!(exit, Some(13));
    }
}
