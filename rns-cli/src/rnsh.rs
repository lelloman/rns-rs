//! Reticulum Remote Shell Utility.
//!
//! Protocol and behaviour are based on the first-party Python `rnsh` utility,
//! which itself credits Aaron Heise's original `rnsh` program.

mod identity;
mod initiator;
mod listener;
mod process;
#[cfg(test)]
mod tests;
mod transport;
mod tty;
mod wire;

use identity::*;
use initiator::*;
use listener::*;
use process::*;
use transport::*;
use tty::*;
use wire::*;

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rns_core::buffer::StreamDataMessage;
use rns_core::types::{DestHash, IdentityHash};
use rns_crypto::identity::Identity;
use rns_net::compressor::Bzip2Compressor;
use rns_net::destination::Destination;
use rns_net::{Callbacks, ChannelSendError, RnsNode, SendError};

use crate::args::{Args, Opt, OptionSpec};
use crate::pyfmt::prettyhexrep;

const APP_NAME: &str = "rnsh";
const DEFAULT_SERVICE_NAME: &str = "default";
const VERSION: &str = env!("FULL_VERSION");

const MSG_MAGIC: u16 = 0xac;
const PROTOCOL_VERSION: u64 = 1;

const MSG_NOOP: u16 = MSG_MAGIC << 8;
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
const PROCESS_OUTPUT_BUFFER_MAX: usize = 1024 * 1024;

static SIGWINCH_SEEN: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
enum RnshError {
    Io(io::Error),
    Protocol(String),
    Channel(ChannelSendError),
    Send,
}

impl From<io::Error> for RnshError {
    fn from(value: io::Error) -> Self {
        RnshError::Io(value)
    }
}

impl From<ChannelSendError> for RnshError {
    fn from(error: ChannelSendError) -> Self {
        Self::Channel(error)
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
            RnshError::Channel(error) => write!(f, "RNS channel send failed: {error}"),
            RnshError::Send => write!(f, "RNS send failed"),
        }
    }
}

/// The status upstream's `main()` exits with when the program raised
/// `SystemExit`, whatever its code (argparse's help, version and errors,
/// and `exit(0)` after printing the identity): it swallows the exception
/// and returns its initial status.
const SWALLOWED_EXIT: i32 = 1;

/// Runs `rnsh` on the process's command line and returns the exit status
/// for the binary to exit with. Blocks until the session ends, or for a
/// listener until it is stopped. Never exits the process itself.
pub fn main() -> i32 {
    let columns = crate::argparse::terminal_columns();
    match CliOptions::parse(std::env::args().skip(1).collect(), columns) {
        Ok(opts) => {
            if opts.version {
                println!("rnsh {} (protocol {})", VERSION, PROTOCOL_VERSION);
                return SWALLOWED_EXIT;
            }
            // Upstream sets up its configuration directory before anything
            // else, even when it then only prints its help.
            if resolve_rnsh_config_dir(opts.rnsh_config.as_deref(), &home_dir()).is_err() {
                crate::pylog::log(
                    "Could not get or create rnsh configuration directory, aborting",
                    crate::pylog::LOG_CRITICAL,
                );
                return 1;
            }
            if opts.print_identity {
                return match print_identity(&opts) {
                    // Upstream ends it with exit(0), which main() swallows.
                    Ok(()) => SWALLOWED_EXIT,
                    Err(err) => {
                        eprintln!("{err}");
                        1
                    }
                };
            }
            let result = if opts.listen {
                listen(opts).map(|_| 0)
            } else if opts.destination.is_some() {
                let destination = opts.destination.clone().unwrap_or_default();
                let mirror = opts.mirror_exit;
                let result = initiate(opts).map(|code| if mirror { code } else { 0 });
                if result.is_ok() {
                    log::info!(target: crate::pylog::INFO_TARGET, "Sesssion with <{destination}> ended");
                }
                result
            } else {
                println!();
                crate::argparse::print_help("rnsh", "rnsh");
                println!();
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
        Err(exit) => {
            print!("{}", exit.stdout);
            eprint!("{}", exit.stderr);
            SWALLOWED_EXIT
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CliOptions {
    rnsh_config: Option<String>,
    rns_config: Option<String>,
    identity: Option<String>,
    verbose: u8,
    quiet: u8,
    print_identity: bool,
    version: bool,
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

/// upstream rnsh's options.
pub(crate) const OPTIONS: OptionSpec = OptionSpec {
    options: &[
        Opt::value("c", "config"),
        Opt::value("", "rnsconfig"),
        Opt::value("i", "identity"),
        Opt::count("v", "verbose"),
        Opt::count("q", "quiet"),
        Opt::flag("p", "print-identity"),
        Opt::flag("l", "listen"),
        Opt::value("s", "service"),
        Opt::value("b", "announce"),
        Opt::value("a", "allowed"),
        Opt::flag("n", "no-auth"),
        Opt::flag("A", "remote-command-as-args"),
        Opt::flag("C", "no-remote-command"),
        Opt::flag("N", "no-id"),
        Opt::flag("m", "mirror"),
        Opt::value("w", "timeout"),
    ],
};

impl CliOptions {
    /// The options upstream's parser takes from `argv`, or what it prints
    /// and the status it exits with when it does not let rnsh run.
    fn parse(argv: Vec<String>, columns: usize) -> Result<Self, crate::argparse::Exit> {
        // As upstream, everything after the first `--` is the command.
        let (rnsh_argv, command) = match argv.iter().position(|arg| arg == "--") {
            Some(idx) => (argv[..idx].to_vec(), argv[idx + 1..].to_vec()),
            None => (argv, Vec::new()),
        };
        let args = Args::parse_spec_from(rnsh_argv, &OPTIONS);
        if let Some(parser) = crate::upstream_parsers::by_name("rnsh") {
            if let Some(exit) = crate::argparse::check(&args, parser, "rnsh", columns) {
                return Err(exit);
            }
        }
        let value = |key: &str| args.get(key).map(str::to_string);
        let mut opts = CliOptions {
            rnsh_config: value("config"),
            rns_config: value("rnsconfig"),
            identity: value("identity"),
            verbose: args.verbosity,
            quiet: args.quiet,
            print_identity: args.has("p"),
            version: args.has("version"),
            listen: args.has("l"),
            service: value("service"),
            // Both checked by the parser above. A negative period announces
            // once, as 0 does.
            announce_period: value("announce")
                .and_then(|b| crate::argparse::python_int(&b))
                .map(|b| b.max(0) as u64),
            allowed: args
                .get_all("allowed")
                .into_iter()
                .map(str::to_string)
                .collect(),
            no_auth: args.has("n"),
            remote_command_as_args: args.has("A"),
            no_remote_command: args.has("C"),
            no_id: args.has("N"),
            mirror_exit: args.has("m"),
            timeout: value("timeout").and_then(|w| crate::argparse::python_float(&w)),
            destination: args.positional.first().cloned(),
            command,
        };
        if opts.listen && opts.service.is_none() {
            opts.service = Some(DEFAULT_SERVICE_NAME.to_string());
        }
        Ok(opts)
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn expand_user_path(path: &str, home: &Path) -> PathBuf {
    if path == "~" {
        home.to_path_buf()
    } else if let Some(suffix) = path.strip_prefix("~/") {
        home.join(suffix)
    } else {
        PathBuf::from(path)
    }
}

fn resolve_rnsh_config_dir(explicit: Option<&str>, home: &Path) -> Result<PathBuf, RnshError> {
    // Upstream's ensure_config_directory, which logs the directories it
    // creates at the default level.
    let create = |dir: PathBuf| -> Result<PathBuf, RnshError> {
        if !dir.is_dir() {
            crate::pylog::log(
                &format!("Creating configuration directory: {}", dir.display()),
                crate::pylog::LOG_NOTICE,
            );
            fs::create_dir_all(&dir)?;
        }
        Ok(dir)
    };
    if let Some(explicit) = explicit {
        return create(expand_user_path(explicit, home));
    }

    let xdg = home.join(".config").join("rnsh");
    if xdg.is_dir() {
        return Ok(xdg);
    }
    create(home.join(".rnsh"))
}

fn resolve_rns_config_dir(explicit: Option<&str>, home: &Path) -> PathBuf {
    explicit
        .map(|path| expand_user_path(path, home))
        .unwrap_or_else(|| home.join(".reticulum"))
}

fn rnsh_log_path(config_dir: &Path, listen: bool) -> PathBuf {
    config_dir.join(if listen {
        "logfile"
    } else {
        "logfile.initiator"
    })
}

/// `compute_target_rns_loglevel`: `LOG_INFO` raised by each -v and
/// lowered by each -q, within `LOG_NONE..=LOG_EXTREME`.
fn rnsh_log_level(verbose: u8, quiet: u8) -> i32 {
    (crate::pylog::LOG_INFO + i32::from(verbose) - i32::from(quiet))
        .clamp(crate::pylog::LOG_NONE, 7)
}
