//! rnid - Reticulum Identity & Encryption Utility.
//!
//! Ported statement by statement from upstream's rnid: the same messages
//! (on stdout, as upstream prints them, `RNS.log` lines included), exit
//! codes, file formats and order of operations.

// The library builds this file too, as rnid_command, for its options;
// #[path] finds these modules beside it in both builds.
#[path = "args.rs"]
mod args;
#[path = "encryption.rs"]
mod encryption;
#[path = "identities.rs"]
mod identities;
#[path = "py_repr.rs"]
mod py_repr;
#[path = "rsg.rs"]
mod rsg;
#[path = "run.rs"]
mod run;
#[path = "signing.rs"]
mod signing;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub use args::*;
use py_repr::*;
use rsg::*;

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process;
use std::time::{Duration, Instant};

use rns_cli::args::{Args, Opt, OptionSpec, Seen};
use rns_cli::configobj::{self, Entry};
use rns_cli::pyfmt::{hexrep, prettyhexrep, prettysize};
use rns_cli::pylog::{
    self, b32decode, b32encode, expanduser, fromhex, identity_from_file, key_to_file, oserror,
    urlsafe_b64decode, urlsafe_b64encode,
};
use rns_core::msgpack::{self, Value};
use rns_crypto::identity::Identity;
use rns_crypto::sha256::{sha256, Sha256};
use rns_crypto::OsRng;

const VERSION: &str = env!("FULL_VERSION");

const DEFAULT_ASPECTS: &str = "rns.id";
const PUB_EXT: &str = "pub";
const SIG_EXT: &str = "rsg";
const MSG_EXT: &str = "rsm";
const ENCRYPT_EXT: &str = "rfe";
const CHUNK_BLOCKS: usize = 1024 * 1024;
const ENC_CHUNK: usize = CHUNK_BLOCKS * 16;
const DEC_CHUNK: usize = ENC_CHUNK + rns_core::constants::TOKEN_OVERHEAD * 2;
const SIGLEN: usize = 64;
const KEYSIZE: usize = 64;
/// `RNS.Transport.PATH_REQUEST_TIMEOUT`, the default of `-t`.
const PATH_REQUEST_TIMEOUT: f64 = 15.0;

const R_OK: i32 = 0;
const R_NO_IDENTITY: i32 = 2;
const R_NO_PUBKEY: i32 = 3;
const R_NO_PRVKEY: i32 = 4;
const R_NO_KEYS: i32 = 5;
const R_NO_FILE: i32 = 6;
const R_INVALID_FILE: i32 = 7;
const R_INVALID_IDENTITY: i32 = 8;
const R_INVALID_ASPECTS: i32 = 9;
const R_INVALID_SIGNATURE: i32 = 10;
const R_FILE_EXISTS: i32 = 11;
const R_DECRYPT_FAILED: i32 = 12;
const R_INVALID_ARGS: i32 = 250;
const R_READ_ERROR: i32 = 252;
const R_WRITE_ERROR: i32 = 253;
const R_UNKNOWN_ERROR: i32 = 254;
const R_INTERRUPTED: i32 = 255;

const RSG_ASCII_HEADER: &str = "#### Start of rsg data ";
const RSG_ASCII_FOOTER: &str = " End of rsg data ####";
const RSG_ASCII_ROW_WIDTH: usize = 64;

#[allow(dead_code)]
fn main() {
    rns_cli::stdout::exit_quietly_on_closed_stdout();
    run_with_args(Args::parse_spec(&OPTIONS), "rnid", "rnid");
}

pub fn run_with_args(args: Args, usage_name: &str, version_name: &str) {
    rns_cli::argparse::enforce(&args, "rnid", usage_name);
    if args.has("version") {
        println!("{} {}", version_name, VERSION);
        return;
    }
    if args.has("help") || args.has("h") {
        rns_cli::argparse::print_help("rnid", usage_name);
        return;
    }
    // `except KeyboardInterrupt: print(""); exit(R_INTERRUPTED)`, until a
    // Reticulum instance installs its own handler.
    rns_cli::stdout::exit_on_interrupt_after_newline(R_INTERRUPTED);
    let mut rnid = Rnid {
        args: Namespace::from_args(&args),
        node: None,
    };
    rnid.main(usage_name);
}

fn isfile(path: &str) -> bool {
    Path::new(path).is_file()
}

/// `str(identity)`.
fn id_str(identity: &Identity) -> String {
    prettyhexrep(identity.hash())
}

/// Python's `str()` of an exception reading or writing `path`.
fn io_error(err: &std::io::Error, path: &str) -> String {
    oserror(err, path)
}

/// `RNS.Destination.hash_from_name_and_identity`.
fn hash_from_name_and_identity(full_name: &str, identity_hash: &[u8]) -> [u8; 16] {
    let name_hash = sha256(full_name.as_bytes());
    let mut material = name_hash[..10].to_vec();
    material.extend_from_slice(identity_hash);
    let mut out = [0u8; 16];
    out.copy_from_slice(&sha256(&material)[..16]);
    out
}

/// What upstream passes as the identity to `-H` and `-V`: an Identity,
/// or the `-i` string when it did not resolve to one.
enum Target<'a> {
    Identity(&'a Identity),
    Str(String),
    None,
}

/// A required signer, once a string was turned into bytes.
enum Signer<'a> {
    Identity(&'a Identity),
    Hash(Vec<u8>),
    None,
}

impl Signer<'_> {
    fn is_truthy(&self) -> bool {
        match self {
            Signer::Identity(_) => true,
            Signer::Hash(h) => !h.is_empty(),
            Signer::None => false,
        }
    }

    /// `RNS.prettyhexrep(identity) if type(identity) == bytes else f"{identity}"`.
    fn describe(&self) -> String {
        match self {
            Signer::Identity(identity) => id_str(identity),
            Signer::Hash(hash) => prettyhexrep(hash),
            Signer::None => "None".into(),
        }
    }
}

/// What a signature is computed over.
enum RsgMessage<'a> {
    Bytes(&'a [u8]),
    File(&'a str),
}

struct NoCallbacks;

impl rns_net::Callbacks for NoCallbacks {
    fn on_announce(&mut self, _: rns_net::AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _: rns_net::DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: rns_net::DestHash, _: Vec<u8>, _: rns_net::PacketHash) {}
}

struct Rnid {
    args: Namespace,
    node: Option<rns_net::RnsNode>,
}

impl Rnid {
    // Reticulum helpers

    // Identity loading and resolution

    // Network operations

    // Signing and validation

    // Encryption and decryption

    // File output

    // Terminal output

    // Helpers
}

fn read_chunk(input: &mut fs::File, size: usize) -> std::io::Result<Vec<u8>> {
    let mut chunk = Vec::new();
    input.take(size as u64).read_to_end(&mut chunk)?;
    Ok(chunk)
}

/// upstream's spinner: `msg` while waiting for `until`, cleared after.
fn spin(until: impl Fn() -> bool, msg: &str, timeout: Option<f64>) -> bool {
    const SYMS: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];
    let deadline =
        timeout.map(|t| Instant::now() + Duration::try_from_secs_f64(t).unwrap_or(Duration::ZERO));
    print!("{msg}   ");
    let mut i = 0;
    while deadline.is_none_or(|d| Instant::now() < d) && !until() {
        std::thread::sleep(Duration::from_millis(100));
        print!("\u{8}\u{8}{} ", SYMS[i]);
        let _ = std::io::stdout().flush();
        i = (i + 1) % SYMS.len();
    }
    print!("\r{}  \r", " ".repeat(msg.chars().count()));
    deadline.is_none_or(|d| Instant::now() <= d)
}
