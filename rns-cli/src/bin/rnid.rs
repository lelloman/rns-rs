//! rnid - Reticulum Identity & Encryption Utility.
//!
//! Ported statement by statement from upstream's rnid: the same messages
//! (on stdout, as upstream prints them, `RNS.log` lines included), exit
//! codes, file formats and order of operations.

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

/// upstream rnid's options. `-d`, `-e`, `-V` and `-s` take any number of
/// paths (`nargs="*"`): the first is the option's value and the rest
/// follow it as positionals in the parser's trace.
pub const OPTIONS: OptionSpec = OptionSpec {
    options: &[
        Opt::value("", "config"),
        Opt::value("i", "identity"),
        Opt::value("g", "generate"),
        Opt::value("m", "import-pub"),
        Opt::value("M", "import-prv"),
        Opt::flag("x", "export-pub"),
        Opt::flag("X", "export-prv"),
        Opt::count("v", "verbose"),
        Opt::count("q", "quiet"),
        Opt::optional("a", "announce"),
        Opt::value("H", "hash"),
        Opt::optional("d", "decrypt"),
        Opt::optional("e", "encrypt"),
        Opt::optional("V", "validate"),
        Opt::optional("s", "sign"),
        Opt::optional("S", "sign-message"),
        Opt::optional("E", "embed-meta"),
        Opt::optional("", "meta-spec"),
        Opt::flag("", "raw"),
        Opt::value("w", "write"),
        Opt::value("r", "read"),
        Opt::flag("f", "force"),
        Opt::flag("I", "stdin"),
        Opt::flag("O", "stdout"),
        Opt::flag("R", "request"),
        Opt::flag("N", "no-cache"),
        Opt::value("t", ""),
        Opt::flag("p", "print-identity"),
        Opt::flag("P", "print-private"),
        Opt::flag("B", "base32"),
        Opt::flag("b", "base64"),
        Opt::flag("U", "base256"),
        Opt::flag("F", "hex"),
        Opt::flag("", "meta"),
        // Rust-only: the older short name of --base256.
        Opt::flag("Z", ""),
    ],
};

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

/// `-S` without a message is upstream's `NO_MESSAGE`.
#[derive(Clone, Debug, PartialEq)]
enum MessageArg {
    NoMessage,
    Text(String),
}

/// `-E` without a path is upstream's `NO_META`.
#[derive(Clone, Debug, PartialEq)]
enum MetaArg {
    NoMeta,
    Path(String),
}

/// upstream's argparse namespace.
#[derive(Debug, Default)]
struct Namespace {
    config: Option<String>,
    identity: Option<String>,
    generate: Option<String>,
    import_pub: Option<String>,
    import_prv: Option<String>,
    export_pub: bool,
    export_prv: bool,
    verbose: i32,
    quiet: i32,
    announce: Option<String>,
    hash: Option<String>,
    decrypt: Option<Vec<String>>,
    encrypt: Option<Vec<String>>,
    validate: Option<Vec<String>>,
    sign: Option<Vec<String>>,
    sign_message: Option<MessageArg>,
    embed_meta: Option<MetaArg>,
    meta_spec: Option<String>,
    raw: bool,
    write: Option<String>,
    read: Option<String>,
    force: bool,
    stdout: bool,
    request: bool,
    no_cache: bool,
    t: f64,
    print_identity: bool,
    print_private: bool,
    base32: bool,
    base64: bool,
    base256: bool,
    hex: bool,
    meta: bool,
}

/// Python's truthiness of an optional string.
fn truthy(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|v| !v.is_empty())
}

fn truthy_list(value: &Option<Vec<String>>) -> bool {
    value.as_ref().is_some_and(|v| !v.is_empty())
}

impl Namespace {
    /// The namespace argparse builds, from what the parser saw: the last
    /// occurrence of an option wins, and the arguments after a `nargs="*"`
    /// option are its values.
    fn from_args(args: &Args) -> Self {
        let mut ns = Namespace {
            t: PATH_REQUEST_TIMEOUT,
            verbose: i32::from(args.verbosity),
            quiet: i32::from(args.quiet),
            ..Default::default()
        };
        let mut collecting: Option<&'static str> = None;
        for seen in &args.trace {
            match seen {
                Seen::Option(opt, value) => {
                    collecting = ns.set(opt, value.clone());
                }
                Seen::Missing(opt) => {
                    collecting = ns.set(opt, None);
                }
                Seen::Positional(value) => {
                    if let Some(list) = collecting.and_then(|dest| ns.list_mut(dest)) {
                        list.push(value.clone());
                    }
                }
                _ => collecting = None,
            }
        }
        ns
    }

    fn list_mut(&mut self, dest: &str) -> Option<&mut Vec<String>> {
        match dest {
            "decrypt" => self.decrypt.as_mut(),
            "encrypt" => self.encrypt.as_mut(),
            "validate" => self.validate.as_mut(),
            "sign" => self.sign.as_mut(),
            _ => None,
        }
    }

    /// Store one option; returns the list it collects into, if any.
    fn set(&mut self, opt: &Opt, value: Option<String>) -> Option<&'static str> {
        let name = if opt.long.is_empty() {
            opt.short
        } else {
            opt.long
        };
        let list = |value: Option<String>| Some(value.into_iter().collect::<Vec<_>>());
        match name {
            "config" => self.config = value,
            "identity" => self.identity = value,
            "generate" => self.generate = value,
            "import-pub" => self.import_pub = value,
            "import-prv" => self.import_prv = value,
            "export-pub" => self.export_pub = true,
            "export-prv" => self.export_prv = true,
            "announce" => self.announce = Some(value.unwrap_or_else(|| DEFAULT_ASPECTS.into())),
            "hash" => self.hash = value,
            "decrypt" => {
                self.decrypt = list(value);
                return Some("decrypt");
            }
            "encrypt" => {
                self.encrypt = list(value);
                return Some("encrypt");
            }
            "validate" => {
                self.validate = list(value);
                return Some("validate");
            }
            "sign" => {
                self.sign = list(value);
                return Some("sign");
            }
            "sign-message" => {
                self.sign_message = Some(value.map_or(MessageArg::NoMessage, MessageArg::Text))
            }
            "embed-meta" => self.embed_meta = Some(value.map_or(MetaArg::NoMeta, MetaArg::Path)),
            "meta-spec" => self.meta_spec = value,
            "raw" => self.raw = true,
            "write" => self.write = value,
            "read" => self.read = value,
            "force" => self.force = true,
            "stdout" => self.stdout = true,
            "request" => self.request = true,
            "no-cache" => self.no_cache = true,
            "t" => {
                if let Some(t) = value.as_deref().and_then(rns_cli::argparse::python_float) {
                    self.t = t;
                }
            }
            "print-identity" => self.print_identity = true,
            "print-private" => self.print_private = true,
            "base32" => self.base32 = true,
            "base64" => self.base64 = true,
            "base256" | "Z" => self.base256 = true,
            "hex" => self.hex = true,
            "meta" => self.meta = true,
            _ => {}
        }
        None
    }

    fn sign_message_truthy(&self) -> bool {
        match &self.sign_message {
            Some(MessageArg::NoMessage) => true,
            Some(MessageArg::Text(text)) => !text.is_empty(),
            None => false,
        }
    }

    fn embed_meta_truthy(&self) -> bool {
        match &self.embed_meta {
            Some(MetaArg::NoMeta) => true,
            Some(MetaArg::Path(path)) => !path.is_empty(),
            None => false,
        }
    }

    fn output(&self) -> &'static str {
        if self.base32 {
            "base32"
        } else if self.base64 {
            "base64"
        } else if self.base256 {
            "base256"
        } else if self.hex {
            "hex"
        } else {
            "bin"
        }
    }
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
    fn exit(&mut self, code: i32) -> ! {
        let _ = std::io::stdout().flush();
        if let Some(node) = self.node.take() {
            node.shutdown();
        }
        process::exit(code)
    }

    fn validate_args(&mut self) {
        let a = &self.args;
        let ops = [
            truthy_list(&a.encrypt),
            truthy_list(&a.decrypt),
            truthy_list(&a.validate),
            truthy_list(&a.sign),
            a.sign_message_truthy(),
        ]
        .iter()
        .filter(|o| **o)
        .count();
        if ops > 1 {
            println!("This utility currently only supports one of the encrypt, decrypt, sign or verify operations per invocation");
            self.exit(1);
        }
        let g = [
            truthy(&a.import_pub),
            truthy(&a.import_prv),
            truthy(&a.identity),
            truthy(&a.generate),
        ]
        .iter()
        .filter(|o| **o)
        .count();
        if g > 1 {
            println!("The -i, -g, -m and -M args are mutually exclusive");
            self.exit(1);
        }
        let g = [a.base64, a.base32, a.base256, a.hex]
            .iter()
            .filter(|o| **o)
            .count();
        if g > 1 {
            println!("The -b, -B, --hex and --base256 args are mutually exclusive");
            self.exit(1);
        }
    }

    fn main(&mut self, usage_name: &str) -> ! {
        self.validate_args();
        let a = &self.args;
        let op_requires_identity = truthy_list(&a.sign)
            || a.sign_message_truthy()
            || truthy_list(&a.encrypt)
            || truthy_list(&a.decrypt)
            || truthy(&a.announce)
            || truthy(&a.write)
            || a.print_identity
            || a.export_pub
            || a.export_prv;
        let no_cache = a.no_cache;
        let identity = self.get_operating_identity(!op_requires_identity, no_cache);
        if identity.is_none() && op_requires_identity {
            println!("Could not get working identity");
            self.exit(R_NO_IDENTITY);
        }
        let mut op = false;
        // `identity or args.identity`.
        let target = match (&identity, &self.args.identity) {
            (Some(identity), _) => Target::Identity(identity),
            (None, Some(s)) if !s.is_empty() => Target::Str(s.clone()),
            _ => Target::None,
        };
        let id = identity.as_ref();
        if self.args.print_identity {
            self.print_identity_information(id.expect("required"));
            op = true;
        }
        if self.args.export_pub {
            self.export_pub_identity(id.expect("required"));
            op = true;
        }
        if self.args.export_prv {
            self.export_prv_identity(id.expect("required"));
            op = true;
        }
        if truthy(&self.args.hash) {
            self.print_hash_information(&target);
            op = true;
        }
        if truthy(&self.args.announce) {
            self.announce(id.expect("required"));
            op = true;
        }
        if truthy_list(&self.args.validate) {
            for path in self.args.validate.clone().unwrap_or_default() {
                self.validate(&path, &target);
            }
            self.exit(R_OK);
        }
        if truthy_list(&self.args.sign) {
            for path in self.args.sign.clone().unwrap_or_default() {
                self.sign(&path, id.expect("required"));
            }
            self.exit(R_OK);
        }
        if self.args.sign_message_truthy() {
            self.sign_message(id.expect("required"));
        }
        if truthy_list(&self.args.encrypt) {
            for path in self.args.encrypt.clone().unwrap_or_default() {
                self.encrypt(&path, id.expect("required"));
            }
            self.exit(R_OK);
        }
        if truthy_list(&self.args.decrypt) {
            for path in self.args.decrypt.clone().unwrap_or_default() {
                self.decrypt(&path, id.expect("required"));
            }
            self.exit(R_OK);
        }
        if truthy(&self.args.write) {
            self.write_identity(id.expect("required"));
            op = true;
        }
        if truthy(&self.args.generate) {
            op = true;
        }
        if !op {
            rns_cli::argparse::print_help("rnid", usage_name);
        }
        self.exit(R_OK)
    }

    // Reticulum helpers

    fn ensure_reticulum(&mut self) -> Result<(), String> {
        if self.node.is_some() {
            return Ok(());
        }
        let mut level = 4;
        if self.args.verbose != 0 || self.args.quiet != 0 {
            level = level + self.args.verbose - self.args.quiet;
        }
        // `RNS.Reticulum(configdir, loglevel=...)` with
        // `RNS.compact_log_fmt`.
        pylog::install_utility_logging(self.args.config.as_deref(), Some(level), 0, true);
        let config_dir =
            rns_net::storage::resolve_config_dir(self.args.config.as_deref().map(Path::new));
        let node = match rns_net::RnsNode::connect_shared_from_config(
            Some(&config_dir),
            Box::new(NoCallbacks),
        ) {
            Ok(node) => node,
            Err(_) => rns_net::RnsNode::from_config(Some(&config_dir), Box::new(NoCallbacks))
                .map_err(|e| e.to_string())?,
        };
        self.node = Some(node);
        pylog::set_loglevel(level);
        if self.args.stdout {
            pylog::set_loglevel(pylog::LOG_NONE);
        }
        // Reticulum's own handler: exit quietly with 0.
        rns_cli::stdout::exit_on_interrupt(0);
        Ok(())
    }

    /// `RNS.Identity.recall(hash)`, or with `from_identity_hash` by the
    /// identity's own hash.
    fn recall(&self, hash: &[u8], from_identity_hash: bool) -> Option<Identity> {
        let entries = self.node.as_ref()?.known_destinations().ok()?;
        let entry = entries.iter().find(|e| {
            if from_identity_hash {
                e.identity_hash[..] == *hash
            } else {
                e.dest_hash[..] == *hash
            }
        })?;
        Identity::from_public_key(&entry.public_key).ok()
    }

    fn recall_any(&self, hash: &[u8]) -> Option<Identity> {
        self.recall(hash, false).or_else(|| self.recall(hash, true))
    }

    // Identity loading and resolution

    fn get_operating_identity(&mut self, allow_none: bool, no_cache: bool) -> Option<Identity> {
        if let Some(path) = self.args.generate.clone().filter(|p| !p.is_empty()) {
            // Before any Reticulum instance sets the log level, so at
            // upstream's default this line is not shown.
            let identity = pylog::new_identity();
            if !self.args.force && isfile(&path) {
                println!("Identity file {path} already exists. Not overwriting.");
                self.exit(R_FILE_EXISTS);
            }
            key_to_file(&identity.get_private_key().unwrap_or([0; KEYSIZE]), &path);
            println!("New identity {} written to {path}", id_str(&identity));
            return Some(identity);
        }
        if let Some(given) = self.args.identity.clone().filter(|p| !p.is_empty()) {
            let load_path = expanduser(&given);
            if isfile(&load_path) {
                match identity_from_file(&load_path) {
                    Some(identity) => {
                        println!("Loaded Identity {} from {load_path}", id_str(&identity));
                        return Some(identity);
                    }
                    None => {
                        println!("Loaded Identity None from {load_path}");
                        println!("Could not load Identity from specified file: 'NoneType' object has no attribute 'get_private_key'");
                        self.exit(R_INVALID_IDENTITY);
                    }
                }
            } else if no_cache {
                if allow_none {
                    return None;
                }
                println!("Could not resolve identity");
                self.exit(R_NO_IDENTITY);
            } else if given.chars().count() == 32 {
                return self.recall_identity(&given, allow_none);
            }
            return None;
        }
        if truthy(&self.args.import_pub) || truthy(&self.args.import_prv) {
            let (spec, private) = match &self.args.import_pub {
                Some(spec) if !spec.is_empty() => (spec.clone(), false),
                _ => (self.args.import_prv.clone().unwrap_or_default(), true),
            };
            let Some(bytes) = self.import_bytes(&spec) else {
                let which = if private { "private" } else { "public" };
                println!("Could not decode specified data to a valid {which} Reticulum Identity");
                self.exit(R_INVALID_IDENTITY);
            };
            let key: &[u8; KEYSIZE] = bytes.as_slice().try_into().expect("checked length");
            if private {
                return Some(Identity::from_private_key(key));
            }
            return match Identity::from_public_key(key) {
                Ok(identity) => Some(identity),
                Err(e) => {
                    println!("Could not create Reticulum identity from specified data: {e:?}");
                    self.exit(R_INVALID_IDENTITY);
                }
            };
        }
        None
    }

    /// The key bytes `-m`/`-M` names: a file of exactly the key's size,
    /// else hex, base32 or base64 text of it.
    fn import_bytes(&self, spec: &str) -> Option<Vec<u8>> {
        let import_path = expanduser(spec);
        if isfile(&import_path) {
            if let Ok(input) = fs::read(&import_path) {
                if input.len() == KEYSIZE {
                    println!("Reticulum Identity imported from {import_path}");
                    return Some(input);
                }
            }
        }
        if spec.chars().count() == KEYSIZE * 2 {
            if let Ok(bytes) = fromhex(spec) {
                if !bytes.is_empty() {
                    println!("Reticulum Identity imported from hex input");
                    // Hex with spaces in it decodes to fewer bytes; upstream
                    // then fails creating the identity.
                    return Some(bytes).filter(|b| b.len() == KEYSIZE);
                }
            }
        }
        if let Some(bytes) = b32decode(spec).filter(|b| b.len() == KEYSIZE) {
            println!("Reticulum Identity imported from base32 input");
            return Some(bytes);
        }
        if let Some(bytes) = urlsafe_b64decode(spec).filter(|b| b.len() == KEYSIZE) {
            println!("Reticulum Identity imported from base64 input");
            return Some(bytes);
        }
        None
    }

    /// `-i` with a 32-character hash: recalled from what the instance
    /// knows, or with `-R` requested from the network.
    fn recall_identity(&mut self, given: &str, allow_none: bool) -> Option<Identity> {
        match self.try_recall_identity(given, allow_none) {
            Ok(identity) => identity,
            Err(e) => {
                println!("Invalid hexadecimal hash provided: {e}");
                self.exit(R_INVALID_IDENTITY);
            }
        }
    }

    fn try_recall_identity(
        &mut self,
        given: &str,
        allow_none: bool,
    ) -> Result<Option<Identity>, String> {
        self.ensure_reticulum()?;
        let requested_hash = fromhex(given)?;
        let mut identity = self.recall_any(&requested_hash);
        match &identity {
            None if allow_none && !self.args.request => return Ok(None),
            None if !self.args.request => {
                println!(
                    "Could not recall Identity for {}.",
                    prettyhexrep(&requested_hash)
                );
                println!("You can query the network for unknown Identities with the -R option.");
                self.exit(R_NO_IDENTITY);
            }
            None => {
                let id_destination_hash =
                    hash_from_name_and_identity(DEFAULT_ASPECTS, &requested_hash);
                if let Some(node) = &self.node {
                    if let Ok(hash) = <[u8; 16]>::try_from(requested_hash.as_slice()) {
                        let _ = node.request_path(&rns_net::DestHash(hash));
                    }
                    let _ = node.request_path(&rns_net::DestHash(id_destination_hash));
                }
                let message = format!(
                    "Requesting unknown Identity for {}",
                    prettyhexrep(&requested_hash)
                );
                spin(
                    || self.recall_any(&requested_hash).is_some(),
                    &message,
                    Some(self.args.t),
                );
                match self.recall_any(&requested_hash) {
                    None => {
                        println!("Identity request timed out");
                        if !allow_none {
                            self.exit(R_NO_IDENTITY);
                        }
                        return Ok(None);
                    }
                    Some(received) => {
                        println!(
                            "Received Identity {} for destination {} from the network",
                            id_str(&received),
                            prettyhexrep(&requested_hash)
                        );
                        identity = Some(received);
                    }
                }
            }
            Some(recalled) => {
                let ident_str = id_str(recalled);
                let hash_str = prettyhexrep(&requested_hash);
                if ident_str == hash_str {
                    println!("Recalled Identity {ident_str}");
                } else {
                    println!("Recalled Identity {ident_str} for destination {hash_str}");
                }
            }
        }
        if let (Some(identity), Some(node)) = (&identity, &self.node) {
            let _ = node.retain_identity(&rns_net::IdentityHash(*identity.hash()));
        }
        Ok(identity)
    }

    // Network operations

    fn announce(&mut self, identity: &Identity) {
        if let Err(e) = self.try_announce(identity) {
            println!("An error ocurred while attempting to send the announce: {e}");
            self.exit(R_UNKNOWN_ERROR);
        }
    }

    fn try_announce(&mut self, identity: &Identity) -> Result<(), String> {
        let announce = self.args.announce.clone().unwrap_or_default();
        self.ensure_reticulum()?;
        let mut parts = announce.split('.');
        let app_name = parts.next().unwrap_or_default().to_string();
        let aspects: Vec<&str> = parts.collect();
        if aspects.is_empty() {
            println!("Invalid destination aspects specified");
            self.exit(R_INVALID_ASPECTS);
        }
        let Some(private_key) = identity.get_private_key() else {
            println!("Cannot announce this destination, since the private key is not held");
            self.exit(R_NO_PRVKEY);
        };
        let node = self.node.as_ref().expect("started");
        let destination = rns_net::Destination::single_in(
            &app_name,
            &aspects,
            rns_net::IdentityHash(*identity.hash()),
        );
        node.register_destination_with_proof(&destination, Some(private_key))
            .map_err(|_| "the instance is not running".to_string())?;
        println!(
            "Announcing {announce} destination {} for identity {}",
            prettyhexrep(&destination.hash.0),
            id_str(identity)
        );
        node.announce_queued(&destination, identity, None)
            .map_err(|_| "the instance is not running".to_string())?;
        std::thread::sleep(Duration::from_millis(250));
        Ok(())
    }

    // Signing and validation

    /// The required signer of `-V`: a string must be an identity hash.
    fn signer_from<'a>(&mut self, target: &'a Target<'a>) -> Signer<'a> {
        match target {
            Target::Identity(identity) => Signer::Identity(identity),
            Target::Str(s) => {
                if s.chars().count() != 32 {
                    println!("Invalid identity hash length");
                    self.exit(R_INVALID_IDENTITY);
                }
                match fromhex(s) {
                    Ok(hash) => Signer::Hash(hash),
                    Err(e) => {
                        println!("Invalid identity hash: {e}");
                        self.exit(R_INVALID_IDENTITY);
                    }
                }
            }
            Target::None => Signer::None,
        }
    }

    fn validate(&mut self, path: &str, target: &Target) {
        let msg_ext = format!(".{MSG_EXT}");
        let sig_ext = format!(".{SIG_EXT}");
        let validate_path = expanduser(path);
        let lower = validate_path.to_lowercase();
        let path_is_msgfile = lower.ends_with(&msg_ext);
        let path_is_sigfile = lower.ends_with(&sig_ext);
        let (signature_path, file_path) = if path_is_sigfile {
            let cut = validate_path.len() - sig_ext.len();
            (validate_path.clone(), validate_path[..cut].to_string())
        } else {
            (format!("{validate_path}{sig_ext}"), validate_path.clone())
        };
        if path_is_msgfile {
            return self.validate_message(&validate_path, target);
        }
        if !isfile(&file_path) {
            println!("The validation target \"{file_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        if !isfile(&signature_path) {
            println!("No signature file exists for \"{file_path}\"");
            self.exit(R_NO_FILE);
        }
        let rsg = match fs::read(&signature_path) {
            Ok(rsg) => rsg,
            Err(e) => {
                println!(
                    "Could not detect rsg format: {}",
                    io_error(&e, &signature_path)
                );
                self.exit(R_UNKNOWN_ERROR);
            }
        };
        if rsg.len() != SIGLEN {
            let signer = self.signer_from(target);
            if let Err(e) = fs::File::open(&file_path) {
                println!("Could not read {file_path}: {}", io_error(&e, &file_path));
                self.exit(R_READ_ERROR);
            }
            match validate_rsg(&rsg, RsgMessage::File(&file_path), &signer) {
                Err(e) => {
                    println!("Error while validating {signature_path}: {e}");
                    self.exit(R_UNKNOWN_ERROR);
                }
                Ok((valid, _, signing_identity)) => {
                    let signer_description = if signer.is_truthy() {
                        format!("\nThis file was NOT signed by {}", signer.describe())
                    } else {
                        String::new()
                    };
                    if !valid {
                        println!(
                            "Invalid signature {signature_path} for file {file_path}{signer_description}"
                        );
                        self.exit(R_INVALID_SIGNATURE);
                    }
                    println!(
                        "Signature is valid, the file {file_path} was signed by {}",
                        signing_identity.as_ref().map_or("None".into(), id_str)
                    );
                }
            }
        } else {
            let Target::Identity(identity) = target else {
                println!(
                    "Cannot validate legacy rsg signatures without an explicit required identity"
                );
                self.exit(R_NO_IDENTITY);
            };
            let data = match fs::read(&file_path) {
                Ok(data) => data,
                Err(e) => {
                    println!("Could not validate signature: {}", io_error(&e, &file_path));
                    self.exit(R_READ_ERROR);
                }
            };
            let signature: &[u8; SIGLEN] = rsg.as_slice().try_into().expect("legacy length");
            if !identity.verify(signature, &data) {
                println!(
                    "Invalid signature {signature_path} for file {file_path}\nThis file was NOT signed by {}",
                    id_str(identity)
                );
                self.exit(R_INVALID_SIGNATURE);
            }
            println!(
                "Signature is valid, the file {file_path} was signed by {}",
                id_str(identity)
            );
            self.exit(R_OK);
        }
    }

    fn validate_message(&mut self, signature_path: &str, target: &Target) {
        if !isfile(signature_path) {
            println!("The signature file \"{signature_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        let rsg = match fs::read(signature_path) {
            Ok(rsg) => rsg,
            Err(e) => {
                println!("Could not read rsg: {}", io_error(&e, signature_path));
                self.exit(R_READ_ERROR);
            }
        };
        let signer = self.signer_from(target);
        if let Err(e) = self.try_validate_message(signature_path, &rsg, &signer) {
            println!("Error while validating {signature_path}: {e}");
            self.exit(R_UNKNOWN_ERROR);
        }
    }

    fn try_validate_message(
        &mut self,
        signature_path: &str,
        rsg: &[u8],
        signer: &Signer,
    ) -> Result<(), String> {
        let contents = extract_signed_rsg_data(rsg);
        let message = match &contents {
            None => return Err("argument of type 'NoneType' is not iterable".into()),
            Some(Value::Map(entries)) => map_get(entries, "message"),
            Some(Value::Array(_) | Value::Str(_)) => None,
            Some(other) => return Err(not_iterable(other)),
        };
        let Some(message) = message else {
            println!("No embedded message in {signature_path}");
            self.exit(R_INVALID_SIGNATURE);
        };
        let message_bytes = match message {
            Value::Bin(b) => b.clone(),
            Value::Str(s) => s.clone().into_bytes(),
            other => {
                return Err(format!(
                    "Invalid input type <class '{}'> for rsg creation",
                    type_name(other)
                ))
            }
        };
        let (valid, signed_data, signing_identity) =
            validate_rsg(rsg, RsgMessage::Bytes(&message_bytes), signer)?;
        let signer_description = if signer.is_truthy() {
            format!("\nThe message was NOT signed by {}", signer.describe())
        } else {
            String::new()
        };
        if !valid {
            println!("Invalid signature in {signature_path}{signer_description}");
            self.exit(R_INVALID_SIGNATURE);
        }
        let Some(Value::Map(signed)) = signed_data else {
            return Err("invalid signed data".into());
        };
        if self.args.meta {
            println!("RSM Metadata\n============\n");
            if let Some(Value::Map(meta)) = map_get(&signed, "meta") {
                for (key, entry) in meta {
                    recurse(entry, &py_str(key), 1);
                }
            }
            println!("\nValidation\n==========");
        }
        let c = if !self.args.meta { ":" } else { "" };
        let f = if !self.args.meta { " following" } else { "" };
        println!(
            "\nSignature is valid, the{f} message was signed by {}{c}\n",
            signing_identity.as_ref().map_or("None".into(), id_str)
        );
        if self.args.meta {
            println!("Message\n=======\n");
        }
        match map_get(&signed, "message") {
            Some(Value::Bin(bytes)) => println!("{}", decode_utf8(bytes)?),
            Some(Value::Str(_)) => return Err("'str' object has no attribute 'decode'".into()),
            _ => return Err("'NoneType' object has no attribute 'decode'".into()),
        }
        self.exit(R_OK)
    }

    fn sign(&mut self, path: &str, identity: &Identity) {
        let sign_path = expanduser(path);
        let rsg_path = format!("{sign_path}.{SIG_EXT}");
        let file_exists = isfile(&sign_path);
        let signature_exists = isfile(&rsg_path);
        let output = self.args.output();
        if identity.get_private_key().is_none() {
            println!("Cannot sign \"{sign_path}\", the identity does not hold a private key");
            self.exit(R_NO_PRVKEY);
        }
        if !file_exists {
            println!("The file \"{sign_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        if output == "bin" && signature_exists && !self.args.force {
            println!("The signature file \"{rsg_path}\" already exists, not overwriting");
            self.exit(R_FILE_EXISTS);
        }
        if let Err(e) = self.try_sign(&sign_path, &rsg_path, identity, output) {
            println!("Could not sign {sign_path}: {e}");
            self.exit(R_UNKNOWN_ERROR);
        }
    }

    fn try_sign(
        &mut self,
        sign_path: &str,
        rsg_path: &str,
        identity: &Identity,
        output: &str,
    ) -> Result<(), String> {
        if self.args.raw {
            let data = fs::read(sign_path).map_err(|e| io_error(&e, sign_path))?;
            let signature = identity.sign(&data).map_err(|e| format!("{e:?}"))?;
            fs::write(rsg_path, signature).map_err(|e| io_error(&e, rsg_path))?;
        } else {
            fs::File::open(sign_path).map_err(|e| io_error(&e, sign_path))?;
            match create_rsg(identity, RsgMessage::File(sign_path), false, None, output)? {
                Rsg::Bin(bytes) => {
                    fs::write(rsg_path, bytes).map_err(|e| io_error(&e, rsg_path))?
                }
                Rsg::Text(text) => println!("\n{}\n", wrap_rsg(&text)),
            }
        }
        println!("Signed file {sign_path} with {}", id_str(identity));
        Ok(())
    }

    fn sign_message(&mut self, identity: &Identity) -> ! {
        let mut message = self.args.sign_message.clone().expect("checked");
        let output = self.args.output();
        if output == "bin" && !truthy(&self.args.write) {
            println!("No write path specified");
            self.exit(R_INVALID_ARGS);
        }
        if identity.get_private_key().is_none() {
            println!("Cannot sign, the identity does not hold a private key");
            self.exit(R_NO_PRVKEY);
        }
        if let Some(read) = self.args.read.clone().filter(|r| !r.is_empty()) {
            if message != MessageArg::NoMessage {
                println!(
                    "Both an input file and command-line provided message was specified, aborting"
                );
                self.exit(R_INVALID_ARGS);
            }
            let sign_path = expanduser(&read);
            if !isfile(&sign_path) {
                println!("The file {sign_path} does not exist");
                self.exit(R_NO_FILE);
            }
            // Read as text, outside upstream's error handling: a failure is
            // an uncaught exception there.
            match fs::read(&sign_path).map(String::from_utf8) {
                Ok(Ok(read)) => message = MessageArg::Text(read),
                Ok(Err(e)) => {
                    let _ = std::io::stdout().flush();
                    eprintln!(
                        "UnicodeDecodeError: {}",
                        utf8_error(e.as_bytes(), e.utf8_error())
                    );
                    self.exit(1);
                }
                Err(e) => {
                    let _ = std::io::stdout().flush();
                    eprintln!("{}", io_error(&e, &sign_path));
                    self.exit(1);
                }
            }
        }
        // Text is hashed as UTF-8; the editor's content is bytes already.
        let message_bytes = match &message {
            MessageArg::NoMessage => self.get_editor_content(),
            MessageArg::Text(text) => text.as_bytes().to_vec(),
        };
        if message_bytes.is_empty() {
            println!("No message specified");
            self.exit(R_INVALID_ARGS);
        }
        let mut meta = None;
        if self.args.embed_meta_truthy() {
            let meta_path = match self.args.embed_meta.clone() {
                Some(MetaArg::Path(path)) => expanduser(&path),
                _ => {
                    let _ = std::io::stdout().flush();
                    eprintln!("TypeError: expected str, bytes or os.PathLike object, not int");
                    self.exit(1);
                }
            };
            let meta_spec_path = match self.args.meta_spec.clone().filter(|s| !s.is_empty()) {
                Some(spec) => spec,
                None => format!("{meta_path}.spec"),
            };
            if !isfile(&meta_path) {
                println!("Metadata file {meta_path} does not exist");
                self.exit(R_NO_FILE);
            }
            let meta_spec_path = Some(meta_spec_path).filter(|p| isfile(p));
            let spec_info = meta_spec_path
                .as_deref()
                .map(|p| format!(" using spec from {p}"))
                .unwrap_or_default();
            println!("Embedding metadata from {meta_path}{spec_info}");
            match rsg_meta_from_file(&meta_path, meta_spec_path.as_deref()) {
                Ok(parsed) => meta = Some(parsed),
                Err(e) => {
                    println!("Could not load metadata from {meta_path}: {e}");
                    self.exit(R_UNKNOWN_ERROR);
                }
            }
        }
        if let Err(e) = self.try_sign_message(identity, &message_bytes, meta.as_ref(), output) {
            println!("Could not sign message: {e}");
        }
        self.exit(R_UNKNOWN_ERROR)
    }

    fn try_sign_message(
        &mut self,
        identity: &Identity,
        message: &[u8],
        meta: Option<&Vec<(String, Entry)>>,
        output: &str,
    ) -> Result<(), String> {
        match create_rsg(identity, RsgMessage::Bytes(message), true, meta, output)? {
            Rsg::Bin(rsg) => {
                let sig_ext = format!(".{MSG_EXT}");
                let mut rsg_path = expanduser(self.args.write.as_deref().unwrap_or_default());
                if !rsg_path.ends_with(&sig_ext) {
                    rsg_path.push_str(&sig_ext);
                }
                if isfile(&rsg_path) && !self.args.force {
                    println!("The signature file \"{rsg_path}\" already exists, not overwriting");
                    self.exit(R_FILE_EXISTS);
                }
                fs::write(&rsg_path, rsg).map_err(|e| io_error(&e, &rsg_path))?;
                println!(
                    "Message signed with {} saved to {rsg_path}",
                    id_str(identity)
                );
                self.exit(R_OK);
            }
            Rsg::Text(text) => println!("\n{}\n", wrap_rsg(&text)),
        }
        println!("Message signed with {}", id_str(identity));
        self.exit(R_OK)
    }

    // Encryption and decryption

    fn encrypt(&mut self, path: &str, identity: &Identity) {
        let encrypt_path = expanduser(path);
        let rfe_path = match self.args.write.clone().filter(|w| !w.is_empty()) {
            Some(write) => write,
            None => format!("{encrypt_path}.{ENCRYPT_EXT}"),
        };
        if identity.get_public_key().is_none() {
            println!("Cannot encrypt \"{encrypt_path}\", the identity does not hold a public key");
            self.exit(R_NO_PUBKEY);
        }
        if !isfile(&encrypt_path) {
            println!("The file \"{encrypt_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        if isfile(&rfe_path) && !self.args.force {
            println!("The encryption output file \"{rfe_path}\" already exists, not overwriting");
            self.exit(R_FILE_EXISTS);
        }
        let mut input = match fs::File::open(&encrypt_path) {
            Ok(file) => file,
            Err(e) => {
                println!(
                    "\nError reading {encrypt_path} for encryption: {}",
                    io_error(&e, &encrypt_path)
                );
                self.exit(R_WRITE_ERROR);
            }
        };
        let mut output = match fs::File::create(&rfe_path) {
            Ok(file) => file,
            Err(e) => {
                println!(
                    "\nError writing encrypted output to {rfe_path}: {}",
                    io_error(&e, &rfe_path)
                );
                self.exit(R_WRITE_ERROR);
            }
        };
        let mut wrote = 0usize;
        loop {
            let chunk = match read_chunk(&mut input, ENC_CHUNK) {
                Ok(chunk) => chunk,
                Err(e) => {
                    println!(
                        "\nError writing encrypted output to {rfe_path}: {}",
                        io_error(&e, &encrypt_path)
                    );
                    self.exit(R_WRITE_ERROR);
                }
            };
            let done = chunk.is_empty();
            if !done {
                let written = identity
                    .encrypt(&chunk, &mut OsRng)
                    .map_err(|e| format!("{e:?}"))
                    .and_then(|token| {
                        output
                            .write_all(&token)
                            .map(|_| token.len())
                            .map_err(|e| io_error(&e, &rfe_path))
                    });
                match written {
                    Ok(n) => wrote += n,
                    Err(e) => {
                        println!("\nError writing encrypted output to {rfe_path}: {e}");
                        self.exit(R_WRITE_ERROR);
                    }
                }
            }
            print!("\rWrote {} to {rfe_path}   ", prettysize(wrote as f64, "B"));
            if done {
                break;
            }
        }
        println!(
            "\nFile {encrypt_path} encrypted for {} to {rfe_path}",
            id_str(identity)
        );
    }

    fn decrypt(&mut self, path: &str, identity: &Identity) {
        let enc_ext = format!(".{ENCRYPT_EXT}");
        let rfe_path = expanduser(path);
        if !rfe_path.ends_with(&enc_ext) {
            println!("The file {rfe_path} does not appear to be a Reticulum encrypted file");
            self.exit(R_INVALID_FILE);
        }
        let decrypt_path = match self.args.write.clone().filter(|w| !w.is_empty()) {
            Some(write) => expanduser(&write),
            None => rfe_path[..rfe_path.len() - enc_ext.len()].to_string(),
        };
        if decrypt_path.is_empty() {
            println!("Invalid output filename");
            self.exit(R_INVALID_FILE);
        }
        if identity.get_private_key().is_none() {
            println!("Cannot decrypt \"{rfe_path}\", the identity does not hold a private key");
            self.exit(R_NO_PRVKEY);
        }
        if !isfile(&rfe_path) {
            println!("The file \"{rfe_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        if isfile(&decrypt_path) && !self.args.force {
            println!(
                "The decryption output file \"{decrypt_path}\" already exists, not overwriting"
            );
            self.exit(R_FILE_EXISTS);
        }
        let mut input = match fs::File::open(&rfe_path) {
            Ok(file) => file,
            Err(e) => {
                println!(
                    "\nError reading {rfe_path} for decryption: {}",
                    io_error(&e, &rfe_path)
                );
                self.exit(R_WRITE_ERROR);
            }
        };
        let mut output = match fs::File::create(&decrypt_path) {
            Ok(file) => file,
            Err(e) => {
                println!(
                    "\nError writing decrypted output to {decrypt_path}: {}",
                    io_error(&e, &decrypt_path)
                );
                self.exit(R_WRITE_ERROR);
            }
        };
        let mut wrote = 0usize;
        loop {
            let chunk = match read_chunk(&mut input, DEC_CHUNK) {
                Ok(chunk) => chunk,
                Err(e) => {
                    println!(
                        "\nError writing decrypted output to {decrypt_path}: {}",
                        io_error(&e, &rfe_path)
                    );
                    self.exit(R_WRITE_ERROR);
                }
            };
            if chunk.is_empty() {
                break;
            }
            // `if not decrypted`: an empty plaintext reads as a failure too.
            match identity.decrypt(&chunk) {
                Ok(plain) if !plain.is_empty() => {
                    if let Err(e) = output.write_all(&plain) {
                        println!(
                            "\nError writing decrypted output to {decrypt_path}: {}",
                            io_error(&e, &decrypt_path)
                        );
                        self.exit(R_WRITE_ERROR);
                    }
                    wrote += plain.len();
                }
                _ => {
                    println!("The provided identity could not decrypt the file");
                    self.exit(R_DECRYPT_FAILED);
                }
            }
            print!(
                "\rWrote {} to {decrypt_path}   ",
                prettysize(wrote as f64, "B")
            );
        }
        println!("\nFile {rfe_path} decrypted to {decrypt_path}");
    }

    // File output

    fn write_identity(&mut self, identity: &Identity) {
        let mut wp = expanduser(self.args.write.as_deref().unwrap_or_default());
        if let (Some(private), true) = (identity.get_private_key(), self.args.export_prv) {
            if !isfile(&wp) || self.args.force {
                key_to_file(&private, &wp);
                println!("Wrote private identity to {wp}");
            } else {
                println!("File {wp} already exists, not overwriting");
                self.exit(R_FILE_EXISTS);
            }
        } else if let Some(public) = identity.get_public_key() {
            if !wp.to_lowercase().ends_with(&format!(".{PUB_EXT}")) {
                wp.push_str(&format!(".{PUB_EXT}"));
            }
            if !isfile(&wp) || self.args.force {
                key_to_file(&public, &wp);
                println!("Wrote public identity to {wp}");
            } else {
                println!("File {wp} already exists, not overwriting");
                self.exit(R_FILE_EXISTS);
            }
        } else {
            println!("Identity holds neither a public nor private key");
            self.exit(R_NO_KEYS);
        }
    }

    // Terminal output

    fn encode_key(&self, key: &[u8]) -> String {
        if self.args.base64 {
            urlsafe_b64encode(key)
        } else if self.args.base32 {
            b32encode(key)
        } else {
            hexrep(key)
        }
    }

    fn print_identity_information(&self, identity: &Identity) {
        println!("Identity Hash : {}", id_str(identity));
        let public = identity.get_public_key().unwrap_or([0; KEYSIZE]);
        println!("Public Key    : {}", self.encode_key(&public));
        if let Some(private) = identity.get_private_key() {
            if self.args.print_private {
                println!("Private Key   : {}", self.encode_key(&private));
            } else {
                println!("Private Key   : Hidden");
            }
        }
    }

    fn print_hash_information(&mut self, target: &Target) {
        let hash = self.args.hash.clone().unwrap_or_default();
        let (identity_hash, destination) = match target {
            Target::None => {
                println!("Invalid identity");
                self.exit(R_INVALID_IDENTITY);
            }
            Target::Str(s) => {
                if s.chars().count() != 32 {
                    println!("Invalid identity hash length");
                    self.exit(R_INVALID_IDENTITY);
                }
                match fromhex(s) {
                    Ok(hash) => (hash, None),
                    Err(e) => {
                        println!("Invalid identity: {e}");
                        self.exit(R_INVALID_IDENTITY);
                    }
                }
            }
            Target::Identity(identity) => {
                // `str(RNS.Destination(identity, OUT, SINGLE, app, *aspects))`.
                let destination_hash = hash_from_name_and_identity(&hash, identity.hash());
                let full = format!(
                    "<{hash}.{}:{}>",
                    hexrep(identity.hash()),
                    hexrep(&destination_hash)
                );
                (identity.hash().to_vec(), Some(full))
            }
        };
        let destination_hash = hash_from_name_and_identity(&hash, &identity_hash);
        println!(
            "The {hash} destination for this Identity is {}",
            prettyhexrep(&destination_hash)
        );
        if let Some(destination) = destination {
            println!("The full destination specifier is {destination}");
        }
    }

    fn export_pub_identity(&mut self, identity: &Identity) {
        match identity.get_public_key() {
            None => {
                println!("Identity doesn't hold a public key, cannot export");
                self.exit(R_NO_PUBKEY);
            }
            Some(key) => println!("Public Identity Keys  : {}", self.encode_key(&key)),
        }
    }

    fn export_prv_identity(&mut self, identity: &Identity) {
        match identity.get_private_key() {
            None => {
                println!("Identity doesn't hold a private key, cannot export");
                self.exit(R_NO_PRVKEY);
            }
            Some(key) => println!("Private Identity Keys : {}", self.encode_key(&key)),
        }
    }

    // Helpers

    fn get_editor_content(&mut self) -> Vec<u8> {
        let mut editor = std::env::var("EDITOR").unwrap_or_default();
        if editor.is_empty() {
            for fallback in ["nano", "vim", "vi"] {
                let found = process::Command::new("which")
                    .arg(fallback)
                    .stdout(process::Stdio::null())
                    .stderr(process::Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if found {
                    editor = fallback.into();
                    break;
                }
            }
        }
        if editor.is_empty() {
            println!("Could not launch editor");
            self.exit(R_READ_ERROR);
        }
        let tmp = std::env::temp_dir().join(format!("tmp-rnid-{}.tmp", process::id()));
        let tmp_name = tmp.to_string_lossy().into_owned();
        if let Err(e) = fs::write(&tmp, b"") {
            println!(
                "Could not get content from editor: {}",
                io_error(&e, &tmp_name)
            );
            self.exit(R_READ_ERROR);
        }
        let status = match process::Command::new(&editor).arg(&tmp).status() {
            Ok(status) => status,
            Err(e) => {
                println!(
                    "Could not get content from editor: {}",
                    io_error(&e, &editor)
                );
                self.exit(R_READ_ERROR);
            }
        };
        if !status.success() {
            println!(
                "Editor exited with error code {}",
                status.code().unwrap_or(-1)
            );
            let _ = fs::remove_file(&tmp);
            self.exit(R_READ_ERROR);
        }
        let content = fs::read(&tmp);
        let _ = fs::remove_file(&tmp);
        match content {
            Ok(content) => content,
            Err(e) => {
                println!(
                    "Could not get content from editor: {}",
                    io_error(&e, &tmp_name)
                );
                self.exit(R_READ_ERROR);
            }
        }
    }
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

/// A created signature: written as bytes, or printed as text.
enum Rsg {
    Bin(Vec<u8>),
    Text(String),
}

/// `get_rsg_hash`.
fn rsg_hash(message: &RsgMessage) -> Result<[u8; 32], String> {
    match message {
        RsgMessage::Bytes(bytes) => Ok(sha256(bytes)),
        RsgMessage::File(path) => {
            let mut file = fs::File::open(path).map_err(|e| io_error(&e, path))?;
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let n = file.read(&mut buf).map_err(|e| io_error(&e, path))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hasher.digest())
        }
    }
}

fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Str(s) if s == key))
        .map(|(_, v)| v)
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Nil => "NoneType",
        Value::Bool(_) => "bool",
        Value::UInt(_) | Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Bin(_) => "bytes",
        Value::Str(_) => "str",
        Value::Array(_) => "list",
        Value::Map(_) => "dict",
    }
}

fn not_iterable(value: &Value) -> String {
    format!("argument of type '{}' is not iterable", type_name(value))
}

fn clone_identity(identity: &Identity) -> Identity {
    match (identity.get_private_key(), identity.get_public_key()) {
        (Some(private), _) => Identity::from_private_key(&private),
        (None, Some(public)) => Identity::from_public_key(&public).expect("a loaded key"),
        (None, None) => unreachable!("an identity holds a key"),
    }
}

/// `create_rsg`.
fn create_rsg(
    signer: &Identity,
    message: RsgMessage,
    embed: bool,
    meta: Option<&Vec<(String, Entry)>>,
    output: &str,
) -> Result<Rsg, String> {
    let (Some(_), Some(public)) = (signer.get_private_key(), signer.get_public_key()) else {
        return Err(format!("{} does not hold a private key", id_str(signer)));
    };
    let mut meta_map = vec![
        (
            Value::Str("signer".into()),
            Value::Bin(signer.hash().to_vec()),
        ),
        (Value::Str("pubkey".into()), Value::Bin(public.to_vec())),
    ];
    if let Some(meta) = meta.filter(|m| !m.is_empty()) {
        for (key, entry) in meta {
            if key != "signer" && key != "pubkey" {
                meta_map.push((Value::Str(key.clone()), entry_value(entry)));
            }
        }
    }
    let mut signed = vec![
        (Value::Str("hashtype".into()), Value::Str("sha256".into())),
        (
            Value::Str("hash".into()),
            Value::Bin(rsg_hash(&message)?.to_vec()),
        ),
        (Value::Str("meta".into()), Value::Map(meta_map)),
    ];
    if embed {
        let bytes = match message {
            RsgMessage::Bytes(bytes) => bytes.to_vec(),
            RsgMessage::File(path) => fs::read(path).map_err(|e| io_error(&e, path))?,
        };
        signed.push((Value::Str("message".into()), Value::Bin(bytes)));
    }
    let envelope = msgpack::pack(&Value::Map(signed));
    let signature = signer.sign(&envelope).map_err(|e| format!("{e:?}"))?;
    let mut rsg_data = signature.to_vec();
    rsg_data.extend_from_slice(&envelope);
    Ok(match output {
        "hex" => Rsg::Text(hexrep(&rsg_data)),
        "base32" => Rsg::Text(b32encode(&rsg_data)),
        "base64" => Rsg::Text(urlsafe_b64encode(&rsg_data)),
        "base256" => Rsg::Text(rns_core::display::b256rep(&rsg_data)),
        _ => Rsg::Bin(rsg_data),
    })
}

/// A ConfigObj value as umsgpack packs it.
fn entry_value(entry: &Entry) -> Value {
    match entry {
        Entry::Str(s) => Value::Str(s.clone()),
        Entry::Int(n) if *n >= 0 => Value::UInt(*n as u64),
        Entry::Int(n) => Value::Int(*n),
        Entry::Float(f) => Value::Float(*f),
        Entry::Bool(b) => Value::Bool(*b),
        Entry::List(items) => Value::Array(items.iter().map(entry_value).collect()),
        Entry::Section(section) => Value::Map(
            section
                .entries()
                .iter()
                .map(|(k, v)| (Value::Str(k.clone()), entry_value(v)))
                .collect(),
        ),
    }
}

/// `wrap_rsg`: rows of 64 characters between a header and a footer, the
/// last row padded with `=`.
fn wrap_rsg(rsg: &str) -> String {
    let header_len = RSG_ASCII_HEADER.chars().count();
    let footer_len = RSG_ASCII_FOOTER.chars().count();
    let mut wrapped = format!(
        "{RSG_ASCII_HEADER}{}\n",
        "#".repeat(RSG_ASCII_ROW_WIDTH - header_len)
    );
    let chars: Vec<char> = rsg.chars().collect();
    for chunk in chars.chunks(RSG_ASCII_ROW_WIDTH) {
        let mut row: String = chunk.iter().collect();
        row.push_str(&"=".repeat(RSG_ASCII_ROW_WIDTH - chunk.len()));
        wrapped.push_str(&row);
        wrapped.push('\n');
    }
    wrapped.push_str(&"#".repeat(RSG_ASCII_ROW_WIDTH - footer_len));
    wrapped.push_str(RSG_ASCII_FOOTER);
    wrapped
}

/// `extract_signed_rsg_data`.
fn extract_signed_rsg_data(rsg: &[u8]) -> Option<Value> {
    msgpack::unpack_exact(rsg.get(SIGLEN..)?).ok()
}

/// `validate_rsg`: whether the signature is valid, the signed data and
/// the identity that signed it.
fn validate_rsg(
    rsg_data: &[u8],
    message: RsgMessage,
    required_signer: &Signer,
) -> Result<(bool, Option<Value>, Option<Identity>), String> {
    if let RsgMessage::Bytes(bytes) = &message {
        if bytes.is_empty() {
            return Err("No message specified for rsg validation".into());
        }
    }
    let rsg_hash = rsg_hash(&message)?;
    if rsg_data.len() == SIGLEN {
        return Err("Cannot validate legacy rsg format".into());
    }
    if rsg_data.len() < SIGLEN + 1 {
        return Ok((false, None, None));
    }
    let signature: &[u8; SIGLEN] = rsg_data[..SIGLEN].try_into().expect("length");
    let envelope = &rsg_data[SIGLEN..];
    let Ok(signed_data) = msgpack::unpack_exact(envelope) else {
        return Ok((false, None, None));
    };
    let signed = match &signed_data {
        Value::Map(entries) => entries,
        Value::Array(_) | Value::Str(_) => return Ok((false, None, None)),
        other => return Err(not_iterable(other)),
    };
    let (Some(hashtype), Some(hash)) = (map_get(signed, "hashtype"), map_get(signed, "hash"))
    else {
        return Ok((false, None, None));
    };
    if !matches!(hashtype, Value::Str(s) if s == "sha256") {
        return Ok((false, None, None));
    }
    let meta = match map_get(signed, "meta") {
        None => return Ok((false, None, None)),
        Some(Value::Map(meta)) => meta,
        Some(Value::Array(_) | Value::Str(_)) => return Ok((false, None, None)),
        Some(other) => return Err(not_iterable(other)),
    };
    if map_get(meta, "signer").is_none() {
        return Ok((false, None, None));
    }
    let Some(pubkey) = map_get(meta, "pubkey") else {
        return Ok((false, None, None));
    };
    let signing_identity = match required_signer {
        Signer::Identity(identity) => clone_identity(identity),
        _ => {
            let Value::Bin(pubkey) = pubkey else {
                return Ok((false, None, None));
            };
            let Ok(key) = <&[u8; KEYSIZE]>::try_from(pubkey.as_slice()) else {
                return Ok((false, None, None));
            };
            match Identity::from_public_key(key) {
                Ok(identity) => identity,
                Err(_) => return Ok((false, None, None)),
            }
        }
    };
    let required_hash = match required_signer {
        Signer::Hash(hash) => hash.clone(),
        _ => signing_identity.hash().to_vec(),
    };
    if signing_identity.hash()[..] != required_hash[..] {
        return Ok((false, None, Some(signing_identity)));
    }
    if !matches!(hash, Value::Bin(h) if h[..] == rsg_hash[..]) {
        return Ok((false, None, Some(signing_identity)));
    }
    let valid = signing_identity.verify(signature, envelope);
    Ok((valid, Some(signed_data.clone()), Some(signing_identity)))
}

/// `rsg_meta_from_file`.
fn rsg_meta_from_file(path: &str, spec_path: Option<&str>) -> Result<Vec<(String, Entry)>, String> {
    let read = |p: &str| fs::read_to_string(p).map_err(|e| io_error(&e, p));
    let spec = match spec_path {
        Some(spec_path) => Some(configobj::parse(&read(spec_path)?)?),
        None => None,
    };
    let mut parsed = configobj::parse(&read(path)?)?;
    if let Some(spec) = spec {
        if !configobj::validate(&mut parsed, &spec) {
            return Err("Metadata did not pass spec validation".into());
        }
    }
    Ok(parsed.entries())
}

/// Python's `str()` of a msgpack value.
fn py_str(value: &Value) -> String {
    match value {
        Value::Str(s) => s.clone(),
        other => py_repr(other),
    }
}

/// Python's `repr()` of a msgpack value.
fn py_repr(value: &Value) -> String {
    match value {
        Value::Nil => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::UInt(n) => n.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => rns_cli::format::python_float(*f),
        Value::Str(s) => rns_cli::argparse::repr(s),
        Value::Bin(b) => rns_cli::pyfmt::str_of(&rns_net::pickle::PickleValue::Bytes(b.clone())),
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
fn recurse(entry: &Value, key: &str, level: usize) {
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
fn utf8_error(bytes: &[u8], e: std::str::Utf8Error) -> String {
    let at = e.valid_up_to();
    let byte = bytes.get(at).copied().unwrap_or(0);
    let reason = match e.error_len() {
        None => "unexpected end of data",
        Some(_) if (0x80..0xc2).contains(&byte) || byte >= 0xf5 => "invalid start byte",
        Some(_) => "invalid continuation byte",
    };
    format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {at}: {reason}")
}

fn decode_utf8(bytes: &[u8]) -> Result<String, String> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|e| utf8_error(bytes, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(argv: &[&str]) -> Namespace {
        Namespace::from_args(&Args::parse_spec_from(
            argv.iter().map(|s| s.to_string()).collect(),
            &OPTIONS,
        ))
    }

    #[test]
    fn namespace_is_argparses() {
        let parsed = ns(&["-i", "x", "-e", "a", "b", "-f"]);
        assert_eq!(parsed.encrypt, Some(vec!["a".into(), "b".into()]));
        assert!(parsed.force);
        assert_eq!(ns(&["-e"]).encrypt, Some(vec![]));
        assert_eq!(ns(&["-a"]).announce.as_deref(), Some("rns.id"));
        assert_eq!(ns(&["-S"]).sign_message, Some(MessageArg::NoMessage));
        assert_eq!(
            ns(&["-S", "hi"]).sign_message,
            Some(MessageArg::Text("hi".into()))
        );
        assert_eq!(ns(&["-E"]).embed_meta, Some(MetaArg::NoMeta));
        assert_eq!(ns(&["-t", "2.5"]).t, 2.5);
        assert_eq!(ns(&[]).t, 15.0);
        assert!(ns(&["-Z"]).base256);
        assert_eq!(ns(&["-s", "a", "-s", "b"]).sign, Some(vec!["b".into()]));
    }

    #[test]
    fn rsg_wrapping_is_upstreams() {
        let wrapped = wrap_rsg("abc");
        let lines: Vec<&str> = wrapped.lines().collect();
        assert_eq!(
            lines[0],
            "#### Start of rsg data #########################################"
        );
        assert_eq!(lines[1], format!("abc{}", "=".repeat(61)));
        assert_eq!(
            lines[2],
            "########################################### End of rsg data ####"
        );
    }

    #[test]
    fn destination_names_hash_as_upstream() {
        // The identity of private key bytes 0..64.
        let identity = Identity::from_private_key(&std::array::from_fn(|i| i as u8));
        assert_eq!(hexrep(identity.hash()), "aca31af0441d81dbec71e82da0b4b5f5");
        assert_eq!(
            hexrep(&hash_from_name_and_identity("app.aspect", identity.hash())),
            "e246e72c1cc4c414f117c4d9630b9444"
        );
    }

    #[test]
    fn expanduser_is_pythons() {
        assert_eq!(expanduser("a/~"), "a/~");
        assert_eq!(expanduser("~nosuchuser12345/a"), "~nosuchuser12345/a");
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(
            expanduser("~/a"),
            format!("{}/a", home.trim_end_matches('/'))
        );
    }
}
