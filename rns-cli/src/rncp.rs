//! rncp - Reticulum File Transfer Utility.
//!
//! Ported from upstream's rncp statement by statement: the same output
//! (progress lines, messages, `RNS.log` lines on stdout), exit codes,
//! identity location, allowed identities, fetch jail and saved file names.


use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, IdentityHash, LinkId};
use rns_net::destination::Destination;
use rns_net::{
    AnnouncedIdentity, Callbacks, ReceivedResourceFile, ResourceReceiveMode, ResourceTransferError,
    ResourceTransferId, RnsNode,
};

use crate::app;
use crate::args::{Args, Opt, OptionSpec};
use crate::pyfmt::{prettyhexrep, prettysize, prettytime, round_float, Num};
use crate::pylog::{
    self, abspath, basename, expanduser, LOG_ERROR, LOG_INFO, LOG_NOTICE, LOG_VERBOSE, LOG_WARNING,
};

const APP_NAME: &str = "rncp";
const ASPECT: &str = "receive";
const FETCH_PATH: &str = "fetch_file";
const REQ_FETCH_NOT_ALLOWED: u64 = 0xF0;
const VERSION: &str = env!("FULL_VERSION");
/// `RNS.Transport.PATH_REQUEST_TIMEOUT`, the default of `-w`.
const PATH_REQUEST_TIMEOUT: f64 = 15.0;
const ERASE: &str = "\x1b[2K\r";
const ES: &str = " ";
const SYMS: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];
const STATS_MAX: usize = 32;

/// upstream rncp's options, and Rust-only long names for -i, -a, -b and -w.
pub(crate) const OPTIONS: OptionSpec = OptionSpec {
    options: &[
        Opt::value("", "config"),
        Opt::count("v", "verbose"),
        Opt::count("q", "quiet"),
        Opt::flag("S", "silent"),
        Opt::flag("l", "listen"),
        Opt::flag("C", "no-compress"),
        Opt::flag("F", "allow-fetch"),
        Opt::flag("f", "fetch"),
        Opt::value("j", "jail"),
        Opt::value("s", "save"),
        Opt::flag("O", "overwrite"),
        Opt::value("b", "announce").rust_only(),
        Opt::value("a", "allowed").rust_only(),
        Opt::flag("n", "no-auth"),
        Opt::flag("p", "print-identity"),
        Opt::value("i", "identity").rust_only(),
        Opt::value("w", "timeout").rust_only(),
        Opt::flag("P", "phy-rates"),
    ],
};

/// upstream's argparse namespace.
#[derive(Debug)]
struct Namespace {
    file: Option<String>,
    destination: Option<String>,
    config: Option<String>,
    verbose: i32,
    quiet: i32,
    silent: bool,
    listen: bool,
    no_compress: bool,
    allow_fetch: bool,
    fetch: bool,
    jail: Option<String>,
    save: Option<String>,
    overwrite: bool,
    b: i64,
    allowed: Option<Vec<String>>,
    no_auth: bool,
    print_identity: bool,
    identity: Option<String>,
    w: f64,
    phy_rates: bool,
}

impl Namespace {
    fn from_args(args: &Args) -> Self {
        let value = |short: &str, long: &str| {
            args.get(short)
                .or_else(|| args.get(long))
                .map(str::to_string)
        };
        let mut allowed: Vec<String> = args.get_all("a").into_iter().map(str::to_string).collect();
        if allowed.is_empty() {
            allowed = args
                .get_all("allowed")
                .into_iter()
                .map(str::to_string)
                .collect();
        }
        Namespace {
            file: args.positional.first().cloned(),
            destination: args.positional.get(1).cloned(),
            config: args.get("config").map(str::to_string),
            verbose: i32::from(args.verbosity),
            quiet: i32::from(args.quiet),
            silent: args.has("S") || args.has("silent"),
            listen: args.has("l") || args.has("listen"),
            no_compress: args.has("C") || args.has("no-compress"),
            allow_fetch: args.has("F") || args.has("allow-fetch"),
            fetch: args.has("f") || args.has("fetch"),
            jail: value("j", "jail"),
            save: value("s", "save"),
            overwrite: args.has("O") || args.has("overwrite"),
            b: value("b", "announce")
                .and_then(|b| crate::argparse::python_int(&b))
                .unwrap_or(-1),
            allowed: (!allowed.is_empty()).then_some(allowed),
            no_auth: args.has("n") || args.has("no-auth"),
            print_identity: args.has("p") || args.has("print-identity"),
            identity: value("i", "identity"),
            w: value("w", "timeout")
                .and_then(|w| crate::argparse::python_float(&w))
                .unwrap_or(PATH_REQUEST_TIMEOUT),
            phy_rates: args.has("P") || args.has("phy-rates"),
        }
    }
}

enum RncpEvent {
    LinkEstablished([u8; 16], bool),
    LinkClosed([u8; 16]),
    Identified([u8; 16], [u8; 16]),
    ResourceStarted([u8; 16], Vec<u8>, u64),
    ResourceFailed([u8; 16]),
    FileReceived([u8; 16], ReceivedResourceFile),
    StreamCompleted(ResourceTransferId),
    StreamFailed(ResourceTransferId),
    StreamProgress(ResourceTransferId, u64, u64),
    ReceiveProgress([u8; 16], u64, u64),
    /// The segment in transfer on a link: its progress and transfer size.
    SegmentProgress([u8; 16], f64, u64),
    Response(Vec<u8>),
    RequestFailed,
    FetchRequested([u8; 16], String),
}

struct RncpCallbacks {
    tx: mpsc::Sender<RncpEvent>,
    allowed: Arc<Mutex<HashSet<[u8; 16]>>>,
    allow_all: bool,
    identified: HashMap<[u8; 16], [u8; 16]>,
}

impl Callbacks for RncpCallbacks {
    fn on_announce(&mut self, _announced: AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}
    fn on_local_delivery(
        &mut self,
        _dest_hash: DestHash,
        _raw: Vec<u8>,
        _packet_hash: rns_core::types::PacketHash,
    ) {
    }
    fn on_link_established(
        &mut self,
        link_id: LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        is_initiator: bool,
    ) {
        let _ = self
            .tx
            .send(RncpEvent::LinkEstablished(link_id.0, is_initiator));
    }
    fn on_link_closed(&mut self, link_id: LinkId, _reason: Option<rns_core::link::TeardownReason>) {
        self.identified.remove(&link_id.0);
        let _ = self.tx.send(RncpEvent::LinkClosed(link_id.0));
    }
    fn on_remote_identified(
        &mut self,
        link_id: LinkId,
        identity_hash: IdentityHash,
        _public_key: [u8; 64],
    ) {
        self.identified.insert(link_id.0, identity_hash.0);
        let _ = self
            .tx
            .send(RncpEvent::Identified(link_id.0, identity_hash.0));
    }
    /// `receive_resource_callback`: from an allowed sender, or anyone with
    /// `-n`.
    fn on_resource_accept_query(
        &mut self,
        link_id: LinkId,
        _resource_hash: Vec<u8>,
        _transfer_size: u64,
        _has_metadata: bool,
    ) -> bool {
        let allowed = self.allowed.lock().unwrap_or_else(|p| p.into_inner());
        self.identified
            .get(&link_id.0)
            .is_some_and(|identity| allowed.contains(identity))
            || self.allow_all
    }
    fn on_resource_started(&mut self, link_id: LinkId, resource_hash: Vec<u8>, data_size: u64) {
        let _ = self.tx.send(RncpEvent::ResourceStarted(
            link_id.0,
            resource_hash,
            data_size,
        ));
    }
    fn on_resource_failed(&mut self, link_id: LinkId, _error: String) {
        let _ = self.tx.send(RncpEvent::ResourceFailed(link_id.0));
    }
    fn on_resource_file_received(&mut self, link_id: LinkId, resource: ReceivedResourceFile) {
        let _ = self.tx.send(RncpEvent::FileReceived(link_id.0, resource));
    }
    fn on_resource_stream_completed(&mut self, _link_id: LinkId, transfer_id: ResourceTransferId) {
        let _ = self.tx.send(RncpEvent::StreamCompleted(transfer_id));
    }
    fn on_resource_stream_failed(
        &mut self,
        _link_id: LinkId,
        transfer_id: ResourceTransferId,
        _error: ResourceTransferError,
    ) {
        let _ = self.tx.send(RncpEvent::StreamFailed(transfer_id));
    }
    fn on_resource_stream_progress(
        &mut self,
        _link_id: LinkId,
        transfer_id: ResourceTransferId,
        transferred: u64,
        total: u64,
    ) {
        let _ = self
            .tx
            .send(RncpEvent::StreamProgress(transfer_id, transferred, total));
    }
    fn on_resource_segment_progress(
        &mut self,
        link_id: LinkId,
        segment_progress: f64,
        transfer_size: u64,
    ) {
        let _ = self.tx.send(RncpEvent::SegmentProgress(
            link_id.0,
            segment_progress,
            transfer_size,
        ));
    }
    fn on_resource_progress(&mut self, link_id: LinkId, received: usize, total: usize) {
        let _ = self.tx.send(RncpEvent::ReceiveProgress(
            link_id.0,
            received as u64,
            total as u64,
        ));
    }
    fn on_response_with_metadata(
        &mut self,
        _link_id: LinkId,
        _request_id: [u8; 16],
        data: Vec<u8>,
        _metadata: Option<Vec<u8>>,
    ) {
        let _ = self.tx.send(RncpEvent::Response(data));
    }
    fn on_request_failed(
        &mut self,
        _link_id: LinkId,
        _request_id: [u8; 16],
        _reason: rns_net::link_manager::RequestFailure,
    ) {
        let _ = self.tx.send(RncpEvent::RequestFailed);
    }
}

pub fn main() -> i32 {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let args = Args::parse_spec_from(arguments, &OPTIONS);
    crate::argparse::enforce(&args, "rncp", "rncp");
    if args.has("version") {
        println!("rncp {VERSION}");
        return 0;
    }
    if args.has("help") || args.has("h") {
        usage();
        return 0;
    }
    // `except KeyboardInterrupt: print(""); ... RNS.exit()`, until a
    // Reticulum instance installs its own handler.
    crate::stdout::exit_on_interrupt_after_newline(0);
    let args = Namespace::from_args(&args);
    let mut rncp = Rncp {
        args,
        node: None,
        events: None,
        tx: None,
        allowed: Arc::new(Mutex::new(HashSet::new())),
        state: State::default(),
    };
    if rncp.args.listen || rncp.args.print_identity {
        rncp.listen()
    } else if rncp.args.fetch {
        if rncp.args.destination.is_some() && rncp.args.file.is_some() {
            rncp.fetch()
        } else {
            println!();
            usage();
            println!();
            0
        }
    } else if rncp.args.destination.is_some() && rncp.args.file.is_some() {
        rncp.send()
    } else {
        println!();
        usage();
        println!();
        0
    }
}

/// Upstream's progress statistics (`sender_progress`): the speed over the
/// last 32 updates.
#[derive(Default)]
struct Progress {
    stats: Vec<(Instant, f64, f64)>,
    speed: f64,
    phy_speed: f64,
}

impl Progress {
    fn update(&mut self, got: f64, phy_got: f64) {
        let now = Instant::now();
        self.stats.push((now, got, phy_got));
        while self.stats.len() > STATS_MAX {
            self.stats.remove(0);
        }
        let span = now.duration_since(self.stats[0].0).as_secs_f64();
        if span == 0.0 {
            self.speed = 0.0;
            self.phy_speed = 0.0;
        } else {
            self.speed = (got - self.stats[0].1) / span;
            let phy_diff = phy_got - self.stats[0].2;
            if phy_diff > 0.0 {
                self.phy_speed = phy_diff / span;
            }
        }
    }
}

/// `round(prg * 100.0, 1)` as Python prints it.
fn percent(prg: f64) -> String {
    crate::format::python_float(round_float(prg * 100.0, 1))
}

/// `size_str`, which is `RNS.prettysize`.
fn size_str(num: f64, suffix: &str) -> String {
    prettysize(num, suffix)
}

fn flush() {
    let _ = std::io::stdout().flush();
}

/// Where received files go: `-s`, checked as upstream checks it.
fn checked_save_path(save: &str) -> Result<String, (i32, &'static str)> {
    let sp = abspath(&expanduser(save));
    if !Path::new(&sp).is_dir() {
        return Err((3, "Output directory not found"));
    }
    if !crate::sys::is_writable(&sp) {
        return Err((4, "Output directory not writable"));
    }
    Ok(sp)
}

/// Why a received file was not saved.
enum SaveError {
    /// Upstream's own message.
    Message(String),
    /// An exception, reported as "An error occurred while saving ...".
    Exception(String),
}

/// Save a received file as upstream does: under the sender's file name in
/// the save directory (or the current one), with a counter appended while
/// the name is taken. `warn` gets the overwrite failure message.
fn save_received(
    resource: ReceivedResourceFile,
    save_path: Option<&str>,
    overwrite: bool,
    warn: &mut dyn FnMut(String),
) -> Result<String, SaveError> {
    let name = resource
        .metadata
        .as_deref()
        .and_then(|m| msgpack::unpack_exact(m).ok())
        .and_then(|m| match m {
            Value::Map(entries) => entries.into_iter().find_map(|(k, v)| match k {
                Value::Str(k) if k == "name" => Some(v),
                _ => None,
            }),
            _ => None,
        });
    let name = match name {
        Some(Value::Bin(bytes)) => String::from_utf8(bytes).map_err(|e| {
            let at = e.utf8_error().valid_up_to();
            SaveError::Exception(format!(
                "'utf-8' codec can't decode byte 0x{:02x} in position {at}: invalid start byte",
                e.as_bytes()[at]
            ))
        })?,
        Some(Value::Str(_)) => {
            return Err(SaveError::Exception(
                "'str' object has no attribute 'decode'".into(),
            ))
        }
        _ => return Err(SaveError::Exception("'name'".into())),
    };
    let filename = basename(&name).to_string();
    let saved_filename = match save_path {
        Some(save_path) => {
            let saved = abspath(&expanduser(&format!("{save_path}/{filename}")));
            if !saved.starts_with(&format!("{save_path}/")) {
                return Err(SaveError::Message(format!(
                    "Invalid save path {saved}, ignoring"
                )));
            }
            saved
        }
        None => filename,
    };
    let mut full_save_path = saved_filename.clone();
    if overwrite
        && Path::new(&full_save_path).is_file()
        && std::fs::remove_file(&full_save_path).is_err()
    {
        warn(format!(
            "Could not overwrite existing file {full_save_path}, renaming instead"
        ));
    }
    let mut counter = 0;
    while Path::new(&full_save_path).is_file() {
        counter += 1;
        full_save_path = format!("{saved_filename}.{counter}");
    }
    resource
        .persist(&full_save_path, false)
        .map(|_| full_save_path.clone())
        .map_err(|e| SaveError::Exception(pylog::oserror(&e, &full_save_path)))
}

/// `bytes.fromhex` of a destination, with upstream's messages.
fn destination_hash(destination: &str) -> Result<[u8; 16], &'static str> {
    if crate::pyfmt::len(destination) != 32 {
        return Err(
            "Allowed destination length is invalid, must be 32 hexadecimal characters (16 bytes).",
        );
    }
    pylog::fromhex(destination)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .ok_or("Invalid destination entered. Check your input.")
}

/// Resource status, numbered as upstream's `RNS.Resource` states.
const ADVERTISED: u8 = 0x02;
const TRANSFERRING: u8 = 0x03;
const COMPLETE: u8 = 0x06;
const FAILED: u8 = 0x07;

/// What the callbacks have reported, for the waiting loops.
#[derive(Default)]
struct State {
    link_id: Option<[u8; 16]>,
    link_active: bool,
    transfer: Option<ResourceTransferId>,
    status: u8,
    prg: f64,
    total_size: f64,
    /// upstream's `get_segment_progress()` and `get_transfer_size()` of
    /// the resource in transfer, for the physical layer rate.
    segment_progress: f64,
    transfer_size: f64,
    progress: Progress,
    request_status: Option<&'static str>,
    /// When the fetched resource started, and its size.
    started: Option<Instant>,
    /// Whether the fetched resource reported progress (upstream's
    /// `current_resource`).
    current_resource: bool,
    received: Option<ReceivedResourceFile>,
    resource_failed: bool,
}

impl State {
    /// upstream's `phy_got`: the bytes of the current segment on the wire.
    fn phy_got(&self) -> f64 {
        self.segment_progress * self.transfer_size
    }

    fn apply(&mut self, event: RncpEvent) {
        let ours = |id: &[u8; 16], link: Option<[u8; 16]>| link.as_ref() == Some(id);
        match event {
            RncpEvent::LinkEstablished(id, true) if ours(&id, self.link_id) => {
                self.link_active = true
            }
            RncpEvent::LinkClosed(id) if ours(&id, self.link_id) => {
                self.link_active = false;
                if (ADVERTISED..COMPLETE).contains(&self.status) {
                    self.status = FAILED;
                }
            }
            RncpEvent::StreamProgress(t, done, total) if Some(t) == self.transfer => {
                self.status = self.status.max(TRANSFERRING);
                self.prg = done as f64 / total.max(1) as f64;
                let got = self.prg * self.total_size;
                self.progress.update(got, self.phy_got());
            }
            RncpEvent::StreamCompleted(t) if Some(t) == self.transfer => {
                self.status = COMPLETE;
                self.prg = 1.0;
                self.segment_progress = 1.0;
                self.progress.update(self.total_size, self.phy_got());
            }
            RncpEvent::SegmentProgress(id, segment_progress, transfer_size)
                if ours(&id, self.link_id) =>
            {
                self.segment_progress = segment_progress;
                self.transfer_size = transfer_size as f64;
            }
            RncpEvent::StreamFailed(t) if Some(t) == self.transfer => self.status = FAILED,
            RncpEvent::Response(data) => {
                self.request_status = Some(match msgpack::unpack_exact(&data) {
                    Ok(Value::Bool(false)) | Ok(Value::UInt(0)) | Ok(Value::Int(0)) => "not_found",
                    Ok(Value::Nil) => "remote_error",
                    Ok(Value::UInt(REQ_FETCH_NOT_ALLOWED)) => "fetch_not_allowed",
                    Ok(Value::Int(n)) if n == REQ_FETCH_NOT_ALLOWED as i64 => "fetch_not_allowed",
                    _ => "found",
                })
            }
            RncpEvent::RequestFailed => self.request_status = Some("unknown"),
            RncpEvent::ResourceStarted(id, _, size) if ours(&id, self.link_id) => {
                self.started.get_or_insert_with(Instant::now);
                self.total_size = size as f64;
            }
            RncpEvent::ReceiveProgress(id, received, total) if ours(&id, self.link_id) => {
                self.current_resource = true;
                self.prg = (received as f64 / total.max(1) as f64).min(1.0);
                let got = self.prg * self.total_size;
                self.progress.update(got, self.phy_got());
            }
            RncpEvent::FileReceived(id, resource) if ours(&id, self.link_id) => {
                self.current_resource = true;
                self.prg = 1.0;
                self.received = Some(resource);
            }
            RncpEvent::ResourceFailed(id) if ours(&id, self.link_id) => self.resource_failed = true,
            _ => {}
        }
    }
}

struct Rncp {
    args: Namespace,
    node: Option<RnsNode>,
    events: Option<mpsc::Receiver<RncpEvent>>,
    tx: Option<mpsc::Sender<RncpEvent>>,
    allowed: Arc<Mutex<HashSet<[u8; 16]>>>,
    state: State,
}

impl Rncp {
    /// `RNS.exit(code)`. Before Reticulum has started, upstream's exit
    /// handler raises instead (it reaches for the missing instance), so
    /// the process ends with that exception: status 1.
    fn exit(&mut self, code: i32) -> ! {
        flush();
        match self.node.take() {
            Some(node) => {
                node.shutdown();
                std::process::exit(code)
            }
            None => {
                eprintln!(
                    "AttributeError: 'NoneType' object has no attribute 'unwants_all_destination_types'"
                );
                std::process::exit(1)
            }
        }
    }

    fn node(&self) -> &RnsNode {
        self.node.as_ref().expect("Reticulum is running")
    }

    fn config_dir(&self) -> std::path::PathBuf {
        rns_net::storage::resolve_config_dir(self.args.config.as_deref().map(Path::new))
    }

    /// `RNS.Reticulum(configdir, loglevel=3+verbosity-quietness)`: attached
    /// to a shared instance, or an instance of its own.
    fn start_reticulum(&mut self, allow_all: bool) {
        let level = (3 + self.args.verbose - self.args.quiet).clamp(0, 8);
        pylog::install_utility_logging(self.args.config.as_deref(), Some(level), 0, false);
        let config_dir = self.config_dir();
        let (tx, rx) = mpsc::channel();
        let callbacks = || {
            Box::new(RncpCallbacks {
                tx: tx.clone(),
                allowed: Arc::clone(&self.allowed),
                allow_all,
                identified: HashMap::new(),
            })
        };
        let node = match RnsNode::connect_shared_from_config(Some(&config_dir), callbacks()) {
            Ok(node) => node,
            Err(_) => match RnsNode::from_config(Some(&config_dir), callbacks()) {
                Ok(node) => node,
                Err(e) => {
                    pylog::log(&format!("Could not start Reticulum: {e}"), LOG_ERROR);
                    self.exit(1);
                }
            },
        };
        self.node = Some(node);
        self.events = Some(rx);
        self.tx = Some(tx);
        // Reticulum's own handler: exit quietly with 0.
        crate::stdout::exit_on_interrupt(0);
    }

    /// `prepare_identity`: the identity at `-i`, or at `rncp` in the
    /// instance's identities directory, created when there is none.
    fn prepare_identity(&mut self) -> rns_crypto::identity::Identity {
        let identity_path = match &self.args.identity {
            Some(path) => path.clone(),
            None => self
                .config_dir()
                .join("storage")
                .join("identities")
                .join(APP_NAME)
                .to_string_lossy()
                .into_owned(),
        };
        if Path::new(&identity_path).is_file() {
            match pylog::identity_from_file(&identity_path) {
                Some(identity) => return identity,
                None => {
                    pylog::log(&format!("Could not load identity for rncp. The identity file at \"{identity_path}\" may be corrupt or unreadable."), LOG_ERROR);
                    self.exit(2);
                }
            }
        }
        pylog::log("No valid saved identity found, creating new...", LOG_INFO);
        let identity = pylog::new_identity();
        pylog::key_to_file(
            &identity.get_private_key().unwrap_or([0; 64]),
            &identity_path,
        );
        identity
    }

    /// Handle the events that arrive within `duration`.
    fn pump(&mut self, duration: Duration) {
        let until = Instant::now() + duration;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            let Some(events) = self.events.as_ref() else {
                std::thread::sleep(left);
                return;
            };
            match events.recv_timeout(left) {
                Ok(event) => self.state.apply(event),
                Err(_) => return,
            }
        }
    }

    /// One turn of upstream's waiting loops: `time.sleep(0.1)` and the
    /// next spinner frame (or, silent, a busy wait without either).
    fn spin(&mut self, silent: bool, i: &mut usize) {
        if silent {
            self.pump(Duration::from_millis(5));
            return;
        }
        self.pump(Duration::from_millis(100));
        print!("\u{8}\u{8}{} ", SYMS[*i]);
        flush();
        *i = (*i + 1) % SYMS.len();
    }

    fn has_path(&self, destination_hash: [u8; 16]) -> bool {
        self.node()
            .has_path(&DestHash(destination_hash))
            .unwrap_or(false)
    }

    /// Request a path and wait for it, printing upstream's lines; returns
    /// the deadline it waited to. `gap` is what follows "requested" when
    /// not silent.
    fn wait_for_path(&mut self, destination_hash: [u8; 16], i: &mut usize) -> Instant {
        let silent = self.args.silent;
        if !self.has_path(destination_hash) {
            let _ = self.node().request_path(&DestHash(destination_hash));
            if silent {
                println!("Path to {} requested", prettyhexrep(&destination_hash));
            } else {
                print!(
                    "Path to {} requested  {ES}",
                    prettyhexrep(&destination_hash)
                );
            }
            flush();
        }
        let timeout = app::adaptive_path_timeout(
            self.node(),
            Duration::try_from_secs_f64(self.args.w).unwrap_or(Duration::ZERO),
        );
        let estab_timeout = Instant::now() + timeout;
        while !self.has_path(destination_hash) && Instant::now() < estab_timeout {
            self.spin(silent, i);
        }
        estab_timeout
    }

    /// Open a link to the listener and wait until it is active or the
    /// deadline passes.
    fn establish_link(
        &mut self,
        destination_hash: [u8; 16],
        estab_timeout: Instant,
        i: &mut usize,
    ) -> Instant {
        let silent = self.args.silent;
        let recalled = self
            .node()
            .recall_identity(&DestHash(destination_hash))
            .ok()
            .flatten();
        let estab_timeout = estab_timeout
            .max(Instant::now() + app::link_establishment_timeout(self.node(), destination_hash));
        if let Some(recalled) = recalled {
            let mut signature_public = [0u8; 32];
            signature_public.copy_from_slice(&recalled.public_key[32..]);
            self.state.link_id = self
                .node()
                .create_link(destination_hash, signature_public)
                .ok();
        }
        while !self.state.link_active && Instant::now() < estab_timeout {
            self.spin(silent, i);
        }
        estab_timeout
    }

    // Listening

    fn listen(&mut self) -> i32 {
        let allow_fetch = self.args.allow_fetch;
        let fetch_auto_compress = !self.args.no_compress;
        let allow_overwrite = self.args.overwrite;
        let disable_auth = self.args.no_auth;
        // `if announce < 0: announce = False`, and `False >= 0`: without
        // -b, the destination is announced once.
        let announce = self.args.b.max(0);

        self.start_reticulum(disable_auth);

        let mut fetch_jail = None;
        if let Some(jail) = self.args.jail.clone() {
            let jail = abspath(&expanduser(&jail));
            pylog::log(
                &format!("Restricting fetch requests to paths under \"{jail}\""),
                LOG_VERBOSE,
            );
            fetch_jail = Some(jail);
        }
        let mut save_path = None;
        if let Some(save) = self.args.save.clone() {
            match checked_save_path(&save) {
                Ok(sp) => {
                    pylog::log(&format!("Saving received files in \"{sp}\""), LOG_VERBOSE);
                    save_path = Some(sp);
                }
                Err((code, message)) => {
                    pylog::log(message, LOG_ERROR);
                    self.exit(code);
                }
            }
        }

        let identity = self.prepare_identity();
        let destination =
            Destination::single_in(APP_NAME, &[ASPECT], IdentityHash(*identity.hash()));

        if self.args.print_identity {
            println!("Identity     : {}", prettyhexrep(identity.hash()));
            println!("Listening on : {}", prettyhexrep(&destination.hash.0));
            self.exit(0);
        }

        let mut allowed_identity_hashes: Vec<[u8; 16]> = Vec::new();
        if !disable_auth {
            let mut allowed: Vec<String> = self.args.allowed.clone().unwrap_or_default();
            let allowed_file_name = "allowed_identities";
            let candidates = [
                format!("/etc/rncp/{allowed_file_name}"),
                expanduser(&format!("~/.config/rncp/{allowed_file_name}")),
                expanduser(&format!("~/.rncp/{allowed_file_name}")),
            ];
            if let Some(allowed_file) = candidates.iter().find(|p| Path::new(p).is_file()) {
                match std::fs::read_to_string(allowed_file) {
                    Ok(text) => {
                        let ali: Vec<String> = text
                            .replace('\r', "")
                            .split('\n')
                            .filter(|a| crate::pyfmt::len(a) == 32)
                            .map(str::to_string)
                            .collect();
                        let ms = if ali.len() == 1 { "y" } else { "ies" };
                        let count = ali.len();
                        allowed.extend(ali);
                        pylog::log(
                            &format!("Loaded {count} allowed identit{ms} from {allowed_file}"),
                            LOG_VERBOSE,
                        );
                    }
                    Err(e) => pylog::log(
                        &format!(
                            "Error while parsing allowed_identities file. The contained exception was: {}",
                            pylog::oserror(&e, allowed_file)
                        ),
                        LOG_ERROR,
                    ),
                }
            }
            for a in &allowed {
                match destination_hash(a) {
                    Ok(hash) => allowed_identity_hashes.push(hash),
                    Err(e) => {
                        pylog::log(&format!("Could not apply allowed identity: {e}"), LOG_ERROR);
                        self.exit(1);
                    }
                }
            }
        }
        if allowed_identity_hashes.is_empty() && !disable_auth {
            pylog::log(
                "No allowed identities configured, rncp will not accept any files!",
                LOG_WARNING,
            );
        }
        *self.allowed.lock().unwrap_or_else(|p| p.into_inner()) =
            allowed_identity_hashes.iter().copied().collect();

        let Ok((signature_private, signature_public)) = app::signature_keys(&identity) else {
            self.exit(1);
        };
        let _ = self
            .node()
            .register_destination_with_proof(&destination, identity.get_private_key());
        let _ = self.node().register_link_destination(
            destination.hash.0,
            signature_private,
            signature_public,
            2,
        );
        // Set before any link comes up: a sender advertises its file as
        // soon as the link is established, before this loop could set the
        // mode on the link, and the file would arrive in memory instead.
        let resources = self.config_dir().join("storage").join("resources");
        let _ = std::fs::create_dir_all(&resources);
        let _ = self.node().set_link_destination_resource_receive_mode(
            destination.hash.0,
            ResourceReceiveMode::TemporaryFile {
                directory: resources,
                max_bytes: None,
            },
        );
        if allow_fetch {
            let allowed_list = if disable_auth {
                pylog::log("Allowing unauthenticated fetch requests", LOG_WARNING);
                None
            } else {
                Some(allowed_identity_hashes.clone())
            };
            let jail = fetch_jail.clone();
            let tx = self.tx.clone().expect("Reticulum is running");
            let _ = self.node().register_request_handler(
                FETCH_PATH,
                allowed_list,
                move |link_id, _, data, _| fetch_request(&jail, link_id, data, &tx),
            );
        }
        pylog::log(
            &format!("rncp listening on {}", prettyhexrep(&destination.hash.0)),
            LOG_INFO,
        );

        let mut next_announce = Some(Instant::now());
        let mut identified: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
        loop {
            if next_announce.is_some_and(|at| Instant::now() >= at) {
                let _ = self.node().announce_queued(&destination, &identity, None);
                next_announce =
                    (announce > 0).then(|| Instant::now() + Duration::from_secs(announce as u64));
            }
            let Some(event) = self
                .events
                .as_ref()
                .and_then(|events| events.recv_timeout(Duration::from_millis(250)).ok())
            else {
                continue;
            };
            match event {
                RncpEvent::LinkEstablished(link_id, false) => {
                    pylog::log("Incoming link established", LOG_VERBOSE);
                    let _ = self.node().set_resource_strategy(link_id, 2);
                }
                RncpEvent::Identified(link_id, identity_hash) => {
                    identified.insert(link_id, identity_hash);
                    if allowed_identity_hashes.contains(&identity_hash) {
                        pylog::log("Authenticated sender", LOG_VERBOSE);
                    } else if !disable_auth {
                        pylog::log("Sender not allowed, tearing down link", LOG_VERBOSE);
                        let _ = self.node().teardown_link(link_id);
                    }
                }
                RncpEvent::LinkClosed(link_id) => {
                    identified.remove(&link_id);
                }
                RncpEvent::ResourceStarted(link_id, resource_hash, _) => {
                    let id_str = identified
                        .get(&link_id)
                        .map(|id| format!(" from {}", prettyhexrep(id)))
                        .unwrap_or_default();
                    pylog::log(
                        &format!(
                            "Starting resource transfer {}{id_str}",
                            prettyhexrep(&resource_hash)
                        ),
                        LOG_INFO,
                    );
                }
                RncpEvent::ResourceFailed(_) => pylog::log("Resource failed", LOG_INFO),
                RncpEvent::FileReceived(link_id, resource) => {
                    pylog::log(
                        &format!(
                            "Incoming resource <{}/{}> completed",
                            crate::pyfmt::hexrep(&resource.original_hash),
                            crate::pyfmt::hexrep(&link_id)
                        ),
                        LOG_INFO,
                    );
                    if resource.metadata.is_none() {
                        pylog::log("Invalid data received, ignoring resource", LOG_WARNING);
                        continue;
                    }
                    let mut warn = |message: String| pylog::log(&message, LOG_ERROR);
                    match save_received(resource, save_path.as_deref(), allow_overwrite, &mut warn)
                    {
                        Ok(saved) => {
                            pylog::log(&format!("Saved received file to {saved}"), LOG_NOTICE)
                        }
                        Err(SaveError::Message(message)) => pylog::log(&message, LOG_ERROR),
                        Err(SaveError::Exception(e)) => pylog::log(
                            &format!("An error occurred while saving received resource: {e}"),
                            LOG_ERROR,
                        ),
                    }
                }
                RncpEvent::FetchRequested(link_id, file_path) => {
                    let name = basename(&file_path).to_string();
                    if let Err(e) = self.node().send_resource_file(
                        link_id,
                        &file_path,
                        Some(app::filename_metadata(&name)),
                        fetch_auto_compress,
                    ) {
                        pylog::log(
                            &format!(
                                "Could not send file to client. The contained exception was: {}",
                                pylog::oserror(&e, &file_path)
                            ),
                            LOG_ERROR,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    // Sending

    fn send(&mut self) -> i32 {
        let destination = self.args.destination.clone().unwrap_or_default();
        let destination_hash = match destination_hash(&destination) {
            Ok(hash) => hash,
            Err(e) => {
                println!("{e}");
                self.exit(1);
            }
        };
        let file = self.args.file.clone().unwrap_or_default();
        let file_path = expanduser(&file);
        if !Path::new(&file_path).is_file() {
            println!("File not found");
            flush();
            std::process::exit(1);
        }
        let metadata = app::filename_metadata(basename(&file_path));
        let silent = self.args.silent;
        let dest = prettyhexrep(&destination_hash);
        print!("{ERASE}");

        self.start_reticulum(false);
        self.node()
            .wants_destination_type(&format!("{APP_NAME}.{ASPECT}"));
        let identity = self.prepare_identity();

        let mut i = 0;
        let estab_timeout = self.wait_for_path(destination_hash, &mut i);
        if !self.has_path(destination_hash) {
            if silent {
                println!("Path not found");
            } else {
                println!("{ERASE}Path not found");
            }
            self.exit(1);
        } else if silent {
            println!("Establishing link with {dest}");
        } else {
            print!("{ERASE}Establishing link with {dest} {ES}");
        }

        let estab_timeout = self.establish_link(destination_hash, estab_timeout, &mut i);
        if Instant::now() > estab_timeout {
            if silent {
                println!("Link establishment with {dest} timed out");
            } else {
                println!("{ERASE}Link establishment with {dest} timed out");
            }
            self.exit(1);
        } else if !self.has_path(destination_hash) {
            if silent {
                println!("No path found to {dest}");
            } else {
                println!("{ERASE}No path found to {dest}");
            }
            self.exit(1);
        } else if silent {
            println!("Advertising file resource...");
        } else {
            print!("{ERASE}Advertising file resource  {ES}");
        }

        let link_id = self.state.link_id.unwrap_or_default();
        if let Some(private) = identity.get_private_key() {
            let _ = self.node().identify_on_link(link_id, private);
        }
        let file_size = std::fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);
        // Upstream's total_size: the data and its packed metadata with a
        // 3-byte length.
        self.state.total_size = (file_size + metadata.len() as u64 + 3) as f64;
        match self.node().send_resource_file(
            link_id,
            &file_path,
            Some(metadata),
            !self.args.no_compress,
        ) {
            Ok(transfer) => {
                self.state.transfer = Some(transfer);
                self.state.status = ADVERTISED;
            }
            Err(e) => {
                println!(
                    "Could not start transfer: {}",
                    pylog::oserror(&e, &file_path)
                );
                self.exit(1);
            }
        }

        while self.state.status < TRANSFERRING {
            self.spin(silent, &mut i);
        }
        let resource_started_at = Instant::now();
        if self.state.status > COMPLETE {
            if silent {
                println!("File was not accepted by {dest}");
            } else {
                println!("{ERASE}File was not accepted by {dest}");
            }
            self.exit(1);
        } else if silent {
            println!("Transferring file...");
        } else {
            print!("{ERASE}Transferring file  {ES}");
        }

        while self.state.status < COMPLETE {
            if silent {
                self.pump(Duration::from_millis(5));
            } else {
                i = self.progress_update(i, false);
            }
        }
        let transfer_time = resource_started_at.elapsed().as_secs_f64();
        self.state.progress.speed = self.state.total_size / transfer_time;
        if !silent {
            self.progress_update(i, true);
        }
        if self.state.status != COMPLETE {
            if silent {
                println!("The transfer failed");
            } else {
                println!("{ERASE}The transfer failed");
            }
            self.exit(1);
        }
        if silent {
            println!("{file_path} copied to {dest}");
        } else {
            println!("\n{file_path} copied to {dest}");
        }
        let _ = self.node().teardown_link(link_id);
        std::thread::sleep(Duration::from_millis(250));
        self.exit(0)
    }

    /// upstream's `progress_update` while sending.
    fn progress_update(&mut self, i: usize, done: bool) -> usize {
        self.pump(Duration::from_millis(100));
        let state = &self.state;
        let prg = if state.status == COMPLETE {
            1.0
        } else {
            state.prg
        };
        let phy_str = if self.args.phy_rates && state.status < COMPLETE {
            format!(
                " ({}ps at physical layer)",
                size_str(state.progress.phy_speed, "b")
            )
        } else {
            String::new()
        };
        let cs = size_str((prg * state.total_size).trunc(), "B");
        let ts = size_str(state.total_size, "B");
        let ss = size_str(state.progress.speed, "b");
        let stat_str = format!("{}% - {cs} of {ts} - {ss}ps{phy_str}", percent(prg));
        if !done {
            print!("{ERASE}Transferring file {} {stat_str}  ", SYMS[i]);
        } else {
            print!("{ERASE}Transfer complete  {stat_str}  ");
        }
        flush();
        (i + 1) % SYMS.len()
    }

    // Fetching

    fn fetch(&mut self) -> i32 {
        let mut save_path = None;
        if let Some(save) = self.args.save.clone() {
            match checked_save_path(&save) {
                Ok(sp) => save_path = Some(sp),
                Err((code, message)) => {
                    pylog::log(message, LOG_ERROR);
                    self.exit(code);
                }
            }
        }
        let destination = self.args.destination.clone().unwrap_or_default();
        let destination_hash = match destination_hash(&destination) {
            Ok(hash) => hash,
            Err(e) => {
                println!("{e}");
                self.exit(1);
            }
        };
        let file = self.args.file.clone().unwrap_or_default();
        let silent = self.args.silent;
        let dest = prettyhexrep(&destination_hash);

        self.start_reticulum(false);
        self.node()
            .wants_destination_type(&format!("{APP_NAME}.{ASPECT}"));
        let identity = self.prepare_identity();

        let mut i = 0;
        let estab_timeout = self.wait_for_path(destination_hash, &mut i);
        if !self.has_path(destination_hash) {
            if silent {
                println!("Path not found");
            } else {
                println!("{ERASE}Path not found");
            }
            self.exit(1);
        } else if silent {
            println!("Establishing link with {dest}");
        } else {
            print!("{ERASE}Establishing link with {dest}  {ES}");
        }

        self.establish_link(destination_hash, estab_timeout, &mut i);
        if !self.has_path(destination_hash) {
            if silent {
                println!("Could not establish link with {dest}");
            } else {
                println!("{ERASE}Could not establish link with {dest}");
            }
            self.exit(1);
        } else if silent {
            println!("Requesting file from remote...");
        } else {
            print!("{ERASE}Requesting file from remote  {ES}");
        }

        let link_id = self.state.link_id.unwrap_or_default();
        if let Some(private) = identity.get_private_key() {
            let _ = self.node().identify_on_link(link_id, private);
        }
        let resources = self.config_dir().join("storage").join("resources");
        let _ = std::fs::create_dir_all(&resources);
        let _ = self.node().set_resource_receive_mode(
            link_id,
            ResourceReceiveMode::TemporaryFile {
                directory: resources,
                max_bytes: None,
            },
        );
        let _ = self.node().set_resource_strategy(link_id, 1);
        if self
            .node()
            .send_request(
                link_id,
                FETCH_PATH,
                &msgpack::pack(&Value::Str(file.clone())),
            )
            .is_err()
        {
            self.state.request_status = Some("unknown");
        }

        while self.state.request_status.is_none() {
            self.spin(silent, &mut i);
        }
        let failure = match self.state.request_status {
            Some("fetch_not_allowed") => Some(format!(
                "Fetch request failed, fetching the file {file} was not allowed by the remote"
            )),
            Some("not_found") => Some(format!(
                "Fetch request failed, the file {file} was not found on the remote"
            )),
            Some("remote_error") => {
                Some("Fetch request failed due to an error on the remote system".to_string())
            }
            Some("unknown") => Some(
                "Fetch request failed due to an unknown error (probably not authorised)"
                    .to_string(),
            ),
            _ => None,
        };
        if !silent {
            print!("{ERASE}");
        }
        if let Some(failure) = failure {
            println!("{failure}");
            let _ = self.node().teardown_link(link_id);
            std::thread::sleep(Duration::from_millis(150));
            self.exit(0);
        }

        let allow_overwrite = self.args.overwrite;
        let mut resource_resolved = false;
        let mut resource_complete = false;
        loop {
            // `fetch_resource_concluded`, which upstream runs as soon as the
            // resource concludes: the loop below ends at its next check.
            if let Some(resource) = self.state.received.take() {
                if resource.metadata.is_none() {
                    // Upstream returns here without resolving the transfer.
                    println!("Invalid data received, ignoring resource");
                } else {
                    let mut warn = |message: String| println!("{message}");
                    match save_received(resource, save_path.as_deref(), allow_overwrite, &mut warn)
                    {
                        Ok(_) => {
                            resource_complete = true;
                            resource_resolved = true;
                        }
                        Err(SaveError::Message(message)) => println!("{message}"),
                        Err(SaveError::Exception(e)) => {
                            println!("An error occurred while saving received resource: {e}")
                        }
                    }
                }
            } else if self.state.resource_failed && !resource_resolved {
                println!("Resource failed");
                resource_resolved = true;
            }
            if resource_resolved {
                break;
            }
            if silent {
                self.pump(Duration::from_millis(5));
                continue;
            }
            self.pump(Duration::from_millis(100));
            let state = &self.state;
            if state.current_resource {
                let prg = state.prg;
                let phy_str = if self.args.phy_rates {
                    format!(
                        " ({}ps at physical layer)",
                        size_str(state.progress.phy_speed, "b")
                    )
                } else {
                    String::new()
                };
                let ps = size_str((prg * state.total_size).trunc(), "B");
                let ts = size_str(state.total_size, "B");
                if prg != 1.0 {
                    let ss = size_str(state.progress.speed, "b");
                    print!(
                        "{ERASE}Transferring file {} {}% - {ps} of {ts} - {ss}ps{phy_str}{ES}",
                        SYMS[i],
                        percent(prg)
                    );
                } else {
                    let delta_time = state
                        .started
                        .map(|s| s.elapsed().as_secs_f64())
                        .unwrap_or(0.0);
                    let speed = state.total_size / delta_time;
                    self.state.progress.speed = speed;
                    let dt_str = prettytime(Num::Float(delta_time), false);
                    let ss = size_str(speed, "b");
                    print!(
                        "{ERASE}Transfer complete  {}% - {ps} of {ts} in {dt_str} - {ss}ps{phy_str}{ES}",
                        percent(prg)
                    );
                }
            } else {
                print!("{ERASE}Waiting for transfer to start {} {ES}", SYMS[i]);
            }
            flush();
            i = (i + 1) % SYMS.len();
        }

        if !self.state.current_resource || !resource_complete {
            if silent {
                println!("The transfer failed");
            } else {
                println!("{ERASE}The transfer failed");
            }
            self.exit(1);
        }
        if silent {
            println!("{file} fetched from {dest}");
        } else {
            println!("\n{file} fetched from {dest}");
        }
        let _ = self.node().teardown_link(link_id);
        std::thread::sleep(Duration::from_millis(100));
        self.exit(0)
    }
}

/// upstream's `fetch_request` handler.
fn fetch_request(
    fetch_jail: &Option<String>,
    link_id: [u8; 16],
    data: &[u8],
    tx: &mpsc::Sender<RncpEvent>,
) -> Option<Vec<u8>> {
    let data = match msgpack::unpack_exact(data) {
        Ok(Value::Str(s)) => s,
        _ => return Some(msgpack::pack(&Value::Nil)),
    };
    let file_path = match fetch_jail {
        Some(jail) => {
            let mut data = data;
            if data.starts_with(&format!("{jail}/")) {
                data = data.replace(&format!("{jail}/"), "");
            }
            let file_path = abspath(&expanduser(&format!("{jail}/{data}")));
            if !file_path.starts_with(&format!("{jail}/")) {
                pylog::log(
                    &format!(
                        "Disallowing fetch request for {file_path} outside of fetch jail {jail}"
                    ),
                    LOG_WARNING,
                );
                return Some(msgpack::pack(&Value::UInt(REQ_FETCH_NOT_ALLOWED)));
            }
            file_path
        }
        None => abspath(&expanduser(&data)),
    };
    if !Path::new(&file_path).is_file() {
        pylog::log(
            &format!("Client-requested file not found: {file_path}"),
            LOG_VERBOSE,
        );
        return Some(msgpack::pack(&Value::Bool(false)));
    }
    pylog::log(&format!("Sending file {file_path} to client"), LOG_VERBOSE);
    let _ = tx.send(RncpEvent::FetchRequested(link_id, file_path));
    Some(msgpack::pack(&Value::Bool(true)))
}

fn usage() {
    crate::argparse::print_help("rncp", "rncp");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_rate_counts_the_segment_on_the_wire() {
        // upstream's phy_got: get_segment_progress() * get_transfer_size(),
        // the current segment's encrypted (and maybe compressed) bytes.
        let link = [7u8; 16];
        let mut state = State {
            link_id: Some(link),
            total_size: 3_000_000.0,
            ..State::default()
        };
        state.apply(RncpEvent::SegmentProgress(link, 0.25, 400_000));
        assert_eq!(state.phy_got(), 100_000.0);
        // Another link's segment is not ours.
        state.apply(RncpEvent::SegmentProgress([8u8; 16], 1.0, 9));
        assert_eq!(state.phy_got(), 100_000.0);
        state.apply(RncpEvent::ReceiveProgress(link, 1, 3));
        assert_eq!(state.progress.stats.last().unwrap().2, 100_000.0);
        assert_eq!(state.progress.stats.last().unwrap().1, 1_000_000.0);
    }

    fn ns(argv: &[&str]) -> Namespace {
        Namespace::from_args(&Args::parse_spec_from(
            argv.iter().map(|s| s.to_string()).collect(),
            &OPTIONS,
        ))
    }

    #[test]
    fn namespace_is_argparses() {
        let hash = "00".repeat(16);
        let o = ns(&["-l", "-vv", "-b", "0", "-a", "aa", "-abb", "-s", "/tmp/in"]);
        assert!(o.listen);
        assert_eq!(o.verbose, 2);
        assert_eq!(o.b, 0);
        assert_eq!(o.allowed, Some(vec!["aa".into(), "bb".into()]));
        assert_eq!(o.save.as_deref(), Some("/tmp/in"));
        let o = ns(&["-lFnb30", "-j", "/srv", "-i", "id", "--config=/c"]);
        assert!(o.listen && o.allow_fetch && o.no_auth);
        assert_eq!(o.b, 30);
        assert_eq!(o.jail.as_deref(), Some("/srv"));
        assert_eq!(o.identity.as_deref(), Some("id"));
        assert_eq!(o.config.as_deref(), Some("/c"));
        let o = ns(&["file.txt", &hash, "-w5", "-CSP"]);
        assert_eq!(o.file.as_deref(), Some("file.txt"));
        assert_eq!(o.destination.as_deref(), Some(hash.as_str()));
        assert_eq!(o.w, 5.0);
        assert!(o.no_compress && o.silent && o.phy_rates);
        let o = ns(&[]);
        assert_eq!((o.b, o.w, o.allowed), (-1, 15.0, None));
    }

    #[test]
    fn destination_messages_are_upstreams() {
        assert!(destination_hash(&"ab".repeat(16)).is_ok());
        assert_eq!(
            destination_hash("abc").unwrap_err(),
            "Allowed destination length is invalid, must be 32 hexadecimal characters (16 bytes)."
        );
        assert_eq!(
            destination_hash(&"zz".repeat(16)).unwrap_err(),
            "Invalid destination entered. Check your input."
        );
    }

    #[test]
    fn progress_numbers_are_upstreams() {
        assert_eq!(percent(0.5), "50.0");
        assert_eq!(percent(1.0), "100.0");
        assert_eq!(percent(0.12345), "12.3");
        assert_eq!(size_str(1500.0, "B"), "1.50 KB");
        assert_eq!(size_str(100.0, "b"), "800 b");
    }
}
