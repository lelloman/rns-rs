//! rnx - Reticulum Remote Execution Utility.
//!
//! Ported from upstream's rnx statement by statement: the same output
//! (spinner lines, result display, messages and `RNS.log` lines on
//! stdout), exit codes and identity location. The listener runs commands
//! in their own process group, with bounded output and a hard kill on
//! timeout or link loss.

#![allow(unsafe_code, reason = "OS calls through libc")]

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, IdentityHash, LinkId};
use rns_net::destination::Destination;
use rns_net::{Callbacks, RnsNode};

use crate::app;
use crate::args::{Args, Opt, OptionSpec};
use crate::pyfmt::{prettyhexrep, prettysize, round_float};
use crate::pylog::{self, LOG_INFO, LOG_NOTICE};

const APP_NAME: &str = "rnx";
const ASPECT: &str = "execute";
const COMMAND_PATH: &str = "command";
const VERSION: &str = env!("FULL_VERSION");
/// `RNS.Transport.PATH_REQUEST_TIMEOUT`, the default of `-w`.
const PATH_REQUEST_TIMEOUT: f64 = 15.0;
/// Output the listener returns when the requester sets no limit.
const DEFAULT_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const MAX_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;
const MAX_STDIN: usize = 8 * 1024 * 1024;
const MAX_COMMAND_TIMEOUT: f64 = 24.0 * 60.0 * 60.0;
const REMOTE_EXEC_GRACE: f64 = 2.0;
const SYMS: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];

/// upstream rnx's options, and the Rust-only long names this
/// implementation has accepted.
pub(crate) static OPTIONS: OptionSpec = OptionSpec::new(
    Some(&crate::upstream_parsers::RNX),
    &[
        ("i", "identity"),
        ("a", "allowed"),
        ("m", "mirror"),
        ("w", "timeout"),
        ("W", "result-timeout"),
    ],
    &[
        Opt::flag("", "no-auth").rust_only(),
        Opt::flag("", "no-id").rust_only(),
    ],
);

/// upstream's argparse namespace.
#[derive(Debug)]
struct Namespace {
    destination: Option<String>,
    command: Option<String>,
    config: Option<String>,
    verbose: i32,
    quiet: i32,
    print_identity: bool,
    listen: bool,
    identity: Option<String>,
    interactive: bool,
    no_announce: bool,
    allowed: Option<Vec<String>>,
    noauth: bool,
    noid: bool,
    detailed: bool,
    mirror: bool,
    w: f64,
    big_w: Option<f64>,
    stdin: Option<String>,
    stdout: Option<i64>,
    stderr: Option<i64>,
}

impl Namespace {
    fn from_args(args: &Args) -> Self {
        let value = |short: &str, long: &str| {
            args.get(short)
                .or_else(|| args.get(long))
                .map(str::to_string)
        };
        let flag = |short: &str, long: &str| args.has(short) || args.has(long);
        let mut allowed: Vec<String> = args.get_all("a").into_iter().map(str::to_string).collect();
        if allowed.is_empty() {
            allowed = args
                .get_all("allowed")
                .into_iter()
                .map(str::to_string)
                .collect();
        }
        let int = |v: Option<String>| v.and_then(|v| crate::argparse::python_int(&v));
        let float = |v: Option<String>| v.and_then(|v| crate::argparse::python_float(&v));
        Namespace {
            destination: args.positional.first().cloned(),
            command: args.positional.get(1).cloned(),
            config: args.get("config").map(str::to_string),
            verbose: i32::from(args.verbosity),
            quiet: i32::from(args.quiet),
            print_identity: flag("p", "print-identity"),
            listen: flag("l", "listen"),
            identity: value("i", "identity"),
            interactive: flag("x", "interactive"),
            no_announce: flag("b", "no-announce"),
            allowed: (!allowed.is_empty()).then_some(allowed),
            noauth: flag("n", "noauth") || args.has("no-auth"),
            noid: flag("N", "noid") || args.has("no-id"),
            detailed: flag("d", "detailed"),
            mirror: flag("m", "mirror"),
            w: float(value("w", "timeout")).unwrap_or(PATH_REQUEST_TIMEOUT),
            big_w: float(value("W", "result-timeout")),
            stdin: args.get("stdin").map(str::to_string),
            stdout: int(args.get("stdout").map(str::to_string)),
            stderr: int(args.get("stderr").map(str::to_string)),
        }
    }
}

enum RnxEvent {
    LinkEstablished([u8; 16], bool, f64),
    LinkClosed([u8; 16]),
    Identified([u8; 16], [u8; 16]),
    Response(Vec<u8>),
    RequestFailed,
    ReceiveProgress([u8; 16], u64, u64),
    CommandRequested {
        link_id: [u8; 16],
        request_id: [u8; 16],
        data: Vec<u8>,
        remote: Option<[u8; 16]>,
    },
    CommandFinished {
        link_id: [u8; 16],
        request_id: [u8; 16],
        response: Vec<u8>,
        cancellation: Arc<AtomicBool>,
    },
}

type CancellationMap = Arc<Mutex<HashMap<[u8; 16], Vec<Arc<AtomicBool>>>>>;

struct RnxCallbacks {
    tx: mpsc::Sender<RnxEvent>,
    cancellations: CancellationMap,
}

impl Callbacks for RnxCallbacks {
    fn on_link_established(
        &mut self,
        link_id: LinkId,
        _dest_hash: DestHash,
        rtt: f64,
        initiator: bool,
    ) {
        let _ = self
            .tx
            .send(RnxEvent::LinkEstablished(link_id.0, initiator, rtt));
    }
    fn on_link_closed(&mut self, link_id: LinkId, _reason: Option<rns_core::link::TeardownReason>) {
        if let Some(tokens) = self
            .cancellations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&link_id.0)
        {
            for token in tokens {
                token.store(true, Ordering::Release);
            }
        }
        let _ = self.tx.send(RnxEvent::LinkClosed(link_id.0));
    }
    fn on_remote_identified(
        &mut self,
        link_id: LinkId,
        identity_hash: IdentityHash,
        _public_key: [u8; 64],
    ) {
        let _ = self
            .tx
            .send(RnxEvent::Identified(link_id.0, identity_hash.0));
    }
    fn on_response_with_metadata(
        &mut self,
        _link_id: LinkId,
        _request_id: [u8; 16],
        data: Vec<u8>,
        _metadata: Option<Vec<u8>>,
    ) {
        let _ = self.tx.send(RnxEvent::Response(data));
    }
    fn on_request_failed(
        &mut self,
        _link_id: LinkId,
        _request_id: [u8; 16],
        _reason: rns_net::link_manager::RequestFailure,
    ) {
        let _ = self.tx.send(RnxEvent::RequestFailed);
    }
    fn on_resource_progress(&mut self, link_id: LinkId, received: usize, total: usize) {
        let _ = self.tx.send(RnxEvent::ReceiveProgress(
            link_id.0,
            received as u64,
            total as u64,
        ));
    }
}

/// Runs `rnx` on the process's command line and returns the exit status
/// for the binary to exit with. Blocks until the command is done; an
/// argument error exits the process directly with status 2.
pub fn main() -> i32 {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let args = Args::parse_spec_from(arguments, &OPTIONS);
    crate::argparse::enforce(&args, "rnx", "rnx");
    if args.has("version") {
        println!("rnx {VERSION}");
        return 0;
    }
    if args.has("help") || args.has("h") {
        usage();
        return 0;
    }
    crate::stdout::exit_on_interrupt_after_newline(0);
    let mut rnx = Rnx {
        args: Namespace::from_args(&args),
        node: None,
        events: None,
        tx: None,
        cancellations: Arc::new(Mutex::new(HashMap::new())),
        identity: None,
        link: None,
    };
    rnx.main()
}

/// `RequestReceipt` states, as upstream numbers them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Receipt {
    Failed,
    Sent,
    Delivered,
    Receiving,
    Ready,
}

/// The client's link to the listener.
struct ClientLink {
    id: [u8; 16],
    active: bool,
    closed: bool,
    rtt: f64,
    did_identify: bool,
}

struct Rnx {
    args: Namespace,
    node: Option<RnsNode>,
    events: Option<mpsc::Receiver<RnxEvent>>,
    tx: Option<mpsc::Sender<RnxEvent>>,
    cancellations: CancellationMap,
    identity: Option<rns_crypto::identity::Identity>,
    link: Option<ClientLink>,
}

/// One request's progress, from the callbacks.
struct Request {
    status: Receipt,
    response: Option<Vec<u8>>,
    progress: f64,
    response_transfer_size: f64,
    stats: Vec<(Instant, f64)>,
    speed: f64,
    sent_at: Instant,
    concluded_at: Option<Instant>,
}

fn flush() {
    let _ = io::stdout().flush();
}

impl Rnx {
    #[allow(
        clippy::expect_used,
        reason = "only called once start_reticulum has set the node"
    )]
    fn node(&self) -> &RnsNode {
        self.node.as_ref().expect("Reticulum is running")
    }

    #[allow(
        clippy::expect_used,
        reason = "only called once start_reticulum has set the sender"
    )]
    fn event_sender(&self) -> mpsc::Sender<RnxEvent> {
        self.tx.clone().expect("Reticulum is running")
    }

    /// Python's `exit(code)`: Reticulum's exit handler runs first.
    fn exit(&mut self, code: i32) -> ! {
        flush();
        let _ = io::stderr().flush();
        if let Some(node) = self.node.take() {
            node.shutdown();
        }
        std::process::exit(code)
    }

    fn config_dir(&self) -> std::path::PathBuf {
        rns_net::storage::resolve_config_dir(self.args.config.as_deref().map(Path::new))
    }

    fn start_reticulum(&mut self) {
        if self.node.is_some() {
            return;
        }
        let level = (3 + self.args.verbose - self.args.quiet).clamp(0, 8);
        pylog::install_utility_logging(self.args.config.as_deref(), Some(level), 0, false);
        let config_dir = self.config_dir();
        let (tx, rx) = mpsc::channel();
        let callbacks = || {
            Box::new(RnxCallbacks {
                tx: tx.clone(),
                cancellations: Arc::clone(&self.cancellations),
            })
        };
        let node = match RnsNode::connect_shared_from_config(Some(&config_dir), callbacks()) {
            Ok(node) => node,
            Err(_) => match RnsNode::from_config(Some(&config_dir), callbacks()) {
                Ok(node) => node,
                Err(e) => {
                    pylog::log(&format!("Could not start Reticulum: {e}"), pylog::LOG_ERROR);
                    self.exit(1);
                }
            },
        };
        self.node = Some(node);
        self.events = Some(rx);
        self.tx = Some(tx);
        crate::stdout::exit_on_interrupt(0);
    }

    /// `prepare_identity`: an unreadable identity file is replaced.
    fn prepare_identity(&mut self) {
        let identity = self.take_identity();
        self.identity = Some(identity);
    }

    /// The prepared identity, taken out of `self`: the one already
    /// prepared, else the saved one, else a new one, saved.
    fn take_identity(&mut self) -> rns_crypto::identity::Identity {
        if let Some(identity) = self.identity.take() {
            return identity;
        }
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
            if let Some(identity) = pylog::identity_from_file(&identity_path) {
                return identity;
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

    fn main(&mut self) -> i32 {
        if self.args.listen || self.args.print_identity {
            self.listen();
        }
        if let (Some(destination), Some(command)) =
            (self.args.destination.clone(), self.args.command.clone())
        {
            let stdin = self.args.stdin.clone();
            let interactive = self.args.interactive;
            self.execute(&destination, &command, stdin, interactive);
        }
        if let (Some(destination), true) = (self.args.destination.clone(), self.args.interactive) {
            let mut code: Option<i64> = None;
            loop {
                let cstr = match code {
                    Some(c) if c != 0 => c.to_string(),
                    _ => String::new(),
                };
                print!("{cstr}> ");
                flush();
                let mut line = String::new();
                match io::stdin().read_line(&mut line) {
                    Ok(0) | Err(_) => self.exit(0),
                    Ok(_) => {}
                }
                let command = line.strip_suffix('\n').unwrap_or(&line).to_string();
                let lower = command.to_lowercase();
                if lower == "exit" || lower == "quit" {
                    self.exit(0);
                }
                if lower == "clear" {
                    print!("\x1bc");
                } else {
                    code = self.execute(&destination, &command, None, true);
                }
            }
        } else {
            println!();
            usage();
            println!();
            0
        }
    }

    // Listening

    fn listen(&mut self) -> ! {
        self.start_reticulum();
        let identity = self.take_identity();
        let destination =
            Destination::single_in(APP_NAME, &[ASPECT], IdentityHash(*identity.hash()));
        if self.args.print_identity {
            println!("Identity     : {}", prettyhexrep(identity.hash()));
            println!("Listening on : {}", prettyhexrep(&destination.hash.0));
            self.exit(0);
        }

        let allow_all = self.args.noauth;
        let mut allowed_identity_hashes: Vec<[u8; 16]> = Vec::new();
        if !allow_all {
            for a in self.args.allowed.clone().unwrap_or_default() {
                let parsed = if crate::pyfmt::len(&a) != 32 {
                    Err("Allowed destination length is invalid, must be 32 hexadecimal characters (16 bytes).".to_string())
                } else {
                    pylog::fromhex(&a)
                        .ok()
                        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
                        .ok_or_else(|| "Invalid destination entered. Check your input.".to_string())
                };
                match parsed {
                    Ok(hash) => allowed_identity_hashes.push(hash),
                    Err(e) => {
                        println!("{e}");
                        self.exit(1);
                    }
                }
            }
            let allowed_file_name = "allowed_identities";
            let candidates = [
                format!("/etc/rnx/{allowed_file_name}"),
                pylog::expanduser(&format!("~/.config/rnx/{allowed_file_name}")),
                pylog::expanduser(&format!("~/.rnx/{allowed_file_name}")),
            ];
            if let Some(allowed_file) = candidates.iter().find(|p| Path::new(p).is_file()) {
                let text = match std::fs::read_to_string(allowed_file) {
                    Ok(text) => text,
                    Err(e) => {
                        println!("{}", pylog::oserror(&e, allowed_file));
                        self.exit(1);
                    }
                };
                for allowed_id in text.replace('\r', "").split('\n') {
                    if crate::pyfmt::len(allowed_id) == 32 {
                        match pylog::fromhex(allowed_id) {
                            Ok(bytes) => {
                                if let Ok(hash) = <[u8; 16]>::try_from(bytes.as_slice()) {
                                    allowed_identity_hashes.push(hash);
                                }
                            }
                            Err(e) => {
                                println!("{e}");
                                self.exit(1);
                            }
                        }
                    }
                }
            }
        }
        if allowed_identity_hashes.is_empty() && !allow_all {
            println!(
                "Warning: No allowed identities configured, rncx will not accept any commands!"
            );
        }

        let Ok((signature_private, signature_public)) = app::signature_keys(&identity) else {
            self.exit(1);
        };
        let node = self.node();
        let _ = node.register_destination_with_proof(&destination, identity.get_private_key());
        let _ = node.register_link_destination(
            destination.hash.0,
            signature_private,
            signature_public,
            0,
        );
        let request_tx = self.event_sender();
        let _ = node.register_deferred_request_handler(
            COMMAND_PATH,
            (!allow_all).then(|| allowed_identity_hashes.clone()),
            move |link_id, _, request_id, data, remote| {
                let _ = request_tx.send(RnxEvent::CommandRequested {
                    link_id,
                    request_id,
                    data: data.to_vec(),
                    remote: remote.map(|(hash, _)| *hash),
                });
            },
        );
        pylog::log(
            &format!(
                "rnx listening for commands on {}",
                prettyhexrep(&destination.hash.0)
            ),
            LOG_NOTICE,
        );
        if !self.args.no_announce {
            let _ = self.node().announce_queued(&destination, &identity, None);
        }

        let tx = self.event_sender();
        loop {
            let Some(event) = self.events.as_ref().and_then(|events| events.recv().ok()) else {
                self.exit(0);
            };
            match event {
                RnxEvent::LinkEstablished(link_id, false, _) => {
                    pylog::log(
                        &format!("Command link {} established", prettyhexrep(&link_id)),
                        LOG_NOTICE,
                    );
                }
                RnxEvent::LinkClosed(link_id) => {
                    pylog::log(
                        &format!("Command link {} closed", prettyhexrep(&link_id)),
                        LOG_NOTICE,
                    );
                }
                RnxEvent::Identified(link_id, identity_hash) => {
                    pylog::log(
                        &format!(
                            "Initiator of link {} identified as {}",
                            prettyhexrep(&link_id),
                            prettyhexrep(&identity_hash)
                        ),
                        LOG_NOTICE,
                    );
                    if !allow_all && !allowed_identity_hashes.contains(&identity_hash) {
                        pylog::log(
                            &format!(
                                "Identity {} not allowed, tearing down link",
                                prettyhexrep(&identity_hash)
                            ),
                            LOG_NOTICE,
                        );
                        let _ = self.node().teardown_link(link_id);
                    }
                }
                RnxEvent::CommandRequested {
                    link_id,
                    request_id,
                    data,
                    remote,
                } => {
                    let cancel = Arc::new(AtomicBool::new(false));
                    self.cancellations
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .entry(link_id)
                        .or_default()
                        .push(cancel.clone());
                    let result_tx = tx.clone();
                    thread::spawn(move || {
                        let response = execute_request(&data, &cancel, remote);
                        let _ = result_tx.send(RnxEvent::CommandFinished {
                            link_id,
                            request_id,
                            response,
                            cancellation: cancel,
                        });
                    });
                }
                RnxEvent::CommandFinished {
                    link_id,
                    request_id,
                    response,
                    cancellation,
                } => {
                    let _ = self
                        .node()
                        .send_deferred_response(link_id, request_id, response);
                    let mut cancellations =
                        self.cancellations.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(tokens) = cancellations.get_mut(&link_id) {
                        tokens.retain(|token| !Arc::ptr_eq(token, &cancellation));
                        if tokens.is_empty() {
                            cancellations.remove(&link_id);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Executing

    /// Apply the events that arrive within `duration` to the link and
    /// the request.
    fn pump(&mut self, duration: Duration, request: &mut Option<&mut Request>) {
        let until = Instant::now() + duration;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            let Some(event) = self.events.as_ref().and_then(|e| e.recv_timeout(left).ok()) else {
                return;
            };
            let ours = |id: &[u8; 16], link: &Option<ClientLink>| {
                link.as_ref().is_some_and(|l| &l.id == id)
            };
            match event {
                RnxEvent::LinkEstablished(id, true, rtt) if ours(&id, &self.link) => {
                    if let Some(link) = self.link.as_mut() {
                        link.active = true;
                        link.rtt = rtt;
                    }
                }
                RnxEvent::LinkClosed(id) if ours(&id, &self.link) => {
                    if let Some(link) = self.link.as_mut() {
                        link.active = false;
                        link.closed = true;
                    }
                    if let Some(request) = request.as_deref_mut() {
                        if matches!(
                            request.status,
                            Receipt::Sent | Receipt::Delivered | Receipt::Receiving
                        ) {
                            request.status = Receipt::Failed;
                        }
                    }
                }
                RnxEvent::Response(data) => {
                    if let Some(request) = request.as_deref_mut() {
                        if request.status != Receipt::Failed {
                            request.status = Receipt::Ready;
                            request.progress = 1.0;
                            request.response = Some(data);
                            request.concluded_at = Some(Instant::now());
                        }
                    }
                }
                RnxEvent::RequestFailed => {
                    if let Some(request) = request.as_deref_mut() {
                        if request.status != Receipt::Ready {
                            request.status = Receipt::Failed;
                        }
                    }
                }
                RnxEvent::ReceiveProgress(id, received, total) if ours(&id, &self.link) => {
                    if let Some(request) = request.as_deref_mut() {
                        if matches!(request.status, Receipt::Sent | Receipt::Delivered) {
                            request.status = Receipt::Receiving;
                        }
                        request.progress = received as f64 / total.max(1) as f64;
                        // The response's transfer size: its parts at the
                        // link's MDU.
                        request.response_transfer_size = total as f64 * 431.0;
                        let now = Instant::now();
                        let got = request.progress * request.response_transfer_size;
                        request.stats.push((now, got));
                        while request.stats.len() > 32 {
                            request.stats.remove(0);
                        }
                        // Just pushed, so there is a first sample.
                        let (first_at, first_got) =
                            request.stats.first().copied().unwrap_or((now, got));
                        let span = now.duration_since(first_at).as_secs_f64();
                        request.speed = if span == 0.0 {
                            0.0
                        } else {
                            (got - first_got) / span
                        };
                    }
                }
                _ => {}
            }
        }
    }

    /// upstream's `spin`: `msg` and a spinner until `until` holds or the
    /// timeout passes, then the line is cleared. Returns false on timeout.
    fn spin(
        &mut self,
        until: impl Fn(&Rnx, Option<&Request>) -> bool,
        msg: &str,
        timeout: Option<f64>,
        mut request: Option<&mut Request>,
    ) -> bool {
        let deadline = timeout
            .map(|t| Instant::now() + Duration::try_from_secs_f64(t).unwrap_or(Duration::ZERO));
        print!("{msg}   ");
        let mut i = 0;
        self.pump(Duration::ZERO, &mut request);
        while deadline.is_none_or(|d| Instant::now() < d) && !until(self, request.as_deref()) {
            self.pump(Duration::from_millis(100), &mut request);
            print!("\u{8}\u{8}{} ", SYMS.get(i).copied().unwrap_or(' '));
            flush();
            i = (i + 1) % SYMS.len();
        }
        print!("\r{}  \r", " ".repeat(msg.chars().count()));
        deadline.is_none_or(|d| Instant::now() <= d)
    }

    /// upstream's `spin_stat`: the result download's progress line.
    fn spin_stat(&mut self, request: &mut Request, timeout: Option<f64>) -> bool {
        let deadline = timeout
            .map(|t| Instant::now() + Duration::try_from_secs_f64(t).unwrap_or(Duration::ZERO));
        let blank = " ".repeat(82);
        let mut i = 0;
        let mut req = Some(&mut *request);
        self.pump(Duration::ZERO, &mut req);
        while deadline.is_none_or(|d| Instant::now() < d)
            && req.as_ref().is_some_and(|r| r.status == Receipt::Receiving)
        {
            self.pump(Duration::from_millis(100), &mut req);
            let Some(r) = req.as_ref() else {
                break;
            };
            let prg = r.progress;
            let stat_str = format!(
                "{}% - {} of {} - {}ps",
                crate::format::python_float(round_float(prg * 100.0, 1)),
                prettysize((prg * r.response_transfer_size).trunc(), "B"),
                prettysize(r.response_transfer_size, "B"),
                prettysize(r.speed, "b")
            );
            print!(
                "\r{blank}\rReceiving result {} {stat_str} ",
                SYMS.get(i).copied().unwrap_or(' ')
            );
            flush();
            i = (i + 1) % SYMS.len();
        }
        print!("\r{blank}\r");
        deadline.is_none_or(|d| Instant::now() <= d)
    }

    /// `exit(code)`, or in interactive mode return from `execute`.
    fn fail(&mut self, message: &str, code: i32, interactive: bool) -> Option<i64> {
        println!("{message}");
        if interactive {
            return None;
        }
        self.exit(code)
    }

    fn execute(
        &mut self,
        destination: &str,
        command: &str,
        stdin: Option<String>,
        interactive: bool,
    ) -> Option<i64> {
        let destination_hash = if crate::pyfmt::len(destination) != 32 {
            Err("Allowed destination length is invalid, must be 32 hexadecimal characters (16 bytes).")
        } else {
            pylog::fromhex(destination)
                .ok()
                .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
                .ok_or("Invalid destination entered. Check your input.")
        };
        let destination_hash = match destination_hash {
            Ok(hash) => hash,
            Err(e) => {
                println!("{e}");
                self.exit(241);
            }
        };
        let timeout = self.args.w;
        self.start_reticulum();
        self.node()
            .wants_destination_type(&format!("{APP_NAME}.{ASPECT}"));
        self.prepare_identity();
        let dest = DestHash(destination_hash);

        if !self.node().has_path(&dest).unwrap_or(false) {
            let _ = self.node().request_path(&dest);
            let medium = self.node().medium_path_timeout().unwrap_or(0.0);
            let found = self.spin(
                |rnx, _| rnx.node().has_path(&dest).unwrap_or(false),
                &format!("Path to {} requested", prettyhexrep(&destination_hash)),
                Some(timeout.max(medium)),
                None,
            );
            if !found {
                println!("Path not found");
                self.exit(242);
            }
        }

        let needs_link = self.link.as_ref().is_none_or(|l| l.closed || !l.active);
        if needs_link {
            let recalled = self.node().recall_identity(&dest).ok().flatten();
            let id = recalled.and_then(|recalled| {
                let mut signature_public = [0u8; 32];
                signature_public.copy_from_slice(&recalled.public_key[32..]);
                self.node()
                    .create_link(destination_hash, signature_public)
                    .ok()
            });
            self.link = id.map(|id| ClientLink {
                id,
                active: false,
                closed: false,
                rtt: 0.0,
                did_identify: false,
            });
        }
        let establishment_timeout =
            app::link_establishment_timeout(self.node(), destination_hash).as_secs_f64();
        let established = self.spin(
            |rnx, _| rnx.link.as_ref().is_some_and(|l| l.active),
            &format!("Establishing link with {}", prettyhexrep(&destination_hash)),
            Some(timeout.max(establishment_timeout)),
            None,
        );
        if !established {
            println!(
                "Could not establish link with {}",
                prettyhexrep(&destination_hash)
            );
            self.exit(243);
        }
        let link_id = self.link.as_ref().map(|l| l.id).unwrap_or_default();
        if !self.args.noid && !self.link.as_ref().is_some_and(|l| l.did_identify) {
            if let Some(private) = self.identity.as_ref().and_then(|i| i.get_private_key()) {
                let _ = self.node().identify_on_link(link_id, private);
            }
            if let Some(link) = self.link.as_mut() {
                link.did_identify = true;
            }
        }

        let request_data = msgpack::pack(&Value::Array(vec![
            Value::Bin(command.as_bytes().to_vec()),
            Value::Float(timeout),
            self.args.stdout.map_or(Value::Nil, Value::Int),
            self.args.stderr.map_or(Value::Nil, Value::Int),
            stdin.map_or(Value::Nil, |s| Value::Bin(s.into_bytes())),
        ]));
        let rtt = self.link.as_ref().map(|l| l.rtt).unwrap_or(0.0);
        let rexec_timeout = timeout + rtt * 4.0 + REMOTE_EXEC_GRACE;
        let mut request = Request {
            status: Receipt::Sent,
            response: None,
            progress: 0.0,
            response_transfer_size: 0.0,
            stats: Vec::new(),
            speed: 0.0,
            sent_at: Instant::now(),
            concluded_at: None,
        };
        if self
            .node()
            .send_request_with_options(
                link_id,
                COMMAND_PATH,
                &request_data,
                Some(MAX_OUTPUT_LIMIT * 2 + 4096),
                Some(rexec_timeout),
            )
            .is_err()
        {
            request.status = Receipt::Failed;
        }

        self.spin(
            |rnx, r| {
                rnx.link.as_ref().is_some_and(|l| l.closed)
                    || r.is_some_and(|r| !matches!(r.status, Receipt::Failed | Receipt::Sent))
            },
            "Sending execution request",
            Some(rexec_timeout + 0.5),
            Some(&mut request),
        );
        if self.link.as_ref().is_some_and(|l| l.closed) {
            println!("Could not request remote execution, link was closed");
            self.exit(244);
        }
        if request.status == Receipt::Failed {
            return self.fail("Could not request remote execution", 244, interactive);
        }
        self.spin(
            |_, r| r.is_some_and(|r| r.status != Receipt::Delivered),
            "Command delivered, awaiting result",
            Some(timeout),
            Some(&mut request),
        );
        if request.status == Receipt::Failed {
            return self.fail("No result was received", 245, interactive);
        }
        let result_timeout = self.args.big_w;
        self.spin_stat(&mut request, result_timeout);
        if request.status == Receipt::Failed {
            return self.fail("Receiving result failed", 246, interactive);
        }

        let Some(response) = request.response.clone() else {
            return self.fail("No response", 249, interactive);
        };
        let Some(result) = decode_result(&response) else {
            return self.fail("Received invalid result", 247, interactive);
        };
        if !result.executed {
            return self.fail("Remote could not execute command", 248, interactive);
        }
        let (stdout, stderr) = (
            result.stdout.clone().unwrap_or_default(),
            result.stderr.clone().unwrap_or_default(),
        );
        if self.args.detailed {
            if !stdout.is_empty() {
                let _ = io::stdout().write_all(&stdout);
            }
            if !stderr.is_empty() {
                let _ = io::stderr().write_all(&stderr);
            }
            flush();
            let _ = io::stderr().flush();
            println!("\n--- End of remote output, rnx done ---");
            if let (Some(started), Some(concluded)) = (result.started, result.concluded) {
                let cmd_duration = round_float(concluded - started, 3);
                println!(
                    "Remote command execution took {} seconds",
                    crate::format::python_float(cmd_duration)
                );
                let total_size = (response.len() + request_data.len()) as f64;
                let response_concluded = request
                    .concluded_at
                    .map(|c| c.duration_since(request.sent_at).as_secs_f64())
                    .unwrap_or(0.0);
                let transfer_duration = round_float(response_concluded - cmd_duration, 3);
                let tdstr = if transfer_duration == 1.0 {
                    " in 1 second".to_string()
                } else if transfer_duration < 10.0 {
                    format!(
                        " in {} seconds",
                        crate::format::python_float(transfer_duration)
                    )
                } else {
                    format!(" in {}", pretty_time(transfer_duration))
                };
                if transfer_duration == 0.0 {
                    flush();
                    eprintln!("ZeroDivisionError: float division by zero");
                    self.exit(1);
                }
                let spdstr = format!(
                    ", effective rate {}ps",
                    prettysize(total_size / transfer_duration, "b")
                );
                println!("Transferred {}{tdstr}{spdstr}", prettysize(total_size, "B"));
            }
            if let (Some(outlen), Some(out)) = (result.outlen, &result.stdout) {
                let tstr = if (out.len() as i64) < outlen {
                    format!(", {} bytes displayed", out.len())
                } else {
                    String::new()
                };
                println!("Remote wrote {outlen} bytes to stdout{tstr}");
            }
            if let (Some(errlen), Some(err)) = (result.errlen, &result.stderr) {
                let tstr = if (err.len() as i64) < errlen {
                    format!(", {} bytes displayed", err.len())
                } else {
                    String::new()
                };
                println!("Remote wrote {errlen} bytes to stderr{tstr}");
            }
        } else {
            if !stdout.is_empty() {
                let _ = io::stdout().write_all(&stdout);
            }
            if !stderr.is_empty() {
                let _ = io::stderr().write_all(&stderr);
            }
            let outlen = result.outlen.unwrap_or(0);
            let errlen = result.errlen.unwrap_or(0);
            let stdoutl = self.args.stdout;
            let stderrl = self.args.stderr;
            if (stdoutl != Some(0) && (stdout.len() as i64) < outlen)
                || (stderrl != Some(0) && (stderr.len() as i64) < errlen)
            {
                flush();
                let _ = io::stderr().flush();
                println!("\nOutput truncated before being returned:");
                if !stdout.is_empty() && (stdout.len() as i64) < outlen {
                    println!("  stdout truncated to {} bytes", stdout.len());
                }
                if !stderr.is_empty() && (stderr.len() as i64) < errlen {
                    println!("  stderr truncated to {} bytes", stderr.len());
                }
            }
        }

        if !interactive {
            let _ = self.node().teardown_link(link_id);
        }
        if !interactive && self.args.mirror {
            match result.retval {
                Some(code) => self.exit(code as i32),
                None => self.exit(240),
            }
        } else if interactive {
            if self.args.mirror {
                result.retval
            } else {
                None
            }
        } else {
            self.exit(0)
        }
    }
}

/// A command result, as the listener returns it.
struct CommandResult {
    executed: bool,
    retval: Option<i64>,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
    outlen: Option<i64>,
    errlen: Option<i64>,
    started: Option<f64>,
    concluded: Option<f64>,
}

fn decode_result(data: &[u8]) -> Option<CommandResult> {
    let Value::Array(values) = msgpack::unpack_exact(data).ok()? else {
        return None;
    };
    let get = |i: usize| values.get(i);
    let int = |v: Option<&Value>| match v? {
        Value::Int(n) => Some(*n),
        Value::UInt(n) => i64::try_from(*n).ok(),
        _ => None,
    };
    let float = |v: Option<&Value>| match v? {
        Value::Float(f) => Some(*f),
        Value::UInt(n) => Some(*n as f64),
        Value::Int(n) => Some(*n as f64),
        _ => None,
    };
    let bytes = |v: Option<&Value>| match v? {
        Value::Bin(b) => Some(b.clone()),
        _ => None,
    };
    if values.len() < 8 {
        return None;
    }
    Some(CommandResult {
        executed: matches!(get(0), Some(Value::Bool(true))),
        retval: int(get(1)),
        stdout: bytes(get(2)),
        stderr: bytes(get(3)),
        outlen: int(get(4)),
        errlen: int(get(5)),
        started: float(get(6)),
        concluded: float(get(7)),
    })
}

/// rnx's own `pretty_time`.
fn pretty_time(time: f64) -> String {
    let days = (time / (24.0 * 3600.0)).floor() as i64;
    let mut time = time % (24.0 * 3600.0);
    let hours = (time / 3600.0).floor() as i64;
    time %= 3600.0;
    let minutes = (time / 60.0).floor() as i64;
    time %= 60.0;
    let seconds = round_float(time, 2);
    let mut components = Vec::new();
    if days > 0 {
        components.push(format!("{days}d"));
    }
    if hours > 0 {
        components.push(format!("{hours}h"));
    }
    if minutes > 0 {
        components.push(format!("{minutes}m"));
    }
    if seconds > 0.0 {
        components.push(format!("{}s", crate::format::python_float(seconds)));
    }
    let mut tstr = String::new();
    let n = components.len();
    for (i, c) in components.iter().enumerate() {
        let i = i + 1;
        if i == 1 {
        } else if i < n {
            tstr.push_str(", ");
        } else {
            tstr.push_str(" and ");
        }
        tstr.push_str(c);
    }
    tstr
}

/// upstream's `execute_received_command`, logging as it does.
fn execute_request(data: &[u8], cancel: &AtomicBool, remote: Option<[u8; 16]>) -> Vec<u8> {
    let started = unix_time();
    let request = decode_command_request(data);
    let Ok(request) = request else {
        return encode_result(false, None, None, None, None, None, started, None);
    };
    let party = |prefix: &str| match remote {
        Some(hash) => format!("{prefix} {}", prettyhexrep(&hash)),
        None => format!("{prefix} unknown requestor"),
    };
    pylog::log(
        &format!("Executing command [{}] {}", request.command, party("for")),
        LOG_NOTICE,
    );
    let argv = split_command(&request.command).unwrap_or_default();
    let Some((program, args)) = argv.split_first() else {
        return encode_result(false, None, None, None, None, None, started, None);
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the closure runs in the forked child before exec and only calls `setsid` and reads
    // errno through `last_os_error` (an OS error does not allocate), all async-signal-safe; it
    // captures nothing.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return encode_result(false, None, None, None, None, None, started, None),
    };
    let pid = child.id() as libc::pid_t;
    if let Some(mut stdin) = child.stdin.take() {
        if let Some(input) = request.stdin {
            let _ = stdin.write_all(input.get(..MAX_STDIN).unwrap_or(&input));
        }
    }
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        // Both are piped above, so the child always has them.
        let _ = child.kill();
        let _ = child.wait();
        return encode_result(false, None, None, None, None, None, started, None);
    };
    let stdout_limit = request
        .stdout_limit
        .unwrap_or(DEFAULT_OUTPUT_LIMIT)
        .min(MAX_OUTPUT_LIMIT);
    let stderr_limit = request
        .stderr_limit
        .unwrap_or(DEFAULT_OUTPUT_LIMIT)
        .min(MAX_OUTPUT_LIMIT);
    let stdout_thread = thread::spawn(move || read_bounded(stdout, stdout_limit));
    let stderr_thread = thread::spawn(move || read_bounded(stderr, stderr_limit));
    let deadline =
        Instant::now() + Duration::from_secs_f64(request.timeout.min(MAX_COMMAND_TIMEOUT));
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if cancel.load(Ordering::Acquire) || Instant::now() >= deadline => {
                timed_out = Instant::now() >= deadline;
                terminate_process_group(pid, &mut child);
                break child.wait().ok();
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(_) => {
                terminate_process_group(pid, &mut child);
                break child.wait().ok();
            }
        }
    };
    if timed_out {
        pylog::log(
            &format!(
                "Command [{}] timed out and is being killed...",
                request.command
            ),
            LOG_NOTICE,
        );
    }
    let (stdout, stdout_total) = stdout_thread.join().unwrap_or_default();
    let (stderr, stderr_total) = stderr_thread.join().unwrap_or_default();
    let concluded = (!timed_out && !cancel.load(Ordering::Acquire)).then(unix_time);
    pylog::log(
        &format!(
            "Delivering result of command [{}] {}",
            request.command,
            party("to")
        ),
        LOG_NOTICE,
    );
    encode_result(
        true,
        status.and_then(|status| status.code()).map(i64::from),
        Some(stdout),
        Some(stderr),
        Some(stdout_total),
        Some(stderr_total),
        started,
        concluded,
    )
}

fn terminate_process_group(pid: libc::pid_t, child: &mut std::process::Child) {
    // `pid` is the child spawned with `setsid`, so it leads its own process
    // group, and it is not reaped yet (the caller just saw `try_wait` return
    // no status and only `child` reaps it), so `-pid` still names that group.
    crate::sys::kill(-pid, libc::SIGTERM);
    let until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < until {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    // The loop above returns as soon as `try_wait` reaps the child, so it is
    // still unreaped here and `-pid` still names its process group.
    crate::sys::kill(-pid, libc::SIGKILL);
}

fn read_bounded(mut reader: impl Read, limit: usize) -> (Vec<u8>, u64) {
    let mut retained = Vec::with_capacity(limit.min(64 * 1024));
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                total = total.saturating_add(count as u64);
                let keep = count.min(limit.saturating_sub(retained.len()));
                retained.extend_from_slice(buffer.get(..keep).unwrap_or_default());
            }
        }
    }
    (retained, total)
}

struct CommandRequest {
    command: String,
    timeout: f64,
    stdout_limit: Option<usize>,
    stderr_limit: Option<usize>,
    stdin: Option<Vec<u8>>,
}

fn decode_command_request(data: &[u8]) -> Result<CommandRequest, ()> {
    let Value::Array(values) = msgpack::unpack_exact(data).map_err(|_| ())? else {
        return Err(());
    };
    let [command, timeout, stdout_limit, stderr_limit, stdin] = values.as_slice() else {
        return Err(());
    };
    let command = match command {
        Value::Bin(value) => String::from_utf8(value.clone()).map_err(|_| ())?,
        Value::Str(value) => value.clone(),
        _ => return Err(()),
    };
    let timeout = match *timeout {
        Value::Float(value) if value.is_finite() && value >= 0.0 => value,
        Value::UInt(value) => value as f64,
        Value::Nil => 15.0,
        _ => return Err(()),
    };
    let limit = |value: &Value| match value {
        Value::UInt(value) => usize::try_from(*value).ok(),
        Value::Nil => None,
        _ => None,
    };
    let stdin = match stdin {
        Value::Bin(value) => Some(value.clone()),
        Value::Nil => None,
        _ => return Err(()),
    };
    if stdin.as_ref().is_some_and(|value| value.len() > MAX_STDIN) {
        return Err(());
    }
    Ok(CommandRequest {
        command,
        timeout,
        stdout_limit: limit(stdout_limit),
        stderr_limit: limit(stderr_limit),
        stdin,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "one argument per element of the msgpack result array the remote side unpacks"
)]
fn encode_result(
    executed: bool,
    status: Option<i64>,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
    stdout_total: Option<u64>,
    stderr_total: Option<u64>,
    started: f64,
    concluded: Option<f64>,
) -> Vec<u8> {
    msgpack::pack(&Value::Array(vec![
        Value::Bool(executed),
        status.map(Value::Int).unwrap_or(Value::Nil),
        stdout.map(Value::Bin).unwrap_or(Value::Nil),
        stderr.map(Value::Bin).unwrap_or(Value::Nil),
        stdout_total.map(Value::UInt).unwrap_or(Value::Nil),
        stderr_total.map(Value::UInt).unwrap_or(Value::Nil),
        Value::Float(started),
        concluded.map(Value::Float).unwrap_or(Value::Nil),
    ]))
}

/// `shlex.split(command)` (POSIX mode): whitespace separates words;
/// single quotes keep everything; in double quotes a backslash escapes
/// only `\\`, `"`, `$`, `` ` `` and a newline; outside quotes it escapes
/// any character.
fn split_command(command: &str) -> Result<Vec<String>, &'static str> {
    let mut output = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                if in_word {
                    output.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => current.push(c),
                        None => return Err("No closing quotation"),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('\\' | '"' | '$' | '`' | '\n')) => current.push(e),
                            Some(other) => {
                                current.push('\\');
                                current.push(other);
                            }
                            None => return Err("No closing quotation"),
                        },
                        Some(c) => current.push(c),
                        None => return Err("No closing quotation"),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some(e) => current.push(e),
                    None => return Err("No escaped character"),
                }
            }
            c => {
                in_word = true;
                current.push(c);
            }
        }
    }
    if in_word {
        output.push(current);
    }
    Ok(output)
}

fn unix_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn usage() {
    crate::argparse::print_help("rnx", "rnx");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_is_argparses() {
        let hash = "00".repeat(16);
        let ns = |argv: &[&str]| {
            Namespace::from_args(&Args::parse_spec_from(
                argv.iter().map(|s| s.to_string()).collect(),
                &OPTIONS,
            ))
        };
        let o = ns(&["-l", "-a", "aa", "-abb", "-vv"]);
        assert!(o.listen);
        assert_eq!(o.allowed, Some(vec!["aa".into(), "bb".into()]));
        assert_eq!(o.verbose, 2);
        let o = ns(&[&hash, "ls -la", "-dmN", "-w5", "-W", "30", "--stdout=10"]);
        assert_eq!(o.destination.as_deref(), Some(hash.as_str()));
        assert_eq!(o.command.as_deref(), Some("ls -la"));
        assert!(o.detailed && o.mirror && o.noid);
        assert_eq!((o.w, o.big_w, o.stdout), (5.0, Some(30.0), Some(10)));
        let o = ns(&[]);
        assert_eq!((o.w, o.big_w, o.allowed), (15.0, None, None));
    }

    #[test]
    fn pretty_time_is_rnxs() {
        assert_eq!(pretty_time(12.5), "12.5s");
        assert_eq!(pretty_time(75.0), "1m and 15.0s");
        assert_eq!(pretty_time(3725.0), "1h, 2m and 5.0s");
    }

    #[test]
    fn shlex_quoting_is_posix() {
        assert_eq!(
            split_command(r#"echo "a\b" "c\"d" '' x"#).unwrap(),
            vec!["echo", "a\\b", "c\"d", "", "x"]
        );
    }

    #[test]
    fn shell_words_are_parsed_without_a_shell() {
        assert_eq!(
            split_command("printf '%s %s' hello\\ world \"ok\"").unwrap(),
            vec!["printf", "%s %s", "hello world", "ok"]
        );
        assert!(split_command("echo 'broken").is_err());
    }

    #[test]
    fn execution_is_bounded_and_reports_total_output() {
        let request = msgpack::pack(&Value::Array(vec![
            Value::Bin(b"printf 123456".to_vec()),
            Value::Float(2.0),
            Value::UInt(3),
            Value::UInt(0),
            Value::Nil,
        ]));
        let result = execute_request(&request, &AtomicBool::new(false), None);
        let result = decode_result(&result).unwrap();
        assert!(result.executed);
        assert_eq!(result.stdout.as_deref(), Some(&b"123"[..]));
        assert_eq!(result.outlen, Some(6));
    }

    #[test]
    fn timeout_kills_the_process_group() {
        let request = msgpack::pack(&Value::Array(vec![
            Value::Bin(b"sh -c 'sleep 10 & wait'".to_vec()),
            Value::Float(0.05),
            Value::UInt(0),
            Value::UInt(0),
            Value::Nil,
        ]));
        let started = Instant::now();
        let result =
            decode_result(&execute_request(&request, &AtomicBool::new(false), None)).unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(result.concluded.is_none());
    }
}
