//! Reticulum-compatible one-shot remote execution utility.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_net::destination::Destination;
use rns_net::{AnnouncedIdentity, Callbacks, RnsNode};

use crate::app;
use crate::format::prettyhexrep;

const APP_NAME: &str = "rnx";
const ASPECT: &str = "execute";
const COMMAND_PATH: &str = "command";
const VERSION: &str = env!("FULL_VERSION");
const DEFAULT_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const MAX_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;
const MAX_STDIN: usize = 8 * 1024 * 1024;
const MAX_COMMAND_TIMEOUT: f64 = 24.0 * 60.0 * 60.0;

#[derive(Debug, Default)]
struct Options {
    destination: Option<String>,
    command: Option<String>,
    config: Option<String>,
    identity: Option<String>,
    listen: bool,
    print_identity: bool,
    no_announce: bool,
    no_auth: bool,
    no_id: bool,
    detailed: bool,
    mirror: bool,
    interactive: bool,
    allowed: Vec<String>,
    timeout: f64,
    result_timeout: Option<f64>,
    stdin: Option<String>,
    stdout_limit: Option<usize>,
    stderr_limit: Option<usize>,
    verbose: u8,
    quiet: u8,
    help: bool,
    version: bool,
}

impl Options {
    fn parse(arguments: Vec<String>) -> Result<Self, String> {
        let mut options = Options {
            timeout: 15.0,
            ..Options::default()
        };
        let mut positional = Vec::new();
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            let mut value = |name: &str| -> Result<String, String> {
                index += 1;
                arguments
                    .get(index)
                    .cloned()
                    .ok_or_else(|| format!("{name} requires a value"))
            };
            match argument.as_str() {
                "--config" => options.config = Some(value(argument)?),
                "-i" | "--identity" => options.identity = Some(value(argument)?),
                "-a" | "--allowed" => options.allowed.push(value(argument)?),
                "-w" | "--timeout" => options.timeout = parse_number(&value(argument)?, "timeout")?,
                "-W" | "--result-timeout" => {
                    options.result_timeout =
                        Some(parse_number(&value(argument)?, "result timeout")?)
                }
                "--stdin" => options.stdin = Some(value(argument)?),
                "--stdout" => {
                    options.stdout_limit = Some(
                        value(argument)?
                            .parse()
                            .map_err(|_| "stdout limit must be an integer")?,
                    )
                }
                "--stderr" => {
                    options.stderr_limit = Some(
                        value(argument)?
                            .parse()
                            .map_err(|_| "stderr limit must be an integer")?,
                    )
                }
                "-l" | "--listen" => options.listen = true,
                "-p" | "--print-identity" => options.print_identity = true,
                "-b" | "--no-announce" => options.no_announce = true,
                "-n" | "--noauth" | "--no-auth" => options.no_auth = true,
                "-N" | "--noid" | "--no-id" => options.no_id = true,
                "-d" | "--detailed" => options.detailed = true,
                "-m" | "--mirror" => options.mirror = true,
                "-x" | "--interactive" => options.interactive = true,
                "-v" | "--verbose" => options.verbose = options.verbose.saturating_add(1),
                "-q" | "--quiet" => options.quiet = options.quiet.saturating_add(1),
                "-h" | "--help" => options.help = true,
                "--version" => options.version = true,
                item if item.starts_with('-') => return Err(format!("unknown option {item}")),
                item => positional.push(item.to_string()),
            }
            index += 1;
        }
        options.destination = positional.first().cloned();
        if positional.len() > 1 {
            options.command = Some(positional[1..].join(" "));
        }
        Ok(options)
    }
}

fn parse_number(value: &str, name: &str) -> Result<f64, String> {
    let value: f64 = value
        .parse()
        .map_err(|_| format!("{name} must be numeric"))?;
    if !value.is_finite() || !(0.0..=MAX_COMMAND_TIMEOUT).contains(&value) {
        return Err(format!("{name} must be between 0 and 86400 seconds"));
    }
    Ok(value)
}

enum RnxEvent {
    Announce,
    LinkEstablished([u8; 16], bool),
    LinkClosed([u8; 16]),
    Response(Vec<u8>),
    CommandRequested {
        link_id: [u8; 16],
        request_id: [u8; 16],
        data: Vec<u8>,
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
    fn on_announce(&mut self, _announced: AnnouncedIdentity) {
        let _ = self.tx.send(RnxEvent::Announce);
    }
    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}
    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
    }
    fn on_link_established(
        &mut self,
        link_id: LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        initiator: bool,
    ) {
        let _ = self
            .tx
            .send(RnxEvent::LinkEstablished(link_id.0, initiator));
    }
    fn on_link_closed(&mut self, link_id: LinkId, _reason: Option<rns_core::link::TeardownReason>) {
        if let Some(tokens) = self.cancellations.lock().unwrap().remove(&link_id.0) {
            for token in tokens {
                token.store(true, Ordering::Release);
            }
        }
        let _ = self.tx.send(RnxEvent::LinkClosed(link_id.0));
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
}

pub fn main() -> i32 {
    let options = match Options::parse(std::env::args().skip(1).collect()) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            usage();
            return 1;
        }
    };
    if options.help {
        usage();
        return 0;
    }
    if options.version {
        println!("rnx {VERSION}");
        return 0;
    }
    init_logging(&options);
    match run(options) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("rnx: {error}");
            1
        }
    }
}

fn run(options: Options) -> Result<i32, Box<dyn std::error::Error>> {
    let config = app::app_config(APP_NAME, None);
    let identity_path = options
        .identity
        .as_deref()
        .map(app::expand_path)
        .unwrap_or_else(|| config.join("identity"));
    let identity = app::load_or_create_identity(&identity_path)?;
    let destination = Destination::single_in(APP_NAME, &[ASPECT], IdentityHash(*identity.hash()));
    if options.print_identity {
        println!("Identity     : {}", prettyhexrep(identity.hash()));
        println!("Listening on : {}", prettyhexrep(&destination.hash.0));
        return Ok(0);
    }

    let cancellations = Arc::new(Mutex::new(HashMap::new()));
    let (tx, rx) = mpsc::channel();
    let node = RnsNode::connect_shared_from_config(
        Some(&app::rns_config(options.config.as_deref())),
        Box::new(RnxCallbacks {
            tx: tx.clone(),
            cancellations: cancellations.clone(),
        }),
    )?;
    if options.listen {
        listen(
            &node,
            &identity,
            destination,
            &config,
            options,
            tx,
            rx,
            cancellations,
        )?;
        Ok(0)
    } else {
        let destination = app::parse_hash_16(
            options
                .destination
                .as_deref()
                .ok_or("missing destination")?,
        )
        .ok_or("destination must be 32 hexadecimal characters")?;
        if options.interactive {
            interactive(&node, &identity, destination, &options, rx)
        } else {
            let command = options.command.as_deref().ok_or("missing command")?;
            execute(&node, &identity, destination, command, &options, &rx)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn listen(
    node: &RnsNode,
    identity: &rns_crypto::identity::Identity,
    destination: Destination,
    config: &std::path::Path,
    options: Options,
    tx: mpsc::Sender<RnxEvent>,
    rx: mpsc::Receiver<RnxEvent>,
    cancellations: CancellationMap,
) -> Result<(), Box<dyn std::error::Error>> {
    let allowed = load_allowed(&options, config)?;
    let allowed_list = (!options.no_auth).then(|| allowed.iter().copied().collect());
    let (signature_private, signature_public) = app::signature_keys(identity)?;
    node.register_destination_with_proof(&destination, identity.get_private_key())?;
    node.register_link_destination(destination.hash.0, signature_private, signature_public, 0)?;
    let request_tx = tx.clone();
    node.register_deferred_request_handler(
        COMMAND_PATH,
        allowed_list,
        move |link_id, _, request_id, data, _| {
            let _ = request_tx.send(RnxEvent::CommandRequested {
                link_id,
                request_id,
                data: data.to_vec(),
            });
        },
    )?;
    if allowed.is_empty() && !options.no_auth {
        eprintln!("warning: no allowed identities configured; no commands will be accepted");
    }
    if options.no_auth {
        eprintln!("warning: accepting unauthenticated remote commands");
    }
    if !options.no_announce {
        node.announce(&destination, identity, None)?;
    }
    eprintln!("rnx listening on {}", prettyhexrep(&destination.hash.0));

    let mut active_links = HashSet::new();
    loop {
        match rx.recv() {
            Ok(RnxEvent::CommandRequested {
                link_id,
                request_id,
                data,
            }) => {
                if !active_links.contains(&link_id) {
                    continue;
                }
                let cancel = Arc::new(AtomicBool::new(false));
                cancellations
                    .lock()
                    .unwrap()
                    .entry(link_id)
                    .or_default()
                    .push(cancel.clone());
                let result_tx = tx.clone();
                thread::spawn(move || {
                    let response = execute_request(&data, &cancel);
                    let _ = result_tx.send(RnxEvent::CommandFinished {
                        link_id,
                        request_id,
                        response,
                        cancellation: cancel,
                    });
                });
            }
            Ok(RnxEvent::CommandFinished {
                link_id,
                request_id,
                response,
                cancellation,
            }) => {
                node.send_deferred_response(link_id, request_id, response)?;
                let mut cancellations = cancellations.lock().unwrap();
                if let Some(tokens) = cancellations.get_mut(&link_id) {
                    tokens.retain(|token| !Arc::ptr_eq(token, &cancellation));
                    if tokens.is_empty() {
                        cancellations.remove(&link_id);
                    }
                }
            }
            Ok(RnxEvent::LinkEstablished(link_id, false)) => {
                active_links.insert(link_id);
            }
            Ok(RnxEvent::LinkClosed(link_id)) => {
                active_links.remove(&link_id);
                if let Some(tokens) = cancellations.lock().unwrap().remove(&link_id) {
                    for token in tokens {
                        token.store(true, Ordering::Release);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => return Ok(()),
        }
    }
}

fn execute_request(data: &[u8], cancel: &AtomicBool) -> Vec<u8> {
    let started = unix_time();
    let request = decode_command_request(data);
    let Ok(request) = request else {
        return encode_result(false, None, None, None, None, None, started, None);
    };
    let argv = match split_command(&request.command) {
        Ok(argv) if !argv.is_empty() => argv,
        _ => return encode_result(false, None, None, None, None, None, started, None),
    };
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
            let _ = stdin.write_all(&input[..input.len().min(MAX_STDIN)]);
        }
    }
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
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
    let (stdout, stdout_total) = stdout_thread.join().unwrap_or_default();
    let (stderr, stderr_total) = stderr_thread.join().unwrap_or_default();
    let concluded = (!timed_out && !cancel.load(Ordering::Acquire)).then(unix_time);
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
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
    }
    let until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < until {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
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
                retained.extend_from_slice(&buffer[..keep]);
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
    if values.len() != 5 {
        return Err(());
    }
    let command = match &values[0] {
        Value::Bin(value) => String::from_utf8(value.clone()).map_err(|_| ())?,
        Value::Str(value) => value.clone(),
        _ => return Err(()),
    };
    let timeout = match values[1] {
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
    let stdin = match &values[4] {
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
        stdout_limit: limit(&values[2]),
        stderr_limit: limit(&values[3]),
        stdin,
    })
}

#[allow(clippy::too_many_arguments)]
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

fn encode_request(command: &str, options: &Options) -> Vec<u8> {
    msgpack::pack(&Value::Array(vec![
        Value::Bin(command.as_bytes().to_vec()),
        Value::Float(options.timeout),
        options
            .stdout_limit
            .map(|value| Value::UInt(value as u64))
            .unwrap_or(Value::Nil),
        options
            .stderr_limit
            .map(|value| Value::UInt(value as u64))
            .unwrap_or(Value::Nil),
        options
            .stdin
            .as_ref()
            .map(|value| Value::Bin(value.as_bytes().to_vec()))
            .unwrap_or(Value::Nil),
    ]))
}

fn execute(
    node: &RnsNode,
    identity: &rns_crypto::identity::Identity,
    destination: [u8; 16],
    command: &str,
    options: &Options,
    rx: &mpsc::Receiver<RnxEvent>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let link_id = connect(node, identity, destination, options, rx)?;
    node.send_request_with_max_response_size(
        link_id,
        COMMAND_PATH,
        &encode_request(command, options),
        Some(MAX_OUTPUT_LIMIT * 2 + 4096),
    )?;
    let timeout = options.result_timeout.unwrap_or(options.timeout + 5.0);
    let deadline = Instant::now() + Duration::from_secs_f64(timeout);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))? {
            RnxEvent::Response(data) => {
                let result = decode_result(&data)?;
                if !result.executed {
                    return Err("remote could not execute command".into());
                }
                io::stdout().write_all(&result.stdout)?;
                io::stderr().write_all(&result.stderr)?;
                if options.detailed {
                    eprintln!(
                        "\nremote stdout: {} bytes ({} returned)",
                        result.stdout_total,
                        result.stdout.len()
                    );
                    eprintln!(
                        "remote stderr: {} bytes ({} returned)",
                        result.stderr_total,
                        result.stderr.len()
                    );
                    if let Some(duration) = result.concluded.map(|end| end - result.started) {
                        eprintln!("remote execution: {duration:.3}s");
                    }
                } else {
                    if result.stdout.len() as u64 != result.stdout_total {
                        eprintln!("\nstdout truncated to {} bytes", result.stdout.len());
                    }
                    if result.stderr.len() as u64 != result.stderr_total {
                        eprintln!("\nstderr truncated to {} bytes", result.stderr.len());
                    }
                }
                node.teardown_link(link_id)?;
                return Ok(if options.mirror {
                    result.status.unwrap_or(240).clamp(0, 255) as i32
                } else {
                    0
                });
            }
            RnxEvent::LinkClosed(id) if id == link_id => {
                return Err("link closed before result arrived".into())
            }
            _ => {}
        }
    }
}

struct CommandResult {
    executed: bool,
    status: Option<i64>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_total: u64,
    stderr_total: u64,
    started: f64,
    concluded: Option<f64>,
}

fn decode_result(data: &[u8]) -> Result<CommandResult, Box<dyn std::error::Error>> {
    let Value::Array(values) =
        msgpack::unpack_exact(data).map_err(|error| format!("invalid result: {error:?}"))?
    else {
        return Err("invalid result".into());
    };
    if values.len() != 8 {
        return Err("invalid result length".into());
    }
    let executed = matches!(values[0], Value::Bool(true));
    let status = match values[1] {
        Value::Int(value) => Some(value),
        Value::UInt(value) => i64::try_from(value).ok(),
        Value::Nil => None,
        _ => return Err("invalid status".into()),
    };
    let bytes = |value: &Value| match value {
        Value::Bin(value) => Ok(value.clone()),
        Value::Nil => Ok(Vec::new()),
        _ => Err("invalid output"),
    };
    let number = |value: &Value| match value {
        Value::UInt(value) => Ok(*value),
        Value::Int(value) if *value >= 0 => Ok(*value as u64),
        _ => Err("invalid output length"),
    };
    let float = |value: &Value| match value {
        Value::Float(value) => Ok(*value),
        Value::UInt(value) => Ok(*value as f64),
        _ => Err("invalid timestamp"),
    };
    Ok(CommandResult {
        executed,
        status,
        stdout: bytes(&values[2])?,
        stderr: bytes(&values[3])?,
        stdout_total: number(&values[4])?,
        stderr_total: number(&values[5])?,
        started: float(&values[6])?,
        concluded: match values[7] {
            Value::Nil => None,
            _ => Some(float(&values[7])?),
        },
    })
}

fn connect(
    node: &RnsNode,
    identity: &rns_crypto::identity::Identity,
    destination: [u8; 16],
    options: &Options,
    rx: &mpsc::Receiver<RnxEvent>,
) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    let configured_timeout = Duration::from_secs_f64(options.timeout);
    let deadline = Instant::now() + app::adaptive_path_timeout(node, configured_timeout);
    if !node.has_path(&DestHash(destination))? {
        node.request_path(&DestHash(destination))?;
    }
    while !node.has_path(&DestHash(destination))? {
        if Instant::now() >= deadline {
            return Err("path request timed out".into());
        }
        let _ = rx.recv_timeout(Duration::from_millis(100));
    }
    let recalled = node
        .recall_identity(&DestHash(destination))?
        .ok_or("destination identity was not recalled")?;
    let mut signature_public = [0u8; 32];
    signature_public.copy_from_slice(&recalled.public_key[32..]);
    let link_id = node.create_link(destination, signature_public)?;
    let link_deadline =
        Instant::now() + configured_timeout.max(app::link_establishment_timeout(node, destination));
    loop {
        match rx.recv_timeout(link_deadline.saturating_duration_since(Instant::now()))? {
            RnxEvent::LinkEstablished(id, true) if id == link_id => break,
            RnxEvent::LinkClosed(id) if id == link_id => {
                return Err("link establishment failed".into())
            }
            _ => {}
        }
    }
    if !options.no_id {
        node.identify_on_link(
            link_id,
            identity
                .get_private_key()
                .ok_or("identity has no private key")?,
        )?;
    }
    Ok(link_id)
}

fn interactive(
    node: &RnsNode,
    identity: &rns_crypto::identity::Identity,
    destination: [u8; 16],
    options: &Options,
    rx: mpsc::Receiver<RnxEvent>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let mut last = 0;
    loop {
        print!(
            "{}> ",
            if last == 0 {
                String::new()
            } else {
                last.to_string()
            }
        );
        io::stdout().flush()?;
        let mut command = String::new();
        if io::stdin().read_line(&mut command)? == 0 {
            return Ok(0);
        }
        let command = command.trim();
        if matches!(command, "exit" | "quit") {
            return Ok(0);
        }
        if command == "clear" {
            print!("\x1bc");
            continue;
        }
        if command.is_empty() {
            continue;
        }
        last = execute(node, identity, destination, command, options, &rx)?;
    }
}

fn split_command(command: &str) -> Result<Vec<String>, &'static str> {
    let mut output = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in command.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                output.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err("unterminated quote or escape");
    }
    if !current.is_empty() {
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

fn load_allowed(options: &Options, config: &std::path::Path) -> io::Result<HashSet<[u8; 16]>> {
    let mut entries = options.allowed.clone();
    let path = config.join("allowed_identities");
    if path.is_file() {
        entries.extend(fs::read_to_string(path)?.lines().map(str::to_string));
    }
    entries
        .into_iter()
        .filter(|entry| !entry.trim().is_empty())
        .map(|entry| {
            app::parse_hash_16(entry.trim()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid allowed identity {entry}"),
                )
            })
        })
        .collect()
}

fn init_logging(options: &Options) {
    let level = (3i16 + options.verbose as i16 - options.quiet as i16).clamp(0, 5);
    let filter = match level {
        0 => "off",
        1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        _ => "trace",
    };
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter));
    let _ = builder.try_init();
}

fn usage() {
    println!("Usage:\n  rnx [options] <destination> <command>\n  rnx --listen [options]\n  rnx --interactive [options] <destination>\n\nOptions:\n  -l, --listen              Listen for commands\n  -x, --interactive         Interactive command prompt\n  -a, --allowed HASH        Allow identity (repeatable)\n  -n, --noauth              Accept unauthenticated commands\n  -N, --noid                Do not identify to listener\n  -b, --no-announce         Do not announce listener\n  -d, --detailed            Show execution and transfer details\n  -m, --mirror              Mirror remote exit status\n  -w, --timeout SECONDS     Connect and command timeout\n  -W, --result-timeout SEC  Maximum result download time\n      --stdin TEXT          Pass command stdin\n      --stdout BYTES        Maximum returned stdout\n      --stderr BYTES        Maximum returned stderr\n  -i, --identity PATH       Identity file\n      --config DIR          Reticulum config directory\n  -p, --print-identity      Print identity and destination\n      --version             Print version");
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let result = execute_request(&request, &AtomicBool::new(false));
        let result = decode_result(&result).unwrap();
        assert!(result.executed);
        assert_eq!(result.stdout, b"123");
        assert_eq!(result.stdout_total, 6);
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
        let result = decode_result(&execute_request(&request, &AtomicBool::new(false))).unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(result.concluded.is_none());
    }
}
