use std::collections::HashMap;
use std::io::{self, Read};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rns_hooks_abi::sentinel::{BackbonePeerPayload, BACKBONE_PEER_PAYLOAD_TYPE};
use rns_net::config;
use rns_net::pickle::PickleValue;
use rns_net::provider_bridge::{HookProviderEventEnvelope, ProviderEnvelope, ProviderMessage};
use rns_net::rpc::derive_auth_key;
use rns_net::storage;
use rns_net::{HookInfo, RpcAddr, RpcClient};

use crate::args::Args;

const VERSION: &str = env!("FULL_VERSION");
const EMBEDDED_HOOK_WASM: &[u8] = include_bytes!(env!("RNS_SENTINEL_HOOK_WASM"));
const HOOK_SPECS: [(&str, &str); 5] = [
    ("rns_sentinel_peer_connected", "BackbonePeerConnected"),
    ("rns_sentinel_peer_disconnected", "BackbonePeerDisconnected"),
    ("rns_sentinel_peer_idle_timeout", "BackbonePeerIdleTimeout"),
    ("rns_sentinel_peer_write_stall", "BackbonePeerWriteStall"),
    ("rns_sentinel_peer_penalty", "BackbonePeerPenalty"),
];

/// Default: penalize after 2 write stalls in 5 minutes.
const DEFAULT_WRITE_STALL_THRESHOLD: u32 = 2;
/// Default: penalize after 4 idle timeouts in 5 minutes.
const DEFAULT_IDLE_TIMEOUT_THRESHOLD: u32 = 4;
/// Default event window for counting events.
const DEFAULT_EVENT_WINDOW: Duration = Duration::from_secs(300);
/// Base blacklist duration.
const DEFAULT_BASE_BLACKLIST_SECS: u64 = 120;
/// Default: flap detection disabled unless explicitly configured.
const DEFAULT_FLAP_THRESHOLD: u32 = 0;
/// Default: connect-rate detection disabled unless explicitly configured.
const DEFAULT_CONNECT_RATE_THRESHOLD: u32 = 0;
/// Default: only very short silent sessions count as flaps.
const DEFAULT_FLAP_MAX_CONNECTION_AGE: Duration = Duration::from_secs(10);

static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

pub fn main_entry() {
    let previous_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        SHOULD_STOP.store(true, Ordering::Relaxed);
        previous_panic_hook(panic_info);
    }));

    let exit_code = match std::panic::catch_unwind(run) {
        Ok(Ok(())) => 0,
        Ok(Err(err)) => {
            eprintln!("rns-sentineld: {}", err);
            1
        }
        Err(_) => 101,
    };

    process::exit(exit_code);
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    if args.has("version") {
        println!("rns-sentineld {}", VERSION);
        return Ok(());
    }
    if args.has("help") || args.has("h") {
        print_usage();
        return Ok(());
    }

    env_logger::Builder::new()
        .filter_level(match args.verbosity {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
        .format_timestamp_secs()
        .init();

    install_signal_handlers();

    let priority = args
        .get("priority")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let write_stall_threshold = args
        .get("write-stall-threshold")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WRITE_STALL_THRESHOLD);
    let idle_timeout_threshold = args
        .get("idle-timeout-threshold")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_IDLE_TIMEOUT_THRESHOLD);
    let event_window_secs = args
        .get("event-window")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_EVENT_WINDOW.as_secs());
    let write_stall_window_secs = args
        .get("write-stall-window")
        .and_then(|s| s.parse().ok())
        .unwrap_or(event_window_secs);
    let idle_timeout_window_secs = args
        .get("idle-timeout-window")
        .and_then(|s| s.parse().ok())
        .unwrap_or(event_window_secs);
    let flap_threshold = args
        .get("flap-threshold")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_FLAP_THRESHOLD);
    let flap_window_secs = args
        .get("flap-window")
        .and_then(|s| s.parse().ok())
        .unwrap_or(event_window_secs);
    let flap_max_connection_age_secs = args
        .get("flap-max-connection-age")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_FLAP_MAX_CONNECTION_AGE.as_secs());
    let connect_rate_threshold = args
        .get("connect-rate-threshold")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CONNECT_RATE_THRESHOLD);
    let connect_rate_window_secs = args
        .get("connect-rate-window")
        .and_then(|s| s.parse().ok())
        .unwrap_or(event_window_secs);
    let base_blacklist_secs = args
        .get("base-blacklist")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BASE_BLACKLIST_SECS);
    let penalty_decay_secs = args
        .get("penalty-decay-interval")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0u64);

    let policy = DetectionPolicy {
        write_stall_threshold,
        idle_timeout_threshold,
        write_stall_window: Duration::from_secs(write_stall_window_secs),
        idle_timeout_window: Duration::from_secs(idle_timeout_window_secs),
        flap_threshold,
        flap_window: Duration::from_secs(flap_window_secs),
        flap_max_connection_age: Duration::from_secs(flap_max_connection_age_secs),
        connect_rate_threshold,
        connect_rate_window: Duration::from_secs(connect_rate_window_secs),
        base_blacklist_secs,
        penalty_decay_interval: (penalty_decay_secs > 0)
            .then(|| Duration::from_secs(penalty_decay_secs)),
    };

    let runtime = RuntimeConfig::load(args.config_path().map(Path::new), args.get("socket"))?;

    let control = RpcControl::new(runtime.rpc_addr.clone(), runtime.auth_key);
    loop {
        unload_stale_hooks(&control);
        match load_hooks(&control, priority) {
            Ok(()) => break,
            Err(err) => {
                log::warn!("waiting for rnsd RPC: {}", err);
                for _ in 0..50 {
                    if SHOULD_STOP.load(Ordering::Relaxed) {
                        return Err("interrupted while waiting for rnsd".to_string());
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    let hook_guard = HookGuard {
        control: control.clone(),
        armed: true,
    };

    let mut stream = loop {
        match UnixStream::connect(&runtime.provider_socket) {
            Ok(s) => break s,
            Err(err) => {
                log::warn!("waiting for provider bridge: {}", err);
                for _ in 0..50 {
                    if SHOULD_STOP.load(Ordering::Relaxed) {
                        return Err("interrupted while waiting for provider bridge".to_string());
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("provider bridge timeout setup failed: {}", e))?;

    log::info!(
        "rns-sentineld started (write_stall={}/{}, idle_timeout={}/{}, flap={}/{}, connect_rate={}/{}, base_blacklist={}s, decay={}s)",
        policy.write_stall_threshold,
        policy.write_stall_window.as_secs(),
        policy.idle_timeout_threshold,
        policy.idle_timeout_window.as_secs(),
        policy.flap_threshold,
        policy.flap_window.as_secs(),
        policy.connect_rate_threshold,
        policy.connect_rate_window.as_secs(),
        policy.base_blacklist_secs,
        policy
            .penalty_decay_interval
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    let mut tracker = PeerTracker::new(policy);

    while !SHOULD_STOP.load(Ordering::Relaxed) {
        match read_provider_envelope(&mut stream) {
            Ok(Some(envelope)) => {
                if let ProviderMessage::Event(ref event) = envelope.message {
                    if let Some(action) = tracker.ingest(event) {
                        if let Err(e) = execute_blacklist(&control, &action.interface_name, &action)
                        {
                            log::warn!("blacklist RPC failed for {}: {}", action.peer_ip, e);
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return Err("provider bridge disconnected".to_string());
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(err) => return Err(format!("provider bridge read failed: {}", err)),
        }
    }

    drop(hook_guard);
    Ok(())
}

fn execute_blacklist(
    control: &RpcControl,
    interface_name: &str,
    action: &BlacklistAction,
) -> Result<(), String> {
    let interface_name = if interface_name.is_empty() {
        control
            .resolve_interface_name(action.server_interface_id)?
            .ok_or_else(|| {
                format!(
                    "could not resolve backbone interface {} for {}",
                    action.server_interface_id, action.peer_ip
                )
            })?
    } else {
        interface_name.to_string()
    };
    log::warn!(
        "blacklisting {} on {} for {}s (level {}): {}",
        action.peer_ip,
        interface_name,
        action.duration_secs,
        action.level,
        action.reason
    );
    control.with_client(|client| {
        client.blacklist_backbone_peer(
            &interface_name,
            &action.peer_ip.to_string(),
            action.duration_secs,
            Some(&action.reason),
            Some(action.level),
        )
    })?;
    Ok(())
}

// --- RPC control (same pattern as statsd) ---

#[derive(Clone)]
struct RpcControl {
    rpc_addr: RpcAddr,
    auth_key: [u8; 32],
}

impl RpcControl {
    fn new(rpc_addr: RpcAddr, auth_key: [u8; 32]) -> Self {
        Self { rpc_addr, auth_key }
    }

    fn with_client<T>(
        &self,
        op: impl FnOnce(&mut RpcClient) -> io::Result<T>,
    ) -> Result<T, String> {
        let mut client = RpcClient::connect(&self.rpc_addr, &self.auth_key)
            .map_err(|e| format!("rpc connect failed: {}", e))?;
        op(&mut client).map_err(|e| format!("rpc call failed: {}", e))
    }

    fn load_hook(&self, name: &str, attach_point: &str, priority: i32) -> Result<(), String> {
        self.with_client(|client| {
            client.load_hook(name, attach_point, priority, EMBEDDED_HOOK_WASM)
        })?
    }

    fn unload_hook(&self, name: &str, attach_point: &str) -> Result<(), String> {
        self.with_client(|client| client.unload_hook(name, attach_point))?
    }

    fn list_hooks(&self) -> Result<Vec<HookInfo>, String> {
        self.with_client(|client| client.list_hooks())
    }

    fn resolve_interface_name(&self, interface_id: u64) -> Result<Option<String>, String> {
        self.with_client(|client| {
            client.call(&PickleValue::Dict(vec![(
                PickleValue::String("get".into()),
                PickleValue::String("backbone_interfaces".into()),
            )]))
        })
        .map(|response| {
            response.as_list().and_then(|entries| {
                entries.iter().find_map(|entry| {
                    let id = entry.get("id").and_then(|v| v.as_int())?;
                    (id == interface_id as i64).then(|| {
                        entry
                            .get("name")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    })?
                })
            })
        })
    }
}

struct HookGuard {
    control: RpcControl,
    armed: bool,
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for (name, attach_point) in HOOK_SPECS {
            let _ = self.control.unload_hook(name, attach_point);
        }
    }
}

struct RuntimeConfig {
    rpc_addr: RpcAddr,
    auth_key: [u8; 32],
    provider_socket: PathBuf,
}

impl RuntimeConfig {
    fn load(config_path: Option<&Path>, socket_override: Option<&str>) -> Result<Self, String> {
        let config_dir = storage::resolve_config_dir(config_path);
        let config_file = config_dir.join("config");
        let rns_config = if config_file.exists() {
            config::parse_file(&config_file).map_err(|e| e.to_string())?
        } else {
            config::parse("").map_err(|e| e.to_string())?
        };
        let paths = storage::ensure_storage_dirs(&config_dir).map_err(|e| e.to_string())?;
        let identity =
            storage::load_or_create_identity(&paths.identities).map_err(|e| e.to_string())?;
        let auth_key = derive_auth_key(&identity.get_private_key().unwrap_or([0u8; 64]));
        let provider_socket = socket_override
            .map(PathBuf::from)
            .or_else(|| rns_config.reticulum.provider_socket_path.map(PathBuf::from))
            .ok_or_else(|| "provider bridge socket is not configured".to_string())?;

        Ok(Self {
            rpc_addr: RpcAddr::Tcp(
                "127.0.0.1".into(),
                rns_config.reticulum.instance_control_port,
            ),
            auth_key,
            provider_socket,
        })
    }
}

// --- Peer tracking & detection ---

struct PeerRecord {
    server_interface_id: u64,
    write_stall_events: Vec<Instant>,
    idle_timeout_events: Vec<Instant>,
    flap_events: Vec<Instant>,
    connect_events: Vec<Instant>,
    blacklist_level: u8,
    last_blacklist_at: Option<Instant>,
    blacklisted_until: Option<Instant>,
    last_decay_check_at: Option<Instant>,
    live_connections: usize,
    interface_name: String,
}

impl PeerRecord {
    fn new(server_interface_id: u64, interface_name: String) -> Self {
        Self {
            server_interface_id,
            write_stall_events: Vec::new(),
            idle_timeout_events: Vec::new(),
            flap_events: Vec::new(),
            connect_events: Vec::new(),
            blacklist_level: 0,
            last_blacklist_at: None,
            blacklisted_until: None,
            last_decay_check_at: None,
            live_connections: 0,
            interface_name,
        }
    }

    fn prune(&mut self, now: Instant, policy: &DetectionPolicy) {
        self.write_stall_events
            .retain(|t| now.duration_since(*t) <= policy.write_stall_window);
        self.idle_timeout_events
            .retain(|t| now.duration_since(*t) <= policy.idle_timeout_window);
        self.flap_events
            .retain(|t| now.duration_since(*t) <= policy.flap_window);
        self.connect_events
            .retain(|t| now.duration_since(*t) <= policy.connect_rate_window);
    }

    fn decay_penalty(&mut self, now: Instant, policy: &DetectionPolicy) {
        let Some(interval) = policy.penalty_decay_interval else {
            return;
        };
        if self.blacklist_level == 0 || self.live_connections > 0 {
            return;
        }
        if self.blacklisted_until.is_some_and(|until| now < until) {
            return;
        }
        let anchor = self
            .last_decay_check_at
            .or(self.blacklisted_until)
            .or(self.last_blacklist_at);
        let Some(anchor) = anchor else {
            return;
        };
        if now <= anchor {
            return;
        }
        let elapsed = now.duration_since(anchor).as_secs();
        let step = interval.as_secs().max(1);
        let levels = (elapsed / step).min(u8::MAX as u64) as u8;
        if levels == 0 {
            return;
        }
        self.blacklist_level = self.blacklist_level.saturating_sub(levels);
        self.last_decay_check_at = if self.blacklist_level == 0 {
            None
        } else {
            Some(anchor + interval * levels as u32)
        };
    }
}

struct BlacklistAction {
    server_interface_id: u64,
    peer_ip: IpAddr,
    interface_name: String,
    duration_secs: u64,
    level: u8,
    reason: String,
}

struct DetectionPolicy {
    write_stall_threshold: u32,
    idle_timeout_threshold: u32,
    write_stall_window: Duration,
    idle_timeout_window: Duration,
    flap_threshold: u32,
    flap_window: Duration,
    flap_max_connection_age: Duration,
    connect_rate_threshold: u32,
    connect_rate_window: Duration,
    base_blacklist_secs: u64,
    penalty_decay_interval: Option<Duration>,
}

impl Default for DetectionPolicy {
    fn default() -> Self {
        Self {
            write_stall_threshold: DEFAULT_WRITE_STALL_THRESHOLD,
            idle_timeout_threshold: DEFAULT_IDLE_TIMEOUT_THRESHOLD,
            write_stall_window: DEFAULT_EVENT_WINDOW,
            idle_timeout_window: DEFAULT_EVENT_WINDOW,
            flap_threshold: DEFAULT_FLAP_THRESHOLD,
            flap_window: DEFAULT_EVENT_WINDOW,
            flap_max_connection_age: DEFAULT_FLAP_MAX_CONNECTION_AGE,
            connect_rate_threshold: DEFAULT_CONNECT_RATE_THRESHOLD,
            connect_rate_window: DEFAULT_EVENT_WINDOW,
            base_blacklist_secs: DEFAULT_BASE_BLACKLIST_SECS,
            penalty_decay_interval: None,
        }
    }
}

struct PeerTracker {
    peers: HashMap<(u64, IpAddr), PeerRecord>,
    policy: DetectionPolicy,
}

impl PeerTracker {
    fn new(policy: DetectionPolicy) -> Self {
        Self {
            peers: HashMap::new(),
            policy,
        }
    }

    fn ingest(&mut self, event: &HookProviderEventEnvelope) -> Option<BlacklistAction> {
        if event.payload_type != BACKBONE_PEER_PAYLOAD_TYPE {
            return None;
        }

        let payload = BackbonePeerPayload::decode(&event.payload)?;
        let peer_ip = decode_ip(&payload)?;
        let interface_name = payload.server_interface_name().unwrap_or("").to_string();
        let server_interface_id = payload.server_interface_id;
        let now = Instant::now();
        let peer_key = (server_interface_id, peer_ip);

        let record = self
            .peers
            .entry(peer_key.clone())
            .or_insert_with(|| PeerRecord::new(server_interface_id, interface_name.clone()));
        record.server_interface_id = server_interface_id;
        if !interface_name.is_empty() {
            record.interface_name = interface_name;
        }
        record.prune(now, &self.policy);
        record.decay_penalty(now, &self.policy);

        match event.attach_point.as_str() {
            "BackbonePeerConnected" => {
                record.live_connections = record.live_connections.saturating_add(1);
                record.connect_events.push(now);
                log::debug!("peer connected: {}", peer_ip);
                (record.connect_events.len() as u32 >= self.policy.connect_rate_threshold
                    && self.policy.connect_rate_threshold > 0)
                    .then(|| self.apply_blacklist(&peer_key, "connection rate exceeded"))
            }
            "BackbonePeerDisconnected" => {
                record.live_connections = record.live_connections.saturating_sub(1);
                log::debug!(
                    "peer disconnected: {} (connected {}s, data={})",
                    peer_ip,
                    payload.connected_for_secs,
                    payload.had_received_data
                );
                if !payload.had_received_data
                    && payload.connected_for_secs <= self.policy.flap_max_connection_age.as_secs()
                {
                    record.flap_events.push(now);
                    if self.policy.flap_threshold > 0
                        && record.flap_events.len() as u32 >= self.policy.flap_threshold
                    {
                        return Some(
                            self.apply_blacklist(&peer_key, "rapid silent reconnect churn"),
                        );
                    }
                }
                None
            }
            "BackbonePeerIdleTimeout" => {
                record.live_connections = record.live_connections.saturating_sub(1);
                record.idle_timeout_events.push(now);
                log::debug!(
                    "peer idle timeout: {} ({}s)",
                    peer_ip,
                    payload.connected_for_secs
                );
                if record.idle_timeout_events.len() as u32 >= self.policy.idle_timeout_threshold {
                    Some(self.apply_blacklist(&peer_key, "repeated idle timeouts"))
                } else {
                    None
                }
            }
            "BackbonePeerWriteStall" => {
                record.live_connections = record.live_connections.saturating_sub(1);
                record.write_stall_events.push(now);
                log::debug!(
                    "peer write stall: {} ({}s)",
                    peer_ip,
                    payload.connected_for_secs
                );
                if record.write_stall_events.len() as u32 >= self.policy.write_stall_threshold {
                    Some(self.apply_blacklist(&peer_key, "repeated write stalls"))
                } else {
                    None
                }
            }
            "BackbonePeerPenalty" => {
                log::debug!(
                    "peer penalized: {} level={} ban={}s",
                    peer_ip,
                    payload.penalty_level,
                    payload.blacklist_for_secs
                );
                None
            }
            _ => None,
        }
    }

    fn apply_blacklist(&mut self, peer_key: &(u64, IpAddr), reason: &str) -> BlacklistAction {
        let record = self.peers.get_mut(peer_key).unwrap();
        record.blacklist_level = record.blacklist_level.saturating_add(1);
        let multiplier = 1u64 << (record.blacklist_level - 1).min(20);
        let duration_secs = self.policy.base_blacklist_secs.saturating_mul(multiplier);
        let now = Instant::now();
        record.last_blacklist_at = Some(now);
        record.blacklisted_until = Some(now + Duration::from_secs(duration_secs));
        record.last_decay_check_at = None;
        // Clear event windows after applying penalty
        record.write_stall_events.clear();
        record.idle_timeout_events.clear();
        record.flap_events.clear();
        record.connect_events.clear();

        BlacklistAction {
            server_interface_id: record.server_interface_id,
            peer_ip: peer_key.1,
            interface_name: record.interface_name.clone(),
            duration_secs,
            level: record.blacklist_level,
            reason: reason.to_string(),
        }
    }
}

fn decode_ip(payload: &BackbonePeerPayload) -> Option<IpAddr> {
    if payload.peer_ip_family == 4 {
        let mut octets = [0u8; 4];
        octets.copy_from_slice(&payload.peer_ip[12..16]);
        if octets == [0u8; 4] {
            octets.copy_from_slice(&payload.peer_ip[..4]);
        }
        Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
    } else if payload.peer_ip_family == 6 {
        Some(IpAddr::V6(std::net::Ipv6Addr::from(payload.peer_ip)))
    } else {
        None
    }
}

// --- Hook management (same pattern as statsd) ---

fn load_hooks(control: &RpcControl, priority: i32) -> Result<(), String> {
    let mut loaded = Vec::new();
    for (name, attach_point) in HOOK_SPECS {
        if let Err(err) = control.load_hook(name, attach_point, priority) {
            for (loaded_name, loaded_attach_point) in loaded.into_iter().rev() {
                let _ = control.unload_hook(loaded_name, loaded_attach_point);
            }
            return Err(format!(
                "failed to load {} at {}: {}",
                name, attach_point, err
            ));
        }
        loaded.push((name, attach_point));
    }
    Ok(())
}

fn unload_stale_hooks(control: &RpcControl) {
    match control.list_hooks() {
        Ok(hooks) => {
            for hook in hooks {
                if HOOK_SPECS.iter().any(|(name, attach_point)| {
                    *name == hook.name && *attach_point == hook.attach_point
                }) {
                    let _ = control.unload_hook(&hook.name, &hook.attach_point);
                }
            }
        }
        Err(err) => {
            log::debug!("could not list hooks for stale cleanup: {}", err);
            for (name, attach_point) in HOOK_SPECS {
                let _ = control.unload_hook(name, attach_point);
            }
        }
    }
}

fn read_provider_envelope(stream: &mut UnixStream) -> io::Result<Option<ProviderEnvelope>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    let envelope: ProviderEnvelope =
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(envelope))
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGHUP,
            signal_handler as *const () as libc::sighandler_t,
        );
    }
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    SHOULD_STOP.store(true, Ordering::Relaxed);
}

fn print_usage() {
    println!("Usage: rns-sentineld [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config PATH, -c PATH      Path to config directory");
    println!("  --socket PATH               Provider bridge socket override");
    println!("  --priority N                 Hook priority (default: 0)");
    println!(
        "  --write-stall-threshold N    Write stalls before blacklist (default: {})",
        DEFAULT_WRITE_STALL_THRESHOLD
    );
    println!(
        "  --idle-timeout-threshold N   Idle timeouts before blacklist (default: {})",
        DEFAULT_IDLE_TIMEOUT_THRESHOLD
    );
    println!(
        "  --event-window SECS          Sliding window for event counting (default: {})",
        DEFAULT_EVENT_WINDOW.as_secs()
    );
    println!(
        "  --write-stall-window SECS    Sliding window for write stalls (default: event-window)"
    );
    println!(
        "  --idle-timeout-window SECS   Sliding window for idle timeouts (default: event-window)"
    );
    println!(
        "  --flap-threshold N           Silent reconnect flaps before blacklist (default: {})",
        DEFAULT_FLAP_THRESHOLD
    );
    println!(
        "  --flap-window SECS           Sliding window for flap detection (default: event-window)"
    );
    println!("  --flap-max-connection-age SECS  Max silent connection age counted as a flap (default: {})", DEFAULT_FLAP_MAX_CONNECTION_AGE.as_secs());
    println!(
        "  --connect-rate-threshold N   Connection attempts before blacklist (default: {})",
        DEFAULT_CONNECT_RATE_THRESHOLD
    );
    println!("  --connect-rate-window SECS   Sliding window for connect-rate detection (default: event-window)");
    println!(
        "  --base-blacklist SECS        Base blacklist duration (default: {})",
        DEFAULT_BASE_BLACKLIST_SECS
    );
    println!("  --penalty-decay-interval SECS  Idle time needed to decay blacklist level by 1 (default: 0)");
    println!("  --version                    Print version");
    println!("  --help, -h                   Print this help");
    println!("  -v                           Increase verbosity");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(
        attach_point: &str,
        ip_octets: [u8; 4],
        connected_for: u64,
    ) -> HookProviderEventEnvelope {
        let mut server_interface_name =
            [0u8; rns_hooks_abi::sentinel::BACKBONE_PEER_INTERFACE_NAME_MAX];
        server_interface_name[..6].copy_from_slice(b"public");
        let payload = BackbonePeerPayload {
            peer_ip_family: 4,
            peer_ip: [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0xff,
                0xff,
                ip_octets[0],
                ip_octets[1],
                ip_octets[2],
                ip_octets[3],
            ],
            peer_port: 4242,
            server_interface_id: 1,
            peer_interface_id: 100,
            connected_for_secs: connected_for,
            had_received_data: true,
            penalty_level: 0,
            blacklist_for_secs: 0,
            event_kind: 0,
            server_interface_name_len: 6,
            server_interface_name,
        };
        HookProviderEventEnvelope {
            ts_unix_ms: 1000,
            node_instance: "test".into(),
            hook_name: "rns_sentinel_test".into(),
            attach_point: attach_point.into(),
            payload_type: BACKBONE_PEER_PAYLOAD_TYPE.into(),
            payload: payload.encode().to_vec(),
        }
    }

    #[test]
    fn write_stall_below_threshold_does_not_trigger() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        let event = make_event("BackbonePeerWriteStall", [192, 168, 1, 1], 30);
        // First stall — below threshold of 2
        assert!(tracker.ingest(&event).is_none());
    }

    #[test]
    fn write_stall_at_threshold_triggers_blacklist() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        let event = make_event("BackbonePeerWriteStall", [192, 168, 1, 2], 30);
        assert!(tracker.ingest(&event).is_none());
        let action = tracker
            .ingest(&event)
            .expect("expected blacklist on 2nd stall");
        assert_eq!(action.peer_ip, "192.168.1.2".parse::<IpAddr>().unwrap());
        assert_eq!(action.level, 1);
        assert_eq!(action.duration_secs, DEFAULT_BASE_BLACKLIST_SECS);
        assert_eq!(action.reason, "repeated write stalls");
    }

    #[test]
    fn idle_timeout_below_threshold_does_not_trigger() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        let event = make_event("BackbonePeerIdleTimeout", [10, 0, 0, 1], 5);
        for _ in 0..3 {
            assert!(tracker.ingest(&event).is_none());
        }
    }

    #[test]
    fn idle_timeout_at_threshold_triggers_blacklist() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        let event = make_event("BackbonePeerIdleTimeout", [10, 0, 0, 2], 5);
        for _ in 0..3 {
            assert!(tracker.ingest(&event).is_none());
        }
        let action = tracker
            .ingest(&event)
            .expect("expected blacklist on 4th idle timeout");
        assert_eq!(action.peer_ip, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(action.level, 1);
        assert_eq!(action.reason, "repeated idle timeouts");
    }

    #[test]
    fn exponential_escalation() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        let event = make_event("BackbonePeerWriteStall", [172, 16, 0, 1], 30);

        // First penalty: level 1, base duration
        tracker.ingest(&event);
        let action = tracker.ingest(&event).unwrap();
        assert_eq!(action.level, 1);
        assert_eq!(action.duration_secs, DEFAULT_BASE_BLACKLIST_SECS); // 120

        // Second penalty: level 2, 2x duration
        tracker.ingest(&event);
        let action = tracker.ingest(&event).unwrap();
        assert_eq!(action.level, 2);
        assert_eq!(action.duration_secs, DEFAULT_BASE_BLACKLIST_SECS * 2); // 240

        // Third penalty: level 3, 4x duration
        tracker.ingest(&event);
        let action = tracker.ingest(&event).unwrap();
        assert_eq!(action.level, 3);
        assert_eq!(action.duration_secs, DEFAULT_BASE_BLACKLIST_SECS * 4); // 480
    }

    #[test]
    fn connect_and_disconnect_do_not_trigger() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        for _ in 0..20 {
            assert!(tracker
                .ingest(&make_event("BackbonePeerConnected", [1, 2, 3, 4], 0))
                .is_none());
            assert!(tracker
                .ingest(&make_event("BackbonePeerDisconnected", [1, 2, 3, 4], 60))
                .is_none());
        }
    }

    #[test]
    fn penalty_event_does_not_trigger() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        for _ in 0..20 {
            assert!(tracker
                .ingest(&make_event("BackbonePeerPenalty", [5, 6, 7, 8], 0))
                .is_none());
        }
    }

    #[test]
    fn different_ips_tracked_independently() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        let event_a = make_event("BackbonePeerWriteStall", [10, 0, 0, 1], 30);
        let event_b = make_event("BackbonePeerWriteStall", [10, 0, 0, 2], 30);
        // One stall each — neither should trigger
        assert!(tracker.ingest(&event_a).is_none());
        assert!(tracker.ingest(&event_b).is_none());
        // Second stall for A triggers
        let action = tracker.ingest(&event_a).expect("expected blacklist for A");
        assert_eq!(action.peer_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        // Second stall for B also triggers (independently)
        let action = tracker.ingest(&event_b).expect("expected blacklist for B");
        assert_eq!(action.peer_ip, "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn unknown_payload_type_ignored() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        let event = HookProviderEventEnvelope {
            ts_unix_ms: 1000,
            node_instance: "test".into(),
            hook_name: "other_hook".into(),
            attach_point: "BackbonePeerWriteStall".into(),
            payload_type: "something.else.v1".into(),
            payload: vec![0; 54],
        };
        assert!(tracker.ingest(&event).is_none());
    }

    #[test]
    fn events_cleared_after_blacklist() {
        let mut tracker = PeerTracker::new(DetectionPolicy::default());
        let event = make_event("BackbonePeerWriteStall", [192, 168, 1, 1], 30);
        // Trigger first blacklist
        tracker.ingest(&event);
        tracker.ingest(&event).expect("first blacklist");
        // Next single stall should NOT trigger (events were cleared)
        assert!(tracker.ingest(&event).is_none());
        // But second stall after clear SHOULD trigger (level 2)
        let action = tracker.ingest(&event).expect("second blacklist");
        assert_eq!(action.level, 2);
    }
}
