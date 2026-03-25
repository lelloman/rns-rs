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
    (
        "rns_sentinel_peer_idle_timeout",
        "BackbonePeerIdleTimeout",
    ),
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
                        return Err(
                            "interrupted while waiting for provider bridge".to_string(),
                        );
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("provider bridge timeout setup failed: {}", e))?;

    log::info!("rns-sentineld started, monitoring backbone peers");

    let mut tracker = PeerTracker::new();

    while !SHOULD_STOP.load(Ordering::Relaxed) {
        match read_provider_envelope(&mut stream) {
            Ok(Some(envelope)) => {
                if let ProviderMessage::Event(ref event) = envelope.message {
                    if let Some(action) = tracker.ingest(event) {
                        if let Err(e) =
                            execute_blacklist(&control, &action.interface_name, &action)
                        {
                            log::warn!(
                                "blacklist RPC failed for {}: {}",
                                action.peer_ip,
                                e
                            );
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
    log::warn!(
        "blacklisting {} on {} for {}s (level {}): {}",
        action.peer_ip,
        interface_name,
        action.duration_secs,
        action.level,
        action.reason
    );
    control.with_client(|client| {
        client.blacklist_backbone_peer(interface_name, &action.peer_ip.to_string(), action.duration_secs)
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
    write_stall_events: Vec<Instant>,
    idle_timeout_events: Vec<Instant>,
    disconnect_events: Vec<Instant>,
    connect_events: Vec<Instant>,
    blacklist_level: u8,
    last_blacklist_at: Option<Instant>,
    interface_name: String,
}

impl PeerRecord {
    fn new(interface_name: String) -> Self {
        Self {
            write_stall_events: Vec::new(),
            idle_timeout_events: Vec::new(),
            disconnect_events: Vec::new(),
            connect_events: Vec::new(),
            blacklist_level: 0,
            last_blacklist_at: None,
            interface_name,
        }
    }

    fn prune(&mut self, now: Instant, window: Duration) {
        self.write_stall_events.retain(|t| now.duration_since(*t) <= window);
        self.idle_timeout_events.retain(|t| now.duration_since(*t) <= window);
        self.disconnect_events.retain(|t| now.duration_since(*t) <= window);
        self.connect_events.retain(|t| now.duration_since(*t) <= window);
    }
}

struct BlacklistAction {
    peer_ip: IpAddr,
    interface_name: String,
    duration_secs: u64,
    level: u8,
    reason: String,
}

struct PeerTracker {
    peers: HashMap<IpAddr, PeerRecord>,
}

impl PeerTracker {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    fn ingest(&mut self, event: &HookProviderEventEnvelope) -> Option<BlacklistAction> {
        if event.payload_type != BACKBONE_PEER_PAYLOAD_TYPE {
            return None;
        }

        let payload = BackbonePeerPayload::decode(&event.payload)?;
        let peer_ip = decode_ip(&payload)?;
        let now = Instant::now();

        let record = self
            .peers
            .entry(peer_ip)
            .or_insert_with(|| PeerRecord::new(event.attach_point.clone()));
        record.prune(now, DEFAULT_EVENT_WINDOW);

        match event.attach_point.as_str() {
            "BackbonePeerConnected" => {
                record.connect_events.push(now);
                log::debug!("peer connected: {}", peer_ip);
                None
            }
            "BackbonePeerDisconnected" => {
                record.disconnect_events.push(now);
                log::debug!(
                    "peer disconnected: {} (connected {}s, data={})",
                    peer_ip,
                    payload.connected_for_secs,
                    payload.had_received_data
                );
                None
            }
            "BackbonePeerIdleTimeout" => {
                record.idle_timeout_events.push(now);
                log::debug!(
                    "peer idle timeout: {} ({}s)",
                    peer_ip,
                    payload.connected_for_secs
                );
                if record.idle_timeout_events.len() as u32 >= DEFAULT_IDLE_TIMEOUT_THRESHOLD {
                    Some(self.apply_blacklist(peer_ip, "repeated idle timeouts"))
                } else {
                    None
                }
            }
            "BackbonePeerWriteStall" => {
                record.write_stall_events.push(now);
                log::debug!(
                    "peer write stall: {} ({}s)",
                    peer_ip,
                    payload.connected_for_secs
                );
                if record.write_stall_events.len() as u32 >= DEFAULT_WRITE_STALL_THRESHOLD {
                    Some(self.apply_blacklist(peer_ip, "repeated write stalls"))
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

    fn apply_blacklist(&mut self, peer_ip: IpAddr, reason: &str) -> BlacklistAction {
        let record = self.peers.get_mut(&peer_ip).unwrap();
        record.blacklist_level = record.blacklist_level.saturating_add(1);
        let multiplier = 1u64 << (record.blacklist_level - 1).min(20);
        let duration_secs = DEFAULT_BASE_BLACKLIST_SECS.saturating_mul(multiplier);
        record.last_blacklist_at = Some(Instant::now());
        // Clear event windows after applying penalty
        record.write_stall_events.clear();
        record.idle_timeout_events.clear();
        record.disconnect_events.clear();

        BlacklistAction {
            peer_ip,
            interface_name: record.interface_name.clone(),
            duration_secs,
            level: record.blacklist_level,
            reason: reason.to_string(),
        }
    }
}

fn decode_ip(payload: &BackbonePeerPayload) -> Option<IpAddr> {
    if payload.peer_ip_family == 4 {
        let octets = payload.ipv4_octets()?;
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
    println!("  --version                    Print version");
    println!("  --help, -h                   Print this help");
    println!("  -v                           Increase verbosity");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(attach_point: &str, ip_octets: [u8; 4], connected_for: u64) -> HookProviderEventEnvelope {
        let payload = BackbonePeerPayload {
            peer_ip_family: 4,
            peer_ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]],
            peer_port: 4242,
            server_interface_id: 1,
            peer_interface_id: 100,
            connected_for_secs: connected_for,
            had_received_data: true,
            penalty_level: 0,
            blacklist_for_secs: 0,
            event_kind: 0,
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
        let mut tracker = PeerTracker::new();
        let event = make_event("BackbonePeerWriteStall", [192, 168, 1, 1], 30);
        // First stall — below threshold of 2
        assert!(tracker.ingest(&event).is_none());
    }

    #[test]
    fn write_stall_at_threshold_triggers_blacklist() {
        let mut tracker = PeerTracker::new();
        let event = make_event("BackbonePeerWriteStall", [192, 168, 1, 2], 30);
        assert!(tracker.ingest(&event).is_none());
        let action = tracker.ingest(&event).expect("expected blacklist on 2nd stall");
        assert_eq!(action.peer_ip, "192.168.1.2".parse::<IpAddr>().unwrap());
        assert_eq!(action.level, 1);
        assert_eq!(action.duration_secs, DEFAULT_BASE_BLACKLIST_SECS);
        assert_eq!(action.reason, "repeated write stalls");
    }

    #[test]
    fn idle_timeout_below_threshold_does_not_trigger() {
        let mut tracker = PeerTracker::new();
        let event = make_event("BackbonePeerIdleTimeout", [10, 0, 0, 1], 5);
        for _ in 0..3 {
            assert!(tracker.ingest(&event).is_none());
        }
    }

    #[test]
    fn idle_timeout_at_threshold_triggers_blacklist() {
        let mut tracker = PeerTracker::new();
        let event = make_event("BackbonePeerIdleTimeout", [10, 0, 0, 2], 5);
        for _ in 0..3 {
            assert!(tracker.ingest(&event).is_none());
        }
        let action = tracker.ingest(&event).expect("expected blacklist on 4th idle timeout");
        assert_eq!(action.peer_ip, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(action.level, 1);
        assert_eq!(action.reason, "repeated idle timeouts");
    }

    #[test]
    fn exponential_escalation() {
        let mut tracker = PeerTracker::new();
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
        let mut tracker = PeerTracker::new();
        for _ in 0..20 {
            assert!(tracker.ingest(&make_event("BackbonePeerConnected", [1, 2, 3, 4], 0)).is_none());
            assert!(tracker.ingest(&make_event("BackbonePeerDisconnected", [1, 2, 3, 4], 60)).is_none());
        }
    }

    #[test]
    fn penalty_event_does_not_trigger() {
        let mut tracker = PeerTracker::new();
        for _ in 0..20 {
            assert!(tracker.ingest(&make_event("BackbonePeerPenalty", [5, 6, 7, 8], 0)).is_none());
        }
    }

    #[test]
    fn different_ips_tracked_independently() {
        let mut tracker = PeerTracker::new();
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
        let mut tracker = PeerTracker::new();
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
        let mut tracker = PeerTracker::new();
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
