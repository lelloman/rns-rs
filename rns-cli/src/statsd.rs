use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rns_hooks_abi::stats::{
    AnnounceStatsPayload, PacketStatsPayload, ANNOUNCE_STATS_PAYLOAD_TYPE,
    PACKET_STATS_PAYLOAD_TYPE,
};
use rns_net::config;
use rns_net::provider_bridge::{ProviderEnvelope, ProviderMessage};
use rns_net::rpc::derive_auth_key;
use rns_net::storage;
use rns_net::{HookInfo, RpcAddr, RpcClient};
use rusqlite::{params, Connection};

use crate::args::Args;

const VERSION: &str = env!("FULL_VERSION");
const EMBEDDED_HOOK_WASM: &[u8] = include_bytes!(env!("RNS_STATSD_HOOK_WASM"));
const HOOK_SPECS: [(&str, &str); 3] = [
    ("rns_statsd_pre_ingress", "PreIngress"),
    ("rns_statsd_send_on_interface", "SendOnInterface"),
    ("rns_statsd_broadcast_all", "BroadcastOnAllInterfaces"),
];

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
            eprintln!("rns-statsd: {}", err);
            1
        }
        Err(_) => 101,
    };

    process::exit(exit_code);
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    if args.has("version") {
        println!("rns-statsd {}", VERSION);
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

    let db_path = args
        .get("db")
        .map(PathBuf::from)
        .ok_or_else(|| "--db PATH is required".to_string())?;
    let flush_interval = Duration::from_secs(
        args.get("flush-interval")
            .or_else(|| args.get("f"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(5),
    );
    let priority = args
        .get("priority")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let runtime = RuntimeConfig::load(args.config_path().map(Path::new), args.get("socket"))?;

    let mut db = StatsDb::open(&db_path).map_err(|e| format!("sqlite open failed: {}", e))?;
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

    let mut aggregator = StatsAggregator::default();
    let mut next_flush = Instant::now() + flush_interval;
    let mut proc_monitor = ProcessMonitor::new();

    while !SHOULD_STOP.load(Ordering::Relaxed) {
        match read_provider_envelope(&mut stream) {
            Ok(Some(envelope)) => aggregator.ingest(envelope),
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

        if Instant::now() >= next_flush {
            db.flush(&mut aggregator)
                .map_err(|e| format!("sqlite flush failed: {}", e))?;
            if let Some(sample) = proc_monitor.sample() {
                db.insert_process_sample(&sample)
                    .map_err(|e| format!("sqlite process sample failed: {}", e))?;
            }
            next_flush = Instant::now() + flush_interval;
        }
    }

    db.flush(&mut aggregator)
        .map_err(|e| format!("sqlite shutdown flush failed: {}", e))?;
    drop(hook_guard);
    Ok(())
}

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CounterKey {
    interface_key: String,
    interface_id: Option<u64>,
    direction: &'static str,
    packet_type: &'static str,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct CounterValue {
    packets: u64,
    bytes: u64,
}

struct AnnounceRecord {
    identity_hash: [u8; 16],
    destination_hash: [u8; 16],
    name_hash: [u8; 10],
    random_hash: [u8; 10],
    hops: u8,
    interface_id: u64,
}

#[derive(Default)]
struct StatsAggregator {
    counters: HashMap<CounterKey, CounterValue>,
    announce_records: Vec<AnnounceRecord>,
}

impl StatsAggregator {
    fn ingest(&mut self, envelope: ProviderEnvelope) {
        match envelope.message {
            ProviderMessage::DroppedEvents { count } => {
                log::warn!("provider bridge dropped {} event(s)", count);
            }
            ProviderMessage::Event(event) => {
                if event.payload_type == ANNOUNCE_STATS_PAYLOAD_TYPE {
                    // Only record announces from RX (PreIngress) to avoid
                    // counting the same announce multiple times on TX fan-out.
                    if event.attach_point != "PreIngress" {
                        return;
                    }
                    match AnnounceStatsPayload::decode(&event.payload) {
                        Some(p) => self.announce_records.push(AnnounceRecord {
                            identity_hash: p.identity_hash,
                            destination_hash: p.destination_hash,
                            name_hash: p.name_hash,
                            random_hash: p.random_hash,
                            hops: p.hops,
                            interface_id: p.interface_id,
                        }),
                        None => {
                            log::warn!("invalid announce payload length: {}", event.payload.len());
                        }
                    }
                    return;
                }
                if event.payload_type != PACKET_STATS_PAYLOAD_TYPE {
                    return;
                }
                let payload = match PacketStatsPayload::decode(&event.payload) {
                    Some(payload) => payload,
                    None => {
                        log::warn!("invalid stats payload length: {}", event.payload.len());
                        return;
                    }
                };
                let direction = match direction_for_attach_point(&event.attach_point) {
                    Some(direction) => direction,
                    None => return,
                };
                let packet_type = packet_type_name(payload.flags);
                let (interface_key, interface_id) =
                    if event.attach_point == "BroadcastOnAllInterfaces" {
                        ("broadcast_all".to_string(), None)
                    } else {
                        (
                            format!("iface:{}", payload.interface_id),
                            Some(payload.interface_id),
                        )
                    };
                let key = CounterKey {
                    interface_key,
                    interface_id,
                    direction,
                    packet_type,
                };
                let counter = self.counters.entry(key).or_default();
                counter.packets += 1;
                counter.bytes += payload.packet_len as u64;
            }
        }
    }
}

struct StatsDb {
    conn: Connection,
}

impl StatsDb {
    fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS packet_counters (
                interface_key TEXT NOT NULL,
                interface_id INTEGER NULL,
                direction TEXT NOT NULL,
                packet_type TEXT NOT NULL,
                packets INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (interface_key, direction, packet_type)
            );
            CREATE TABLE IF NOT EXISTS seen_identities (
                identity_hash BLOB NOT NULL PRIMARY KEY,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                announce_count INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS seen_destinations (
                destination_hash BLOB NOT NULL PRIMARY KEY,
                identity_hash BLOB NOT NULL,
                name_hash BLOB NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                announce_count INTEGER NOT NULL DEFAULT 1,
                last_hops INTEGER NOT NULL,
                last_interface_id INTEGER NULL
            );
            CREATE TABLE IF NOT EXISTS seen_names (
                name_hash BLOB NOT NULL PRIMARY KEY,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                announce_count INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS process_samples (
                ts_ms INTEGER NOT NULL PRIMARY KEY,
                pid INTEGER NOT NULL,
                rss_bytes INTEGER NOT NULL,
                cpu_user_ms INTEGER NOT NULL,
                cpu_system_ms INTEGER NOT NULL,
                threads INTEGER NOT NULL,
                fds INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seen_announces (
                destination_hash BLOB NOT NULL,
                random_hash BLOB NOT NULL,
                identity_hash BLOB NOT NULL,
                name_hash BLOB NOT NULL,
                hops INTEGER NOT NULL,
                interface_id INTEGER NULL,
                seen_at_ms INTEGER NOT NULL,
                PRIMARY KEY (destination_hash, random_hash)
            );",
        )?;
        Ok(Self { conn })
    }

    fn flush(&mut self, aggregator: &mut StatsAggregator) -> rusqlite::Result<()> {
        if aggregator.counters.is_empty() && aggregator.announce_records.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        let now = now_unix_ms() as i64;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO packet_counters (
                    interface_key, interface_id, direction, packet_type, packets, bytes, updated_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(interface_key, direction, packet_type) DO UPDATE SET
                    interface_id = excluded.interface_id,
                    packets = packet_counters.packets + excluded.packets,
                    bytes = packet_counters.bytes + excluded.bytes,
                    updated_at_ms = excluded.updated_at_ms",
            )?;
            for (key, value) in aggregator.counters.drain() {
                stmt.execute(params![
                    key.interface_key,
                    key.interface_id.map(|v| v as i64),
                    key.direction,
                    key.packet_type,
                    value.packets as i64,
                    value.bytes as i64,
                    now,
                ])?;
            }
        }
        if !aggregator.announce_records.is_empty() {
            let mut ann_stmt = tx.prepare(
                "INSERT INTO seen_announces (
                    destination_hash, random_hash, identity_hash, name_hash,
                    hops, interface_id, seen_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(destination_hash, random_hash) DO NOTHING",
            )?;
            let mut id_stmt = tx.prepare(
                "INSERT INTO seen_identities (identity_hash, first_seen_ms, last_seen_ms, announce_count)
                 VALUES (?1, ?2, ?2, 1)
                 ON CONFLICT(identity_hash) DO UPDATE SET
                    last_seen_ms = excluded.last_seen_ms,
                    announce_count = seen_identities.announce_count + 1",
            )?;
            let mut dest_stmt = tx.prepare(
                "INSERT INTO seen_destinations (
                    destination_hash, identity_hash, name_hash,
                    first_seen_ms, last_seen_ms, announce_count,
                    last_hops, last_interface_id
                ) VALUES (?1, ?2, ?3, ?4, ?4, 1, ?5, ?6)
                ON CONFLICT(destination_hash) DO UPDATE SET
                    last_seen_ms = excluded.last_seen_ms,
                    announce_count = seen_destinations.announce_count + 1,
                    last_hops = excluded.last_hops,
                    last_interface_id = excluded.last_interface_id",
            )?;
            let mut name_stmt = tx.prepare(
                "INSERT INTO seen_names (name_hash, first_seen_ms, last_seen_ms, announce_count)
                 VALUES (?1, ?2, ?2, 1)
                 ON CONFLICT(name_hash) DO UPDATE SET
                    last_seen_ms = excluded.last_seen_ms,
                    announce_count = seen_names.announce_count + 1",
            )?;
            for rec in aggregator.announce_records.drain(..) {
                let inserted = ann_stmt.execute(params![
                    rec.destination_hash.as_slice(),
                    rec.random_hash.as_slice(),
                    rec.identity_hash.as_slice(),
                    rec.name_hash.as_slice(),
                    rec.hops as i64,
                    rec.interface_id as i64,
                    now,
                ])?;
                // Only update rollup tables for genuinely new announces
                if inserted == 0 {
                    continue;
                }
                id_stmt.execute(params![rec.identity_hash.as_slice(), now,])?;
                dest_stmt.execute(params![
                    rec.destination_hash.as_slice(),
                    rec.identity_hash.as_slice(),
                    rec.name_hash.as_slice(),
                    now,
                    rec.hops as i64,
                    rec.interface_id as i64,
                ])?;
                name_stmt.execute(params![rec.name_hash.as_slice(), now,])?;
            }
        }
        tx.commit()
    }
}

struct ProcessSample {
    pid: u32,
    rss_bytes: u64,
    cpu_user_ms: u64,
    cpu_system_ms: u64,
    threads: u32,
    fds: u32,
}

struct ProcessMonitor {
    pid: Option<u32>,
}

impl ProcessMonitor {
    fn new() -> Self {
        let pid = find_pid_by_comm("rnsd");
        if let Some(pid) = pid {
            log::info!("monitoring rnsd process pid={}", pid);
        } else {
            log::warn!("could not find rnsd process to monitor");
        }
        Self { pid }
    }

    fn sample(&mut self) -> Option<ProcessSample> {
        let pid = match self.pid {
            Some(p) => p,
            None => {
                self.pid = find_pid_by_comm("rnsd");
                self.pid?
            }
        };
        match read_proc_sample(pid) {
            Some(s) => Some(s),
            None => {
                log::warn!("rnsd pid={} disappeared, will re-scan", pid);
                self.pid = None;
                None
            }
        }
    }
}

fn find_pid_by_comm(name: &str) -> Option<u32> {
    let proc_dir = fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let pid_str = fname.to_str()?;
        if !pid_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = fs::read_to_string(&comm_path) {
            if comm.trim() == name {
                return pid_str.parse().ok();
            }
        }
    }
    None
}

fn read_proc_sample(pid: u32) -> Option<ProcessSample> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Fields after (comm): find closing paren to handle spaces in comm
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // fields[0] = state, [1] = ppid, ... [11] = utime, [12] = stime, ... [17] = num_threads, ... [21] = rss
    if fields.len() < 22 {
        return None;
    }
    let utime_ticks: u64 = fields[11].parse().ok()?;
    let stime_ticks: u64 = fields[12].parse().ok()?;
    let num_threads: u32 = fields[17].parse().ok()?;
    let rss_pages: u64 = fields[21].parse().ok()?;

    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;

    let fds = fs::read_dir(format!("/proc/{}/fd", pid))
        .map(|d| d.count() as u32)
        .unwrap_or(0);

    Some(ProcessSample {
        pid,
        rss_bytes: rss_pages * page_size,
        cpu_user_ms: utime_ticks * 1000 / clk_tck,
        cpu_system_ms: stime_ticks * 1000 / clk_tck,
        threads: num_threads,
        fds,
    })
}

impl StatsDb {
    fn insert_process_sample(&mut self, sample: &ProcessSample) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO process_samples (ts_ms, pid, rss_bytes, cpu_user_ms, cpu_system_ms, threads, fds)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                now_unix_ms() as i64,
                sample.pid as i64,
                sample.rss_bytes as i64,
                sample.cpu_user_ms as i64,
                sample.cpu_system_ms as i64,
                sample.threads as i64,
                sample.fds as i64,
            ],
        )?;
        Ok(())
    }
}

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

fn direction_for_attach_point(attach_point: &str) -> Option<&'static str> {
    match attach_point {
        "PreIngress" => Some("rx"),
        "SendOnInterface" | "BroadcastOnAllInterfaces" => Some("tx"),
        _ => None,
    }
}

fn packet_type_name(flags: u8) -> &'static str {
    match flags & 0x03 {
        rns_core::constants::PACKET_TYPE_ANNOUNCE => "announce",
        rns_core::constants::PACKET_TYPE_LINKREQUEST => "linkrequest",
        rns_core::constants::PACKET_TYPE_PROOF => "proof",
        _ => "data",
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
    println!("Usage: rns-statsd --db PATH [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config PATH, -c PATH      Path to config directory");
    println!("  --db PATH                   SQLite database path");
    println!("  --flush-interval SECONDS    Flush interval (default: 5)");
    println!("  --socket PATH               Override provider bridge socket path");
    println!("  --priority N                Hook priority (default: 0)");
    println!("  --version                   Show version");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_event_updates_interface_counter() {
        let payload = PacketStatsPayload {
            flags: 0x01,
            packet_len: 128,
            interface_id: 42,
        }
        .encode()
        .to_vec();
        let envelope = ProviderEnvelope {
            version: 1,
            seq: 1,
            message: ProviderMessage::Event(rns_net::HookProviderEventEnvelope {
                ts_unix_ms: 1,
                node_instance: "node".into(),
                hook_name: "stats".into(),
                attach_point: "PreIngress".into(),
                payload_type: PACKET_STATS_PAYLOAD_TYPE.into(),
                payload,
            }),
        };
        let mut agg = StatsAggregator::default();
        agg.ingest(envelope);
        assert_eq!(agg.counters.len(), 1);
        let (key, value) = agg.counters.iter().next().unwrap();
        assert_eq!(key.interface_key, "iface:42");
        assert_eq!(key.direction, "rx");
        assert_eq!(key.packet_type, "announce");
        assert_eq!(
            *value,
            CounterValue {
                packets: 1,
                bytes: 128
            }
        );
    }

    #[test]
    fn broadcast_uses_synthetic_interface_key() {
        let payload = PacketStatsPayload {
            flags: 0x03,
            packet_len: 64,
            interface_id: 99,
        }
        .encode()
        .to_vec();
        let envelope = ProviderEnvelope {
            version: 1,
            seq: 2,
            message: ProviderMessage::Event(rns_net::HookProviderEventEnvelope {
                ts_unix_ms: 1,
                node_instance: "node".into(),
                hook_name: "stats".into(),
                attach_point: "BroadcastOnAllInterfaces".into(),
                payload_type: PACKET_STATS_PAYLOAD_TYPE.into(),
                payload,
            }),
        };
        let mut agg = StatsAggregator::default();
        agg.ingest(envelope);
        let (key, _) = agg.counters.iter().next().unwrap();
        assert_eq!(key.interface_key, "broadcast_all");
        assert_eq!(key.interface_id, None);
        assert_eq!(key.direction, "tx");
        assert_eq!(key.packet_type, "proof");
    }

    #[test]
    fn sqlite_flush_accumulates_counts() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("stats.db");
        let mut db = StatsDb::open(&db_path).unwrap();
        let mut agg = StatsAggregator::default();
        let key = CounterKey {
            interface_key: "iface:7".into(),
            interface_id: Some(7),
            direction: "tx",
            packet_type: "data",
        };
        agg.counters.insert(
            key.clone(),
            CounterValue {
                packets: 2,
                bytes: 50,
            },
        );
        db.flush(&mut agg).unwrap();

        let mut agg2 = StatsAggregator::default();
        agg2.counters.insert(
            key,
            CounterValue {
                packets: 3,
                bytes: 25,
            },
        );
        db.flush(&mut agg2).unwrap();

        let row: (i64, i64) = db
            .conn
            .query_row(
                "SELECT packets, bytes FROM packet_counters WHERE interface_key = 'iface:7'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, (5, 75));
    }

    #[test]
    fn announce_event_populates_tables() {
        let announce_payload = AnnounceStatsPayload {
            identity_hash: [0xAA; 16],
            destination_hash: [0xBB; 16],
            name_hash: [0xCC; 10],
            random_hash: [0xDD; 10],
            hops: 2,
            interface_id: 5,
        }
        .encode()
        .to_vec();
        let envelope = ProviderEnvelope {
            version: 1,
            seq: 10,
            message: ProviderMessage::Event(rns_net::HookProviderEventEnvelope {
                ts_unix_ms: 1,
                node_instance: "node".into(),
                hook_name: "stats".into(),
                attach_point: "PreIngress".into(),
                payload_type: ANNOUNCE_STATS_PAYLOAD_TYPE.into(),
                payload: announce_payload,
            }),
        };
        let mut agg = StatsAggregator::default();
        agg.ingest(envelope);
        assert_eq!(agg.announce_records.len(), 1);
        assert_eq!(agg.announce_records[0].hops, 2);

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("stats.db");
        let mut db = StatsDb::open(&db_path).unwrap();
        db.flush(&mut agg).unwrap();

        let id_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM seen_identities", [], |row| row.get(0))
            .unwrap();
        assert_eq!(id_count, 1);

        let dest_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM seen_destinations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(dest_count, 1);

        let name_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM seen_names", [], |row| row.get(0))
            .unwrap();
        assert_eq!(name_count, 1);

        let (hops, iface): (i64, i64) = db
            .conn
            .query_row(
                "SELECT last_hops, last_interface_id FROM seen_destinations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(hops, 2);
        assert_eq!(iface, 5);
    }

    #[test]
    fn announce_flush_deduplicates_by_random_hash() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("stats.db");
        let mut db = StatsDb::open(&db_path).unwrap();

        // Same announce (same destination + random_hash) seen 3 times (e.g. on 3 interfaces)
        for _ in 0..3 {
            let mut agg = StatsAggregator::default();
            agg.announce_records.push(AnnounceRecord {
                identity_hash: [0x11; 16],
                destination_hash: [0x22; 16],
                name_hash: [0x33; 10],
                random_hash: [0x44; 10],
                hops: 1,
                interface_id: 9,
            });
            db.flush(&mut agg).unwrap();
        }

        // Should only count as 1 unique announce
        let count: i64 = db
            .conn
            .query_row("SELECT announce_count FROM seen_identities", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        let count: i64 = db
            .conn
            .query_row("SELECT announce_count FROM seen_destinations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        let ann_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM seen_announces", [], |row| row.get(0))
            .unwrap();
        assert_eq!(ann_count, 1);
    }

    #[test]
    fn different_announces_from_same_destination_count_separately() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("stats.db");
        let mut db = StatsDb::open(&db_path).unwrap();

        // Two different announces (different random_hash) from same destination
        for i in 0..2u8 {
            let mut agg = StatsAggregator::default();
            agg.announce_records.push(AnnounceRecord {
                identity_hash: [0x11; 16],
                destination_hash: [0x22; 16],
                name_hash: [0x33; 10],
                random_hash: [i; 10],
                hops: 1,
                interface_id: 9,
            });
            db.flush(&mut agg).unwrap();
        }

        let count: i64 = db
            .conn
            .query_row("SELECT announce_count FROM seen_destinations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);

        let ann_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM seen_announces", [], |row| row.get(0))
            .unwrap();
        assert_eq!(ann_count, 2);
    }
}
