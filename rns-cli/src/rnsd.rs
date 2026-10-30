use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};

use crate::args::Args;
use rns_net::storage;
use rns_net::{Callbacks, InterfaceId, RnsNode};

const VERSION: &str = env!("FULL_VERSION");
const LOG_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

struct RotatingLogWriter {
    path: PathBuf,
    max_file_bytes: u64,
}

impl RotatingLogWriter {
    fn new(path: PathBuf, max_file_bytes: u64) -> io::Result<Self> {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            max_file_bytes,
        })
    }

    fn rotate(&self) -> io::Result<()> {
        let previous = archive_path(&self.path);
        remove_log_if_present(&previous)?;
        fs::rename(&self.path, previous)
    }
}

impl Write for RotatingLogWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(buffer)?;
        file.flush()?;
        drop(file);

        if self.path.metadata()?.len() > self.max_file_bytes {
            self.rotate()?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn archive_path(path: &Path) -> PathBuf {
    let mut archive = path.as_os_str().to_os_string();
    archive.push(".1");
    PathBuf::from(archive)
}

fn remove_log_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

struct DaemonCallbacks {
    announce_level: log::Level,
}

impl Callbacks for DaemonCallbacks {
    fn on_announce(&mut self, announced: rns_net::AnnouncedIdentity) {
        let rssi = match announced.rssi {
            Some(x) => format!(", rssi:{}", x),
            None => "".to_string(),
        };
        let snr = match announced.snr {
            Some(x) => format!(", snr:{}", x),
            None => "".to_string(),
        };
        log::log!(
            self.announce_level,
            "Announce received for {} (hops: {}{}{})",
            hex(&announced.dest_hash.0),
            announced.hops,
            rssi,
            snr,
        );
    }

    fn on_path_updated(&mut self, dest_hash: rns_net::DestHash, hops: u8) {
        log::trace!(target: rns_net::logging::PATHING_LOG_TARGET,
            "Path updated for {} (hops: {})",
            hex(&dest_hash.0),
            hops,
        );
    }

    fn on_local_delivery(
        &mut self,
        dest_hash: rns_net::DestHash,
        _raw: Vec<u8>,
        _hash: rns_net::PacketHash,
    ) {
        log::debug!("Local delivery for {}", hex(&dest_hash.0));
    }

    fn on_interface_up(&mut self, id: InterfaceId) {
        log::info!("Interface {} up", id.0);
    }

    fn on_interface_down(&mut self, id: InterfaceId) {
        log::info!("Interface {} down", id.0);
    }
}

pub fn main_entry() {
    main_entry_from(Args::parse());
}

pub fn main_entry_from(args: Args) {
    main_entry_impl(args, "rnsd", "rnsd", log::Level::Debug);
}

pub fn main_entry_from_named(args: Args, usage_name: &str, version_name: &str) {
    // `rns-ctl daemon` historically reported received announces at INFO,
    // while the standalone `rnsd` binary keeps them at DEBUG.
    main_entry_impl(args, usage_name, version_name, log::Level::Info);
}

fn main_entry_impl(args: Args, usage_name: &str, version_name: &str, announce_level: log::Level) {
    if args.has("version") {
        println!("{} {}", version_name, VERSION);
        return;
    }

    if args.has("help") || args.has("h") {
        print_usage(usage_name);
        return;
    }

    if args.has("exampleconfig") {
        print!("{}", EXAMPLE_CONFIG);
        return;
    }

    let service_mode = args.has("s");
    let config_path = args.config_path().map(|s| s.to_string());
    let logging = configured_logging(config_path.as_deref());
    let log_level = effective_log_level(logging.loglevel, args.verbosity, args.quiet, service_mode);
    let log_filter = rns_net::logging::numeric_log_filter(log_level);

    if service_mode {
        let config_dir =
            storage::resolve_config_dir(config_path.as_ref().map(|s| Path::new(s.as_str())));
        let logfile_path = config_dir.join("logfile");
        let writer = RotatingLogWriter::new(logfile_path.clone(), LOG_MAX_FILE_BYTES);
        match writer {
            Ok(writer) => {
                let mut builder = env_logger::Builder::new();
                builder
                    .filter_level(log_filter.default)
                    .filter_module(rns_net::logging::PATHING_LOG_TARGET, log_filter.pathing)
                    .target(env_logger::Target::Pipe(Box::new(writer)));
                apply_log_timestamp_format(&mut builder, logging.logtimestamps);
                builder.init();
            }
            Err(e) => {
                eprintln!("Could not open logfile {}: {}", logfile_path.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        let mut builder = env_logger::Builder::new();
        builder
            .filter_level(log_filter.default)
            .filter_module(rns_net::logging::PATHING_LOG_TARGET, log_filter.pathing);
        apply_log_timestamp_format(&mut builder, logging.logtimestamps);
        builder.init();
    }

    log::info!("Starting rnsd {}", VERSION);
    if let Err(err) = register_native_sidecar_hooks() {
        log::error!("Failed to register built-in sidecar hooks: {}", err);
        std::process::exit(1);
    }

    let node = RnsNode::from_config(
        config_path.as_ref().map(|s| Path::new(s.as_str())),
        Box::new(DaemonCallbacks { announce_level }),
    );

    let node = match node {
        Ok(n) => n,
        Err(e) => {
            log::error!("Failed to start: {}", e);
            std::process::exit(1);
        }
    };

    let (stop_tx, stop_rx) = channel::<()>();

    unsafe {
        libc::signal(
            libc::SIGINT,
            signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            signal_handler as *const () as libc::sighandler_t,
        );
    }
    lock_stop_tx().replace(stop_tx);

    log::info!("rnsd started");

    loop {
        match stop_rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(()) => break,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }

    log::info!("Shutting down...");
    node.shutdown();
    log::info!("rnsd stopped");
}

fn configured_logging(config_path: Option<&str>) -> rns_net::config::LoggingSection {
    let config_dir = storage::resolve_config_dir(config_path.map(Path::new));
    let config_file = config_dir.join("config");
    if !config_file.exists() {
        return rns_net::config::LoggingSection::default();
    }

    match rns_net::config::parse_file(&config_file) {
        Ok(config) => config.logging,
        Err(err) => {
            eprintln!(
                "Could not parse logging config {}: {}",
                config_file.display(),
                err
            );
            rns_net::config::LoggingSection::default()
        }
    }
}

fn effective_log_level(configured: u8, verbosity: u8, quietness: u8, service_mode: bool) -> u8 {
    if service_mode {
        configured.min(rns_net::logging::LOG_EXTREME)
    } else {
        rns_net::logging::adjust_log_level(configured, verbosity, quietness)
    }
}

fn apply_log_timestamp_format(builder: &mut env_logger::Builder, include_timestamps: bool) {
    if include_timestamps {
        builder.format_timestamp_secs();
    } else {
        builder.format_timestamp(None);
    }
}

#[cfg(any(feature = "rns-hooks-native", feature = "rns-hooks-builtin"))]
fn register_native_sidecar_hooks() -> Result<(), String> {
    rns_stats_hook::register_builtin_hooks()
        .map_err(|err| format!("stats hook registration failed: {}", err))?;
    rns_sentinel_hook::register_builtin_hooks()
        .map_err(|err| format!("sentinel hook registration failed: {}", err))?;
    Ok(())
}

#[cfg(not(any(feature = "rns-hooks-native", feature = "rns-hooks-builtin")))]
fn register_native_sidecar_hooks() -> Result<(), String> {
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

static STOP_TX: std::sync::Mutex<Option<Sender<()>>> = std::sync::Mutex::new(None);

fn lock_stop_tx() -> std::sync::MutexGuard<'static, Option<Sender<()>>> {
    match STOP_TX.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::warn!("recovering poisoned rnsd stop channel mutex");
            poisoned.into_inner()
        }
    }
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    let guard = lock_stop_tx();
    if let Some(ref tx) = *guard {
        let _ = tx.send(());
    }
}

fn print_usage(usage_name: &str) {
    println!("Usage: {usage_name} [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config PATH, -c PATH  Path to config directory");
    println!("  -s                      Service mode (log to file)");
    println!("  --exampleconfig         Print example config and exit");
    println!("  -v                      Increase verbosity (can repeat)");
    println!("  -q                      Decrease verbosity (can repeat)");
    println!("  --version               Print version and exit");
    println!("  --help, -h              Print this help");
}

const EXAMPLE_CONFIG: &str = r#"# This is an example Reticulum config file.
# It can be used as a starting point for your own configuration.

[reticulum]
  enable_transport = false
  # When transport is disabled, the transport-facing identity is ephemeral by
  # default. Set this to true to reuse the stored identity across restarts.
  static_transport_identity = false
  # Mask local zero-hop SINGLE/LINK traffic on external interfaces.
  local_hops_delta = false
  share_instance = true
  shared_instance_port = 37428
  instance_control_port = 37429
  # Set to false to block rnstatus --attach/--detach/--reload.
  # enable_interface_management = false
  panic_on_interface_error = false

  # Packet deduplication uses a bounded table. "eager" prefaults its
  # payload pages at startup; "lazy" grows storage as packets arrive.
  packet_hashlist_max_entries = 250000
  packet_hashlist_allocation = eager

  # Global gravity for interfaces without a specific gravity option.
  # default_gravity = 0

  # Optional mode for interfaces created from discovery announces.
  # autoconnect_interface_mode = gateway

  # Gravity assigned to interfaces created from discovery announces.
  # autoconnect_interface_gravity = 0

  # Allow auto-connected interfaces to propagate announces to internal mode.
  # autoconnect_announces_to_internal = yes

  # Allow auto-connecting discovered interfaces from unverified or experimental
  # implementations. Dangerous; leave disabled unless you understand the risk.
  # autoconnect_unverified_implementations = no

  # You can enable a hop limiter, that will drop all packets
  # exceeding the specified maximum hop count (1 to 128).
  # hop_limiter = 16

[stamps]
  # This section configures stamping behaviour and defaults.
  # In most cases, you do not need to change this, but on
  # constrained systems especially, tuning these parameters
  # can be very beneficial.

  # During the 1.6.x phased transition to network stamp usage,
  # it is possible to enable early opt-in on stamp generation
  # and enforcement. Stamps are validated, while generation,
  # emission and enforcement are disabled by default for
  # destinations and path requests. Link requests are already
  # stamped if the destination announced a cost. Upstream 1.6.1
  # will enable generation and emission by default, and 1.6.2
  # will activate enforcement. Any option can be enabled early
  # by configuration; setting one to "no" keeps the default
  # rather than forcing it off.
  # stamp_destinations = yes
  # stamp_prs = yes
  # enforce_stamps = yes

  # Also stamp link requests to destinations that announced no
  # link request cost, at the default link request cost below.
  # always_stamp_lrs = yes

  # The built-in costs below are fractional (23.5, 19.8 and
  # 19.2); configured costs and values are whole numbers.

  # The default required stamp cost for an announce, and its
  # destination to be considered valid. This applies both to
  # announces received directly, and transported by this node,
  # if transport is enabled. Any announced destination not
  # meeting the cost will be ignored once stamps are enforced.
  # destination_cost = 24

  # The default value this instance will target when generating
  # new destination stamps. An application may set a higher
  # target, but applications requesting a lower value than the
  # default will always generate at least the default value.
  # Destination stamps are cached and reused, so a one-time
  # high-value generation is usually a good idea.
  # destination_value = 25

  # The default required path request stamp cost. Path requests
  # that do not meet the requirement are ignored once stamps
  # are enforced.
  # pr_cost = 20

  # The default target value of path request stamps generated
  # by this instance.
  # pr_value = 20

  # The default link request stamp cost to announce for local
  # destinations that do not set their own (0 to 40), and to
  # stamp with when always_stamp_lrs is set.
  # lr_cost = 19

  # The maximum amount of time to spend attempting to generate
  # link request and path request stamps, in seconds.
  # lr_stamp_timeout = 15
  # pr_stamp_timeout = 15

[logging]
  # Valid log levels are 0 through 8:
  #   0: Critical information only
  #   1: Errors
  #   2: Warnings
  #   3: Notices
  #   4: Information (default)
  #   5: Verbose logging
  #   6: Debug logging
  #   7: Path logging
  #   8: Extreme logging
  loglevel = 4

  # Disable timestamp inclusion when an external logging tool
  # provides its own timestamps or formatting.
  # logtimestamps = no

# ─── Interface examples ──────────────────────────────────────────────

# TCP client: connect to a remote transport node
#
# [[TCP Client]]
#   type = TCPClientInterface
#   target_host = amsterdam.connect.reticulum.network
#   target_port = 4965

# TCP server: accept incoming connections
#
# [[TCP Server]]
#   type = TCPServerInterface
#   listen_ip = 0.0.0.0
#   listen_port = 4965

# UDP interface: broadcast on LAN
#
# [[UDP Interface]]
#   type = UDPInterface
#   listen_ip = 0.0.0.0
#   listen_port = 4242
#   forward_ip = 255.255.255.255
#   forward_port = 4242

# Serial interface: point-to-point serial port
#
# [[Serial Interface]]
#   type = SerialInterface
#   port = /dev/ttyUSB0
#   speed = 115200
#   databits = 8
#   parity = none
#   stopbits = 1

# KISS interface: for TNC modems
#
# [[KISS Interface]]
#   type = KISSInterface
#   port = /dev/ttyUSB1
#   speed = 115200
#   databits = 8
#   parity = none
#   stopbits = 1
#   preamble = 350
#   txtail = 20
#   persistence = 64
#   slottime = 20
#   flow_control = false

# RNode LoRa interface
#
# [[RNode LoRa Interface]]
#   type = RNodeInterface
#   port = /dev/ttyACM0
#   frequency = 867200000
#   bandwidth = 125000
#   txpower = 7
#   spreadingfactor = 8
#   codingrate = 5

# Pipe interface: stdin/stdout of a subprocess
#
# [[Pipe Interface]]
#   type = PipeInterface
#   command = cat

# Backbone interface: TCP mesh
#
# [[Backbone]]
#   type = BackboneInterface
#   listen_ip = 0.0.0.0
#   listen_port = 4243
#   peers = 10.0.0.1:4243, 10.0.0.2:4243
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_logging_defaults_to_info_with_timestamps() {
        let dir = tempfile::tempdir().unwrap();

        let logging = configured_logging(Some(dir.path().to_str().unwrap()));
        assert_eq!(logging.loglevel, 4);
        assert!(logging.logtimestamps);
    }

    #[test]
    fn configured_logging_reads_level_and_timestamps_together() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("config"),
            "[logging]\nloglevel = 7\nlogtimestamps = no\n",
        )
        .unwrap();

        let logging = configured_logging(Some(dir.path().to_str().unwrap()));
        assert_eq!(logging.loglevel, 7);
        assert!(!logging.logtimestamps);
    }

    #[test]
    fn service_mode_uses_configured_level_without_cli_adjustment() {
        assert_eq!(effective_log_level(7, 3, 0, true), 7);
        assert_eq!(effective_log_level(7, 0, 3, true), 7);
    }

    #[test]
    fn foreground_mode_adjusts_configured_level() {
        assert_eq!(effective_log_level(4, 3, 0, false), 7);
        assert_eq!(effective_log_level(4, 0, 3, false), 1);
        assert_eq!(effective_log_level(4, 2, 1, false), 5);
    }

    #[test]
    fn example_config_documents_and_parses_the_stamps_section() {
        for key in [
            "hop_limiter",
            "stamp_destinations",
            "stamp_prs",
            "always_stamp_lrs",
            "enforce_stamps",
            "destination_cost",
            "destination_value",
            "pr_cost",
            "pr_value",
            "lr_cost",
            "lr_stamp_timeout",
            "pr_stamp_timeout",
        ] {
            assert!(
                EXAMPLE_CONFIG.contains(&format!("# {key} = ")),
                "{key} is not documented"
            );
        }
        // Every option is commented out, so the example keeps the defaults.
        let config = rns_net::config::parse(EXAMPLE_CONFIG).unwrap();
        assert_eq!(config.stamps, rns_net::config::StampsSection::default());
        assert_eq!(
            config.reticulum.hop_limiter,
            rns_core::constants::HOP_LIMITER
        );
    }

    #[test]
    fn example_config_documents_all_supported_logging_levels() {
        assert!(EXAMPLE_CONFIG.contains("Valid log levels are 0 through 8"));
        assert!(EXAMPLE_CONFIG.contains("7: Path logging"));
        assert!(EXAMPLE_CONFIG.contains("8: Extreme logging"));
    }

    #[test]
    fn service_log_rotation_retains_only_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logfile");
        let mut writer = RotatingLogWriter::new(path.clone(), 12).unwrap();

        for _ in 0..5 {
            writer.write_all(b"123456\n").unwrap();
        }

        assert!(path.exists());
        assert!(archive_path(&path).exists());
        assert!(!path.with_extension("2").exists());
    }

    #[test]
    fn service_log_rotation_defaults_match_upstream() {
        assert_eq!(LOG_MAX_FILE_BYTES, 5 * 1024 * 1024);
    }

    #[test]
    fn service_log_write_is_visible_without_async_flush_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logfile");
        let mut writer = RotatingLogWriter::new(path.clone(), LOG_MAX_FILE_BYTES).unwrap();
        writer.write_all(b"synchronous log line\n").unwrap();

        assert_eq!(fs::read(path).unwrap(), b"synchronous log line\n");
    }
}
