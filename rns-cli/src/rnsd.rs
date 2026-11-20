//! `rnsd`, the Reticulum daemon: runs a node from the config directory
//! until it is signalled to stop.

use rns_core::encoding::hex;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::args::{Args, Opt, OptionSpec};
use crate::signals::{self, PipeWriter, SignalPipe};
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

/// Failures are returned, never logged: logging from inside the logger's
/// write would re-enter it. Upstream's `RNS.log` logs from its own failure
/// path and switched its lock to an `RLock` for that (rgit `9ef6c90e`).
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
        // rns-ctl's daemon reports announces at the default level (as a
        // Notice); rnsd, as upstream, only when debugging.
        let target = if self.announce_level == log::Level::Info {
            crate::pylog::NOTICE_TARGET
        } else {
            module_path!()
        };
        log::log!(
            target: target,
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
        log::debug!("Interface {} up", id.0);
    }

    fn on_interface_down(&mut self, id: InterfaceId) {
        log::info!("Interface {} down", id.0);
    }
}

/// upstream rnsd's options, and the Rust-only `-c` for `--config`.
pub const OPTIONS: OptionSpec = OptionSpec {
    options: &[
        Opt::value("", "config"),
        Opt::count("v", "verbose"),
        Opt::count("q", "quiet"),
        Opt::flag("s", "service"),
        Opt::flag("i", "interactive"),
        Opt::flag("", "exampleconfig"),
        Opt::value("c", ""),
    ],
};

/// Runs `rnsd` on the process's command line; see [`main_entry_from`].
pub fn main_entry() {
    main_entry_from(Args::parse_spec(&OPTIONS));
}

/// Runs `rnsd` on already parsed `args`: starts the node and blocks until
/// SIGINT or SIGTERM (or, with `-i`, the end of console input), then shuts
/// it down. Installs the process's logger and SIGINT/SIGTERM handlers.
/// Exits the process with status 1 when the node cannot start, and with 2
/// on an argument error.
pub fn main_entry_from(args: Args) {
    main_entry_impl(args, "rnsd", "rnsd", log::Level::Debug);
}

/// [`main_entry_from`] for `rns-ctl daemon`: `usage_name` and
/// `version_name` are the program names printed in usage and by
/// `--version`, and received announces are logged at info rather than
/// debug level.
pub fn main_entry_from_named(args: Args, usage_name: &str, version_name: &str) {
    // `rns-ctl daemon` historically reported received announces at INFO,
    // while the standalone `rnsd` binary keeps them at DEBUG.
    main_entry_impl(args, usage_name, version_name, log::Level::Info);
}

fn main_entry_impl(args: Args, usage_name: &str, version_name: &str, announce_level: log::Level) {
    crate::argparse::enforce(&args, "rnsd", usage_name);
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

    // `RNS.log` lines: on stdout, or with -s in the config directory's
    // logfile.
    let out: Box<dyn Write + Send> = if service_mode {
        let config_dir =
            storage::resolve_config_dir(config_path.as_ref().map(|s| Path::new(s.as_str())));
        let logfile_path = config_dir.join("logfile");
        match RotatingLogWriter::new(logfile_path.clone(), LOG_MAX_FILE_BYTES) {
            Ok(writer) => Box::new(writer),
            Err(e) => {
                eprintln!("Could not open logfile {}: {}", logfile_path.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        Box::new(std::io::stdout())
    };
    let _ = crate::pylog::RnsLogger::install(i32::from(log_level), logging.logtimestamps, out);

    log::debug!("Starting rnsd {}", VERSION);
    let interactive = args.has("interactive");
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
    if node.is_connected_to_shared_instance() {
        log::warn!(
            "Started rnsd version {} connected to another shared local instance, \
             this is probably NOT what you want!",
            VERSION
        );
    } else {
        log::info!(target: crate::pylog::NOTICE_TARGET, "Started rnsd version {}", VERSION);
    }

    let stop_rx = match SignalPipe::new(false) {
        Ok(pipe) => pipe,
        Err(e) => {
            log::error!("Failed to set up signal handling: {}", e);
            std::process::exit(1);
        }
    };
    stop_rx.route(&[signals::SIGINT, signals::SIGTERM], 1);

    if interactive {
        let stop = stop_rx.writer();
        std::thread::spawn(move || interactive_console(&stop));
    }

    // Until SIGINT or SIGTERM, or with -i the end of the console's input.
    // As upstream's signal handlers, SIGINT stops rnsd at the console too.
    if let Err(error) = stop_rx.wait() {
        log::warn!("signal pipe failed: {}; shutting down", error);
    }

    log::debug!("Shutting down...");
    node.shutdown();
    log::debug!("rnsd stopped");
}

fn configured_logging(config_path: Option<&str>) -> rns_net::config::LoggingSection {
    crate::pylog::configured_logging(config_path)
}

fn effective_log_level(configured: u8, verbosity: u8, quietness: u8, service_mode: bool) -> u8 {
    if service_mode {
        configured.min(rns_net::logging::LOG_EXTREME)
    } else {
        rns_net::logging::adjust_log_level(configured, verbosity, quietness)
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

fn print_usage(usage_name: &str) {
    crate::argparse::print_help("rnsd", usage_name);
}

/// The prompt of upstream's console (`code.interact`), on stdout.
const CONSOLE_PROMPT: &str = ">>> ";

/// `rnsd -i`. Upstream drops into a Python console (`code.interact`) once
/// Reticulum is up and stops when the console ends. There is no Python
/// interpreter here: the console keeps that lifecycle and its prompt,
/// banner and exit message on stderr, and says so for each statement.
fn interactive_console(stop: &PipeWriter) {
    use std::io::BufRead;
    eprint!(
        "rnsd {VERSION} interactive console\n\
         This rnsd has no Python interpreter, statements are not run.\n\
         End the input (Ctrl-D) to stop rnsd.\n"
    );
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        print!("{CONSOLE_PROMPT}");
        let _ = std::io::stdout().flush();
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) if line.trim().is_empty() => {}
            Ok(_) => eprintln!("Python statements cannot be run by this rnsd"),
        }
    }
    eprint!("\nnow exiting InteractiveConsole...\n");
    stop.write(1);
}

/// What upstream's `rnsd --exampleconfig` prints, byte for byte
/// (`tests/generate_example_config.py`).
const EXAMPLE_CONFIG: &str = include_str!("example_config");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_upstream_invocations_as_argparse_does() {
        // (argv, service, interactive, config, verbosity, quiet)
        type Case<'a> = (&'a [&'a str], bool, bool, Option<&'a str>, u8, u8);
        let cases: &[Case] = &[
            (&["-s"], true, false, None, 0, 0),
            (&["--service", "-v"], true, false, None, 1, 0),
            (&["--serv", "--config", "/c"], true, false, Some("/c"), 0, 0),
            (&["--config=/c", "-svvq"], true, false, Some("/c"), 2, 1),
            (&["-i", "-v"], false, true, None, 1, 0),
            (
                &["--interactive", "--quiet", "--verbose"],
                false,
                true,
                None,
                1,
                1,
            ),
            (&["-c", "/c"], false, false, Some("/c"), 0, 0),
        ];
        for (argv, service, interactive, config, verbosity, quiet) in cases {
            let args =
                Args::parse_spec_from(argv.iter().map(|s| s.to_string()).collect(), &OPTIONS);
            assert_eq!(
                (
                    args.has("s"),
                    args.has("interactive"),
                    args.config_path(),
                    args.verbosity,
                    args.quiet
                ),
                (*service, *interactive, *config, *verbosity, *quiet),
                "{argv:?}"
            );
            assert!(args.unknown.is_empty(), "{argv:?}");
        }
        assert!(Args::parse_spec_from(vec!["--example".into()], &OPTIONS).has("exampleconfig"));
    }

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
    fn example_config_is_upstreams_and_parses_to_the_defaults() {
        assert!(EXAMPLE_CONFIG.starts_with("# This is an example Reticulum config file.\n"));
        for key in [
            "stamp_destinations",
            "enforce_stamps",
            "destination_cost",
            "lr_stamp_timeout",
            "pr_stamp_timeout",
        ] {
            assert!(EXAMPLE_CONFIG.contains(&format!("# {key} = ")), "{key}");
        }
        let config = rns_net::config::parse(EXAMPLE_CONFIG).unwrap();
        assert_eq!(config.stamps, rns_net::config::StampsSection::default());
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
