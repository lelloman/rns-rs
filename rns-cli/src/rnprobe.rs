//! rnprobe - Reticulum Network Probe Utility
//!
//! Sends probe packets to a Reticulum destination and reports the round-trip
//! time of each delivery proof, as upstream's `rnprobe` does: attached to a
//! running shared instance (Rust or Python), or as an instance of its own.

use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::args::{Args, Opt, OptionSpec};
use crate::exit::{self, Exit, Status};
use crate::format::python_float;
use crate::pyfmt::{prettyhexrep, round_float, str_of};
use rns_core::types::{DestHash, PacketHash};
use rns_net::event::{QueryRequest, QueryResponse, MAX_PROBE_PAYLOAD_SIZE};
use rns_net::pickle::PickleValue;
use rns_net::{config, storage, Callbacks, Destination, RnsNode, SharedInstanceRpc};

const VERSION: &str = env!("FULL_VERSION");
const DEFAULT_PROBE_SIZE: usize = 16;
/// Upstream's `DEFAULT_TIMEOUT`, added to the first-hop timeout.
const DEFAULT_TIMEOUT: f64 = 12.0;

/// upstream rnprobe's options: `-s`, `-n`, `-t` and `-w` always take a
/// value (`-t 5`, `-t5` or `--timeout=5`).
pub static OPTIONS: OptionSpec = OptionSpec::new(
    Some(&crate::upstream_parsers::RNPROBE),
    &[],
    &[
        // Rust-only: the shared parser's `-c` and an alias of `--probes`.
        Opt::value("c", ""),
        Opt::value("", "count").rust_only(),
    ],
);

/// The `rnprobe` binary: options from the command line.
pub fn main() -> ExitCode {
    crate::stdout::exit_quietly_on_closed_stdout();
    exit::exit_code(run_with_args(
        Args::parse_spec(&OPTIONS),
        "rnprobe",
        "rnprobe",
    ))
}

/// A delivery proof: the probe it proves, the round trip, and the packet
/// that carried it.
type Proof = (PacketHash, f64, Option<PacketHash>);

struct ProbeCallbacks {
    proofs: mpsc::Sender<Proof>,
}

impl Callbacks for ProbeCallbacks {
    fn on_proof_packet(
        &mut self,
        _: DestHash,
        packet_hash: PacketHash,
        rtt: f64,
        proof_packet: Option<PacketHash>,
    ) {
        let _ = self.proofs.send((packet_hash, rtt, proof_packet));
    }
}

/// Runs `rnprobe` on already parsed `args`. `usage_name` is the program name
/// printed in usage and errors (e.g. `rns-ctl rnprobe`), `version_name` the one
/// printed by `--version`.
///
/// Blocks until the command is done, and gives upstream's exit status;
/// exits the process itself on an argument error.
pub fn run_with_args(args: Args, usage_name: &str, version_name: &str) -> Status {
    crate::argparse::enforce(&args, "rnprobe", usage_name);
    if args.has("version") {
        println!("{} {}", version_name, VERSION);
        return Ok(());
    }
    if args.has("help") || args.has("h") {
        print_usage(usage_name);
        return Ok(());
    }

    // As upstream, the first -v adds detail to the output rather than log
    // level, and without one the level drops to warnings:
    // `RNS.Reticulum(configdir, loglevel=3+verbosity-1)`.
    crate::pylog::install_utility_logging(
        args.config_path(),
        Some(2 + i32::from(args.verbosity)),
        0,
        false,
    );

    let options = match Options::from_args(&args) {
        Ok(options) => options,
        Err(OptionsError::Usage) => {
            println!();
            print_usage(usage_name);
            println!();
            return Ok(());
        }
        Err(OptionsError::Message(message)) => {
            println!("{message}");
            return Ok(());
        }
    };
    // Upstream's Reticulum exits quietly with 0 on SIGINT.
    crate::stdout::exit_on_interrupt(0);
    match probe(&options) {
        0 => Ok(()),
        code => Err(Exit(code)),
    }
}

#[derive(Debug, PartialEq)]
struct Options {
    config: Option<String>,
    /// Negative sizes fail where upstream's `os.urandom` raises.
    size: i64,
    /// Upstream sends while this is non-zero: a negative count never ends.
    probes: i64,
    timeout: Option<f64>,
    wait: f64,
    app_name: String,
    aspects: Vec<String>,
    dest_hash: [u8; 16],
    verbose: bool,
}

#[derive(Debug, PartialEq)]
enum OptionsError {
    /// No destination: upstream prints the help.
    Usage,
    /// Upstream prints the message and exits.
    Message(String),
}

impl Options {
    fn from_args(args: &Args) -> Result<Self, OptionsError> {
        let value = |short: &str, long: &str| args.get(short).or_else(|| args.get(long));
        // argparse fills `full_name` first: without a second positional
        // there is no destination hash, and upstream prints its help.
        let (full_name, hash) = match args.positional.as_slice() {
            [full_name, hash, ..] => (full_name, hash),
            _ => return Err(OptionsError::Usage),
        };
        let (app_name, aspects) = app_and_aspects_from_name(full_name);
        if crate::pyfmt::len(hash) != 32 {
            return Err(OptionsError::Message(
                "Destination length is invalid, must be 32 hexadecimal characters (16 bytes)."
                    .into(),
            ));
        }
        let dest_hash = parse_dest_hash(hash).ok_or_else(|| {
            OptionsError::Message("Invalid destination entered. Check your input.".into())
        })?;
        // argparse has validated the numbers already.
        let int = |v: Option<&str>| v.and_then(crate::argparse::python_int);
        let float = |v: Option<&str>| v.and_then(crate::argparse::python_float);
        Ok(Options {
            config: args.config_path().map(str::to_string),
            size: int(value("s", "size")).unwrap_or(DEFAULT_PROBE_SIZE as i64),
            probes: int(value("n", "probes").or_else(|| args.get("count"))).unwrap_or(1),
            timeout: float(value("t", "timeout")),
            wait: float(value("w", "wait")).unwrap_or(0.0).max(0.0),
            app_name,
            aspects,
            dest_hash,
            verbose: args.verbosity > 0,
        })
    }
}

/// `RNS.Destination.app_and_aspects_from_name`.
fn app_and_aspects_from_name(full_name: &str) -> (String, Vec<String>) {
    let mut parts = full_name.split('.');
    let app_name = parts.next().unwrap_or_default().to_string();
    (app_name, parts.map(str::to_string).collect())
}

/// Run the probes; returns the process exit code (upstream's: 1 when no path
/// was found, 2 on any packet loss, 3 for an oversize probe, 0 otherwise).
fn probe(options: &Options) -> i32 {
    let config_dir = storage::resolve_config_dir(options.config.as_deref().map(Path::new));
    let (tx, rx) = mpsc::channel();
    let callbacks = || Box::new(ProbeCallbacks { proofs: tx.clone() });
    // As upstream: attached to a running shared instance, or as an instance
    // of its own.
    let node = match RnsNode::connect_shared_from_config(Some(&config_dir), callbacks()) {
        Ok(node) => node,
        Err(_) => match RnsNode::from_config(Some(&config_dir), callbacks()) {
            Ok(node) => node,
            Err(e) => {
                eprintln!("Could not start Reticulum: {e}");
                return 1;
            }
        },
    };
    let instance = if node.is_connected_to_shared_instance() {
        InstanceRpc::for_config_dir(&config_dir)
    } else {
        None
    };
    let code = Prober {
        node: &node,
        instance: instance.as_ref(),
        options,
        proofs: &rx,
    }
    .run();
    node.shutdown();
    code
}

/// Upstream's spinner, one frame per 100 ms poll.
struct Spinner(usize);

impl Spinner {
    const SYMS: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];

    fn tick(&mut self) {
        print!("\u{8}\u{8}{} ", Self::SYMS[self.0]);
        flush();
        self.0 = (self.0 + 1) % Self::SYMS.len();
    }
}

const POLL: Duration = Duration::from_millis(100);
/// `RNS.Packet.TIMEOUT_PER_HOP`.
const TIMEOUT_PER_HOP: f64 = 6.0;
/// `RNS.Transport.receipts_check_interval`.
const RECEIPTS_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// `RNS.Transport.PATHFINDER_M`, upstream's hop count without a path.
const PATHFINDER_M: u8 = 128;

#[derive(PartialEq)]
enum Receipt {
    Sent,
    Delivered(f64, Option<PacketHash>),
    Failed,
}

struct Prober<'a> {
    node: &'a RnsNode,
    instance: Option<&'a InstanceRpc>,
    options: &'a Options,
    proofs: &'a mpsc::Receiver<Proof>,
}

impl Prober<'_> {
    /// `reticulum.get_first_hop_timeout`: the shared instance's when
    /// attached to one, else this instance's.
    fn first_hop_timeout(&self, dest_hash: &[u8; 16]) -> f64 {
        match self.instance {
            Some(rpc) => rpc.first_hop_timeout(dest_hash),
            None => match self.node.query(QueryRequest::FirstHopTimeout {
                dest_hash: *dest_hash,
            }) {
                Ok(QueryResponse::FirstHopTimeout(timeout)) => Some(timeout),
                _ => None,
            },
        }
        .unwrap_or(rns_core::constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP)
    }

    fn medium_path_timeout(&self) -> f64 {
        match self.instance {
            Some(rpc) => rpc.medium_path_timeout(),
            None => self.node.medium_path_timeout().ok(),
        }
        .unwrap_or(0.0)
    }

    /// `timeout or max(DEFAULT_TIMEOUT+first_hop_timeout, medium_path_timeout)`:
    /// a zero timeout is upstream's default too.
    fn timeout(&self) -> Duration {
        let seconds = match self.options.timeout {
            Some(timeout) if timeout != 0.0 => timeout,
            _ => (DEFAULT_TIMEOUT + self.first_hop_timeout(&self.options.dest_hash))
                .max(self.medium_path_timeout()),
        };
        Duration::try_from_secs_f64(seconds).unwrap_or(Duration::ZERO)
    }

    fn hops_to(&self, dest_hash: &[u8; 16]) -> u8 {
        self.node
            .hops_to(&DestHash(*dest_hash))
            .ok()
            .flatten()
            .unwrap_or(PATHFINDER_M)
    }

    /// `reticulum.get_next_hop` and `get_next_hop_if_name`, as upstream's
    /// verbose output shows them.
    fn next_hop_details(&self) -> String {
        let dest_hash = &self.options.dest_hash;
        let (next_hop, if_name) = match self.instance {
            Some(rpc) => (
                rpc.next_hop(dest_hash),
                rpc.next_hop_if_name(dest_hash)
                    .unwrap_or_else(|| "None".into()),
            ),
            None => (
                match self.node.query(QueryRequest::NextHop {
                    dest_hash: *dest_hash,
                }) {
                    Ok(QueryResponse::NextHop(Some(hop))) => Some(hop.next_hop.to_vec()),
                    _ => None,
                },
                match self.node.query(QueryRequest::NextHopIfName {
                    dest_hash: *dest_hash,
                }) {
                    Ok(QueryResponse::NextHopIfName(Some(name))) => name,
                    _ => "None".into(),
                },
            ),
        };
        let via = next_hop
            .map(|hop| format!(" via {}", prettyhexrep(&hop)))
            .unwrap_or_default();
        let on = if if_name != "None" {
            format!(" on {if_name}")
        } else {
            String::new()
        };
        via + &on
    }

    fn run(&self) -> i32 {
        let options = self.options;
        let dest = DestHash(options.dest_hash);
        let pretty = prettyhexrep(&options.dest_hash);
        let has_path = || self.node.has_path(&dest).unwrap_or(false);

        if !has_path() {
            let _ = self.node.request_path(&dest);
            print!("Path to {pretty} requested   ");
            flush();
        }
        let deadline = Instant::now() + self.timeout();
        let mut spinner = Spinner(0);
        while !has_path() && Instant::now() <= deadline {
            std::thread::sleep(POLL);
            spinner.tick();
        }
        if Instant::now() > deadline {
            println!("\r{:58}\rPath request timed out", "");
            return 1;
        }

        let Some(recalled) = self.node.recall_identity(&dest).ok().flatten() else {
            println!("\r{:58}\rCould not recall the identity of {pretty}", "");
            return 1;
        };
        let aspects: Vec<&str> = options.aspects.iter().map(String::as_str).collect();
        let destination = Destination::single_out(&options.app_name, &aspects, &recalled);

        let mut probes = options.probes;
        let mut sent = 0u64;
        let mut replies = 0u64;
        while probes != 0 {
            if sent > 0 {
                std::thread::sleep(
                    Duration::try_from_secs_f64(options.wait).unwrap_or(Duration::MAX),
                );
            }
            let Ok(size) = usize::try_from(options.size) else {
                flush();
                eprintln!("ValueError: negative argument not allowed");
                return 1;
            };
            if let Some(message) = oversize_probe_error(size) {
                println!("{message}");
                return 3;
            }
            let mut payload = vec![0u8; size];
            rns_crypto::Rng::fill_bytes(&mut rns_crypto::OsRng, &mut payload);
            // `PacketReceipt`'s own timeout, from when it was sent, for the
            // destination the probe is addressed to (which differs from the
            // hash given when the name does not match it); upstream notices
            // it on its next receipts check, up to a second later.
            let addressed = &destination.hash.0;
            let receipt_deadline = Instant::now()
                + Duration::try_from_secs_f64(
                    self.first_hop_timeout(addressed)
                        + TIMEOUT_PER_HOP * f64::from(self.hops_to(addressed)),
                )
                .unwrap_or(Duration::ZERO)
                + RECEIPTS_CHECK_INTERVAL;
            let packet_hash = self.node.send_packet_queued(&destination, &payload).ok();
            sent += 1;

            let more = if options.verbose {
                self.next_hop_details()
            } else {
                String::new()
            };
            print!(
                "\rSent probe {sent} ({} bytes) to {pretty}{more}   ",
                options.size
            );

            let deadline = Instant::now() + self.timeout();
            let mut spinner = Spinner(0);
            let mut receipt = Receipt::Sent;
            loop {
                while let Ok((hash, rtt, proof_packet)) = self.proofs.try_recv() {
                    if receipt == Receipt::Sent && Some(hash) == packet_hash {
                        receipt = Receipt::Delivered(rtt, proof_packet);
                    }
                }
                if receipt == Receipt::Sent && Instant::now() > receipt_deadline {
                    receipt = Receipt::Failed;
                }
                if receipt != Receipt::Sent || Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(POLL);
                spinner.tick();
            }

            if Instant::now() > deadline {
                println!("\r{:64}\rProbe timed out", "");
            } else {
                println!("\u{8}\u{8} ");
                flush();
                if let Receipt::Delivered(rtt, proof_packet) = receipt {
                    replies += 1;
                    let hops = self.hops_to(&options.dest_hash);
                    println!(
                        "Valid reply from {}\nRound-trip time is {} over {} hop{}{}\n",
                        prettyhexrep(&destination.hash.0),
                        rtt_string(rtt),
                        hops,
                        if hops != 1 { "s" } else { "" },
                        self.reception_stats(proof_packet),
                    );
                } else {
                    println!("\r{:58}\rProbe timed out", "");
                }
            }
            probes -= 1;
        }

        if sent == 0 {
            // Upstream divides by the number sent.
            flush();
            eprintln!("ZeroDivisionError: division by zero");
            return 1;
        }
        let loss = round_float((1.0 - replies as f64 / sent as f64) * 100.0, 2);
        println!(
            "Sent {sent}, received {replies}, packet loss {}%",
            python_float(loss)
        );
        if loss > 0.0 {
            2
        } else {
            0
        }
    }

    /// Upstream's reception stats suffix for the proof that answered a
    /// probe. A shared instance client asks the instance, which saw the
    /// packet arrive (`get_packet_rssi`, `_snr`, `_q`); an instance of its
    /// own reads the proof packet's RSSI and SNR, as upstream, which has no
    /// link quality there.
    fn reception_stats(&self, proof_packet: Option<PacketHash>) -> String {
        let Some(PacketHash(hash)) = proof_packet else {
            return String::new();
        };
        let (rssi, snr, q) = match self.instance {
            Some(rpc) => {
                let stat = |what| {
                    rpc.packet_stat(what, &hash)
                        .filter(|v| *v != PickleValue::None)
                        .map(|v| str_of(&v))
                };
                (stat("packet_rssi"), stat("packet_snr"), stat("packet_q"))
            }
            None => (
                self.node
                    .packet_rssi(&hash)
                    .ok()
                    .flatten()
                    .map(|v| v.to_string()),
                self.node
                    .packet_snr(&hash)
                    .ok()
                    .flatten()
                    .map(|v| python_float(f64::from(v))),
                None,
            ),
        };
        let mut stats = String::new();
        if let Some(rssi) = rssi {
            stats += &format!(" [RSSI {rssi} dBm]");
        }
        if let Some(snr) = snr {
            stats += &format!(" [SNR {snr} dB]");
        }
        if let Some(q) = q {
            stats += &format!(" [Link Quality {q}%]");
        }
        stats
    }
}

fn flush() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Upstream's round-trip string: seconds from one second up, else
/// milliseconds, rounded to three decimals.
fn rtt_string(rtt: f64) -> String {
    if rtt >= 1.0 {
        format!("{} seconds", python_float(round_float(rtt, 3)))
    } else {
        format!(
            "{} milliseconds",
            python_float(round_float(rtt * 1000.0, 3))
        )
    }
}

/// The shared instance's RPC, for what upstream's shared clients ask it:
/// the first-hop timeout and the next hop of a path. Absent when no shared
/// instance RPC key is available; the probe itself never needs it.
struct InstanceRpc(SharedInstanceRpc);

impl InstanceRpc {
    fn for_config_dir(config_dir: &Path) -> Option<Self> {
        let config_file = config_dir.join("config");
        let rns_config = if config_file.exists() {
            config::parse_file(&config_file).ok()?
        } else {
            config::parse("").ok()?
        };
        SharedInstanceRpc::new(&rns_config.reticulum, || {
            storage::load_identity(&config_dir.join("storage").join("transport_identity"))
        })
        .ok()
        .map(InstanceRpc)
    }

    fn get(&self, what: &str, dest_hash: &[u8; 16]) -> Option<PickleValue> {
        let mut client = self.0.connect().ok()?;
        client
            .call(&PickleValue::Dict(vec![
                (
                    PickleValue::String("get".into()),
                    PickleValue::String(what.into()),
                ),
                (
                    PickleValue::String("destination_hash".into()),
                    PickleValue::Bytes(dest_hash.to_vec()),
                ),
            ]))
            .ok()
    }

    /// Upstream's `get_packet_rssi` / `_snr` / `_q` on the shared instance.
    fn packet_stat(&self, what: &str, packet_hash: &[u8; 32]) -> Option<PickleValue> {
        let mut client = self.0.connect().ok()?;
        client
            .call(&PickleValue::Dict(vec![
                (
                    PickleValue::String("get".into()),
                    PickleValue::String(what.into()),
                ),
                (
                    PickleValue::String("packet_hash".into()),
                    PickleValue::Bytes(packet_hash.to_vec()),
                ),
            ]))
            .ok()
    }

    fn medium_path_timeout(&self) -> Option<f64> {
        let mut client = self.0.connect().ok()?;
        let value = client
            .call(&PickleValue::Dict(vec![(
                PickleValue::String("get".into()),
                PickleValue::String("medium_path_timeout".into()),
            )]))
            .ok()?;
        value
            .as_float()
            .or_else(|| value.as_int().map(|v| v as f64))
    }

    fn first_hop_timeout(&self, dest_hash: &[u8; 16]) -> Option<f64> {
        let value = self.get("first_hop_timeout", dest_hash)?;
        value
            .as_float()
            .or_else(|| value.as_int().map(|v| v as f64))
    }

    fn next_hop(&self, dest_hash: &[u8; 16]) -> Option<Vec<u8>> {
        self.get("next_hop", dest_hash)?
            .as_bytes()
            .map(<[u8]>::to_vec)
    }

    fn next_hop_if_name(&self, dest_hash: &[u8; 16]) -> Option<String> {
        self.get("next_hop_if_name", dest_hash)?
            .as_str()
            .map(str::to_string)
    }
}

/// Size on the wire of a probe carrying `payload_size` random bytes: HEADER_1
/// header, ephemeral public key, IV, PKCS7-padded ciphertext and HMAC.
fn probe_packet_size(payload_size: usize) -> usize {
    use rns_core::constants::{AES128_BLOCKSIZE, HEADER_MINSIZE, KEYSIZE, TOKEN_OVERHEAD};
    HEADER_MINSIZE
        + KEYSIZE / 16
        + TOKEN_OVERHEAD
        + (payload_size / AES128_BLOCKSIZE + 1) * AES128_BLOCKSIZE
}

/// Python-`rnprobe`-style error for payloads that cannot fit in one packet.
fn oversize_probe_error(payload_size: usize) -> Option<String> {
    if payload_size <= MAX_PROBE_PAYLOAD_SIZE {
        return None;
    }
    Some(format!(
        "Error: Probe packet size of {} bytes exceed MTU of {} bytes",
        probe_packet_size(payload_size),
        rns_core::constants::MTU,
    ))
}

fn parse_dest_hash(hex: &str) -> Option<[u8; 16]> {
    rns_core::encoding::hex_decode_array(hex)
}

fn print_usage(usage_name: &str) {
    crate::argparse::print_help("rnprobe", usage_name);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(argv: &[&str]) -> Result<Options, OptionsError> {
        Options::from_args(&Args::parse_spec_from(
            argv.iter().map(|s| s.to_string()).collect(),
            &OPTIONS,
        ))
    }

    const HASH: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn short_value_options_take_their_value() {
        let parsed =
            options(&["-t", "3", "-s", "32", "-n", "4", "-w", "0.5", "a.b", HASH]).unwrap();
        assert_eq!(parsed.timeout, Some(3.0));
        assert_eq!(parsed.size, 32);
        assert_eq!(parsed.probes, 4);
        assert_eq!(parsed.wait, 0.5);
        assert_eq!(options(&["-t10", "a.b", HASH]).unwrap().timeout, Some(10.0));
        assert_eq!(
            options(&["a.b", HASH, "-t", "10"]).unwrap().timeout,
            Some(10.0)
        );
        assert_eq!(
            options(&["--timeout", "7", "a.b", HASH]).unwrap().timeout,
            Some(7.0)
        );
        assert_eq!(options(&["--count", "2", "a.b", HASH]).unwrap().probes, 2);
    }

    #[test]
    fn parses_upstream_invocations_as_argparse_does() {
        // (argv, size, probes, timeout, wait, verbose, app name)
        type Case<'a> = (&'a [&'a str], i64, i64, Option<f64>, f64, bool, &'a str);
        let cases: &[Case] = &[
            (
                &["rnstransport.probe", HASH],
                16,
                1,
                None,
                0.0,
                false,
                "rnstransport",
            ),
            (&["-n", "-1", "a.b", HASH], 16, -1, None, 0.0, false, "a"),
            (&["-s", " 1_6 ", "a.b", HASH], 16, 1, None, 0.0, false, "a"),
            (&["a.b", HASH, "-s32", "-n=3"], 32, 3, None, 0.0, false, "a"),
            (
                &["-v", "--size", "8", "--probes=2", "a.b", HASH],
                8,
                2,
                None,
                0.0,
                true,
                "a",
            ),
            (
                &["--timeout", "2.5", "--wait", "1", "x.y", HASH],
                16,
                1,
                Some(2.5),
                1.0,
                false,
                "x",
            ),
            (
                &["--tim", "2", "--wa=1", "--pro", "4", "x.y", HASH],
                16,
                4,
                Some(2.0),
                1.0,
                false,
                "x",
            ),
            (
                &["-vvt", "3", "x.y", HASH, "-w0.25"],
                16,
                1,
                Some(3.0),
                0.25,
                true,
                "x",
            ),
            (
                &["--config", "/tmp/x", "rnstransport.probe", HASH],
                16,
                1,
                None,
                0.0,
                false,
                "rnstransport",
            ),
        ];
        for (argv, size, probes, timeout, wait, verbose, app) in cases {
            let parsed = options(argv).unwrap_or_else(|e| panic!("{argv:?}: {e:?}"));
            assert_eq!(
                (
                    parsed.size,
                    parsed.probes,
                    parsed.timeout,
                    parsed.wait,
                    parsed.verbose
                ),
                (*size, *probes, *timeout, *wait, *verbose),
                "{argv:?}"
            );
            assert_eq!(parsed.app_name, *app, "{argv:?}");
        }
        assert_eq!(
            options(&["--config=/tmp/x", "a.b", HASH])
                .unwrap()
                .config
                .as_deref(),
            Some("/tmp/x")
        );
    }

    #[test]
    fn full_name_and_hash_as_upstream_takes_them() {
        let parsed = options(&["rnstransport.probe", HASH]).unwrap();
        assert_eq!(parsed.app_name, "rnstransport");
        assert_eq!(parsed.aspects, vec!["probe".to_string()]);
        let parsed = options(&["app.one.two", HASH]).unwrap();
        assert_eq!(parsed.app_name, "app");
        assert_eq!(parsed.aspects, vec!["one".to_string(), "two".to_string()]);
        // argparse takes a lone positional for the full name: upstream
        // then has no destination and prints its help.
        assert_eq!(options(&[HASH]), Err(OptionsError::Usage));
        assert_eq!(options(&[]), Err(OptionsError::Usage));
        // Upstream's length check counts characters.
        assert!(matches!(
            options(&["a.b", "é123456789abcdef0123456789abcdef"]),
            Err(OptionsError::Message(m)) if m == "Invalid destination entered. Check your input."
        ));
        assert_eq!(options(&["", HASH]).unwrap().app_name, "");
        assert_eq!(options(&["only.a.name"]), Err(OptionsError::Usage));
        assert!(matches!(
            options(&["a.b", "abcd"]),
            Err(OptionsError::Message(m)) if m.starts_with("Destination length is invalid")
        ));
        assert!(matches!(
            options(&["a.b", "zz23456789abcdef0123456789abcdef"]),
            Err(OptionsError::Message(m)) if m == "Invalid destination entered. Check your input."
        ));
    }

    #[test]
    fn output_numbers_match_upstream() {
        assert_eq!(rtt_string(0.0012345), "1.234 milliseconds");
        assert_eq!(rtt_string(0.0012346), "1.235 milliseconds");
        assert_eq!(rtt_string(0.25), "250.0 milliseconds");
        assert_eq!(rtt_string(1.0), "1.0 seconds");
        assert_eq!(rtt_string(2.34567), "2.346 seconds");
        assert_eq!(python_float(round_float(0.0, 2)), "0.0");
        assert_eq!(
            python_float(round_float((1.0 - 2.0 / 3.0) * 100.0, 2)),
            "33.33"
        );
        assert_eq!(python_float(100.0), "100.0");
        assert_eq!(prettyhexrep(&[0xab, 0x01]), "<ab01>");
    }

    #[test]
    fn oversize_probe_error_matches_mtu_boundary() {
        assert_eq!(MAX_PROBE_PAYLOAD_SIZE, 399);
        assert_eq!(probe_packet_size(MAX_PROBE_PAYLOAD_SIZE), 499);
        assert!(oversize_probe_error(16).is_none());
        assert!(oversize_probe_error(MAX_PROBE_PAYLOAD_SIZE).is_none());
        let msg = oversize_probe_error(400).unwrap();
        assert_eq!(
            msg,
            "Error: Probe packet size of 515 bytes exceed MTU of 500 bytes"
        );
    }

    #[test]
    fn parse_hashes() {
        assert_eq!(parse_dest_hash(HASH).unwrap()[15], 0xef);
        assert_eq!(
            parse_dest_hash("0123456789ABCDEF0123456789ABCDEF").unwrap()[1],
            0x23
        );
        assert!(parse_dest_hash("0123").is_none());
        assert!(parse_dest_hash(&format!("{HASH}00")).is_none());
        assert!(parse_dest_hash("zz23456789abcdef0123456789abcdef").is_none());
        assert!(parse_dest_hash("é123456789abcdef0123456789abcde").is_none());
    }
}
