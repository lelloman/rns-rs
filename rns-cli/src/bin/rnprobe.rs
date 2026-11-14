//! rnprobe - Reticulum Network Probe Utility
//!
//! Sends probe packets to a Reticulum destination and reports the round-trip
//! time of each delivery proof, as upstream's `rnprobe` does: attached to a
//! running shared instance (Rust or Python), or as an instance of its own.

use std::path::Path;
use std::process;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rns_cli::args::{Args, Opt, OptionSpec};
use rns_core::types::{DestHash, PacketHash};
use rns_net::event::{QueryRequest, QueryResponse, MAX_PROBE_PAYLOAD_SIZE};
use rns_net::pickle::PickleValue;
use rns_net::{
    config, storage, AnnouncedIdentity, Callbacks, Destination, RnsNode, RpcAddr, RpcClient,
};

const VERSION: &str = env!("FULL_VERSION");
const DEFAULT_PROBE_SIZE: usize = 16;
/// Upstream's `DEFAULT_TIMEOUT`, added to the first-hop timeout.
const DEFAULT_TIMEOUT: f64 = 12.0;
/// The destination probed when only a hash is given.
const DEFAULT_FULL_NAME: &str = "rnstransport.probe";

/// upstream rnprobe's options: `-s`, `-n`, `-t` and `-w` always take a
/// value (`-t 5`, `-t5` or `--timeout=5`).
pub const OPTIONS: OptionSpec = OptionSpec {
    options: &[
        Opt::value("", "config"),
        Opt::value("s", "size"),
        Opt::value("n", "probes"),
        Opt::value("t", "timeout"),
        Opt::value("w", "wait"),
        Opt::count("v", "verbose"),
        // Rust-only: the shared parser's `-c` and an alias of `--probes`.
        Opt::value("c", ""),
        Opt::value("", "count").rust_only(),
    ],
};

#[allow(dead_code)]
fn main() {
    rns_cli::stdout::exit_quietly_on_closed_stdout();
    run_with_args(Args::parse_spec(&OPTIONS), "rnprobe", "rnprobe");
}

/// A delivery proof: the probe it proves, the round trip, and the packet
/// that carried it.
type Proof = (PacketHash, f64, Option<PacketHash>);

struct ProbeCallbacks {
    proofs: mpsc::Sender<Proof>,
}

impl Callbacks for ProbeCallbacks {
    fn on_announce(&mut self, _: AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
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

pub fn run_with_args(args: Args, usage_name: &str, version_name: &str) {
    if args.has("version") {
        println!("{} {}", version_name, VERSION);
        return;
    }
    if args.has("help") || args.has("h") {
        print_usage(usage_name);
        return;
    }

    // As upstream, the first -v adds detail to the output; more raise the
    // log level.
    let level = (2i16 + args.verbosity.saturating_sub(1) as i16).clamp(0, 5);
    let filter = ["off", "error", "warn", "info", "debug", "trace"][level as usize];
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter))
        .format_timestamp_secs()
        .try_init();

    let options = match Options::from_args(&args) {
        Ok(options) => options,
        Err(OptionsError::Usage) => {
            println!();
            print_usage(usage_name);
            println!();
            return;
        }
        Err(OptionsError::Message(message)) => {
            println!("{message}");
            return;
        }
    };
    if let Some(message) = oversize_probe_error(options.size) {
        println!("{}", message);
        process::exit(3);
    }
    process::exit(probe(&options));
}

#[derive(Debug, PartialEq)]
struct Options {
    config: Option<String>,
    size: usize,
    probes: usize,
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
        // `full_name destination_hash`, as upstream takes them; a lone hash
        // probes the transport's probe destination.
        let (full_name, hash) = match args.positional.as_slice() {
            [] => return Err(OptionsError::Usage),
            [hash] if parse_dest_hash(hash).is_some() => (DEFAULT_FULL_NAME.to_string(), hash),
            [_] => return Err(OptionsError::Usage),
            [full_name, hash, ..] => (full_name.clone(), hash),
        };
        let (app_name, aspects) = app_and_aspects_from_name(&full_name)?;
        if hash.len() != 32 {
            return Err(OptionsError::Message(
                "Destination length is invalid, must be 32 hexadecimal characters (16 bytes)."
                    .into(),
            ));
        }
        let dest_hash = parse_dest_hash(hash).ok_or_else(|| {
            OptionsError::Message("Invalid destination entered. Check your input.".into())
        })?;
        Ok(Options {
            config: args.config_path().map(str::to_string),
            size: parse_number(value("s", "size"), "-s/--size", "int")?
                .unwrap_or(DEFAULT_PROBE_SIZE),
            probes: parse_number(
                value("n", "probes").or_else(|| args.get("count")),
                "-n/--probes",
                "int",
            )?
            .unwrap_or(1),
            timeout: parse_number(value("t", "timeout"), "-t/--timeout", "float")?,
            wait: parse_number(value("w", "wait"), "-w/--wait", "float")?.unwrap_or(0.0),
            app_name,
            aspects,
            dest_hash,
            verbose: args.verbosity > 0,
        })
    }
}

fn parse_number<T: std::str::FromStr>(
    value: Option<&str>,
    name: &str,
    kind: &str,
) -> Result<Option<T>, OptionsError> {
    value
        .map(|v| {
            v.parse::<T>().map_err(|_| {
                OptionsError::Message(format!("argument {name}: invalid {kind} value: '{v}'"))
            })
        })
        .transpose()
}

/// `RNS.Destination.app_and_aspects_from_name`.
fn app_and_aspects_from_name(full_name: &str) -> Result<(String, Vec<String>), OptionsError> {
    let mut parts = full_name.split('.');
    let app_name = parts.next().unwrap_or_default().to_string();
    if app_name.is_empty() {
        return Err(OptionsError::Message(
            "The full destination name including application name aspects must be specified for the destination".into(),
        ));
    }
    Ok((app_name, parts.map(str::to_string).collect()))
}

/// Run the probes; returns the process exit code (upstream's: 1 when no path
/// was found, 2 on any packet loss, 0 otherwise).
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
    let instance = InstanceRpc::for_config_dir(&config_dir);
    let code = run_probes(&node, instance.as_ref(), options, &rx);
    node.shutdown();
    code
}

fn run_probes(
    node: &RnsNode,
    instance: Option<&InstanceRpc>,
    options: &Options,
    proofs: &mpsc::Receiver<Proof>,
) -> i32 {
    let dest = DestHash(options.dest_hash);
    let pretty = prettyhexrep(&options.dest_hash);
    let timeout = || {
        options.timeout.unwrap_or_else(|| {
            let first_hop = instance
                .and_then(|rpc| rpc.first_hop_timeout(&options.dest_hash))
                .or_else(|| local_first_hop_timeout(node, &options.dest_hash))
                .unwrap_or(rns_core::constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP);
            let medium = node.medium_path_timeout().unwrap_or(0.0);
            (DEFAULT_TIMEOUT + first_hop).max(medium)
        })
    };

    if !node.has_path(&dest).unwrap_or(false) {
        let _ = node.request_path(&dest);
        print!("Path to {pretty} requested   ");
        flush();
    }
    let deadline = Instant::now() + Duration::from_secs_f64(timeout());
    while !node.has_path(&dest).unwrap_or(false) {
        if Instant::now() > deadline {
            println!("\r{:58}\rPath request timed out", "");
            return 1;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let Some(recalled) = node.recall_identity(&dest).ok().flatten() else {
        println!("\r{:58}\rCould not recall the identity of {pretty}", "");
        return 1;
    };
    let aspects: Vec<&str> = options.aspects.iter().map(String::as_str).collect();
    let destination = Destination::single_out(&options.app_name, &aspects, &recalled);

    let mut sent = 0usize;
    let mut replies = 0usize;
    for _ in 0..options.probes {
        if sent > 0 {
            std::thread::sleep(Duration::from_secs_f64(options.wait));
        }
        let mut payload = vec![0u8; options.size];
        rns_crypto::Rng::fill_bytes(&mut rns_crypto::OsRng, &mut payload);
        sent += 1;
        let packet_hash = match node.send_packet_queued(&destination, &payload) {
            Ok(hash) => hash,
            Err(e) => {
                println!("\rCould not send probe to {pretty}: {e:?}");
                continue;
            }
        };

        let more = if options.verbose {
            let via = instance
                .and_then(|rpc| rpc.next_hop(&options.dest_hash))
                .map(|hop| format!(" via {}", prettyhexrep(&hop)))
                .unwrap_or_default();
            let on = instance
                .and_then(|rpc| rpc.next_hop_if_name(&options.dest_hash))
                .filter(|name| name != "None")
                .map(|name| format!(" on {name}"))
                .unwrap_or_default();
            format!("{via}{on}")
        } else {
            String::new()
        };
        print!(
            "\rSent probe {sent} ({} bytes) to {pretty}{more}   ",
            options.size
        );
        flush();

        let deadline = Instant::now() + Duration::from_secs_f64(timeout());
        let reply = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break None;
            }
            match proofs.recv_timeout(left.min(Duration::from_millis(100))) {
                Ok((hash, rtt, proof_packet)) if hash == packet_hash => {
                    break Some((rtt, proof_packet))
                }
                _ => continue,
            }
        };
        match reply {
            None => println!("\r{:64}\rProbe timed out", ""),
            Some((rtt, proof_packet)) => {
                println!("\u{8}\u{8} ");
                replies += 1;
                let hops = node.hops_to(&dest).ok().flatten().unwrap_or(0);
                println!(
                    "Valid reply from {}\nRound-trip time is {} over {} hop{}{}\n",
                    prettyhexrep(&destination.hash.0),
                    rtt_string(rtt),
                    hops,
                    if hops != 1 { "s" } else { "" },
                    reception_stats(node, instance, proof_packet),
                );
            }
        }
    }

    let loss = python_round((1.0 - replies as f64 / sent.max(1) as f64) * 100.0, 2);
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

fn flush() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Upstream's round-trip string: seconds from one second up, else
/// milliseconds, rounded to three decimals.
fn rtt_string(rtt: f64) -> String {
    if rtt >= 1.0 {
        format!("{} seconds", python_float(python_round(rtt, 3)))
    } else {
        format!(
            "{} milliseconds",
            python_float(python_round(rtt * 1000.0, 3))
        )
    }
}

fn python_round(value: f64, digits: i32) -> f64 {
    let scale = 10f64.powi(digits);
    (value * scale).round() / scale
}

/// A float as Python's `str()` writes it: the shortest round-trip form, with
/// a `.0` on whole numbers.
fn python_float(value: f64) -> String {
    let text = format!("{value}");
    if text.contains(['.', 'e', 'i', 'N']) {
        text
    } else {
        format!("{text}.0")
    }
}

/// `RNS.prettyhexrep`.
fn prettyhexrep(hash: &[u8]) -> String {
    format!("<{}>", rns_cli::format::prettyhexrep(hash))
}

/// Upstream's reception stats suffix for the proof that answered a probe.
/// A shared instance client asks the instance, which saw the packet arrive
/// (`get_packet_rssi`, `_snr`, `_q`); an instance of its own reads the
/// proof packet's RSSI and SNR, as upstream, which has no link quality there.
fn reception_stats(
    node: &RnsNode,
    instance: Option<&InstanceRpc>,
    proof_packet: Option<PacketHash>,
) -> String {
    let Some(PacketHash(hash)) = proof_packet else {
        return String::new();
    };
    let (rssi, snr, q) = if node.is_connected_to_shared_instance() {
        let Some(rpc) = instance else {
            return String::new();
        };
        let stat = |what| rpc.packet_stat(what, &hash).and_then(|v| python_str(&v));
        (stat("packet_rssi"), stat("packet_snr"), stat("packet_q"))
    } else {
        (
            node.packet_rssi(&hash)
                .ok()
                .flatten()
                .map(|v| v.to_string()),
            node.packet_snr(&hash)
                .ok()
                .flatten()
                .map(|v| python_float(f64::from(v))),
            None,
        )
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

/// A number as Python's `str()` writes it; `None` for anything else.
fn python_str(value: &PickleValue) -> Option<String> {
    value
        .as_int()
        .map(|v| v.to_string())
        .or_else(|| value.as_float().map(python_float))
}

fn local_first_hop_timeout(node: &RnsNode, dest_hash: &[u8; 16]) -> Option<f64> {
    match node.query(QueryRequest::FirstHopTimeout {
        dest_hash: *dest_hash,
    }) {
        Ok(QueryResponse::FirstHopTimeout(timeout)) => Some(timeout),
        _ => None,
    }
}

/// The shared instance's RPC, for what upstream's shared clients ask it:
/// the first-hop timeout and the next hop of a path. Absent when no shared
/// instance RPC key is available; the probe itself never needs it.
struct InstanceRpc {
    addr: RpcAddr,
    auth_key: [u8; 32],
}

impl InstanceRpc {
    fn for_config_dir(config_dir: &Path) -> Option<Self> {
        let config_file = config_dir.join("config");
        let rns_config = if config_file.exists() {
            config::parse_file(&config_file).ok()?
        } else {
            config::parse("").ok()?
        };
        let auth_key = match rns_config.reticulum.rpc_key {
            Some(key) => key,
            None => {
                let identity =
                    storage::load_identity(&config_dir.join("storage").join("transport_identity"))
                        .ok()?;
                rns_net::rpc::derive_auth_key(&identity.get_private_key()?)
            }
        };
        Some(InstanceRpc {
            addr: RpcAddr::for_shared_instance(&rns_config.reticulum),
            auth_key,
        })
    }

    fn get(&self, what: &str, dest_hash: &[u8; 16]) -> Option<PickleValue> {
        let mut client = RpcClient::connect(&self.addr, &self.auth_key).ok()?;
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
        let mut client = RpcClient::connect(&self.addr, &self.auth_key).ok()?;
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
    if hex.len() != 32 || !hex.is_ascii() {
        return None;
    }
    let mut result = [0u8; 16];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(result)
}

fn print_usage(usage_name: &str) {
    println!(
        "usage: {usage_name} [-h] [--config CONFIG] [-s SIZE] [-n PROBES] [-t seconds] [-w seconds] [--version] [-v] [full_name] [destination_hash]"
    );
    println!();
    println!("Reticulum Probe Utility");
    println!();
    println!("positional arguments:");
    println!("  full_name             full destination name in dotted notation");
    println!("                        (with a lone hash: {DEFAULT_FULL_NAME})");
    println!("  destination_hash      hexadecimal hash of the destination");
    println!();
    println!("options:");
    println!("  -h, --help            show this help message and exit");
    println!("  --config CONFIG       path to alternative Reticulum config directory");
    println!(
        "  -s, --size SIZE       size of probe packet payload in bytes (max {MAX_PROBE_PAYLOAD_SIZE})"
    );
    println!("  -n, --probes PROBES   number of probes to send");
    println!("  -t, --timeout seconds");
    println!("                        timeout before giving up");
    println!("  -w, --wait seconds    time between each probe");
    println!("  --version             show program's version number and exit");
    println!("  -v, --verbose");
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
        assert_eq!(options(&["-t10", HASH]).unwrap().timeout, Some(10.0));
        assert_eq!(options(&[HASH, "-t", "10"]).unwrap().timeout, Some(10.0));
        assert_eq!(
            options(&["--timeout", "7", HASH]).unwrap().timeout,
            Some(7.0)
        );
        assert_eq!(options(&["--count", "2", HASH]).unwrap().probes, 2);
    }

    #[test]
    fn parses_upstream_invocations_as_argparse_does() {
        // (argv, size, probes, timeout, wait, verbose, app name)
        type Case<'a> = (&'a [&'a str], usize, usize, Option<f64>, f64, bool, &'a str);
        let cases: &[Case] = &[
            (&[HASH], 16, 1, None, 0.0, false, "rnstransport"),
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
                &["--timeout", "2.5", "--wait", "1", HASH],
                16,
                1,
                Some(2.5),
                1.0,
                false,
                "rnstransport",
            ),
            (
                &["--tim", "2", "--wa=1", "--pro", "4", HASH],
                16,
                4,
                Some(2.0),
                1.0,
                false,
                "rnstransport",
            ),
            (
                &["-vvt", "3", HASH, "-w0.25"],
                16,
                1,
                Some(3.0),
                0.25,
                true,
                "rnstransport",
            ),
            (
                &["--config", "/tmp/x", HASH],
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
            options(&["--config=/tmp/x", HASH])
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
        // A lone hash probes the transport probe destination.
        let parsed = options(&[HASH]).unwrap();
        assert_eq!(parsed.app_name, "rnstransport");
        assert_eq!(parsed.aspects, vec!["probe".to_string()]);
        assert_eq!(parsed.dest_hash[0], 0x01);
        assert_eq!(options(&[]), Err(OptionsError::Usage));
        assert_eq!(options(&["only.a.name"]), Err(OptionsError::Usage));
        assert!(matches!(
            options(&["a.b", "abcd"]),
            Err(OptionsError::Message(m)) if m.starts_with("Destination length is invalid")
        ));
        assert!(matches!(
            options(&["a.b", "zz23456789abcdef0123456789abcdef"]),
            Err(OptionsError::Message(m)) if m == "Invalid destination entered. Check your input."
        ));
        assert!(matches!(
            options(&["-t", "soon", HASH]),
            Err(OptionsError::Message(_))
        ));
    }

    #[test]
    fn output_numbers_match_upstream() {
        assert_eq!(rtt_string(0.0012345), "1.235 milliseconds");
        assert_eq!(rtt_string(0.25), "250.0 milliseconds");
        assert_eq!(rtt_string(1.0), "1.0 seconds");
        assert_eq!(rtt_string(2.34567), "2.346 seconds");
        assert_eq!(python_float(python_round(0.0, 2)), "0.0");
        assert_eq!(
            python_float(python_round((1.0 - 2.0 / 3.0) * 100.0, 2)),
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
