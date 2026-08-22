//! Reticulum-compatible file transfer utility.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, IdentityHash, LinkId};
use rns_net::destination::Destination;
use rns_net::{
    AnnouncedIdentity, Callbacks, ReceivedResourceFile, ResourceReceiveMode, ResourceTransferError,
    ResourceTransferId, RnsNode,
};

use crate::app;
use crate::format::prettyhexrep;

const APP_NAME: &str = "rncp";
const ASPECT: &str = "receive";
const FETCH_PATH: &str = "fetch_file";
const FETCH_NOT_ALLOWED: u64 = 0xf0;
const VERSION: &str = env!("FULL_VERSION");

#[derive(Debug, Default)]
struct Options {
    file: Option<String>,
    destination: Option<String>,
    config: Option<String>,
    identity: Option<String>,
    listen: bool,
    fetch: bool,
    allow_fetch: bool,
    no_compress: bool,
    no_auth: bool,
    print_identity: bool,
    overwrite: bool,
    silent: bool,
    phy_rates: bool,
    save: Option<String>,
    jail: Option<String>,
    allowed: Vec<String>,
    announce: Option<u64>,
    timeout: f64,
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
            let mut take_value = |name: &str| -> Result<String, String> {
                index += 1;
                arguments
                    .get(index)
                    .cloned()
                    .ok_or_else(|| format!("{name} requires a value"))
            };
            match argument.as_str() {
                "--config" => options.config = Some(take_value("--config")?),
                "-i" | "--identity" => options.identity = Some(take_value(argument)?),
                "-j" | "--jail" => options.jail = Some(take_value(argument)?),
                "-s" | "--save" => options.save = Some(take_value(argument)?),
                "-a" | "--allowed" => options.allowed.push(take_value(argument)?),
                "-b" | "--announce" => {
                    options.announce = Some(
                        take_value(argument)?
                            .parse()
                            .map_err(|_| "announce interval must be an integer".to_string())?,
                    )
                }
                "-w" | "--timeout" => options.timeout = parse_timeout(&take_value(argument)?)?,
                "-l" | "--listen" => options.listen = true,
                "-f" | "--fetch" => options.fetch = true,
                "-F" | "--allow-fetch" => options.allow_fetch = true,
                "-C" | "--no-compress" => options.no_compress = true,
                "-n" | "--no-auth" => options.no_auth = true,
                "-p" | "--print-identity" => options.print_identity = true,
                "-O" | "--overwrite" => options.overwrite = true,
                "-S" | "--silent" => options.silent = true,
                "-P" | "--phy-rates" => options.phy_rates = true,
                "-v" | "--verbose" => options.verbose = options.verbose.saturating_add(1),
                "-q" | "--quiet" => options.quiet = options.quiet.saturating_add(1),
                "-h" | "--help" => options.help = true,
                "--version" => options.version = true,
                value if value.starts_with('-') => return Err(format!("unknown option {value}")),
                value => positional.push(value.to_string()),
            }
            index += 1;
        }
        options.file = positional.first().cloned();
        options.destination = positional.get(1).cloned();
        if positional.len() > 2 {
            return Err("too many positional arguments".into());
        }
        Ok(options)
    }
}

fn parse_timeout(value: &str) -> Result<f64, String> {
    let timeout: f64 = value
        .parse()
        .map_err(|_| "timeout must be numeric".to_string())?;
    if !timeout.is_finite() || !(0.0..=24.0 * 60.0 * 60.0).contains(&timeout) {
        return Err("timeout must be between 0 and 86400 seconds".into());
    }
    Ok(timeout)
}

enum RncpEvent {
    Announce,
    LinkEstablished([u8; 16], bool),
    LinkClosed([u8; 16]),
    FileReceived([u8; 16], ReceivedResourceFile),
    StreamCompleted([u8; 16], ResourceTransferId),
    StreamFailed([u8; 16], ResourceTransferId, ResourceTransferError),
    StreamProgress(ResourceTransferId, u64, u64),
    ReceiveProgress([u8; 16], u64, u64),
    Response(Vec<u8>),
    FetchRequested([u8; 16], PathBuf),
}

struct RncpCallbacks {
    tx: mpsc::Sender<RncpEvent>,
    allowed: HashSet<[u8; 16]>,
    allow_all: bool,
    identified: HashMap<[u8; 16], [u8; 16]>,
}

impl Callbacks for RncpCallbacks {
    fn on_announce(&mut self, _announced: AnnouncedIdentity) {
        let _ = self.tx.send(RncpEvent::Announce);
    }
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
    }
    fn on_resource_accept_query(
        &mut self,
        link_id: LinkId,
        _resource_hash: Vec<u8>,
        _transfer_size: u64,
        _has_metadata: bool,
    ) -> bool {
        self.allow_all
            || self
                .identified
                .get(&link_id.0)
                .is_some_and(|identity| self.allowed.contains(identity))
    }
    fn on_resource_file_received(&mut self, link_id: LinkId, resource: ReceivedResourceFile) {
        let _ = self.tx.send(RncpEvent::FileReceived(link_id.0, resource));
    }
    fn on_resource_stream_completed(&mut self, link_id: LinkId, transfer_id: ResourceTransferId) {
        let _ = self
            .tx
            .send(RncpEvent::StreamCompleted(link_id.0, transfer_id));
    }
    fn on_resource_stream_failed(
        &mut self,
        link_id: LinkId,
        transfer_id: ResourceTransferId,
        error: ResourceTransferError,
    ) {
        let _ = self
            .tx
            .send(RncpEvent::StreamFailed(link_id.0, transfer_id, error));
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
        println!("rncp {VERSION}");
        return 0;
    }
    init_logging(&options);
    match run(options) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("rncp: {error}");
            1
        }
    }
}

fn run(options: Options) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = app::app_config(APP_NAME, None);
    let identity_path = options
        .identity
        .as_deref()
        .map(app::expand_path)
        .unwrap_or_else(|| config_dir.join("identity"));
    let identity = app::load_or_create_identity(&identity_path)?;
    let destination = Destination::single_in(APP_NAME, &[ASPECT], IdentityHash(*identity.hash()));
    if options.print_identity {
        println!("Identity     : {}", prettyhexrep(identity.hash()));
        println!("Listening on : {}", prettyhexrep(&destination.hash.0));
        return Ok(());
    }

    let allowed = load_allowed(&options, &config_dir)?;
    let (tx, rx) = mpsc::channel();
    let node = RnsNode::connect_shared_from_config(
        Some(&app::rns_config(options.config.as_deref())),
        Box::new(RncpCallbacks {
            tx: tx.clone(),
            allowed: allowed.clone(),
            allow_all: options.no_auth,
            identified: HashMap::new(),
        }),
    )?;

    if options.listen {
        listen(&node, &identity, destination, allowed, options, tx, rx)
    } else {
        let destination_hash = app::parse_hash_16(
            options
                .destination
                .as_deref()
                .ok_or("missing destination")?,
        )
        .ok_or("destination must be 32 hexadecimal characters")?;
        let file = options.file.as_deref().ok_or("missing file")?;
        if options.fetch {
            fetch(&node, &identity, destination_hash, file, &options, rx)
        } else {
            send(
                &node,
                &identity,
                destination_hash,
                Path::new(file),
                &options,
                rx,
            )
        }
    }
}

fn listen(
    node: &RnsNode,
    identity: &rns_crypto::identity::Identity,
    destination: Destination,
    allowed: HashSet<[u8; 16]>,
    options: Options,
    tx: mpsc::Sender<RncpEvent>,
    rx: mpsc::Receiver<RncpEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (signature_private, signature_public) = app::signature_keys(identity)?;
    node.register_destination_with_proof(&destination, identity.get_private_key())?;
    node.register_link_destination(destination.hash.0, signature_private, signature_public, 2)?;

    let jail = options.jail.as_deref().map(app::expand_path);
    let jail = jail.map(|path| path.canonicalize()).transpose()?;
    let allowed_list = (!options.no_auth).then(|| allowed.iter().copied().collect());
    let allow_fetch = options.allow_fetch;
    node.register_request_handler(FETCH_PATH, allowed_list, move |link_id, _, data, _| {
        if !allow_fetch {
            return Some(app::uint_value(FETCH_NOT_ALLOWED));
        }
        let Some(requested) = app::decode_request_string(data) else {
            return Some(app::bool_value(false));
        };
        let candidate = match &jail {
            Some(root) => {
                let requested = Path::new(&requested);
                let joined = if requested.is_absolute() {
                    requested.to_path_buf()
                } else {
                    root.join(requested)
                };
                match joined.canonicalize() {
                    Ok(path) if path.starts_with(root) => path,
                    _ => return Some(app::uint_value(FETCH_NOT_ALLOWED)),
                }
            }
            None => match app::expand_path(&requested).canonicalize() {
                Ok(path) => path,
                Err(_) => return Some(app::bool_value(false)),
            },
        };
        if !candidate.is_file() {
            return Some(app::bool_value(false));
        }
        let _ = tx.send(RncpEvent::FetchRequested(link_id, candidate));
        Some(app::bool_value(true))
    })?;

    if allowed.is_empty() && !options.no_auth {
        eprintln!("warning: no allowed identities configured; no transfers will be accepted");
    }
    if options.no_auth {
        eprintln!("warning: accepting unauthenticated rncp transfers");
    }
    eprintln!("rncp listening on {}", prettyhexrep(&destination.hash.0));
    let save = save_directory(options.save.as_deref())?;
    let temporary = config_temp_directory()?;
    let mut last_announce = Instant::now() - Duration::from_secs(24 * 60 * 60);
    let mut announced = false;
    loop {
        if let Some(period) = options.announce {
            if !announced || period > 0 && last_announce.elapsed() >= Duration::from_secs(period) {
                node.announce(&destination, identity, None)?;
                announced = true;
                last_announce = Instant::now();
            }
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RncpEvent::LinkEstablished(link_id, false)) => {
                node.set_resource_receive_mode(
                    link_id,
                    ResourceReceiveMode::TemporaryFile {
                        directory: temporary.clone(),
                        max_bytes: None,
                    },
                )?;
                node.set_resource_strategy(link_id, 2)?;
            }
            Ok(RncpEvent::FileReceived(_, resource)) => {
                save_resource(resource, &save, options.overwrite)?;
            }
            Ok(RncpEvent::FetchRequested(link_id, path)) => {
                let filename = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or("invalid filename")?;
                node.send_resource_file(
                    link_id,
                    &path,
                    Some(app::filename_metadata(filename)),
                    !options.no_compress,
                )?;
            }
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

fn send(
    node: &RnsNode,
    identity: &rns_crypto::identity::Identity,
    destination: [u8; 16],
    path: &Path,
    options: &Options,
    rx: mpsc::Receiver<RncpEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_file() {
        return Err("source is not a regular file".into());
    }
    let timeout = Duration::from_secs_f64(options.timeout);
    let link_id = connect(node, identity, destination, timeout, &rx)?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("invalid filename")?;
    let transfer_id = node.send_resource_file(
        link_id,
        path,
        Some(app::filename_metadata(filename)),
        !options.no_compress,
    )?;
    let mut deadline = Instant::now() + timeout;
    loop {
        let event = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))?;
        match event {
            RncpEvent::StreamCompleted(id, transfer)
                if id == link_id && transfer == transfer_id =>
            {
                if !options.silent {
                    println!(
                        "{} copied to {}",
                        path.display(),
                        prettyhexrep(&destination)
                    );
                }
                node.teardown_link(link_id)?;
                return Ok(());
            }
            RncpEvent::StreamProgress(transfer, done, total)
                if transfer == transfer_id && !options.silent =>
            {
                deadline = Instant::now() + timeout;
                eprint!(
                    "\r{:.1}% ({done}/{total} bytes)",
                    done as f64 * 100.0 / total.max(1) as f64
                );
            }
            RncpEvent::StreamProgress(transfer, _, _) if transfer == transfer_id => {
                deadline = Instant::now() + timeout;
            }
            RncpEvent::StreamFailed(id, transfer, error)
                if id == link_id && transfer == transfer_id =>
            {
                return Err(format!("transfer failed: {error:?}").into())
            }
            RncpEvent::LinkClosed(id) if id == link_id => {
                return Err("link closed before transfer completed".into())
            }
            _ => {}
        }
    }
}

fn fetch(
    node: &RnsNode,
    identity: &rns_crypto::identity::Identity,
    destination: [u8; 16],
    requested: &str,
    options: &Options,
    rx: mpsc::Receiver<RncpEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let timeout = Duration::from_secs_f64(options.timeout);
    let link_id = connect(node, identity, destination, timeout, &rx)?;
    let temporary = config_temp_directory()?;
    node.set_resource_receive_mode(
        link_id,
        ResourceReceiveMode::TemporaryFile {
            directory: temporary,
            max_bytes: None,
        },
    )?;
    node.set_resource_strategy(link_id, 1)?;
    node.send_request(
        link_id,
        FETCH_PATH,
        &msgpack::pack(&Value::Str(requested.into())),
    )?;
    let save = save_directory(options.save.as_deref())?;
    let mut deadline = Instant::now() + timeout;
    let mut accepted = false;
    let mut received = None;
    loop {
        let event = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))?;
        match event {
            RncpEvent::Response(data) => match msgpack::unpack_exact(&data)
                .map_err(|error| format!("invalid fetch response: {error:?}"))?
            {
                Value::UInt(FETCH_NOT_ALLOWED) => {
                    return Err("remote denied the fetch request".into())
                }
                Value::Bool(false) => return Err("remote file was not found".into()),
                Value::Bool(true) => {
                    accepted = true;
                    deadline = Instant::now() + timeout;
                    if let Some(resource) = received.take() {
                        let saved = save_resource(resource, &save, options.overwrite)?;
                        if !options.silent {
                            println!(
                                "{} fetched from {}",
                                saved.display(),
                                prettyhexrep(&destination)
                            );
                        }
                        node.teardown_link(link_id)?;
                        return Ok(());
                    }
                }
                _ => return Err("invalid fetch response".into()),
            },
            RncpEvent::FileReceived(id, resource) if id == link_id && accepted => {
                let saved = save_resource(resource, &save, options.overwrite)?;
                if !options.silent {
                    println!(
                        "{} fetched from {}",
                        saved.display(),
                        prettyhexrep(&destination)
                    );
                }
                node.teardown_link(link_id)?;
                return Ok(());
            }
            RncpEvent::FileReceived(id, resource) if id == link_id => {
                received = Some(resource);
                deadline = Instant::now() + timeout;
            }
            RncpEvent::ReceiveProgress(id, done, total) if id == link_id => {
                deadline = Instant::now() + timeout;
                if !options.silent {
                    eprint!(
                        "\r{:.1}% ({done}/{total} bytes)",
                        done as f64 * 100.0 / total.max(1) as f64
                    );
                }
            }
            RncpEvent::LinkClosed(id) if id == link_id => {
                return Err("link closed before fetch completed".into())
            }
            _ => {}
        }
    }
}

fn connect(
    node: &RnsNode,
    identity: &rns_crypto::identity::Identity,
    destination: [u8; 16],
    timeout: Duration,
    rx: &mpsc::Receiver<RncpEvent>,
) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    let path_timeout = app::adaptive_path_timeout(node, timeout);
    let deadline = Instant::now() + path_timeout;
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
        Instant::now() + timeout.max(app::link_establishment_timeout(node, destination));
    loop {
        let event = rx.recv_timeout(link_deadline.saturating_duration_since(Instant::now()))?;
        match event {
            RncpEvent::LinkEstablished(id, true) if id == link_id => break,
            RncpEvent::LinkClosed(id) if id == link_id => {
                return Err("link establishment failed".into())
            }
            _ => {}
        }
    }
    node.identify_on_link(
        link_id,
        identity
            .get_private_key()
            .ok_or("identity has no private key")?,
    )?;
    Ok(link_id)
}

fn save_resource(
    resource: ReceivedResourceFile,
    directory: &Path,
    overwrite: bool,
) -> io::Result<PathBuf> {
    let filename = resource
        .metadata
        .as_deref()
        .and_then(app::metadata_filename)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Resource has no filename metadata",
            )
        })?;
    let destination = app::collision_destination(directory, &filename, overwrite)?;
    resource.persist(destination, overwrite)
}

fn save_directory(value: Option<&str>) -> io::Result<PathBuf> {
    let path = value
        .map(app::expand_path)
        .unwrap_or(std::env::current_dir()?);
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "save directory does not exist",
        ));
    }
    path.canonicalize()
}

fn config_temp_directory() -> io::Result<PathBuf> {
    let directory = app::app_config(APP_NAME, None).join("resources");
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

fn load_allowed(options: &Options, config: &Path) -> io::Result<HashSet<[u8; 16]>> {
    let mut entries = options.allowed.clone();
    let file = config.join("allowed_identities");
    if file.is_file() {
        entries.extend(fs::read_to_string(file)?.lines().map(str::to_string));
    }
    entries
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            app::parse_hash_16(value.trim()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid allowed identity {value}"),
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
    println!("Usage:\n  rncp [options] <file> <destination>\n  rncp --fetch [options] <remote-file> <destination>\n  rncp --listen [options]\n\nOptions:\n  -l, --listen              Listen for transfers\n  -f, --fetch               Fetch instead of send\n  -F, --allow-fetch         Serve authenticated fetch requests\n  -j, --jail DIR            Restrict fetches to DIR\n  -s, --save DIR            Save received files in DIR\n  -O, --overwrite           Replace an existing destination\n  -a, --allowed HASH        Allow identity (repeatable)\n  -n, --no-auth             Accept unauthenticated peers\n  -i, --identity PATH       Identity file\n      --config DIR          Reticulum config directory\n  -b, --announce SECONDS    Announce once/periodically\n  -C, --no-compress         Disable Resource compression\n  -w, --timeout SECONDS     Path/link/transfer timeout\n  -S, --silent              Hide progress\n  -p, --print-identity      Print identity and destination\n      --version             Print version");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_round_trip_and_collision_names_are_safe() {
        let metadata = app::filename_metadata("../hello.txt");
        assert_eq!(
            app::metadata_filename(&metadata).as_deref(),
            Some("../hello.txt")
        );
        let directory = tempfile::tempdir().unwrap();
        let first = app::collision_destination(directory.path(), "../hello.txt", false).unwrap();
        assert_eq!(
            first,
            directory.path().canonicalize().unwrap().join("hello.txt")
        );
        fs::write(&first, b"existing").unwrap();
        let second = app::collision_destination(directory.path(), "hello.txt", false).unwrap();
        assert_eq!(second.file_name().unwrap(), "hello.txt.1");
    }

    #[test]
    fn parser_accepts_upstream_workflows() {
        let options = Options::parse(vec![
            "-f".into(),
            "-O".into(),
            "remote".into(),
            "00".repeat(16),
        ])
        .unwrap();
        assert!(options.fetch && options.overwrite);
        assert_eq!(options.file.as_deref(), Some("remote"));
    }
}
