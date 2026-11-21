use std::fs;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// `rnsd -i` keeps upstream's console lifecycle: prompts on stdout, the
/// console's messages on stderr, and the end of its input stops rnsd with
/// status 0.
#[test]
fn interactive_rnsd_stops_at_the_end_of_its_input() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("config"),
        "[reticulum]\n  share_instance = No\n[logging]\n  loglevel = 2\n",
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rnsd"))
        .args(["--config", dir.path().to_str().unwrap(), "-i"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start rnsd -i");
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"print(1)\n\n").unwrap();
    }

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("rnsd -i did not stop at the end of its input");
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child.stdout.unwrap().read_to_string(&mut stdout).unwrap();
    child.stderr.unwrap().read_to_string(&mut stderr).unwrap();

    assert_eq!(status.code(), Some(0), "stderr:\n{stderr}");
    assert_eq!(stdout, ">>> >>> >>> ");
    assert!(
        stderr.ends_with(
            "Python statements cannot be run by this rnsd\n\nnow exiting InteractiveConsole...\n"
        ),
        "{stderr}"
    );
}

/// The transport identity used by the management tests below. The expected
/// lines were produced by upstream's rnsd with this transport identity.
const TRANSPORT_IDENTITY: &str = "13a257aa35f3770df0ad24e87b6f023c7cff78a5d2f0a0858c2a134d5d4250b0\
                                  fb4c7adc0606555e055a779e72b6fe0b230923f8b201c84b7a6bf585881a7b3e";
const MANAGEMENT_NOTICES: [&str; 2] = [
    "Enabled remote management on <rnstransport.remote.management.8a6775fe2568d05c765ef91673043c87:1b158d77d64684a082f1d6350673ed9a>",
    "Transport Instance will respond to probe requests on <rnstransport.probe.8a6775fe2568d05c765ef91673043c87:3d477c4ae377b955c67b4d45398f1fb7>",
];

fn transport_identity_key() -> Vec<u8> {
    (0..TRANSPORT_IDENTITY.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&TRANSPORT_IDENTITY[i..i + 2], 16).unwrap())
        .collect()
}

/// The config of a transport rnsd with probes and remote management,
/// logging at `loglevel`, with `extra` added to its `[reticulum]` section.
fn management_config(loglevel: u8, extra: &str) -> String {
    format!(
        "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n  \
         respond_to_probes = Yes\n  enable_remote_management = Yes\n{extra}\
         [logging]\n  loglevel = {loglevel}\n[interfaces]\n"
    )
}

/// Starts rnsd with `config` on `dir`, with `dir` as its home directory,
/// waits for it to finish starting, stops it and returns its log.
fn rnsd_startup_log(dir: &std::path::Path, config: &str) -> String {
    startup_log_of(Command::new(env!("CARGO_BIN_EXE_rnsd")), dir, config)
}

/// `rnsd_startup_log` for upstream's rnsd.
fn python_rnsd_startup_log(dir: &std::path::Path, config: &str) -> String {
    let mut python = Command::new("python3");
    python
        .args(["-m", "RNS.Utilities.rnsd"])
        .env("PYTHONUNBUFFERED", "1");
    startup_log_of(python, dir, config)
}

/// `rnsd_startup_log` for the rnsd that `rnsd` runs.
fn startup_log_of(mut rnsd: Command, dir: &std::path::Path, config: &str) -> String {
    fs::write(dir.join("config"), config).unwrap();
    let log = dir.join("rnsd.log");
    let mut child = rnsd
        .args(["--config", dir.to_str().unwrap()])
        .env("HOME", dir)
        .stdin(Stdio::null())
        .stdout(fs::File::create(&log).unwrap())
        .stderr(Stdio::null())
        .spawn()
        .expect("start rnsd");
    let deadline = Instant::now() + Duration::from_secs(30);
    let output = loop {
        let output = fs::read_to_string(&log).unwrap_or_default();
        if output.contains("Started rnsd version") || Instant::now() >= deadline {
            break output;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("rnsd exited with {status}:\n{output}");
        }
        thread::sleep(Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();
    output
}

/// The messages `log` holds at the level named `level`.
fn log_messages(log: &str, level: &str) -> Vec<String> {
    let tag = format!("] [{level}]");
    log.lines()
        .filter_map(|line| line.split_once(tag.as_str()).map(|(_, msg)| msg))
        .map(|msg| msg.trim_start().to_string())
        .collect()
}

/// The notice messages of `log` other than the version line.
fn management_notices_of(log: &str) -> Vec<String> {
    log_messages(log, "Notice")
        .into_iter()
        .filter(|msg| !msg.starts_with("Started rnsd version"))
        .collect()
}

/// Starts a transport rnsd with probes and remote management on `dir`, waits
/// for it to finish starting, stops it and returns its notice messages other
/// than the version line.
fn management_notices(dir: &std::path::Path) -> Vec<String> {
    management_notices_of(&rnsd_startup_log(dir, &management_config(4, "")))
}

/// A transport instance announces its probe responder and remote management
/// destinations with upstream's notice lines, and takes its transport
/// identity from storage/transport_identity as upstream does.
#[test]
fn rnsd_logs_its_management_destinations_as_upstream() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("storage")).unwrap();
    fs::write(
        dir.path().join("storage/transport_identity"),
        transport_identity_key(),
    )
    .unwrap();
    assert_eq!(management_notices(dir.path()), MANAGEMENT_NOTICES);
}

/// A config directory that only holds the node identity rns-rs kept before
/// (storage/identities/identity) keeps it as the transport identity and
/// gains storage/transport_identity.
#[test]
fn rnsd_carries_the_node_identity_over_to_transport_identity() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("storage/identities")).unwrap();
    fs::write(
        dir.path().join("storage/identities/identity"),
        transport_identity_key(),
    )
    .unwrap();
    assert_eq!(management_notices(dir.path()), MANAGEMENT_NOTICES);
    assert_eq!(
        fs::read(dir.path().join("storage/transport_identity")).unwrap(),
        transport_identity_key()
    );
}

/// With `network_identity` configured, the transport identity still comes
/// from storage/transport_identity, and the network identity is created at
/// the configured path, after `~` expansion, then loaded from it, with
/// upstream's log lines.
#[test]
fn rnsd_keeps_the_network_identity_apart_from_the_transport_identity() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("storage")).unwrap();
    fs::write(
        dir.path().join("storage/transport_identity"),
        transport_identity_key(),
    )
    .unwrap();
    let network_identity_path = dir.path().join("network_identity");
    let config = management_config(5, "  network_identity = ~/network_identity\n");

    let log = rnsd_startup_log(dir.path(), &config);
    assert_eq!(management_notices_of(&log), MANAGEMENT_NOTICES, "{log}");
    let generated = format!(
        "Network identity generated and persisted to {}",
        network_identity_path.display()
    );
    assert!(log_messages(&log, "Verbose").contains(&generated), "{log}");
    let network_identity = fs::read(&network_identity_path).unwrap();
    assert_eq!(network_identity.len(), 64);
    assert_ne!(network_identity, transport_identity_key());

    let log = rnsd_startup_log(dir.path(), &config);
    assert_eq!(management_notices_of(&log), MANAGEMENT_NOTICES, "{log}");
    let loaded = format!(
        "Network identity loaded from {}",
        network_identity_path.display()
    );
    assert!(log_messages(&log, "Verbose").contains(&loaded), "{log}");
    assert_eq!(fs::read(&network_identity_path).unwrap(), network_identity);
    assert_eq!(
        fs::read(dir.path().join("storage/transport_identity")).unwrap(),
        transport_identity_key()
    );
}

/// The Verbose messages of `log` about identities, in order, with each
/// `<hash>` replaced by `<A>`, `<B>`, ... in order of first appearance, and
/// the hashes in that order.
fn identity_messages(log: &str) -> (Vec<String>, Vec<String>) {
    letter_hashes(
        log_messages(log, "Verbose")
            .into_iter()
            .filter(|msg| msg.contains("dentity")),
    )
}

/// `messages` with each `<hash>` replaced by `<A>`, `<B>`, ... in order of
/// first appearance, and the hashes in that order.
fn letter_hashes(messages: impl Iterator<Item = String>) -> (Vec<String>, Vec<String>) {
    let mut hashes: Vec<String> = Vec::new();
    let messages = messages
        .map(|msg| {
            let Some((head, rest)) = msg.split_once('<') else {
                return msg;
            };
            let Some((hash, tail)) = rest.split_once('>') else {
                return msg;
            };
            assert!(
                hash.len() == 32
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{msg}"
            );
            let index = hashes.iter().position(|h| h == hash).unwrap_or_else(|| {
                hashes.push(hash.to_string());
                hashes.len() - 1
            });
            format!("{head}<{}>{tail}", (b'A' + index as u8) as char)
        })
        .collect();
    (messages, hashes)
}

/// The hex hash of the identity whose private key is in `path`.
fn identity_file_hash(path: &std::path::Path) -> String {
    let key: [u8; 64] = fs::read(path).unwrap().try_into().unwrap();
    rns_crypto::identity::Identity::from_private_key(&key)
        .hash()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The Verbose messages of rnsd's startup in `log`, up to the known
/// destinations it loads, with `dir` written `<dir>`, the time the load took
/// `<time>`, and hashes lettered as `identity_messages` letters them; and
/// the hashes.
fn startup_messages(log: &str, dir: &std::path::Path) -> (Vec<String>, Vec<String>) {
    let dir = dir.display().to_string();
    let mut messages = Vec::new();
    for msg in log_messages(log, "Verbose") {
        if let Some((loaded, time)) = msg.split_once(" known destinations from storage in ") {
            assert!(time.ends_with("µs") || time.ends_with("ms"), "{log}");
            let (mut messages, hashes) = letter_hashes(messages.into_iter());
            for msg in &mut messages {
                *msg = msg.replace(&dir, "<dir>");
            }
            messages.push(format!(
                "{loaded} known destinations from storage in <time>"
            ));
            return (messages, hashes);
        }
        messages.push(msg);
    }
    panic!("no known destinations loaded:\n{log}")
}

/// rnsd's startup messages: `identities`, then the interfaces, the
/// configuration and the known destinations.
fn startup(identities: &[&str]) -> Vec<String> {
    identities
        .iter()
        .copied()
        .chain([
            "Bringing up system interfaces...",
            "System interfaces are ready",
            "Configuration loaded from <dir>/config",
            "Loaded 0 known destinations from storage in <time>",
        ])
        .map(str::to_string)
        .collect()
}

/// rnsd logs the identities it creates and where its transport identity
/// comes from with upstream's Verbose lines, in upstream 1.6.1's order
/// (25cce0a8, `Transport.ensure_identity` before the interfaces): the
/// network identity, then the transport identity, created when storage holds
/// none, loaded from storage/transport_identity or carried over from the
/// node identity, on an instance without transport the ephemeral identity
/// it uses instead, and the application identity; then the interfaces, the
/// configuration and the known destinations. Where a Python Reticulum 1.6.1
/// is installed, upstream's rnsd logs the same on a directory set up the
/// same way.
#[test]
fn rnsd_logs_its_transport_identity_as_upstream() {
    let non_transport = "[reticulum]\n  enable_transport = No\n  share_instance = No\n\
                         [logging]\n  loglevel = 5\n[interfaces]\n";
    let python = python_reticulum_1_6_1();
    if !python {
        eprintln!("No Python Reticulum 1.6.1; not compared with upstream");
    }
    let upstream = |dir: &std::path::Path, config: &str, expected: &[String]| {
        if python {
            let log = python_rnsd_startup_log(dir, config);
            assert_eq!(startup_messages(&log, dir).0, expected, "{log}");
        }
    };
    let with_stored_transport_identity = || {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("storage")).unwrap();
        fs::write(
            dir.path().join("storage/transport_identity"),
            transport_identity_key(),
        )
        .unwrap();
        dir
    };

    // A new directory: created, then replaced by an ephemeral identity.
    let created = startup(&[
        "No valid Transport Identity in storage, creating...",
        "Identity keys created for <A>",
        "Identity keys created for <B>",
        "Initialized ephemeral transport identity <B>",
        "Identity keys created for <C>",
    ]);
    let dir = tempfile::tempdir().unwrap();
    let python_dir = tempfile::tempdir().unwrap();
    let log = rnsd_startup_log(dir.path(), non_transport);
    let (messages, hashes) = startup_messages(&log, dir.path());
    assert_eq!(messages, created, "{log}");
    assert_eq!(
        hashes[0],
        identity_file_hash(&dir.path().join("storage/transport_identity"))
    );
    let first_ephemeral = hashes[1].clone();
    upstream(python_dir.path(), non_transport, &created);

    // Restarted: loaded, with a new ephemeral identity.
    let restarted = startup(&[
        "Loaded Transport Identity from storage",
        "Identity keys created for <A>",
        "Initialized ephemeral transport identity <A>",
        "Identity keys created for <B>",
    ]);
    let log = rnsd_startup_log(dir.path(), non_transport);
    let (messages, hashes) = startup_messages(&log, dir.path());
    assert_eq!(messages, restarted, "{log}");
    assert_ne!(hashes[0], first_ephemeral);
    upstream(python_dir.path(), non_transport, &restarted);

    // A transport instance uses the stored identity itself.
    let loaded = startup(&[
        "Loaded Transport Identity from storage",
        "Identity keys created for <A>",
    ]);
    let dir = with_stored_transport_identity();
    let log = rnsd_startup_log(dir.path(), &management_config(5, ""));
    assert_eq!(startup_messages(&log, dir.path()).0, loaded, "{log}");
    let python_dir = with_stored_transport_identity();
    upstream(python_dir.path(), &management_config(5, ""), &loaded);

    // The node identity rns-rs kept before is carried over, so loaded.
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("storage/identities")).unwrap();
    fs::write(
        dir.path().join("storage/identities/identity"),
        transport_identity_key(),
    )
    .unwrap();
    let log = rnsd_startup_log(dir.path(), &management_config(5, ""));
    assert_eq!(startup_messages(&log, dir.path()).0, loaded, "{log}");
    assert_eq!(management_notices_of(&log), MANAGEMENT_NOTICES, "{log}");

    // A new network identity comes first, while the config is read.
    let network = management_config(5, "  network_identity = ~/network_identity\n");
    let network_created = startup(&[
        "Identity keys created for <A>",
        "Network identity generated and persisted to <dir>/network_identity",
        "Loaded Transport Identity from storage",
        "Identity keys created for <B>",
    ]);
    let log = rnsd_startup_log(dir.path(), &network);
    let (messages, hashes) = startup_messages(&log, dir.path());
    assert_eq!(messages, network_created, "{log}");
    assert_eq!(
        hashes[0],
        identity_file_hash(&dir.path().join("network_identity"))
    );
    upstream(python_dir.path(), &network, &network_created);
}

/// The hash of `rnstransport.network` for the network identity whose
/// private key is `TRANSPORT_IDENTITY`.
fn network_destination_hash() -> String {
    let identity = rns_crypto::identity::Identity::from_private_key(
        &transport_identity_key().try_into().unwrap(),
    );
    rns_core::destination::destination_hash("rnstransport", &["network"], Some(identity.hash()))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Starts rnsd on `dir` with `config`, logging to `dir/rnsd.log`.
fn spawn_rnsd(dir: &std::path::Path, config: &str) -> std::process::Child {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("config"), config).unwrap();
    Command::new(env!("CARGO_BIN_EXE_rnsd"))
        .args(["--config", dir.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(fs::File::create(dir.join("rnsd.log")).unwrap())
        .stderr(Stdio::null())
        .spawn()
        .expect("start rnsd")
}

/// Waits until a socket named `name` listens in the abstract namespace.
fn wait_for_abstract_socket(name: &str) {
    let needle = format!("@{name}");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !fs::read_to_string("/proc/net/unix")
        .unwrap_or_default()
        .lines()
        .any(|line| line.split_whitespace().last() == Some(needle.as_str()))
    {
        assert!(Instant::now() < deadline, "nothing listens on {needle}");
        thread::sleep(Duration::from_millis(50));
    }
}

fn enforcing_instance_name() -> String {
    format!("enforcing-{}", std::process::id())
}

/// Asks the shared instance on `instance_dir` over RPC to request a path to
/// `destination` itself.
fn instance_request_path(instance_dir: &std::path::Path, destination: &str) {
    let key = fs::read(instance_dir.join("storage/transport_identity")).unwrap();
    let auth_key = rns_net::rpc::derive_auth_key(&key);
    let address = rns_net::rpc::RpcAddr::local(enforcing_instance_name(), 37429);
    let hash: Vec<u8> = (0..destination.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&destination[i..i + 2], 16).unwrap())
        .collect();
    let mut client = rns_net::rpc::RpcClient::connect(&address, &auth_key).expect("connect to RPC");
    client
        .call(&rns_net::pickle::PickleValue::Dict(vec![(
            rns_net::pickle::PickleValue::String("request_path".into()),
            rns_net::pickle::PickleValue::Bytes(hash),
        )]))
        .expect("request_path over RPC");
}

/// A publisher rnsd with a network identity, serving TCP, and a shared
/// instance that dials it and enforces stamps, on `root`. Returns both
/// processes, the instance's config directory and the publisher's
/// `rnstransport.network` destination.
fn enforcing_instance_with_publisher(
    root: &std::path::Path,
) -> ([std::process::Child; 2], std::path::PathBuf, String) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let stamps = "[stamps]\n  enforce_stamps = Yes\n  destination_value = 8\n  \
                  destination_cost = 8\n  pr_value = 8\n  pr_cost = 8\n\n";
    let network_identity = root.join("network_identity");
    fs::write(&network_identity, transport_identity_key()).unwrap();
    let publisher = spawn_rnsd(
        &root.join("publisher"),
        &format!(
            "{stamps}[reticulum]\n  enable_transport = No\n  share_instance = No\n  \
             network_identity = {}\n\
             [logging]\n  loglevel = 4\n\
             [interfaces]\n  [[server]]\n    type = TCPServerInterface\n    \
             enabled = Yes\n    listen_ip = 127.0.0.1\n    listen_port = {port}\n",
            network_identity.display()
        ),
    );
    let instance = enforcing_instance_name();
    let instance_dir = root.join("instance");
    let receiver = spawn_rnsd(
        &instance_dir,
        &format!(
            "{stamps}[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
             instance_name = {instance}\n\
             [logging]\n  loglevel = 4\n\
             [interfaces]\n  [[client]]\n    type = TCPClientInterface\n    \
             enabled = Yes\n    target_host = 127.0.0.1\n    target_port = {port}\n"
        ),
    );
    wait_for_abstract_socket(&format!("rns/{instance}/rpc"));
    (
        [publisher, receiver],
        instance_dir,
        network_destination_hash(),
    )
}

/// The last line rnpath printed, after its spinner.
fn final_line(stdout: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    stdout
        .trim_end()
        .rsplit(['\r', '\n'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// rnpath, a client of a shared instance that enforces stamps, learns a
/// path through it. Its path request carries its transport identity hash,
/// so the stamp after it is read as one; without it the stamped request
/// had the length of an unstamped one and the instance dropped it.
#[cfg(target_os = "linux")]
#[test]
fn rnpath_finds_a_path_through_a_stamp_enforcing_instance() {
    let root = tempfile::tempdir().unwrap();
    let (mut daemons, instance_dir, destination) = enforcing_instance_with_publisher(root.path());
    let config = instance_dir.to_str().unwrap();
    // Once the instance holds the path, which it requests itself, a new
    // client only learns it by asking the instance.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut requested = Instant::now() - Duration::from_secs(10);
    loop {
        if requested.elapsed() >= Duration::from_secs(2) {
            instance_request_path(&instance_dir, &destination);
            requested = Instant::now();
        }
        let table = Command::new(env!("CARGO_BIN_EXE_rnpath"))
            .args(["--config", config, "-t"])
            .output()
            .expect("run rnpath -t");
        if String::from_utf8_lossy(&table.stdout).contains(&format!("<{destination}>")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the instance never learned {destination}:\n{}",
            fs::read_to_string(instance_dir.join("rnsd.log")).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(250));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_rnpath"))
        .args(["--config", config, "-w", "5", &destination])
        .output()
        .expect("run rnpath");
    // Upstream's rnpath is the reference, where a Python Reticulum that
    // stamps its path requests (1.6.1) is installed.
    let python = python_reticulum_1_6_1().then(|| {
        Command::new("python3")
            .args([
                "-m",
                "RNS.Utilities.rnpath",
                "--config",
                config,
                "-w",
                "5",
                &destination,
            ])
            .env("PYTHONUNBUFFERED", "1")
            .output()
            .expect("run Python rnpath")
    });
    for daemon in &mut daemons {
        let _ = daemon.kill();
        let _ = daemon.wait();
    }
    assert!(
        final_line(&output.stdout).starts_with(&format!(
            "Path found, destination <{destination}> is 1 hop away"
        )),
        "{}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        fs::read_to_string(instance_dir.join("rnsd.log")).unwrap_or_default(),
        fs::read_to_string(root.path().join("publisher/rnsd.log")).unwrap_or_default()
    );
    match python {
        Some(python) => assert_eq!(
            final_line(&output.stdout),
            final_line(&python.stdout),
            "{}",
            String::from_utf8_lossy(&python.stderr)
        ),
        None => eprintln!("No Python Reticulum 1.6.1; not compared with upstream"),
    }
}

/// Whether a Python Reticulum that stamps its path requests (1.6.1) is
/// installed, to compare with upstream's utilities.
fn python_reticulum_1_6_1() -> bool {
    Command::new("python3")
        .args([
            "-c",
            "import RNS; print(getattr(RNS.Transport, 'STAMP_PRS', False))",
        ])
        .output()
        .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).trim() == "True")
}

/// rnpath finds a destination the shared instance hosts itself, such as
/// its `rnstransport.network`, 0 hops away via the instance's transport
/// identity on the shared instance interface, as upstream's instance
/// answers from `Transport.destinations_map`.
#[cfg(target_os = "linux")]
#[test]
fn rnpath_finds_the_instance_s_own_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let instance = format!("own-destinations-{}", std::process::id());
    let network_identity = dir.path().join("network_identity");
    fs::write(&network_identity, transport_identity_key()).unwrap();
    // The instance answers with its stamped path-response announce. At the
    // default 25-bit target the stamp search outlasted rnpath's wait on a
    // busy CI runner; the config cannot turn stamping off, so the target is
    // kept low enough to grind at once.
    let mut rnsd = spawn_rnsd(
        dir.path(),
        &format!(
            "[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
             instance_name = {instance}\n  network_identity = {}\n\
             [stamps]\n  destination_value = 8\n  destination_cost = 8\n\
             [logging]\n  loglevel = 4\n[interfaces]\n",
            network_identity.display()
        ),
    );
    wait_for_abstract_socket(&format!("rns/{instance}/rpc"));
    let destination = network_destination_hash();
    let config = dir.path().to_str().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rnpath"))
        .args(["--config", config, "-w", "10", &destination])
        .output()
        .expect("run rnpath");
    let python = python_reticulum_1_6_1().then(|| {
        Command::new("python3")
            .args([
                "-m",
                "RNS.Utilities.rnpath",
                "--config",
                config,
                "-w",
                "10",
                &destination,
            ])
            .env("PYTHONUNBUFFERED", "1")
            .output()
            .expect("run Python rnpath")
    });
    let _ = rnsd.kill();
    let _ = rnsd.wait();
    let found = final_line(&output.stdout);
    let prefix = format!("Path found, destination <{destination}> is 0 hops away via <");
    let suffix = format!("> on Shared Instance[rns/{instance}]");
    assert!(
        found.starts_with(&prefix) && found.ends_with(&suffix),
        "{found}\n{}",
        fs::read_to_string(dir.path().join("rnsd.log")).unwrap_or_default()
    );
    match python {
        Some(python) => assert_eq!(found, final_line(&python.stdout)),
        None => eprintln!("No Python Reticulum 1.6.1; not compared with upstream"),
    }
}

/// The startup messages about the configuration and identities in a
/// utility's output, logged as upstream's `RNS.log` lines
/// (`[time] [Verbose]  message`), with hashes normalized as
/// `identity_messages` does.
fn client_startup_messages(output: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(output);
    let log: String = text
        .lines()
        .filter(|line| line.starts_with('[') && line.contains("] [Verbose]  "))
        .map(|line| format!("{line}\n"))
        .collect();
    let (messages, _) = identity_messages(&log);
    let config = log_messages(&log, "Verbose")
        .into_iter()
        .filter(|msg| msg.starts_with("Configuration loaded from"));
    config.chain(messages).collect()
}

/// A shared instance client logs upstream's startup lines at Verbose, as
/// upstream's client runs Transport.start: the network identity and the
/// configuration, the stored transport identity, the ephemeral one it uses
/// instead, and its application identity.
#[cfg(target_os = "linux")]
#[test]
fn shared_clients_log_their_identities_as_upstream() {
    let dir = tempfile::tempdir().unwrap();
    let instance = format!("client-identities-{}", std::process::id());
    let network_identity = dir.path().join("network_identity");
    fs::write(&network_identity, transport_identity_key()).unwrap();
    let mut rnsd = spawn_rnsd(
        dir.path(),
        &format!(
            "[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
             instance_name = {instance}\n  network_identity = {}\n\
             [logging]\n  loglevel = 4\n[interfaces]\n",
            network_identity.display()
        ),
    );
    wait_for_abstract_socket(&format!("rns/{instance}/rpc"));
    let config = dir.path().to_str().unwrap();
    let rust = Command::new(env!("CARGO_BIN_EXE_rnstatus"))
        .args(["--config", config, "-vv"])
        .output()
        .expect("run rnstatus");
    let python = python_reticulum_1_6_1().then(|| {
        Command::new("python3")
            .args(["-m", "RNS.Utilities.rnstatus", "--config", config, "-vv"])
            .env("PYTHONUNBUFFERED", "1")
            .output()
            .expect("run Python rnstatus")
    });
    let _ = rnsd.kill();
    let _ = rnsd.wait();
    let messages = client_startup_messages(&rust.stdout);
    assert_eq!(
        messages,
        [
            format!(
                "Configuration loaded from {}",
                dir.path().join("config").display()
            ),
            format!(
                "Network identity loaded from {}",
                network_identity.display()
            ),
            "Loaded Transport Identity from storage".into(),
            "Identity keys created for <A>".into(),
            "Initialized ephemeral transport identity <A>".into(),
            "Identity keys created for <B>".into(),
        ],
        "{}",
        String::from_utf8_lossy(&rust.stderr)
    );
    // Nothing else at Verbose: upstream's client logs its connection to the
    // instance only at Debug.
    let verbose = |output: &[u8]| -> Vec<String> {
        log_messages(&String::from_utf8_lossy(output), "Verbose")
            .into_iter()
            .map(|msg| msg.split('<').next().unwrap_or_default().to_string())
            .collect()
    };
    // As upstream 1.6.1 (25cce0a8), the transport identities come before
    // "Configuration loaded".
    let order = verbose(&rust.stdout);
    let position = |prefix: &str| order.iter().position(|msg| msg.starts_with(prefix));
    assert!(
        position("Initialized ephemeral transport identity")
            < position("Configuration loaded from"),
        "{order:?}"
    );
    assert!(
        !verbose(&rust.stdout)
            .iter()
            .any(|msg| msg.contains("interface online") || msg.contains("Connected to")),
        "{}",
        String::from_utf8_lossy(&rust.stdout)
    );
    match python {
        Some(python) => {
            assert_eq!(messages, client_startup_messages(&python.stdout));
            assert_eq!(verbose(&rust.stdout), verbose(&python.stdout));
        }
        None => eprintln!("No Python Reticulum 1.6.1; not compared with upstream"),
    }
}

/// The `[Level]  message` lines of a utility's Python-style output, with
/// timestamps and spinners dropped.
fn utility_log_lines(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .split(['\r', '\n'])
        .filter_map(|line| {
            let rest = line.strip_prefix('[')?;
            let (_, message) = rest.split_once("] ")?;
            message.starts_with('[').then(|| message.to_string())
        })
        .collect()
}

/// rncp logs the identity it creates as upstream's does: "Identity keys
/// created" at Verbose after "No valid saved identity found" at Info, so
/// only from -vv on.
#[cfg(target_os = "linux")]
#[test]
fn rncp_logs_the_identity_it_creates_as_upstream() {
    let dir = tempfile::tempdir().unwrap();
    let instance = format!("rncp-identity-{}", std::process::id());
    let mut rnsd = spawn_rnsd(
        dir.path(),
        &format!(
            "[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
             instance_name = {instance}\n[logging]\n  loglevel = 4\n[interfaces]\n"
        ),
    );
    wait_for_abstract_socket(&format!("rns/{instance}/rpc"));
    let file = dir.path().join("file.txt");
    fs::write(&file, b"payload").unwrap();
    let identity = dir.path().join("storage/identities/rncp");
    let rncp = |verbosity: &[&str]| {
        let _ = fs::remove_file(&identity);
        Command::new(env!("CARGO_BIN_EXE_rncp"))
            .args(["--config", dir.path().to_str().unwrap(), "-w", "1"])
            .args(verbosity)
            .arg(&file)
            .arg("00112233445566778899aabbccddeeff")
            .output()
            .expect("run rncp")
    };
    let quiet = rncp(&[]);
    let verbose = rncp(&["-vv"]);
    let _ = rnsd.kill();
    let _ = rnsd.wait();

    assert!(
        !String::from_utf8_lossy(&quiet.stdout).contains("Identity keys created"),
        "{}",
        String::from_utf8_lossy(&quiet.stdout)
    );
    let lines = utility_log_lines(&verbose.stdout);
    let created = lines
        .iter()
        .position(|line| line == "[Info]     No valid saved identity found, creating new...")
        .unwrap_or_else(|| panic!("{lines:?}"));
    assert_eq!(
        lines.get(created + 1),
        Some(&format!(
            "[Verbose]  Identity keys created for <{}>",
            identity_file_hash(&identity)
        )),
        "{lines:?}"
    );
}

/// rnpath starts a Reticulum client for its table modes too, as upstream's
/// does, so `-t -vv` logs the client's startup.
#[cfg(target_os = "linux")]
#[test]
fn rnpath_table_mode_starts_a_client_as_upstream() {
    let dir = tempfile::tempdir().unwrap();
    let instance = format!("rnpath-table-{}", std::process::id());
    let mut rnsd = spawn_rnsd(
        dir.path(),
        &format!(
            "[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
             instance_name = {instance}\n[logging]\n  loglevel = 4\n[interfaces]\n"
        ),
    );
    wait_for_abstract_socket(&format!("rns/{instance}/rpc"));
    let config = dir.path().to_str().unwrap();
    let rust = Command::new(env!("CARGO_BIN_EXE_rnpath"))
        .args(["--config", config, "-vv", "-t"])
        .output()
        .expect("run rnpath");
    let python = python_reticulum_1_6_1().then(|| {
        Command::new("python3")
            .args([
                "-m",
                "RNS.Utilities.rnpath",
                "--config",
                config,
                "-vv",
                "-t",
            ])
            .env("PYTHONUNBUFFERED", "1")
            .output()
            .expect("run Python rnpath")
    });
    let _ = rnsd.kill();
    let _ = rnsd.wait();
    let messages = client_startup_messages(&rust.stdout);
    assert_eq!(
        messages[1..],
        [
            "Loaded Transport Identity from storage",
            "Identity keys created for <A>",
            "Initialized ephemeral transport identity <A>",
            "Identity keys created for <B>",
        ],
        "{}",
        String::from_utf8_lossy(&rust.stdout)
    );
    match python {
        Some(python) => assert_eq!(messages, client_startup_messages(&python.stdout)),
        None => eprintln!("No Python Reticulum 1.6.1; not compared with upstream"),
    }
}
