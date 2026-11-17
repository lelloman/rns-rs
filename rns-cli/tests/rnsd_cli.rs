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
    fs::write(dir.join("config"), config).unwrap();
    let log = dir.join("rnsd.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rnsd"))
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

/// The Verbose messages of `log` about the transport identity, in order.
fn transport_identity_messages(log: &str) -> Vec<String> {
    log_messages(log, "Verbose")
        .into_iter()
        .filter(|msg| msg.contains("Transport Identity") || msg.contains("transport identity"))
        .collect()
}

/// rnsd logs where its transport identity comes from with upstream's
/// Verbose lines: created when storage holds none, loaded from
/// storage/transport_identity or carried over from the node identity, and,
/// on an instance without transport, the ephemeral identity it uses
/// instead.
#[test]
fn rnsd_logs_its_transport_identity_as_upstream() {
    let non_transport = "[reticulum]\n  enable_transport = No\n  share_instance = No\n\
                         [logging]\n  loglevel = 5\n[interfaces]\n";
    let ephemeral = |msg: &str| -> bool {
        let Some(hash) = msg
            .strip_prefix("Initialized ephemeral transport identity <")
            .and_then(|rest| rest.strip_suffix('>'))
        else {
            return false;
        };
        hash.len() == 32
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };

    // A new directory: created, then replaced by an ephemeral identity.
    let dir = tempfile::tempdir().unwrap();
    let log = rnsd_startup_log(dir.path(), non_transport);
    let messages = transport_identity_messages(&log);
    assert_eq!(messages.len(), 2, "{log}");
    assert_eq!(
        messages[0], "No valid Transport Identity in storage, creating...",
        "{log}"
    );
    assert!(ephemeral(&messages[1]), "{log}");
    let first_ephemeral = messages[1].clone();

    // Restarted: loaded, with a new ephemeral identity.
    let log = rnsd_startup_log(dir.path(), non_transport);
    let messages = transport_identity_messages(&log);
    assert_eq!(messages.len(), 2, "{log}");
    assert_eq!(
        messages[0], "Loaded Transport Identity from storage",
        "{log}"
    );
    assert!(ephemeral(&messages[1]), "{log}");
    assert_ne!(messages[1], first_ephemeral);

    // A transport instance uses the stored identity itself.
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("storage")).unwrap();
    fs::write(
        dir.path().join("storage/transport_identity"),
        transport_identity_key(),
    )
    .unwrap();
    let log = rnsd_startup_log(dir.path(), &management_config(5, ""));
    assert_eq!(
        transport_identity_messages(&log),
        ["Loaded Transport Identity from storage"],
        "{log}"
    );

    // The node identity rns-rs kept before is carried over, so loaded.
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("storage/identities")).unwrap();
    fs::write(
        dir.path().join("storage/identities/identity"),
        transport_identity_key(),
    )
    .unwrap();
    let log = rnsd_startup_log(dir.path(), &management_config(5, ""));
    assert_eq!(
        transport_identity_messages(&log),
        ["Loaded Transport Identity from storage"],
        "{log}"
    );
    assert_eq!(management_notices_of(&log), MANAGEMENT_NOTICES, "{log}");
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
    let instance = format!("enforcing-{}", std::process::id());
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
    // Once the instance holds the path, from the publisher's announce, a
    // new client only learns it by asking the instance.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
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
    let stamping_python = Command::new("python3")
        .args([
            "-c",
            "import RNS; print(getattr(RNS.Transport, 'STAMP_PRS', False))",
        ])
        .output()
        .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).trim() == "True");
    let python = stamping_python.then(|| {
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
