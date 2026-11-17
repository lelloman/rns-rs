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
