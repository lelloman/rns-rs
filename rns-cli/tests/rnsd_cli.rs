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

/// Starts a transport rnsd with probes and remote management on `dir`, waits
/// for it to finish starting, stops it and returns its notice messages other
/// than the version line.
fn management_notices(dir: &std::path::Path) -> Vec<String> {
    fs::write(
        dir.join("config"),
        "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n  \
         respond_to_probes = Yes\n  enable_remote_management = Yes\n\
         [logging]\n  loglevel = 4\n[interfaces]\n",
    )
    .unwrap();
    let log = dir.join("rnsd.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rnsd"))
        .args(["--config", dir.to_str().unwrap()])
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
        .lines()
        .filter_map(|line| line.split_once("] [Notice]   ").map(|(_, msg)| msg))
        .filter(|msg| !msg.starts_with("Started rnsd version"))
        .map(str::to_string)
        .collect()
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
