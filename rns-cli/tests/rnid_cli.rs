use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use rns_core::destination::destination_hash;
use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::{Callbacks, QueryRequest, QueryResponse, RnsNode};

struct NoopCallbacks;

impl Callbacks for NoopCallbacks {
    fn on_announce(&mut self, _announced: rns_net::AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: rns_net::DestHash, _hops: u8) {}

    fn on_local_delivery(
        &mut self,
        _dest_hash: rns_net::DestHash,
        _raw: Vec<u8>,
        _packet_hash: rns_net::PacketHash,
    ) {
    }
}

fn rnid(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rnid"))
        .args(args)
        .output()
        .expect("run rnid")
}

fn assert_success(output: Output) -> String {
    if !output.status.success() {
        panic!(
            "rnid failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A shared instance of its own name: the RPC client tries the abstract
/// socket `\0rns/<instance_name>/rpc` first, so tests running side by side
/// must not share one.
fn write_daemon_config(dir: &Path, rpc_port: u16) {
    fs::write(
        dir.join("config"),
        format!(
            r#"
[reticulum]
enable_transport = False
share_instance = Yes
instance_name = rnid-test-{rpc_port}
instance_control_port = {rpc_port}

# rnid stamps its announce (upstream 51fa8413) and exits 0.25 s after
# queueing it, as upstream's does; a cheap stamp is found in time.
[stamps]
destination_value = 2
destination_cost = 2

[interfaces]
"#
        ),
    )
    .unwrap();
}

fn wait_for_rpc(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // Where the daemon serves RPC: its abstract socket on Linux.
        let addr = rns_net::RpcAddr::local(format!("rnid-test-{port}"), port);
        if addr.accepts_connections().is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for rnsd RPC on {}",
            port
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn inject_identity(node: &RnsNode, dest_hash: [u8; 16], identity: &Identity) {
    let response = node
        .query(QueryRequest::InjectIdentity {
            dest_hash,
            identity_hash: *identity.hash(),
            public_key: identity.get_public_key().unwrap(),
            app_data: None,
            hops: 1,
            received_at: 1.0,
        })
        .unwrap();
    assert!(matches!(response, QueryResponse::InjectIdentity(true)));
}

/// Wait for the instance's periodic flush to write `dest_hash` to its
/// known destinations database, which shared instance clients read.
fn wait_for_flush(dir: &Path, dest_hash: [u8; 16]) {
    let db = dir.join("storage").join("known_destinations.db");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let flushed = rns_net::storage_sqlite::KnownDestinationsStore::open_read_only(&db, 16)
            .and_then(|store| store.load_all())
            .is_ok_and(|entries| entries.iter().any(|(hash, _)| *hash == dest_hash));
        if flushed {
            return;
        }
        assert!(Instant::now() < deadline, "known destination never flushed");
        thread::sleep(Duration::from_millis(250));
    }
}

fn write_private_identity(path: &Path, identity: &Identity) {
    fs::write(path, identity.get_private_key().unwrap()).unwrap();
}

/// Lines `RNS.log` writes: `[YYYY-MM-DD HH:MM:SS] ...`.
fn is_log_line(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() > 22
        && b[0] == b'['
        && b[1..5].iter().all(u8::is_ascii_digit)
        && b[5] == b'-'
        && b[20] == b']'
}

fn normalize(stdout: &str, root: &str) -> String {
    stdout
        .replace(root, "ROOT")
        .split_inclusive('\n')
        .filter(|line| !is_log_line(line))
        .collect()
}

fn snapshot(root: &Path) -> serde_json::Map<String, serde_json::Value> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if rel == "cfg" || rel == ".reticulum" {
                continue;
            }
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                let data = fs::read(&path).unwrap();
                let value = if rel.ends_with(".rfe") {
                    format!("size:{}", data.len())
                } else {
                    hex(&rns_crypto::sha256::sha256(&data))
                };
                out.push((rel, value));
            }
        }
    }
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort();
    files
        .into_iter()
        .map(|(k, v)| (k, serde_json::Value::String(v)))
        .collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Every case `tests/generate_rnid_fixtures.py` recorded from upstream's
/// rnid: the same stdout and exit code at every step, and the same files
/// left behind.
#[test]
fn rnid_matches_upstream() {
    let fixture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/rnid/cases.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut failures = Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        let dir = tempdir();
        let root = dir.path().canonicalize().unwrap();
        for (rel, data) in fixture["files"].as_object().unwrap() {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, unhex(data.as_str().unwrap())).unwrap();
        }
        let root_s = path_str(&root);
        for step in case["steps"].as_array().unwrap() {
            let argv: Vec<&str> = step["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            let out = Command::new(env!("CARGO_BIN_EXE_rnid"))
                .args(&argv)
                .current_dir(&root)
                .env("HOME", &root)
                .env("COLUMNS", "80")
                .env_remove("RUST_LOG")
                .output()
                .unwrap();
            let stdout = normalize(&String::from_utf8_lossy(&out.stdout), &root_s);
            let expected = step["stdout"].as_str().unwrap();
            let code = out.status.code();
            let expected_code = step["code"].as_i64().map(|c| c as i32);
            if stdout != expected || code != expected_code {
                failures.push(format!(
                    "{argv:?}\n  expected ({expected_code:?}): {expected:?}\n  got      ({code:?}): {stdout:?}\n  stderr: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
        }
        let files = snapshot(&root);
        if serde_json::Value::Object(files.clone()) != case["files"] {
            failures.push(format!(
                "{}\n  files expected: {}\n  files got:      {:?}",
                case["steps"][0]["argv"], case["files"], files
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} differences from upstream:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn request_identity_over_rpc_encrypts_and_retains_all_matching_destinations() {
    let dir = tempdir();
    let rpc_port = free_port();
    write_daemon_config(dir.path(), rpc_port);
    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    wait_for_rpc(rpc_port);

    let identity = Identity::new(&mut OsRng);
    let identity_hash = *identity.hash();
    let primary_dest = destination_hash("rns", &["id"], Some(&identity_hash));
    let secondary_dest = [0xA7; 16];
    inject_identity(&node, primary_dest, &identity);
    inject_identity(&node, secondary_dest, &identity);
    wait_for_flush(dir.path(), primary_dest);
    wait_for_flush(dir.path(), secondary_dest);

    let message = dir.path().join("network-secret.txt");
    let encrypted = dir.path().join("network-secret.txt.rfe");
    let decrypted = dir.path().join("network-secret.out");
    let private_rid = dir.path().join("network-private.rid");
    fs::write(&message, b"daemon resolved public identity").unwrap();
    write_private_identity(&private_rid, &identity);

    let config_dir = path_str(dir.path());
    let message_s = path_str(&message);
    let encrypted_s = path_str(&encrypted);
    let decrypted_s = path_str(&decrypted);
    let private_rid_s = path_str(&private_rid);
    let stdout = assert_success(rnid(&[
        "--config",
        &config_dir,
        "-R",
        "-i",
        &hex(&identity_hash),
        "-e",
        &message_s,
    ]));
    assert!(
        stdout.contains(&format!("Recalled Identity <{}>", hex(&identity_hash))),
        "{stdout}"
    );
    assert!(encrypted.exists());

    assert_success(rnid(&[
        "-i",
        &private_rid_s,
        "-d",
        &encrypted_s,
        "-w",
        &decrypted_s,
    ]));
    assert_eq!(
        fs::read(&decrypted).unwrap(),
        b"daemon resolved public identity"
    );

    let entries = node.known_destinations().unwrap();
    let retained_for_identity = entries
        .iter()
        .filter(|entry| entry.identity_hash == identity_hash && entry.retained)
        .count();
    assert_eq!(
        retained_for_identity, 2,
        "rnid should retain every known destination for the resolved identity"
    );

    node.shutdown();
}

#[test]
fn request_identity_over_rpc_validates_required_signer_by_destination_hash() {
    let dir = tempdir();
    let rpc_port = free_port();
    write_daemon_config(dir.path(), rpc_port);
    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    wait_for_rpc(rpc_port);

    let identity = Identity::new(&mut OsRng);
    let identity_hash = *identity.hash();
    let dest_hash = destination_hash("rns", &["id"], Some(&identity_hash));
    inject_identity(&node, dest_hash, &identity);
    wait_for_flush(dir.path(), dest_hash);

    let private_rid = dir.path().join("signer.rid");
    let message = dir.path().join("required-signer.txt");
    write_private_identity(&private_rid, &identity);
    fs::write(&message, b"destination hash signer lookup").unwrap();

    let private_rid_s = path_str(&private_rid);
    let message_s = path_str(&message);
    assert_success(rnid(&["-i", &private_rid_s, "-s", &message_s]));
    let sig = dir.path().join("required-signer.txt.rsg");

    assert_success(rnid(&[
        "--config",
        &path_str(dir.path()),
        "-R",
        "-i",
        &hex(&dest_hash),
        "-V",
        &path_str(&sig),
    ]));

    let entry = node
        .known_destinations()
        .unwrap()
        .into_iter()
        .find(|entry| entry.dest_hash == dest_hash)
        .expect("injected destination should still be known");
    assert!(entry.retained);

    node.shutdown();
}

struct AnnounceRecorder(std::sync::mpsc::Sender<[u8; 16]>);

impl Callbacks for AnnounceRecorder {
    fn on_announce(&mut self, announced: rns_net::AnnouncedIdentity) {
        let _ = self.0.send(announced.dest_hash.0);
    }

    fn on_path_updated(&mut self, _dest_hash: rns_net::DestHash, _hops: u8) {}

    fn on_local_delivery(
        &mut self,
        _dest_hash: rns_net::DestHash,
        _raw: Vec<u8>,
        _packet_hash: rns_net::PacketHash,
    ) {
    }
}

#[test]
fn announce_sends_the_identity_destination_through_the_shared_instance() {
    let dir = tempdir();
    let rpc_port = free_port();
    write_daemon_config(dir.path(), rpc_port);
    let (tx, rx) = std::sync::mpsc::channel();
    let _node = RnsNode::from_config(Some(dir.path()), Box::new(AnnounceRecorder(tx))).unwrap();
    wait_for_rpc(rpc_port);

    let identity = Identity::new(&mut OsRng);
    let private_rid = dir.path().join("announcer.rid");
    write_private_identity(&private_rid, &identity);
    let config_dir = path_str(dir.path());
    let private_rid_s = path_str(&private_rid);

    for (aspects, app, rest) in [
        (None, "rns", vec!["id"]),
        (Some("example.service.v1"), "example", vec!["service", "v1"]),
    ] {
        let mut args = vec!["--config", &config_dir, "-i", &private_rid_s, "-a"];
        if let Some(aspects) = aspects {
            args.push(aspects);
        }
        let stdout = assert_success(rnid(&args));
        let dest = destination_hash(app, &rest, Some(identity.hash()));
        assert!(
            stdout.contains(&format!(
                "Announcing {} destination <{}> for identity <{}>",
                aspects.unwrap_or("rns.id"),
                hex(&dest),
                hex(identity.hash())
            )),
            "{stdout}"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(announced) if announced == dest => break,
                Ok(_) => continue,
                Err(_) => panic!("announce for {} not seen", hex(&dest)),
            }
        }
    }
}
