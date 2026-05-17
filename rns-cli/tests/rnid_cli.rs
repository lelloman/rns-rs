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

fn assert_failure(output: Output) -> String {
    if output.status.success() {
        panic!(
            "rnid unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn last_hex_line(stdout: &str, bytes: usize) -> String {
    stdout
        .lines()
        .map(str::trim)
        .find(|line| line.len() == bytes * 2 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("no {}-byte hex line in:\n{}", bytes, stdout))
        .to_string()
}

fn identity_hash_from_output(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| {
            let (_, rhs) = line.split_once(':')?;
            let value = rhs.trim();
            if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
                Some(value.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("no identity hash in:\n{}", stdout))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn rsg_ascii_block(stdout: &str) -> String {
    let mut block = Vec::new();
    let mut in_block = false;
    for line in stdout.lines() {
        if line.starts_with("#### Start of rsg data ") {
            in_block = true;
        }
        if in_block {
            block.push(line);
        }
        if line.ends_with(" End of rsg data ####") {
            break;
        }
    }
    assert!(!block.is_empty(), "no wrapped rsg block in:\n{}", stdout);
    block.join("\n")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_daemon_config(dir: &Path, rpc_port: u16) {
    fs::write(
        dir.join("config"),
        format!(
            r#"
[reticulum]
enable_transport = False
share_instance = Yes
instance_control_port = {}

[interfaces]
"#,
            rpc_port
        ),
    )
    .unwrap();
}

fn wait_for_rpc(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
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

fn write_private_identity(path: &Path, identity: &Identity) {
    fs::write(path, identity.get_private_key().unwrap()).unwrap();
}

#[test]
fn public_and_private_identity_import_export_and_write() {
    let dir = tempdir();
    let rid = dir.path().join("alice.rid");
    let rid_s = path_str(&rid);

    let generated = assert_success(rnid(&["-g", &rid_s]));
    assert!(generated.contains("Generated new identity"));
    assert_eq!(fs::read(&rid).unwrap().len(), 64);

    let public_hex = last_hex_line(&assert_success(rnid(&["-i", &rid_s, "-x"])), 64);
    let private_hex = last_hex_line(&assert_success(rnid(&["-i", &rid_s, "-X"])), 64);
    assert_ne!(public_hex, private_hex);

    let public_stem = dir.path().join("alice-public");
    let public_stem_s = path_str(&public_stem);
    assert_success(rnid(&["-m", &public_hex, "-w", &public_stem_s]));
    let public_file = dir.path().join("alice-public.pub");
    assert_eq!(fs::read(&public_file).unwrap().len(), 64);

    let reexported = last_hex_line(
        &assert_success(rnid(&["-m", &path_str(&public_file), "-x"])),
        64,
    );
    assert_eq!(reexported, public_hex);

    let imported_rid = dir.path().join("imported.rid");
    assert_success(rnid(&[
        "-M",
        &private_hex,
        "-X",
        "-w",
        &path_str(&imported_rid),
    ]));
    assert_eq!(fs::read(imported_rid).unwrap().len(), 64);
}

#[test]
fn rsg_sign_validate_and_tamper_detection() {
    let dir = tempdir();
    let rid = dir.path().join("alice.rid");
    let msg = dir.path().join("message.txt");
    let rid_s = path_str(&rid);
    let msg_s = path_str(&msg);
    assert_success(rnid(&["-g", &rid_s]));
    fs::write(&msg, b"hello signed world").unwrap();

    assert_success(rnid(&["-i", &rid_s, "-s", &msg_s]));
    let sig = dir.path().join("message.txt.rsg");
    assert!(fs::read(&sig).unwrap().len() > 64);

    assert_success(rnid(&["-V", &path_str(&sig)]));
    fs::write(&msg, b"tampered").unwrap();
    let failure = assert_failure(rnid(&["-V", &path_str(&sig)]));
    assert!(failure.contains("Invalid signature"));
}

#[test]
fn rsg_validate_accepts_multiple_paths() {
    let dir = tempdir();
    let rid = dir.path().join("alice.rid");
    let msg1 = dir.path().join("message-one.txt");
    let msg2 = dir.path().join("message-two.txt");
    let rid_s = path_str(&rid);
    let msg1_s = path_str(&msg1);
    let msg2_s = path_str(&msg2);
    assert_success(rnid(&["-g", &rid_s]));
    fs::write(&msg1, b"first signed message").unwrap();
    fs::write(&msg2, b"second signed message").unwrap();

    assert_success(rnid(&["-i", &rid_s, "-s", &msg1_s]));
    assert_success(rnid(&["-i", &rid_s, "-s", &msg2_s]));
    let sig1_s = path_str(&msg1.with_extension("txt.rsg"));
    let sig2_s = path_str(&msg2.with_extension("txt.rsg"));

    let output = assert_success(rnid(&["-V", &sig1_s, &sig2_s]));
    assert_eq!(output.matches("Signature is valid").count(), 2);
}

#[test]
fn rsg_ascii_output_formats_validate_and_do_not_overwrite_signature_file() {
    let dir = tempdir();
    let rid = dir.path().join("alice.rid");
    let msg = dir.path().join("message.txt");
    let sig = dir.path().join("message.txt.rsg");
    let rid_s = path_str(&rid);
    let msg_s = path_str(&msg);
    let sig_s = path_str(&sig);
    assert_success(rnid(&["-g", &rid_s]));
    fs::write(&msg, b"ascii wrapped signatures").unwrap();
    fs::write(&sig, b"keep existing binary signature").unwrap();

    let hex_stdout = assert_success(rnid(&["-i", &rid_s, "-s", &msg_s, "--hex"]));
    assert_eq!(fs::read(&sig).unwrap(), b"keep existing binary signature");
    fs::write(&sig, rsg_ascii_block(&hex_stdout)).unwrap();
    assert_success(rnid(&["-V", &sig_s]));

    let base32_stdout = assert_success(rnid(&["-i", &rid_s, "-s", &msg_s, "-B"]));
    fs::write(&sig, rsg_ascii_block(&base32_stdout)).unwrap();
    assert_success(rnid(&["-V", &sig_s]));

    let base64_stdout = assert_success(rnid(&["-i", &rid_s, "-s", &msg_s, "-b"]));
    fs::write(&sig, rsg_ascii_block(&base64_stdout)).unwrap();
    assert_success(rnid(&["-V", &sig_s]));

    let base256_stdout = assert_success(rnid(&["-i", &rid_s, "-s", &msg_s, "--base256"]));
    fs::write(&sig, rsg_ascii_block(&base256_stdout)).unwrap();
    assert_success(rnid(&["-V", &sig_s]));
}

#[test]
fn hex_base32_base64_and_base256_rsg_flags_are_mutually_exclusive() {
    let failure = assert_failure(rnid(&["--hex", "-b"]));
    assert!(failure.contains("-b, -B, --base256 and --hex"));
}

#[test]
fn legacy_raw_rsg_requires_explicit_identity() {
    let dir = tempdir();
    let rid = dir.path().join("alice.rid");
    let msg = dir.path().join("legacy.bin");
    let rid_s = path_str(&rid);
    let msg_s = path_str(&msg);
    assert_success(rnid(&["-g", &rid_s]));
    fs::write(&msg, b"legacy signature payload").unwrap();

    assert_success(rnid(&["-i", &rid_s, "--raw", "-s", &msg_s]));
    let sig = dir.path().join("legacy.bin.rsg");
    assert_eq!(fs::read(&sig).unwrap().len(), 64);

    let no_identity = assert_failure(rnid(&["-V", &path_str(&sig)]));
    assert!(no_identity.contains("legacy"));
    assert_success(rnid(&["-i", &rid_s, "-V", &path_str(&sig)]));
}

#[test]
fn public_only_encrypts_but_cannot_decrypt_or_sign() {
    let dir = tempdir();
    let rid = dir.path().join("alice.rid");
    let msg = dir.path().join("secret.txt");
    let decrypted = dir.path().join("secret.out");
    let rid_s = path_str(&rid);
    let msg_s = path_str(&msg);
    assert_success(rnid(&["-g", &rid_s]));
    fs::write(&msg, b"quiet plaintext").unwrap();
    let public_hex = last_hex_line(&assert_success(rnid(&["-i", &rid_s, "-x"])), 64);

    assert_success(rnid(&["-m", &public_hex, "-e", &msg_s]));
    let encrypted = dir.path().join("secret.txt.rfe");
    assert!(encrypted.exists());

    let public_decrypt = assert_failure(rnid(&["-m", &public_hex, "-d", &path_str(&encrypted)]));
    assert!(public_decrypt.contains("private key"));

    let public_sign = assert_failure(rnid(&["-m", &public_hex, "-s", &msg_s, "-f"]));
    assert!(public_sign.contains("private key"));

    assert_success(rnid(&[
        "-i",
        &rid_s,
        "-d",
        &path_str(&encrypted),
        "-w",
        &path_str(&decrypted),
    ]));
    assert_eq!(fs::read(decrypted).unwrap(), b"quiet plaintext");
}

#[test]
fn rsg_validation_accepts_required_signer_identity_hash() {
    let dir = tempdir();
    let rid = dir.path().join("alice.rid");
    let msg = dir.path().join("message.txt");
    let rid_s = path_str(&rid);
    let msg_s = path_str(&msg);
    let generated = assert_success(rnid(&["-g", &rid_s]));
    let identity_hash = identity_hash_from_output(&generated);
    fs::write(&msg, b"required signer").unwrap();

    assert_success(rnid(&["-i", &rid_s, "-s", &msg_s]));
    let sig = dir.path().join("message.txt.rsg");
    assert_success(rnid(&["-i", &identity_hash, "-V", &path_str(&sig)]));

    let wrong_hash = "000102030405060708090a0b0c0d0e0f";
    let failure = assert_failure(rnid(&["-i", wrong_hash, "-V", &path_str(&sig)]));
    assert!(failure.contains(wrong_hash));
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
    assert!(stdout.contains("Retained Identity"));
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
