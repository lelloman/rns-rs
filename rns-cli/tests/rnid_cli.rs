use std::fs;
use std::path::Path;
use std::process::{Command, Output};

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
