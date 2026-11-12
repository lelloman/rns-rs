//! `rnir` and `rnpkg`, placeholders upstream: they start Reticulum and exit.

use std::process::Command;

fn standalone_config() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "[reticulum]\nenable_transport = False\nshare_instance = No\n\n[interfaces]\n",
    )
    .unwrap();
    dir
}

#[test]
fn placeholders_start_reticulum_and_exit() {
    for binary in [env!("CARGO_BIN_EXE_rnir"), env!("CARGO_BIN_EXE_rnpkg")] {
        let config = standalone_config();
        let out = Command::new(binary)
            .args(["--config", config.path().to_str().unwrap(), "-q"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{binary}: {out:?}");
        // Starting Reticulum created its storage.
        assert!(config.path().join("storage").is_dir());

        let out = Command::new(binary).arg("--version").output().unwrap();
        let name = std::path::Path::new(binary)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).starts_with(&format!("{name} ")));
    }
}

#[test]
fn rnpkg_prints_its_example_config() {
    let out = Command::new(env!("CARGO_BIN_EXE_rnpkg"))
        .arg("--exampleconfig")
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "# This is an example package manager configuration file.\n\n"
    );
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn rnpkg_example_config_matches_python() {
    let python = Command::new("python3")
        .args(["-m", "RNS.Utilities.rnpkg", "--exampleconfig"])
        .output()
        .unwrap();
    let rust = Command::new(env!("CARGO_BIN_EXE_rnpkg"))
        .arg("--exampleconfig")
        .output()
        .unwrap();
    assert_eq!(rust.stdout, python.stdout);
}
