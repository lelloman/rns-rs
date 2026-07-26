use std::process::Command;

fn rnsh(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rnsh"))
        .args(args)
        .output()
        .expect("run rnsh")
}

#[test]
fn help_documents_separate_application_and_reticulum_config_paths() {
    let output = rnsh(&["--help"]);
    assert!(output.status.success());
    let help = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(help.contains("-c, --config PATH        rnsh application config directory"));
    assert!(help.contains("--rnsconfig PATH     Reticulum config directory"));
}

#[test]
fn rnsconfig_is_long_only_at_the_process_boundary() {
    let accepted = rnsh(&["--rnsconfig", "/tmp/reticulum", "--version"]);
    assert!(accepted.status.success());

    let rejected = rnsh(&["-r", "/tmp/reticulum", "--version"]);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("unknown option -r"));
}

#[test]
fn print_identity_creates_upstream_paths_in_selected_rnsh_directory() {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("app");
    let rns = temp.path().join("rns");
    let app_string = app.to_string_lossy();
    let rns_string = rns.to_string_lossy();

    let initiator = rnsh(&[
        "--config",
        &app_string,
        "--rnsconfig",
        &rns_string,
        "--print-identity",
    ]);
    assert!(initiator.status.success());
    assert!(app.join("identity").is_file());
    assert!(app.join("logfile.initiator").is_file());

    let listener = rnsh(&[
        "-c",
        &app_string,
        "--rnsconfig",
        &rns_string,
        "--listen",
        "--service",
        "dev-shell_1!",
        "--print-identity",
    ]);
    assert!(listener.status.success());
    assert!(app.join("identity.devshell1").is_file());
}

#[test]
fn legacy_identity_warns_but_is_not_silently_copied() {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("app");
    let rns = temp.path().join("rns");
    let old = rns.join("storage/identities/rnsh");
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    let old_key = [0x44; 64];
    std::fs::write(&old, old_key).unwrap();

    let output = rnsh(&[
        "--config",
        &app.to_string_lossy(),
        "--rnsconfig",
        &rns.to_string_lossy(),
        "--print-identity",
    ]);

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("existing pre-migration rnsh identity"));
    assert!(stderr.contains(old.to_string_lossy().as_ref()));
    assert!(stderr.contains(app.join("identity").to_string_lossy().as_ref()));
    assert_eq!(std::fs::read(&old).unwrap(), old_key);
    assert_ne!(std::fs::read(app.join("identity")).unwrap(), old_key);
}
