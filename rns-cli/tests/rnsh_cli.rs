use std::process::Command;

/// As upstream's, rnsh exits 1 after its help, its version and printing
/// its identity: its main() swallows the SystemExit they end with.
fn swallowed_exit(output: &std::process::Output) -> bool {
    output.status.code() == Some(1)
}

fn rnsh(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rnsh"))
        .args(args)
        .output()
        .expect("run rnsh")
}

/// A Reticulum config with no interfaces and no shared instance, so the
/// instance `--print-identity` starts stays off the network.
fn write_quiet_rns_config(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("config"),
        "[reticulum]\n  share_instance = No\n\n[interfaces]\n",
    )
    .unwrap();
}

#[test]
fn help_documents_separate_application_and_reticulum_config_paths() {
    let output = rnsh(&["--help"]);
    assert!(swallowed_exit(&output));
    let help = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(help.contains(
        "  --config CONFIG, -c CONFIG\n                        path to config directory\n"
    ));
    assert!(help.contains(
        "  --rnsconfig RNSCONFIG\n                        path to alternative Reticulum config directory\n"
    ));
}

#[test]
fn rnsconfig_is_long_only_at_the_process_boundary() {
    let accepted = rnsh(&["--rnsconfig", "/tmp/reticulum", "--version"]);
    assert!(swallowed_exit(&accepted));
    assert!(String::from_utf8_lossy(&accepted.stdout).starts_with("rnsh "));

    let rejected = rnsh(&["-r", "/tmp/reticulum"]);
    assert!(swallowed_exit(&rejected));
    assert!(rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr)
        .ends_with("rnsh: error: unrecognized arguments: -r\n"));
}

#[test]
fn print_identity_creates_upstream_paths_in_selected_rnsh_directory() {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("app");
    let rns = temp.path().join("rns");
    let app_string = app.to_string_lossy();
    let rns_string = rns.to_string_lossy();
    write_quiet_rns_config(&rns);

    let initiator = rnsh(&[
        "--config",
        &app_string,
        "--rnsconfig",
        &rns_string,
        "--print-identity",
    ]);
    assert!(swallowed_exit(&initiator));
    assert!(app.join("identity").is_file());
    // As upstream's, printing the identity logs to stdout, not to a file.
    assert!(!app.join("logfile.initiator").exists());
    let stdout = String::from_utf8_lossy(&initiator.stdout);
    assert!(
        stdout.contains(&format!(
            "] [Notice]   Creating identity {}",
            app.join("identity").display()
        )),
        "{stdout}"
    );

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
    assert!(swallowed_exit(&listener));
    assert!(app.join("identity.devshell1").is_file());
}

#[test]
fn print_identity_starts_reticulum_which_writes_the_default_config() {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("app");
    let rns = temp.path().join("rns");

    let output = rnsh(&[
        "--config",
        &app.to_string_lossy(),
        "--rnsconfig",
        &rns.to_string_lossy(),
        "-p",
    ]);

    assert!(swallowed_exit(&output));
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        std::fs::read(rns.join("config")).unwrap(),
        rns_net::storage::DEFAULT_CONFIG
    );
    assert!(rns.join("storage").is_dir());
    // Upstream's log lines, then the identity, on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let messages: Vec<&str> = stdout
        .lines()
        .map(|line| line.split_once("] [Notice]   ").map_or(line, |(_, m)| m))
        .collect();
    let identity_line = messages.last().unwrap();
    assert!(identity_line.starts_with("Identity     : <"), "{stdout}");
    assert_eq!(
        messages[..messages.len() - 1],
        [
            format!("Creating configuration directory: {}", app.display()),
            "Could not load config file, creating default configuration file...".to_string(),
            format!(
                "Default config file created. Make any necessary changes in {}/config and restart Reticulum if needed.",
                rns.display()
            ),
            format!("Creating identity {}", app.join("identity").display()),
        ]
    );
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
    write_quiet_rns_config(&rns);

    let output = rnsh(&[
        "--config",
        &app.to_string_lossy(),
        "--rnsconfig",
        &rns.to_string_lossy(),
        "--print-identity",
    ]);

    assert!(swallowed_exit(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("existing pre-migration rnsh identity"));
    assert!(stderr.contains(old.to_string_lossy().as_ref()));
    assert!(stderr.contains(app.join("identity").to_string_lossy().as_ref()));
    assert_eq!(std::fs::read(&old).unwrap(), old_key);
    assert_ne!(std::fs::read(app.join("identity")).unwrap(), old_key);
}
