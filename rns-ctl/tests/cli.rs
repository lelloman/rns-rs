//! rns-ctl's command lines parse as argparse does: help on stdout with
//! status 0, errors after the usage on stderr with status 2.

use std::process::{Command, Output};

fn rns_ctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rns-ctl"))
        .args(args)
        .env("COLUMNS", "80")
        .output()
        .expect("run rns-ctl")
}

fn error(args: &[&str]) -> String {
    let output = rns_ctl(args);
    assert_eq!(output.status.code(), Some(2), "{args:?}");
    assert!(output.stdout.is_empty(), "{args:?}");
    String::from_utf8(output.stderr).unwrap()
}

#[test]
fn a_config_before_the_command_applies_to_it() {
    // The daily VPS report and the backbone smoke test run
    // `rns-ctl --config DIR status -j`; the directory goes to the command.
    let dir = std::env::temp_dir().join(format!("rns-ctl-top-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config"),
        "[reticulum]\n  share_instance = Yes\n  instance_name = rns-ctl-top-config-test\n",
    )
    .unwrap();
    let dir_s = dir.to_str().unwrap();
    for args in [
        vec!["--config", dir_s, "status", "-j"],
        vec!["-c", dir_s, "status", "-j"],
    ] {
        let output = rns_ctl(&args);
        assert_ne!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "No shared RNS instance available to get status from\n",
            "{args:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn top_level_errors_are_argparses() {
    let usage = "usage: rns-ctl [-h] [--version] [-c PATH] command [args ...]\n";
    assert_eq!(
        error(&[]),
        format!("{usage}rns-ctl: error: the following arguments are required: command, args\n")
    );
    assert_eq!(
        error(&["bogus"]),
        format!(
            "{usage}rns-ctl: error: argument command: invalid choice: 'bogus' (choose from \
             'config', 'backbone', 'http', 'status', 'probe', 'path', 'id', 'daemon', 'hook')\n"
        )
    );
    assert_eq!(
        error(&["--bogus", "status"]),
        format!("{usage}rns-ctl: error: unrecognized arguments: --bogus\n")
    );
    let help = rns_ctl(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.starts_with(usage), "{help}");
    assert!(help.contains("\ncommands:\n  config "), "{help}");
}

#[test]
fn subcommand_errors_are_argparses() {
    for (args, message) in [
        (
            &["config", "--bogus"][..],
            "rns-ctl config: error: unrecognized arguments: --bogus\n",
        ),
        (
            &["http", "--port", "x"][..],
            "rns-ctl http: error: argument -p/--port: invalid int value: 'x'\n",
        ),
        (
            &["hook", "--point"][..],
            "rns-ctl hook: error: argument --point: expected one argument\n",
        ),
        (
            &["backbone", "-j", "a", "b", "c", "d", "e"][..],
            "rns-ctl backbone: error: unrecognized arguments: e\n",
        ),
        // The upstream utilities' own parsers, as `rns-ctl <command>`.
        (
            &["path", "--bogus"][..],
            "rns-ctl path: error: unrecognized arguments: --bogus\n",
        ),
        (
            &["status", "-s"][..],
            "rns-ctl status: error: argument -s/--sort: expected one argument\n",
        ),
    ] {
        let stderr = error(args);
        assert!(
            stderr.starts_with(&format!("usage: rns-ctl {} [-h]", args[0])),
            "{stderr}"
        );
        assert!(stderr.ends_with(message), "{args:?}: {stderr}");
    }
    for command in ["config", "backbone", "http", "hook", "path", "daemon"] {
        let help = rns_ctl(&[command, "-h"]);
        assert_eq!(help.status.code(), Some(0), "{command}");
        let help = String::from_utf8(help.stdout).unwrap();
        assert!(
            help.starts_with(&format!("usage: rns-ctl {command} [-h]")),
            "{help}"
        );
    }
}
