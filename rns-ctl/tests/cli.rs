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
fn top_level_errors_are_argparses() {
    let usage = "usage: rns-ctl [-h] [--version] command [args ...]\n";
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
