use std::process::ExitCode;

use rns_cli::args::Args;
use rns_ctl::cli;
use rns_ctl::cmd;

fn main() -> ExitCode {
    rns_cli::stdout::exit_quietly_on_closed_stdout();
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // As argparse's subparsers: options before the command are rns-ctl's,
    // everything from the command on is the command's. `-c/--config PATH`
    // takes a value, so it is skipped over to find the command.
    let mut at = 0;
    while at < argv.len() {
        let arg = &argv[at];
        if arg == "-c" || arg == "--config" {
            at += 2;
        } else if arg.starts_with('-') && arg != "-" {
            at += 1;
        } else {
            break;
        }
    }
    let at = at.min(argv.len());
    let (head, tail) = argv.split_at(at);
    let top = cli::TOP.parse("rns-ctl", head.to_vec());
    if top.has("version") {
        println!("rns-ctl {}", env!("FULL_VERSION"));
        return ExitCode::SUCCESS;
    }
    let Some((command, tail)) = tail.split_first() else {
        cli::TOP.error(
            "rns-ctl",
            "the following arguments are required: command, args",
        );
    };
    // A config directory given before the command applies to it, as the
    // daily report and smoke test pass it (`rns-ctl --config DIR status`).
    let tail = match top.get("config") {
        Some(config) => {
            let mut forwarded = vec!["--config".to_string(), config.to_string()];
            forwarded.extend(tail.iter().cloned());
            forwarded
        }
        None => tail.to_vec(),
    };

    let status = match command.as_str() {
        "config" => cmd::config::run(cli::parse(&cli::CONFIG, "config", tail)),
        "backbone" => cmd::backbone::run(cli::parse(&cli::BACKBONE, "backbone", tail)),
        "http" => cmd::http::run(cli::parse(&cli::HTTP, "http", tail)),
        "hook" => cmd::hook::run(cli::parse(&cli::HOOK, "hook", tail)),
        "status" => cmd::status::run(Args::parse_spec_from(tail, &rns_cli::rnstatus::OPTIONS)),
        "probe" => cmd::probe::run(Args::parse_spec_from(tail, &rns_cli::rnprobe::OPTIONS)),
        "path" => cmd::path::run(Args::parse_spec_from(tail, &rns_cli::rnpath::OPTIONS)),
        "id" => cmd::id::run(Args::parse_spec_from(tail, &rns_cli::rnid::OPTIONS)),
        "daemon" => cmd::daemon::run(Args::parse_spec_from(tail, &rns_cli::rnsd::OPTIONS)),
        other => {
            let choices: Vec<String> = cli::COMMAND_NAMES
                .iter()
                .map(|name| rns_cli::argparse::repr(name))
                .collect();
            cli::TOP.error(
                "rns-ctl",
                &format!(
                    "argument command: invalid choice: {} (choose from {})",
                    rns_cli::argparse::repr(other),
                    choices.join(", ")
                ),
            );
        }
    };
    rns_cli::exit::exit_code(status)
}
