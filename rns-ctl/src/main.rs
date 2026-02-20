use rns_ctl::args::Args;
use rns_ctl::cmd;

fn main() {
    let args = Args::parse();

    if args.has("version") {
        println!("rns-ctl {}", env!("FULL_VERSION"));
        return;
    }

    if args.has("help") && args.positional.is_empty() {
        print_help();
        return;
    }

    match args.positional.first().map(|s| s.as_str()) {
        Some("http") => cmd::http::run(strip_subcommand(args)),
        Some("status") => cmd::status::run(strip_subcommand(args)),
        Some("probe") => cmd::probe::run(strip_subcommand(args)),
        Some("path") => cmd::path::run(strip_subcommand(args)),
        Some("id") => cmd::id::run(strip_subcommand(args)),
        Some("daemon") => cmd::daemon::run(strip_subcommand(args)),
        Some("hook") => cmd::hook::run(strip_subcommand(args)),
        Some(other) => {
            eprintln!("Unknown subcommand: {}", other);
            print_help();
            std::process::exit(1);
        }
        None => print_help(),
    }
}

fn strip_subcommand(mut args: Args) -> Args {
    if !args.positional.is_empty() {
        args.positional.remove(0);
    }
    args
}

fn print_help() {
    println!(
        "rns-ctl - Reticulum Network Stack control tool

USAGE:
    rns-ctl <COMMAND> [OPTIONS]

COMMANDS:
    http        Start HTTP/WebSocket control server
    status      Display interface status
    probe       Probe path reachability
    path        Display/manage path table
    id          Identity management
    daemon      Start RNS daemon node
    hook        Manage WASM hooks (list/load/unload)

OPTIONS:
    -h, --help      Show this help
        --version   Show version

Run 'rns-ctl <COMMAND> --help' for more information on a command."
    );
}
