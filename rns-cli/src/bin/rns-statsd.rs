//! rns-statsd - records traffic statistics of a running Reticulum instance
//! into an SQLite database (see `rns_cli::statsd`).

fn main() -> std::process::ExitCode {
    rns_cli::statsd::main_entry()
}
