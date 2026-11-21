//! rns-sentineld - blacklists misbehaving backbone peers of a running
//! Reticulum instance (see `rns_cli::sentineld`).

fn main() -> std::process::ExitCode {
    rns_cli::sentineld::main_entry()
}
