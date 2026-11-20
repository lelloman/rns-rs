//! rnsh - Reticulum Remote Shell Utility

fn main() -> std::process::ExitCode {
    rns_cli::exit::code(rns_cli::rnsh::main())
}
