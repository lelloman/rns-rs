//! rnx - Reticulum Remote Execution Utility.

fn main() -> std::process::ExitCode {
    rns_cli::stdout::exit_quietly_on_closed_stdout();
    rns_cli::exit::code(rns_cli::rnx::main())
}
