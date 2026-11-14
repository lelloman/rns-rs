fn main() {
    rns_cli::stdout::exit_quietly_on_closed_stdout();
    std::process::exit(rns_cli::rnx::main());
}
