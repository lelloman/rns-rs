//! rnir - Reticulum Distributed Identity Resolver (a placeholder upstream).

fn main() -> std::process::ExitCode {
    rns_cli::stdout::exit_quietly_on_closed_stdout();
    rns_cli::exit::code(rns_cli::placeholder::main(
        &rns_cli::placeholder::Placeholder {
            name: "rnir",
            description: "Reticulum Distributed Identity Resolver",
            example_config: None,
        },
    ))
}
