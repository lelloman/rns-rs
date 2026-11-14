//! rnir - Reticulum Distributed Identity Resolver (a placeholder upstream).

fn main() {
    rns_cli::stdout::exit_quietly_on_closed_stdout();
    std::process::exit(rns_cli::placeholder::main(
        &rns_cli::placeholder::Placeholder {
            name: "rnir",
            description: "Reticulum Distributed Identity Resolver",
            example_config: None,
        },
    ));
}
