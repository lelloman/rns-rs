//! rnir - Reticulum Distributed Identity Resolver (a placeholder upstream).

fn main() {
    std::process::exit(rns_cli::placeholder::main(
        &rns_cli::placeholder::Placeholder {
            name: "rnir",
            description: "Reticulum Distributed Identity Resolver",
            example_config: None,
        },
    ));
}
