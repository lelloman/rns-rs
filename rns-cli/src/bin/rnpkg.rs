//! rnpkg - Reticulum Meta Package Manager (a placeholder upstream).

fn main() -> std::process::ExitCode {
    rns_cli::stdout::exit_quietly_on_closed_stdout();
    rns_cli::exit::code(rns_cli::placeholder::main(
        &rns_cli::placeholder::Placeholder {
            name: "rnpkg",
            description: "Reticulum Meta Package Manager",
            example_config: Some(rns_cli::placeholder::RNPKG_EXAMPLE_CONFIG),
        },
    ))
}
