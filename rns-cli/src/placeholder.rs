//! `rnir` and `rnpkg`: upstream ships both as placeholders for programs to
//! come. Each starts Reticulum and exits, so scripts that call them behave
//! the same here.

use std::path::Path;

use crate::args::{Args, Opt, OptionSpec};

const VERSION: &str = env!("FULL_VERSION");

struct NoCallbacks;

impl rns_net::Callbacks for NoCallbacks {
    fn on_announce(&mut self, _announced: rns_net::AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _dest_hash: rns_net::DestHash, _hops: u8) {}
    fn on_local_delivery(
        &mut self,
        _dest_hash: rns_net::DestHash,
        _raw: Vec<u8>,
        _packet_hash: rns_net::PacketHash,
    ) {
    }
}

/// What one placeholder is called and what it may print.
pub struct Placeholder {
    pub name: &'static str,
    pub description: &'static str,
    /// The `--exampleconfig` text, for a placeholder that has one.
    pub example_config: Option<&'static str>,
}

/// upstream rnpkg's example configuration.
pub const RNPKG_EXAMPLE_CONFIG: &str = "# This is an example package manager configuration file.\n";

/// upstream rnpkg's options, and the Rust-only `-c` for `--config`.
pub(crate) const OPTIONS: OptionSpec = OptionSpec {
    options: &[
        Opt::value("", "config"),
        Opt::count("v", "verbose"),
        Opt::count("q", "quiet"),
        Opt::flag("", "exampleconfig"),
        Opt::value("c", ""),
    ],
};

/// upstream rnir's options: rnpkg's without `--exampleconfig`.
pub(crate) const RNIR_OPTIONS: OptionSpec = OptionSpec {
    options: &[
        Opt::value("", "config"),
        Opt::count("v", "verbose"),
        Opt::count("q", "quiet"),
        Opt::value("c", ""),
    ],
};

pub fn main(placeholder: &Placeholder) -> i32 {
    let spec = if placeholder.example_config.is_some() {
        &OPTIONS
    } else {
        &RNIR_OPTIONS
    };
    let args = Args::parse_spec(spec);
    crate::argparse::enforce(&args, placeholder.name, placeholder.name);
    if args.has("version") {
        println!("{} {VERSION}", placeholder.name);
        return 0;
    }
    if args.has("help") {
        crate::argparse::print_help(placeholder.name, placeholder.name);
        return 0;
    }
    if let (true, Some(example)) = (args.has("exampleconfig"), placeholder.example_config) {
        // upstream prints it with print(), adding a newline.
        println!("{example}");
        return 0;
    }

    // `RNS.Reticulum(configdir, verbosity=verbosity-quietness)`: the
    // configured level, raised or lowered.
    crate::pylog::install_utility_logging(
        args.config_path(),
        None,
        i32::from(args.verbosity) - i32::from(args.quiet),
        false,
    );

    // Start Reticulum as upstream does: attached to a running shared
    // instance, or as an instance of its own.
    let config = args.config_path().map(Path::new);
    let started = match rns_net::RnsNode::connect_shared_from_config(
        Some(&crate::app::rns_config(args.config_path())),
        Box::new(NoCallbacks),
    ) {
        Ok(node) => Ok(node),
        Err(_) => rns_net::RnsNode::from_config(config, Box::new(NoCallbacks)),
    };
    match started {
        Ok(node) => {
            node.shutdown();
            0
        }
        Err(e) => {
            eprintln!("Could not start Reticulum: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_upstream_invocations_as_argparse_does() {
        let parse = |argv: &[&str]| {
            Args::parse_spec_from(argv.iter().map(|s| s.to_string()).collect(), &OPTIONS)
        };
        let args = parse(&["--config=/c", "-vvq"]);
        assert_eq!(
            (args.config_path(), args.verbosity, args.quiet),
            (Some("/c"), 2, 1)
        );
        let args = parse(&["--conf", "/c", "--verb", "--example"]);
        assert_eq!((args.config_path(), args.verbosity), (Some("/c"), 1));
        assert!(args.has("exampleconfig"));
        assert!(parse(&["--vers"]).has("version"));
    }
}
