//! `rnir` and `rnpkg`: upstream ships both as placeholders for programs to
//! come. Each starts Reticulum and exits, so scripts that call them behave
//! the same here.

use std::path::Path;

use crate::args::Args;

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

pub fn main(placeholder: &Placeholder) -> i32 {
    let args = Args::parse();
    if args.has("version") {
        println!("{} {VERSION}", placeholder.name);
        return 0;
    }
    if args.has("help") {
        let example = if placeholder.example_config.is_some() {
            "\n  --exampleconfig  Print verbose configuration example to stdout and exit"
        } else {
            ""
        };
        println!(
            "usage: {} [-h] [--config CONFIG] [-v] [-q]{} [--version]\n\n{}\n\noptions:\n  -h, --help       Show this help message and exit\n  --config CONFIG  Path to alternative Reticulum config directory\n  -v, --verbose\n  -q, --quiet{example}\n  --version        Show program's version number and exit",
            placeholder.name,
            if placeholder.example_config.is_some() { " [--exampleconfig]" } else { "" },
            placeholder.description,
        );
        return 0;
    }
    if let (true, Some(example)) = (args.has("exampleconfig"), placeholder.example_config) {
        // upstream prints it with print(), adding a newline.
        println!("{example}");
        return 0;
    }

    let level = (3i16 + args.verbosity as i16 - args.quiet as i16).clamp(0, 5);
    let filter = ["off", "error", "warn", "info", "debug", "trace"][level as usize];
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter))
        .try_init();

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
