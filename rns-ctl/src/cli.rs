//! rns-ctl's command lines: argparse's help, errors and exit status 2, as
//! the upstream utilities print theirs. The subcommands that stand for an
//! upstream utility (`status`, `probe`, `path`, `id`, `daemon`) take that
//! utility's own options, help and errors.

use rns_cli::argparse::{Nargs, Parser, Ty};
use rns_cli::native_cli::{count, flag, help, positional, value, version, Cli};

use crate::args::Args;

/// The subcommands, as `rns-ctl --help` lists them.
const COMMANDS: &str = "\
commands:
  config      inspect and update runtime configuration
  backbone    inspect backbone peer state and blacklist
  http        start the HTTP/WebSocket control server
  status      display interface status, like rnstatus
  probe       probe path reachability, like rnprobe
  path        display and manage the path table, like rnpath
  id          identity management, like rnid
  daemon      start the RNS daemon node, like rnsd
  hook        manage hooks (list, load, unload, ...)

Run 'rns-ctl <command> --help' for more information on a command.";

pub static TOP: Cli = Cli::new(
    Parser {
        name: "rns-ctl",
        description: Some("Reticulum Network Stack control tool"),
        epilog: None,
        raw_description: false,
        actions: &[
            help(),
            version(),
            value(
                &["-c", "--config"],
                "config",
                "PATH",
                Ty::Str,
                "path to config directory, for any command",
            ),
            positional("command", Nargs::One, "the command to run"),
            positional("args", Nargs::ZeroOrMore, "the command's arguments"),
        ],
    },
    Some(COMMANDS),
);

/// The names of the subcommands, in the order `TOP` lists them.
pub const COMMAND_NAMES: &[&str] = &[
    "config", "backbone", "http", "status", "probe", "path", "id", "daemon", "hook",
];

pub static CONFIG: Cli = Cli::new(
    Parser {
        name: "rns-ctl config",
        description: Some("Inspect and update runtime configuration on a running node"),
        epilog: None,
        raw_description: false,
        actions: &[
            help(),
            value(
                &["-c", "--config"],
                "config",
                "PATH",
                Ty::Str,
                "path to config directory",
            ),
            flag(&["-j", "--json"], "json", "JSON output"),
            flag(&["--keys-only"], "keys_only", "print only keys for list"),
            flag(
                &["--value-only"],
                "value_only",
                "print only the effective value",
            ),
            value(
                &["--prefix"],
                "prefix",
                "PREFIX",
                Ty::Str,
                "list only the keys starting with PREFIX",
            ),
            version(),
            positional("command", Nargs::Optional, "list, get, set or reset"),
            positional("key", Nargs::Optional, "the runtime config key"),
            positional("value", Nargs::Optional, "the value to set"),
        ],
    },
    Some(
        "\
commands:
  list [--prefix PREFIX]  list supported runtime config entries
  get <key>               get one runtime config entry
  set <key> <value>       set one runtime config value
  reset <key>             reset one runtime config value",
    ),
);

pub static BACKBONE: Cli = Cli::new(
    Parser {
        name: "rns-ctl backbone",
        description: Some("Inspect backbone peer state and blacklist"),
        epilog: None,
        raw_description: false,
        actions: &[
            help(),
            value(
                &["-c", "--config"],
                "config",
                "PATH",
                Ty::Str,
                "path to config directory",
            ),
            flag(&["-j", "--json"], "json", "JSON output"),
            positional("command", Nargs::Optional, "blacklist or provider"),
            positional("action", Nargs::Optional, "list or clear, for blacklist"),
            positional("interface", Nargs::Optional, "backbone interface name"),
            positional("ip", Nargs::Optional, "peer IP, for blacklist clear"),
        ],
    },
    Some(
        "\
commands:
  blacklist list [INTERFACE] [--json]
  blacklist clear <INTERFACE> <IP>
  provider [--json]",
    ),
);

pub static HTTP: Cli = Cli::new(
    Parser {
        name: "rns-ctl http",
        description: Some("HTTP/WebSocket control interface for Reticulum"),
        epilog: None,
        raw_description: false,
        actions: &[
            help(),
            value(
                &["-c", "--config"],
                "config",
                "PATH",
                Ty::Str,
                "path to RNS config directory",
            ),
            value(
                &["-p", "--port"],
                "port",
                "PORT",
                Ty::Int,
                "HTTP port (default: 8080, env: RNSCTL_HTTP_PORT)",
            ),
            value(
                &["-H", "--host"],
                "host",
                "HOST",
                Ty::Str,
                "bind host (default: 127.0.0.1, env: RNSCTL_HOST)",
            ),
            value(
                &["-t", "--token"],
                "token",
                "TOKEN",
                Ty::Str,
                "auth bearer token (env: RNSCTL_AUTH_TOKEN); when unset, a token is \
                 generated and written to <config dir>/http-token",
            ),
            flag(
                &["-d", "--daemon"],
                "daemon",
                "connect as client to running rnsd",
            ),
            flag(
                &["--disable-auth"],
                "disable_auth",
                "disable authentication",
            ),
            value(
                &["--tls-cert"],
                "tls_cert",
                "PATH",
                Ty::Str,
                "TLS certificate file (env: RNSCTL_TLS_CERT, requires the 'tls' feature)",
            ),
            value(
                &["--tls-key"],
                "tls_key",
                "PATH",
                Ty::Str,
                "TLS private key file (env: RNSCTL_TLS_KEY, requires the 'tls' feature)",
            ),
            value(
                &["--hooks-dir"],
                "hooks_dir",
                "PATH",
                Ty::Str,
                "directory native hooks may be loaded from through the API (default: \
                 <config dir>/hooks, env: RNSCTL_HOOKS_DIR)",
            ),
            count(&["-v", "--verbose"], "verbose", "increase verbosity"),
            version(),
        ],
    },
    None,
);

/// `rns-ctl hook`'s epilog, naming the default hook type.
macro_rules! hook_epilog {
    ($default_type:literal) => {
        concat!(
            "\
commands:
  list                                 list loaded hooks
  load <path> --point <HookPoint>      load a hook
       [--type wasm|native|builtin] [--priority N] [--name NAME]
       [--builtin ID]                  built-in hook ID (defaults to <path>)
  unload <name> --point <HookPoint>    unload a hook
  reload <name> --point <HookPoint>    reload a hook
       --path <hook_file_or_builtin_id> [--type wasm|native|builtin]
  enable <name> --point <HookPoint>    enable a loaded hook
  disable <name> --point <HookPoint>   disable a loaded hook
  set-priority <name> --point <HookPoint> --priority N

--type defaults to ",
            $default_type,
            ". Native hooks must be requested with --type native and an
absolute path inside the server's configured hooks directory (default:
<config dir>/hooks).

hook points:
  PreIngress, PreDispatch, AnnounceReceived, PathUpdated,
  AnnounceRetransmit, LinkRequestReceived, LinkEstablished,
  LinkClosed, InterfaceUp, InterfaceDown, InterfaceConfigChanged,
  SendOnInterface, BroadcastOnAllInterfaces, DeliverLocal,
  TunnelSynthesize, Tick"
        )
    };
}

#[cfg(feature = "rns-hooks-wasm")]
const HOOK_EPILOG: &str = hook_epilog!("wasm");
#[cfg(not(feature = "rns-hooks-wasm"))]
const HOOK_EPILOG: &str = hook_epilog!("builtin");

pub static HOOK: Cli = Cli::new(
    Parser {
        name: "rns-ctl hook",
        description: Some("Manage the hooks of a node serving rns-ctl http"),
        epilog: None,
        raw_description: false,
        actions: &[
            help(),
            value(
                &["--url"],
                "url",
                "URL",
                Ty::Str,
                "HTTP server URL (default: http://127.0.0.1:8080)",
            ),
            value(
                &["-t", "--token"],
                "token",
                "TOKEN",
                Ty::Str,
                "bearer auth token (generated tokens: <config dir>/http-token)",
            ),
            value(
                &["--point"],
                "point",
                "HookPoint",
                Ty::Str,
                "the hook point",
            ),
            value(
                &["--type"],
                "type",
                "TYPE",
                Ty::Str,
                "wasm, native or builtin",
            ),
            value(&["--priority"], "priority", "N", Ty::Int, "hook priority"),
            value(&["--name"], "name", "NAME", Ty::Str, "hook name"),
            value(&["--builtin"], "builtin", "ID", Ty::Str, "built-in hook ID"),
            value(
                &["--id"],
                "id",
                "ID",
                Ty::Str,
                rns_cli::native_cli::SUPPRESS,
            ),
            value(
                &["--path"],
                "path",
                "PATH",
                Ty::Str,
                "hook file or built-in hook ID, for reload",
            ),
            positional("command", Nargs::Optional, "what to do, below"),
            positional("target", Nargs::Optional, "hook path or name"),
        ],
    },
    Some(HOOK_EPILOG),
);

/// Parse a subcommand's arguments with `cli`, as `rns-ctl <name>`.
pub fn parse(cli: &'static Cli, name: &str, argv: Vec<String>) -> Args {
    cli.parse(&format!("rns-ctl {name}"), argv)
}
