//! Command lines of the tools and subcommands only this implementation has
//! (`rns-sentineld`, `rns-statsd`, `rns-ctl`), parsed the way upstream's
//! utilities parse theirs: argparse's `--help`, its errors for unknown
//! options and missing or mistyped values, and exit status 2.

use std::sync::OnceLock;

use crate::argparse::{self, Action, Kind, Nargs, Parser, Ty};
use crate::args::{Args, OptionSpec};

/// argparse's `SUPPRESS`, as an option's help: the option is left out of
/// the usage and the help.
pub const SUPPRESS: &str = "==SUPPRESS==";

/// A tool's argparse parser, and text shown after its options, verbatim.
pub struct Cli {
    /// The tool's arguments.
    pub parser: Parser,
    /// Text printed after the help, as written.
    pub epilog: Option<&'static str>,
    spec: OnceLock<OptionSpec>,
}

const fn action(
    opts: &'static [&'static str],
    dest: &'static str,
    kind: Kind,
    nargs: Nargs,
    metavar: Option<&'static str>,
    help: Option<&'static str>,
    ty: Ty,
) -> Action {
    Action {
        opts,
        dest,
        kind,
        nargs,
        metavar,
        help,
        ty,
        required: false,
    }
}

/// `-h, --help`.
pub const fn help() -> Action {
    action(
        &["-h", "--help"],
        "help",
        Kind::Help,
        Nargs::Zero,
        None,
        Some("show this help message and exit"),
        Ty::Str,
    )
}

/// `--version`.
pub const fn version() -> Action {
    action(
        &["--version"],
        "version",
        Kind::Version,
        Nargs::Zero,
        None,
        Some("show program's version number and exit"),
        Ty::Str,
    )
}

/// A `store_true` option.
pub const fn flag(opts: &'static [&'static str], dest: &'static str, help: &'static str) -> Action {
    action(
        opts,
        dest,
        Kind::StoreTrue,
        Nargs::Zero,
        None,
        Some(help),
        Ty::Str,
    )
}

/// A `count` option such as `-v`.
pub const fn count(
    opts: &'static [&'static str],
    dest: &'static str,
    help: &'static str,
) -> Action {
    action(
        opts,
        dest,
        Kind::Count,
        Nargs::Zero,
        None,
        Some(help),
        Ty::Str,
    )
}

/// An option taking one value of type `ty`, shown as `metavar`.
pub const fn value(
    opts: &'static [&'static str],
    dest: &'static str,
    metavar: &'static str,
    ty: Ty,
    help: &'static str,
) -> Action {
    action(
        opts,
        dest,
        Kind::Store,
        Nargs::One,
        Some(metavar),
        Some(help),
        ty,
    )
}

/// A positional argument.
pub const fn positional(dest: &'static str, nargs: Nargs, help: &'static str) -> Action {
    action(&[], dest, Kind::Store, nargs, None, Some(help), Ty::Str)
}

impl Cli {
    /// A tool from its parser and epilog.
    pub const fn new(parser: Parser, epilog: Option<&'static str>) -> Self {
        Cli {
            parser,
            epilog,
            spec: OnceLock::new(),
        }
    }

    /// The option table [`Args::parse_spec_from`] reads, from the parser.
    pub fn spec(&'static self) -> &'static OptionSpec {
        self.spec
            .get_or_init(|| OptionSpec::new(Some(&self.parser), &[], &[]))
    }

    /// Parse `argv` for `prog`. As argparse, `--help` prints the help and
    /// exits 0, and an invalid command line prints the usage and the error
    /// to stderr and exits 2.
    pub fn parse(&'static self, prog: &str, argv: Vec<String>) -> Args {
        let args = Args::parse_spec_from(argv, self.spec());
        if let Some(exit) = argparse::check(&args, &self.parser, prog, argparse::terminal_columns())
        {
            if exit.code == 0 {
                print!("{}", self.help_text(prog));
            }
            eprint!("{}", exit.stderr);
            std::process::exit(exit.code);
        }
        args
    }

    /// The `--help` text for `prog`.
    pub fn help_text(&self, prog: &str) -> String {
        self.help_text_at(prog, argparse::terminal_columns())
    }

    /// The `--help` text for `prog` at a terminal of `columns`, as
    /// argparse's `RawDescriptionHelpFormatter` prints the epilog.
    pub fn help_text_at(&self, prog: &str, columns: usize) -> String {
        let help = argparse::format_help(&self.parser, prog, columns);
        match self.epilog {
            Some(epilog) => format!("{help}\n{epilog}\n"),
            None => help,
        }
    }

    /// Prints [`Cli::help_text`] to stdout.
    pub fn print_help(&self, prog: &str) {
        print!("{}", self.help_text(prog));
    }

    /// argparse's `parser.error(message)`: the usage and the message on
    /// stderr, exit status 2.
    pub fn error(&self, prog: &str, message: &str) -> ! {
        eprintln!(
            "{}{prog}: error: {message}",
            argparse::format_usage(&self.parser, prog, argparse::terminal_columns())
        );
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TOOL: Cli = Cli::new(
        Parser {
            name: "tool",
            description: Some("A tool"),
            epilog: None,
            raw_description: false,
            actions: &[
                help(),
                value(&["-c", "--config"], "config", "PATH", Ty::Str, "config"),
                value(&["--priority"], "priority", "N", Ty::Int, "priority"),
                flag(&["-j", "--json"], "json", "JSON output"),
                count(&["-v", "--verbose"], "verbose", "more output"),
                version(),
                positional("command", Nargs::Optional, "what to do"),
            ],
        },
        Some("More text."),
    );

    fn check(argv: &[&str]) -> Option<argparse::Exit> {
        let args = Args::parse_spec_from(argv.iter().map(|s| s.to_string()).collect(), TOOL.spec());
        argparse::check(&args, &TOOL.parser, "tool", 80)
    }

    #[test]
    fn parses_as_argparse() {
        let args = Args::parse_spec_from(
            ["-c", "/x", "--prio=3", "-jvv", "list"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            TOOL.spec(),
        );
        assert_eq!(args.config_path(), Some("/x"));
        assert_eq!(args.get("priority"), Some("3"));
        assert!(args.has("json") && args.has("j"));
        assert_eq!(args.verbosity, 2);
        assert_eq!(args.positional, ["list"]);
        assert!(check(&["-c", "/x", "list"]).is_none());
    }

    #[test]
    fn reports_errors_as_argparse() {
        let usage = "usage: tool [-h] [-c PATH] [--priority N] [-j] [-v] [--version] [command]\n";
        let error = |argv: &[&str]| {
            let exit = check(argv).unwrap();
            assert_eq!(exit.code, 2);
            exit.stderr
        };
        assert_eq!(
            error(&["--bogus"]),
            format!("{usage}tool: error: unrecognized arguments: --bogus\n")
        );
        assert_eq!(
            error(&["--priority", "x"]),
            format!("{usage}tool: error: argument --priority: invalid int value: 'x'\n")
        );
        assert_eq!(
            error(&["-c"]),
            format!("{usage}tool: error: argument -c/--config: expected one argument\n")
        );
        assert_eq!(
            error(&["a", "b"]),
            format!("{usage}tool: error: unrecognized arguments: b\n")
        );
        assert_eq!(check(&["-h"]).unwrap().code, 0);
        // Python's argparse, with RawDescriptionHelpFormatter, prints:
        assert_eq!(
            TOOL.help_text_at("tool", 80),
            "usage: tool [-h] [-c PATH] [--priority N] [-j] [-v] [--version] [command]\n\n\
             A tool\n\npositional arguments:\n  command               what to do\n\n\
             options:\n  -h, --help            show this help message and exit\n  \
             -c PATH, --config PATH\n                        config\n  \
             --priority N          priority\n  -j, --json            JSON output\n  \
             -v, --verbose         more output\n  \
             --version             show program's version number and exit\n\n\
             More text.\n"
        );
    }
}
