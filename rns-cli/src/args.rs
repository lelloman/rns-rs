//! Simple command-line argument parser.
//!
//! No external dependencies. Supports `--flag`, `--key value`, `-v` (count),
//! and positional arguments.

use std::collections::HashMap;

/// How an option takes its value, as upstream's argparse declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `store_true`: never takes a value.
    Flag,
    /// `store`: always takes one, attached (`-t5`, `--timeout=5`) or as the
    /// next argument.
    Value,
    /// `nargs="?"` or `nargs="*"`: takes the next argument when it is not
    /// an option itself.
    Optional,
    /// `count`; `verbose` and `quiet` feed [`Args::verbosity`] and
    /// [`Args::quiet`].
    Count,
}

/// One option of a tool: its short name (one character), its long name
/// (without `--`), either of which may be empty, and how it takes a value.
#[derive(Clone, Copy, Debug)]
pub struct Opt {
    pub short: &'static str,
    pub long: &'static str,
    pub kind: Kind,
    /// Whether the long name is upstream's. Only upstream's long names may
    /// be abbreviated, so a Rust-only option never makes an abbreviation
    /// upstream accepts ambiguous.
    pub upstream: bool,
}

impl Opt {
    pub const fn new(short: &'static str, long: &'static str, kind: Kind) -> Self {
        Opt {
            short,
            long,
            kind,
            upstream: true,
        }
    }
    pub const fn flag(short: &'static str, long: &'static str) -> Self {
        Self::new(short, long, Kind::Flag)
    }
    pub const fn value(short: &'static str, long: &'static str) -> Self {
        Self::new(short, long, Kind::Value)
    }
    pub const fn optional(short: &'static str, long: &'static str) -> Self {
        Self::new(short, long, Kind::Optional)
    }
    pub const fn count(short: &'static str, long: &'static str) -> Self {
        Self::new(short, long, Kind::Count)
    }
    /// The same option, with a long name upstream does not have.
    pub const fn rust_only(self) -> Self {
        Opt {
            upstream: false,
            ..self
        }
    }
}

/// A tool's options, mirroring its upstream argument parser (plus the
/// Rust-only options it accepts). `-h`/`--help` and `--version` are implied.
pub struct OptionSpec {
    pub options: &'static [Opt],
}

const IMPLIED: &[Opt] = &[Opt::flag("h", "help"), Opt::flag("", "version")];

/// What a long name stands for.
enum LongMatch {
    Opt(&'static Opt),
    /// An abbreviation of more than one upstream option.
    Ambiguous,
    None,
}

impl OptionSpec {
    fn all(&self) -> impl Iterator<Item = &'static Opt> {
        let options: &'static [Opt] = self.options;
        options.iter().chain(IMPLIED.iter())
    }

    fn short(&self, c: char) -> Option<&'static Opt> {
        self.all().find(|o| o.short.chars().eq(std::iter::once(c)))
    }

    /// The upstream long options `name` abbreviates, as `--name`s.
    pub fn abbreviated(&self, name: &str) -> Vec<String> {
        self.all()
            .filter(|o| o.upstream && !o.long.is_empty() && o.long.starts_with(name))
            .map(|o| format!("--{}", o.long))
            .collect()
    }

    /// The option a long name stands for: an exact match, or as argparse
    /// does, the one upstream option it is an unambiguous prefix of.
    fn long(&self, name: &str) -> LongMatch {
        if name.is_empty() {
            return LongMatch::None;
        }
        if let Some(opt) = self.all().find(|o| o.long == name) {
            return LongMatch::Opt(opt);
        }
        let mut matches = self
            .all()
            .filter(|o| o.upstream && !o.long.is_empty() && o.long.starts_with(name));
        match (matches.next(), matches.next()) {
            (Some(opt), None) => LongMatch::Opt(opt),
            (Some(_), Some(_)) => LongMatch::Ambiguous,
            _ => LongMatch::None,
        }
    }
}

/// One thing the parser saw on the command line, in order, for argparse's
/// error reporting ([`crate::argparse::check`]).
#[derive(Clone, Debug)]
pub enum Seen {
    /// A known option, with the value it took.
    Option(&'static Opt, Option<String>),
    /// An option that takes a value, given without one.
    Missing(&'static Opt),
    /// A flag given an explicit value (`--all=1`, `-a=1`, `-aZ`).
    Ignored(&'static Opt, String),
    /// An abbreviation of more than one option: the argument and the
    /// options it could stand for.
    Ambiguous(String, Vec<String>),
    /// An option the tool does not have, as given.
    Unknown(String),
    Positional(String),
}

/// Parsed command-line arguments.
pub struct Args {
    pub flags: HashMap<String, String>,
    pub positional: Vec<String>,
    pub verbosity: u8,
    pub quiet: u8,
    /// Every value an option was given, in order, under each of its names:
    /// what [`Args::get_all`] reads for options given more than once.
    pub values: Vec<(String, String)>,
    /// Options a tool's [`OptionSpec`] does not know, as given. They are
    /// still parsed as the shared parser would.
    pub unknown: Vec<String>,
    /// Options given without the value they take (argparse: "expected one
    /// argument").
    pub missing: Vec<String>,
    /// Everything [`Args::parse_spec_from`] saw, in order.
    pub trace: Vec<Seen>,
}

/// Long options that never take a value.
const BOOLEAN_LONG: &[&str] = &[
    "version",
    "exampleconfig",
    "help",
    "stdin",
    "stdout",
    "force",
    "blackholed",
    "base256",
    "base32",
    "base64",
    "raw",
    "request",
    "no-cache",
    "print-identity",
    "print-private",
    "export-pub",
    "export-prv",
    "pr-stats",
    "filter-stats",
    "tunnels",
    "burst",
    "blocked-ips",
    "queues",
    "pps",
    "hex",
    "meta",
    "daemon",
    "disable-auth",
    "json",
    "value-only",
    "keys-only",
    "show-stale",
    "show-unknown",
];

/// Whether an argument is a value rather than an option, as argparse
/// decides it: `-` alone and negative numbers are values.
fn is_value(arg: &String) -> bool {
    !arg.starts_with('-') || arg == "-" || looks_negative(arg)
}

/// argparse's negative number pattern: `-5`, `-.5`, `-1.5`.
fn looks_negative(arg: &str) -> bool {
    let Some(number) = arg.strip_prefix('-') else {
        return false;
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if number.contains('.') {
        digits(whole) && !fraction.is_empty() && digits(fraction)
    } else {
        !whole.is_empty() && digits(whole)
    }
}

impl Args {
    /// Parse command-line arguments (skipping argv[0]).
    pub fn parse() -> Self {
        Self::parse_from(std::env::args().skip(1).collect())
    }

    /// Parse the multi-command `rns-ctl` surface, where several short options
    /// accept values that are boolean flags in standalone tools.
    pub fn parse_control() -> Self {
        Self::parse_control_from(std::env::args().skip(1).collect())
    }

    /// Parse from a list of argument strings.
    pub fn parse_from(args: Vec<String>) -> Self {
        Self::parse_profile(args, false)
    }

    pub fn parse_control_from(args: Vec<String>) -> Self {
        Self::parse_profile(args, true)
    }

    /// Parse with a tool's own option table.
    pub fn parse_spec(spec: &OptionSpec) -> Self {
        Self::parse_spec_from(std::env::args().skip(1).collect(), spec)
    }

    pub fn parse_spec_from(args: Vec<String>, spec: &OptionSpec) -> Self {
        let mut parsed = Args {
            flags: HashMap::new(),
            positional: Vec::new(),
            verbosity: 0,
            quiet: 0,
            values: Vec::new(),
            unknown: Vec::new(),
            missing: Vec::new(),
            trace: Vec::new(),
        };
        let mut iter = args.into_iter().peekable();

        while let Some(arg) = iter.next() {
            if arg == "--" {
                for rest in iter.by_ref() {
                    parsed.trace.push(Seen::Positional(rest.clone()));
                    parsed.positional.push(rest);
                }
                break;
            } else if let Some(key) = arg.strip_prefix("--") {
                let (name, inline) = match key.split_once('=') {
                    Some((name, value)) => (name, Some(value.to_string())),
                    None => (key, None),
                };
                let opt = match spec.long(name) {
                    LongMatch::Opt(opt) => opt,
                    LongMatch::Ambiguous => {
                        parsed.unknown.push(arg.clone());
                        parsed
                            .trace
                            .push(Seen::Ambiguous(arg.clone(), spec.abbreviated(name)));
                        continue;
                    }
                    LongMatch::None => {
                        // Not one of the tool's options. As argparse, it
                        // takes no value: what follows is parsed on its own.
                        parsed.unknown.push(arg.clone());
                        parsed.trace.push(Seen::Unknown(arg.clone()));
                        parsed.store_key(name, inline.unwrap_or_else(|| "true".into()));
                        continue;
                    }
                };
                if matches!(opt.kind, Kind::Flag | Kind::Count) {
                    if let Some(value) = inline {
                        // argparse: "ignored explicit argument".
                        parsed.unknown.push(arg.clone());
                        parsed.trace.push(Seen::Ignored(opt, value));
                        continue;
                    }
                }
                let value = match inline {
                    Some(value) => Some(value),
                    None => Self::take(opt.kind, &mut iter),
                };
                if value.is_none() && opt.kind == Kind::Value {
                    parsed.missing.push(format!("--{}", opt.long));
                    parsed.trace.push(Seen::Missing(opt));
                } else {
                    parsed.trace.push(Seen::Option(opt, value.clone()));
                }
                parsed.store(opt, value);
            } else if arg.len() > 1 && arg.starts_with('-') && !looks_negative(&arg) {
                let chars: Vec<char> = arg[1..].chars().collect();
                if spec.short(chars[0]).is_none() {
                    // argparse: the whole argument is unrecognized.
                    parsed.unknown.push(arg.clone());
                    parsed.trace.push(Seen::Unknown(arg.clone()));
                    continue;
                }
                // As argparse's consume_optional: each flag of a group takes
                // the rest of the argument as its explicit argument, which
                // must start with another option letter; `=` after a letter
                // separates an explicit value.
                let mut i = 0;
                while let Some(opt) = chars.get(i).and_then(|c| spec.short(*c)) {
                    let rest: String = chars[i + 1..].iter().collect();
                    let (sep, explicit) = match rest.strip_prefix('=') {
                        Some(value) => (true, value.to_string()),
                        None => (false, rest.clone()),
                    };
                    if matches!(opt.kind, Kind::Flag | Kind::Count) {
                        if rest.is_empty() {
                            parsed.trace.push(Seen::Option(opt, None));
                            parsed.store(opt, None);
                            break;
                        }
                        if sep || explicit.starts_with('-') || explicit.is_empty() {
                            parsed.unknown.push(arg.clone());
                            parsed.trace.push(Seen::Ignored(opt, explicit));
                            break;
                        }
                        parsed.trace.push(Seen::Option(opt, None));
                        parsed.store(opt, None);
                        if spec.short(chars[i + 1]).is_none() {
                            let extra = format!("-{rest}");
                            parsed.unknown.push(extra.clone());
                            parsed.trace.push(Seen::Unknown(extra));
                            break;
                        }
                        i += 1;
                        continue;
                    }
                    // A value option ends a group, its value the rest of the
                    // argument (`-t5`, `-t=5`) or the next one: `-t 5`.
                    let value = if rest.is_empty() {
                        Self::take(opt.kind, &mut iter)
                    } else {
                        Some(explicit)
                    };
                    if value.is_none() && opt.kind == Kind::Value {
                        parsed.missing.push(format!("-{}", chars[i]));
                        parsed.trace.push(Seen::Missing(opt));
                    } else {
                        parsed.trace.push(Seen::Option(opt, value.clone()));
                    }
                    parsed.store(opt, value);
                    break;
                }
            } else {
                parsed.trace.push(Seen::Positional(arg.clone()));
                parsed.positional.push(arg);
            }
        }
        parsed
    }

    /// The value an option without an attached one takes from the
    /// arguments that follow.
    fn take(
        kind: Kind,
        iter: &mut std::iter::Peekable<std::vec::IntoIter<String>>,
    ) -> Option<String> {
        match kind {
            Kind::Flag | Kind::Count => None,
            // As argparse, an option-like argument is not a value.
            Kind::Value => iter.next_if(is_value),
            Kind::Optional => match iter.peek() {
                Some(next) if is_value(next) => iter.next(),
                _ => None,
            },
        }
    }

    fn store(&mut self, opt: &Opt, value: Option<String>) {
        if opt.kind == Kind::Count {
            match opt.long {
                "verbose" => self.verbosity = self.verbosity.saturating_add(1),
                "quiet" => self.quiet = self.quiet.saturating_add(1),
                _ => {}
            }
            return;
        }
        let value = value.unwrap_or_else(|| "true".into());
        for key in [opt.short, opt.long] {
            if !key.is_empty() {
                self.store_key(key, value.clone());
            }
        }
    }

    fn store_key(&mut self, key: &str, value: String) {
        self.values.push((key.to_string(), value.clone()));
        self.flags.insert(key.to_string(), value);
    }

    fn parse_profile(args: Vec<String>, control: bool) -> Self {
        let mut flags = HashMap::new();
        let mut positional = Vec::new();
        let mut verbosity: u8 = 0;
        let mut quiet: u8 = 0;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            if arg == "--" {
                // Everything after -- is positional
                positional.extend(iter);
                break;
            } else if let Some(key) = arg.strip_prefix("--") {
                let key = key.to_string();
                // Check for --key=value syntax
                if let Some(eq_pos) = key.find('=') {
                    let (k, v) = key.split_at(eq_pos);
                    flags.insert(k.to_string(), v[1..].to_string());
                } else {
                    // Boolean flags that don't take values
                    match key.as_str() {
                        "verbose" => verbosity = verbosity.saturating_add(1),
                        "quiet" => quiet = quiet.saturating_add(1),
                        k if BOOLEAN_LONG.contains(&k) => {
                            flags.insert(key, "true".into());
                        }
                        _ => {
                            // Next arg is the value
                            if let Some(val) = iter.next() {
                                flags.insert(key, val);
                            } else {
                                flags.insert(key, "true".into());
                            }
                        }
                    }
                }
            } else if arg.starts_with('-') && arg.len() > 1 {
                // Short flags
                let chars: Vec<char> = arg[1..].chars().collect();
                for &c in &chars {
                    match c {
                        'v' => verbosity = verbosity.saturating_add(1),
                        'q' => quiet = quiet.saturating_add(1),
                        'a' | 'b' | 'r' | 'j' | 'P' | 'F' | 'D' | 'l' | 'f' | 'A' | 'Z' | 't'
                        | 'p' | 'x' | 'T'
                            if !control =>
                        {
                            flags.insert(c.to_string(), "true".into());
                        }
                        'a' | 'b' | 'r' | 'j' | 'P' | 'F' | 'D' | 'l' | 'f' | 'A' | 'Z'
                            if control =>
                        {
                            flags.insert(c.to_string(), "true".into());
                        }
                        'h' => {
                            flags.insert("help".into(), "true".into());
                        }
                        _ => {
                            // Short flag that may take a value: -c /path, -s rate
                            // Only consume next arg if it doesn't look like a flag
                            if chars.len() == 1 {
                                let next_is_value = iter
                                    .as_slice()
                                    .first()
                                    .map(|s| !s.starts_with('-') || s == "-")
                                    .unwrap_or(false);
                                if next_is_value {
                                    if let Some(val) = iter.next() {
                                        flags.insert(c.to_string(), val);
                                    } else {
                                        flags.insert(c.to_string(), "true".into());
                                    }
                                } else {
                                    flags.insert(c.to_string(), "true".into());
                                }
                            } else {
                                flags.insert(c.to_string(), "true".into());
                            }
                        }
                    }
                }
            } else {
                positional.push(arg);
            }
        }

        Args {
            flags,
            positional,
            verbosity,
            quiet,
            values: Vec::new(),
            unknown: Vec::new(),
            missing: Vec::new(),
            trace: Vec::new(),
        }
    }

    /// Get a flag value by long or short name.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.flags.get(key).map(|s| s.as_str())
    }

    /// Every value an option was given, in order (`-a x -a y`).
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        let all: Vec<&str> = self
            .values
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect();
        if all.is_empty() {
            self.get(key).into_iter().collect()
        } else {
            all
        }
    }

    /// Check if a flag is set.
    pub fn has(&self, key: &str) -> bool {
        self.flags.contains_key(key)
    }

    /// Get config path from --config or -c flag.
    pub fn config_path(&self) -> Option<&str> {
        self.get("config").or_else(|| self.get("c"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Args {
        Args::parse_from(s.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn parse_config_and_verbose() {
        let a = args(&["--config", "/path/to/config", "-vv", "-s"]);
        assert_eq!(a.config_path(), Some("/path/to/config"));
        assert_eq!(a.verbosity, 2);
        assert!(a.has("s"));
    }

    #[test]
    fn long_verbosity_counts() {
        let a = args(&["--verbose", "--verbose", "--quiet"]);
        assert_eq!((a.verbosity, a.quiet), (2, 1));
        assert!(a.positional.is_empty());
    }

    const SPEC: OptionSpec = OptionSpec {
        options: &[
            Opt::flag("x", "execute"),
            Opt::flag("p", "print"),
            Opt::optional("a", "announce"),
            Opt::value("t", "timeout"),
            Opt::value("i", ""),
            Opt::flag("", "table"),
            Opt::flag("", "tables-too"),
            Opt::count("v", "verbose"),
            Opt::count("q", "quiet"),
            Opt::value("", "allowed").rust_only(),
        ],
    };

    fn spec(s: &[&str]) -> Args {
        Args::parse_spec_from(s.iter().map(|s| s.to_string()).collect(), &SPEC)
    }

    #[test]
    fn spec_profile_follows_the_tool_table() {
        let a = spec(&["-t", "12", "-xp", "-a", "-i", "id", "file"]);
        assert_eq!(a.get("t"), Some("12"));
        assert_eq!(a.get("timeout"), Some("12"));
        assert!(a.has("x") && a.has("p") && a.has("execute") && a.has("print"));
        assert_eq!(a.get("a"), Some("true"));
        assert_eq!(a.get("i"), Some("id"));
        assert_eq!(a.positional, vec!["file"]);
        assert!(a.unknown.is_empty());
        let a = spec(&["-a", "app.aspect", "-t5", "--announce", "--verbose"]);
        assert_eq!(a.get("a"), Some("true"));
        assert_eq!(a.get("t"), Some("5"));
        assert_eq!(a.verbosity, 1);
    }

    #[test]
    fn spec_profile_parses_as_argparse() {
        // Attached values, also after flags in a group and after `=`.
        assert_eq!(spec(&["-xt5"]).get("timeout"), Some("5"));
        assert_eq!(spec(&["-t=5"]).get("t"), Some("5"));
        assert_eq!(spec(&["-vxt=5"]).get("t"), Some("5"));
        assert_eq!(spec(&["--timeout=5"]).get("t"), Some("5"));
        // A value option takes the next argument, even a negative number.
        assert_eq!(spec(&["-t", "-5"]).get("t"), Some("-5"));
        // An optional value is not taken from an option, nor a dash-less
        // negative number mistaken for one.
        let a = spec(&["-a", "-x"]);
        assert_eq!(a.get("a"), Some("true"));
        assert!(a.has("x"));
        assert_eq!(spec(&["-a", "-1"]).get("a"), Some("-1"));
        // Flags after positionals; negative numbers and `-` are positional.
        let a = spec(&["one", "-x", "-1.5", "-", "-v", "-vq"]);
        assert_eq!(a.positional, vec!["one", "-1.5", "-"]);
        assert!(a.has("x"));
        assert_eq!((a.verbosity, a.quiet), (2, 1));
        // Unique prefixes of upstream long names, exact Rust-only names.
        assert_eq!(spec(&["--time", "3"]).get("t"), Some("3"));
        assert!(spec(&["--exec"]).has("x"));
        assert!(spec(&["--verb"]).verbosity == 1);
        assert!(spec(&["--table"]).has("table"));
        assert!(spec(&["--tables"]).has("tables-too"));
        assert!(spec(&["--ver"]).unknown == vec!["--ver"]);
        assert_eq!(spec(&["--allowed", "h"]).get("allowed"), Some("h"));
        assert!(spec(&["--allow", "h"]).unknown == vec!["--allow"]);
        // `--` ends the options.
        assert_eq!(spec(&["--", "-x"]).positional, vec!["-x"]);
        // Help and version are implied.
        assert!(spec(&["-h"]).has("help"));
        assert!(spec(&["--vers"]).has("version"));
        // Repeated values are all kept.
        let a = spec(&["-i", "one", "-itwo"]);
        assert_eq!(a.get_all("i"), vec!["one", "two"]);
        assert_eq!(a.get("i"), Some("two"));
        // Unknown options are reported and, as argparse, take no value.
        let a = spec(&["-k", "v", "--other", "w", "--execute=1"]);
        assert_eq!(a.unknown, vec!["-k", "--other", "--execute=1"]);
        assert_eq!(a.positional, vec!["v", "w"]);
        assert!(!a.has("execute"));
        // A flag group ending in an unknown letter keeps its flags and
        // reports the rest; `=` after a flag is an ignored explicit value.
        let a = spec(&["-xvZq"]);
        assert!(a.has("x") && a.verbosity == 1);
        assert_eq!(a.unknown, vec!["-Zq"]);
        assert!(matches!(spec(&["-x=1"]).trace[..], [Seen::Ignored(_, ref v)] if v == "1"));
        // A value option does not take an option as its value.
        assert_eq!(spec(&["-t", "-x"]).missing, vec!["-t"]);
        // Value options without a value are reported.
        assert_eq!(spec(&["-x", "-t"]).missing, vec!["-t"]);
        assert_eq!(spec(&["--time"]).missing, vec!["--timeout"]);
        assert!(spec(&["-a"]).missing.is_empty());
    }

    #[test]
    fn parse_version() {
        let a = args(&["--version"]);
        assert!(a.has("version"));
    }

    #[test]
    fn parse_positional() {
        let a = args(&["-t", "abcd1234"]);
        assert!(a.has("t"));
        assert_eq!(a.positional, vec!["abcd1234"]);
    }

    #[test]
    fn tunnels_flag_takes_no_value() {
        // rnstatus -T (upstream 3281e283) leaves a name filter positional.
        let a = args(&["-T", "Backbone"]);
        assert!(a.has("T"));
        assert_eq!(a.positional, vec!["Backbone"]);
        assert!(args(&["--tunnels"]).has("tunnels"));
    }

    #[test]
    fn control_profile_allows_ambiguous_short_values() {
        let parsed = Args::parse_control_from(vec!["-t".into(), "12".into()]);
        assert_eq!(parsed.get("t"), Some("12"));
    }

    #[test]
    fn control_profile_treats_blocked_ips_as_boolean() {
        let parsed = Args::parse_control_from(vec![
            "status".into(),
            "-b".into(),
            "Backbone Listener".into(),
        ]);
        assert!(parsed.has("b"));
        assert_eq!(parsed.positional, vec!["status", "Backbone Listener"]);
    }

    #[test]
    fn parse_short_config() {
        let a = args(&["-c", "/my/config"]);
        assert_eq!(a.config_path(), Some("/my/config"));
    }

    #[test]
    fn parse_quiet() {
        let a = args(&["-qq"]);
        assert_eq!(a.quiet, 2);
    }

    #[test]
    fn parse_new_boolean_flags() {
        let a = args(&["-l", "-f", "-m", "-A", "-P", "-Z", "-b", "filter"]);
        assert!(a.has("l"));
        assert!(a.has("f"));
        assert!(a.has("m"));
        assert!(a.has("A"));
        assert!(a.has("P"));
        assert!(a.has("Z"));
        assert!(a.has("b"));
        assert_eq!(a.positional, vec!["filter"]);
    }

    #[test]
    fn parse_long_boolean_flags() {
        let a = args(&[
            "--stdin",
            "--stdout",
            "--force",
            "--blackholed",
            "--base256",
            "--base32",
            "--base64",
            "--raw",
            "--request",
            "--no-cache",
            "--print-identity",
            "--print-private",
            "--export-pub",
            "--export-prv",
            "--pr-stats",
            "--filter-stats",
            "--burst",
            "--blocked-ips",
            "--queues",
            "--meta",
        ]);
        assert!(a.has("stdin"));
        assert!(a.has("stdout"));
        assert!(a.has("force"));
        assert!(a.has("blackholed"));
        assert!(a.has("base256"));
        assert!(a.has("base32"));
        assert!(a.has("base64"));
        assert!(a.has("raw"));
        assert!(a.has("request"));
        assert!(a.has("no-cache"));
        assert!(a.has("print-identity"));
        assert!(a.has("print-private"));
        assert!(a.has("export-pub"));
        assert!(a.has("export-prv"));
        assert!(a.has("pr-stats"));
        assert!(a.has("filter-stats"));
        assert!(a.has("burst"));
        assert!(a.has("blocked-ips"));
        assert!(a.has("queues"));
        assert!(a.has("meta"));
    }

    #[test]
    fn parse_exampleconfig() {
        let a = args(&["--exampleconfig"]);
        assert!(a.has("exampleconfig"));
    }

    #[test]
    fn flag_with_value_vs_boolean() {
        // -s with a non-flag value should capture it
        let a = args(&["-s", "rate"]);
        assert_eq!(a.get("s"), Some("rate"));

        // -s followed by another flag should be boolean
        let a = args(&["-s", "-v"]);
        assert!(a.has("s"));
        assert_eq!(a.get("s"), Some("true"));
        assert_eq!(a.verbosity, 1);

        // -m with a value
        let a = args(&["-m", "5"]);
        assert_eq!(a.get("m"), Some("5"));

        // -m alone (boolean)
        let a = args(&["-m"]);
        assert!(a.has("m"));

        // -B with a hash value
        let a = args(&["-B", "abcdef1234567890"]);
        assert_eq!(a.get("B"), Some("abcdef1234567890"));

        // -B alone (boolean for base32 mode)
        let a = args(&["-B"]);
        assert!(a.has("B"));
    }
}
