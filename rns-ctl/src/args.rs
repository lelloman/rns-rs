//! Simple command-line argument parser.
//!
//! No external dependencies. Supports `--flag`, `--key value`, `-v` (count),
//! and positional arguments.

use std::collections::HashMap;

/// Parsed command-line arguments.
pub struct Args {
    pub flags: HashMap<String, String>,
    pub positional: Vec<String>,
    pub verbosity: u8,
    pub quiet: u8,
}

impl Args {
    /// Parse command-line arguments (skipping argv[0]).
    pub fn parse() -> Self {
        Self::parse_from(std::env::args().skip(1).collect())
    }

    /// Parse from a list of argument strings.
    pub fn parse_from(args: Vec<String>) -> Self {
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
            } else if arg.starts_with("--") {
                let key = arg[2..].to_string();
                // Check for --key=value syntax
                if let Some(eq_pos) = key.find('=') {
                    let (k, v) = key.split_at(eq_pos);
                    flags.insert(k.to_string(), v[1..].to_string());
                } else {
                    // Boolean flags that don't take values
                    match key.as_str() {
                        "version" | "exampleconfig" | "help"
                        | "stdin" | "stdout" | "force"
                        | "blackholed"
                        | "daemon" | "disable-auth" => {
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
                        'a' | 'r' | 'j' | 'P' | 'D'
                        | 'l' | 'f' | 'A' => {
                            flags.insert(c.to_string(), "true".into());
                        }
                        'h' => {
                            flags.insert("help".into(), "true".into());
                        }
                        _ => {
                            // Short flag that may take a value: -c /path, -s rate
                            // Only consume next arg if it doesn't look like a flag
                            if chars.len() == 1 {
                                let next_is_value = iter.as_slice().first()
                                    .map(|s| !s.starts_with('-') || s == "-")
                                    .unwrap_or(false);
                                if next_is_value {
                                    let val = iter.next().unwrap();
                                    flags.insert(c.to_string(), val);
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
        }
    }

    /// Get a flag value by long or short name.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.flags.get(key).map(|s| s.as_str())
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
    fn parse_version() {
        let a = args(&["--version"]);
        assert!(a.has("version"));
    }

    #[test]
    fn parse_short_flag_with_value() {
        // -t with a non-flag value captures it (used by probe -t SECS, http -t TOKEN)
        let a = args(&["-t", "abcd1234"]);
        assert_eq!(a.get("t"), Some("abcd1234"));
    }

    #[test]
    fn parse_short_flag_boolean() {
        // -t alone is boolean (used by status -t, path -t)
        let a = args(&["-t"]);
        assert!(a.has("t"));
        assert_eq!(a.get("t"), Some("true"));
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
        let a = args(&["-l", "-f", "-m", "-A"]);
        assert!(a.has("l"));
        assert!(a.has("f"));
        assert!(a.has("m"));
        assert!(a.has("A"));
    }

    #[test]
    fn parse_long_boolean_flags() {
        let a = args(&["--stdin", "--stdout", "--force", "--blackholed"]);
        assert!(a.has("stdin"));
        assert!(a.has("stdout"));
        assert!(a.has("force"));
        assert!(a.has("blackholed"));
    }

    #[test]
    fn parse_exampleconfig() {
        let a = args(&["--exampleconfig"]);
        assert!(a.has("exampleconfig"));
    }

    #[test]
    fn parse_short_d_boolean() {
        // -d alone is boolean (used by http -d for daemon mode)
        let a = args(&["-d"]);
        assert!(a.has("d"));
        assert_eq!(a.get("d"), Some("true"));
    }

    #[test]
    fn parse_short_d_with_value() {
        // -d with a value (used by id -d FILE, path -d HASH)
        let a = args(&["-d", "file.enc"]);
        assert_eq!(a.get("d"), Some("file.enc"));
    }

    #[test]
    fn parse_daemon_long() {
        let a = args(&["--daemon"]);
        assert!(a.has("daemon"));
    }

    #[test]
    fn parse_disable_auth() {
        let a = args(&["--disable-auth"]);
        assert!(a.has("disable-auth"));
    }

    #[test]
    fn parse_help() {
        let a = args(&["--help"]);
        assert!(a.has("help"));
        let a = args(&["-h"]);
        assert!(a.has("help"));
    }

    #[test]
    fn parse_short_p_with_value() {
        // -p with a value (used by http -p PORT)
        let a = args(&["-p", "8080"]);
        assert_eq!(a.get("p"), Some("8080"));
    }

    #[test]
    fn parse_short_p_boolean() {
        // -p alone is boolean (used by id -p for print public key)
        let a = args(&["-p"]);
        assert!(a.has("p"));
    }

    #[test]
    fn parse_short_x_with_value() {
        // -x with a value (used by path -x HASH)
        let a = args(&["-x", "abcd1234"]);
        assert_eq!(a.get("x"), Some("abcd1234"));
    }

    #[test]
    fn parse_short_x_boolean() {
        // -x alone is boolean (used by id -x for export hex)
        let a = args(&["-x"]);
        assert!(a.has("x"));
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
