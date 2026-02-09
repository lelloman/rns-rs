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
                        | "blackholed" => {
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
                        'a' | 'r' | 't' | 'j' | 'p' | 'P' | 'x' | 'D'
                        | 'l' | 'f' | 'A' => {
                            flags.insert(c.to_string(), "true".into());
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
    fn parse_positional() {
        let a = args(&["-t", "abcd1234"]);
        assert!(a.has("t"));
        assert_eq!(a.positional, vec!["abcd1234"]);
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
