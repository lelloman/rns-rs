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
                        "version" | "exampleconfig" | "help" => {
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
                        's' | 'a' | 'r' | 't' | 'j' | 'p' | 'P' | 'b' | 'B' | 'x' | 'D' => {
                            flags.insert(c.to_string(), "true".into());
                        }
                        _ => {
                            // Short flag with value: -c /path
                            if chars.len() == 1 {
                                if let Some(val) = iter.next() {
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
}
