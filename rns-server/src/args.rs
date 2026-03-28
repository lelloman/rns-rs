use std::collections::HashMap;

#[derive(Clone)]
pub struct Args {
    pub flags: HashMap<String, String>,
    pub positional: Vec<String>,
    pub verbosity: u8,
    pub quiet: u8,
}

impl Args {
    pub fn parse() -> Self {
        Self::parse_from(std::env::args().skip(1).collect())
    }

    pub fn parse_from(args: Vec<String>) -> Self {
        let mut flags = HashMap::new();
        let mut positional = Vec::new();
        let mut verbosity: u8 = 0;
        let mut quiet: u8 = 0;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            if arg == "--" {
                positional.extend(iter);
                break;
            } else if let Some(key) = arg.strip_prefix("--") {
                if let Some(eq_pos) = key.find('=') {
                    let (k, v) = key.split_at(eq_pos);
                    flags.insert(k.to_string(), v[1..].to_string());
                    continue;
                }
                match key {
                    "help" | "version" | "dry-run" | "disable-auth" | "no-http" => {
                        flags.insert(key.to_string(), "true".into());
                    }
                    _ => {
                        if let Some(value) = iter.next() {
                            flags.insert(key.to_string(), value);
                        } else {
                            flags.insert(key.to_string(), "true".into());
                        }
                    }
                }
            } else if arg.starts_with('-') && arg.len() > 1 {
                let chars: Vec<char> = arg[1..].chars().collect();
                for &c in &chars {
                    match c {
                        'v' => verbosity = verbosity.saturating_add(1),
                        'q' => quiet = quiet.saturating_add(1),
                        'h' => {
                            flags.insert("help".into(), "true".into());
                        }
                        'c' => {
                            if chars.len() == 1 {
                                if let Some(value) = iter.next() {
                                    flags.insert("config".into(), value);
                                } else {
                                    flags.insert("config".into(), "true".into());
                                }
                            } else {
                                flags.insert("config".into(), "true".into());
                            }
                        }
                        _ => {
                            flags.insert(c.to_string(), "true".into());
                        }
                    }
                }
            } else {
                positional.push(arg);
            }
        }

        Self {
            flags,
            positional,
            verbosity,
            quiet,
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.flags.get(key).map(|s| s.as_str())
    }

    pub fn has(&self, key: &str) -> bool {
        self.flags.contains_key(key)
    }

    pub fn config_path(&self) -> Option<&str> {
        self.get("config")
    }
}

#[cfg(test)]
mod tests {
    use super::Args;

    #[test]
    fn parse_start_with_config() {
        let args = Args::parse_from(vec![
            "start".into(),
            "--config".into(),
            "/tmp/rns".into(),
            "-vv".into(),
        ]);
        assert_eq!(args.positional, vec!["start"]);
        assert_eq!(args.config_path(), Some("/tmp/rns"));
        assert_eq!(args.verbosity, 2);
    }

    #[test]
    fn parse_short_config() {
        let args = Args::parse_from(vec!["start".into(), "-c".into(), "/tmp/rns".into()]);
        assert_eq!(args.config_path(), Some("/tmp/rns"));
    }
}
