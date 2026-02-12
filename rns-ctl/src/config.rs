use std::collections::HashMap;

/// Configuration for rns-ctl.
pub struct CtlConfig {
    /// Bind host (default: "127.0.0.1").
    pub host: String,
    /// HTTP port (default: 8080).
    pub port: u16,
    /// Bearer token for auth. If None and !disable_auth, a random token is generated.
    pub auth_token: Option<String>,
    /// Skip auth entirely.
    pub disable_auth: bool,
    /// Path to RNS config directory.
    pub config_path: Option<String>,
    /// Connect as shared instance client (--daemon).
    pub daemon_mode: bool,
    /// TLS certificate path.
    pub tls_cert: Option<String>,
    /// TLS private key path.
    pub tls_key: Option<String>,
}

impl Default for CtlConfig {
    fn default() -> Self {
        CtlConfig {
            host: "127.0.0.1".into(),
            port: 8080,
            auth_token: None,
            disable_auth: false,
            config_path: None,
            daemon_mode: false,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// Parsed command-line arguments.
pub struct Args {
    pub flags: HashMap<String, String>,
    pub verbosity: u8,
}

impl Args {
    pub fn parse() -> Self {
        Self::parse_from(std::env::args().skip(1).collect())
    }

    pub fn parse_from(args: Vec<String>) -> Self {
        let mut flags = HashMap::new();
        let mut verbosity: u8 = 0;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            if arg.starts_with("--") {
                let key = arg[2..].to_string();
                if let Some(eq_pos) = key.find('=') {
                    let (k, v) = key.split_at(eq_pos);
                    flags.insert(k.to_string(), v[1..].to_string());
                } else {
                    match key.as_str() {
                        "help" | "daemon" | "disable-auth" | "version" => {
                            flags.insert(key, "true".into());
                        }
                        _ => {
                            if let Some(val) = iter.next() {
                                flags.insert(key, val);
                            } else {
                                flags.insert(key, "true".into());
                            }
                        }
                    }
                }
            } else if arg.starts_with('-') && arg.len() > 1 {
                for c in arg[1..].chars() {
                    match c {
                        'v' => verbosity = verbosity.saturating_add(1),
                        'h' => {
                            flags.insert("help".into(), "true".into());
                        }
                        'd' => {
                            flags.insert("daemon".into(), "true".into());
                        }
                        _ => {
                            // Short flag with value: -c /path, -p 8080, -t token
                            if let Some(val) = iter.next() {
                                flags.insert(c.to_string(), val);
                            } else {
                                flags.insert(c.to_string(), "true".into());
                            }
                        }
                    }
                }
            }
        }

        Args { flags, verbosity }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.flags.get(key).map(|s| s.as_str())
    }

    pub fn has(&self, key: &str) -> bool {
        self.flags.contains_key(key)
    }
}

/// Build CtlConfig from CLI args + environment variables.
pub fn from_args_and_env(args: &Args) -> CtlConfig {
    let mut cfg = CtlConfig::default();

    // CLI args take precedence over env vars
    cfg.host = args
        .get("host")
        .or_else(|| args.get("H"))
        .map(String::from)
        .or_else(|| std::env::var("RNSCTL_HOST").ok())
        .unwrap_or(cfg.host);

    cfg.port = args
        .get("port")
        .or_else(|| args.get("p"))
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            std::env::var("RNSCTL_HTTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(cfg.port);

    cfg.auth_token = args
        .get("token")
        .or_else(|| args.get("t"))
        .map(String::from)
        .or_else(|| std::env::var("RNSCTL_AUTH_TOKEN").ok());

    cfg.disable_auth = args.has("disable-auth")
        || std::env::var("RNSCTL_DISABLE_AUTH")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

    cfg.config_path = args
        .get("config")
        .or_else(|| args.get("c"))
        .map(String::from)
        .or_else(|| std::env::var("RNSCTL_CONFIG_PATH").ok());

    cfg.daemon_mode = args.has("daemon");

    cfg.tls_cert = args
        .get("tls-cert")
        .map(String::from)
        .or_else(|| std::env::var("RNSCTL_TLS_CERT").ok());

    cfg.tls_key = args
        .get("tls-key")
        .map(String::from)
        .or_else(|| std::env::var("RNSCTL_TLS_KEY").ok());

    cfg
}

pub fn print_help() {
    println!(
        "rns-ctl - HTTP/WebSocket control interface for Reticulum

USAGE:
    rns-ctl [OPTIONS]

OPTIONS:
    -c, --config PATH       Path to RNS config directory
    -p, --port PORT         HTTP port (default: 8080, env: RNSCTL_HTTP_PORT)
    -H, --host HOST         Bind host (default: 127.0.0.1, env: RNSCTL_HOST)
    -t, --token TOKEN       Auth bearer token (env: RNSCTL_AUTH_TOKEN)
    -d, --daemon            Connect as client to running rnsd
        --disable-auth      Disable authentication
        --tls-cert PATH     TLS certificate file (env: RNSCTL_TLS_CERT, requires 'tls' feature)
        --tls-key PATH      TLS private key file (env: RNSCTL_TLS_KEY, requires 'tls' feature)
    -v                      Increase verbosity (repeat for more)
    -h, --help              Show this help
        --version           Show version"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Args {
        Args::parse_from(s.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn parse_basic() {
        let a = args(&["--port", "9090", "--host", "0.0.0.0", "-vv"]);
        assert_eq!(a.get("port"), Some("9090"));
        assert_eq!(a.get("host"), Some("0.0.0.0"));
        assert_eq!(a.verbosity, 2);
    }

    #[test]
    fn parse_short_config() {
        let a = args(&["-c", "/tmp/rns"]);
        assert_eq!(a.get("c"), Some("/tmp/rns"));
    }

    #[test]
    fn parse_daemon() {
        let a = args(&["-d"]);
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
    fn config_from_args() {
        let a = args(&["--port", "3000", "--host", "0.0.0.0", "--token", "secret", "--daemon"]);
        let cfg = from_args_and_env(&a);
        assert_eq!(cfg.port, 3000);
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.auth_token.as_deref(), Some("secret"));
        assert!(cfg.daemon_mode);
    }
}
