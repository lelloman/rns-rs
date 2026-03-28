use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use rns_ctl::state::{
    LaunchProcessSnapshot, ProcessControlCommand, ServerConfigSnapshot,
    ServerConfigValidationSnapshot, ServerHttpConfigSnapshot, SharedState,
};
use serde::{Deserialize, Serialize};

use crate::args::Args;
use crate::supervisor::{ProcessReadiness, ProcessSpec, ReadinessTarget, Role, SupervisorConfig};

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub config_path: Option<PathBuf>,
    pub resolved_config_dir: PathBuf,
    pub server_config_file_path: PathBuf,
    pub server_config_file_present: bool,
    pub stats_db_path: PathBuf,
    pub rnsd_bin: PathBuf,
    pub sentineld_bin: PathBuf,
    pub statsd_bin: PathBuf,
    pub http: HttpConfig,
    pub rnsd_rpc_addr: std::net::SocketAddr,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub auth_token: Option<String>,
    pub disable_auth: bool,
    pub daemon_mode: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerConfigFile {
    #[serde(default)]
    pub stats_db_path: Option<String>,
    #[serde(default)]
    pub rnsd_bin: Option<String>,
    #[serde(default)]
    pub sentineld_bin: Option<String>,
    #[serde(default)]
    pub statsd_bin: Option<String>,
    #[serde(default)]
    pub http: ServerHttpConfigFile,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerHttpConfigFile {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub disable_auth: Option<bool>,
}

impl ServerConfig {
    pub fn from_args(args: &Args) -> Self {
        let config_path = args.config_path().map(PathBuf::from);
        let resolved_config_dir =
            rns_net::storage::resolve_config_dir(args.config_path().map(Path::new));
        let server_config_file_path = resolved_config_dir.join("rns-server.json");
        let (file_cfg, file_present) = Self::load_config_file(&server_config_file_path)
            .unwrap_or_else(|err| {
                log::warn!(
                    "failed to load server config file {}: {}",
                    server_config_file_path.display(),
                    err
                );
                (ServerConfigFile::default(), false)
            });
        Self::build(
            config_path,
            resolved_config_dir,
            server_config_file_path,
            file_present,
            &file_cfg,
            Some(args),
        )
    }

    pub fn validate_json_with_current_context(
        &self,
        body: &[u8],
    ) -> Result<ServerConfigValidationSnapshot, String> {
        let candidate = Self::parse_config_json(body)?;
        let validated = Self::build(
            self.config_path.clone(),
            self.resolved_config_dir.clone(),
            self.server_config_file_path.clone(),
            self.server_config_file_present,
            &candidate,
            None,
        );

        let mut warnings = Vec::new();
        warnings.push(format!(
            "Validation used config dir {} and did not write any files.",
            self.resolved_config_dir.display()
        ));

        Ok(ServerConfigValidationSnapshot {
            valid: true,
            config: validated.snapshot(),
            warnings,
        })
    }

    pub fn supervisor_config(
        &self,
        shared_state: Option<SharedState>,
        control_rx: Option<mpsc::Receiver<ProcessControlCommand>>,
    ) -> SupervisorConfig {
        SupervisorConfig {
            specs: self.process_specs(),
            shared_state,
            control_rx,
            readiness: self.readiness_checks(),
        }
    }

    pub fn process_specs(&self) -> Vec<ProcessSpec> {
        vec![
            ProcessSpec {
                role: Role::Rnsd,
                bin: self.rnsd_bin.clone(),
                args: self.config_args(),
            },
            ProcessSpec {
                role: Role::Sentineld,
                bin: self.sentineld_bin.clone(),
                args: self.config_args(),
            },
            ProcessSpec {
                role: Role::Statsd,
                bin: self.statsd_bin.clone(),
                args: self.statsd_args(),
            },
        ]
    }

    pub fn snapshot(&self) -> ServerConfigSnapshot {
        ServerConfigSnapshot {
            config_path: self
                .config_path
                .as_ref()
                .map(|path| path.display().to_string()),
            resolved_config_dir: self.resolved_config_dir.display().to_string(),
            server_config_file_path: self.server_config_file_path.display().to_string(),
            server_config_file_present: self.server_config_file_present,
            stats_db_path: self.stats_db_path.display().to_string(),
            http: ServerHttpConfigSnapshot {
                enabled: self.http.enabled,
                host: self.http.host.clone(),
                port: self.http.port,
                auth_mode: if self.http.disable_auth {
                    "disabled".into()
                } else {
                    "bearer-token".into()
                },
                token_configured: self.http.auth_token.is_some(),
                daemon_mode: self.http.daemon_mode,
            },
            launch_plan: self
                .process_specs()
                .into_iter()
                .map(|spec| LaunchProcessSnapshot {
                    name: spec.role.display_name().to_string(),
                    bin: spec.bin.display().to_string(),
                    args: spec.args.clone(),
                    command_line: spec.command_line(),
                })
                .collect(),
        }
    }

    pub fn http_enabled(&self) -> bool {
        self.http.enabled
    }

    pub fn ctl_args(&self, verbosity: u8) -> rns_ctl::args::Args {
        let mut argv = vec!["--daemon".to_string()];
        if let Some(config_path) = &self.config_path {
            argv.push("--config".into());
            argv.push(config_path.display().to_string());
        }
        argv.push("--host".into());
        argv.push(self.http.host.clone());
        argv.push("--port".into());
        argv.push(self.http.port.to_string());
        if let Some(token) = &self.http.auth_token {
            argv.push("--token".into());
            argv.push(token.clone());
        }
        if self.http.disable_auth {
            argv.push("--disable-auth".into());
        }
        if verbosity > 0 {
            argv.push(format!("-{}", "v".repeat(verbosity as usize)));
        }
        rns_ctl::args::Args::parse_from(argv)
    }

    pub fn control_http_command_line(&self) -> String {
        let mut parts = vec!["embedded rns-ctl http".to_string(), "--daemon".to_string()];
        if let Some(config) = &self.config_path {
            parts.push("--config".to_string());
            parts.push(config.display().to_string());
        }
        parts.push("--host".to_string());
        parts.push(self.http.host.clone());
        parts.push("--port".to_string());
        parts.push(self.http.port.to_string());
        if let Some(token) = &self.http.auth_token {
            parts.push("--token".to_string());
            parts.push(token.clone());
        }
        if self.http.disable_auth {
            parts.push("--disable-auth".to_string());
        }
        parts.join(" ")
    }

    fn readiness_checks(&self) -> Vec<ProcessReadiness> {
        let mut readiness = vec![ProcessReadiness {
            role: Role::Rnsd,
            target: ReadinessTarget::Tcp(self.rnsd_rpc_addr),
        }];

        let sidecar_target = ReadinessTarget::ProcessAge(Duration::from_secs(1));

        readiness.push(ProcessReadiness {
            role: Role::Sentineld,
            target: sidecar_target.clone(),
        });
        readiness.push(ProcessReadiness {
            role: Role::Statsd,
            target: sidecar_target,
        });
        readiness
    }

    fn config_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(path) = &self.config_path {
            args.push("--config".into());
            args.push(path.display().to_string());
        }
        args
    }

    fn statsd_args(&self) -> Vec<String> {
        let mut args = self.config_args();
        args.push("--db".into());
        args.push(self.stats_db_path.display().to_string());
        args
    }

    fn ctl_args_from_server_args(args: &Args) -> rns_ctl::args::Args {
        let mut argv = vec!["--daemon".to_string()];
        if let Some(config_path) = args.config_path() {
            argv.push("--config".into());
            argv.push(config_path.to_string());
        }
        if let Some(host) = args.get("http-host") {
            argv.push("--host".into());
            argv.push(host.to_string());
        }
        if let Some(port) = args.get("http-port") {
            argv.push("--port".into());
            argv.push(port.to_string());
        }
        if let Some(token) = args.get("http-token") {
            argv.push("--token".into());
            argv.push(token.to_string());
        }
        if args.has("disable-auth") {
            argv.push("--disable-auth".into());
        }
        rns_ctl::args::Args::parse_from(argv)
    }

    fn resolve_rpc_port(config_dir: &Path) -> u16 {
        let config_file = config_dir.join("config");
        let parsed = if config_file.exists() {
            rns_net::config::parse_file(&config_file).ok()
        } else {
            rns_net::config::parse("").ok()
        };

        parsed
            .as_ref()
            .map(|cfg| cfg.reticulum.instance_control_port)
            .unwrap_or(37429)
    }

    fn build(
        config_path: Option<PathBuf>,
        resolved_config_dir: PathBuf,
        server_config_file_path: PathBuf,
        server_config_file_present: bool,
        file_cfg: &ServerConfigFile,
        args: Option<&Args>,
    ) -> Self {
        let ctl_cfg = args
            .map(Self::ctl_args_from_server_args)
            .map(|ctl_args| rns_ctl::config::from_args_and_env(&ctl_args));

        let stats_db_path = args
            .and_then(|args| args.get("stats-db"))
            .map(PathBuf::from)
            .or_else(|| file_cfg.stats_db_path.as_ref().map(PathBuf::from))
            .unwrap_or_else(|| resolved_config_dir.join("stats.db"));
        let rnsd_bin = args
            .and_then(|args| args.get("rnsd-bin"))
            .map(PathBuf::from)
            .or_else(|| file_cfg.rnsd_bin.as_ref().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("rnsd"));
        let sentineld_bin = args
            .and_then(|args| args.get("sentineld-bin"))
            .map(PathBuf::from)
            .or_else(|| file_cfg.sentineld_bin.as_ref().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("rns-sentineld"));
        let statsd_bin = args
            .and_then(|args| args.get("statsd-bin"))
            .map(PathBuf::from)
            .or_else(|| file_cfg.statsd_bin.as_ref().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("rns-statsd"));

        let http_enabled = if args.is_some_and(|args| args.has("no-http")) {
            false
        } else {
            file_cfg.http.enabled.unwrap_or(true)
        };
        let http_host = ctl_cfg
            .as_ref()
            .map(|cfg| cfg.host.clone())
            .filter(|_| {
                args.is_some_and(|args| args.get("http-host").is_some())
                    || env_present("RNSCTL_HOST")
            })
            .or_else(|| file_cfg.http.host.clone())
            .unwrap_or_else(|| "127.0.0.1".into());
        let http_port = ctl_cfg
            .as_ref()
            .map(|cfg| cfg.port)
            .filter(|_| {
                args.is_some_and(|args| args.get("http-port").is_some())
                    || env_present("RNSCTL_HTTP_PORT")
            })
            .or(file_cfg.http.port)
            .unwrap_or(8080);
        let http_auth_token = ctl_cfg
            .as_ref()
            .and_then(|cfg| cfg.auth_token.clone())
            .filter(|_| {
                args.is_some_and(|args| args.get("http-token").is_some())
                    || env_present("RNSCTL_AUTH_TOKEN")
            })
            .or_else(|| file_cfg.http.auth_token.clone());
        let http_disable_auth = if args.is_some_and(|args| args.has("disable-auth"))
            || env_true("RNSCTL_DISABLE_AUTH")
        {
            true
        } else {
            file_cfg.http.disable_auth.unwrap_or(false)
        };

        let rpc_port = Self::resolve_rpc_port(&resolved_config_dir);

        Self {
            config_path,
            resolved_config_dir,
            server_config_file_path,
            server_config_file_present,
            stats_db_path,
            rnsd_bin,
            sentineld_bin,
            statsd_bin,
            http: HttpConfig {
                enabled: http_enabled,
                host: http_host,
                port: http_port,
                auth_token: http_auth_token,
                disable_auth: http_disable_auth,
                daemon_mode: true,
            },
            rnsd_rpc_addr: format!("127.0.0.1:{rpc_port}")
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:37429".parse().unwrap()),
        }
    }

    fn load_config_file(path: &Path) -> Result<(ServerConfigFile, bool), String> {
        if !path.exists() {
            return Ok((ServerConfigFile::default(), false));
        }
        let body = std::fs::read(path)
            .map_err(|err| format!("failed to read {}: {}", path.display(), err))?;
        let cfg = Self::parse_config_json(&body)?;
        Ok((cfg, true))
    }

    fn parse_config_json(body: &[u8]) -> Result<ServerConfigFile, String> {
        serde_json::from_slice(body).map_err(|err| format!("invalid server config JSON: {}", err))
    }
}

fn env_present(name: &str) -> bool {
    std::env::var_os(name).is_some()
}

fn env_true(name: &str) -> bool {
    std::env::var(name)
        .map(|value| value == "true" || value == "1")
        .unwrap_or(false)
}
