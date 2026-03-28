use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use rns_ctl::state::{
    LaunchProcessSnapshot, ProcessControlCommand, ServerConfigSnapshot, ServerHttpConfigSnapshot,
    SharedState,
};

use crate::args::Args;
use crate::supervisor::{ProcessReadiness, ProcessSpec, ReadinessTarget, Role, SupervisorConfig};

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub config_path: Option<PathBuf>,
    pub resolved_config_dir: PathBuf,
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

impl ServerConfig {
    pub fn from_args(args: &Args) -> Self {
        let config_path = args.config_path().map(PathBuf::from);
        let resolved_config_dir =
            rns_net::storage::resolve_config_dir(args.config_path().map(Path::new));
        let stats_db_path = args
            .get("stats-db")
            .map(PathBuf::from)
            .unwrap_or_else(|| resolved_config_dir.join("stats.db"));
        let rnsd_bin = args
            .get("rnsd-bin")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("rnsd"));
        let sentineld_bin = args
            .get("sentineld-bin")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("rns-sentineld"));
        let statsd_bin = args
            .get("statsd-bin")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("rns-statsd"));

        let ctl_cfg = rns_ctl::config::from_args_and_env(&Self::ctl_args_from_server_args(args));
        let rpc_port = Self::resolve_rpc_port(&resolved_config_dir);

        Self {
            config_path,
            resolved_config_dir,
            stats_db_path,
            rnsd_bin,
            sentineld_bin,
            statsd_bin,
            http: HttpConfig {
                enabled: !args.has("no-http"),
                host: ctl_cfg.host,
                port: ctl_cfg.port,
                auth_token: ctl_cfg.auth_token,
                disable_auth: ctl_cfg.disable_auth,
                daemon_mode: ctl_cfg.daemon_mode,
            },
            rnsd_rpc_addr: format!("127.0.0.1:{rpc_port}")
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:37429".parse().unwrap()),
        }
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
}
