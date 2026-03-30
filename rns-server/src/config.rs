use rns_ctl::state::{
    LaunchProcessSnapshot, ProcessControlCommand, ServerConfigApplyPlan, ServerConfigChange,
    ServerConfigFieldSchema, ServerConfigMutationMode, ServerConfigMutationResult,
    ServerConfigSchemaSnapshot, ServerConfigSnapshot, ServerConfigValidationSnapshot,
    ServerHttpConfigSnapshot, SharedState,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use crate::args::Args;
use crate::supervisor::{ProcessReadiness, ProcessSpec, ReadinessTarget, Role, SupervisorConfig};

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub config_path: Option<PathBuf>,
    pub resolved_config_dir: PathBuf,
    pub server_config_file_path: PathBuf,
    pub server_config_file_present: bool,
    pub file_config: ServerConfigFile,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
        let mut warnings = Self::validate_file_config(&candidate)?;
        let validated = self.with_file_config(&candidate, self.server_config_file_present);
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

    pub fn mutate_json_with_current_context(
        &self,
        mode: ServerConfigMutationMode,
        body: &[u8],
        control_tx: Option<mpsc::Sender<ProcessControlCommand>>,
    ) -> Result<ServerConfigMutationResult, String> {
        let candidate = Self::parse_config_json(body)?;
        let warnings = Self::validate_file_config(&candidate)?;
        let next = self.with_file_config(&candidate, true);
        let apply_plan = self.apply_plan(&next);

        std::fs::create_dir_all(&self.resolved_config_dir).map_err(|err| {
            format!(
                "failed to create config dir {}: {}",
                self.resolved_config_dir.display(),
                err
            )
        })?;
        let serialized = serde_json::to_vec_pretty(&candidate)
            .map_err(|err| format!("failed to serialize server config JSON: {}", err))?;
        std::fs::write(&self.server_config_file_path, serialized).map_err(|err| {
            format!(
                "failed to write {}: {}",
                self.server_config_file_path.display(),
                err
            )
        })?;

        if matches!(mode, ServerConfigMutationMode::Apply) {
            if let Some(tx) = control_tx {
                for process in &apply_plan.processes_to_restart {
                    tx.send(ProcessControlCommand::Restart(process.clone()))
                        .map_err(|_| {
                            format!("failed to queue restart for process '{}'", process)
                        })?;
                }
            }
        }

        Ok(ServerConfigMutationResult {
            action: match mode {
                ServerConfigMutationMode::Save => "save".into(),
                ServerConfigMutationMode::Apply => "apply".into(),
            },
            config: next.snapshot(),
            apply_plan,
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
                args: self.rnsd_args(),
            },
            ProcessSpec {
                role: Role::Sentineld,
                bin: self.sentineld_bin.clone(),
                args: self.sentineld_args(),
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
            server_config_file_json: self.editable_file_json(),
            stats_db_path: self.stats_db_path.display().to_string(),
            rnsd_bin: self.rnsd_bin.display().to_string(),
            sentineld_bin: self.sentineld_bin.display().to_string(),
            statsd_bin: self.statsd_bin.display().to_string(),
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

    pub fn schema_snapshot(&self) -> ServerConfigSchemaSnapshot {
        ServerConfigSchemaSnapshot {
            format: "rns-server.json".into(),
            example_config_json: Self::example_config_json(),
            notes: vec![
                format!(
                    "The config file is loaded from {}.",
                    self.server_config_file_path.display()
                ),
                "Only fields present in rns-server.json are persisted; CLI flags still override them at startup.".into(),
                "Changing process launch settings restarts only the affected child processes. Changing embedded HTTP settings requires restarting rns-server.".into(),
            ],
            fields: vec![
                ServerConfigFieldSchema {
                    field: "stats_db_path".into(),
                    field_type: "string".into(),
                    required: false,
                    default_value: self.resolved_config_dir.join("stats.db").display().to_string(),
                    description: "SQLite database path used by rns-statsd.".into(),
                    effect: "Restarts rns-statsd when changed.".into(),
                },
                ServerConfigFieldSchema {
                    field: "rnsd_bin".into(),
                    field_type: "string".into(),
                    required: false,
                    default_value: "rnsd".into(),
                    description: "Executable used for the Reticulum daemon.".into(),
                    effect: "Restarts rnsd when changed.".into(),
                },
                ServerConfigFieldSchema {
                    field: "sentineld_bin".into(),
                    field_type: "string".into(),
                    required: false,
                    default_value: "rns-sentineld".into(),
                    description: "Executable used for the sentinel sidecar.".into(),
                    effect: "Restarts rns-sentineld when changed.".into(),
                },
                ServerConfigFieldSchema {
                    field: "statsd_bin".into(),
                    field_type: "string".into(),
                    required: false,
                    default_value: "rns-statsd".into(),
                    description: "Executable used for the stats sidecar.".into(),
                    effect: "Restarts rns-statsd when changed.".into(),
                },
                ServerConfigFieldSchema {
                    field: "http.enabled".into(),
                    field_type: "boolean".into(),
                    required: false,
                    default_value: "true".into(),
                    description: "Enable or disable the embedded HTTP control plane.".into(),
                    effect: "Requires restarting rns-server.".into(),
                },
                ServerConfigFieldSchema {
                    field: "http.host".into(),
                    field_type: "string".into(),
                    required: false,
                    default_value: "127.0.0.1".into(),
                    description: "Bind host for the embedded HTTP control plane.".into(),
                    effect: "Requires restarting rns-server.".into(),
                },
                ServerConfigFieldSchema {
                    field: "http.port".into(),
                    field_type: "u16".into(),
                    required: false,
                    default_value: "8080".into(),
                    description: "Bind port for the embedded HTTP control plane.".into(),
                    effect: "Requires restarting rns-server.".into(),
                },
                ServerConfigFieldSchema {
                    field: "http.auth_token".into(),
                    field_type: "string".into(),
                    required: false,
                    default_value: "(generated if auth is enabled and no token is configured)".into(),
                    description: "Optional fixed bearer token for the embedded HTTP control plane.".into(),
                    effect: "Requires restarting rns-server.".into(),
                },
                ServerConfigFieldSchema {
                    field: "http.disable_auth".into(),
                    field_type: "boolean".into(),
                    required: false,
                    default_value: "false".into(),
                    description: "Disable bearer-token authentication on the embedded HTTP control plane.".into(),
                    effect: "Requires restarting rns-server.".into(),
                },
            ],
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
        vec![
            ProcessReadiness {
                role: Role::Rnsd,
                target: ReadinessTarget::Tcp(self.rnsd_rpc_addr),
            },
            ProcessReadiness {
                role: Role::Sentineld,
                target: ReadinessTarget::ReadyFile(self.sentineld_ready_file_path()),
            },
            ProcessReadiness {
                role: Role::Statsd,
                target: ReadinessTarget::ReadyFile(self.statsd_ready_file_path()),
            },
        ]
    }

    fn rnsd_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(path) = &self.config_path {
            args.push("--config".into());
            args.push(path.display().to_string());
        }
        args
    }

    fn sentineld_args(&self) -> Vec<String> {
        let mut args = self.rnsd_args();
        args.push("--ready-file".into());
        args.push(self.sentineld_ready_file_path().display().to_string());
        args
    }

    fn statsd_args(&self) -> Vec<String> {
        let mut args = self.rnsd_args();
        args.push("--db".into());
        args.push(self.stats_db_path.display().to_string());
        args.push("--ready-file".into());
        args.push(self.statsd_ready_file_path().display().to_string());
        args
    }

    fn sentineld_ready_file_path(&self) -> PathBuf {
        self.resolved_config_dir.join("rns-sentineld.ready")
    }

    fn statsd_ready_file_path(&self) -> PathBuf {
        self.resolved_config_dir.join("rns-statsd.ready")
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
            file_config: file_cfg.clone(),
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
        Self::validate_file_config(&cfg)?;
        Ok((cfg, true))
    }

    fn parse_config_json(body: &[u8]) -> Result<ServerConfigFile, String> {
        serde_json::from_slice(body).map_err(|err| format!("invalid server config JSON: {}", err))
    }

    fn validate_file_config(file_cfg: &ServerConfigFile) -> Result<Vec<String>, String> {
        let mut warnings = Vec::new();

        validate_optional_nonempty("stats_db_path", file_cfg.stats_db_path.as_deref())?;
        validate_optional_nonempty("rnsd_bin", file_cfg.rnsd_bin.as_deref())?;
        validate_optional_nonempty("sentineld_bin", file_cfg.sentineld_bin.as_deref())?;
        validate_optional_nonempty("statsd_bin", file_cfg.statsd_bin.as_deref())?;
        validate_optional_nonempty("http.host", file_cfg.http.host.as_deref())?;
        validate_optional_nonempty("http.auth_token", file_cfg.http.auth_token.as_deref())?;

        if matches!(file_cfg.http.enabled, Some(true)) && matches!(file_cfg.http.port, Some(0)) {
            return Err("http.port must be greater than 0 when HTTP is enabled".into());
        }

        if matches!(file_cfg.http.enabled, Some(false))
            && (file_cfg.http.host.is_some()
                || file_cfg.http.port.is_some()
                || file_cfg.http.auth_token.is_some()
                || file_cfg.http.disable_auth.is_some())
        {
            warnings.push(
                "HTTP config fields are present while http.enabled=false; they will be saved but remain inactive until HTTP is re-enabled."
                    .into(),
            );
        }

        if matches!(file_cfg.http.disable_auth, Some(true)) && file_cfg.http.auth_token.is_some() {
            warnings.push(
                "http.auth_token is set but disable_auth=true, so the token will be ignored until auth is enabled again."
                    .into(),
            );
        }

        Ok(warnings)
    }

    fn with_file_config(&self, file_cfg: &ServerConfigFile, file_present: bool) -> Self {
        Self::build(
            self.config_path.clone(),
            self.resolved_config_dir.clone(),
            self.server_config_file_path.clone(),
            file_present,
            file_cfg,
            None,
        )
    }

    fn apply_plan(&self, next: &Self) -> ServerConfigApplyPlan {
        let current_specs = self.process_specs();
        let next_specs = next.process_specs();
        let mut processes_to_restart = Vec::new();
        let mut changes = Vec::new();

        for current in &current_specs {
            let Some(next_spec) = next_specs.iter().find(|spec| spec.role == current.role) else {
                continue;
            };
            if current.bin != next_spec.bin || current.args != next_spec.args {
                let name = current.role.display_name().to_string();
                processes_to_restart.push(name.clone());
                if current.bin != next_spec.bin {
                    changes.push(ServerConfigChange {
                        field: format!("{name}.bin"),
                        before: current.bin.display().to_string(),
                        after: next_spec.bin.display().to_string(),
                        effect: format!("restart {name}"),
                    });
                }
                if current.args != next_spec.args {
                    changes.push(ServerConfigChange {
                        field: format!("{name}.args"),
                        before: if current.args.is_empty() {
                            "(none)".into()
                        } else {
                            current.args.join(" ")
                        },
                        after: if next_spec.args.is_empty() {
                            "(none)".into()
                        } else {
                            next_spec.args.join(" ")
                        },
                        effect: format!("restart {name}"),
                    });
                }
            }
        }

        let control_plane_restart_required = self.http.enabled != next.http.enabled
            || self.http.host != next.http.host
            || self.http.port != next.http.port
            || self.http.auth_token != next.http.auth_token
            || self.http.disable_auth != next.http.disable_auth;

        if self.stats_db_path != next.stats_db_path {
            changes.push(ServerConfigChange {
                field: "stats_db_path".into(),
                before: self.stats_db_path.display().to_string(),
                after: next.stats_db_path.display().to_string(),
                effect: "restart rns-statsd".into(),
            });
        }
        if self.http.enabled != next.http.enabled {
            changes.push(ServerConfigChange {
                field: "http.enabled".into(),
                before: self.http.enabled.to_string(),
                after: next.http.enabled.to_string(),
                effect: "restart rns-server".into(),
            });
        }
        if self.http.host != next.http.host {
            changes.push(ServerConfigChange {
                field: "http.host".into(),
                before: self.http.host.clone(),
                after: next.http.host.clone(),
                effect: "restart rns-server".into(),
            });
        }
        if self.http.port != next.http.port {
            changes.push(ServerConfigChange {
                field: "http.port".into(),
                before: self.http.port.to_string(),
                after: next.http.port.to_string(),
                effect: "restart rns-server".into(),
            });
        }
        if self.http.disable_auth != next.http.disable_auth {
            changes.push(ServerConfigChange {
                field: "http.disable_auth".into(),
                before: self.http.disable_auth.to_string(),
                after: next.http.disable_auth.to_string(),
                effect: "restart rns-server".into(),
            });
        }
        if self.http.auth_token != next.http.auth_token {
            changes.push(ServerConfigChange {
                field: "http.auth_token".into(),
                before: mask_token(&self.http.auth_token),
                after: mask_token(&next.http.auth_token),
                effect: "restart rns-server".into(),
            });
        }

        let mut notes = Vec::new();
        if processes_to_restart.is_empty() {
            notes.push("No supervised child restart is required for this config.".into());
        } else {
            notes.push(format!(
                "Restart required for: {}.",
                processes_to_restart.join(", ")
            ));
        }
        if control_plane_restart_required {
            notes.push(
                "Embedded control-plane HTTP settings changed and will only take effect after restarting rns-server."
                    .into(),
            );
        }

        ServerConfigApplyPlan {
            processes_to_restart,
            control_plane_restart_required,
            notes,
            changes,
        }
    }

    fn editable_file_json(&self) -> String {
        serde_json::to_string_pretty(&self.file_config)
            .unwrap_or_else(|_| "{\n  \"http\": {}\n}".into())
    }

    fn example_config_json() -> String {
        serde_json::to_string_pretty(&ServerConfigFile {
            stats_db_path: Some("stats.db".into()),
            rnsd_bin: Some("rnsd".into()),
            sentineld_bin: Some("rns-sentineld".into()),
            statsd_bin: Some("rns-statsd".into()),
            http: ServerHttpConfigFile {
                enabled: Some(true),
                host: Some("127.0.0.1".into()),
                port: Some(8080),
                auth_token: None,
                disable_auth: Some(false),
            },
        })
        .unwrap_or_else(|_| "{\n  \"http\": {}\n}".into())
    }
}

fn validate_optional_nonempty(field: &str, value: Option<&str>) -> Result<(), String> {
    if value.is_some_and(|raw| raw.trim().is_empty()) {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}

fn env_present(name: &str) -> bool {
    std::env::var_os(name).is_some()
}

fn env_true(name: &str) -> bool {
    std::env::var(name)
        .map(|value| value == "true" || value == "1")
        .unwrap_or(false)
}

fn mask_token(token: &Option<String>) -> String {
    match token {
        Some(value) if !value.is_empty() => format!("set({} chars)", value.len()),
        _ => "unset".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpConfig, ServerConfig, ServerConfigFile, ServerHttpConfigFile};
    use crate::supervisor::{ReadinessTarget, Role};
    use std::path::PathBuf;

    fn test_config() -> ServerConfig {
        ServerConfig {
            config_path: Some(PathBuf::from("/tmp/rns")),
            resolved_config_dir: PathBuf::from("/tmp/rns"),
            server_config_file_path: PathBuf::from("/tmp/rns/rns-server.json"),
            server_config_file_present: true,
            file_config: ServerConfigFile::default(),
            stats_db_path: PathBuf::from("/tmp/rns/stats.db"),
            rnsd_bin: PathBuf::from("rnsd"),
            sentineld_bin: PathBuf::from("rns-sentineld"),
            statsd_bin: PathBuf::from("rns-statsd"),
            http: HttpConfig {
                enabled: true,
                host: "127.0.0.1".into(),
                port: 8080,
                auth_token: None,
                disable_auth: false,
                daemon_mode: true,
            },
            rnsd_rpc_addr: "127.0.0.1:37429".parse().unwrap(),
        }
    }

    #[test]
    fn apply_plan_restarts_statsd_when_db_changes() {
        let current = test_config();
        let next = current.with_file_config(
            &ServerConfigFile {
                stats_db_path: Some("/tmp/rns/other-stats.db".into()),
                ..ServerConfigFile::default()
            },
            true,
        );

        let plan = current.apply_plan(&next);

        assert_eq!(plan.processes_to_restart, vec!["rns-statsd".to_string()]);
        assert!(plan
            .changes
            .iter()
            .any(|change| change.field == "stats_db_path"));
    }

    #[test]
    fn apply_plan_requires_server_restart_for_http_port_change() {
        let current = test_config();
        let next = current.with_file_config(
            &ServerConfigFile {
                http: ServerHttpConfigFile {
                    port: Some(9090),
                    ..ServerHttpConfigFile::default()
                },
                ..ServerConfigFile::default()
            },
            true,
        );

        let plan = current.apply_plan(&next);

        assert!(plan.control_plane_restart_required);
        assert!(plan.processes_to_restart.is_empty());
        assert!(plan
            .changes
            .iter()
            .any(|change| change.field == "http.port" && change.after == "9090"));
    }

    #[test]
    fn validation_rejects_unknown_fields() {
        let err = ServerConfig::parse_config_json(br#"{"unknown":true}"#).unwrap_err();
        assert!(err.contains("unknown field"));
    }

    #[test]
    fn validation_rejects_empty_strings() {
        let err = ServerConfig::validate_file_config(&ServerConfigFile {
            stats_db_path: Some("   ".into()),
            ..ServerConfigFile::default()
        })
        .unwrap_err();
        assert_eq!(err, "stats_db_path cannot be empty");
    }

    #[test]
    fn validation_warns_when_http_fields_are_disabled() {
        let warnings = ServerConfig::validate_file_config(&ServerConfigFile {
            http: ServerHttpConfigFile {
                enabled: Some(false),
                port: Some(8080),
                ..ServerHttpConfigFile::default()
            },
            ..ServerConfigFile::default()
        })
        .unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("http.enabled=false"));
    }

    #[test]
    fn process_specs_include_sidecar_ready_file_args() {
        let config = test_config();
        let specs = config.process_specs();

        let sentineld = specs
            .iter()
            .find(|spec| spec.role == Role::Sentineld)
            .unwrap();
        assert!(sentineld.args.windows(2).any(|pair| {
            pair[0] == "--ready-file" && pair[1] == "/tmp/rns/rns-sentineld.ready"
        }));

        let statsd = specs.iter().find(|spec| spec.role == Role::Statsd).unwrap();
        assert!(statsd
            .args
            .windows(2)
            .any(|pair| { pair[0] == "--ready-file" && pair[1] == "/tmp/rns/rns-statsd.ready" }));
    }

    #[test]
    fn readiness_checks_use_ready_files_for_sidecars() {
        let config = test_config();
        let readiness = config.readiness_checks();

        let sentineld = readiness
            .iter()
            .find(|entry| entry.role == Role::Sentineld)
            .unwrap();
        match &sentineld.target {
            ReadinessTarget::ReadyFile(path) => {
                assert_eq!(path, &PathBuf::from("/tmp/rns/rns-sentineld.ready"));
            }
            _ => panic!("unexpected sentineld readiness target"),
        }

        let statsd = readiness
            .iter()
            .find(|entry| entry.role == Role::Statsd)
            .unwrap();
        match &statsd.target {
            ReadinessTarget::ReadyFile(path) => {
                assert_eq!(path, &PathBuf::from("/tmp/rns/rns-statsd.ready"));
            }
            _ => panic!("unexpected statsd readiness target"),
        }
    }
}
