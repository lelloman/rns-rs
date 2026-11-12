use std::collections::HashMap;
use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::logs::{LogPolicy, LogStore};
use crate::self_exec::{resolve_self_exec, self_exec_display};
use rns_ctl::state::{
    bump_process_restart_count, mark_process_failed_spawn, mark_process_running,
    mark_process_stopped, push_process_log, record_process_termination_observation,
    set_process_log_path, set_process_readiness, ProcessControlCommand, SharedState,
};
use rns_net::{event::DrainStatus, HookInfo, RpcAddr, RpcClient};

mod drain;
mod process;
mod readiness;
mod wake;

use self::process::{
    check_exits, exit_code, role_from_name, spawn_child, terminate_child, terminate_children,
    ManagedChild,
};
use self::readiness::ready_file_path_for_role;
pub use self::readiness::{ProcessReadiness, ReadinessTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Rnsd,
    Sentineld,
    Statsd,
}

impl Role {
    pub fn display_name(self) -> &'static str {
        match self {
            Role::Rnsd => "rnsd",
            Role::Sentineld => "rns-sentineld",
            Role::Statsd => "rns-statsd",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub role: Role,
    pub command: ProcessCommand,
    pub args: Vec<String>,
}

impl ProcessSpec {
    pub fn command_line(&self) -> String {
        let mut parts = vec![self.command.display(self.role)];
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessCommand {
    External(PathBuf),
    SelfInvoke,
}

impl ProcessCommand {
    pub fn display(&self, role: Role) -> String {
        match self {
            ProcessCommand::External(path) => path.display().to_string(),
            ProcessCommand::SelfInvoke => {
                format!(
                    "{} --internal-role {}",
                    self_exec_display(),
                    role.display_name()
                )
            }
        }
    }
}

pub struct SupervisorConfig {
    pub specs: Vec<ProcessSpec>,
    pub shared_state: Option<SharedState>,
    pub control_rx: Option<mpsc::Receiver<ProcessControlCommand>>,
    pub readiness: Vec<ProcessReadiness>,
    pub log_dir: Option<(PathBuf, LogPolicy)>,
    pub rnsd_drain: Option<RnsdDrainConfig>,
}

pub struct Supervisor {
    specs: Vec<ProcessSpec>,
    shared_state: Option<SharedState>,
    /// Taken by a run, which forwards commands to its loop.
    control_rx: std::sync::Mutex<Option<mpsc::Receiver<ProcessControlCommand>>>,
    readiness: Vec<ProcessReadiness>,
    log_store: Option<LogStore>,
    rnsd_drain: Option<RnsdDrainConfig>,
}

fn read_shared_state<'a>(
    state: &'a SharedState,
) -> std::sync::RwLockReadGuard<'a, rns_ctl::state::CtlState> {
    match state.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned supervisor shared state read lock");
            poisoned.into_inner()
        }
    }
}

#[derive(Debug, Clone)]
pub struct RnsdDrainConfig {
    pub rpc_addr: RpcAddr,
    pub auth_key: [u8; 32],
    pub timeout: Duration,
    pub poll_interval: Duration,
}

impl Supervisor {
    pub fn new(config: SupervisorConfig) -> Self {
        Self {
            specs: config.specs,
            shared_state: config.shared_state,
            control_rx: std::sync::Mutex::new(config.control_rx),
            readiness: config.readiness,
            log_store: config
                .log_dir
                .map(|(dir, policy)| LogStore::with_policy(dir, policy)),
            rnsd_drain: config.rnsd_drain,
        }
    }

    pub fn specs(&self) -> &[ProcessSpec] {
        &self.specs
    }

    pub fn run(&self) -> Result<i32, String> {
        self.run_with_started_hook(|| Ok(()))
    }

    pub fn run_with_started_hook<F>(&self, on_started: F) -> Result<i32, String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        let mut children = self
            .specs
            .iter()
            .map(|spec| spawn_child(spec, self.shared_state.as_ref(), self.log_store.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut unexpected_restart_counts = HashMap::new();

        on_started()?;

        let wake = wake::Wake::new().map_err(|e| format!("cannot set up the supervisor: {}", e))?;
        wake.install_signal_handlers();
        let control = self.forward_control_commands(wake.waker());
        let mut exit_watches: HashMap<u32, std::os::fd::OwnedFd> = HashMap::new();
        let mut next_probe = Instant::now();
        let mut stop = false;

        loop {
            if stop {
                log::info!("shutdown requested");
                self.drain_rnsd(&children, "supervisor shutdown");
                terminate_children(&mut children, self.shared_state.as_ref(), &self.readiness);
                return Ok(0);
            }

            while let Some(command) = control.as_ref().and_then(|rx| rx.try_recv().ok()) {
                self.handle_control_command(command, &mut children)?;
            }

            if Instant::now() >= next_probe {
                // Often while a process is starting, then as a health check.
                let interval = if self.refresh_readiness() {
                    READINESS_HEALTH_INTERVAL
                } else {
                    READINESS_STARTUP_INTERVAL
                };
                next_probe = Instant::now() + interval;
            }

            if let Some((role, status)) = check_exits(&mut children)? {
                log::warn!("{} exited with status {}", role.display_name(), status);
                if self.restart_unexpected_exit(
                    role,
                    status,
                    &mut children,
                    &mut unexpected_restart_counts,
                )? {
                    continue;
                }
                if let Some(state) = self.shared_state.as_ref() {
                    mark_process_stopped(state, role.display_name(), status.code());
                }
                terminate_children(&mut children, self.shared_state.as_ref(), &self.readiness);
                return Ok(exit_code(status));
            }

            // Sleep until a child exits, a command or signal arrives, or the
            // next probe is due. Without a way to watch a child's exit, check
            // as often as the threads before did.
            exit_watches.retain(|pid, _| children.iter().any(|c| c.child.id() == *pid));
            let mut watched = true;
            for managed in &children {
                let pid = managed.child.id();
                if let std::collections::hash_map::Entry::Vacant(entry) = exit_watches.entry(pid) {
                    match wake::exit_watch(pid) {
                        Some(fd) => {
                            entry.insert(fd);
                        }
                        None => watched = false,
                    }
                }
            }
            let mut timeout = next_probe
                .saturating_duration_since(Instant::now())
                .min(READINESS_HEALTH_INTERVAL);
            if !watched {
                timeout = timeout.min(UNWATCHED_EXIT_CHECK);
            }
            let fds: Vec<_> = exit_watches
                .values()
                .map(std::os::fd::AsRawFd::as_raw_fd)
                .collect();
            stop = wake.wait(&fds, timeout);
        }
    }

    /// Hand control commands to the loop through a channel of the run's
    /// own, waking it for each.
    fn forward_control_commands(
        &self,
        waker: wake::Waker,
    ) -> Option<mpsc::Receiver<ProcessControlCommand>> {
        let commands = self
            .control_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()?;
        let (tx, rx) = mpsc::channel();
        let spawned = thread::Builder::new()
            .name("supervisor-ctl".into())
            .spawn(move || {
                while let Ok(command) = commands.recv() {
                    if tx.send(command).is_err() {
                        return;
                    }
                    waker.wake();
                }
            });
        if let Err(e) = spawned {
            log::error!("cannot take process control commands: {}", e);
            return None;
        }
        Some(rx)
    }
}

/// How often readiness is probed while some process is not ready.
const READINESS_STARTUP_INTERVAL: Duration = Duration::from_millis(200);
/// How often readiness is probed once every process is ready.
const READINESS_HEALTH_INTERVAL: Duration = Duration::from_secs(5);
/// How often children are checked for an exit when it cannot be watched.
const UNWATCHED_EXIT_CHECK: Duration = Duration::from_millis(200);

impl Supervisor {
    fn restart_unexpected_exit(
        &self,
        role: Role,
        status: ExitStatus,
        children: &mut [ManagedChild],
        unexpected_restart_counts: &mut HashMap<Role, usize>,
    ) -> Result<bool, String> {
        const MAX_UNEXPECTED_RESTARTS: usize = 3;
        const UNEXPECTED_RESTART_BACKOFF: Duration = Duration::from_millis(200);

        let Some(index) = children.iter().position(|child| child.role == role) else {
            return Ok(false);
        };
        let Some(spec) = self.specs.iter().find(|spec| spec.role == role) else {
            return Ok(false);
        };

        let attempts = unexpected_restart_counts.entry(role).or_insert(0);
        if *attempts >= MAX_UNEXPECTED_RESTARTS {
            return Ok(false);
        }
        *attempts += 1;

        if let Some(state) = self.shared_state.as_ref() {
            mark_process_stopped(state, role.display_name(), status.code());
            bump_process_restart_count(state, role.display_name());
            push_process_log(
                state,
                role.display_name(),
                "supervisor",
                format!(
                    "unexpected exit with status {}; restarting ({}/{})",
                    exit_code(status),
                    *attempts,
                    MAX_UNEXPECTED_RESTARTS
                ),
            );
        }

        thread::sleep(UNEXPECTED_RESTART_BACKOFF);
        children[index] = spawn_child(spec, self.shared_state.as_ref(), self.log_store.clone())?;
        Ok(true)
    }

    fn handle_control_command(
        &self,
        command: ProcessControlCommand,
        children: &mut Vec<ManagedChild>,
    ) -> Result<(), String> {
        match command {
            ProcessControlCommand::Restart(name) => self.restart_process(&name, children),
            ProcessControlCommand::Start(name) => self.start_process(&name, children),
            ProcessControlCommand::Stop(name) => self.stop_process(&name, children),
        }
    }

    fn restart_process(&self, name: &str, children: &mut [ManagedChild]) -> Result<(), String> {
        let Some(role) = role_from_name(name) else {
            return Err(format!("unknown process '{}'", name));
        };
        let Some(spec) = self.specs.iter().find(|spec| spec.role == role) else {
            return Err(format!("missing process spec for '{}'", name));
        };

        if let Some(index) = children.iter().position(|child| child.role == role) {
            self.drain_role(role, children, "process restart");
            let ready_file = ready_file_path_for_role(role, &self.readiness);
            terminate_child(
                &mut children[index],
                self.shared_state.as_ref(),
                ready_file.as_ref(),
            )
            .map_err(|e| {
                format!(
                    "failed to terminate {} during restart: {}",
                    role.display_name(),
                    e
                )
            })?;
            if let Some(state) = self.shared_state.as_ref() {
                mark_process_stopped(state, role.display_name(), None);
                bump_process_restart_count(state, role.display_name());
            }
            children[index] =
                spawn_child(spec, self.shared_state.as_ref(), self.log_store.clone())?;
        }

        Ok(())
    }

    fn start_process(&self, name: &str, children: &mut Vec<ManagedChild>) -> Result<(), String> {
        let Some(role) = role_from_name(name) else {
            return Err(format!("unknown process '{}'", name));
        };
        if children.iter().any(|child| child.role == role) {
            return Ok(());
        }
        let Some(spec) = self.specs.iter().find(|spec| spec.role == role) else {
            return Err(format!("missing process spec for '{}'", name));
        };
        children.push(spawn_child(
            spec,
            self.shared_state.as_ref(),
            self.log_store.clone(),
        )?);
        Ok(())
    }

    fn stop_process(&self, name: &str, children: &mut Vec<ManagedChild>) -> Result<(), String> {
        let Some(role) = role_from_name(name) else {
            return Err(format!("unknown process '{}'", name));
        };
        let Some(index) = children.iter().position(|child| child.role == role) else {
            return Ok(());
        };
        self.drain_role(role, children, "process stop");
        let ready_file = ready_file_path_for_role(role, &self.readiness);
        terminate_child(
            &mut children[index],
            self.shared_state.as_ref(),
            ready_file.as_ref(),
        )
        .map_err(|e| {
            format!(
                "failed to terminate {} during stop: {}",
                role.display_name(),
                e
            )
        })?;
        if let Some(state) = self.shared_state.as_ref() {
            let code = children[index]
                .child
                .try_wait()
                .ok()
                .flatten()
                .and_then(|status| status.code());
            mark_process_stopped(state, role.display_name(), code);
        }
        children.remove(index);
        Ok(())
    }

    /// Probe every process's readiness, returning whether all are ready.
    fn refresh_readiness(&self) -> bool {
        let Some(state) = self.shared_state.as_ref() else {
            return true;
        };

        let mut all_ready = true;
        for readiness in &self.readiness {
            let (ready, ready_state, detail) = readiness.probe(state);
            all_ready &= ready;
            set_process_readiness(state, readiness.name(), ready, ready_state, detail);
        }
        all_ready
    }
}

#[cfg(test)]
mod tests {
    use super::drain::{
        drain_complete_for_shutdown, format_drain_status_detail, log_rnsd_drain_progress,
        reflect_rnsd_drain_status, request_rnsd_drain, wait_for_rnsd_drain,
    };
    use super::process::{command_for_spec, role_from_name, shutdown_priority};
    use super::readiness::{
        inspect_ready_file, missing_required_hooks, observe_sidecar_draining, probe_ready_file,
        ready_file_path_for_role,
    };
    use super::{
        ProcessCommand, ProcessReadiness, ProcessSpec, ReadinessTarget, RnsdDrainConfig, Role,
        Supervisor, SupervisorConfig,
    };
    use rns_ctl::state::{ensure_process, mark_process_running, CtlState, SharedState};
    use rns_net::{
        event::EventSender,
        event::{DrainStatus, Event, LifecycleState, QueryRequest, QueryResponse},
        HookInfo, RpcAddr, RpcServer,
    };
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::mpsc;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn supervisor_holds_expected_specs() {
        let specs = vec![
            ProcessSpec {
                role: Role::Rnsd,
                command: ProcessCommand::External(PathBuf::from("rnsd")),
                args: vec!["--config".into(), "/tmp/rns".into()],
            },
            ProcessSpec {
                role: Role::Sentineld,
                command: ProcessCommand::External(PathBuf::from("rns-sentineld")),
                args: vec!["--config".into(), "/tmp/rns".into()],
            },
            ProcessSpec {
                role: Role::Statsd,
                command: ProcessCommand::External(PathBuf::from("rns-statsd")),
                args: vec![
                    "--config".into(),
                    "/tmp/rns".into(),
                    "--db".into(),
                    "/tmp/rns/stats.db".into(),
                ],
            },
        ];

        let supervisor = SupervisorConfig {
            specs,
            shared_state: None,
            control_rx: None,
            readiness: Vec::new(),
            log_dir: None,
            rnsd_drain: None,
        };

        assert_eq!(supervisor.specs.len(), 3);
        assert_eq!(supervisor.specs[0].role, Role::Rnsd);
        assert_eq!(supervisor.specs[1].role, Role::Sentineld);
        assert_eq!(supervisor.specs[2].role, Role::Statsd);
        assert!(supervisor.specs[2].args.iter().any(|arg| arg == "--db"));
    }

    #[test]
    fn process_spec_command_line() {
        let spec = ProcessSpec {
            role: Role::Rnsd,
            command: ProcessCommand::External(PathBuf::from("rnsd")),
            args: vec!["--config".into(), "/data".into()],
        };
        assert_eq!(spec.command_line(), "rnsd --config /data");
    }

    #[test]
    fn self_invoke_command_line_uses_internal_role() {
        let spec = ProcessSpec {
            role: Role::Statsd,
            command: ProcessCommand::SelfInvoke,
            args: vec!["--config".into(), "/data".into()],
        };
        assert_eq!(
            spec.command_line(),
            "/proc/self/exe --internal-role rns-statsd --config /data"
        );
    }

    #[test]
    fn self_invoke_command_builder_includes_internal_role_args() {
        let spec = ProcessSpec {
            role: Role::Sentineld,
            command: ProcessCommand::SelfInvoke,
            args: vec!["--config".into(), "/data".into()],
        };
        let command = command_for_spec(&spec).unwrap();
        let program = command.get_program().to_string_lossy().to_string();
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        assert!(program == "/proc/self/exe" || !program.is_empty());
        assert_eq!(
            args,
            vec![
                "--internal-role".to_string(),
                "rns-sentineld".to_string(),
                "--config".to_string(),
                "/data".to_string()
            ]
        );
    }

    #[test]
    fn role_from_name_maps_known_processes() {
        assert_eq!(role_from_name("rnsd"), Some(Role::Rnsd));
        assert_eq!(role_from_name("rns-sentineld"), Some(Role::Sentineld));
        assert_eq!(role_from_name("rns-statsd"), Some(Role::Statsd));
        assert_eq!(role_from_name("unknown"), None);
    }

    #[test]
    fn shutdown_priority_stops_sidecars_before_rnsd() {
        let mut roles = vec![Role::Rnsd, Role::Sentineld, Role::Statsd];
        roles.sort_by_key(|role| shutdown_priority(*role));
        assert_eq!(roles, vec![Role::Statsd, Role::Sentineld, Role::Rnsd]);
    }

    #[test]
    fn missing_required_hooks_requires_enabled_hook_match() {
        let hooks = vec![
            HookInfo {
                name: "hook-a".into(),
                hook_type: "wasm".into(),
                attach_point: "AttachA".into(),
                priority: 0,
                enabled: true,
                consecutive_traps: 0,
            },
            HookInfo {
                name: "hook-b".into(),
                hook_type: "wasm".into(),
                attach_point: "AttachB".into(),
                priority: 0,
                enabled: false,
                consecutive_traps: 0,
            },
        ];
        let required = vec![
            ("hook-a".to_string(), "AttachA".to_string()),
            ("hook-b".to_string(), "AttachB".to_string()),
            ("hook-c".to_string(), "AttachC".to_string()),
        ];

        let missing = missing_required_hooks(&hooks, &required);

        assert_eq!(
            missing,
            vec!["hook-b@AttachB".to_string(), "hook-c@AttachC".to_string()]
        );
    }

    #[test]
    fn ready_file_probe_requires_matching_process_and_pid() {
        let path = unique_temp_path("rns-sentineld");
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rns-sentineld");
        mark_process_running(&state, "rns-sentineld", 4242);
        std::fs::write(
            &path,
            "version=1\nstatus=ready\nprocess=rns-sentineld\npid=4242\ndetail=provider ready\n",
        )
        .unwrap();

        let detail = probe_ready_file(&path, "rns-sentineld", &state).unwrap();
        assert!(detail.contains("provider ready"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ready_file_probe_rejects_stale_pid() {
        let path = unique_temp_path("rns-statsd");
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rns-statsd");
        mark_process_running(&state, "rns-statsd", 99);
        std::fs::write(
            &path,
            "version=1\nstatus=ready\nprocess=rns-statsd\npid=77\ndetail=stats ready\n",
        )
        .unwrap();

        let err = probe_ready_file(&path, "rns-statsd", &state).unwrap_err();
        assert!(err.contains("stale"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn inspect_ready_file_accepts_draining_status_for_matching_process_and_pid() {
        let path = unique_temp_path("rns-statsd");
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rns-statsd");
        mark_process_running(&state, "rns-statsd", 77);
        std::fs::write(
            &path,
            "version=1\nstatus=draining\nprocess=rns-statsd\npid=77\ndetail=flushing stats\n",
        )
        .unwrap();

        let contract = inspect_ready_file(&path, "rns-statsd", &state).unwrap();
        assert_eq!(contract.status, "draining");
        assert_eq!(contract.detail, "flushing stats");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ready_file_target_is_constructible() {
        let target = ReadinessTarget::ReadyFile(PathBuf::from("/tmp/rns.ready"));
        match target {
            ReadinessTarget::ReadyFile(path) => assert_eq!(path, PathBuf::from("/tmp/rns.ready")),
            _ => panic!("unexpected target"),
        }
    }

    #[test]
    fn ready_file_path_for_role_selects_matching_ready_file_target() {
        let path = PathBuf::from("/tmp/rns-sentineld.ready");
        let readiness = vec![
            ProcessReadiness {
                role: Role::Sentineld,
                target: ReadinessTarget::ReadyFile(path.clone()),
            },
            ProcessReadiness {
                role: Role::Rnsd,
                target: ReadinessTarget::ProcessAge(std::time::Duration::from_secs(1)),
            },
        ];

        assert_eq!(
            ready_file_path_for_role(Role::Sentineld, &readiness),
            Some(path)
        );
        assert_eq!(ready_file_path_for_role(Role::Statsd, &readiness), None);
    }

    #[test]
    fn observe_sidecar_draining_updates_process_state() {
        let path = unique_temp_path("rns-sentineld");
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rns-sentineld");
        mark_process_running(&state, "rns-sentineld", 4242);
        std::fs::write(
            &path,
            "version=1\nstatus=draining\nprocess=rns-sentineld\npid=4242\ndetail=draining queue\n",
        )
        .unwrap();

        let managed = super::ManagedChild {
            role: Role::Sentineld,
            child: Command::new("sleep").arg("0").spawn().unwrap(),
        };

        assert!(observe_sidecar_draining(
            &managed,
            Some(&state),
            Some(&path)
        ));

        let snapshot = {
            let s = state.read().unwrap();
            s.processes.get("rns-sentineld").cloned().unwrap()
        };
        assert!(!snapshot.ready);
        assert_eq!(snapshot.ready_state, "draining");
        assert!(snapshot
            .status_detail
            .unwrap_or_default()
            .contains("draining queue"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn format_drain_status_detail_includes_deadline_when_present() {
        let status = DrainStatus {
            state: LifecycleState::Draining,
            drain_age_seconds: Some(1.2),
            deadline_remaining_seconds: Some(2.5),
            drain_complete: false,
            interface_writer_queued_frames: 0,
            provider_backlog_events: 0,
            provider_consumer_queued_events: 0,
            detail: Some("draining 2 links".into()),
        };

        assert_eq!(
            format_drain_status_detail(&status),
            "draining 2 links (deadline 2.5s remaining)"
        );
    }

    #[test]
    fn reflect_rnsd_drain_status_updates_process_readiness() {
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rnsd");
        mark_process_running(&state, "rnsd", 1234);

        reflect_rnsd_drain_status(
            Some(&state),
            &DrainStatus {
                state: LifecycleState::Draining,
                drain_age_seconds: Some(0.5),
                deadline_remaining_seconds: Some(1.0),
                drain_complete: false,
                interface_writer_queued_frames: 0,
                provider_backlog_events: 0,
                provider_consumer_queued_events: 0,
                detail: Some("1 link still active".into()),
            },
        );

        let snapshot = {
            let s = state.read().unwrap();
            s.processes.get("rnsd").cloned().unwrap()
        };
        assert!(!snapshot.ready);
        assert_eq!(snapshot.ready_state, "draining");
        assert!(snapshot
            .status_detail
            .unwrap_or_default()
            .contains("1 link still active"));
    }

    #[test]
    fn log_rnsd_drain_progress_deduplicates_identical_updates() {
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rnsd");
        let mut last_observed = None;
        let draining = DrainStatus {
            state: LifecycleState::Draining,
            drain_age_seconds: Some(0.5),
            deadline_remaining_seconds: Some(2.0),
            drain_complete: false,
            interface_writer_queued_frames: 0,
            provider_backlog_events: 0,
            provider_consumer_queued_events: 0,
            detail: Some("1 link still active".into()),
        };

        log_rnsd_drain_progress(Some(&state), &draining, &mut last_observed);
        log_rnsd_drain_progress(Some(&state), &draining, &mut last_observed);
        log_rnsd_drain_progress(
            Some(&state),
            &DrainStatus {
                state: LifecycleState::Stopping,
                drain_age_seconds: Some(1.5),
                deadline_remaining_seconds: Some(0.0),
                drain_complete: true,
                interface_writer_queued_frames: 0,
                provider_backlog_events: 0,
                provider_consumer_queued_events: 0,
                detail: Some("tearing down remaining work".into()),
            },
            &mut last_observed,
        );

        let log_count = {
            let s = state.read().unwrap();
            s.process_logs
                .get("rnsd")
                .map(|logs| logs.len())
                .unwrap_or(0)
        };
        assert_eq!(log_count, 2);
    }

    #[test]
    fn drain_complete_for_shutdown_accepts_expired_deadline() {
        let status = DrainStatus {
            state: LifecycleState::Draining,
            drain_age_seconds: Some(1.0),
            deadline_remaining_seconds: Some(0.0),
            drain_complete: false,
            interface_writer_queued_frames: 0,
            provider_backlog_events: 0,
            provider_consumer_queued_events: 0,
            detail: Some("1 link still active".into()),
        };

        assert!(drain_complete_for_shutdown(&status));
    }

    #[test]
    fn request_rnsd_drain_emits_begin_drain_over_rpc() {
        let (event_tx, event_rx) = rns_net::event::channel();
        let auth_key = [0x42; 32];
        let (rpc_addr, _server) = start_test_rpc_server(auth_key, event_tx);
        let config = RnsdDrainConfig {
            rpc_addr,
            auth_key,
            timeout: Duration::from_millis(250),
            poll_interval: Duration::from_millis(10),
        };

        request_rnsd_drain(&config, "test shutdown").unwrap();

        match event_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            Event::BeginDrain { timeout } => assert_eq!(timeout, config.timeout),
            other => panic!("expected BeginDrain event, got {:?}", other),
        }
    }

    #[test]
    fn wait_for_rnsd_drain_returns_true_after_live_rpc_completion() {
        let (event_tx, event_rx) = rns_net::event::channel();
        let auth_key = [0x24; 32];
        let (rpc_addr, _server) = start_test_rpc_server(auth_key, event_tx);
        let config = RnsdDrainConfig {
            rpc_addr,
            auth_key,
            timeout: Duration::from_millis(250),
            poll_interval: Duration::from_millis(10),
        };
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rnsd");
        mark_process_running(&state, "rnsd", 1234);
        let (done_tx, done_rx) = mpsc::channel();

        let driver = std::thread::spawn(move || {
            let mut polls = 0usize;
            while let Ok(event) = event_rx.recv_timeout(Duration::from_secs(1)) {
                if let Ok((QueryRequest::DrainStatus, resp_tx)) = event.into_query() {
                    polls += 1;
                    let _ = resp_tx.send(QueryResponse::DrainStatus(DrainStatus {
                        state: if polls == 1 {
                            LifecycleState::Draining
                        } else {
                            LifecycleState::Stopping
                        },
                        drain_age_seconds: Some((polls as f64) * 0.05),
                        deadline_remaining_seconds: Some(if polls == 1 { 0.2 } else { 0.0 }),
                        drain_complete: polls > 1,
                        interface_writer_queued_frames: if polls == 1 { 2 } else { 0 },
                        provider_backlog_events: 0,
                        provider_consumer_queued_events: 0,
                        detail: Some(if polls == 1 {
                            "waiting for queued interface writes".into()
                        } else {
                            "all work drained".into()
                        }),
                    }));
                    if polls > 1 {
                        break;
                    }
                }
            }
            let _ = done_tx.send(());
        });

        assert!(wait_for_rnsd_drain(&config, Some(&state)));
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        driver.join().unwrap();

        let snapshot = {
            let s = state.read().unwrap();
            s.processes.get("rnsd").cloned().unwrap()
        };
        assert_eq!(snapshot.ready_state, "stopping");
        assert!(snapshot
            .status_detail
            .unwrap_or_default()
            .contains("all work drained"));
    }

    #[test]
    fn wait_for_rnsd_drain_times_out_when_live_rpc_never_completes() {
        let (event_tx, event_rx) = rns_net::event::channel();
        let auth_key = [0x11; 32];
        let (rpc_addr, _server) = start_test_rpc_server(auth_key, event_tx);
        let config = RnsdDrainConfig {
            rpc_addr,
            auth_key,
            timeout: Duration::from_millis(120),
            poll_interval: Duration::from_millis(10),
        };
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rnsd");
        mark_process_running(&state, "rnsd", 777);
        let (stop_tx, stop_rx) = mpsc::channel();

        let driver = std::thread::spawn(move || loop {
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Event::Query(request, resp_tx))
                    if matches!(*request, QueryRequest::DrainStatus) =>
                {
                    let _ = resp_tx.send(QueryResponse::DrainStatus(DrainStatus {
                        state: LifecycleState::Draining,
                        drain_age_seconds: Some(0.05),
                        deadline_remaining_seconds: Some(0.05),
                        drain_complete: false,
                        interface_writer_queued_frames: 1,
                        provider_backlog_events: 2,
                        provider_consumer_queued_events: 3,
                        detail: Some("still draining queued work".into()),
                    }));
                }
                Ok(_) => {}
                Err(_) => break,
            }
            if stop_rx.try_recv().is_ok() {
                break;
            }
        });

        assert!(!wait_for_rnsd_drain(&config, Some(&state)));
        let _ = stop_tx.send(());
        driver.join().unwrap();

        let snapshot = {
            let s = state.read().unwrap();
            s.processes.get("rnsd").cloned().unwrap()
        };
        assert_eq!(snapshot.ready_state, "draining");
        assert!(snapshot
            .status_detail
            .unwrap_or_default()
            .contains("still draining queued work"));
    }

    #[test]
    fn stop_process_requests_rnsd_drain_before_termination() {
        let (event_tx, event_rx) = rns_net::event::channel();
        let auth_key = [0x51; 32];
        let (rpc_addr, _server) = start_test_rpc_server(auth_key, event_tx);
        let supervisor = Supervisor::new(SupervisorConfig {
            specs: vec![ProcessSpec {
                role: Role::Rnsd,
                command: ProcessCommand::External(PathBuf::from("sleep")),
                args: vec!["60".into()],
            }],
            shared_state: None,
            control_rx: None,
            readiness: Vec::new(),
            log_dir: None,
            rnsd_drain: Some(RnsdDrainConfig {
                rpc_addr,
                auth_key,
                timeout: Duration::from_millis(250),
                poll_interval: Duration::from_millis(10),
            }),
        });
        let mut children = vec![super::ManagedChild {
            role: Role::Rnsd,
            child: Command::new("sleep").arg("60").spawn().unwrap(),
        }];
        let (done_tx, done_rx) = mpsc::channel();

        let driver = std::thread::spawn(move || {
            let mut saw_begin_drain = false;
            while let Ok(event) = event_rx.recv_timeout(Duration::from_secs(1)) {
                match event {
                    Event::BeginDrain { .. } => saw_begin_drain = true,
                    Event::Query(request, resp_tx)
                        if matches!(*request, QueryRequest::DrainStatus) =>
                    {
                        let _ = resp_tx.send(QueryResponse::DrainStatus(DrainStatus {
                            state: LifecycleState::Stopping,
                            drain_age_seconds: Some(0.05),
                            deadline_remaining_seconds: Some(0.0),
                            drain_complete: true,
                            interface_writer_queued_frames: 0,
                            provider_backlog_events: 0,
                            provider_consumer_queued_events: 0,
                            detail: Some("ready to stop".into()),
                        }));
                        let _ = done_tx.send(saw_begin_drain);
                        break;
                    }
                    _ => {}
                }
            }
        });

        supervisor.stop_process("rnsd", &mut children).unwrap();
        assert!(children.is_empty());
        assert!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        driver.join().unwrap();
    }

    #[test]
    fn restart_process_requests_rnsd_drain_before_replacement() {
        let (event_tx, event_rx) = rns_net::event::channel();
        let auth_key = [0x61; 32];
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rnsd");
        let (rpc_addr, _server) = start_test_rpc_server(auth_key, event_tx);
        let supervisor = Supervisor::new(SupervisorConfig {
            specs: vec![ProcessSpec {
                role: Role::Rnsd,
                command: ProcessCommand::External(PathBuf::from("sleep")),
                args: vec!["60".into()],
            }],
            shared_state: Some(state.clone()),
            control_rx: None,
            readiness: Vec::new(),
            log_dir: None,
            rnsd_drain: Some(RnsdDrainConfig {
                rpc_addr: rpc_addr.clone(),
                auth_key,
                timeout: Duration::from_millis(250),
                poll_interval: Duration::from_millis(10),
            }),
        });
        let original = Command::new("sleep").arg("60").spawn().unwrap();
        mark_process_running(&state, "rnsd", original.id());
        let original_pid = original.id();
        let mut children = vec![super::ManagedChild {
            role: Role::Rnsd,
            child: original,
        }];
        let (done_tx, done_rx) = mpsc::channel();

        let driver = std::thread::spawn(move || {
            let mut saw_begin_drain = false;
            while let Ok(event) = event_rx.recv_timeout(Duration::from_secs(1)) {
                match event {
                    Event::BeginDrain { .. } => saw_begin_drain = true,
                    Event::Query(request, resp_tx)
                        if matches!(*request, QueryRequest::DrainStatus) =>
                    {
                        let _ = resp_tx.send(QueryResponse::DrainStatus(DrainStatus {
                            state: LifecycleState::Stopping,
                            drain_age_seconds: Some(0.05),
                            deadline_remaining_seconds: Some(0.0),
                            drain_complete: true,
                            interface_writer_queued_frames: 0,
                            provider_backlog_events: 0,
                            provider_consumer_queued_events: 0,
                            detail: Some("ready to restart".into()),
                        }));
                        let _ = done_tx.send(saw_begin_drain);
                        break;
                    }
                    _ => {}
                }
            }
        });

        supervisor.restart_process("rnsd", &mut children).unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].role, Role::Rnsd);
        assert_ne!(children[0].child.id(), original_pid);
        assert!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        driver.join().unwrap();

        let snapshot = {
            let s = state.read().unwrap();
            s.processes.get("rnsd").cloned().unwrap()
        };
        assert_eq!(snapshot.restart_count, 1);

        let _ = children[0].child.kill();
        let _ = children[0].child.wait();
    }

    #[test]
    fn supervisor_restarts_unexpectedly_exited_child_instead_of_exiting() {
        let _stops = STOP_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_root = std::env::temp_dir().join(format!(
            "rns-server-supervisor-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_root).unwrap();
        let count_path = temp_root.join("count");
        let script_path = temp_root.join("restart-once.sh");
        std::fs::write(
            &script_path,
            format!(
                "#!/usr/bin/env bash\nset -eu\ncount_file=\"{}\"\ncount=$(cat \"$count_file\" 2>/dev/null || echo 0)\ncount=$((count+1))\nprintf '%s' \"$count\" > \"$count_file\"\nif [ \"$count\" -eq 1 ]; then\n  exit 7\nfi\nsleep 60\n",
                count_path.display()
            ),
        )
        .unwrap();

        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rns-sentineld");
        // bash reads the script rather than executing it: executing a file
        // just written fails with "Text file busy" when another test thread
        // forks while the write descriptor is still open.
        let supervisor = Supervisor::new(SupervisorConfig {
            specs: vec![ProcessSpec {
                role: Role::Sentineld,
                command: ProcessCommand::External(PathBuf::from("bash")),
                args: vec![script_path.display().to_string()],
            }],
            shared_state: Some(state.clone()),
            control_rx: None,
            readiness: Vec::new(),
            log_dir: None,
            rnsd_drain: None,
        });
        let (result_tx, result_rx) = mpsc::channel();

        let handle = std::thread::spawn(move || {
            let result = supervisor.run();
            let _ = result_tx.send(result);
        });

        match result_rx.recv_timeout(Duration::from_secs(2)) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(result) => panic!("supervisor exited unexpectedly: {:?}", result),
            Err(err) => panic!("failed waiting for supervisor result: {}", err),
        }

        let restart_count = {
            let s = state.read().unwrap();
            let process = s.processes.get("rns-sentineld").cloned().unwrap();
            assert!(
                process.pid.is_some(),
                "expected restarted child to be running"
            );
            process.restart_count
        };
        assert_eq!(restart_count, 1);
        assert_eq!(std::fs::read_to_string(&count_path).unwrap(), "2");

        super::wake::request_stop();
        let result = result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(result.unwrap(), 0);
        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(temp_root);
    }

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{now}.ready", std::process::id()))
    }

    fn start_test_rpc_server(auth_key: [u8; 32], event_tx: EventSender) -> (RpcAddr, RpcServer) {
        for _ in 0..16 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let rpc_addr = RpcAddr::Tcp("127.0.0.1".into(), port);
            match RpcServer::start(&rpc_addr, auth_key, event_tx.clone()) {
                Ok(server) => return (rpc_addr, server),
                Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(err) => panic!("failed to start rpc server for test: {err}"),
            }
        }

        panic!("failed to allocate rpc server address for test");
    }

    /// Stopping reaches the latest run only, so tests that stop a run take
    /// turns.
    static STOP_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn voluntary_switches(tid: i64) -> u64 {
        let status = std::fs::read_to_string(format!("/proc/self/task/{tid}/status")).unwrap();
        status
            .lines()
            .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    #[test]
    fn supervisor_sleeps_until_a_command_or_a_child_exit_needs_it() {
        let _stops = STOP_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        ensure_process(&state, "rns-sentineld");
        let (control_tx, control_rx) = mpsc::channel();
        let supervisor = Supervisor::new(SupervisorConfig {
            specs: vec![ProcessSpec {
                role: Role::Sentineld,
                command: ProcessCommand::External(PathBuf::from("/bin/sleep")),
                args: vec!["30".into()],
            }],
            shared_state: Some(state.clone()),
            control_rx: Some(control_rx),
            readiness: Vec::new(),
            log_dir: None,
            rnsd_drain: None,
        });
        let (tid_tx, tid_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            // SAFETY: gettid has no preconditions.
            let _ = tid_tx.send(unsafe { libc::gettid() } as i64);
            let _ = result_tx.send(supervisor.run());
        });
        let tid = tid_rx.recv().unwrap();

        // Idle: a child running, nothing to do. The loop used to wake five
        // times a second.
        std::thread::sleep(Duration::from_millis(300));
        let before = voluntary_switches(tid);
        std::thread::sleep(Duration::from_secs(1));
        let woke = voluntary_switches(tid) - before;
        assert!(
            woke <= 2,
            "supervisor woke {woke} times in a second while idle"
        );

        // A command is handled as soon as it arrives.
        let sent = std::time::Instant::now();
        control_tx
            .send(rns_ctl::state::ProcessControlCommand::Stop(
                "rns-sentineld".into(),
            ))
            .unwrap();
        while state.read().unwrap().processes["rns-sentineld"]
            .pid
            .is_some()
        {
            assert!(
                sent.elapsed() < Duration::from_secs(2),
                "stop command not handled"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        super::wake::request_stop();
        let result = result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(result.unwrap(), 0);
        handle.join().unwrap();
    }
}
