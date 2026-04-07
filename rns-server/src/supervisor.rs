use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::logs::LogStore;
use crate::self_exec::{resolve_self_exec, self_exec_display};
use rns_ctl::state::{
    bump_process_restart_count, mark_process_failed_spawn, mark_process_running,
    mark_process_stopped, push_process_log, set_process_log_path, set_process_readiness,
    ProcessControlCommand, SharedState,
};
use rns_net::{event::DrainStatus, HookInfo, RpcAddr, RpcClient};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub log_dir: Option<PathBuf>,
    pub rnsd_drain: Option<RnsdDrainConfig>,
}

pub struct Supervisor {
    specs: Vec<ProcessSpec>,
    shared_state: Option<SharedState>,
    control_rx: Option<mpsc::Receiver<ProcessControlCommand>>,
    readiness: Vec<ProcessReadiness>,
    log_store: Option<LogStore>,
    rnsd_drain: Option<RnsdDrainConfig>,
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
            control_rx: config.control_rx,
            readiness: config.readiness,
            log_store: config.log_dir.map(LogStore::new),
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

        on_started()?;

        let stop_rx = install_signal_handlers();

        loop {
            if stop_rx.try_recv().is_ok() {
                log::info!("shutdown requested");
                self.drain_rnsd(&children, "supervisor shutdown");
                terminate_children(&mut children, self.shared_state.as_ref(), &self.readiness);
                return Ok(0);
            }

            if let Some(command) = self.next_control_command() {
                self.handle_control_command(command, &mut children)?;
            }

            self.refresh_readiness();

            if let Some((role, status)) = check_exits(&mut children)? {
                log::warn!("{} exited with status {}", role.display_name(), status);
                if let Some(state) = self.shared_state.as_ref() {
                    mark_process_stopped(state, role.display_name(), status.code());
                }
                terminate_children(&mut children, self.shared_state.as_ref(), &self.readiness);
                return Ok(exit_code(status));
            }

            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Supervisor {
    fn next_control_command(&self) -> Option<ProcessControlCommand> {
        self.control_rx.as_ref().and_then(|rx| rx.try_recv().ok())
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

    fn restart_process(&self, name: &str, children: &mut Vec<ManagedChild>) -> Result<(), String> {
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

    fn refresh_readiness(&self) {
        let Some(state) = self.shared_state.as_ref() else {
            return;
        };

        for readiness in &self.readiness {
            let (ready, ready_state, detail) = readiness.probe(state);
            set_process_readiness(state, readiness.name(), ready, ready_state, detail);
        }
    }

    fn drain_role(&self, role: Role, children: &[ManagedChild], reason: &str) {
        if role == Role::Rnsd {
            self.drain_rnsd(children, reason);
        }
    }

    fn drain_rnsd(&self, children: &[ManagedChild], reason: &str) {
        let Some(config) = self.rnsd_drain.as_ref() else {
            return;
        };
        if !children.iter().any(|child| child.role == Role::Rnsd) {
            return;
        }
        match request_rnsd_drain(config, reason) {
            Ok(()) => {
                let drained = wait_for_rnsd_drain(config);
                if drained {
                    log::info!("rnsd drain completed before {}", reason);
                } else {
                    log::warn!("rnsd drain timed out before {}", reason);
                }
            }
            Err(err) => {
                log::warn!("failed to request rnsd drain before {}: {}", reason, err);
            }
        }
    }
}

struct ManagedChild {
    role: Role,
    child: Child,
}

fn role_from_name(name: &str) -> Option<Role> {
    match name {
        "rnsd" => Some(Role::Rnsd),
        "rns-sentineld" => Some(Role::Sentineld),
        "rns-statsd" => Some(Role::Statsd),
        _ => None,
    }
}

#[derive(Clone)]
pub enum ReadinessTarget {
    Tcp(SocketAddr),
    UnixSocket(PathBuf),
    ReadyFile(PathBuf),
    HookSet {
        rpc_addr: RpcAddr,
        auth_key: [u8; 32],
        required_hooks: Vec<(String, String)>,
    },
    ProcessAge(Duration),
}

#[derive(Clone)]
pub struct ProcessReadiness {
    pub role: Role,
    pub target: ReadinessTarget,
}

impl ProcessReadiness {
    pub fn name(&self) -> &'static str {
        self.role.display_name()
    }

    fn probe(&self, state: &SharedState) -> (bool, &'static str, Option<String>) {
        match &self.target {
            ReadinessTarget::Tcp(addr) => {
                match TcpStream::connect_timeout(addr, Duration::from_millis(150)) {
                    Ok(_) => (true, "ready", Some(format!("listening on {}", addr))),
                    Err(err) => (false, "waiting", Some(format!("waiting for {}", err))),
                }
            }
            ReadinessTarget::UnixSocket(path) => match UnixStream::connect(path) {
                Ok(_) => (
                    true,
                    "ready",
                    Some(format!("socket available at {}", path.display())),
                ),
                Err(err) => (
                    false,
                    "waiting",
                    Some(format!("waiting for socket {}: {}", path.display(), err)),
                ),
            },
            ReadinessTarget::ReadyFile(path) => match probe_ready_file(path, self.name(), state) {
                Ok(detail) => (true, "ready", Some(detail)),
                Err(err) => (false, "waiting", Some(err)),
            },
            ReadinessTarget::HookSet {
                rpc_addr,
                auth_key,
                required_hooks,
            } => match probe_hook_set(rpc_addr, auth_key, required_hooks) {
                Ok((true, detail)) => (true, "ready", Some(detail)),
                Ok((false, detail)) => (false, "warming", Some(detail)),
                Err(err) => (
                    false,
                    "waiting",
                    Some(format!("waiting for hook load: {}", err)),
                ),
            },
            ReadinessTarget::ProcessAge(min_age) => {
                let started_at = {
                    let s = state.read().unwrap();
                    s.processes
                        .get(self.name())
                        .and_then(|process| process.started_at)
                };
                match started_at {
                    Some(started_at) if started_at.elapsed() >= *min_age => (
                        true,
                        "ready",
                        Some("process has stayed up past startup window".into()),
                    ),
                    Some(started_at) => (
                        false,
                        "warming",
                        Some(format!(
                            "startup grace period {:.1}s remaining",
                            (min_age.as_secs_f64() - started_at.elapsed().as_secs_f64()).max(0.0)
                        )),
                    ),
                    None => (false, "stopped", Some("process is not running".into())),
                }
            }
        }
    }
}

fn probe_ready_file(
    path: &PathBuf,
    process_name: &str,
    state: &SharedState,
) -> Result<String, String> {
    let contract = inspect_ready_file(path, process_name, state)?;

    if contract.status != "ready" {
        return Err(format!(
            "readiness file {} reports status={}",
            path.display(),
            contract.status
        ));
    }

    Ok(format!(
        "{} (pid {}, file {})",
        contract.detail,
        contract.pid,
        path.display()
    ))
}

fn inspect_ready_file(
    path: &PathBuf,
    process_name: &str,
    state: &SharedState,
) -> Result<ReadyFileContract, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|err| format!("waiting for readiness file {}: {}", path.display(), err))?;
    let contract = ReadyFileContract::parse(&body)?;

    if contract.process != process_name {
        return Err(format!(
            "readiness file {} belongs to {}",
            path.display(),
            contract.process
        ));
    }

    let expected_pid = {
        let s = state.read().unwrap();
        s.processes
            .get(process_name)
            .and_then(|process| process.pid)
    };
    if let Some(expected_pid) = expected_pid {
        if contract.pid != expected_pid {
            return Err(format!(
                "readiness file {} is stale for pid {} (expected {})",
                path.display(),
                contract.pid,
                expected_pid
            ));
        }
    }

    Ok(contract)
}

struct ReadyFileContract {
    status: String,
    process: String,
    pid: u32,
    detail: String,
}

impl ReadyFileContract {
    fn parse(body: &str) -> Result<Self, String> {
        let mut status = None;
        let mut process = None;
        let mut pid = None;
        let mut detail = None;

        for line in body.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = unescape_ready_value(value);
            match key {
                "status" => status = Some(value),
                "process" => process = Some(value),
                "pid" => {
                    pid = Some(
                        value
                            .parse::<u32>()
                            .map_err(|err| format!("invalid readiness pid '{}': {}", value, err))?,
                    )
                }
                "detail" => detail = Some(value),
                _ => {}
            }
        }

        Ok(Self {
            status: status.ok_or_else(|| "readiness file missing status".to_string())?,
            process: process.ok_or_else(|| "readiness file missing process".to_string())?,
            pid: pid.ok_or_else(|| "readiness file missing pid".to_string())?,
            detail: detail.unwrap_or_else(|| "ready".into()),
        })
    }
}

fn unescape_ready_value(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn probe_hook_set(
    rpc_addr: &RpcAddr,
    auth_key: &[u8; 32],
    required_hooks: &[(String, String)],
) -> Result<(bool, String), String> {
    let mut client = RpcClient::connect(rpc_addr, auth_key)
        .map_err(|err| format!("rpc connect failed: {}", err))?;
    let hooks = client
        .list_hooks()
        .map_err(|err| format!("list_hooks failed: {}", err))?;

    let missing = missing_required_hooks(&hooks, required_hooks);

    if missing.is_empty() {
        Ok((
            true,
            format!("all {} required hooks loaded", required_hooks.len()),
        ))
    } else {
        Ok((false, format!("missing hooks: {}", missing.join(", "))))
    }
}

fn missing_required_hooks(hooks: &[HookInfo], required_hooks: &[(String, String)]) -> Vec<String> {
    required_hooks
        .iter()
        .filter(|(name, attach_point)| {
            !hooks.iter().any(|hook| {
                hook.name == *name && hook.attach_point == *attach_point && hook.enabled
            })
        })
        .map(|(name, attach_point)| format!("{name}@{attach_point}"))
        .collect()
}

fn request_rnsd_drain(config: &RnsdDrainConfig, reason: &str) -> Result<(), String> {
    log::info!(
        "requesting rnsd drain before {} with {:.3}s timeout",
        reason,
        config.timeout.as_secs_f64()
    );
    let mut client = RpcClient::connect(&config.rpc_addr, &config.auth_key)
        .map_err(|err| format!("rpc connect failed: {}", err))?;
    client
        .begin_drain(config.timeout)
        .map_err(|err| format!("begin_drain failed: {}", err))?;
    Ok(())
}

fn wait_for_rnsd_drain(config: &RnsdDrainConfig) -> bool {
    let deadline = std::time::Instant::now() + config.timeout;
    while std::time::Instant::now() < deadline {
        match fetch_rnsd_drain_status(config) {
            Ok(Some(status)) if drain_complete_for_shutdown(&status) => return true,
            Ok(Some(_)) => {}
            Ok(None) => {}
            Err(err) => log::debug!("rnsd drain status poll failed: {}", err),
        }
        thread::sleep(config.poll_interval);
    }
    false
}

fn fetch_rnsd_drain_status(config: &RnsdDrainConfig) -> Result<Option<DrainStatus>, String> {
    let mut client = RpcClient::connect(&config.rpc_addr, &config.auth_key)
        .map_err(|err| format!("rpc connect failed: {}", err))?;
    client
        .drain_status()
        .map_err(|err| format!("drain_status failed: {}", err))
}

fn drain_complete_for_shutdown(status: &DrainStatus) -> bool {
    status.drain_complete || status.deadline_remaining_seconds == Some(0.0)
}

fn spawn_child(
    spec: &ProcessSpec,
    shared_state: Option<&SharedState>,
    log_store: Option<LogStore>,
) -> Result<ManagedChild, String> {
    log::info!("starting {}", spec.command_line());
    let mut command = command_for_spec(spec)?;
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            let err = format!("failed to start {}: {}", spec.role.display_name(), e);
            if let Some(state) = shared_state {
                mark_process_failed_spawn(state, spec.role.display_name(), err.clone());
            }
            return Err(err);
        }
    };
    if let Some(state) = shared_state {
        if let Some(stdout) = child.stdout.as_ref() {
            let _ = stdout;
        }
        mark_process_running(state, spec.role.display_name(), child.id());
        if let Some(store) = log_store.as_ref() {
            set_process_log_path(
                state,
                spec.role.display_name(),
                store
                    .process_log_path(spec.role.display_name())
                    .display()
                    .to_string(),
            );
        }
    }
    let mut managed = ManagedChild {
        role: spec.role,
        child,
    };
    if let Some(state) = shared_state {
        attach_log_streams(&mut managed, state.clone(), log_store);
    }
    Ok(managed)
}

fn command_for_spec(spec: &ProcessSpec) -> Result<Command, String> {
    match &spec.command {
        ProcessCommand::External(bin) => {
            let mut command = Command::new(bin);
            command.args(&spec.args);
            Ok(command)
        }
        ProcessCommand::SelfInvoke => {
            let mut command = Command::new(resolve_self_exec()?);
            command.arg("--internal-role");
            command.arg(spec.role.display_name());
            command.args(&spec.args);
            Ok(command)
        }
    }
}

fn attach_log_streams(child: &mut ManagedChild, state: SharedState, log_store: Option<LogStore>) {
    let process_name = child.role.display_name().to_string();

    if let Some(stdout) = child.child.stdout.take() {
        let state = state.clone();
        let process_name = process_name.clone();
        let log_store = log_store.clone();
        let _ = thread::Builder::new()
            .name(format!("{}-stdout", process_name))
            .spawn(move || read_log_stream(stdout, state, process_name, "stdout", log_store));
    }

    if let Some(stderr) = child.child.stderr.take() {
        let log_store = log_store.clone();
        let _ = thread::Builder::new()
            .name(format!("{}-stderr", process_name))
            .spawn(move || read_log_stream(stderr, state, process_name, "stderr", log_store));
    }
}

fn read_log_stream<R: io::Read + Send + 'static>(
    stream: R,
    state: SharedState,
    process_name: String,
    stream_name: &'static str,
    log_store: Option<LogStore>,
) {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        match line {
            Ok(line) => {
                push_process_log(&state, &process_name, stream_name, line.clone());
                if let Some(store) = log_store.as_ref() {
                    if let Err(err) = store.append_line(&process_name, stream_name, &line) {
                        push_process_log(
                            &state,
                            &process_name,
                            "supervisor",
                            format!("durable log write failed: {}", err),
                        );
                    }
                }
            }
            Err(err) => {
                push_process_log(
                    &state,
                    &process_name,
                    stream_name,
                    format!("log stream read error: {}", err),
                );
                break;
            }
        }
    }
}

fn check_exits(children: &mut [ManagedChild]) -> Result<Option<(Role, ExitStatus)>, String> {
    for managed in children {
        let status = managed
            .child
            .try_wait()
            .map_err(|e| format!("failed to poll {}: {}", managed.role.display_name(), e))?;
        if let Some(status) = status {
            return Ok(Some((managed.role, status)));
        }
    }
    Ok(None)
}

fn shutdown_priority(role: Role) -> u8 {
    match role {
        Role::Statsd => 0,
        Role::Sentineld => 1,
        Role::Rnsd => 2,
    }
}

fn terminate_children(
    children: &mut [ManagedChild],
    shared_state: Option<&SharedState>,
    readiness: &[ProcessReadiness],
) {
    children.sort_by_key(|managed| shutdown_priority(managed.role));
    for managed in children.iter_mut() {
        let ready_file = ready_file_path_for_role(managed.role, readiness);
        if let Err(e) = terminate_child(managed, shared_state, ready_file.as_ref()) {
            log::warn!("failed to stop {}: {}", managed.role.display_name(), e);
        }
        if let Some(state) = shared_state {
            let code = managed
                .child
                .try_wait()
                .ok()
                .flatten()
                .and_then(|status| status.code());
            mark_process_stopped(state, managed.role.display_name(), code);
        }
    }
}

fn terminate_child(
    managed: &mut ManagedChild,
    shared_state: Option<&SharedState>,
    ready_file: Option<&PathBuf>,
) -> io::Result<()> {
    if managed.child.try_wait()?.is_some() {
        return Ok(());
    }

    #[cfg(unix)]
    unsafe {
        libc::kill(managed.child.id() as i32, libc::SIGTERM);
    }

    for _ in 0..20 {
        if managed.child.try_wait()?.is_some() {
            return Ok(());
        }
        observe_sidecar_draining(managed, shared_state, ready_file);
        std::thread::sleep(Duration::from_millis(100));
    }

    managed.child.kill()?;
    let _ = managed.child.wait();
    Ok(())
}

fn observe_sidecar_draining(
    managed: &ManagedChild,
    shared_state: Option<&SharedState>,
    ready_file: Option<&PathBuf>,
) {
    let Some(state) = shared_state else {
        return;
    };
    let Some(path) = ready_file else {
        return;
    };
    let Ok(contract) = inspect_ready_file(path, managed.role.display_name(), state) else {
        return;
    };
    if contract.status != "draining" {
        return;
    }

    set_process_readiness(
        state,
        managed.role.display_name(),
        false,
        "draining",
        Some(format!(
            "{} (pid {}, file {})",
            contract.detail,
            contract.pid,
            path.display()
        )),
    );
}

fn ready_file_path_for_role(role: Role, readiness: &[ProcessReadiness]) -> Option<PathBuf> {
    readiness.iter().find_map(|probe| {
        if probe.role != role {
            return None;
        }
        match &probe.target {
            ReadinessTarget::ReadyFile(path) => Some(path.clone()),
            _ => None,
        }
    })
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

static STOP_TX: std::sync::Mutex<Option<mpsc::Sender<()>>> = std::sync::Mutex::new(None);

extern "C" fn signal_handler(_sig: libc::c_int) {
    if let Ok(guard) = STOP_TX.lock() {
        if let Some(ref tx) = *guard {
            let _ = tx.send(());
        }
    }
}

fn install_signal_handlers() -> mpsc::Receiver<()> {
    let (stop_tx, stop_rx) = mpsc::channel();
    STOP_TX.lock().unwrap().replace(stop_tx);
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as *const () as usize);
        libc::signal(libc::SIGTERM, signal_handler as *const () as usize);
    }
    stop_rx
}

#[cfg(test)]
mod tests {
    use super::{
        command_for_spec, inspect_ready_file, missing_required_hooks, probe_ready_file,
        ready_file_path_for_role, role_from_name, shutdown_priority, ProcessCommand,
        ProcessReadiness, ProcessSpec, ReadinessTarget, Role, SupervisorConfig,
    };
    use rns_ctl::state::{ensure_process, mark_process_running, CtlState, SharedState};
    use rns_net::HookInfo;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};
    use std::time::{SystemTime, UNIX_EPOCH};

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
                attach_point: "AttachA".into(),
                priority: 0,
                enabled: true,
                consecutive_traps: 0,
            },
            HookInfo {
                name: "hook-b".into(),
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

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{now}.ready", std::process::id()))
    }
}
