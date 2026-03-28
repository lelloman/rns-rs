use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::mpsc;
use std::time::Duration;

use rns_ctl::state::{
    bump_process_restart_count, mark_process_failed_spawn, mark_process_running,
    mark_process_stopped, set_process_readiness, ProcessControlCommand, SharedState,
};

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
    pub bin: PathBuf,
    pub args: Vec<String>,
}

impl ProcessSpec {
    pub fn command_line(&self) -> String {
        let mut parts = vec![self.bin.display().to_string()];
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }
}

pub struct SupervisorConfig {
    pub specs: Vec<ProcessSpec>,
    pub shared_state: Option<SharedState>,
    pub control_rx: Option<mpsc::Receiver<ProcessControlCommand>>,
    pub readiness: Vec<ProcessReadiness>,
}

pub struct Supervisor {
    specs: Vec<ProcessSpec>,
    shared_state: Option<SharedState>,
    control_rx: Option<mpsc::Receiver<ProcessControlCommand>>,
    readiness: Vec<ProcessReadiness>,
}

impl Supervisor {
    pub fn new(config: SupervisorConfig) -> Self {
        Self {
            specs: config.specs,
            shared_state: config.shared_state,
            control_rx: config.control_rx,
            readiness: config.readiness,
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
            .map(|spec| spawn_child(spec, self.shared_state.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;

        on_started()?;

        let stop_rx = install_signal_handlers();

        loop {
            if stop_rx.try_recv().is_ok() {
                log::info!("shutdown requested");
                terminate_children(&mut children, self.shared_state.as_ref());
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
                terminate_children(&mut children, self.shared_state.as_ref());
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
            terminate_child(&mut children[index]).map_err(|e| {
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
            children[index] = spawn_child(spec, self.shared_state.as_ref())?;
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
        children.push(spawn_child(spec, self.shared_state.as_ref())?);
        Ok(())
    }

    fn stop_process(&self, name: &str, children: &mut Vec<ManagedChild>) -> Result<(), String> {
        let Some(role) = role_from_name(name) else {
            return Err(format!("unknown process '{}'", name));
        };
        let Some(index) = children.iter().position(|child| child.role == role) else {
            return Ok(());
        };
        terminate_child(&mut children[index]).map_err(|e| {
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

fn spawn_child(
    spec: &ProcessSpec,
    shared_state: Option<&SharedState>,
) -> Result<ManagedChild, String> {
    log::info!("starting {}", spec.command_line());
    let mut command = Command::new(&spec.bin);
    command.args(&spec.args);
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
        mark_process_running(state, spec.role.display_name(), child.id());
    }
    Ok(ManagedChild {
        role: spec.role,
        child,
    })
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

fn terminate_children(children: &mut [ManagedChild], shared_state: Option<&SharedState>) {
    for managed in children.iter_mut() {
        if let Err(e) = terminate_child(managed) {
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

fn terminate_child(managed: &mut ManagedChild) -> io::Result<()> {
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
        std::thread::sleep(Duration::from_millis(100));
    }

    managed.child.kill()?;
    let _ = managed.child.wait();
    Ok(())
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
    use super::{Role, SupervisorConfig};
    use std::path::PathBuf;

    #[test]
    fn builds_expected_specs() {
        let config = SupervisorConfig {
            config_path: Some(PathBuf::from("/tmp/rns")),
            stats_db_path: PathBuf::from("/tmp/rns/stats.db"),
            rnsd_bin: PathBuf::from("rnsd"),
            sentineld_bin: PathBuf::from("rns-sentineld"),
            statsd_bin: PathBuf::from("rns-statsd"),
            shared_state: None,
            control_rx: None,
            readiness: Vec::new(),
            dry_run: false,
        };

        let specs = config.process_specs();
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].role, Role::Rnsd);
        assert_eq!(specs[1].role, Role::Sentineld);
        assert_eq!(specs[2].role, Role::Statsd);
        assert!(specs[2].args.iter().any(|arg| arg == "--db"));
    }
}
