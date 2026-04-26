use super::*;

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

    pub(crate) fn probe(&self, state: &SharedState) -> (bool, &'static str, Option<String>) {
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
                    let s = read_shared_state(state);
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

pub(crate) fn probe_ready_file(
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

pub(crate) fn inspect_ready_file(
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
        let s = read_shared_state(state);
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

pub(crate) struct ReadyFileContract {
    pub(crate) status: String,
    pub(crate) process: String,
    pub(crate) pid: u32,
    pub(crate) detail: String,
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

pub(crate) fn missing_required_hooks(
    hooks: &[HookInfo],
    required_hooks: &[(String, String)],
) -> Vec<String> {
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

pub(crate) fn observe_sidecar_draining(
    managed: &ManagedChild,
    shared_state: Option<&SharedState>,
    ready_file: Option<&PathBuf>,
) -> bool {
    let Some(state) = shared_state else {
        return false;
    };
    let Some(path) = ready_file else {
        return false;
    };
    let Ok(contract) = inspect_ready_file(path, managed.role.display_name(), state) else {
        return false;
    };
    if contract.status != "draining" {
        return false;
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
    true
}

pub(crate) fn ready_file_path_for_role(
    role: Role,
    readiness: &[ProcessReadiness],
) -> Option<PathBuf> {
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
