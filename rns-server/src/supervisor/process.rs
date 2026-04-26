use super::*;

pub(crate) struct ManagedChild {
    pub(crate) role: Role,
    pub(crate) child: Child,
}

pub(crate) fn role_from_name(name: &str) -> Option<Role> {
    match name {
        "rnsd" => Some(Role::Rnsd),
        "rns-sentineld" => Some(Role::Sentineld),
        "rns-statsd" => Some(Role::Statsd),
        _ => None,
    }
}

pub(crate) fn spawn_child(
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

pub(crate) fn command_for_spec(spec: &ProcessSpec) -> Result<Command, String> {
    match &spec.command {
        ProcessCommand::External(bin) => {
            let mut command = Command::new(bin);
            command.args(&spec.args);
            Ok(command)
        }
        ProcessCommand::SelfInvoke => {
            let mut command = Command::new(resolve_self_exec()?);
            command.arg0(spec.role.display_name());
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

pub(crate) fn check_exits(
    children: &mut [ManagedChild],
) -> Result<Option<(Role, ExitStatus)>, String> {
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

pub(crate) fn shutdown_priority(role: Role) -> u8 {
    match role {
        Role::Statsd => 0,
        Role::Sentineld => 1,
        Role::Rnsd => 2,
    }
}

const TERMINATE_GRACE_POLLS: usize = 20;
const TERMINATE_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminationObservation {
    pub(crate) drain_acknowledged: bool,
    pub(crate) forced_kill: bool,
}

pub(crate) fn terminate_children(
    children: &mut [ManagedChild],
    shared_state: Option<&SharedState>,
    readiness: &[ProcessReadiness],
) {
    children.sort_by_key(|managed| shutdown_priority(managed.role));
    for managed in children.iter_mut() {
        let ready_file = ready_file_path_for_role(managed.role, readiness);
        match terminate_child(managed, shared_state, ready_file.as_ref()) {
            Ok(observation) => {
                if let Some(state) = shared_state {
                    record_process_termination_observation(
                        state,
                        managed.role.display_name(),
                        observation.drain_acknowledged,
                        observation.forced_kill,
                    );
                }
                if observation.drain_acknowledged {
                    log::info!(
                        "{} acknowledged draining before exit",
                        managed.role.display_name()
                    );
                }
                if observation.forced_kill {
                    log::warn!(
                        "{} did not exit within {:.1}s; sent SIGKILL",
                        managed.role.display_name(),
                        TERMINATE_GRACE_POLLS as f64 * TERMINATE_POLL_INTERVAL.as_secs_f64()
                    );
                }
            }
            Err(e) => {
                log::warn!("failed to stop {}: {}", managed.role.display_name(), e);
            }
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

pub(crate) fn terminate_child(
    managed: &mut ManagedChild,
    shared_state: Option<&SharedState>,
    ready_file: Option<&PathBuf>,
) -> io::Result<TerminationObservation> {
    if managed.child.try_wait()?.is_some() {
        return Ok(TerminationObservation {
            drain_acknowledged: false,
            forced_kill: false,
        });
    }

    #[cfg(unix)]
    unsafe {
        libc::kill(managed.child.id() as i32, libc::SIGTERM);
    }

    let mut drain_acknowledged = false;
    for _ in 0..TERMINATE_GRACE_POLLS {
        if managed.child.try_wait()?.is_some() {
            return Ok(TerminationObservation {
                drain_acknowledged,
                forced_kill: false,
            });
        }
        drain_acknowledged |= observe_sidecar_draining(managed, shared_state, ready_file);
        std::thread::sleep(TERMINATE_POLL_INTERVAL);
    }

    managed.child.kill()?;
    let _ = managed.child.wait();
    Ok(TerminationObservation {
        drain_acknowledged,
        forced_kill: true,
    })
}

pub(crate) fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}
