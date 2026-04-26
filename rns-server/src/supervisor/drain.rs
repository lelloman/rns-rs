use super::*;

impl Supervisor {
    pub(crate) fn drain_role(&self, role: Role, children: &[ManagedChild], reason: &str) {
        if role == Role::Rnsd {
            self.drain_rnsd(children, reason);
        }
    }

    pub(crate) fn drain_rnsd(&self, children: &[ManagedChild], reason: &str) {
        let Some(config) = self.rnsd_drain.as_ref() else {
            return;
        };
        if !children.iter().any(|child| child.role == Role::Rnsd) {
            return;
        }
        match request_rnsd_drain(config, reason) {
            Ok(()) => {
                let drained = wait_for_rnsd_drain(config, self.shared_state.as_ref());
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

pub(crate) fn request_rnsd_drain(config: &RnsdDrainConfig, reason: &str) -> Result<(), String> {
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

pub(crate) fn wait_for_rnsd_drain(
    config: &RnsdDrainConfig,
    shared_state: Option<&SharedState>,
) -> bool {
    let deadline = std::time::Instant::now() + config.timeout;
    let mut last_observed = None;
    while std::time::Instant::now() < deadline {
        match fetch_rnsd_drain_status(config) {
            Ok(Some(status)) => {
                reflect_rnsd_drain_status(shared_state, &status);
                log_rnsd_drain_progress(shared_state, &status, &mut last_observed);
                if drain_complete_for_shutdown(&status) {
                    return true;
                }
            }
            Ok(None) => {}
            Err(err) => log::debug!("rnsd drain status poll failed: {}", err),
        }
        thread::sleep(config.poll_interval);
    }
    false
}

pub(crate) fn log_rnsd_drain_progress(
    shared_state: Option<&SharedState>,
    status: &DrainStatus,
    last_observed: &mut Option<(String, String)>,
) {
    let ready_state = match status.state {
        rns_net::event::LifecycleState::Active => "ready",
        rns_net::event::LifecycleState::Draining => "draining",
        rns_net::event::LifecycleState::Stopping => "stopping",
        rns_net::event::LifecycleState::Stopped => "stopped",
    }
    .to_string();
    let detail = format_drain_status_detail(status);
    let observed = (ready_state.clone(), detail.clone());
    if last_observed.as_ref() == Some(&observed) {
        return;
    }
    *last_observed = Some(observed);

    log::info!("rnsd {}: {}", ready_state, detail);
    if let Some(state) = shared_state {
        push_process_log(state, Role::Rnsd.display_name(), "supervisor", detail);
    }
}

pub(crate) fn reflect_rnsd_drain_status(shared_state: Option<&SharedState>, status: &DrainStatus) {
    let Some(state) = shared_state else {
        return;
    };
    let ready_state = match status.state {
        rns_net::event::LifecycleState::Active => "ready",
        rns_net::event::LifecycleState::Draining => "draining",
        rns_net::event::LifecycleState::Stopping => "stopping",
        rns_net::event::LifecycleState::Stopped => "stopped",
    };
    set_process_readiness(
        state,
        Role::Rnsd.display_name(),
        false,
        ready_state,
        Some(format_drain_status_detail(status)),
    );
}

pub(crate) fn format_drain_status_detail(status: &DrainStatus) -> String {
    let mut detail = status
        .detail
        .clone()
        .unwrap_or_else(|| "drain status unavailable".into());
    if let Some(remaining) = status.deadline_remaining_seconds {
        detail.push_str(&format!(" (deadline {:.1}s remaining)", remaining.max(0.0)));
    }
    detail
}

fn fetch_rnsd_drain_status(config: &RnsdDrainConfig) -> Result<Option<DrainStatus>, String> {
    let mut client = RpcClient::connect(&config.rpc_addr, &config.auth_key)
        .map_err(|err| format!("rpc connect failed: {}", err))?;
    client
        .drain_status()
        .map_err(|err| format!("drain_status failed: {}", err))
}

pub(crate) fn drain_complete_for_shutdown(status: &DrainStatus) -> bool {
    status.drain_complete || status.deadline_remaining_seconds == Some(0.0)
}
