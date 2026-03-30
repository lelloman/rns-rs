use std::sync::{mpsc, Arc, RwLock};

use rns_ctl::state::{
    ensure_process, note_server_config_applied, note_server_config_saved, set_control_tx,
    set_server_config, set_server_config_mutator, set_server_config_schema,
    set_server_config_validator, set_server_mode, CtlState, ProcessControlCommand, SharedState,
};

use crate::args::Args;
use crate::config::ServerConfig;

const MANAGED_PROCESSES: [&str; 3] = ["rnsd", "rns-sentineld", "rns-statsd"];

pub fn new_supervised_state() -> (
    SharedState,
    mpsc::Sender<ProcessControlCommand>,
    mpsc::Receiver<ProcessControlCommand>,
) {
    let shared_state: SharedState = Arc::new(RwLock::new(CtlState::new()));
    let (control_tx, control_rx) = mpsc::channel();
    set_server_mode(&shared_state, "supervised");
    set_control_tx(&shared_state, control_tx.clone());
    for process in MANAGED_PROCESSES {
        ensure_process(&shared_state, process);
    }
    (shared_state, control_tx, control_rx)
}

pub fn install_config_bridge(shared_state: &SharedState, args: &Args, config: &ServerConfig) {
    set_server_config(shared_state, config.snapshot());
    set_server_config_schema(shared_state, config.schema_snapshot());
    set_server_config_validator(
        shared_state,
        Arc::new({
            let config = config.clone();
            move |body| config.validate_json_with_current_context(body)
        }),
    );
    set_server_config_mutator(
        shared_state,
        Arc::new({
            let config = config.clone();
            let args = args.clone();
            let shared_state = shared_state.clone();
            move |mode, body| {
                let control_tx = {
                    let s = shared_state.read().unwrap();
                    s.control_tx.clone()
                };
                let result = config.mutate_json_with_current_context(mode, body, control_tx)?;
                match mode {
                    rns_ctl::state::ServerConfigMutationMode::Save => {
                        note_server_config_saved(&shared_state, &result.apply_plan);
                    }
                    rns_ctl::state::ServerConfigMutationMode::Apply => {
                        let refreshed = ServerConfig::from_args(&args);
                        reload_embedded_http_auth_if_needed(
                            &shared_state,
                            &config,
                            &refreshed,
                            &result.apply_plan,
                        );
                        note_server_config_applied(&shared_state, &result.apply_plan);
                        set_server_config(&shared_state, refreshed.snapshot());
                        return Ok(result);
                    }
                }
                let refreshed = ServerConfig::from_args(&args);
                set_server_config(&shared_state, refreshed.snapshot());
                Ok(result)
            }
        }),
    );
}

fn reload_embedded_http_auth_if_needed(
    shared_state: &SharedState,
    current: &ServerConfig,
    next: &ServerConfig,
    apply_plan: &rns_ctl::state::ServerConfigApplyPlan,
) {
    if !apply_plan.control_plane_reload_required || apply_plan.control_plane_restart_required {
        return;
    }
    if current.http.auth_token == next.http.auth_token
        && current.http.disable_auth == next.http.disable_auth
    {
        return;
    }

    let config_handle = {
        let s = shared_state.read().unwrap();
        s.control_plane_config.clone()
    };
    let Some(config_handle) = config_handle else {
        return;
    };

    let mut config = config_handle.write().unwrap();
    config.auth_token = next.http.auth_token.clone();
    config.disable_auth = next.http.disable_auth;
    log::info!("reloaded embedded control-plane auth settings in place");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_supervised_state_registers_managed_processes() {
        let (shared_state, _tx, _rx) = new_supervised_state();
        let state = shared_state.read().unwrap();
        assert_eq!(state.server_mode, "supervised");
        for process in MANAGED_PROCESSES {
            assert!(state.processes.contains_key(process));
        }
        assert!(state.control_tx.is_some());
    }
}
