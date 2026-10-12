use std::sync::{mpsc, Arc, RwLock};

use rns_ctl::state::{
    ensure_process, note_server_config_applied, note_server_config_saved, set_control_tx,
    set_server_config, set_server_config_mutator, set_server_config_schema,
    set_server_config_validator, set_server_mode, CtlState, ProcessControlCommand, SharedState,
};

use crate::args::Args;
use crate::config::ServerConfig;

#[cfg(any(
    feature = "rns-hooks-native",
    feature = "rns-hooks-wasm",
    feature = "rns-hooks-builtin"
))]
const MANAGED_PROCESSES: [&str; 3] = ["rnsd", "rns-sentineld", "rns-statsd"];

#[cfg(not(any(
    feature = "rns-hooks-native",
    feature = "rns-hooks-wasm",
    feature = "rns-hooks-builtin"
)))]
const MANAGED_PROCESSES: [&str; 1] = ["rnsd"];

fn read_shared_state<'a>(
    state: &'a SharedState,
) -> std::sync::RwLockReadGuard<'a, rns_ctl::state::CtlState> {
    match state.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned control-plane shared state read lock");
            poisoned.into_inner()
        }
    }
}

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
                    let s = read_shared_state(&shared_state);
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
        let s = read_shared_state(shared_state);
        s.control_plane_config.clone()
    };
    let Some(config_handle) = config_handle else {
        return;
    };

    let mut config = match config_handle.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned embedded control-plane config write lock");
            poisoned.into_inner()
        }
    };
    apply_auth_reload(
        &mut config,
        next.http.auth_token.as_deref(),
        next.http.disable_auth,
    );
    log::info!("reloaded embedded control-plane auth settings in place");
}

/// Apply reloaded auth settings to the live control-plane config.
///
/// A reload that enables auth but names no token keeps the token already in
/// use, so the control plane stays reachable with the known token instead of
/// ending up with auth enabled and nothing that can match.
fn apply_auth_reload(
    config: &mut rns_ctl::config::CtlConfig,
    next_token: Option<&str>,
    next_disable_auth: bool,
) {
    match next_token {
        Some(token) => config.auth_token = Some(token.to_string()),
        None if next_disable_auth => config.auth_token = None,
        None => {
            if config.auth_token.is_some() {
                log::warn!(
                    "http.auth_token was removed from the configuration while auth stays enabled; \
                     keeping the previous token until a new one is configured"
                );
            }
        }
    }
    config.disable_auth = next_disable_auth;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_config(token: Option<&str>, disable_auth: bool) -> rns_ctl::config::CtlConfig {
        rns_ctl::config::CtlConfig {
            auth_token: token.map(String::from),
            disable_auth,
            ..rns_ctl::config::CtlConfig::default()
        }
    }

    #[test]
    fn auth_reload_replaces_the_token_when_one_is_given() {
        let mut config = live_config(Some("old"), false);
        apply_auth_reload(&mut config, Some("new"), false);
        assert_eq!(config.auth_token.as_deref(), Some("new"));
        assert!(!config.disable_auth);
    }

    #[test]
    fn auth_reload_without_a_token_keeps_the_previous_one_while_auth_is_enabled() {
        let mut config = live_config(Some("old"), false);
        apply_auth_reload(&mut config, None, false);
        assert_eq!(config.auth_token.as_deref(), Some("old"));
        assert!(!config.disable_auth);
    }

    #[test]
    fn auth_reload_that_disables_auth_clears_the_token() {
        let mut config = live_config(Some("old"), false);
        apply_auth_reload(&mut config, None, true);
        assert_eq!(config.auth_token, None);
        assert!(config.disable_auth);
    }

    #[test]
    fn auth_reload_that_re_enables_auth_with_a_token_sets_both() {
        let mut config = live_config(None, true);
        apply_auth_reload(&mut config, Some("new"), false);
        assert_eq!(config.auth_token.as_deref(), Some("new"));
        assert!(!config.disable_auth);
    }

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
