use std::collections::{HashMap, VecDeque};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::Instant;

use serde::Serialize;

use rns_crypto::identity::Identity;
use rns_net::{Destination, RnsNode};

use crate::encode::to_hex;

const MAX_RECORDS: usize = 1000;

/// Shared state accessible from HTTP handlers and Callbacks.
pub type SharedState = Arc<RwLock<CtlState>>;
pub type ServerConfigValidator =
    Arc<dyn Fn(&[u8]) -> Result<ServerConfigValidationSnapshot, String> + Send + Sync>;
pub type ServerConfigMutator = Arc<
    dyn Fn(ServerConfigMutationMode, &[u8]) -> Result<ServerConfigMutationResult, String>
        + Send
        + Sync,
>;

/// Registry of WebSocket broadcast senders.
pub type WsBroadcast = Arc<Mutex<Vec<std::sync::mpsc::Sender<WsEvent>>>>;

pub struct CtlState {
    pub started_at: Instant,
    pub server_mode: String,
    pub server_config: Option<ServerConfigSnapshot>,
    pub server_config_schema: Option<ServerConfigSchemaSnapshot>,
    pub server_config_status: ServerConfigStatusState,
    pub server_config_validator: Option<ServerConfigValidator>,
    pub server_config_mutator: Option<ServerConfigMutator>,
    pub identity_hash: Option<[u8; 16]>,
    pub identity: Option<Identity>,
    pub announces: VecDeque<AnnounceRecord>,
    pub packets: VecDeque<PacketRecord>,
    pub proofs: VecDeque<ProofRecord>,
    pub link_events: VecDeque<LinkEventRecord>,
    pub resource_events: VecDeque<ResourceEventRecord>,
    pub process_events: VecDeque<ProcessEventRecord>,
    pub process_logs: HashMap<String, VecDeque<ProcessLogRecord>>,
    pub destinations: HashMap<[u8; 16], DestinationEntry>,
    pub processes: HashMap<String, ManagedProcessState>,
    pub control_tx: Option<mpsc::Sender<ProcessControlCommand>>,
    pub node_handle: Option<Arc<Mutex<Option<RnsNode>>>>,
}

/// A registered destination plus metadata for the API.
pub struct DestinationEntry {
    pub destination: Destination,
    /// Full name: "app_name.aspect1.aspect2"
    pub full_name: String,
}

impl CtlState {
    pub fn new() -> Self {
        CtlState {
            started_at: Instant::now(),
            server_mode: "standalone".into(),
            server_config: None,
            server_config_schema: None,
            server_config_status: ServerConfigStatusState::default(),
            server_config_validator: None,
            server_config_mutator: None,
            identity_hash: None,
            identity: None,
            announces: VecDeque::new(),
            packets: VecDeque::new(),
            proofs: VecDeque::new(),
            link_events: VecDeque::new(),
            resource_events: VecDeque::new(),
            process_events: VecDeque::new(),
            process_logs: HashMap::new(),
            destinations: HashMap::new(),
            processes: HashMap::new(),
            control_tx: None,
            node_handle: None,
        }
    }

    pub fn uptime_seconds(&self) -> f64 {
        self.started_at.elapsed().as_secs_f64()
    }
}

fn push_capped<T>(deque: &mut VecDeque<T>, item: T) {
    if deque.len() >= MAX_RECORDS {
        deque.pop_front();
    }
    deque.push_back(item);
}

pub fn push_announce(state: &SharedState, record: AnnounceRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.announces, record);
}

pub fn push_packet(state: &SharedState, record: PacketRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.packets, record);
}

pub fn push_proof(state: &SharedState, record: ProofRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.proofs, record);
}

pub fn push_link_event(state: &SharedState, record: LinkEventRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.link_events, record);
}

pub fn push_resource_event(state: &SharedState, record: ResourceEventRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.resource_events, record);
}

/// Broadcast a WsEvent to all connected WebSocket clients.
pub fn broadcast(ws: &WsBroadcast, event: WsEvent) {
    let mut senders = ws.lock().unwrap();
    senders.retain(|tx| tx.send(event.clone()).is_ok());
}

pub fn set_server_mode(state: &SharedState, mode: impl Into<String>) {
    let mut s = state.write().unwrap();
    s.server_mode = mode.into();
}

pub fn set_server_config(state: &SharedState, config: ServerConfigSnapshot) {
    let mut s = state.write().unwrap();
    s.server_config = Some(config);
}

pub fn set_server_config_schema(state: &SharedState, schema: ServerConfigSchemaSnapshot) {
    let mut s = state.write().unwrap();
    s.server_config_schema = Some(schema);
}

pub fn note_server_config_saved(state: &SharedState, apply_plan: &ServerConfigApplyPlan) {
    let mut s = state.write().unwrap();
    s.server_config_status.last_saved_at = Some(Instant::now());
    s.server_config_status.last_action = Some("save".into());
    s.server_config_status.last_action_at = Some(Instant::now());
    s.server_config_status.pending_process_restarts.clear();
    s.server_config_status.control_plane_restart_required =
        apply_plan.control_plane_restart_required;
    s.server_config_status.runtime_differs_from_saved =
        !apply_plan.processes_to_restart.is_empty() || apply_plan.control_plane_restart_required;
    s.server_config_status.last_apply_plan = Some(apply_plan.clone());
}

pub fn note_server_config_applied(state: &SharedState, apply_plan: &ServerConfigApplyPlan) {
    let mut s = state.write().unwrap();
    let now = Instant::now();
    s.server_config_status.last_saved_at = Some(now);
    s.server_config_status.last_apply_at = Some(now);
    s.server_config_status.last_action = Some("apply".into());
    s.server_config_status.last_action_at = Some(now);
    s.server_config_status.pending_process_restarts = apply_plan.processes_to_restart.clone();
    s.server_config_status.control_plane_restart_required =
        apply_plan.control_plane_restart_required;
    s.server_config_status.runtime_differs_from_saved =
        !s.server_config_status.pending_process_restarts.is_empty()
            || s.server_config_status.control_plane_restart_required;
    s.server_config_status.last_apply_plan = Some(apply_plan.clone());
}

pub fn reconcile_config_status_for_process(
    state: &SharedState,
    name: &str,
    ready: bool,
    status: &str,
) {
    let mut s = state.write().unwrap();
    if ready {
        s.server_config_status
            .pending_process_restarts
            .retain(|process| process != name);
    }
    if status == "failed" {
        s.server_config_status.runtime_differs_from_saved = true;
    } else if s.server_config_status.pending_process_restarts.is_empty()
        && !s.server_config_status.control_plane_restart_required
    {
        s.server_config_status.runtime_differs_from_saved = false;
    }
}

pub fn set_server_config_validator(state: &SharedState, validator: ServerConfigValidator) {
    let mut s = state.write().unwrap();
    s.server_config_validator = Some(validator);
}

pub fn set_server_config_mutator(state: &SharedState, mutator: ServerConfigMutator) {
    let mut s = state.write().unwrap();
    s.server_config_mutator = Some(mutator);
}

pub fn ensure_process(state: &SharedState, name: impl Into<String>) {
    let mut s = state.write().unwrap();
    let name = name.into();
    s.processes
        .entry(name.clone())
        .or_insert_with(|| ManagedProcessState::new(name.clone()));
    s.process_logs.entry(name.clone()).or_default();
    push_capped(
        &mut s.process_events,
        ProcessEventRecord::new(name, "registered", Some("process registered".into())),
    );
}

pub fn push_process_log(state: &SharedState, name: &str, stream: &str, line: impl Into<String>) {
    let mut s = state.write().unwrap();
    let recent_log_lines = {
        let logs = s.process_logs.entry(name.to_string()).or_default();
        if logs.len() >= MAX_RECORDS {
            logs.pop_front();
        }
        logs.push_back(ProcessLogRecord {
            process: name.to_string(),
            stream: stream.to_string(),
            line: line.into(),
            recorded_at: Instant::now(),
        });
        logs.len()
    };
    let process = s
        .processes
        .entry(name.to_string())
        .or_insert_with(|| ManagedProcessState::new(name.to_string()));
    process.last_log_at = Some(Instant::now());
    process.recent_log_lines = recent_log_lines;
}

pub fn set_process_log_path(state: &SharedState, name: &str, path: impl Into<String>) {
    let mut s = state.write().unwrap();
    let process = s
        .processes
        .entry(name.to_string())
        .or_insert_with(|| ManagedProcessState::new(name.to_string()));
    process.durable_log_path = Some(path.into());
}

pub fn set_control_tx(state: &SharedState, tx: mpsc::Sender<ProcessControlCommand>) {
    let mut s = state.write().unwrap();
    s.control_tx = Some(tx);
}

pub fn mark_process_running(state: &SharedState, name: &str, pid: u32) {
    let mut s = state.write().unwrap();
    let process = s
        .processes
        .entry(name.to_string())
        .or_insert_with(|| ManagedProcessState::new(name.to_string()));
    process.status = "running".into();
    process.ready = false;
    process.ready_state = "starting".into();
    process.pid = Some(pid);
    process.started_at = Some(Instant::now());
    process.last_transition_at = Some(Instant::now());
    process.last_error = None;
    process.status_detail = Some("process spawned".into());
    push_capped(
        &mut s.process_events,
        ProcessEventRecord::new(name.to_string(), "running", Some(format!("pid={}", pid))),
    );
    drop(s);
    reconcile_config_status_for_process(state, name, false, "running");
}

pub fn bump_process_restart_count(state: &SharedState, name: &str) {
    let mut s = state.write().unwrap();
    let restart_count = {
        let process = s
            .processes
            .entry(name.to_string())
            .or_insert_with(|| ManagedProcessState::new(name.to_string()));
        process.restart_count = process.restart_count.saturating_add(1);
        process.restart_count
    };
    push_capped(
        &mut s.process_events,
        ProcessEventRecord::new(
            name.to_string(),
            "restart_requested",
            Some(format!("restart_count={}", restart_count)),
        ),
    );
}

pub fn mark_process_stopped(state: &SharedState, name: &str, exit_code: Option<i32>) {
    let mut s = state.write().unwrap();
    let process = s
        .processes
        .entry(name.to_string())
        .or_insert_with(|| ManagedProcessState::new(name.to_string()));
    process.status = "stopped".into();
    process.ready = false;
    process.ready_state = "stopped".into();
    process.pid = None;
    process.last_exit_code = exit_code;
    process.started_at = None;
    process.last_transition_at = Some(Instant::now());
    process.status_detail = Some("process stopped".into());
    push_capped(
        &mut s.process_events,
        ProcessEventRecord::new(
            name.to_string(),
            "stopped",
            Some(format!(
                "exit_code={}",
                exit_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".into())
            )),
        ),
    );
    drop(s);
    reconcile_config_status_for_process(state, name, false, "stopped");
}

pub fn mark_process_failed_spawn(state: &SharedState, name: &str, error: String) {
    let mut s = state.write().unwrap();
    let detail = {
        let process = s
            .processes
            .entry(name.to_string())
            .or_insert_with(|| ManagedProcessState::new(name.to_string()));
        process.status = "failed".into();
        process.ready = false;
        process.ready_state = "failed".into();
        process.pid = None;
        process.last_error = Some(error);
        process.started_at = None;
        process.last_transition_at = Some(Instant::now());
        process.status_detail = process.last_error.clone();
        process.last_error.clone()
    };
    push_capped(
        &mut s.process_events,
        ProcessEventRecord::new(name.to_string(), "spawn_failed", detail),
    );
    drop(s);
    reconcile_config_status_for_process(state, name, false, "failed");
}

pub fn set_process_readiness(
    state: &SharedState,
    name: &str,
    ready: bool,
    ready_state: &str,
    status_detail: Option<String>,
) {
    let mut s = state.write().unwrap();
    let detail_clone = {
        let process = s
            .processes
            .entry(name.to_string())
            .or_insert_with(|| ManagedProcessState::new(name.to_string()));
        process.ready = ready;
        process.ready_state = ready_state.to_string();
        process.status_detail = status_detail;
        process.status_detail.clone()
    };
    let should_record = match s.process_events.back() {
        Some(last) => {
            last.process != name || last.event != ready_state || last.detail != detail_clone
        }
        None => true,
    };
    if should_record {
        push_capped(
            &mut s.process_events,
            ProcessEventRecord::new(name.to_string(), ready_state.to_string(), detail_clone),
        );
    }
    drop(s);
    reconcile_config_status_for_process(state, name, ready, ready_state);
}

// --- Record types ---

#[derive(Debug, Clone, Serialize)]
pub struct AnnounceRecord {
    pub dest_hash: String,
    pub identity_hash: String,
    pub hops: u8,
    pub app_data: Option<String>,
    pub received_at: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketRecord {
    pub dest_hash: String,
    pub packet_hash: String,
    pub data_base64: String,
    pub received_at: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProofRecord {
    pub dest_hash: String,
    pub packet_hash: String,
    pub rtt: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkEventRecord {
    pub link_id: String,
    pub event_type: String,
    pub is_initiator: Option<bool>,
    pub rtt: Option<f64>,
    pub identity_hash: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceEventRecord {
    pub link_id: String,
    pub event_type: String,
    pub data_base64: Option<String>,
    pub metadata_base64: Option<String>,
    pub error: Option<String>,
    pub received: Option<usize>,
    pub total: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ProcessEventRecord {
    pub process: String,
    pub event: String,
    pub detail: Option<String>,
    pub recorded_at: Instant,
}

#[derive(Debug, Clone)]
pub struct ProcessLogRecord {
    pub process: String,
    pub stream: String,
    pub line: String,
    pub recorded_at: Instant,
}

impl ProcessEventRecord {
    fn new(process: String, event: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            process,
            event: event.into(),
            detail,
            recorded_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigSnapshot {
    pub config_path: Option<String>,
    pub resolved_config_dir: String,
    pub server_config_file_path: String,
    pub server_config_file_present: bool,
    pub server_config_file_json: String,
    pub stats_db_path: String,
    pub rnsd_bin: String,
    pub sentineld_bin: String,
    pub statsd_bin: String,
    pub http: ServerHttpConfigSnapshot,
    pub launch_plan: Vec<LaunchProcessSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigSchemaSnapshot {
    pub format: String,
    pub example_config_json: String,
    pub notes: Vec<String>,
    pub fields: Vec<ServerConfigFieldSchema>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigFieldSchema {
    pub field: String,
    pub field_type: String,
    pub required: bool,
    pub default_value: String,
    pub description: String,
    pub effect: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigStatusSnapshot {
    pub last_saved_age_seconds: Option<f64>,
    pub last_apply_age_seconds: Option<f64>,
    pub last_action: Option<String>,
    pub last_action_age_seconds: Option<f64>,
    pub pending_process_restarts: Vec<String>,
    pub control_plane_restart_required: bool,
    pub runtime_differs_from_saved: bool,
    pub converged: bool,
    pub summary: String,
    pub last_apply_plan: Option<ServerConfigApplyPlan>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerHttpConfigSnapshot {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub auth_mode: String,
    pub token_configured: bool,
    pub daemon_mode: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchProcessSnapshot {
    pub name: String,
    pub bin: String,
    pub args: Vec<String>,
    pub command_line: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigValidationSnapshot {
    pub valid: bool,
    pub config: ServerConfigSnapshot,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigMutationResult {
    pub action: String,
    pub config: ServerConfigSnapshot,
    pub apply_plan: ServerConfigApplyPlan,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigApplyPlan {
    pub processes_to_restart: Vec<String>,
    pub control_plane_restart_required: bool,
    pub notes: Vec<String>,
    pub changes: Vec<ServerConfigChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigChange {
    pub field: String,
    pub before: String,
    pub after: String,
    pub effect: String,
}

#[derive(Debug, Clone, Copy)]
pub enum ServerConfigMutationMode {
    Save,
    Apply,
}

#[derive(Debug, Clone, Default)]
pub struct ServerConfigStatusState {
    pub last_saved_at: Option<Instant>,
    pub last_apply_at: Option<Instant>,
    pub last_action: Option<String>,
    pub last_action_at: Option<Instant>,
    pub pending_process_restarts: Vec<String>,
    pub control_plane_restart_required: bool,
    pub runtime_differs_from_saved: bool,
    pub last_apply_plan: Option<ServerConfigApplyPlan>,
}

impl ServerConfigStatusState {
    pub fn snapshot(&self) -> ServerConfigStatusSnapshot {
        let converged =
            self.pending_process_restarts.is_empty() && !self.control_plane_restart_required;
        let summary = if self.runtime_differs_from_saved {
            if self.control_plane_restart_required {
                "Saved config is not fully active; rns-server restart is still required.".into()
            } else if self.pending_process_restarts.is_empty() {
                "Saved config differs from runtime state.".into()
            } else {
                format!(
                    "Waiting for restarted processes to converge: {}.",
                    self.pending_process_restarts.join(", ")
                )
            }
        } else {
            "Running state is converged with the saved config.".into()
        };

        ServerConfigStatusSnapshot {
            last_saved_age_seconds: self
                .last_saved_at
                .map(|instant| instant.elapsed().as_secs_f64()),
            last_apply_age_seconds: self
                .last_apply_at
                .map(|instant| instant.elapsed().as_secs_f64()),
            last_action: self.last_action.clone(),
            last_action_age_seconds: self
                .last_action_at
                .map(|instant| instant.elapsed().as_secs_f64()),
            pending_process_restarts: self.pending_process_restarts.clone(),
            control_plane_restart_required: self.control_plane_restart_required,
            runtime_differs_from_saved: self.runtime_differs_from_saved,
            converged,
            summary,
            last_apply_plan: self.last_apply_plan.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagedProcessState {
    pub name: String,
    pub status: String,
    pub ready: bool,
    pub ready_state: String,
    pub pid: Option<u32>,
    pub last_exit_code: Option<i32>,
    pub restart_count: u32,
    pub last_error: Option<String>,
    pub status_detail: Option<String>,
    pub durable_log_path: Option<String>,
    pub last_log_at: Option<Instant>,
    pub recent_log_lines: usize,
    pub started_at: Option<Instant>,
    pub last_transition_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub enum ProcessControlCommand {
    Restart(String),
    Start(String),
    Stop(String),
}

impl ManagedProcessState {
    pub fn new(name: String) -> Self {
        Self {
            name,
            status: "stopped".into(),
            ready: false,
            ready_state: "stopped".into(),
            pid: None,
            last_exit_code: None,
            restart_count: 0,
            last_error: None,
            status_detail: None,
            durable_log_path: None,
            last_log_at: None,
            recent_log_lines: 0,
            started_at: None,
            last_transition_at: None,
        }
    }

    pub fn uptime_seconds(&self) -> Option<f64> {
        self.started_at
            .map(|started| started.elapsed().as_secs_f64())
    }

    pub fn last_transition_seconds(&self) -> Option<f64> {
        self.last_transition_at
            .map(|transition| transition.elapsed().as_secs_f64())
    }

    pub fn last_log_age_seconds(&self) -> Option<f64> {
        self.last_log_at
            .map(|logged| logged.elapsed().as_secs_f64())
    }
}

// --- WebSocket events ---

#[derive(Debug, Clone)]
pub struct WsEvent {
    pub topic: &'static str,
    pub payload: serde_json::Value,
}

impl WsEvent {
    pub fn announce(record: &AnnounceRecord) -> Self {
        WsEvent {
            topic: "announces",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn packet(record: &PacketRecord) -> Self {
        WsEvent {
            topic: "packets",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn proof(record: &ProofRecord) -> Self {
        WsEvent {
            topic: "proofs",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn link(record: &LinkEventRecord) -> Self {
        WsEvent {
            topic: "links",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn resource(record: &ResourceEventRecord) -> Self {
        WsEvent {
            topic: "resources",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn to_json(&self) -> String {
        let obj = serde_json::json!({
            "type": self.topic.trim_end_matches('s'),
            "data": self.payload,
        });
        serde_json::to_string(&obj).unwrap_or_default()
    }
}

/// Helper to create an AnnounceRecord from callback data.
pub fn make_announce_record(announced: &rns_net::AnnouncedIdentity) -> AnnounceRecord {
    AnnounceRecord {
        dest_hash: to_hex(&announced.dest_hash.0),
        identity_hash: to_hex(&announced.identity_hash.0),
        hops: announced.hops,
        app_data: announced
            .app_data
            .as_ref()
            .map(|d| crate::encode::to_base64(d)),
        received_at: announced.received_at,
    }
}
