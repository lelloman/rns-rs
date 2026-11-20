use std::collections::{HashMap, VecDeque};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

use serde::Serialize;

use rns_crypto::identity::Identity;
use rns_net::{Destination, RnsNode};

use crate::encode::to_hex;

const MAX_RECORDS: usize = 1000;

/// Shared state accessible from HTTP handlers and Callbacks.
pub type SharedState = Arc<RwLock<CtlState>>;
/// Shared, live-reloadable HTTP control-plane configuration. Auth checks read
/// it on every request, so writes take effect without a restart.
pub type ControlPlaneConfigHandle = Arc<RwLock<crate::config::CtlConfig>>;
/// Checks a candidate `rns-server.json` document without saving it. Installed
/// by the supervisor; returns the resolved configuration and any warnings, or
/// the reason the document is rejected.
pub type ServerConfigValidator =
    Arc<dyn Fn(&[u8]) -> Result<ServerConfigValidationSnapshot, String> + Send + Sync>;
/// Saves (and, in [`ServerConfigMutationMode::Apply`], applies) a new
/// `rns-server.json` document. Installed by the supervisor; returns what
/// changed and what still has to restart, or the reason it was rejected.
pub type ServerConfigMutator = Arc<
    dyn Fn(ServerConfigMutationMode, &[u8]) -> Result<ServerConfigMutationResult, String>
        + Send
        + Sync,
>;

/// Registry of WebSocket broadcast senders.
pub type WsBroadcast = Arc<Mutex<Vec<std::sync::mpsc::Sender<WsEvent>>>>;

/// Everything the control plane knows about the node and, under
/// `rns-server`, the supervised processes.
///
/// Event histories (announces, packets, proofs, link, resource and process
/// events, each process's log) keep the most recent 1000 entries and drop the
/// oldest. Access it through [`SharedState`].
pub struct CtlState {
    /// When this state was created; the control plane's uptime counts from here.
    pub started_at: Instant,
    /// `"standalone"` for a plain `rns-ctl http`, `"supervised"` under `rns-server`.
    pub server_mode: String,
    /// The supervisor's resolved configuration, when running under `rns-server`.
    pub server_config: Option<ServerConfigSnapshot>,
    /// Description of the editable `rns-server.json` fields, when supervised.
    pub server_config_schema: Option<ServerConfigSchemaSnapshot>,
    /// Progress of the last configuration save or apply.
    pub server_config_status: ServerConfigStatusState,
    /// Validator for `POST /api/config/validate`; `None` when not supervised.
    pub server_config_validator: Option<ServerConfigValidator>,
    /// Save/apply hook for the config endpoints; `None` when not supervised.
    pub server_config_mutator: Option<ServerConfigMutator>,
    /// Hash of the node's identity, once loaded from the config directory.
    pub identity_hash: Option<[u8; 16]>,
    /// The node's identity with its private key, once loaded.
    pub identity: Option<Identity>,
    /// Announces received, oldest first.
    pub announces: VecDeque<AnnounceRecord>,
    /// Packets delivered to local destinations, plus channel messages and
    /// request responses, oldest first.
    pub packets: VecDeque<PacketRecord>,
    /// Delivery proofs received, oldest first.
    pub proofs: VecDeque<ProofRecord>,
    /// Link lifecycle events, oldest first.
    pub link_events: VecDeque<LinkEventRecord>,
    /// Resource transfer events, oldest first.
    pub resource_events: VecDeque<ResourceEventRecord>,
    /// Supervised-process lifecycle events, oldest first.
    pub process_events: VecDeque<ProcessEventRecord>,
    /// Recent output lines of each supervised process, by process name.
    pub process_logs: HashMap<String, VecDeque<ProcessLogRecord>>,
    /// Destinations registered through the API, by destination hash.
    pub destinations: HashMap<[u8; 16], DestinationEntry>,
    /// Supervised processes, by name.
    pub processes: HashMap<String, ManagedProcessState>,
    /// Channel to the supervisor for start/stop/restart requests; `None` when
    /// not supervised.
    pub control_tx: Option<mpsc::Sender<ProcessControlCommand>>,
    /// The HTTP server's live configuration, set when the server is prepared.
    pub control_plane_config: Option<ControlPlaneConfigHandle>,
    /// The node the API talks to. The inner `Option` is `None` until the node
    /// (or, in daemon mode, the connection to the shared instance) is up.
    pub node_handle: Option<Arc<Mutex<Option<RnsNode>>>>,
}

/// A registered destination plus metadata for the API.
pub struct DestinationEntry {
    /// The registered destination.
    pub destination: Destination,
    /// Full name: "app_name.aspect1.aspect2"
    pub full_name: String,
}

impl Default for CtlState {
    fn default() -> Self {
        Self::new()
    }
}

impl CtlState {
    /// Empty state in `"standalone"` mode, with the uptime clock starting now.
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
            control_plane_config: None,
            node_handle: None,
        }
    }

    /// Seconds since this state was created.
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

pub(crate) fn read_state<'a>(state: &'a SharedState) -> RwLockReadGuard<'a, CtlState> {
    match state.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned control-plane shared state read lock");
            poisoned.into_inner()
        }
    }
}

pub(crate) fn write_state<'a>(state: &'a SharedState) -> RwLockWriteGuard<'a, CtlState> {
    match state.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned control-plane shared state write lock");
            poisoned.into_inner()
        }
    }
}

pub(crate) fn read_control_plane_config<'a>(
    config: &'a ControlPlaneConfigHandle,
) -> RwLockReadGuard<'a, crate::config::CtlConfig> {
    match config.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned control-plane config read lock");
            poisoned.into_inner()
        }
    }
}

pub(crate) fn lock_ws_broadcast<'a>(
    ws: &'a WsBroadcast,
) -> MutexGuard<'a, Vec<std::sync::mpsc::Sender<WsEvent>>> {
    match ws.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned WebSocket broadcast registry");
            poisoned.into_inner()
        }
    }
}

pub(crate) fn lock_node_handle<'a>(
    node: &'a Arc<Mutex<Option<RnsNode>>>,
) -> MutexGuard<'a, Option<RnsNode>> {
    match node.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned node handle lock");
            poisoned.into_inner()
        }
    }
}

pub(crate) fn push_announce(state: &SharedState, record: AnnounceRecord) {
    let mut s = write_state(state);
    push_capped(&mut s.announces, record);
}

pub(crate) fn push_packet(state: &SharedState, record: PacketRecord) {
    let mut s = write_state(state);
    push_capped(&mut s.packets, record);
}

pub(crate) fn push_proof(state: &SharedState, record: ProofRecord) {
    let mut s = write_state(state);
    push_capped(&mut s.proofs, record);
}

pub(crate) fn push_link_event(state: &SharedState, record: LinkEventRecord) {
    let mut s = write_state(state);
    push_capped(&mut s.link_events, record);
}

pub(crate) fn push_resource_event(state: &SharedState, record: ResourceEventRecord) {
    let mut s = write_state(state);
    push_capped(&mut s.resource_events, record);
}

/// Broadcast a WsEvent to all connected WebSocket clients.
pub fn broadcast(ws: &WsBroadcast, event: WsEvent) {
    let mut senders = lock_ws_broadcast(ws);
    senders.retain(|tx| tx.send(event.clone()).is_ok());
}

/// Set [`CtlState::server_mode`].
pub fn set_server_mode(state: &SharedState, mode: impl Into<String>) {
    let mut s = write_state(state);
    s.server_mode = mode.into();
}

/// Publish the supervisor's current resolved configuration.
pub fn set_server_config(state: &SharedState, config: ServerConfigSnapshot) {
    let mut s = write_state(state);
    s.server_config = Some(config);
}

/// Publish the description of the editable configuration fields.
pub fn set_server_config_schema(state: &SharedState, schema: ServerConfigSchemaSnapshot) {
    let mut s = write_state(state);
    s.server_config_schema = Some(schema);
}

/// Record that a configuration was saved but not applied. The runtime is
/// marked as differing from the saved file when `apply_plan` needs any restart
/// or reload.
pub fn note_server_config_saved(state: &SharedState, apply_plan: &ServerConfigApplyPlan) {
    let mut s = write_state(state);
    s.server_config_status.last_saved_at = Some(Instant::now());
    s.server_config_status.last_action = Some("save".into());
    s.server_config_status.last_action_at = Some(Instant::now());
    s.server_config_status.pending_process_restarts.clear();
    s.server_config_status.control_plane_reload_required = apply_plan.control_plane_reload_required;
    s.server_config_status.control_plane_restart_required =
        apply_plan.control_plane_restart_required;
    s.server_config_status.runtime_differs_from_saved = !apply_plan.processes_to_restart.is_empty()
        || apply_plan.control_plane_reload_required
        || apply_plan.control_plane_restart_required;
    s.server_config_status.last_apply_plan = Some(apply_plan.clone());
}

/// Record that a configuration was saved and applied. The processes in
/// `apply_plan` stay pending until each reports ready (see
/// [`set_process_readiness`]); an embedded HTTP reload is taken as done.
pub fn note_server_config_applied(state: &SharedState, apply_plan: &ServerConfigApplyPlan) {
    let mut s = write_state(state);
    let now = Instant::now();
    s.server_config_status.last_saved_at = Some(now);
    s.server_config_status.last_apply_at = Some(now);
    s.server_config_status.last_action = Some("apply".into());
    s.server_config_status.last_action_at = Some(now);
    s.server_config_status.pending_process_restarts = apply_plan.processes_to_restart.clone();
    s.server_config_status.control_plane_reload_required = false;
    s.server_config_status.control_plane_restart_required =
        apply_plan.control_plane_restart_required;
    s.server_config_status.runtime_differs_from_saved =
        !s.server_config_status.pending_process_restarts.is_empty()
            || s.server_config_status.control_plane_restart_required;
    s.server_config_status.last_apply_plan = Some(apply_plan.clone());
}

pub(crate) fn reconcile_config_status_for_process(
    state: &SharedState,
    name: &str,
    ready: bool,
    status: &str,
) {
    let mut s = write_state(state);
    if ready {
        s.server_config_status
            .pending_process_restarts
            .retain(|process| process != name);
    }
    if status == "failed" {
        s.server_config_status.runtime_differs_from_saved = true;
    } else if s.server_config_status.pending_process_restarts.is_empty()
        && !s.server_config_status.control_plane_reload_required
        && !s.server_config_status.control_plane_restart_required
    {
        s.server_config_status.runtime_differs_from_saved = false;
    }
}

/// Install the validator behind the config validation endpoint.
pub fn set_server_config_validator(state: &SharedState, validator: ServerConfigValidator) {
    let mut s = write_state(state);
    s.server_config_validator = Some(validator);
}

/// Install the save/apply hook behind the config endpoints.
pub fn set_server_config_mutator(state: &SharedState, mutator: ServerConfigMutator) {
    let mut s = write_state(state);
    s.server_config_mutator = Some(mutator);
}

/// Register a supervised process (as stopped) if it is not known yet, and
/// log a `registered` event.
pub fn ensure_process(state: &SharedState, name: impl Into<String>) {
    let mut s = write_state(state);
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

/// Append one output line of process `name`; `stream` labels where it came
/// from (`stdout`, `stderr`). Registers the process if it is unknown.
pub fn push_process_log(state: &SharedState, name: &str, stream: &str, line: impl Into<String>) {
    let mut s = write_state(state);
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

/// Record the file that durably keeps process `name`'s output.
pub fn set_process_log_path(state: &SharedState, name: &str, path: impl Into<String>) {
    let mut s = write_state(state);
    let process = s
        .processes
        .entry(name.to_string())
        .or_insert_with(|| ManagedProcessState::new(name.to_string()));
    process.durable_log_path = Some(path.into());
}

/// Install the channel that carries process control requests to the
/// supervisor.
pub fn set_control_tx(state: &SharedState, tx: mpsc::Sender<ProcessControlCommand>) {
    let mut s = write_state(state);
    s.control_tx = Some(tx);
}

pub(crate) fn set_control_plane_config(state: &SharedState, config: ControlPlaneConfigHandle) {
    let mut s = write_state(state);
    s.control_plane_config = Some(config);
}

/// Record that process `name` was spawned as `pid`. It reads as not ready
/// (`starting`) until [`set_process_readiness`] says otherwise.
pub fn mark_process_running(state: &SharedState, name: &str, pid: u32) {
    let mut s = write_state(state);
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

/// Count one restart of process `name` and log a `restart_requested` event.
pub fn bump_process_restart_count(state: &SharedState, name: &str) {
    let mut s = write_state(state);
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

/// Record how process `name` went down: whether it acknowledged a drain
/// request, and whether it had to be killed. Logs an event only when either is
/// true.
pub fn record_process_termination_observation(
    state: &SharedState,
    name: &str,
    drain_acknowledged: bool,
    forced_kill: bool,
) {
    let mut s = write_state(state);
    let detail = {
        let process = s
            .processes
            .entry(name.to_string())
            .or_insert_with(|| ManagedProcessState::new(name.to_string()));
        if drain_acknowledged {
            process.drain_ack_count = process.drain_ack_count.saturating_add(1);
        }
        if forced_kill {
            process.forced_kill_count = process.forced_kill_count.saturating_add(1);
        }

        let mut parts = Vec::new();
        if drain_acknowledged {
            parts.push(format!("drain_ack_count={}", process.drain_ack_count));
        }
        if forced_kill {
            parts.push(format!("forced_kill_count={}", process.forced_kill_count));
        }
        (!parts.is_empty()).then(|| parts.join(", "))
    };

    if let Some(detail) = detail {
        push_capped(
            &mut s.process_events,
            ProcessEventRecord::new(name.to_string(), "termination_observed", Some(detail)),
        );
    }
}

/// Record that process `name` exited, with its exit code when it has one.
pub fn mark_process_stopped(state: &SharedState, name: &str, exit_code: Option<i32>) {
    let mut s = write_state(state);
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

/// Record that process `name` could not be spawned, with the reason.
pub fn mark_process_failed_spawn(state: &SharedState, name: &str, error: String) {
    let mut s = write_state(state);
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

/// Set process `name`'s readiness, its state label (`ready`, `draining`, ...)
/// and detail. Logs an event unless it repeats the last one; a process that
/// becomes ready leaves the pending-restart list of the config status.
pub fn set_process_readiness(
    state: &SharedState,
    name: &str,
    ready: bool,
    ready_state: &str,
    status_detail: Option<String>,
) {
    let mut s = write_state(state);
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

/// A received announce, as the API and WebSocket clients see it.
#[derive(Debug, Clone, Serialize)]
pub struct AnnounceRecord {
    /// Announced destination hash, lowercase hex.
    pub dest_hash: String,
    /// Hash of the announcing identity, lowercase hex.
    pub identity_hash: String,
    /// Hops the announce travelled.
    pub hops: u8,
    /// Application data carried by the announce, base64.
    pub app_data: Option<String>,
    /// When it arrived, Unix time in seconds.
    pub received_at: f64,
}

/// Data delivered to a local destination, as the API and WebSocket clients see
/// it.
///
/// Channel messages and request responses use the same record: their
/// `dest_hash` is `channel:<link id>:<msgtype>` or
/// `response:<link id>:<request id>` and their `packet_hash` is empty.
#[derive(Debug, Clone, Serialize)]
pub struct PacketRecord {
    /// Destination the data was delivered to, lowercase hex (see above for
    /// channel messages and responses).
    pub dest_hash: String,
    /// Packet hash, lowercase hex.
    pub packet_hash: String,
    /// Payload, base64.
    pub data_base64: String,
    /// When it arrived, Unix time in seconds.
    pub received_at: f64,
}

/// A delivery proof received for a packet this node sent.
#[derive(Debug, Clone, Serialize)]
pub struct ProofRecord {
    /// Destination the proven packet was sent to, lowercase hex.
    pub dest_hash: String,
    /// Hash of the proven packet, lowercase hex.
    pub packet_hash: String,
    /// Round-trip time in seconds.
    pub rtt: f64,
}

/// A link lifecycle event.
#[derive(Debug, Clone, Serialize)]
pub struct LinkEventRecord {
    /// Link id, lowercase hex.
    pub link_id: String,
    /// `established`, `closed`, `identified`, `direct_established`,
    /// `direct_lost` or `direct_failed`.
    pub event_type: String,
    /// Whether this node initiated the link; set on `established`.
    pub is_initiator: Option<bool>,
    /// Link round-trip time in seconds; set on `established`.
    pub rtt: Option<f64>,
    /// Identity the peer proved, lowercase hex; set on `identified`.
    pub identity_hash: Option<String>,
    /// Teardown reason on `closed`, interface or reason code on the direct
    /// connection events.
    pub reason: Option<String>,
}

/// A resource transfer event on a link.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceEventRecord {
    /// Link id, lowercase hex.
    pub link_id: String,
    /// `received`, `completed`, `failed` or `progress`.
    pub event_type: String,
    /// The resource's data, base64; set on `received`.
    pub data_base64: Option<String>,
    /// The resource's metadata, base64; set on `received` when it had any.
    pub metadata_base64: Option<String>,
    /// Failure reason; set on `failed`.
    pub error: Option<String>,
    /// Parts received so far; set on `progress`.
    pub received: Option<usize>,
    /// Total parts; set on `progress`.
    pub total: Option<usize>,
}

/// A lifecycle event of a supervised process.
#[derive(Debug, Clone)]
pub struct ProcessEventRecord {
    /// Process name.
    pub process: String,
    /// What happened: `registered`, `running`, `stopped`, `spawn_failed`,
    /// `restart_requested`, `termination_observed`, or a readiness state.
    pub event: String,
    /// Free-form detail, such as the pid or exit code.
    pub detail: Option<String>,
    /// When it was recorded.
    pub recorded_at: Instant,
}

/// One output line of a supervised process.
#[derive(Debug, Clone)]
pub struct ProcessLogRecord {
    /// Process name.
    pub process: String,
    /// Where the line came from, such as `stdout` or `stderr`.
    pub stream: String,
    /// The line, without its line terminator.
    pub line: String,
    /// When it was recorded.
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

/// The supervisor's resolved configuration, as the config endpoints report
/// it. Paths are rendered as strings.
#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigSnapshot {
    /// Config directory given on the command line, if any.
    pub config_path: Option<String>,
    /// Config directory in use.
    pub resolved_config_dir: String,
    /// Path of `rns-server.json`.
    pub server_config_file_path: String,
    /// Whether that file exists; without it the defaults apply.
    pub server_config_file_present: bool,
    /// The editable configuration, as pretty-printed JSON.
    pub server_config_file_json: String,
    /// Path of the stats database `rns-statsd` writes and the stats endpoints read.
    pub stats_db_path: String,
    /// How `rnsd` is launched: a binary path or a self-spawn label.
    pub rnsd_bin: String,
    /// How `rns-sentineld` is launched.
    pub sentineld_bin: String,
    /// How `rns-statsd` is launched.
    pub statsd_bin: String,
    /// Embedded HTTP control-plane settings.
    pub http: ServerHttpConfigSnapshot,
    /// The processes the supervisor starts, in order.
    pub launch_plan: Vec<LaunchProcessSnapshot>,
}

/// Description of the editable configuration file, for clients that build a
/// form or validate input.
#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigSchemaSnapshot {
    /// Name of the documented file, `rns-server.json`.
    pub format: String,
    /// A complete example document.
    pub example_config_json: String,
    /// General notes on editing the file.
    pub notes: Vec<String>,
    /// One entry per field.
    pub fields: Vec<ServerConfigFieldSchema>,
}

/// One editable configuration field.
#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigFieldSchema {
    /// Field path, such as `http.port`.
    pub field: String,
    /// Value type, such as `string`, `u16`, `boolean` or `u64|null`.
    pub field_type: String,
    /// Whether the document must set it.
    pub required: bool,
    /// Value used when it is not set, rendered for display.
    pub default_value: String,
    /// What the field controls.
    pub description: String,
    /// What changing it takes, such as which process restarts.
    pub effect: String,
}

/// Whether the running system has caught up with the saved configuration, as
/// `GET /api/config/status` reports it. Built by
/// [`ServerConfigStatusState::snapshot`]; ages are in seconds.
#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigStatusSnapshot {
    /// Time since the last save (an apply is also a save).
    pub last_saved_age_seconds: Option<f64>,
    /// Time since the last apply.
    pub last_apply_age_seconds: Option<f64>,
    /// `save` or `apply`.
    pub last_action: Option<String>,
    /// Time since the last save or apply.
    pub last_action_age_seconds: Option<f64>,
    /// The last apply plan's overall action while it has not converged.
    pub pending_action: Option<String>,
    /// What still has to restart or reload: process names, `embedded-http-auth`,
    /// `rns-server`.
    pub pending_targets: Vec<String>,
    /// What the operator or system still has to do, in words; `None` once
    /// converged.
    pub blocking_reason: Option<String>,
    /// Processes restarted by the last apply that have not reported ready yet.
    pub pending_process_restarts: Vec<String>,
    /// Saved HTTP auth settings are not loaded yet; an apply loads them.
    pub control_plane_reload_required: bool,
    /// Saved HTTP bind or enablement changes need an `rns-server` restart.
    pub control_plane_restart_required: bool,
    /// The running system does not match the saved file.
    pub runtime_differs_from_saved: bool,
    /// No restart or reload is pending.
    pub converged: bool,
    /// One-sentence description of the state, for display.
    pub summary: String,
    /// Plan of the last save or apply.
    pub last_apply_plan: Option<ServerConfigApplyPlan>,
}

/// Embedded HTTP control-plane settings of the supervisor.
#[derive(Debug, Clone, Serialize)]
pub struct ServerHttpConfigSnapshot {
    /// Whether `rns-server` runs the HTTP control plane.
    pub enabled: bool,
    /// Bind address.
    pub host: String,
    /// Bind port.
    pub port: u16,
    /// `bearer-token` or `disabled`.
    pub auth_mode: String,
    /// Whether a token is set in the configuration (the token itself is never
    /// reported).
    pub token_configured: bool,
    /// Whether the control plane talks to `rnsd` as a shared-instance client
    /// instead of running its own node.
    pub daemon_mode: bool,
}

/// A process the supervisor launches.
#[derive(Debug, Clone, Serialize)]
pub struct LaunchProcessSnapshot {
    /// Process name, such as `rnsd`.
    pub name: String,
    /// Binary that is executed.
    pub bin: String,
    /// Arguments passed to it.
    pub args: Vec<String>,
    /// The whole command line, for display.
    pub command_line: String,
}

/// Outcome of validating a configuration document.
#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigValidationSnapshot {
    /// Whether it would be accepted.
    pub valid: bool,
    /// The configuration it resolves to.
    pub config: ServerConfigSnapshot,
    /// Problems that do not block saving it.
    pub warnings: Vec<String>,
}

/// Outcome of saving or applying a configuration document.
#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigMutationResult {
    /// `save` or `apply`.
    pub action: String,
    /// The configuration now saved.
    pub config: ServerConfigSnapshot,
    /// What the change requires to take effect.
    pub apply_plan: ServerConfigApplyPlan,
    /// Problems that did not block the change.
    pub warnings: Vec<String>,
}

/// What a configuration change requires to take effect.
#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigApplyPlan {
    /// Summary of the strongest step needed: `none`, `restart_children`,
    /// `reload_control_plane` or `restart_server`.
    pub overall_action: String,
    /// Supervised processes that must restart.
    pub processes_to_restart: Vec<String>,
    /// The embedded HTTP auth settings must be reloaded.
    pub control_plane_reload_required: bool,
    /// `rns-server` itself must restart (HTTP bind or enablement changed).
    pub control_plane_restart_required: bool,
    /// Explanations for the operator.
    pub notes: Vec<String>,
    /// Each field that changed.
    pub changes: Vec<ServerConfigChange>,
}

/// One changed configuration field.
#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigChange {
    /// Field path, such as `http.port`.
    pub field: String,
    /// Old value, rendered for display.
    pub before: String,
    /// New value, rendered for display.
    pub after: String,
    /// What the change requires, in words.
    pub effect: String,
}

/// What a configuration mutation does after validating the document.
#[derive(Debug, Clone, Copy)]
pub enum ServerConfigMutationMode {
    /// Write the file only; the running system keeps the old settings.
    Save,
    /// Write the file and restart or reload what the change affects.
    Apply,
}

/// Raw progress of configuration saves and applies, kept in [`CtlState`].
/// [`snapshot`](Self::snapshot) turns it into the reported form.
#[derive(Debug, Clone, Default)]
pub struct ServerConfigStatusState {
    /// When the configuration was last saved (an apply is also a save).
    pub last_saved_at: Option<Instant>,
    /// When it was last applied.
    pub last_apply_at: Option<Instant>,
    /// `save` or `apply`.
    pub last_action: Option<String>,
    /// When the last save or apply happened.
    pub last_action_at: Option<Instant>,
    /// Processes the last apply restarted that have not reported ready yet.
    pub pending_process_restarts: Vec<String>,
    /// Saved HTTP auth settings are not loaded yet.
    pub control_plane_reload_required: bool,
    /// Saved HTTP bind or enablement changes need an `rns-server` restart.
    pub control_plane_restart_required: bool,
    /// The running system does not match the saved file.
    pub runtime_differs_from_saved: bool,
    /// Plan of the last save or apply.
    pub last_apply_plan: Option<ServerConfigApplyPlan>,
}

impl ServerConfigStatusState {
    /// The reported form, with ages measured from now and a summary of what is
    /// still pending.
    pub fn snapshot(&self) -> ServerConfigStatusSnapshot {
        let converged = self.pending_process_restarts.is_empty()
            && !self.control_plane_reload_required
            && !self.control_plane_restart_required;
        let pending_action = (!converged)
            .then(|| {
                self.last_apply_plan
                    .as_ref()
                    .map(|plan| plan.overall_action.clone())
            })
            .flatten();
        let mut pending_targets = self.pending_process_restarts.clone();
        if self.control_plane_reload_required {
            pending_targets.push("embedded-http-auth".into());
        }
        if self.control_plane_restart_required {
            pending_targets.push("rns-server".into());
        }
        let blocking_reason = if self.control_plane_restart_required {
            Some("Restart rns-server to apply embedded HTTP bind or enablement changes.".into())
        } else if self.control_plane_reload_required {
            Some("Apply config to reload embedded HTTP auth settings into the running control plane.".into())
        } else if !self.pending_process_restarts.is_empty() {
            Some(format!(
                "Waiting for restarted processes to become ready: {}.",
                self.pending_process_restarts.join(", ")
            ))
        } else {
            None
        };
        let summary = if self.runtime_differs_from_saved {
            if self.control_plane_restart_required {
                "Saved config is not fully active; rns-server restart is still required.".into()
            } else if self.control_plane_reload_required {
                "Saved config is not fully active; embedded HTTP auth reload is still required."
                    .into()
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
            pending_action,
            pending_targets,
            blocking_reason,
            pending_process_restarts: self.pending_process_restarts.clone(),
            control_plane_reload_required: self.control_plane_reload_required,
            control_plane_restart_required: self.control_plane_restart_required,
            runtime_differs_from_saved: self.runtime_differs_from_saved,
            converged,
            summary,
            last_apply_plan: self.last_apply_plan.clone(),
        }
    }
}

/// The supervisor's view of one managed process.
#[derive(Debug, Clone)]
pub struct ManagedProcessState {
    /// Process name.
    pub name: String,
    /// `stopped`, `running` or `failed`.
    pub status: String,
    /// Whether the process reported ready.
    pub ready: bool,
    /// Readiness label: `stopped`, `starting`, `ready`, `draining`, `failed`, ...
    pub ready_state: String,
    /// OS process id while running.
    pub pid: Option<u32>,
    /// Exit code of the last run, when it exited with one.
    pub last_exit_code: Option<i32>,
    /// Restarts since registration.
    pub restart_count: u32,
    /// Times the process acknowledged a drain request before stopping.
    pub drain_ack_count: u32,
    /// Times the process had to be killed.
    pub forced_kill_count: u32,
    /// Last spawn error.
    pub last_error: Option<String>,
    /// Detail for the current status, for display.
    pub status_detail: Option<String>,
    /// File that keeps the process's output.
    pub durable_log_path: Option<String>,
    /// When the last output line arrived.
    pub last_log_at: Option<Instant>,
    /// Output lines held in memory for it.
    pub recent_log_lines: usize,
    /// When the current run started; `None` when not running.
    pub started_at: Option<Instant>,
    /// When the status last changed.
    pub last_transition_at: Option<Instant>,
}

/// A request to the supervisor, by process name.
#[derive(Debug, Clone)]
pub enum ProcessControlCommand {
    /// Stop the process and start it again.
    Restart(String),
    /// Start the process if it is not running.
    Start(String),
    /// Stop the process; it stays down until started again.
    Stop(String),
}

impl ManagedProcessState {
    /// A stopped, never-run process.
    pub fn new(name: String) -> Self {
        Self {
            name,
            status: "stopped".into(),
            ready: false,
            ready_state: "stopped".into(),
            pid: None,
            last_exit_code: None,
            restart_count: 0,
            drain_ack_count: 0,
            forced_kill_count: 0,
            last_error: None,
            status_detail: None,
            durable_log_path: None,
            last_log_at: None,
            recent_log_lines: 0,
            started_at: None,
            last_transition_at: None,
        }
    }

    /// Seconds since the current run started; `None` when not running.
    pub fn uptime_seconds(&self) -> Option<f64> {
        self.started_at
            .map(|started| started.elapsed().as_secs_f64())
    }

    /// Seconds since the status last changed.
    pub fn last_transition_seconds(&self) -> Option<f64> {
        self.last_transition_at
            .map(|transition| transition.elapsed().as_secs_f64())
    }

    /// Seconds since the last output line.
    pub fn last_log_age_seconds(&self) -> Option<f64> {
        self.last_log_at
            .map(|logged| logged.elapsed().as_secs_f64())
    }
}

// --- WebSocket events ---

/// An event pushed to WebSocket subscribers.
#[derive(Debug, Clone)]
pub struct WsEvent {
    /// Subscription topic: `announces`, `packets`, `proofs`, `links` or
    /// `resources`.
    pub topic: &'static str,
    /// The event's record as JSON.
    pub payload: serde_json::Value,
}

impl WsEvent {
    pub(crate) fn announce(record: &AnnounceRecord) -> Self {
        WsEvent {
            topic: "announces",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub(crate) fn packet(record: &PacketRecord) -> Self {
        WsEvent {
            topic: "packets",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub(crate) fn proof(record: &ProofRecord) -> Self {
        WsEvent {
            topic: "proofs",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub(crate) fn link(record: &LinkEventRecord) -> Self {
        WsEvent {
            topic: "links",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub(crate) fn resource(record: &ResourceEventRecord) -> Self {
        WsEvent {
            topic: "resources",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub(crate) fn to_json(&self) -> String {
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

#[cfg(test)]
mod tests {
    use super::{
        mark_process_running, record_process_termination_observation, CtlState, SharedState,
    };
    use std::sync::{Arc, RwLock};

    #[test]
    fn termination_observation_tracks_drain_ack_and_forced_kill_counts() {
        let state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        mark_process_running(&state, "rnsd", 1234);

        record_process_termination_observation(&state, "rnsd", true, false);
        record_process_termination_observation(&state, "rnsd", false, true);

        let snapshot = {
            let s = state.read().unwrap();
            s.processes.get("rnsd").cloned().unwrap()
        };
        assert_eq!(snapshot.drain_ack_count, 1);
        assert_eq!(snapshot.forced_kill_count, 1);
    }
}
