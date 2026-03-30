const tokenInput = document.getElementById("token");
const saveButton = document.getElementById("saveToken");
const statusEl = document.getElementById("status");
const serverModeEl = document.getElementById("serverMode");
const uptimeEl = document.getElementById("uptime");
const runningEl = document.getElementById("running");
const readyEl = document.getElementById("ready");
const configConvergedEl = document.getElementById("configConverged");
const configStatusSummaryEl = document.getElementById("configStatusSummary");
const configRuntimeBadgeEl = document.getElementById("configRuntimeBadge");
const configRuntimeDetailEl = document.getElementById("configRuntimeDetail");
const configRestartBadgeEl = document.getElementById("configRestartBadge");
const configRestartDetailEl = document.getElementById("configRestartDetail");
const configControlPlaneBadgeEl = document.getElementById("configControlPlaneBadge");
const configControlPlaneDetailEl = document.getElementById("configControlPlaneDetail");
const configLastActionEl = document.getElementById("configLastAction");
const configLastSavedEl = document.getElementById("configLastSaved");
const configLastAppliedEl = document.getElementById("configLastApplied");
const configPathEl = document.getElementById("configPath");
const configDirEl = document.getElementById("configDir");
const serverConfigFileEl = document.getElementById("serverConfigFile");
const statsDbEl = document.getElementById("statsDb");
const rnsdBinEl = document.getElementById("rnsdBin");
const sentineldBinEl = document.getElementById("sentineldBin");
const statsdBinEl = document.getElementById("statsdBin");
const httpBindEl = document.getElementById("httpBind");
const httpAuthEl = document.getElementById("httpAuth");
const launchPlanRowsEl = document.getElementById("launchPlanRows");
const configCandidateEl = document.getElementById("configCandidate");
const builderStatsDbPathEl = document.getElementById("builderStatsDbPath");
const builderRnsdBinEl = document.getElementById("builderRnsdBin");
const builderSentineldBinEl = document.getElementById("builderSentineldBin");
const builderStatsdBinEl = document.getElementById("builderStatsdBin");
const builderHttpEnabledEl = document.getElementById("builderHttpEnabled");
const builderHttpHostEl = document.getElementById("builderHttpHost");
const builderHttpPortEl = document.getElementById("builderHttpPort");
const builderHttpDisableAuthEl = document.getElementById("builderHttpDisableAuth");
const builderHttpAuthTokenEl = document.getElementById("builderHttpAuthToken");
const loadCurrentConfigButton = document.getElementById("loadCurrentConfig");
const loadExampleConfigButton = document.getElementById("loadExampleConfig");
const syncBuilderFromJsonButton = document.getElementById("syncBuilderFromJson");
const syncJsonFromBuilderButton = document.getElementById("syncJsonFromBuilder");
const formatConfigButton = document.getElementById("formatConfig");
const validateConfigButton = document.getElementById("validateConfig");
const saveConfigButton = document.getElementById("saveConfig");
const applyConfigButton = document.getElementById("applyConfig");
const configValidationStatusEl = document.getElementById("configValidationStatus");
const configActionSummaryEl = document.getElementById("configActionSummary");
const configWarningListEl = document.getElementById("configWarningList");
const configPlanSummaryEl = document.getElementById("configPlanSummary");
const configChangeRowsEl = document.getElementById("configChangeRows");
const configSchemaNotesEl = document.getElementById("configSchemaNotes");
const configSchemaRowsEl = document.getElementById("configSchemaRows");
const configValidationResultEl = document.getElementById("configValidationResult");
const processRowsEl = document.getElementById("processRows");
const processEventRowsEl = document.getElementById("processEventRows");
const logProcessNameEl = document.getElementById("logProcessName");
const logStatusEl = document.getElementById("logStatus");
const processLogOutputEl = document.getElementById("processLogOutput");
let configEditorDirty = false;
let configBuilderDirty = false;
let selectedLogProcess = null;
let currentConfigJson = "";
let schemaExampleJson = "";

const params = new URLSearchParams(window.location.search);
const initialToken = params.get("token") || localStorage.getItem("rnsctl_token") || "";
tokenInput.value = initialToken;

function fmtSeconds(value) {
  if (value == null) return "-";
  const total = Math.floor(value);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  return `${hours}h ${minutes}m ${seconds}s`;
}

function fmtAge(value) {
  if (value == null) return "-";
  if (value < 1) return "<1s ago";
  return `${fmtSeconds(value)} ago`;
}

function setBadge(el, label, className) {
  el.textContent = label;
  el.className = `pill ${className}`;
}

function authHeaders() {
  const token = tokenInput.value.trim();
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
}

async function fetchJson(path) {
  const response = await fetch(path, { headers: authHeaders() });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
  return response.json();
}

async function postJson(path) {
  const response = await fetch(path, { method: "POST", headers: authHeaders() });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
  return response.json();
}

function renderProcesses(processes) {
  processRowsEl.innerHTML = "";
  for (const process of processes) {
    const tr = document.createElement("tr");
    const statusClass = process.status === "running" ? "running" : (process.status || "stopped");
    const healthSummary = [
      process.status_detail ?? process.last_error ?? "",
      process.last_log_age_seconds != null ? `last log ${fmtAge(process.last_log_age_seconds)}` : "",
      process.durable_log_path ? `file ${process.durable_log_path}` : "",
    ].filter(Boolean).join(" | ");
    tr.innerHTML = `
      <td>${process.name}</td>
      <td><span class="pill ${statusClass}">${process.status}</span></td>
      <td>${process.ready ? "yes" : (process.ready_state ?? "no")}</td>
      <td>${process.pid ?? "-"}</td>
      <td>${fmtSeconds(process.uptime_seconds)}</td>
      <td>${fmtSeconds(process.last_transition_seconds)}</td>
      <td>${process.last_exit_code ?? "-"}</td>
      <td>${healthSummary}</td>
      <td>
        <button class="secondary" data-start="${process.name}">Start</button>
        <button class="secondary" data-stop="${process.name}">Stop</button>
        <button class="secondary" data-restart="${process.name}">Restart</button>
      </td>
      <td><button class="secondary" data-logs="${process.name}">View Logs</button></td>
    `;
    processRowsEl.appendChild(tr);
  }

  if (!selectedLogProcess && processes.length > 0) {
    selectedLogProcess = processes[0].name;
  }

  for (const button of processRowsEl.querySelectorAll("[data-restart]")) {
    button.addEventListener("click", async () => {
      const name = button.getAttribute("data-restart");
      statusEl.textContent = `Restarting ${name}...`;
      try {
        await postJson(`/api/processes/${name}/restart`);
        statusEl.textContent = `Restart queued for ${name}`;
        refresh();
      } catch (error) {
        statusEl.textContent = error.message;
      }
    });
  }
  for (const button of processRowsEl.querySelectorAll("[data-start]")) {
    button.addEventListener("click", async () => {
      const name = button.getAttribute("data-start");
      statusEl.textContent = `Starting ${name}...`;
      try {
        await postJson(`/api/processes/${name}/start`);
        statusEl.textContent = `Start queued for ${name}`;
        refresh();
      } catch (error) {
        statusEl.textContent = error.message;
      }
    });
  }
  for (const button of processRowsEl.querySelectorAll("[data-stop]")) {
    button.addEventListener("click", async () => {
      const name = button.getAttribute("data-stop");
      statusEl.textContent = `Stopping ${name}...`;
      try {
        await postJson(`/api/processes/${name}/stop`);
        statusEl.textContent = `Stop queued for ${name}`;
        refresh();
      } catch (error) {
        statusEl.textContent = error.message;
      }
    });
  }
  for (const button of processRowsEl.querySelectorAll("[data-logs]")) {
    button.addEventListener("click", async () => {
      selectedLogProcess = button.getAttribute("data-logs");
      await refreshLogs();
    });
  }
}

function renderProcessEvents(events) {
  processEventRowsEl.innerHTML = "";
  for (const event of events) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${event.process}</td>
      <td>${event.event}</td>
      <td>${fmtSeconds(event.age_seconds)}</td>
      <td>${event.detail ?? ""}</td>
    `;
    processEventRowsEl.appendChild(tr);
  }
}

function renderConfig(config) {
  configPathEl.textContent = config?.config_path ?? "(default)";
  configDirEl.textContent = config?.resolved_config_dir ?? "-";
  serverConfigFileEl.textContent = config?.server_config_file_path
    ? `${config.server_config_file_path}${config.server_config_file_present ? "" : " (not present)"}`
    : "-";
  statsDbEl.textContent = config?.stats_db_path ?? "-";
  rnsdBinEl.textContent = config?.rnsd_bin ?? "-";
  sentineldBinEl.textContent = config?.sentineld_bin ?? "-";
  statsdBinEl.textContent = config?.statsd_bin ?? "-";

  if (config?.http?.enabled) {
    httpBindEl.textContent = `${config.http.host}:${config.http.port}`;
    const tokenMode = config.http.token_configured ? "token set" : "token generated at startup";
    httpAuthEl.textContent = `${config.http.auth_mode}, ${tokenMode}, daemon=${config.http.daemon_mode ? "yes" : "no"}`;
  } else {
    httpBindEl.textContent = "disabled";
    httpAuthEl.textContent = "disabled";
  }

  launchPlanRowsEl.innerHTML = "";
  for (const process of config?.launch_plan || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${process.name}</td>
      <td>${process.bin}</td>
      <td>${process.args && process.args.length ? process.args.join(" ") : "-"}</td>
    `;
    launchPlanRowsEl.appendChild(tr);
  }

  if (!configEditorDirty) {
    configCandidateEl.value = config?.server_config_file_json ?? "";
  }
  if (!configBuilderDirty) {
    populateBuilder(configFromSnapshot(config));
  }
  currentConfigJson = config?.server_config_file_json ?? "";
}

function renderConfigStatus(status) {
  if (!status) {
    configConvergedEl.textContent = "-";
    configStatusSummaryEl.textContent = "No config status yet.";
    setBadge(configRuntimeBadgeEl, "unknown", "info");
    setBadge(configRestartBadgeEl, "unknown", "info");
    setBadge(configControlPlaneBadgeEl, "unknown", "info");
    configRuntimeDetailEl.textContent = "No config status yet.";
    configRestartDetailEl.textContent = "No process restart information yet.";
    configControlPlaneDetailEl.textContent = "No control-plane restart information yet.";
    configLastActionEl.textContent = "-";
    configLastSavedEl.textContent = "-";
    configLastAppliedEl.textContent = "-";
    return;
  }

  configConvergedEl.textContent = status.converged ? "yes" : "no";
  const pending = status.pending_process_restarts?.length
    ? ` Pending restarts: ${status.pending_process_restarts.join(", ")}.`
    : "";
  const action = status.last_action
    ? ` Last action: ${status.last_action}.`
    : "";
  configStatusSummaryEl.textContent = `${status.summary}${action}${pending}`;

  if (status.runtime_differs_from_saved) {
    setBadge(configRuntimeBadgeEl, "drifted", "warn");
    configRuntimeDetailEl.textContent = "Saved config is not fully active in the current runtime state.";
  } else {
    setBadge(configRuntimeBadgeEl, "aligned", "ok");
    configRuntimeDetailEl.textContent = "Runtime state matches the saved config.";
  }

  if (status.pending_process_restarts?.length) {
    setBadge(configRestartBadgeEl, "pending", "warn");
    configRestartDetailEl.textContent = `Waiting on: ${status.pending_process_restarts.join(", ")}.`;
  } else {
    setBadge(configRestartBadgeEl, "clear", "ok");
    configRestartDetailEl.textContent = "No supervised child process restart is pending.";
  }

  if (status.control_plane_restart_required) {
    setBadge(configControlPlaneBadgeEl, "restart required", "warn");
    configControlPlaneDetailEl.textContent = "Restart rns-server to apply embedded HTTP control-plane changes.";
  } else {
    setBadge(configControlPlaneBadgeEl, "active", "ok");
    configControlPlaneDetailEl.textContent = "Embedded HTTP control-plane settings are active.";
  }

  configLastActionEl.textContent = status.last_action
    ? `${status.last_action} (${fmtAge(status.last_action_age_seconds)})`
    : "-";
  configLastSavedEl.textContent = fmtAge(status.last_saved_age_seconds);
  configLastAppliedEl.textContent = fmtAge(status.last_apply_age_seconds);
}

async function validateConfigCandidate() {
  await runConfigAction("/api/config/validate", "Validating...", "Validation");
}

async function saveConfigCandidate() {
  await runConfigAction("/api/config", "Saving...", "Save");
}

async function applyConfigCandidate() {
  await runConfigAction("/api/config/apply", "Saving and applying...", "Apply");
}

async function runConfigAction(path, pendingMessage, actionLabel) {
  try {
    syncJsonFromBuilder({ silent: true });
    configValidationStatusEl.textContent = pendingMessage;
    configActionSummaryEl.textContent = pendingMessage;
    configValidationResultEl.textContent = "";
    renderWarnings([]);
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders(),
      },
      body: configCandidateEl.value.trim(),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `${response.status} ${response.statusText}`);
    }
    configValidationStatusEl.textContent = `${actionLabel} succeeded`;
    configValidationResultEl.textContent = JSON.stringify(payload.result, null, 2);
    renderConfigPlan(payload.result?.apply_plan);
    renderActionSummary(payload.result, actionLabel);
    renderWarnings(payload.result?.warnings || []);
    if (path !== "/api/config/validate") {
      configEditorDirty = false;
      configBuilderDirty = false;
    }
    await refresh();
  } catch (error) {
    configValidationStatusEl.textContent = `${actionLabel} failed`;
    configActionSummaryEl.textContent = error.message;
    configValidationResultEl.textContent = error.message;
  }
}

function renderConfigPlan(plan) {
  if (!plan) {
    configPlanSummaryEl.textContent = "No plan yet";
    configChangeRowsEl.innerHTML = "";
    return;
  }

  const restartList = plan.processes_to_restart?.length
    ? plan.processes_to_restart.join(", ")
    : "none";
  const controlPlane = plan.control_plane_restart_required ? "yes" : "no";
  const notes = plan.notes?.length ? ` ${plan.notes.join(" ")}` : "";
  configPlanSummaryEl.textContent = `Processes to restart: ${restartList}. rns-server restart required: ${controlPlane}.${notes}`;

  configChangeRowsEl.innerHTML = "";
  for (const change of plan.changes || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${change.field}</td>
      <td>${change.before}</td>
      <td>${change.after}</td>
      <td>${change.effect}</td>
    `;
    configChangeRowsEl.appendChild(tr);
  }
}

function renderConfigSchema(schema) {
  if (!schema) {
    schemaExampleJson = "";
    configSchemaNotesEl.textContent = "No schema loaded yet";
    configSchemaRowsEl.innerHTML = "";
    return;
  }

  schemaExampleJson = schema.example_config_json || "";
  configSchemaNotesEl.textContent = (schema.notes || []).join(" ");
  configSchemaRowsEl.innerHTML = "";
  for (const field of schema.fields || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${field.field}</td>
      <td>${field.field_type}</td>
      <td>${field.default_value}</td>
      <td>${field.effect}<div class="muted">${field.description ?? ""}</div></td>
    `;
    configSchemaRowsEl.appendChild(tr);
  }
}

function parseConfigText(text) {
  return JSON.parse((text || "").trim() || "{}");
}

function normalizeOptionalText(value) {
  const trimmed = (value || "").trim();
  return trimmed ? trimmed : undefined;
}

function configFromSnapshot(config) {
  return parseConfigText(config?.server_config_file_json ?? "{}");
}

function populateBuilder(config) {
  const http = config?.http || {};
  builderStatsDbPathEl.value = config?.stats_db_path || "";
  builderRnsdBinEl.value = config?.rnsd_bin || "";
  builderSentineldBinEl.value = config?.sentineld_bin || "";
  builderStatsdBinEl.value = config?.statsd_bin || "";
  builderHttpEnabledEl.checked = http.enabled !== false;
  builderHttpHostEl.value = http.host || "";
  builderHttpPortEl.value = http.port != null ? String(http.port) : "";
  builderHttpDisableAuthEl.checked = http.disable_auth === true;
  builderHttpAuthTokenEl.value = http.auth_token || "";
  configBuilderDirty = false;
}

function buildConfigFromBuilder() {
  const config = {};
  const http = {
    enabled: builderHttpEnabledEl.checked,
    disable_auth: builderHttpDisableAuthEl.checked,
  };
  const statsDbPath = normalizeOptionalText(builderStatsDbPathEl.value);
  const rnsdBin = normalizeOptionalText(builderRnsdBinEl.value);
  const sentineldBin = normalizeOptionalText(builderSentineldBinEl.value);
  const statsdBin = normalizeOptionalText(builderStatsdBinEl.value);
  const httpHost = normalizeOptionalText(builderHttpHostEl.value);
  const httpAuthToken = normalizeOptionalText(builderHttpAuthTokenEl.value);
  const httpPortValue = builderHttpPortEl.value.trim();

  if (statsDbPath) config.stats_db_path = statsDbPath;
  if (rnsdBin) config.rnsd_bin = rnsdBin;
  if (sentineldBin) config.sentineld_bin = sentineldBin;
  if (statsdBin) config.statsd_bin = statsdBin;
  if (httpHost) http.host = httpHost;
  if (httpAuthToken) http.auth_token = httpAuthToken;
  if (httpPortValue) {
    const parsedPort = Number.parseInt(httpPortValue, 10);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      throw new Error("HTTP port must be an integer between 1 and 65535");
    }
    http.port = parsedPort;
  }

  config.http = http;
  return config;
}

function loadConfigEditor(text, statusMessage) {
  configCandidateEl.value = text || "";
  configEditorDirty = false;
  configValidationStatusEl.textContent = statusMessage;
}

function syncBuilderFromJson(options = {}) {
  const parsed = parseConfigText(configCandidateEl.value);
  populateBuilder(parsed);
  if (!options.silent) {
    configValidationStatusEl.textContent = "Builder updated from JSON";
  }
}

function syncJsonFromBuilder(options = {}) {
  configCandidateEl.value = JSON.stringify(buildConfigFromBuilder(), null, 2);
  configEditorDirty = false;
  if (!options.silent) {
    configValidationStatusEl.textContent = "Builder exported to JSON";
  }
}

function formatConfigEditor() {
  try {
    const parsed = parseConfigText(configCandidateEl.value);
    configCandidateEl.value = JSON.stringify(parsed, null, 2);
    configEditorDirty = false;
    configValidationStatusEl.textContent = "Candidate JSON formatted";
  } catch (error) {
    configValidationStatusEl.textContent = `Format failed: ${error.message}`;
  }
}

function renderWarnings(warnings) {
  configWarningListEl.innerHTML = "";
  for (const warning of warnings || []) {
    const li = document.createElement("li");
    li.textContent = warning;
    configWarningListEl.appendChild(li);
  }
}

function renderActionSummary(result, actionLabel) {
  if (!result) {
    configActionSummaryEl.textContent = "No config action run yet";
    return;
  }
  const childRestarts = result.apply_plan?.processes_to_restart?.length
    ? result.apply_plan.processes_to_restart.join(", ")
    : "none";
  const serverRestart = result.apply_plan?.control_plane_restart_required ? "yes" : "no";
  const warningCount = result.warnings?.length || 0;
  configActionSummaryEl.textContent = `${actionLabel}: child restarts ${childRestarts}; rns-server restart required ${serverRestart}; warnings ${warningCount}.`;
}

function renderProcessLogs(process, lines) {
  logProcessNameEl.textContent = process || "No process selected";
  if (!process) {
    logStatusEl.textContent = "Choose a process log stream";
    processLogOutputEl.textContent = "";
    return;
  }
  logStatusEl.textContent = `${lines.length} recent lines`;
  processLogOutputEl.textContent = lines
    .slice()
    .reverse()
    .map((entry) => `[${entry.stream}] ${entry.line}`)
    .join("\n");
}

function renderProcessLogPayload(payload) {
  const lines = payload.lines || [];
  renderProcessLogs(payload.process, lines);
  const details = [
    `${lines.length} recent lines`,
    payload.recent_log_lines != null ? `${payload.recent_log_lines} buffered` : "",
    payload.last_log_age_seconds != null ? `last log ${fmtAge(payload.last_log_age_seconds)}` : "",
    payload.durable_log_path ? `file ${payload.durable_log_path}` : "",
  ].filter(Boolean);
  logStatusEl.textContent = details.join(" | ");
}

async function refreshLogs() {
  if (!selectedLogProcess) {
    renderProcessLogs(null, []);
    return;
  }
  try {
    const payload = await fetchJson(`/api/processes/${selectedLogProcess}/logs?limit=200`);
    renderProcessLogPayload(payload);
  } catch (error) {
    logProcessNameEl.textContent = selectedLogProcess;
    logStatusEl.textContent = error.message;
    processLogOutputEl.textContent = "";
  }
}

async function refresh() {
  try {
    const [node, config, configSchema, configStatus, processes, processEvents] = await Promise.all([
      fetchJson("/api/node"),
      fetchJson("/api/config"),
      fetchJson("/api/config/schema"),
      fetchJson("/api/config/status"),
      fetchJson("/api/processes"),
      fetchJson("/api/process_events"),
    ]);
    serverModeEl.textContent = node.server_mode || "-";
    uptimeEl.textContent = fmtSeconds(node.uptime_seconds);
    runningEl.textContent = `${node.processes_running}/${node.process_count}`;
    readyEl.textContent = `${node.processes_ready}/${node.process_count}`;
    renderConfig(config.config);
    renderConfigSchema(configSchema.schema);
    renderConfigStatus(configStatus.status);
    renderProcesses(processes.processes || []);
    renderProcessEvents(processEvents.events || []);
    await refreshLogs();
    statusEl.textContent = "Connected";
  } catch (error) {
    statusEl.textContent = error.message;
  }
}

saveButton.addEventListener("click", () => {
  localStorage.setItem("rnsctl_token", tokenInput.value.trim());
  refresh();
});
configCandidateEl.addEventListener("input", () => {
  configEditorDirty = true;
});
for (const input of [
  builderStatsDbPathEl,
  builderRnsdBinEl,
  builderSentineldBinEl,
  builderStatsdBinEl,
  builderHttpEnabledEl,
  builderHttpHostEl,
  builderHttpPortEl,
  builderHttpDisableAuthEl,
  builderHttpAuthTokenEl,
]) {
  input.addEventListener("input", () => {
    configBuilderDirty = true;
  });
  input.addEventListener("change", () => {
    configBuilderDirty = true;
  });
}

loadCurrentConfigButton.addEventListener("click", () => {
  loadConfigEditor(currentConfigJson, "Loaded current saved config");
  syncBuilderFromJson({ silent: true });
});
loadExampleConfigButton.addEventListener("click", () => {
  loadConfigEditor(schemaExampleJson, "Loaded example config");
  syncBuilderFromJson({ silent: true });
});
syncBuilderFromJsonButton.addEventListener("click", () => {
  try {
    syncBuilderFromJson();
  } catch (error) {
    configValidationStatusEl.textContent = `Builder sync failed: ${error.message}`;
  }
});
syncJsonFromBuilderButton.addEventListener("click", () => {
  try {
    syncJsonFromBuilder();
  } catch (error) {
    configValidationStatusEl.textContent = `Builder export failed: ${error.message}`;
  }
});
formatConfigButton.addEventListener("click", () => {
  formatConfigEditor();
  try {
    syncBuilderFromJson({ silent: true });
  } catch (_error) {
  }
});
validateConfigButton.addEventListener("click", () => {
  validateConfigCandidate();
});
saveConfigButton.addEventListener("click", () => {
  saveConfigCandidate();
});
applyConfigButton.addEventListener("click", () => {
  applyConfigCandidate();
});

refresh();
setInterval(refresh, 2000);
