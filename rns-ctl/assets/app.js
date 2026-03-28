const tokenInput = document.getElementById("token");
const saveButton = document.getElementById("saveToken");
const statusEl = document.getElementById("status");
const serverModeEl = document.getElementById("serverMode");
const uptimeEl = document.getElementById("uptime");
const runningEl = document.getElementById("running");
const readyEl = document.getElementById("ready");
const configConvergedEl = document.getElementById("configConverged");
const configStatusSummaryEl = document.getElementById("configStatusSummary");
const configPathEl = document.getElementById("configPath");
const configDirEl = document.getElementById("configDir");
const serverConfigFileEl = document.getElementById("serverConfigFile");
const statsDbEl = document.getElementById("statsDb");
const httpBindEl = document.getElementById("httpBind");
const httpAuthEl = document.getElementById("httpAuth");
const launchPlanRowsEl = document.getElementById("launchPlanRows");
const configCandidateEl = document.getElementById("configCandidate");
const validateConfigButton = document.getElementById("validateConfig");
const saveConfigButton = document.getElementById("saveConfig");
const applyConfigButton = document.getElementById("applyConfig");
const configValidationStatusEl = document.getElementById("configValidationStatus");
const configPlanSummaryEl = document.getElementById("configPlanSummary");
const configChangeRowsEl = document.getElementById("configChangeRows");
const configValidationResultEl = document.getElementById("configValidationResult");
const processRowsEl = document.getElementById("processRows");
const processEventRowsEl = document.getElementById("processEventRows");
const logProcessNameEl = document.getElementById("logProcessName");
const logStatusEl = document.getElementById("logStatus");
const processLogOutputEl = document.getElementById("processLogOutput");
let configEditorDirty = false;
let selectedLogProcess = null;

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
    tr.innerHTML = `
      <td>${process.name}</td>
      <td><span class="pill ${statusClass}">${process.status}</span></td>
      <td>${process.ready ? "yes" : (process.ready_state ?? "no")}</td>
      <td>${process.pid ?? "-"}</td>
      <td>${fmtSeconds(process.uptime_seconds)}</td>
      <td>${fmtSeconds(process.last_transition_seconds)}</td>
      <td>${process.last_exit_code ?? "-"}</td>
      <td>${process.status_detail ?? process.last_error ?? ""}</td>
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
}

function renderConfigStatus(status) {
  if (!status) {
    configConvergedEl.textContent = "-";
    configStatusSummaryEl.textContent = "No config status yet.";
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
  configValidationStatusEl.textContent = pendingMessage;
  configValidationResultEl.textContent = "";
  try {
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
    if (path !== "/api/config/validate") {
      configEditorDirty = false;
    }
    await refresh();
  } catch (error) {
    configValidationStatusEl.textContent = `${actionLabel} failed`;
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
  configPlanSummaryEl.textContent = `Processes to restart: ${restartList}. rns-server restart required: ${controlPlane}.`;

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

async function refreshLogs() {
  if (!selectedLogProcess) {
    renderProcessLogs(null, []);
    return;
  }
  try {
    const payload = await fetchJson(`/api/processes/${selectedLogProcess}/logs?limit=200`);
    renderProcessLogs(payload.process, payload.lines || []);
  } catch (error) {
    logProcessNameEl.textContent = selectedLogProcess;
    logStatusEl.textContent = error.message;
    processLogOutputEl.textContent = "";
  }
}

async function refresh() {
  try {
    const [node, config, configStatus, processes, processEvents] = await Promise.all([
      fetchJson("/api/node"),
      fetchJson("/api/config"),
      fetchJson("/api/config/status"),
      fetchJson("/api/processes"),
      fetchJson("/api/process_events"),
    ]);
    serverModeEl.textContent = node.server_mode || "-";
    uptimeEl.textContent = fmtSeconds(node.uptime_seconds);
    runningEl.textContent = `${node.processes_running}/${node.process_count}`;
    readyEl.textContent = `${node.processes_ready}/${node.process_count}`;
    renderConfig(config.config);
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
