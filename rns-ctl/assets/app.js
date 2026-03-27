const tokenInput = document.getElementById("token");
const saveButton = document.getElementById("saveToken");
const statusEl = document.getElementById("status");
const serverModeEl = document.getElementById("serverMode");
const uptimeEl = document.getElementById("uptime");
const runningEl = document.getElementById("running");
const readyEl = document.getElementById("ready");
const processRowsEl = document.getElementById("processRows");
const processEventRowsEl = document.getElementById("processEventRows");

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
    `;
    processRowsEl.appendChild(tr);
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

async function refresh() {
  try {
    const [node, processes, processEvents] = await Promise.all([
      fetchJson("/api/node"),
      fetchJson("/api/processes"),
      fetchJson("/api/process_events"),
    ]);
    serverModeEl.textContent = node.server_mode || "-";
    uptimeEl.textContent = fmtSeconds(node.uptime_seconds);
    runningEl.textContent = `${node.processes_running}/${node.process_count}`;
    readyEl.textContent = `${node.processes_ready}/${node.process_count}`;
    renderProcesses(processes.processes || []);
    renderProcessEvents(processEvents.events || []);
    statusEl.textContent = "Connected";
  } catch (error) {
    statusEl.textContent = error.message;
  }
}

saveButton.addEventListener("click", () => {
  localStorage.setItem("rnsctl_token", tokenInput.value.trim());
  refresh();
});

refresh();
setInterval(refresh, 2000);
