const tokenInput = document.getElementById("token");
const saveButton = document.getElementById("saveToken");
const statusEl = document.getElementById("status");
const serverModeEl = document.getElementById("serverMode");
const uptimeEl = document.getElementById("uptime");
const runningEl = document.getElementById("running");
const readyEl = document.getElementById("ready");
const telemetryWindowLabelEl = document.getElementById("telemetryWindowLabel");
const telemetryAnnounceTotalEl = document.getElementById("telemetryAnnounceTotal");
const telemetryAnnounceDetailEl = document.getElementById("telemetryAnnounceDetail");
const telemetryUniqueDestinationsEl = document.getElementById("telemetryUniqueDestinations");
const telemetryDestinationDetailEl = document.getElementById("telemetryDestinationDetail");
const telemetryPacketActivityEl = document.getElementById("telemetryPacketActivity");
const telemetryPacketDetailEl = document.getElementById("telemetryPacketDetail");
const telemetryDropTotalEl = document.getElementById("telemetryDropTotal");
const telemetryDropDetailEl = document.getElementById("telemetryDropDetail");
const announceTrendSummaryEl = document.getElementById("announceTrendSummary");
const announceBurstBadgeEl = document.getElementById("announceBurstBadge");
const announceTrendBarsEl = document.getElementById("announceTrendBars");
const systemTrendSummaryEl = document.getElementById("systemTrendSummary");
const systemAnomalyBadgeEl = document.getElementById("systemAnomalyBadge");
const systemTrendBarsEl = document.getElementById("systemTrendBars");
const telemetryInterfacesRowsEl = document.getElementById("telemetryInterfacesRows");
const telemetryDestinationsRowsEl = document.getElementById("telemetryDestinationsRows");
const telemetryPacketsRowsEl = document.getElementById("telemetryPacketsRows");
const telemetryAlertListEl = document.getElementById("telemetryAlertList");
const telemetryRestartListEl = document.getElementById("telemetryRestartList");
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
const builderDirtyStateEl = document.getElementById("builderDirtyState");
const configActionSummaryEl = document.getElementById("configActionSummary");
const configWarningListEl = document.getElementById("configWarningList");
const configPlanSummaryEl = document.getElementById("configPlanSummary");
const configPlanActionEl = document.getElementById("configPlanAction");
const configPlanImpactEl = document.getElementById("configPlanImpact");
const configPlanTargetsEl = document.getElementById("configPlanTargets");
const configPlanChangeCountEl = document.getElementById("configPlanChangeCount");
const configChangeRowsEl = document.getElementById("configChangeRows");
const configSchemaNotesEl = document.getElementById("configSchemaNotes");
const configSchemaRowsEl = document.getElementById("configSchemaRows");
const configValidationResultEl = document.getElementById("configValidationResult");
const processRowsEl = document.getElementById("processRows");
const processEventRowsEl = document.getElementById("processEventRows");
const selectedProcessNameEl = document.getElementById("selectedProcessName");
const selectedProcessSummaryEl = document.getElementById("selectedProcessSummary");
const selectedProcessStatusBadgeEl = document.getElementById("selectedProcessStatusBadge");
const selectedProcessReadyEl = document.getElementById("selectedProcessReady");
const selectedProcessReadyDetailEl = document.getElementById("selectedProcessReadyDetail");
const selectedProcessRestartsEl = document.getElementById("selectedProcessRestarts");
const selectedProcessTransitionEl = document.getElementById("selectedProcessTransition");
const selectedProcessLastExitEl = document.getElementById("selectedProcessLastExit");
const selectedProcessLastErrorEl = document.getElementById("selectedProcessLastError");
const selectedProcessLogCountEl = document.getElementById("selectedProcessLogCount");
const selectedProcessLogMetaEl = document.getElementById("selectedProcessLogMeta");
const selectedProcessEventRowsEl = document.getElementById("selectedProcessEventRows");
const logProcessNameEl = document.getElementById("logProcessName");
const logStatusEl = document.getElementById("logStatus");
const processLogOutputEl = document.getElementById("processLogOutput");
const toggleAdvancedConfigButton = document.getElementById("toggleAdvancedConfig");
const advancedConfigSectionEl = document.getElementById("advancedConfigSection");
let configEditorDirty = false;
let configBuilderDirty = false;
let advancedConfigVisible = false;
let selectedProcess = null;
let selectedLogProcess = null;
let currentConfigJson = "";
let schemaExampleJson = "";
let latestProcesses = [];
let latestProcessEvents = [];
let latestTelemetry = {
  summary: null,
  announces: null,
  interfaces: null,
  destinations: null,
  packets: null,
  packetSeries: null,
  links: null,
  system: null,
};

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

function fmtInteger(value) {
  if (value == null || Number.isNaN(value)) return "-";
  return new Intl.NumberFormat("en-US").format(value);
}

function fmtBytes(value) {
  if (value == null || Number.isNaN(value)) return "-";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let current = value;
  let unit = units[0];
  for (let i = 1; i < units.length && current >= 1024; i += 1) {
    current /= 1024;
    unit = units[i];
  }
  const digits = current >= 100 || unit === "B" ? 0 : 1;
  return `${current.toFixed(digits)} ${unit}`;
}

function fmtWindow(seconds) {
  if (seconds == null) return "-";
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

function fmtTimestamp(value) {
  if (value == null) return "-";
  return new Date(value).toLocaleString();
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

function renderSimpleRows(container, rows, emptyMessage) {
  container.innerHTML = "";
  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "rank-row";
    empty.innerHTML = `<strong>No data</strong><div class="rank-meta">${emptyMessage}</div>`;
    container.appendChild(empty);
    return;
  }
  for (const row of rows) {
    const item = document.createElement("div");
    item.className = row.className || "rank-row";
    item.innerHTML = `<strong>${row.title}</strong><div class="${row.metaClass || "rank-meta"}">${row.meta}</div>`;
    container.appendChild(item);
  }
}

function renderSparkBars(container, items, options = {}) {
  container.innerHTML = "";
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "rank-row";
    empty.innerHTML = `<strong>No samples</strong><div class="rank-meta">${options.emptyMessage || "No historical samples available for this window."}</div>`;
    container.appendChild(empty);
    return;
  }

  const maxValue = items.reduce((max, item) => Math.max(max, item.value || 0), 0);
  const scaleMax = maxValue > 0 ? maxValue : 1;
  for (const item of items) {
    const bar = document.createElement("div");
    const height = Math.max(8, Math.round(((item.value || 0) / scaleMax) * 120));
    bar.className = `spark-bar${item.warn ? " warn-bar" : ""}`;
    bar.style.height = `${height}px`;
    bar.setAttribute("data-label", item.label);
    bar.title = item.title;
    container.appendChild(bar);
  }
}

function renderTelemetry(summary, announces, interfaces, destinations, packets, packetSeries, links, system) {
  latestTelemetry = { summary, announces, interfaces, destinations, packets, packetSeries, links, system };
  const windowSeconds = summary?.window?.seconds || announces?.window?.seconds || packetSeries?.window?.seconds || links?.window?.seconds || system?.window?.seconds || null;
  telemetryWindowLabelEl.textContent = fmtWindow(windowSeconds);

  const announceTotal = summary?.announces?.total ?? null;
  const uniqueDestinations = summary?.announces?.unique_destinations ?? null;
  const packetCounters = summary?.packets?.active_counters_in_window ?? null;
  const providerDrops = summary?.system?.provider_dropped_events ?? null;
  const firstSeen = summary?.announces?.first_seen_ms;
  const lastSeen = summary?.announces?.last_seen_ms;
  const packetTotals = (packetSeries?.series || []).reduce((totals, bucket) => ({
    packets: totals.packets + (bucket.total_packets || 0),
    bytes: totals.bytes + (bucket.total_bytes || 0),
  }), { packets: 0, bytes: 0 });

  telemetryAnnounceTotalEl.textContent = fmtInteger(announceTotal);
  telemetryAnnounceDetailEl.textContent = announceTotal
    ? `First seen ${fmtTimestamp(firstSeen)}. Last seen ${fmtTimestamp(lastSeen)}.`
    : "No announces recorded in the current window.";
  telemetryUniqueDestinationsEl.textContent = fmtInteger(uniqueDestinations);
  telemetryDestinationDetailEl.textContent = uniqueDestinations
    ? `${fmtInteger(summary?.announces?.unique_identities ?? 0)} unique identities and ${fmtInteger(summary?.announces?.unique_interfaces ?? 0)} interfaces participated.`
    : "No active destination set in the current window.";
  telemetryPacketActivityEl.textContent = fmtInteger(packetCounters);
  telemetryPacketDetailEl.textContent = `Window ${fmtInteger(packetTotals.packets)} packets / ${fmtBytes(packetTotals.bytes)} | lifetime RX ${fmtInteger(summary?.packets?.rx_packets ?? 0)} / TX ${fmtInteger(summary?.packets?.tx_packets ?? 0)}`;
  telemetryDropTotalEl.textContent = fmtInteger(providerDrops);
  telemetryDropDetailEl.textContent = providerDrops
    ? `Provider drops were observed in ${fmtInteger(system?.anomalies?.provider_drop_buckets?.length ?? 0)} buckets.`
    : "No provider drop samples were recorded in the current window.";

  renderAnnounceTelemetry(announces);
  renderSystemTelemetry(system);
  renderTelemetryRankings(interfaces, destinations, packets);
  renderTelemetryAlerts(announces, system, packetSeries, links);
}

function renderAnnounceTelemetry(announces) {
  const series = announces?.series || [];
  const burstBuckets = announces?.anomalies?.burst_buckets || [];
  const peak = series.reduce((max, bucket) => Math.max(max, bucket.announce_count || 0), 0);
  const average = announces?.anomalies?.average_announce_count_per_bucket || 0;
  announceTrendSummaryEl.textContent = series.length
    ? `Peak bucket ${fmtInteger(peak)} announces. Average ${average.toFixed(1)} per bucket.`
    : "No announce buckets recorded in the current window.";
  setBadge(
    announceBurstBadgeEl,
    burstBuckets.length ? `${burstBuckets.length} burst${burstBuckets.length === 1 ? "" : "s"}` : "steady",
    burstBuckets.length ? "warn" : "ok",
  );
  renderSparkBars(
    announceTrendBarsEl,
    series.slice(-12).map((bucket) => ({
      value: bucket.announce_count || 0,
      warn: burstBuckets.some((burst) => burst.bucket_start_ms === bucket.bucket_start_ms),
      label: new Date(bucket.bucket_start_ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      title: `${fmtInteger(bucket.announce_count || 0)} announces, ${fmtInteger(bucket.unique_destinations || 0)} destinations`,
    })),
    { emptyMessage: "No announce trend data yet." },
  );
}

function renderSystemTelemetry(system) {
  const series = system?.series || [];
  const dropBuckets = system?.anomalies?.provider_drop_buckets || [];
  const peakRss = series.reduce((max, bucket) => Math.max(max, bucket.max_rss_bytes || 0), 0);
  const latestSample = system?.latest_process_sample;
  systemTrendSummaryEl.textContent = latestSample
    ? `Latest RSS ${fmtBytes(latestSample.rss_bytes)} | threads ${fmtInteger(latestSample.threads)} | fds ${fmtInteger(latestSample.fds)} | peak RSS ${fmtBytes(peakRss)}`
    : "No process samples recorded yet.";
  setBadge(
    systemAnomalyBadgeEl,
    dropBuckets.length ? `${dropBuckets.length} drop bucket${dropBuckets.length === 1 ? "" : "s"}` : "stable",
    dropBuckets.length ? "bad" : "ok",
  );
  renderSparkBars(
    systemTrendBarsEl,
    series.slice(-12).map((bucket) => ({
      value: Math.max(bucket.max_rss_bytes || 0, (bucket.provider_dropped_events || 0) * 1024 * 1024),
      warn: (bucket.provider_dropped_events || 0) > 0,
      label: new Date(bucket.bucket_start_ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      title: `max RSS ${fmtBytes(bucket.max_rss_bytes || 0)}, drops ${fmtInteger(bucket.provider_dropped_events || 0)}`,
    })),
    { emptyMessage: "No system pressure data yet." },
  );
}

function renderTelemetryRankings(interfaces, destinations, packets) {
  renderSimpleRows(
    telemetryInterfacesRowsEl,
    (interfaces?.interfaces || []).slice(0, 5).map((entry) => ({
      title: `Interface ${entry.interface_id ?? "unknown"} · ${fmtInteger(entry.announce_count)} announces`,
      meta: `${fmtInteger(entry.unique_destinations)} destinations | hops ${entry.min_hops}-${entry.max_hops} | last seen ${fmtTimestamp(entry.last_seen_ms)}`,
    })),
    "No interface telemetry yet.",
  );
  renderSimpleRows(
    telemetryDestinationsRowsEl,
    (destinations?.destinations || []).slice(0, 5).map((entry) => ({
      title: `${entry.destination_hash.slice(0, 12)}… · ${fmtInteger(entry.announce_count)} announces`,
      meta: `lifetime ${fmtInteger(entry.lifetime_announce_count ?? 0)} | interface ${entry.last_interface_id ?? "unknown"} | hops ${entry.min_hops}-${entry.max_hops}`,
    })),
    "No destination telemetry yet.",
  );
  renderSimpleRows(
    telemetryPacketsRowsEl,
    (packets?.counters || []).slice(0, 5).map((entry) => ({
      title: `${entry.direction} ${entry.packet_type} · ${fmtInteger(entry.packets)} packets`,
      meta: `${entry.interface_key} | ${fmtBytes(entry.bytes)} | updated ${fmtTimestamp(entry.updated_at_ms)}`,
    })),
    "No recently active packet counters yet.",
  );
}

function renderTelemetryAlerts(announces, system, packetSeries, links) {
  const burstBuckets = announces?.anomalies?.burst_buckets || [];
  const dropBuckets = system?.anomalies?.provider_drop_buckets || [];
  const busyPacketBuckets = packetSeries?.anomalies?.busy_buckets || [];
  const linkCloseBuckets = links?.anomalies?.close_buckets || [];
  const announceAlerts = [];
  if (burstBuckets.length) {
    const hottest = burstBuckets.reduce((top, bucket) =>
      (bucket.announce_count || 0) > (top.announce_count || 0) ? bucket : top, burstBuckets[0]);
    announceAlerts.push({
      className: "alert-row warn",
      title: `Announce burst at ${fmtTimestamp(hottest.bucket_start_ms)}`,
      metaClass: "alert-meta",
      meta: `${fmtInteger(hottest.announce_count || 0)} announces in one bucket. ${fmtInteger(burstBuckets.length)} burst bucket(s) crossed the 2x average threshold.`,
    });
  }
  if (dropBuckets.length) {
    const worst = dropBuckets.reduce((top, bucket) =>
      (bucket.provider_dropped_events || 0) > (top.provider_dropped_events || 0) ? bucket : top, dropBuckets[0]);
    announceAlerts.push({
      className: "alert-row bad",
      title: `Provider drop spike at ${fmtTimestamp(worst.bucket_start_ms)}`,
      metaClass: "alert-meta",
      meta: `${fmtInteger(worst.provider_dropped_events || 0)} dropped events in one bucket. ${fmtInteger(dropBuckets.length)} bucket(s) showed provider backpressure.`,
    });
  }
  if (busyPacketBuckets.length) {
    const busiest = busyPacketBuckets.reduce((top, bucket) =>
      (bucket.total_packets || 0) > (top.total_packets || 0) ? bucket : top, busyPacketBuckets[0]);
    announceAlerts.push({
      className: "alert-row warn",
      title: `Packet spike at ${fmtTimestamp(busiest.bucket_start_ms)}`,
      metaClass: "alert-meta",
      meta: `${fmtInteger(busiest.total_packets || 0)} packets / ${fmtBytes(busiest.total_bytes || 0)} in one bucket. ${fmtInteger(busyPacketBuckets.length)} packet bucket(s) crossed the 2x average threshold.`,
    });
  }
  if (linkCloseBuckets.length) {
    const noisiest = linkCloseBuckets.reduce((top, bucket) =>
      (bucket.closed || 0) > (top.closed || 0) ? bucket : top, linkCloseBuckets[0]);
    announceAlerts.push({
      className: "alert-row warn",
      title: `Link churn at ${fmtTimestamp(noisiest.bucket_start_ms)}`,
      metaClass: "alert-meta",
      meta: `${fmtInteger(noisiest.closed || 0)} closed link event(s) in one bucket. ${fmtInteger(linkCloseBuckets.length)} bucket(s) recorded link teardown activity.`,
    });
  }
  if (!announceAlerts.length) {
    announceAlerts.push({
      className: "alert-row",
      title: "No telemetry anomalies",
      metaClass: "alert-meta",
      meta: "The current historical window did not flag announce bursts, packet spikes, provider drop spikes, or link churn.",
    });
  }
  renderSimpleRows(telemetryAlertListEl, announceAlerts, "No telemetry anomalies.");

  const restartSignals = [];
  const unstableProcesses = latestProcesses
    .filter((process) => (process.restart_count || 0) > 0 || process.last_error)
    .sort((a, b) => (b.restart_count || 0) - (a.restart_count || 0));
  for (const process of unstableProcesses.slice(0, 4)) {
    restartSignals.push({
      className: process.last_error ? "alert-row bad" : "alert-row warn",
      title: `${process.name} · ${fmtInteger(process.restart_count || 0)} restart(s)`,
      metaClass: "alert-meta",
      meta: `${process.last_error || process.status_detail || "No additional detail"} | last transition ${fmtAge(process.last_transition_seconds)}`,
    });
  }
  const restartEvents = latestProcessEvents
    .filter((event) => /restart|exit|fail|crash|stop/i.test(event.event))
    .slice(0, 4);
  for (const event of restartEvents) {
    restartSignals.push({
      className: "alert-row warn",
      title: `${event.process} · ${event.event}`,
      metaClass: "alert-meta",
      meta: `${fmtAge(event.age_seconds)} | ${event.detail || "No detail"}`,
    });
  }
  for (const entry of (links?.interfaces || []).slice(0, 3)) {
    if ((entry.closed_count || 0) === 0 && (entry.established_count || 0) === 0) continue;
    restartSignals.push({
      className: (entry.closed_count || 0) > 0 ? "alert-row warn" : "alert-row",
      title: `Interface ${entry.interface_id ?? "unknown"} link activity`,
      metaClass: "alert-meta",
      meta: `${fmtInteger(entry.established_count || 0)} established | ${fmtInteger(entry.closed_count || 0)} closed | ${fmtInteger(entry.unique_links || 0)} unique links | last seen ${fmtTimestamp(entry.last_seen_ms)}`,
    });
  }
  if (!restartSignals.length) {
    restartSignals.push({
      className: "alert-row",
      title: "No restart churn",
      metaClass: "alert-meta",
      meta: "Supervised processes show no recent restart or failure signals.",
    });
  }
  renderSimpleRows(telemetryRestartListEl, restartSignals, "No restart diagnostics.");
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
  latestProcesses = processes;
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
        <button class="secondary" data-select="${process.name}">Inspect</button>
        <button class="secondary" data-start="${process.name}">Start</button>
        <button class="secondary" data-stop="${process.name}">Stop</button>
        <button class="secondary" data-restart="${process.name}">Restart</button>
      </td>
      <td><button class="secondary" data-logs="${process.name}">View Logs</button></td>
    `;
    if (process.name === selectedProcess) {
      tr.classList.add("process-row-selected");
    }
    processRowsEl.appendChild(tr);
  }

  if (!selectedProcess && processes.length > 0) {
    selectedProcess = processes[0].name;
  }
  if (!selectedLogProcess && processes.length > 0) {
    selectedLogProcess = selectedProcess || processes[0].name;
  }
  if (selectedProcess && !processes.some((process) => process.name === selectedProcess)) {
    selectedProcess = processes[0]?.name || null;
  }
  if (selectedLogProcess && !processes.some((process) => process.name === selectedLogProcess)) {
    selectedLogProcess = selectedProcess;
  }

  for (const button of processRowsEl.querySelectorAll("[data-select]")) {
    button.addEventListener("click", () => {
      selectedProcess = button.getAttribute("data-select");
      renderProcesses(latestProcesses);
      renderSelectedProcessDetail();
    });
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
      selectedProcess = selectedLogProcess;
      renderProcesses(latestProcesses);
      renderSelectedProcessDetail();
      await refreshLogs();
    });
  }
}

function renderProcessEvents(events) {
  latestProcessEvents = events;
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
  renderSelectedProcessDetail();
}

function selectedProcessRecord() {
  return latestProcesses.find((process) => process.name === selectedProcess) || null;
}

function renderSelectedProcessDetail() {
  const process = selectedProcessRecord();
  selectedProcessEventRowsEl.innerHTML = "";
  if (!process) {
    selectedProcessNameEl.textContent = "No process selected";
    selectedProcessSummaryEl.textContent = "Select a process to inspect its runtime detail, recent events, and logs.";
    setBadge(selectedProcessStatusBadgeEl, "idle", "info");
    selectedProcessReadyEl.textContent = "-";
    selectedProcessReadyDetailEl.textContent = "No process selected.";
    selectedProcessRestartsEl.textContent = "0";
    selectedProcessTransitionEl.textContent = "No transition data yet.";
    selectedProcessLastExitEl.textContent = "-";
    selectedProcessLastErrorEl.textContent = "No recorded process error.";
    selectedProcessLogCountEl.textContent = "0";
    selectedProcessLogMetaEl.textContent = "No log metadata yet.";
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="3" class="muted">No process selected.</td>`;
    selectedProcessEventRowsEl.appendChild(tr);
    return;
  }

  selectedProcessNameEl.textContent = process.name;
  selectedProcessSummaryEl.textContent = [
    `PID ${process.pid ?? "-"}`,
    `uptime ${fmtSeconds(process.uptime_seconds)}`,
    process.status_detail || process.last_error || "No extra runtime detail",
  ].join(" | ");
  setBadge(
    selectedProcessStatusBadgeEl,
    process.status || "unknown",
    process.status === "running" ? "running" : (process.status || "stopped"),
  );
  selectedProcessReadyEl.textContent = process.ready ? "ready" : (process.ready_state || "not-ready");
  selectedProcessReadyDetailEl.textContent = process.status_detail || process.last_error || "No readiness detail recorded.";
  selectedProcessRestartsEl.textContent = String(process.restart_count ?? 0);
  selectedProcessTransitionEl.textContent = `Last transition ${fmtAge(process.last_transition_seconds)}.`;
  selectedProcessLastExitEl.textContent = process.last_exit_code != null ? String(process.last_exit_code) : "-";
  selectedProcessLastErrorEl.textContent = process.last_error || "No recorded process error.";
  selectedProcessLogCountEl.textContent = String(process.recent_log_lines ?? 0);
  selectedProcessLogMetaEl.textContent = [
    process.last_log_age_seconds != null ? `Last log ${fmtAge(process.last_log_age_seconds)}` : "",
    process.durable_log_path ? `File ${process.durable_log_path}` : "",
  ].filter(Boolean).join(" | ") || "No log metadata yet.";

  const events = latestProcessEvents.filter((event) => event.process === process.name).slice(0, 6);
  if (!events.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="3" class="muted">No recent lifecycle events for ${process.name}.</td>`;
    selectedProcessEventRowsEl.appendChild(tr);
    return;
  }

  for (const event of events) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${event.event}</td>
      <td>${fmtAge(event.age_seconds)}</td>
      <td>${event.detail ?? ""}</td>
    `;
    selectedProcessEventRowsEl.appendChild(tr);
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
  updateBuilderDirtyState();
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
  const pendingAction = status.pending_action
    ? ` Pending action: ${status.pending_action}.`
    : "";
  const pendingTargets = status.pending_targets?.length
    ? ` Targets: ${status.pending_targets.join(", ")}.`
    : "";
  configStatusSummaryEl.textContent = `${status.summary}${action}${pendingAction}${pendingTargets}${pending}`;

  if (status.runtime_differs_from_saved) {
    setBadge(configRuntimeBadgeEl, "drifted", "warn");
    configRuntimeDetailEl.textContent = status.blocking_reason || "Saved config is not fully active in the current runtime state.";
  } else {
    setBadge(configRuntimeBadgeEl, "aligned", "ok");
    configRuntimeDetailEl.textContent = "Runtime state matches the saved config.";
  }

  if (status.pending_process_restarts?.length) {
    setBadge(configRestartBadgeEl, "pending", "warn");
    configRestartDetailEl.textContent = status.blocking_reason || `Waiting on: ${status.pending_process_restarts.join(", ")}.`;
  } else {
    setBadge(configRestartBadgeEl, "clear", "ok");
    configRestartDetailEl.textContent = "No supervised child process restart is pending.";
  }

  if (status.control_plane_restart_required) {
    setBadge(configControlPlaneBadgeEl, "restart required", "warn");
    configControlPlaneDetailEl.textContent = "Restart rns-server to apply embedded HTTP control-plane changes.";
  } else if (status.control_plane_reload_required) {
    setBadge(configControlPlaneBadgeEl, "reload pending", "warn");
    configControlPlaneDetailEl.textContent = "Embedded HTTP auth settings were saved but are not active in runtime yet.";
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
    setBadge(configPlanActionEl, "unknown", "info");
    configPlanImpactEl.textContent = "Validate a config change to preview its operational impact.";
    configPlanTargetsEl.textContent = "No targets yet.";
    configPlanChangeCountEl.textContent = "0";
    configChangeRowsEl.innerHTML = "";
    return;
  }

  const restartList = plan.processes_to_restart?.length
    ? plan.processes_to_restart.join(", ")
    : "none";
  const controlPlane = plan.control_plane_restart_required ? "yes" : "no";
  const action = plan.overall_action || "unknown";
  const targets = [
    ...(plan.processes_to_restart || []),
    ...(plan.control_plane_reload_required ? ["embedded-http-auth"] : []),
    ...(plan.control_plane_restart_required ? ["rns-server"] : []),
  ];
  const impact = describePlanImpact(plan);
  const notes = plan.notes?.length ? ` ${plan.notes.join(" ")}` : "";
  configPlanSummaryEl.textContent = `Action: ${action}. Processes to restart: ${restartList}. rns-server restart required: ${controlPlane}.${notes}`;
  setBadge(configPlanActionEl, action.replaceAll("_", " "), planBadgeClass(plan));
  configPlanImpactEl.textContent = impact;
  configPlanTargetsEl.innerHTML = targets.length
    ? `<div class="target-list">${targets.map((target) => `<span class="pill info">${target}</span>`).join("")}</div>`
    : "No runtime targets affected.";
  configPlanChangeCountEl.textContent = String((plan.changes || []).length);

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

function describePlanImpact(plan) {
  switch (plan.overall_action) {
    case "none":
      return "No runtime impact. The candidate matches the current effective configuration.";
    case "restart_children":
      return "Applying this config will restart one or more supervised child processes.";
    case "reload_control_plane":
      return "Applying this config will reload embedded HTTP auth settings without restarting rns-server.";
    case "restart_children_and_reload_control_plane":
      return "Applying this config will restart child processes and reload embedded HTTP auth settings.";
    case "restart_server":
      return "Applying this config will still require a full rns-server restart before all control-plane changes take effect.";
    case "restart_children_and_server":
      return "Applying this config will restart child processes and still require a full rns-server restart.";
    default:
      return "Validate the config to inspect its operational impact.";
  }
}

function planBadgeClass(plan) {
  switch (plan.overall_action) {
    case "none":
      return "ok";
    case "reload_control_plane":
      return "info";
    case "restart_children":
    case "restart_children_and_reload_control_plane":
      return "warn";
    case "restart_server":
    case "restart_children_and_server":
      return "warn";
    default:
      return "info";
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
  updateBuilderDirtyState();
}

function syncBuilderFromJson(options = {}) {
  const parsed = parseConfigText(configCandidateEl.value);
  populateBuilder(parsed);
  if (!options.silent) {
    configValidationStatusEl.textContent = "Builder updated from JSON";
  }
  updateBuilderDirtyState();
}

function syncJsonFromBuilder(options = {}) {
  configCandidateEl.value = JSON.stringify(buildConfigFromBuilder(), null, 2);
  configEditorDirty = false;
  configBuilderDirty = false;
  if (!options.silent) {
    configValidationStatusEl.textContent = "Generated JSON updated from builder";
  }
  updateBuilderDirtyState();
}

function formatConfigEditor() {
  try {
    const parsed = parseConfigText(configCandidateEl.value);
    configCandidateEl.value = JSON.stringify(parsed, null, 2);
    configEditorDirty = false;
    configValidationStatusEl.textContent = "Candidate JSON formatted";
    updateBuilderDirtyState();
  } catch (error) {
    configValidationStatusEl.textContent = `Format failed: ${error.message}`;
  }
}

function updateBuilderDirtyState() {
  if (!builderDirtyStateEl) return;
  builderDirtyStateEl.textContent = configBuilderDirty
    ? "Builder changes are waiting to be generated into JSON"
    : "Builder is in sync";
}

function setAdvancedConfigVisible(visible) {
  advancedConfigVisible = visible;
  advancedConfigSectionEl.classList.toggle("hidden", !visible);
  toggleAdvancedConfigButton.textContent = visible ? "Hide Advanced JSON" : "Show Advanced JSON";
}

function syncJsonFromBuilderOnInput() {
  try {
    syncJsonFromBuilder({ silent: true });
  } catch (error) {
    configValidationStatusEl.textContent = `Builder export failed: ${error.message}`;
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
  const action = result.apply_plan?.overall_action || "unknown";
  const warningCount = result.warnings?.length || 0;
  configActionSummaryEl.textContent = `${actionLabel}: action ${action}; child restarts ${childRestarts}; rns-server restart required ${serverRestart}; warnings ${warningCount}.`;
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
    const [node, config, configSchema, configStatus, processes, processEvents, statsSummary, statsAnnounces, statsInterfaces, statsDestinations, statsPackets, statsPacketSeries, statsLinks, statsSystem] = await Promise.all([
      fetchJson("/api/node"),
      fetchJson("/api/config"),
      fetchJson("/api/config/schema"),
      fetchJson("/api/config/status"),
      fetchJson("/api/processes"),
      fetchJson("/api/process_events"),
      fetchJson("/api/stats/summary?window=24h"),
      fetchJson("/api/stats/announces?window=24h&bucket=1h"),
      fetchJson("/api/stats/interfaces?window=24h&limit=5"),
      fetchJson("/api/stats/destinations?window=24h&limit=5"),
      fetchJson("/api/stats/packets?window=24h&limit=5"),
      fetchJson("/api/stats/packets/series?window=24h&bucket=1h"),
      fetchJson("/api/stats/links?window=24h&bucket=1h&limit=5"),
      fetchJson("/api/stats/system?window=24h&bucket=1h"),
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
    renderTelemetry(statsSummary, statsAnnounces, statsInterfaces, statsDestinations, statsPackets, statsPacketSeries, statsLinks, statsSystem);
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
  updateBuilderDirtyState();
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
    updateBuilderDirtyState();
    syncJsonFromBuilderOnInput();
  });
  input.addEventListener("change", () => {
    configBuilderDirty = true;
    updateBuilderDirtyState();
    syncJsonFromBuilderOnInput();
  });
}
toggleAdvancedConfigButton.addEventListener("click", () => {
  setAdvancedConfigVisible(!advancedConfigVisible);
});

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

setAdvancedConfigVisible(false);
updateBuilderDirtyState();
refresh();
setInterval(refresh, 2000);
