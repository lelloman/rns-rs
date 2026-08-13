"use strict";

const state = {
  meta: null,
  rows: [],
  traffic: [],
  colors: ["#c9f45b", "#55d7d0", "#ff9d57", "#b899ff", "#ff6b64", "#72a7ff"]
};
const metrics = {
  announce_24h: { label: "Announces / 24h", format: compact },
  load1: { label: "Load average / 1m", format: value => value.toFixed(2) },
  memory_percent: {
    label: "Memory used", suffix: "%", format: value => `${value.toFixed(1)}%`,
    value: row => row.mem_total_mb > 0 ? row.mem_used_mb / row.mem_total_mb * 100 : null
  },
  established_sessions_4242: { label: "Established sessions", format: compact },
  backbone_up_count: { label: "Backbone interfaces up", format: compact },
  public_interfaces_up: { label: "Public interfaces up", format: compact },
  packet_freshness_max_age_seconds: { label: "Packet freshness age", format: duration },
  idle_timeout_events_24h: { label: "Idle timeouts / 24h", format: compact },
  provider_bridge_dropped_24h: { label: "Provider drops / 24h", format: compact },
  blacklist_active_entries: { label: "Active blacklist entries", format: compact }
};

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[char]);
}

function compact(value) {
  return new Intl.NumberFormat("en", { notation: Math.abs(value) >= 10000 ? "compact" : "standard", maximumFractionDigits: 1 }).format(value);
}

function duration(seconds) {
  if (seconds === -1) return "missing";
  if (seconds < 0) return `${seconds}s`;
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

function byteSize(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = 0;
  while (Math.abs(amount) >= 1000 && unit < units.length - 1) { amount /= 1000; unit++; }
  return `${amount.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function isoShift(dateString, days) {
  const date = new Date(`${dateString}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function spanDays(start, end) {
  return Math.round((new Date(`${end}T00:00:00Z`) - new Date(`${start}T00:00:00Z`)) / 86400000) + 1;
}

async function fetchJson(url) {
  const response = await fetch(url);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

async function init() {
  try {
    state.meta = await fetchJson("/api/meta");
    if (!state.meta.first_date) throw new Error("The database contains no daily reports.");
    $("#coverage-line").textContent = `${state.meta.first_date} → ${state.meta.last_date} · ${state.meta.hosts.length} canonical hosts`;
    $("#start-date").min = state.meta.first_date;
    $("#start-date").max = state.meta.last_date;
    $("#end-date").min = state.meta.first_date;
    $("#end-date").max = state.meta.last_date;
    $("#end-date").value = state.meta.last_date;
    $("#start-date").value = maxDate(state.meta.first_date, isoShift(state.meta.last_date, -89));
    $("#host-filters").insertAdjacentHTML("beforeend", state.meta.hosts.map(host =>
      `<label><input type="checkbox" value="${escapeHtml(host.host)}" checked>${escapeHtml(host.host)}</label>`
    ).join(""));
    $("#traffic-host").innerHTML = state.meta.hosts.map(host =>
      `<option value="${escapeHtml(host.host)}">${escapeHtml(host.host)}</option>`
    ).join("");
    wireEvents();
    await load();
    setStatus("READY", "ready");
  } catch (error) {
    showError(error);
  }
}

function wireEvents() {
  $("#apply").addEventListener("click", load);
  $("#metric").addEventListener("change", renderChart);
  $$("#traffic-host, #traffic-measure, #traffic-direction").forEach(control =>
    control.addEventListener("change", renderTrafficChart)
  );
  $$("[data-days]").forEach(button => button.addEventListener("click", () => {
    $$("[data-days]").forEach(item => item.classList.toggle("active", item === button));
    const value = button.dataset.days;
    $("#end-date").value = state.meta.last_date;
    $("#start-date").value = value === "all"
      ? state.meta.first_date
      : maxDate(state.meta.first_date, isoShift(state.meta.last_date, -Number(value) + 1));
    load();
  }));
  window.addEventListener("resize", debounce(() => { renderChart(); renderTrafficChart(); }, 120));
}

function maxDate(a, b) { return a > b ? a : b; }

async function load() {
  hideError();
  setStatus("QUERYING", "loading");
  const hosts = $$("#host-filters input:checked").map(input => input.value);
  if (!hosts.length) return showError(new Error("Select at least one host."));
  const params = new URLSearchParams({ start: $("#start-date").value, end: $("#end-date").value });
  hosts.forEach(host => params.append("host", host));
  try {
    const [dailyResult, trafficResult] = await Promise.all([
      fetchJson(`/api/daily?${params}`),
      fetchJson(`/api/traffic?${params}`)
    ]);
    state.rows = dailyResult.rows;
    state.traffic = trafficResult.rows;
    render();
    setStatus("READY", "ready");
  } catch (error) {
    showError(error);
  }
}

function setStatus(text, className) {
  const status = $("#status");
  status.textContent = text;
  status.className = `status ${className}`;
}

function showError(error) {
  $("#error").textContent = error.message || String(error);
  $("#error").classList.remove("hidden");
  setStatus("ERROR", "failed");
}

function hideError() { $("#error").classList.add("hidden"); }

function render() {
  renderKpis();
  renderChart();
  renderTrafficChart();
  renderQuality();
  renderTable();
}

function valid(rows, field) {
  return rows.map(row => Number(row[field])).filter(value => Number.isFinite(value) && value !== -1);
}

function average(values) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
}

function renderKpis() {
  const start = $("#start-date").value;
  const end = $("#end-date").value;
  const selectedHosts = $$("#host-filters input:checked").map(input => input.value);
  const possible = spanDays(start, end) * selectedHosts.length;
  const health = state.rows.filter(row => row.health_state === "healthy").length;
  const announces = valid(state.rows, "announce_24h");
  const incidents = ["idle_timeout_events_24h", "provider_bridge_dropped_24h", "provider_bridge_disconnected_24h"]
    .flatMap(field => valid(state.rows, field)).reduce((sum, value) => sum + value, 0);
  const versioned = state.rows.filter(row => row.rns_server_master_version && row.rns_ctl_master_version);
  const current = versioned.filter(row => row.rns_server_matches_master === 1 && row.rns_ctl_matches_master === 1).length;
  const cards = [
    ["Coverage", possible ? `${(state.rows.length / possible * 100).toFixed(1)}%` : "—", `${state.rows.length} of ${possible} host-days`, state.rows.length === possible ? "good" : "warn"],
    ["Healthy captures", state.rows.length ? `${(health / state.rows.length * 100).toFixed(1)}%` : "—", `${health} healthy · ${state.rows.length - health} other`, health === state.rows.length ? "good" : "warn"],
    ["Mean announces", announces.length ? compact(average(announces)) : "—", `${announces.length} valid daily values`, ""],
    ["Recorded incidents", compact(incidents), "timeouts + drops + disconnects", incidents ? "warn" : "good"],
    ["Current binaries", versioned.length ? `${(current / versioned.length * 100).toFixed(1)}%` : "—", `${versioned.length} captures have a version baseline`, versioned.length && current === versioned.length ? "good" : "warn"]
  ];
  $("#kpis").innerHTML = cards.map(([name, value, detail, tone]) =>
    `<article class="kpi"><div class="name">${name}</div><div class="value ${tone}">${value}</div><div class="detail">${detail}</div></article>`
  ).join("");
}

function metricValue(row, config, field) {
  const value = config.value ? config.value(row) : Number(row[field]);
  return Number.isFinite(value) && value !== -1 ? value : null;
}

function renderChart() {
  const canvas = $("#trend-chart");
  const field = $("#metric").value;
  const config = metrics[field];
  $("#chart-title").textContent = config.label;
  const hosts = $$("#host-filters input:checked").map(input => input.value).sort();
  const series = hosts.map(host => ({
    host,
    points: state.rows.filter(row => row.host === host).map(row => ({ date: row.report_date, value: metricValue(row, config, field) })).filter(point => point.value !== null)
  }));
  const values = series.flatMap(item => item.points.map(point => point.value));
  $("#chart-empty").classList.toggle("hidden", values.length > 0);
  $("#legend").innerHTML = hosts.map((host, index) =>
    `<span style="--legend-color:${state.colors[index]}">${escapeHtml(host)}</span>`
  ).join("");

  const box = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.floor(box.width * ratio));
  canvas.height = Math.max(1, Math.floor(box.height * ratio));
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, box.width, box.height);
  if (!values.length) return;

  const pad = { left: 62, right: 18, top: 15, bottom: 35 };
  const width = box.width - pad.left - pad.right;
  const height = box.height - pad.top - pad.bottom;
  const minDate = new Date(`${$("#start-date").value}T00:00:00Z`).getTime();
  const maxDateValue = new Date(`${$("#end-date").value}T00:00:00Z`).getTime();
  let minValue = Math.min(...values);
  let maxValue = Math.max(...values);
  if (minValue === maxValue) { minValue = Math.max(0, minValue - 1); maxValue += 1; }
  const valuePad = (maxValue - minValue) * .08;
  minValue = minValue >= 0 ? Math.max(0, minValue - valuePad) : minValue - valuePad;
  maxValue += valuePad;
  const x = date => pad.left + (new Date(`${date}T00:00:00Z`).getTime() - minDate) / Math.max(1, maxDateValue - minDate) * width;
  const y = value => pad.top + (maxValue - value) / (maxValue - minValue) * height;

  ctx.font = "11px ui-monospace, monospace";
  ctx.lineWidth = 1;
  for (let tick = 0; tick <= 4; tick++) {
    const yy = pad.top + height * tick / 4;
    const value = maxValue - (maxValue - minValue) * tick / 4;
    ctx.strokeStyle = "#303833";
    ctx.beginPath(); ctx.moveTo(pad.left, yy); ctx.lineTo(box.width - pad.right, yy); ctx.stroke();
    ctx.fillStyle = "#92998e";
    ctx.textAlign = "right"; ctx.textBaseline = "middle";
    ctx.fillText(config.format(value), pad.left - 9, yy);
  }
  [0, .5, 1].forEach(position => {
    const time = minDate + (maxDateValue - minDate) * position;
    ctx.fillStyle = "#92998e"; ctx.textAlign = position === 0 ? "left" : position === 1 ? "right" : "center";
    ctx.textBaseline = "bottom";
    ctx.fillText(new Date(time).toISOString().slice(0, 10), pad.left + width * position, box.height);
  });
  series.forEach((item, index) => {
    ctx.strokeStyle = state.colors[index]; ctx.fillStyle = state.colors[index]; ctx.lineWidth = 2;
    ctx.beginPath();
    item.points.forEach((point, pointIndex) => {
      const xx = x(point.date), yy = y(point.value);
      if (pointIndex === 0) ctx.moveTo(xx, yy); else ctx.lineTo(xx, yy);
    });
    ctx.stroke();
    item.points.forEach(point => { ctx.beginPath(); ctx.arc(x(point.date), y(point.value), 2.2, 0, Math.PI * 2); ctx.fill(); });
  });
}

function renderTrafficChart() {
  const canvas = $("#traffic-chart");
  const host = $("#traffic-host").value;
  const measure = $("#traffic-measure").value;
  const direction = $("#traffic-direction").value;
  const formatter = measure === "bytes" ? byteSize : compact;
  const rows = state.traffic.filter(row =>
    row.host === host && row.query_ok === 1 && Number(row[measure]) >= 0
  );
  const grouped = new Map();
  rows.forEach(row => {
    if (direction !== "combined" && row.direction !== direction) return;
    const key = `${row.report_date}|${row.packet_type}`;
    grouped.set(key, (grouped.get(key) || 0) + Number(row[measure]));
  });
  const preferredOrder = ["announce", "data", "linkrequest", "proof"];
  const packetTypes = [...new Set(rows.map(row => row.packet_type))].sort((a, b) => {
    const ai = preferredOrder.indexOf(a), bi = preferredOrder.indexOf(b);
    return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi) || a.localeCompare(b);
  });
  const series = packetTypes.map(packetType => ({
    host: packetType,
    points: [...grouped.entries()]
      .filter(([key]) => key.endsWith(`|${packetType}`))
      .map(([key, value]) => ({ date: key.split("|", 1)[0], value }))
      .sort((a, b) => a.date.localeCompare(b.date))
  }));
  const values = series.flatMap(item => item.points.map(point => point.value));
  $("#traffic-title").textContent = `${measure === "bytes" ? "Bytes" : "Packets"} by packet type`;
  $("#traffic-empty").classList.toggle("hidden", values.length > 0);
  $("#traffic-legend").innerHTML = packetTypes.map((packetType, index) =>
    `<span style="--legend-color:${state.colors[index]}">${escapeHtml(packetType)}</span>`
  ).join("");

  const validDates = new Set(rows.map(row => row.report_date));
  const observedDates = new Set(state.rows.filter(row => row.host === host).map(row => row.report_date));
  const total = rows.reduce((sum, row) => {
    if (direction !== "combined" && row.direction !== direction) return sum;
    return sum + Number(row[measure]);
  }, 0);
  const nonAnnounce = rows.reduce((sum, row) => {
    if (row.packet_type === "announce" || (direction !== "combined" && row.direction !== direction)) return sum;
    return sum + Number(row[measure]);
  }, 0);
  const share = total ? `${(nonAnnounce / total * 100).toFixed(1)}% non-announce` : "no traffic mix yet";
  $("#traffic-coverage").textContent = `${host} · ${validDates.size}/${observedDates.size} observed days have traffic totals · ${share}`;

  const box = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.floor(box.width * ratio));
  canvas.height = Math.max(1, Math.floor(box.height * ratio));
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, box.width, box.height);
  if (!values.length) return;

  const pad = { left: 72, right: 18, top: 15, bottom: 35 };
  const width = box.width - pad.left - pad.right;
  const height = box.height - pad.top - pad.bottom;
  const minDate = new Date(`${$("#start-date").value}T00:00:00Z`).getTime();
  const maxDate = new Date(`${$("#end-date").value}T00:00:00Z`).getTime();
  const maxValue = Math.max(...values) * 1.08 || 1;
  const x = date => pad.left + (new Date(`${date}T00:00:00Z`).getTime() - minDate) / Math.max(1, maxDate - minDate) * width;
  const y = value => pad.top + (maxValue - value) / maxValue * height;

  ctx.font = "11px ui-monospace, monospace";
  ctx.lineWidth = 1;
  for (let tick = 0; tick <= 4; tick++) {
    const yy = pad.top + height * tick / 4;
    const value = maxValue * (1 - tick / 4);
    ctx.strokeStyle = "#303833";
    ctx.beginPath(); ctx.moveTo(pad.left, yy); ctx.lineTo(box.width - pad.right, yy); ctx.stroke();
    ctx.fillStyle = "#92998e"; ctx.textAlign = "right"; ctx.textBaseline = "middle";
    ctx.fillText(formatter(value), pad.left - 9, yy);
  }
  [0, .5, 1].forEach(position => {
    const time = minDate + (maxDate - minDate) * position;
    ctx.fillStyle = "#92998e"; ctx.textAlign = position === 0 ? "left" : position === 1 ? "right" : "center";
    ctx.textBaseline = "bottom";
    ctx.fillText(new Date(time).toISOString().slice(0, 10), pad.left + width * position, box.height);
  });
  series.forEach((item, index) => {
    ctx.strokeStyle = state.colors[index]; ctx.fillStyle = state.colors[index]; ctx.lineWidth = 2;
    ctx.beginPath();
    item.points.forEach((point, pointIndex) => {
      if (pointIndex === 0) ctx.moveTo(x(point.date), y(point.value));
      else ctx.lineTo(x(point.date), y(point.value));
    });
    ctx.stroke();
    item.points.forEach(point => { ctx.beginPath(); ctx.arc(x(point.date), y(point.value), 2.2, 0, Math.PI * 2); ctx.fill(); });
  });
}

function renderQuality() {
  const start = $("#start-date").value;
  const end = $("#end-date").value;
  const expected = spanDays(start, end);
  const hosts = $$("#host-filters input:checked").map(input => input.value).sort();
  const queryFields = ["announce_24h", "idle_timeout_events_24h", "provider_bridge_dropped_24h", "provider_bridge_disconnected_24h"];
  const items = hosts.map(host => {
    const rows = state.rows.filter(row => row.host === host);
    const missingDays = expected - rows.length;
    const failedValues = rows.reduce((count, row) => count + queryFields.filter(field => Number(row[field]) === -1).length, 0);
    const nonhealthy = rows.filter(row => row.health_state !== "healthy").length;
    const issues = missingDays + failedValues + nonhealthy;
    return `<div class="quality-item ${issues ? "issue" : ""}">
      <strong>${escapeHtml(host)}</strong>
      <span>${rows.length}/${expected} days · ${missingDays} missing · ${failedValues} failed query values · ${nonhealthy} non-healthy captures</span>
    </div>`;
  });
  if (!items.length) items.push('<div class="quality-item issue"><strong>No observations</strong><span>Adjust the date range or host selection.</span></div>');
  $("#quality").innerHTML = `<div class="quality-grid">${items.join("")}</div>`;
}

function renderTable() {
  const rows = [...state.rows].sort((a, b) => b.report_date.localeCompare(a.report_date) || a.host.localeCompare(b.host));
  $("#row-count").textContent = `${rows.length} rows`;
  $("#daily-table").innerHTML = rows.map(row => {
    const announces = row.announce_24h < 0 ? "missing" : compact(row.announce_24h);
    const memory = row.mem_total_mb > 0 ? `${(row.mem_used_mb / row.mem_total_mb * 100).toFixed(1)}%` : "—";
    const publicUp = row.public_interfaces_total ? `${row.public_interfaces_up}/${row.public_interfaces_total}` : "—";
    const versionKnown = row.rns_server_master_version && row.rns_ctl_master_version;
    const versionCurrent = versionKnown && row.rns_server_matches_master && row.rns_ctl_matches_master;
    const versionClass = versionKnown ? (versionCurrent ? "good" : "warn") : "";
    return `<tr>
      <td>${escapeHtml(row.report_date)}</td><td>${escapeHtml(row.host)}</td>
      <td><span class="health-pill ${row.health_state === "healthy" ? "" : "bad"}">${escapeHtml(row.health_state)}</span></td>
      <td>${announces}</td><td>${Number(row.load1).toFixed(2)}</td><td>${memory}</td>
      <td>${row.established_sessions_4242}</td><td>${publicUp}</td>
      <td class="${row.idle_timeout_events_24h > 0 ? "warn" : ""}">${row.idle_timeout_events_24h < 0 ? "missing" : row.idle_timeout_events_24h}</td>
      <td class="${versionClass}" title="${escapeHtml(row.rns_server_version)} / ${escapeHtml(row.rns_ctl_version)}">${versionKnown ? (versionCurrent ? "master" : "drift") : "unknown"}</td>
    </tr>`;
  }).join("");
}

function debounce(callback, wait) {
  let timeout;
  return (...args) => { clearTimeout(timeout); timeout = setTimeout(() => callback(...args), wait); };
}

init();
