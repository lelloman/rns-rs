const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class FakeClassList {
  constructor(element) {
    this.element = element;
    this.classes = new Set();
  }

  add(name) {
    this.classes.add(name);
    this.element.className = Array.from(this.classes).join(" ");
  }

  remove(name) {
    this.classes.delete(name);
    this.element.className = Array.from(this.classes).join(" ");
  }

  toggle(name, force) {
    if (force === undefined) {
      if (this.classes.has(name)) {
        this.remove(name);
      } else {
        this.add(name);
      }
    } else if (force) {
      this.add(name);
    } else {
      this.remove(name);
    }
  }
}

class FakeElement {
  constructor(tagName = "div", ownerDocument = null) {
    this.tagName = tagName.toUpperCase();
    this.ownerDocument = ownerDocument;
    this.children = [];
    this.parentNode = null;
    this.listeners = new Map();
    this.attributes = {};
    this.style = {};
    this.className = "";
    this.classList = new FakeClassList(this);
    this._textContent = "";
    this._innerHTML = "";
    this.value = "";
    this.checked = false;
  }

  set id(value) {
    this._id = value;
    if (this.ownerDocument) {
      this.ownerDocument.elements.set(value, this);
    }
  }

  get id() {
    return this._id;
  }

  set textContent(value) {
    this._textContent = String(value);
  }

  get textContent() {
    return this._textContent;
  }

  set innerHTML(value) {
    this._innerHTML = String(value);
    this.children = [];
    this._textContent = this._innerHTML.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();

    const buttonPattern = /<button[^>]*\s(data-[a-z-]+)="([^"]+)"[^>]*>([^<]*)<\/button>/g;
    for (const match of this._innerHTML.matchAll(buttonPattern)) {
      const button = new FakeElement("button", this.ownerDocument);
      button.attributes[match[1]] = match[2];
      button.textContent = match[3].trim();
      this.appendChild(button);
    }
  }

  get innerHTML() {
    return this._innerHTML;
  }

  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, []);
    }
    this.listeners.get(type).push(listener);
  }

  getAttribute(name) {
    return this.attributes[name] ?? null;
  }

  querySelectorAll(selector) {
    const attrMatch = selector.match(/^\[(data-[a-z-]+)\]$/);
    if (!attrMatch) {
      return [];
    }
    const attrName = attrMatch[1];
    const results = [];
    const visit = (node) => {
      if (node.attributes && Object.prototype.hasOwnProperty.call(node.attributes, attrName)) {
        results.push(node);
      }
      for (const child of node.children || []) {
        visit(child);
      }
    };
    visit(this);
    return results;
  }

  async click() {
    const listeners = this.listeners.get("click") || [];
    for (const listener of listeners) {
      await listener({ target: this, currentTarget: this });
    }
  }
}

class FakeDocument {
  constructor() {
    this.elements = new Map();
  }

  createElement(tagName) {
    return new FakeElement(tagName, this);
  }

  getElementById(id) {
    return this.elements.get(id) || null;
  }
}

function createJsonResponse(payload) {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    async json() {
      return payload;
    },
    async text() {
      return JSON.stringify(payload);
    },
  };
}

function createErrorResponse(status, error) {
  return {
    ok: false,
    status,
    statusText: "Bad Request",
    async json() {
      return { error };
    },
    async text() {
      return JSON.stringify({ error });
    },
  };
}

function makeUiHarness() {
  const document = new FakeDocument();
  const source = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");
  const ids = Array.from(source.matchAll(/getElementById\("([^"]+)"\)/g), (match) => match[1]);
  for (const id of new Set(ids)) {
    const element = new FakeElement("div", document);
    element.id = id;
  }

  const calls = [];
  const state = {
    node: {
      server_mode: "supervised",
      uptime_seconds: 42,
      process_count: 3,
      processes_running: 3,
      processes_ready: 3,
    },
    config: {
      config: {
        config_path: "/data",
        resolved_config_dir: "/data",
        server_config_file_path: "/data/rns-server.json",
        server_config_file_present: true,
        server_config_file_json: JSON.stringify({
          stats_db_path: "/data/stats.db",
          http: { enabled: true, host: "0.0.0.0", port: 8080, disable_auth: true },
        }, null, 2),
        stats_db_path: "/data/stats.db",
        rnsd_bin: "rnsd",
        sentineld_bin: "rns-sentineld",
        statsd_bin: "rns-statsd",
        http: {
          enabled: true,
          host: "0.0.0.0",
          port: 8080,
          auth_mode: "disabled",
          token_configured: false,
          daemon_mode: true,
        },
        launch_plan: [
          { name: "rnsd", bin: "rnsd", args: ["--config", "/data"] },
          { name: "rns-sentineld", bin: "rns-sentineld", args: ["--config", "/data"] },
          { name: "rns-statsd", bin: "rns-statsd", args: ["--config", "/data", "--db", "/data/stats.db"] },
        ],
      },
    },
    schema: {
      schema: {
        example_config_json: "{\n  \"http\": {\n    \"port\": 8080\n  }\n}",
        notes: ["Schema note"],
        fields: [
          {
            field: "stats_db_path",
            field_type: "string",
            default_value: "/data/stats.db",
            effect: "restart rns-statsd",
            description: "Stats DB path",
          },
        ],
      },
    },
    configStatus: {
      status: {
        converged: true,
        summary: "Runtime matches saved config.",
        runtime_differs_from_saved: false,
        pending_process_restarts: [],
        control_plane_reload_required: false,
        control_plane_restart_required: false,
        last_action: "apply",
        last_action_age_seconds: 2,
        last_saved_age_seconds: 2,
        last_apply_age_seconds: 2,
        pending_action: "none",
        pending_targets: [],
        blocking_reason: null,
      },
    },
    processes: {
      processes: [
        {
          name: "rnsd",
          status: "running",
          ready: true,
          ready_state: "ready",
          pid: 100,
          last_exit_code: null,
          restart_count: 0,
          last_error: null,
          status_detail: "listening on 127.0.0.1:37429",
          durable_log_path: "/data/logs/rnsd.log",
          last_log_age_seconds: 1,
          recent_log_lines: 10,
          uptime_seconds: 42,
          last_transition_seconds: 2,
        },
        {
          name: "rns-statsd",
          status: "running",
          ready: true,
          ready_state: "ready",
          pid: 102,
          last_exit_code: null,
          restart_count: 2,
          last_error: null,
          status_detail: "stats database open",
          durable_log_path: "/data/logs/rns-statsd.log",
          last_log_age_seconds: 1,
          recent_log_lines: 5,
          uptime_seconds: 30,
          last_transition_seconds: 1,
        },
      ],
    },
    processEvents: {
      events: [
        { process: "rnsd", event: "ready", age_seconds: 2, detail: "rpc online" },
        { process: "rns-statsd", event: "restart", age_seconds: 1, detail: "config apply" },
      ],
    },
    logs: {
      process: "rnsd",
      durable_log_path: "/data/logs/rnsd.log",
      last_log_age_seconds: 1,
      recent_log_lines: 10,
      lines: [{ stream: "stderr", line: "rnsd started", age_seconds: 1 }],
    },
  };

  const validateResult = {
    result: {
      valid: true,
      warnings: [],
      apply_plan: {
        overall_action: "restart_children",
        processes_to_restart: ["rns-statsd"],
        control_plane_reload_required: false,
        control_plane_restart_required: false,
        notes: ["Restart required for stats DB path."],
        changes: [
          {
            field: "stats_db_path",
            before: "/data/stats.db",
            after: "/data/new.db",
            effect: "restart rns-statsd",
          },
        ],
      },
    },
  };

  async function fetchStub(url, options = {}) {
    calls.push({ url, options });
    const method = options.method || "GET";
    if (method === "GET") {
      if (url === "/api/node") return createJsonResponse(state.node);
      if (url === "/api/config") return createJsonResponse(state.config);
      if (url === "/api/config/schema") return createJsonResponse(state.schema);
      if (url === "/api/config/status") return createJsonResponse(state.configStatus);
      if (url === "/api/processes") return createJsonResponse(state.processes);
      if (url.startsWith("/api/process_events")) return createJsonResponse(state.processEvents);
      if (url.startsWith("/api/processes/") && url.includes("/logs")) {
        const process = url.split("/")[3];
        return createJsonResponse({ ...state.logs, process });
      }
      return createErrorResponse(404, `Unhandled GET ${url}`);
    }

    if (method === "POST") {
      if (
        url === "/api/config/validate" ||
        url === "/api/config" ||
        url === "/api/config/apply"
      ) {
        return createJsonResponse({
          ...validateResult,
          result: {
            ...validateResult.result,
            action: url === "/api/config/validate" ? undefined : (url.endsWith("/apply") ? "apply" : "save"),
          },
        });
      }
      if (url.startsWith("/api/processes/")) {
        const parts = url.split("/");
        return createJsonResponse({
          ok: true,
          queued: true,
          action: parts[4],
          process: parts[3],
        });
      }
      return createErrorResponse(404, `Unhandled POST ${url}`);
    }

    return createErrorResponse(405, `Unhandled method ${method}`);
  }

  const context = {
    console,
    document,
    window: { location: { search: "" } },
    localStorage: {
      getItem() {
        return "";
      },
      setItem() {},
    },
    URLSearchParams,
    fetch: fetchStub,
    setInterval() {
      return 1;
    },
    clearInterval() {},
  };

  vm.runInNewContext(source, context, { filename: "app.js" });

  return { document, calls, state };
}

async function flushUi() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

test("app.js renders operator state on initial refresh", async () => {
  const { document } = makeUiHarness();
  await flushUi();

  assert.equal(document.getElementById("serverMode").textContent, "supervised");
  assert.equal(document.getElementById("running").textContent, "3/3");
  assert.equal(document.getElementById("ready").textContent, "3/3");
  assert.equal(document.getElementById("selectedProcessName").textContent, "rnsd");
  assert.match(
    document.getElementById("selectedProcessSummary").textContent,
    /listening on 127\.0\.0\.1:37429/,
  );
  assert.equal(document.getElementById("logProcessName").textContent, "rnsd");
  assert.match(document.getElementById("processLogOutput").textContent, /\[stderr\] rnsd started/);
});

test("app.js validate, save, and apply actions hit config endpoints", async () => {
  const { document, calls } = makeUiHarness();
  await flushUi();

  await document.getElementById("validateConfig").click();
  await flushUi();
  await document.getElementById("saveConfig").click();
  await flushUi();
  await document.getElementById("applyConfig").click();
  await flushUi();

  const postPaths = calls
    .filter((call) => (call.options.method || "GET") === "POST")
    .map((call) => call.url);
  assert.deepEqual(postPaths.slice(0, 3), [
    "/api/config/validate",
    "/api/config",
    "/api/config/apply",
  ]);
  assert.match(document.getElementById("configPlanSummary").textContent, /Action: restart_children/);
  assert.match(document.getElementById("configActionSummary").textContent, /Apply:/);
});

test("app.js process control buttons queue restart and update status", async () => {
  const { document, calls } = makeUiHarness();
  await flushUi();

  const restartButton = document.getElementById("processRows").querySelectorAll("[data-restart]")[0];
  await restartButton.click();
  await flushUi();

  const lastPost = calls
    .filter((call) => (call.options.method || "GET") === "POST")
    .at(-1);
  assert.equal(lastPost.url, "/api/processes/rnsd/restart");
  assert.equal(document.getElementById("status").textContent, "Connected");
  assert.equal(document.getElementById("selectedProcessName").textContent, "rnsd");
});
