"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const { test, beforeEach, afterEach } = require("node:test");

const root = path.resolve(__dirname, "../..");
const api = path.join(root, "apps/api");
const envKeys = [
  "AUTO_SYNC_METRICS_ENABLED", "AUTO_SYNC_METRICS_LABELS",
  "AUTO_SYNC_METRICS_EXTRA_LABELS", "AUTO_SYNC_METRICS_MONITORING_GROUP",
];
let previousEnv;
beforeEach(() => {
  previousEnv = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));
  for (const key of envKeys) delete process.env[key];
});
afterEach(() => {
  for (const [key, value] of Object.entries(previousEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

function load(filename, mocks) {
  const mod = new Module(filename);
  mod.filename = filename;
  mod.paths = Module._nodeModulePaths(path.dirname(filename));
  mod.require = id => Object.hasOwn(mocks, id) ? mocks[id] : Module._load(id, mod, false);
  mod._compile(fs.readFileSync(filename, "utf8"), filename);
  return mod.exports;
}

function fixture(labels) {
  let stored = { enabled: true, override_metrics: true, labels, monitoring_group: "saved" };
  const writes = [];
  const pool = {
    async query(sql, params) {
      if (sql.includes("SELECT is_admin")) return { rows: [{ is_admin: true }] };
      if (sql.startsWith("SELECT")) return { rows: [{ auto_sync_metrics: stored }] };
      assert.match(sql, /^UPDATE system_settings SET auto_sync_metrics/);
      stored = JSON.parse(params[0]);
      writes.push(stored);
      return { rows: [] };
    },
  };
  const logger = { warn() {}, error() {}, debug() {} };
  const settings = load(path.join(api, "services/systemSettings.js"), {
    "../utils/logger": { logger },
  });
  const policy = load(path.join(api, "services/autoSyncMetricLabels.js"), {
    "./systemSettings": settings,
  });
  const routes = new Map();
  const noop = () => {};
  const middleware = () => noop;
  const router = {
    get() {}, post() {}, delete() {},
    put(url, ...handlers) { routes.set(url, handlers.at(-1)); },
  };
  const mocks = {
    express: { Router: () => router },
    "../db/database": { pool },
    "../services/systemSettings": settings,
    "../services/autoSyncMetricLabels": policy,
  };
  // Unrelated admin endpoints are registered but never invoked.
  const unused = new Proxy({}, { get: () => middleware });
  load(path.join(api, "routes/admin.js"), new Proxy(mocks, {
    getOwnPropertyDescriptor: () => ({ configurable: true, enumerable: true }),
    get: (target, key) => Object.hasOwn(target, key) ? target[key] : unused,
  }));
  return {
    writes,
    stored: () => stored,
    async save(requested, expectedWrites = 1) {
      const res = {
        statusCode: 200,
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return this; },
      };
      await routes.get("/api/v1/admin/auto-sync/metrics")({
        user: { id: "admin" },
        body: { enabled: true, override_metrics: true, labels: requested },
      }, res);
      assert.equal(res.statusCode, 200, JSON.stringify(res.body));
      assert.equal(writes.length, expectedWrites);
      return res.body;
    },
  };
}

for (const selected of [false, true]) {
  test(`admin save ${selected ? "enables" : "disables"} permitted owner under extra-label lock`, async () => {
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
    const f = fixture(selected ? ["kind"] : ["kind", "owner_username"]);
    const requested = selected ? ["kind", "owner_username"] : ["kind"];
    const response = await f.save(requested);
    assert.deepEqual(f.stored().labels, requested);
    assert.deepEqual(response.labels, requested);
    assert.equal(response.extra_labels_locked, true);
    assert.equal(response.labels_locked, false);
  });
}

for (const allowlist of ["none", "project"]) {
  test(`admin save cannot select an owner denied by ${allowlist}`, async () => {
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = allowlist;
    const f = fixture(["kind"]);
    const response = await f.save(["kind", "owner_username"]);
    assert.deepEqual(f.stored().labels, ["kind"]);
    assert.ok(!response.labels.includes("owner_username"));
  });
}

test("denied saved owners stay dormant without overwriting their stored choice", async () => {
  process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "none";
  const f = fixture(["kind", "owner_username"]);
  const response = await f.save(["kind"]);
  assert.deepEqual(f.stored().labels, ["kind", "owner_username"]);
  assert.deepEqual(response.labels, ["kind"]);
});

test("owner permission alone never selects an owner on save", async () => {
  process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
  const f = fixture(["kind"]);
  const response = await f.save(["kind"]);
  assert.deepEqual(f.stored().labels, ["kind"]);
  assert.deepEqual(response.labels, ["kind"]);
});

test("explicit owner selection remains supported with an empty environment allowlist", async () => {
  process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "";
  const f = fixture(["kind"]);
  assert.deepEqual((await f.save(["kind", "owner_username"])).labels, ["kind", "owner_username"]);
  assert.deepEqual(f.stored().labels, ["kind", "owner_username"]);
});

test("owner edits preserve dormant asset choices and legacy deployment asset defaults", async () => {
  process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "project,owner_username";
  const f = fixture(["kind", "asset_name"]);
  const response = await f.save(["kind", "project", "owner_username", "group"]);
  assert.deepEqual(f.stored().labels, ["kind", "owner_username", "asset_name"]);
  assert.deepEqual(response.labels, ["kind", "project", "owner_username"]);
});

for (const deploymentLabels of ["kind", "kind,owner_username", "none"]) {
  test(`complete deployment selection ${deploymentLabels} cannot be changed by admin save`, async () => {
    process.env.AUTO_SYNC_METRICS_ENABLED = "true";
    process.env.AUTO_SYNC_METRICS_LABELS = deploymentLabels;
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
    const saved = ["kind", "asset_name"];
    const f = fixture(saved);
    const requested = deploymentLabels.includes("owner_username") ? ["kind"] : ["owner_username"];
    const response = await f.save(requested, 0);
    assert.deepEqual(f.stored().labels, saved);
    assert.deepEqual(response.labels, deploymentLabels === "none" ? [] : deploymentLabels.split(","));
    assert.equal(response.labels_locked, true);
  });
}
