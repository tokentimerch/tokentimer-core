"use strict";

// Disposable PostgreSQL must already be migrated. Exercises the actual API
// metrics bootstrap over HTTP, real import transactions and a real Prometheus.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const { pathToFileURL } = require("node:url");
const { spawnSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const args = process.argv.slice(2);
const option = (name, fallback) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const apiIndex = path.resolve(option("--api-index", path.join(root, "apps/api/index.js")));
const provider = option("--provider", "gitlab");
const evidence = path.resolve(option("--evidence", path.join(root, ".build/auto-sync-live-evidence")));
fs.mkdirSync(evidence, { recursive: true });
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
const apiRequire = createRequire(path.join(root, "apps/api/index.js"));
const editionRequire = createRequire(apiIndex);
const express = apiRequire("express");
const { Registry } = apiRequire("prom-client");
const { pool } = apiRequire("./db/database");
const collector = apiRequire("./services/autoSyncMetrics");
const provenance = apiRequire("./services/autoSyncProvenance");
const Token = apiRequire("./db/models/Token");
const image = "prom/prometheus:v3.12.0@sha256:69f5241418838263316593f7274a304b095c40bcf22e57272865da91bd60a8ac";
const container = `tt-auto-sync-prom-${crypto.randomUUID().slice(0, 8)}`;
const events = [];
const servers = [];
let prometheus, userId, workspaceId, workerPool, runs;
function record(name, data) {
  events.push({ at: new Date().toISOString(), name, data });
  fs.writeFileSync(path.join(evidence, "events.json"), JSON.stringify(events, null, 2));
  console.log(name);
}
function docker(...parameters) {
  const result = spawnSync("docker", parameters, { encoding: "utf8" });
  fs.appendFileSync(path.join(evidence, "docker.log"), `${parameters.join(" ")}\n${result.stdout || ""}${result.stderr || ""}\n`);
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}
async function waitFor(name, work, timeout = 25000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try { last = await work(); if (last) return last; } catch (error) { last = error.message; }
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  throw new Error(`${name} timed out: ${JSON.stringify(last)}`);
}
async function query(expression) {
  const response = await fetch(`${prometheus}/api/v1/query?query=${encodeURIComponent(expression)}`);
  const result = await response.json();
  assert.equal(result.status, "success", JSON.stringify(result));
  record("promql", { expression, result: result.data.result });
  return result.data.result;
}
async function alerts() {
  const response = await fetch(`${prometheus}/api/v1/alerts`);
  const result = await response.json();
  assert.equal(result.status, "success");
  return result.data.alerts.filter(alert => alert.state === "firing");
}
async function capture(name) {
  for (let i = 0; i < servers.length; i++) {
    const response = await fetch(`http://127.0.0.1:${servers[i].port}/metrics`);
    fs.writeFileSync(path.join(evidence, `${name}-api-${i}.prom`), await response.text());
    assert.equal(response.status, 200);
  }
  record(name, { alerts: await alerts() });
}
async function bootstrap(port = 0) {
  const source = fs.readFileSync(apiIndex, "utf8");
  const start = source.indexOf("const metricsEnabled =");
  const end = source.indexOf("// Metrics middleware", start);
  assert.ok(start >= 0 && end > start);
  const app = express();
  const registry = new Registry();
  vm.runInNewContext(source.slice(start, end), {
    process: { env: { ENABLE_METRICS: "true" } }, client: { register: registry }, app,
    logger: { error: (...message) => record("scrape-error", message) },
    require: name => name.includes("services/autoSyncMetrics") ? collector : editionRequire(name),
  }, { filename: apiIndex });
  const server = await new Promise(resolve => { const listening = app.listen(port, "0.0.0.0", () => resolve(listening)); });
  return { server, port: server.address().port };
}
async function closeServer(server) {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
async function main() {
  assert.match(process.env.DB_NAME || "", /_issue71_test$/, "Use a disposable, migrated database");
  record("candidate", { apiIndex, provider, image, db: process.env.DB_NAME,
    coreCommit: spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).stdout.trim(),
    collectorSha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "apps/api/services/autoSyncMetrics.js"))).digest("hex") });
  ({ pool: workerPool } = await import(pathToFileURL(path.join(root, "apps/worker/src/db.js")).href));
  runs = await import(pathToFileURL(path.join(root, "apps/worker/src/shared/autoSyncRuns.js")).href);
  servers.push(await bootstrap(), await bootstrap());
  const rules = yaml.load(fs.readFileSync(path.join(root, "deploy/prometheus/auto-sync.rules.yaml"), "utf8"));
  // Accelerate only time windows/grace periods; promtool separately tests the
  // unmodified shipped 15-minute, 3-hour and 25-hour examples.
  for (const group of rules.groups) for (const rule of group.rules) {
    rule.expr = rule.expr.replaceAll("[15m]", "[10s]").replaceAll("[3h]", "[30s]").replaceAll("90000", "10");
    rule.for = rule.for === "0m" ? "0s" : "3s";
  }
  fs.writeFileSync(path.join(evidence, "live-rules.yaml"), yaml.dump(rules, { lineWidth: -1 }));
  fs.writeFileSync(path.join(evidence, "prometheus.yaml"), yaml.dump({
    global: { scrape_interval: "1s", evaluation_interval: "1s", scrape_timeout: "900ms" },
    rule_files: ["/work/live-rules.yaml"], scrape_configs: [{ job_name: "tokentimer-api",
      static_configs: [{ targets: servers.map(s => `host.docker.internal:${s.port}`), labels: { installation: "local-test" } }] }],
  }));
  docker("run", "--detach", "--name", container, "-p", "127.0.0.1::9090", "-v", `${evidence}:/work:ro`, image,
    "--config.file=/work/prometheus.yaml", "--storage.tsdb.path=/prometheus");
  const port = docker("port", container, "9090/tcp").match(/:(\d+)$/)[1];
  prometheus = `http://127.0.0.1:${port}`;
  const selector = `{job="tokentimer-api",provider="${provider}"}`;
  const created = `auto_sync_items_created_total${selector}`;
  await waitFor("both targets and baseline samples", async () => {
    const samples = await query(`count_over_time(${created}[10s])`);
    return samples.length === 2 && samples.every(sample => Number(sample.value[1]) >= 4);
  });
  assert.ok((await query(created)).every(sample => Number(sample.value[1]) === 0));
  assert.equal((await alerts()).length, 0);
  await capture("baseline");

  userId = (await pool.query("INSERT INTO users(email, display_name, password_hash) VALUES ($1,'Metrics test','test-only') RETURNING id",
    [`prometheus-${crypto.randomUUID()}@example.test`])).rows[0].id;
  workspaceId = crypto.randomUUID();
  await pool.query("INSERT INTO workspaces(id, name, created_by) VALUES ($1,'Metrics test',$2)", [workspaceId, userId]);
  await pool.query("UPDATE auto_sync_feature_state SET multi_config_enabled=TRUE WHERE id=TRUE");
  const config = (await pool.query(`INSERT INTO auto_sync_configs
    (workspace_id, provider, credentials_encrypted, connection_key, created_by, next_sync_at)
    VALUES ($1,$2,'test-only','Prometheus verification',$3,NOW()) RETURNING *`, [workspaceId, provider, userId])).rows[0];
  async function claim() {
    await pool.query("UPDATE auto_sync_configs SET next_sync_at=NOW() WHERE id=$1", [config.id]);
    const run = (await runs.claimDueAutoSyncRuns()).find(row => row.id === config.id);
    assert.ok(run);
    return { configId: run.id, workspaceId, provider, runId: run.runId,
      generation: run.generation, scanVersion: Number(run.scanVersion), leaseOwner: run.leaseOwner, run };
  }
  let context = await claim();
  const payload = { name: "Prometheus test asset", location: "metrics.example.test", type: "api_key", category: "key_secret",
    expiration: "2028-01-01", source_provider: provider, source_instance: "metrics.example.test", source_owner_key: "test-owner",
    source_kind: provider === "vault" ? "vault-kv" : "gitlab-pat", source_object_id: "observed-object", source_observed_at: new Date() };
  const importAsset = () => provenance.upsertImportedToken({ context, payload: { ...payload }, workspaceId, userId, manual: false, assignMembership() {} });
  const imported = await importAsset();
  assert.equal(imported.created, true);
  await waitFor("committed creation scraped by both replicas", async () => {
    const values = await query(created);
    return values.length === 2 && values.every(sample => Number(sample.value[1]) === 1);
  });
  await waitFor("created asset alert firing", async () => (await alerts()).some(alert => alert.labels.alertname === "AutoSyncCreatedAssets"));
  const increase = `max by (installation, job, provider) (increase(${created}[10s]))`;
  const deduplicated = Number((await query(increase))[0].value[1]);
  const incorrectlySummed = Number((await query(`sum(increase(${created}[10s]))`))[0].value[1]);
  assert.ok(deduplicated >= 1 && deduplicated < 1.8);
  assert.ok(incorrectlySummed >= 2);
  record("creation-observed", { deduplicated, incorrectlySummed });
  await capture("created");

  assert.equal((await importAsset()).created, false);
  payload.name = "Updated existing asset";
  assert.equal((await importAsset()).created, false);
  await closeServer(servers[0].server);
  servers[0] = await bootstrap(servers[0].port);
  await runs.withCurrentRun(context.run, client => runs.finishAutoSyncRun(client, context.run, { status: "partial", created: 1, errors: 1 }));
  await waitFor("partial outcome observed", async () => {
    const values = await query(`auto_sync_run_outcomes_total{job="tokentimer-api",provider="${provider}",status="partial"}`);
    return values.length === 2 && values.every(sample => Number(sample.value[1]) === 1);
  });
  assert.ok((await query(`auto_sync_last_success_timestamp_seconds${selector}`)).every(sample => Number(sample.value[1]) === 0));
  assert.ok((await query(created)).every(sample => Number(sample.value[1]) === 1));
  await capture("retry-update-restart-partial");

  await pool.query("ALTER TABLE auto_sync_provider_stats RENAME TO auto_sync_provider_stats_unavailable");
  try {
    const response = await fetch(`http://127.0.0.1:${servers[0].port}/metrics`);
    assert.equal(response.status, 500);
    assert.equal(await response.text(), "metrics error");
    await waitFor("scrape failure detected", async () => {
      const values = await query('up{job="tokentimer-api"}');
      return values.length === 2 && values.every(sample => Number(sample.value[1]) === 0);
    });
    await waitFor("scrape failure alert fires", async () => (await alerts()).some(alert => alert.labels.alertname === "TokenTimerAPIDown"));
    record("database-failure", { status: 500, alerts: await alerts() });
  } finally {
    await pool.query("ALTER TABLE auto_sync_provider_stats_unavailable RENAME TO auto_sync_provider_stats");
  }
  await waitFor("scrapes recover", async () => {
    const values = await query('up{job="tokentimer-api"}');
    return values.length === 2 && values.every(sample => Number(sample.value[1]) === 1);
  });
  context = await claim();
  assert.equal((await importAsset()).created, false);
  await runs.withCurrentRun(context.run, client => runs.finishAutoSyncRun(client, context.run, { status: "success" }));
  await waitFor("success freshness observed", async () => {
    const values = await query(`auto_sync_last_success_timestamp_seconds${selector}`);
    return values.length === 2 && values.every(sample => Number(sample.value[1]) > 0);
  });
  await waitFor("idle creation window clears", async () => !(await alerts()).some(alert => alert.labels.alertname === "AutoSyncCreatedAssets"));
  assert.ok((await query(created)).every(sample => Number(sample.value[1]) === 1));
  assert.ok((await query(`resets(${created}[5m])`)).every(sample => Number(sample.value[1]) === 0));
  await capture("success-idle");

  await pool.query("UPDATE auto_sync_run_freshness SET last_attempt_at=TO_TIMESTAMP(1), last_success_at=TO_TIMESTAMP(1) WHERE provider=$1", [provider]);
  await waitFor("stale provider alerts fire", async () => {
    const names = new Set((await alerts()).map(alert => alert.labels.alertname));
    return names.has("AutoSyncNotRunning") && names.has("AutoSyncNoRecentSuccess");
  });
  await capture("stale-enabled");
  await pool.query("UPDATE auto_sync_configs SET enabled=FALSE WHERE id=$1", [config.id]);
  await waitFor("disabled provider health alerts clear", async () => !(await alerts()).some(alert => /AutoSync(NotRunning|NoRecentSuccess|Never|ProviderFailures)/.test(alert.labels.alertname)));
  await capture("disabled");
  await Token.delete(imported.token.id);
  await pool.query("DELETE FROM workspaces WHERE id=$1", [workspaceId]);
  workspaceId = null;
  assert.ok((await query(created)).every(sample => Number(sample.value[1]) === 1));
  await capture("deleted");
  const final = await (await fetch(`${prometheus}/api/v1/targets`)).json();
  fs.writeFileSync(path.join(evidence, "targets.json"), JSON.stringify(final, null, 2));
  record("PASS", { provider, checks: ["zero baseline", "committed creation", "replica deduplication", "retry/update exclusion",
    "API restart", "partial outcome", "database failure returns 500", "scrape outage alert", "successful completion freshness",
    "idle window clears", "no counter reset", "stale health alerts", "disabled provider suppresses alerts", "deletion retains total"] });
}
main().catch(error => { record("FAIL", { message: error.message, stack: error.stack }); process.exitCode = 1; }).finally(async () => {
  for (const entry of servers) await closeServer(entry.server);
  const result = spawnSync("docker", ["rm", "--force", "--volumes", container], { encoding: "utf8" });
  fs.writeFileSync(path.join(evidence, "cleanup.log"), `${result.stdout || ""}${result.stderr || ""}`);
  if (workspaceId) await pool.query("DELETE FROM workspaces WHERE id=$1", [workspaceId]);
  await workerPool?.end();
  await pool.end();
});
