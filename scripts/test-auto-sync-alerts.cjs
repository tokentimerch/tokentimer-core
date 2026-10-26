"use strict";

// Run the shipped rules through Prometheus's evaluator, not a PromQL imitation.
// Optional --values paths also verify the Core/edition Helm examples verbatim.
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const { spawnSync } = require("node:child_process");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
const root = path.resolve(__dirname, "..");
const image = "prom/prometheus:v3.12.0@sha256:69f5241418838263316593f7274a304b095c40bcf22e57272865da91bd60a8ac";
const args = process.argv.slice(2);
const evidence = args.includes("--evidence") ? path.resolve(args[args.indexOf("--evidence") + 1])
  : path.join(root, ".build", "auto-sync-alert-evidence");
fs.mkdirSync(evidence, { recursive: true });
const rulePath = path.join(root, "deploy/prometheus/auto-sync.rules.yaml");
const rules = yaml.load(fs.readFileSync(rulePath, "utf8"));
const group = rules.groups[0];
const sources = [rulePath, path.join(root, "deploy/helm/examples/values-full-test.yaml"),
  path.join(root, "deploy/helm/examples/values-auto-sync-alerts.yaml")];
for (let i = 0; i < args.length; i++) if (args[i] === "--values") sources.push(path.resolve(args[++i]));
for (const file of sources.slice(1)) {
  const values = yaml.load(fs.readFileSync(file, "utf8"));
  const monitoring = (values.tokentimer || values).monitoring;
  if (values.kind !== "PrometheusRule") assert.equal(monitoring.prometheusRules.enabled, true, `${file}: rules must be enabled`);
  const groups = values.kind === "PrometheusRule" ? values.spec.groups : monitoring.prometheusRules.groups;
  assert.deepEqual(groups.find(g => g.name === group.name), group, `${file}: example drift`);
}
const defaults = { installation: "lab", job: "tokentimer-api", provider: "gitlab" };
function series(name, values, labels = {}) {
  const all = Object.entries({ ...defaults, ...labels }).filter(([, value]) => value !== undefined);
  return { series: `${name}{${all.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(",")}}`, values };
}
function expected(name, labels = {}) {
  const rule = group.rules.find(r => r.alert === name);
  const exp_labels = { ...defaults, ...labels, ...rule.labels };
  for (const [key, value] of Object.entries(exp_labels)) if (value === undefined) delete exp_labels[key];
  return { exp_labels, exp_annotations: Object.fromEntries(Object.entries(rule.annotations).map(([key, value]) =>
    [key, value.replaceAll("{{ $labels.provider }}", exp_labels.provider)])) };
}
const allNames = group.rules.map(rule => rule.alert);
const tests = [];
function scenario(name, input, time, firing = {}) {
  tests.push({ name, interval: "1m", input_series: input,
    alert_rule_test: allNames.map(alertname => ({ eval_time: time, alertname,
      exp_alerts: (firing[alertname] || []).map(labels => expected(alertname, labels)) })) });
}
const enabled = value => series("auto_sync_enabled_configurations", `${value}+0x1600`);
const attempt = value => series("auto_sync_last_attempt_timestamp_seconds", `${value}+0x1600`);
const success = value => series("auto_sync_last_success_timestamp_seconds", `${value}+0x1600`);
const outcome = (status, values, extra = {}) => series("auto_sync_run_outcomes_total", values, { status, ...extra });
scenario("unused providers stay quiet, including zero timestamps", [enabled(0), attempt(0), success(0),
  series("auto_sync_items_created_total", "0+0x1600")], "26h");
scenario("a nonzero first scrape is a baseline, not a newly observed creation", [
  series("auto_sync_items_created_total", "100+0x30")], "15m");
scenario("first creation after an observed zero baseline fires", [
  series("auto_sync_items_created_total", "0+0x4 1+0x20")], "6m", { AutoSyncCreatedAssets: [{}] });
scenario("created assets are deduplicated across API replicas", [
  series("auto_sync_items_created_total", "20+0x4 21+0x20", { instance: "api-a" }),
  series("auto_sync_items_created_total", "20+0x4 21+0x20", { instance: "api-b" })], "6m", { AutoSyncCreatedAssets: [{}] });
scenario("creation notification clears when the window becomes idle", [
  series("auto_sync_items_created_total", "20+0x4 21+0x30")], "21m");
scenario("API restart retaining the database total creates no false activity", [
  series("auto_sync_items_created_total", "21+0x4 _ _ 21+0x20")], "12m");
scenario("replacement target's existing total is not counted as new inventory", [
  series("auto_sync_items_created_total", "21+0x5 stale", { instance: "old" }),
  series("auto_sync_items_created_total", "_ _ _ _ _ _ 21+0x20", { instance: "new" })], "12m");
scenario("separate installations do not suppress each other's activity", [
  series("auto_sync_items_created_total", "20+0x4 21+0x20", { installation: "one" }),
  series("auto_sync_items_created_total", "100+0x30", { installation: "two" })], "6m",
  { AutoSyncCreatedAssets: [{ installation: "one" }] });
const failed = "0+0x59 1+0x29 2+0x29 3+0x60";
scenario("three failed outcomes with no successes page once across replicas", [enabled(1),
  outcome("failed", failed, { instance: "api-a" }), outcome("failed", failed, { instance: "api-b" }),
  outcome("success", "0+0x180")], "3h", { AutoSyncProviderFailures: [{}] });
scenario("one failed outcome copied across three replicas does not meet the failure threshold", [enabled(1),
  ...["a", "b", "c"].map(instance => outcome("failed", "0+0x59 1+0x121", { instance })),
  outcome("success", "0+0x180")], "3h");
scenario("a successful completion in the window suppresses provider failure escalation", [enabled(1),
  outcome("failed", failed), outcome("success", "0+0x149 1+0x31")], "3h");
scenario("partial and superseded outcomes do not masquerade as failed", [enabled(1),
  outcome("failed", "0+0x180"), outcome("success", "0+0x180"),
  outcome("partial", failed), outcome("superseded", failed)], "3h");
scenario("disabled connections suppress stale and failed-provider health alerts", [enabled(0), attempt(1), success(1),
  outcome("failed", failed), outcome("success", "0+0x180")], "3h");
scenario("disabled connections remain quiet after 26 hours", [enabled(0), attempt(1), success(1)], "26h");
scenario("recent attempts with old success report lack of success, not a stopped worker", [enabled(1),
  series("auto_sync_last_attempt_timestamp_seconds", "0+60x1600"), success(1)], "26h",
  { AutoSyncNoRecentSuccess: [{}] });
scenario("a provider with old attempts and old success reports both stale signals", [enabled(1), attempt(1), success(1)],
  "26h", { AutoSyncNotRunning: [{}], AutoSyncNoRecentSuccess: [{}] });
scenario("new enabled connection has a scheduling grace period", [enabled(1), attempt(0), success(0)], "24h");
scenario("enabled connection which never starts eventually alerts", [enabled(1), attempt(0), success(0)], "26h",
  { AutoSyncNeverStarted: [{}] });
scenario("attempts without any success eventually alert without zero-timestamp false positives", [enabled(1),
  series("auto_sync_last_attempt_timestamp_seconds", "1+60x1600"), success(0)], "26h",
  { AutoSyncNeverSucceeded: [{}] });
scenario("scrape outage is distinct from zero activity and has a grace period", [
  series("up", "0+0x5", { provider: undefined, instance: "api-a" })], "1m");
scenario("sustained scrape outage alerts", [series("up", "0+0x5", { provider: undefined, instance: "api-a" })], "2m",
  { TokenTimerAPIDown: [{ provider: undefined, instance: "api-a" }] });
fs.writeFileSync(path.join(evidence, "rules.yaml"), yaml.dump(rules, { lineWidth: -1 }));
fs.writeFileSync(path.join(evidence, "tests.yaml"), yaml.dump({ rule_files: ["/work/rules.yaml"], evaluation_interval: "1m", tests }, { lineWidth: -1 }));
fs.writeFileSync(path.join(evidence, "sources.json"), JSON.stringify({ at: new Date().toISOString(), image,
  sources: sources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex") })),
  scenarios: tests.map(test => test.name), assertions: tests.length * allNames.length }, null, 2));
const result = spawnSync("docker", ["run", "--rm", "--network=none", "--entrypoint", "/bin/promtool", "-v", `${evidence}:/work:ro`, image,
  "test", "rules", "/work/tests.yaml"], { encoding: "utf8" });
const log = `${result.stdout || ""}${result.stderr || ""}`;
fs.writeFileSync(path.join(evidence, "promtool.log"), log);
process.stdout.write(log);
if (result.error) throw result.error;
assert.equal(result.status, 0, "promtool rule scenarios failed; see saved evidence");
console.log(`${tests.length} scenarios, ${tests.length * allNames.length} alert-state assertions passed; evidence: ${evidence}`);
