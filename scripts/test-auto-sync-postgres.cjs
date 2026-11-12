"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

function suiteEnvironments(env) {
  assert.equal(env.NODE_ENV, "test", "Set NODE_ENV=test");
  assert.match(env.DB_NAME || "", /^[a-zA-Z0-9_]+_issue71_test$/, "Use a disposable fencing database");
  assert.match(env.AUTO_SYNC_METRIC_LABELS_DB_NAME || "", /^[a-zA-Z0-9_]+_metric_labels_test$/,
    "Set AUTO_SYNC_METRIC_LABELS_DB_NAME to a separate disposable metric-label database");
  if (env.CI) assert.equal(env.AUTO_SYNC_PROMTOOL_IMAGE, "prom/prometheus:v3.12.0",
    "CI requires the pinned Prometheus parser");
  return [env, { ...env, DB_NAME: env.AUTO_SYNC_METRIC_LABELS_DB_NAME }];
}

function main() {
  const [fencing, labels] = suiteEnvironments(process.env);
  const run = (args, env) => {
    const result = spawnSync(process.execPath, args, {
      cwd: path.resolve(__dirname, ".."), env, stdio: "inherit",
    });
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status || 1);
  };
  run(["--test", "--test-concurrency=1", "--test-force-exit",
    "tests/postgres/auto-sync-fencing.test.js", "tests/postgres/auto-sync-run-metrics.test.js"], fencing);
  run(["apps/api/migrations/migrate.js"], labels);
  run(["--test", "--test-concurrency=1", "--test-force-exit",
    "tests/postgres/auto-sync-metric-labels.test.js"], labels);
}

module.exports = { suiteEnvironments };
if (require.main === module) main();
