"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { suiteEnvironments } = require("../../scripts/test-auto-sync-postgres.cjs");

const env = { NODE_ENV: "test", DB_NAME: "fencing_issue71_test",
  AUTO_SYNC_METRIC_LABELS_DB_NAME: "owners_metric_labels_test" };
test("auto-sync PostgreSQL runner isolates metric labels without changing the fencing database", () => {
  const [fencing, labels] = suiteEnvironments(env);
  assert.equal(fencing.DB_NAME, "fencing_issue71_test");
  assert.equal(labels.DB_NAME, "owners_metric_labels_test");
  assert.equal(env.DB_NAME, "fencing_issue71_test");
  for (const patch of [{ NODE_ENV: "production" }, { DB_NAME: "production" },
    { AUTO_SYNC_METRIC_LABELS_DB_NAME: undefined }, { AUTO_SYNC_METRIC_LABELS_DB_NAME: env.DB_NAME }]) {
    assert.throws(() => suiteEnvironments({ ...env, ...patch }));
  }
});
test("CI auto-sync qualification requires the pinned Prometheus parser", () => {
  for (const image of [undefined, "prom/prometheus:latest"]) {
    assert.throws(() => suiteEnvironments({ ...env, CI: "true", AUTO_SYNC_PROMTOOL_IMAGE: image }));
  }
  assert.doesNotThrow(() => suiteEnvironments({
    ...env, CI: "true", AUTO_SYNC_PROMTOOL_IMAGE: "prom/prometheus:v3.12.0",
  }));
});
