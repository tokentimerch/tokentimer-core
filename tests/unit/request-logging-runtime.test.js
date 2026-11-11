"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

test("production logging preserves correlation under buffering and real HTTP middleware", () => {
  const result = spawnSync(process.execPath, [
    path.resolve(__dirname, "../helpers/request-logging-probe.js"),
    path.resolve(__dirname, "../../apps/api/index.js"),
  ], { encoding: "utf8", timeout: 15000, env: {
    ...process.env, NODE_ENV: "production", LOG_SERVICE_NAME: "tokentimer-core-api", PROBE_EXPECT_SERVICE: "tokentimer-core-api",
  } });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.match(result.stdout, /PROBE_RESULT {"buffered":90,"http":8}/);
  assert.doesNotMatch(result.stdout, /raw-body-marker|raw-path-marker|forged-client-id|forged-metadata/);
});
