"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const path = require("node:path");

test("production API loads both limiter boundaries before attempting database startup", { timeout: 30_000 }, async (t) => {
  const root = path.resolve(__dirname, "../..");
  const child = spawn(process.execPath, [path.join(root, "apps/api/index.js")], {
    cwd: root,
    env: { ...process.env, NODE_ENV: "production", SESSION_SECRET: "synthetic-startup-test-session-secret", CERTOPS_ENABLED: "false", DB_HOST: "127.0.0.1", DB_PORT: "1", DB_NAME: "startup_test", DB_USER: "test", DB_PASSWORD: "test", DISABLE_ADMIN_BOOTSTRAP: "true" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let output = "";
  const result = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve("timeout"), 25_000);
    const finish = (value) => { clearTimeout(timer); resolve(value); };
    const observe = (chunk) => { output += chunk.toString(); if (/Database connection attempt/.test(output)) finish("database"); };
    child.stdout.on("data", observe);
    child.stderr.on("data", observe);
    child.once("error", (error) => finish(error.message));
    child.once("exit", (code) => finish(`exit ${code}`));
  });
  assert.equal(result, "database", output.slice(-3000));
  assert.doesNotMatch(output, /circular dependency|is not a function|is not defined/i);
});
