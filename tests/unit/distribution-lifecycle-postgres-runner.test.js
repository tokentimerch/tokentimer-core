"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const runner = path.resolve(__dirname, "../../scripts/run-distribution-lifecycle-postgres.cjs");

async function runController(readyAt) {
  let elapsed = 0;
  const calls = [], files = new Map(), errors = [];
  const result = await vm.runInNewContext(fs.readFileSync(runner, "utf8"), {
    __dirname: path.dirname(runner),
    Date: { now: () => elapsed },
    setTimeout(callback, delay) { elapsed += delay; callback(); },
    require(name) {
      if (name === "node:fs") return {
        mkdirSync() {},
        writeFileSync(file, content) { files.set(path.basename(file), content); },
      };
      if (name === "node:crypto") return { randomBytes: size => Buffer.alloc(size, 1) };
      if (name === "node:child_process") return {
        spawnSync(command, args, options) {
          calls.push({ command, args: [...args], options });
          if (command === "docker" && args[0] === "port")
            return { status: 0, stdout: "127.0.0.1:54321\n" };
          if (command === "docker" && args.includes("pg_isready"))
            return { status: elapsed >= readyAt ? 0 : 1 };
          if (command === "docker" && args[0] === "logs")
            return { status: 0, stdout: "PostgreSQL is still initializing\n", stderr: "" };
          return { status: 0, stdout: "passed\n", stderr: "" };
        },
      };
      return require(name);
    },
    process: { execPath: process.execPath, env: {}, stdout: { write() {} }, exitCode: 0 },
    console: { log() {}, error(message) { errors.push(message); } },
  });
  return { calls, files, errors, elapsed, result };
}

function assertCleanup(calls) {
  const cleanup = calls.at(-1);
  assert.equal(cleanup.command, "docker");
  assert.deepEqual(cleanup.args.slice(0, -1), ["rm", "--force", "--volumes"]);
  assert.match(cleanup.args.at(-1), /^tt-distribution-lifecycle-/);
}

test("the real controller accepts PostgreSQL startup beyond fifteen seconds", async () => {
  const { calls, errors, elapsed } = await runController(32000);
  assert.deepEqual(errors, []);
  assert.ok(elapsed >= 32000);
  assert.equal(calls.filter(call => call.command === process.execPath).length, 4);
  const lifecycle = calls.find(call => call.args.includes("tests/postgres/distribution-lifecycle.test.js"));
  assert.ok(lifecycle.args.includes("--test-concurrency=1"), "shared-database files must not overlap their lock fixtures");
  const probes = calls.filter(call => call.args.includes("pg_isready"));
  for (const probe of probes) {
    assert.ok(probe.args.includes("127.0.0.1"), "wait for the final TCP server");
    assert.equal(probe.options.timeout, 10000);
  }
  assertCleanup(calls);
});

test("permanent startup failure is bounded, preserves diagnostics and cleans the owned volume", async () => {
  const { calls, files, errors, elapsed } = await runController(Infinity);
  assert.ok(elapsed >= 120000 && elapsed <= 120250);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /PostgreSQL unavailable/);
  assert.match(files.get("startup.log") || "", /still initializing/);
  assert.equal(calls.filter(call => call.command === process.execPath).length, 0);
  assertCleanup(calls);
});
