"use strict";

// Exercise the real CLI: a successful coverage gate must represent measured
// source lines for its package, including when no functions or branches exist.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const repo = path.resolve(__dirname, "../..");
const script = path.join(repo, "scripts/check-coverage-threshold.js");
function record(source, found = 10, hit = 10) {
  return `SF:${source}\nLF:${found}\nLH:${hit}\nFNF:0\nFNH:0\nBRF:0\nBRH:0\nend_of_record\n`;
}
function run(content, extra = [], canonicalFrontend = false) {
  const directory = canonicalFrontend
    ? path.join(repo, "apps/dashboard/coverage")
    : fs.mkdtempSync(path.join(os.tmpdir(), "coverage-threshold-"));
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, `threshold-${crypto.randomUUID()}.info`);
  fs.writeFileSync(file, content, { flag: "wx" });
  try {
    return spawnSync(process.execPath, [script, "--lcov", file, ...extra], {
      cwd: repo, encoding: "utf8", timeout: 10000,
    });
  } finally {
    fs.unlinkSync(file);
    if (!canonicalFrontend) fs.rmdirSync(directory);
  }
}
const backend = ["--config", "scripts/coverage-floors.cjs", "--package", "backend"];
test("coverage CLI refuses empty, source-free and zero-line reports", () => {
  for (const content of ["", "TN:empty\n", "LF:10\nLH:10\n", record("apps/api/index.js", 0, 0)]) {
    const result = run(content, backend);
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /coverage-check:/);
  }
});
test("coverage CLI refuses malformed, incomplete and inconsistent evidence", () => {
  for (const content of [
    "SF:apps/api/index.js\nLF:wat\nLH:0\nend_of_record\n",
    "SF:apps/api/index.js\nLF:10\nend_of_record\n",
    "SF:apps/api/index.js\nLF:10\nLH:10\n",
    record("apps/api/index.js", 10, 11),
    record("apps/api/index.js").replace("FNH:0", "FNH:1"),
    record("apps/api/index.js").replace("FNH:0\n", ""),
    record("apps/api/index.js").replace("BRF:0\n", ""),
    record("apps/api/index.js").replace("LF:10", "LF:10:garbage"),
  ]) assert.equal(run(content, backend).status, 1);
});
test("backend gate accepts actual source paths and legitimate zero functions or branches", () => {
  for (const source of [
    "apps/api/index.js", "apps/worker/src/runner.js", "packages/config/index.js",
    "C:\\work\\core\\apps\\api\\index.js", "file:///C:/work/core/apps/api/index.js",
  ]) {
    const result = run(record(source), backend);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /lines: 100/);
  }
  assert.equal(run("SF:apps/api/index.js\nLF:10\nLH:10\nend_of_record\n", backend).status, 0);
});
test("unrelated sources cannot fill the selected package's coverage floor", () => {
  assert.equal(run(record("tests/unit/example.test.js"), backend).status, 1);
  const result = run(record("apps/api/index.js", 100, 10) + record("tests/unit/example.test.js", 1000, 1000), backend);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /lines 10 < 50/);
});
test("frontend gate accepts canonical dashboard-relative and repository-relative reports", () => {
  const flags = ["--config", "scripts/coverage-floors.cjs", "--package", "frontend"];
  assert.equal(run(record("src/App.jsx"), flags, true).status, 0);
  assert.equal(run(record("apps/dashboard/src/App.jsx"), flags).status, 0);
  assert.equal(run(record("apps/api/index.js"), flags).status, 1);
  assert.equal(run(record("src/App.jsx"), flags).status, 1);
});
test("generic CLI thresholds and package validation keep their existing behavior", () => {
  assert.equal(run(record("custom/source.js", 10, 5), ["--lines", "50"]).status, 0);
  assert.equal(run(record("custom/source.js", 10, 4), ["--lines", "50"]).status, 1);
  assert.equal(run(record("apps/api/index.js"), ["--config", "scripts/coverage-floors.cjs", "--package", "missing"]).status, 1);
});
