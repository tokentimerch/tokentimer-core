"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { concurrency, run } = require("./run-certops-tooling-tests");

test("tooling rejects invalid worker overrides instead of changing test selection", () => {
  for (const value of ["0", "-1", "1.5", "17", "4 --test-name-pattern=skip", "NaN"]) assert.throws(() => concurrency(value));
  assert.equal(concurrency("4"), 4);
  assert.throws(() => run({ files: [] }), /Empty tooling/);
});

test("tooling subprocess propagates assertion failure and timeout as failures", { timeout: 15000 }, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-tooling-runner-"));
  const file = path.join(root, "fixture.test.cjs");
  try {
    fs.writeFileSync(file, 'require("node:test")("fixture", () => {});');
    assert.equal(run({ files: [file], workers: 1, stdio: "pipe", timeoutMs: 5000 }).exitCode, 0);
    fs.writeFileSync(file, 'require("node:test")("fixture", () => { throw new Error("deliberate fixture failure"); });');
    assert.equal(run({ files: [file], workers: 1, stdio: "pipe", timeoutMs: 5000 }).exitCode, 1);
    fs.writeFileSync(file, 'require("node:test")("fixture", () => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2000); });');
    const timed = run({ files: [file], workers: 1, stdio: "pipe", timeoutMs: 100 });
    assert.equal(timed.error?.code, "ETIMEDOUT");
    assert.equal(timed.exitCode, 1);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
