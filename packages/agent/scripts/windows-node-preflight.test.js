"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

test("checks external Node trust before any runtime probe", { skip: process.platform !== "win32" }, () => {
  const script = path.join(__dirname, "test-windows-node-preflight.ps1");
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", script], {
    encoding: "utf8", timeout: 30000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /PASS: trusted path reaches both Node probes/);
  assert.equal((result.stdout.match(/rejected before Node/g) || []).length, 8);
});
