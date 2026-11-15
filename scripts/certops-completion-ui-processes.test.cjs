"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { stopOwnedChildren, waitForStartup } = require("./certops-completion-ui-processes.cjs");

function child(source) { return spawn(process.execPath, ["-e", source], { stdio: "ignore", windowsHide: true }); }
function closed(process) { return process.exitCode !== null || process.signalCode !== null ? Promise.resolve() : once(process, "close"); }

test("startup failure stops only the owned live child", async () => {
  const running = child("setInterval(() => {}, 1000)");
  const failed = child("process.exit(1)");
  const unrelated = child("setInterval(() => {}, 1000)");
  try {
    await assert.rejects(waitForStartup([running, failed], async () => false, { timeoutMs: 5000, pollMs: 20 }), /application exited/);
    await closed(running);
    assert.equal(unrelated.exitCode, null);
    assert.equal(unrelated.signalCode, null);
  } finally { stopOwnedChildren([running, failed, unrelated]); await Promise.all([closed(running), closed(failed), closed(unrelated)]); }
});

test("startup timeout stops owned children", async () => {
  const running = child("setInterval(() => {}, 1000)");
  try {
    await assert.rejects(waitForStartup([running], async () => false, { timeoutMs: 50, pollMs: 10 }), /timed out/);
    await closed(running);
  } finally { stopOwnedChildren([running]); await closed(running); }
});
