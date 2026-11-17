"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { spawnSync } = require("node:child_process");

function probe(t, env) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "vault-precondition-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const scripts = path.join(root, "scripts");
  fs.mkdirSync(scripts);
  for (const file of ["run-cleanup-completion-acceptance.cjs", "certops-linux-systemd-ownership.js"])
    fs.copyFileSync(path.join(__dirname, file), path.join(scripts, file));
  const result = spawnSync(process.execPath, [path.join(scripts, "run-cleanup-completion-acceptance.cjs"), "--native-vault-restart"], { env, encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 1);
  const report = JSON.parse(fs.readFileSync(path.join(root, "qualification-results", "linux-vault-cleanup-failure.json"), "utf8"));
  assert.equal(report.status, "failed");
  assert.equal(report.failures[0].stage, "preconditions");
  assert.doesNotMatch(JSON.stringify(report) + result.stderr, /sensitive-fake-value/);
  return report;
}

test("invalid native environment emits a bounded precondition failure", t => {
  probe(t, { GITHUB_ACTIONS: "false", TT_CLEANUP_ARTIFACT_ID: "sensitive-fake-value" });
});

test("missing artifact identity fails before any native work", { skip: process.platform !== "linux" || process.getuid() !== 0 }, t => {
  probe(t, { GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST: "1", RUNNER_TEMP: os.tmpdir(), GITHUB_REF: "refs/heads/main", GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "1", TT_CLEANUP_ARTIFACT_ID: "sensitive-fake-value", TT_CLEANUP_ARTIFACT_SHA256: "a".repeat(64) });
});
