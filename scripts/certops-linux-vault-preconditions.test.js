"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { spawnSync } = require("node:child_process");

function probe(t, env, mode = "--native-vault-restart", suite = "linux-vault-cleanup") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "vault-precondition-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const entry = "scripts/run-cleanup-completion-acceptance.cjs";
  for (const file of [entry, "scripts/certops-linux-systemd-ownership.js", "scripts/certops-linux-cleanup-case.cjs",
    "packages/contracts/certops/material-cleanup.cjs"]) {
    const target = path.join(root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.resolve(__dirname, "..", file), target);
  }
  const result = spawnSync(process.execPath, [path.join(root, entry), mode], { env, encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 1);
  const report = JSON.parse(fs.readFileSync(path.join(root, "qualification-results", `${suite}-failure.json`), "utf8"));
  assert.equal(report.suite, `${suite}-restart`);
  assert.equal(report.status, "failed");
  assert.equal(report.failures[0].stage, "preconditions");
  assert.doesNotMatch(JSON.stringify(report) + result.stderr, /sensitive-fake-value/);
  return report;
}

test("invalid native environment emits a bounded precondition failure", t => {
  probe(t, { GITHUB_ACTIONS: "false", TT_CLEANUP_ARTIFACT_ID: "sensitive-fake-value" });
});

test("invalid native staging environment emits its own bounded precondition failure", t => {
  probe(t, { GITHUB_ACTIONS: "false", TT_CLEANUP_ARTIFACT_ID: "sensitive-fake-value" }, "--native-staging", "linux-staging");
});

test("missing artifact identity fails before any native work", { skip: process.platform !== "linux" || process.getuid() !== 0 }, t => {
  probe(t, { GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST: "1", RUNNER_TEMP: os.tmpdir(), GITHUB_REF: "refs/heads/main", GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "1", TT_CLEANUP_ARTIFACT_ID: "sensitive-fake-value", TT_CLEANUP_ARTIFACT_SHA256: "a".repeat(64) });
});

test("native OpenBao staging requires the shared distribution candidate", { skip: process.platform !== "linux" || process.getuid() !== 0 }, t => {
  probe(t, {
    GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST: "1",
    RUNNER_TEMP: os.tmpdir(), GITHUB_REF: "refs/heads/main", GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "1",
    TT_CLEANUP_ARTIFACT_ID: "456", TT_CLEANUP_ARTIFACT_SHA256: "a".repeat(64),
  }, "--native-openbao-staging", "linux-openbao-staging");
});
