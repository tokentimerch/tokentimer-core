"use strict";
// Exercise the CLI with owned subprocess fixtures; no Docker host or real secret is used.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

function invoke(fail = false, diagnostic = "") {
  const project = "tt-wildcard-ux-ci-privacy";
  const sentinel = "private-audit-fixture-must-not-reach-console";
  const messages = [], artifacts = [];
  const entry = { exports: {} };
  const processFixture = {
    argv: ["node", "audit.js", project, "owned/privacy.json", JSON.stringify([
      "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002",
    ])],
    env: { TT_UX_CORE_COMMIT: "a".repeat(40), TT_UX_CERTIFICATE_MODE: "wildcard" },
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "certops-distribution-privacy.js"), "utf8"), {
    module: entry, process: processFixture,
    console: { log: value => messages.push(value), error: value => messages.push(value) },
    require: Object.assign(name => {
      if (name === "node:fs") return { mkdirSync() {}, writeFileSync: (_, data) => artifacts.push(data) };
      if (name === "node:child_process") return { spawnSync: (_, args) => {
        if (fail) return { status: 1, stdout: sentinel, stderr: diagnostic + sentinel };
        if (args[0] === "inspect") return { status: 0, stdout: project };
        if (args.includes("node")) return { status: 0, stdout: JSON.stringify({ evidence: sentinel }) };
        return { status: 0, stdout: sentinel, stderr: sentinel };
      } };
      return require(name);
    }, { main: entry }),
  });
  return { messages, artifacts, sentinel, processFixture, audit: entry.exports.audit };
}

test("privacy CLI preserves evidence artifact without logging audit data or metadata", () => {
  const result = invoke();
  assert.deepEqual(result.messages, ["Owned distribution zero-custody audit completed"]);
  const report = JSON.parse(result.artifacts[0]);
  assert.equal(report.evidence, result.sentinel);
  assert.equal(report.candidateSha, "a".repeat(40));
  assert.equal(report.certificateMode, "wildcard");
  assert.equal(result.processFixture.exitCode, undefined);
});

test("privacy CLI failure logs only a fixed message and publishes no artifact", () => {
  const result = invoke(true);
  assert.deepEqual(result.messages, ["Owned distribution zero-custody audit failed"]);
  assert.equal(result.artifacts.length, 0);
  assert.equal(result.processFixture.exitCode, 1);
});

test("customer auditor adopts only the protected issuer token owner before historical reads", () => {
  const entry = { exports: {} };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../tests/wildcard-vault/ux-lab/privacy-audit.cjs"), "utf8"), {
    module: entry, require: Object.assign(name => require(name), { main: {} }),
    process: { stdin: { setEncoding() {}, on() {} } }, console,
  });
  const { adoptTokenOwner } = entry.exports;
  const calls = [], runtime = { getuid: () => 0, setgid: id => calls.push(["gid", id]), setuid: id => calls.push(["uid", id]) };
  const stat = { isFile: () => true, isSymbolicLink: () => false, uid: 10001, gid: 10001, mode: 0o100600 };
  const options = value => ({ fileSystem: { lstatSync: () => value }, runtime });
  adoptTokenOwner("/lab/issuer/material-token", options(stat));
  assert.deepEqual(calls, [["gid", 10001], ["uid", 10001]]);
  calls.length = 0;
  adoptTokenOwner("/lab/issuer/material-token", options({ ...stat, uid: 0, gid: 0 }));
  assert.deepEqual(calls, []);
  for (const change of [{ uid: 10002 }, { gid: 10002 }, { mode: 0o100644 }, { isSymbolicLink: () => true }, { isFile: () => false }])
    assert.throws(() => adoptTokenOwner("/lab/issuer/material-token", options({ ...stat, ...change })));
  assert.throws(() => adoptTokenOwner("/arbitrary/credential", options(stat)));
  assert.deepEqual(calls, []);
});

test("privacy failures expose only an allowlisted phase and numeric counters", () => {
  const marker = "CERTOPS_PRIVACY_FAILURE=history:3:12:4";
  const result = invoke(true, marker + "\n");
  assert.throws(() => result.audit(result.processFixture.argv[2], "owned/privacy.json", JSON.parse(result.processFixture.argv[4])), error => {
    assert.ok(error.message.includes(marker));
    assert.ok(!error.message.includes(result.sentinel));
    return true;
  });
  const unsafe = invoke(true, "CERTOPS_PRIVACY_FAILURE=history:private-material\n");
  assert.throws(() => unsafe.audit(unsafe.processFixture.argv[2], "owned/privacy.json", JSON.parse(unsafe.processFixture.argv[4])), error => {
    assert.ok(!error.message.includes("private-material"));
    assert.ok(!error.message.includes("CERTOPS_PRIVACY_FAILURE"));
    return true;
  });
});
