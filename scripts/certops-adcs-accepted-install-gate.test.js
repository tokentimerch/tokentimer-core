"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const helper = require("../tests/e2e/helpers/certops-adcs-accepted-install-recovery");
const bound = require("../tests/e2e/helpers/certops-adcs-bound-install-recovery");
const root = path.resolve(__dirname, "..");
const error = /active observation-loss interruption and atomic descendant containment are not qualified/;
const nativeError = /active observation-loss interruption and atomic descendant containment\s*(?:\|\s*)?are\s*(?:\|\s*)?not qualified/;
const blocked = ["accepted-before-bind", "bound-before-complete"];
test("unsafe accepted-install phases remain disabled without an environment bypass", () => {
  for (const name of ["CERTOPS_ADCS_DISPOSABLE_LAB", "CERTOPS_QUALIFICATION_CONTINUE", "CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT"]) {
    const before = process.env[name]; process.env[name] = "1";
    try { for (const phase of blocked) assert.throws(() => helper.assertAcceptedInstallExperimentAvailable(phase), error); }
    finally { if (before === undefined) delete process.env[name]; else process.env[name] = before; }
  }
  for (const phase of [undefined, "none", "keygen_intent", "prepared", "submitting", "installing", "issued"]) assert.doesNotThrow(() => helper.assertAcceptedInstallExperimentAvailable(phase));
});
test("direct helper and both wrappers refuse before accessing the fixture", async () => {
  let touches = 0;
  const context = new Proxy({}, { get() { touches++; throw new Error("Unexpected context access"); } });
  for (const phase of blocked) await assert.rejects(helper.qualifyObservedInstallRecovery(context, phase), error);
  await assert.rejects(helper.qualifyAcceptedInstallRecovery(context), error);
  await assert.rejects(bound.qualifyBoundInstallRecovery(context), error);
  assert.equal(touches, 0);
});
test("the E2E and provisioning gates run before setup", () => {
  const suite = fs.readFileSync(path.join(root, "tests/e2e/certops-adcs-real-e2e.test.js"), "utf8");
  const start = suite.indexOf('test("Domain-backed AD CS real API agent CNG and IIS"');
  const gate = suite.indexOf('.assertAcceptedInstallExperimentAvailable(process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT)', start);
  assert.ok(start >= 0 && gate > start && gate < suite.indexOf('assert.equal(process.platform', start));
  const provision = fs.readFileSync(path.join(root, "infra/certops-adcs/provision-lab.ps1"), "utf8");
  assert.ok(provision.indexOf("if($JournalPhaseExperiment -in") < provision.indexOf(". (Join-Path $PSScriptRoot 'arm-operation.ps1')"));
});
test("Windows scripts reject before observation or Azure access", { skip: process.platform !== "win32" }, () => {
  const dir = path.join(root, "infra/certops-adcs");
  for (const name of ["accepted-install-phase-fault.ps1", "bound-install-phase-fault.ps1"]) {
    const run = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(dir, name), "-OwnedDirectory", "unused", "-ConfigDirectory", "unused", "-RepositoryRoot", "unused", "-NodeExecutable", "unused"], { encoding: "utf8", timeout: 10000 });
    assert.equal(run.status, 1, run.error?.message); assert.match(run.stderr, nativeError); assert.doesNotMatch(run.stdout, /CERTOPS_ACCEPTED_INSTALL_READY/);
  }
  for (const phase of blocked) {
    const run = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(dir, "provision-lab.ps1"), "-ResourceGroup", "tt-certops-11-1", "-Location", "unused", "-JournalPhaseExperiment", phase], { encoding: "utf8", timeout: 10000 });
    assert.equal(run.status, 1, run.error?.message); assert.match(run.stderr, nativeError);
  }
});
