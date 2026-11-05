"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHostGate } = require("../packages/agent/scripts/host-gate");

test("CA fixture failures expose only approved script names", async () => {
  const gate = createHostGate({ suite: "fixture", reportPath: null, continueOnFailure: true });
  await gate.preflight();
  for (const script of ["foreign-request.ps1", "owned-ca-checkpoint.ps1", "secret.ps1"]) {
    const error = Object.assign(new Error("private"), { code: "CERTOPS_NATIVE_COMMAND_FAILED", qualificationCommand: { executable: "powershell.exe", exitStatus: 1, script } });
    await gate.scenario(`ca-fixture-${gate.report.scenarios.length}`, async () => { throw error; });
  }
  assert.equal(gate.report.scenarios[0].failure.command.script, "foreign-request.ps1");
  assert.equal(gate.report.scenarios[1].failure.command.script, "owned-ca-checkpoint.ps1");
  assert.equal(gate.report.scenarios[2].failure.command.script, undefined);
  assert.doesNotMatch(JSON.stringify(gate.report), /secret|private/i);
});
