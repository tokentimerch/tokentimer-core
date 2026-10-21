"use strict";

// The qualification gate can keep running after an isolated journey fails (continue-on-failure), but a
// run that did so must still end as failed and must never validate as release evidence.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const softFailures = require("../tests/e2e/helpers/certops-adcs-soft-failures");
const { verifyReport } = require("./certops-qualification-report");

async function gateWith(options) {
  const gate = createHostGate({ suite: "enterprise-adcs-real", strict: true, candidateSha: "a".repeat(40), requiredCapabilities: ["api"], probeCapabilities: async () => ({ api: { available: true } }), ...options });
  await gate.preflight();
  return gate;
}

test("default mode stops at the first failed scenario exactly as before", async () => {
  const gate = await gateWith({ continueOnFailure: false });
  await assert.rejects(gate.scenario("first", async () => { throw new Error("boom"); }), /boom/);
  assert.equal(gate.report.scenarios[0].status, "failed");
  assert.equal(gate.report.scenarios[0].failure, undefined);
  assert.equal(await gate.guard("cleanup", async () => 7), 7);
  await assert.rejects(gate.guard("cleanup", async () => { throw new Error("raised"); }), /raised/);
});

test("continue mode records every failure, keeps running and still ends failed", async () => {
  const gate = await gateWith({ continueOnFailure: true });
  await gate.scenario("first", async () => { throw Object.assign(new Error("first token=SECRETVALUE"), { code: "CERTOPS_EXAMPLE" }); });
  await gate.scenario("second", async () => {});
  await gate.guard("scratch-cleanup", async () => { throw new Error("cleanup failed"); });
  await gate.scenario("third", async () => { throw new TypeError("third"); });
  assert.deepEqual(gate.report.scenarios.map((row) => row.status), ["failed", "passed", "failed"]);
  assert.equal(gate.report.scenarios[0].failure.errorCode, "CERTOPS_EXAMPLE");
  assert.equal(gate.report.scenarios[2].failure.errorClass, "TypeError");
  assert.equal(gate.report.scenarios[2].failure.afterEarlierFailure, true);
  assert.equal(gate.report.guardedFailures.length, 1);
  assert.equal(gate.report.continueOnFailure, true);
  assert.equal(gate.report.status, "failed");
  await assert.rejects(gate.finish({ requiredScenarios: ["first", "second", "third"] }), /Host qualification incomplete/);
  assert.equal(gate.report.status, "failed");
  assert.doesNotMatch(JSON.stringify(gate.report), /SECRETVALUE|first token/, "release-shaped reports carry no messages");
});

test("a failure budget stops a run that is clearly broken", async () => {
  const gate = await gateWith({ continueOnFailure: true, maxFailures: 2 });
  await gate.scenario("a", async () => { throw new Error("a"); });
  await gate.scenario("b", async () => { throw new Error("b"); });
  await assert.rejects(gate.scenario("c", async () => { throw new Error("c"); }), /c/);
  assert.equal(gate.report.failureBudgetExhausted, true);
});

test("debug detail adds redacted messages and stack frames only when asked for", async () => {
  const gate = await gateWith({ continueOnFailure: true, debugDetail: true });
  await gate.scenario("x", async () => { throw new Error("denied password=hunter2 for host"); });
  const debug = gate.report.scenarios[0].failure.debug;
  assert.match(debug.message, /denied/);
  assert.doesNotMatch(JSON.stringify(debug), /hunter2/);
  assert.ok(debug.stack.length > 0);
  assert.equal(gate.report.debugDetail, true);
});

test("diagnostic reports never validate as release evidence", () => {
  const base = { schemaVersion: 1, suite: "enterprise-adcs-real", strict: true, status: "passed", finishedAt: new Date().toISOString(), startedAt: new Date(Date.now() - 1000).toISOString(), candidateSha: "a".repeat(40), evidenceLevel: "real-host", scenarios: [], requiredScenarios: [], requiredCapabilities: [], missingCapabilities: [], missingScenarios: [], capabilities: {} };
  for (const marker of [{ debugDetail: true }, { guardedFailures: [] }, { failureBudgetExhausted: true }]) {
    assert.ok(verifyReport({ ...base, ...marker }, ["x"]).includes("Diagnostic reports are not release evidence"));
  }
  assert.ok(!verifyReport(base, ["x"]).includes("Diagnostic reports are not release evidence"));
});

test("journey helpers are guarded only in continue mode and keep their results", async () => {
  const calls = [];
  const state = { continueOnFailure: true, guard: async (label, run) => { calls.push(label); try { return await run(); } catch { return undefined; } } };
  const exported = { qualifyThing: async (value) => { if (value === "bad") throw new Error("bad"); return value; }, other: () => "unchanged" };
  softFailures.wrapExports(exported, "C:\\repo\\tests\\e2e\\helpers\\certops-adcs-thing.js", () => state);
  assert.equal(await exported.qualifyThing("ok"), "ok");
  assert.equal(await exported.qualifyThing("bad"), undefined);
  assert.equal(exported.other(), "unchanged");
  assert.deepEqual(calls, ["certops-adcs-thing.qualifyThing", "certops-adcs-thing.qualifyThing"]);
  state.continueOnFailure = false;
  await assert.rejects(exported.qualifyThing("bad"), /bad/);
});

test("a scenario whose journey failure was swallowed by the guard is reported as failed", async () => {
  const gate = await gateWith({ continueOnFailure: true });
  await gate.scenario("outer", async () => {
    await gate.scenario("inner", async () => {
      await gate.guard("journey.qualifyThing", async () => { throw new Error("timed out"); });
    });
  });
  await gate.scenario("clean", async () => {});
  assert.deepEqual(gate.report.scenarios.map((row) => row.status), ["failed", "failed", "passed"]);
  assert.equal(gate.report.scenarios[1].failure.errorClass, "Error");
  assert.equal(gate.report.status, "failed");
});

test("a hung scenario fails by id after its timeout and later scenarios still run", async () => {
  const gate = await gateWith({ continueOnFailure: true, scenarioTimeoutMs: 50 });
  await gate.scenario("hung", () => new Promise(() => {}));
  await gate.scenario("after", async () => {});
  assert.deepEqual(gate.report.scenarios.map((row) => row.status), ["failed", "passed"]);
  assert.equal(gate.report.scenarios[0].failure.errorCode, "CERTOPS_SCENARIO_TIMEOUT");
  assert.equal(gate.report.status, "failed");
  await assert.rejects(gateWith({ scenarioTimeoutMs: -1 }), /Invalid scenario timeout/);
});
