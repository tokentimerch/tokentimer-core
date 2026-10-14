/**
 * Regression tests for strict prerequisite handling, mandatory scenario accounting and
 * bounded qualification evidence. Uses controlled probes and temporary report files;
 * these tests verify the evidence mechanism and do not certify a native Windows host. */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { createHostGate, classifyWindowsHost } = require("./host-gate");
const { verifyReport } = require("../../../scripts/certops-qualification-report");
const gate = () => createHostGate({ suite: "fixture", candidateSha: "a".repeat(40), strict: true, requiredCapabilities: ["native"], probeCapabilities: async () => ({ native: { available: true } }) });
test("shared Windows build numbers require native server product type", () => {
  for (const [build, server] of [["17763", "2019"], ["20348", "2022"], ["26100", "2025"]]) {
    assert.equal(classifyWindowsHost(build, 1), `desktop-${build}`);
    assert.equal(classifyWindowsHost(build, 3), server);
    assert.equal(classifyWindowsHost(build, 2), server);
    assert.equal(classifyWindowsHost(build, undefined), "unknown");
  }
  assert.equal(classifyWindowsHost("99999", 3), "unknown");
});
test("strict preflight refuses missing capabilities", async () => {
  const missing = createHostGate({ suite: "fixture", strict: true, requiredCapabilities: ["native"] });
  await assert.rejects(missing.preflight(), /capabilities unavailable/);
  await assert.rejects(missing.scenario("test", async () => {}), /preflight/);
});
test("required named scenarios and completion are verified", async () => {
  const run = gate(); await run.preflight();
  await run.scenario("native-roundtrip", async () => assert.equal(1, 1));
  const report = await run.finish({ requiredScenarios: ["native-roundtrip"] });
  assert.deepEqual(verifyReport(report, ["native-roundtrip"], { expectedSha: "a".repeat(40) }), []);
});
test("missing, skipped, empty and failed runs cannot qualify", async () => {
  const empty = gate(); await empty.preflight(); await assert.rejects(empty.finish(), /incomplete/);
  const skipped = gate(); await skipped.preflight(); await assert.rejects(skipped.skip("native", "fixture"), /skipped/);
  const failed = gate(); await failed.preflight(); await assert.rejects(failed.scenario("native", async () => { throw new Error("assertion"); }), /assertion/);
  await assert.rejects(failed.finish(), /incomplete/);
  const missing = gate(); await missing.preflight(); await missing.scenario("other", async () => {}); await assert.rejects(missing.finish({ requiredScenarios: ["native"] }), /incomplete/);
});
test("persisted evidence excludes raw probe secrets and failed assertion messages", async () => {
  const fs = require("node:fs/promises");
  const path = require("node:path");
  const directory = await fs.mkdtemp(path.join(require("node:os").tmpdir(), "qualification-"));
  const reportPath = path.join(directory, "report.json");
  try {
    const run = createHostGate({ suite: "fixture", strict: true, reportPath, probeCapabilities: async () => ({ native: { available: true, password: "raw-secret", evidence: "token=probe-secret " + "x".repeat(1000) } }) });
    await run.preflight();
    await assert.rejects(run.scenario("failed", async () => { throw new Error("password=assertion-secret"); }));
    const contents = await fs.readFile(reportPath, "utf8");
    assert.equal(/raw-secret|probe-secret|assertion-secret/.test(contents), false);
    const report = JSON.parse(contents);
    assert.equal(report.scenarios[0].status, "failed");
    assert.ok(report.capabilities.native.evidence.length <= 512);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});
test("malformed capability probes fail closed", async () => {
  for (const result of [null, undefined, { native: { available: "true" } }]) {
    const run = createHostGate({ suite: "fixture", strict: true, requiredCapabilities: ["native"], probeCapabilities: async () => result });
    await assert.rejects(run.preflight());
    assert.equal(run.report.status, "failed");
  }
});
test("cleanup failure prevents qualification despite passing scenario", async () => {
  const run = gate(); await run.preflight(); await run.scenario("operation", async () => {});
  await assert.rejects(run.finish({ cleanup: { status: "failed", summary: "fixture remains" } }), /incomplete/);
  assert.equal(run.report.cleanup.status, "failed");
  assert.ok(verifyReport(run.report, ["operation"]).includes("Host cleanup did not pass"));
});
test("completed report persists atomically with explicit cleanup evidence", async () => {
  const fs = require("node:fs/promises");
  const path = require("node:path");
  const directory = await fs.mkdtemp(path.join(require("node:os").tmpdir(), "qualification-success-"));
  try {
    const reportPath = path.join(directory, "report.json");
    const run = createHostGate({ suite: "fixture", strict: true, reportPath, candidateSha: "a".repeat(40) });
    await run.preflight(); await run.scenario("native", async () => {}, { evidenceLevel: "real-host", oracle: "Independent host state" });
    await run.finish({ requiredScenarios: ["native"], cleanup: { status: "passed" } });
    const saved = JSON.parse(await fs.readFile(reportPath, "utf8"));
    assert.deepEqual(verifyReport(saved, ["native"], { expectedSha: "a".repeat(40) }), []);
    assert.equal(saved.cleanup.status, "passed");
    assert.deepEqual(await fs.readdir(directory), ["report.json"]);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});
test("probe evidence redacts bearer values and URI credentials", async () => {
  const run = createHostGate({ suite: "fixture", probeCapabilities: async () => ({ native: { available: true, evidence: "https://probe-user:probe-password@host.invalid Bearer bearer-secret ttboot_bootstrap-secret ttagent_0123456789abcdef_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" } }) });
  await run.preflight();
  assert.doesNotMatch(run.report.capabilities.native.evidence, /probe-user|probe-password|bearer-secret|bootstrap-secret|ttagent_/);
});
