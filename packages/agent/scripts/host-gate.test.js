/**
 * Regression tests for strict prerequisite handling, mandatory scenario accounting and
 * bounded qualification evidence. Uses controlled probes and temporary report files;
 * these tests verify the evidence mechanism and do not certify a native Windows host. */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { createHostGate, classifyWindowsHost } = require("./host-gate");
const { verifyReport } = require("../../../scripts/certops-qualification-report");
test("HTTP.sys failures expose only a fixed stage code", async () => {
  const { annotateFailure } = require("./host/discovery-http-sys-fixture");
  const run = createHostGate({ suite: "fixture", reportPath: null });
  await run.preflight();
  const error = annotateFailure(new Error("private path"), "CERTIFICATE_WEBHOSTING");
  await assert.rejects(run.scenario("http-sys", async () => { throw error; }));
  assert.equal(run.report.scenarios[0].failure.errorCode, "CERTOPS_HTTP_SYS_CERTIFICATE_WEBHOSTING");
  assert.doesNotMatch(JSON.stringify(run.report), /private path/);
  assert.equal(annotateFailure(new Error(), "private path").code, "CERTOPS_HTTP_SYS_OTHER");
});
test("HTTP.sys fixture refuses existing selectors using native registry observations", () => {
  const { hasSelector } = require("./host/discovery-http-sys-fixture");
  assert.equal(hasSelector([{ selector: "EXAMPLE.test:443" }], "example.test:443"), true);
  assert.equal(hasSelector([{ selector: "example.test:443" }], "example.test:444"), false);
  assert.throws(() => hasSelector([{}], "example.test:443"));
});

test("native command failures retain only bounded diagnostic metadata", async () => {
  const gate = createHostGate({ suite: "fixture", strict: true, reportPath: null, continueOnFailure: true });
  await gate.preflight();
  const error = Object.assign(new Error("private token and path"), { code: "CERTOPS_NATIVE_COMMAND_FAILED", qualificationCommand: { executable: "powershell.exe", exitStatus: 1, script: "owned-issued-request.ps1", issuedStep: "enumeration", powerShellCode: "PermissionDenied", scriptHead: "private command arguments" } });
  await gate.scenario("owned-command", async () => { throw error; });
  const failure = gate.report.scenarios[0].failure;
  assert.deepEqual(failure.command, { executable: "powershell.exe", exitStatus: 1, script: "owned-issued-request.ps1", issuedStep: "enumeration", powerShellCode: "PermissionDenied" });
  assert.equal(JSON.stringify(failure).includes("private"), false);
  const issuedError = Object.assign(new Error("private"), { code: "CERTOPS_NATIVE_COMMAND_FAILED", qualificationCommand: { executable: "powershell.exe", exitStatus: 1, script: "owned-issued-request.ps1", issuedStep: "connection", issuedHresults: ["0x80070005", "private-value", "0xFFFFFFFF"] } });
  await gate.scenario("owned-issued-hresult", async () => { throw issuedError; });
  assert.deepEqual(gate.report.scenarios[1].failure.command.issuedHresults, ["0x80070005", "0xFFFFFFFF"]);
  const second = Object.assign(new Error("secret"), { code: "CERTOPS_NATIVE_COMMAND_FAILED", qualificationCommand: { executable: "powershell.exe", exitStatus: 1, powerShellCode: "Issued leaf uses a foreign native key" } });
  await gate.scenario("owned-command-classification", async () => { throw second; });
  assert.equal(gate.report.scenarios[2].failure.command.failure, "foreign-native-key");
  assert.equal(JSON.stringify(gate.report.scenarios[2].failure).includes("secret"), false);
});

test("an outside-scenario failure survives finish without exposing private details", async () => {
  const gate = createHostGate({ suite: "fixture", strict: true, reportPath: null });
  await gate.preflight();
  await gate.scenario("complete-before-setup-error", async () => {});
  const failure = Object.assign(new Error("password=private-fixture-value ttboot_private_fixture"), { code: "ERR_ASSERTION" });
  failure.stack = "Error: private-fixture-value\n    at setup (C:\\private\\credential-weak-acl-fixture.js:227:3)";
  await gate.recordFailure(failure);
  await gate.recordFailure(new Error("later cleanup diagnostic"));
  await assert.rejects(gate.finish({ requiredScenarios: ["complete-before-setup-error"] }), /Host qualification incomplete/);
  assert.equal(gate.report.status, "failed");
  assert.deepEqual(gate.report.failure, { errorClass: "Error", errorCode: "ERR_ASSERTION", sourceFrame: "credential-weak-acl-fixture.js:227" });
  assert.equal(JSON.stringify(gate.report).includes("private-fixture"), false);
  assert.equal(JSON.stringify(gate.report).includes("C:\\private"), false);
});
test("fail-fast scenarios retain the original bounded failure before cleanup", async () => {
  const run = createHostGate({ suite: "fixture", strict: true, reportPath: null });
  await run.preflight();
  const error = Object.assign(new Error("private-fixture-value"), { code: "ERR_ASSERTION" });
  error.stack = "Error: private-fixture-value\n    at check (C:\\private\\orphan-journal-fixture.js:317:7)";
  await assert.rejects(run.scenario("owned-key-check", async () => { throw error; }));
  assert.deepEqual(run.report.scenarios[0].failure, { errorClass: "Error", errorCode: "ERR_ASSERTION", sourceFrame: "orphan-journal-fixture.js:317" });
  await run.recordFailure(new AggregateError([error], "private fixture state"));
  assert.equal(JSON.stringify(run.report).includes("private-fixture-value"), false);
  assert.equal(JSON.stringify(run.report).includes("C:\\private"), false);
});
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
