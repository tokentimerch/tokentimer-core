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
test("IIS fixture refuses existing selectors and incomplete native inventories", () => {
  const { selectNativeEndpoint } = require("./host/iis-fixture");
  const row = { keyedBy: "hostnameport", ipPort: "LOCALHOST:443", thumbprint: "A".repeat(40) };
  assert.equal(selectNativeEndpoint({ ok: true, bindings: [row] }, "hostnameport", "localhost:443"), row);
  assert.equal(selectNativeEndpoint({ ok: true, bindings: [row] }, "ipport", "127.0.0.1:443"), null);
  assert.throws(() => selectNativeEndpoint({ ok: false, bindings: [] }, "ipport", "127.0.0.1:443"));
  assert.throws(() => selectNativeEndpoint({ ok: true, bindings: [{ keyedBy: "ipport", ipPort: null }] }, "ipport", "127.0.0.1:443"));
  assert.throws(() => selectNativeEndpoint({ ok: true, bindings: [row, row] }, "hostnameport", "localhost:443"));
});
test("IIS fixture preserves endpoints with foreign ownership", () => {
  const { assertOwnedNativeEndpoint } = require("./host/iis-fixture");
  const row = { appId: "owned", storeName: "MY", thumbprint: "A".repeat(40) };
  const certificates = [{ thumbprint: row.thumbprint }];
  assert.doesNotThrow(() => assertOwnedNativeEndpoint(row, row, certificates));
  assert.doesNotThrow(() => assertOwnedNativeEndpoint(null, row, certificates));
  assert.throws(() => assertOwnedNativeEndpoint(row, null, certificates));
  assert.throws(() => assertOwnedNativeEndpoint({ ...row, appId: "foreign" }, row, certificates));
  assert.throws(() => assertOwnedNativeEndpoint({ ...row, thumbprint: "B".repeat(40) }, row, certificates));
  assert.throws(() => assertOwnedNativeEndpoint({ ...row, storeName: "WebHosting" }, row, certificates));
});
test("IIS rebind receipts accept only exact owned selector and certificate commands", () => {
  const { recordOwnedAppId, assertOwnedNativeEndpoint } = require("./host/iis-fixture");
  const id = "01234567-89ab-cdef-0123-456789abcdef", thumb = "A".repeat(40), selector = "ipport=127.0.0.1:1234";
  const receipts = new Map(), certificates = [{ thumbprint: thumb }];
  const command = ["http", "add", "sslcert", selector, `certhash=${thumb}`, `appid={${id}}`, "certstorename=My"];
  recordOwnedAppId(command, [selector], certificates, receipts);
  const receipt = { appId: "original", appIds: [receipts.get(selector)] };
  assert.doesNotThrow(() => assertOwnedNativeEndpoint({ appId: `{${id}}`, storeName: "My", thumbprint: thumb }, receipt, certificates));
  assert.throws(() => assertOwnedNativeEndpoint({ appId: "foreign", storeName: "My", thumbprint: thumb }, receipt, certificates));
  assert.throws(() => assertOwnedNativeEndpoint({ appId: "original", storeName: "My", thumbprint: thumb }, receipt, certificates));
  const foreign = new Map();
  recordOwnedAppId(command, ["ipport=127.0.0.1:9999"], certificates, foreign);
  recordOwnedAppId(command, [selector], [{ thumbprint: "B".repeat(40) }], foreign);
  assert.equal(foreign.size, 0);
});
test("retention fixture preserves unowned or changed HTTP.sys bindings", () => {
  const { ownedBinding, verifyBindingReceipt } = require("./host/retention-fixture");
  const row = { kind: "SslBindingInfo", selector: "127.0.0.1:1234", thumbprint: "A".repeat(40), store: "My", appId: "01234567-89ab-cdef-0123-456789abcdef", flags: 0 };
  const receipt = ownedBinding([row], 1234, row.thumbprint);
  verifyBindingReceipt([row], 1234, row.thumbprint, receipt);
  assert.throws(() => verifyBindingReceipt([row], 1234, row.thumbprint, undefined));
  assert.throws(() => verifyBindingReceipt([{ ...row, appId: "11234567-89ab-cdef-0123-456789abcdef" }], 1234, row.thumbprint, receipt));
  assert.throws(() => ownedBinding([{ ...row, thumbprint: "B".repeat(40) }], 1234, row.thumbprint));
});
test("retention acceptance failure reports only a bounded native code", () => {
  const { assertFixtureAccept } = require("./host/retention-elapsed-fixture");
  assert.doesNotThrow(() => assertFixtureAccept({ ok: true }));
  assert.throws(() => assertFixtureAccept({ ok: false, stderrExcerpt: "private data 0x800B0109" }), error => error.code === "CERTOPS_RETENTION_ACCEPT_H800B0109" && !error.message.includes("private"));
  assert.throws(() => assertFixtureAccept({ ok: false, stage: "repairstore", stdoutExcerpt: "private" }), error => error.code === "CERTOPS_RETENTION_REPAIRSTORE_FAILED");
});
test("native retention store names are case-insensitive but must match", () => {
  const { assertNativeStore } = require("./host/retention-elapsed-fixture");
  assert.doesNotThrow(() => assertNativeStore("MY", "My"));
  assert.doesNotThrow(() => assertNativeStore("WEBHOSTING", "WebHosting"));
  assert.throws(() => assertNativeStore("", "My"), error => error.code === "CERTOPS_RETENTION_STORE_MISSING");
  assert.throws(() => assertNativeStore("WebHosting", "My"), error => error.code === "CERTOPS_RETENTION_STORE_MISMATCH");
});
test("retention endpoint cleanup deletes only an exact receipt and verifies absence", async () => {
  const { cleanupOwnedEndpoint } = require("./host/retention-elapsed-fixture");
  const receipt = { thumbprint: "A".repeat(40), store: "My", appId: "owned" };
  let current = null, removals = 0;
  const read = async () => current;
  const remove = async () => { removals++; current = null; };
  await cleanupOwnedEndpoint({ read, remove, receipt });
  assert.equal(removals, 0);
  current = { ...receipt, appId: "foreign" };
  await assert.rejects(cleanupOwnedEndpoint({ read, remove, receipt }), /Preserve replaced/);
  assert.equal(removals, 0);
  current = { ...receipt };
  await cleanupOwnedEndpoint({ read, remove, receipt });
  assert.equal(removals, 1);
  current = { ...receipt };
  await assert.rejects(cleanupOwnedEndpoint({ read, remove: async () => {}, receipt }), /remains/);
});
test("retention signing root is removed only if its exact public identity remains", async () => {
  const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
  const { withOwnedRetentionRoot } = require("./host/retention-root-fixture");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "retention-root-control-"));
  try {
    fs.copyFileSync(path.join(__dirname, "../src/verify/fixtures/ca.crt.pem"), path.join(directory, "ca.pem"));
    const root = new crypto.X509Certificate(fs.readFileSync(path.join(directory, "ca.pem")));
    let present = false, foreign = false, removed = false;
    const powershell = script => {
      if (script.startsWith("[bool]")) return present ? "True" : "False";
      if (script.startsWith("$c=")) return JSON.stringify({ raw: (foreign ? Buffer.from("foreign") : root.raw).toString("base64"), hasPrivateKey: false });
      if (script.startsWith("Remove-Item")) { removed = true; present = false; return ""; }
      throw new Error("Unexpected test command");
    };
    const run = () => { present = true; };
    assert.equal(await withOwnedRetentionRoot({ powershell, run, workDir: directory, execute: async () => 7 }), 7);
    assert.equal(removed, true); assert.equal(present, false);
    removed = false;
    await assert.rejects(withOwnedRetentionRoot({ powershell, run, workDir: directory, execute: async () => { foreign = true; } }), /Preserve a replaced root/);
    assert.equal(removed, false); assert.equal(present, true);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("native command failures retain only bounded diagnostic metadata", async () => {
  const gate = createHostGate({ suite: "fixture", strict: true, reportPath: null, continueOnFailure: true });
  await gate.preflight();
  const error = Object.assign(new Error("private token and path"), { code: "CERTOPS_NATIVE_COMMAND_FAILED", qualificationCommand: { executable: "powershell.exe", exitStatus: 1, script: "owned-issued-request.ps1", issuedStep: "enumeration", powerShellCode: "PermissionDenied", scriptHead: "private command arguments" } });
  await gate.scenario("owned-command", async () => { throw error; });
  const failure = gate.report.scenarios[0].failure;
  assert.deepEqual(failure.command, { executable: "powershell.exe", exitStatus: 1, script: "owned-issued-request.ps1", issuedStep: "enumeration", powerShellCode: "PermissionDenied" });
  assert.equal(JSON.stringify(failure).includes("private"), false);
  const issuedError = Object.assign(new Error("private"), { code: "CERTOPS_NATIVE_COMMAND_FAILED", qualificationCommand: { executable: "powershell.exe", exitStatus: 1, script: "owned-issued-request.ps1", issuedStep: "connection", issuedHresults: ["0x80070005", "private-value", "0xFFFFFFFF"], issuedCaDiag: ["identity-match", "private-value", "local-open-failure", "english-open-success"] } });
  await gate.scenario("owned-issued-hresult", async () => { throw issuedError; });
  assert.deepEqual(gate.report.scenarios[1].failure.command.issuedHresults, ["0x80070005", "0xFFFFFFFF"]);
  assert.deepEqual(gate.report.scenarios[1].failure.command.issuedCaDiag, ["identity-match", "local-open-failure", "english-open-success"]);
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
test("host wrapper failures retain only the native fixture callsite", async () => {
  const run = createHostGate({ suite: "fixture", reportPath: null });
  await run.preflight();
  const error = new Error("private output");
  error.stack = "Error: private output\n at run (C:\\private\\windows-host.test.js:59:3)\n at check (C:\\private\\retention-fixture.js:40:2)";
  await assert.rejects(run.scenario("native", async () => { throw error; }));
  assert.equal(run.report.scenarios[0].failure.fixtureFrame, "retention-fixture.js:40");
  assert.doesNotMatch(JSON.stringify(run.report), /private/);
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
