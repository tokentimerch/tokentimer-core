"use strict";
// Pure evidence/adversarial controls and compile-only checks. No SCM, IIS,
// HTTP.sys, certificate-store or CNG operation is invoked on this workstation.
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const interposer = require("../tests/e2e/helpers/certops-windows-bind-interposer");
const helper = require("../tests/e2e/helpers/certops-windows-installed-bind-failure-native");
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const {fixture:proof,nativeReceipt:receipt}=require('./fixtures/certops-windows-installed-bind-failure-native.cjs');
const expected = p => ({ jobId: p.jobId, selector: p.selector, predecessor: p.predecessorThumbprint, candidate: p.candidateThumbprint });
test("native binding receipt rejects shim errors, fake success, overflow, drainage and foreign selectors", () => {
  const p = receipt(); assert.equal(interposer.verifyNativeReceipt(p, expected(p)), true);
  for (const change of [{ forwardedExitCode: 197 }, { forwardedExitCode: 0 }, { nativeErrorCode: 1312 }, { seedExitCode: 1 }, { captureOverflow: true }, { drainFailure: true }, { nativeChildrenDrained: false }, { certificateStoreModified: true }, { selector: "foreign.example:443" }, { candidateThumbprint: "D".repeat(40) }, { originalArgvSha256: "f".repeat(64) }]) assert.throws(() => interposer.verifyNativeReceipt({ ...p, ...change }, expected(p)));
  for (const change of [ [...p.originalArgv, "hostnameport=foreign.example:443"], [...p.originalArgv.slice(0, 4), "certhash=" + "A".repeat(40), ...p.originalArgv.slice(5)] ]) assert.throws(() => interposer.verifyNativeReceipt({ ...p, originalArgv: change, originalArgvSha256: sha(JSON.stringify(change)) }, expected(p)));
  for (const change of [{ jobId: "-".repeat(36) }, { selector: "*:443" }, { selector: "owned.example.test:99999" }, { predecessorThumbprint: "not-a-thumbprint" }]) { const bad = { ...p, ...change }; assert.throws(() => interposer.verifyNativeReceipt(bad, expected(bad))); }
  for (const argv of [p.originalArgv.filter(arg => !arg.startsWith("appid=")), [...p.originalArgv, p.originalArgv.find(arg => arg.startsWith("appid="))]]) assert.throws(() => interposer.verifyNativeReceipt({ ...p, originalArgv: argv, originalArgvSha256: sha(JSON.stringify(argv)) }, expected(p)));
});
test("native bind proof requires current-job native fault, actual rollback and restored service environment", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) { const bad = proof(); delete bad[key]; assert.throws(() => helper.verifyProof(bad), key); }
  for (const change of [{ rolledBack: false }, { failureCode: "VERIFY_FAILED" }, { serviceEnvironmentRestored: false }, { scope: "installed-public-bind-failure-injection-and-rollback" }, { retryJobStatus: "failed" }, { fingerprints: ["d".repeat(64), "b".repeat(64), "a".repeat(64)] }]) assert.throws(() => helper.verifyProof({ ...proof(), ...change }));
});
test("retained native source extraction fails closed and default launch remains NUL", () => {
  const source = fs.readFileSync(path.join(__dirname, "../tests/e2e/helpers/certops-windows-contained-process.ps1"), "utf8");
  const program = fs.readFileSync(path.join(__dirname, "../tests/e2e/helpers/certops-windows-bind-interposer.cs"), "utf8");
  const combined = interposer.launcherSource(source, program);
  assert.match(combined, /AssignProcessToJobObject/); assert.match(combined, /CreateProcess\([\s\S]*0x08000004/);
  assert.match(combined, /captureOverflow=false,drainFailure=false/);
  assert.match(combined, /LastNativeOutput[\s\S]*183/); assert.doesNotMatch(program, /store\.Remove|DeleteKey|DeletePrivateKey|DeleteSubKey|netsh.*reset/i);
  assert.throws(() => interposer.launcherSource("", program)); assert.throws(() => interposer.launcherSource(source + source, program));
});
test("manual native workflow has both Server SKUs and actual producer rather than parser-only success", () => {
  const workflow = fs.readFileSync(path.join(__dirname, "../.github/workflows/certops-windows-installed-bind-failure.yml"), "utf8");
  assert.match(workflow, /workflow_dispatch:/); assert.doesNotMatch(workflow, /pull_request:|\n  push:|\n  schedule:/);
  assert.match(workflow, /windows_server: \[windows-2022, windows-2025\]/);
  assert.match(workflow, /scripts\/certops-windows-bind-failure-native\.js/);
});
