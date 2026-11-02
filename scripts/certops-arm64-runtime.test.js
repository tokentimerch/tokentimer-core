"use strict";
/** Pure proof adversaries and real disposable child-process drain controls.
 * Nothing here runs Windows certificate, CNG, service or trust-store operations. */
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
const fixture = require("./certops-arm64-runtime");
function architecture() { return { productType: 1, build: "26200", cpuArchitectures: [12], platform: "win32", nodeArchitecture: "arm64", powershellArchitecture: "arm64", goHostArchitecture: "arm64", goHostOs: "windows", nodePeMachine: 0xaa64, powershellPeMachine: 0xaa64, goPeMachine: 0xaa64, certreqPeMachine: 0xaa64, certutilPeMachine: 0xaa64, administrator: true }; }
function proof() {
  return { scope: "native-windows11-arm64-cng-public-fixture", architecture: architecture(), helperPeMachine: 0xaa64, helperSha256: "a".repeat(64), helperExecuted: true, serverQualified: false, iisQualified: false, domainAdcsQualified: false, privateCaKeyPersisted: false, cleanupCompleted: true,
    cases: fixture.profiles.map(profile => ({ profile, csrSignatureVerified: true, csrPublicKeyMatchesLeaf: true, dnsSanVerified: true, keyUsageVerified: true, publicLeafSignatureVerified: true, nativeAssociationVerified: true, nativeSignatureVerified: true, protectedExportDenied: true, exportableControlSucceeded: true, privateBuffersZeroed: true, custodyUnchanged: true, machineStoreReferenceFound: true, exactReferenceExcluded: true, ownedArtifactsAbsent: true, chainVerdict: "revocation_unknown", wrongPinVerdict: "ca_key_changed", malformedVerdict: "invalid", storesScanned: 5, privateExportHResult: -2146893813 })) };
}
test("native architecture rejects emulation, mixed inbox binaries and server relabeling", () => {
  assert.equal(fixture.verifyArchitecture(architecture()), true);
  for (const [field, value] of [["productType", 3], ["build", "19045"], ["cpuArchitectures", [12, 9]], ["nodeArchitecture", "x64"], ["powershellArchitecture", "x64"], ["goHostArchitecture", "amd64"], ["goPeMachine", 0x8664], ["certreqPeMachine", 0xa641], ["certutilPeMachine", 0xa64e], ["administrator", false]]) assert.throws(() => fixture.verifyArchitecture({ ...architecture(), [field]: value }));
});
test("bounded ARM64 proof refuses missing profiles, custody facts, fabricated success and widened scope", () => {
  assert.equal(fixture.verifyProof(proof()), true);
  for (const field of ["helperExecuted", "cleanupCompleted"]) { const value = proof(); value[field] = false; assert.throws(() => fixture.verifyProof(value)); }
  for (const field of ["serverQualified", "iisQualified", "domainAdcsQualified", "privateCaKeyPersisted"]) { const value = proof(); value[field] = true; assert.throws(() => fixture.verifyProof(value)); }
  for (const field of Object.keys(proof().cases[0]).filter(name => typeof proof().cases[0][name] === "boolean")) { const value = proof(); value.cases[0][field] = false; assert.throws(() => fixture.verifyProof(value)); }
  for (const mutate of [value => value.cases.pop(), value => value.cases[1] = value.cases[0], value => value.cases[0].chainVerdict = "valid", value => value.cases[0].wrongPinVerdict = "revocation_unknown", value => value.cases[0].storesScanned = 0, value => value.cases[0].privateExportHResult = 0, value => value.privateBuffer = "unexpected", value => value.cases[0].rawInventory = []]) { const value = proof(); mutate(value); assert.throws(() => fixture.verifyProof(value)); }
});
test("PE parser rejects truncated headers and records ARM64EC distinctly", () => {
  const bytes = Buffer.alloc(128); bytes.writeUInt16LE(0x5a4d, 0); bytes.writeUInt32LE(64, 60); bytes.writeUInt32LE(0x4550, 64); bytes.writeUInt16LE(0xaa64, 68);
  assert.equal(fixture.peMachine(bytes), 0xaa64); bytes.writeUInt16LE(0xa641, 68); assert.equal(fixture.peMachine(bytes), 0xa641);
  for (const bad of [Buffer.alloc(63), Buffer.alloc(128), (() => { const value = Buffer.from(bytes); value.writeUInt32LE(127, 60); return value; })()]) assert.throws(() => fixture.peMachine(bad));
});
test("operation guards, exact marker and path bounds refuse cleanup before native code", async () => {
  const runId = crypto.randomUUID(), workDir = path.join(os.tmpdir(), `certops-arm64-${runId}`), file = path.join(os.tmpdir(), `certops-arm64-receipt-${runId}.json`);
  fs.mkdirSync(workDir); fs.writeFileSync(path.join(workDir, ".owner"), runId); fs.writeFileSync(file, "{}");
  const receipt = { schemaVersion: 1, suite: fixture.suite, runId, receiptPath: file, temporaryParent: path.resolve(os.tmpdir()), workDir, ownerPid: process.pid, activeOperation: null, cases: [] };
  try {
    assert.equal(fixture.validateReceipt(receipt, file), receipt);
    for (const mutate of [value => value.activeOperation = "production-cng-csr", value => value.workDir = os.tmpdir(), value => value.ownerPid = -1, value => value.temporaryParent = path.dirname(os.tmpdir()), value => value.cases = [{ profile: "rsa-2048", containerName: `tokentimer-enr-${crypto.randomUUID()}`, absentBeforeCreation: false }]]) { const value = structuredClone(receipt); mutate(value); assert.throws(() => fixture.validateReceipt(value, file)); }
    fs.writeFileSync(file, JSON.stringify({ ...receipt, activeOperation: "production-cng-csr" }));
    await assert.rejects(fixture.cleanup(file), /Undrained operation/); assert.equal(fs.existsSync(workDir), true);
    fs.writeFileSync(path.join(workDir, ".owner"), "foreign"); assert.throws(() => fixture.validateReceipt(receipt, file));
  } finally { assert.equal(path.dirname(path.resolve(workDir)), path.resolve(os.tmpdir())); fs.rmSync(path.join(workDir, ".owner")); fs.rmdirSync(workDir); fs.rmSync(file); }
});
test("real child executor waits for close and retains nonzero native verdict stdout", async () => {
  const executor = fixture.makeExecutor(); assert.equal(executor.drained(), true);
  const pending = executor.result(process.execPath, ["-e", "setTimeout(()=>process.stdout.write('closed'),50)"]); assert.equal(executor.drained(), false);
  assert.equal((await pending).stdout, "closed"); assert.equal(executor.drained(), true);
  await assert.rejects(executor.result(process.execPath, ["-e", "process.stdout.write(JSON.stringify({verdict:'revocation_unknown'}));process.exitCode=1"]), error => error.code === 1 && JSON.parse(error.stdout).verdict === "revocation_unknown");
  assert.equal(executor.drained(), true);
});
test("terminated child permanently withholds operation drain authorization", async () => {
  const executor = fixture.makeExecutor();
  await assert.rejects(executor.result(process.execPath, ["-e", "setInterval(()=>{},1000)"], { timeout: 100 }));
  assert.equal(executor.drained(), false, "A killed native operation cannot authorize cleanup");
});
test("standalone report verifier rejects stale sources, omitted capability and desktop relabeling", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-arm64-report-proof-")), file = path.join(directory, "controlled.json"), repository = path.resolve(__dirname, "..");
  const stamp = "2026-10-14T00:00:00.000Z";
  const makeReport = () => ({ schemaVersion: 1, suite: fixture.suite, strict: true, platform: "win32", architecture: "arm64", nodeVersion: "v24.0.0", candidateSha: process.env.GITHUB_SHA || "a".repeat(40), evidenceLevel: "real-host", status: "passed", startedAt: stamp, finishedAt: stamp, cleanup: { status: "passed" }, requiredScenarios: [...fixture.requiredScenarios], requiredCapabilities: [...fixture.requiredCapabilities], missingScenarios: [], missingCapabilities: [], capabilities: Object.fromEntries(fixture.requiredCapabilities.map(name => [name, { available: true }])), scenarios: fixture.requiredScenarios.map(id => ({ id, status: "passed", evidenceLevel: "real-host", startedAt: stamp, finishedAt: stamp })), nativeArchitectureProbe: architecture(), nativeArm64CngRuntime: proof(), qualificationEnvironment: { osFamily: "windows", osVersion: "desktop-26200", productType: 1, measurement: "native", architecture: "arm64" }, fixtureSources: fixture.requiredSources.map(source => ({ file: source, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(repository, source))).digest("hex") })) });
  try {
    fs.writeFileSync(file, JSON.stringify(makeReport())); assert.equal(fixture.verifyFile(file), true);
    for (const mutate of [report => report.fixtureSources[0].sha256 = "f".repeat(64), report => report.fixtureSources.pop(), report => report.requiredCapabilities.pop(), report => report.capabilities.administrator.available = false, report => report.qualificationEnvironment.osVersion = "2025", report => report.scenarios.pop(), report => report.scenarios[0].status = "skipped", report => report.cleanup.status = "failed"]) {
      const report = makeReport(); mutate(report); fs.writeFileSync(file, JSON.stringify(report)); assert.throws(() => fixture.verifyFile(file));
    }
  } finally { assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir())); fs.rmSync(file); fs.rmdirSync(directory); }
});
