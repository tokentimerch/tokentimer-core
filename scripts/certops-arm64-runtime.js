"use strict";
/** Manual Windows 11 ARM64 CNG producer. Production certreq/store/chain bridges
 * run against two owned local public leaves. This is not domain CA issuance,
 * Server/IIS/service qualification or published package qualification.
 * Persistent operation guards refuse cleanup after an undrained interruption.
 * The independent workflow cleanup never kills or adopts a process/key. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto"), cp = require("node:child_process");
const contract = require("./certops-arm64-runtime-proof");
const root = path.resolve(__dirname, "..");
const psScript = path.join(__dirname, "certops-arm64-native.ps1");
const requiredSources = Object.freeze([
  "scripts/certops-arm64-runtime.js", "scripts/certops-arm64-runtime-proof.js", "scripts/certops-arm64-native.ps1",
  ".github/workflows/certops-windows-arm64-cng.yml", "packages/agent/scripts/host-gate.js", "packages/agent/scripts/build-windows-chain-helper.js",
  "packages/agent/scripts/host/cng-export-fixture.js", "packages/agent/src/windows-cert-store/index.js", "packages/agent/src/windows-key-survivors/index.js",
  "packages/agent/vendor/log-scrub/secret-material.js",
  "packages/agent/src/issuers/chain-helper.js", "packages/agent/src/issuers/csr-certificate-key.js", "packages/agent/src/issuers/der-extensions.js",
  "packages/agent/reference/adcs-chain/go.mod", "packages/agent/reference/adcs-chain/go.sum", "packages/agent/reference/adcs-chain/main.go",
  "packages/agent/reference/adcs-chain/chaincore/chain_windows.go", "packages/agent/reference/adcs-chain/chaincore/result.go", "packages/agent/reference/adcs-chain/chaincore/trust_map.go",
  "packages/agent/reference/adcs-chain/keyrefs/scan_windows.go", "packages/agent/reference/adcs-chain/keyrefs/result.go",
]);
function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function save(file, value) {
  const temporary = `${file}.${process.pid}.tmp`;
  const fd = fs.openSync(temporary, "wx");
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
}
function validateReceipt(value, file) {
  assert.equal(value.schemaVersion, 1); assert.equal(value.suite, contract.suite); assert.match(value.runId, /^[a-f0-9-]{36}$/);
  assert.equal(value.receiptPath, path.resolve(file));
  assert.equal(path.dirname(value.receiptPath), value.temporaryParent);
  assert.equal(path.basename(value.workDir), `certops-arm64-${value.runId}`);
  assert.equal(path.dirname(value.workDir), value.temporaryParent); assert.equal(path.resolve(value.temporaryParent), path.resolve(os.tmpdir()));
  assert.equal(fs.lstatSync(value.workDir).isSymbolicLink(), false);
  assert.equal(fs.realpathSync(value.workDir).toLowerCase(), path.resolve(value.workDir).toLowerCase());
  assert.equal(fs.lstatSync(file).isSymbolicLink(), false);
  assert.equal(fs.readFileSync(path.join(value.workDir, ".owner"), "utf8"), value.runId);
  assert.ok(Number.isSafeInteger(value.ownerPid) && value.ownerPid > 0);
  assert.equal(value.activeOperation, null, "Undrained operation: preserve owned state");
  assert.ok(Array.isArray(value.cases) && value.cases.length <= 2);
  for (const item of value.cases) {
    assert.ok(contract.profiles.includes(item.profile)); assert.match(item.containerName, /^tokentimer-enr-[a-f0-9-]{36}$/);
    assert.equal(item.absentBeforeCreation, true);
    if (item.uniqueName !== undefined) assert.match(item.uniqueName, /^[a-zA-Z0-9_-]{1,200}$/);
    if (item.thumbprint !== undefined) {
      assert.match(item.thumbprint, /^[A-F0-9]{40}$/);
      const cert = new crypto.X509Certificate(Buffer.from(item.der, "base64"));
      assert.equal(cert.fingerprint.replaceAll(":", ""), item.thumbprint);
    }
    if (item.control) { assert.match(item.control.containerName, /^tokentimer-enr-[a-f0-9-]{36}$/); assert.equal(item.control.absentBeforeCreation, true); assert.equal(item.control.exportPolicy, 3); }
  }
  if (value.root) {
    const cert = new crypto.X509Certificate(Buffer.from(value.root.der, "base64"));
    assert.equal(cert.fingerprint.replaceAll(":", ""), value.root.thumbprint); assert.equal(cert.ca, true);
  }
  return value;
}
function makeExecutor() {
  let pending = 0, uncertain = false;
  function execFile(file, args, options, callback) {
    pending++; let closed = false, result, delivered = false, child;
    const deliver = () => { if (!delivered && closed && result) { delivered = true; callback(...result); } };
    try {
      child = cp.execFile(file, args, { ...options, windowsHide: true }, (...values) => { if (values[0]?.killed || values[0]?.signal) uncertain = true; result = values; deliver(); });
      child.once("close", () => { closed = true; pending--; deliver(); });
      child.once("error", () => { if (child.pid) uncertain = true; });
      return child;
    } catch (error) { pending--; throw error; }
  }
  const result = (file, args, options = {}) => new Promise((resolve, reject) => execFile(file, args, { encoding: "utf8", timeout: 60000, maxBuffer: 128 * 1024, ...options }, (error, stdout, stderr) => { if (error) { error.stdout = stdout; error.stderr = stderr; reject(error); } else resolve({ stdout, stderr }); }));
  const execute = async (file, args, options = {}) => { try { return (await result(file, args, options)).stdout.trim(); } catch { throw new Error(`Native child failed: ${path.basename(file)}`); } };
  return { execFile, execute, result, drained: () => pending === 0 && !uncertain };
}
function nativePe(file) { return contract.peMachine(fs.readFileSync(file)); }
async function context(receiptPath, value) {
  const executor = makeExecutor(); const pwsh = process.env.CERTOPS_ARM64_PWSH;
  assert.ok(pwsh && path.isAbsolute(pwsh), "Explicit native PowerShell path required"); assert.equal(nativePe(pwsh), 0xaa64);
  async function operation(name, action) {
    assert.equal(value.activeOperation, null); value.activeOperation = name; save(receiptPath, value);
    try { return await action(); }
    finally { if (executor.drained()) { value.activeOperation = null; save(receiptPath, value); } }
  }
  const command = script => executor.execute(pwsh, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(`$ErrorActionPreference='Stop';${script}`, "utf16le").toString("base64")]);
  async function native(mode, input) {
    const file = path.join(value.workDir, `public-input-${crypto.randomUUID()}.json`);
    fs.writeFileSync(file, JSON.stringify(input), { flag: "wx" });
    try { return await executor.execute(pwsh, ["-NoProfile", "-NonInteractive", "-File", psScript, "-Mode", mode, "-InputPath", file]); }
    finally { fs.rmSync(file, { force: true }); }
  }
  return { executor, operation, command, native };
}
async function cleanup(receiptPath, { sameOwner = false } = {}) {
  if (!fs.existsSync(receiptPath)) return { status: "absent" };
  const value = validateReceipt(JSON.parse(fs.readFileSync(receiptPath, "utf8")), receiptPath);
  const lock = `${receiptPath}.cleanup-lock`;
  const lockFd = fs.openSync(lock, "wx"); fs.closeSync(lockFd);
  let cleaned = false;
  try {
  const ctx = await context(receiptPath, value);
  if (!sameOwner) {
    const alive = await ctx.command(`$p=Get-Process -Id ${value.ownerPid} -ErrorAction SilentlyContinue;if($p){'present'}else{'absent'}`);
    assert.equal(alive, "absent", "Producer identity/PID still exists; preserve state");
  } else assert.equal(value.ownerPid, process.pid);
  if (value.cases.length) { assert.equal(nativePe(value.helperPath), 0xaa64); assert.equal(sha256(fs.readFileSync(value.helperPath)), value.helperSha256); }
  const { inspectMachineKeySurvivors } = require("../packages/agent/src/windows-key-survivors");
  for (const item of value.cases) {
    if (item.control) {
      assert.ok(item.control.uniqueName, "Unobserved exportable control is preserved");
      const refs = await inspectMachineKeySurvivors({ containerName: item.control.containerName, helperPath: value.helperPath, execFileImpl: ctx.executor.execFile });
      assert.equal(refs.ok, true); assert.equal(refs.shared, false);
      assert.equal(await ctx.operation("remove-control", () => ctx.native("RemoveKey", item.control)), "absent");
    }
    assert.ok(item.uniqueName, "Unobserved CNG creation is preserved");
    if (item.thumbprint) assert.equal(await ctx.operation("remove-public-leaf", () => ctx.native("RemoveLeaf", item)), "absent");
    const refs = await inspectMachineKeySurvivors({ containerName: item.containerName, helperPath: value.helperPath, execFileImpl: ctx.executor.execFile });
    assert.equal(refs.ok, true); assert.equal(refs.shared, false, "Other machine-store certificate protects the key");
    assert.equal(await ctx.operation("remove-owned-key", () => ctx.native("RemoveKey", item)), "absent");
  }
  if (value.root) assert.equal(await ctx.operation("remove-public-root", () => ctx.native("RemoveRoot", value.root)), "absent");
  assert.equal(ctx.executor.drained(), true);
  // No recursive removal on failure. Marker, links and parent bounds are checked
  // again immediately before the final owned temporary directory removal.
  validateReceipt(value, receiptPath);
  for (const entry of fs.readdirSync(value.workDir, { recursive: true, withFileTypes: true })) assert.equal(entry.isSymbolicLink(), false);
  fs.rmSync(value.workDir, { recursive: true }); fs.rmSync(receiptPath);
  cleaned = true;
  return { status: "passed" };
  } finally { if (cleaned) fs.rmSync(lock); }
}
async function main() {
  assert.equal(process.platform, "win32"); assert.equal(process.arch, "arm64");
  assert.equal(process.env.CERTOPS_ARM64_NATIVE_REQUIRED, "1", "Explicit native mutation opt-in required");
  assert.equal(process.env.CERTOPS_QUALIFICATION_STRICT, "1");
  const receiptPath = path.resolve(process.env.CERTOPS_ARM64_RECEIPT || ""); assert.ok(process.env.CERTOPS_ARM64_RECEIPT);
  assert.equal(fs.existsSync(receiptPath), false, "Existing receipt is never adopted");
  const runId = crypto.randomUUID(), temporaryParent = path.resolve(os.tmpdir()), workDir = path.join(temporaryParent, `certops-arm64-${runId}`);
  fs.mkdirSync(workDir); fs.writeFileSync(path.join(workDir, ".owner"), runId, { flag: "wx" });
  const value = { schemaVersion: 1, suite: contract.suite, runId, receiptPath, temporaryParent, workDir, ownerPid: process.pid, activeOperation: null, cases: [] }; save(receiptPath, value);
  const ctx = await context(receiptPath, value); let architecture;
  const { createHostGate } = require("../packages/agent/scripts/host-gate");
  const gate = createHostGate({ suite: contract.suite, strict: true, fixtureSource: { file: "scripts/certops-arm64-runtime.js", sha256: sha256(fs.readFileSync(__filename)) }, requiredCapabilities: contract.requiredCapabilities, probeCapabilities: async () => {
    const observed = JSON.parse(await ctx.native("Probe", { ownerPid: process.pid }));
    const certreqPath = path.join(process.env.SystemRoot, "System32/certreq.exe"), certutilPath = path.join(process.env.SystemRoot, "System32/certutil.exe");
    const goPath = await ctx.command("(Get-Command go -CommandType Application -ErrorAction Stop).Source");
    const { ownerStartTicks, ...publicObserved } = observed;
    architecture = { ...publicObserved, platform: process.platform, nodeArchitecture: process.arch, nodePeMachine: nativePe(process.execPath), powershellPeMachine: nativePe(process.env.CERTOPS_ARM64_PWSH), goPeMachine: nativePe(goPath), certreqPeMachine: nativePe(certreqPath), certutilPeMachine: nativePe(certutilPath), goHostArchitecture: await ctx.executor.execute(goPath, ["env", "GOHOSTARCH"]), goHostOs: await ctx.executor.execute(goPath, ["env", "GOHOSTOS"]) };
    gate.report.nativeArchitectureProbe = architecture;
    gate.report.qualificationEnvironment = { osFamily: "windows", osVersion: `desktop-${architecture.build}`, productType: architecture.productType, measurement: "native", architecture: "arm64" };
    contract.verifyArchitecture(architecture); value.ownerStartTicks = ownerStartTicks; save(receiptPath, value);
    return Object.fromEntries(contract.requiredCapabilities.map(name => [name, { available: true, evidence: "Measured ARM64 desktop/native PE and runtime; administrator" }]));
  } });
  const proof = { scope: "native-windows11-arm64-cng-public-fixture", serverQualified: false, iisQualified: false, domainAdcsQualified: false, privateCaKeyPersisted: false, cases: [] };
  let primary, cleanupResult;
  try {
    await gate.preflight();
    await gate.scenario(contract.requiredScenarios[0], async () => { contract.verifyArchitecture(architecture); proof.architecture = architecture; });
    await gate.scenario(contract.requiredScenarios[1], async () => {
      const builder = require("../packages/agent/scripts/build-windows-chain-helper");
      value.helperPath = builder.buildOne("arm64", workDir, { run: (file, args, options) => cp.spawnSync(file, args, { ...options, timeout: 180000 }) });
      value.helperSha256 = sha256(fs.readFileSync(value.helperPath)); save(receiptPath, value);
      proof.helperPeMachine = nativePe(value.helperPath); proof.helperSha256 = value.helperSha256;
      const name = require("../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(crypto.randomUUID());
      const query = await require("../packages/agent/src/windows-key-survivors").inspectMachineKeySurvivors({ containerName: name, helperPath: value.helperPath, execFileImpl: ctx.executor.execFile });
      assert.equal(query.ok, true); assert.equal(query.shared, false); proof.helperExecuted = true;
    });
    const store = require("../packages/agent/src/windows-cert-store"), custody = require("../packages/agent/scripts/host/cng-export-fixture");
    const certreqPath = path.join(process.env.SystemRoot, "System32/certreq.exe"), certutilPath = path.join(process.env.SystemRoot, "System32/certutil.exe");
    await gate.scenario(contract.requiredScenarios[2], async () => {
      for (const profile of contract.profiles) {
        const enrollmentId = crypto.randomUUID(), containerName = store.buildEnrollmentContainerName(enrollmentId), item = { profile, algorithm: profile, store: "My", containerName };
        const exists = await ctx.command(`[Security.Cryptography.CngKey]::Exists('${containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`);
        assert.equal(exists, "False"); item.absentBeforeCreation = true; value.cases.push(item); save(receiptPath, value);
        const directory = path.join(workDir, profile); fs.mkdirSync(directory);
        const generated = await ctx.operation("production-cng-csr", () => store.generateCsrViaCng({ commonName: `${profile}.certops.invalid`, altNames: [`${profile}.certops.invalid`], enrollmentId, algorithm: profile, workDir: directory, certreqPath, certutilPath, execFileImpl: ctx.executor.execFile }));
        assert.equal(generated.ok, true); assert.equal(generated.containerName, containerName);
        item.csrPath = path.join(directory, "public.csr"); fs.writeFileSync(item.csrPath, generated.csrPem, { flag: "wx" });
        const nativeKey = JSON.parse(await ctx.native("Key", item)); assert.equal(nativeKey.keyName, containerName); item.uniqueName = nativeKey.uniqueName; save(receiptPath, value);
      }
      const signed = JSON.parse(await ctx.native("Sign", { runId, cases: value.cases }));
      assert.equal(signed.rootEphemeralVerified, true);
      const ca = new crypto.X509Certificate(signed.rootPem); assert.equal(ca.ca, true); assert.equal(ca.verify(ca.publicKey), true);
      assert.equal(ca.raw.toString("base64"), signed.rootDer); assert.equal(ca.fingerprint.replaceAll(":", ""), signed.rootThumbprint);
      value.root = { der: signed.rootDer, thumbprint: signed.rootThumbprint }; save(receiptPath, value);
      fs.writeFileSync(path.join(workDir, "ca.pem"), signed.rootPem, { flag: "wx" });
      for (const item of value.cases) {
        const leaf = signed.cases.find(candidate => candidate.profile === item.profile); assert.ok(leaf);
        const certificate = new crypto.X509Certificate(leaf.pem), csr = fs.readFileSync(item.csrPath, "utf8");
        assert.equal(certificate.raw.toString("base64"), leaf.der); assert.equal(certificate.fingerprint.replaceAll(":", ""), leaf.thumbprint);
        assert.equal(certificate.verify(ca.publicKey), true); assert.equal(certificate.checkHost(`${item.profile}.certops.invalid`), `${item.profile}.certops.invalid`);
        assert.equal(require("../packages/agent/src/issuers/csr-certificate-key").certificateMatchesCsr(csr, leaf.pem), true);
        const der = require("../packages/agent/src/issuers/der-extensions");
        assert.deepEqual(der.readKeyUsageNames(certificate.raw).sort(), item.profile === "rsa-2048" ? ["digitalSignature", "keyEncipherment"] : ["digitalSignature"]);
        item.thumbprint = leaf.thumbprint; item.der = leaf.der; item.certPath = path.join(path.dirname(item.csrPath), "leaf.pem"); fs.writeFileSync(item.certPath, leaf.pem, { flag: "wx" }); save(receiptPath, value);
        assert.equal(leaf.csrSignatureVerified, true); assert.equal(leaf.keyUsageVerified, true);
        proof.cases.push({ profile: item.profile, csrSignatureVerified: true, csrPublicKeyMatchesLeaf: true, dnsSanVerified: true, keyUsageVerified: true, publicLeafSignatureVerified: true });
      }
    });
    await gate.scenario(contract.requiredScenarios[3], async () => {
      assert.equal(await ctx.operation("trust-owned-public-root", () => ctx.native("Trust", value.root)), "trusted");
      for (const item of value.cases) {
        const accepted = await ctx.operation("production-public-leaf-acceptance", () => store.acceptCertificateViaCng({ certificatePem: fs.readFileSync(item.certPath, "utf8"), workDir: path.dirname(item.csrPath), store: "My", certreqPath, certutilPath, execFileImpl: ctx.executor.execFile })); assert.equal(accepted.ok, true);
        const before = JSON.parse(await ctx.command(custody.metadataScript(item))); assert.equal(before.uniqueName, item.uniqueName); assert.equal(before.raw, item.der);
        item.control = { containerName: store.buildEnrollmentContainerName(crypto.randomUUID()), exportPolicy: 3, absentBeforeCreation: true };
        assert.equal(await ctx.command(`[Security.Cryptography.CngKey]::Exists('${item.control.containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`), "False"); save(receiptPath, value);
        const nonce = crypto.randomBytes(32);
        const result = JSON.parse(await ctx.operation("native-export-control-and-refusal", () => ctx.command(custody.buildExportScript(item, item.control.containerName, nonce.toString("base64")))));
        const control = JSON.parse(await ctx.native("Key", item.control)); item.control.uniqueName = control.uniqueName; save(receiptPath, value);
        custody.verifyResult(item, result, nonce, before, JSON.parse(await ctx.command(custody.metadataScript(item))));
        Object.assign(proof.cases.find(row => row.profile === item.profile), { nativeAssociationVerified: true, nativeSignatureVerified: true, protectedExportDenied: true, exportableControlSucceeded: true, privateBuffersZeroed: true, custodyUnchanged: true, privateExportHResult: result.privateExportHResult });
      }
    });
    await gate.scenario(contract.requiredScenarios[4], async () => {
      const { inspectMachineKeySurvivors } = require("../packages/agent/src/windows-key-survivors"), { validateCertificateChain } = require("../packages/agent/src/issuers/chain-helper");
      const ca = new crypto.X509Certificate(fs.readFileSync(path.join(workDir, "ca.pem"))), pin = sha256(ca.publicKey.export({ type: "spki", format: "der" }));
      const malformed = path.join(workDir, "malformed.pem"); fs.writeFileSync(malformed, "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n");
      for (const item of value.cases) {
        const refs = await inspectMachineKeySurvivors({ containerName: item.containerName, helperPath: value.helperPath, execFileImpl: ctx.executor.execFile }); assert.equal(refs.ok, true); assert.equal(refs.shared, true); assert.equal(refs.matches, 1);
        const excluded = await inspectMachineKeySurvivors({ containerName: item.containerName, store: "My", thumbprint: item.thumbprint, helperPath: value.helperPath, execFileImpl: ctx.executor.execFile }); assert.equal(excluded.ok, true); assert.equal(excluded.shared, false);
        const check = (certPath, caKeySha256) => validateCertificateChain({ helperPath: value.helperPath, certPath, caCertPath: path.join(workDir, "ca.pem"), caKeySha256, execFileImpl: ctx.executor.result, timeoutMs: 30000 });
        const trusted = await check(item.certPath, pin); assert.equal(trusted.ok, true); assert.equal(trusted.verdict, "revocation_unknown");
        const wrong = await check(item.certPath, pin === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64)); assert.equal(wrong.verdict, "ca_key_changed");
        const invalid = await check(malformed, pin); assert.equal(invalid.verdict, "invalid");
        Object.assign(proof.cases.find(row => row.profile === item.profile), { machineStoreReferenceFound: true, exactReferenceExcluded: true, storesScanned: refs.storesScanned, chainVerdict: trusted.verdict, wrongPinVerdict: wrong.verdict, malformedVerdict: invalid.verdict });
      }
    });
  } catch (error) { primary = error; }
  finally {
    try {
      await gate.scenario(contract.requiredScenarios[5], async () => { assert.equal(ctx.executor.drained(), true); cleanupResult = await cleanup(receiptPath, { sameOwner: true }); proof.cleanupCompleted = true; for (const item of proof.cases) item.ownedArtifactsAbsent = true; });
    } catch (error) { cleanupResult = { status: "failed" }; primary = primary ? new AggregateError([primary, error], "Native run and cleanup failed") : error; }
    if (!primary) { contract.verifyProof(proof); gate.report.nativeArm64CngRuntime = proof; }
    gate.report.fixtureSources = requiredSources.map(file => ({ file, sha256: sha256(fs.readFileSync(path.join(root, file))) }));
    await gate.finish({ requiredScenarios: contract.requiredScenarios, cleanup: { status: cleanupResult?.status === "passed" ? "passed" : "failed" } }).catch(error => { primary ||= error; });
  }
  if (primary) throw primary;
  return gate.report;
}
function verifyFile(file) {
  const report = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(report.suite, contract.suite); assert.equal(report.platform, "win32"); assert.equal(report.architecture, "arm64");
  assert.deepEqual([...report.requiredScenarios].sort(), [...contract.requiredScenarios].sort());
  assert.deepEqual([...report.requiredCapabilities].sort(), [...contract.requiredCapabilities].sort());
  assert.deepEqual(require("./certops-qualification-report").verifyReport(report, contract.requiredScenarios, { expectedSha: process.env.GITHUB_SHA }), []);
  contract.verifyRuntimeReport(report);
  assert.deepEqual(report.fixtureSources.map(item => item.file).sort(), [...requiredSources].sort());
  for (const source of report.fixtureSources) assert.equal(source.sha256, sha256(fs.readFileSync(path.join(root, source.file))));
  return true;
}
if (require.main === module) {
  const action = process.argv[2] === "--verify-report" ? Promise.resolve().then(() => verifyFile(process.argv[3])) : process.argv[2] === "--cleanup" ? cleanup(path.resolve(process.env.CERTOPS_ARM64_RECEIPT || "")) : main();
  action.catch(() => { console.error("ARM64 native qualification or exact-owned cleanup failed; preserve private receipt on the disposable host"); process.exitCode = 1; });
}
module.exports = { main, cleanup, validateReceipt, makeExecutor, requiredSources, verifyFile, ...contract };
