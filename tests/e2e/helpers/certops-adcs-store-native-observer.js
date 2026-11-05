"use strict";

// This observer is for the disposable Windows member only. It never invents
// evidence if the accepted-before-completion window is missed.
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { X509Certificate, createHash } = require("node:crypto");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");

const SHA256 = /^[a-f0-9]{64}$/;
function verifyNativeFault(value, { configDir }) {
  assert.equal(value.nativeIdentity, "LocalSystem");
  assert.equal(value.observedPostAccept, true);
  assert.equal(value.nativeProcessDrained, true);
  assert.equal(value.keyPossessionVerified, true);
  assert.equal(value.store, "LocalMachine\\My");
  assert.equal(value.iisBindingTouched, false);
  for (const name of ["hasPrivateKey", "nonExportable", "machineKey"]) assert.equal(value[name], true);
  assert.match(value.enrollmentId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.equal(value.containerName, `tokentimer-enr-${value.enrollmentId}`);
  assert.match(value.fingerprintSha256, SHA256);
  assert.match(value.csrSpkiSha256, SHA256);
  const read = readEnrollmentJournal(configDir, value.enrollmentId);
  assert.equal(read.kind, "valid");
  assert.equal(read.journal.state, "installing");
  assert.equal(read.journal.installStep, "accept");
  for (const name of ["jobId", "containerName", "snapshotSha256", "csrSpkiSha256"]) assert.equal(read.journal[name], value[name]);
  const leaf = new X509Certificate(read.artifacts.leafPem);
  const fingerprint = createHash("sha256").update(leaf.raw).digest("hex");
  const leafSpkiSha256 = createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  assert.equal(fingerprint, value.fingerprintSha256);
  assert.equal(leafSpkiSha256, value.csrSpkiSha256);
  // The native observer signs a fresh challenge using the non-exportable
  // machine key and verifies it against this exact leaf's public key.
  return { ...value, leafSpkiSha256, keySpkiSha256: leafSpkiSha256 };
}

function startNativeStoreObserver({ workDir, configDir, root, nodeExecutable = process.execPath,
  spawnImpl = spawn, timeoutMs = 195000 }) {
  const env = Object.fromEntries(["SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "PSModulePath", "CERTOPS_ADCS_DISPOSABLE_LAB"].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
  const script = path.join(root, "infra/certops-adcs/store-accept-phase-fault.ps1");
  const child = spawnImpl("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", script,
    "-OwnedDirectory", workDir, "-ConfigDirectory", configDir, "-RepositoryRoot", root, "-NodeExecutable", nodeExecutable],
  { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  let output = "", overflow = false, closed = false, proven = false, seenReady = false;
  let readyResolve, readyReject, resultResolve, resultReject, closeResolve;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; }); ready.catch(() => {});
  const result = new Promise((resolve, reject) => { resultResolve = resolve; resultReject = reject; }); result.catch(() => {});
  const close = new Promise(resolve => { closeResolve = resolve; });
  const timer = setTimeout(() => child.kill(), timeoutMs);
  child.stdout.on("data", chunk => {
    if (Buffer.byteLength(output) + chunk.length > 8192) { overflow = true; child.kill(); return; }
    output += chunk.toString("utf8");
    if (!seenReady && output.includes("CERTOPS_STORE_ACCEPT_READY")) { seenReady = true; readyResolve(); }
  });
  child.stderr.resume();
  child.once("error", () => { readyReject(new Error("Native store observer failed to start")); resultReject(new Error("Native store observer failed to start")); });
  child.once("close", code => {
    clearTimeout(timer); closed = true; closeResolve();
    if (!seenReady) readyReject(new Error("Native store observer prerequisites failed"));
    try {
      assert.equal(code, 0); assert.equal(overflow, false);
      const evidence = JSON.parse(output.replace("CERTOPS_STORE_ACCEPT_READY", "").trim());
      const checked = verifyNativeFault(evidence, { configDir });
      proven = true; resultResolve(checked);
    } catch { resultReject(new Error("Native post-accept window and process drainage were not proven")); }
  });
  return { ready, result, hasLiveChild: () => !closed || !proven,
    async stopAndDrain() {
      clearTimeout(timer); if (!closed) child.kill();
      let drainTimer; try { await Promise.race([close, new Promise((_, reject) => { drainTimer = setTimeout(() => reject(new Error("Native store observer did not drain")), 30000); })]); }
      finally { clearTimeout(drainTimer); }
    } };
}
module.exports = { startNativeStoreObserver, verifyNativeFault };
