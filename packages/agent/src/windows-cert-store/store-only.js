"use strict";

// Read-only inspection for store-only enrollment. Callers must hold the store
// lock when using this result to decide whether to accept or complete a job.
const path = require("node:path");
const fs = require("node:fs");
const { execFile } = require("node:child_process");
const { X509Certificate } = require("node:crypto");
const { execWithoutShell, isAgentOwnedContainerName, acquireStoreLock,
  acceptCertificateViaCng, markIssuedContainerAccepted, readIssuedContainerRecord } = require("./index");

function inspectProcess(execFileImpl, command, signal) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toLowerCase() === "psmodulepath") delete env[key];
  const run = (file, args, opts, callback) => execFileImpl(file, args, { ...opts, env, maxBuffer: 1024 * 1024 }, callback);
  return execWithoutShell(run, ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command], 60000, signal);
}

async function inspectStoreOnlyCertificate({ certificatePem, containerName, execFileImpl = execFile, signal, now = Date.now() }) {
  if (!isAgentOwnedContainerName(containerName)) return { status: "error", error: "invalid owned CNG container" };
  let certificate;
  try { certificate = new X509Certificate(certificatePem); }
  catch { return { status: "error", error: "invalid issued certificate" }; }
  const thumbprint = certificate.fingerprint.replace(/:/g, "").toUpperCase();
  const fingerprintSha256 = certificate.fingerprint256.replace(/:/g, "").toLowerCase();
  let script;
  try { script = fs.readFileSync(path.join(__dirname, "inspect-store.ps1"), "utf8"); }
  catch { return { status: "error", error: "machine store inspection helper unavailable" }; }
  // Both values have closed alphabets and are not interpreted by a shell.
  // Invoke the bundled script as a command, like the existing Windows store
  // reader, so a local script execution policy does not require a bypass.
  const command = `& {\n${script}\n} -Thumbprint '${thumbprint}' -Container '${containerName}'`;
  const result = await inspectProcess(execFileImpl, command, signal);
  if (result.exitCode !== 0 || result.execError) return { status: "error", error: "machine store inspection failed" };
  let observed;
  try { observed = JSON.parse(result.stdout); }
  catch { return { status: "error", error: "machine store inspection returned invalid data" }; }
  if (!observed || typeof observed !== "object" || typeof observed.present !== "boolean") return { status: "error", error: "machine store inspection is incomplete" };
  if (!observed.present) return { status: "absent", thumbprint, fingerprintSha256 };
  if (observed.fingerprintSha256 !== fingerprintSha256 || String(observed.thumbprint || "").toUpperCase() !== thumbprint ||
      observed.hasPrivateKey !== true || observed.machineKey !== true || observed.nonExportable !== true || observed.containerMatches !== true || observed.keyPossessionVerified !== true) {
    return { status: "error", error: "machine store certificate or protected key does not match enrollment" };
  }
  const notBefore = Date.parse(observed.notBefore), notAfter = Date.parse(observed.notAfter);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter) || notBefore > now || notAfter <= now ||
      !/^[A-Fa-f0-9]+$/.test(observed.serialNumber || "")) return { status: "error", error: "machine store certificate validity is invalid" };
  return { status: "complete", thumbprint, fingerprintSha256, notBefore: observed.notBefore, notAfter: observed.notAfter, serialNumber: observed.serialNumber };
}

// Diagnostic observation only. The caller holds the enrollment and machine
// store locks and supplies the lease assertion. A matching snapshot cannot
// authorize acceptance until its atomicity and native behavior are qualified.
async function inspectPendingStoreRequest({ certificatePem, containerName, csrSpkiSha256,
  assertHeld, execFileImpl = execFile, signal }) {
  const failure = () => ({ status: "unavailable", safeToAccept: false });
  if (!isAgentOwnedContainerName(containerName) || !/^[a-f0-9]{64}$/.test(csrSpkiSha256 || "") ||
      typeof assertHeld !== "function" || signal?.aborted) return failure();
  let certificate, script;
  try {
    certificate = new X509Certificate(certificatePem);
    const { createHash } = require("node:crypto");
    const spki = certificate.publicKey.export({ type: "spki", format: "der" });
    if (createHash("sha256").update(spki).digest("hex") !== csrSpkiSha256) return failure();
    script = fs.readFileSync(path.join(__dirname, "inspect-pending-request.ps1"), "utf8");
  } catch { return failure(); }
  const encoded = certificate.raw.toString("base64");
  if (encoded.length > 16000) return failure();
  try {
    assertHeld();
    if (signal?.aborted) return failure();
    const command = `& {\n${script}\n} -CertificateBase64 '${encoded}' -Container '${containerName}'`;
    const result = await inspectProcess(execFileImpl, command, signal);
    assertHeld();
    if (signal?.aborted || result.exitCode !== 0 || result.execError) return failure();
    const observed = JSON.parse(result.stdout);
    if (!observed || !Number.isSafeInteger(observed.matchingRequests) || observed.matchingRequests < 0 ||
        observed.matchingRequests > 1 || typeof observed.verified !== "boolean" ||
        (observed.verified && observed.matchingRequests !== 1)) return failure();
    return { status: "observed", matchingRequests: observed.matchingRequests,
      keyMatches: observed.verified, safeToAccept: false };
  } catch { return failure(); }
}

// The predecessor fingerprint comes from the frozen signed enrollment, never
// a name search. Explicit null means first issuance; missing is invalid.
async function observeStoreOnlyPredecessor({ fingerprintSha256, execFileImpl = execFile, signal }) {
  if (fingerprintSha256 === null) return { existingNotAfter: null, existingSerialHex: null };
  if (typeof fingerprintSha256 !== "string" || !/^[a-f0-9]{64}$/.test(fingerprintSha256)) {
    return { error: "signed predecessor fingerprint is missing or invalid" };
  }
  let script;
  try { script = fs.readFileSync(path.join(__dirname, "find-predecessor.ps1"), "utf8"); }
  catch { return { error: "machine store predecessor helper unavailable" }; }
  const command = `& {\n${script}\n} -Fingerprint '${fingerprintSha256}'`;
  const result = await inspectProcess(execFileImpl, command, signal);
  if (result.exitCode !== 0 || result.execError) return { error: "cannot inspect signed predecessor in machine store" };
  let value;
  try { value = JSON.parse(result.stdout); } catch { return { error: "invalid predecessor inspection output" }; }
  if (!value || value.fingerprintSha256 !== fingerprintSha256 || value.hasPrivateKey !== true ||
      !Number.isFinite(Date.parse(value.notAfter)) || !/^[A-Fa-f0-9]+$/.test(value.serialNumber || "")) {
    return { error: "signed predecessor is missing a matching usable certificate or key" };
  }
  return { existingNotAfter: value.notAfter, existingSerialHex: value.serialNumber };
}

/**
 * Install a validated enrollment in My without activating a service. The
 * caller holds the enrollment lock, journals intent, and checks its job lease.
 * A recovery never runs bare accept when inspection cannot prove it safe.
 */
async function installStoreOnlyCertificate({ certificatePem, containerName, stateDir, workDir,
  mode, certificateValidated, onBeforeMutation, onInstallStep, execFileImpl, signal,
  acquireLockImpl = acquireStoreLock, inspectImpl = inspectStoreOnlyCertificate,
  acceptImpl = acceptCertificateViaCng, readReceiptImpl = readIssuedContainerRecord,
  markReceiptImpl = markIssuedContainerAccepted }) {
  if (!isAgentOwnedContainerName(containerName) || typeof stateDir !== "string" || !stateDir ||
      typeof workDir !== "string" || !workDir || !["initial", "recovery"].includes(mode) ||
      certificateValidated !== true || typeof onBeforeMutation !== "function" || typeof onInstallStep !== "function") {
    return { status: "failed", errorMessage: "store installation prerequisites are incomplete" };
  }
  let expected, expectedSha256;
  try {
    const certificate = new X509Certificate(certificatePem);
    expected = certificate.fingerprint.replace(/:/g, "").toUpperCase();
    expectedSha256 = certificate.fingerprint256.replace(/:/g, "").toLowerCase();
  }
  catch { return { status: "failed", errorMessage: "issued certificate is invalid" }; }
  let lock;
  try { lock = acquireLockImpl(stateDir, "My"); }
  catch { return { status: "failed", retryableInterrupt: true, errorMessage: "machine store lock unavailable" }; }
  try {
    return await lock.run(async (lockSignal) => {
      lock.assertHeld();
      const receipt = readReceiptImpl({ stateDir, containerName });
      if (receipt && (receipt.containerName !== containerName ||
          (receipt.status === "enrolled_by_agent" && String(receipt.acceptedThumbprint || "").toUpperCase() !== expected))) {
        return { status: "failed", errorMessage: "owned key receipt conflicts with issued certificate" };
      }
      const operationSignal = lockSignal && signal ? AbortSignal.any([lockSignal, signal]) : lockSignal || signal;
      const opts = { certificatePem, containerName, execFileImpl, signal: operationSignal };
      let proof = await inspectImpl(opts);
      lock.assertHeld();
      if (operationSignal?.aborted) return { status: "failed", retryableInterrupt: true, errorMessage: "machine store inspection aborted" };
      if (proof.status === "absent") {
        if (mode === "recovery" || receipt?.status === "enrolled_by_agent") return { status: "failed", retryableInterrupt: true,
          errorMessage: "accepted certificate is absent; reconcile before retrying acceptance" };
        onBeforeMutation("store-accept");
        await onInstallStep("accept");
        lock.assertHeld();
        if (operationSignal?.aborted) return { status: "failed", retryableInterrupt: true,
          errorMessage: "machine store acceptance aborted before mutation" };
        const accepted = await acceptImpl({ certificatePem, workDir, store: "My", execFileImpl, signal: operationSignal });
        lock.assertHeld();
        if (accepted.ok !== true || String(accepted.thumbprint || "").toUpperCase() !== expected) {
          return { status: "failed", retryableInterrupt: true, errorMessage: "certificate acceptance requires reconciliation" };
        }
        proof = await inspectImpl(opts);
        lock.assertHeld();
      }
      if (proof.status !== "complete" || proof.thumbprint !== expected || proof.fingerprintSha256 !== expectedSha256) return { status: "failed", retryableInterrupt: true,
        errorMessage: proof.error || "store certificate and protected key could not be verified" };
      if (operationSignal?.aborted) return { status: "failed", retryableInterrupt: true, errorMessage: "machine store verification aborted" };
      // The ownership receipt is required for future lifecycle decisions.
      // If persistence fails, retain the key and reconcile the installed leaf.
      onBeforeMutation("store-acceptance-receipt");
      lock.assertHeld();
      let receiptMarked;
      try { receiptMarked = markReceiptImpl({ stateDir, containerName, acceptedThumbprint: expected, store: "My" }); }
      catch { receiptMarked = false; }
      lock.assertHeld();
      if (receiptMarked !== true || operationSignal?.aborted) return { status: "failed", retryableInterrupt: true,
        errorMessage: "machine store ownership receipt requires reconciliation" };
      return { status: "succeeded", keyRotated: null, storeProof: proof };
    });
  } catch (error) {
    if (error?.code === "STORE_LOCK_LOST" || signal?.aborted) return { status: "failed", retryableInterrupt: true, errorMessage: "machine store lock or lease lost" };
    throw error;
  } finally { lock.release(); }
}

module.exports = { inspectStoreOnlyCertificate, inspectPendingStoreRequest, observeStoreOnlyPredecessor, installStoreOnlyCertificate };
