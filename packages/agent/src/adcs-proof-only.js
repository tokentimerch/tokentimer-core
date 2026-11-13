"use strict";

// This path only reads durable enrollment artifacts and inspects the machine
// store. It never creates a key, contacts a CA, accepts a leaf or binds a service.
const crypto = require("node:crypto");
const { decodeEnrollmentSnapshot, readEnrollmentJournal } = require("./issuers");
const { storeSnapshotTargetError } = require("./adcs-windows-iis");
const { acquireEnrollmentLock, acquireStoreLock, buildEnrollmentContainerName } = require("./windows-cert-store");
const { inspectStoreOnlyCertificate } = require("./windows-cert-store/store-only");
const { buildEvidenceItem } = require("./evidence");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;

async function executeAdcsProofOnly({ job, jobId, claimId, client, stateDir, execFileImpl, signal, reportEvidence,
  readJournal = readEnrollmentJournal, acquireEnrollment = acquireEnrollmentLock,
  acquireStore = acquireStoreLock, inspect = inspectStoreOnlyCertificate }) {
  const fail = message => ({ status: "failed", keyRotated: null, errorMessage: message });
  const proof = job?.adcsProof;
  if (job?.action !== "adcs-installation-proof" || job?.issuerKind !== "adcs" || job?.keyMode !== "os-store-managed" ||
      !proof || typeof proof !== "object" || Array.isArray(proof) ||
      Object.keys(proof).some(key => !["receiptId", "enrollmentId", "agentId", "originalJobId", "originalClaimId", "originalAttempt", "snapshotSha256", "destinationSha256", "fingerprintSha256", "csrSpkiSha256"].includes(key)) ||
      [proof.receiptId, proof.enrollmentId, proof.agentId, proof.originalJobId, proof.originalClaimId].some(value => !UUID.test(value || "")) ||
      !Number.isInteger(proof.originalAttempt) || proof.originalAttempt < 1 ||
      [proof.snapshotSha256, proof.destinationSha256, proof.fingerprintSha256, proof.csrSpkiSha256].some(value => !HASH.test(value || "")) ||
      typeof stateDir !== "string" || !stateDir || typeof reportEvidence !== "function") return fail("invalid signed AD CS installation proof request");
  const decoded = decodeEnrollmentSnapshot(job);
  if (!decoded.ok || decoded.terminalState || decoded.reconcileRequestId !== undefined ||
      decoded.enrollmentId !== proof.enrollmentId || decoded.snapshotSha256 !== proof.snapshotSha256 ||
      storeSnapshotTargetError(decoded.snapshot, job.target) || decoded.snapshot.destinationSha256 !== proof.destinationSha256) {
    return fail("AD CS installation proof snapshot or destination does not match");
  }
  let enrollmentLock;
  try { enrollmentLock = acquireEnrollment(stateDir, proof.enrollmentId); }
  catch { return fail("AD CS installation proof enrollment lock is unavailable"); }
  try {
    return await enrollmentLock.run(async enrollmentSignal => {
      enrollmentLock.assertHeld();
      const read = readJournal(stateDir, proof.enrollmentId);
      if (read.kind !== "valid" || !["installing", "installed"].includes(read.journal.state) ||
          read.journal.snapshotSha256 !== proof.snapshotSha256 || read.journal.csrSpkiSha256 !== proof.csrSpkiSha256 ||
          read.journal.containerName !== buildEnrollmentContainerName(proof.enrollmentId) || typeof read.artifacts?.leafPem !== "string") {
        return fail("AD CS installation proof durable identity is unavailable or mismatched");
      }
      let leaf;
      try { leaf = new crypto.X509Certificate(read.artifacts.leafPem); } catch { return fail("AD CS installation proof leaf is invalid"); }
      const fingerprint = crypto.createHash("sha256").update(leaf.raw).digest("hex");
      const spki = crypto.createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex");
      if (fingerprint !== proof.fingerprintSha256 || spki !== proof.csrSpkiSha256) return fail("AD CS installation proof leaf does not match the expected identity");
      let storeLock;
      try { storeLock = acquireStore(stateDir, "My"); } catch { return fail("AD CS installation proof store lock is unavailable"); }
      try {
        return await storeLock.run(async storeSignal => {
          enrollmentLock.assertHeld(); storeLock.assertHeld();
          const signals = [signal, enrollmentSignal, storeSignal].filter(Boolean);
          const operationSignal = signals.length > 1 ? AbortSignal.any(signals) : signals[0];
          const observed = await inspect({ certificatePem: read.artifacts.leafPem, containerName: read.journal.containerName, execFileImpl, signal: operationSignal });
          enrollmentLock.assertHeld(); storeLock.assertHeld();
          if (operationSignal?.aborted || observed.status !== "complete" || observed.fingerprintSha256 !== fingerprint) return fail("AD CS installation proof cannot verify the expected leaf and key");
          const metadata = [{ name: "step", value: "adcs-proof-only" }, { name: "store", value: "LocalMachine\\My" },
            { name: "destinationType", value: "windows-cert-store" }, { name: "validTo", value: new Date(leaf.validTo).toISOString() },
            ...Object.entries(proof).map(([name, value]) => ({ name: name === "agentId" ? "ownerAgentId" : name, value })),
            { name: "keyPossessionVerified", value: true }, { name: "machineKey", value: true }, { name: "nonExportable", value: true }];
          const item = buildEvidenceItem({ eventType: "validation.passed", observedAt: new Date().toISOString(), fingerprintSha256: fingerprint,
            summary: "Verified the expected certificate and protected key in the machine store.", metadata });
          await reportEvidence(client, jobId, [item], claimId);
          enrollmentLock.assertHeld(); storeLock.assertHeld();
          return { status: "succeeded", keyRotated: null };
        });
      } finally { storeLock.release(); }
    });
  } catch { return fail("AD CS installation proof could not be completed"); }
  finally { enrollmentLock.release(); }
}

module.exports = { executeAdcsProofOnly };
