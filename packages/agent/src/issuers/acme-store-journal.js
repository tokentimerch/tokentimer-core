"use strict";

// The caller must hold its durable job lock across this operation. An order
// is never retried after submission may have begun: the local ACME wrappers
// do not provide a universally recoverable order identifier.
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { durableWriteFileSync } = require("./adcs-enrollment-journal");
const { certificateMatchesCsr } = require("./csr-certificate-key");
const { extractSpkiFromCsr } = require("./der-extensions");
const { isAgentOwnedContainerName, buildEnrollmentContainerName } = require("../windows-cert-store");
const { buildEvidenceItem } = require("../evidence");

function digest(value) { return createHash("sha256").update(value, "utf8").digest("hex"); }
function spkiDigest(csrPem) { return createHash("sha256").update(extractSpkiFromCsr(csrPem)).digest("hex"); }
// Verify bytes supplied inside an already signature-verified dispatch. This
// helper is not an authorization substitute for envelope/agent verification.
function decodeAcmeStoreDispatch(job) {
  const binding = job?.acmeStoreEnrollment;
  if (!binding || typeof binding !== "object" || Array.isArray(binding) ||
      Object.keys(binding).some(key => !["enrollmentId", "originalJobId", "requestB64", "requestSha256"].includes(key)) ||
      !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(binding.enrollmentId || "") ||
      !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(binding.originalJobId || "") ||
      !/^[a-f0-9]{64}$/.test(binding.requestSha256 || "") || typeof binding.requestB64 !== "string" ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(binding.requestB64)) throw new Error("invalid ACME store dispatch binding");
  const bytes = Buffer.from(binding.requestB64, "base64");
  if (!bytes.length || bytes.length > 32768 || bytes.toString("base64") !== binding.requestB64 || createHash("sha256").update(bytes).digest("hex") !== binding.requestSha256) throw new Error("ACME store snapshot hash mismatch");
  let snapshot;
  try { snapshot = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("invalid ACME store snapshot"); }
  let normalizedEndpoint;
  try { normalizedEndpoint = new URL(job.caEndpoint).href; } catch { throw new Error("invalid signed ACME endpoint"); }
  const allowed = ["version", "workspaceId", "certificateId", "agentId", "agentPublicId", "jobId", "target", "dnsNames", "caEndpoint", "commandRef", "dnsProvider", "dnsZone", "keyAlgorithm", "acmeKind", "preferredChain", "eabAccountRef", "issuanceMode", "predecessorFingerprintSha256"];
  allowed.push("iisConsumers");
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot) || Object.keys(snapshot).some(key => !allowed.includes(key)) ||
      snapshot.version !== 1 || snapshot.workspaceId !== job.workspaceId || snapshot.certificateId !== job.certificateId ||
      snapshot.agentPublicId !== job.agentId || snapshot.jobId !== binding.originalJobId ||
      (job.action === "renew" && job.jobId !== binding.originalJobId) ||
      !["renew", "continue-enrollment"].includes(job.action) || job.issuerKind !== "acme" || job.keyMode !== "os-store-managed" ||
      !snapshot.target || snapshot.target.type !== "windows-cert-store" || snapshot.target.store !== "My" ||
      Object.keys(snapshot.target).some(key => !["type", "reference", "store"].includes(key)) ||
      job.target?.type !== snapshot.target.type || job.target?.reference !== snapshot.target.reference || job.target?.store !== "My" ||
      Object.keys(job.target).some(key => !["type", "reference", "store"].includes(key)) ||
      !Array.isArray(snapshot.dnsNames) || !snapshot.dnsNames.includes(snapshot.target.reference) ||
      !Array.isArray(job.sans) || JSON.stringify([...new Set(job.sans)].sort()) !== JSON.stringify(snapshot.dnsNames) ||
      snapshot.caEndpoint !== normalizedEndpoint || snapshot.commandRef !== job.commandRef || snapshot.dnsProvider !== job.dnsProvider ||
      snapshot.dnsZone !== job.dnsZone || snapshot.acmeKind !== (job.acmeKind || "certbot") ||
      snapshot.preferredChain !== (job.preferredChain || null) || snapshot.eabAccountRef !== (job.eabRef || job.accountRef || null) ||
      job.keyRotation === false) throw new Error("ACME store snapshot does not match signed job");
  const algorithm = job.keyAlgorithm === "rsa" ? `rsa-${job.keySize}` : job.keyAlgorithm === "ecdsa" ? `ec-p${job.keySize}` : null;
  if (algorithm !== snapshot.keyAlgorithm || !["issue", "renew"].includes(snapshot.issuanceMode) ||
      (snapshot.issuanceMode === "issue" ? snapshot.predecessorFingerprintSha256 !== null : !/^[a-f0-9]{64}$/.test(snapshot.predecessorFingerprintSha256 || "")) ||
      !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(snapshot.agentId || "")) throw new Error("invalid ACME store key or predecessor identity");
  return { enrollmentId: binding.enrollmentId, originalJobId: binding.originalJobId, requestSha256: binding.requestSha256, snapshot };
}
function storeEnrollmentLockId(jobId) {
  if (typeof jobId !== "string" || !jobId || jobId.length > 256) throw new Error("invalid ACME job identity");
  const hash = digest(`acme-store:${jobId}`);
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20, 32)}`;
}
function buildAcmeStoreReceiptEvidence(receipt, claimId) {
  if (!receipt || typeof receipt !== "object" || typeof claimId !== "string" || !claimId) throw new Error("invalid ACME receipt or claim");
  const metadata = [{ name: "step", value: "acme-store-receipt" }];
  for (const name of ["receiptId", "enrollmentId", "requestSha256", "containerName", "state", "csrSha256", "csrSpkiSha256", "leafSpkiSha256", "orderReferenceSha256", "store", "keyPossessionVerified", "machineKey", "nonExportable", "serialNumber", "validFrom", "validTo", "subject", "issuer", "subjectAltNames"]) {
    if (receipt[name] !== undefined && receipt[name] !== null) metadata.push({ name, value: receipt[name] });
  }
  return { ...buildEvidenceItem({ eventType: "validation.passed", observedAt: new Date().toISOString(),
    ...(receipt.fingerprintSha256 ? { fingerprintSha256: receipt.fingerprintSha256 } : {}),
    summary: "ACME machine-store enrollment checkpoint.", metadata }), evidenceId: digest(`acme-store-evidence:${receipt.receiptId}:${claimId}`) };
}
function journalPath(stateDir, jobId) {
  if (typeof stateDir !== "string" || !path.isAbsolute(stateDir) || typeof jobId !== "string" || !jobId || jobId.length > 256) throw new Error("invalid ACME journal identity");
  return path.join(stateDir, "acme-store-enrollments", `${digest(jobId)}.json`);
}
function diskStorage(stateDir, jobId) {
  const file = journalPath(stateDir, jobId);
  return {
    read() {
      try { return JSON.parse(fs.readFileSync(file, "utf8")); }
      catch (error) { if (error.code === "ENOENT") return null; throw error; }
    },
    write(value) { durableWriteFileSync(file, JSON.stringify(value)); },
  };
}

// Read this before creating any key. A missing record is the only state that
// permits a fresh enrollment; unreadable or foreign state must fail closed.
function readStoreEnrollment({ stateDir, jobId, agentId, assertLock, storage = diskStorage(stateDir, jobId) }) {
  if (typeof agentId !== "string" || !agentId || typeof assertLock !== "function") throw new Error("ACME store enrollment prerequisites are incomplete");
  assertLock();
  const record = storage.read();
  if (!record) return null;
  if (record.version !== 1 || record.jobId !== jobId || record.agentId !== agentId ||
      record.containerName !== buildEnrollmentContainerName(storeEnrollmentLockId(jobId)) ||
      !/^[a-f0-9]{64}$/.test(record.domainsSha256 || "") ||
      !/^[a-f0-9]{64}$/.test(record.requestSha256 || "") ||
      !["keygen_intent", "prepared", "submitting", "issued", "installing", "installed"].includes(record.state)) throw new Error("invalid durable ACME store enrollment");
  if (record.state !== "keygen_intent" && (typeof record.csrPem !== "string" ||
      digest(record.csrPem) !== record.csrSha256 || spkiDigest(record.csrPem) !== record.csrSpkiSha256)) throw new Error("invalid durable ACME CSR");
  if (["issued", "installing", "installed"].includes(record.state) && (typeof record.certificatePem !== "string" || !certificateMatchesCsr(record.csrPem, record.certificatePem))) {
    throw new Error("invalid durable ACME certificate");
  }
  return record;
}

function prepareStoreEnrollment({ stateDir, jobId, agentId, domains, requestSha256, assertLock, storage = diskStorage(stateDir, jobId) }) {
  if (!Array.isArray(domains) || !domains.length || domains.some(name => typeof name !== "string" || !name)) throw new Error("invalid ACME domains");
  if (!/^[a-f0-9]{64}$/.test(requestSha256 || "")) throw new Error("invalid ACME request identity");
  const existing = readStoreEnrollment({ stateDir, jobId, agentId, assertLock, storage });
  if (existing) {
    if (existing.domainsSha256 !== digest(JSON.stringify(domains)) || existing.requestSha256 !== requestSha256) throw new Error("ACME store enrollment request conflicts");
    return { record: existing, created: false };
  }
  const record = { version: 1, jobId, agentId, containerName: buildEnrollmentContainerName(storeEnrollmentLockId(jobId)),
    domainsSha256: digest(JSON.stringify(domains)), requestSha256, state: "keygen_intent" };
  storage.write(record);
  assertLock();
  return { record, created: true };
}

function saveStoreCsr({ stateDir, jobId, agentId, csrPem, assertLock, storage = diskStorage(stateDir, jobId) }) {
  const record = readStoreEnrollment({ stateDir, jobId, agentId, assertLock, storage });
  if (!record || record.state !== "keygen_intent" || typeof csrPem !== "string" || !csrPem) throw new Error("ACME keygen intent is unavailable");
  const prepared = { ...record, state: "prepared", csrPem, csrSha256: digest(csrPem), csrSpkiSha256: spkiDigest(csrPem) };
  storage.write(prepared);
  assertLock();
  return prepared;
}

// Caller holds this job's enrollment lock. A corrupt or unreadable journal is
// deliberately indistinguishable from protected state for cleanup purposes.
function isAcmeStoreContainerProtected({ stateDir, jobId, containerName }) {
  try {
    if (buildEnrollmentContainerName(storeEnrollmentLockId(jobId)) !== containerName) return false;
    return diskStorage(stateDir, jobId).read() !== null;
  } catch { return true; }
}

function markStoreInstallation({ stateDir, jobId, agentId, assertLock, storage = diskStorage(stateDir, jobId), completed = false }) {
  const record = readStoreEnrollment({ stateDir, jobId, agentId, assertLock, storage });
  const expected = completed ? "installing" : "issued";
  if (!record || record.state !== expected) throw new Error("ACME store installation state is invalid");
  const next = { ...record, state: completed ? "installed" : "installing" };
  storage.write(next);
  assertLock();
  return next;
}

async function runAcmeStoreOperation({ stateDir, jobId, enrollmentId, agentId, domains, requestSha256, acquireLock, recordContainer,
  generateCsr, submit, reportReceipt, reportIssuance, install, recoveryOnly = false, storage = diskStorage(stateDir, jobId) }) {
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(enrollmentId || "") ||
      [acquireLock, recordContainer, generateCsr, submit, reportReceipt, reportIssuance, install].some(fn => typeof fn !== "function")) throw new Error("ACME store operation callbacks are incomplete");
  const lockId = storeEnrollmentLockId(jobId);
  const lock = acquireLock(stateDir, lockId);
  try {
    return await lock.run(async signal => {
      const assertLock = () => lock.assertHeld();
      const common = { stateDir, jobId, agentId, domains, requestSha256, assertLock, storage };
      if (recoveryOnly) {
        const existing = readStoreEnrollment(common);
        // A recovery job never creates a key or submits/retries an order,
        // even when the original stopped before its durable CSR checkpoint.
        if (!existing || ["keygen_intent", "prepared", "submitting"].includes(existing.state)) {
          return { outcome: "uncertain", recovered: true };
        }
      }
      let { record, created } = prepareStoreEnrollment(common);
      if (record.state === "keygen_intent") {
        if (!created) return { outcome: "uncertain", stage: "keygen" };
        // The job journal points at the deterministic container before the
        // native process can create it, so orphan cleanup takes this lock.
        await recordContainer(record.containerName);
        assertLock();
        const generated = await generateCsr({ enrollmentId: lockId, containerName: record.containerName, signal });
        assertLock();
        if (!generated || generated.ok !== true || generated.containerName !== record.containerName) return { outcome: "uncertain", stage: "keygen" };
        record = saveStoreCsr({ ...common, csrPem: generated.csrPem });
      }
      const receipt = async (state, extra = {}) => {
        const hash = digest(`acme-store-receipt:${enrollmentId}:${state}`);
        const receiptId = `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20, 32)}`;
        await reportReceipt({ receiptId, enrollmentId, requestSha256, containerName: record.containerName, state,
          csrSha256: record.csrSha256, csrSpkiSha256: record.csrSpkiSha256, ...extra });
        assertLock();
      };
      await receipt("prepared");
      if (["submitting", "issued", "installing", "installed"].includes(record.state)) await receipt("submitting");
      const issuance = await issueStoreCertificateOnce({ ...common, containerName: record.containerName, csrPem: record.csrPem,
        submit, signal, beforeSubmit: () => receipt("submitting") });
      if (issuance.outcome !== "issued") { await receipt("uncertain"); return issuance; }
      const validation = require("../verify").validateCertificateForDeploy({ certificatePem: issuance.certificatePem,
        privateKeyPem: null, requestedSans: domains, chainPems: issuance.chainPem ? [issuance.chainPem] : [] });
      if (!validation.valid) return { status: "failed", keyRotated: null,
        errorMessage: `ACME certificate validation failed (${validation.code}): ${validation.detail}` };
      const cert = new (require("node:crypto").X509Certificate)(issuance.certificatePem);
      const fingerprintSha256 = cert.fingerprint256.replace(/:/g, "").toLowerCase();
      await receipt("issued", { fingerprintSha256, leafSpkiSha256: record.csrSpkiSha256 });
      // Durable issued state precedes every externally visible report.
      await reportIssuance(issuance);
      assertLock();
      const latest = readStoreEnrollment(common);
      const recovery = latest.state !== "issued";
      if (!recovery) markStoreInstallation(common);
      await receipt("installing", { fingerprintSha256 });
      const result = await install({ certificatePem: issuance.certificatePem, containerName: record.containerName, recovery, signal });
      assertLock();
      if (result?.status === "succeeded") {
        if (result.storeProof?.status !== "complete" || result.storeProof.fingerprintSha256 !== fingerprintSha256) {
          return { status: "failed", retryableInterrupt: true, errorMessage: "native machine-store proof is missing or mismatched" };
        }
        if (latest.state !== "installed") markStoreInstallation({ ...common, completed: true });
        await receipt("installed", { fingerprintSha256, store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true });
      }
      return result;
    });
  } finally { lock.release(); }
}

async function issueStoreCertificateOnce({ stateDir, jobId, agentId, containerName, csrPem, domains, requestSha256,
  submit, beforeSubmit, assertLock, signal, storage = diskStorage(stateDir, jobId) }) {
  if (typeof agentId !== "string" || !agentId || !isAgentOwnedContainerName(containerName) ||
      typeof csrPem !== "string" || !csrPem || !Array.isArray(domains) || !domains.length ||
      domains.some((name) => typeof name !== "string" || !name) || !/^[a-f0-9]{64}$/.test(requestSha256 || "") || typeof submit !== "function" || typeof beforeSubmit !== "function" || typeof assertLock !== "function") {
    throw new Error("ACME store enrollment prerequisites are incomplete");
  }
  assertLock();
  const expected = { jobId, agentId, containerName, csrSha256: digest(csrPem), csrSpkiSha256: spkiDigest(csrPem), domainsSha256: digest(JSON.stringify(domains)), requestSha256 };
  let record = readStoreEnrollment({ stateDir, jobId, agentId, assertLock, storage });
  if (record) {
    if (record.version !== 1 || Object.entries(expected).some(([key, value]) => record[key] !== value) || record.csrPem !== csrPem) {
      throw new Error("ACME store enrollment identity conflicts with its durable journal");
    }
    if (["issued", "installing", "installed"].includes(record.state)) {
      if (typeof record.certificatePem !== "string" || !certificateMatchesCsr(csrPem, record.certificatePem)) throw new Error("invalid durable ACME certificate");
      return { outcome: "issued", certificatePem: record.certificatePem, chainPem: record.chainPem || null, recovered: true };
    }
    // A crash in, or immediately before, the client call is ambiguous. Do
    // not delete the key or generate a replacement order without an operator.
    if (record.state === "submitting") return { outcome: "uncertain", recovered: true };
    if (record.state !== "prepared") throw new Error("ACME CSR has not been durably prepared");
  } else {
    throw new Error("ACME keygen intent is missing");
  }
  record = { ...record, state: "submitting" };
  storage.write(record);
  assertLock();
  // No CA submission before the server has durably acknowledged intent.
  await beforeSubmit(record);
  assertLock();
  let issuance;
  try { issuance = await submit({ csrPem, domains, signal }); }
  catch { return { outcome: "uncertain", recovered: false }; }
  assertLock();
  if (!issuance || issuance.outcome !== "issued" || typeof issuance.certificatePem !== "string" ||
      !certificateMatchesCsr(csrPem, issuance.certificatePem)) {
    return { outcome: "uncertain", recovered: false };
  }
  // Persist all public artifacts and the owned key association before any
  // result upload. A failed write leaves the submission uncertain on replay.
  const issued = { ...record, state: "issued", certificatePem: issuance.certificatePem,
    chainPem: typeof issuance.chainPem === "string" ? issuance.chainPem : null };
  storage.write(issued);
  assertLock();
  return { ...issuance, recovered: false };
}

// Once orchestration starts, a thrown transport, journal or native error can
// follow an external effect. Keep the job recoverable instead of reporting an
// ordinary failure which the operator continuation cannot address.
async function runAcmeStoreOperationForJob(options) {
  let detail = "ACME order or installation requires reconciliation";
  try {
    const result = await runAcmeStoreOperation(options);
    if (result?.outcome !== "uncertain" && result?.status !== "failed") return result;
    if (typeof result?.errorMessage === "string" && result.errorMessage.trim()) {
      detail = result.errorMessage.trim().slice(0, 500);
    }
  } catch {
    // The durable journal remains the authority for any later continuation.
  }
  return { status: "orphaned_unknown_effect", keyRotated: null,
    errorMessage: `${detail} (needsOperatorReconciliation=true; reconciliationReason=acme_store_outcome_uncertain)` };
}

module.exports = { decodeAcmeStoreDispatch, buildAcmeStoreReceiptEvidence, issueStoreCertificateOnce, readStoreEnrollment, prepareStoreEnrollment, saveStoreCsr, markStoreInstallation, runAcmeStoreOperation, runAcmeStoreOperationForJob, storeEnrollmentLockId, isAcmeStoreContainerProtected, diskStorage };
