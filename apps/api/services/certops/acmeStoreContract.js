"use strict";

// Contract primitives for a future ACME machine-store enrollment. This module
// is not wired to a route, job claim or an advertised agent capability.
const { createHash } = require("node:crypto");
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HEX = /^[a-f0-9]{64}$/;
const DNS = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const REFERENCE = /^[A-Za-z0-9_.:-]{1,128}$/;
const STATES = Object.freeze({
  keygen_intent: ["prepared", "uncertain"],
  prepared: ["submitting", "uncertain"],
  submitting: ["issued", "uncertain"],
  issued: ["installing"],
  installing: ["installed", "uncertain"],
  uncertain: ["issued"], installed: [],
});
function invalid(message) { const error = new Error(message); error.code = "CERTOPS_ACME_STORE_INVALID"; throw error; }
function uuid(value, field) { if (typeof value !== "string" || !UUID.test(value)) invalid(`invalid ${field}`); return value; }
function hash(value, field) { if (typeof value !== "string" || !HEX.test(value)) invalid(`invalid ${field}`); return value; }
function ref(value, field) { if (typeof value !== "string" || !REFERENCE.test(value)) invalid(`invalid ${field}`); return value; }
function dns(value, wildcard = false) {
  if (typeof value !== "string" || value.length > 253 || (!DNS.test(value) && !(wildcard && value.startsWith("*.") && DNS.test(value.slice(2))))) invalid("invalid DNS name");
  return value;
}
function containerForJob(jobId) {
  uuid(jobId, "job");
  const hex = createHash("sha256").update(`acme-store:${jobId}`, "utf8").digest("hex");
  return `tokentimer-enr-${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function freezeAcmeStoreRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) invalid("missing request");
  const allowed = ["workspaceId", "certificateId", "agentId", "agentPublicId", "jobId", "target", "dnsNames", "caEndpoint", "commandRef", "dnsProvider", "dnsZone", "keyAlgorithm", "acmeKind", "preferredChain", "eabAccountRef", "issuanceMode", "predecessorFingerprintSha256"];
  if (Object.keys(input).some(key => !allowed.includes(key))) invalid("unsupported request field");
  const workspaceId = uuid(input.workspaceId, "workspace"), certificateId = uuid(input.certificateId, "certificate"),
    agentId = uuid(input.agentId, "agent"), jobId = uuid(input.jobId, "job");
  const target = input.target;
  if (!target || target.type !== "windows-cert-store" || target.store !== "My" ||
      Object.keys(target).some(key => !["type", "reference", "store"].includes(key))) invalid("invalid store target");
  const reference = dns(target.reference);
  if (!Array.isArray(input.dnsNames) || !input.dnsNames.length || input.dnsNames.length > 100) invalid("invalid DNS names");
  const dnsNames = [...new Set(input.dnsNames.map(name => dns(name, true)))].sort();
  if (!dnsNames.includes(reference)) invalid("target name is not authorized");
  let ca;
  try { ca = new URL(input.caEndpoint); } catch { invalid("invalid ACME endpoint"); }
  if (ca.protocol !== "https:" || ca.username || ca.password || ca.search || ca.hash) invalid("invalid ACME endpoint");
  const keyAlgorithm = input.keyAlgorithm;
  if (!["rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"].includes(keyAlgorithm)) invalid("unsupported key algorithm");
  if (!["certbot", "acme.sh"].includes(input.acmeKind)) invalid("unsupported ACME client");
  if (!["issue", "renew"].includes(input.issuanceMode)) invalid("invalid issuance mode");
  if (input.issuanceMode === "issue" && input.predecessorFingerprintSha256 !== null) invalid("first issuance cannot have a predecessor");
  if (input.issuanceMode === "renew") hash(input.predecessorFingerprintSha256, "predecessor fingerprint");
  const preferredChain = input.preferredChain == null ? null : input.preferredChain;
  if (preferredChain !== null && (typeof preferredChain !== "string" || !preferredChain.trim() || preferredChain.length > 256 || /[\u0000-\u001f\u007f]/.test(preferredChain))) invalid("invalid preferred chain");
  const eabAccountRef = input.eabAccountRef == null ? null : ref(input.eabAccountRef, "ACME account reference");
  const request = { version: 1, workspaceId, certificateId, agentId, agentPublicId: ref(input.agentPublicId, "public agent identity"), jobId,
    target: { type: "windows-cert-store", reference, store: "My" }, dnsNames,
    caEndpoint: ca.href, commandRef: ref(input.commandRef, "command reference"),
    dnsProvider: ref(input.dnsProvider, "DNS provider"), dnsZone: dns(input.dnsZone), keyAlgorithm,
    acmeKind: input.acmeKind, preferredChain, eabAccountRef,
    issuanceMode: input.issuanceMode, predecessorFingerprintSha256: input.predecessorFingerprintSha256 };
  const requestBytes = Buffer.from(JSON.stringify(request), "utf8");
  return { request, requestBytes, requestSha256: createHash("sha256").update(requestBytes).digest("hex") };
}

// Called under the enrollment row lock, after the protocol layer authenticates
// the agent and current claim. Side effects and promotion are deliberately not
// performed here; callers must persist the returned record transactionally.
function applyAcmeStoreEvidence({ record, evidence, agentId, claimId }) {
  if (!record || !evidence || typeof record !== "object" || typeof evidence !== "object") invalid("missing enrollment evidence");
  uuid(record.workspaceId, "workspace"); uuid(record.certificateId, "certificate");
  uuid(record.agentId, "owner agent"); uuid(record.jobId, "original job");
  uuid(record.enrollmentId, "enrollment"); uuid(record.currentJobId, "current job");
  if (record.containerName !== containerForJob(record.jobId) || evidence.containerName !== record.containerName) invalid("owned key container changed");
  hash(record.requestSha256, "request hash");
  if (agentId !== record.agentId || evidence.agentId !== record.agentId ||
      evidence.enrollmentId !== record.enrollmentId || evidence.jobId !== record.currentJobId || evidence.requestSha256 !== record.requestSha256 ||
      !UUID.test(claimId || "") || evidence.claimId !== claimId) invalid("evidence is not bound to the owner and claim");
  if (!Object.hasOwn(STATES, record.state) || !STATES[record.state].includes(evidence.state)) invalid("invalid enrollment transition");
  const next = { ...record, state: evidence.state };
  if (evidence.state === "prepared") {
    next.csrSpkiSha256 = hash(evidence.csrSpkiSha256, "CSR public-key hash");
    next.csrSha256 = hash(evidence.csrSha256, "CSR hash");
  }
  if (["submitting", "issued", "installing", "installed"].includes(evidence.state)) {
    hash(record.csrSha256, "recorded CSR hash"); hash(record.csrSpkiSha256, "recorded CSR public-key hash");
    if (evidence.csrSha256 !== undefined && evidence.csrSha256 !== record.csrSha256) invalid("CSR identity changed");
    if (evidence.csrSpkiSha256 !== record.csrSpkiSha256) invalid("CSR public-key identity changed");
  }
  if (evidence.state === "issued") {
    next.fingerprintSha256 = hash(evidence.fingerprintSha256, "leaf fingerprint");
    if (record.state === "uncertain" && (!record.fingerprintSha256 || record.fingerprintSha256 !== next.fingerprintSha256)) {
      invalid("uncertain enrollment lacks the original expected leaf identity");
    }
    if (evidence.leafSpkiSha256 !== record.csrSpkiSha256) invalid("leaf does not match the recorded CSR");
    if (evidence.orderReferenceSha256 !== undefined && evidence.orderReferenceSha256 !== null) {
      next.orderReferenceSha256 = hash(evidence.orderReferenceSha256, "order reference hash");
    }
  }
  if (["installing", "installed"].includes(evidence.state)) {
    hash(record.fingerprintSha256, "recorded leaf fingerprint");
    if (evidence.fingerprintSha256 !== record.fingerprintSha256) invalid("installed leaf identity changed");
  }
  if (evidence.state === "installed" && (evidence.store !== "LocalMachine\\My" ||
      evidence.keyPossessionVerified !== true || evidence.machineKey !== true || evidence.nonExportable !== true)) invalid("native store proof is incomplete");
  return next;
}

module.exports = { freezeAcmeStoreRequest, applyAcmeStoreEvidence, containerForJob };
