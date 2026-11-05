"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { freezeAcmeStoreRequest, applyAcmeStoreEvidence, containerForJob } = require("../../apps/api/services/certops/acmeStoreContract");
const ids = { workspaceId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", certificateId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  agentId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", jobId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
  enrollmentId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", claimId: "ffffffff-ffff-4fff-8fff-ffffffffffff" };
function request() { return { workspaceId: ids.workspaceId, certificateId: ids.certificateId, agentId: ids.agentId, agentPublicId: "agent-public-one", jobId: ids.jobId,
  target: { type: "windows-cert-store", reference: "app.example.com", store: "My" },
  dnsNames: ["app.example.com", "alt.example.com"], caEndpoint: "https://acme.example.com/directory",
  commandRef: "certbot-csr", dnsProvider: "dns-provider", dnsZone: "example.com", keyAlgorithm: "rsa-2048",
  acmeKind: "certbot", issuanceMode: "issue", predecessorFingerprintSha256: null }; }
function setup() {
  const requestSha256 = freezeAcmeStoreRequest(request()).requestSha256;
  const record = { ...ids, currentJobId: ids.jobId, containerName: containerForJob(ids.jobId), requestSha256, state: "keygen_intent" };
  const evidence = { agentId: ids.agentId, jobId: ids.jobId, enrollmentId: ids.enrollmentId, claimId: ids.claimId, containerName: record.containerName, requestSha256 };
  const apply = (row, event) => applyAcmeStoreEvidence({ record: row, evidence: { ...evidence, ...event }, agentId: ids.agentId, claimId: ids.claimId });
  return { record, evidence, apply };
}
test("frozen identity is deterministic and changes with owner, destination, CA or command", () => {
  const { storeEnrollmentLockId } = require("../../packages/agent/src/issuers/acme-store-journal");
  assert.equal(containerForJob(ids.jobId), `tokentimer-enr-${storeEnrollmentLockId(ids.jobId)}`);
  const initial = freezeAcmeStoreRequest(request());
  assert.equal(initial.requestSha256, freezeAcmeStoreRequest({ ...request(), dnsNames: [...request().dnsNames].reverse() }).requestSha256);
  for (const patch of [{ agentId: ids.jobId }, { caEndpoint: "https://other.example.com/directory" }, { commandRef: "other" }, { target: { type: "windows-cert-store", reference: "alt.example.com", store: "My" } }]) {
    assert.notEqual(initial.requestSha256, freezeAcmeStoreRequest({ ...request(), ...patch }).requestSha256);
  }
  assert.notEqual(initial.requestSha256, freezeAcmeStoreRequest({ ...request(), issuanceMode: "renew", predecessorFingerprintSha256: "a".repeat(64) }).requestSha256);
  assert.deepEqual(freezeAcmeStoreRequest({ ...request(), dnsNames: ["app.example.com", "*.example.com"] }).request.dnsNames, ["*.example.com", "app.example.com"]);
  for (const patch of [{ caEndpoint: "http://acme.example.com/" }, { caEndpoint: "https://user:secret@acme.example.com/" }, { target: { type: "windows-cert-store", reference: "app.example.com", store: "Root" } }, { dnsNames: ["other.example.com"] }, { issuanceMode: "renew" }, { arbitraryField: "ignored" }]) {
    assert.throws(() => freezeAcmeStoreRequest({ ...request(), ...patch }));
  }
});
test("store proof promotes only the recorded CSR and leaf on the bound agent and current claim", () => {
  const { record, evidence, apply } = setup(), csr = "a".repeat(64), spki = "b".repeat(64), leaf = "c".repeat(64);
  const prepared = apply(record, { state: "prepared", csrSha256: csr, csrSpkiSha256: spki });
  const submitting = apply(prepared, { state: "submitting", csrSpkiSha256: spki });
  const issued = apply(submitting, { state: "issued", csrSpkiSha256: spki, leafSpkiSha256: spki, fingerprintSha256: leaf });
  const installing = apply(issued, { state: "installing", csrSpkiSha256: spki, fingerprintSha256: leaf });
  const proof = { state: "installed", csrSpkiSha256: spki, fingerprintSha256: leaf, store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true };
  assert.equal(apply(installing, proof).state, "installed");
  for (const patch of [{ fingerprintSha256: "d".repeat(64) }, { csrSpkiSha256: "d".repeat(64) }, { containerName: containerForJob(ids.agentId) }, { nonExportable: false }, { machineKey: false }, { store: "LocalMachine\\Root" }, { agentId: ids.jobId }, { jobId: ids.agentId }, { claimId: ids.agentId }, { enrollmentId: ids.agentId }]) {
    assert.throws(() => apply(installing, { ...proof, ...patch }));
  }
  assert.throws(() => apply(submitting, { state: "issued", csrSpkiSha256: spki, leafSpkiSha256: "d".repeat(64), fingerprintSha256: leaf }));
  assert.throws(() => apply({ ...submitting, csrSpkiSha256: null }, { state: "issued", csrSpkiSha256: spki, leafSpkiSha256: spki, fingerprintSha256: leaf }));
  assert.throws(() => applyAcmeStoreEvidence({ record: installing, evidence: { ...evidence, ...proof }, agentId: ids.jobId, claimId: ids.claimId }));
});
test("an uncertain order cannot automatically create a replacement or promote without recorded identity", () => {
  const { record, apply } = setup();
  const uncertain = apply(record, { state: "uncertain" });
  assert.throws(() => apply(uncertain, { state: "submitting" }));
  assert.throws(() => apply(uncertain, { state: "issued", fingerprintSha256: "a".repeat(64) }));
  assert.throws(() => apply(uncertain, { state: "installed" }));
  const prepared = apply(record, { state: "prepared", csrSha256: "a".repeat(64), csrSpkiSha256: "b".repeat(64) });
  const submitting = apply(prepared, { state: "submitting", csrSpkiSha256: "b".repeat(64) });
  const recoverable = apply(submitting, { state: "uncertain" });
  assert.throws(() => apply(recoverable, { state: "issued", csrSpkiSha256: "b".repeat(64), leafSpkiSha256: "b".repeat(64), fingerprintSha256: "c".repeat(64) }));
  const issued = apply(submitting, { state: "issued", csrSpkiSha256: "b".repeat(64), leafSpkiSha256: "b".repeat(64), fingerprintSha256: "c".repeat(64) });
  const installing = apply(issued, { state: "installing", csrSpkiSha256: "b".repeat(64), fingerprintSha256: "c".repeat(64) });
  const withExpectedLeaf = apply(installing, { state: "uncertain" });
  assert.equal(apply(withExpectedLeaf, { state: "issued", csrSpkiSha256: "b".repeat(64), leafSpkiSha256: "b".repeat(64), fingerprintSha256: "c".repeat(64) }).state, "issued");
});

test("agent binds the signed snapshot bytes to the original job, public owner, destination and issuer", () => {
  const { decodeAcmeStoreDispatch } = require("../../packages/agent/src/issuers/acme-store-journal");
  const frozen = freezeAcmeStoreRequest(request());
  const job = { workspaceId: ids.workspaceId, certificateId: ids.certificateId, jobId: ids.jobId, agentId: "agent-public-one", action: "renew",
    issuerKind: "acme", keyMode: "os-store-managed", target: request().target, sans: request().dnsNames,
    caEndpoint: request().caEndpoint, commandRef: request().commandRef, dnsProvider: request().dnsProvider, dnsZone: request().dnsZone,
    acmeKind: "certbot", keyAlgorithm: "rsa", keySize: 2048,
    acmeStoreEnrollment: { enrollmentId: ids.enrollmentId, originalJobId: ids.jobId, requestB64: frozen.requestBytes.toString("base64"), requestSha256: frozen.requestSha256 } };
  assert.equal(decodeAcmeStoreDispatch(job).requestSha256, frozen.requestSha256);
  for (const patch of [{ agentId: "foreign-agent" }, { caEndpoint: "https://other.example.com/directory" },
    { target: { ...job.target, reference: "other.example.com" } }, { sans: ["app.example.com"] }, { keySize: 4096 }, { jobId: ids.agentId },
    { acmeStoreEnrollment: { ...job.acmeStoreEnrollment, requestSha256: "0".repeat(64) } }]) {
    assert.throws(() => decodeAcmeStoreDispatch({ ...job, ...patch }));
  }
});
