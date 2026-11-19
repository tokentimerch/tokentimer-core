"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { persistAgentJobEvidenceBatch } = require("../../apps/api/services/certops/agentObservations");

function fixture() {
  const calls = [], id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", workspaceId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", claimId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc", enrollmentId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const client = { async query(sql) { calls.push(sql); return { rows: [] }; }, release() { calls.push("release"); } };
  const agent = { id, workspaceId, agentId: "real-public-agent" };
  const evidenceItems = [{ evidenceId: "ev-1", eventType: "validation.passed", metadata: [
    { name: "step", value: "acme-store-receipt" }, { name: "enrollmentId", value: enrollmentId },
    { name: "receiptId", value: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }, { name: "state", value: "prepared" },
    { name: "requestSha256", value: "a".repeat(64) }, { name: "csrSha256", value: "b".repeat(64) },
    { name: "csrSpkiSha256", value: "c".repeat(64) }, { name: "containerName", value: "tokentimer-enr-12345678-1234-1234-1234-123456789abc" },
    { name: "agentId", value: "attacker" }, { name: "claimId", value: "attacker" },
  ] }];
  const args = { dbPool: { connect: async () => client }, agent, envelope: {}, jobId: "ffffffff-ffff-4fff-8fff-ffffffffffff", claimId, evidenceItems,
    deps: { assertCurrentAgentCredential: async () => calls.push("credential"), enforceAgentSequence: async () => calls.push("sequence"), assertEvidenceClaimOwnership: async () => ({ claimId }),
      applyAcmeStoreReceiptTx: async input => { calls.push("receipt"); assert.equal(input.authenticatedAgentRowId, id); assert.equal(input.evidence.agentId, id); assert.equal(input.evidence.claimId, claimId); assert.equal(input.evidence.enrollmentId, enrollmentId); },
      createCertificateEvidence: async () => { calls.push("evidence"); return { id: "stored" }; } } };
  return { args, calls };
}
test("authenticated receipt and ordinary evidence commit in one transaction", async () => {
  const f = fixture();
  assert.equal((await persistAgentJobEvidenceBatch(f.args)).evidenceCount, 1);
  assert.deepEqual(f.calls, ["BEGIN", "credential", "sequence", "receipt", "evidence", "COMMIT", "release"]);
});
test("claim, receipt or evidence failure rolls back the entire batch", async () => {
  for (const component of ["assertCurrentAgentCredential", "assertEvidenceClaimOwnership", "applyAcmeStoreReceiptTx", "createCertificateEvidence"]) {
    const f = fixture(); f.args.deps[component] = async () => { throw new Error("refused"); };
    await assert.rejects(persistAgentJobEvidenceBatch(f.args), /refused/);
    assert.ok(f.calls.includes("ROLLBACK")); assert.equal(f.calls.includes("COMMIT"), false);
  }
});

test("actual AD CS proof and ACME receipt pass the agent evidence boundary", () => {
  const { buildWindowsStoreProofEvidence } = require("../../packages/agent/src/index");
  const { buildAcmeStoreReceiptEvidence } = require("../../packages/agent/src/issuers/acme-store-journal");
  const { validateEnvelope } = require("../../apps/api/routes/certops-agent")._test;
  const storeProof = buildWindowsStoreProofEvidence({ storeEnrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", storeDestinationSha256: "a".repeat(64),
    fingerprintSha256: "b".repeat(64), facts: { serialNumber: "AB", validFrom: "2026-01-01T00:00:00.000Z", validTo: "2027-01-01T00:00:00.000Z", subject: "CN=app.example.com", issuer: "CN=CA", dnsSans: ["app.example.com"] } });
  storeProof.evidenceId = "store-proof-1";
  const receipt = buildAcmeStoreReceiptEvidence({ receiptId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", requestSha256: "a".repeat(64),
    containerName: "tokentimer-enr-12345678-1234-1234-1234-123456789abc", state: "installed", csrSha256: "c".repeat(64), csrSpkiSha256: "d".repeat(64),
    fingerprintSha256: "b".repeat(64), store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true }, "claim-01");
  const envelope = { schemaVersion: 1, protocolVersion: "1.0.0", messageType: "evidence", agentId: "agent-01", sentAt: new Date().toISOString(),
    body: { jobId: "job-01", claimId: "claim-01", evidenceItems: [storeProof, receipt] } };
  assert.doesNotThrow(() => validateEnvelope(envelope, "evidence"));
  const receiptMetadata = Object.fromEntries(receipt.metadata.map(entry => [entry.name, entry.value]));
  const sameReceipt = { ...receiptMetadata, fingerprintSha256: receipt.fingerprintSha256 };
  assert.equal(buildAcmeStoreReceiptEvidence(sameReceipt, "claim-01").evidenceId, receipt.evidenceId);
  assert.notEqual(buildAcmeStoreReceiptEvidence(sameReceipt, "claim-02").evidenceId, receipt.evidenceId);
  assert.throws(() => buildAcmeStoreReceiptEvidence(sameReceipt));
  const names = storeProof.metadata.map(item => item.name);
  assert.ok(names.includes("keyPossessionVerified")); assert.equal(names.includes("privateKeyVerified"), false);
});

test("receipt transmission waits for the real client and preserves the claim-specific id", async () => {
  const { reportAcmeStoreReceipt } = require("../../packages/agent/src/index");
  const receipt = { receiptId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    requestSha256: "a".repeat(64), containerName: "tokentimer-enr-12345678-1234-1234-1234-123456789abc", state: "prepared",
    csrSha256: "b".repeat(64), csrSpkiSha256: "c".repeat(64) };
  let seen;
  await assert.rejects(reportAcmeStoreReceipt({ async reportEvidence(body) { seen = body; throw new Error("server unavailable"); } }, "job-1", receipt, "claim-1"), /server unavailable/);
  assert.equal(seen.claimId, "claim-1");
  const envelope = { schemaVersion: 1, protocolVersion: "1.0.0", messageType: "evidence", agentId: "agent-01", sentAt: new Date().toISOString(), body: seen };
  assert.doesNotThrow(() => require("../../apps/api/routes/certops-agent")._test.validateEnvelope(envelope, "evidence"));
  assert.match(seen.evidenceItems[0].evidenceId, /^[a-f0-9]{64}$/);
  const first = seen.evidenceItems[0].evidenceId;
  await reportAcmeStoreReceipt({ async reportEvidence(body) { assert.equal(body.evidenceItems[0].evidenceId, first); } }, "job-1", receipt, "claim-1");
});

test("AD CS expected identity and its evidence are recorded atomically", async () => {
  const f = fixture();
  f.args.evidenceItems[0].metadata = [{ name: "step", value: "adcs.expected-identity" }];
  f.args.deps.createCertificateEvidence = async () => { f.calls.push("evidence"); return { id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }; };
  f.args.deps.recordAdcsExpectedIdentityTx = async input => { f.calls.push("expected"); assert.equal(input.evidenceId, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"); };
  await persistAgentJobEvidenceBatch(f.args);
  assert.deepEqual(f.calls, ["BEGIN", "credential", "sequence", "evidence", "expected", "COMMIT", "release"]);
  const failed = fixture(); failed.args.evidenceItems[0].metadata = [{ name: "step", value: "adcs.expected-identity" }];
  failed.args.deps.createCertificateEvidence = async () => ({ id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" });
  failed.args.deps.recordAdcsExpectedIdentityTx = async () => { throw new Error("wrong claim"); };
  await assert.rejects(persistAgentJobEvidenceBatch(failed.args), /wrong claim/);
  assert.ok(failed.calls.includes("ROLLBACK")); assert.equal(failed.calls.includes("COMMIT"), false);
});

test("AD CS expected leaf evidence is derived from DER and awaits server acknowledgement", async () => {
  const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
  const { reportAdcsExpectedIdentity } = require("../../packages/agent/src/index");
  const pem = fs.readFileSync(path.join(__dirname, "../../packages/agent/src/verify/fixtures/leaf.crt.pem"), "utf8");
  const leaf = new crypto.X509Certificate(pem), spki = crypto.createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const args = { jobId: "job-1", claimId: "claim-1", enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    destinationSha256: "a".repeat(64), csrSpkiSha256: spki, certificatePem: pem };
  let body;
  await reportAdcsExpectedIdentity({ ...args, client: { async reportEvidence(value) { body = value; } } });
  assert.equal(body.claimId, args.claimId);
  assert.equal(body.evidenceItems[0].fingerprintSha256, crypto.createHash("sha256").update(leaf.raw).digest("hex"));
  const meta = Object.fromEntries(body.evidenceItems[0].metadata.map(entry => [entry.name, entry.value]));
  assert.equal(meta.csrSpkiSha256, spki); assert.equal(meta.leafSpkiSha256, spki);
  const envelope = { schemaVersion: 1, protocolVersion: "1.0.0", messageType: "evidence", agentId: "agent-01", sentAt: new Date().toISOString(), body };
  assert.doesNotThrow(() => require("../../apps/api/routes/certops-agent")._test.validateEnvelope(envelope, "evidence"));
  let sent = false;
  await assert.rejects(reportAdcsExpectedIdentity({ ...args, csrSpkiSha256: "f".repeat(64), client: { async reportEvidence() { sent = true; } } }), /does not match/);
  assert.equal(sent, false);
  await assert.rejects(reportAdcsExpectedIdentity({ ...args, client: { async reportEvidence() { throw new Error("ack lost"); } } }), /ack lost/);
});
