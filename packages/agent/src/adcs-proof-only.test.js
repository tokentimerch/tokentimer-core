"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { executeAdcsProofOnly } = require("./adcs-proof-only");
const pem = fs.readFileSync(path.join(__dirname, "verify/fixtures/leaf.crt.pem"), "utf8"), leaf = new crypto.X509Certificate(pem);
const hex = value => crypto.createHash("sha256").update(value).digest("hex");
const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", target = { type: "windows-cert-store", reference: "app.example.com", store: "My" };
const destinationSha256 = hex(JSON.stringify(target)), spki = hex(leaf.publicKey.export({ type: "spki", format: "der" })), fingerprint = hex(leaf.raw);
const snapshot = { kind: "adcs", destinationType: target.type, destinationSha256, predecessorFingerprintSha256: null, authorizedDnsNames: [target.reference] };
const bytes = Buffer.from(JSON.stringify(snapshot)), snapshotSha256 = hex(bytes);
const proof = { receiptId: id, enrollmentId: id, agentId: id, originalJobId: id, originalClaimId: id, originalAttempt: 1,
  snapshotSha256, destinationSha256, fingerprintSha256: fingerprint, csrSpkiSha256: spki };
function fixture() {
  const events = [], lock = { assertHeld() {}, async run(fn) { return fn(new AbortController().signal); }, release() {} };
  const job = { action: "adcs-installation-proof", issuerKind: "adcs", keyMode: "os-store-managed", target, adcsProof: proof,
    enrollment: { enrollmentId: id, attempt: 1, snapshotSha256, snapshotB64: bytes.toString("base64") } };
  return { events, args: { job, jobId: "proof-job", claimId: "claim-1", client: {}, stateDir: "state", acquireEnrollment: () => lock, acquireStore: () => lock,
    readJournal: () => ({ kind: "valid", journal: { state: "installed", snapshotSha256, csrSpkiSha256: spki, containerName: `tokentimer-enr-${id}` }, artifacts: { leafPem: pem } }),
    inspect: async () => ({ status: "complete", fingerprintSha256: fingerprint }), reportEvidence: async (_client, _job, items, claimId) => { assert.equal(claimId, "claim-1"); events.push(...items); } } };
}
test("read-only proof verifies the original leaf and reports the fresh claim evidence", async () => {
  const f = fixture(); assert.equal((await executeAdcsProofOnly(f.args)).status, "succeeded");
  assert.equal(f.events.length, 1); assert.equal(f.events[0].fingerprintSha256, fingerprint);
  assert.equal(f.events[0].metadata.find(x => x.name === "step").value, "adcs-proof-only");
  assert.equal(f.events[0].metadata.find(x => x.name === "ownerAgentId").value, id);
  assert.equal(f.events[0].metadata.some(x => x.name === "agentId"), false);
  const item = { ...f.events[0], evidenceId: "proof-1" };
  const envelope = { schemaVersion: 1, protocolVersion: "1.0.0", messageType: "evidence", agentId: "agent-1", sentAt: new Date().toISOString(),
    body: { jobId: "job-1", claimId: "claim-1", evidenceItems: [item] } };
  assert.doesNotThrow(() => require("../../../apps/api/routes/certops-agent")._test.validateEnvelope(envelope, "evidence"));
});
test("substitution or unproven key never emits success evidence", async () => {
  for (const mutate of [
    f => { f.args.job = { ...f.args.job, adcsProof: { ...proof, fingerprintSha256: "f".repeat(64) } }; },
    f => { f.args.job = { ...f.args.job, target: { ...target, reference: "other.example.com" } }; },
    f => { f.args.job = { ...f.args.job, enrollment: { ...f.args.job.enrollment, snapshotSha256: "f".repeat(64) } }; },
    f => { f.args.inspect = async () => ({ status: "error" }); },
    f => { f.args.readJournal = () => ({ kind: "not_found" }); },
  ]) { const f = fixture(); mutate(f); assert.equal((await executeAdcsProofOnly(f.args)).status, "failed"); assert.equal(f.events.length, 0); }
});

test("proof-only serializes its current claim through the real evidence builder", async () => {
  const f = fixture();
  let body;
  f.args.client = require("./protocol").createProtocolClient({ serverUrl: "https://example.test", agentId: "agent-1", protocolVersion: "1.0.0", getCredential: () => "ttagent_agent-1_0123456789abcdef", fetchImpl: async (_url, init) => { body = JSON.parse(init.body); return { ok: true, status: 202, json: async () => ({ accepted: true }) }; } });
  f.args.reportEvidence = require("./index").reportStepEvidence;
  assert.equal((await executeAdcsProofOnly(f.args)).status, "succeeded");
  assert.equal(body.body.claimId, "claim-1");
  assert.ok(body.body.evidenceItems[0].evidenceId);
  assert.doesNotThrow(() => require("../../../apps/api/routes/certops-agent")._test.validateEnvelope(body, "evidence"));
});
