"use strict";
// Read-only production candidate searches against the real lost-response CSR.
// Ambiguity is created by one explicitly owned operator submission, never by
// editing the agent journal or by allowing an automatic retry of uncertainty.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { readEnrollmentJournal, createAdcsIssuer, assertIssuanceOutcome,
  resolveAdcsCmcHelperPath } = require("../../../packages/agent/src/issuers");
const { tryReconcileUncertainSubmission } = require("../../../packages/agent/src/issuers/adcs-enrollment-reconcile");

function verifyCandidateProof(proof) {
  assert.deepEqual(Object.keys(proof).sort(), ["origin", "outcomes", "requestIds", "caRequestCounts", "originalCsrSha256", "originalSpkiSha256", "journalAndKeyPreserved", "operatorDuplicateRevoked", "agentSubmissionCount", "operatorInjectedSubmissionCount"].sort());
  assert.equal(proof.origin, "real-response-loss-with-one-explicit-operator-duplicate");
  assert.deepEqual(proof.outcomes, ["unresolved", "unique_candidate", "ambiguous"]);
  assert.deepEqual(proof.caRequestCounts, [1, 1, 2]);
  assert.ok(Array.isArray(proof.requestIds) && proof.requestIds.length === 2);
  assert.equal(new Set(proof.requestIds).size, 2);
  for (const id of proof.requestIds) { assert.match(id, /^[1-9][0-9]{0,9}$/); assert.ok(Number(id) <= 0xffffffff); }
  for (const key of ["originalCsrSha256", "originalSpkiSha256"]) assert.match(proof[key], /^[a-f0-9]{64}$/);
  assert.equal(proof.journalAndKeyPreserved, true);
  assert.equal(proof.operatorDuplicateRevoked, true);
  assert.equal(proof.agentSubmissionCount, 1);
  assert.equal(proof.operatorInjectedSubmissionCount, 1);
  return true;
}

async function qualifyResponseLossCandidates({ fixture, api, gate, configDir, workDir,
  enrollmentId, domain, authority, requestId, command }) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  const root = path.resolve(__dirname, "../../..");
  const file = "tests/e2e/helpers/certops-adcs-response-loss-candidates.js";
  gate.report.fixtureSources ??= [];
  gate.report.fixtureSources.push({file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex")});
  const original = readEnrollmentJournal(configDir, enrollmentId);
  assert.equal(original.kind, "valid");
  assert.equal(original.journal.state, "submission_uncertain");
  assert.ok(original.artifacts.csrPem?.includes("BEGIN CERTIFICATE REQUEST"));
  const native = (script, args) => JSON.parse(command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, `infra/certops-adcs/${script}.ps1`), ...args]));
  const observe = id => native("owned-request-observation", ["-CommonName", domain, "-RequestId", String(id)]);
  const officer = (id, action) => command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(root, "infra/certops-adcs/officer-action.ps1"), "-CommonName", domain, "-RequestId", String(id), "-Action", action]);
  const unchanged = async () => {
    assert.deepEqual(readEnrollmentJournal(configDir, enrollmentId), original);
    const row = (await fixture.pool.query("SELECT state,request_id,operator_request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, enrollmentId])).rows[0];
    assert.equal(row.state, "submission_uncertain"); assert.equal(row.request_id, null); assert.equal(row.operator_request_id, null);
    assert.ok(command("certutil.exe", ["-csp", "Microsoft Software Key Storage Provider", "-key"]).includes(original.journal.containerName));
  };
  const directory = path.join(workDir, "response-loss-candidates");
  fs.mkdirSync(directory);
  const caCertPath = path.join(directory, "public-ca.cer");
  fs.writeFileSync(caCertPath, Buffer.from(authority.certificateB64, "base64"));
  const helper = resolveAdcsCmcHelperPath(); assert.equal(helper.error, undefined);
  const issuer = createAdcsIssuer({ caConfig: original.journal.caConfig, template: original.journal.template,
    caKeySha256: authority.keySha256, caCertPath, helperPath: helper.path, scratchDir: directory,
    jobId: `response-candidates-${crypto.randomUUID()}`, enrollmentId, timeoutMs: 30000 });
  const search = (start, windowSize = 1) => tryReconcileUncertainSubmission({ issuer, stateDir: configDir,
    caConfig: original.journal.caConfig, csrSpkiSha256: original.journal.csrSpkiSha256,
    reconcileSearchFrom: start, windowSize, assertIssuanceOutcome });
  assert.equal(observe(requestId).subjectRequestCount, 1);
  const checkpoint = native("owned-ca-checkpoint", ["-RunId", domain.match(/^certops-adcs-([a-f0-9]+)-/)[1]]);
  assert.ok(checkpoint.highestRequestId < 0xffffffff);
  const zero = await search(checkpoint.highestRequestId + 1);
  assert.equal(zero.status, "unresolved"); assert.equal(zero.certificatePem, undefined); assert.equal(zero.requestId, undefined); await unchanged();
  const one = await search(requestId);
  assert.equal(one.status, "unique_candidate"); assert.equal(String(one.requestId), String(requestId)); assert.equal(one.attachmentEligible, true); await unchanged();
  assert.equal(observe(requestId).subjectRequestCount, 1);
  let duplicateId, primary, cleanup;
  try {
    const submitted = assertIssuanceOutcome(await issuer.submit({ csrPem: original.artifacts.csrPem, domains: [domain] }));
    assert.equal(submitted.outcome, "pending");
    duplicateId = Number(submitted.requestId);
    assert.ok(Number.isInteger(duplicateId) && duplicateId > requestId && duplicateId <= 0xffffffff);
    const duplicate = observe(duplicateId); assert.equal(duplicate.subjectRequestCount, 2); assert.equal(duplicate.disposition, 9);
    officer(duplicateId, "approve");
    const retrieved = assertIssuanceOutcome(await issuer.retrieve(duplicateId)); assert.equal(retrieved.outcome, "issued");
    const leaf = new crypto.X509Certificate(retrieved.certificatePem);
    assert.equal(leaf.verify(new crypto.X509Certificate(Buffer.from(authority.certificateB64, "base64")).publicKey), true);
    assert.equal(crypto.createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex"), original.journal.csrSpkiSha256);
    assert.ok(duplicateId - requestId < 64);
    const multiple = await search(requestId, duplicateId - requestId + 1);
    assert.equal(multiple.status, "ambiguous"); assert.equal(multiple.matchCount, 2);
    assert.equal(multiple.certificatePem, undefined); assert.equal(multiple.requestId, undefined);
    await unchanged(); assert.equal(observe(requestId).subjectRequestCount, 2);
  } catch (error) { primary = error; }
  finally {
    if (duplicateId) try { const owned = observe(duplicateId); officer(duplicateId, owned.disposition === 9 ? "deny" : "revoke"); if (owned.disposition === 20) assert.equal(observe(duplicateId).disposition, 21); } catch (error) { cleanup = error; }
  }
  if (cleanup) throw new AggregateError([...(primary ? [primary] : []), cleanup], "Response-loss candidate observation and owned duplicate cleanup failed");
  if (primary) throw primary;
  const proof = { origin: "real-response-loss-with-one-explicit-operator-duplicate", outcomes: [zero.status, one.status, "ambiguous"],
    requestIds: [String(requestId), String(duplicateId)], caRequestCounts: [1, 1, 2],
    originalCsrSha256: original.journal.csrSha256, originalSpkiSha256: original.journal.csrSpkiSha256,
    journalAndKeyPreserved: true, operatorDuplicateRevoked: true, agentSubmissionCount: 1, operatorInjectedSubmissionCount: 1 };
  verifyCandidateProof(proof);
  return proof;
}
module.exports = { qualifyResponseLossCandidates, verifyCandidateProof };
