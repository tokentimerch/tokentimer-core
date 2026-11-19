"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { _test } = require("../../apps/api/services/certops/agentDispatch");

const target = { type: "windows-cert-store", reference: "host.example", store: "My" };
const hash = (value) => createHash("sha256").update(value).digest("hex");
const destination = hash(JSON.stringify(target));
const bytes = Buffer.from(JSON.stringify({ destinationType: target.type, destinationSha256: destination }));
const job = { id: "job", claim_id: "claim", enrollment_id: "enrollment", subject_id: "certificate", assigned_agent_id: "agent", claimed_by_agent_id: "agent", payload: { target } };
const proof = { enrollmentId: "enrollment", destinationType: target.type, destinationSha256: destination, store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true, fingerprintSha256: "a".repeat(64) };
const enrollment = { agent_id: "agent", certificate_id: "certificate", snapshot_bytes: bytes, snapshot_sha256: hash(bytes), deploy_target: target };

function clientFor(metadata = proof, row = enrollment) {
  return { async query(sql, params) {
    if (sql.includes("FROM certificate_evidence")) {
      assert.match(sql, /claim_id = \$3::uuid/);
      assert.match(sql, /step' = 'store-verify'/);
      assert.deepEqual(params, ["workspace", "job", "claim"]);
      return { rows: metadata ? [{ metadata }] : [] };
    }
    assert.match(sql, /FROM certificate_enrollments/);
    assert.deepEqual(params, ["workspace", "enrollment"]);
    return { rows: row ? [row] : [] };
  } };
}

test("accepts only the original agent's claim-bound, frozen store proof", async () => {
  assert.deepEqual(await _test.loadReconciliationEvidence(clientFor(), "workspace", job, { id: "agent" }), proof);
});

test("rejects substituted agents, enrollment, destination and unverified key", async () => {
  for (const changed of [
    { enrollmentId: "other" }, { destinationSha256: "b".repeat(64) },
    { store: "LocalMachine\\WebHosting" }, { keyPossessionVerified: false },
    { machineKey: false }, { nonExportable: false }, { fingerprintSha256: "bad" },
  ]) {
    assert.equal(await _test.loadReconciliationEvidence(clientFor({ ...proof, ...changed }), "workspace", job, { id: "agent" }), null);
  }
  assert.equal(await _test.loadReconciliationEvidence(clientFor(), "workspace", job, { id: "other" }), null);
  assert.equal(await _test.loadReconciliationEvidence(clientFor(proof, { ...enrollment, snapshot_sha256: "bad" }), "workspace", job, { id: "agent" }), null);
  assert.equal(await _test.loadReconciliationEvidence(clientFor(proof, { ...enrollment, agent_id: "other" }), "workspace", job, { id: "agent" }), null);
});

test("ACME promotion requires the persisted CSR, issued leaf, owner and same claim", async () => {
  const acmeJob = { ...job, enrollment_id: null };
  const snapshotBytes = Buffer.from(JSON.stringify({ workspaceId: "workspace", certificateId: "certificate", agentId: "agent", jobId: "job", target }));
  const row = { id: "acme-enrollment", agent_id: "agent", certificate_id: "certificate", original_job_id: "job", current_job_id: "job",
    container_name: "container", request_bytes: snapshotBytes, request_sha256: hash(snapshotBytes), state: "installed", csr_sha256: "b".repeat(64),
    csr_spki_sha256: "c".repeat(64), fingerprint_sha256: "a".repeat(64) };
  const receipt = { enrollmentId: row.id, requestSha256: row.request_sha256, containerName: row.container_name,
    csrSha256: row.csr_sha256, csrSpkiSha256: row.csr_spki_sha256, fingerprintSha256: row.fingerprint_sha256,
    store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true };
  const client = (metadata = receipt, persisted = row) => ({ async query(sql, params) {
    if (sql.includes("FROM certificate_evidence")) { assert.match(sql, /acme-store-receipt/); assert.deepEqual(params, ["workspace", "job", "claim"]); return { rows: [{ metadata }] }; }
    assert.match(sql, /certops_acme_store_enrollments/); return { rows: [persisted] };
  } });
  assert.deepEqual(await _test.loadReconciliationEvidence(client(), "workspace", acmeJob, { id: "agent" }), receipt);
  for (const change of [{ fingerprintSha256: "f".repeat(64) }, { csrSpkiSha256: "f".repeat(64) },
    { containerName: "other" }, { keyPossessionVerified: false }, { enrollmentId: "other" }]) {
    assert.equal(await _test.loadReconciliationEvidence(client({ ...receipt, ...change }), "workspace", acmeJob, { id: "agent" }), null);
  }
  for (const change of [{ state: "uncertain" }, { csr_spki_sha256: null }, { agent_id: "other" }, { request_sha256: "f".repeat(64) }]) {
    assert.equal(await _test.loadReconciliationEvidence(client(receipt, { ...row, ...change }), "workspace", acmeJob, { id: "agent" }), null);
  }
  const recoveryJob = { ...acmeJob, id: "recovery", operation: "continue-enrollment", claim_id: "claim" };
  const recoveryClient = { async query(sql, params) {
    if (sql.includes("FROM certificate_evidence")) { assert.deepEqual(params, ["workspace", "recovery", "claim"]); return { rows: [{ metadata: receipt }] }; }
    return { rows: [{ ...row, current_job_id: "recovery" }] };
  } };
  assert.deepEqual(await _test.loadReconciliationEvidence(recoveryClient, "workspace", recoveryJob, { id: "agent" }), receipt);
});

test("first issuance recovery preserves the original job identity for both store issuers", async () => {
  for (const operation of ["adcs-installation-proof", "continue-enrollment"]) {
    const recovery = { ...job, id: "recovery", operation,
      enrollment_id: operation === "adcs-installation-proof" ? "enrollment" : null };
    const calls = [];
    const client = { async query(sql, params) {
      calls.push({ sql, params });
      if (sql.includes("SELECT original.id")) {
        assert.deepEqual(params, operation === "adcs-installation-proof"
          ? ["workspace", "recovery", "agent", "certificate", "enrollment", "a".repeat(64)]
          : ["workspace", "recovery", "agent", "certificate", "a".repeat(64)]);
        assert.match(sql, /original\.assigned_agent_id/);
        assert.match(sql, /original\.subject_id/);
        assert.match(sql, /original\.subject_type='managed_certificate'/);
        return { rows: [{ id: "original-issue", operation: "issue", certificate_identity_id: null }] };
      }
      assert.match(sql, /INSERT INTO certops_issuance_job_identities/);
      assert.deepEqual(params, ["workspace", "original-issue", "a".repeat(64)]);
      return { rows: [], rowCount: 1 };
    } };
    await _test.preserveRecoveredIssuanceIdentity({ client, workspaceId: "workspace", job: recovery, fingerprint: "a".repeat(64) });
    assert.equal(calls.length, 2);
    await assert.rejects(_test.preserveRecoveredIssuanceIdentity({ client: { query: async () => ({ rows: [] }) },
      workspaceId: "workspace", job: recovery, fingerprint: "a".repeat(64) }), /Original store enrollment job/);
    await assert.rejects(_test.preserveRecoveredIssuanceIdentity({ client: { query: async () => ({ rows: [{ id: "a" }, { id: "b" }] }) },
      workspaceId: "workspace", job: recovery, fingerprint: "a".repeat(64) }), /ambiguous/);
  }
});

test("replaying recovered issuance accepts only the existing matching identity", async () => {
  const recovery = { ...job, id: "recovery", operation: "continue-enrollment", enrollment_id: null };
  let existing = true;
  const client = { async query(sql, params) {
    if (sql.includes("SELECT original.id")) return { rows: [{ id: "original-issue", operation: "issue", certificate_identity_id: null }] };
    assert.deepEqual(params, ["workspace", "original-issue", "a".repeat(64)]);
    if (sql.includes("INSERT INTO certops_issuance_job_identities")) return { rowCount: 0, rows: [] };
    assert.match(sql, /identity\.fingerprint_sha256/);
    return { rowCount: existing ? 1 : 0, rows: existing ? [{}] : [] };
  } };
  await _test.preserveRecoveredIssuanceIdentity({ client, workspaceId: "workspace", job: recovery, fingerprint: "a".repeat(64) });
  existing = false;
  await assert.rejects(_test.preserveRecoveredIssuanceIdentity({ client, workspaceId: "workspace", job: recovery,
    fingerprint: "a".repeat(64) }), /Unable to preserve/);
});
