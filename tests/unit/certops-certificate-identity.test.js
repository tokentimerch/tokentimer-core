"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeFingerprint,
  retireCertificateIdentity,
} = require("../../apps/api/services/certops/certificateIdentity");

const workspaceId = "11111111-1111-4111-8111-111111111111";
const identityId = "22222222-2222-4222-8222-222222222222";
const fingerprint = "ab".repeat(32);

function dbFor({ lifecycle = "active", observations = [], running = [] } = {}) {
  const statements = [];
  const identity = {
    id: identityId,
    workspace_id: workspaceId,
    fingerprint_sha256: fingerprint,
    lifecycle_status: lifecycle,
  };
  const client = {
    async query(sql) {
      statements.push(sql);
      if (sql.includes("FROM certops_certificate_identities") && sql.includes("FOR UPDATE")) {
        return { rows: [identity], rowCount: 1 };
      }
      if (sql.includes("FROM certificate_instances ci")) {
        return { rows: observations, rowCount: observations.length };
      }
      if (sql.includes("SELECT cj.id FROM certificate_jobs")) {
        return { rows: running, rowCount: running.length };
      }
      if (sql.includes("UPDATE certops_certificate_identities SET")) {
        return { rows: [{ ...identity, lifecycle_status: "decommissioned" }], rowCount: 1 };
      }
      if (sql.includes("SELECT DISTINCT token_id")) return { rows: [], rowCount: 0 };
      return { rows: [], rowCount: 0 };
    },
    release() {},
  };
  return { statements, connect: async () => client };
}

function decommission(db, overrides = {}) {
  return retireCertificateIdentity({
    workspaceId, identityId, expectedFingerprintSha256: fingerprint,
    status: "decommissioned", reason: "Operator verified replacement",
    client: db, ...overrides,
  });
}

test("fingerprint normalization accepts colon format and rejects missing identity", () => {
  assert.equal(normalizeFingerprint("AB:".repeat(31) + "AB"), fingerprint);
  assert.equal(normalizeFingerprint("not a fingerprint"), null);
});

test("identity precondition fails without a fingerprint before any mutation", async () => {
  const db = dbFor();
  await assert.rejects(decommission(db, { expectedFingerprintSha256: null }),
    { code: "CERTOPS_IDENTITY_PRECONDITION_REQUIRED" });
  assert.equal(db.statements.length, 0);
});

test("fresh confirmed service use blocks decommission even with acknowledgment", async () => {
  const db = dbFor({ observations: [{ presence_state: "confirmed_present",
    evidence_kind: "service_binding", fresh: true }] });
  await assert.rejects(decommission(db, { acknowledgeUncertainty: true }),
    { code: "CERTOPS_CERTIFICATE_STILL_SERVING" });
  assert(db.statements.includes("ROLLBACK"));
  assert(!db.statements.some((sql) => sql.includes("UPDATE certops_certificate_identities SET")));
});

test("unknown visibility requires acknowledgment and a running install blocks afterward", async () => {
  const db = dbFor({ observations: [{ presence_state: "unknown", fresh: false }],
    running: [{ id: "job-1" }] });
  await assert.rejects(decommission(db), { code: "CERTOPS_VISIBILITY_ACK_REQUIRED" });
  await assert.rejects(decommission(db, { acknowledgeUncertainty: true }),
    { code: "CERTOPS_MUTATION_RUNNING" });
});

test("acknowledged uncertain decommission commits and preserves source management", async () => {
  const db = dbFor({ observations: [{ presence_state: "unknown", fresh: false }] });
  const result = await decommission(db, { acknowledgeUncertainty: true });
  assert.equal(result.lifecycleStatus, "decommissioned");
  assert(db.statements.includes("COMMIT"));
  assert(!db.statements.some((sql) => sql.includes("UPDATE certops_management_periods")));
});

test("revoked lifecycle cannot be downgraded to decommissioned", async () => {
  const db = dbFor({ lifecycle: "revoked" });
  await assert.rejects(decommission(db, { acknowledgeUncertainty: true }),
    { code: "CERTOPS_LIFECYCLE_DOWNGRADE" });
});
