"use strict";

/**
 * Named audit/evidence-redaction test, modeled on certctl's
 * audit_redact_test.go: prove that a field which must never reach an audit
 * row (a `pem` / full private-key-bearing value) is actually stripped before
 * the row is written, not merely "supposed to be" by convention.
 *
 * The exact target this pattern was written for, a `distribute-trust` job
 * type carrying a `pem` field on its signed payload, does not exist yet in
 * this codebase (it is referenced only as a future decision in
 * docs/adr/0012-certops-windows-execution-surface-and-trust-anchors.md). The
 * closest currently-existing analogous case is tested here instead:
 * agentDispatch.ingestResult's CERTOPS_JOB_FAILED audit event. Its
 * errorMessage field is agent-controlled free text (the agent is a machine
 * principal on the far side of a network boundary, not a value the control
 * plane constructs), so a compromised or buggy agent that echoes a private
 * key or another secret into its failure text is exactly the same shape of
 * risk as a job type whose payload carries a `pem` field: attacker-reachable
 * input flowing into a durable, widely-readable, exportable audit trail.
 *
 * tests/unit/certops-audit-coverage.test.js already has one light check of
 * this mechanism ("scrubs key material out of the agent's error text"). This
 * file goes further, on purpose, in the direction certctl's redact test
 * goes: multiple secret shapes (not just one PEM block), a field explicitly
 * labelled "pem" inside the free text (so the exact field name called out in
 * the backlog item is represented even though this schema has no literal
 * `pem` field), a full deep-scan of the ENTIRE audit_events row (not just
 * the one field expected to be redacted, in case a secret leaked into a
 * different metadata key), and a check that the same redaction also holds
 * for the certificate_jobs.error_message column that the same code path
 * persists, since that is a second durable, queryable store the same
 * agent-controlled text reaches.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const dispatch = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentDispatch.js"),
);
const {
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
  GENERIC_SECRET_REDACTION_PLACEHOLDER,
} = require(
  path.resolve(__dirname, "../../packages/log-scrub/secret-material.js"),
);

const WORKSPACE = "11111111-1111-4111-8111-111111111111";

const AGENT = {
  id: "agent-row-1",
  workspaceId: WORKSPACE,
  agentId: "edge-01",
  status: "active",
  protocolVersion: "1.0.0",
};

/**
 * Same shape as tests/unit/certops-audit-coverage.test.js's resultPool, kept
 * local and minimal so this file has no cross-file test-order coupling.
 * Captures both the audit_events insert (what an operator/exporter reads)
 * and the certificate_jobs UPDATE (the other durable store this same
 * agent-controlled text reaches) on the same mock transaction client.
 */
function resultPool() {
  const audits = [];
  const transaction = [];
  let jobUpdateParams = null;
  const client = {
    async query(text, params) {
      const sql = typeof text === "string" ? text : text?.text || "";
      const trimmed = sql.trim().toUpperCase();
      if (trimmed === "BEGIN" || trimmed === "COMMIT" || trimmed === "ROLLBACK") {
        transaction.push(trimmed);
        return { rows: [] };
      }
      if (sql.includes("INSERT INTO audit_events")) {
        audits.push({
          actorUserId: params[0],
          action: params[2],
          targetType: params[3],
          metadata: params[6],
          workspaceId: params[7],
        });
        return { rows: [] };
      }
      if (sql.includes("SET last_sequence")) return { rows: [{ id: "agent-row-1" }] };
      if (sql.includes("FROM certops_agents")) return { rows: [{ id: "agent-row-1" }] };
      if (sql.includes("INSERT INTO certops_outbox")) {
        return { rows: [{ id: "outbox-1" }] };
      }
      if (sql.includes("FROM certificate_jobs") && sql.includes("FOR UPDATE")) {
        return {
          rows: [
            {
              id: 42,
              status: "claimed",
              claimed_by_agent_id: "agent-row-1",
              claim_id: "claim-1",
              operation: "renew",
              subject_type: "managed_certificate",
              subject_id: null,
              error_code: null,
              completed_at: null,
              mode: "real",
              source: "auto",
              payload: null,
            },
          ],
        };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        jobUpdateParams = params;
        return {
          rows: [
            {
              id: 42,
              status: params[1],
              error_code: params[2],
              completed_at: new Date(),
              needs_operator_reconciliation: false,
              reconciliation_reason: null,
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    },
    release() {},
  };
  return {
    audits,
    transaction,
    get jobUpdateParams() {
      return jobUpdateParams;
    },
    client,
    connect: async () => client,
    query: client.query,
  };
}

async function ingestFailure(errorMessage) {
  const pool = resultPool();
  await dispatch.ingestResult({
    dbPool: pool,
    agent: AGENT,
    envelope: { sequence: 11 },
    body: {
      jobId: "42",
      claimId: "claim-1",
      attemptId: "claim-1",
      nonce: "n-1",
      status: "failed",
      errorMessage,
    },
    deps: { consumeNonce: async () => ({ consumed: true }) },
  });
  return pool;
}

describe("CERTOPS_JOB_FAILED audit/evidence redaction (closest existing analog to distribute-trust's pem field)", () => {
  it("never writes a PKCS8 private-key PEM block to the audit row, even under a literal pem: label", async () => {
    const privateKeyPem =
      "-----BEGIN PRIVATE KEY-----\n" +
      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDVeryFakeKeyMaterialThatMustNeverSurvive\n" +
      "-----END PRIVATE KEY-----";
    // The literal "pem:" label stands in for the backlog item's example field
    // name; this schema has no field literally called pem, but agent free
    // text is unstructured and can contain anything, including a copy-pasted
    // "pem: <value>" fragment from a misconfigured deploy script.
    const errorMessage = `distribute-trust rollback failed; pem: ${privateKeyPem}`;

    const pool = await ingestFailure(errorMessage);

    assert.equal(pool.audits.length, 1);
    const event = pool.audits[0];
    assert.equal(event.action, "CERTOPS_JOB_FAILED");

    const auditRowJson = JSON.stringify(event);
    assert.equal(
      auditRowJson.includes("BEGIN PRIVATE KEY"),
      false,
      "audit row must not contain a PEM private-key header",
    );
    assert.equal(
      auditRowJson.includes("VeryFakeKeyMaterialThatMustNeverSurvive"),
      false,
      "audit row must not contain the key body",
    );
    assert.equal(
      event.metadata.errorMessage.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER),
      true,
      "redacted errorMessage must carry the private-key placeholder, not just drop the field silently",
    );

    // Second durable store reached by the same untrusted text: the
    // certificate_jobs.error_message column persisted in the same
    // transaction. Index 3 is error_message, per the UPDATE in
    // agentDispatch.ingestResult.
    const persistedErrorMessage = pool.jobUpdateParams[3];
    assert.equal(
      String(persistedErrorMessage).includes("BEGIN PRIVATE KEY"),
      false,
      "certificate_jobs.error_message must not contain a PEM private-key header either",
    );
  });

  it("never writes an EC private-key PEM block to the audit row", async () => {
    const ecKeyPem =
      "-----BEGIN EC PRIVATE KEY-----\n" +
      "MHcCAQEEIFakeEcKeyBytesThatMustNeverReachAnyAuditOrEvidenceRow\n" +
      "-----END EC PRIVATE KEY-----";
    const pool = await ingestFailure(`agent panicked while holding ${ecKeyPem}`);

    const auditRowJson = JSON.stringify(pool.audits[0]);
    assert.equal(auditRowJson.includes("BEGIN EC PRIVATE KEY"), false);
    assert.equal(
      auditRowJson.includes("FakeEcKeyBytesThatMustNeverReachAnyAuditOrEvidenceRow"),
      false,
    );
    assert.equal(
      pool.audits[0].metadata.errorMessage.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER),
      true,
    );
  });

  it("redacts a generic secret (password=) in the same audit row, distinct from key-material redaction", async () => {
    const secretValue = "S3cretDeployPassword!!";
    const errorMessage = `ssh auth failed: password=${secretValue} for host web-01`;
    const pool = await ingestFailure(errorMessage);

    const { errorMessage: storedMessage } = pool.audits[0].metadata;
    assert.equal(storedMessage.includes(secretValue), false);
    assert.equal(storedMessage.includes(GENERIC_SECRET_REDACTION_PLACEHOLDER), true);
  });

  it("redacts an Authorization bearer token embedded in the error text", async () => {
    const token = "abcXYZ123.fakeBearerTokenValue.doNotLeak";
    const errorMessage = `webhook call failed: Authorization: Bearer ${token}`;
    const pool = await ingestFailure(errorMessage);

    const { errorMessage: storedMessage } = pool.audits[0].metadata;
    assert.equal(storedMessage.includes(token), false);
    assert.equal(storedMessage.includes(GENERIC_SECRET_REDACTION_PLACEHOLDER), true);
  });
});
