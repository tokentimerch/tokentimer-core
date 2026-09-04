"use strict";

/**
 * Named audit/evidence-redaction test: prove that a field which must never
 * reach a persisted row (a `pem` / full private-key-bearing value) is
 * actually stripped or rejected before the row is written, not merely
 * "supposed to be" by convention.
 *
 * This file exercises the REAL persistence writers directly:
 * apps/api/services/certops/jobs.js (createCertificateJob) and
 * apps/api/services/certops/evidence.js (createCertificateEvidence). Only
 * the terminal SQL execution is stubbed, via the same minimal in-memory
 * Postgres-like mock client already used by tests/unit/certops-jobs.test.js
 * and tests/unit/certops-evidence.test.js; every normalization, field-name
 * check, and content scan the writers run is the unmodified production
 * code path. tests/unit runs with no database available (see
 * scripts/run-unit-tests.js and the "Backend Quality Checks" CI job), so a
 * live-database version of this test lives instead in
 * tests/integration/certops-jobs-evidence.test.js, which already covers the
 * same rejection behavior end-to-end against a real Postgres instance.
 *
 * Trust-anchor: PR #125 added SUBJECT_TYPES.trust_anchor and the
 * distribute-trust/revoke-trust operations. The tests below exercise the
 * real distribute-trust/revoke-trust write path the same way the
 * managed_certificate tests above exercise the certificate write path,
 * proving createCertificateJob's forbidden-field rejection also holds for
 * a trust_anchor subject and the operation this pattern was originally
 * written for.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  PRIVATE_KEY_MATERIAL_REJECTED,
  SUBJECT_TYPES,
  createCertificateJob,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
);
const { createCertificateEvidence } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/evidence.js"),
);
const {
  GENERIC_SECRET_REDACTION_PLACEHOLDER,
} = require(
  path.resolve(__dirname, "../../packages/log-scrub/secret-material.js"),
);

const WORKSPACE = "11111111-1111-4111-8111-111111111111";

// PKCS8 PEM header/footer plus a body substring distinctive enough that its
// presence anywhere in a persisted row can only mean the raw key material
// leaked through; ordinary base64 certificate/log content would not collide
// with it.
const PRIVATE_KEY_PEM =
  "-----BEGIN PRIVATE KEY-----\n" +
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDVeryFakeKeyMaterialThatMustNeverSurvive\n" +
  "-----END PRIVATE KEY-----";
const PRIVATE_KEY_PEM_BODY_SUBSTRING =
  "VeryFakeKeyMaterialThatMustNeverSurvive";

/**
 * Minimal in-memory Postgres-like mock, trimmed to the two INSERT shapes and
 * two lookup shapes createCertificateJob/createCertificateEvidence issue in
 * this test's code paths. Mirrors the fuller mocks in
 * tests/unit/certops-jobs.test.js and tests/unit/certops-evidence.test.js;
 * kept local and smaller here so this file has no cross-file coupling.
 */
function json(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function createMemoryClient() {
  const jobs = [];
  const evidence = [];
  const queryLog = [];
  let nextJob = 1;
  let nextEvidence = 1;

  return {
    jobs,
    evidence,
    queryLog,
    async query(sql, params = []) {
      const normalizedSql = sql.replace(/\s+/g, " ");
      queryLog.push({ sql: normalizedSql, params });

      if (
        normalizedSql.includes("FROM workspaces") &&
        normalizedSql.includes("certops_require_approval_always")
      ) {
        return { rows: [{ certops_require_approval_always: false }] };
      }

      if (normalizedSql.includes("INSERT INTO certificate_jobs")) {
        const row = {
          id: `job-${nextJob++}`,
          workspace_id: params[0],
          operation: params[1],
          status: params[2],
          mode: params[3],
          source: params[4],
          executor_kind: params[5],
          requested_by_user_id: params[6],
          requested_by_api_token_id: params[7],
          idempotency_key: params[8],
          subject_type: params[9],
          subject_id: params[10],
          payload: json(params[11]),
          result_metadata: json(params[12]),
          error_code: params[13],
          error_message: params[14],
          assigned_agent_id: params[15],
          required_target_selector: params[16],
          required_dns_provider: params[17],
          required_command_profile: params[18],
          created_at: new Date(),
          updated_at: new Date(),
          queued_at: params[19],
          started_at: params[20],
          completed_at: params[21],
          canceled_at: params[22],
          creation_request_hash: params[23],
        };
        jobs.push(row);
        return { rows: [row] };
      }

      if (
        normalizedSql.includes("FROM certificate_jobs") &&
        normalizedSql.includes("AND id = $2") &&
        normalizedSql.includes("LIMIT 1")
      ) {
        return {
          rows: jobs.filter(
            (row) => row.workspace_id === params[0] && row.id === params[1],
          ),
        };
      }

      if (normalizedSql.includes("INSERT INTO certificate_evidence")) {
        const row = {
          id: `evidence-${nextEvidence++}`,
          workspace_id: params[0],
          job_id: params[1],
          evidence_type: params[2],
          subject_type: params[3],
          subject_id: params[4],
          metadata: json(params[5]),
          redacted_output: params[6],
          output_truncated: params[7],
          output_sha256: params[8],
          output_size_bytes: params[9],
          observed_at: params[10],
          created_by_user_id: params[11],
          created_by_api_token_id: params[12],
          created_by_agent_id: params[13] ?? null,
          client_evidence_id: params[14] ?? null,
          created_at: new Date(),
        };
        evidence.push(row);
        return { rows: [row] };
      }

      throw new Error(`unexpected query in certops-audit-redaction test mock: ${normalizedSql}`);
    },
  };
}

async function createBaselineJob(client) {
  return createCertificateJob({
    client,
    workspaceId: WORKSPACE,
    operation: "deploy",
    subjectType: "managed_certificate",
    subjectId: "cert-1",
    payload: { certificateId: "cert-1" },
  });
}

function insertCountFor(queryLog, table) {
  return queryLog.filter((entry) => entry.sql.includes(`INSERT INTO ${table}`))
    .length;
}

describe("CertOps job/evidence persistence never stores raw pem or private-key material", () => {
  it("SUBJECT_TYPES now has a trust_anchor entry (PR #125)", () => {
    assert.equal(SUBJECT_TYPES.includes("trust_anchor"), true);
  });

  it("createCertificateJob rejects a distribute-trust job whose payload carries a pem field, before any row is persisted", async () => {
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE,
          operation: "distribute-trust",
          subjectType: "trust_anchor",
          subjectId: "anchor-1",
          payload: { pem: PRIVATE_KEY_PEM },
        }),
      (error) => error.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.equal(client.jobs.length, 0);
    assert.equal(insertCountFor(client.queryLog, "certificate_jobs"), 0);
  });

  it("createCertificateEvidence rejects a raw private-key PEM block in evidence against a trust_anchor subject, before any row is persisted", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE,
      operation: "distribute-trust",
      subjectType: "trust_anchor",
      subjectId: "anchor-1",
      payload: { trustAnchorId: "anchor-1" },
    });
    const evidenceInsertsBefore = insertCountFor(client.queryLog, "certificate_evidence");

    await assert.rejects(
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE,
          jobId: job.id,
          evidenceType: "trust.distributed",
          subjectType: "trust_anchor",
          subjectId: "anchor-1",
          metadata: { output: PRIVATE_KEY_PEM },
        }),
      (error) => error.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.equal(client.evidence.length, 0);
    assert.equal(
      insertCountFor(client.queryLog, "certificate_evidence"),
      evidenceInsertsBefore,
    );
  });

  it("createCertificateJob rejects a payload field literally named pem, before any row is persisted", async () => {
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE,
          operation: "deploy",
          subjectType: "managed_certificate",
          subjectId: "cert-1",
          payload: { pem: "value does not matter, the field name alone is forbidden" },
        }),
      (error) => error.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.equal(client.jobs.length, 0);
    assert.equal(insertCountFor(client.queryLog, "certificate_jobs"), 0);
  });

  it("createCertificateJob rejects a raw private-key PEM block nested anywhere in the payload, before any row is persisted", async () => {
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE,
          operation: "deploy",
          subjectType: "managed_certificate",
          subjectId: "cert-1",
          payload: {
            deploy: { note: `attaching key: ${PRIVATE_KEY_PEM}` },
          },
        }),
      (error) => error.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.equal(client.jobs.length, 0);
    assert.equal(insertCountFor(client.queryLog, "certificate_jobs"), 0);
  });

  it("createCertificateEvidence rejects a raw private-key PEM block anywhere in metadata, before any row is persisted", async () => {
    const client = createMemoryClient();
    const job = await createBaselineJob(client);
    const evidenceInsertsBefore = insertCountFor(client.queryLog, "certificate_evidence");

    await assert.rejects(
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE,
          jobId: job.id,
          evidenceType: "certificate.observed",
          metadata: { output: PRIVATE_KEY_PEM },
        }),
      (error) => error.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.equal(client.evidence.length, 0);
    assert.equal(
      insertCountFor(client.queryLog, "certificate_evidence"),
      evidenceInsertsBefore,
    );
  });

  it("createCertificateEvidence rejects a raw private-key PEM block passed as the evidence output string, before any row is persisted", async () => {
    const client = createMemoryClient();
    const job = await createBaselineJob(client);

    await assert.rejects(
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE,
          jobId: job.id,
          evidenceType: "validation.failed",
          output: `verify failed, dumping key for debugging: ${PRIVATE_KEY_PEM}`,
        }),
      (error) => error.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.equal(client.evidence.length, 0);
  });

  it("no field of any persisted job or evidence row contains the submitted pem value or its base64 body, across every rejection above", async () => {
    // Belt-and-suspenders full-row deep scan, run after the rejection tests
    // above on a fresh client that attempts the same three submissions in
    // sequence. Asserting per-call codes (above) proves the writers refuse
    // the request; this proves that refusal really left nothing behind, by
    // inspecting every field of every row actually stored, not just the one
    // field each writer was expected to guard.
    const client = createMemoryClient();
    const job = await createBaselineJob(client);

    for (const attempt of [
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE,
          operation: "deploy",
          subjectType: "managed_certificate",
          subjectId: "cert-1",
          payload: { pem: PRIVATE_KEY_PEM },
        }),
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE,
          jobId: job.id,
          evidenceType: "certificate.observed",
          metadata: { note: PRIVATE_KEY_PEM },
        }),
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE,
          jobId: job.id,
          evidenceType: "validation.failed",
          output: PRIVATE_KEY_PEM,
        }),
    ]) {
      await assert.rejects(attempt, (error) => error.code === PRIVATE_KEY_MATERIAL_REJECTED);
    }

    const allPersistedRows = JSON.stringify([...client.jobs, ...client.evidence]);
    assert.equal(allPersistedRows.includes("BEGIN PRIVATE KEY"), false);
    assert.equal(allPersistedRows.includes(PRIVATE_KEY_PEM_BODY_SUBSTRING), false);
    // Only the one baseline job (created before any rejected attempt) should
    // exist; every rejected attempt above must have left the store alone.
    assert.equal(client.jobs.length, 1);
    assert.equal(client.evidence.length, 0);
  });

  it("createCertificateEvidence redacts (does not reject) a generic secret in evidence output, and the persisted row carries no trace of the raw secret", async () => {
    // Contrast case: private-key material is hard-rejected (above), but a
    // generic secret embedded in free-form evidence output is redacted and
    // the (redacted) evidence is still persisted, per
    // packages/log-scrub/secret-material.js's documented two-outcome design.
    const client = createMemoryClient();
    const job = await createBaselineJob(client);
    const secretValue = "S3cretDeployPassword!!";

    const persisted = await createCertificateEvidence({
      client,
      workspaceId: WORKSPACE,
      jobId: job.id,
      evidenceType: "validation.failed",
      output: `ssh auth failed: password=${secretValue} for host web-01`,
    });

    assert.equal(persisted.redactedOutput.includes(secretValue), false);
    assert.equal(
      persisted.redactedOutput.includes(GENERIC_SECRET_REDACTION_PLACEHOLDER),
      true,
    );

    const storedRow = client.evidence.find((row) => row.id === persisted.id);
    const storedRowJson = JSON.stringify(storedRow);
    assert.equal(storedRowJson.includes(secretValue), false);
    assert.equal(storedRowJson.includes(GENERIC_SECRET_REDACTION_PLACEHOLDER), true);
  });
});
