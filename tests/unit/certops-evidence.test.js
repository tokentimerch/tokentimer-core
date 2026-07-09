"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { createCertificateJob } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
);
const {
  CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE,
  CERTOPS_EVIDENCE_TYPE_INVALID,
  PRIVATE_KEY_MATERIAL_REJECTED,
  createCertificateEvidence,
  getCertificateEvidenceById,
  listCertificateEvidence,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/evidence.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const WORKSPACE_B = "22222222-2222-4222-8222-222222222222";
const PRIVATE_KEY_PEM =
  "-----BEGIN EC PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END EC PRIVATE KEY-----";

function json(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function createMemoryClient() {
  const jobs = [];
  const evidence = [];
  const queryLog = [];
  let nextJob = 1;
  let nextEvidence = 1;
  let tick = 0;
  const now = () => new Date(Date.UTC(2026, 5, 30, 1, tick++, 0));

  return {
    jobs,
    evidence,
    queryLog,
    async query(sql, params = []) {
      const normalizedSql = sql.replace(/\s+/g, " ");
      queryLog.push({ sql: normalizedSql, params });

      if (normalizedSql.includes("INSERT INTO certificate_jobs")) {
        const createdAt = now();
        const row = {
          id: `job-${nextJob++}`,
          workspace_id: params[0],
          operation: params[1],
          status: params[2],
          source: params[3],
          requested_by_user_id: params[4],
          requested_by_api_token_id: params[5],
          idempotency_key: params[6],
          subject_type: params[7],
          subject_id: params[8],
          payload: json(params[9]),
          result_metadata: json(params[10]),
          error_code: params[11],
          error_message: params[12],
          created_at: createdAt,
          updated_at: createdAt,
          queued_at: params[13],
          started_at: params[14],
          completed_at: params[15],
          canceled_at: params[16],
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
          created_at: now(),
        };
        evidence.push(row);
        return { rows: [row] };
      }

      if (
        normalizedSql.includes("FROM certificate_evidence") &&
        normalizedSql.includes("AND id = $2") &&
        normalizedSql.includes("LIMIT 1")
      ) {
        return {
          rows: evidence.filter(
            (row) => row.workspace_id === params[0] && row.id === params[1],
          ),
        };
      }

      if (
        normalizedSql.includes("FROM certificate_evidence") &&
        normalizedSql.includes("ORDER BY created_at DESC")
      ) {
        let rows = evidence.filter((row) => row.workspace_id === params[0]);
        let paramIndex = 1;
        if (normalizedSql.includes("job_id = $")) {
          rows = rows.filter((row) => row.job_id === params[paramIndex]);
          paramIndex += 1;
        }
        if (normalizedSql.includes("subject_type = $")) {
          rows = rows.filter((row) => row.subject_type === params[paramIndex]);
          paramIndex += 1;
        }
        if (normalizedSql.includes("subject_id = $")) {
          rows = rows.filter((row) => row.subject_id === params[paramIndex]);
        }
        return { rows };
      }

      throw new Error(`Unexpected query: ${normalizedSql}`);
    },
  };
}

function collectKeys(value, keys = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, keys);
    return keys;
  }
  if (!value || typeof value !== "object") return keys;
  for (const [key, item] of Object.entries(value)) {
    keys.push(key);
    collectKeys(item, keys);
  }
  return keys;
}

function assertNoCustodyKeys(value) {
  const forbidden = [
    "privatekey",
    "privatekeypem",
    "encryptedprivatekey",
    "keymaterial",
    "pfxblob",
    "jksblob",
    "tlskey",
    "caprivatekey",
    "keystorepassword",
    "privatekeypassword",
    "keypassword",
    "password",
    "secret",
    "credential",
    "tokensecret",
    "apisecret",
    "rawsecret",
    "rawprivatekey",
    "rawkey",
    "pemprivatekey",
  ];

  for (const key of collectKeys(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    const hit = forbidden.find((fragment) => normalized.includes(fragment));
    assert.equal(hit, undefined, `${key} looks like a custody field`);
  }
  assert.equal(JSON.stringify(value).includes("PRIVATE KEY"), false);
}

async function createJob(client, workspaceId = WORKSPACE_A) {
  return createCertificateJob({
    client,
    workspaceId,
    operation: "renew",
    payload: { certificateId: "cert-1" },
  });
}

describe("CertOps evidence service", () => {
  it("creates evidence with safe public metadata", async () => {
    const client = createMemoryClient();
    const job = await createJob(client);
    const evidence = await createCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      evidenceType: "certificate.observed",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      metadata: {
        fingerprintSha256:
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        issuerCn: "TokenTimer Test CA",
        notAfter: "2027-06-30T00:00:00.000Z",
      },
      observedAt: "2026-06-30T01:00:00.000Z",
    });

    assert.equal(evidence.workspaceId, WORKSPACE_A);
    assert.equal(evidence.jobId, job.id);
    assert.equal(evidence.evidenceType, "certificate.observed");
    assert.equal(evidence.metadata.issuerCn, "TokenTimer Test CA");
    assert.match(evidence.observedAt, /^2026-06-30T01:00:00/);
    assertNoCustodyKeys(evidence);

    const bySubjectId = await listCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      subjectId: "cert-1",
    });
    assert.deepEqual(bySubjectId.items.map((item) => item.id), [evidence.id]);
  });

  it("gets and lists evidence scoped by workspace and job", async () => {
    const client = createMemoryClient();
    const jobA = await createJob(client, WORKSPACE_A);
    const jobB = await createJob(client, WORKSPACE_B);
    const evidenceA = await createCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      jobId: jobA.id,
      evidenceType: "deployment.checked",
      metadata: { target: "endpoint/api.example.com" },
    });
    await createCertificateEvidence({
      client,
      workspaceId: WORKSPACE_B,
      jobId: jobB.id,
      evidenceType: "deployment.checked",
      metadata: { target: "endpoint/other.example.com" },
    });

    assert.equal(
      (await getCertificateEvidenceById({
        client,
        workspaceId: WORKSPACE_A,
        evidenceId: evidenceA.id,
      })).id,
      evidenceA.id,
    );
    assert.equal(
      await getCertificateEvidenceById({
        client,
        workspaceId: WORKSPACE_B,
        evidenceId: evidenceA.id,
      }),
      null,
    );

    const listA = await listCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      jobId: jobA.id,
    });
    const listB = await listCertificateEvidence({
      client,
      workspaceId: WORKSPACE_B,
      jobId: jobB.id,
    });
    assert.deepEqual(listA.items.map((item) => item.id), [evidenceA.id]);
    assert.equal(listB.items.some((item) => item.id === evidenceA.id), false);
  });

  it("rejects invalid evidence types", async () => {
    const client = createMemoryClient();
    const job = await createJob(client);

    await assert.rejects(
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          evidenceType: "private-key.uploaded",
          metadata: {},
        }),
      (error) => error?.code === CERTOPS_EVIDENCE_TYPE_INVALID,
    );
  });

  it("rejects dangerous metadata recursively before persistence", async () => {
    const client = createMemoryClient();
    const job = await createJob(client);

    await assert.rejects(
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          evidenceType: "certificate.observed",
          metadata: { nested: [{ password: "not-allowed" }] },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.equal(client.evidence.length, 0);

    await assert.rejects(
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          evidenceType: "certificate.observed",
          metadata: { output: PRIVATE_KEY_PEM },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.equal(client.evidence.length, 0);
  });

  it("stores bounded redacted output separately from normalized metadata", async () => {
    const client = createMemoryClient();
    const job = await createJob(client);
    const evidence = await createCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      evidenceType: "deployment.checked",
      metadata: { target: "endpoint/api.example.com" },
      output: "deployment ok password=swordfish",
    });

    assert.equal(evidence.metadata.target, "endpoint/api.example.com");
    assert.equal(evidence.redactedOutput, "deployment ok [REDACTED]");
    assert.equal(evidence.outputTruncated, false);
    assert.equal(evidence.outputSizeBytes, Buffer.byteLength("deployment ok password=swordfish"));
    assert.match(evidence.outputSha256, /^[a-f0-9]{64}$/);
    assert.equal(evidence.outputRedactionApplied, true);
    assert.equal(JSON.stringify(evidence).includes("swordfish"), false);
  });

  it("rejects private-key and oversized evidence output before persistence", async () => {
    const client = createMemoryClient();
    const job = await createJob(client);

    await assert.rejects(
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          evidenceType: "deployment.checked",
          metadata: { target: "endpoint/api.example.com" },
          output: PRIVATE_KEY_PEM,
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );

    await assert.rejects(
      () =>
        createCertificateEvidence({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          evidenceType: "deployment.checked",
          metadata: { target: "endpoint/api.example.com" },
          output: "a".repeat(65537),
        }),
      (error) => error?.code === CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE,
    );
  });

  it("rejects secret-looking subject IDs before persistence", async () => {
    const client = createMemoryClient();
    const job = await createJob(client);

    for (const subjectId of ["password=swordfish", "credential=abc"]) {
      await assert.rejects(
        () =>
          createCertificateEvidence({
            client,
            workspaceId: WORKSPACE_A,
            jobId: job.id,
            evidenceType: "certificate.observed",
            subjectType: "managed_certificate",
            subjectId,
            metadata: { fingerprintSha256: "safe-public-fingerprint" },
          }),
        (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
      );
    }

    assert.equal(client.evidence.length, 0);
    assert.equal(JSON.stringify(client.evidence).includes("swordfish"), false);
    assert.equal(JSON.stringify(client.evidence).includes("credential=abc"), false);
  });

  it("rejects secret-looking subject ID filters before querying", async () => {
    const client = createMemoryClient();

    await assert.rejects(
      () =>
        listCertificateEvidence({
          client,
          workspaceId: WORKSPACE_A,
          subjectId: "password=swordfish",
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );

    assert.equal(client.queryLog.length, 0);
  });

  it("does not return private-key-looking fields", async () => {
    const client = createMemoryClient();
    const job = await createJob(client);
    await createCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      evidenceType: "validation.passed",
      metadata: { policy: "hostname-match", result: "passed" },
    });

    const listed = await listCertificateEvidence({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
    });
    assertNoCustodyKeys(listed);
  });
});
