"use strict";

/**
 * Upfront issuance (ADR-0008).
 *
 * The behaviour under test is the fix for a real product hole: a bare manual
 * renew job with no subject would run a full ACME order and deploy a genuine
 * certificate, and TokenTimer would record nothing at all. These tests pin the
 * two halves of the fix that make that impossible to reintroduce silently:
 * the identity is created before the job that references it, and the identity
 * is reconciled from the agent's own evidence about what it deployed.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  ISSUANCE_KEY_MODE,
  ISSUANCE_SOURCE,
  ISSUANCE_STATUS,
  createCertificateIssuanceJob,
  normalizeIssuanceRequest,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/issuance.js"),
);
const { JOB_OPERATIONS } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
);
const dispatch = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentDispatch.js"),
);
const { migrations } = require(
  path.resolve(__dirname, "../../apps/api/migrations/migrate.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const NEW_CERT_ID = "22222222-2222-4222-8222-222222222222";

const BASE_PAYLOAD = Object.freeze({
  target: { type: "domain", reference: "web-01.example.com" },
  commandRef: "certbot-csr",
  caEndpoint: "https://acme-staging-v02.api.letsencrypt.org/directory",
  certPath: "/etc/ssl/tokentimer/web-01.example.com.pem",
  dnsZone: "example.com",
  dnsProvider: "cloudflare",
});

/**
 * A valid issue request. `payload` overrides are merged into BASE_PAYLOAD, and
 * an explicit `undefined` removes the base key, so a test can assert a
 * required field is genuinely required.
 */
function validRequest({ payload, ...overrides } = {}) {
  const merged = { ...BASE_PAYLOAD, ...(payload || {}) };
  for (const key of Object.keys(payload || {})) {
    if (payload[key] === undefined) delete merged[key];
  }
  return {
    workspaceId: WORKSPACE_A,
    idempotencyKey: "issue-web-01",
    payload: merged,
    ...overrides,
  };
}

/**
 * Records every write so a test can assert not just the outcome but that no
 * certificate row was created on a rejected or replayed request.
 */
function createIssuanceClient({
  existingJobId = null,
  existingCertificateId = null,
} = {}) {
  const state = { inserts: [], queries: [] };
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ sql, params });
      if (sql.includes("FROM managed_certificates") && sql.includes("source_ref")) {
        return { rows: existingCertificateId ? [{ id: existingCertificateId }] : [] };
      }
      if (sql.includes("FROM certificate_jobs") && sql.includes("idempotency_key")) {
        return { rows: existingJobId ? [{ id: existingJobId }] : [] };
      }
      if (sql.includes("INSERT INTO managed_certificates")) {
        state.inserts.push(params);
        return {
          rows: [
            {
              id: NEW_CERT_ID,
              status: ISSUANCE_STATUS,
              source: ISSUANCE_SOURCE,
              source_ref: params[3],
              common_name: params[4],
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  return { state, client };
}

describe("certops issuance request validation", () => {
  it("accepts a well-formed request and defaults sans to the common name", () => {
    const normalized = normalizeIssuanceRequest(validRequest());
    assert.equal(normalized.idempotencyKey, "issue-web-01");
    assert.equal(normalized.commonName, "web-01.example.com");
    assert.deepEqual(normalized.sans, ["web-01.example.com"]);
    assert.equal(
      normalized.certPath,
      "/etc/ssl/tokentimer/web-01.example.com.pem",
    );
  });

  it("lowercases and de-duplicates an explicit sans list", () => {
    const normalized = normalizeIssuanceRequest(
      validRequest({
        payload: {
          sans: ["WEB-01.example.com", "alt.example.com", "alt.example.com"],
        },
      }),
    );
    assert.deepEqual(normalized.sans, ["web-01.example.com", "alt.example.com"]);
  });

  it("requires an idempotencyKey so a retry cannot create a duplicate certificate", () => {
    assert.throws(
      () => normalizeIssuanceRequest(validRequest({ idempotencyKey: undefined })),
      /idempotencyKey/,
    );
  });

  it("rejects a caller-supplied subjectId", () => {
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ subjectType: "managed_certificate", subjectId: NEW_CERT_ID }),
        ),
      /must not carry subjectType or subjectId/,
    );
  });

  it("rejects a caller-supplied payload.certificateId", () => {
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ payload: { certificateId: NEW_CERT_ID } }),
        ),
      /must not carry payload.certificateId/,
    );
  });

  it("requires payload.target.reference and payload.certPath", () => {
    assert.throws(
      () => normalizeIssuanceRequest(validRequest({ payload: { target: undefined } })),
      /payload.target/,
    );
    assert.throws(
      () => normalizeIssuanceRequest(validRequest({ payload: { certPath: undefined } })),
      /payload.certPath/,
    );
  });

  it("rejects a sans list that does not cover the common name", () => {
    // A certificate whose SANs omit the name its inventory row is keyed on
    // would deploy and then fail every subsequent verification.
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ payload: { sans: ["other.example.com"] } }),
        ),
      /must include payload.target.reference/,
    );
  });

  it("rejects a target reference that is not a DNS name", () => {
    assert.throws(
      () =>
        normalizeIssuanceRequest(
          validRequest({ payload: { target: { reference: "not a hostname" } } }),
        ),
      /valid DNS name/,
    );
  });
});

describe("certops issuance job creation", () => {
  it("creates the provisioning certificate before the job", async () => {
    const { state, client } = createIssuanceClient();
    let jobOptions = null;
    await createCertificateIssuanceJob({
      ...validRequest(),
      client,
      jobCreatorOverride: async (options) => {
        jobOptions = options;
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.equal(state.inserts.length, 1, "one certificate row expected");
    const insert = state.inserts[0];
    assert.equal(insert[1], ISSUANCE_STATUS);
    assert.equal(insert[2], ISSUANCE_SOURCE);
    assert.equal(insert[3], "issue-web-01", "source_ref is the idempotency key");
    assert.equal(insert[4], "web-01.example.com");
    assert.equal(insert[6], ISSUANCE_KEY_MODE);
    assert.equal(
      insert[7],
      "file:///etc/ssl/tokentimer/web-01.example.com.pem",
      "key_reference is an opaque path pointer, never key material",
    );

    assert.equal(jobOptions.operation, "issue");
    assert.equal(jobOptions.subjectType, "managed_certificate");
    assert.equal(jobOptions.subjectId, NEW_CERT_ID);
    assert.equal(
      jobOptions.payload.certificateId,
      NEW_CERT_ID,
      "server-assigned certificateId must match the row it reconciles",
    );
  });

  it("creates no second certificate when the idempotency key replays", async () => {
    const { state, client } = createIssuanceClient({
      existingJobId: "job-1",
      existingCertificateId: NEW_CERT_ID,
    });
    await createCertificateIssuanceJob({
      ...validRequest(),
      client,
      jobCreatorOverride: async () => ({ job: { id: "job-1" }, created: false }),
    });
    assert.equal(
      state.inserts.length,
      0,
      "a replay must not create an orphan provisioning row",
    );
  });

  it("derives identical job options on the replay, so it replays instead of conflicting", async () => {
    // Regression: the replay path used to hand createCertificateJob the bare
    // request (no subjectId, no server-assigned certificateId), so its
    // creation-request hash differed from the original and a byte-identical
    // retry was reported as an idempotency conflict (HTTP 409) instead of
    // returning the original job. Found by live end-to-end testing.
    const captured = [];
    const jobCreatorOverride = async (options) => {
      captured.push(options);
      return { job: { id: "job-1" }, created: captured.length === 1 };
    };

    const first = createIssuanceClient();
    await createCertificateIssuanceJob({
      ...validRequest(),
      client: first.client,
      jobCreatorOverride,
    });

    const replay = createIssuanceClient({
      existingJobId: "job-1",
      existingCertificateId: NEW_CERT_ID,
    });
    await createCertificateIssuanceJob({
      ...validRequest(),
      client: replay.client,
      jobCreatorOverride,
    });

    assert.equal(captured.length, 2);
    const strip = ({ client, jobCreatorOverride: _ignored, ...rest }) => rest;
    assert.deepEqual(
      strip(captured[1]),
      strip(captured[0]),
      "replayed job options must be identical to the original",
    );
  });

  it("does not create an identity when the key belongs to a non-issuance job", async () => {
    // Key reused across operations: there is no issuance certificate to reuse,
    // and inventing one would leave an orphan row behind the conflict that
    // createCertificateJob is about to raise.
    const { state, client } = createIssuanceClient({ existingJobId: "job-renew" });
    let jobOptions = null;
    await createCertificateIssuanceJob({
      ...validRequest(),
      client,
      jobCreatorOverride: async (options) => {
        jobOptions = options;
        return { job: { id: "job-renew" }, created: false };
      },
    });
    assert.equal(state.inserts.length, 0);
    assert.equal(jobOptions.subjectId, undefined);
  });

  it("refuses to run without the kill-switch-locked client", async () => {
    await assert.rejects(
      () => createCertificateIssuanceJob({ ...validRequest(), client: null }),
      /kill-switch-locked client/,
    );
  });
});

describe("certops issue operation plumbing", () => {
  it("is a recognised job operation", () => {
    assert.ok(JOB_OPERATIONS.includes("issue"));
  });

  it("dispatches to agents as the renew wire action", () => {
    // The agent-facing action enum is deliberately unchanged so fielded
    // agents run issue jobs with no upgrade (ADR-0008/ADR-0002).
    assert.equal(dispatch._test.wireActionForOperation("issue"), "renew");
    assert.equal(dispatch._test.wireActionForOperation("renew"), "renew");
    assert.equal(dispatch._test.wireActionForOperation("deploy"), "deploy");
  });

  it("raises the renewal-failure alert for a failed issuance", () => {
    assert.ok(dispatch._test.RENEWAL_ALERTING_OPERATIONS.has("issue"));
    assert.ok(dispatch._test.RENEWAL_ALERTING_OPERATIONS.has("renew"));
    assert.ok(!dispatch._test.RENEWAL_ALERTING_OPERATIONS.has("deploy"));
  });
});

describe("certops provisioning reconciliation", () => {
  const jobFixture = {
    id: 42,
    operation: "issue",
    subject_type: "managed_certificate",
    subject_id: NEW_CERT_ID,
  };

  function reconcileClient({ provisioning = true, metadata = {} } = {}) {
    const state = { updates: [] };
    const client = {
      query: async (text, params) => {
        const sql = typeof text === "string" ? text : text?.text || "";
        if (sql.includes("FROM managed_certificates")) {
          return { rows: provisioning ? [{ id: NEW_CERT_ID }] : [] };
        }
        if (sql.includes("FROM certificate_evidence")) {
          return { rows: [{ metadata }] };
        }
        if (sql.includes("UPDATE managed_certificates")) {
          state.updates.push(params);
          return { rows: [] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };
    return { state, client };
  }

  it("promotes a provisioning certificate and backfills from evidence", async () => {
    const { state, client } = reconcileClient({
      metadata: {
        fingerprintSha256: "a".repeat(64),
        serialNumber: "04AABB",
        subject: "CN=web-01.example.com",
        issuer: "CN=Staging Fake LE",
        validFrom: "Jul 26 10:00:00 2026 GMT",
        validTo: "Oct 24 10:00:00 2026 GMT",
        subjectAltNames: "web-01.example.com,alt.example.com",
      },
    });

    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
    });

    assert.equal(result, String(NEW_CERT_ID));
    assert.equal(state.updates.length, 1);
    const params = state.updates[0];
    assert.equal(params[2], "a".repeat(64));
    assert.equal(params[3], "04AABB");
    assert.equal(params[4], "CN=web-01.example.com");
    assert.equal(params[5], "CN=Staging Fake LE");
    assert.equal(params[6], new Date("Jul 26 10:00:00 2026 GMT").toISOString());
    assert.equal(params[7], new Date("Oct 24 10:00:00 2026 GMT").toISOString());
    assert.equal(params[8], "web-01.example.com,alt.example.com");
  });

  it("is a no-op when the subject is already active", async () => {
    const { state, client } = reconcileClient({ provisioning: false });
    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
    });
    assert.equal(result, null);
    assert.equal(state.updates.length, 0);
  });

  it("reconciles a plain renew retry against a still-provisioning subject", async () => {
    // The retry path after a failed issuance is an ordinary renew job. Keying
    // reconciliation on the subject's status rather than the operation is what
    // makes it converge with no special casing.
    const { state, client } = reconcileClient({
      metadata: { fingerprintSha256: "b".repeat(64) },
    });
    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: { ...jobFixture, operation: "renew" },
    });
    assert.equal(result, String(NEW_CERT_ID));
    assert.equal(state.updates.length, 1);
  });

  it("still promotes when the job produced no verify evidence", async () => {
    // A missing verify step must not leave the row stuck in provisioning
    // forever: promote, and leave the metadata columns untouched.
    const { state, client } = reconcileClient({ metadata: {} });
    const result = await dispatch._test.reconcileProvisionedCertificate({
      client,
      workspaceId: WORKSPACE_A,
      job: jobFixture,
    });
    assert.equal(result, String(NEW_CERT_ID));
    assert.equal(state.updates[0][2], null);
    assert.equal(state.updates[0][8], null);
  });

  it("skips jobs with no managed_certificate subject", async () => {
    const { state, client } = reconcileClient();
    assert.equal(
      await dispatch._test.reconcileProvisionedCertificate({
        client,
        workspaceId: WORKSPACE_A,
        job: { ...jobFixture, subject_type: "external" },
      }),
      null,
    );
    assert.equal(
      await dispatch._test.reconcileProvisionedCertificate({
        client,
        workspaceId: WORKSPACE_A,
        job: { ...jobFixture, subject_id: null },
      }),
      null,
    );
    assert.equal(state.updates.length, 0);
  });
});

describe("migration 33 issuance vocabulary", () => {
  const migration = migrations.find((entry) => entry.version === 33);

  it("exists and widens both managed_certificates constraints", () => {
    assert.ok(migration, "migration 33 expected");
    assert.match(migration.sql, /'provisioning'/);
    assert.match(migration.sql, /'agent_issuance'/);
    assert.match(migration.sql, /managed_certificates_status_check/);
    assert.match(migration.sql, /managed_certificates_source_check/);
  });

  it("keeps the earlier statuses and sources", () => {
    for (const value of [
      "discovered",
      "active",
      "renewing",
      "expiring",
      "expired",
      "revoked",
      "decommissioned",
    ]) {
      assert.match(migration.sql, new RegExp(`'${value}'`));
    }
    for (const value of ["manual", "cert_manager", "agent_filesystem"]) {
      assert.match(migration.sql, new RegExp(`'${value}'`));
    }
  });

  it("widens the partial unique indexes that enumerate sources", () => {
    // The service-layer ON CONFLICT predicates must keep matching these index
    // predicates exactly, or arbiter inference stops resolving.
    assert.match(
      migration.sql,
      /uq_managed_certificates_workspace_source_ref[\s\S]*agent_issuance/,
    );
    assert.match(
      migration.sql,
      /uq_managed_certificates_workspace_fingerprint_import[\s\S]*agent_issuance/,
    );
  });
});

describe("migration 34 issue job operation", () => {
  const migration = migrations.find((entry) => entry.version === 34);

  it("widens certificate_jobs.operation to accept issue", () => {
    // Regression: migration 33 taught managed_certificates about issuance but
    // left this constraint alone, so every issue request failed at COMMIT with
    // an opaque HTTP 500. The unit tests could not see it because they stub the
    // database; only live testing against a real stack caught it.
    assert.ok(migration, "migration 34 expected");
    assert.match(migration.sql, /certificate_jobs_operation_check/);
    assert.match(migration.sql, /'issue'/);
  });

  it("keeps every previously accepted operation", () => {
    for (const value of ["renew", "deploy", "reload", "revoke", "noop"]) {
      assert.match(migration.sql, new RegExp(`'${value}'`));
    }
  });

  it("accepts exactly the operations the service layer declares", () => {
    const declared = migration.sql.match(/operation IN \(([^)]+)\)/);
    assert.ok(declared, "operation IN (...) list expected");
    const values = declared[1]
      .split(",")
      .map((entry) => entry.trim().replace(/^'|'$/g, ""));
    assert.deepEqual([...values].sort(), [...JOB_OPERATIONS].sort());
  });
});
