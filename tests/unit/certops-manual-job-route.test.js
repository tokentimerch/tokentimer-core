"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const certOpsRouter = require(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
);
const {
  NOT_FOUND_RESPONSE,
  createRequireCertOpsEnabled,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/middleware/require-certops-enabled.js",
  ),
);
const {
  CERTOPS_WORKSPACE_PAUSED,
  createManualCertificateJob,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/workspaceKillSwitch.js",
  ),
);

function createTransactionalPool({ certOpsPaused = false, certificates = [] } = {}) {
  const queries = [];
  const jobs = [];
  let nextJob = 1;
  const client = {
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, " ").trim();
      queries.push({ sql: normalized, params });
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) {
        return { rows: [] };
      }
      if (normalized.startsWith("SELECT id, certops_paused FROM workspaces")) {
        return {
          rows: [{ id: "workspace-1", certops_paused: certOpsPaused }],
        };
      }
      if (normalized.includes("FROM managed_certificates")) {
        const [workspaceId, certificateId] = params;
        const row = certificates.find(
          (cert) =>
            cert.workspace_id === workspaceId && cert.id === certificateId,
        );
        return { rows: row ? [row] : [] };
      }
      if (normalized.includes("pg_advisory_xact_lock")) {
        return { rows: [{ pg_advisory_xact_lock: "" }] };
      }
      if (
        normalized.includes("FROM certificate_jobs") &&
        normalized.includes("operation = ANY($3::text[])") &&
        normalized.includes("FOR UPDATE")
      ) {
        return { rows: [] };
      }
      if (normalized.includes("idempotency_key = $2")) {
        return { rows: [] };
      }
      if (normalized.includes("INSERT INTO certificate_jobs")) {
        const createdAt = new Date(Date.UTC(2026, 5, 30, 0, 0, 0));
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
          payload: JSON.parse(params[11]),
          result_metadata: JSON.parse(params[12]),
          error_code: params[13],
          error_message: params[14],
          assigned_agent_id: params[15],
          required_target_selector: params[16],
          required_dns_provider: params[17],
          required_command_profile: params[18],
          created_at: createdAt,
          updated_at: createdAt,
          queued_at: params[19],
          started_at: params[20],
          completed_at: params[21],
          canceled_at: params[22],
          creation_request_hash: params[23],
        };
        jobs.push(row);
        return { rows: [row] };
      }
      if (normalized.includes("INSERT INTO audit_events")) {
        return { rows: [] };
      }
      throw new Error(`Unexpected query: ${normalized}`);
    },
    release() {},
  };

  return {
    client,
    jobs,
    queries,
    async connect() {
      return client;
    },
  };
}

function responseRecorder() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

async function invokeAfterEarlyGlobalGate(
  handler,
  { flagResolver, onEarlyGate },
) {
  const req = {
    workspace: { id: "workspace-1" },
    user: { id: 42 },
    body: { operation: "deploy" },
  };
  const res = responseRecorder();
  const earlyGate = createRequireCertOpsEnabled({ flagResolver });
  await earlyGate(req, res, () => {
    onEarlyGate();
    return handler(req, res);
  });
  return res;
}

describe("CertOps manual-job route transactional gate errors", () => {
  it("hides a global disable that occurs after the early middleware check", async () => {
    const pool = createTransactionalPool();
    let certOpsEnabled = true;
    let earlyGateCalls = 0;
    let jobCreatorCalls = 0;
    let auditCalls = 0;
    const handler = certOpsRouter._test.createManualCertificateJobHandler({
      manualJobCreator: (options) =>
        createManualCertificateJob({
          ...options,
          dbPool: pool,
          certOpsEnabledResolver: async () => certOpsEnabled,
          jobCreator: async () => {
            jobCreatorCalls += 1;
            return { job: { id: "must-not-exist" }, created: true };
          },
          auditWriter: async () => {
            auditCalls += 1;
          },
        }),
    });
    const response = await invokeAfterEarlyGlobalGate(handler, {
      flagResolver: async () => {
        earlyGateCalls += 1;
        return certOpsEnabled;
      },
      onEarlyGate: () => {
        certOpsEnabled = false;
      },
    });

    assert.equal(earlyGateCalls, 1);
    assert.equal(response.statusCode, 404);
    assert.deepEqual(response.body, NOT_FOUND_RESPONSE);
    assert.equal(jobCreatorCalls, 0);
    assert.equal(auditCalls, 0);
    assert.deepEqual(pool.jobs, []);
    assert.equal(pool.queries[0].sql, "BEGIN");
    assert.equal(
      pool.queries.some((query) => query.sql.endsWith("FOR SHARE")),
      true,
    );
    assert.equal(pool.queries.at(-1).sql, "ROLLBACK");
  });

  it("preserves the paused 409 after the early middleware check", async () => {
    const pool = createTransactionalPool({ certOpsPaused: true });
    let certOpsEnabled = true;
    let earlyGateCalls = 0;
    let jobCreatorCalls = 0;
    let auditCalls = 0;
    const handler = certOpsRouter._test.createManualCertificateJobHandler({
      manualJobCreator: (options) =>
        createManualCertificateJob({
          ...options,
          dbPool: pool,
          certOpsEnabledResolver: async () => certOpsEnabled,
          jobCreator: async () => {
            jobCreatorCalls += 1;
            return { job: { id: "must-not-exist" }, created: true };
          },
          auditWriter: async () => {
            auditCalls += 1;
          },
        }),
    });
    const response = await invokeAfterEarlyGlobalGate(handler, {
      flagResolver: async () => {
        earlyGateCalls += 1;
        return certOpsEnabled;
      },
      onEarlyGate: () => {},
    });

    assert.equal(earlyGateCalls, 1);
    assert.equal(response.statusCode, 409);
    assert.deepEqual(response.body, {
      error: "CertOps is paused for this workspace",
      code: CERTOPS_WORKSPACE_PAUSED,
    });
    assert.equal(jobCreatorCalls, 0);
    assert.equal(auditCalls, 0);
    assert.deepEqual(pool.jobs, []);
    assert.equal(pool.queries.at(-1).sql, "ROLLBACK");
  });
});

describe("CertOps handleCertOpsError status mapping", () => {
  function record() {
    const res = responseRecorder();
    return res;
  }

  // Regression: these codes are thrown on user-supplied input reachable
  // through admin routes (job payload/metadata, execution fields, manual
  // renewal profile, oversized certificate PEM). Before this fix they
  // fell through handleCertOpsError's `return null` and every caller's
  // catch block turned them into a generic 500 INTERNAL_ERROR, hiding a
  // client-input problem behind a server-error status.
  const cases = [
    ["CERTOPS_JOB_METADATA_INVALID", 400],
    ["CERTOPS_JOB_EXECUTION_FIELD_INVALID", 400],
    ["CERTOPS_JOB_EXECUTION_FIELD_REQUIRED", 400],
    ["CERTOPS_RENEWAL_PROFILE_INVALID", 400],
    ["CERTOPS_RENEWAL_PROFILE_INCOMPLETE", 400],
    ["CERTOPS_RENEWAL_OVERRIDE_INVALID", 400],
    ["CERTOPS_CERTIFICATE_TOO_LARGE", 400],
  ];

  for (const [code, expectedStatus] of cases) {
    it(`maps ${code} to ${expectedStatus}, not a generic 500`, () => {
      const res = record();
      const handled = certOpsRouter._test.handleCertOpsError(res, {
        code,
        message: "boom",
      });
      assert.notEqual(handled, null);
      assert.equal(res.statusCode, expectedStatus);
      assert.equal(res.body.code, code);
    });
  }

  it("still falls through to null for genuinely unmapped codes", () => {
    const res = record();
    const handled = certOpsRouter._test.handleCertOpsError(res, {
      code: "SOME_UNRELATED_ERROR",
      message: "boom",
    });
    assert.equal(handled, null);
    assert.equal(res.statusCode, null);
  });
});

describe("CertOps manual renew job creation routes through the canonical materializer", () => {
  const CERT_ID = "d1111111-1111-4111-8111-111111111111";

  function validRenewalProfileSource() {
    return {
      schemaVersion: 1,
      profileId: "profile-1",
      profileName: "web-tls",
      sanPolicy: {
        mode: "exact",
        sans: ["app.example.com"],
        allowWildcards: false,
      },
      keyAlgorithm: "rsa",
      keySize: 2048,
      keyRotationPolicy: { rotateOnRenew: true },
      preferredChain: null,
      ca: {
        endpoint: "https://acme-v02.api.letsencrypt.org/directory",
        accountRef: null,
        eabRef: null,
      },
      acme: { kind: "certbot", commandRef: "acme-renew-default" },
      dns: { provider: "cloudflare", zone: "example.com" },
      deploymentTargets: [
        {
          type: "endpoint",
          reference: "host/web",
          certPath: "/etc/ssl/certs/app.pem",
          reloadService: "nginx",
        },
      ],
      target: {
        type: "endpoint",
        reference: "host/web",
        certPath: "/etc/ssl/certs/app.pem",
      },
      verification: { host: "app.example.com", port: 443, requireMatch: true },
    };
  }

  function certificateRow(overrides = {}) {
    return {
      id: CERT_ID,
      workspace_id: "workspace-1",
      common_name: "app.example.com",
      subject_alt_names: ["app.example.com"],
      not_after: new Date("2026-08-01T00:00:00.000Z"),
      key_mode: "agent-local",
      profile_id: "profile-1",
      profile_name: "web-tls",
      profile_key_mode: "agent-local",
      profile_public_metadata: { renewalProfile: validRenewalProfileSource() },
      ...overrides,
    };
  }

  function renewRequest(body) {
    return {
      workspace: { id: "workspace-1" },
      user: { id: 42 },
      authz: { workspaceRole: "workspace_manager" },
      body: { operation: "renew", subjectType: "managed_certificate", ...body },
    };
  }

  it("fails at creation time with a clear, specific error when the certificate has no stored renewal profile, instead of a generic 500", async () => {
    const pool = createTransactionalPool({
      certificates: [certificateRow({ profile_id: null })],
    });
    const handler = certOpsRouter._test.createManualCertificateJobHandler({
      manualJobCreator: (options) =>
        createManualCertificateJob({
          ...options,
          dbPool: pool,
          certOpsEnabledResolver: async () => true,
        }),
    });

    const res = responseRecorder();
    await handler(renewRequest({ subjectId: CERT_ID }), res);

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.code, "CERTOPS_RENEWAL_PROFILE_INCOMPLETE");
    assert.deepEqual(pool.jobs, []);
    assert.equal(pool.queries.at(-1).sql, "ROLLBACK");
  });

  it("creates the same renew payload the scheduler would build for the same certificate, with no override supplied", async () => {
    const { buildRenewalJobPayload } = require(
      path.resolve(
        __dirname,
        "../../apps/api/services/certops/renewalProfile.js",
      ),
    );
    const certificate = certificateRow();
    const pool = createTransactionalPool({ certificates: [certificate] });
    const handler = certOpsRouter._test.createManualCertificateJobHandler({
      manualJobCreator: (options) =>
        createManualCertificateJob({
          ...options,
          dbPool: pool,
          certOpsEnabledResolver: async () => true,
        }),
    });

    const res = responseRecorder();
    await handler(renewRequest({ subjectId: CERT_ID }), res);

    assert.equal(res.statusCode, 201);
    const schedulerPayload = buildRenewalJobPayload({ certificate });
    const storedPayload = pool.jobs?.[0]?.payload;
    assert.ok(storedPayload);
    const { mode, ...storedWithoutMode } = storedPayload;
    assert.deepEqual(
      { ...storedWithoutMode, reason: schedulerPayload.reason },
      schedulerPayload,
    );
  });

  it("rejects a manual renew request that tries to override a non-allowlisted field, with 400 not a silent apply", async () => {
    const pool = createTransactionalPool({
      certificates: [certificateRow()],
    });
    const handler = certOpsRouter._test.createManualCertificateJobHandler({
      manualJobCreator: (options) =>
        createManualCertificateJob({
          ...options,
          dbPool: pool,
          certOpsEnabledResolver: async () => true,
        }),
    });

    const res = responseRecorder();
    await handler(
      renewRequest({
        subjectId: CERT_ID,
        payload: { caEndpoint: "https://operator-supplied.example/acme" },
      }),
      res,
    );

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.code, "CERTOPS_RENEWAL_OVERRIDE_INVALID");
    assert.deepEqual(pool.jobs, []);
  });

  it("applies an allowlisted reason override and changes nothing else in the created job's payload", async () => {
    const certificate = certificateRow();
    const pool = createTransactionalPool({ certificates: [certificate] });
    const handler = certOpsRouter._test.createManualCertificateJobHandler({
      manualJobCreator: (options) =>
        createManualCertificateJob({
          ...options,
          dbPool: pool,
          certOpsEnabledResolver: async () => true,
        }),
    });

    const res = responseRecorder();
    await handler(
      renewRequest({
        subjectId: CERT_ID,
        payload: { reason: "customer requested" },
      }),
      res,
    );

    assert.equal(res.statusCode, 201);
    assert.equal(res.body.job.payload.reason, "customer requested");
    assert.equal(res.body.job.payload.commandRef, "acme-renew-default");
  });
});
