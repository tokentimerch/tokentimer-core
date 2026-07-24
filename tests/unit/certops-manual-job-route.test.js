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

function createTransactionalPool({ certOpsPaused = false } = {}) {
  const queries = [];
  const jobs = [];
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
    ["CERTOPS_RENEWAL_PROFILE_INVALID", 400],
    ["CERTOPS_RENEWAL_PROFILE_INCOMPLETE", 400],
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
