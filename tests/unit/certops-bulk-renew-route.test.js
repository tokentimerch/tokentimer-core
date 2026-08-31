"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const certOpsRouter = require(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
);
const { NOT_FOUND_RESPONSE } = require(
  path.resolve(
    __dirname,
    "../../apps/api/middleware/require-certops-enabled.js",
  ),
);
const { CERTOPS_DISABLED } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/settings.js"),
);
const { CERTOPS_WORKSPACE_PAUSED } = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/workspaceKillSwitch.js",
  ),
);
const { CERTOPS_CERTIFICATE_NOT_FOUND } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
);
const { CERTOPS_JOB_INVALID } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
);
const {
  CERTOPS_RENEWAL_OVERRIDE_INVALID,
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/renewalProfile.js"),
);

const { bulkRenewCertificatesHandler, parseBulkRenewRequest } =
  certOpsRouter._test;

// Every handler under test gets stubbed DB-backed collaborators: the real
// defaults would reach the pool.
function makeHandler(overrides = {}) {
  return bulkRenewCertificatesHandler({
    activeJobFinder: async () => null,
    renewalPreflight: async () => ({}),
    ...overrides,
  });
}

function uuid(n) {
  return `aaaaaaaa-0000-4000-8000-${String(n).padStart(12, "0")}`;
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

function makeRequest(body) {
  return {
    workspace: { id: "workspace-1" },
    user: { id: 42 },
    body,
  };
}

describe("CertOps bulk-renew route", () => {
  it("creates a renew job per certificate and reports an all-success envelope", async () => {
    const creatorCalls = [];
    let jobCounter = 0;
    const handler = makeHandler({
      certificateLoader: async () => ({ id: "found" }),
      manualJobCreator: async (options) => {
        creatorCalls.push(options);
        jobCounter += 1;
        return { job: { id: `job-${jobCounter}` } };
      },
    });

    const res = responseRecorder();
    await handler(
      makeRequest({ certificateIds: [uuid(1), uuid(2), uuid(3)] }),
      res,
    );

    assert.strictEqual(res.statusCode, 200);
    assert.deepStrictEqual(res.body.summary, {
      requested: 3,
      succeeded: 3,
      failed: 0,
    });
    assert.ok(!("dryRun" in res.body));
    assert.deepStrictEqual(res.body.results, [
      { certificateId: uuid(1), ok: true, jobId: "job-1" },
      { certificateId: uuid(2), ok: true, jobId: "job-2" },
      { certificateId: uuid(3), ok: true, jobId: "job-3" },
    ]);

    assert.strictEqual(creatorCalls.length, 3);
    for (const [index, call] of creatorCalls.entries()) {
      assert.strictEqual(call.workspaceId, "workspace-1");
      assert.strictEqual(call.operation, "renew");
      assert.strictEqual(call.subjectType, "managed_certificate");
      assert.strictEqual(call.subjectId, uuid(index + 1));
      assert.deepStrictEqual(call.payload, {});
      assert.strictEqual(typeof call.jobCreator, "function");
      assert.strictEqual(call.source, "api");
      assert.strictEqual(call.requiresApproval, false);
      assert.strictEqual(call.requestedByUserId, 42);
      assert.strictEqual(call.actorUserId, 42);
      assert.strictEqual(call.idempotencyKey, null);
    }
  });

  it("leaves the per-item idempotency key unset when the caller omits one, so the same certificate stays renewable", async () => {
    const { bulkRenewItemIdempotencyKey } = certOpsRouter._test;
    assert.strictEqual(bulkRenewItemIdempotencyKey(undefined, uuid(1)), null);
    assert.strictEqual(bulkRenewItemIdempotencyKey(null, uuid(1)), null);
    assert.strictEqual(
      bulkRenewItemIdempotencyKey("client-key", uuid(1)),
      `bulk-renew:client-key:${uuid(1)}`,
    );

    // Two sequential bulk renews of the same certificate without a client
    // key must both reach creation with no key, so neither collides with the
    // other on the jobs table's (workspace, idempotency_key) uniqueness.
    const creatorCalls = [];
    const usedKeys = new Set();
    const handler = makeHandler({
      certificateLoader: async () => ({ id: "found" }),
      manualJobCreator: async (options) => {
        creatorCalls.push(options);
        if (options.idempotencyKey) {
          if (usedKeys.has(options.idempotencyKey)) {
            const err = new Error(
              "Idempotency key was already used with a different CertOps job request",
            );
            err.code = "CERTOPS_JOB_IDEMPOTENCY_CONFLICT";
            throw err;
          }
          usedKeys.add(options.idempotencyKey);
        }
        return { job: { id: `job-${creatorCalls.length}` }, created: true };
      },
    });

    const first = responseRecorder();
    await handler(makeRequest({ certificateIds: [uuid(9)] }), first);
    const second = responseRecorder();
    await handler(makeRequest({ certificateIds: [uuid(9)] }), second);

    assert.strictEqual(creatorCalls.length, 2);
    assert.strictEqual(creatorCalls[0].idempotencyKey, null);
    assert.strictEqual(creatorCalls[1].idempotencyKey, null);
    assert.deepStrictEqual(first.body.results, [
      { certificateId: uuid(9), ok: true, jobId: "job-1" },
    ]);
    assert.deepStrictEqual(second.body.results, [
      { certificateId: uuid(9), ok: true, jobId: "job-2" },
    ]);
  });

  it("derives a per-certificate key from a caller-supplied request key so a replayed batch is a no-op", async () => {
    const created = new Map();
    const creatorCalls = [];
    const handler = makeHandler({
      certificateLoader: async () => ({ id: "found" }),
      manualJobCreator: async (options) => {
        creatorCalls.push(options);
        const existing = created.get(options.idempotencyKey);
        if (existing) return { job: existing, created: false };
        const job = { id: `job-${created.size + 1}` };
        created.set(options.idempotencyKey, job);
        return { job, created: true };
      },
    });

    const body = { certificateIds: [uuid(9)], idempotencyKey: "batch-1" };
    const first = responseRecorder();
    await handler(makeRequest(body), first);
    const second = responseRecorder();
    await handler(makeRequest(body), second);

    assert.strictEqual(
      creatorCalls[0].idempotencyKey,
      `bulk-renew:batch-1:${uuid(9)}`,
    );
    assert.deepStrictEqual(first.body.results, [
      { certificateId: uuid(9), ok: true, jobId: "job-1" },
    ]);
    assert.deepStrictEqual(second.body.results, [
      { certificateId: uuid(9), ok: true, jobId: "job-1", replayed: true },
    ]);
  });

  it("reports a mixed envelope where item failures never abort the batch", async () => {
    const handler = makeHandler({
      certificateLoader: async ({ certId }) =>
        certId === uuid(2) ? null : { id: certId },
      manualJobCreator: async ({ subjectId }) => {
        if (subjectId === uuid(3)) {
          const err = new Error("CertOps is paused for this workspace");
          err.code = CERTOPS_WORKSPACE_PAUSED;
          throw err;
        }
        if (subjectId === uuid(4)) {
          throw new Error("connection reset");
        }
        return { job: { id: "job-ok" } };
      },
    });

    const res = responseRecorder();
    await handler(
      makeRequest({
        certificateIds: [uuid(1), uuid(2), uuid(3), uuid(4), uuid(5)],
      }),
      res,
    );

    assert.strictEqual(res.statusCode, 200);
    assert.deepStrictEqual(res.body.summary, {
      requested: 5,
      succeeded: 2,
      failed: 3,
    });
    assert.deepStrictEqual(res.body.results, [
      { certificateId: uuid(1), ok: true, jobId: "job-ok" },
      {
        certificateId: uuid(2),
        ok: false,
        errorCode: CERTOPS_CERTIFICATE_NOT_FOUND,
        message: "Certificate not found",
      },
      {
        certificateId: uuid(3),
        ok: false,
        errorCode: CERTOPS_WORKSPACE_PAUSED,
        message: "CertOps is paused for this workspace",
      },
      {
        certificateId: uuid(4),
        ok: false,
        errorCode: "INTERNAL_ERROR",
        message: "Failed to create CertOps job",
      },
      { certificateId: uuid(5), ok: true, jobId: "job-ok" },
    ]);
  });

  it("keeps the disabled-rollout 404 posture instead of a per-item failure", async () => {
    const handler = makeHandler({
      certificateLoader: async () => ({ id: "found" }),
      manualJobCreator: async () => {
        const err = new Error("CertOps is not enabled");
        err.code = CERTOPS_DISABLED;
        throw err;
      },
    });

    const res = responseRecorder();
    await handler(makeRequest({ certificateIds: [uuid(1)] }), res);

    assert.strictEqual(res.statusCode, 404);
    assert.deepStrictEqual(res.body, NOT_FOUND_RESPONSE);
  });

  it("validates and reports without creating jobs on dryRun", async () => {
    let creatorCalls = 0;
    const handler = makeHandler({
      certificateLoader: async ({ certId }) =>
        certId === uuid(2) ? null : { id: certId },
      manualJobCreator: async () => {
        creatorCalls += 1;
        return { job: { id: "must-not-exist" } };
      },
    });

    const res = responseRecorder();
    await handler(
      makeRequest({ certificateIds: [uuid(1), uuid(2)], dryRun: true }),
      res,
    );

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(creatorCalls, 0);
    assert.strictEqual(res.body.dryRun, true);
    assert.deepStrictEqual(res.body.summary, {
      requested: 2,
      succeeded: 1,
      failed: 1,
    });
    assert.deepStrictEqual(res.body.results[0], {
      certificateId: uuid(1),
      ok: true,
    });
    assert.strictEqual(res.body.results[1].ok, false);
  });

  it("fails a dry-run item whose stored renewal profile is incomplete, instead of reporting it as renewable", async () => {
    const preflightCalls = [];
    const handler = makeHandler({
      certificateLoader: async ({ certId }) => ({ id: certId }),
      renewalPreflight: async (options) => {
        preflightCalls.push(options);
        if (options.certificateId === uuid(2)) {
          const err = new Error("Certificate has no linked renewal profile");
          err.code = CERTOPS_RENEWAL_PROFILE_INCOMPLETE;
          throw err;
        }
        return {};
      },
      manualJobCreator: async () => {
        throw new Error("creator must not run on a dry run");
      },
    });

    const res = responseRecorder();
    await handler(
      makeRequest({
        certificateIds: [uuid(1), uuid(2)],
        dryRun: true,
        payload: { reason: "audit" },
      }),
      res,
    );

    assert.strictEqual(res.statusCode, 200);
    assert.deepStrictEqual(res.body.summary, {
      requested: 2,
      succeeded: 1,
      failed: 1,
    });
    assert.deepStrictEqual(res.body.results, [
      { certificateId: uuid(1), ok: true },
      {
        certificateId: uuid(2),
        ok: false,
        errorCode: CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
        message: "Certificate has no linked renewal profile",
      },
    ]);
    // Preflight receives the same override payload the real run would build
    // the job payload from.
    assert.deepStrictEqual(preflightCalls[0], {
      workspaceId: "workspace-1",
      certificateId: uuid(1),
      payload: { reason: "audit" },
    });
  });

  it("reports an in-flight renew job as activeJobId on a dry run that otherwise passes preflight", async () => {
    const handler = makeHandler({
      certificateLoader: async ({ certId }) => ({ id: certId }),
      activeJobFinder: async () => ({ id: "job-in-flight" }),
      manualJobCreator: async () => {
        throw new Error("creator must not run on a dry run");
      },
    });

    const res = responseRecorder();
    await handler(
      makeRequest({ certificateIds: [uuid(1)], dryRun: true }),
      res,
    );

    assert.deepStrictEqual(res.body.results, [
      { certificateId: uuid(1), ok: true, activeJobId: "job-in-flight" },
    ]);
  });

  it("passes requiresApproval and an allowlisted payload override through to the service path", async () => {
    const creatorCalls = [];
    const handler = makeHandler({
      certificateLoader: async () => ({ id: "found" }),
      manualJobCreator: async (options) => {
        creatorCalls.push(options);
        return { job: { id: "job-1" } };
      },
    });

    const res = responseRecorder();
    await handler(
      makeRequest({
        certificateIds: [uuid(1)],
        requiresApproval: true,
        payload: { reason: "customer-requested" },
      }),
      res,
    );

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(creatorCalls[0].requiresApproval, true);
    assert.deepStrictEqual(creatorCalls[0].payload, {
      reason: "customer-requested",
    });
  });

  it("rejects a non-allowlisted payload override with 400 before any item runs", async () => {
    const handler = makeHandler({
      certificateLoader: async () => {
        throw new Error("loader must not run on a rejected override");
      },
      manualJobCreator: async () => {
        throw new Error("creator must not run on a rejected override");
      },
    });

    const res = responseRecorder();
    await handler(
      makeRequest({
        certificateIds: [uuid(1)],
        payload: { caEndpoint: "https://ca.example.com/acme" },
      }),
      res,
    );

    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.body.code, CERTOPS_RENEWAL_OVERRIDE_INVALID);
  });

  it("rejects whole-request shape problems with 400 before any item runs", async () => {
    const badBodies = [
      undefined,
      null,
      [],
      {},
      { certificateIds: [] },
      { certificateIds: "not-an-array" },
      { certificateIds: [uuid(1), "not-a-uuid"] },
      { certificateIds: [uuid(1), 7] },
      { certificateIds: [uuid(1), uuid(1)] },
      { certificateIds: Array.from({ length: 101 }, (_, i) => uuid(i + 1)) },
      { certificateIds: [uuid(1)], dryRun: "yes" },
      { certificateIds: [uuid(1)], requiresApproval: "yes" },
      { certificateIds: [uuid(1)], payload: [] },
      { certificateIds: [uuid(1)], payload: null },
      { certificateIds: [uuid(1)], operation: "revoke" },
    ];

    for (const body of badBodies) {
      const handler = makeHandler({
        certificateLoader: async () => {
          throw new Error("loader must not run on a 400 request");
        },
        manualJobCreator: async () => {
          throw new Error("creator must not run on a 400 request");
        },
      });
      const res = responseRecorder();
      await handler(makeRequest(body), res);

      assert.strictEqual(
        res.statusCode,
        400,
        `expected 400 for body ${JSON.stringify(body)}`,
      );
      assert.strictEqual(res.body.code, CERTOPS_JOB_INVALID);
    }
  });

  it("dedupes case-insensitively and caps ids at 100", () => {
    const duplicate = parseBulkRenewRequest({
      certificateIds: [uuid(1), uuid(1).toUpperCase()],
    });
    assert.match(duplicate.error, /duplicates/);

    const atCap = parseBulkRenewRequest({
      certificateIds: Array.from({ length: 100 }, (_, i) => uuid(i + 1)),
    });
    assert.strictEqual(atCap.error, undefined);
    assert.strictEqual(atCap.certificateIds.length, 100);

    const mixedCase = parseBulkRenewRequest({
      certificateIds: [uuid(1).toUpperCase()],
    });
    assert.deepStrictEqual(mixedCase.certificateIds, [uuid(1)]);
  });
});
