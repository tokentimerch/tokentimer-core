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

const { bulkRenewCertificatesHandler, parseBulkRenewRequest } =
  certOpsRouter._test;

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
    const handler = bulkRenewCertificatesHandler({
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
      assert.strictEqual(call.payload.certificateId, uuid(index + 1));
      assert.strictEqual(call.source, "api");
      assert.strictEqual(call.requiresApproval, false);
      assert.strictEqual(call.requestedByUserId, 42);
      assert.strictEqual(call.actorUserId, 42);
      assert.strictEqual(
        call.idempotencyKey,
        `bulk-renew:auto:${uuid(index + 1)}`,
      );
    }
  });

  it("derives a stable auto idempotency key when the caller omits one", async () => {
    const { bulkRenewItemIdempotencyKey } = certOpsRouter._test;
    assert.strictEqual(
      bulkRenewItemIdempotencyKey(undefined, uuid(1)),
      `bulk-renew:auto:${uuid(1)}`,
    );
    assert.strictEqual(
      bulkRenewItemIdempotencyKey("client-key", uuid(1)),
      `bulk-renew:client-key:${uuid(1)}`,
    );

    const creatorCalls = [];
    const handler = bulkRenewCertificatesHandler({
      certificateLoader: async () => ({ id: "found" }),
      manualJobCreator: async (options) => {
        creatorCalls.push(options);
        return {
          job: { id: `job-${creatorCalls.length}` },
          created: creatorCalls.length === 1,
        };
      },
    });

    const first = responseRecorder();
    await handler(makeRequest({ certificateIds: [uuid(9)] }), first);
    const second = responseRecorder();
    await handler(makeRequest({ certificateIds: [uuid(9)] }), second);

    assert.strictEqual(first.statusCode, 200);
    assert.strictEqual(second.statusCode, 200);
    assert.strictEqual(creatorCalls.length, 2);
    assert.strictEqual(
      creatorCalls[0].idempotencyKey,
      creatorCalls[1].idempotencyKey,
    );
    assert.strictEqual(
      creatorCalls[0].idempotencyKey,
      `bulk-renew:auto:${uuid(9)}`,
    );
  });

  it("reports a mixed envelope where item failures never abort the batch", async () => {
    const handler = bulkRenewCertificatesHandler({
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
    const handler = bulkRenewCertificatesHandler({
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
    const handler = bulkRenewCertificatesHandler({
      certificateLoader: async ({ certId }) =>
        certId === uuid(2) ? null : { id: certId },
      activeJobFinder: async () => null,
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

  it("passes requiresApproval and shared payload through to the service path", async () => {
    const creatorCalls = [];
    const handler = bulkRenewCertificatesHandler({
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
        payload: { caEndpoint: "https://ca.example.com/acme" },
      }),
      res,
    );

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(creatorCalls[0].requiresApproval, true);
    assert.deepStrictEqual(creatorCalls[0].payload, {
      caEndpoint: "https://ca.example.com/acme",
      certificateId: uuid(1),
    });
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
      const handler = bulkRenewCertificatesHandler({
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
