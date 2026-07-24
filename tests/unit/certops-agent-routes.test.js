"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const routerModule = require(
  path.resolve(__dirname, "../../apps/api/routes/certops-agent.js"),
);
const {
  isCertOpsMachineTokenCsrfExemptPath,
} = require(path.resolve(__dirname, "../../apps/api/middleware/csrf-exempt.js"));
const {
  CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES,
  certOpsMachineWriteRouteFamily,
  isExactCertOpsMachineWritePost,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/middleware/certops-executor-body-parser.js",
  ),
);
const { machineTokenRateLimitKey } = require(
  path.resolve(
    __dirname,
    "../../apps/api/middleware/machine-token-rate-limit.js",
  ),
);

const { _test } = routerModule;
const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";

const AGENT_PATHS = [
  "/api/v1/certops/agent/register",
  "/api/v1/certops/agent/heartbeat",
  "/api/v1/certops/agent/jobs/claim",
  "/api/v1/certops/agent/jobs/results",
];

function createResponse() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

function agentFixture(overrides = {}) {
  return {
    id: "agent-row-1",
    workspaceId: WORKSPACE_A,
    agentId: "agent-01",
    status: "active",
    protocolVersion: "1.0.0",
    agentVersion: "0.1.0",
    ...overrides,
  };
}

function envelope(messageType, body) {
  return {
    schemaVersion: 1,
    protocolVersion: "1.0.0",
    messageType,
    agentId: "agent-01",
    sentAt: "2026-07-22T10:00:00.000Z",
    body,
  };
}

describe("CSRF exemption for agent-protocol paths", () => {
  it("accepts the four exact paths, trailing slash, case-insensitive, mounted form", () => {
    for (const exact of AGENT_PATHS) {
      const req = { method: "POST" };
      assert.equal(isCertOpsMachineTokenCsrfExemptPath(exact, req), true, exact);
      assert.equal(
        isCertOpsMachineTokenCsrfExemptPath(`${exact}/`, req),
        true,
        `${exact}/`,
      );
      assert.equal(
        isCertOpsMachineTokenCsrfExemptPath(exact.toUpperCase(), req),
        true,
        exact.toUpperCase(),
      );
      const mounted = exact.replace(/^\/api/, "");
      assert.equal(
        isCertOpsMachineTokenCsrfExemptPath(mounted, req),
        true,
        mounted,
      );
    }
  });

  it("rejects neighbors, descendants, and non-POST methods", () => {
    const post = { method: "POST" };
    for (const bad of [
      "/api/v1/certops/agent",
      "/api/v1/certops/agent/registerx",
      "/api/v1/certops/agent/register/extra",
      "/api/v1/certops/agent//register",
      "/api/v1/certops/agents/register",
      "/prefix/api/v1/certops/agent/register",
      "/api/v1/certops/agent/jobs",
      "/api/v1/certops/agent/jobs/claims",
    ]) {
      assert.equal(isCertOpsMachineTokenCsrfExemptPath(bad, post), false, bad);
    }
    assert.equal(
      isCertOpsMachineTokenCsrfExemptPath(AGENT_PATHS[0], { method: "GET" }),
      false,
    );
  });
});

describe("Body-parser route-family detection for agent paths", () => {
  it("classifies the four paths as the agent-protocol family", () => {
    for (const exact of AGENT_PATHS) {
      assert.equal(
        certOpsMachineWriteRouteFamily(exact),
        CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES.agentProtocol,
        exact,
      );
      assert.equal(
        certOpsMachineWriteRouteFamily(`${exact}/`),
        CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES.agentProtocol,
      );
    }
  });

  it("matches exact POSTs only through isExactCertOpsMachineWritePost", () => {
    assert.equal(
      isExactCertOpsMachineWritePost({
        method: "POST",
        path: AGENT_PATHS[2],
      }),
      true,
    );
    assert.equal(
      isExactCertOpsMachineWritePost({
        method: "GET",
        path: AGENT_PATHS[2],
      }),
      false,
    );
    assert.equal(
      isExactCertOpsMachineWritePost({
        method: "POST",
        path: "/api/v1/certops/agent/jobs/claim/extra",
      }),
      false,
    );
  });
});

describe("Rate-limit key generation for agent identities", () => {
  it("builds workspace:prefix:agentRowId keys from agentRateLimitIdentity", () => {
    const req = { certopsAgent: agentFixture() };
    let advanced = false;
    _test.agentRateLimitIdentity(req, null, () => {
      advanced = true;
    });
    assert.equal(advanced, true);
    assert.equal(
      machineTokenRateLimitKey(req),
      `certops-machine:${WORKSPACE_A}:ttagent_agent-01:agent-row-1`,
    );
  });

  it("keys bootstrap registrations on the bootstrap token prefix, no machine id", () => {
    const req = {
      agentBootstrapToken: {
        id: "boot-1",
        workspaceId: WORKSPACE_A,
        tokenPrefix: "ttboot_0123456789abcdef",
      },
    };
    _test.agentRateLimitIdentity(req, null, () => {});
    assert.equal(
      machineTokenRateLimitKey(req),
      `certops-machine:${WORKSPACE_A}:ttboot_0123456789abcdef`,
    );
  });

  it("yields no key (auth-required) when neither identity is present", () => {
    const req = {};
    _test.agentRateLimitIdentity(req, null, () => {});
    assert.equal(machineTokenRateLimitKey(req), null);
  });
});

describe("Retired agent guard", () => {
  it("answers 410 for a retired agent without touching the handler", () => {
    const res = createResponse();
    let nextCalled = false;
    _test.requireNonRetiredAgent(
      { certopsAgent: agentFixture({ status: "retired" }) },
      res,
      () => {
        nextCalled = true;
      },
    );
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 410);
    assert.equal(res.body.code, "CERTOPS_AGENT_RETIRED");
  });

  it("passes offline agents through (they are alive again)", () => {
    const res = createResponse();
    let nextCalled = false;
    _test.requireNonRetiredAgent(
      { certopsAgent: agentFixture({ status: "offline" }) },
      res,
      () => {
        nextCalled = true;
      },
    );
    assert.equal(nextCalled, true);
    assert.equal(res.statusCode, null);
  });
});

describe("Heartbeat handler", () => {
  it("retired freeze: no last_seen_at update happens because the guard fires first", async () => {
    // Route chain places requireNonRetiredAgent before heartbeatHandler, so
    // a retired agent never reaches recordHeartbeat. Assert the pairing:
    const res = createResponse();
    const req = {
      certopsAgent: agentFixture({ status: "retired" }),
      body: envelope("heartbeat", { agentVersion: "0.1.0" }),
    };
    let heartbeatCalls = 0;
    _test.requireNonRetiredAgent(req, res, async () => {
      await _test.heartbeatHandler(req, res, {
        recordHeartbeat: async () => {
          heartbeatCalls += 1;
          return { ok: true };
        },
      });
    });
    assert.equal(res.statusCode, 410);
    assert.equal(heartbeatCalls, 0);
  });

  it("returns the signing key announcement for a valid heartbeat", async () => {
    const res = createResponse();
    const req = {
      certopsAgent: agentFixture(),
      body: envelope("heartbeat", {
        agentVersion: "0.1.0",
        ntpSynced: true,
        uptimeSeconds: 10,
      }),
    };
    await _test.heartbeatHandler(req, res, {
      recordHeartbeat: async () => ({
        ok: true,
        status: "active",
        lastSeenAt: "2026-07-22T10:00:00.000Z",
        signingKeyId: "key-1",
        signingPublicKeyPem: "pem",
      }),
    });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.signingKeyId, "key-1");
    assert.equal(res.body.signingPublicKeyPem, "pem");
  });

  it("rejects a malformed envelope with 400", async () => {
    const res = createResponse();
    await _test.heartbeatHandler(
      { certopsAgent: agentFixture(), body: { messageType: "heartbeat" } },
      res,
      {},
    );
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.code, "CERTOPS_AGENT_MESSAGE_INVALID");
  });

  it("rejects an invalid sequence field with 400 before the service runs", async () => {
    let serviceCalled = false;
    for (const badSequence of [0, -3, 1.5, "7", null]) {
      const res = createResponse();
      const body = envelope("heartbeat", { agentVersion: "0.1.0" });
      body.sequence = badSequence;
      await _test.heartbeatHandler({ certopsAgent: agentFixture(), body }, res, {
        recordHeartbeat: async () => {
          serviceCalled = true;
          return { ok: true };
        },
      });
      assert.equal(res.statusCode, 400, `sequence ${JSON.stringify(badSequence)}`);
      assert.equal(res.body.code, "CERTOPS_AGENT_MESSAGE_INVALID");
    }
    assert.equal(serviceCalled, false);
  });

  it("maps a sequence regression from the service to 409", async () => {
    const res = createResponse();
    const body = envelope("heartbeat", { agentVersion: "0.1.0" });
    body.sequence = 2;
    await _test.heartbeatHandler({ certopsAgent: agentFixture(), body }, res, {
      recordHeartbeat: async () => {
        const error = new Error("regression");
        error.code = "CERTOPS_AGENT_SEQUENCE_REGRESSION";
        throw error;
      },
    });
    assert.equal(res.statusCode, 409);
    assert.equal(res.body.code, "CERTOPS_AGENT_SEQUENCE_REGRESSION");
  });
});

describe("Claim handler", () => {
  it("maps the workspace kill switch to 409 CERTOPS_WORKSPACE_PAUSED", async () => {
    const res = createResponse();
    await _test.claimHandler(
      {
        certopsAgent: agentFixture(),
        body: envelope("claim", { maxJobs: 1, supportedActions: ["renew"] }),
      },
      res,
      {
        claimJobs: async () => {
          const error = new Error("paused");
          error.code = "CERTOPS_WORKSPACE_PAUSED";
          throw error;
        },
      },
    );
    assert.equal(res.statusCode, 409);
    assert.equal(res.body.code, "CERTOPS_WORKSPACE_PAUSED");
  });

  it("passes the validated claim body through to the service", async () => {
    const res = createResponse();
    let seenBody = null;
    await _test.claimHandler(
      {
        certopsAgent: agentFixture(),
        body: envelope("claim", { maxJobs: 3, supportedActions: ["renew"] }),
      },
      res,
      {
        claimJobs: async ({ body }) => {
          seenBody = body;
          return { jobs: [] };
        },
      },
    );
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { jobs: [] });
    assert.equal(seenBody.maxJobs, 3);
    assert.deepEqual(seenBody.supportedActions, ["renew"]);
  });
});

describe("Results handler", () => {
  it("maps ownership mismatch to 409", async () => {
    const res = createResponse();
    await _test.resultsHandler(
      {
        certopsAgent: agentFixture(),
        body: envelope("result", {
          jobId: "42",
          attemptId: "claim-1",
          claimId: "claim-1",
          nonce: "n-1",
          status: "succeeded",
        }),
      },
      res,
      {
        ingestResult: async () => {
          const error = new Error("mismatch");
          error.code = "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH";
          throw error;
        },
      },
    );
    assert.equal(res.statusCode, 409);
    assert.equal(res.body.code, "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH");
  });

  it("maps nonce replay to 409 CERTOPS_AGENT_RESULT_NONCE_REJECTED", async () => {
    const res = createResponse();
    await _test.resultsHandler(
      {
        certopsAgent: agentFixture(),
        body: envelope("result", {
          jobId: "42",
          attemptId: "claim-1",
          claimId: "claim-1",
          nonce: "n-1",
          status: "failed",
        }),
      },
      res,
      {
        ingestResult: async () => {
          const error = new Error("replay");
          error.code = "CERTOPS_AGENT_RESULT_NONCE_REJECTED";
          error.replayed = true;
          throw error;
        },
      },
    );
    assert.equal(res.statusCode, 409);
    assert.equal(res.body.code, "CERTOPS_AGENT_RESULT_NONCE_REJECTED");
  });

  it("falls back to attemptId when the schema-only result body omits claimId", async () => {
    const res = createResponse();
    let seenClaimId = null;
    await _test.resultsHandler(
      {
        certopsAgent: agentFixture(),
        body: envelope("result", {
          jobId: "42",
          attemptId: "claim-1",
          nonce: "n-1",
          status: "succeeded",
        }),
      },
      res,
      {
        ingestResult: async ({ body }) => {
          seenClaimId = body.claimId;
          return { ok: true, jobId: "42", status: "succeeded" };
        },
      },
    );
    assert.equal(res.statusCode, 200);
    assert.equal(seenClaimId, "claim-1");
  });

  it("evidence path appends lock-free without an ingestResult transition", async () => {
    const res = createResponse();
    const batchCalls = [];
    let ingestCalled = false;
    await _test.resultsHandler(
      {
        certopsAgent: agentFixture(),
        body: envelope("evidence", {
          jobId: "42",
          evidenceItems: [
            {
              evidenceId: "ev_item_1",
              eventType: "certificate.observed",
              observedAt: "2026-07-22T10:00:00.000Z",
              summary: "observed cert",
            },
          ],
        }),
      },
      res,
      {
        ingestResult: async () => {
          ingestCalled = true;
          throw new Error("must not be called for evidence");
        },
        persistAgentJobEvidenceBatch: async (options) => {
          batchCalls.push(options);
          return { ok: true, evidenceCount: 1, items: [{ id: "ev-1" }] };
        },
      },
    );
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { ok: true, evidenceCount: 1 });
    assert.equal(ingestCalled, false);
    assert.equal(batchCalls.length, 1);
    assert.equal(batchCalls[0].jobId, "42");
    assert.equal(batchCalls[0].evidenceItems[0].evidenceId, "ev_item_1");
  });

  it("evidence from a non-claiming agent is rejected before persistence", async () => {
    const res = createResponse();
    let batchEntered = false;
    await _test.resultsHandler(
      {
        certopsAgent: agentFixture(),
        body: envelope("evidence", {
          jobId: "42",
          evidenceItems: [
            {
              evidenceId: "ev_item_2",
              eventType: "certificate.observed",
              observedAt: "2026-07-22T10:00:00.000Z",
            },
          ],
        }),
      },
      res,
      {
        persistAgentJobEvidenceBatch: async () => {
          batchEntered = true;
          const error = new Error(
            "Evidence does not match the claim for this job",
          );
          error.code = "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH";
          throw error;
        },
      },
    );
    assert.equal(res.statusCode, 409);
    assert.equal(res.body.code, "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH");
    assert.equal(batchEntered, true);
  });

  it("evidence path enforces the sequence before appending and maps regression to 409", async () => {
    const res = createResponse();
    let evidenceAppended = false;
    const body = envelope("evidence", {
      jobId: "42",
      evidenceItems: [
        {
          evidenceId: "ev_item_3",
          eventType: "certificate.observed",
          observedAt: "2026-07-22T10:00:00.000Z",
        },
      ],
    });
    body.sequence = 5;
    await _test.resultsHandler({ certopsAgent: agentFixture(), body }, res, {
      persistAgentJobEvidenceBatch: async ({ envelope: seen }) => {
        assert.equal(seen.sequence, 5);
        const error = new Error("regression");
        error.code = "CERTOPS_AGENT_SEQUENCE_REGRESSION";
        throw error;
      },
      createCertificateEvidence: async () => {
        evidenceAppended = true;
        return { id: "ev-1" };
      },
    });
    assert.equal(res.statusCode, 409);
    assert.equal(res.body.code, "CERTOPS_AGENT_SEQUENCE_REGRESSION");
    assert.equal(evidenceAppended, false);
  });

  it("passes the envelope through to ingestResult for sequence enforcement", async () => {
    const res = createResponse();
    let seenEnvelope = null;
    const body = envelope("result", {
      jobId: "42",
      attemptId: "claim-1",
      claimId: "claim-1",
      nonce: "n-1",
      status: "succeeded",
    });
    body.sequence = 8;
    await _test.resultsHandler({ certopsAgent: agentFixture(), body }, res, {
      ingestResult: async ({ envelope: env }) => {
        seenEnvelope = env;
        return { ok: true, jobId: "42", status: "succeeded" };
      },
    });
    assert.equal(res.statusCode, 200);
    assert.equal(seenEnvelope.sequence, 8);
  });
});

describe("Register handler", () => {
  it("returns 201 with the exact client-consumed shape", async () => {
    const res = createResponse();
    await _test.registerHandler(
      {
        agentBootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A },
        body: envelope("register", {
          bootstrapTokenId: "boot-1",
          agentVersion: "0.1.0",
        }),
      },
      res,
      {
        registerAgent: async () => ({
          agentId: "agent-01",
          credential: "ttagent_secret",
          protocolVersion: "1.0.0",
          signingKeyId: "key-1",
          signingPublicKeyPem: "pem",
        }),
      },
    );
    assert.equal(res.statusCode, 201);
    assert.deepEqual(Object.keys(res.body).sort(), [
      "agentId",
      "credential",
      "protocolVersion",
      "signingKeyId",
      "signingPublicKeyPem",
    ]);
  });

  it("maps the consumed-race to a generic 401", async () => {
    const res = createResponse();
    await _test.registerHandler(
      {
        agentBootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A },
        body: envelope("register", {
          bootstrapTokenId: "boot-1",
          agentVersion: "0.1.0",
        }),
      },
      res,
      {
        registerAgent: async () => {
          const error = new Error("consumed");
          error.code = "CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED";
          throw error;
        },
      },
    );
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.code, "CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED");
  });
});
