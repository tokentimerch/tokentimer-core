"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
  CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
  CERTOPS_AGENT_RESULT_NONCE_REJECTED,
  CERTOPS_AGENT_SEQUENCE_REGRESSION,
  claimJobs,
  enforceAgentSequence,
  ingestResult,
  recordHeartbeat,
  registerAgent,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentDispatch.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";

function createMockPool(handler) {
  const state = {
    queries: [],
    released: false,
    transaction: [],
  };
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ text: sql, params });
      const trimmed = sql.trim().toUpperCase();
      if (
        trimmed === "BEGIN" ||
        trimmed === "COMMIT" ||
        trimmed === "ROLLBACK"
      ) {
        state.transaction.push(trimmed);
        return { rows: [] };
      }
      return handler(sql, params, state);
    },
    release: () => {
      state.released = true;
    },
  };
  return {
    state,
    client,
    connect: async () => client,
    query: client.query,
  };
}

function agentFixture(overrides = {}) {
  return {
    id: "agent-row-1",
    workspaceId: WORKSPACE_A,
    agentId: "agent-01",
    name: "Edge agent",
    status: "active",
    protocolVersion: "1.0.0",
    agentVersion: "0.1.0",
    pinnedSigningKeyId: null,
    lastSeenAt: null,
    retiredAt: null,
    ...overrides,
  };
}

function registerEnvelope() {
  return {
    schemaVersion: 1,
    protocolVersion: "1.0.0",
    messageType: "register",
    agentId: "agent-01",
    sentAt: "2026-07-22T10:00:00.000Z",
  };
}

function registerBody() {
  return {
    bootstrapTokenId: "boot-1",
    agentVersion: "0.1.0",
    hostname: "edge-01",
    platform: "linux",
    nodeVersion: "22.1.0",
    declaredTargetSelectors: ["*.example.com"],
    declaredCommandProfileNames: ["nginx-reload"],
  };
}

describe("agentDispatch.enforceAgentSequence", () => {
  it("accepts a strictly greater sequence via a single CAS UPDATE", async () => {
    const queries = [];
    const client = {
      query: async (sql, params) => {
        queries.push({ sql, params });
        return { rows: [{ id: "agent-row-1" }] };
      },
    };
    await enforceAgentSequence({
      client,
      agentRowId: "agent-row-1",
      envelope: { sequence: 7 },
    });
    assert.equal(queries.length, 1);
    assert.match(queries[0].sql, /SET last_sequence = \$2/);
    assert.match(queries[0].sql, /last_sequence < \$2/);
    assert.deepEqual(queries[0].params, ["agent-row-1", 7]);
  });

  it("rejects a replayed/lower sequence with CERTOPS_AGENT_SEQUENCE_REGRESSION", async () => {
    const client = {
      // Zero rows matched: stored last_sequence >= incoming sequence.
      query: async () => ({ rows: [] }),
    };
    await assert.rejects(
      enforceAgentSequence({
        client,
        agentRowId: "agent-row-1",
        envelope: { sequence: 3 },
      }),
      (error) => error.code === CERTOPS_AGENT_SEQUENCE_REGRESSION,
    );
  });

  it("is a no-op for envelopes without a sequence (legacy agents)", async () => {
    const client = {
      query: async () => {
        throw new Error("no query expected for a sequence-less envelope");
      },
    };
    await enforceAgentSequence({
      client,
      agentRowId: "agent-row-1",
      envelope: {},
    });
    await enforceAgentSequence({
      client,
      agentRowId: "agent-row-1",
      envelope: { sequence: 0 },
    });
  });
});

describe("agentDispatch.registerAgent", () => {
  it("registers happy path: inserts row, consumes token, returns credential once", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("INSERT INTO certops_agents")) {
        return {
          rows: [
            { id: "agent-row-1", agent_id: "agent-01", protocol_version: "1.0.0" },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    const consumed = [];
    const result = await registerAgent({
      dbPool,
      bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A },
      envelope: registerEnvelope(),
      body: registerBody(),
      deps: {
        ensureActiveSigningKey: async () => ({
          signingKeyId: "key-1",
          publicKeyPem: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----",
        }),
        generateAgentCredential: () => ({
          credentialPrefix: "ttagent_0123456789abcdef",
          credentialHash: "hash",
          plaintextCredential: `ttagent_0123456789abcdef_${"b".repeat(64)}`,
        }),
        consumeBootstrapToken: async (options) => {
          consumed.push(options);
          return { id: "boot-1" };
        },
      },
    });

    assert.equal(result.agentId, "agent-01");
    assert.equal(result.protocolVersion, "1.0.0");
    assert.equal(result.signingKeyId, "key-1");
    assert.match(result.credential, /^ttagent_/);
    assert.match(result.signingPublicKeyPem, /BEGIN PUBLIC KEY/);
    assert.equal(consumed.length, 1);
    assert.equal(consumed[0].tokenId, "boot-1");
    assert.equal(consumed[0].agentRowId, "agent-row-1");
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
    assert.equal(dbPool.state.released, true);
  });

  it("answers the consumed-race with the generic 401 code and rolls back", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("INSERT INTO certops_agents")) {
        return {
          rows: [
            { id: "agent-row-1", agent_id: "agent-01", protocol_version: "1.0.0" },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    await assert.rejects(
      registerAgent({
        dbPool,
        bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A },
        envelope: registerEnvelope(),
        body: registerBody(),
        deps: {
          ensureActiveSigningKey: async () => ({
            signingKeyId: "key-1",
            publicKeyPem: "pem",
          }),
          generateAgentCredential: () => ({
            credentialPrefix: "ttagent_0123456789abcdef",
            credentialHash: "hash",
            plaintextCredential: "ttagent_x",
          }),
          // Lost the single-use race.
          consumeBootstrapToken: async () => null,
        },
      }),
      (error) => error.code === CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
    );
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "ROLLBACK"]);
    assert.equal(dbPool.state.released, true);
  });

  it("seeds last_sequence from the register envelope (new generation), 0 when absent", async () => {
    const insertParams = [];
    const makePool = () =>
      createMockPool((sql, params) => {
        if (sql.includes("INSERT INTO certops_agents")) {
          insertParams.push(params);
          return {
            rows: [
              { id: "agent-row-1", agent_id: "agent-01", protocol_version: "1.0.0" },
            ],
          };
        }
        throw new Error(`unexpected query: ${sql}`);
      });
    const deps = {
      ensureActiveSigningKey: async () => ({ signingKeyId: "key-1", publicKeyPem: "pem" }),
      generateAgentCredential: () => ({
        credentialPrefix: "ttagent_0123456789abcdef",
        credentialHash: "hash",
        plaintextCredential: "ttagent_x",
      }),
      consumeBootstrapToken: async () => ({ id: "boot-1" }),
    };

    await registerAgent({
      dbPool: makePool(),
      bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A },
      envelope: { ...registerEnvelope(), sequence: 5 },
      body: registerBody(),
      deps,
    });
    await registerAgent({
      dbPool: makePool(),
      bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A },
      envelope: registerEnvelope(),
      body: registerBody(),
      deps,
    });

    // last_sequence is the 14th insert parameter.
    assert.equal(insertParams[0][13], 5);
    assert.equal(insertParams[1][13], 0);
  });
});

describe("agentDispatch.recordHeartbeat", () => {
  it("recovers an offline agent to active and reports the signing key", async () => {
    const updates = [];
    const dbPool = createMockPool(() => ({ rows: [] }));
    dbPool.query = async (sql, params) => {
      updates.push({ sql, params });
      return {
        rows: [
          {
            id: "agent-row-1",
            status: "active",
            last_seen_at: new Date("2026-07-22T10:00:00.000Z"),
          },
        ],
      };
    };

    const result = await recordHeartbeat({
      dbPool,
      agent: agentFixture({ status: "offline" }),
      envelope: { clockOffsetMs: 12 },
      body: { agentVersion: "0.1.1", ntpSynced: true, uptimeSeconds: 3600 },
      deps: {
        getActiveSigningKeyPublicInfo: async () => ({
          signingKeyId: "key-1",
          publicKeyPem: "pem",
        }),
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.status, "active");
    assert.equal(result.signingKeyId, "key-1");
    assert.equal(result.signingPublicKeyPem, "pem");
    assert.equal(updates.length, 1);
    const sql = updates[0].sql;
    assert.match(sql, /status = CASE WHEN status = 'offline' THEN 'active'/);
    assert.match(sql, /status <> 'retired'/);
    assert.match(sql, /last_seen_at = NOW\(\)/);
  });

  it("rejects a sequence regression before any heartbeat write", async () => {
    const dbPool = createMockPool(() => ({ rows: [] }));
    dbPool.query = async (sql, params) => {
      if (sql.includes("SET last_sequence")) {
        // CAS matches zero rows: regression.
        return { rows: [] };
      }
      throw new Error(`no heartbeat write expected, got: ${sql}`);
    };

    await assert.rejects(
      recordHeartbeat({
        dbPool,
        agent: agentFixture(),
        envelope: { clockOffsetMs: null, sequence: 2 },
        body: { agentVersion: "0.1.0" },
        deps: {
          getActiveSigningKeyPublicInfo: async () => null,
        },
      }),
      (error) => error.code === CERTOPS_AGENT_SEQUENCE_REGRESSION,
    );
  });
});

describe("agentDispatch.claimJobs", () => {
  const CLAIM_DEPS_BASE = {
    lockWorkspaceForCertOpsSideEffect: async () => ({ locked: true }),
    signJobForDispatch: async ({ job }) => ({
      ...job,
      nonce: "n-1",
      issuedAt: "2026-07-22T10:00:00.000Z",
      expiresAt: "2026-07-22T10:05:00.000Z",
      signingKeyId: "key-1",
      signature: "sig",
    }),
  };

  it("claims pending jobs, sets lease fields, and returns signed payloads", async () => {
    let livenessUpdates = 0;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("SET last_seen_at = NOW()")) {
        livenessUpdates += 1;
        assert.equal(params[0], "agent-row-1");
        assert.match(sql, /status <> 'retired'/);
        return { rows: [] };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        assert.equal(params[0], WORKSPACE_A);
        assert.deepEqual(params[1], ["renew"]);
        assert.equal(params[2], 2);
        return {
          rows: [
            {
              id: 42,
              workspace_id: WORKSPACE_A,
              operation: "renew",
              subject_type: "certificate",
              subject_id: "cert-1",
              payload: { domain: "example.com" },
            },
          ],
        };
      }
      if (sql.includes("SET status = 'claimed'")) {
        assert.match(sql, /claimed_by_agent_id = \$2/);
        assert.match(sql, /claim_id = gen_random_uuid\(\)/);
        assert.match(sql, /lease_expires_at = NOW\(\) \+ make_interval/);
        assert.match(sql, /attempt_count = attempt_count \+ 1/);
        assert.equal(params[1], "agent-row-1");
        assert.equal(params[2], 900);
        return {
          rows: [
            {
              id: 42,
              claim_id: "claim-uuid-1",
              lease_expires_at: new Date("2026-07-22T10:15:00.000Z"),
              attempt_count: 1,
              operation: "renew",
              subject_type: "certificate",
              subject_id: "cert-1",
              payload: { domain: "example.com" },
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await claimJobs({
      dbPool,
      agent: agentFixture(),
      body: { maxJobs: 2, supportedActions: ["renew"] },
      env: {},
      deps: CLAIM_DEPS_BASE,
    });

    assert.equal(result.jobs.length, 1);
    const job = result.jobs[0];
    assert.equal(job.jobId, "42");
    assert.equal(job.claimId, "claim-uuid-1");
    assert.equal(
      job.attemptId,
      "claim-uuid-1",
      "dispatch payload must carry a server-assigned attemptId mirroring claimId",
    );
    assert.equal(job.action, "renew");
    assert.equal(job.domain, "example.com");
    assert.equal(job.nonce, "n-1");
    assert.equal(job.signature, "sig");
    assert.equal(job.signingKeyId, "key-1");
    assert.equal(
      livenessUpdates,
      1,
      "claiming must advance the agent's last_seen_at (liveness signal)",
    );
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("honors CERTOPS_JOB_LEASE_SECONDS from env", async () => {
    let leaseParam = null;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("SET last_seen_at = NOW()")) {
        return { rows: [] };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        return {
          rows: [{ id: 1, operation: "renew", payload: {} }],
        };
      }
      if (sql.includes("SET status = 'claimed'")) {
        leaseParam = params[2];
        return {
          rows: [
            {
              id: 1,
              claim_id: "c",
              lease_expires_at: new Date(),
              attempt_count: 1,
              operation: "renew",
              payload: {},
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await claimJobs({
      dbPool,
      agent: agentFixture(),
      body: { maxJobs: 1, supportedActions: ["renew"] },
      env: { CERTOPS_JOB_LEASE_SECONDS: "120" },
      deps: CLAIM_DEPS_BASE,
    });
    assert.equal(leaseParam, 120);
  });

  it("propagates the workspace kill switch and claims nothing", async () => {
    const dbPool = createMockPool((sql) => {
      throw new Error(`no job query expected, got: ${sql}`);
    });
    await assert.rejects(
      claimJobs({
        dbPool,
        agent: agentFixture(),
        body: { maxJobs: 1, supportedActions: ["renew"] },
        env: {},
        deps: {
          ...CLAIM_DEPS_BASE,
          lockWorkspaceForCertOpsSideEffect: async () => {
            const error = new Error("paused");
            error.code = "CERTOPS_WORKSPACE_PAUSED";
            throw error;
          },
        },
      }),
      (error) => error.code === "CERTOPS_WORKSPACE_PAUSED",
    );
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "ROLLBACK"]);
  });

  it("returns an empty set without selecting when supportedActions is empty", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SET last_seen_at = NOW()")) {
        return { rows: [] };
      }
      throw new Error(`no job query expected, got: ${sql}`);
    });
    const result = await claimJobs({
      dbPool,
      agent: agentFixture(),
      body: { maxJobs: 4, supportedActions: [] },
      env: {},
      deps: CLAIM_DEPS_BASE,
    });
    assert.deepEqual(result, { jobs: [] });
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("rejects a sequence regression before locking the workspace or claiming", async () => {
    let workspaceLocked = false;
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SET last_sequence")) {
        return { rows: [] };
      }
      throw new Error(`no job query expected, got: ${sql}`);
    });
    await assert.rejects(
      claimJobs({
        dbPool,
        agent: agentFixture(),
        envelope: { sequence: 1 },
        body: { maxJobs: 1, supportedActions: ["renew"] },
        env: {},
        deps: {
          ...CLAIM_DEPS_BASE,
          lockWorkspaceForCertOpsSideEffect: async () => {
            workspaceLocked = true;
            return { locked: true };
          },
        },
      }),
      (error) => error.code === CERTOPS_AGENT_SEQUENCE_REGRESSION,
    );
    assert.equal(workspaceLocked, false);
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "ROLLBACK"]);
  });

  it("accepts an increasing sequence and proceeds with the claim", async () => {
    let casParams = null;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("SET last_sequence")) {
        casParams = params;
        return { rows: [{ id: "agent-row-1" }] };
      }
      if (sql.includes("SET last_seen_at = NOW()")) {
        return { rows: [] };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    const result = await claimJobs({
      dbPool,
      agent: agentFixture(),
      envelope: { sequence: 9 },
      body: { maxJobs: 1, supportedActions: ["renew"] },
      env: {},
      deps: CLAIM_DEPS_BASE,
    });
    assert.deepEqual(result, { jobs: [] });
    assert.deepEqual(casParams, ["agent-row-1", 9]);
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });
});

describe("agentDispatch.ingestResult", () => {
  function lockedJobRow(overrides = {}) {
    return {
      id: 42,
      status: "claimed",
      claimed_by_agent_id: "agent-row-1",
      claim_id: "claim-uuid-1",
      ...overrides,
    };
  }

  function resultBody(overrides = {}) {
    return {
      jobId: "42",
      attemptId: "claim-uuid-1",
      claimId: "claim-uuid-1",
      nonce: "n-1",
      status: "failed",
      errorMessage: "renewal timed out",
      ...overrides,
    };
  }

  it("rejects ownership mismatch with 409-shaped error before consuming the nonce", async () => {
    let nonceConsulted = false;
    const dbPool = createMockPool((sql) => {
      if (sql.includes("FOR UPDATE")) {
        return { rows: [lockedJobRow({ claim_id: "someone-elses-claim" })] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    await assert.rejects(
      ingestResult({
        dbPool,
        agent: agentFixture(),
        body: resultBody(),
        deps: {
          consumeNonce: async () => {
            nonceConsulted = true;
            return { consumed: true };
          },
        },
      }),
      (error) => error.code === CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
    );
    assert.equal(nonceConsulted, false);
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "ROLLBACK"]);
  });

  it("rejects a replayed nonce", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("FOR UPDATE")) return { rows: [lockedJobRow()] };
      throw new Error(`unexpected query: ${sql}`);
    });
    await assert.rejects(
      ingestResult({
        dbPool,
        agent: agentFixture(),
        body: resultBody(),
        deps: {
          consumeNonce: async () => ({
            consumed: false,
            code: "CERTOPS_NONCE_REPLAYED",
          }),
        },
      }),
      (error) =>
        error.code === CERTOPS_AGENT_RESULT_NONCE_REJECTED &&
        error.replayed === true,
    );
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "ROLLBACK"]);
  });

  it("persists error_code on terminal failure and clears the lease", async () => {
    let updateParams = null;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("FOR UPDATE")) return { rows: [lockedJobRow()] };
      if (sql.includes("UPDATE certificate_jobs")) {
        updateParams = params;
        assert.match(sql, /lease_expires_at = NULL/);
        assert.match(sql, /completed_at = COALESCE\(completed_at, NOW\(\)\)/);
        return {
          rows: [
            {
              id: 42,
              status: "failed",
              error_code: params[2],
              completed_at: new Date("2026-07-22T10:20:00.000Z"),
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody(),
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    assert.equal(result.status, "failed");
    assert.equal(result.errorCode, "AGENT_RESULT_FAILED");
    assert.equal(updateParams[1], "failed");
    assert.equal(updateParams[2], "AGENT_RESULT_FAILED");
    assert.equal(updateParams[3], "renewal timed out");
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("clears error fields on success", async () => {
    let updateParams = null;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("FOR UPDATE")) {
        return { rows: [lockedJobRow({ status: "running" })] };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        updateParams = params;
        return {
          rows: [
            {
              id: 42,
              status: "succeeded",
              error_code: null,
              completed_at: new Date(),
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody({ status: "succeeded", errorMessage: undefined }),
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });
    assert.equal(result.status, "succeeded");
    assert.equal(result.errorCode, null);
    assert.equal(updateParams[2], null);
    assert.equal(updateParams[3], null);
  });

  it("rejects a sequence regression after nonce consumption and rolls the whole transaction back", async () => {
    let nonceConsumed = false;
    const dbPool = createMockPool((sql) => {
      if (sql.includes("FOR UPDATE")) return { rows: [lockedJobRow()] };
      if (sql.includes("SET last_sequence")) {
        // Check ordering: auth (route), nonce replay, then sequence.
        assert.equal(nonceConsumed, true, "nonce must be checked before sequence");
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    await assert.rejects(
      ingestResult({
        dbPool,
        agent: agentFixture(),
        envelope: { sequence: 4 },
        body: resultBody(),
        deps: {
          consumeNonce: async () => {
            nonceConsumed = true;
            return { consumed: true };
          },
        },
      }),
      (error) => error.code === CERTOPS_AGENT_SEQUENCE_REGRESSION,
    );
    // Rollback also un-consumes the nonce ledger write for this message.
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "ROLLBACK"]);
  });

  it("accepts an increasing sequence and completes result ingestion", async () => {
    let casParams = null;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("FOR UPDATE")) return { rows: [lockedJobRow()] };
      if (sql.includes("SET last_sequence")) {
        casParams = params;
        return { rows: [{ id: "agent-row-1" }] };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        return {
          rows: [
            {
              id: 42,
              status: "failed",
              error_code: params[2],
              completed_at: new Date(),
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      envelope: { sequence: 11 },
      body: resultBody(),
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });
    assert.equal(result.status, "failed");
    assert.deepEqual(casParams, ["agent-row-1", 11]);
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });
});
