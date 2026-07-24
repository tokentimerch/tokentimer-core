"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
  CERTOPS_AGENT_COMPATIBILITY_BLOCKED,
  CERTOPS_AGENT_DEPLOY_CERT_UNAVAILABLE,
  CERTOPS_AGENT_LEASE_INVALID,
  CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
  CERTOPS_AGENT_RESULT_NONCE_REJECTED,
  CERTOPS_AGENT_RESULT_STATUS_INVALID,
  CERTOPS_AGENT_SEQUENCE_REGRESSION,
  claimJobs,
  enforceAgentSequence,
  ingestResult,
  recordHeartbeat,
  registerAgent,
  renewJobLease,
  _test: dispatchTest,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentDispatch.js"),
);
const {
  ENCRYPTION_VERSION,
  encryptRegistrationCredential,
  _test: cryptoTest,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/registrationCredentialCrypto.js",
  ),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const VALID_REGISTRATION_ENCRYPTION_KEY = "a".repeat(64);

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

function registerBody(overrides = {}) {
  return {
    bootstrapTokenId: "boot-1",
    agentVersion: "0.1.0",
    registrationId: "550e8400-e29b-41d4-a716-446655440000",
    hostname: "edge-01",
    platform: "linux",
    nodeVersion: "22.1.0",
    declaredTargetSelectors: ["*.example.com"],
    declaredCommandProfileNames: ["nginx-reload"],
    ...overrides,
  };
}

function registrationQueryHandler({
  tokenStatus = "active",
  insertAgent = true,
  replayRow = null,
  agentRow = {
    id: "agent-row-1",
    agent_id: "agent-01",
    protocol_version: "1.0.0",
  },
  onReplayInsert = null,
  expireReplayLookup = false,
} = {}) {
  const replays = replayRow ? [replayRow] : [];
  return (sql, params) => {
    if (
      sql.includes("FROM certops_agent_bootstrap_tokens") &&
      sql.includes("FOR UPDATE")
    ) {
      return {
        rows: [{ id: "boot-1", status: tokenStatus, workspace_id: WORKSPACE_A }],
      };
    }
    if (sql.includes("FROM certops_agent_registration_replays")) {
      if (expireReplayLookup) return { rows: [] };
      const match = replays.find(
        (row) =>
          row.bootstrap_token_id === params[0] &&
          row.registration_id === params[1],
      );
      return { rows: match ? [match] : [] };
    }
    if (sql.includes("INSERT INTO certops_agents")) {
      if (!insertAgent) return { rows: [] };
      return { rows: [agentRow] };
    }
    if (sql.includes("INSERT INTO certops_agent_registration_replays")) {
      const row = {
        bootstrap_token_id: params[1],
        registration_id: params[2],
        agent_id: params[3],
        credential_ciphertext: params[4],
        encryption_version: params[5],
        protocol_version: params[6],
        signing_key_id: params[7],
        signing_public_key_pem: params[8],
      };
      replays.push(row);
      if (onReplayInsert) onReplayInsert(row, params);
      return { rows: [row] };
    }
    throw new Error(`unexpected query: ${sql}`);
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

  it("accepts a sequence-less envelope only while the agent has never sequenced", async () => {
    const client = {
      query: async (sql) => {
        assert.match(sql, /SELECT last_sequence FROM certops_agents/);
        return { rows: [{ last_sequence: 0 }] };
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

  it("rejects a sequence-less envelope once the agent has sent sequenced traffic (no-bypass)", async () => {
    const client = {
      query: async (sql) => {
        assert.match(sql, /SELECT last_sequence FROM certops_agents/);
        return { rows: [{ last_sequence: 12 }] };
      },
    };
    await assert.rejects(
      enforceAgentSequence({
        client,
        agentRowId: "agent-row-1",
        envelope: {},
      }),
      (error) => error.code === CERTOPS_AGENT_SEQUENCE_REGRESSION,
    );
  });
});

describe("agentDispatch.registerAgent", () => {
  let savedRegistrationKey;

  beforeEach(() => {
    savedRegistrationKey = process.env[cryptoTest.ENV_KEY_NAME];
    process.env[cryptoTest.ENV_KEY_NAME] = VALID_REGISTRATION_ENCRYPTION_KEY;
  });

  afterEach(() => {
    if (savedRegistrationKey === undefined) {
      delete process.env[cryptoTest.ENV_KEY_NAME];
    } else {
      process.env[cryptoTest.ENV_KEY_NAME] = savedRegistrationKey;
    }
  });

  it("registers happy path: inserts row, consumes token, persists encrypted replay, returns credential once", async () => {
    const persisted = [];
    const dbPool = createMockPool(
      registrationQueryHandler({
        onReplayInsert: (row) => persisted.push(row),
      }),
    );
    const consumed = [];
    const credential = `ttagent_0123456789abcdef_${"b".repeat(64)}`;
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
          plaintextCredential: credential,
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
    assert.equal(result.credential, credential);
    assert.match(result.signingPublicKeyPem, /BEGIN PUBLIC KEY/);
    assert.equal(consumed.length, 1);
    assert.equal(consumed[0].tokenId, "boot-1");
    assert.equal(consumed[0].agentRowId, "agent-row-1");
    assert.equal(persisted.length, 1);
    assert.equal(persisted[0].registration_id, registerBody().registrationId);
    assert.notEqual(persisted[0].credential_ciphertext, credential);
    assert.equal(persisted[0].credential_ciphertext.includes("ttagent_"), false);
    assert.match(
      persisted[0].credential_ciphertext,
      /^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$/,
    );
    assert.equal(persisted[0].encryption_version, ENCRYPTION_VERSION);
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
    assert.equal(dbPool.state.released, true);
  });

  it("fails closed when the registration encryption key is missing", async () => {
    delete process.env[cryptoTest.ENV_KEY_NAME];
    const dbPool = createMockPool(registrationQueryHandler());
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
            plaintextCredential: `ttagent_0123456789abcdef_${"e".repeat(64)}`,
          }),
          consumeBootstrapToken: async () => ({ id: "boot-1" }),
        },
      }),
      (error) =>
        error.code === "CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING" &&
        !String(error.message).includes("ttagent_"),
    );
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "ROLLBACK"]);
  });

  it("replays the same response for a retry with the same registrationId after the token is spent", async () => {
    const credential = `ttagent_0123456789abcdef_${"c".repeat(64)}`;
    const ciphertext = encryptRegistrationCredential(credential);
    const dbPool = createMockPool(
      registrationQueryHandler({
        tokenStatus: "used",
        replayRow: {
          bootstrap_token_id: "boot-1",
          registration_id: "550e8400-e29b-41d4-a716-446655440000",
          agent_id: "agent-01",
          credential_ciphertext: ciphertext,
          encryption_version: ENCRYPTION_VERSION,
          protocol_version: "1.0.0",
          signing_key_id: "key-1",
          signing_public_key_pem: "pem-1",
        },
      }),
    );
    let consumeCalls = 0;
    const result = await registerAgent({
      dbPool,
      bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A, status: "used" },
      envelope: registerEnvelope(),
      body: registerBody(),
      deps: {
        ensureActiveSigningKey: async () => {
          throw new Error("must not mint on replay");
        },
        generateAgentCredential: () => {
          throw new Error("must not mint on replay");
        },
        consumeBootstrapToken: async () => {
          consumeCalls += 1;
          return null;
        },
      },
    });

    assert.deepEqual(result, {
      agentId: "agent-01",
      credential,
      protocolVersion: "1.0.0",
      signingKeyId: "key-1",
      signingPublicKeyPem: "pem-1",
    });
    assert.equal(consumeCalls, 0);
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("hard-rejects a different registrationId against an already-spent token", async () => {
    const dbPool = createMockPool(
      registrationQueryHandler({ tokenStatus: "used" }),
    );
    await assert.rejects(
      registerAgent({
        dbPool,
        bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A, status: "used" },
        envelope: registerEnvelope(),
        body: registerBody({ registrationId: "different-registration-id" }),
        deps: {
          ensureActiveSigningKey: async () => ({
            signingKeyId: "key-1",
            publicKeyPem: "pem",
          }),
          generateAgentCredential: () => ({
            credentialPrefix: "ttagent_0123456789abcdef",
            credentialHash: "hash",
            plaintextCredential: `ttagent_0123456789abcdef_${"a".repeat(64)}`,
          }),
          consumeBootstrapToken: async () => null,
        },
      }),
      (error) => error.code === CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
    );
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "ROLLBACK"]);
  });

  it("rejects replay after the encrypted row expires", async () => {
    const credential = `ttagent_0123456789abcdef_${"f".repeat(64)}`;
    const dbPool = createMockPool(
      registrationQueryHandler({
        tokenStatus: "used",
        expireReplayLookup: true,
        replayRow: {
          bootstrap_token_id: "boot-1",
          registration_id: "550e8400-e29b-41d4-a716-446655440000",
          agent_id: "agent-01",
          credential_ciphertext: encryptRegistrationCredential(credential),
          encryption_version: ENCRYPTION_VERSION,
          protocol_version: "1.0.0",
          signing_key_id: "key-1",
          signing_public_key_pem: "pem-1",
        },
      }),
    );
    await assert.rejects(
      registerAgent({
        dbPool,
        bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A, status: "used" },
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
            plaintextCredential: credential,
          }),
          consumeBootstrapToken: async () => null,
        },
      }),
      (error) => error.code === CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
    );
  });

  it("treats a corrupt ciphertext as replay-not-available (spent token hard-rejects)", async () => {
    const dbPool = createMockPool(
      registrationQueryHandler({
        tokenStatus: "used",
        replayRow: {
          bootstrap_token_id: "boot-1",
          registration_id: "550e8400-e29b-41d4-a716-446655440000",
          agent_id: "agent-01",
          credential_ciphertext: "deadbeef:00:ff",
          encryption_version: ENCRYPTION_VERSION,
          protocol_version: "1.0.0",
          signing_key_id: "key-1",
          signing_public_key_pem: "pem-1",
        },
      }),
    );
    await assert.rejects(
      registerAgent({
        dbPool,
        bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A, status: "used" },
        envelope: registerEnvelope(),
        body: registerBody(),
        deps: {
          ensureActiveSigningKey: async () => {
            throw new Error("must not mint");
          },
          generateAgentCredential: () => {
            throw new Error("must not mint");
          },
          consumeBootstrapToken: async () => null,
        },
      }),
      (error) =>
        error.code === CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED &&
        !String(error.message).includes("ttagent_"),
    );
  });

  it("answers the consumed-race with the generic 401 code and rolls back", async () => {
    const dbPool = createMockPool(registrationQueryHandler());
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
            plaintextCredential: `ttagent_0123456789abcdef_${"a".repeat(64)}`,
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
    const makePool = () => {
      const pool = createMockPool(registrationQueryHandler());
      const original = pool.client.query.bind(pool.client);
      pool.client.query = async (text, params) => {
        const sql = typeof text === "string" ? text : text?.text || "";
        if (sql.includes("INSERT INTO certops_agents")) {
          insertParams.push(params);
        }
        return original(text, params);
      };
      return pool;
    };
    const deps = {
      ensureActiveSigningKey: async () => ({ signingKeyId: "key-1", publicKeyPem: "pem" }),
      generateAgentCredential: () => ({
        credentialPrefix: "ttagent_0123456789abcdef",
        credentialHash: "hash",
        plaintextCredential: `ttagent_0123456789abcdef_${"a".repeat(64)}`,
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
      body: registerBody({ registrationId: "second-registration-id" }),
      deps,
    });

    // last_sequence is the 14th insert parameter.
    assert.equal(insertParams[0][13], 5);
    assert.equal(insertParams[1][13], 0);
  });

  it("resolves sequential duplicate registrationIds to a single agent credential", async () => {
    const credential = `ttagent_0123456789abcdef_${"d".repeat(64)}`;
    const sharedReplays = [];
    let tokenStatus = "active";
    let agentInserted = false;
    const handler = (sql, params) => {
      if (
        sql.includes("FROM certops_agent_bootstrap_tokens") &&
        sql.includes("FOR UPDATE")
      ) {
        return {
          rows: [
            { id: "boot-1", status: tokenStatus, workspace_id: WORKSPACE_A },
          ],
        };
      }
      if (sql.includes("FROM certops_agent_registration_replays")) {
        const match = sharedReplays.find(
          (row) =>
            row.bootstrap_token_id === params[0] &&
            row.registration_id === params[1],
        );
        return { rows: match ? [match] : [] };
      }
      if (sql.includes("INSERT INTO certops_agents")) {
        if (agentInserted) return { rows: [] };
        agentInserted = true;
        return {
          rows: [
            {
              id: "agent-row-1",
              agent_id: "agent-01",
              protocol_version: "1.0.0",
            },
          ],
        };
      }
      if (sql.includes("INSERT INTO certops_agent_registration_replays")) {
        const row = {
          bootstrap_token_id: params[1],
          registration_id: params[2],
          agent_id: params[3],
          credential_ciphertext: params[4],
          encryption_version: params[5],
          protocol_version: params[6],
          signing_key_id: params[7],
          signing_public_key_pem: params[8],
        };
        sharedReplays.push(row);
        tokenStatus = "used";
        return { rows: [row] };
      }
      throw new Error(`unexpected query: ${sql}`);
    };

    const deps = {
      ensureActiveSigningKey: async () => ({
        signingKeyId: "key-1",
        publicKeyPem: "pem-1",
      }),
      generateAgentCredential: () => ({
        credentialPrefix: "ttagent_0123456789abcdef",
        credentialHash: "hash",
        plaintextCredential: credential,
      }),
      consumeBootstrapToken: async () => {
        tokenStatus = "used";
        return { id: "boot-1" };
      },
    };

    const first = await registerAgent({
      dbPool: createMockPool(handler),
      bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A },
      envelope: registerEnvelope(),
      body: registerBody(),
      deps,
    });
    const second = await registerAgent({
      dbPool: createMockPool(handler),
      bootstrapToken: { id: "boot-1", workspaceId: WORKSPACE_A, status: "used" },
      envelope: registerEnvelope(),
      body: registerBody(),
      deps,
    });

    assert.deepEqual(first, second);
    assert.equal(sharedReplays.length, 1);
    assert.equal(agentInserted, true);
    assert.equal(sharedReplays[0].credential_ciphertext.includes("ttagent_"), false);
  });

  it("uses a configurable short replay TTL defaulting to 15 minutes", () => {
    assert.equal(dispatchTest.DEFAULT_REGISTRATION_REPLAY_TTL_MS, 15 * 60 * 1000);
    assert.equal(dispatchTest.registrationReplayTtlMs({}), 15 * 60 * 1000);
    assert.equal(
      dispatchTest.registrationReplayTtlMs({
        CERTOPS_REGISTRATION_REPLAY_TTL_MS: "60000",
      }),
      60000,
    );
    assert.equal(
      dispatchTest.registrationReplayTtlMs({
        CERTOPS_REGISTRATION_REPLAY_TTL_MS: "nope",
      }),
      15 * 60 * 1000,
    );
  });
});

describe("agentDispatch.recordHeartbeat", () => {
  it("recovers an offline agent to active and reports the signing key", async () => {
    const updates = [];
    const dbPool = createMockPool((sql, params) => {
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
    });

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
        getSigningKeyRotationNotice: async () => null,
        acknowledgeSigningKey: async () => ({ acknowledged: false }),
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.status, "active");
    assert.equal(result.signingKeyId, "key-1");
    assert.equal(result.signingPublicKeyPem, "pem");
    assert.equal(result.signingKeyRotation, null);
    const heartbeatWrites = updates.filter(({ sql }) =>
      sql.includes("last_seen_at = NOW()"),
    );
    assert.equal(heartbeatWrites.length, 1);
    const sql = heartbeatWrites[0].sql;
    assert.match(sql, /status = CASE WHEN status = 'offline' THEN 'active'/);
    assert.match(sql, /status <> 'retired'/);
    assert.match(sql, /last_seen_at = NOW\(\)/);
    // The sequence bump and heartbeat write share one transaction.
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("rejects a sequence regression before any heartbeat write", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SET last_sequence")) {
        // CAS matches zero rows: regression.
        return { rows: [] };
      }
      throw new Error(`no heartbeat write expected, got: ${sql}`);
    });

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
      if (sql.includes("SELECT last_sequence")) {
        // Legacy (sequence-less) poll from an agent that never sequenced.
        return { rows: [{ last_sequence: 0 }] };
      }
      if (sql.includes("SET last_seen_at = NOW()")) {
        livenessUpdates += 1;
        assert.equal(params[0], "agent-row-1");
        assert.match(sql, /status <> 'retired'/);
        return { rows: [] };
      }
      if (sql.includes("SELECT declared_target_selectors")) {
        return {
          rows: [
            {
              declared_target_selectors: ["*.example.com"],
              declared_command_profile_names: ["nginx-reload"],
              supported_dns_providers: ["route53"],
            },
          ],
        };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        assert.equal(params[0], WORKSPACE_A);
        assert.deepEqual(params[1], ["renew"]);
        assert.equal(params[2], "agent-row-1");
        assert.match(sql, /executor_kind = 'agent'/);
        assert.equal(params[6], 2);
        return {
          rows: [
            {
              id: 42,
              workspace_id: WORKSPACE_A,
              operation: "renew",
              subject_type: "certificate",
              subject_id: "cert-1",
              payload: { domain: "example.com" },
              executor_kind: "agent",
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
      if (sql.includes("SELECT last_sequence")) {
        return { rows: [{ last_sequence: 0 }] };
      }
      if (sql.includes("SET last_seen_at = NOW()")) {
        return { rows: [] };
      }
      if (sql.includes("SELECT declared_target_selectors")) {
        return {
          rows: [
            {
              declared_target_selectors: [],
              declared_command_profile_names: [],
              supported_dns_providers: [],
            },
          ],
        };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        return {
          rows: [{ id: 1, operation: "renew", payload: {}, executor_kind: "agent" }],
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
      if (sql.includes("SELECT last_sequence")) {
        return { rows: [{ last_sequence: 0 }] };
      }
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
      if (sql.includes("SELECT last_sequence")) {
        return { rows: [{ last_sequence: 0 }] };
      }
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
      if (sql.includes("SELECT declared_target_selectors")) {
        return {
          rows: [
            {
              declared_target_selectors: [],
              declared_command_profile_names: [],
              supported_dns_providers: [],
            },
          ],
        };
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

  it("excludes controller-lane jobs from agent claims (B2)", async () => {
    let claimSql = null;
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SELECT last_sequence")) {
        return { rows: [{ last_sequence: 0 }] };
      }
      if (sql.includes("SET last_seen_at = NOW()")) return { rows: [] };
      if (sql.includes("SELECT declared_target_selectors")) {
        return {
          rows: [
            {
              declared_target_selectors: [],
              declared_command_profile_names: [],
              supported_dns_providers: [],
            },
          ],
        };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        claimSql = sql;
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    await claimJobs({
      dbPool,
      agent: agentFixture(),
      body: { maxJobs: 1, supportedActions: ["deploy"] },
      env: {},
      deps: CLAIM_DEPS_BASE,
    });
    assert.match(claimSql, /executor_kind = 'agent'/);
  });

  it("attaches public certificate PEM and hash for deploy jobs (B15)", async () => {
    const pem =
      "-----BEGIN CERTIFICATE-----\nMIIBdeploy\n-----END CERTIFICATE-----\n";
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SELECT last_sequence")) {
        return { rows: [{ last_sequence: 0 }] };
      }
      if (sql.includes("SET last_seen_at = NOW()")) return { rows: [] };
      if (sql.includes("SELECT declared_target_selectors")) {
        return {
          rows: [
            {
              declared_target_selectors: [],
              declared_command_profile_names: [],
              supported_dns_providers: [],
            },
          ],
        };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        return {
          rows: [
            {
              id: "job-deploy-1",
              operation: "deploy",
              subject_type: "managed_certificate",
              subject_id: "mc-1",
              payload: { certPath: "/etc/ssl/cert.pem" },
              executor_kind: "agent",
            },
          ],
        };
      }
      if (sql.includes("FROM managed_certificates")) {
        return {
          rows: [
            {
              certificate_pem: pem,
              fingerprint_sha256: "a".repeat(64),
            },
          ],
        };
      }
      if (sql.includes("SET status = 'claimed'")) {
        return {
          rows: [
            {
              id: "job-deploy-1",
              claim_id: "claim-d1",
              lease_expires_at: new Date("2026-07-22T10:15:00.000Z"),
              attempt_count: 1,
              operation: "deploy",
              subject_type: "managed_certificate",
              subject_id: "mc-1",
              payload: { certPath: "/etc/ssl/cert.pem" },
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await claimJobs({
      dbPool,
      agent: agentFixture(),
      body: { maxJobs: 1, supportedActions: ["deploy"] },
      env: {},
      deps: CLAIM_DEPS_BASE,
    });
    assert.equal(result.jobs.length, 1);
    assert.equal(result.jobs[0].certificatePem, pem.trim());
    assert.equal(typeof result.jobs[0].certificatePemSha256, "string");
    assert.equal(result.jobs[0].certificatePemSha256.length, 64);
    assert.equal(result.jobs[0].target.fingerprintSha256, "a".repeat(64));
  });

  it("blocks deploy jobs when public certificate inventory is missing (B15)", async () => {
    let blocked = false;
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SELECT last_sequence")) {
        return { rows: [{ last_sequence: 0 }] };
      }
      if (sql.includes("SET last_seen_at = NOW()")) return { rows: [] };
      if (sql.includes("SELECT declared_target_selectors")) {
        return {
          rows: [
            {
              declared_target_selectors: [],
              declared_command_profile_names: [],
              supported_dns_providers: [],
            },
          ],
        };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        return {
          rows: [
            {
              id: "job-deploy-2",
              operation: "deploy",
              subject_type: "managed_certificate",
              subject_id: "mc-missing",
              payload: {},
              executor_kind: "agent",
            },
          ],
        };
      }
      if (sql.includes("FROM managed_certificates")) {
        return { rows: [] };
      }
      if (sql.includes("SET status = 'blocked'")) {
        blocked = true;
        assert.equal(sql.includes("error_code"), true);
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await claimJobs({
      dbPool,
      agent: agentFixture(),
      body: { maxJobs: 1, supportedActions: ["deploy"] },
      env: {},
      deps: CLAIM_DEPS_BASE,
    });
    assert.deepEqual(result, { jobs: [] });
    assert.equal(blocked, true);
  });

  it("rejects claim when compatibilityState is blocked and does not assign jobs", async () => {
    let claimed = false;
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SELECT last_sequence") || sql.includes("SET last_sequence")) {
        return { rows: [{ last_sequence: 0, id: "agent-row-1" }] };
      }
      if (sql.includes("SET status = 'claimed'")) {
        claimed = true;
        return { rows: [] };
      }
      throw new Error(`no job claim expected, got: ${sql}`);
    });

    await assert.rejects(
      claimJobs({
        dbPool,
        agent: agentFixture({ protocolVersion: "0.0.1", agentVersion: "0.0.1" }),
        body: { maxJobs: 1, supportedActions: ["renew"] },
        env: {
          CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
          CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.999.999",
          CERTOPS_AGENT_MIN_AGENT_VERSION: "0.10.0",
          CERTOPS_AGENT_MAX_AGENT_VERSION: "99.999.999",
        },
        deps: CLAIM_DEPS_BASE,
      }),
      (error) =>
        error.code === CERTOPS_AGENT_COMPATIBILITY_BLOCKED &&
        /compatibility policy/i.test(error.message),
    );
    assert.equal(claimed, false);
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "ROLLBACK"]);
  });

  it("allows claim for outdated (not blocked) agents", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SELECT last_sequence") || sql.includes("SET last_sequence")) {
        return { rows: [{ last_sequence: 0, id: "agent-row-1" }] };
      }
      if (sql.includes("SET last_seen_at = NOW()")) return { rows: [] };
      if (sql.includes("SELECT declared_target_selectors")) {
        return {
          rows: [
            {
              declared_target_selectors: [],
              declared_command_profile_names: [],
              supported_dns_providers: [],
            },
          ],
        };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) return { rows: [] };
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await claimJobs({
      dbPool,
      agent: agentFixture({ agentVersion: "0.1.0" }),
      body: { maxJobs: 1, supportedActions: ["renew"] },
      env: {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.999.999",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.1.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "0.5.0",
      },
      deps: CLAIM_DEPS_BASE,
    });
    assert.deepEqual(result, { jobs: [] });
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("allows claim for compatible agents at the minimum protocol floor", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SELECT last_sequence") || sql.includes("SET last_sequence")) {
        return { rows: [{ last_sequence: 0, id: "agent-row-1" }] };
      }
      if (sql.includes("SET last_seen_at = NOW()")) return { rows: [] };
      if (sql.includes("SELECT declared_target_selectors")) {
        return {
          rows: [
            {
              declared_target_selectors: [],
              declared_command_profile_names: [],
              supported_dns_providers: [],
            },
          ],
        };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) return { rows: [] };
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await claimJobs({
      dbPool,
      agent: agentFixture({ protocolVersion: "1.0.0", agentVersion: "0.10.0" }),
      body: { maxJobs: 1, supportedActions: ["renew"] },
      env: {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.999.999",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.10.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "99.999.999",
      },
      deps: CLAIM_DEPS_BASE,
    });
    assert.deepEqual(result, { jobs: [] });
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });
});

describe("agentDispatch.renewJobLease", () => {
  it("transitions claimed→running, extends lease, and extends the nonce (B6/B7)", async () => {
    let extendedNonce = null;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("SELECT last_sequence")) {
        return { rows: [{ last_sequence: 0 }] };
      }
      if (sql.includes("SELECT id, status, claimed_by_agent_id")) {
        return {
          rows: [
            {
              id: "job-1",
              status: "claimed",
              claimed_by_agent_id: "agent-row-1",
              claim_id: "claim-1",
              lease_expires_at: new Date("2026-07-22T10:15:00.000Z"),
            },
          ],
        };
      }
      if (sql.includes("SET status = 'running'")) {
        assert.equal(params[1], 900);
        return {
          rows: [
            {
              id: "job-1",
              status: "running",
              claim_id: "claim-1",
              lease_expires_at: new Date("2026-07-22T10:30:00.000Z"),
              lease_renewed_at: new Date("2026-07-22T10:15:00.000Z"),
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await renewJobLease({
      dbPool,
      agent: agentFixture(),
      jobId: "job-1",
      claimId: "claim-1",
      envelope: {},
      env: {},
      deps: {
        extendJobNonceExpiry: async (opts) => {
          extendedNonce = opts;
          return {
            extended: true,
            expiresAt: "2026-07-22T11:35:00.000Z",
          };
        },
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.status, "running");
    assert.equal(result.claimId, "claim-1");
    assert.equal(result.nonceExpiresAt, "2026-07-22T11:35:00.000Z");
    assert.equal(extendedNonce.jobId, "job-1");
    assert.equal(extendedNonce.nonceTtlSeconds, 4800);
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("rejects lease renew with ownership mismatch", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SELECT last_sequence")) {
        return { rows: [{ last_sequence: 0 }] };
      }
      if (sql.includes("SELECT id, status, claimed_by_agent_id")) {
        return {
          rows: [
            {
              id: "job-1",
              status: "claimed",
              claimed_by_agent_id: "other-agent",
              claim_id: "claim-1",
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    await assert.rejects(
      renewJobLease({
        dbPool,
        agent: agentFixture(),
        jobId: "job-1",
        claimId: "claim-1",
        deps: { extendJobNonceExpiry: async () => ({ extended: false }) },
      }),
      (error) => error.code === CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
    );
  });

  it("rejects lease renew without claimId", async () => {
    await assert.rejects(
      renewJobLease({
        dbPool: createMockPool(() => ({ rows: [] })),
        agent: agentFixture(),
        jobId: "job-1",
        claimId: "",
      }),
      (error) => error.code === CERTOPS_AGENT_LEASE_INVALID,
    );
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

  it("maps orphaned_unknown_effect and persists reconciliation fields from errorMessage", async () => {
    let updateParams = null;
    let updateSql = null;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("FOR UPDATE")) {
        return { rows: [lockedJobRow({ status: "running", mode: "real" })] };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        updateSql = sql;
        updateParams = params;
        return {
          rows: [
            {
              id: 42,
              status: "orphaned_unknown_effect",
              error_code: params[2],
              completed_at: new Date("2026-07-22T10:20:00.000Z"),
              needs_operator_reconciliation: true,
              reconciliation_reason: params[5],
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody({
        status: "orphaned_unknown_effect",
        errorMessage:
          "target 2 failed (multi-target rollback uncertain: target 1 rollback failed; " +
          "needsOperatorReconciliation=true; reconciliationReason=multi_target_rollback_uncertain)",
      }),
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    assert.equal(result.status, "orphaned_unknown_effect");
    assert.equal(updateParams[1], "orphaned_unknown_effect");
    assert.equal(updateParams[4], true);
    assert.equal(updateParams[5], "multi_target_rollback_uncertain");
    assert.match(updateSql, /needs_operator_reconciliation/);
    assert.match(updateSql, /reconciliation_reason/);
  });

  it("sets fallback reconciliation_reason when orphaned markers are missing", async () => {
    let updateParams = null;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("FOR UPDATE")) {
        return { rows: [lockedJobRow({ status: "running", mode: "real" })] };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        updateParams = params;
        return {
          rows: [
            {
              id: 42,
              status: "orphaned_unknown_effect",
              error_code: params[2],
              completed_at: new Date(),
              needs_operator_reconciliation: true,
              reconciliation_reason: params[5],
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody({
        status: "orphaned_unknown_effect",
        errorMessage: "first-ever deploy may be live; operator reconciliation is required",
      }),
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    assert.equal(updateParams[4], true);
    assert.equal(
      updateParams[5],
      dispatchTest.FALLBACK_ORPHANED_RECONCILIATION_REASON,
    );
  });

  it("does not set needs_operator_reconciliation for dry_run_complete", async () => {
    let updateParams = null;
    const dbPool = createMockPool((sql, params) => {
      if (sql.includes("FOR UPDATE")) {
        return {
          rows: [lockedJobRow({ status: "running", mode: "dry_run" })],
        };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        updateParams = params;
        return {
          rows: [
            {
              id: 42,
              status: "dry_run_complete",
              error_code: null,
              completed_at: new Date(),
              needs_operator_reconciliation: false,
              reconciliation_reason: null,
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody({
        status: "dry_run_complete",
        errorMessage: undefined,
      }),
      deps: { consumeNonce: async () => ({ consumed: true }) },
    });

    assert.equal(result.status, "dry_run_complete");
    assert.equal(updateParams[4], false);
    assert.equal(updateParams[5], null);
  });

  it("rejects dry_run jobs that report succeeded", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("FOR UPDATE")) {
        return { rows: [lockedJobRow({ mode: "dry_run" })] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    await assert.rejects(
      ingestResult({
        dbPool,
        agent: agentFixture(),
        body: resultBody({ status: "succeeded", errorMessage: undefined }),
        deps: { consumeNonce: async () => ({ consumed: true }) },
      }),
      (error) => error.code === CERTOPS_AGENT_RESULT_STATUS_INVALID,
    );
  });

  it("rejects real jobs that report dry_run_complete", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("FOR UPDATE")) {
        return { rows: [lockedJobRow({ mode: "real" })] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    await assert.rejects(
      ingestResult({
        dbPool,
        agent: agentFixture(),
        body: resultBody({
          status: "dry_run_complete",
          errorMessage: undefined,
        }),
        deps: { consumeNonce: async () => ({ consumed: true }) },
      }),
      (error) => error.code === CERTOPS_AGENT_RESULT_STATUS_INVALID,
    );
  });

  it("rejects dry_run jobs that report orphaned_unknown_effect", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("FOR UPDATE")) {
        return { rows: [lockedJobRow({ mode: "dry_run" })] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    await assert.rejects(
      ingestResult({
        dbPool,
        agent: agentFixture(),
        body: resultBody({ status: "orphaned_unknown_effect" }),
        deps: { consumeNonce: async () => ({ consumed: true }) },
      }),
      (error) => error.code === CERTOPS_AGENT_RESULT_STATUS_INVALID,
    );
  });

  it("treats duplicate terminal result delivery as idempotent", async () => {
    const completedAt = new Date("2026-07-22T10:20:00.000Z");
    let updateCount = 0;
    const dbPool = createMockPool((sql) => {
      if (sql.includes("FOR UPDATE")) {
        return {
          rows: [
            lockedJobRow({
              status: "orphaned_unknown_effect",
              mode: "real",
              error_code: "AGENT_RESULT_ORPHANED_UNKNOWN_EFFECT",
              completed_at: completedAt,
            }),
          ],
        };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        updateCount += 1;
        throw new Error("duplicate terminal results must not re-write");
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody({ status: "orphaned_unknown_effect" }),
      deps: {
        consumeNonce: async () => ({
          consumed: false,
          code: "CERTOPS_NONCE_REPLAYED",
        }),
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.duplicate, true);
    assert.equal(result.status, "orphaned_unknown_effect");
    assert.equal(updateCount, 0);
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("parses agent reconciliation markers from errorMessage", () => {
    const parsed = dispatchTest.parseReconciliationFromErrorMessage(
      "boom (needsOperatorReconciliation=true; reconciliationReason=multi_target_rollback_uncertain)",
    );
    assert.equal(parsed.needsOperatorReconciliation, true);
    assert.equal(parsed.reconciliationReason, "multi_target_rollback_uncertain");
  });

  it("locks the agent row before the job row (matches claim/lease lock ordering, avoids AB-BA deadlock)", async () => {
    // Regression: claimJobs/renewJobLease both lock certops_agents before
    // any certificate_jobs row (via enforceAgentSequence's FOR UPDATE on
    // the agent row, ahead of the job SELECT). ingestResult used to invert
    // this by locking the job row first and the agent row only later
    // inside enforceSequence, which could deadlock against a concurrent
    // claim/lease-renew for the same agent. Assert the query order here so
    // a future refactor cannot silently reintroduce the inversion.
    const queryOrder = [];
    const dbPool = createMockPool((sql) => {
      if (sql.includes("FROM certops_agents") && sql.includes("FOR UPDATE")) {
        queryOrder.push("agent-lock");
        return { rows: [{ id: "agent-row-1" }] };
      }
      if (sql.includes("FROM certificate_jobs") && sql.includes("FOR UPDATE")) {
        queryOrder.push("job-lock");
        return { rows: [lockedJobRow({ status: "running", mode: "real" })] };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        return {
          rows: [
            {
              id: 42,
              status: "succeeded",
              error_code: null,
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
      body: resultBody({ status: "succeeded", errorMessage: undefined }),
      deps: {
        consumeNonce: async () => ({ consumed: true }),
        enforceAgentSequence: async () => {},
      },
    });

    assert.equal(result.status, "succeeded");
    assert.deepEqual(queryOrder, ["agent-lock", "job-lock"]);
  });
});
