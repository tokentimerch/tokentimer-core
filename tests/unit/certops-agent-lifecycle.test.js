"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { pool } = require(
  path.resolve(__dirname, "../../apps/api/db/database.js"),
);
const certOpsRouter = require(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
);
const agentRegistry = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/agentRegistry.js",
  ),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const AGENT_ROW_ID = "22222222-2222-4222-8222-222222222222";
const BOOT_TOKEN_ID = "33333333-3333-4333-8333-333333333333";

function createMemoryDb() {
  const bootstrapRows = [];
  const agentRows = [];
  const jobLeases = [];
  const auditEvents = [];
  let nextBootId = 0;

  const db = {
    bootstrapRows,
    agentRows,
    jobLeases,
    auditEvents,
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, " ").trim();

      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) {
        return { rows: [] };
      }

      if (normalized.includes("INSERT INTO audit_events")) {
        auditEvents.push({
          actorUserId: params[0],
          action: params[2],
          targetType: params[3],
          metadata: params[6],
          workspaceId: params[7],
        });
        return { rows: [] };
      }

      if (normalized.includes("INSERT INTO certops_agent_bootstrap_tokens")) {
        nextBootId += 1;
        const row = {
          id: nextBootId === 1 ? BOOT_TOKEN_ID : `boot-${nextBootId}`,
          workspace_id: params[0],
          name: params[1],
          token_prefix: params[2],
          token_hash: params[3],
          status: "active",
          expires_at: params[4],
          used_at: null,
          used_by_agent_id: null,
          revoked_at: null,
          revoked_by: null,
          created_by: params[5],
          created_at: new Date("2026-07-01T00:00:00.000Z"),
          updated_at: new Date("2026-07-01T00:00:00.000Z"),
        };
        bootstrapRows.push(row);
        return { rows: [row] };
      }

      if (
        normalized.includes("FROM certops_agent_bootstrap_tokens") &&
        normalized.includes("WHERE workspace_id = $1") &&
        normalized.includes("AND id = $2")
      ) {
        return {
          rows: bootstrapRows.filter(
            (row) => row.workspace_id === params[0] && row.id === params[1],
          ),
        };
      }

      if (
        normalized.includes("FROM certops_agent_bootstrap_tokens") &&
        normalized.includes("ORDER BY created_at DESC")
      ) {
        return {
          rows: bootstrapRows.filter((row) => row.workspace_id === params[0]),
        };
      }

      if (
        normalized.includes("UPDATE certops_agent_bootstrap_tokens") &&
        normalized.includes("SET status = 'revoked'")
      ) {
        const row = bootstrapRows.find(
          (item) => item.workspace_id === params[0] && item.id === params[1],
        );
        if (!row || row.status !== "active") return { rows: [] };
        row.status = "revoked";
        row.revoked_at = new Date("2026-07-01T00:01:00.000Z");
        row.revoked_by = params[2] || null;
        row.updated_at = new Date("2026-07-01T00:01:00.000Z");
        return { rows: [row] };
      }

      if (
        normalized.includes("FROM certops_agents") &&
        normalized.includes("WHERE workspace_id = $1") &&
        normalized.includes("AND id = $2")
      ) {
        return {
          rows: agentRows.filter(
            (row) => row.workspace_id === params[0] && row.id === params[1],
          ),
        };
      }

      if (
        normalized.includes("FROM certops_agents") &&
        normalized.includes("ORDER BY created_at DESC")
      ) {
        return {
          rows: agentRows.filter((row) => row.workspace_id === params[0]),
        };
      }

      if (normalized.includes("SELECT COUNT(*)::int AS leased_jobs")) {
        const leased = jobLeases.filter(
          (job) =>
            job.claimed_by_agent_id === params[0] &&
            ["claimed", "running"].includes(job.status) &&
            job.lease_expires_at instanceof Date &&
            job.lease_expires_at.getTime() > Date.now(),
        );
        return { rows: [{ leased_jobs: leased.length }] };
      }

      if (
        normalized.includes("UPDATE certops_agents") &&
        normalized.includes("SET status = 'retired'")
      ) {
        const row = agentRows.find(
          (item) => item.workspace_id === params[0] && item.id === params[1],
        );
        if (!row || row.status === "retired") return { rows: [] };
        row.status = "retired";
        row.retired_at = new Date("2026-07-02T00:00:00.000Z");
        row.retired_by_user_id = params[2] || null;
        row.retire_reason = params[3] || null;
        row.updated_at = new Date("2026-07-02T00:00:00.000Z");
        return { rows: [row] };
      }

      throw new Error(`Unexpected query: ${normalized}`);
    },
    release() {},
  };
  return db;
}

function agentRow(overrides = {}) {
  return {
    id: AGENT_ROW_ID,
    workspace_id: WORKSPACE_A,
    agent_id: "agent-host-1",
    name: "edge agent",
    hostname: "edge-1.internal",
    platform: "linux",
    agent_version: "1.2.3",
    protocol_version: "1.0.0",
    credential_prefix: "ttagent_0123456789abcdef",
    credential_hash: "a".repeat(64),
    status: "active",
    last_seen_at: new Date("2026-07-01T12:00:00.000Z"),
    clock_offset_ms: 25,
    created_at: new Date("2026-06-01T00:00:00.000Z"),
    retired_at: null,
    retired_by_user_id: null,
    retire_reason: null,
    updated_at: new Date("2026-06-01T00:00:00.000Z"),
    ...overrides,
  };
}

function responseRecorder() {
  return {
    statusCode: 200,
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

function findRouteHandler(method, routePath) {
  const layer = certOpsRouter.stack.find(
    (item) =>
      item.route &&
      item.route.path === routePath &&
      item.route.methods[method],
  );
  assert.ok(layer, `${method.toUpperCase()} ${routePath} route not registered`);
  const stack = layer.route.stack;
  return stack[stack.length - 1].handle;
}

async function invokeRoute(method, routePath, { body = {}, params = {} } = {}) {
  const handler = findRouteHandler(method, routePath);
  const req = {
    workspace: { id: WORKSPACE_A },
    user: { id: 42 },
    authz: { workspaceRole: "workspace_manager" },
    body,
    params,
  };
  const res = responseRecorder();
  await handler(req, res);
  return res;
}

let db;

// Route handlers reach the DB through the shared pool; point both the
// direct-query and transaction paths at the in-memory fake.
beforeEach(() => {
  db = createMemoryDb();
  pool.query = (...args) => db.query(...args);
  pool.connect = async () => db;
});

describe("CertOps agent bootstrap token routes", () => {
  it("create returns 201 with metadata, the raw token exactly once, and audits", async () => {
    const res = await invokeRoute(
      "post",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
      {
        body: {
          name: "rack-42 onboarding",
          expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        },
      },
    );

    assert.equal(res.statusCode, 201);
    assert.match(res.body.plaintextToken, /^ttboot_[a-f0-9]{16}_[a-f0-9]{64}$/);
    assert.equal(res.body.token.name, "rack-42 onboarding");
    assert.equal(res.body.token.status, "active");
    // Metadata must expose only the prefix, never the hash or raw secret.
    assert.equal(res.body.token.tokenHash, undefined);
    assert.equal(
      JSON.stringify(res.body.token).includes(res.body.plaintextToken),
      false,
    );

    assert.equal(db.auditEvents.length, 1);
    const audit = db.auditEvents[0];
    assert.equal(audit.action, "CERTOPS_AGENT_BOOTSTRAP_TOKEN_CREATED");
    assert.equal(audit.targetType, "certops_agent_bootstrap_token");
    assert.equal(audit.actorUserId, 42);
    assert.equal(audit.workspaceId, WORKSPACE_A);
    assert.equal(audit.metadata.name, "rack-42 onboarding");
    assert.ok(audit.metadata.token_prefix.startsWith("ttboot_"));
    assert.equal(audit.metadata.token_hash, undefined);
  });

  it("create rejects invalid expiry via the service validation", async () => {
    const res = await invokeRoute(
      "post",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
      { body: { name: "bad", expiresAt: "not-a-date" } },
    );
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.code, "CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID");
    assert.equal(db.auditEvents.length, 0);
  });

  it("list returns metadata without hashes or raw tokens", async () => {
    await invokeRoute(
      "post",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
      {
        body: {
          name: "listed token",
          expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        },
      },
    );

    const res = await invokeRoute(
      "get",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
    );

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.items.length, 1);
    const item = res.body.items[0];
    assert.equal(item.name, "listed token");
    assert.ok(item.tokenPrefix.startsWith("ttboot_"));
    const serialized = JSON.stringify(res.body);
    assert.doesNotMatch(serialized, /token_hash|tokenHash/);
    assert.doesNotMatch(serialized, /ttboot_[a-f0-9]{16}_[a-f0-9]{64}/);
  });

  it("revoke marks the token revoked and writes a revocation audit", async () => {
    const created = await invokeRoute(
      "post",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
      {
        body: {
          name: "revocable",
          expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        },
      },
    );
    db.auditEvents.length = 0;

    const res = await invokeRoute(
      "post",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens/:tokenId/revoke",
      { params: { tokenId: created.body.token.id } },
    );

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.token.status, "revoked");
    assert.equal(db.auditEvents.length, 1);
    assert.equal(
      db.auditEvents[0].action,
      "CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED",
    );
    assert.ok(db.auditEvents[0].metadata.revoked_at);

    // Second revoke is a no-op read of current state: no duplicate audit.
    const again = await invokeRoute(
      "post",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens/:tokenId/revoke",
      { params: { tokenId: created.body.token.id } },
    );
    assert.equal(again.statusCode, 200);
    assert.equal(again.body.token.status, "revoked");
    assert.equal(db.auditEvents.length, 1);
  });

  it("revoke returns 404 for unknown token and 400 for malformed id", async () => {
    const missing = await invokeRoute(
      "post",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens/:tokenId/revoke",
      { params: { tokenId: BOOT_TOKEN_ID } },
    );
    assert.equal(missing.statusCode, 404);
    assert.equal(missing.body.code, "CERTOPS_AGENT_BOOTSTRAP_TOKEN_NOT_FOUND");

    const malformed = await invokeRoute(
      "post",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens/:tokenId/revoke",
      { params: { tokenId: "not-a-uuid" } },
    );
    assert.equal(malformed.statusCode, 400);
    assert.equal(malformed.body.code, "CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID");
  });
});

describe("CertOps agents list route", () => {
  it("maps registry columns to the workspace metadata shape", async () => {
    db.agentRows.push(agentRow());

    const res = await invokeRoute(
      "get",
      "/api/v1/workspaces/:id/certops/agents",
    );

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.items.length, 1);
    assert.deepEqual(res.body.items[0], {
      id: AGENT_ROW_ID,
      agentId: "agent-host-1",
      name: "edge agent",
      hostname: "edge-1.internal",
      platform: "linux",
      agentVersion: "1.2.3",
      protocolVersion: "1.0.0",
      status: "active",
      lastSeenAt: "2026-07-01T12:00:00.000Z",
      clockOffsetMs: 25,
      createdAt: "2026-06-01T00:00:00.000Z",
      retiredAt: null,
      retireReason: null,
    });
  });

  it("never exposes credential_prefix or credential_hash", async () => {
    db.agentRows.push(agentRow());

    const res = await invokeRoute(
      "get",
      "/api/v1/workspaces/:id/certops/agents",
    );

    const serialized = JSON.stringify(res.body);
    assert.doesNotMatch(serialized, /credential/i);
    assert.doesNotMatch(serialized, /ttagent_[a-f0-9]{16}/);
    assert.equal(serialized.includes("a".repeat(64)), false);
  });

  it("includes retired agents with their retirement state", async () => {
    db.agentRows.push(
      agentRow({
        status: "retired",
        retired_at: new Date("2026-07-02T00:00:00.000Z"),
        retire_reason: "decommissioned host",
      }),
    );

    const res = await invokeRoute(
      "get",
      "/api/v1/workspaces/:id/certops/agents",
    );
    assert.equal(res.body.items[0].status, "retired");
    assert.equal(res.body.items[0].retiredAt, "2026-07-02T00:00:00.000Z");
    assert.equal(res.body.items[0].retireReason, "decommissioned host");
  });
});

describe("CertOps agent retire route", () => {
  const retirePath = "/api/v1/workspaces/:id/certops/agents/:agentId/retire";

  function leaseJob(overrides = {}) {
    return {
      claimed_by_agent_id: AGENT_ROW_ID,
      status: "claimed",
      lease_expires_at: new Date(Date.now() + 5 * 60 * 1000),
      ...overrides,
    };
  }

  it("blocks non-forced retire with 409 and the leased-job count", async () => {
    db.agentRows.push(agentRow());
    db.jobLeases.push(leaseJob(), leaseJob({ status: "running" }));

    const res = await invokeRoute("post", retirePath, {
      params: { agentId: AGENT_ROW_ID },
      body: {},
    });

    assert.equal(res.statusCode, 409);
    assert.equal(res.body.code, "CERTOPS_AGENT_RETIRE_BLOCKED");
    assert.deepEqual(res.body.dependencies, { leasedJobs: 2 });
    assert.equal(db.agentRows[0].status, "active");
    assert.equal(db.auditEvents.length, 0);
  });

  it("ignores expired leases in the pre-flight count", async () => {
    db.agentRows.push(agentRow());
    db.jobLeases.push(
      leaseJob({ lease_expires_at: new Date(Date.now() - 1000) }),
    );

    const res = await invokeRoute("post", retirePath, {
      params: { agentId: AGENT_ROW_ID },
      body: {},
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.agent.status, "retired");
  });

  it("rejects force without a reason with 400 before mutating", async () => {
    db.agentRows.push(agentRow());
    db.jobLeases.push(leaseJob());

    for (const body of [
      { force: true },
      { force: true, reason: "" },
      { force: true, reason: "   " },
      { force: true, reason: 7 },
      { force: true, reason: "bad\u0000reason" },
      { force: true, reason: "x".repeat(501) },
    ]) {
      const res = await invokeRoute("post", retirePath, {
        params: { agentId: AGENT_ROW_ID },
        body,
      });
      assert.equal(res.statusCode, 400, JSON.stringify(body).slice(0, 60));
      assert.equal(res.body.code, "CERTOPS_AGENT_RETIRE_REASON_INVALID");
    }
    assert.equal(db.agentRows[0].status, "active");
    assert.equal(db.auditEvents.length, 0);
  });

  it("force with reason retires despite leases, audits, and leaves jobs alone", async () => {
    db.agentRows.push(agentRow());
    db.jobLeases.push(leaseJob(), leaseJob({ status: "running" }));

    const res = await invokeRoute("post", retirePath, {
      params: { agentId: AGENT_ROW_ID },
      body: { force: true, reason: "  host compromised  " },
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.agent.status, "retired");
    assert.equal(res.body.agent.retiredAt, "2026-07-02T00:00:00.000Z");
    assert.equal(res.body.agent.retireReason, "host compromised");
    assert.equal(db.agentRows[0].retired_by_user_id, 42);

    assert.equal(db.auditEvents.length, 1);
    const audit = db.auditEvents[0];
    assert.equal(audit.action, "CERTOPS_AGENT_RETIRED");
    assert.equal(audit.targetType, "certops_agent");
    assert.deepEqual(audit.metadata, {
      agentId: "agent-host-1",
      force: true,
      reason: "host compromised",
      leasedJobs: 2,
    });

    // Leased jobs are untouched; the lease reaper worker owns their expiry.
    assert.equal(
      db.jobLeases.every((job) =>
        ["claimed", "running"].includes(job.status),
      ),
      true,
    );
  });

  it("retires without force when no active leases exist and audits", async () => {
    db.agentRows.push(agentRow());

    const res = await invokeRoute("post", retirePath, {
      params: { agentId: AGENT_ROW_ID },
      body: {},
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.agent.status, "retired");
    assert.equal(db.auditEvents.length, 1);
    assert.deepEqual(db.auditEvents[0].metadata, {
      agentId: "agent-host-1",
      force: false,
      reason: null,
      leasedJobs: 0,
    });
  });

  it("is idempotent: re-retire returns current state with no duplicate audit", async () => {
    db.agentRows.push(agentRow());

    const first = await invokeRoute("post", retirePath, {
      params: { agentId: AGENT_ROW_ID },
      body: {},
    });
    assert.equal(first.statusCode, 200);
    assert.equal(db.auditEvents.length, 1);

    const second = await invokeRoute("post", retirePath, {
      params: { agentId: AGENT_ROW_ID },
      body: {},
    });
    assert.equal(second.statusCode, 200);
    assert.equal(second.body.agent.status, "retired");
    assert.equal(second.body.agent.retiredAt, "2026-07-02T00:00:00.000Z");
    assert.equal(db.auditEvents.length, 1);
  });

  it("returns 404 for unknown agents and 400 for malformed ids", async () => {
    const missing = await invokeRoute("post", retirePath, {
      params: { agentId: AGENT_ROW_ID },
      body: {},
    });
    assert.equal(missing.statusCode, 404);
    assert.equal(missing.body.code, "CERTOPS_AGENT_NOT_FOUND");

    const malformed = await invokeRoute("post", retirePath, {
      params: { agentId: "nope" },
      body: {},
    });
    assert.equal(malformed.statusCode, 400);
    assert.equal(malformed.body.code, "CERTOPS_AGENT_INVALID");
  });
});

describe("agentRegistry service internals", () => {
  it("agentMetadataFromRow drops credential fields", () => {
    const metadata = agentRegistry._test.agentMetadataFromRow(agentRow());
    assert.equal("credentialPrefix" in metadata, false);
    assert.equal("credentialHash" in metadata, false);
    assert.doesNotMatch(JSON.stringify(metadata), /credential/i);
  });

  it("normalizeRequiredRetireReason trims and enforces bounds", () => {
    assert.equal(
      agentRegistry._test.normalizeRequiredRetireReason("  ok  "),
      "ok",
    );
    for (const bad of [undefined, null, "", "  ", 5, "x".repeat(501), "a\u0001b"]) {
      assert.throws(
        () => agentRegistry._test.normalizeRequiredRetireReason(bad),
        (err) => err.code === "CERTOPS_AGENT_RETIRE_REASON_INVALID",
      );
    }
  });
});



