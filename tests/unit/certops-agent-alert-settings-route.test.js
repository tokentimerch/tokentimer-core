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

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const AGENT_ROW_ID = "22222222-2222-4222-8222-222222222222";

function createMemoryDb() {
  const agentRows = [
    {
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
      downtime_alerts_enabled: true,
      contact_group_id: null,
      updated_at: new Date("2026-06-01T00:00:00.000Z"),
    },
  ];
  const auditEvents = [];
  const workspaceSettings = {
    contact_groups: [{ id: "g1", email_contact_ids: ["c1"] }],
  };

  const db = {
    agentRows,
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

      if (
        normalized.includes("FROM workspace_settings") &&
        normalized.includes("jsonb_array_elements")
      ) {
        const [, contactGroupId] = params;
        const found = workspaceSettings.contact_groups.some(
          (g) => g.id === contactGroupId,
        );
        const rows = found ? [{ x: 1 }] : [];
        return { rows, rowCount: rows.length };
      }

      if (
        normalized.includes("FROM certops_agents") &&
        normalized.includes("WHERE workspace_id = $1") &&
        normalized.includes("AND id = $2") &&
        !normalized.startsWith("UPDATE")
      ) {
        return {
          rows: agentRows.filter(
            (row) => row.workspace_id === params[0] && row.id === params[1],
          ),
        };
      }

      if (normalized.startsWith("UPDATE certops_agents")) {
        const row = agentRows.find(
          (item) => item.workspace_id === params[0] && item.id === params[1],
        );
        if (!row) return { rows: [] };
        let idx = 2; // params[0]=workspaceId, params[1]=agentId, then in-order set clauses
        if (normalized.includes("downtime_alerts_enabled = $")) {
          row.downtime_alerts_enabled = params[idx];
          idx += 1;
        }
        if (normalized.includes("contact_group_id = $")) {
          row.contact_group_id = params[idx];
          idx += 1;
        }
        row.updated_at = new Date("2026-07-02T00:00:00.000Z");
        return { rows: [row] };
      }

      throw new Error(`Unexpected query: ${normalized}`);
    },
    release() {},
  };
  return db;
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

async function invokeRoute(
  method,
  routePath,
  { body = {}, params = {}, query = {} } = {},
) {
  const handler = findRouteHandler(method, routePath);
  const req = {
    workspace: { id: WORKSPACE_A },
    user: { id: 42 },
    authz: { workspaceRole: "workspace_manager" },
    body,
    params,
    query,
  };
  const res = responseRecorder();
  await handler(req, res);
  return res;
}

let db;

beforeEach(() => {
  db = createMemoryDb();
  pool.query = (...args) => db.query(...args);
  pool.connect = async () => db;
});

const alertSettingsPath =
  "/api/v1/workspaces/:id/certops/agents/:agentId/alert-settings";

describe("CertOps agent alert-settings route", () => {
  it("updates downtimeAlertsEnabled and audits the change", async () => {
    const res = await invokeRoute("patch", alertSettingsPath, {
      params: { agentId: AGENT_ROW_ID },
      body: { downtimeAlertsEnabled: false },
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.agent.downtimeAlertsEnabled, false);
    assert.equal(db.agentRows[0].downtime_alerts_enabled, false);
    assert.equal(db.auditEvents.length, 1);
    assert.equal(
      db.auditEvents[0].action,
      "CERTOPS_AGENT_ALERT_SETTINGS_UPDATED",
    );
  });

  it("updates contactGroupId when it exists in the workspace", async () => {
    const res = await invokeRoute("patch", alertSettingsPath, {
      params: { agentId: AGENT_ROW_ID },
      body: { contactGroupId: "g1" },
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.agent.contactGroupId, "g1");
    assert.equal(db.agentRows[0].contact_group_id, "g1");
  });

  it("clears contactGroupId with null", async () => {
    db.agentRows[0].contact_group_id = "g1";
    const res = await invokeRoute("patch", alertSettingsPath, {
      params: { agentId: AGENT_ROW_ID },
      body: { contactGroupId: null },
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.agent.contactGroupId, null);
  });

  it("rejects a contactGroupId that does not exist in the workspace", async () => {
    const res = await invokeRoute("patch", alertSettingsPath, {
      params: { agentId: AGENT_ROW_ID },
      body: { contactGroupId: "does-not-exist" },
    });

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.code, "CERTOPS_AGENT_CONTACT_GROUP_INVALID");
    assert.equal(db.agentRows[0].contact_group_id, null);
  });

  it("returns 404 for an unknown agent", async () => {
    const res = await invokeRoute("patch", alertSettingsPath, {
      params: { agentId: "99999999-9999-4999-8999-999999999999" },
      body: { downtimeAlertsEnabled: true },
    });

    assert.equal(res.statusCode, 404);
    assert.equal(res.body.code, "CERTOPS_AGENT_NOT_FOUND");
  });

  it("rejects an invalid agentId before touching the DB", async () => {
    const res = await invokeRoute("patch", alertSettingsPath, {
      params: { agentId: "not-a-uuid" },
      body: { downtimeAlertsEnabled: true },
    });

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.code, "CERTOPS_AGENT_INVALID");
  });

  it("rejects an empty body with neither field supplied", async () => {
    const res = await invokeRoute("patch", alertSettingsPath, {
      params: { agentId: AGENT_ROW_ID },
      body: {},
    });

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.code, "CERTOPS_AGENT_ALERT_SETTINGS_EMPTY");
  });

  it("allows updating both fields together", async () => {
    const res = await invokeRoute("patch", alertSettingsPath, {
      params: { agentId: AGENT_ROW_ID },
      body: { downtimeAlertsEnabled: true, contactGroupId: "g1" },
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.agent.downtimeAlertsEnabled, true);
    assert.equal(res.body.agent.contactGroupId, "g1");
  });
});
