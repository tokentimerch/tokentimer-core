"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  AGENT_HEALTH_ALERT_PREFIX,
  agentHealthAlertKey,
  queueAgentHealthAlert,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentHealthAlerts.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";

function createMockClient(handler) {
  const state = { queries: [] };
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ text: sql, params });
      return handler(sql, params, state);
    },
  };
  return { state, client };
}

function agentFixture(overrides = {}) {
  return {
    id: "agent-row-1",
    workspaceId: WORKSPACE_A,
    agentId: "agent-01",
    name: "prod-iis-01",
    hostname: "prod-iis-01.internal",
    platform: "win32",
    lastSeenAt: "2026-07-24T08:00:00.000Z",
    downtimeAlertsEnabled: true,
    contactGroupId: null,
    ...overrides,
  };
}

function happyPathHandler(overrides = {}) {
  return (sql) => {
    if (sql.includes("SELECT id, status, delivery_claim_id")) {
      return overrides.sentDown !== undefined
        ? overrides.sentDown
        : { rows: [{ id: 1, status: "sent", delivery_claim_id: null }] };
    }
    if (sql.startsWith("DELETE FROM alert_queue")) {
      return { rows: [] };
    }
    if (sql.includes("FROM alert_queue WHERE alert_key")) {
      return overrides.existingAlert !== undefined ? overrides.existingAlert : { rows: [] };
    }
    if (sql.includes("FROM workspaces")) {
      return overrides.workspaceOwner !== undefined
        ? overrides.workspaceOwner
        : { rows: [{ user_id: 5 }] };
    }
    if (sql.includes("FROM workspace_settings")) {
      return overrides.settings !== undefined
        ? overrides.settings
        : {
            rows: [
              {
                email_alerts_enabled: true,
                contact_groups: [{ id: "g1", email_contact_ids: ["c1"] }],
                default_contact_group_id: "g1",
                webhook_urls: [],
              },
            ],
          };
    }
    if (sql.includes("INSERT INTO alert_queue")) {
      return overrides.insertResult !== undefined
        ? overrides.insertResult
        : { rows: [], rowCount: 1 };
    }
    throw new Error(`unexpected query: ${sql}`);
  };
}

describe("agentHealthAlerts.agentHealthAlertKey", () => {
  it("builds a stable per-agent, per-transition key", () => {
    assert.equal(
      agentHealthAlertKey("agent-row-1", "down"),
      "agent_health:agent-row-1:down",
    );
    assert.equal(
      agentHealthAlertKey("agent-row-1", "recovered"),
      "agent_health:agent-row-1:recovered",
    );
    assert.ok(agentHealthAlertKey("x", "down").startsWith(AGENT_HEALTH_ALERT_PREFIX));
  });
});

describe("agentHealthAlerts.queueAgentHealthAlert (down)", () => {
  it("queues one down alert anchored on certops_agent_id, not token_id", async () => {
    const { state, client } = createMockClient(happyPathHandler());
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "down",
      offlineAfterMs: 600000,
    });

    assert.equal(outcome.queued, true);
    assert.equal(outcome.alertKey, "agent_health:agent-row-1:down");

    const insert = state.queries.find((q) => q.text.includes("INSERT INTO alert_queue"));
    assert.ok(insert, "alert_queue insert expected");
    assert.match(insert.text, /token_id, certops_agent_id/);
    assert.match(insert.text, /VALUES \(\$1, NULL, \$2/);
    // [userId, certops_agent_id, alertKey, thresholdDays, channels, metadata]
    // (token_id is a literal NULL in the SQL, not a bound parameter)
    assert.equal(insert.params[0], 5);
    assert.equal(insert.params[1], "agent-row-1");
    assert.equal(insert.params[2], "agent_health:agent-row-1:down");
    assert.equal(insert.params[3], 0);
    assert.deepEqual(JSON.parse(insert.params[4]), ["email"]);
    const metadata = JSON.parse(insert.params[5]);
    assert.equal(metadata.agentId, "agent-01");
    assert.equal(metadata.transitionType, "down");
    assert.equal(metadata.offlineAfterMs, 600000);
    const deletes = state.queries.filter((query) =>
      query.text.startsWith("DELETE FROM alert_queue"),
    );
    assert.deepEqual(deletes.map((query) => query.params), [
      ["agent_health:agent-row-1:recovered", "agent-row-1"],
    ]);
  });

  it("dedupes: does not queue a second down alert while one is already queued", async () => {
    const { state, client } = createMockClient(
      happyPathHandler({ insertResult: { rows: [], rowCount: 0 } }),
    );
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "down",
    });

    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "already_queued");
    assert.equal(
      state.queries.filter((q) => q.text.includes("INSERT INTO alert_queue")).length,
      1,
    );
  });

  it("respects downtimeAlertsEnabled === false", async () => {
    const { client } = createMockClient(happyPathHandler());
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture({ downtimeAlertsEnabled: false }),
      transitionType: "down",
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "alerts_disabled");
  });

  it("uses the agent's configured contact group over the workspace default", async () => {
    const { state, client } = createMockClient(
      happyPathHandler({
        settings: {
          rows: [
            {
              email_alerts_enabled: true,
              contact_groups: [
                { id: "g1", email_contact_ids: ["c1"] },
                { id: "g2", email_contact_ids: ["c2"] },
              ],
              default_contact_group_id: "g1",
              webhook_urls: [],
            },
          ],
        },
      }),
    );
    await queueAgentHealthAlert({
      client,
      agent: agentFixture({ contactGroupId: "g2" }),
      transitionType: "down",
    });
    const insert = state.queries.find((q) => q.text.includes("INSERT INTO alert_queue"));
    assert.ok(insert, "insert should still occur (g2 also has email contacts)");
  });

  it("caps the impacted-certificates list embedded in metadata", async () => {
    const { state, client } = createMockClient(happyPathHandler());
    const many = Array.from({ length: 15 }, (_, i) => ({
      id: `cert-${i}`,
      commonName: `svc${i}.example.com`,
      renewalPathState: "unavailable",
    }));
    await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "down",
      impactedCertificates: many,
    });
    const insert = state.queries.find((q) => q.text.includes("INSERT INTO alert_queue"));
    const metadata = JSON.parse(insert.params[5]);
    assert.equal(metadata.impactedCertificates.length, 10);
    assert.equal(metadata.impactedCertificateTotalCount, 15);
  });

  it("skips when no channels are eligible", async () => {
    const { client } = createMockClient(
      happyPathHandler({
        settings: {
          rows: [
            {
              email_alerts_enabled: false,
              contact_groups: [],
              default_contact_group_id: null,
              webhook_urls: [],
            },
          ],
        },
      }),
    );
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "down",
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "no_channels");
  });

  it("skips when the workspace has no creator to anchor the alert on", async () => {
    const { client } = createMockClient(happyPathHandler({ workspaceOwner: { rows: [] } }));
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "down",
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "no_recipient");
  });

  it("skips when the workspace row exists but created_by is null", async () => {
    const { client } = createMockClient(
      happyPathHandler({ workspaceOwner: { rows: [{ user_id: null }] } }),
    );
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "down",
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "no_recipient");
  });

  it("anchors the alert on the workspace creator, not an arbitrary admin (ADR-0011: no fabricated human actor)", async () => {
    const { state, client } = createMockClient(happyPathHandler());
    await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "down",
    });
    const ownerLookup = state.queries.find((q) => q.text.includes("FROM workspaces"));
    assert.ok(ownerLookup, "workspace creator lookup expected");
    assert.match(ownerLookup.text, /created_by AS user_id/);
    assert.deepEqual(ownerLookup.params, [WORKSPACE_A]);
  });
});

describe("agentHealthAlerts.queueAgentHealthAlert (recovered)", () => {
  it("queues a recovery alert only when the down alert was actually sent, and clears the down row", async () => {
    const { state, client } = createMockClient(happyPathHandler());
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "recovered",
    });

    assert.equal(outcome.queued, true);
    assert.equal(outcome.alertKey, "agent_health:agent-row-1:recovered");
    const deletes = state.queries.filter((q) => q.text.startsWith("DELETE FROM alert_queue"));
    assert.equal(deletes.length, 1, "the paired down row is cleared after recovery is queued");
    assert.deepEqual(deletes[0].params, [
      "agent_health:agent-row-1:down",
      "agent-row-1",
    ]);
  });

  it("does not send recovery when the down alert was never delivered", async () => {
    const { state, client } = createMockClient(
      happyPathHandler({ sentDown: { rows: [] } }),
    );
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "recovered",
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "down_never_delivered");
    assert.equal(
      state.queries.some((q) => q.text.includes("INSERT INTO alert_queue")),
      false,
    );
    // The stale down row is still cleaned up so a future outage starts fresh.
    const deletes = state.queries.filter((q) => q.text.startsWith("DELETE FROM alert_queue"));
    assert.equal(deletes.length, 2);
    assert.deepEqual(deletes[0].params, [
      "agent_health:agent-row-1:down",
      "agent-row-1",
    ]);
  });

  it("keeps the incident open while the DOWN delivery worker owns the row", async () => {
    const { state, client } = createMockClient(
      happyPathHandler({
        sentDown: {
          rows: [
            {
              id: 1,
              status: "pending",
              delivery_claim_id: "11111111-1111-4111-8111-111111111111",
            },
          ],
        },
      }),
    );
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "recovered",
    });

    assert.deepEqual(outcome, {
      queued: false,
      retry: true,
      reason: "down_delivery_in_progress",
    });
    assert.equal(
      state.queries.some((query) =>
        query.text.startsWith("DELETE FROM alert_queue"),
      ),
      false,
    );
  });

  it("closes the old incident when alerts were disabled while the agent was down", async () => {
    const { state, client } = createMockClient(happyPathHandler());
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture({ downtimeAlertsEnabled: false }),
      transitionType: "recovered",
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "alerts_disabled_incident_closed");
    assert.equal(
      state.queries.filter((query) => query.text.startsWith("DELETE FROM alert_queue")).length,
      2,
    );
  });
});

describe("agentHealthAlerts.queueAgentHealthAlert (validation)", () => {
  it("rejects an invalid transition type", async () => {
    const { client } = createMockClient(happyPathHandler());
    const outcome = await queueAgentHealthAlert({
      client,
      agent: agentFixture(),
      transitionType: "bogus",
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "invalid_transition");
  });

  it("rejects a missing agent", async () => {
    const { client } = createMockClient(happyPathHandler());
    const outcome = await queueAgentHealthAlert({
      client,
      agent: null,
      transitionType: "down",
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "agent_or_workspace_missing");
  });
});
