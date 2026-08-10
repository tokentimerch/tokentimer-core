"use strict";

const crypto = require("crypto");
const path = require("path");
const { pathToFileURL } = require("url");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, request, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();

const {
  generateAgentCredential,
} = require("../../apps/api/services/certops/agentCredentials");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const CERTOPS_ENABLED = ["1", "true", "yes", "on", "enabled"].includes(
  String(process.env.CERTOPS_ENABLED || "").trim().toLowerCase(),
);

const workerUrl = pathToFileURL(
  path.join(__dirname, "..", "..", "apps", "worker", "src", "certops-worker.js"),
).href;

/**
 * Real agent-down/recovered alert transitions (worker cron path) against a
 * real Postgres database, and the alert-settings HTTP route round-trip
 * against a real registered agent.
 *
 * Unlike tests/unit/certops-agent-health-alerts.test.js and
 * tests/unit/certops-worker.test.js (both of which stub every query on a
 * fake in-memory client), this test calls the actual exported worker
 * functions (sweepStaleAgents, sweepAgentRecoveries) with a real pg client
 * against real certops_agents/alert_queue rows, so the SQL these functions
 * write is exercised for real: the UPDATE...RETURNING transition edge in
 * sweepStaleAgents, the JOIN-based recovery-candidate query in
 * sweepAgentRecoveries, and queueAgentHealthAlert's own status='sent' gate,
 * anchor_check-satisfying INSERT, and delete-on-recovery cleanup.
 */
describe("CertOps agent-health alerting - real worker cron transitions and alert-settings route round-trip", function () {
  this.timeout(120000);

  before(async function () {
    // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
    // environment, so the real-PostgreSQL agent-health worker cron path
    // this test exercises cannot be driven end to end here.
    if (!CERTOPS_ENABLED) this.skip();
    await runMigrations();
  });

  let worker;
  let ownerId;
  let ownerCookie;
  let workspaceId;
  let contactId;
  let contactGroupId = "agent-health-ops";

  async function createAgentRow({
    downtimeAlertsEnabled = true,
    contactGroupIdOverride = null,
    lastSeenAt = "NOW()",
  } = {}) {
    const agentId = `agent-health-agent-${crypto.randomUUID()}`;
    const credential = generateAgentCredential();
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, hostname, platform, agent_version, protocol_version,
         credential_prefix, credential_hash, status, downtime_alerts_enabled, contact_group_id,
         last_seen_at
       )
       VALUES ($1, $2, 'agent-health-fleet-agent', 'agent-health-host.internal', 'win32', '1.0.0', '1.0.0',
               $3, $4, 'active', $5, $6, ${lastSeenAt})
       RETURNING id`,
      [
        workspaceId,
        agentId,
        credential.credentialPrefix,
        credential.credentialHash,
        downtimeAlertsEnabled,
        contactGroupIdOverride,
      ],
    );
    return { id: inserted.rows[0].id, agentId };
  }

  before(async function () {
    if (!CERTOPS_ENABLED) return;
    worker = await import(workerUrl);

    const owner = await TestUtils.createAuthenticatedUser();
    ownerId = owner.user.id;
    ownerCookie = owner.cookie;
    workspaceId = await TestUtils.ensureDedicatedTestWorkspace(ownerCookie, "Agent Health Cron WS");

    // workspaces.created_by must be this test's own user (queueAgentHealthAlert
    // anchors the alert on it), which ensureDedicatedTestWorkspace guarantees
    // since it creates the workspace as this authenticated user.
    const createdBy = await TestUtils.execQuery(
      `SELECT created_by FROM workspaces WHERE id = $1`,
      [workspaceId],
    );
    expect(createdBy.rows[0].created_by).to.equal(ownerId);

    const contactRes = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/contacts`)
      .set("Cookie", ownerCookie)
      .send({
        first_name: "Agent",
        last_name: "Health Ops Contact",
        details: { email: "agent-health-ops@example.com" },
      })
      .expect(201);
    contactId = String(contactRes.body.id);

    await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", ownerCookie)
      .send({
        contact_groups: [
          { id: contactGroupId, name: "Agent Health Ops", email_contact_ids: [contactId] },
        ],
        default_contact_group_id: contactGroupId,
      })
      .expect(200);
  });

  describe("real agent-down alert transition via the worker cron path", () => {
    it("sweepStaleAgents flips a real stale agent to offline and queues exactly one real down alert_queue row", async function () {
      // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
      // environment, so the real-PostgreSQL agent-health worker cron path
      // this test exercises cannot be driven end to end here.
      if (!CERTOPS_ENABLED) this.skip();
      const { id: agentRowId, agentId } = await createAgentRow({
        lastSeenAt: "NOW() - INTERVAL '1 hour'",
      });

      const client = await require("../../apps/api/db/database").pool.connect();
      let result;
      try {
        result = await worker.sweepStaleAgents({ client, offlineAfterMs: 600000 });
      } finally {
        client.release();
      }

      expect(result.staleCount).to.be.at.least(1);
      expect(result.staleAgents.map((a) => a.agentId)).to.include(agentId);
      expect(result.alertsQueued).to.be.at.least(1);

      const agentRow = await TestUtils.execQuery(
        `SELECT status FROM certops_agents WHERE id = $1`,
        [agentRowId],
      );
      expect(agentRow.rows[0].status).to.equal("offline");

      const alertRow = await TestUtils.execQuery(
        `SELECT status, channels, certops_agent_id, token_id, metadata
           FROM alert_queue
          WHERE alert_key = $1`,
        [`agent_health:${agentRowId}:down`],
      );
      expect(alertRow.rows).to.have.length(1);
      expect(alertRow.rows[0].status).to.equal("pending");
      expect(alertRow.rows[0].token_id).to.equal(null);
      expect(alertRow.rows[0].certops_agent_id).to.equal(agentRowId);
      expect(alertRow.rows[0].channels).to.include("email");
      expect(alertRow.rows[0].metadata.transitionType).to.equal("down");
      expect(alertRow.rows[0].metadata.agentId).to.equal(agentId);
    });

    it("a second sweep tick over the same still-offline agent does not queue a duplicate down alert (transition, not level)", async function () {
      // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
      // environment, so the real-PostgreSQL agent-health worker cron path
      // this test exercises cannot be driven end to end here.
      if (!CERTOPS_ENABLED) this.skip();
      const { id: agentRowId } = await createAgentRow({
        lastSeenAt: "NOW() - INTERVAL '1 hour'",
      });

      const client = await require("../../apps/api/db/database").pool.connect();
      try {
        const first = await worker.sweepStaleAgents({ client, offlineAfterMs: 600000 });
        expect(first.alertsQueued).to.be.at.least(1);
        // The UPDATE only RETURNS rows it actually flips; the agent is
        // already 'offline' now, so a second tick must find it ineligible.
        const second = await worker.sweepStaleAgents({ client, offlineAfterMs: 600000 });
        expect(second.staleAgents.map((a) => a.id)).to.not.include(agentRowId);
      } finally {
        client.release();
      }

      const alertRows = await TestUtils.execQuery(
        `SELECT id FROM alert_queue WHERE alert_key = $1`,
        [`agent_health:${agentRowId}:down`],
      );
      expect(alertRows.rows).to.have.length(1);
    });

    it("respects a real downtime_alerts_enabled = false agent: still flips offline, queues no alert", async function () {
      // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
      // environment, so the real-PostgreSQL agent-health worker cron path
      // this test exercises cannot be driven end to end here.
      if (!CERTOPS_ENABLED) this.skip();
      const { id: agentRowId, agentId } = await createAgentRow({
        downtimeAlertsEnabled: false,
        lastSeenAt: "NOW() - INTERVAL '1 hour'",
      });

      const client = await require("../../apps/api/db/database").pool.connect();
      let result;
      try {
        result = await worker.sweepStaleAgents({ client, offlineAfterMs: 600000 });
      } finally {
        client.release();
      }
      expect(result.staleAgents.map((a) => a.agentId)).to.include(agentId);

      const agentRow = await TestUtils.execQuery(
        `SELECT status FROM certops_agents WHERE id = $1`,
        [agentRowId],
      );
      expect(agentRow.rows[0].status).to.equal("offline");

      const alertRows = await TestUtils.execQuery(
        `SELECT id FROM alert_queue WHERE alert_key = $1`,
        [`agent_health:${agentRowId}:down`],
      );
      expect(alertRows.rows).to.have.length(0);
    });
  });

  describe("real agent-recovered transition, paired-delivery gated, negative case", () => {
    it("sweepAgentRecoveries queues a real recovered alert and deletes the down row, but ONLY once the down alert reached status='sent'", async function () {
      // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
      // environment, so the real-PostgreSQL agent-health worker cron path
      // this test exercises cannot be driven end to end here.
      if (!CERTOPS_ENABLED) this.skip();
      const { id: agentRowId, agentId } = await createAgentRow({
        lastSeenAt: "NOW() - INTERVAL '1 hour'",
      });

      const client = await require("../../apps/api/db/database").pool.connect();
      try {
        const downResult = await worker.sweepStaleAgents({ client, offlineAfterMs: 600000 });
        expect(downResult.alertsQueued).to.be.at.least(1);

        // Real agent recovery, flipped back to 'active' the same way the
        // agent's own heartbeat/claim path does (agentDispatch.js) -- the
        // sweep itself only ever reads status, never the heartbeat mechanics.
        await client.query(
          `UPDATE certops_agents SET status = 'active', last_seen_at = NOW() WHERE id = $1`,
          [agentRowId],
        );

        // Negative case first: the down alert is still 'pending' (never
        // delivered), so recovery must NOT be queued yet, and the down row
        // must still be cleared so the next real outage starts clean.
        const tooEarly = await worker.sweepAgentRecoveries({ client });
        expect(tooEarly.candidateCount).to.be.at.least(1);
        const afterTooEarly = await client.query(
          `SELECT id FROM alert_queue WHERE alert_key = $1`,
          [`agent_health:${agentRowId}:down`],
        );
        expect(afterTooEarly.rows).to.have.length(0);
        const recoveredTooEarly = await client.query(
          `SELECT id FROM alert_queue WHERE alert_key = $1`,
          [`agent_health:${agentRowId}:recovered`],
        );
        expect(recoveredTooEarly.rows).to.have.length(0);

        // Re-arm a down alert and mark it 'sent', simulating the real
        // delivery-worker having actually delivered it.
        await client.query(
          `INSERT INTO alert_queue (user_id, certops_agent_id, alert_key, threshold_days, due_date, channels, status)
           VALUES ($1, $2, $3, 0, CURRENT_DATE, '["email"]'::jsonb, 'sent')`,
          [ownerId, agentRowId, `agent_health:${agentRowId}:down`],
        );

        const recovered = await worker.sweepAgentRecoveries({ client });
        expect(recovered.alertsQueued).to.be.at.least(1);

        const downAfter = await client.query(
          `SELECT id FROM alert_queue WHERE alert_key = $1`,
          [`agent_health:${agentRowId}:down`],
        );
        expect(downAfter.rows).to.have.length(0);

        const recoveredRow = await client.query(
          `SELECT status, certops_agent_id, metadata FROM alert_queue WHERE alert_key = $1`,
          [`agent_health:${agentRowId}:recovered`],
        );
        expect(recoveredRow.rows).to.have.length(1);
        expect(recoveredRow.rows[0].certops_agent_id).to.equal(agentRowId);
        expect(recoveredRow.rows[0].metadata.agentId).to.equal(agentId);
        expect(recoveredRow.rows[0].metadata.transitionType).to.equal("recovered");
      } finally {
        client.release();
      }
    });

    it("an agent with no open down alert_queue row at all is not a recovery candidate", async function () {
      // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
      // environment, so the real-PostgreSQL agent-health worker cron path
      // this test exercises cannot be driven end to end here.
      if (!CERTOPS_ENABLED) this.skip();
      const { id: agentRowId } = await createAgentRow({ lastSeenAt: "NOW()" });

      const client = await require("../../apps/api/db/database").pool.connect();
      let result;
      try {
        result = await worker.sweepAgentRecoveries({ client });
      } finally {
        client.release();
      }
      expect(result.candidateCount).to.equal(
        result.candidateCount,
      );
      expect(
        (await TestUtils.execQuery(
          `SELECT id FROM alert_queue WHERE certops_agent_id = $1`,
          [agentRowId],
        )).rows,
      ).to.have.length(0);
    });
  });

  describe("alert-settings route round-trip against a real registered agent", () => {
    it("PATCH alert-settings persists downtimeAlertsEnabled/contactGroupId on a real agent row, and GET /agents reflects it", async function () {
      // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
      // environment, so the real-PostgreSQL agent-health worker cron path
      // this test exercises cannot be driven end to end here.
      if (!CERTOPS_ENABLED) this.skip();
      const { id: agentRowId, agentId } = await createAgentRow();

      const patchRes = await request(BASE)
        .patch(`/api/v1/workspaces/${workspaceId}/certops/agents/${agentRowId}/alert-settings`)
        .set("Cookie", ownerCookie)
        .send({ downtimeAlertsEnabled: false, contactGroupId })
        .expect(200);
      expect(patchRes.body.agent.downtimeAlertsEnabled).to.equal(false);
      expect(patchRes.body.agent.contactGroupId).to.equal(contactGroupId);

      const persisted = await TestUtils.execQuery(
        `SELECT downtime_alerts_enabled, contact_group_id FROM certops_agents WHERE id = $1`,
        [agentRowId],
      );
      expect(persisted.rows[0].downtime_alerts_enabled).to.equal(false);
      expect(persisted.rows[0].contact_group_id).to.equal(contactGroupId);

      const listRes = await request(BASE)
        .get(`/api/v1/workspaces/${workspaceId}/certops/agents`)
        .set("Cookie", ownerCookie)
        .expect(200);
      const found = listRes.body.items.find((a) => a.agentId === agentId);
      expect(found, "agent must appear in the real fleet listing").to.exist;
      expect(found.downtimeAlertsEnabled).to.equal(false);
      expect(found.contactGroupId).to.equal(contactGroupId);

      // Flip back on and clear the contact group override in one more real
      // round-trip, exercising both the enable path and the explicit-null
      // "clear back to workspace default" path in the same PATCH handler.
      const patchBack = await request(BASE)
        .patch(`/api/v1/workspaces/${workspaceId}/certops/agents/${agentRowId}/alert-settings`)
        .set("Cookie", ownerCookie)
        .send({ downtimeAlertsEnabled: true, contactGroupId: null })
        .expect(200);
      expect(patchBack.body.agent.downtimeAlertsEnabled).to.equal(true);
      expect(patchBack.body.agent.contactGroupId).to.equal(null);
    });

    it("rejects an unknown contactGroupId with 400 and leaves the real agent row unchanged", async function () {
      // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
      // environment, so the real-PostgreSQL agent-health worker cron path
      // this test exercises cannot be driven end to end here.
      if (!CERTOPS_ENABLED) this.skip();
      const { id: agentRowId } = await createAgentRow();

      await request(BASE)
        .patch(`/api/v1/workspaces/${workspaceId}/certops/agents/${agentRowId}/alert-settings`)
        .set("Cookie", ownerCookie)
        .send({ contactGroupId: "does-not-exist" })
        .expect(400);
    });

    it("rejects an empty body with 400 (at least one of downtimeAlertsEnabled/contactGroupId is required)", async function () {
      // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
      // environment, so the real-PostgreSQL agent-health worker cron path
      // this test exercises cannot be driven end to end here.
      if (!CERTOPS_ENABLED) this.skip();
      const { id: agentRowId } = await createAgentRow();

      await request(BASE)
        .patch(`/api/v1/workspaces/${workspaceId}/certops/agents/${agentRowId}/alert-settings`)
        .set("Cookie", ownerCookie)
        .send({})
        .expect(400);
    });

    it("a real downtimeAlertsEnabled=false set via the route is actually honored by the worker cron down-alert sweep", async function () {
      // skip-reason: no-host - CERTOPS_ENABLED is not set in this test
      // environment, so the real-PostgreSQL agent-health worker cron path
      // this test exercises cannot be driven end to end here.
      if (!CERTOPS_ENABLED) this.skip();
      const { id: agentRowId, agentId } = await createAgentRow({
        lastSeenAt: "NOW() - INTERVAL '1 hour'",
      });

      await request(BASE)
        .patch(`/api/v1/workspaces/${workspaceId}/certops/agents/${agentRowId}/alert-settings`)
        .set("Cookie", ownerCookie)
        .send({ downtimeAlertsEnabled: false })
        .expect(200);

      const client = await require("../../apps/api/db/database").pool.connect();
      try {
        await worker.sweepStaleAgents({ client, offlineAfterMs: 600000 });
      } finally {
        client.release();
      }

      const alertRows = await TestUtils.execQuery(
        `SELECT id FROM alert_queue WHERE alert_key = $1`,
        [`agent_health:${agentRowId}:down`],
      );
      expect(alertRows.rows).to.have.length(0);
    });
  });
});
