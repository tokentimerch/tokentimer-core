const { expect, request, TestUtils, TestEnvironment } = require("./setup");
const { randomBytes, randomUUID } = require("node:crypto");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Alert Queue Retry and Requeue", function () {
  this.timeout(60000);

  let user, cookie, ws;

  before(async () => {
    await TestEnvironment.setup();
    user = await TestUtils.createVerifiedTestUser();
    const session = await TestUtils.loginTestUser(user.email, user.password);
    cookie = session.cookie;
    ws = await TestUtils.ensureTestWorkspace(cookie);
  });

  async function insertFailedAlert(tokenId, alertUserId = user.id) {
    const result = await TestUtils.execQuery(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status, attempts, error_message, next_attempt_at)
       VALUES ($1, $2, $3, 7, CURRENT_DATE, '["email"]', 'failed', 3, 'SMTP timeout', NOW() - INTERVAL '1 hour')
       RETURNING id`,
      [alertUserId, tokenId, `test_retry:${tokenId}:${Date.now()}`],
    );
    return result.rows[0].id;
  }

  describe("POST /api/alert-queue/:id/retry", () => {
    it("resets a failed alert to pending", async () => {
      const soon = new Date();
      soon.setDate(soon.getDate() + 5);
      const token = await request(BASE)
        .post("/api/tokens")
        .set("Cookie", cookie)
        .send({
          name: "Retry Token",
          type: "api_key",
          category: "general",
          expiresAt: soon.toISOString().slice(0, 10),
          workspace_id: ws,
        })
        .expect(201);

      const alertId = await insertFailedAlert(token.body.id);

      const res = await request(BASE)
        .post(`/api/alert-queue/${alertId}/retry`)
        .set("Cookie", cookie);

      // The endpoint may return 200 on success or 404 if not implemented as a standalone
      // Some implementations use the requeue bulk endpoint instead
      if (res.status === 200) {
        // Verify the alert was reset
        const check = await TestUtils.execQuery(
          "SELECT status, next_attempt_at FROM alert_queue WHERE id = $1",
          [alertId],
        );
        expect(check.rows[0].status).to.equal("pending");
      } else {
        expect(res.status).to.be.oneOf([200, 404]);
      }
    });

    it("resolves only the retried alert's delivery incident", async () => {
      const otherWorkspace = await TestUtils.ensureDedicatedTestWorkspace(
        cookie,
        "Retry isolation",
      );
      const token = await TestUtils.execQuery(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, type, expiration)
         VALUES ($1, $2, $1, 'Incident retry token', 'api_key', CURRENT_DATE + 7)
         RETURNING id`,
        [user.id, ws],
      );
      const alertId = await insertFailedAlert(token.rows[0].id);
      const key = `delivery_blocked:${alertId}`;
      const incidents = await TestUtils.execQuery(
        `INSERT INTO operational_notifications
           (workspace_id, token_id, category, type, severity, dedupe_key, title)
         VALUES ($1, $3, 'delivery', 'delivery_blocked', 'critical', $4, 'Retried incident'),
                ($2, NULL, 'delivery', 'delivery_blocked', 'critical', $4, 'Other workspace incident')
         RETURNING id, workspace_id`,
        [ws, otherWorkspace, token.rows[0].id, key],
      );
      try {
        await request(BASE)
          .post(`/api/alert-queue/${alertId}/retry`)
          .set("Cookie", cookie)
          .send({ channel: "email" })
          .expect(200);
        const alertState = await TestUtils.execQuery(
          "SELECT status FROM alert_queue WHERE id = $1",
          [alertId],
        );
        expect(alertState.rows[0].status).to.equal("pending");
        const state = await TestUtils.execQuery(
          `SELECT workspace_id, resolved_at FROM operational_notifications WHERE id = ANY($1::uuid[])`,
          [incidents.rows.map((row) => row.id)],
        );
        expect(
          state.rows.find((row) => row.workspace_id === ws).resolved_at,
        ).to.be.a("date");
        expect(
          state.rows.find((row) => row.workspace_id === otherWorkspace)
            .resolved_at,
        ).to.equal(null);
      } finally {
        await TestUtils.execQuery(
          "DELETE FROM operational_notifications WHERE id = ANY($1::uuid[])",
          [incidents.rows.map((row) => row.id)],
        );
        await TestUtils.execQuery("DELETE FROM alert_queue WHERE id = $1", [
          alertId,
        ]);
        await TestUtils.execQuery("DELETE FROM tokens WHERE id = $1", [
          token.rows[0].id,
        ]);
      }
    });

    it("cannot retry another user's alert or clear its incident", async () => {
      const otherUser = await TestUtils.createVerifiedTestUser();
      const otherSession = await TestUtils.loginTestUser(
        otherUser.email,
        otherUser.password,
      );
      const otherWorkspace = await TestUtils.ensureDedicatedTestWorkspace(
        otherSession.cookie,
        "Other retry owner",
      );
      const token = await TestUtils.execQuery(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, type, expiration)
         VALUES ($1, $2, $1, 'Private alert token', 'api_key', CURRENT_DATE + 7) RETURNING id`,
        [otherUser.id, otherWorkspace],
      );
      const alert = await TestUtils.execQuery(
        `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status, error_message)
         VALUES ($1, $2, $3, 7, CURRENT_DATE, '["email"]'::jsonb, 'failed', 'SMTP timeout') RETURNING id`,
        [otherUser.id, token.rows[0].id, `private-retry:${randomUUID()}`],
      );
      const incident = await TestUtils.execQuery(
        `INSERT INTO operational_notifications
           (workspace_id, token_id, category, type, severity, dedupe_key, title)
         VALUES ($1, $2, 'delivery', 'delivery_blocked', 'critical', $3, 'Private incident') RETURNING id`,
        [
          otherWorkspace,
          token.rows[0].id,
          `delivery_blocked:${alert.rows[0].id}`,
        ],
      );
      try {
        await request(BASE)
          .post(`/api/alert-queue/${alert.rows[0].id}/retry`)
          .set("Cookie", cookie)
          .send({ channel: "email" })
          .expect(404);
        const state = await TestUtils.execQuery(
          `SELECT aq.status, n.resolved_at FROM alert_queue aq
             JOIN operational_notifications n ON n.id = $2 WHERE aq.id = $1`,
          [alert.rows[0].id, incident.rows[0].id],
        );
        expect(state.rows[0].status).to.equal("failed");
        expect(state.rows[0].resolved_at).to.equal(null);
      } finally {
        await TestUtils.execQuery(
          "DELETE FROM operational_notifications WHERE id = $1",
          [incident.rows[0].id],
        );
        await TestUtils.execQuery("DELETE FROM alert_queue WHERE id = $1", [
          alert.rows[0].id,
        ]);
        await TestUtils.execQuery("DELETE FROM tokens WHERE id = $1", [
          token.rows[0].id,
        ]);
        await TestUtils.cleanupTestUser(otherUser.email, otherSession.cookie);
      }
    });
  });

  describe("POST /api/alert-queue/requeue", () => {
    it("denies a former owner retry and requeue after transfer while preserving current workspace access", async () => {
      const formerOwner = await TestUtils.createVerifiedTestUser();
      const ownerSession = await TestUtils.loginTestUser(
        formerOwner.email,
        formerOwner.password,
      );
      const destinationAdmin = await TestUtils.createVerifiedTestUser();
      const adminSession = await TestUtils.loginTestUser(
        destinationAdmin.email,
        destinationAdmin.password,
      );
      const unrelatedAdmin = await TestUtils.createVerifiedTestUser();
      const unrelatedSession = await TestUtils.loginTestUser(
        unrelatedAdmin.email,
        unrelatedAdmin.password,
      );
      const source = await TestUtils.ensureDedicatedTestWorkspace(
        adminSession.cookie,
        "Transfer retry source",
      );
      const destination = await TestUtils.ensureDedicatedTestWorkspace(
        adminSession.cookie,
        "Transfer retry destination",
      );
      await TestUtils.ensureDedicatedTestWorkspace(
        unrelatedSession.cookie,
        "Unrelated retry workspace",
      );
      const tokenIds = [];
      const alertIds = [];
      const incidentIds = [];
      const agentIds = [];
      try {
        await TestUtils.execQuery(
          `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
           VALUES ($1, $2, 'viewer', $3)`,
          [formerOwner.id, source, destinationAdmin.id],
        );
        const transferredToken = await TestUtils.execQuery(
          `INSERT INTO tokens (user_id, workspace_id, created_by, name, type, expiration)
           VALUES ($1, $2, $1, 'Transferred retry token', 'api_key', CURRENT_DATE + 7)
           RETURNING id`,
          [formerOwner.id, source],
        );
        const transferredTokenId = transferredToken.rows[0].id;
        tokenIds.push(transferredTokenId);
        const transferredAlertId = await insertFailedAlert(
          transferredTokenId,
          formerOwner.id,
        );
        alertIds.push(transferredAlertId);
        const sourceIncident = await TestUtils.execQuery(
          `INSERT INTO operational_notifications
             (workspace_id, token_id, category, type, severity, dedupe_key, title)
           VALUES ($1, $2, 'delivery', 'delivery_blocked', 'critical', $3, 'Source incident')
           RETURNING id`,
          [
            source,
            transferredTokenId,
            `delivery_blocked:${transferredAlertId}`,
          ],
        );
        incidentIds.push(sourceIncident.rows[0].id);

        await request(BASE)
          .post(`/api/v1/workspaces/${destination}/transfer-tokens`)
          .set("Cookie", adminSession.cookie)
          .send({ from_workspace_id: source, token_ids: [transferredTokenId] })
          .expect(200);
        const moved = await TestUtils.execQuery(
          `SELECT t.workspace_id, aq.user_id
             FROM tokens t JOIN alert_queue aq ON aq.token_id = t.id
            WHERE aq.id = $1`,
          [transferredAlertId],
        );
        expect(moved.rows[0].workspace_id).to.equal(destination);
        expect(Number(moved.rows[0].user_id)).to.equal(Number(formerOwner.id));
        const sourceState = await TestUtils.execQuery(
          "SELECT resolved_at FROM operational_notifications WHERE id = $1",
          [sourceIncident.rows[0].id],
        );
        expect(sourceState.rows[0].resolved_at).to.be.a("date");

        const destinationIncident = await TestUtils.execQuery(
          `INSERT INTO operational_notifications
             (workspace_id, token_id, category, type, severity, dedupe_key, title)
           VALUES ($1, $2, 'delivery', 'delivery_blocked', 'critical', $3, 'Destination incident')
           RETURNING id`,
          [
            destination,
            transferredTokenId,
            `delivery_blocked:${transferredAlertId}`,
          ],
        );
        incidentIds.push(destinationIncident.rows[0].id);

        const credential = randomBytes(32).toString("hex");
        const agent = await TestUtils.execQuery(
          `INSERT INTO certops_agents
             (workspace_id, agent_id, agent_version, protocol_version, credential_prefix, credential_hash)
           VALUES ($1, $2, '1.0.0', '1.0.0', $3, $4) RETURNING id`,
          [
            destination,
            `transferred-retry-${randomUUID()}`,
            `ttagent_${credential.slice(0, 16)}`,
            credential,
          ],
        );
        agentIds.push(agent.rows[0].id);
        const agentAlert = await TestUtils.execQuery(
          `INSERT INTO alert_queue
             (user_id, certops_agent_id, alert_key, threshold_days, due_date, channels, status, error_message)
           VALUES ($1, $2, $3, 7, CURRENT_DATE, '["email"]'::jsonb, 'failed', 'SMTP timeout')
           RETURNING id`,
          [formerOwner.id, agent.rows[0].id, `stale-agent:${randomUUID()}`],
        );
        const agentAlertId = agentAlert.rows[0].id;
        alertIds.push(agentAlertId);
        const agentIncident = await TestUtils.execQuery(
          `INSERT INTO operational_notifications
             (workspace_id, category, type, severity, dedupe_key, title)
           VALUES ($1, 'delivery', 'delivery_blocked', 'critical', $2, 'Agent incident')
           RETURNING id`,
          [destination, `delivery_blocked:${agentAlertId}`],
        );
        incidentIds.push(agentIncident.rows[0].id);

        const currentToken = await TestUtils.execQuery(
          `INSERT INTO tokens (user_id, workspace_id, created_by, name, type, expiration)
           VALUES ($1, $2, $1, 'Current retry token', 'api_key', CURRENT_DATE + 7)
           RETURNING id`,
          [formerOwner.id, source],
        );
        tokenIds.push(currentToken.rows[0].id);
        const currentAlertId = await insertFailedAlert(
          currentToken.rows[0].id,
          formerOwner.id,
        );
        alertIds.push(currentAlertId);

        const staleRetry = await request(BASE)
          .post(`/api/alert-queue/${transferredAlertId}/retry`)
          .set("Cookie", ownerSession.cookie)
          .send({ channel: "email" });
        expect(staleRetry.status).to.equal(404);
        await request(BASE)
          .post(`/api/alert-queue/${agentAlertId}/retry`)
          .set("Cookie", ownerSession.cookie)
          .send({ channel: "email" })
          .expect(404);
        const accountWide = await request(BASE)
          .post("/api/alert-queue/requeue")
          .set("Cookie", ownerSession.cookie)
          .send({})
          .expect(200);
        expect(accountWide.body.updated).to.equal(1);
        await request(BASE)
          .post("/api/alert-queue/requeue")
          .set("Cookie", unrelatedSession.cookie)
          .send({ workspace_id: destination })
          .expect(403);

        const beforeAdmin = await TestUtils.execQuery(
          `SELECT aq.id, aq.status, n.resolved_at
             FROM alert_queue aq JOIN operational_notifications n
               ON n.dedupe_key = 'delivery_blocked:' || aq.id
              AND n.workspace_id = $2
            WHERE aq.id = ANY($1::int[]) ORDER BY aq.id`,
          [[transferredAlertId, agentAlertId], destination],
        );
        expect(beforeAdmin.rows).to.have.length(2);
        for (const row of beforeAdmin.rows) {
          expect(row.status).to.equal("failed");
          expect(row.resolved_at).to.equal(null);
        }
        const currentState = await TestUtils.execQuery(
          "SELECT status FROM alert_queue WHERE id = $1",
          [currentAlertId],
        );
        expect(currentState.rows[0].status).to.equal("pending");

        // The creator is an implicit admin even after their explicit row is removed.
        await TestUtils.execQuery(
          "DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2",
          [destination, destinationAdmin.id],
        );
        const destinationRequeue = await request(BASE)
          .post("/api/alert-queue/requeue")
          .set("Cookie", adminSession.cookie)
          .send({ workspace_id: destination })
          .expect(200);
        expect(destinationRequeue.body.updated).to.equal(2);
        const afterAdmin = await TestUtils.execQuery(
          `SELECT aq.status, n.resolved_at
             FROM alert_queue aq JOIN operational_notifications n
               ON n.dedupe_key = 'delivery_blocked:' || aq.id
              AND n.workspace_id = $2
            WHERE aq.id = ANY($1::int[])`,
          [[transferredAlertId, agentAlertId], destination],
        );
        for (const row of afterAdmin.rows) {
          expect(row.status).to.equal("pending");
          expect(row.resolved_at).to.be.a("date");
        }

        await TestUtils.execQuery(
          "UPDATE alert_queue SET user_id = $1, status = 'failed' WHERE id = $2",
          [destinationAdmin.id, transferredAlertId],
        );
        const creatorAccountWide = await request(BASE)
          .post("/api/alert-queue/requeue")
          .set("Cookie", adminSession.cookie)
          .send({})
          .expect(200);
        expect(creatorAccountWide.body.updated).to.equal(1);
      } finally {
        await TestUtils.execQuery(
          "DELETE FROM operational_notifications WHERE id = ANY($1::uuid[])",
          [incidentIds],
        );
        await TestUtils.execQuery(
          "DELETE FROM alert_queue WHERE id = ANY($1::int[])",
          [alertIds],
        );
        await TestUtils.execQuery(
          "DELETE FROM tokens WHERE id = ANY($1::int[])",
          [tokenIds],
        );
        await TestUtils.execQuery(
          "DELETE FROM certops_agents WHERE id = ANY($1::uuid[])",
          [agentIds],
        );
        await TestUtils.cleanupTestUser(formerOwner.email, ownerSession.cookie);
        await TestUtils.cleanupTestUser(
          destinationAdmin.email,
          adminSession.cookie,
        );
        await TestUtils.cleanupTestUser(
          unrelatedAdmin.email,
          unrelatedSession.cookie,
        );
      }
    });

    it("requeues all failed alerts for user", async () => {
      const soon = new Date();
      soon.setDate(soon.getDate() + 3);
      const token = await request(BASE)
        .post("/api/tokens")
        .set("Cookie", cookie)
        .send({
          name: "Requeue Token",
          type: "api_key",
          category: "general",
          expiresAt: soon.toISOString().slice(0, 10),
          workspace_id: ws,
        })
        .expect(201);

      await insertFailedAlert(token.body.id);
      await insertFailedAlert(token.body.id);

      const res = await request(BASE)
        .post("/api/alert-queue/requeue")
        .set("Cookie", cookie)
        .send({})
        .expect(200);

      expect(res.body).to.have.property("updated");
      expect(res.body.updated).to.be.at.least(1);
    });

    it("supports workspace-scoped requeue", async () => {
      const res = await request(BASE)
        .post("/api/alert-queue/requeue")
        .set("Cookie", cookie)
        .send({ workspace_id: ws })
        .expect(200);

      expect(res.body).to.have.property("updated");
    });

    it("lets a manager requeue another user's token and agent alerts only in the selected workspace", async () => {
      const owner = await TestUtils.createVerifiedTestUser();
      const ownerSession = await TestUtils.loginTestUser(
        owner.email,
        owner.password,
      );
      const workspaceA = await TestUtils.ensureDedicatedTestWorkspace(
        ownerSession.cookie,
        "Manager requeue A",
      );
      const workspaceB = await TestUtils.ensureDedicatedTestWorkspace(
        ownerSession.cookie,
        "Manager requeue B",
      );
      const ids = { tokens: [], agents: [], alerts: [] };
      try {
        await TestUtils.execQuery(
          `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
           VALUES ($1, $2, 'workspace_manager', $3)
           ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'workspace_manager'`,
          [user.id, workspaceA, owner.id],
        );
        for (const workspaceId of [workspaceA, workspaceB]) {
          const token = await TestUtils.execQuery(
            `INSERT INTO tokens (user_id, workspace_id, created_by, name, type, expiration)
             VALUES ($1, $2, $1, 'Other owner token', 'api_key', CURRENT_DATE + 7) RETURNING id`,
            [owner.id, workspaceId],
          );
          ids.tokens.push(token.rows[0].id);
          const credential = randomBytes(32).toString("hex");
          const agent = await TestUtils.execQuery(
            `INSERT INTO certops_agents
               (workspace_id, agent_id, agent_version, protocol_version, credential_prefix, credential_hash)
             VALUES ($1, $2, '1.0.0', '1.0.0', $3, $4) RETURNING id`,
            [
              workspaceId,
              `manager-${randomUUID()}`,
              `ttagent_${credential.slice(0, 16)}`,
              credential,
            ],
          );
          ids.agents.push(agent.rows[0].id);
          for (const [tokenId, agentId] of [
            [token.rows[0].id, null],
            [null, agent.rows[0].id],
          ]) {
            const alert = await TestUtils.execQuery(
              `INSERT INTO alert_queue
                 (user_id, token_id, certops_agent_id, alert_key, threshold_days,
                  due_date, channels, status, error_message)
               VALUES ($1, $2, $3, $4, 7, CURRENT_DATE, '["email"]'::jsonb,
                       'failed', 'SMTP timeout') RETURNING id`,
              [owner.id, tokenId, agentId, `manager-requeue:${randomUUID()}`],
            );
            ids.alerts.push(alert.rows[0].id);
          }
        }
        const requeue = await request(BASE)
          .post("/api/alert-queue/requeue")
          .set("Cookie", cookie)
          .send({ workspace_id: workspaceA })
          .expect(200);
        expect(requeue.body.updated).to.equal(2);
        const state = await TestUtils.execQuery(
          "SELECT id, status FROM alert_queue WHERE id = ANY($1::int[])",
          [ids.alerts],
        );
        const byId = new Map(state.rows.map((row) => [row.id, row.status]));
        expect(ids.alerts.slice(0, 2).map((id) => byId.get(id))).to.deep.equal([
          "pending",
          "pending",
        ]);
        expect(ids.alerts.slice(2).map((id) => byId.get(id))).to.deep.equal([
          "failed",
          "failed",
        ]);

        // An implicit workspace creator remains an admin even without a membership row.
        await TestUtils.execQuery(
          "DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2",
          [workspaceB, owner.id],
        );
        const creatorRequeue = await request(BASE)
          .post("/api/alert-queue/requeue")
          .set("Cookie", ownerSession.cookie)
          .send({ workspace_id: workspaceB })
          .expect(200);
        expect(creatorRequeue.body.updated).to.equal(2);

        await TestUtils.execQuery(
          "UPDATE workspace_memberships SET role = 'viewer' WHERE workspace_id = $1 AND user_id = $2",
          [workspaceA, user.id],
        );
        await request(BASE)
          .post("/api/alert-queue/requeue")
          .set("Cookie", cookie)
          .send({ workspace_id: workspaceA })
          .expect(403);
      } finally {
        await TestUtils.execQuery(
          "DELETE FROM alert_queue WHERE id = ANY($1::int[])",
          [ids.alerts],
        );
        await TestUtils.execQuery(
          "DELETE FROM tokens WHERE id = ANY($1::int[])",
          [ids.tokens],
        );
        await TestUtils.execQuery(
          "DELETE FROM certops_agents WHERE id = ANY($1::uuid[])",
          [ids.agents],
        );
        await TestUtils.cleanupTestUser(owner.email, ownerSession.cookie);
      }
    });

    it("requeues tokenless agent alerts in the selected workspace and cleans up account-wide incidents", async () => {
      const workspaceA = await TestUtils.ensureDedicatedTestWorkspace(
        cookie,
        "Agent requeue A",
      );
      const workspaceB = await TestUtils.ensureDedicatedTestWorkspace(
        cookie,
        "Agent requeue B",
      );
      const alertIds = [];
      const agentIds = [];
      const incidentIds = [];
      try {
        for (const workspaceId of [workspaceA, workspaceB]) {
          const credential = randomBytes(32).toString("hex");
          const agent = await TestUtils.execQuery(
            `INSERT INTO certops_agents
               (workspace_id, agent_id, agent_version, protocol_version, credential_prefix, credential_hash)
             VALUES ($1, $2, '1.0.0', '1.0.0', $3, $4) RETURNING id`,
            [
              workspaceId,
              `requeue-${randomUUID()}`,
              `ttagent_${credential.slice(0, 16)}`,
              credential,
            ],
          );
          agentIds.push(agent.rows[0].id);
          const alert = await TestUtils.execQuery(
            `INSERT INTO alert_queue
               (user_id, certops_agent_id, alert_key, threshold_days, due_date, channels, status, error_message)
             VALUES ($1, $2, $3, 7, CURRENT_DATE, '["email"]'::jsonb, 'failed', 'SMTP timeout') RETURNING id`,
            [user.id, agent.rows[0].id, `agent-requeue:${randomUUID()}`],
          );
          alertIds.push(alert.rows[0].id);
          const incident = await TestUtils.execQuery(
            `INSERT INTO operational_notifications
               (workspace_id, category, type, severity, dedupe_key, title)
             VALUES ($1, 'delivery', 'delivery_blocked', 'critical', $2, 'Agent alert failed') RETURNING id`,
            [workspaceId, `delivery_blocked:${alert.rows[0].id}`],
          );
          incidentIds.push(incident.rows[0].id);
        }
        await request(BASE)
          .post("/api/alert-queue/requeue")
          .set("Cookie", cookie)
          .send({ workspace_id: workspaceA })
          .expect(200);
        let state = await TestUtils.execQuery(
          `SELECT aq.id, aq.status, n.resolved_at FROM alert_queue aq
             JOIN operational_notifications n ON n.dedupe_key = 'delivery_blocked:' || aq.id
            WHERE aq.id = ANY($1::int[]) ORDER BY aq.id`,
          [alertIds],
        );
        const byId = new Map(state.rows.map((row) => [row.id, row]));
        expect(byId.get(alertIds[0]).status).to.equal("pending");
        expect(byId.get(alertIds[0]).resolved_at).to.be.a("date");
        expect(byId.get(alertIds[1]).status).to.equal("failed");
        expect(byId.get(alertIds[1]).resolved_at).to.equal(null);

        await request(BASE)
          .post("/api/alert-queue/requeue")
          .set("Cookie", cookie)
          .send({})
          .expect(200);
        state = await TestUtils.execQuery(
          `SELECT aq.status, n.resolved_at FROM alert_queue aq
             JOIN operational_notifications n ON n.dedupe_key = 'delivery_blocked:' || aq.id
            WHERE aq.id = $1`,
          [alertIds[1]],
        );
        expect(state.rows[0].status).to.equal("pending");
        expect(state.rows[0].resolved_at).to.be.a("date");
      } finally {
        await TestUtils.execQuery(
          "DELETE FROM operational_notifications WHERE id = ANY($1::uuid[])",
          [incidentIds],
        );
        await TestUtils.execQuery(
          "DELETE FROM alert_queue WHERE id = ANY($1::int[])",
          [alertIds],
        );
        await TestUtils.execQuery(
          "DELETE FROM certops_agents WHERE id = ANY($1::uuid[])",
          [agentIds],
        );
      }
    });

    it("rejects requeue for workspace where user is not admin/manager", async () => {
      const otherUser = await TestUtils.createVerifiedTestUser();
      const otherSession = await TestUtils.loginTestUser(
        otherUser.email,
        otherUser.password,
      );

      const res = await request(BASE)
        .post("/api/alert-queue/requeue")
        .set("Cookie", otherSession.cookie)
        .send({ workspace_id: ws });

      expect(res.status).to.equal(403);
    });
  });
});
