const { expect, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");
const http = require("node:http");
const { randomUUID } = require("node:crypto");

describe("Delivery degraded threshold (real worker)", function () {
  this.timeout(180000);

  it("warns at failure 2 without a retry timestamp, updates the same row, then escalates", async () => {
    await TestEnvironment.setup();
    const user = await TestUtils.createAuthenticatedUser();
    const userId = user.id || user.user?.id;
    const workspaceId = await TestUtils.ensureDedicatedTestWorkspace(
      user.cookie,
      "Degraded threshold",
    );
    const server = http.createServer((_request, response) => {
      response.writeHead(503);
      response.end("unavailable");
    });
    const client = new Client({
      user: process.env.DB_USER || "tokentimer",
      host: process.env.DB_HOST || "localhost",
      database: process.env.DB_NAME || "tokentimer",
      password: process.env.DB_PASSWORD || "password",
      port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
      ssl: false,
    });
    let tokenId;
    let alertId;
    try {
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      await client.connect();
      const webhookUrl = `http://127.0.0.1:${server.address().port}/fail`;
      await client.query(
        `INSERT INTO workspace_settings
           (workspace_id, webhook_urls, webhooks_alerts_enabled,
            email_alerts_enabled, contact_groups, default_contact_group_id,
            delivery_window_start, delivery_window_end, delivery_window_tz)
         VALUES ($1, $2::jsonb, TRUE, FALSE, $3::jsonb, 'ops',
                 '00:00', '23:59', 'UTC')
         ON CONFLICT (workspace_id) DO UPDATE SET
           webhook_urls = EXCLUDED.webhook_urls,
           webhooks_alerts_enabled = TRUE,
           email_alerts_enabled = FALSE,
           contact_groups = EXCLUDED.contact_groups,
           default_contact_group_id = 'ops',
           delivery_window_start = '00:00',
           delivery_window_end = '23:59', delivery_window_tz = 'UTC'`,
        [
          workspaceId,
          JSON.stringify([{ name: "Fail", kind: "generic", url: webhookUrl }]),
          JSON.stringify([{ id: "ops", name: "Ops", webhook_names: ["Fail"] }]),
        ],
      );
      const token = await client.query(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, type, expiration)
         VALUES ($1, $2, $1, 'Threshold webhook token', 'ssl_cert', CURRENT_DATE + INTERVAL '7 days')
         RETURNING id`,
        [userId, workspaceId],
      );
      tokenId = token.rows[0].id;
      await client.query(
        `INSERT INTO token_contact_groups (token_id, workspace_id, contact_group_id)
         VALUES ($1, $2, 'ops')`,
        [tokenId, workspaceId],
      );
      const alert = await client.query(
        `INSERT INTO alert_queue
           (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
         VALUES ($1, $2, $3, 7, CURRENT_DATE, '["webhooks"]'::jsonb, 'pending')
         RETURNING id`,
        [userId, tokenId, `degraded:${randomUUID()}`],
      );
      alertId = alert.rows[0].id;
      const workerEnv = {
        ...process.env,
        NODE_ENV: "development",
        ALERT_DEGRADED_ATTEMPTS_THRESHOLD: "2",
        ALERT_MAX_ATTEMPTS: "4",
        WEBHOOK_ALLOW_PRIVATE_IPS: "true",
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        NO_PROXY: "127.0.0.1,localhost",
        SMTP_HOST: "127.0.0.1",
        SMTP_PORT: String(process.env.TT_TEST_MAILHOG_SMTP_PORT || "1025"),
        SMTP_USER: "test@example.test",
        SMTP_PASS: "local-test-only",
        FROM_EMAIL: "noreply@example.test",
        SMTP_REQUIRE_TLS: "false",
        SMTP_SECURE: "false",
      };
      const run = () =>
        TestUtils.runNode(
          "node",
          ["src/delivery-worker.js"],
          "apps/worker",
          workerEnv,
        );
      const state = async () => {
        const queue = await client.query(
          "SELECT status, attempts_webhooks, next_attempt_at, error_message FROM alert_queue WHERE id = $1",
          [alertId],
        );
        const incidents = await client.query(
          `SELECT id, type, severity, message, metadata, resolved_at
             FROM operational_notifications
            WHERE workspace_id = $1 AND dedupe_key = $2 AND resolved_at IS NULL`,
          [workspaceId, `delivery_blocked:${alertId}`],
        );
        return { queue: queue.rows[0], incidents: incidents.rows };
      };

      await run();
      const first = await state();
      expect(Number(first.queue.attempts_webhooks)).to.equal(1);
      expect(first.incidents).to.have.length(0);

      await run();
      const second = await state();
      expect(Number(second.queue.attempts_webhooks)).to.equal(2);
      expect(second.queue.next_attempt_at).to.equal(null);
      expect(second.incidents).to.have.length(1);
      expect(second.incidents[0].type).to.equal("delivery_degraded");
      expect(second.incidents[0].severity).to.equal("warning");
      expect(second.incidents[0].message).to.include("generic: HTTP 503");
      expect(second.incidents[0].message).not.to.include("undefined");
      expect(second.incidents[0].metadata).not.to.have.property(
        "next_attempt_at",
      );
      expect(second.queue.error_message).to.include("generic: HTTP 503");
      const incidentId = second.incidents[0].id;

      await run();
      const third = await state();
      expect(Number(third.queue.attempts_webhooks)).to.equal(3);
      expect(third.queue.next_attempt_at).to.be.a("date");
      expect(third.incidents).to.have.length(1);
      expect(third.incidents[0].id).to.equal(incidentId);
      expect(third.incidents[0].metadata.next_attempt_at).to.be.a("string");

      // Advance only the retry clock; delivery still goes through the worker.
      await client.query(
        "UPDATE alert_queue SET next_attempt_at = NULL WHERE id = $1",
        [alertId],
      );
      await run();
      const fourth = await state();
      expect(fourth.queue.status).to.equal("blocked");
      expect(fourth.incidents).to.have.length(1);
      expect(fourth.incidents[0].id).to.equal(incidentId);
      expect(fourth.incidents[0].type).to.equal("delivery_blocked");
      expect(fourth.incidents[0].severity).to.equal("critical");
      expect(fourth.incidents[0].message).to.include("generic: HTTP 503");
      expect(fourth.incidents[0].message).not.to.include("undefined");
    } finally {
      if (alertId) {
        await client.query("DELETE FROM alert_queue WHERE id = $1", [alertId]);
      }
      if (tokenId) {
        await client.query("DELETE FROM tokens WHERE id = $1", [tokenId]);
      }
      await client.end();
      await TestUtils.cleanupTestUser(user.email, user.cookie);
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
