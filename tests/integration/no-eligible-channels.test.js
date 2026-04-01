const { expect, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");

describe("No Eligible Channels → Do Not Queue", function () {
  this.timeout(60000);

  let client;
  let user;
  let wsId;

  before(async () => {
    await TestEnvironment.setup();
    client = new Client({
      user: process.env.DB_USER || "tokentimer",
      host: process.env.DB_HOST || "localhost",
      database: process.env.DB_NAME || "tokentimer",
      password: process.env.DB_PASSWORD || "password",
      port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
      ssl: false,
    });
    await client.connect();

    const u = await TestUtils.createAuthenticatedUser();
    user = u;
    // Ensure a workspace exists for this user
    wsId = require("crypto").randomUUID();
    await client.query(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,'oss',$3)`,
      [wsId, `WS ${user.id}`, user.id],
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1,$2,'admin',$1)`,
      [user.id, wsId],
    );
    user.workspace_id = wsId;

    // Disable email and webhooks in workspace settings
    await client.query(
      `INSERT INTO workspace_settings (workspace_id, email_alerts_enabled, webhooks_alerts_enabled, webhook_urls)
       VALUES ($1, FALSE, FALSE, '[]'::jsonb)
       ON CONFLICT (workspace_id) DO UPDATE SET email_alerts_enabled = FALSE, webhooks_alerts_enabled = FALSE, webhook_urls = '[]'::jsonb`,
      [wsId],
    );
  });

  after(async () => {
    try {
      // Clean up all test data
      if (wsId) {
        await client.query(`DELETE FROM alert_queue WHERE workspace_id = $1`, [
          wsId,
        ]);
        await client.query(
          `DELETE FROM audit_events WHERE target_id IN (SELECT id FROM tokens WHERE workspace_id = $1)`,
          [wsId],
        );
        await client.query(`DELETE FROM tokens WHERE workspace_id = $1`, [
          wsId,
        ]);
        await client.query(
          `DELETE FROM workspace_contacts WHERE workspace_id = $1`,
          [wsId],
        );
        await client.query(
          `DELETE FROM workspace_settings WHERE workspace_id = $1`,
          [wsId],
        );
        await client.query(
          `DELETE FROM workspace_memberships WHERE workspace_id = $1`,
          [wsId],
        );
        await client.query(`DELETE FROM workspaces WHERE id = $1`, [wsId]);
      }
      if (user && user.id) {
        await client.query(`DELETE FROM alert_queue WHERE user_id = $1`, [
          user.id,
        ]);
        await client.query(`DELETE FROM tokens WHERE user_id = $1`, [user.id]);
        await client.query(`DELETE FROM users WHERE id = $1`, [user.id]);
      }
    } catch (err) {
      // Log but don't fail cleanup
      console.error("Cleanup error:", err.message);
    }
    await client.end();
  });

  it("should not queue alert when no channels are eligible", async () => {
    // Create a token expiring today
    const today = new Date();
    const tokenRes = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1, $2, $1, $3, $4, 'api_key', 'general') RETURNING id`,
      [
        user.id,
        user.workspace_id,
        "No Channels Token",
        today.toISOString().slice(0, 10),
      ],
    );

    // Run discovery
    await TestUtils.runNode("node", ["src/queue-manager.js"], "apps/worker");

    // Verify no alert queued
    const rows = await client.query(
      `SELECT * FROM alert_queue WHERE user_id = $1`,
      [user.id],
    );
    expect(rows.rowCount).to.equal(0);
  });
});
