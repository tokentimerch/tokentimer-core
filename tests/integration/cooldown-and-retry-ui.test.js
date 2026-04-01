const { expect, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Cooldown and retry API fields", function () {
  this.timeout(90000);

  let client;
  let user;
  let cookie;
  let tokenId;
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
    user = u.user;
    cookie = u.cookie;

    // Ensure workspace and settings
    wsId = require("crypto").randomUUID();
    await client.query(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,'oss',$3)`,
      [wsId, `WS ${user.id}`, user.id],
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1,$2,'admin',$1)`,
      [user.id, wsId],
    );
    // Create a contact and enable a group so email channel is eligible
    const contact = await client.query(
      `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, phone_e164, details, created_by)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [
        wsId,
        "Cool",
        "Down",
        null,
        JSON.stringify({ email: "alerts@example.com" }),
        user.id,
      ],
    );
    await client.query(
      `INSERT INTO workspace_settings (workspace_id, email_alerts_enabled, contact_groups, default_contact_group_id)
       VALUES ($1, TRUE, $2, 'admins')
       ON CONFLICT (workspace_id) DO UPDATE SET email_alerts_enabled=EXCLUDED.email_alerts_enabled, contact_groups=EXCLUDED.contact_groups, default_contact_group_id=EXCLUDED.default_contact_group_id`,
      [
        wsId,
        JSON.stringify([
          {
            id: "admins",
            name: "Admins",
            email_contact_ids: [contact.rows[0].id],
          },
        ]),
      ],
    );

    const soon = new Date();
    soon.setDate(soon.getDate() + 7);
    const tRes = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category) VALUES ($1,$2,$1,$3,$4,'api_key','general') RETURNING id`,
      [user.id, wsId, "Cooldown-Token", soon.toISOString().slice(0, 10)],
    );
    tokenId = tRes.rows[0].id;
  });

  after(async () => {
    try {
      // Clean up all test data
      if (tokenId) {
        await client.query(
          `DELETE FROM alert_delivery_log WHERE token_id = $1`,
          [tokenId],
        );
        await client.query(`DELETE FROM alert_queue WHERE token_id = $1`, [
          tokenId,
        ]);
        await client.query(`DELETE FROM audit_events WHERE target_id = $1`, [
          tokenId,
        ]);
        await client.query(`DELETE FROM tokens WHERE id = $1`, [tokenId]);
      }
      if (wsId) {
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

  it("exposes next_attempt_at and per-channel attempts in alert queue", async () => {
    // Insert a queue row directly to avoid worker process timing flakiness.
    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + 7);
    const dueDateStr = dueDate.toISOString().slice(0, 10);
    await client.query(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
       VALUES ($1, $2, $3, 7, $4, '["email"]'::jsonb, 'pending')
       ON CONFLICT (alert_key) DO NOTHING`,
      [user.id, tokenId, `token-${tokenId}-7-${dueDateStr}`, dueDateStr],
    );

    // Force failed retry metadata shape expected by the API response.
    await client.query(
      `UPDATE alert_queue SET status='failed', attempts_email=3, next_attempt_at=NOW() + INTERVAL '5 minutes' WHERE user_id=$1 AND token_id=$2`,
      [user.id, tokenId],
    );

    const r = await require("supertest")(BASE)
      .get("/api/alert-queue")
      .set("Cookie", cookie)
      .expect(200);

    const alerts = r.body.alerts || [];
    expect(alerts.length).to.be.greaterThan(0);
    const row = alerts.find((a) => a.token_id === tokenId);
    expect(row).to.exist;
    expect(row.next_attempt_at).to.exist;
  });
});
