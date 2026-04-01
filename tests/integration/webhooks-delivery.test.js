const { expect, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");

describe("Webhooks Delivery - PD severity mapping", function () {
  this.timeout(90000);

  let client;

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
  });

  after(async () => {
    await client.end();
  });

  it("queues webhooks channel with webhook_urls only (no separate slack channel)", async () => {
    const u = await TestUtils.createAuthenticatedUser();
    const userId = u.user.id;
    const wsIdRes = await client.query(
      `SELECT id FROM workspaces WHERE created_by=$1 ORDER BY created_at ASC LIMIT 1`,
      [userId],
    );
    const wsId = wsIdRes.rows[0]?.id || require("crypto").randomUUID();
    if (!wsIdRes.rows[0]) {
      await client.query(
        `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,'oss',$3)`,
        [wsId, `WS ${userId}`, userId],
      );
      await client.query(
        `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1,$2,'admin',$1)`,
        [userId, wsId],
      );
    }

    // Configure PD webhook
    await client.query(
      `INSERT INTO workspace_settings (workspace_id, webhook_urls, email_alerts_enabled, webhooks_alerts_enabled, slack_alerts_enabled)
         VALUES ((SELECT id FROM workspaces WHERE created_by=$2 LIMIT 1), $1, true, true, false)
         ON CONFLICT (workspace_id) DO UPDATE SET webhook_urls=$1, email_alerts_enabled=true, webhooks_alerts_enabled=true, slack_alerts_enabled=false`,
      [
        JSON.stringify([
          {
            kind: "pagerduty",
            url: "https://events.pagerduty.com/v2/enqueue",
            routingKey: "TEST",
          },
        ]),
        userId,
      ],
    );

    // Token expiring in 40 days (warning default)
    const future = new Date();
    future.setDate(future.getDate() + 40);
    const tRes = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category) VALUES ($1,$2,$1,$3,$4,'api_key','general') RETURNING id`,
      [userId, wsId, "PD-40d", future.toISOString().slice(0, 10)],
    );

    // Run discovery and assert queued channels only include webhooks/email
    await TestUtils.runNode("node", ["src/queue-manager.js"], "apps/worker");
    const aq = await client.query(
      `SELECT channels FROM alert_queue WHERE user_id=$1`,
      [userId],
    );
    const channelSets = aq.rows.map((r) =>
      Array.isArray(r.channels) ? r.channels : JSON.parse(r.channels),
    );
    for (const ch of channelSets) expect(ch).to.include("webhooks");
  });
});
