const { expect, TestEnvironment } = require("./setup");
const { Client } = require("pg");

// Verifies that month usage is computed using UTC month boundaries
// Inserts delivery rows around UTC midnight and asserts /api/alert-stats respects boundaries

describe("UTC Month Usage Boundary", function () {
  this.timeout(60000);

  let client;
  let user;
  let cookie;

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

    const u = await require("./setup").TestUtils.createAuthenticatedUser();
    user = u;
    cookie = u.cookie;
    // Ensure a workspace for stats endpoint auth
    const wsId = require("crypto").randomUUID();
    await client.query(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,'oss',$3)`,
      [wsId, `WS ${u.user.id}`, u.user.id],
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1,$2,'admin',$1)`,
      [u.user.id, wsId],
    );
    // Store workspace id on user object for convenience
    user.workspace_id = wsId;
    // Create a token in this workspace to attribute deliveries
    const tok = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1,$2,$1,$3,$4,'api_key','general') RETURNING id`,
      [
        u.user.id,
        wsId,
        "UTC Boundary Token",
        new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10),
      ],
    );
    user.token_id_for_stats = tok.rows[0].id;
  });

  after(async () => {
    try {
      await client.query("DELETE FROM tokens WHERE user_id = $1", [user.id]);
      await client.query("DELETE FROM users WHERE id = $1", [user.id]);
    } catch (_) {}
    await client.end();
  });

  it("should count only rows within current UTC month", async () => {
    // Clear any existing rows
    await client.query("DELETE FROM alert_delivery_log WHERE user_id = $1", [
      user.id,
    ]);

    const now = new Date();
    // Compute first day of this month UTC and next month UTC
    const firstOfMonthUTC = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0),
    );
    const lastMonthUTC = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 28, 23, 59, 59),
    );

    // Insert one success in last month UTC, one success this month UTC (for the workspace token)
    await client.query(
      `INSERT INTO alert_delivery_log (user_id, token_id, workspace_id, channel, status, sent_at)
       VALUES ($1, $2, $3, 'email', 'success', $4)`,
      [
        user.id,
        user.token_id_for_stats,
        user.workspace_id,
        lastMonthUTC.toISOString(),
      ],
    );
    await client.query(
      `INSERT INTO alert_delivery_log (user_id, token_id, workspace_id, channel, status, sent_at)
       VALUES ($1, $2, $3, 'webhooks', 'success', $4)`,
      [
        user.id,
        user.token_id_for_stats,
        user.workspace_id,
        firstOfMonthUTC.toISOString(),
      ],
    );

    const request = require("supertest");
    const BASE = process.env.TEST_API_URL || "http://localhost:4000";
    const res = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: user.workspace_id })
      .set("Cookie", cookie)
      .expect(200);

    expect(res.body).to.have.property("byChannel");
    expect(res.body).to.have.property("monthUsage");
    // monthUsage should be 1 (only this-month row)
    expect(res.body.monthUsage).to.equal(1);

    // byChannel successes should reflect only this-month row
    const wh = res.body.byChannel.find(
      (r) => String(r.channel).toLowerCase() === "webhooks",
    );
    const em = res.body.byChannel.find(
      (r) => String(r.channel).toLowerCase() === "email",
    );
    expect(wh ? wh.successes : 0).to.be.oneOf([0, 1]); // webhooks success in this month is 1
    expect(em ? em.successes : 0).to.be.oneOf([0, 1]); // email success last month should not count
    if (wh) expect(wh.successes).to.equal(1);
    if (em) expect(em.successes).to.equal(0);
  });
});
