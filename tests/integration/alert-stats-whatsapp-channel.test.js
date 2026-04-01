const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Alert stats includes whatsapp channel", function () {
  this.timeout(60000);

  let client;
  let user;
  let cookie;
  let workspaceId;

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
    workspaceId = await TestUtils.ensureTestWorkspace(cookie);
  });

  after(async () => {
    try {
      await client.query("DELETE FROM tokens WHERE user_id = $1", [user.id]);
      await client.query("DELETE FROM users WHERE id = $1", [user.id]);
    } catch (_) {}
    await client.end();
  });

  it("byChannel shows whatsapp successes when present", async () => {
    // Create token and insert a successful whatsapp delivery for current month
    const token = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1,$2,$1,$3,$4,'api_key','general') RETURNING id`,
      [
        user.id,
        workspaceId,
        "WA Stats",
        new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10),
      ],
    );
    await client.query(
      `INSERT INTO alert_delivery_log (user_id, token_id, workspace_id, channel, status, sent_at)
       VALUES ($1,$2,$3,'whatsapp','success', NOW())`,
      [user.id, token.rows[0].id, workspaceId],
    );

    const res = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: workspaceId })
      .set("Cookie", cookie)
      .expect(200);

    expect(res.body).to.have.property("byChannel");
    const wa = res.body.byChannel.find(
      (r) => String(r.channel).toLowerCase() === "whatsapp",
    );
    expect(wa).to.exist;
    expect(wa.successes).to.be.greaterThan(0);
  });
});
