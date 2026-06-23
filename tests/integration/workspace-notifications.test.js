const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Workspace operational notifications API", function () {
  this.timeout(120000);

  let admin;
  let adminCookie;
  let adminUserId;
  let viewer;
  let viewerCookie;
  let outsider;
  let outsiderCookie;
  let workspaceId;
  let client;
  let tokenId;
  let alertKey;

  function fetchNotifications(cookie, wsId = workspaceId) {
    return request(BASE)
      .get(`/api/v1/workspaces/${wsId}/notifications`)
      .set("Cookie", cookie);
  }

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

    admin = await TestUtils.createAuthenticatedUser();
    adminCookie = admin.cookie;
    adminUserId = admin.id || admin.user?.id;
    workspaceId = await TestUtils.ensureDedicatedTestWorkspace(
      adminCookie,
      "Notifications WS",
    );

    viewer = await TestUtils.createAuthenticatedUser();
    viewerCookie = viewer.cookie;
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'viewer', $3)
       ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'viewer'`,
      [viewer.id || viewer.user?.id, workspaceId, adminUserId],
    );

    outsider = await TestUtils.createAuthenticatedUser();
    outsiderCookie = outsider.cookie;
  });

  after(async () => {
    if (tokenId) {
      await client.query("DELETE FROM alert_queue WHERE token_id = $1", [
        tokenId,
      ]);
      await client.query("DELETE FROM tokens WHERE id = $1", [tokenId]);
    }
    await client.end();
    await TestUtils.cleanupTestUser(viewer.email, viewerCookie);
    await TestUtils.cleanupTestUser(outsider.email, outsiderCookie);
    await TestUtils.cleanupTestUser(admin.email, adminCookie);
  });

  it("returns empty items when no deferred alerts exist", async () => {
    const res = await fetchNotifications(adminCookie).expect(200);
    expect(res.body).to.have.property("items");
    expect(res.body.items).to.be.an("array").that.is.empty;
  });

  it("returns alerts-out-of-window for admin when pending OUT_OF_WINDOW alerts exist", async () => {
    alertKey = `test-out-of-window-${Date.now()}`;
    const tokenRes = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, name, type, expiration, created_by)
       VALUES ($1, $2, $3, $4, CURRENT_DATE + INTERVAL '7 days', $5)
       RETURNING id`,
      [adminUserId, workspaceId, "Notification Test Token", "ssl_cert", adminUserId],
    );
    tokenId = tokenRes.rows[0].id;

    await client.query(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status, error_message)
       VALUES ($1, $2, $3, $4, CURRENT_DATE, $5::jsonb, 'pending', 'OUT_OF_WINDOW')`,
      [adminUserId, tokenId, alertKey, 7, JSON.stringify(["email"])],
    );

    const res = await fetchNotifications(adminCookie).expect(200);
    expect(res.body.items).to.have.length(1);
    const item = res.body.items[0];
    expect(item.id).to.equal("alerts-out-of-window");
    expect(item.kind).to.equal("info");
    expect(item.text).to.equal("1 alert waiting for delivery window");
    expect(item.href).to.equal("/control-center");
    expect(item.count).to.equal(1);
  });

  it("uses plural copy for multiple deferred alerts", async () => {
    const secondKey = `${alertKey}-second`;
    await client.query(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status, error_message)
       VALUES ($1, $2, $3, $4, CURRENT_DATE, $5::jsonb, 'pending', 'OUT_OF_WINDOW')`,
      [adminUserId, tokenId, secondKey, 1, JSON.stringify(["email"])],
    );

    const res = await fetchNotifications(adminCookie).expect(200);
    expect(res.body.items).to.have.length(1);
    expect(res.body.items[0].text).to.equal(
      "2 alerts waiting for delivery window",
    );
    expect(res.body.items[0].count).to.equal(2);

    await client.query("DELETE FROM alert_queue WHERE alert_key = $1", [
      secondKey,
    ]);
  });

  it("hides deferred alerts from viewers", async () => {
    const res = await fetchNotifications(viewerCookie).expect(200);
    expect(res.body.items).to.be.an("array").that.is.empty;
  });

  it("requires authentication", async () => {
    await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/notifications`)
      .expect(401);
  });

  it("requires workspace membership", async () => {
    await fetchNotifications(outsiderCookie, workspaceId).expect(403);
  });
});
