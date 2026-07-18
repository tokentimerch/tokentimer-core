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

describe("Persisted operational notifications (bell)", function () {
  this.timeout(120000);

  let admin;
  let adminCookie;
  let adminUserId;
  let viewer;
  let viewerCookie;
  let workspaceId;
  let client;
  let tokenId;
  let notifId;
  let autoSyncNotifId;

  function fetchNotifications(cookie, wsId = workspaceId) {
    return request(BASE)
      .get(`/api/v1/workspaces/${wsId}/notifications`)
      .set("Cookie", cookie);
  }

  function markRead(cookie, id, wsId = workspaceId) {
    return request(BASE)
      .post(`/api/v1/workspaces/${wsId}/notifications/${id}/read`)
      .set("Cookie", cookie);
  }

  function markAllRead(cookie, wsId = workspaceId) {
    return request(BASE)
      .post(`/api/v1/workspaces/${wsId}/notifications/read-all`)
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
      "Persisted Notifications WS",
    );

    viewer = await TestUtils.createAuthenticatedUser();
    viewerCookie = viewer.cookie;
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'viewer', $3)
       ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'viewer'`,
      [viewer.id || viewer.user?.id, workspaceId, adminUserId],
    );

    const tokenRes = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, name, type, expiration, created_by)
       VALUES ($1, $2, $3, $4, CURRENT_DATE + INTERVAL '7 days', $5)
       RETURNING id`,
      [
        adminUserId,
        workspaceId,
        "Persisted Notification Token",
        "ssl_cert",
        adminUserId,
      ],
    );
    tokenId = tokenRes.rows[0].id;
  });

  after(async () => {
    if (tokenId) {
      await client.query(
        "DELETE FROM operational_notifications WHERE token_id = $1",
        [tokenId],
      );
      await client.query("DELETE FROM tokens WHERE id = $1", [tokenId]);
    }
    if (autoSyncNotifId) {
      await client.query("DELETE FROM operational_notifications WHERE id = $1", [
        autoSyncNotifId,
      ]);
    }
    await client.end();
    await TestUtils.cleanupTestUser(viewer.email, viewerCookie);
    await TestUtils.cleanupTestUser(admin.email, adminCookie);
  });

  it("surfaces an unresolved critical delivery notification with unreadCount", async () => {
    const insertRes = await client.query(
      `INSERT INTO operational_notifications
         (workspace_id, token_id, category, type, severity, dedupe_key, title, message, metadata)
       VALUES ($1,$2,'delivery','delivery_blocked','critical',$3,$4,$5,$6::jsonb)
       RETURNING id`,
      [
        workspaceId,
        tokenId,
        `delivery_blocked:test-${Date.now()}`,
        "Delivery blocked: Persisted Notification Token",
        "Maximum delivery attempts reached",
        JSON.stringify({ workspace_name: "Persisted Notifications WS" }),
      ],
    );
    notifId = insertRes.rows[0].id;

    const res = await fetchNotifications(adminCookie).expect(200);
    expect(res.body).to.have.property("unreadCount");
    const item = res.body.items.find((it) => it.id === notifId);
    expect(item).to.exist;
    expect(item.kind).to.equal("error");
    expect(item.text).to.equal("Delivery blocked: Persisted Notification Token");
    expect(item.href).to.equal("/control-center");
    expect(item.isRead).to.equal(false);
    expect(item.persisted).to.equal(true);
    expect(res.body.unreadCount).to.be.at.least(1);
  });

  it("routes auto_sync notifications to the import panel href", async () => {
    const insertRes = await client.query(
      `INSERT INTO operational_notifications
         (workspace_id, token_id, category, type, severity, dedupe_key, title, message, metadata)
       VALUES ($1, NULL, 'auto_sync','auto_sync_failed','warning',$2,$3,$4,$5::jsonb)
       RETURNING id`,
      [
        workspaceId,
        `auto_sync_failed:test-${Date.now()}`,
        "Auto-sync failed: github",
        "Auto-sync run failed",
        JSON.stringify({ provider: "github" }),
      ],
    );
    autoSyncNotifId = insertRes.rows[0].id;

    const res = await fetchNotifications(adminCookie).expect(200);
    const item = res.body.items.find((it) => it.id === autoSyncNotifId);
    expect(item).to.exist;
    expect(item.kind).to.equal("warning");
    expect(item.href).to.equal("/dashboard?import=github&autoSyncManage=1");
  });

  it("marking a single notification as read only affects that user's view", async () => {
    await markRead(adminCookie, notifId).expect(200);

    const adminRes = await fetchNotifications(adminCookie).expect(200);
    const adminItem = adminRes.body.items.find((it) => it.id === notifId);
    expect(adminItem.isRead).to.equal(true);

    const viewerRes = await fetchNotifications(viewerCookie).expect(200);
    const viewerItem = viewerRes.body.items.find((it) => it.id === notifId);
    // Viewer is not privileged and the notification is token-scoped to the
    // admin's own token, so a non-privileged non-owner should not see it.
    expect(viewerItem).to.be.undefined;
  });

  it("404s when a non-privileged, non-owner member tries to mark a token-scoped notification as read", async () => {
    // notifId is token-scoped to the admin's own token; the viewer role is
    // neither privileged nor the token owner, so it must not be able to
    // mark it as read even by guessing/observing the id out-of-band.
    await markRead(viewerCookie, notifId).expect(404);
  });

  it("404s when marking a notification from a different workspace as read", async () => {
    const otherWorkspaceId = await TestUtils.ensureDedicatedTestWorkspace(
      adminCookie,
      "Other WS For Notif 404",
    );
    await markRead(adminCookie, notifId, otherWorkspaceId).expect(404);
  });

  it("mark-all-as-read clears unreadCount for the acting user", async () => {
    const before = await fetchNotifications(adminCookie).expect(200);
    expect(before.body.unreadCount).to.be.at.least(1);

    await markAllRead(adminCookie).expect(200);

    const after = await fetchNotifications(adminCookie).expect(200);
    expect(after.body.unreadCount).to.equal(0);
    for (const item of after.body.items) {
      if (item.persisted) expect(item.isRead).to.equal(true);
    }
  });

  it("resolving the underlying incident removes it from the bell", async () => {
    await client.query(
      `UPDATE operational_notifications SET resolved_at = NOW() WHERE id = $1`,
      [notifId],
    );
    const res = await fetchNotifications(adminCookie).expect(200);
    const item = res.body.items.find((it) => it.id === notifId);
    expect(item).to.be.undefined;
  });

  it("requires workspace membership to mark-all-as-read", async () => {
    const outsider = await TestUtils.createAuthenticatedUser();
    try {
      await markAllRead(outsider.cookie).expect(403);
    } finally {
      await TestUtils.cleanupTestUser(outsider.email, outsider.cookie);
    }
  });
});
