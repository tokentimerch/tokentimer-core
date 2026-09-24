const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");
const {
  raiseOperationalNotification,
} = require("../../apps/api/services/operationalNotifications");

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
      [
        adminUserId,
        workspaceId,
        "Notification Test Token",
        "ssl_cert",
        adminUserId,
      ],
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
  let viewerUserId;
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
    viewerUserId = viewer.id || viewer.user?.id;
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'viewer', $3)
       ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'viewer'`,
      [viewerUserId, workspaceId, adminUserId],
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
      await client.query(
        "DELETE FROM operational_notifications WHERE id = $1",
        [autoSyncNotifId],
      );
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
    expect(item.text).to.equal(
      "Delivery blocked: Persisted Notification Token",
    );
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

  it("links a persisted auto-sync incident to its exact config and current workspace", async () => {
    const configId = "cfg/one two";
    const inserted = await client.query(
      `INSERT INTO operational_notifications
         (workspace_id, category, type, severity, dedupe_key, title, metadata)
       VALUES ($1, 'auto_sync', 'auto_sync_failed', 'warning', $2,
               'Exact GitLab config', $3::jsonb)
       RETURNING id`,
      [
        workspaceId,
        `auto_sync_failed:href-${Date.now()}`,
        JSON.stringify({
          provider: "gitlab",
          auto_sync_config_id: configId,
          workspace_id: "stale-workspace-id",
        }),
      ],
    );
    try {
      const res = await fetchNotifications(adminCookie).expect(200);
      const item = res.body.items.find((row) => row.id === inserted.rows[0].id);
      expect(item.href).to.equal(
        `/dashboard?import=gitlab&autoSyncManage=1&autoSyncConfigId=cfg%2Fone%20two&workspace=${encodeURIComponent(workspaceId)}`,
      );
    } finally {
      await client.query(
        "DELETE FROM operational_notifications WHERE id = $1",
        [inserted.rows[0].id],
      );
    }
  });

  it("deduplicates computed auto-sync failures by config with a legacy provider fallback", async () => {
    const config = await client.query(
      `INSERT INTO auto_sync_configs
         (workspace_id, provider, credentials_encrypted, frequency, enabled,
          last_sync_status, last_sync_error, created_by)
       VALUES ($1, 'gitlab', 'fixture', 'daily', TRUE, 'failed', 'Timeout', $2)
       RETURNING id`,
      [workspaceId, adminUserId],
    );
    const computedConfigId = config.rows[0].id;
    const incidentIds = [];
    const insertIncident = async (configId) => {
      const inserted = await client.query(
        `INSERT INTO operational_notifications
           (workspace_id, category, type, severity, dedupe_key, title, metadata)
         VALUES ($1, 'auto_sync', 'auto_sync_failed', 'warning', $2,
                 'GitLab config incident', $3::jsonb)
         RETURNING id`,
        [
          workspaceId,
          `auto_sync_failed:dedupe-${Date.now()}-${incidentIds.length}`,
          JSON.stringify({
            provider: "gitlab",
            ...(configId ? { auto_sync_config_id: configId } : {}),
          }),
        ],
      );
      incidentIds.push(inserted.rows[0].id);
      return inserted.rows[0].id;
    };
    try {
      const otherIncidentId = await insertIncident(
        "11111111-1111-4111-8111-111111111111",
      );
      let res = await fetchNotifications(adminCookie).expect(200);
      expect(
        res.body.items.some((item) => item.id === otherIncidentId),
      ).to.equal(true);
      const computed = res.body.items.find(
        (item) => item.id === `auto-sync-failed-${computedConfigId}`,
      );
      expect(computed.href).to.equal(
        `/dashboard?import=gitlab&autoSyncManage=1&autoSyncConfigId=${computedConfigId}&workspace=${workspaceId}`,
      );

      const matchingIncidentId = await insertIncident(computedConfigId);
      res = await fetchNotifications(adminCookie).expect(200);
      expect(
        res.body.items.some((item) => item.id === otherIncidentId),
      ).to.equal(true);
      expect(
        res.body.items.some((item) => item.id === matchingIncidentId),
      ).to.equal(true);
      expect(
        res.body.items.some(
          (item) => item.id === `auto-sync-failed-${computedConfigId}`,
        ),
      ).to.equal(false);

      await client.query(
        "DELETE FROM operational_notifications WHERE id = $1",
        [matchingIncidentId],
      );
      const legacyIncidentId = await insertIncident(null);
      res = await fetchNotifications(adminCookie).expect(200);
      expect(
        res.body.items.some((item) => item.id === legacyIncidentId),
      ).to.equal(true);
      expect(
        res.body.items.some(
          (item) => item.id === `auto-sync-failed-${computedConfigId}`,
        ),
      ).to.equal(false);
    } finally {
      await client.query(
        "DELETE FROM operational_notifications WHERE id = ANY($1::uuid[])",
        [incidentIds],
      );
      await client.query("DELETE FROM auto_sync_configs WHERE id = $1", [
        computedConfigId,
      ]);
    }
  });

  it("restricts workspace-level incidents to managers while retaining owner-scoped delivery incidents", async () => {
    await client.query(
      "UPDATE workspace_memberships SET role = 'workspace_manager' WHERE workspace_id = $1 AND user_id = $2",
      [workspaceId, viewerUserId],
    );
    try {
      const managerRes = await fetchNotifications(viewerCookie).expect(200);
      expect(
        managerRes.body.items.some((item) => item.id === autoSyncNotifId),
      ).to.equal(true);
      expect(
        managerRes.body.items.some((item) => item.id === notifId),
      ).to.equal(true);
    } finally {
      await client.query(
        "UPDATE workspace_memberships SET role = 'viewer' WHERE workspace_id = $1 AND user_id = $2",
        [workspaceId, viewerUserId],
      );
    }

    const ownerToken = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, name, type, expiration, created_by)
       VALUES ($1, $2, 'Viewer-owned notification token', 'ssl_cert',
               CURRENT_DATE + INTERVAL '7 days', $1)
       RETURNING id`,
      [viewerUserId, workspaceId],
    );
    const ownerTokenId = ownerToken.rows[0].id;
    try {
      const ownerIncident = await client.query(
        `INSERT INTO operational_notifications
           (workspace_id, token_id, category, type, severity, dedupe_key, title)
         VALUES ($1, $2, 'delivery', 'delivery_blocked', 'critical', $3, 'Owner delivery blocked')
         RETURNING id`,
        [workspaceId, ownerTokenId, `owner-delivery:${Date.now()}`],
      );
      const ownerIncidentId = ownerIncident.rows[0].id;
      const adminRes = await fetchNotifications(adminCookie).expect(200);
      expect(
        adminRes.body.items.some((item) => item.id === ownerIncidentId),
      ).to.equal(true);
      const viewerRes = await fetchNotifications(viewerCookie).expect(200);
      expect(
        viewerRes.body.items.some((item) => item.id === autoSyncNotifId),
      ).to.equal(false);
      const visibleOwnerIncident = viewerRes.body.items.find(
        (item) => item.id === ownerIncidentId,
      );
      expect(visibleOwnerIncident).to.exist;
      expect(visibleOwnerIncident.message).to.equal(null);
      expect(viewerRes.body.unreadCount).to.equal(1);

      await markRead(viewerCookie, autoSyncNotifId).expect(404);
      await markAllRead(viewerCookie).expect(200);
      const reads = await client.query(
        `SELECT notification_id FROM operational_notification_reads
          WHERE user_id = $1 AND notification_id = ANY($2::uuid[])`,
        [viewerUserId, [autoSyncNotifId, ownerIncidentId]],
      );
      expect(reads.rows.map((row) => row.notification_id)).to.deep.equal([
        ownerIncidentId,
      ]);
    } finally {
      await client.query(
        "DELETE FROM operational_notifications WHERE token_id = $1",
        [ownerTokenId],
      );
      await client.query("DELETE FROM tokens WHERE id = $1", [ownerTokenId]);
    }
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

  it("rejects malformed notification IDs without a database error and keeps unknown UUIDs as 404", async () => {
    const malformed = await markRead(adminCookie, "not-a-uuid").expect(400);
    expect(malformed.body.code).to.equal("VALIDATION_ERROR");
    await markRead(adminCookie, "00000000-0000-4000-8000-000000000000").expect(
      404,
    );
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

  it("makes a read warning unread on critical escalation without duplicating the incident", async () => {
    const dedupeKey = `delivery_blocked:escalation-${Date.now()}`;
    const incident = {
      workspaceId,
      tokenId,
      category: "delivery",
      type: "delivery_degraded",
      dedupeKey,
      title: "Delivery retrying",
      message: "Webhook failing",
    };
    const warningId = await raiseOperationalNotification(client, {
      ...incident,
      severity: "warning",
    });
    expect(warningId).to.be.a("string");
    await markRead(adminCookie, warningId).expect(200);
    expect(
      (await fetchNotifications(adminCookie).expect(200)).body.items.find(
        (item) => item.id === warningId,
      ).isRead,
    ).to.equal(true);

    const criticalId = await raiseOperationalNotification(client, {
      ...incident,
      severity: "critical",
      type: "delivery_blocked",
      title: "Delivery blocked",
    });
    expect(criticalId).to.equal(warningId);
    const rows = await client.query(
      "SELECT id FROM operational_notifications WHERE workspace_id = $1 AND dedupe_key = $2",
      [workspaceId, dedupeKey],
    );
    expect(rows.rowCount).to.equal(1);
    const escalated = await fetchNotifications(adminCookie).expect(200);
    const item = escalated.body.items.find((entry) => entry.id === warningId);
    expect(item.severity).to.equal("critical");
    expect(item.isRead).to.equal(false);

    await markRead(adminCookie, warningId).expect(200);
    await raiseOperationalNotification(client, {
      ...incident,
      severity: "critical",
      type: "delivery_blocked",
      title: "Delivery blocked",
    });
    const repeat = await fetchNotifications(adminCookie).expect(200);
    expect(
      repeat.body.items.find((entry) => entry.id === warningId).isRead,
    ).to.equal(true);
  });

  it("counts every visible unread incident while keeping an old escalated incident in the bounded list", async () => {
    const before = await fetchNotifications(adminCookie).expect(200);
    const viewerBefore = await fetchNotifications(viewerCookie).expect(200);
    const prefix = `limit-test:${Date.now()}`;
    try {
      const old = await client.query(
        `INSERT INTO operational_notifications
           (workspace_id, token_id, category, type, severity, dedupe_key, title,
            created_at, updated_at)
         VALUES ($1, $2, 'delivery', 'delivery_degraded', 'warning', $3,
                 'Old incident', NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days')
         RETURNING id`,
        [workspaceId, tokenId, `${prefix}:old`],
      );
      const oldId = old.rows[0].id;
      await markRead(adminCookie, oldId).expect(200);
      await client.query(
        `INSERT INTO operational_notifications
           (workspace_id, token_id, category, type, severity, dedupe_key, title,
            created_at, updated_at)
         SELECT $1, $2, 'delivery', 'delivery_degraded', 'warning',
                $3 || ':' || g, 'Recent incident ' || g,
                NOW() - INTERVAL '1 hour' + g * INTERVAL '1 second',
                NOW() - INTERVAL '1 hour' + g * INTERVAL '1 second'
           FROM generate_series(1, 55) AS g`,
        [workspaceId, tokenId, prefix],
      );
      const criticalId = await raiseOperationalNotification(client, {
        workspaceId,
        tokenId,
        category: "delivery",
        type: "delivery_blocked",
        severity: "critical",
        dedupeKey: `${prefix}:old`,
        title: "Old incident escalated",
      });
      expect(criticalId).to.equal(oldId);

      const adminRes = await fetchNotifications(adminCookie).expect(200);
      const persisted = adminRes.body.items.filter((item) => item.persisted);
      expect(persisted).to.have.length(50);
      expect(adminRes.body.unreadCount).to.equal(before.body.unreadCount + 56);
      expect(persisted[0].id).to.equal(oldId);
      expect(persisted[0].severity).to.equal("critical");
      expect(persisted[0].isRead).to.equal(false);

      const viewerRes = await fetchNotifications(viewerCookie).expect(200);
      expect(viewerRes.body.unreadCount).to.equal(
        viewerBefore.body.unreadCount,
      );
      expect(viewerRes.body.items.some((item) => item.id === oldId)).to.equal(
        false,
      );
    } finally {
      await client.query(
        "DELETE FROM operational_notifications WHERE workspace_id = $1 AND dedupe_key LIKE $2",
        [workspaceId, `${prefix}:%`],
      );
    }
  });

  it("retries an unsent critical delivery incident on a later sweep", async () => {
    const {
      sendOperationalIncidentEmail,
      retryPendingOperationalIncidentEmails,
    } = await import("../../apps/worker/src/shared/opNotifications.js");
    const title = `Retry email ${Date.now()}`;
    const result = await client.query(
      `INSERT INTO operational_notifications
         (workspace_id, token_id, category, type, severity, dedupe_key, title)
       VALUES ($1, $2, 'delivery', 'delivery_blocked', 'critical', $3, $4)
       RETURNING id`,
      [
        workspaceId,
        tokenId,
        `delivery_blocked:email-retry-${Date.now()}`,
        title,
      ],
    );
    const notificationId = result.rows[0].id;
    const incident = {
      notificationId,
      workspaceId,
      tokenId,
      category: "delivery",
      title,
    };
    await sendOperationalIncidentEmail(client, incident, async () => ({
      success: false,
      error: "SMTP down",
    }));
    const failed = await client.query(
      "SELECT email_sent_at, email_claim_id, email_claimed_at FROM operational_notifications WHERE id = $1",
      [notificationId],
    );
    expect(failed.rows[0].email_sent_at).to.equal(null);
    expect(failed.rows[0].email_claim_id).to.equal(null);
    expect(failed.rows[0].email_claimed_at).to.be.a("date");

    let sends = 0;
    await retryPendingOperationalIncidentEmails(client, async ({ subject }) => {
      if (subject.includes(title)) sends += 1;
      return { success: true };
    });
    expect(sends).to.equal(0);

    await client.query(
      "UPDATE operational_notifications SET email_claimed_at = NOW() - INTERVAL '16 minutes' WHERE id = $1",
      [notificationId],
    );
    await retryPendingOperationalIncidentEmails(client, async () => ({
      success: false,
      error: "SMTP still down",
    }));
    const retryFailed = await client.query(
      "SELECT email_sent_at, email_claim_id, email_claimed_at FROM operational_notifications WHERE id = $1",
      [notificationId],
    );
    expect(retryFailed.rows[0].email_sent_at).to.equal(null);
    expect(retryFailed.rows[0].email_claim_id).to.equal(null);
    expect(retryFailed.rows[0].email_claimed_at).to.be.a("date");

    await client.query(
      `UPDATE operational_notifications
          SET email_claim_id = '00000000-0000-4000-8000-000000000001',
              email_claimed_at = NOW() - INTERVAL '16 minutes'
        WHERE id = $1`,
      [notificationId],
    );
    const { deliveryWorkerJob } =
      await import("../../apps/worker/src/delivery-worker.js");
    await deliveryWorkerJob({
      closePool: false,
      incidentEmailSender: async ({ subject }) => {
        if (subject.includes(title)) sends += 1;
        return { success: true };
      },
    });
    expect(sends).to.be.at.least(1);

    const retried = await client.query(
      "SELECT email_sent_at, email_claim_id FROM operational_notifications WHERE id = $1",
      [notificationId],
    );
    expect(retried.rows[0].email_sent_at).to.be.a("date");
    expect(retried.rows[0].email_claim_id).to.equal(null);
  });

  it("emails only current workspace members who own the token, plus admins", async () => {
    const { sendOperationalIncidentEmail } =
      await import("../../apps/worker/src/shared/opNotifications.js");
    const matchingWorkspaceId = await TestUtils.ensureDedicatedTestWorkspace(
      adminCookie,
      "Matching incident recipients",
    );
    const otherWorkspaceId = await TestUtils.ensureDedicatedTestWorkspace(
      adminCookie,
      "Other incident recipients",
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'viewer', $3)`,
      [viewerUserId, matchingWorkspaceId, adminUserId],
    );
    const tokens = await client.query(
      `INSERT INTO tokens (user_id, workspace_id, name, type, expiration, created_by)
       VALUES ($1, $3, 'Viewer-owned recipient token', 'ssl_cert',
               CURRENT_DATE + INTERVAL '7 days', $2),
              ($2, $3, 'Admin-owned recipient token', 'ssl_cert',
               CURRENT_DATE + INTERVAL '7 days', $2)
       RETURNING id, user_id`,
      [viewerUserId, adminUserId, matchingWorkspaceId],
    );
    const viewerTokenId = tokens.rows.find(
      (row) => row.user_id === viewerUserId,
    ).id;
    const adminTokenId = tokens.rows.find(
      (row) => row.user_id === adminUserId,
    ).id;
    const incidentIds = [];
    try {
      for (const [
        incidentWorkspaceId,
        incidentTokenId,
        expected,
        removeOwner,
      ] of [
        [matchingWorkspaceId, viewerTokenId, [viewer.email, admin.email]],
        [otherWorkspaceId, viewerTokenId, [admin.email]],
        [matchingWorkspaceId, adminTokenId, [admin.email]],
        [matchingWorkspaceId, viewerTokenId, [admin.email], true],
      ]) {
        if (removeOwner) {
          await client.query(
            "DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2",
            [matchingWorkspaceId, viewerUserId],
          );
          const stillOwned = await client.query(
            "SELECT user_id FROM tokens WHERE id = $1",
            [viewerTokenId],
          );
          expect(stillOwned.rows[0].user_id).to.equal(viewerUserId);
        }
        const notification = await client.query(
          `INSERT INTO operational_notifications
             (workspace_id, token_id, category, type, severity, dedupe_key, title)
           VALUES ($1, $2, 'delivery', 'delivery_blocked', 'critical', $3,
                   'Recipient scope test') RETURNING id`,
          [
            incidentWorkspaceId,
            incidentTokenId,
            `recipient-scope:${Date.now()}:${incidentIds.length}`,
          ],
        );
        const notificationId = notification.rows[0].id;
        incidentIds.push(notificationId);
        const recipients = [];
        await sendOperationalIncidentEmail(
          client,
          {
            notificationId,
            workspaceId: incidentWorkspaceId,
            tokenId: incidentTokenId,
            category: "delivery",
            title: "Recipient scope test",
          },
          async ({ to }) => {
            recipients.push(to);
            return { success: true };
          },
        );
        expect(recipients.sort()).to.deep.equal(
          expected.map((email) => email.toLowerCase()).sort(),
        );
      }
    } finally {
      await client.query(
        "DELETE FROM operational_notifications WHERE id = ANY($1::uuid[])",
        [incidentIds],
      );
      await client.query("DELETE FROM tokens WHERE id = ANY($1::int[])", [
        tokens.rows.map((row) => row.id),
      ]);
      await client.query(
        "DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2",
        [matchingWorkspaceId, viewerUserId],
      );
    }
  });

  it("skips email failures, resolved incidents, and sent incidents while retrying auto-sync once", async () => {
    const { retryPendingOperationalIncidentEmails } =
      await import("../../apps/worker/src/shared/opNotifications.js");
    const cases = [
      {
        title: "Email recursion array",
        metadata: { failed_channels: ["webhooks", "EMAIL"] },
      },
      { title: "Email recursion channel", metadata: { channel: "email" } },
      { title: "Resolved incident", resolved: true },
      { title: "Already sent incident", sent: true },
      { title: "Auto-sync retry", category: "auto_sync" },
    ];
    const ids = new Map();
    for (const testCase of cases) {
      const result = await client.query(
        `INSERT INTO operational_notifications
           (workspace_id, token_id, category, type, severity, dedupe_key, title,
            metadata, resolved_at, email_sent_at)
         VALUES ($1, $2, $3, $4, 'critical', $5, $6, $7::jsonb, $8, $9)
         RETURNING id`,
        [
          workspaceId,
          testCase.category === "auto_sync" ? null : tokenId,
          testCase.category || "delivery",
          testCase.category === "auto_sync"
            ? "auto_sync_failed"
            : "delivery_blocked",
          `email-sweep:${testCase.title}:${Date.now()}`,
          testCase.title,
          JSON.stringify(testCase.metadata || {}),
          testCase.resolved ? new Date() : null,
          testCase.sent ? new Date() : null,
        ],
      );
      ids.set(testCase.title, result.rows[0].id);
    }

    const subjects = [];
    const sendEmail = async ({ subject }) => {
      subjects.push(subject);
      return { success: true };
    };
    await retryPendingOperationalIncidentEmails(client, sendEmail);
    await retryPendingOperationalIncidentEmails(client, sendEmail);

    expect(
      subjects.filter((subject) => subject.includes("Auto-sync retry")),
    ).to.have.length(1);
    for (const title of [
      "Email recursion array",
      "Email recursion channel",
      "Resolved incident",
      "Already sent incident",
    ]) {
      expect(subjects.some((subject) => subject.includes(title))).to.equal(
        false,
      );
    }
    const rows = await client.query(
      `SELECT id, email_sent_at, email_claimed_at
         FROM operational_notifications WHERE id = ANY($1::uuid[])`,
      [[...ids.values()]],
    );
    const byId = new Map(rows.rows.map((row) => [row.id, row]));
    expect(byId.get(ids.get("Auto-sync retry")).email_sent_at).to.be.a("date");
    for (const title of [
      "Email recursion array",
      "Email recursion channel",
      "Resolved incident",
    ]) {
      expect(byId.get(ids.get(title)).email_sent_at).to.equal(null);
      expect(byId.get(ids.get(title)).email_claimed_at).to.equal(null);
    }
  });

  it("does not double-send when two workers sweep the same critical incident", async () => {
    const { retryPendingOperationalIncidentEmails } =
      await import("../../apps/worker/src/shared/opNotifications.js");
    const title = `Concurrent retry ${Date.now()}`;
    const result = await client.query(
      `INSERT INTO operational_notifications
         (workspace_id, token_id, category, type, severity, dedupe_key, title)
       VALUES ($1, $2, 'delivery', 'delivery_blocked', 'critical', $3, $4)
       RETURNING id`,
      [
        workspaceId,
        tokenId,
        `delivery_blocked:concurrent-${Date.now()}`,
        title,
      ],
    );
    const notificationId = result.rows[0].id;
    const otherClient = new Client({
      user: process.env.DB_USER || "tokentimer",
      host: process.env.DB_HOST || "localhost",
      database: process.env.DB_NAME || "tokentimer",
      password: process.env.DB_PASSWORD || "password",
      port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
      ssl: false,
    });
    await otherClient.connect();
    let targetSends = 0;
    const sendEmail = async ({ subject }) => {
      if (subject.includes(title)) {
        targetSends += 1;
        await new Promise((resolve) => setTimeout(resolve, 30));
      }
      return { success: true };
    };
    try {
      await Promise.all([
        retryPendingOperationalIncidentEmails(client, sendEmail),
        retryPendingOperationalIncidentEmails(otherClient, sendEmail),
      ]);
    } finally {
      await otherClient.end();
    }
    expect(targetSends).to.equal(1);
    const sent = await client.query(
      "SELECT email_sent_at FROM operational_notifications WHERE id = $1",
      [notificationId],
    );
    expect(sent.rows[0].email_sent_at).to.be.a("date");
  });

  it("does not exceed the workspace email cap when different incidents send concurrently", async () => {
    const capWorkspaceId = await TestUtils.ensureDedicatedTestWorkspace(
      adminCookie,
      "Concurrent incident cap",
    );
    const inserted = await client.query(
      `INSERT INTO operational_notifications
         (workspace_id, category, type, severity, dedupe_key, title)
       VALUES ($1, 'auto_sync', 'auto_sync_failed', 'critical', $2, 'Concurrent cap A'),
              ($1, 'auto_sync', 'auto_sync_failed', 'critical', $3, 'Concurrent cap B')
       RETURNING id, title`,
      [capWorkspaceId, `cap:a:${Date.now()}`, `cap:b:${Date.now()}`],
    );
    const otherClient = new Client({
      user: process.env.DB_USER || "tokentimer",
      host: process.env.DB_HOST || "localhost",
      database: process.env.DB_NAME || "tokentimer",
      password: process.env.DB_PASSWORD || "password",
      port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
      ssl: false,
    });
    await otherClient.connect();
    const previousCap = process.env.OP_NOTIFICATION_EMAIL_DAILY_CAP;
    process.env.OP_NOTIFICATION_EMAIL_DAILY_CAP = "1";
    const { sendOperationalIncidentEmail } = await import(
      `../../apps/worker/src/shared/opNotifications.js?cap-concurrent=${Date.now()}`
    );
    let sends = 0;
    const sendEmail = async () => {
      sends += 1;
      await new Promise((resolve) => setTimeout(resolve, 100));
      return { success: true };
    };
    try {
      await Promise.all(
        inserted.rows.map((row, index) =>
          sendOperationalIncidentEmail(
            index === 0 ? client : otherClient,
            {
              notificationId: row.id,
              workspaceId: capWorkspaceId,
              category: "auto_sync",
              title: row.title,
            },
            sendEmail,
          ),
        ),
      );
      const rows = await client.query(
        `SELECT email_sent_at, email_claim_id, email_claimed_at
           FROM operational_notifications WHERE id = ANY($1::uuid[])`,
        [inserted.rows.map((row) => row.id)],
      );
      expect(sends).to.equal(1);
      expect(
        rows.rows.filter((row) => row.email_sent_at !== null),
      ).to.have.length(1);
      expect(
        rows.rows.filter((row) => row.email_sent_at === null),
      ).to.have.length(1);
      expect(rows.rows.every((row) => row.email_claim_id === null)).to.equal(
        true,
      );
      expect(
        rows.rows.find((row) => row.email_sent_at === null).email_claimed_at,
      ).to.be.a("date");
    } finally {
      if (previousCap === undefined)
        delete process.env.OP_NOTIFICATION_EMAIL_DAILY_CAP;
      else process.env.OP_NOTIFICATION_EMAIL_DAILY_CAP = previousCap;
      await otherClient.end();
      await client.query(
        "DELETE FROM operational_notifications WHERE id = ANY($1::uuid[])",
        [inserted.rows.map((row) => row.id)],
      );
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
    await markRead(adminCookie, notifId).expect(404);
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
