const { expect, TestEnvironment, TestUtils } = require("./setup");

const parseChannelList = (value) => {
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return String(value)
      .split(/[\s,]+/)
      .filter(Boolean);
  }
};

describe("Channel Selection", function () {
  this.timeout(60000);

  const createdUserIds = [];
  const createdWorkspaceIds = [];

  before(async () => {
    await TestEnvironment.setup();
  });

  after(async () => {
    try {
      // Clean up all test data
      for (const wsId of createdWorkspaceIds) {
        await TestUtils.execQuery(
          `DELETE FROM alert_delivery_log WHERE token_id IN (SELECT id FROM tokens WHERE workspace_id = $1)`,
          [wsId],
        );
        await TestUtils.execQuery(
          `DELETE FROM alert_queue WHERE workspace_id = $1`,
          [wsId],
        );
        await TestUtils.execQuery(
          `DELETE FROM audit_events WHERE target_id IN (SELECT id FROM tokens WHERE workspace_id = $1)`,
          [wsId],
        );
        await TestUtils.execQuery(
          `DELETE FROM tokens WHERE workspace_id = $1`,
          [wsId],
        );
        await TestUtils.execQuery(
          `DELETE FROM workspace_contacts WHERE workspace_id = $1`,
          [wsId],
        );
        await TestUtils.execQuery(
          `DELETE FROM workspace_settings WHERE workspace_id = $1`,
          [wsId],
        );
        await TestUtils.execQuery(
          `DELETE FROM workspace_memberships WHERE workspace_id = $1`,
          [wsId],
        );
        await TestUtils.execQuery(`DELETE FROM workspaces WHERE id = $1`, [
          wsId,
        ]);
      }
      for (const userId of createdUserIds) {
        await TestUtils.execQuery(
          `DELETE FROM alert_queue WHERE user_id = $1`,
          [userId],
        );
        await TestUtils.execQuery(`DELETE FROM tokens WHERE user_id = $1`, [
          userId,
        ]);
        await TestUtils.execQuery(`DELETE FROM users WHERE id = $1`, [userId]);
      }
    } catch (err) {
      // Log but don't fail cleanup
      console.error("Cleanup error:", err.message);
    }
  });

  it("Email included only when a contact group defines recipients", async () => {
    const u = await TestUtils.createAuthenticatedUser();
    const user = u.user;
    createdUserIds.push(user.id);

    // Ensure workspace and settings with no email recipients
    const wsId = require("crypto").randomUUID();
    createdWorkspaceIds.push(wsId);
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,'oss',$3)`,
      [wsId, `WS ${user.id}`, user.id],
    );
    await TestUtils.execQuery(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1,$2,'admin',$1)`,
      [user.id, wsId],
    );
    await TestUtils.execQuery(
      `INSERT INTO workspace_settings (workspace_id, email_alerts_enabled, contact_groups, default_contact_group_id)
       VALUES ($1, TRUE, $2, 'admins')
       ON CONFLICT (workspace_id) DO UPDATE SET email_alerts_enabled=EXCLUDED.email_alerts_enabled, contact_groups=EXCLUDED.contact_groups, default_contact_group_id=EXCLUDED.default_contact_group_id`,
      [
        wsId,
        JSON.stringify([
          { id: "admins", name: "Admins", email_contact_ids: [] },
        ]),
      ],
    );
    await TestUtils.execQuery(
      `UPDATE workspace_settings
         SET delivery_window_start='00:00', delivery_window_end='23:59', delivery_window_tz='UTC'
       WHERE workspace_id=$1`,
      [wsId],
    );

    const expiry = new Date();
    expiry.setDate(expiry.getDate() + 7);
    const expiration = expiry.toISOString().slice(0, 10);

    const missingToken = await TestUtils.execQuery(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1,$2,$1,$3,$4,'api_key','general') RETURNING id`,
      [user.id, wsId, "Email Missing Contacts", expiration],
    );
    const missingTokenId = missingToken.rows[0].id;
    await TestUtils.execQuery(
      `UPDATE tokens SET contact_group_id='admins' WHERE id=$1`,
      [missingTokenId],
    );

    await TestUtils.runNode(
      "node",
      ["src/queue-manager.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );
    await TestUtils.runNode(
      "node",
      ["src/delivery-worker.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );

    const missingQueue = await TestUtils.execQuery(
      `SELECT status, error_message FROM alert_queue WHERE token_id=$1 ORDER BY id DESC LIMIT 1`,
      [missingTokenId],
    );
    // New behavior: discovery doesn't queue alerts with no eligible channels
    expect(missingQueue.rowCount).to.equal(0);

    // Verify audit event was written instead
    const auditRes = await TestUtils.execQuery(
      `SELECT action, metadata FROM audit_events WHERE target_id=$1 AND action='ALERT_NOT_QUEUED_NO_CHANNEL' ORDER BY occurred_at DESC LIMIT 1`,
      [missingTokenId],
    );
    expect(auditRes.rowCount).to.equal(1);

    await TestUtils.execQuery(`DELETE FROM alert_queue WHERE token_id=$1`, [
      missingTokenId,
    ]);
    await TestUtils.execQuery(`DELETE FROM tokens WHERE id=$1`, [
      missingTokenId,
    ]);

    // Reset contact groups and settings before positive case
    await TestUtils.execQuery(
      `UPDATE workspace_settings
         SET contact_groups = $2,
             email_alerts_enabled = TRUE
       WHERE workspace_id = $1`,
      [
        wsId,
        JSON.stringify([
          { id: "admins", name: "Admins", email_contact_ids: [] },
        ]),
      ],
    );

    // Positive case: add an email contact and enable recipients
    const contactInsert = await TestUtils.execQuery(
      `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, details, created_by)
       VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [
        wsId,
        "Alert",
        "Recipient",
        JSON.stringify({ email: "alerts@example.com" }),
        user.id,
      ],
    );
    const contactId = contactInsert.rows?.[0]?.id;
    expect(contactId, "contact id").to.exist;

    await TestUtils.execQuery(
      `UPDATE workspace_settings
         SET contact_groups=$2,
             email_alerts_enabled=TRUE
       WHERE workspace_id=$1`,
      [
        wsId,
        JSON.stringify([
          {
            id: "admins",
            name: "Admins",
            email_contact_ids: [String(contactId)],
          },
        ]),
      ],
    );

    const tokenWithRecipients = await TestUtils.execQuery(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1,$2,$1,$3,$4,'api_key','general') RETURNING id`,
      [user.id, wsId, "Email With Contacts", expiration],
    );
    const tokenWithRecipientsId = tokenWithRecipients.rows[0].id;
    await TestUtils.execQuery(
      `UPDATE tokens SET contact_group_id='admins' WHERE id=$1`,
      [tokenWithRecipientsId],
    );

    await TestUtils.runNode(
      "node",
      ["src/queue-manager.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );
    await TestUtils.runNode(
      "node",
      ["src/delivery-worker.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );

    // Wait a moment for delivery log to be written
    await TestUtils.wait(500);

    const deliveryLog = await TestUtils.execQuery(
      `SELECT channel, status FROM alert_delivery_log WHERE token_id=$1`,
      [tokenWithRecipientsId],
    );
    const emailDeliveries = (deliveryLog.rows || []).filter(
      (row) => row.channel === "email" && row.status === "success",
    );
    expect(emailDeliveries.length).to.equal(1);
  });

  it("Webhooks included on OSS plan when a group selects webhook name(s)", async () => {
    const u = await TestUtils.createAuthenticatedUser();
    createdUserIds.push(u.user.id);

    const wsId = require("crypto").randomUUID();
    createdWorkspaceIds.push(wsId);
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,'oss',$3)`,
      [wsId, `WS Webhook ${u.user.id}`, u.user.id],
    );
    await TestUtils.execQuery(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1,$2,'admin',$1)`,
      [u.user.id, wsId],
    );

    const contactRes = await TestUtils.execQuery(
      `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, details, created_by)
       VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [
        wsId,
        "Ops",
        "Admin",
        JSON.stringify({ email: "ops@example.com" }),
        u.user.id,
      ],
    );
    const contactId = contactRes.rows[0].id;

    await TestUtils.execQuery(
      `INSERT INTO workspace_settings (workspace_id, webhooks_alerts_enabled, webhook_urls, email_alerts_enabled, contact_groups, default_contact_group_id)
       VALUES ($1, TRUE, $2, TRUE, $3, 'admins')
       ON CONFLICT (workspace_id) DO UPDATE SET webhooks_alerts_enabled=EXCLUDED.webhooks_alerts_enabled, webhook_urls=EXCLUDED.webhook_urls, email_alerts_enabled=EXCLUDED.email_alerts_enabled, contact_groups=EXCLUDED.contact_groups, default_contact_group_id=EXCLUDED.default_contact_group_id`,
      [
        wsId,
        JSON.stringify([
          {
            name: "Discord",
            kind: "discord",
            url: "https://discord.com/api/webhooks/test",
          },
        ]),
        JSON.stringify([
          {
            id: "admins",
            name: "Admins",
            email_contact_ids: [String(contactId)],
            webhook_names: ["Discord"],
          },
        ]),
      ],
    );
    await TestUtils.execQuery(
      `UPDATE workspace_settings
         SET delivery_window_start='00:00', delivery_window_end='23:59', delivery_window_tz='UTC'
       WHERE workspace_id=$1`,
      [wsId],
    );

    const expiry = new Date();
    expiry.setDate(expiry.getDate() + 7);
    await TestUtils.execQuery(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category) VALUES ($1,$2,$1,$3,$4,'api_key','general')`,
      [u.user.id, wsId, "OSS Webhooks", expiry.toISOString().slice(0, 10)],
    );

    await TestUtils.runNode(
      "node",
      ["src/queue-manager.js"],
      "apps/worker",
      process.env,
      {
        allowExitCodes: [0, 1],
      },
    );

    const res = await TestUtils.execQuery(
      `SELECT channels FROM alert_queue WHERE user_id=$1`,
      [u.user.id],
    );

    expect(res.rowCount).to.equal(1);
    expect(parseChannelList(res.rows[0].channels)).to.include("webhooks");
  });
});
