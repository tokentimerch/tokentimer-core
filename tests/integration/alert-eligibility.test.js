const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const DAY_MS = 86400000;

function utcDate(offsetDays = 0) {
  const now = new Date();
  const today = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
  );
  return new Date(today + offsetDays * DAY_MS).toISOString().slice(0, 10);
}

describe("Alert eligibility API and queue discovery parity", function () {
  this.timeout(60000);

  let account;
  let viewer;
  let workspaceId;
  const tokenIds = [];
  const fixtures = {};

  async function insertToken(name, expirationOffset, options = {}) {
    const result = await TestUtils.execQuery(
      `INSERT INTO tokens (
         user_id, workspace_id, created_by, name, expiration, imported_at,
         type, category, contact_group_id, cert_lifecycle_status
       ) VALUES ($1, $2, $1, $3, $4, $5, 'api_key', $6, $7, $8)
       RETURNING id`,
      [
        account.user.id,
        workspaceId,
        name,
        utcDate(expirationOffset),
        options.importedAt || null,
        options.category || "general",
        options.contactGroupId || null,
        options.certLifecycleStatus || null,
      ],
    );
    const id = result.rows[0].id;
    tokenIds.push(id);
    const membershipIds = Object.prototype.hasOwnProperty.call(
      options,
      "assignedGroupIds",
    )
      ? options.assignedGroupIds
      : options.contactGroupId
        ? [options.contactGroupId]
        : [];
    for (const groupId of membershipIds) {
      await TestUtils.execQuery(
        `INSERT INTO token_contact_groups (token_id, workspace_id, contact_group_id)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING`,
        [id, workspaceId, groupId],
      );
    }
    return id;
  }

  async function loadStates(cookie = account.cookie) {
    const response = await request(BASE)
      .get("/api/tokens")
      .query({ workspace_id: workspaceId, limit: 100 })
      .set("Cookie", cookie)
      .expect(200);
    return new Map(
      response.body.items
        .filter((token) => tokenIds.includes(token.id))
        .map((token) => [token.id, token.alert_state]),
    );
  }

  before(async () => {
    await TestEnvironment.setup();
    account = await TestUtils.createAuthenticatedUser();
    workspaceId = await TestUtils.ensureTestWorkspace(account.cookie);

    await TestUtils.execQuery(
      `INSERT INTO workspace_settings (
         workspace_id, alert_thresholds, email_alerts_enabled,
         contact_groups, default_contact_group_id, webhook_urls
       ) VALUES ($1, $2::jsonb, TRUE, $3::jsonb, 'ops', '[]'::jsonb)
       ON CONFLICT (workspace_id) DO UPDATE SET
         alert_thresholds = EXCLUDED.alert_thresholds,
         email_alerts_enabled = TRUE,
         contact_groups = EXCLUDED.contact_groups,
         default_contact_group_id = 'ops',
         webhook_urls = '[]'::jsonb`,
      [
        workspaceId,
        JSON.stringify([7, 0, -2]),
        JSON.stringify([
          { id: "ops", name: "Operations", email_contact_ids: ["c1"] },
          {
            id: "no-post",
            name: "No post-expiry",
            email_contact_ids: ["c1"],
            thresholds: [7, 0],
          },
          { id: "empty", name: "Empty", thresholds: [7, 0, -2] },
          {
            id: "a",
            name: "Group A",
            email_contact_ids: ["c1"],
            thresholds: [7, 1],
          },
          {
            id: "z",
            name: "Group Z",
            email_contact_ids: ["c1"],
            thresholds: [30, 14],
          },
          {
            id: "c",
            name: "Group C",
            email_contact_ids: ["c1"],
            thresholds: [30, 14],
          },
        ]),
      ],
    );
  });

  after(async () => {
    if (tokenIds.length > 0) {
      await TestUtils.execQuery(
        "DELETE FROM alert_delivery_log WHERE token_id = ANY($1::int[])",
        [tokenIds],
      );
      await TestUtils.execQuery(
        "DELETE FROM alert_queue WHERE token_id = ANY($1::int[])",
        [tokenIds],
      );
      await TestUtils.execQuery(
        "DELETE FROM audit_events WHERE target_id = ANY($1::int[])",
        [tokenIds],
      );
      await TestUtils.execQuery(
        "DELETE FROM tokens WHERE id = ANY($1::int[])",
        [tokenIds],
      );
    }
    if (viewer) {
      await TestUtils.cleanupTestUser(viewer.user.email, viewer.cookie);
    }
    if (account) {
      await TestUtils.cleanupTestUser(account.user.email, account.cookie);
    }
  });

  it("reports the same threshold, import, retirement, and channel decisions used by discovery", async () => {
    const dueBeforeThreshold = await insertToken("Due before import", 7, {
      importedAt: utcDate(-1),
    });
    const staleAfterThreshold = await insertToken("Stale after threshold", 5, {
      importedAt: utcDate(0),
    });
    const expiryDay = await insertToken("Expiry day", 0, {
      importedAt: utcDate(0),
    });
    const beforeNegativeThreshold = await insertToken(
      "Before negative threshold",
      -1,
      { importedAt: utcDate(-1) },
    );
    const negativeThresholdDue = await insertToken("Negative threshold due", -2, {
      importedAt: utcDate(-3),
    });
    const expiredAtImport = await insertToken("Expired at import", -1, {
      importedAt: utcDate(0),
      contactGroupId: "no-post",
    });
    const retired = await insertToken("Retired certificate", 0, {
      importedAt: utcDate(-1),
      category: "cert",
      certLifecycleStatus: "revoked",
    });
    const noChannels = await insertToken("No eligible channels", 0, {
      importedAt: utcDate(-1),
      contactGroupId: "empty",
    });
    Object.assign(fixtures, { dueBeforeThreshold, expiryDay });

    const beforeDiscovery = await loadStates();
    expect(beforeDiscovery.get(dueBeforeThreshold).eligibility).to.include({
      status: "due",
      reason: "threshold_reached",
      effective_threshold: 7,
    });
    expect(beforeDiscovery.get(staleAfterThreshold).eligibility).to.include({
      status: "suppressed",
      reason: "stale_import_threshold",
      effective_threshold: 7,
    });
    expect(beforeDiscovery.get(expiryDay).eligibility).to.include({
      status: "due",
      effective_threshold: 0,
      threshold_type: "expiry_day",
    });
    expect(beforeDiscovery.get(beforeNegativeThreshold).eligibility).to.include({
      status: "outside_threshold",
      next_threshold: -2,
    });
    expect(beforeDiscovery.get(negativeThresholdDue).eligibility).to.include({
      status: "due",
      effective_threshold: -2,
      threshold_type: "post_expiry",
    });
    expect(beforeDiscovery.get(expiredAtImport).eligibility).to.include({
      status: "outside_threshold",
      reason: "post_expiry_threshold_not_configured",
    });
    expect(
      beforeDiscovery.get(expiredAtImport).eligibility.metadata.expired_at_import,
    ).to.equal(true);
    expect(beforeDiscovery.get(retired).eligibility).to.include({
      status: "suppressed",
      reason: "retired_certificate",
    });
    expect(beforeDiscovery.get(noChannels).eligibility).to.include({
      status: "suppressed",
      reason: "no_eligible_channels",
    });

    await TestUtils.runNode("node", ["src/queue-manager.js"], "apps/worker");

    const queued = await TestUtils.execQuery(
      `SELECT token_id, threshold_days, status
       FROM alert_queue
       WHERE token_id = ANY($1::int[])
       ORDER BY token_id`,
      [tokenIds],
    );
    const queuedByToken = new Map(
      queued.rows.map((row) => [row.token_id, row]),
    );
    expect([...queuedByToken.keys()].sort((a, b) => a - b)).to.deep.equal(
      [dueBeforeThreshold, expiryDay, negativeThresholdDue].sort(
        (a, b) => a - b,
      ),
    );
    expect(queuedByToken.get(dueBeforeThreshold).threshold_days).to.equal(7);
    expect(queuedByToken.get(expiryDay).threshold_days).to.equal(0);
    expect(queuedByToken.get(negativeThresholdDue).threshold_days).to.equal(-2);

    const afterDiscovery = await loadStates();
    expect(afterDiscovery.get(dueBeforeThreshold).eligibility.status).to.equal(
      "due",
    );
    expect(afterDiscovery.get(dueBeforeThreshold).delivery.status).to.equal(
      "pending",
    );
    expect(afterDiscovery.get(staleAfterThreshold).delivery).to.equal(null);
    expect(afterDiscovery.get(retired).delivery).to.equal(null);
  });

  it("reports delivery windows, attempts, and limits without changing eligibility", async () => {
    const firstDue = fixtures.dueBeforeThreshold;
    const secondDue = fixtures.expiryDay;
    const firstAlert = await TestUtils.execQuery(
      "SELECT id FROM alert_queue WHERE token_id = $1",
      [firstDue],
    );
    const secondAlert = await TestUtils.execQuery(
      "SELECT id FROM alert_queue WHERE token_id = $1",
      [secondDue],
    );
    const firstAlertId = firstAlert.rows[0].id;
    const secondAlertId = secondAlert.rows[0]?.id;

    await TestUtils.execQuery(
      `UPDATE alert_queue
       SET status = 'pending', error_message = 'OUT_OF_WINDOW',
           last_attempt = NOW(), next_attempt_at = NOW() + INTERVAL '1 hour'
       WHERE id = $1`,
      [firstAlertId],
    );
    await TestUtils.execQuery(
      `INSERT INTO alert_delivery_log (
         alert_queue_id, user_id, token_id, workspace_id, channel, status,
         error_message
       ) VALUES ($1, $2, $3, $4, 'email', 'deferred', 'OUT_OF_WINDOW')`,
      [firstAlertId, account.user.id, firstDue, workspaceId],
    );

    if (secondAlertId) {
      await TestUtils.execQuery(
        `UPDATE alert_queue
         SET status = 'limit_exceeded', error_message = 'PLAN_LIMIT'
         WHERE id = $1`,
        [secondAlertId],
      );
    }

    const states = await loadStates();
    expect(states.get(firstDue).eligibility.status).to.equal("due");
    expect(states.get(firstDue).delivery).to.include({
      status: "pending",
      reason: "delivery_window",
    });
    expect(states.get(firstDue).delivery.latest_attempt).to.include({
      channel: "email",
      status: "deferred",
    });
    expect(states.get(firstDue).delivery.next_attempt_at).to.not.equal(null);

    if (secondAlertId) {
      expect(states.get(secondDue).delivery).to.include({
        status: "limit_exceeded",
        reason: "monthly_plan_limit",
      });
    }
  });

  it("keeps viewer access read-only", async () => {
    viewer = await TestUtils.createAuthenticatedUser();
    await TestUtils.execQuery(
      `INSERT INTO workspace_memberships (
         user_id, workspace_id, role, invited_by
       ) VALUES ($1, $2, 'viewer', $3)
       ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'viewer'`,
      [viewer.user.id, workspaceId, account.user.id],
    );

    const visible = await loadStates(viewer.cookie);
    expect(visible.size).to.equal(tokenIds.length);

    await request(BASE)
      .post("/api/alert-queue/requeue")
      .set("Cookie", viewer.cookie)
      .send({ workspace_id: workspaceId })
      .expect(403);
  });

  it("unions assigned-group thresholds instead of using only the lex-smallest group", async () => {
    const tokenId = await insertToken("Unioned thresholds", 20, {
      importedAt: utcDate(-1),
      contactGroupId: "a",
      assignedGroupIds: ["a", "z"],
    });
    const states = await loadStates();
    const eligibility = states.get(tokenId).eligibility;
    expect(eligibility).to.include({
      status: "due",
      reason: "threshold_reached",
      effective_threshold: 30,
      contact_group_id: "a",
    });
    expect(eligibility.effective_thresholds).to.include.members([30, 14, 7, 1]);
  });

  it("follows join-table membership when it disagrees with the singular column", async () => {
    const tokenId = await insertToken("Join not singular", 20, {
      importedAt: utcDate(-1),
      contactGroupId: "c",
      assignedGroupIds: ["a"],
    });
    const states = await loadStates();
    const eligibility = states.get(tokenId).eligibility;
    expect(eligibility.contact_group_id).to.equal("a");
    expect(eligibility.status).to.equal("outside_threshold");
    expect(eligibility.effective_threshold).to.equal(null);
    expect(eligibility.effective_thresholds).to.include(1);
    expect(eligibility.effective_thresholds).to.not.include(30);
  });
});
