const crypto = require("crypto");
const { Client } = require("pg");
const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Alert lifecycle APIs", function () {
  this.timeout(120000);

  let client;
  let owner;
  let manager;
  let viewer;
  let outsider;
  let workspaceA;
  let workspaceB;
  let tokenA;
  let tokenB;
  let staleToken;
  let retiredToken;
  let alertA;
  let alertB;

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

    owner = await TestUtils.createAuthenticatedUser();
    manager = await TestUtils.createAuthenticatedUser();
    viewer = await TestUtils.createAuthenticatedUser();
    outsider = await TestUtils.createAuthenticatedUser();
    workspaceA = crypto.randomUUID();
    workspaceB = crypto.randomUUID();

    await client.query(
      `INSERT INTO workspaces (id, name, plan, created_by)
       VALUES ($1, 'Lifecycle A', 'oss', $3), ($2, 'Lifecycle B', 'oss', $3)`,
      [workspaceA, workspaceB, owner.user.id],
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $4, 'admin', $1),
              ($2, $4, 'workspace_manager', $1),
              ($3, $4, 'viewer', $1),
              ($1, $5, 'admin', $1)`,
      [owner.user.id, manager.user.id, viewer.user.id, workspaceA, workspaceB],
    );

    const insertToken = async (workspaceId, name, overrides = {}) => {
      const result = await client.query(
        `INSERT INTO tokens (
           user_id, workspace_id, created_by, name, expiration, imported_at,
           type, category, cert_lifecycle_status
         ) VALUES ($1, $2, $1, $3, $4, $5, 'api_key', $6, $7)
         RETURNING id`,
        [
          owner.user.id,
          workspaceId,
          name,
          overrides.expiration || "2026-09-20",
          overrides.importedAt || "2026-09-01T00:00:00.000Z",
          overrides.category || "general",
          overrides.lifecycle || null,
        ],
      );
      return result.rows[0].id;
    };

    tokenA = await insertToken(workspaceA, "Lifecycle production cert");
    tokenB = await insertToken(workspaceB, "Other workspace secret");
    staleToken = await insertToken(workspaceA, "Current stale import", {
      expiration: "2026-09-15",
      importedAt: "2026-09-14T00:00:00.000Z",
    });
    retiredToken = await insertToken(workspaceA, "Current retired cert", {
      category: "cert",
      lifecycle: "revoked",
    });

    const queueA = await client.query(
      `INSERT INTO alert_queue (
         user_id, token_id, alert_key, threshold_days, due_date, channels,
         status, created_at, updated_at
       ) VALUES (
         $1, $2, $3, 7, DATE '2026-09-13', '["email"]', 'sent',
         TIMESTAMP '2026-09-13 08:03:00', TIMESTAMP '2026-09-13 08:05:00'
       ) RETURNING id`,
      [owner.user.id, tokenA, `token_expiry:${tokenA}:poswin:7`],
    );
    alertA = queueA.rows[0].id;
    await client.query(
      `INSERT INTO alert_delivery_log (
         alert_queue_id, user_id, token_id, workspace_id, channel, status,
         sent_at, error_message
       ) VALUES
         ($1, $2, $3, $4, 'email', 'failed', TIMESTAMP '2026-09-13 08:04:00',
          'ops@example.test failed at https://hooks.example.test/private token=secret-value'),
         ($1, $2, $3, $4, 'email', 'success', TIMESTAMP '2026-09-13 08:05:00', NULL)`,
      [alertA, owner.user.id, tokenA, workspaceA],
    );
    await client.query(
      `INSERT INTO audit_events (
         subject_user_id, action, target_type, target_id, workspace_id,
         occurred_at, metadata
       ) VALUES
         ($1, 'ALERT_SENT', 'token', $2, $3, TIMESTAMP '2026-09-13 08:05:00',
          $4::jsonb),
         ($1, 'ALERT_RETRY_SCHEDULED', 'token', $2, $3,
          TIMESTAMP '2026-09-13 08:04:30',
          $5::jsonb)`,
      [
        owner.user.id,
        tokenA,
        workspaceA,
        JSON.stringify({
          days: 7,
          alert_id: alertA,
          alert_key: `token_expiry:${tokenA}:poswin:7`,
        }),
        JSON.stringify({
          days: 7,
          alert_id: alertA,
          alert_key: `token_expiry:${tokenA}:poswin:7`,
          next_attempt_at: "2026-09-13T08:05:00.000Z",
          channels_to_retry: ["email"],
        }),
      ],
    );

    const queueB = await client.query(
      `INSERT INTO alert_queue (
         user_id, token_id, alert_key, threshold_days, due_date, channels,
         status, created_at, updated_at
       ) VALUES ($1, $2, $3, 7, CURRENT_DATE, '["email"]', 'failed', NOW(), NOW())
       RETURNING id`,
      [owner.user.id, tokenB, `token_expiry:${tokenB}:poswin:7`],
    );
    alertB = queueB.rows[0].id;
    await client.query(
      `INSERT INTO alert_delivery_log (
         alert_queue_id, user_id, token_id, workspace_id, channel, status,
         error_message
       ) VALUES ($1, $2, $3, $4, 'email', 'failed', 'must not leak')`,
      [queueB.rows[0].id, owner.user.id, tokenB, workspaceB],
    );
  });

  after(async () => {
    try {
      const tokenIds = [tokenA, tokenB, staleToken, retiredToken].filter(
        Boolean,
      );
      if (tokenIds.length > 0) {
        await client.query(
          "DELETE FROM audit_events WHERE target_id = ANY($1::int[])",
          [tokenIds],
        );
        await client.query(
          "DELETE FROM alert_delivery_log WHERE token_id = ANY($1::int[])",
          [tokenIds],
        );
        await client.query("DELETE FROM tokens WHERE id = ANY($1::int[])", [
          tokenIds,
        ]);
      }
      await client.query(
        "DELETE FROM audit_events WHERE workspace_id = ANY($1::uuid[])",
        [[workspaceA, workspaceB].filter(Boolean)],
      );
      await client.query("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [
        [workspaceA, workspaceB].filter(Boolean),
      ]);
      for (const user of [owner, manager, viewer, outsider]) {
        if (user?.email && user?.cookie) {
          await TestUtils.cleanupTestUser(user.email, user.cookie);
        }
      }
    } finally {
      await client.end();
    }
  });

  it("returns an ordered, redacted token timeline without duplicate sent events", async () => {
    const response = await request(BASE)
      .get(`/api/tokens/${tokenA}/alert-timeline?limit=20&offset=0`)
      .set("Cookie", viewer.cookie)
      .expect(200);

    expect(response.body.items).to.be.an("array");
    expect(response.body.items.map((item) => item.type)).to.include.members([
      "threshold_reached",
      "alert_queued",
      "delivery_failed",
      "retry_scheduled",
      "delivery_succeeded",
    ]);
    expect(
      response.body.items.filter((item) => item.type === "delivery_succeeded"),
    ).to.have.length(1);
    expect(JSON.stringify(response.body)).not.to.match(
      /ops@example\.test|hooks\.example\.test|secret-value/,
    );
    const times = response.body.items.map((item) =>
      new Date(item.occurred_at).getTime(),
    );
    expect(times).to.deep.equal([...times].sort((a, b) => b - a));
  });

  it("allows viewer token reads without granting retry mutation access", async () => {
    await request(BASE)
      .get(`/api/tokens/${tokenA}/alert-timeline`)
      .set("Cookie", viewer.cookie)
      .expect(200);
    await request(BASE)
      .post(`/api/alert-queue/${alertA}/retry`)
      .set("Cookie", viewer.cookie)
      .send({ channel: "email" })
      .expect(404);
    await request(BASE)
      .post("/api/alert-queue/requeue")
      .set("Cookie", viewer.cookie)
      .send({ workspace_id: workspaceA })
      .expect(403);
  });

  it("hides token history from non-members", async () => {
    await request(BASE)
      .get(`/api/tokens/${tokenA}/alert-timeline`)
      .set("Cookie", outsider.cookie)
      .expect(404);
  });

  it("does not fabricate history from current stale-import or retired eligibility", async () => {
    for (const tokenId of [staleToken, retiredToken]) {
      const response = await request(BASE)
        .get(`/api/tokens/${tokenId}/alert-timeline`)
        .set("Cookie", viewer.cookie)
        .expect(200);
      expect(response.body.items).to.deep.equal([]);
    }
  });

  it("enforces Control Center RBAC and workspace isolation", async () => {
    const path = `/api/v1/workspaces/${workspaceA}/control-center/alert-activity`;
    const managerResponse = await request(BASE)
      .get(path)
      .set("Cookie", manager.cookie)
      .expect(200);
    expect(managerResponse.body.items).to.not.be.empty;
    expect(
      managerResponse.body.items.every(
        (item) => item.workspace_id === workspaceA,
      ),
    ).to.equal(true);
    expect(JSON.stringify(managerResponse.body)).not.to.include(
      "Other workspace secret",
    );

    await request(BASE).get(path).set("Cookie", viewer.cookie).expect(403);
    await request(BASE).get(path).set("Cookie", outsider.cookie).expect(403);
  });

  it("keeps eligibility counts authoritative beyond 500 while token rows are paged", async () => {
    const path = `/api/v1/workspaces/${workspaceA}/control-center/alert-eligibility-summary`;
    const bulkPrefix = `Lifecycle aggregate ${crypto.randomUUID()}`;
    await client.query(
      `INSERT INTO tokens (
         user_id, workspace_id, created_by, name, expiration, imported_at,
         type, category
       )
       SELECT $1, $2, $1, $3 || '-' || value, DATE '2027-12-31',
              TIMESTAMP '2026-09-01 00:00:00', 'api_key', 'general'
         FROM generate_series(1, 501) AS value`,
      [owner.user.id, workspaceA, bulkPrefix],
    );
    try {
      const summary = await request(BASE)
        .get(path)
        .set("Cookie", manager.cookie)
        .expect(200);
      expect(summary.body.total).to.equal(504);
      expect(
        Object.values(summary.body.counts).reduce(
          (sum, count) => sum + count,
          0,
        ),
      ).to.equal(504);

      const firstPage = await request(BASE)
        .get(`/api/tokens?workspace_id=${workspaceA}&limit=1&offset=0`)
        .set("Cookie", manager.cookie)
        .expect(200);
      const nextPage = await request(BASE)
        .get(`/api/tokens?workspace_id=${workspaceA}&limit=1&offset=1`)
        .set("Cookie", manager.cookie)
        .expect(200);
      expect(firstPage.body.total).to.equal(504);
      expect(nextPage.body.total).to.equal(504);
      expect(firstPage.body.items).to.have.length(1);
      expect(nextPage.body.items).to.have.length(1);
      expect(nextPage.body.items[0].id).not.to.equal(
        firstPage.body.items[0].id,
      );
    } finally {
      await client.query(
        "DELETE FROM tokens WHERE workspace_id=$1 AND name LIKE $2",
        [workspaceA, `${bulkPrefix}%`],
      );
    }

    await request(BASE).get(path).set("Cookie", viewer.cookie).expect(403);
    await request(BASE).get(path).set("Cookie", outsider.cookie).expect(403);
  });

  it("paginates recent workspace activity newest-first", async () => {
    const first = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceA}/control-center/alert-activity?limit=2&offset=0`,
      )
      .set("Cookie", manager.cookie)
      .expect(200);
    expect(first.body.items).to.have.length(2);
    expect(first.body.pagination).to.include({
      limit: 2,
      offset: 0,
      hasMore: true,
    });

    const second = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceA}/control-center/alert-activity?limit=2&offset=2`,
      )
      .set("Cookie", manager.cookie)
      .expect(200);
    expect(second.body.items).to.not.be.empty;
    expect(second.body.items[0].id).not.to.equal(first.body.items[0].id);
  });

  it("paginates by queue creation rather than old rows recently updated", async () => {
    for (let threshold = 99; threshold < 104; threshold++) {
      await client.query(
        `INSERT INTO alert_queue (user_id,token_id,alert_key,threshold_days,
           due_date,channels,status,created_at,updated_at)
         VALUES ($1,$2,$3,$4,CURRENT_DATE,'["email"]','sent',
           TIMESTAMP '2026-01-01 08:00:00',NOW())`,
        [
          owner.user.id,
          tokenB,
          `token_expiry:${tokenB}:poswin:${threshold}`,
          threshold,
        ],
      );
    }
    const response = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceB}/control-center/alert-activity?limit=2`,
      )
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(response.body.items.map((item) => item.id)).to.include(
      `queue:${alertB}`,
    );
  });

  it("never derives an expiry threshold or a sent delivery from discarded health/retirement alerts", async () => {
    const discardedRows = await client.query(
      `INSERT INTO alert_queue (user_id,token_id,alert_key,threshold_days,due_date,
       channels,status,error_message)
       VALUES ($1,$2,$3,7,CURRENT_DATE,'["email"]','sent',
         'Discarded: certificate revoked or decommissioned'),
         ($1,$4,$5,7,CURRENT_DATE,'["email"]','sent',
         'Discarded: endpoint recovered before threshold'),
         ($1,$4,$6,7,CURRENT_DATE,'["email"]','pending',NULL)
       RETURNING id, alert_key`,
      [
        owner.user.id,
        retiredToken,
        `token_expiry:${retiredToken}:poswin:7`,
        tokenB,
        `endpoint_health:${tokenB}:down`,
        `cert_renewal_failed:${tokenB}`,
      ],
    );
    const retired = await request(BASE)
      .get(`/api/tokens/${retiredToken}/alert-timeline`)
      .set("Cookie", viewer.cookie)
      .expect(200);
    const endpoint = await request(BASE)
      .get(`/api/tokens/${tokenB}/alert-timeline`)
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(
      retired.body.items.some((item) => item.type === "delivery_succeeded"),
    ).to.equal(false);
    expect(
      retired.body.items.some((item) => item.type === "alert_discarded"),
    ).to.equal(true);
    const nonExpiryIds = discardedRows.rows
      .filter((row) => !row.alert_key.startsWith("token_expiry:"))
      .map((row) => row.id);
    expect(
      endpoint.body.items.some((item) => nonExpiryIds.includes(item.alert_id)),
    ).to.equal(false);
    const retiredDetails = await request(BASE)
      .get(`/api/tokens/${retiredToken}`)
      .set("Cookie", viewer.cookie)
      .expect(200);
    expect(retiredDetails.body.alert_state.delivery.status).to.equal(
      "discarded",
    );
    await client.query(
      `INSERT INTO alert_queue (user_id,token_id,alert_key,threshold_days,
         due_date,channels,status)
       VALUES ($1,$2,$3,0,CURRENT_DATE,'["email"]','sent')`,
      [owner.user.id, staleToken, `token_expiry:${staleToken}:poswin:0`],
    );
    const unverified = await request(BASE)
      .get(`/api/tokens/${staleToken}`)
      .set("Cookie", viewer.cookie)
      .expect(200);
    expect(unverified.body.alert_state.delivery.status).to.equal(
      "sent_unverified",
    );
    const staleTimeline = await request(BASE)
      .get(`/api/tokens/${staleToken}/alert-timeline`)
      .set("Cookie", viewer.cookie)
      .expect(200);
    expect(
      staleTimeline.body.items.some(
        (item) => item.type === "delivery_succeeded",
      ),
    ).to.equal(false);
  });

  it("does not use a threshold-zero endpoint success audit as expiry delivery evidence", async () => {
    const expiryKey = `token_expiry:${tokenB}:poswin:0`;
    const endpointKey = `endpoint_health:${tokenB}:recovered`;
    const expiry = await client.query(
      `INSERT INTO alert_queue (user_id,token_id,alert_key,threshold_days,
         due_date,channels,status)
       VALUES ($1,$2,$3,0,CURRENT_DATE,'["email"]','sent') RETURNING id`,
      [owner.user.id, tokenB, expiryKey],
    );
    const endpoint = await client.query(
      `INSERT INTO alert_queue (user_id,token_id,alert_key,threshold_days,
         due_date,channels,status)
       VALUES ($1,$2,$3,0,CURRENT_DATE,'["email"]','sent') RETURNING id`,
      [owner.user.id, tokenB, endpointKey],
    );
    await client.query(
      `INSERT INTO audit_events (subject_user_id,action,target_type,target_id,
         workspace_id,metadata)
       VALUES ($1,'ALERT_SENT','token',$2,$3,$4::jsonb)`,
      [
        owner.user.id,
        tokenB,
        workspaceB,
        JSON.stringify({
          days: 0,
          alert_id: endpoint.rows[0].id,
          alert_key: endpointKey,
        }),
      ],
    );
    const details = await request(BASE)
      .get(`/api/tokens/${tokenB}`)
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(details.body.alert_state.delivery.alert_id).to.equal(
      expiry.rows[0].id,
    );
    expect(details.body.alert_state.delivery.status).to.equal(
      "sent_unverified",
    );
    const timeline = await request(BASE)
      .get(`/api/tokens/${tokenB}/alert-timeline?limit=100`)
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(
      timeline.body.items.some(
        (item) =>
          item.type === "delivery_succeeded" &&
          item.alert_id === endpoint.rows[0].id,
      ),
    ).to.equal(false);
    expect(
      timeline.body.items.some(
        (item) =>
          item.type === "delivery_succeeded" &&
          item.alert_id === expiry.rows[0].id,
      ),
    ).to.equal(false);
    expect(
      timeline.body.items.some(
        (item) =>
          item.type === "threshold_reached" &&
          item.alert_id === endpoint.rows[0].id,
      ),
    ).to.equal(false);
    await client.query(
      `INSERT INTO audit_events (subject_user_id,action,target_type,target_id,
         workspace_id,metadata)
       VALUES ($1,'ALERT_SENT','token',$2,$3,$4::jsonb)`,
      [
        owner.user.id,
        tokenB,
        workspaceB,
        JSON.stringify({ days: 0, alert_key: expiryKey }),
      ],
    );
    const keyMatched = await request(BASE)
      .get(`/api/tokens/${tokenB}`)
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(keyMatched.body.alert_state.delivery.status).to.equal("sent");
  });

  it("redacts queue and latest-attempt errors in both viewer-readable token APIs", async () => {
    const privateError =
      "ops@example.test https://hooks.example.test/private +49 151 23456789 password=hunter2";
    await client.query("UPDATE alert_queue SET error_message=$1 WHERE id=$2", [
      privateError,
      alertA,
    ]);
    await client.query(
      `INSERT INTO alert_delivery_log (alert_queue_id,user_id,token_id,workspace_id,
        channel,status,sent_at,error_message)
       VALUES ($1,$2,$3,$4,'email','failed',NOW(),$5)`,
      [alertA, owner.user.id, tokenA, workspaceA, privateError],
    );
    for (const path of [
      `/api/tokens?workspace_id=${workspaceA}&limit=10`,
      `/api/tokens/${tokenA}`,
    ]) {
      const response = await request(BASE)
        .get(path)
        .set("Cookie", viewer.cookie)
        .expect(200);
      const token = path.includes("limit=")
        ? response.body.items.find((item) => item.id === tokenA)
        : response.body;
      expect(token.alert_state.delivery.error_message).to.be.a("string");
      expect(token.alert_state.delivery.latest_attempt.error_message).to.be.a(
        "string",
      );
      expect(JSON.stringify(token.alert_state)).not.to.match(
        /ops@example\.test|hooks\.example\.test|151 23456789|hunter2/,
      );
    }
  });

  it("retains delivery and audit history in A after transferring its token to B", async () => {
    const before = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceB}/control-center/alert-activity?limit=100`,
      )
      .set("Cookie", owner.cookie)
      .expect(200);
    await request(BASE)
      .post(`/api/v1/workspaces/${workspaceB}/transfer-tokens`)
      .set("Cookie", owner.cookie)
      .send({ from_workspace_id: workspaceA, token_ids: [tokenA] })
      .expect(200);
    const persisted = await client.query(
      "SELECT DISTINCT workspace_id FROM alert_delivery_log WHERE token_id=$1",
      [tokenA],
    );
    expect(persisted.rows.map((row) => row.workspace_id)).to.deep.equal([
      workspaceA,
    ]);
    const auditWorkspaces = await client.query(
      `SELECT DISTINCT workspace_id FROM audit_events
        WHERE target_type='token' AND target_id=$1
          AND action IN ('ALERT_SENT','ALERT_RETRY_SCHEDULED')`,
      [tokenA],
    );
    expect(auditWorkspaces.rows.map((row) => row.workspace_id)).to.deep.equal([
      workspaceA,
    ]);
    const activityA = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceA}/control-center/alert-activity?limit=100`,
      )
      .set("Cookie", manager.cookie)
      .expect(200);
    const activityB = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceB}/control-center/alert-activity?limit=100`,
      )
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(
      activityA.body.items.some(
        (item) =>
          item.alert_id === alertA && item.type === "delivery_succeeded",
      ),
    ).to.equal(true);
    expect(
      activityA.body.items.some(
        (item) =>
          item.alert_id === alertA &&
          item.type === "retry_scheduled" &&
          item.source === "audit_events",
      ),
    ).to.equal(true);
    expect(
      activityB.body.items.some((item) => item.token_id === tokenA),
    ).to.equal(false);
    expect(activityB.body.items.map((item) => item.id)).to.deep.equal(
      before.body.items.map((item) => item.id),
    );
    const tokenTimeline = await request(BASE)
      .get(`/api/tokens/${tokenA}/alert-timeline?limit=100`)
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(
      tokenTimeline.body.items.some((item) => item.alert_id === alertA),
    ).to.equal(true);
  });

  it("attributes current-month alert-stats to the token's current workspace after transfer", async () => {
    // tokenA was already transferred to workspaceB by the prior test; historical
    // delivery rows still record workspaceA.
    const persisted = await client.query(
      "SELECT DISTINCT workspace_id FROM alert_delivery_log WHERE token_id=$1",
      [tokenA],
    );
    expect(persisted.rows.map((row) => row.workspace_id)).to.deep.equal([
      workspaceA,
    ]);
    const tokenWorkspace = await client.query(
      "SELECT workspace_id FROM tokens WHERE id=$1",
      [tokenA],
    );
    expect(tokenWorkspace.rows[0].workspace_id).to.equal(workspaceB);

    const statsA = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: workspaceA })
      .set("Cookie", owner.cookie)
      .expect(200);
    const statsB = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: workspaceB })
      .set("Cookie", owner.cookie)
      .expect(200);

    expect(statsA.body.monthUsage).to.equal(0);
    expect(statsB.body.monthUsage).to.be.at.least(1);
    const emailB = (statsB.body.byChannel || []).find(
      (row) => String(row.channel).toLowerCase() === "email",
    );
    expect(emailB).to.exist;
    expect(emailB.successes).to.be.at.least(1);
  });

  it("keeps deleted-token current-month deliveries on historical workspace_id", async () => {
    const before = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: workspaceA })
      .set("Cookie", owner.cookie)
      .expect(200);
    const doomed = await client.query(
      `INSERT INTO tokens (
         user_id, workspace_id, created_by, name, expiration, type, category
       ) VALUES ($1, $2, $1, 'Doomed stats token', DATE '2026-10-01', 'api_key', 'general')
       RETURNING id`,
      [owner.user.id, workspaceA],
    );
    const doomedId = doomed.rows[0].id;
    await client.query(
      `INSERT INTO alert_delivery_log (
         user_id, token_id, workspace_id, channel, status, sent_at
       ) VALUES ($1, $2, $3, 'email', 'success', NOW())`,
      [owner.user.id, doomedId, workspaceA],
    );
    await client.query("DELETE FROM tokens WHERE id=$1", [doomedId]);
    const orphan = await client.query(
      "SELECT token_id, workspace_id FROM alert_delivery_log WHERE token_id IS NULL AND workspace_id=$1 ORDER BY id DESC LIMIT 1",
      [workspaceA],
    );
    expect(orphan.rows[0].workspace_id).to.equal(workspaceA);

    const after = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: workspaceA })
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(after.body.monthUsage).to.equal((before.body.monthUsage || 0) + 1);
  });

  it("counts tokenless agent-health style deliveries via persisted workspace_id", async () => {
    const before = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: workspaceA })
      .set("Cookie", owner.cookie)
      .expect(200);
    await client.query(
      `INSERT INTO alert_delivery_log (
         user_id, token_id, workspace_id, channel, status, sent_at
       ) VALUES ($1, NULL, $2, 'email', 'success', NOW())`,
      [owner.user.id, workspaceA],
    );
    const after = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: workspaceA })
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(after.body.monthUsage).to.equal((before.body.monthUsage || 0) + 1);
    const emailA = (after.body.byChannel || []).find(
      (row) => String(row.channel).toLowerCase() === "email",
    );
    expect(emailA).to.exist;
    expect(emailA.attempts).to.be.at.least(1);
  });

  it("records a post-transfer manual retry against the alert and B workspace", async () => {
    await request(BASE)
      .post(`/api/alert-queue/${alertA}/retry`)
      .set("Cookie", owner.cookie)
      .send({ channel: "email" })
      .expect(200);
    const audit = await client.query(
      `SELECT workspace_id,metadata FROM audit_events
        WHERE action='ALERT_MANUAL_RETRY' AND target_type='alert'
          AND target_id=$1 ORDER BY occurred_at DESC LIMIT 1`,
      [alertA],
    );
    expect(audit.rows).to.have.length(1);
    expect(audit.rows[0].workspace_id).to.equal(workspaceB);
    expect(audit.rows[0].metadata.alert_id).to.equal(alertA);
    expect(audit.rows[0].metadata.alert_key).to.equal(
      `token_expiry:${tokenA}:poswin:7`,
    );
    const oldActivity = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceA}/control-center/alert-activity?limit=100`,
      )
      .set("Cookie", manager.cookie)
      .expect(200);
    const newActivity = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceB}/control-center/alert-activity?limit=100`,
      )
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(
      oldActivity.body.items.some(
        (item) => item.type === "alert_requeued" && item.alert_id === alertA,
      ),
    ).to.equal(false);
    expect(
      newActivity.body.items.some(
        (item) => item.type === "alert_requeued" && item.alert_id === alertA,
      ),
    ).to.equal(true);
  });
});
