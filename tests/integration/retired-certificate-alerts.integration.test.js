const crypto = require("crypto");
const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

function daysFromNow(days) {
  const date = new Date();
  date.setDate(date.getDate() + days);
  return date.toISOString().slice(0, 10);
}

function weekStartDateUtc() {
  const now = new Date();
  const day = now.getUTCDay();
  const diff = day === 0 ? 6 : day - 1;
  const monday = new Date(now);
  monday.setUTCDate(now.getUTCDate() - diff);
  monday.setUTCHours(0, 0, 0, 0);
  return monday.toISOString().slice(0, 10);
}

describe("Retired certificate alerts against PostgreSQL", function () {
  this.timeout(120000);

  let user;
  let cookie;
  let workspaceId;
  let alertContactId;
  let digestContactId;
  const alertGroupId = "retired-alert-ops";
  const digestGroupId = "retired-digest-ops";

  async function insertManagedCertificate(tokenId, label) {
    const inserted = await TestUtils.execQuery(
      `INSERT INTO managed_certificates (
         workspace_id, token_id, status, source, name,
         common_name, fingerprint_sha256
       )
       VALUES ($1, $2, 'active', 'api', $3, $4, $5)
       RETURNING id`,
      [
        workspaceId,
        tokenId,
        label,
        `${label}.certops.example`,
        crypto.randomBytes(32).toString("hex"),
      ],
    );
    return inserted.rows[0].id;
  }

  async function insertUnhealthyEndpointMonitor(tokenId) {
    const inserted = await TestUtils.execQuery(
      `INSERT INTO domain_monitors (
         workspace_id, url, token_id, health_check_enabled, check_interval,
         last_health_status, previous_health_status, consecutive_failures,
         alert_after_failures, last_health_check_at, created_by
       )
       VALUES ($1, $2, $3, TRUE, 'hourly',
               'unhealthy', 'healthy', 2, 1, NOW(), $4)
       RETURNING id`,
      [
        workspaceId,
        `https://retired-endpoint-${crypto.randomUUID()}.example`,
        tokenId,
        user.id,
      ],
    );
    return inserted.rows[0].id;
  }

  async function insertRenewalJob(certificateId) {
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certificate_jobs (
         workspace_id, operation, status, source, executor_kind, mode,
         subject_type, subject_id, payload, requested_by_user_id
       )
       VALUES ($1, 'renew', 'failed', 'api', 'agent', 'real',
               'managed_certificate', $2, '{}'::jsonb, $3)
       RETURNING id`,
      [workspaceId, String(certificateId), user.id],
    );
    return inserted.rows[0].id;
  }

  async function insertAlert({ tokenId, alertKey, status, dueOffsetDays = 0 }) {
    const inserted = await TestUtils.execQuery(
      `INSERT INTO alert_queue (
         user_id, token_id, alert_key, threshold_days, due_date, channels, status
       )
       VALUES ($1, $2, $3, 7, CURRENT_DATE + ($5::integer), '["email"]'::jsonb, $4)
       RETURNING id, status, alert_key`,
      [user.id, tokenId, alertKey, status, dueOffsetDays],
    );
    return inserted.rows[0];
  }

  async function retireCertificate(certificateId, status) {
    await request(BASE)
      .post(
        `/api/v1/workspaces/${workspaceId}/certops/certificates/${certificateId}/retire`,
      )
      .set("Cookie", cookie)
      .send({ status, reason: "retired-certificate-alert integration" })
      .expect(200);
  }

  async function createExpiringToken(name, groupId) {
    const created = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name,
        type: "tls_cert",
        category: "cert",
        expiresAt: daysFromNow(6),
        workspace_id: workspaceId,
        contact_group_id: groupId,
      })
      .expect(201);
    return created.body.id;
  }

  async function alertRows(tokenId) {
    const result = await TestUtils.execQuery(
      `SELECT alert_key, status, error_message
         FROM alert_queue
        WHERE token_id = $1
        ORDER BY alert_key`,
      [tokenId],
    );
    return result.rows;
  }

  async function waitForAlert(id, predicate, timeoutMs = 20000) {
    const started = Date.now();
    let row;
    while (Date.now() - started < timeoutMs) {
      const result = await TestUtils.execQuery(
        "SELECT id, status, error_message FROM alert_queue WHERE id = $1",
        [id],
      );
      row = result.rows[0];
      if (row && predicate(row)) {
        return row;
      }
      await TestUtils.wait(250);
    }
    throw new Error(
      `Timed out waiting for alert ${id}: ${JSON.stringify(row || null)}`,
    );
  }

  async function waitForSuccessfulEmailDelivery(alertId, timeoutMs = 20000) {
    const started = Date.now();
    let alertRow;
    let logRows = [];
    while (Date.now() - started < timeoutMs) {
      const alert = await TestUtils.execQuery(
        "SELECT id, status, error_message FROM alert_queue WHERE id = $1",
        [alertId],
      );
      alertRow = alert.rows[0];
      const log = await TestUtils.execQuery(
        `SELECT channel, status, error_message
           FROM alert_delivery_log
          WHERE alert_queue_id = $1 AND channel = 'email'`,
        [alertId],
      );
      logRows = log.rows;
      const discarded = /revoked or decommissioned|endpoint recovered before threshold/i.test(
        String(alertRow?.error_message || ""),
      );
      if (
        alertRow?.status === "sent" &&
        !discarded &&
        logRows.some((row) => row.status === "success")
      ) {
        return { alert: alertRow, log: logRows };
      }
      await TestUtils.wait(250);
    }
    throw new Error(
      `Timed out waiting for successful email delivery of ${alertId}: alert=${JSON.stringify(alertRow || null)} log=${JSON.stringify(logRows)}`,
    );
  }

  async function runDeliveryWorker() {
    await TestUtils.runNode("node", ["src/delivery-worker.js"], "apps/worker", {
      ...process.env,
      NODE_ENV: "test",
      SMTP_HOST: process.env.SMTP_HOST || "localhost",
      SMTP_PORT: process.env.SMTP_PORT || "1025",
    });
  }

  before(async () => {
    await TestEnvironment.setup();
    user = await TestUtils.createVerifiedTestUser();
    const session = await TestUtils.loginTestUser(user.email, user.password);
    cookie = session.cookie;
    workspaceId = await TestUtils.ensureDedicatedTestWorkspace(
      cookie,
      "Retired cert alerts",
    );

    const alertContact = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/contacts`)
      .set("Cookie", cookie)
      .send({
        first_name: "Retired",
        last_name: "Alerts",
        details: { email: user.email },
      })
      .expect(201);
    alertContactId = alertContact.body.id;

    const digestContact = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/contacts`)
      .set("Cookie", cookie)
      .send({
        first_name: "Retired",
        last_name: "Digest",
        details: { email: user.email },
      })
      .expect(201);
    digestContactId = digestContact.body.id;

    await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", cookie)
      .send({
        email_alerts_enabled: true,
        alert_thresholds: [30, 14, 7, 1, 0],
        delivery_window_start: "00:00",
        delivery_window_end: "23:59",
        delivery_window_tz: "UTC",
        contact_groups: [
          {
            id: alertGroupId,
            name: "Retired alert ops",
            email_contact_ids: [alertContactId],
          },
          {
            id: digestGroupId,
            name: "Retired digest ops",
            email_contact_ids: [digestContactId],
            weekly_digest_email: true,
          },
        ],
        default_contact_group_id: alertGroupId,
      })
      .expect(200);
  });

  after(async () => {
    if (user?.email && cookie) {
      await TestUtils.cleanupTestUser(user.email, cookie);
    }
  });

  it("deletes this certificate's unsent renewal-failure alerts on retire, including limit_exceeded, without dropping sibling expiry", async () => {
    const tokenId = await createExpiringToken(
      `shared-retire-${Date.now()}`,
      alertGroupId,
    );
    const certA = await insertManagedCertificate(tokenId, "shared-a");
    const certB = await insertManagedCertificate(tokenId, "shared-b");
    const jobA = await insertRenewalJob(certA);
    const jobB = await insertRenewalJob(certB);

    await insertAlert({
      tokenId,
      alertKey: `token_expiry:${tokenId}:poswin:7`,
      status: "pending",
      dueOffsetDays: 2,
    });
    await insertAlert({
      tokenId,
      alertKey: `cert_renewal_failed:${jobA}`,
      status: "limit_exceeded",
      dueOffsetDays: 2,
    });
    await insertAlert({
      tokenId,
      alertKey: `cert_renewal_failed:${jobB}`,
      status: "pending",
      dueOffsetDays: 2,
    });
    await insertAlert({
      tokenId,
      alertKey: `endpoint_health:retired-pipeline-${crypto.randomUUID()}:down`,
      status: "pending",
      dueOffsetDays: 2,
    });

    await retireCertificate(certA, "revoked");

    const afterFirst = await alertRows(tokenId);
    expect(
      afterFirst.some((row) => row.alert_key === `cert_renewal_failed:${jobA}`),
    ).to.equal(false);
    expect(
      afterFirst.some(
        (row) =>
          row.alert_key === `cert_renewal_failed:${jobB}` &&
          row.status === "pending",
      ),
    ).to.equal(true);
    expect(
      afterFirst.some(
        (row) =>
          row.alert_key === `token_expiry:${tokenId}:poswin:7` &&
          row.status === "pending",
      ),
    ).to.equal(true);
    expect(
      afterFirst.some((row) => row.alert_key.startsWith("endpoint_health:")),
    ).to.equal(true);

    const tokenAfterFirst = await TestUtils.execQuery(
      "SELECT cert_lifecycle_status FROM tokens WHERE id = $1",
      [tokenId],
    );
    expect(tokenAfterFirst.rows[0].cert_lifecycle_status).to.not.equal(
      "revoked",
    );

    await retireCertificate(certB, "decommissioned");

    const afterLast = await alertRows(tokenId);
    expect(
      afterLast.some((row) => row.alert_key.startsWith("token_expiry:")),
    ).to.equal(false);
    expect(
      afterLast.some((row) =>
        row.alert_key.startsWith("cert_renewal_failed:"),
      ),
    ).to.equal(false);
    expect(
      afterLast.some((row) => row.alert_key.startsWith("endpoint_health:")),
    ).to.equal(true);
  });

  it("delivers endpoint-health after the last shared-token sibling is retired", async () => {
    const tokenId = await createExpiringToken(
      `endpoint-after-retire-${Date.now()}`,
      alertGroupId,
    );
    const certA = await insertManagedCertificate(tokenId, "endpoint-a");
    const certB = await insertManagedCertificate(tokenId, "endpoint-b");
    const monitorId = await insertUnhealthyEndpointMonitor(tokenId);

    await insertAlert({
      tokenId,
      alertKey: `token_expiry:${tokenId}:poswin:7`,
      status: "pending",
      dueOffsetDays: 2,
    });
    const endpoint = await insertAlert({
      tokenId,
      alertKey: `endpoint_health:${monitorId}:down`,
      status: "pending",
      dueOffsetDays: 2,
    });

    await retireCertificate(certA, "revoked");
    await retireCertificate(certB, "decommissioned");

    const tokenAfter = await TestUtils.execQuery(
      "SELECT cert_lifecycle_status FROM tokens WHERE id = $1",
      [tokenId],
    );
    expect(tokenAfter.rows[0].cert_lifecycle_status).to.equal("decommissioned");

    const afterRetire = await alertRows(tokenId);
    expect(
      afterRetire.some((row) => row.alert_key.startsWith("token_expiry:")),
    ).to.equal(false);
    expect(
      afterRetire.some(
        (row) =>
          row.alert_key === `endpoint_health:${monitorId}:down` &&
          row.status === "pending",
      ),
    ).to.equal(true);

    await TestUtils.execQuery(
      "UPDATE alert_queue SET due_date = CURRENT_DATE WHERE id = $1",
      [endpoint.id],
    );

    await runDeliveryWorker();

    const delivered = await waitForSuccessfulEmailDelivery(endpoint.id);
    expect(delivered.alert.status).to.equal("sent");
    expect(String(delivered.alert.error_message || "")).to.not.match(
      /revoked or decommissioned/i,
    );
    expect(
      delivered.log.some(
        (row) => row.channel === "email" && row.status === "success",
      ),
    ).to.equal(true);
    const sentAudit = await TestUtils.execQuery(
      `SELECT workspace_id, metadata FROM audit_events
        WHERE action = 'ALERT_SENT'
          AND metadata->>'alert_id' = $1
          AND metadata->>'alert_key' = $2
        ORDER BY occurred_at DESC LIMIT 1`,
      [String(endpoint.id), `endpoint_health:${monitorId}:down`],
    );
    expect(sentAudit.rows).to.have.length(1);
    expect(sentAudit.rows[0].workspace_id).to.equal(workspaceId);
    expect(sentAudit.rows[0].metadata.alert_id).to.equal(endpoint.id);
  });

  it("does not enqueue expiry alerts for a fully retired token, and still enqueues a live one", async () => {
    const liveTokenId = await createExpiringToken(
      `live-discovery-${Date.now()}`,
      alertGroupId,
    );
    const retiredTokenId = await createExpiringToken(
      `retired-discovery-${Date.now()}`,
      alertGroupId,
    );
    await TestUtils.execQuery(
      `UPDATE tokens
          SET cert_lifecycle_status = 'revoked'
        WHERE id = $1`,
      [retiredTokenId],
    );

    await TestUtils.runNode("node", ["src/queue-manager.js"], "apps/worker");

    const liveQueued = await TestUtils.execQuery(
      `SELECT id, alert_key FROM alert_queue
        WHERE token_id = $1 AND alert_key LIKE 'token_expiry:%'`,
      [liveTokenId],
    );
    const retiredQueued = await TestUtils.execQuery(
      `SELECT alert_key FROM alert_queue
        WHERE token_id = $1 AND alert_key LIKE 'token_expiry:%'`,
      [retiredTokenId],
    );

    expect(liveQueued.rows.length).to.be.at.least(1);
    expect(retiredQueued.rows.length).to.equal(0);
    const queuedAudit = await TestUtils.execQuery(
      `SELECT workspace_id, metadata FROM audit_events
        WHERE action='ALERT_QUEUED' AND target_type='token' AND target_id=$1
          AND metadata->>'alert_id'=$2
        ORDER BY occurred_at DESC LIMIT 1`,
      [liveTokenId, String(liveQueued.rows[0].id)],
    );
    expect(queuedAudit.rows).to.have.length(1);
    expect(queuedAudit.rows[0].workspace_id).to.equal(workspaceId);
    expect(queuedAudit.rows[0].metadata.alert_key)
      .to.equal(liveQueued.rows[0].alert_key);
  });

  it("discards leftover renewal-failure delivery for a retired certificate while the shared token stays live", async () => {
    const tokenId = await createExpiringToken(
      `shared-delivery-${Date.now()}`,
      alertGroupId,
    );
    const certA = await insertManagedCertificate(tokenId, "delivery-a");
    const certB = await insertManagedCertificate(tokenId, "delivery-b");
    await retireCertificate(certA, "decommissioned");

    const leftoverJob = await insertRenewalJob(certA);
    const leftover = await insertAlert({
      tokenId,
      alertKey: `cert_renewal_failed:${leftoverJob}`,
      status: "pending",
    });
    const expiry = await insertAlert({
      tokenId,
      alertKey: `token_expiry:${tokenId}:poswin:7`,
      status: "pending",
    });
    const endpoint = await insertAlert({
      tokenId,
      alertKey: `endpoint_health:retired-delivery-${crypto.randomUUID()}:down`,
      status: "pending",
    });

    await runDeliveryWorker();

    const leftoverAfter = await waitForAlert(
      leftover.id,
      (row) =>
        row.status === "sent" &&
        /revoked or decommissioned/i.test(String(row.error_message || "")),
    );
    expect(leftoverAfter.status).to.equal("sent");

    const expiryAfter = await TestUtils.execQuery(
      "SELECT error_message FROM alert_queue WHERE id = $1",
      [expiry.id],
    );
    expect(String(expiryAfter.rows[0]?.error_message || "")).to.not.match(
      /revoked or decommissioned/i,
    );

    const endpointAfter = await TestUtils.execQuery(
      "SELECT error_message FROM alert_queue WHERE id = $1",
      [endpoint.id],
    );
    expect(String(endpointAfter.rows[0]?.error_message || "")).to.not.match(
      /revoked or decommissioned/i,
    );

    const sibling = await TestUtils.execQuery(
      "SELECT status FROM managed_certificates WHERE id = $1",
      [certB],
    );
    expect(sibling.rows[0].status).to.equal("active");
  });

  it("omits a fully retired token from the weekly digest", async () => {
    const liveName = `digest-live-${Date.now()}`;
    const retiredName = `digest-retired-${Date.now()}`;
    await createExpiringToken(liveName, digestGroupId);
    const retiredTokenId = await createExpiringToken(retiredName, digestGroupId);
    await TestUtils.execQuery(
      `UPDATE tokens
          SET cert_lifecycle_status = 'decommissioned'
        WHERE id = $1`,
      [retiredTokenId],
    );
    await TestUtils.execQuery(
      "DELETE FROM weekly_digest_log WHERE workspace_id = $1",
      [workspaceId],
    );

    await TestUtils.runNode(
      "node",
      ["src/weekly-digest-runner.js"],
      "apps/worker",
      {
        ...process.env,
        NODE_ENV: "test",
        SMTP_HOST: process.env.SMTP_HOST || "localhost",
        SMTP_PORT: process.env.SMTP_PORT || "1025",
      },
    );

    const logged = await TestUtils.execQuery(
      `SELECT tokens_count
         FROM weekly_digest_log
        WHERE workspace_id = $1
          AND contact_group_id = $2
          AND week_start_date = $3`,
      [workspaceId, digestGroupId, weekStartDateUtc()],
    );
    expect(logged.rows).to.have.length(1);
    expect(Number(logged.rows[0].tokens_count)).to.equal(1);
  });
});
