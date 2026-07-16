const http = require("http");
const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { startLocalHttpsServer } = require("./helpers/local-https-server");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Endpoint check worker integration", function () {
  this.timeout(120000);

  let testUser;
  let session;
  let workspaceId;
  let tokenId;
  let monitorId;
  let healthyServer;
  let healthyUrl;
  let emailContactId;

  async function runEndpointWorker() {
    await TestUtils.runNode("node", ["src/endpoint-check-worker.js"], "apps/worker", {
      ...process.env,
      NODE_ENV: "test",
    });
  }

  async function runDeliveryWorker(envOverrides = {}) {
    await TestUtils.runNode(
      "node",
      ["src/delivery-worker.js"],
      "apps/worker",
      {
        ...process.env,
        NODE_ENV: "test",
        ...envOverrides,
      },
    );
  }

  before(async () => {
    await TestEnvironment.setup();
    testUser = await TestUtils.createVerifiedTestUser();
    session = await TestUtils.loginTestUser(testUser.email, "SecureTest123!@#");

    const wsList = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", session.cookie)
      .expect(200);
    workspaceId = wsList?.body?.items?.[0]?.id;

    const contactRes = await TestUtils.execQuery(
      `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, phone_e164, details, created_by)
       VALUES ($1, 'Endpoint', 'Alerts', '+41790000001', $2::jsonb, $3)
       RETURNING id`,
      [workspaceId, JSON.stringify({ email: "endpoint-alerts@example.com" }), testUser.id],
    );
    emailContactId = String(contactRes.rows[0].id);

    await TestUtils.execQuery(
      `INSERT INTO workspace_settings (
         workspace_id,
         email_alerts_enabled,
         contact_groups,
         default_contact_group_id,
         webhook_urls
       )
       VALUES ($1, TRUE, $2::jsonb, 'endpoint-default', $3::jsonb)
       ON CONFLICT (workspace_id) DO UPDATE SET
         email_alerts_enabled = TRUE,
         contact_groups = EXCLUDED.contact_groups,
         default_contact_group_id = EXCLUDED.default_contact_group_id,
         webhook_urls = EXCLUDED.webhook_urls`,
      [
        workspaceId,
        JSON.stringify([
          {
            id: "endpoint-default",
            name: "Endpoint Default",
            email_contact_ids: [emailContactId],
            whatsapp_contact_ids: [emailContactId],
            webhook_names: ["Ops Slack"],
          },
        ]),
        JSON.stringify([{ name: "Ops Slack", url: "https://hooks.slack.com/services/T0/B0/abc" }]),
      ],
    );

    const tokenRes = await TestUtils.execQuery(
      `INSERT INTO tokens (workspace_id, name, expiration, type, category)
       VALUES ($1, 'endpoint-worker-token', '2099-12-31', 'ssl_cert', 'cert')
       RETURNING id`,
      [workspaceId],
    );
    tokenId = tokenRes.rows[0].id;
  });

  after(async () => {
    try {
      if (healthyServer) {
        await new Promise((resolve) => healthyServer.close(resolve));
      }
    } catch (_) {}

    if (monitorId) {
      await TestUtils.execQuery("DELETE FROM alert_queue WHERE alert_key LIKE $1", [
        `endpoint_health:${monitorId}:%`,
      ]);
      await TestUtils.execQuery("DELETE FROM domain_monitors WHERE id = $1", [monitorId]);
    }
    if (tokenId) {
      await TestUtils.execQuery("DELETE FROM tokens WHERE id = $1", [tokenId]);
    }
    if (testUser?.email && session?.cookie) {
      await TestUtils.cleanupTestUser(testUser.email, session.cookie);
    }
  });

  it("queues down and recovered alerts across real health transitions", async () => {
    healthyServer = http.createServer((req, res) => {
      res.statusCode = 200;
      res.end("ok");
    });
    await new Promise((resolve) => healthyServer.listen(0, "127.0.0.1", resolve));
    const { port } = healthyServer.address();
    healthyUrl = `http://127.0.0.1:${port}`;

    const monitorRes = await TestUtils.execQuery(
      `INSERT INTO domain_monitors
        (workspace_id, url, token_id, health_check_enabled, check_interval, last_health_status, consecutive_failures, alert_after_failures, created_by)
       VALUES ($1, 'http://127.0.0.1:9', $2, TRUE, '1min', 'healthy', 0, 1, $3)
       RETURNING id`,
      [workspaceId, tokenId, testUser.id],
    );
    monitorId = monitorRes.rows[0].id;

    await runEndpointWorker();

    let downAlert = await TestUtils.execQuery(
      "SELECT alert_key, status FROM alert_queue WHERE alert_key = $1",
      [`endpoint_health:${monitorId}:down`],
    );
    expect(downAlert.rows).to.have.length(1);
    expect(downAlert.rows[0].status).to.equal("pending");

    await TestUtils.execQuery(
      "UPDATE domain_monitors SET last_health_check_at = NOW() - INTERVAL '2 minutes' WHERE id = $1",
      [monitorId],
    );
    await runEndpointWorker();

    downAlert = await TestUtils.execQuery(
      "SELECT alert_key FROM alert_queue WHERE alert_key = $1",
      [`endpoint_health:${monitorId}:down`],
    );
    expect(downAlert.rows).to.have.length(1);

    await TestUtils.execQuery(
      "UPDATE alert_queue SET status = 'sent' WHERE alert_key = $1",
      [`endpoint_health:${monitorId}:down`],
    );
    await TestUtils.execQuery(
      `UPDATE domain_monitors
       SET url = $2, last_health_status = 'error', last_health_check_at = NOW() - INTERVAL '2 minutes'
       WHERE id = $1`,
      [monitorId, healthyUrl],
    );

    await runEndpointWorker();

    const recoveredAlert = await TestUtils.execQuery(
      "SELECT alert_key FROM alert_queue WHERE alert_key = $1",
      [`endpoint_health:${monitorId}:recovered`],
    );
    expect(recoveredAlert.rows).to.have.length(1);

    const staleDown = await TestUtils.execQuery(
      "SELECT alert_key FROM alert_queue WHERE alert_key = $1",
      [`endpoint_health:${monitorId}:down`],
    );
    expect(staleDown.rows).to.have.length(0);
  });

  it("queues endpoint alerts using default contact group channel eligibility", async () => {
    const tokenRes = await TestUtils.execQuery(
      `INSERT INTO tokens (workspace_id, name, expiration, type, category)
       VALUES ($1, 'endpoint-worker-multi-channel', '2099-12-31', 'ssl_cert', 'cert')
       RETURNING id`,
      [workspaceId],
    );
    const localTokenId = tokenRes.rows[0].id;

    const monitorRes = await TestUtils.execQuery(
      `INSERT INTO domain_monitors
        (workspace_id, url, token_id, health_check_enabled, check_interval, last_health_status, consecutive_failures, alert_after_failures, created_by)
       VALUES ($1, 'http://127.0.0.1:9', $2, TRUE, '1min', 'healthy', 0, 1, $3)
       RETURNING id`,
      [workspaceId, localTokenId, testUser.id],
    );
    const localMonitorId = monitorRes.rows[0].id;

    // Add WhatsApp and webhook selections to the default group for this scenario.
    await TestUtils.execQuery(
      `UPDATE workspace_settings
       SET contact_groups = $2::jsonb
       WHERE workspace_id = $1`,
      [
        workspaceId,
        JSON.stringify([
          {
            id: "endpoint-default",
            name: "Endpoint Default",
            email_contact_ids: [emailContactId],
            whatsapp_contact_ids: [emailContactId],
            webhook_names: ["Ops Slack"],
          },
        ]),
      ],
    );

    await runEndpointWorker();

    const alertRes = await TestUtils.execQuery(
      "SELECT channels FROM alert_queue WHERE alert_key = $1",
      [`endpoint_health:${localMonitorId}:down`],
    );
    expect(alertRes.rows).to.have.length(1);
    const channels = Array.isArray(alertRes.rows[0].channels)
      ? alertRes.rows[0].channels
      : JSON.parse(String(alertRes.rows[0].channels || "[]"));
    expect(channels).to.include.members(["email", "webhooks", "whatsapp"]);

    await TestUtils.execQuery("DELETE FROM alert_queue WHERE alert_key LIKE $1", [
      `endpoint_health:${localMonitorId}:%`,
    ]);
    await TestUtils.execQuery("DELETE FROM domain_monitors WHERE id = $1", [localMonitorId]);
    await TestUtils.execQuery("DELETE FROM tokens WHERE id = $1", [localTokenId]);
  });

  it("uses endpoint-specific WhatsApp templates and endpoint webhook metadata", async () => {
    healthyServer = http.createServer((req, res) => {
      res.statusCode = 200;
      res.end("ok");
    });
    await new Promise((resolve) => healthyServer.listen(0, "127.0.0.1", resolve));
    const { port } = healthyServer.address();
    const localHealthyUrl = `http://127.0.0.1:${port}`;

    const tokenRes = await TestUtils.execQuery(
      `INSERT INTO tokens (workspace_id, name, expiration, type, category)
       VALUES ($1, 'endpoint-worker-template-test', '2099-12-31', 'ssl_cert', 'cert')
       RETURNING id`,
      [workspaceId],
    );
    const localTokenId = tokenRes.rows[0].id;

    const monitorRes = await TestUtils.execQuery(
      `INSERT INTO domain_monitors
        (workspace_id, url, token_id, health_check_enabled, check_interval, last_health_status, consecutive_failures, alert_after_failures, created_by)
       VALUES ($1, 'http://127.0.0.1:9', $2, TRUE, '1min', 'healthy', 0, 1, $3)
       RETURNING id`,
      [workspaceId, localTokenId, testUser.id],
    );
    const localMonitorId = monitorRes.rows[0].id;

    const downSid = "HX_ENDPOINT_DOWN_TEST";
    const recoveredSid = "HX_ENDPOINT_RECOVERED_TEST";

    await runEndpointWorker();
    await runDeliveryWorker({
      TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN: downSid,
      TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED: recoveredSid,
    });

    const downWhatsAppLog = await TestUtils.execQuery(
      `SELECT metadata
         FROM alert_delivery_log
        WHERE token_id = $1 AND channel = 'whatsapp'
        ORDER BY sent_at DESC
        LIMIT 1`,
      [localTokenId],
    );
    expect(downWhatsAppLog.rows).to.have.length(1);
    expect(downWhatsAppLog.rows[0].metadata.contentSid).to.equal(downSid);
    expect(downWhatsAppLog.rows[0].metadata.template_kind).to.equal(
      "endpoint_down",
    );

    const downWebhookLog = await TestUtils.execQuery(
      `SELECT metadata
         FROM alert_delivery_log
        WHERE token_id = $1 AND channel = 'webhooks'
        ORDER BY sent_at DESC
        LIMIT 1`,
      [localTokenId],
    );
    expect(downWebhookLog.rows).to.have.length(1);
    expect(downWebhookLog.rows[0].metadata.payload_type).to.equal(
      "endpoint_health",
    );
    expect(downWebhookLog.rows[0].metadata.endpoint_transition).to.equal("down");

    await TestUtils.execQuery(
      "UPDATE alert_queue SET status = 'sent' WHERE alert_key = $1",
      [`endpoint_health:${localMonitorId}:down`],
    );
    await TestUtils.execQuery(
      `UPDATE domain_monitors
       SET url = $2, last_health_status = 'error', last_health_check_at = NOW() - INTERVAL '2 minutes'
       WHERE id = $1`,
      [localMonitorId, localHealthyUrl],
    );

    await runEndpointWorker();
    await runDeliveryWorker({
      TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN: downSid,
      TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED: recoveredSid,
    });

    const recoveredWhatsAppLog = await TestUtils.execQuery(
      `SELECT metadata
         FROM alert_delivery_log
        WHERE token_id = $1 AND channel = 'whatsapp'
          AND metadata->>'template_kind' = 'endpoint_recovered'
        ORDER BY sent_at DESC
        LIMIT 1`,
      [localTokenId],
    );
    expect(recoveredWhatsAppLog.rows).to.have.length(1);
    expect(recoveredWhatsAppLog.rows[0].metadata.contentSid).to.equal(
      recoveredSid,
    );

    await TestUtils.execQuery("DELETE FROM alert_queue WHERE alert_key LIKE $1", [
      `endpoint_health:${localMonitorId}:%`,
    ]);
    await TestUtils.execQuery(
      "DELETE FROM alert_delivery_log WHERE token_id = $1",
      [localTokenId],
    );
    await TestUtils.execQuery("DELETE FROM domain_monitors WHERE id = $1", [
      localMonitorId,
    ]);
    await TestUtils.execQuery("DELETE FROM tokens WHERE id = $1", [localTokenId]);
  });

  it("bridges HTTPS endpoint observations into CertOps inventory when a token is linked", async () => {
    const httpsServer = await startLocalHttpsServer();
    let localTokenId;
    let localMonitorId;

    const runBridgeWorker = () =>
      TestUtils.runNode(
        "node",
        ["src/endpoint-check-worker.js"],
        "apps/worker",
        {
          ...process.env,
          NODE_ENV: "test",
          CERTOPS_ENABLED: "true",
        },
      );

    const queryBridgeRows = () =>
      TestUtils.execQuery(
        `SELECT mc.id AS managed_id,
                mc.source,
                mc.source_ref,
                mc.token_id,
                mc.fingerprint_sha256 AS managed_fingerprint,
                mc.serial_number AS managed_serial,
                ct.id AS target_id,
                ct.domain_monitor_id,
                ci.id AS instance_id,
                ci.observed_fingerprint_sha256 AS instance_fingerprint
           FROM managed_certificates mc
           JOIN certificate_targets ct
             ON ct.workspace_id = mc.workspace_id
            AND ct.source = mc.source
            AND ct.source_ref = mc.source_ref
           JOIN certificate_instances ci
             ON ci.workspace_id = mc.workspace_id
            AND ci.managed_certificate_id = mc.id
            AND ci.target_id = ct.id
          WHERE mc.workspace_id = $1
            AND mc.source = 'endpoint_monitor'
            AND mc.source_ref = $2
          ORDER BY ci.created_at ASC`,
        [workspaceId, String(localMonitorId)],
      );

    const countManagedCertificates = async () => {
      const res = await TestUtils.execQuery(
        `SELECT COUNT(*)::int AS n
           FROM managed_certificates
          WHERE workspace_id = $1
            AND source = 'endpoint_monitor'
            AND source_ref = $2`,
        [workspaceId, String(localMonitorId)],
      );
      return res.rows[0].n;
    };

    try {
      const tokenRes = await TestUtils.execQuery(
        `INSERT INTO tokens (workspace_id, name, expiration, type, category)
         VALUES ($1, 'endpoint-certops-bridge-token', '2099-12-31', 'ssl_cert', 'cert')
         RETURNING id`,
        [workspaceId],
      );
      localTokenId = tokenRes.rows[0].id;

      const monitorRes = await TestUtils.execQuery(
        `INSERT INTO domain_monitors
          (workspace_id, url, token_id, health_check_enabled, check_interval, created_by)
         VALUES ($1, $2, $3, FALSE, '1min', $4)
         RETURNING id`,
        [workspaceId, httpsServer.url, localTokenId, testUser.id],
      );
      localMonitorId = monitorRes.rows[0].id;

      await runBridgeWorker();

      const certopsRows = await queryBridgeRows();

      expect(certopsRows.rows).to.have.length(1);
      expect(certopsRows.rows[0].domain_monitor_id).to.equal(localMonitorId);
      expect(String(certopsRows.rows[0].token_id)).to.equal(String(localTokenId));
      expect(certopsRows.rows[0].instance_id).to.be.a("string");
      expect(await countManagedCertificates()).to.equal(1);

      const firstManagedId = certopsRows.rows[0].managed_id;
      const firstFingerprint = certopsRows.rows[0].instance_fingerprint;
      expect(firstFingerprint).to.be.a("string");

      // Re-observing the SAME certificate refreshes the existing instance row
      // (last-seen) instead of appending a new one. The claim/completion path
      // now advances last_health_check_at (scheduling state), so make the
      // monitor due again before each re-run.
      await TestUtils.execQuery(
        `UPDATE domain_monitors
            SET last_health_check_at = NOW() - INTERVAL '2 minutes',
                check_claimed_until = NULL
          WHERE id = $1`,
        [localMonitorId],
      );
      await runBridgeWorker();
      const afterRefresh = await queryBridgeRows();
      expect(afterRefresh.rows).to.have.length(1);
      expect(afterRefresh.rows[0].instance_id).to.equal(
        certopsRows.rows[0].instance_id,
      );
      expect(afterRefresh.rows[0].instance_fingerprint).to.equal(firstFingerprint);
      expect(await countManagedCertificates()).to.equal(1);

      // Rotate the served certificate (new fingerprint/serial, same monitor URL).
      // A new fingerprint at the same monitor APPENDS a second instance row, while
      // the single managed_certificate row is updated in place.
      httpsServer.rotateCertificate();
      await TestUtils.execQuery(
        `UPDATE domain_monitors
            SET last_health_check_at = NOW() - INTERVAL '2 minutes',
                check_claimed_until = NULL
          WHERE id = $1`,
        [localMonitorId],
      );
      await runBridgeWorker();
      const afterRotation = await queryBridgeRows();
      expect(afterRotation.rows).to.have.length(2);
      expect(await countManagedCertificates()).to.equal(1);
      const rotatedManagedIds = new Set(
        afterRotation.rows.map((row) => String(row.managed_id)),
      );
      expect(rotatedManagedIds.size).to.equal(1);
      expect(rotatedManagedIds.has(String(firstManagedId))).to.equal(true);
      const rotatedFingerprints = new Set(
        afterRotation.rows.map((row) => row.instance_fingerprint),
      );
      expect(rotatedFingerprints.size).to.equal(2);
      expect(rotatedFingerprints.has(firstFingerprint)).to.equal(true);
      const managedFingerprint = afterRotation.rows[0].managed_fingerprint;
      expect(managedFingerprint).to.not.equal(firstFingerprint);
      expect(rotatedFingerprints.has(managedFingerprint)).to.equal(true);
    } finally {
      if (localMonitorId) {
        await TestUtils.execQuery(
          "DELETE FROM certificate_instances WHERE workspace_id = $1 AND domain_monitor_id = $2",
          [workspaceId, localMonitorId],
        );
        await TestUtils.execQuery(
          "DELETE FROM certificate_targets WHERE workspace_id = $1 AND domain_monitor_id = $2",
          [workspaceId, localMonitorId],
        );
        await TestUtils.execQuery(
          "DELETE FROM managed_certificates WHERE workspace_id = $1 AND source_ref = $2",
          [workspaceId, String(localMonitorId)],
        );
        await TestUtils.execQuery("DELETE FROM domain_monitors WHERE id = $1", [
          localMonitorId,
        ]);
      }
      if (localTokenId) {
        await TestUtils.execQuery("DELETE FROM tokens WHERE id = $1", [localTokenId]);
      }
      await httpsServer.close();
    }
  });
});
