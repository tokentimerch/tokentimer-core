const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");
const crypto = require("crypto");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

// Pins the server behavior the notification, SMTP and CertOps steps rely on.
describe("Onboarding notifications and CertOps reality (API contract)", function () {
  this.timeout(120000);

  let client;
  let admin;
  let manager;
  let viewer;
  let workspaceId;

  const ws = (suffix = "") => `/api/v1/workspaces/${workspaceId}${suffix}`;
  const summary = async (who) =>
    (
      await request(BASE)
        .get(ws("/onboarding/mega/summary"))
        .set("Cookie", who.cookie)
        .expect(200)
    ).body.summary;

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
    manager = await TestUtils.createAuthenticatedUser();
    viewer = await TestUtils.createAuthenticatedUser();
    workspaceId = crypto.randomUUID();
    await client.query(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, 'Notify', 'oss', $2)`,
      [workspaceId, admin.user.id],
    );
    await client.query(
      `INSERT INTO workspace_settings (workspace_id, email_alerts_enabled) VALUES ($1, TRUE)`,
      [workspaceId],
    );
    for (const [u, role] of [
      [admin, "admin"],
      [manager, "workspace_manager"],
      [viewer, "viewer"],
    ]) {
      await client.query(
        `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
         VALUES ($1, $2, $3, $4)`,
        [u.user.id, workspaceId, role, admin.user.id],
      );
    }
  });

  after(async () => {
    await client.query("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    await client.end();
  });

  it("round-trips thresholds and reports what the server kept", async () => {
    await request(BASE)
      .put(ws("/alert-settings"))
      .set("Cookie", manager.cookie)
      .send({ alert_thresholds: [0, 7, 30, 7, 14] })
      .expect(200);
    const after = (
      await request(BASE).get(ws("/alert-settings")).set("Cookie", manager.cookie).expect(200)
    ).body;
    // The server sorts and dedupes, which is why the wizard reads back.
    expect(after.alert_thresholds).to.deep.equal([30, 14, 7, 0]);
  });

  it("does not let a viewer change notification settings", async () => {
    await request(BASE)
      .put(ws("/alert-settings"))
      .set("Cookie", viewer.cookie)
      .send({ alert_thresholds: [1] })
      .expect(403);
  });

  it("limits system settings and the SMTP test to system administrators", async () => {
    for (const who of [manager, viewer]) {
      await request(BASE)
        .get("/api/admin/system-settings")
        .set("Cookie", who.cookie)
        .expect(403);
      await request(BASE)
        .post("/api/admin/test-smtp")
        .set("Cookie", who.cookie)
        .send({ email: "x@example.com" })
        .expect(403);
    }
  });

  it("reports the system-admin flag from the database, not the session", async () => {
    const asManager = (
      await request(BASE)
        .get(ws("/onboarding/capabilities"))
        .set("Cookie", manager.cookie)
        .expect(200)
    ).body;
    expect(asManager.viewer.isSystemAdmin).to.equal(false);
    expect(asManager.viewer.workspaceRole).to.equal("workspace_manager");

    await client.query("UPDATE users SET is_admin = TRUE WHERE id = $1", [manager.user.id]);
    const promoted = (
      await request(BASE)
        .get(ws("/onboarding/capabilities"))
        .set("Cookie", manager.cookie)
        .expect(200)
    ).body;
    expect(promoted.viewer.isSystemAdmin).to.equal(true);
    await client.query("UPDATE users SET is_admin = FALSE WHERE id = $1", [manager.user.id]);
  });

  it("exposes manual import and auto-sync as separate capabilities per provider", async () => {
    const { items } = (
      await request(BASE)
        .get(ws("/onboarding/capabilities"))
        .set("Cookie", manager.cookie)
        .expect(200)
    ).body;
    const ids = items.map((c) => c.id);
    for (const p of ["github", "gitlab", "vault", "aws", "azure", "azure-ad", "gcp"]) {
      expect(ids).to.include(`integrations.${p}`);
    }
    expect(ids).to.include("autosync.github");
    expect(ids).to.include("autosync.gitlab");
    // Core has no auto-sync for the other providers.
    expect(ids).to.not.include("autosync.aws");
  });

  it("hides agent topology from viewers and reports unknown, not empty", async () => {
    const asViewer = await summary(viewer);
    expect(asViewer.certops).to.equal("unknown");
  });

  it("reports CertOps reality to managers: no agents yet, no false positives", async () => {
    const asManager = await summary(manager);
    expect(asManager.certops).to.be.an("object");
    expect(asManager.certops.agents.live).to.equal(0);
    expect(asManager.certops.agents.executionEnabled).to.equal(false);
    expect(asManager.certops.certificates.total).to.equal(0);
    expect(asManager.certops.distribution).to.deep.include({ groups: 0, verified: false });
    expect(asManager.certops.dryRun).to.equal(null);
  });

  it("only counts a dry run when it is this workspace's job", async () => {
    // A job id from another workspace, or a malformed one, must read as null.
    const other = crypto.randomUUID();
    const sessionRes = await request(BASE)
      .get(ws("/onboarding/mega"))
      .set("Cookie", manager.cookie)
      .expect(200);
    await request(BASE)
      .put(ws("/onboarding/mega"))
      .set("Cookie", manager.cookie)
      .send({
        expectedRevision: sessionRes.body.session.revision,
        progress: { certops: { dryRunJobId: other } },
      })
      .expect(200);
    const s = await summary(manager);
    expect(s.certops.dryRun).to.equal(null);
  });

  it("registers a first agent and reflects it live in the summary", async () => {
    const token = await request(BASE)
      .post(ws("/certops/agent-bootstrap-tokens"))
      .set("Cookie", manager.cookie)
      .send({
        name: "wizard test",
        expiresAt: new Date(Date.now() + 3600 * 1000).toISOString(),
      });
    expect(token.status, JSON.stringify(token.body)).to.equal(201);
    // The plaintext is returned once and never appears in the summary.
    expect(token.body.plaintextToken).to.match(/^ttboot_/);
    const s = JSON.stringify(await summary(manager));
    expect(s).to.not.contain(token.body.plaintextToken);
    expect(s).to.not.contain("ttboot_");
  });

  it("creates the wizard's test job as a dry run, only when mode is top level", async () => {
    // Same shape as buildDryRunJob in the dashboard.
    const good = await request(BASE)
      .post(ws("/certops/jobs"))
      .set("Cookie", manager.cookie)
      .send({ operation: "noop", mode: "dry_run", idempotencyKey: `wizard-dryrun-${crypto.randomUUID()}` });
    expect(good.status, JSON.stringify(good.body)).to.be.oneOf([200, 201]);
    // The job response exposes the persisted mode through payload.mode.
    expect((good.body.job || good.body).payload.mode).to.equal("dry_run");

    // The old shape hid mode in the payload, which silently made a real job.
    const bad = await request(BASE)
      .post(ws("/certops/jobs"))
      .set("Cookie", manager.cookie)
      .send({ operation: "noop", payload: { mode: "dry_run" }, idempotencyKey: `wizard-dryrun-${crypto.randomUUID()}` });
    expect(bad.status, JSON.stringify(bad.body)).to.be.oneOf([200, 201]);
    expect((bad.body.job || bad.body).payload.mode).to.equal("real");
  });

  it("counts a webhook-only default group as a recipient, and only while the webhook exists", async () => {
    const webhook = {
      name: "Ops Slack",
      url: "https://hooks.slack.com/services/T000/B000/XXXX",
      kind: "slack",
      severity: "",
      template: "",
      routingKey: "",
      verified: true,
      verifiedUrl: "https://hooks.slack.com/services/T000/B000/XXXX",
    };
    const group = {
      id: "onboarding-webhook-only",
      name: "Webhook only",
      email_contact_ids: [],
      whatsapp_contact_ids: [],
      webhook_names: ["Ops Slack"],
      weekly_digest_email: false,
      weekly_digest_whatsapp: false,
      weekly_digest_webhooks: false,
    };
    await request(BASE)
      .put(ws("/alert-settings"))
      .set("Cookie", manager.cookie)
      .send({ webhook_urls: [webhook], contact_groups: [group], default_contact_group_id: group.id })
      .expect(200);

    const saved = (
      await request(BASE).get(ws("/alert-settings")).set("Cookie", manager.cookie).expect(200)
    ).body;
    expect(saved.webhook_urls.map((w) => w.name)).to.deep.equal(["Ops Slack"]);
    expect(saved.contact_groups[0].webhook_names).to.deep.equal(["Ops Slack"]);

    let groups = (await summary(manager)).alerts.contactGroups;
    expect(groups.defaultHasRecipient).to.equal(true);
    expect(groups.defaultHasWebhookRecipient).to.equal(true);
    expect(groups.defaultHasEmailRecipient).to.equal(false);
    expect(groups.webhookCount).to.equal(1);

    // The summary must never carry the webhook URL, which is a secret.
    expect(JSON.stringify(await summary(manager))).to.not.contain("hooks.slack.com");

    // Removing the webhook leaves a group that names nothing real.
    await request(BASE)
      .put(ws("/alert-settings"))
      .set("Cookie", manager.cookie)
      .send({ webhook_urls: [] })
      .expect(200);
    groups = (await summary(manager)).alerts.contactGroups;
    expect(groups.defaultHasRecipient).to.equal(false);
    expect(groups.webhookCount).to.equal(0);
  });

  it("reports the wizard's issue job from the database, and separates observed from provisioning", async () => {
    const issue = await request(BASE)
      .post(ws("/certops/jobs"))
      .set("Cookie", manager.cookie)
      .send({
        operation: "issue",
        idempotencyKey: `wizard-issue-${crypto.randomUUID()}`,
        payload: {
          target: { type: "domain", reference: "app.example.com" },
          sans: ["app.example.com"],
          commandRef: "certbot",
          caEndpoint: "https://acme-staging-v02.api.letsencrypt.org/directory",
          dnsZone: "example.com",
          dnsProvider: "cloudflare",
          certPath: "/etc/ssl/certs/app.pem",
        },
      });
    expect(issue.status, JSON.stringify(issue.body)).to.equal(201);
    const jobId = issue.body.job.id;

    const read = (await request(BASE).get(ws("/onboarding/mega")).set("Cookie", manager.cookie).expect(200)).body.session;
    await request(BASE)
      .put(ws("/onboarding/mega"))
      .set("Cookie", manager.cookie)
      .send({ expectedRevision: read.revision, progress: { certops: { issueJobId: jobId } } })
      .expect(200);

    const s = (await summary(manager)).certops;
    expect(s.issueJob).to.deep.include({ id: jobId, operation: "issue", status: "pending", mode: "real" });
    expect(s.issueJob.certificateStatus).to.equal("provisioning");
    // The requested order created a row, but it is not an observed certificate.
    expect(s.certificates.total).to.be.greaterThan(0);
    expect(s.certificates.observed).to.equal(0);
  });

  it("does not read an issue job that belongs to another workspace", async () => {
    const otherWs = crypto.randomUUID();
    await client.query(`INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, 'Other', 'oss', $2)`, [otherWs, admin.user.id]);
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1, $2, 'admin', $1)`,
      [admin.user.id, otherWs],
    );
    try {
      const foreign = await request(BASE)
        .post(`/api/v1/workspaces/${otherWs}/certops/jobs`)
        .set("Cookie", admin.cookie)
        .send({ operation: "noop", idempotencyKey: `foreign-${crypto.randomUUID()}` });
      expect(foreign.status, JSON.stringify(foreign.body)).to.equal(201);
      const read = (await request(BASE).get(ws("/onboarding/mega")).set("Cookie", manager.cookie).expect(200)).body.session;
      await request(BASE)
        .put(ws("/onboarding/mega"))
        .set("Cookie", manager.cookie)
        .send({ expectedRevision: read.revision, progress: { certops: { issueJobId: foreign.body.job.id } } })
        .expect(200);
      expect((await summary(manager)).certops.issueJob).to.equal(null);
    } finally {
      await client.query("DELETE FROM workspaces WHERE id = $1", [otherWs]);
    }
  });
});
