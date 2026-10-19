const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");
const crypto = require("crypto");
const { startLocalHttpsServer } = require("./helpers/local-https-server");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

// Walks the same endpoints, in the same order, as the first-value wizard
// journey, and pins the server behaviors its client-side logic depends on.
describe("Onboarding first-value journey (API contract)", function () {
  this.timeout(120000);

  let client;
  let owner;
  let workspaceId;
  let https;
  let monitor;

  const ws = (suffix = "") => `/api/v1/workspaces/${workspaceId}${suffix}`;
  const summary = async () =>
    (
      await request(BASE)
        .get(ws("/onboarding/mega/summary"))
        .set("Cookie", owner.cookie)
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
    owner = await TestUtils.createAuthenticatedUser();
    workspaceId = crypto.randomUUID();
    await client.query(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, 'First value', 'oss', $2)`,
      [workspaceId, owner.user.id],
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'admin', $1)`,
      [owner.user.id, workspaceId],
    );
    https = await startLocalHttpsServer();
  });

  after(async () => {
    await https.close();
    await client.query("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    await client.end();
  });

  it("creates the monitor, reads the certificate and links an asset", async () => {
    const res = await request(BASE)
      .post(ws("/domains"))
      .set("Cookie", owner.cookie)
      .send({ url: https.url, health_check_enabled: true })
      .expect(201);
    monitor = res.body;
    expect(monitor.ssl_valid_to, "certificate expiry").to.be.ok;
    expect(monitor.token_id, "linked asset").to.be.ok;

    const s = await summary();
    const item = s.monitors.items.find((m) => m.id === monitor.id);
    expect(item.certificateExpiresAt).to.be.ok;
    expect(item.tokenId).to.equal(monitor.token_id);
  });

  it("is idempotent per URL, so a retry cannot create a second monitor", async () => {
    const again = await request(BASE)
      .post(ws("/domains"))
      .set("Cookie", owner.cookie)
      .send({ url: https.url })
      .expect(200);
    expect(again.body.id).to.equal(monitor.id);
    const list = await request(BASE)
      .get(ws("/domains"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(list.body.items.filter((m) => m.url === monitor.url)).to.have.length(1);
  });

  it("reports no usable recipient until a default group has an email contact", async () => {
    const before = await summary();
    expect(before.alerts.contactGroups.defaultHasEmailRecipient).to.equal(false);
    const token = await request(BASE)
      .get(`/api/tokens/${monitor.token_id}`)
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(token.body.alert_state.eligibility.eligible_channels).to.deep.equal([]);
  });

  it("keeps existing groups intact when the wizard appends one", async () => {
    const existingContact = (
      await request(BASE)
        .post(ws("/contacts"))
        .set("Cookie", owner.cookie)
        .send({
          first_name: "Pat",
          last_name: "Existing",
          details: { email: "pat@example.com" },
        })
        .expect(201)
    ).body;
    await request(BASE)
      .put(ws("/alert-settings"))
      .set("Cookie", owner.cookie)
      .send({
        contact_groups: [
          {
            id: "platform",
            name: "Platform",
            email_contact_ids: [existingContact.id],
            thresholds: [90, 30],
            weekly_digest_email: true,
          },
        ],
      })
      .expect(200);

    // The wizard reads the live list, appends, and writes it back.
    const settings = (
      await request(BASE).get(ws("/alert-settings")).set("Cookie", owner.cookie).expect(200)
    ).body;
    const contact = (
      await request(BASE)
        .post(ws("/contacts"))
        .set("Cookie", owner.cookie)
        .send({
          first_name: "Ana",
          last_name: "Lopez",
          details: { email: "ana@example.com" },
        })
        .expect(201)
    ).body;
    await request(BASE)
      .put(ws("/alert-settings"))
      .set("Cookie", owner.cookie)
      .send({
        contact_groups: [
          ...settings.contact_groups,
          {
            id: "onboarding-ana-example-com",
            name: "Alert recipients",
            email_contact_ids: [contact.id],
            weekly_digest_email: false,
            weekly_digest_whatsapp: false,
            weekly_digest_webhooks: false,
          },
        ],
        default_contact_group_id: "onboarding-ana-example-com",
      })
      .expect(200);

    const after = (
      await request(BASE).get(ws("/alert-settings")).set("Cookie", owner.cookie).expect(200)
    ).body;
    expect(after.default_contact_group_id).to.equal("onboarding-ana-example-com");
    const platform = after.contact_groups.find((g) => g.id === "platform");
    expect(platform.thresholds).to.deep.equal([90, 30]);
    expect(platform.weekly_digest_email).to.equal(true);
    expect(platform.email_contact_ids).to.deep.equal([existingContact.id]);
  });

  it("routes the existing asset through the new default group", async () => {
    const s = await summary();
    expect(s.alerts.contactGroups.defaultHasEmailRecipient).to.equal(true);
    const token = await request(BASE)
      .get(`/api/tokens/${monitor.token_id}`)
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(token.body.alert_state.eligibility.eligible_channels).to.include("email");
  });

  it("returns the identity of a conflicting asset so the wizard can reconcile", async () => {
    const body = {
      workspace_id: workspaceId,
      name: "Deploy key",
      category: "key_secret",
      type: "api_key",
      expiresAt: "2099-01-15",
      location: "ci/prod",
    };
    await request(BASE).post("/api/tokens").set("Cookie", owner.cookie).send(body).expect(201);
    const dup = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", owner.cookie)
      .send(body)
      .expect(409);
    expect(dup.body.code).to.equal("DUPLICATE_TOKEN");
    expect(dup.body.existing_token).to.include({
      name: "Deploy key",
      location: "ci/prod",
    });
    expect(dup.body.existing_token.id).to.be.a("number");
  });

  it("does not conflict on an empty location, which is why the wizard reconciles by identity", async () => {
    const body = {
      workspace_id: workspaceId,
      name: "No location key",
      category: "key_secret",
      type: "api_key",
      expiresAt: "2099-02-01",
    };
    await request(BASE).post("/api/tokens").set("Cookie", owner.cookie).send(body).expect(201);
    await request(BASE).post("/api/tokens").set("Cookie", owner.cookie).send(body).expect(201);

    const found = await request(BASE)
      .get("/api/tokens")
      .query({ workspace_id: workspaceId, q: "No location key", limit: 20 })
      .set("Cookie", owner.cookie)
      .expect(200);
    const matches = found.body.items.filter((t) => t.name === "No location key");
    // The duplicate really exists server-side, so only a pre-create lookup by
    // identity can prevent it.
    expect(matches).to.have.length(2);
    expect(matches[0]).to.include.keys("name", "category", "type", "expiresAt");
  });
});
