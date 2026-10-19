const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");
const crypto = require("crypto");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Onboarding sessions", function () {
  this.timeout(120000);

  let client;
  let owner;
  let viewer;
  let outsider;
  let workspaceId;
  let otherWorkspaceId;

  const path = (ws, suffix = "") => `/api/v1/workspaces/${ws}/onboarding${suffix}`;

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
    viewer = await TestUtils.createAuthenticatedUser();
    outsider = await TestUtils.createAuthenticatedUser();

    workspaceId = crypto.randomUUID();
    otherWorkspaceId = crypto.randomUUID();
    for (const id of [workspaceId, otherWorkspaceId]) {
      await client.query(
        `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, $2, 'oss', $3)`,
        [id, `Onboarding ${id.slice(0, 8)}`, owner.user.id],
      );
    }
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'admin', $1)`,
      [owner.user.id, workspaceId],
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'viewer', $3)`,
      [viewer.user.id, workspaceId, owner.user.id],
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'admin', $1)`,
      [owner.user.id, otherWorkspaceId],
    );
  });

  after(async () => {
    await client.query("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [
      [workspaceId, otherWorkspaceId],
    ]);
    await client.end();
  });

  it("starts empty at revision 0", async () => {
    const res = await request(BASE)
      .get(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(res.body.session.exists).to.equal(false);
    expect(res.body.session.revision).to.equal(0);
  });

  it("resumes on another device without losing state", async () => {
    const created = await request(BASE)
      .put(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .send({
        expectedRevision: 0,
        intent: { goal: "monitor_https" },
        progress: { position: "monitor" },
        operation_refs: { monitorUrl: "https://example.com" },
      })
      .expect(200);
    expect(created.body.session.revision).to.equal(1);

    // A second login for the same user is a different device.
    const second = await TestUtils.loginTestUser(owner.email, owner.password);
    const resumed = await request(BASE)
      .get(path(workspaceId, "/mega"))
      .set("Cookie", second.cookie)
      .expect(200);
    expect(resumed.body.session.intent.goal).to.equal("monitor_https");
    expect(resumed.body.session.operationRefs.monitorUrl).to.equal(
      "https://example.com",
    );
    expect(resumed.body.session.revision).to.equal(1);
  });

  it("rejects a stale write with the current session for replay", async () => {
    const res = await request(BASE)
      .put(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .send({ expectedRevision: 0, progress: { position: "stale" } })
      .expect(409);
    expect(res.body.code).to.equal("REVISION_CONFLICT");
    expect(res.body.current.revision).to.equal(1);
    expect(res.body.current.progress.position).to.equal("monitor");

    const ok = await request(BASE)
      .put(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .send({
        expectedRevision: res.body.current.revision,
        progress: { position: "contacts" },
      })
      .expect(200);
    expect(ok.body.session.revision).to.equal(2);
    // Sections not sent are preserved.
    expect(ok.body.session.operationRefs.monitorUrl).to.equal(
      "https://example.com",
    );
  });

  it("refuses to persist credentials", async () => {
    const res = await request(BASE)
      .put(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .send({ expectedRevision: 2, operation_refs: { apiKey: "x" } })
      .expect(400);
    expect(res.body.code).to.equal("SECRET_REJECTED");

    await request(BASE)
      .put(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .send({
        expectedRevision: 2,
        progress: { note: "ttboot_0123456789abcdef_" + "a".repeat(64) },
      })
      .expect(400);

    const after = await request(BASE)
      .get(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(after.body.session.revision).to.equal(2);
  });

  it("keeps sessions private per user and per workspace", async () => {
    const asViewer = await request(BASE)
      .get(path(workspaceId, "/mega"))
      .set("Cookie", viewer.cookie)
      .expect(200);
    expect(asViewer.body.session.exists).to.equal(false);

    const otherWs = await request(BASE)
      .get(path(otherWorkspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(otherWs.body.session.exists).to.equal(false);

    const certops = await request(BASE)
      .get(path(workspaceId, "/certops"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(certops.body.session.exists).to.equal(false);
  });

  it("lets viewers keep their own progress but not see non-members' workspaces", async () => {
    await request(BASE)
      .put(path(workspaceId, "/mega"))
      .set("Cookie", viewer.cookie)
      .send({ expectedRevision: 0, intent: { goal: "just_look" } })
      .expect(200);

    const res = await request(BASE)
      .get(path(workspaceId, "/mega"))
      .set("Cookie", outsider.cookie);
    expect([403, 404]).to.include(res.status);
  });

  it("requires authentication and a known flow", async () => {
    await request(BASE).get(path(workspaceId, "/mega")).expect(401);
    await request(BASE)
      .get(path(workspaceId, "/bogus"))
      .set("Cookie", owner.cookie)
      .expect(400);
  });

  it("derives completion from what really exists, not from stored refs", async () => {
    const monitorId = crypto.randomUUID();
    await client.query(
      `INSERT INTO domain_monitors (id, workspace_id, url, created_by)
       VALUES ($1, $2, 'https://example.com', $3)`,
      [monitorId, workspaceId, owner.user.id],
    );
    const sessionRes = await request(BASE)
      .get(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .expect(200);
    await request(BASE)
      .put(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .send({
        expectedRevision: sessionRes.body.session.revision,
        operation_refs: { monitorIds: [monitorId], tokenIds: [999999999] },
      })
      .expect(200);

    const present = await request(BASE)
      .get(path(workspaceId, "/mega/summary"))
      .set("Cookie", owner.cookie)
      .expect(200);
    const refs = present.body.summary.references;
    expect(refs.monitorIds.existing).to.deep.equal([monitorId]);
    expect(refs.tokenIds.missing).to.deep.equal([999999999]);
    expect(present.body.summary.monitors.total).to.equal(1);
    expect(present.body.summary.alerts.contactGroups).to.have.property("count");

    await client.query("DELETE FROM domain_monitors WHERE id = $1", [monitorId]);
    const gone = await request(BASE)
      .get(path(workspaceId, "/mega/summary"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(gone.body.summary.references.monitorIds.missing).to.deep.equal([
      monitorId,
    ]);
    expect(gone.body.summary.monitors.total).to.equal(0);
  });

  it("reports role-aware capabilities and the docs base URL", async () => {
    const asOwner = await request(BASE)
      .get(path(workspaceId, "/capabilities"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(asOwner.body.docsBaseUrl).to.match(/^https:\/\//);
    const endpoint = asOwner.body.items.find((c) => c.id === "monitoring.endpoint");
    expect(endpoint.state).to.equal("ready");
    const adcs = asOwner.body.items.find((c) => c.id === "certops.adcs");
    expect(adcs.state).to.equal("candidate");

    const asViewer = await request(BASE)
      .get(path(workspaceId, "/capabilities"))
      .set("Cookie", viewer.cookie)
      .expect(200);
    const viewerEndpoint = asViewer.body.items.find(
      (c) => c.id === "monitoring.endpoint",
    );
    expect(viewerEndpoint.state).to.equal("role_handoff");
    expect(viewerEndpoint.blockers[0].code).to.equal("ROLE_REQUIRED");
  });

  it("resets only the session, never created assets", async () => {
    const res = await request(BASE)
      .post(path(workspaceId, "/mega/reset"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(res.body.reset).to.equal(true);
    const after = await request(BASE)
      .get(path(workspaceId, "/mega"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(after.body.session.exists).to.equal(false);
    const again = await request(BASE)
      .post(path(workspaceId, "/mega/reset"))
      .set("Cookie", owner.cookie)
      .expect(200);
    expect(again.body.reset).to.equal(false);
  });
});
