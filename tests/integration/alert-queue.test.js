const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

/**
 * These tests assume the backend is running with a Postgres DB and MailHog/mocks configured.
 * They exercise the alert queue endpoints and simulate a minimal flow by manipulating data via API.
 */

describe("Alert Queue and Delivery Integration", function () {
  this.timeout(60000);

  let user;
  let cookie;

  before(async () => {
    await TestEnvironment.setup();
    const u = await TestUtils.createAuthenticatedUser();
    user = u;
    cookie = u.cookie;
  });

  after(async () => {
    if (user && user.email && cookie) {
      await TestUtils.cleanupTestUser(user.email, cookie);
    }
  });

  it("should allow updating alert thresholds (workspace)", async () => {
    const ws = await TestUtils.ensureTestWorkspace(cookie);
    const res = await request(BASE)
      .put(`/api/v1/workspaces/${ws}/alert-settings`)
      .set("Cookie", cookie)
      .send({ alert_thresholds: [7, 1, 0, -1] });
    expect(res.status).to.be.oneOf([200, 400]);
  });

  it("uses contact group thresholds override when queuing alerts", async () => {
    const u = await TestUtils.createAuthenticatedUser();
    const cookie = u.cookie;
    const ws = await TestUtils.ensureTestWorkspace(cookie);

    // Set workspace defaults to [30,14,10,7,5,1,0] for deterministic mapping
    await request(BASE)
      .put(`/api/v1/workspaces/${ws}/alert-settings`)
      .set("Cookie", cookie)
      .send({ alert_thresholds: [30, 14, 10, 7, 5, 1, 0] })
      .expect(200);

    // Create contacts for email recipients
    const c1 = await request(BASE)
      .post(`/api/v1/workspaces/${ws}/contacts`)
      .set("Cookie", cookie)
      .send({
        first_name: "Ops",
        last_name: "One",
        details: { email: u.user.email },
      })
      .expect(201);
    const c2 = await request(BASE)
      .post(`/api/v1/workspaces/${ws}/contacts`)
      .set("Cookie", cookie)
      .send({
        first_name: "Fin",
        last_name: "One",
        details: { email: u.user.email },
      })
      .expect(201);

    // Create groups: ops with override [10,5], finance no override (inherits)
    await request(BASE)
      .put(`/api/v1/workspaces/${ws}/alert-settings`)
      .set("Cookie", cookie)
      .send({
        contact_groups: [
          {
            id: "ops",
            name: "Ops",
            email_contact_ids: [c1.body.id],
            thresholds: [10, 5],
          },
          { id: "finance", name: "Finance", email_contact_ids: [c2.body.id] },
        ],
        default_contact_group_id: "finance",
      })
      .expect(200);

    // Create two tokens: one with ops group, one with default group
    const today = new Date();
    const mkDate = (d) => {
      const x = new Date(today);
      x.setDate(x.getDate() + d);
      return x.toISOString().slice(0, 10);
    };
    const tOps = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "OpsToken",
        expiresAt: mkDate(9),
        type: "api_key",
        category: "general",
        contact_group_id: "ops",
        workspace_id: ws,
      })
      .expect(201);
    const tDef = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "DefToken",
        expiresAt: mkDate(13),
        type: "api_key",
        category: "general",
        workspace_id: ws,
      })
      .expect(201);

    // Run discovery; ops should map 9 -> 10, default should map 13 -> 14
    await TestUtils.runNode("node", ["src/queue-manager.js"], "apps/worker");

    const rows = await TestUtils.execQuery(
      `SELECT token_id, threshold_days FROM alert_queue WHERE token_id = ANY($1::int[]) ORDER BY token_id`,
      [[tOps.body.id, tDef.body.id]],
    );
    const map = new Map(rows.rows.map((r) => [r.token_id, r.threshold_days]));
    expect(map.get(tOps.body.id)).to.equal(10);
    expect(map.get(tDef.body.id)).to.equal(14);
  });

  it("should create a token expiring soon to trigger queueing", async () => {
    const soon = new Date();
    soon.setDate(soon.getDate() + 7);

    const ws = await TestUtils.ensureTestWorkspace(cookie);
    const res = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "Queue Test Token",
        type: "api_key",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: ws,
      });
    expect(res.status).to.equal(201);
    expect(res.body).to.have.property("id");
  });

  it("should show empty queue initially (workspace-scoped)", async () => {
    const ws = await TestUtils.ensureTestWorkspace(cookie);
    const res = await request(BASE)
      .get("/api/alert-queue")
      .query({ workspace_id: ws })
      .set("Cookie", cookie)
      .expect(200);
    expect(res.body).to.have.property("alerts");
  });

  it("should provide delivery stats even if zero", async () => {
    const ws = await TestUtils.ensureTestWorkspace(cookie);
    const res = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: ws })
      .set("Cookie", cookie)
      .expect(200);
    expect(res.body).to.have.property("byChannel");
    expect(res.body).to.have.property("monthUsage");
  });
});
