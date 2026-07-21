const { request, expect, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Control center stats API", function () {
  this.timeout(90000);

  let ownerUser;
  let ownerSession;
  let viewerUser;
  let viewerSession;
  let workspaceId;

  before(async () => {
    ownerUser = await TestUtils.createVerifiedTestUser();
    ownerSession = await TestUtils.loginTestUser(
      ownerUser.email,
      "SecureTest123!@#",
    );

    workspaceId = (
      await request(BASE)
        .post("/api/v1/workspaces")
        .set("Cookie", ownerSession.cookie)
        .send({ name: `Control Center Stats WS ${Date.now()}` })
        .expect(201)
    ).body.id;

    viewerUser = await TestUtils.createVerifiedTestUser();
    viewerSession = await TestUtils.loginTestUser(
      viewerUser.email,
      "SecureTest123!@#",
    );

    await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/members`)
      .set("Cookie", ownerSession.cookie)
      .send({ email: viewerUser.email, role: "viewer" })
      .expect(201);
  });

  after(async () => {
    if (ownerSession?.cookie) {
      await TestUtils.cleanupTestUser(ownerUser.email, ownerSession.cookie);
    }
    if (viewerSession?.cookie) {
      await TestUtils.cleanupTestUser(viewerUser.email, viewerSession.cookie);
    }
  });

  it("returns 403 for viewers (manager role required)", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/control-center/stats`)
      .set("Cookie", viewerSession.cookie)
      .expect(403);
    expect(res.body.error).to.equal("Forbidden");
  });

  it("returns aggregated stats for workspace managers", async () => {
    const expired = new Date();
    expired.setUTCDate(expired.getUTCDate() - 3);
    const expiredDate = expired.toISOString().slice(0, 10);
    const soon = new Date();
    soon.setUTCDate(soon.getUTCDate() + 5);

    await TestUtils.execQuery(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1, $2, $1, $3, $4, 'tls_cert', 'cert')`,
      [ownerUser.id, workspaceId, "CC Stats Expired Cert", expiredDate],
    );

    await request(BASE)
      .post("/api/tokens")
      .set("Cookie", ownerSession.cookie)
      .send({
        name: "CC Stats Soon Key",
        type: "api_key",
        category: "key_secret",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: workspaceId,
      })
      .expect(201);

    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/control-center/stats`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);

    expect(res.body).to.have.property("totalAssets");
    expect(res.body.totalAssets).to.be.at.least(2);
    expect(res.body).to.have.property("buckets");
    expect(res.body.buckets).to.include.keys(
      "healthy",
      "neverExpires",
      "expiring7",
      "expiring8To30",
      "expired",
      "critical",
    );
    expect(res.body.buckets.critical).to.equal(
      res.body.buckets.expired + res.body.buckets.expiring7,
    );
    expect(res.body).to.have.property("sources");
    expect(Array.isArray(res.body.sources)).to.equal(true);
    expect(res.body).to.have.property("needsAttention");
    expect(res.body.needsAttention.length).to.be.at.most(10);
    expect(res.body.isComplete).to.equal(true);
    expect(res.body.generatedAt).to.be.a("string");

    const attentionBuckets = res.body.needsAttention.map((item) => item.bucket);
    expect(attentionBuckets.some((b) => b === "expired" || b === "expiring7"))
      .to.equal(true);
  });

  it("reports the true privileged-token total separately from the capped preview list", async () => {
    const farFuture = new Date();
    farFuture.setUTCFullYear(farFuture.getUTCFullYear() + 5);
    const farFutureDate = farFuture.toISOString().slice(0, 10);

    const privilegedNames = [];
    for (let i = 0; i < 25; i += 1) {
      const name = `CC Stats Privileged Token ${i}`;
      privilegedNames.push(name);
      await TestUtils.execQuery(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category, privileges)
         VALUES ($1, $2, $1, $3, $4, 'api_key', 'key_secret', $5)`,
        [ownerUser.id, workspaceId, name, farFutureDate, "admin, write, delete"],
      );
    }

    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/control-center/stats`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);

    expect(res.body).to.have.property("privilegeHighlightsTotal");
    expect(Array.isArray(res.body.privilegeHighlights)).to.equal(true);
    expect(res.body.privilegeHighlights.length).to.be.at.most(20);
    expect(res.body.privilegeHighlightsTotal).to.be.at.least(
      privilegedNames.length,
    );
    expect(res.body.privilegeHighlightsTotal).to.be.at.least(
      res.body.privilegeHighlights.length,
    );
    expect(res.body).to.have.property("privilegeHighlightsHasMore");
    expect(res.body.privilegeHighlightsHasMore).to.equal(true);

    // Second page picks up where the embedded first page left off.
    const page2 = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceId}/control-center/privilege-highlights`,
      )
      .query({ limit: 20, offset: res.body.privilegeHighlights.length })
      .set("Cookie", ownerSession.cookie)
      .expect(200);

    expect(page2.body).to.have.property("items");
    expect(page2.body).to.have.property("total");
    expect(page2.body).to.have.property("hasMore");
    expect(page2.body.items.length).to.be.at.least(1);
    const firstPageIds = new Set(
      res.body.privilegeHighlights.map((item) => item.id),
    );
    expect(page2.body.items.every((item) => !firstPageIds.has(item.id))).to
      .equal(true);
  });

  it("paginates the perpetual assets list via the never-expires endpoint", async () => {
    const names = [];
    for (let i = 0; i < 25; i += 1) {
      const name = `CC Stats Perpetual Asset ${i}`;
      names.push(name);
      await TestUtils.execQuery(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES ($1, $2, $1, $3, '9999-12-31', 'api_key', 'key_secret')`,
        [ownerUser.id, workspaceId, name],
      );
    }

    const statsRes = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/control-center/stats`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);

    expect(statsRes.body).to.have.property("neverExpiresHasMore");
    expect(statsRes.body.neverExpiresHasMore).to.equal(true);
    expect(statsRes.body.neverExpires.length).to.be.at.most(20);

    const page2 = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/control-center/never-expires`)
      .query({ limit: 20, offset: statsRes.body.neverExpires.length })
      .set("Cookie", ownerSession.cookie)
      .expect(200);

    expect(page2.body.items.length).to.be.at.least(1);
    expect(page2.body.total).to.be.at.least(names.length);
    const firstPageIds = new Set(
      statsRes.body.neverExpires.map((item) => item.id),
    );
    expect(page2.body.items.every((item) => !firstPageIds.has(item.id))).to
      .equal(true);
  });

  it("rejects viewers from the pagination endpoints (manager role required)", async () => {
    const res1 = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/control-center/never-expires`)
      .set("Cookie", viewerSession.cookie)
      .expect(403);
    expect(res1.body.error).to.equal("Forbidden");

    const res2 = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceId}/control-center/privilege-highlights`,
      )
      .set("Cookie", viewerSession.cookie)
      .expect(403);
    expect(res2.body.error).to.equal("Forbidden");
  });
});
