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

    const wsRes = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    workspaceId = wsRes?.body?.items?.[0]?.id;

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
    const soon = new Date();
    soon.setUTCDate(soon.getUTCDate() + 5);

    await request(BASE)
      .post("/api/tokens")
      .set("Cookie", ownerSession.cookie)
      .send({
        name: "CC Stats Expired Cert",
        type: "tls_cert",
        category: "cert",
        expiresAt: expired.toISOString().slice(0, 10),
        workspace_id: workspaceId,
      })
      .expect(201);

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
});
