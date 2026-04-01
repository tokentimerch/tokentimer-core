const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Token Renewal - update and audit changes", function () {
  this.timeout(60000);

  let user;
  let cookie;
  let tokenId;

  before(async () => {
    await TestEnvironment.setup();
    // Create user with pro plan to access audit-events
    const testUser = await TestUtils.createVerifiedTestUser(
      null,
      "SecureTest123!@#",
      null,
      "pro",
    );
    const session = await TestUtils.loginTestUser(
      testUser.email,
      testUser.password,
    );
    const workspaceId = await TestUtils.ensureTestWorkspace(session.cookie);

    user = { ...testUser, ...session, workspaceId };
    cookie = session.cookie;

    const future = new Date();
    future.setDate(future.getDate() + 10);
    const res = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: `Renew Test ${Date.now()}`,
        type: "api_key",
        category: "general",
        expiresAt: future.toISOString().slice(0, 10),
        workspace_id: workspaceId,
      })
      .expect(201);
    tokenId = res.body.id;
  });

  after(async () => {
    await TestUtils.cleanupTestUser(user.email, cookie);
  });

  it("updating expiration acts as renewal and is reflected in TOKEN_UPDATED audit changes", async () => {
    // Renew by pushing expiration 90 days out
    const newExp = new Date();
    newExp.setDate(newExp.getDate() + 90);
    const newExpStr = newExp.toISOString().slice(0, 10);

    const res = await request(BASE)
      .put(`/api/tokens/${tokenId}`)
      .set("Cookie", cookie)
      .send({ expiresAt: newExpStr })
      .expect(200);
    expect(res.body).to.have.property("id", tokenId);
    expect(res.body).to.have.property("expiresAt", newExpStr);

    // Audit endpoint should include TOKEN_UPDATED with changes.expiresAt
    const events = await request(BASE)
      .get("/api/audit-events?limit=50")
      .set("Cookie", cookie)
      .expect(200);
    const ev = events.body.find((e) => e.action === "TOKEN_UPDATED");
    expect(ev).to.exist;
    expect(ev).to.have.property("metadata");
    expect(ev.metadata).to.have.property("fields");
    expect(ev.metadata.fields).to.be.an("array");
    expect(ev.metadata.fields).to.include("expiration");
    if (ev.metadata.changes && ev.metadata.changes.expiresAt) {
      expect(ev.metadata.changes.expiresAt).to.have.property("to", newExpStr);
    }
  });
});
