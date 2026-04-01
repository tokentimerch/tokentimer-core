const { expect, request, TestUtils, TestEnvironment } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Workspace Transfer Tokens", function () {
  this.timeout(60000);

  let user, cookie, wsA, wsB;

  before(async () => {
    await TestEnvironment.setup();
    user = await TestUtils.createVerifiedTestUser();
    const session = await TestUtils.loginTestUser(user.email, user.password);
    cookie = session.cookie;

    const resA = await request(BASE)
      .post("/api/v1/workspaces")
      .set("Cookie", cookie)
      .send({ name: `Transfer Source ${Date.now()}` })
      .expect(201);
    wsA =
      resA.body.id || resA.body.workspace?.id || resA.body?.workspace?.id;

    const resB = await request(BASE)
      .post("/api/v1/workspaces")
      .set("Cookie", cookie)
      .send({ name: `Transfer Target ${Date.now()}` })
      .expect(201);
    wsB =
      resB.body.id || resB.body.workspace?.id || resB.body?.workspace?.id;

    // If workspace creation returns the id in a different shape, fall back to ensureTestWorkspace
    if (!wsA) wsA = await TestUtils.ensureTestWorkspace(cookie);
    if (!wsB) {
      const res = await request(BASE)
        .post("/api/v1/workspaces")
        .set("Cookie", cookie)
        .send({ name: `Transfer Target Fallback ${Date.now()}` });
      wsB = res.body.id || res.body.workspace?.id;
    }
  });

  it("transfers tokens from source to target workspace", async () => {
    const soon = new Date();
    soon.setDate(soon.getDate() + 30);

    const t1 = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "Xfer Token 1",
        type: "api_key",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: wsA,
      })
      .expect(201);

    const t2 = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "Xfer Token 2",
        type: "ssl_cert",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: wsA,
      })
      .expect(201);

    const res = await request(BASE)
      .post(`/api/v1/workspaces/${wsB}/transfer-tokens`)
      .set("Cookie", cookie)
      .send({
        from_workspace_id: wsA,
        token_ids: [t1.body.id, t2.body.id],
      });

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("moved");
    expect(res.body.moved).to.equal(2);

    // Verify tokens are now in target workspace
    const check = await TestUtils.execQuery(
      "SELECT workspace_id FROM tokens WHERE id = ANY($1::int[])",
      [[t1.body.id, t2.body.id]],
    );
    for (const row of check.rows) {
      expect(row.workspace_id).to.equal(wsB);
    }
  });

  it("rejects transfer with missing from_workspace_id", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${wsB}/transfer-tokens`)
      .set("Cookie", cookie)
      .send({ token_ids: [1] })
      .expect(400);

    expect(res.body.code).to.equal("VALIDATION_ERROR");
  });

  it("rejects transfer with empty token_ids", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${wsB}/transfer-tokens`)
      .set("Cookie", cookie)
      .send({ from_workspace_id: wsA, token_ids: [] })
      .expect(400);

    expect(res.body.code).to.equal("VALIDATION_ERROR");
  });

  it("rejects transfer when source and target are the same", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${wsA}/transfer-tokens`)
      .set("Cookie", cookie)
      .send({ from_workspace_id: wsA, token_ids: [1] })
      .expect(400);

    expect(res.body.code).to.equal("VALIDATION_ERROR");
  });
});
