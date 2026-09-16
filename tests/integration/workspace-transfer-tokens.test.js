const crypto = require("crypto");
const { expect, request, TestUtils, TestEnvironment } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

async function putNamedGroup(cookie, workspaceId, groupId, name, contactId) {
  await request(BASE)
    .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
    .set("Cookie", cookie)
    .send({
      contact_groups: [
        {
          id: groupId,
          name,
          email_contact_ids: contactId ? [contactId] : [],
        },
      ],
      default_contact_group_id: groupId,
    })
    .expect(200);
}

async function createWorkspaceContact(cookie, workspaceId, email) {
  const res = await request(BASE)
    .post(`/api/v1/workspaces/${workspaceId}/contacts`)
    .set("Cookie", cookie)
    .send({
      first_name: "Transfer",
      last_name: "Contact",
      details: { email },
    })
    .expect(201);
  return String(res.body.id);
}

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

  it("transfers a grouped token and remaps the join row into the destination", async () => {
    const soon = new Date();
    soon.setDate(soon.getDate() + 30);
    const contactA = await createWorkspaceContact(
      cookie,
      wsA,
      `xfer-a-${Date.now()}@example.com`,
    );
    const contactB = await createWorkspaceContact(
      cookie,
      wsB,
      `xfer-b-${Date.now()}@example.com`,
    );
    await putNamedGroup(cookie, wsA, "src-ops", "On-call", contactA);
    await putNamedGroup(cookie, wsB, "dest-ops", "On-call", contactB);

    const created = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: `Grouped Xfer ${Date.now()}`,
        type: "api_key",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: wsA,
        contact_group_ids: ["src-ops"],
      })
      .expect(201);

    const res = await request(BASE)
      .post(`/api/v1/workspaces/${wsB}/transfer-tokens`)
      .set("Cookie", cookie)
      .send({ from_workspace_id: wsA, token_ids: [created.body.id] })
      .expect(200);

    expect(res.body.moved).to.equal(1);
    expect(res.body.dropped_contact_groups).to.deep.equal([]);

    const token = await TestUtils.execQuery(
      "SELECT workspace_id, contact_group_id FROM tokens WHERE id = $1",
      [created.body.id],
    );
    expect(token.rows[0].workspace_id).to.equal(wsB);
    expect(token.rows[0].contact_group_id).to.equal("dest-ops");

    const join = await TestUtils.execQuery(
      `SELECT workspace_id, contact_group_id
         FROM token_contact_groups
        WHERE token_id = $1`,
      [created.body.id],
    );
    expect(join.rows).to.have.length(1);
    expect(join.rows[0].workspace_id).to.equal(wsB);
    expect(join.rows[0].contact_group_id).to.equal("dest-ops");
  });

  it("moves an endpoint monitor with the token", async () => {
    const soon = new Date();
    soon.setDate(soon.getDate() + 30);
    const created = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: `Monitored Xfer ${Date.now()}`,
        type: "ssl_cert",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: wsA,
      })
      .expect(201);

    const monitor = await TestUtils.execQuery(
      `INSERT INTO domain_monitors (
         workspace_id, url, token_id, created_by
       ) VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [
        wsA,
        `https://xfer-monitor-${crypto.randomUUID()}.example`,
        created.body.id,
        user.id,
      ],
    );

    await request(BASE)
      .post(`/api/v1/workspaces/${wsB}/transfer-tokens`)
      .set("Cookie", cookie)
      .send({ from_workspace_id: wsA, token_ids: [created.body.id] })
      .expect(200);

    const moved = await TestUtils.execQuery(
      "SELECT workspace_id, token_id FROM domain_monitors WHERE id = $1",
      [monitor.rows[0].id],
    );
    expect(moved.rows[0].workspace_id).to.equal(wsB);
    expect(moved.rows[0].token_id).to.equal(created.body.id);
  });

  it("moves a managed certificate with the token", async () => {
    const soon = new Date();
    soon.setDate(soon.getDate() + 30);
    const created = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: `Managed Xfer ${Date.now()}`,
        type: "ssl_cert",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: wsA,
      })
      .expect(201);

    const fingerprint = crypto.randomBytes(32).toString("hex");
    const cert = await TestUtils.execQuery(
      `INSERT INTO managed_certificates (
         workspace_id, token_id, status, source, name, fingerprint_sha256
       ) VALUES ($1, $2, 'active', 'api', $3, $4)
       RETURNING id`,
      [wsA, created.body.id, `xfer-cert-${Date.now()}`, fingerprint],
    );

    await request(BASE)
      .post(`/api/v1/workspaces/${wsB}/transfer-tokens`)
      .set("Cookie", cookie)
      .send({ from_workspace_id: wsA, token_ids: [created.body.id] })
      .expect(200);

    const moved = await TestUtils.execQuery(
      "SELECT workspace_id, token_id FROM managed_certificates WHERE id = $1",
      [cert.rows[0].id],
    );
    expect(moved.rows[0].workspace_id).to.equal(wsB);
    expect(moved.rows[0].token_id).to.equal(created.body.id);
  });

  it("rejects a managed-certificate fingerprint collision in the destination", async () => {
    const soon = new Date();
    soon.setDate(soon.getDate() + 30);
    const fingerprint = crypto.randomBytes(32).toString("hex");

    const sourceToken = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: `Collision Src ${Date.now()}`,
        type: "ssl_cert",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: wsA,
      })
      .expect(201);

    const destToken = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: `Collision Dest ${Date.now()}`,
        type: "ssl_cert",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: wsB,
      })
      .expect(201);

    await TestUtils.execQuery(
      `INSERT INTO managed_certificates (
         workspace_id, token_id, status, source, name, fingerprint_sha256
       ) VALUES ($1, $2, 'active', 'api', $3, $4)`,
      [wsA, sourceToken.body.id, "src-collision", fingerprint],
    );
    await TestUtils.execQuery(
      `INSERT INTO managed_certificates (
         workspace_id, token_id, status, source, name, fingerprint_sha256
       ) VALUES ($1, $2, 'active', 'api', $3, $4)`,
      [wsB, destToken.body.id, "dest-collision", fingerprint],
    );

    const res = await request(BASE)
      .post(`/api/v1/workspaces/${wsB}/transfer-tokens`)
      .set("Cookie", cookie)
      .send({ from_workspace_id: wsA, token_ids: [sourceToken.body.id] })
      .expect(409);

    expect(res.body.code).to.equal("TRANSFER_CONFLICT");

    const stillSource = await TestUtils.execQuery(
      "SELECT workspace_id FROM tokens WHERE id = $1",
      [sourceToken.body.id],
    );
    expect(stillSource.rows[0].workspace_id).to.equal(wsA);
  });
});
