const { request, expect, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Workspace pending invitations list", function () {
  this.timeout(90000);

  let ownerUser;
  let ownerSession;
  let outsiderUser;
  let outsiderSession;
  let workspaceId;
  const pendingEmail = `pending-${Date.now()}@example.com`;

  before(async () => {
    ownerUser = await TestUtils.createVerifiedTestUser();
    ownerSession = await TestUtils.loginTestUser(
      ownerUser.email,
      "SecureTest123!@#",
    );
    outsiderUser = await TestUtils.createVerifiedTestUser();
    outsiderSession = await TestUtils.loginTestUser(
      outsiderUser.email,
      "SecureTest123!@#",
    );

    const wsRes = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    workspaceId = wsRes?.body?.items?.[0]?.id;

    await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/members`)
      .set("Cookie", ownerSession.cookie)
      .send({ email: pendingEmail, role: "viewer" })
      .expect(201);
  });

  after(async () => {
    await TestUtils.execQuery(
      "DELETE FROM workspace_invitations WHERE LOWER(email) = LOWER($1)",
      [pendingEmail],
    );
    await TestUtils.cleanupTestUser(ownerUser.email, ownerSession.cookie);
    await TestUtils.cleanupTestUser(outsiderUser.email, outsiderSession.cookie);
  });

  it("returns pending invitations without leaking the token column", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/invitations?limit=100&offset=0`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    expect(res.body.items).to.be.an("array");
    const found = res.body.items.find(
      (inv) => String(inv.email).toLowerCase() === pendingEmail.toLowerCase(),
    );
    expect(found, "pending invitation should be listed").to.exist;
    expect(found.role).to.equal("viewer");
    expect(found).to.not.have.property("token");
    expect(found.accepted_at == null).to.equal(true);
  });

  it("excludes already-accepted invitations from the list", async () => {
    await TestUtils.execQuery(
      `UPDATE workspace_invitations
          SET accepted_at = NOW()
        WHERE workspace_id = $1 AND LOWER(email) = LOWER($2)`,
      [workspaceId, pendingEmail],
    );
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/invitations?limit=100&offset=0`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    const stillThere = res.body.items.find(
      (inv) => String(inv.email).toLowerCase() === pendingEmail.toLowerCase(),
    );
    expect(stillThere, "accepted invitation must not appear").to.not.exist;
  });

  it("rejects non-members with 403", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/invitations?limit=100&offset=0`)
      .set("Cookie", outsiderSession.cookie);
    expect([401, 403]).to.include(res.status);
  });
});
