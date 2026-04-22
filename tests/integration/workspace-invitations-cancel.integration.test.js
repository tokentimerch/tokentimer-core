const { request, expect, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Workspace pending invitation cancellation", function () {
  this.timeout(90000);

  let ownerUser;
  let ownerSession;
  let viewerUser;
  let viewerSession;
  let outsiderUser;
  let outsiderSession;
  let workspaceId;

  async function seedInvite(email, role = "viewer") {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/members`)
      .set("Cookie", ownerSession.cookie)
      .send({ email, role })
      .expect(201);
    expect(res.body.role).to.equal(role);
    const row = await TestUtils.execQuery(
      `SELECT id FROM workspace_invitations
        WHERE workspace_id = $1 AND LOWER(email) = LOWER($2)
          AND accepted_at IS NULL
        ORDER BY created_at DESC LIMIT 1`,
      [workspaceId, email],
    );
    return row.rows[0]?.id;
  }

  before(async () => {
    ownerUser = await TestUtils.createVerifiedTestUser();
    ownerSession = await TestUtils.loginTestUser(
      ownerUser.email,
      "SecureTest123!@#",
    );
    viewerUser = await TestUtils.createVerifiedTestUser();
    viewerSession = await TestUtils.loginTestUser(
      viewerUser.email,
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
      .send({ email: viewerUser.email, role: "viewer" })
      .expect(201);
  });

  after(async () => {
    await TestUtils.execQuery(
      `DELETE FROM workspace_invitations WHERE workspace_id = $1`,
      [workspaceId],
    );
    await TestUtils.cleanupTestUser(ownerUser.email, ownerSession.cookie);
    await TestUtils.cleanupTestUser(viewerUser.email, viewerSession.cookie);
    await TestUtils.cleanupTestUser(outsiderUser.email, outsiderSession.cookie);
  });

  it("admin cancels a pending invitation and writes audit event", async () => {
    const email = `cancel-${Date.now()}@example.com`;
    const invId = await seedInvite(email);
    expect(invId, "seed returned invitation id").to.exist;

    await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/invitations/${invId}`)
      .set("Cookie", ownerSession.cookie)
      .expect(204);

    const check = await TestUtils.execQuery(
      `SELECT 1 FROM workspace_invitations WHERE id = $1`,
      [invId],
    );
    expect(check.rowCount).to.equal(0);

    const audit = await TestUtils.execQuery(
      `SELECT action, target_type, metadata
         FROM audit_events
        WHERE workspace_id = $1 AND action = 'INVITATION_CANCELLED'
          AND actor_user_id = $2
        ORDER BY occurred_at DESC
        LIMIT 5`,
      [workspaceId, ownerUser.id],
    );
    const hit = audit.rows.find(
      (r) =>
        r.metadata &&
        String(r.metadata.email || "").toLowerCase() === email.toLowerCase(),
    );
    expect(hit, "audit event for cancelled invitation").to.exist;
    expect(hit.target_type).to.equal("workspace_invitation");
    expect(hit.metadata.role).to.equal("viewer");
    expect(hit.metadata.invitation_id).to.equal(invId);
    expect(hit.metadata.workspace_name).to.be.a("string");
  });

  it("viewer lacks membership.cancel_invite permission", async () => {
    const email = `cancel-viewer-${Date.now()}@example.com`;
    const invId = await seedInvite(email);
    expect(invId).to.exist;

    const res = await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/invitations/${invId}`)
      .set("Cookie", viewerSession.cookie);
    expect([401, 403]).to.include(res.status);

    const check = await TestUtils.execQuery(
      `SELECT 1 FROM workspace_invitations WHERE id = $1`,
      [invId],
    );
    expect(check.rowCount).to.equal(1);
  });

  it("outsider cannot cancel invitations in a foreign workspace (IDOR guard)", async () => {
    const email = `cancel-outsider-${Date.now()}@example.com`;
    const invId = await seedInvite(email);
    expect(invId).to.exist;

    const res = await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/invitations/${invId}`)
      .set("Cookie", outsiderSession.cookie);
    expect([401, 403, 404]).to.include(res.status);

    const check = await TestUtils.execQuery(
      `SELECT 1 FROM workspace_invitations WHERE id = $1`,
      [invId],
    );
    expect(check.rowCount).to.equal(1);
  });

  it("returns 404 for unknown invitation id under the same workspace", async () => {
    const bogus = "00000000-0000-0000-0000-000000000000";
    const res = await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/invitations/${bogus}`)
      .set("Cookie", ownerSession.cookie);
    expect(res.status).to.equal(404);
  });

  it("does not cancel invitations that were already accepted", async () => {
    const email = `cancel-accepted-${Date.now()}@example.com`;
    const invId = await seedInvite(email);
    expect(invId).to.exist;
    await TestUtils.execQuery(
      `UPDATE workspace_invitations SET accepted_at = NOW() WHERE id = $1`,
      [invId],
    );
    const res = await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/invitations/${invId}`)
      .set("Cookie", ownerSession.cookie);
    expect(res.status).to.equal(404);
    const check = await TestUtils.execQuery(
      `SELECT 1 FROM workspace_invitations WHERE id = $1`,
      [invId],
    );
    expect(check.rowCount).to.equal(1);
  });
});
