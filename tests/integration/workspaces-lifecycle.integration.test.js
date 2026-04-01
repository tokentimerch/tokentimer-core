const { request, expect, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Workspaces lifecycle and membership integration", function () {
  this.timeout(90000);

  let ownerUser;
  let ownerSession;
  let memberUser;
  let memberSession;
  let workspaceId;
  let ownerContactId;

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

    memberUser = await TestUtils.createVerifiedTestUser();
    memberSession = await TestUtils.loginTestUser(
      memberUser.email,
      "SecureTest123!@#",
    );

    const contact = await TestUtils.execQuery(
      `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, details, created_by)
       VALUES ($1, 'Owner', 'Primary', $2::jsonb, $3)
       RETURNING id`,
      [workspaceId, JSON.stringify({ email: ownerUser.email }), ownerUser.id],
    );
    ownerContactId = contact.rows[0]?.id;
  });

  after(async () => {
    await TestUtils.cleanupTestUser(ownerUser.email, ownerSession.cookie);
    await TestUtils.cleanupTestUser(memberUser.email, memberSession.cookie);
  });

  it("invite lifecycle: create and resend invitation for existing user", async () => {
    const createInvite = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/members`)
      .set("Cookie", ownerSession.cookie)
      .send({ email: memberUser.email, role: "viewer" })
      .expect(201);
    expect(createInvite.body.role).to.equal("viewer");

    let list = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/members?limit=100&offset=0`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    const firstMembership = list.body.items.find(
      (m) => m.user_id === memberUser.id,
    );
    expect(firstMembership).to.exist;
    expect(firstMembership.role).to.equal("viewer");

    const resendInvite = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/members`)
      .set("Cookie", ownerSession.cookie)
      .send({ email: memberUser.email, role: "workspace_manager" })
      .expect(201);
    expect(resendInvite.body.role).to.equal("workspace_manager");

    list = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/members?limit=100&offset=0`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    const updatedMembership = list.body.items.find(
      (m) => m.user_id === memberUser.id,
    );
    expect(updatedMembership).to.exist;
    expect(updatedMembership.role).to.equal("workspace_manager");
  });

  it("member role transitions and forbidden cases", async () => {
    // Existing member (manager) can access workspace details
    const memberWorkspace = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}`)
      .set("Cookie", memberSession.cookie)
      .expect(200);
    expect(["workspace_manager", "viewer", "admin"]).to.include(
      memberWorkspace.body.role,
    );

    // Cannot change admin role via API
    const forbiddenAdminChange = await request(BASE)
      .patch(`/api/v1/workspaces/${workspaceId}/members/${ownerUser.id}`)
      .set("Cookie", ownerSession.cookie)
      .send({ role: "viewer" });
    expect(forbiddenAdminChange.status).to.equal(403);

    // Valid transition manager -> viewer
    await request(BASE)
      .patch(`/api/v1/workspaces/${workspaceId}/members/${memberUser.id}`)
      .set("Cookie", ownerSession.cookie)
      .send({ role: "viewer" })
      .expect(200);

    // Viewer cannot remove admin
    const removeAdminAsViewer = await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/members/${ownerUser.id}`)
      .set("Cookie", memberSession.cookie);
    expect([401, 403]).to.include(removeAdminAsViewer.status);
  });

  it("revoke member and persist contact-group defaults in workspace settings", async () => {
    await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/members/${memberUser.id}`)
      .set("Cookie", ownerSession.cookie)
      .expect(204);

    const afterRevoke = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/members?limit=100&offset=0`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    const stillPresent = afterRevoke.body.items.find(
      (m) => m.user_id === memberUser.id,
    );
    expect(stillPresent).to.not.exist;

    const contactGroupId = "default-main";
    const payload = {
      contact_groups: [
        {
          id: contactGroupId,
          name: "Main Team",
          email_contact_ids: [ownerContactId],
          webhook_names: ["default-webhook"],
          weekly_digest_email: true,
        },
      ],
      default_contact_group_id: contactGroupId,
    };
    await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", ownerSession.cookie)
      .send(payload)
      .expect(200);

    const settings = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", ownerSession.cookie)
      .expect(200);
    expect(settings.body.default_contact_group_id).to.equal(contactGroupId);
    expect(settings.body.contact_groups).to.be.an("array");
    expect(settings.body.contact_groups[0]).to.include({
      id: contactGroupId,
      name: "Main Team",
    });
  });
});
