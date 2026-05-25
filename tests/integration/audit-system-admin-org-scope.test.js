const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const TEST_ACTION = "ORG_AUDIT_SYSTEM_ADMIN_TEST";

describe("Audit organization scope for system admins", function () {
  this.timeout(60000);

  let systemAdminUser;
  let otherUser;
  let systemAdminCookie;
  let otherWorkspaceId;

  before(async () => {
    await TestEnvironment.setup();

    systemAdminUser = await TestUtils.createVerifiedTestUser(
      null,
      "SecureTest123!@#",
      null,
      "oss",
    );
    const systemAdminSession = await TestUtils.loginTestUser(
      systemAdminUser.email,
      systemAdminUser.password,
    );
    systemAdminCookie = systemAdminSession.cookie;

    otherUser = await TestUtils.createVerifiedTestUser(
      null,
      "SecureTest123!@#",
      null,
      "oss",
    );

    const wsResult = await TestUtils.execQuery(
      "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
      [otherUser.id],
    );
    otherWorkspaceId = wsResult.rows[0]?.id;

    await TestUtils.execQuery(
      "UPDATE users SET is_admin = TRUE WHERE id = $1",
      [systemAdminUser.id],
    );
    await TestUtils.execQuery(
      "DELETE FROM workspace_memberships WHERE user_id = $1",
      [systemAdminUser.id],
    );
    await TestUtils.execQuery(
      `INSERT INTO audit_events
         (actor_user_id, subject_user_id, action, target_type, target_id, channel, metadata, workspace_id)
       VALUES
         ($1, $2, $3, 'workspace', NULL, NULL, '{"source":"system-admin-org-scope"}', $4)`,
      [systemAdminUser.id, otherUser.id, TEST_ACTION, otherWorkspaceId],
    );
  });

  after(async () => {
    const userIds = [systemAdminUser.id, otherUser.id];
    await TestUtils.execQuery("DELETE FROM audit_events WHERE action = $1", [
      TEST_ACTION,
    ]);
    await TestUtils.execQuery(
      `DELETE FROM audit_events
       WHERE actor_user_id = ANY($1::int[]) OR subject_user_id = ANY($1::int[])`,
      [userIds],
    );
    await TestUtils.execQuery(
      "DELETE FROM workspace_memberships WHERE user_id = ANY($1::int[])",
      [userIds],
    );
    await TestUtils.execQuery(
      "DELETE FROM workspaces WHERE created_by = ANY($1::int[])",
      [userIds],
    );
    await TestUtils.execQuery("DELETE FROM users WHERE id = ANY($1::int[])", [
      userIds,
    ]);
  });

  it("allows a pure system admin to view organization audit events", async () => {
    const res = await request(BASE)
      .get(`/api/audit-events?scope=organization&action=${TEST_ACTION}`)
      .set("Cookie", systemAdminCookie)
      .expect(200);

    expect(res.body).to.be.an("array");
    expect(res.body.length).to.equal(1);
    expect(res.body[0].action).to.equal(TEST_ACTION);
    expect(res.body[0].workspace_id).to.equal(otherWorkspaceId);
  });

  it("allows a pure system admin to export organization audit events", async () => {
    const res = await request(BASE)
      .get(
        `/api/account/export-audit?scope=organization&format=json&action=${TEST_ACTION}`,
      )
      .set("Cookie", systemAdminCookie)
      .expect(200);

    expect(res.body).to.have.property("events");
    expect(res.body.events).to.be.an("array");
    expect(res.body.events.length).to.equal(1);
    expect(res.body.events[0].action).to.equal(TEST_ACTION);
  });
});
