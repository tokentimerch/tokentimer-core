const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Audit Filtering and Search", function () {
  this.timeout(60000);

  let user;
  let cookie;
  let workspaceId;

  before(async () => {
    await TestEnvironment.setup();
    // Create user with oss plan to access audit-events
    const testUser = await TestUtils.createVerifiedTestUser(
      null,
      "SecureTest123!@#",
      null,
      "oss",
    );
    const session = await TestUtils.loginTestUser(
      testUser.email,
      testUser.password,
    );

    // Get the workspace ID
    const wsResult = await TestUtils.execQuery(
      "SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1",
      [testUser.id],
    );
    workspaceId = wsResult.rows[0]?.id;

    // Ensure workspace has pro plan
    await TestUtils.execQuery(
      "UPDATE workspaces SET plan = 'oss' WHERE id = $1",
      [workspaceId],
    );

    user = { ...testUser, ...session, workspaceId };
    cookie = session.cookie;

    // Insert some test audit events directly for reliable testing
    await TestUtils.execQuery(
      `INSERT INTO audit_events (subject_user_id, action, metadata, workspace_id, occurred_at)
       VALUES 
       ($1, 'TEST_ACTION_A', '{"key": "value_a", "search": "findme"}', $2, NOW()),
       ($1, 'TEST_ACTION_B', '{"key": "value_b", "search": "hidden"}', $2, NOW() - INTERVAL '1 minute'),
       ($1, 'TEST_ACTION_A', '{"key": "value_c"}', $2, NOW() - INTERVAL '2 minutes')`,
      [user.id, workspaceId],
    );
  });

  after(async () => {
    await TestUtils.cleanupTestUser(user.email, cookie);
  });

  it("GET /api/audit-events filters by action", async () => {
    const res = await request(BASE)
      .get("/api/audit-events?action=TEST_ACTION_A")
      .set("Cookie", cookie)
      .expect(200);

    expect(res.body).to.be.an("array");
    expect(res.body.length).to.be.at.least(2);
    res.body.forEach((event) => {
      expect(event.action).to.equal("TEST_ACTION_A");
    });
  });

  it("GET /api/audit-events searches by query string", async () => {
    const res = await request(BASE)
      .get("/api/audit-events?query=findme")
      .set("Cookie", cookie)
      .expect(200);

    expect(res.body).to.be.an("array");
    expect(res.body.length).to.equal(1);
    expect(res.body[0].metadata.search).to.equal("findme");
  });

  it("GET /api/v1/workspaces/:id/audit-events filters by action and query", async () => {
    const res = await request(BASE)
      .get(
        `/api/v1/workspaces/${workspaceId}/audit-events?action=TEST_ACTION_A&query=value_c`,
      )
      .set("Cookie", cookie)
      .expect(200);

    expect(res.body).to.be.an("array");
    expect(res.body.length).to.equal(1);
    expect(res.body[0].action).to.equal("TEST_ACTION_A");
    expect(res.body[0].metadata.key).to.equal("value_c");
  });

  it("GET /api/account/export-audit respects action and query filters", async () => {
    const res = await request(BASE)
      .get(
        "/api/account/export-audit?format=json&action=TEST_ACTION_A&query=findme",
      )
      .set("Cookie", cookie)
      .expect(200);

    expect(res.body).to.have.property("events");
    expect(res.body.events).to.be.an("array");
    expect(res.body.events.length).to.equal(1);
    expect(res.body.events[0].action).to.equal("TEST_ACTION_A");
  });
});
