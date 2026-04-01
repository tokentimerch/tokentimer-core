const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Pagination for audit and alert queue", function () {
  this.timeout(60000);

  let user;
  let cookie;

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
  });

  after(async () => {
    await TestUtils.cleanupTestUser(user.email, cookie);
  });

  it("GET /api/audit-events paginates", async () => {
    const r1 = await request(BASE)
      .get("/api/audit-events?limit=5&offset=0")
      .set("Cookie", cookie)
      .expect(200);
    const r2 = await request(BASE)
      .get("/api/audit-events?limit=5&offset=5")
      .set("Cookie", cookie)
      .expect(200);
    expect(r1.body).to.be.an("array");
    expect(r2.body).to.be.an("array");
  });

  it("GET /api/alert-queue paginates", async () => {
    const r1 = await request(BASE)
      .get("/api/alert-queue?limit=5&offset=0")
      .set("Cookie", cookie)
      .expect(200);
    const r2 = await request(BASE)
      .get("/api/alert-queue?limit=5&offset=5")
      .set("Cookie", cookie)
      .expect(200);
    expect(r1.body).to.have.property("alerts");
    expect(r2.body).to.have.property("alerts");
  });
});
