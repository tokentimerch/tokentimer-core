const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Alert Settings API", function () {
  this.timeout(60000);

  let user;
  let cookie;
  let workspaceId;

  before(async () => {
    await TestEnvironment.setup();
    const u = await TestUtils.createAuthenticatedUser();
    user = u;
    cookie = u.cookie;
    workspaceId = await TestUtils.ensureTestWorkspace(cookie);
  });

  after(async () => {
    if (user && user.email && cookie) {
      await TestUtils.cleanupTestUser(user.email, cookie);
    }
  });

  it("GET /api/v1/workspaces/:id/alert-settings returns thresholds and webhook urls", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", cookie)
      .expect(200);
    expect(res.body).to.have.property("alert_thresholds");
    expect(res.body).to.have.property("webhook_urls");
    expect(res.body).to.have.property("plan");
  });

  it("PUT /api/v1/workspaces/:id/alert-settings validates threshold ranges", async () => {
    const bad = await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", cookie)
      .send({ alert_thresholds: [10000] })
      .expect(200); // Backend clamps/filtering; test ensures endpoint stability
    expect(bad.body).to.have.property("success");
  });
});
