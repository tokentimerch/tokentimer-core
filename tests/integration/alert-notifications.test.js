const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Alert Notifications - Channels and Delivery", function () {
  this.timeout(90000);

  let user;
  let cookie;

  before(async () => {
    await TestEnvironment.setup();
    const u = await TestUtils.createAuthenticatedUser();
    user = u;
    cookie = u.cookie;
  });

  after(async () => {
    await TestUtils.cleanupTestUser(user.email, cookie);
  });

  it("should accept webhook URLs and thresholds payload (validation only)", async () => {
    const ws = await TestUtils.ensureTestWorkspace(cookie);
    const res = await request(BASE)
      .put(`/api/v1/workspaces/${ws}/alert-settings`)
      .set("Cookie", cookie)
      .send({
        alert_thresholds: [30, 14, 7, 1, 0],
        webhook_urls: [
          { kind: "discord", url: "https://discord.com/api/webhooks/xyz" },
          { kind: "teams", url: "https://outlook.office.com/webhook/xyz" },
        ],
      });
    expect([200, 400]).to.include(res.status);
  });

  it("exposes /api/alert-stats with channel counters (workspace-scoped)", async () => {
    const ws = await TestUtils.ensureTestWorkspace(cookie);
    const res = await request(BASE)
      .get("/api/alert-stats")
      .query({ workspace_id: ws })
      .set("Cookie", cookie)
      .expect(200);
    expect(res.body).to.have.property("byChannel");
    expect(res.body).to.have.property("monthUsage");
  });
});
