const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Webhooks Settings - Slack migration and PagerDuty fields", function () {
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

  it("GET returns webhook_urls", async () => {
    const res = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", cookie)
      .expect(200);
    expect(res.body).to.have.property("webhook_urls");
  });

  it("PUT persists webhook.severity, template, and pagerduty.routingKey", async () => {
    const payload = {
      alert_thresholds: [30, 14, 7, 1, 0],
      webhook_urls: [
        { kind: "discord", url: "https://discord.com/api/webhooks/x" },
        { kind: "teams", url: "https://outlook.office.com/webhook/x" },
        {
          kind: "pagerduty",
          url: "https://events.pagerduty.com/v2/enqueue",
          routingKey: "ROUTING_KEY_TEST",
          severity: "critical",
          template: "Custom Title",
        },
        { kind: "slack", url: "https://hooks.slack.com/services/x" },
      ],
      email_alerts_enabled: true,
      webhooks_alerts_enabled: true,
    };
    const res = await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", cookie)
      .send(payload)
      .expect(200);
    expect(res.body).to.have.property("success");

    const get = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", cookie)
      .expect(200);
    const urls = get.body.webhook_urls || [];
    const pd = urls.find((w) => w.kind === "pagerduty");
    expect(pd).to.include.keys(["routingKey", "severity", "template"]);
  });
});
