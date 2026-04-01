const { expect, request, TestUtils, TestEnvironment } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Webhook SSRF Protection", function () {
  this.timeout(60000);

  // Each test uses a fresh user to avoid per-user rate limits and cooldowns
  async function freshUserCookie() {
    const u = await TestUtils.createVerifiedTestUser();
    const s = await TestUtils.loginTestUser(u.email, u.password);
    return s.cookie;
  }

  before(async () => {
    await TestEnvironment.setup();
  });

  describe("POST /api/test-webhook host allowlist", () => {
    it("rejects private IP webhooks for non-generic kinds", async () => {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({
          url: "http://127.0.0.1:8080/webhook",
          kind: "slack",
        });

      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("WEBHOOK_HOST_NOT_ALLOWED");
    });

    it("rejects internal network URLs for provider webhooks", async () => {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({
          url: "http://192.168.1.1:3000/hook",
          kind: "discord",
        });

      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("WEBHOOK_HOST_NOT_ALLOWED");
    });

    it("rejects unknown hosts for Slack kind", async () => {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({
          url: "https://evil.example.com/steal-data",
          kind: "slack",
        });

      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("WEBHOOK_HOST_NOT_ALLOWED");
    });

    it("rejects unknown hosts for PagerDuty kind", async () => {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({
          url: "https://evil.example.com/pd",
          kind: "pagerduty",
          routingKey: "a".repeat(32),
        });

      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("WEBHOOK_HOST_NOT_ALLOWED");
    });

    it("validates PagerDuty routing key format", async () => {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({
          url: "https://events.pagerduty.com/v2/enqueue",
          kind: "pagerduty",
          routingKey: "too-short",
        });

      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("VALIDATION_ERROR");
    });

    it("requires PagerDuty routing key", async () => {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({
          url: "https://events.pagerduty.com/v2/enqueue",
          kind: "pagerduty",
        });

      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("VALIDATION_ERROR");
    });

    it("rejects invalid webhook URL", async () => {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({
          url: "not-a-url",
          kind: "generic",
        });

      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("VALIDATION_ERROR");
    });

    it("rejects missing webhook URL", async () => {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({ kind: "generic" });

      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("VALIDATION_ERROR");
    });

    it("rejects non-http(s) protocol", async () => {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({
          url: "ftp://hooks.slack.com/services/T123/B456/xyz",
          kind: "slack",
        });

      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("VALIDATION_ERROR");
    });
  });
});
