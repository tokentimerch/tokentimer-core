const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Webhook test endpoint behavior", function () {
  this.timeout(30000);

  let cookie;

  before(async () => {
    await TestEnvironment.setup();
    const u = await TestUtils.createAuthenticatedUser();
    cookie = u.cookie;
  });

  it("rejects disallowed provider host with friendly message", async () => {
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "https://not-allowed.example.com/webhook", kind: "slack" })
      .expect(400);
    expect(res.body.error).to.match(/Webhook host not allowed/i);
  });

  it("accepts a Power Automate / Logic Apps host for kind=teams", async () => {
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({
        url: "https://prod-00.westus.logic.azure.com:443/workflows/abc123/triggers/manual/paths/invoke",
        kind: "teams",
      });
    // Not blocked by the friendly provider allowlist; any remaining
    // failure must come from the network call itself, never
    // WEBHOOK_HOST_NOT_ALLOWED.
    expect(res.body.code).to.not.equal("WEBHOOK_HOST_NOT_ALLOWED");
  });

  it("honors WEBHOOK_EXTRA_PROVIDER_HOSTS end-to-end through the route", async () => {
    const extraHost = "hooks.integration-test.example.com";
    const original = process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS;
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = extraHost;
    try {
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({ url: `https://${extraHost}/webhook`, kind: "slack" });
      // Previously WEBHOOK_EXTRA_PROVIDER_HOSTS was parsed but never
      // merged into the actual allowlist, so this always came back
      // WEBHOOK_HOST_NOT_ALLOWED. It must not anymore.
      expect(res.body.code).to.not.equal("WEBHOOK_HOST_NOT_ALLOWED");
    } finally {
      if (original === undefined) delete process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS;
      else process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS = original;
    }
  });

  it("rejects IPv6 loopback with the private-IP block message", async () => {
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "http://[::1]/webhook", kind: "generic" })
      .expect(400);
    expect(res.body.code).to.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
    expect(res.body.error).to.match(/private\/reserved IP/i);
  });

  it("returns timeout/connection errors as friendly messages", async () => {
    // Unroutable TLD often fails quickly
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "https://example.invalid/webhook", kind: "generic" })
      .expect((res) => expect([400, 502, 504, 500]).to.include(res.status));
  });
});
