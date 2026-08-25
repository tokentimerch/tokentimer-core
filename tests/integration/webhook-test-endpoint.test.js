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
    // Own user: this case reaches the real network-fetch stage, which arms
    // the 5s per-user test-webhook cooldown. Sharing `cookie` with the other
    // cases below would make them intermittently see 429 instead of their
    // actual expected response.
    const { cookie: teamsCookie } = await TestUtils.createAuthenticatedUser();
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", teamsCookie)
      .send({
        url: "https://prod-00.westus.logic.azure.com:443/workflows/abc123/triggers/manual/paths/invoke",
        kind: "teams",
      });
    expect(res.status).to.not.equal(429);
    // Not blocked by the friendly provider allowlist; any remaining
    // failure must come from the network call itself, never
    // WEBHOOK_HOST_NOT_ALLOWED.
    expect(res.body.code).to.not.equal("WEBHOOK_HOST_NOT_ALLOWED");
  });

  it("honors WEBHOOK_EXTRA_PROVIDER_HOSTS end-to-end through the route", async () => {
    // The Dockerized API under test runs in its own process/container, so
    // mutating process.env here would only affect this test-runner process,
    // never the API actually receiving the request. The extra host below
    // must instead be configured on the API service itself (see
    // WEBHOOK_EXTRA_PROVIDER_HOSTS in deploy/compose/docker-compose.test.yml).
    const extraHost = "hooks.integration-test.example.com";
    // Own user: also reaches the network-fetch stage and must not leak
    // cooldown into the cases below.
    const { cookie: extraHostCookie } =
      await TestUtils.createAuthenticatedUser();
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", extraHostCookie)
      .send({ url: `https://${extraHost}/webhook`, kind: "slack" });
    expect(res.status).to.not.equal(429);
    // Previously WEBHOOK_EXTRA_PROVIDER_HOSTS was parsed but never
    // merged into the actual allowlist, so this always came back
    // WEBHOOK_HOST_NOT_ALLOWED. It must not anymore.
    expect(res.body.code).to.not.equal("WEBHOOK_HOST_NOT_ALLOWED");
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
      .send({ url: "https://example.invalid/webhook", kind: "generic" });
    expect(res.status).to.not.equal(429);
    expect([400, 502, 504, 500]).to.include(res.status);
  });
});
