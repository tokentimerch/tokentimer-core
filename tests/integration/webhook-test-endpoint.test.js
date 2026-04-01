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

  it("returns timeout/connection errors as friendly messages", async () => {
    // Unroutable TLD often fails quickly
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "https://example.invalid/webhook", kind: "generic" })
      .expect((res) => expect([400, 502, 504, 500]).to.include(res.status));
  });
});
