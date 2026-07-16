const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

/**
 * Verifies the SSRF private-IP guard on POST /api/test-webhook (issue #63,
 * point 3). The test API stack sets WEBHOOK_ENFORCE_PRIVATE_IP_CHECK=true so
 * the guard runs despite NODE_ENV=test, matching production behavior where
 * the Test button must fail for destinations that alert delivery would block.
 *
 * The WEBHOOK_ALLOW_PRIVATE_IPS=true escape hatch cannot be toggled per
 * request (it is process-level env on the API container); its precedence over
 * enforcement is covered by unit tests in
 * tests/unit/webhook-private-ip-gate.test.js.
 */
describe("Webhook private-IP blocking (WEBHOOK_ALLOW_PRIVATE_IPS gate)", function () {
  this.timeout(30000);

  let cookie;

  before(async () => {
    await TestEnvironment.setup();
    const u = await TestUtils.createAuthenticatedUser();
    cookie = u.cookie;
  });

  it("blocks generic webhooks resolving to a private IP", async () => {
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "http://192.168.50.10:3000/hooks/rocketchat", kind: "generic" })
      .expect(400);
    expect(res.body.code).to.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
    expect(res.body.error).to.match(/private\/reserved IP/i);
    expect(res.body.error).to.include("WEBHOOK_ALLOW_PRIVATE_IPS");
  });

  it("blocks generic webhooks targeting loopback", async () => {
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "http://127.0.0.1:8080/webhook", kind: "generic" })
      .expect(400);
    expect(res.body.code).to.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
  });

  it("blocks generic webhooks targeting link-local metadata range", async () => {
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "http://169.254.169.254/latest/meta-data", kind: "generic" })
      .expect(400);
    expect(res.body.code).to.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
  });

  it("keeps returning WEBHOOK_HOST_NOT_ALLOWED for provider kinds on private IPs", async () => {
    // Provider allowlist runs before the private-IP check, so provider kinds
    // keep their historical error code for non-allowlisted hosts.
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "http://192.168.1.1:3000/hook", kind: "slack" })
      .expect(400);
    expect(res.body.code).to.equal("WEBHOOK_HOST_NOT_ALLOWED");
  });

  it("does not block public destinations on the private-IP rule", async () => {
    // example.invalid never resolves; DNS failure passes the IP check and the
    // request fails later at connect time, so any error must not be the
    // private-IP block.
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "https://example.invalid/webhook", kind: "generic" });
    expect(res.body.code || "").to.not.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
  });
});
