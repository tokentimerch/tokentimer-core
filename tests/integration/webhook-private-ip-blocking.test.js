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

  before(async () => {
    await TestEnvironment.setup();
  });

  // The endpoint is rate limited per user (5/min, 10/5min) plus a 5s
  // per-user cooldown. Mirrors webhook-ssrf-protection.test.js's
  // freshUserCookie() helper: a genuinely fresh, verified user for every
  // single request (not just per test) is what actually keeps every case
  // clear of the limiter in a full suite run, since a per-test-only fresh
  // user still shares its single request's quota with whatever residual
  // state the limiter's key resolves to under load.
  async function freshUserCookie() {
    const u = await TestUtils.createVerifiedTestUser();
    const s = await TestUtils.loginTestUser(u.email, u.password);
    return s.cookie;
  }

  it("blocks generic webhooks resolving to a private IP", async () => {
    const cookie = await freshUserCookie();
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
    const cookie = await freshUserCookie();
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "http://127.0.0.1:8080/webhook", kind: "generic" })
      .expect(400);
    expect(res.body.code).to.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
  });

  it("blocks generic webhooks targeting link-local metadata range", async () => {
    const cookie = await freshUserCookie();
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
    const cookie = await freshUserCookie();
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
    const cookie = await freshUserCookie();
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "https://example.invalid/webhook", kind: "generic" });
    expect(res.body.code || "").to.not.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
  });

  it("blocks IPv6 loopback literals", async () => {
    const cookie = await freshUserCookie();
    const res = await request(BASE)
      .post("/api/test-webhook")
      .set("Cookie", cookie)
      .send({ url: "http://[::1]/webhook", kind: "generic" })
      .expect(400);
    expect(res.body.code).to.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
  });

  it("blocks IPv4-mapped IPv6 loopback and RFC1918 literals", async () => {
    // Fresh user per iteration; see freshUserCookie() comment above.
    for (const url of [
      "http://[::ffff:127.0.0.1]/webhook",
      "http://[::ffff:10.0.0.1]/webhook",
      "http://[::ffff:192.168.1.1]/webhook",
      "http://[::ffff:169.254.169.254]/latest/meta-data",
    ]) {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({ url, kind: "generic" })
        .expect(400);
      expect(res.body.code, url).to.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
    }
  });

  it("blocks IPv6 unique-local and link-local literals", async () => {
    // Fresh user per iteration; see freshUserCookie() comment above.
    for (const url of [
      "http://[fd12:3456:789a:1::1]/webhook",
      "http://[fe80::1]/webhook",
    ]) {
      const cookie = await freshUserCookie();
      const res = await request(BASE)
        .post("/api/test-webhook")
        .set("Cookie", cookie)
        .send({ url, kind: "generic" })
        .expect(400);
      expect(res.body.code, url).to.equal("WEBHOOK_PRIVATE_IP_BLOCKED");
    }
  });
});
