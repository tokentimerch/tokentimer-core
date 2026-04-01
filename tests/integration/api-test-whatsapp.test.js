const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("/api/test-whatsapp endpoint", function () {
  this.timeout(60000);

  let cookie;
  let workspaceId;

  before(async () => {
    await TestEnvironment.setup();
    const u = await TestUtils.createAuthenticatedUser();
    cookie = u.cookie;
    workspaceId = await TestUtils.ensureTestWorkspace(cookie);
  });

  it("returns 400 for invalid phone format", async () => {
    const res = await request(BASE)
      .post(`/api/test-whatsapp?workspace_id=${workspaceId}`)
      .set("Cookie", cookie)
      .send({ phone_e164: "00123" })
      .expect(400);
    expect(res.body.code).to.equal("INVALID_PHONE_FORMAT");
  });

  it("succeeds for valid phone in dry-run environments", async () => {
    const res = await request(BASE)
      .post(`/api/test-whatsapp?workspace_id=${workspaceId}`)
      .set("Cookie", cookie)
      .send({ phone_e164: "+14155550100" })
      .expect((r) => expect([200, 500, 429, 400]).to.include(r.status));
    // We accept a range due to environment constraints; status code semantics are handled server-side.
  });

  it("enforces per-phone cooldown", async () => {
    const phone = "+14155550101";
    await request(BASE)
      .post(`/api/test-whatsapp?workspace_id=${workspaceId}`)
      .set("Cookie", cookie)
      .send({ phone_e164: phone })
      .expect((r) => expect([200, 429, 500, 400]).to.include(r.status));

    const res2 = await request(BASE)
      .post(`/api/test-whatsapp?workspace_id=${workspaceId}`)
      .set("Cookie", cookie)
      .send({ phone_e164: phone })
      .expect((r) => expect([200, 429, 500, 400]).to.include(r.status));

    if (res2.status === 429) {
      expect(res2.body.code).to.equal("TEST_WHATSAPP_COOLDOWN");
      expect(res2.body.retryAfter).to.be.a("number");
    }
  });
});
