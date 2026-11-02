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

  it("rejects an arbitrary phone that is not a verified contact", async () => {
    const res = await request(BASE)
      .post(`/api/test-whatsapp?workspace_id=${workspaceId}`)
      .set("Cookie", cookie)
      .send({ phone_e164: "+14155550100" })
      .expect(400);
    expect(res.body.code).to.equal("CONTACT_REQUIRED");
  });

  it("rejects a second arbitrary phone instead of applying a client-side cooldown", async () => {
    const phone = "+14155550101";
    const first = await request(BASE)
      .post(`/api/test-whatsapp?workspace_id=${workspaceId}`)
      .set("Cookie", cookie)
      .send({ phone_e164: phone })
      .expect(400);
    const second = await request(BASE)
      .post(`/api/test-whatsapp?workspace_id=${workspaceId}`)
      .set("Cookie", cookie)
      .send({ phone_e164: phone })
      .expect(400);
    expect(first.body.code).to.equal("CONTACT_REQUIRED");
    expect(second.body.code).to.equal("CONTACT_REQUIRED");
  });
});
