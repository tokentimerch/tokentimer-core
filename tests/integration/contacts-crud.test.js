const { expect, request, TestEnvironment, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Workspace contacts CRUD", function () {
  this.timeout(60000);

  let cookie;
  let workspaceId;

  before(async () => {
    await TestEnvironment.setup();
    const u = await TestUtils.createAuthenticatedUser();
    cookie = u.cookie;
    workspaceId = await TestUtils.ensureTestWorkspace(cookie);
  });

  it("creates, updates, and deletes a contact", async () => {
    // Create
    const c = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/contacts`)
      .set("Cookie", cookie)
      .send({
        first_name: "Alice",
        last_name: "Ops",
        phone_e164: "+14155550123",
      })
      .expect(201);
    const id = c.body.id;

    // Update
    const u1 = await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/contacts/${id}`)
      .set("Cookie", cookie)
      .send({ last_name: "Operations", phone_e164: "+14155550123" })
      .expect(200);
    expect(u1.body.last_name).to.equal("Operations");

    // Delete
    await request(BASE)
      .delete(`/api/v1/workspaces/${workspaceId}/contacts/${id}`)
      .set("Cookie", cookie)
      .expect(200);
  });

  it("validates E.164 on update", async () => {
    const c = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/contacts`)
      .set("Cookie", cookie)
      .send({ first_name: "Bob", last_name: "Ops", phone_e164: "+14155550124" })
      .expect(201);
    const id = c.body.id;

    await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/contacts/${id}`)
      .set("Cookie", cookie)
      .send({ phone_e164: "00123" })
      .expect(400);
  });
});
