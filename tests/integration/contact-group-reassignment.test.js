const { expect, request, TestUtils, TestEnvironment } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Contact Group Reassignment", function () {
  this.timeout(60000);

  let user, cookie, ws;

  before(async () => {
    await TestEnvironment.setup();
    user = await TestUtils.createVerifiedTestUser();
    const session = await TestUtils.loginTestUser(user.email, user.password);
    cookie = session.cookie;
    ws = await TestUtils.ensureTestWorkspace(cookie);
  });

  it("reassigns tokens from one contact group to another", async () => {
    const c1 = await request(BASE)
      .post(`/api/v1/workspaces/${ws}/contacts`)
      .set("Cookie", cookie)
      .send({
        first_name: "GroupA",
        last_name: "Contact",
        details: { email: "groupa@example.com" },
      })
      .expect(201);

    const c2 = await request(BASE)
      .post(`/api/v1/workspaces/${ws}/contacts`)
      .set("Cookie", cookie)
      .send({
        first_name: "GroupB",
        last_name: "Contact",
        details: { email: "groupb@example.com" },
      })
      .expect(201);

    await request(BASE)
      .put(`/api/v1/workspaces/${ws}/alert-settings`)
      .set("Cookie", cookie)
      .send({
        contact_groups: [
          {
            id: "group-a",
            name: "Group A",
            email_contact_ids: [c1.body.id],
          },
          {
            id: "group-b",
            name: "Group B",
            email_contact_ids: [c2.body.id],
          },
        ],
      })
      .expect(200);

    const soon = new Date();
    soon.setDate(soon.getDate() + 10);

    await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "CG Token 1",
        type: "api_key",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: ws,
        contact_group_id: "group-a",
      })
      .expect(201);

    await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: "CG Token 2",
        type: "api_key",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: ws,
        contact_group_id: "group-a",
      })
      .expect(201);

    const res = await request(BASE)
      .post(`/api/v1/workspaces/${ws}/tokens/reassign-contact-group`)
      .set("Cookie", cookie)
      .send({ from_group_id: "group-a", to_group_id: "group-b" })
      .expect(200);

    expect(res.body).to.have.property("updated");
    expect(res.body.updated).to.be.at.least(2);

    const check = await TestUtils.execQuery(
      "SELECT contact_group_id FROM tokens WHERE workspace_id = $1 AND contact_group_id = 'group-b'",
      [ws],
    );
    expect(check.rows.length).to.be.at.least(2);
  });

  it("rejects when from and to are the same", async () => {
    await request(BASE)
      .post(`/api/v1/workspaces/${ws}/tokens/reassign-contact-group`)
      .set("Cookie", cookie)
      .send({ from_group_id: "group-a", to_group_id: "group-a" })
      .expect(400);
  });

  it("rejects when from_group_id does not exist", async () => {
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${ws}/tokens/reassign-contact-group`)
      .set("Cookie", cookie)
      .send({ from_group_id: "nonexistent", to_group_id: "group-b" })
      .expect(400);

    expect(res.body.code).to.equal("VALIDATION_ERROR");
  });

  it("rejects when required fields are missing", async () => {
    await request(BASE)
      .post(`/api/v1/workspaces/${ws}/tokens/reassign-contact-group`)
      .set("Cookie", cookie)
      .send({})
      .expect(400);
  });
});
