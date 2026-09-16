const { expect, request, TestUtils, TestEnvironment } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Token contact_group_ids HTTP round-trip", function () {
  this.timeout(60000);

  let cookie;
  let ws;

  before(async () => {
    await TestEnvironment.setup();
    const user = await TestUtils.createAuthenticatedUser();
    cookie = user.cookie;
    ws = await TestUtils.ensureDedicatedTestWorkspace(
      cookie,
      "Token contact groups",
    );

    await request(BASE)
      .put(`/api/v1/workspaces/${ws}/alert-settings`)
      .set("Cookie", cookie)
      .send({
        contact_groups: [
          { id: "zeta", name: "Zeta", email_contact_ids: [] },
          { id: "alpha", name: "Alpha", email_contact_ids: [] },
          { id: "default-ws", name: "Workspace default", email_contact_ids: [] },
        ],
        default_contact_group_id: "default-ws",
      })
      .expect(200);
  });

  it("POSTs two ids, GETs them sorted with lex-smallest singular, and PUT [] clears to workspace default", async () => {
    const soon = new Date();
    soon.setDate(soon.getDate() + 30);

    const created = await request(BASE)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({
        name: `Plural Groups ${Date.now()}`,
        type: "api_key",
        category: "general",
        expiresAt: soon.toISOString().slice(0, 10),
        workspace_id: ws,
        contact_group_ids: ["zeta", "alpha"],
      })
      .expect(201);

    const fetched = await request(BASE)
      .get(`/api/tokens/${created.body.id}`)
      .set("Cookie", cookie)
      .expect(200);

    expect(fetched.body.contact_group_ids).to.deep.equal(["alpha", "zeta"]);
    expect(fetched.body.contact_group_id).to.equal("alpha");

    await request(BASE)
      .put(`/api/tokens/${created.body.id}`)
      .set("Cookie", cookie)
      .send({ contact_group_ids: [] })
      .expect(200);

    const cleared = await request(BASE)
      .get(`/api/tokens/${created.body.id}`)
      .set("Cookie", cookie)
      .expect(200);

    expect(cleared.body.contact_group_ids).to.deep.equal([]);
    expect(cleared.body.contact_group_id).to.equal(null);
  });
});
