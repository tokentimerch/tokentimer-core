const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

describe("Contact Groups - settings validation, caps, and RBAC", function () {
  this.timeout(120000);

  let admin;
  let adminCookie;
  let viewer;
  let viewerCookie;
  let workspaceId;
  let client;

  async function createContact(email) {
    const name = email.split("@")[0];
    const res = await request(BASE)
      .post(`/api/v1/workspaces/${workspaceId}/contacts`)
      .set("Cookie", adminCookie)
      .send({
        first_name: name,
        last_name: "Contact",
        details: { email },
      })
      .expect(201);
    return String(res.body.id);
  }

  before(async () => {
    await TestEnvironment.setup();
    client = new Client({
      user: process.env.DB_USER || "tokentimer",
      host: process.env.DB_HOST || "localhost",
      database: process.env.DB_NAME || "tokentimer",
      password: process.env.DB_PASSWORD || "password",
      port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
      ssl: false,
    });
    await client.connect();

    admin = await TestUtils.createAuthenticatedUser();
    adminCookie = admin.cookie;
    workspaceId = await TestUtils.ensureTestWorkspace(adminCookie);

    // Create a viewer in the same workspace
    viewer = await TestUtils.createAuthenticatedUser();
    viewerCookie = viewer.cookie;
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1,$2,'viewer',$3)
       ON CONFLICT (user_id, workspace_id) DO UPDATE SET role='viewer'`,
      [viewer.user.id, workspaceId, admin.user.id],
    );
  });

  after(async () => {
    await client.end();
  });

  it("persists thresholds override on contact groups and returns them on GET", async () => {
    const opsContact = await createContact("ops@example.com");
    const finContact = await createContact("finance@example.com");
    const payload = {
      contact_groups: [
        {
          id: "ops",
          name: "Ops",
          email_contact_ids: [opsContact],
          thresholds: [15, 60, 30, 30], // unsorted with duplicate to test normalization
        },
        { id: "finance", name: "Finance", email_contact_ids: [finContact] },
      ],
      default_contact_group_id: "finance",
    };
    await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", adminCookie)
      .send(payload)
      .expect(200);

    const get = await request(BASE)
      .get(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", adminCookie)
      .expect(200);
    const ops = get.body.contact_groups.find((g) => g.id === "ops");
    expect(ops).to.exist;
    // Should be normalized, unique, sorted desc
    expect(ops.thresholds).to.deep.equal([60, 30, 15]);
  });

  it("forbids viewers to update contact groups", async () => {
    await request(BASE)
      .put(`/api/v1/workspaces/${workspaceId}/alert-settings`)
      .set("Cookie", viewerCookie)
      .send({
        contact_groups: [{ id: "z", name: "Z", email_contact_ids: [] }],
      })
      .expect(403);
  });
});
