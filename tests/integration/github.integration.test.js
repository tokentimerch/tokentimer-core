const { request, expect, TestUtils } = require("./setup");

describe("GitHub integration endpoints", () => {
  let session;
  let workspaceId;

  before(async () => {
    const user = await TestUtils.createVerifiedTestUser(
      null,
      "SecureTest123!@#",
      null,
      "pro",
    );

    // Get the workspace ID for this user
    const { rows } = await TestUtils.execQuery(
      `SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1`,
      [user.id],
    );
    workspaceId = rows[0]?.id;

    session = await TestUtils.loginTestUser(user.email, "SecureTest123!@#");
  });

  it("rejects scan without baseUrl/token", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/github/scan")
      .set("Cookie", session.cookie)
      .send({ workspace_id: workspaceId })
      .expect(400);
    expect(res.body.error).to.match(/baseUrl and token/i);
  });

  it("validates baseUrl format", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/github/scan")
      .set("Cookie", session.cookie)
      .send({
        workspace_id: workspaceId,
        baseUrl: "x".repeat(600), // Too long
        token: "test-token",
      })
      .expect((res) => {
        expect([400, 502]).to.include(res.status);
      });
  });

  it("validates token format", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/github/scan")
      .set("Cookie", session.cookie)
      .send({
        workspace_id: workspaceId,
        baseUrl: "https://github.com",
        token: "x".repeat(600), // Too long
      })
      .expect((res) => {
        expect([400, 502]).to.include(res.status);
      });
  });

  it("validates maxItems range", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/github/scan")
      .set("Cookie", session.cookie)
      .send({
        workspace_id: workspaceId,
        baseUrl: "https://github.com",
        token: "test-token",
        maxItems: 5000, // Too high
      })
      .expect((res) => {
        expect([400, 502]).to.include(res.status);
      });
  });

  it("handles scan with invalid credentials gracefully", async () => {
    const res = await request("http://localhost:4000")
      .post("/api/v1/integrations/github/scan")
      .set("Cookie", session.cookie)
      .send({
        workspace_id: workspaceId,
        baseUrl: "https://api.github.com",
        token: "invalid-token",
      })
      .expect((res) => {
        expect([401, 403, 502]).to.include(res.status);
      });
  });
});
