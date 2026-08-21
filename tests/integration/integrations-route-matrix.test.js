const { request, expect, TestUtils } = require("./setup");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const WORKER_SECRET =
  process.env.WORKER_API_KEY ||
  process.env.SESSION_SECRET ||
  "test-session-secret-key";

describe("Integrations route matrix", function () {
  this.timeout(90000);

  let adminUser;
  let adminSession;
  let viewerUser;
  let viewerSession;
  let managerUser;
  let managerSession;
  let removedUser;
  let removedSession;
  let foreignUser;
  let foreignSession;
  let workspaceId;
  let foreignWorkspaceId;

  const workspaceScanRoutes = [
    { path: "/api/v1/integrations/vault/scan", body: {} },
    { path: "/api/v1/integrations/vault/mounts", body: {} },
    { path: "/api/v1/integrations/gitlab/scan", body: {} },
    { path: "/api/v1/integrations/github/scan", body: {} },
    { path: "/api/v1/integrations/aws/detect-regions", body: {} },
    { path: "/api/v1/integrations/aws/scan", body: {} },
    { path: "/api/v1/integrations/azure/scan", body: {} },
    { path: "/api/v1/integrations/gcp/scan", body: {} },
    { path: "/api/v1/integrations/azure-ad/scan", body: {} },
  ];

  const allRoutes = [
    ...workspaceScanRoutes,
    { path: "/api/v1/integrations/vault/import", body: { items: [] } },
    { path: "/api/v1/integrations/check-duplicates", body: { items: [] } },
    { path: "/api/v1/integrations/import", body: { items: [] } },
  ];

  before(async () => {
    adminUser = await TestUtils.createVerifiedTestUser();
    adminSession = await TestUtils.loginTestUser(
      adminUser.email,
      "SecureTest123!@#",
    );

    const wsRes = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", adminSession.cookie)
      .expect(200);
    workspaceId = wsRes?.body?.items?.[0]?.id;

    viewerUser = await TestUtils.createVerifiedTestUser();
    viewerSession = await TestUtils.loginTestUser(
      viewerUser.email,
      "SecureTest123!@#",
    );
    await TestUtils.execQuery(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'viewer', $3)
       ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'viewer'`,
      [viewerUser.id, workspaceId, adminUser.id],
    );

    managerUser = await TestUtils.createVerifiedTestUser();
    managerSession = await TestUtils.loginTestUser(
      managerUser.email,
      "SecureTest123!@#",
    );
    await TestUtils.execQuery(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'workspace_manager', $3)
       ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'workspace_manager'`,
      [managerUser.id, workspaceId, adminUser.id],
    );

    removedUser = await TestUtils.createVerifiedTestUser();
    removedSession = await TestUtils.loginTestUser(
      removedUser.email,
      "SecureTest123!@#",
    );
    await TestUtils.execQuery(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'workspace_manager', $3)
       ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = 'workspace_manager'`,
      [removedUser.id, workspaceId, adminUser.id],
    );
    await TestUtils.execQuery(
      `DELETE FROM workspace_memberships WHERE user_id = $1 AND workspace_id = $2`,
      [removedUser.id, workspaceId],
    );

    foreignUser = await TestUtils.createVerifiedTestUser();
    foreignSession = await TestUtils.loginTestUser(
      foreignUser.email,
      "SecureTest123!@#",
    );
    const foreignWs = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", foreignSession.cookie)
      .expect(200);
    foreignWorkspaceId = foreignWs?.body?.items?.[0]?.id;
  });

  after(async () => {
    await TestUtils.cleanupTestUser(adminUser.email, adminSession.cookie);
    await TestUtils.cleanupTestUser(viewerUser.email, viewerSession.cookie);
    await TestUtils.cleanupTestUser(managerUser.email, managerSession.cookie);
    await TestUtils.cleanupTestUser(removedUser.email, removedSession.cookie);
    await TestUtils.cleanupTestUser(foreignUser.email, foreignSession.cookie);
  });

  it("enforces auth guard across provider routes", async () => {
    for (const route of allRoutes) {
      const res = await request(BASE)
        .post(`${route.path}?workspace_id=${workspaceId}`)
        .send(route.body);
      expect([401, 403]).to.include(res.status);
    }
  });

  it("requires workspace_id on scan and helper routes", async () => {
    for (const route of workspaceScanRoutes) {
      const res = await request(BASE)
        .post(route.path)
        .set("Cookie", adminSession.cookie)
        .send(route.body);
      expect(res.status).to.equal(400);
      expect(res.body.code).to.equal("WORKSPACE_REQUIRED");
    }
  });

  it("rejects unknown and foreign workspace ids on scan routes", async () => {
    const missingId = "00000000-0000-4000-8000-000000000001";
    const missingRes = await request(BASE)
      .post(`/api/v1/integrations/github/scan?workspace_id=${missingId}`)
      .set("Cookie", adminSession.cookie)
      .send({});
    expect(missingRes.status).to.equal(404);

    for (const route of workspaceScanRoutes) {
      const res = await request(BASE)
        .post(`${route.path}?workspace_id=${foreignWorkspaceId}`)
        .set("Cookie", adminSession.cookie)
        .send(route.body);
      expect(res.status).to.equal(403);
      expect(res.body.error).to.match(/not a workspace member/i);
    }
  });

  it("rejects viewers on scan and helper routes", async () => {
    for (const route of workspaceScanRoutes) {
      const res = await request(BASE)
        .post(`${route.path}?workspace_id=${workspaceId}`)
        .set("Cookie", viewerSession.cookie)
        .send(route.body);
      expect(res.status).to.equal(403);
      expect(res.body.error).to.equal("Forbidden: insufficient role");
      expect(res.body.code).to.equal("INSUFFICIENT_ROLE");
    }
  });

  it("rejects a removed member whose session is still valid", async () => {
    for (const route of workspaceScanRoutes) {
      const res = await request(BASE)
        .post(`${route.path}?workspace_id=${workspaceId}`)
        .set("Cookie", removedSession.cookie)
        .send(route.body);
      expect(res.status).to.equal(403);
      expect(res.body.error).to.match(/not a workspace member/i);
    }
  });

  it("lets managers and admins through workspace authorization", async () => {
    const sessions = [managerSession, adminSession];
    for (const cookieHolder of sessions) {
      const res = await request(BASE)
        .post(`/api/v1/integrations/github/scan?workspace_id=${workspaceId}`)
        .set("Cookie", cookieHolder.cookie)
        .send({});
      expect(res.status).to.equal(400);
      expect(res.body.error).to.match(/baseUrl and token/i);
    }
  });

  it("accepts workspace_id in the request body", async () => {
    const res = await request(BASE)
      .post("/api/v1/integrations/github/scan")
      .set("Cookie", adminSession.cookie)
      .send({ workspace_id: workspaceId });
    expect(res.status).to.equal(400);
    expect(res.body.error).to.match(/baseUrl and token/i);
  });

  it("allows worker bearer on aws detect-regions when workspace_id is present", async () => {
    const res = await request(BASE)
      .post(`/api/v1/integrations/aws/detect-regions?workspace_id=${workspaceId}`)
      .set("Authorization", `Bearer ${WORKER_SECRET}`)
      .send({});

    expect(res.status).to.equal(400);
    expect(res.body.error).to.match(/accessKeyId and secretAccessKey/i);
    expect(res.body.code).to.not.equal("VIEWER_NOT_ALLOWED");
  });

  it("enforces role guard for viewer on import endpoints", async () => {
    const dupRes = await request(BASE)
      .post(`/api/v1/integrations/check-duplicates?workspace_id=${workspaceId}`)
      .set("Cookie", viewerSession.cookie)
      .send({ items: [{ name: "test", location: null }] });
    expect(dupRes.status).to.equal(403);

    const importRes = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", viewerSession.cookie)
      .send({
        items: [
          {
            name: "viewer-denied-token",
            expiration: "2099-12-31",
            category: "general",
            type: "other",
          },
        ],
      });
    expect(importRes.status).to.equal(403);
  });

  it("returns invalid payload errors and provider auth failures", async () => {
    const invalid = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({});
    expect(invalid.status).to.equal(400);

    const providerAuthFailure = await request(BASE)
      .post(`/api/v1/integrations/github/scan?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({
        baseUrl: "https://api.github.com",
        token: "definitely-invalid-token",
        include: {
          tokens: true,
          sshKeys: true,
          deployKeys: true,
          secrets: true,
        },
        maxItems: 5,
      });
    expect([401, 403, 429, 500, 502]).to.include(providerAuthFailure.status);
    expect(providerAuthFailure.body).to.have.property("error");
  });

  it("supports duplicate detection and conflict update behavior on import", async () => {
    await TestUtils.execQuery(
      `INSERT INTO tokens (workspace_id, name, expiration, type, category, location)
       VALUES ($1, $2, $3, 'api_key', 'key_secret', $4)`,
      [workspaceId, "matrix-import-token", "2030-01-01", "gitlab/project-1"],
    );

    const dup = await request(BASE)
      .post(`/api/v1/integrations/check-duplicates?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({
        items: [{ name: "matrix-import-token", location: "gitlab/project-1" }],
      })
      .expect(200);
    expect(dup.body.duplicate_count).to.be.at.least(1);

    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({
        items: [
          {
            name: "matrix-import-token",
            location: "gitlab/project-1",
            expiration: "2031-02-02",
            category: "key_secret",
            type: "api_key",
          },
        ],
      })
      .expect(201);

    expect(res.body.updated_count).to.be.at.least(1);

    const updated = await TestUtils.execQuery(
      `SELECT TO_CHAR(expiration::date, 'YYYY-MM-DD') AS expiration_date
       FROM tokens
       WHERE workspace_id = $1 AND name = $2 AND location = $3
       ORDER BY updated_at DESC NULLS LAST, created_at DESC
       LIMIT 1`,
      [workspaceId, "matrix-import-token", "gitlab/project-1"],
    );
    expect(updated.rows).to.have.length(1);
    expect(updated.rows[0].expiration_date).to.equal("2031-02-02");
  });

  it("keeps processing when one import item is invalid", async () => {
    const res = await request(BASE)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Cookie", adminSession.cookie)
      .send({
        items: [
          {
            name: "matrix-valid-created",
            location: "github/repo-1",
            expiration: "2035-03-03",
            category: "key_secret",
            type: "api_key",
          },
          {
            name: "",
            location: "github/repo-2",
            expiration: "2036-04-04",
            category: "key_secret",
            type: "api_key",
          },
        ],
      })
      .expect(201);

    expect(res.body.created_count).to.be.at.least(1);
    expect(res.body.error_count).to.be.at.least(1);
    expect(res.body.errors).to.be.an("array");

    const created = await TestUtils.execQuery(
      `SELECT id
       FROM tokens
       WHERE workspace_id = $1 AND name = $2 AND location = $3
       LIMIT 1`,
      [workspaceId, "matrix-valid-created", "github/repo-1"],
    );
    expect(created.rows).to.have.length(1);
  });
});
