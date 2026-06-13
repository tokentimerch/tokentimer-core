const { expect, request, TestEnvironment, TestUtils } = require("./setup");
const { Client } = require("pg");
const crypto = require("crypto");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

function statsPath(workspaceId) {
  return `/api/v1/workspaces/${workspaceId}/control-center/stats`;
}

function isoDateOffset(days) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

describe("Control Center stats RBAC", function () {
  this.timeout(120000);

  let client;
  let owner;
  let ownerCookie;
  let manager;
  let managerCookie;
  let viewer;
  let viewerCookie;
  let outsider;
  let outsiderCookie;
  let workspaceAId;
  let workspaceBId;
  let tokenAExpiredId;
  let tokenAHealthyId;
  let tokenBSecretId;

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

    owner = await TestUtils.createAuthenticatedUser();
    ownerCookie = owner.cookie;
    manager = await TestUtils.createAuthenticatedUser();
    managerCookie = manager.cookie;
    viewer = await TestUtils.createAuthenticatedUser();
    viewerCookie = viewer.cookie;
    outsider = await TestUtils.createAuthenticatedUser();
    outsiderCookie = outsider.cookie;

    workspaceAId = crypto.randomUUID();
    workspaceBId = crypto.randomUUID();

    await client.query(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, $2, 'oss', $3)`,
      [workspaceAId, "Control Center Stats A", owner.user.id],
    );
    await client.query(
      `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, $2, 'oss', $3)`,
      [workspaceBId, "Control Center Stats B", owner.user.id],
    );

    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'admin', $1)`,
      [owner.user.id, workspaceAId],
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'workspace_manager', $3)`,
      [manager.user.id, workspaceAId, owner.user.id],
    );
    await client.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
       VALUES ($1, $2, 'viewer', $3)`,
      [viewer.user.id, workspaceAId, owner.user.id],
    );

    const insertToken = async (
      workspaceId,
      name,
      expiration,
      category = "general",
    ) => {
      const res = await client.query(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES ($1, $2, $1, $3, $4, 'api_key', $5)
         RETURNING id`,
        [owner.user.id, workspaceId, name, expiration, category],
      );
      return res.rows[0].id;
    };

    tokenAExpiredId = await insertToken(
      workspaceAId,
      "CC-Stats-A-Expired",
      isoDateOffset(-2),
      "cert",
    );
    tokenAHealthyId = await insertToken(
      workspaceAId,
      "CC-Stats-A-Healthy",
      isoDateOffset(90),
      "license",
    );
    await insertToken(
      workspaceAId,
      "CC-Stats-A-Expiring7",
      isoDateOffset(5),
      "key_secret",
    );

    tokenBSecretId = await insertToken(
      workspaceBId,
      "CC-Stats-B-Secret-Leak-Probe",
      isoDateOffset(3),
      "general",
    );
  });

  after(async () => {
    try {
      if (workspaceAId || workspaceBId) {
        await client.query(
          "DELETE FROM tokens WHERE workspace_id = ANY($1::uuid[])",
          [[workspaceAId, workspaceBId].filter(Boolean)],
        );
        await client.query("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [
          [workspaceAId, workspaceBId].filter(Boolean),
        ]);
      }
      for (const u of [
        { email: owner?.email, cookie: ownerCookie },
        { email: manager?.email, cookie: managerCookie },
        { email: viewer?.email, cookie: viewerCookie },
        { email: outsider?.email, cookie: outsiderCookie },
      ]) {
        if (u.email && u.cookie) {
          await TestUtils.cleanupTestUser(u.email, u.cookie);
        }
      }
    } catch (_) {}
    await client.end();
  });

  it("rejects non-members with 403", async () => {
    const res = await request(BASE)
      .get(statsPath(workspaceAId))
      .set("Cookie", outsiderCookie);
    expect(res.status).to.equal(403);
    expect(res.body.error).to.match(/Forbidden/i);
  });

  it("rejects viewers with 403", async () => {
    const res = await request(BASE)
      .get(statsPath(workspaceAId))
      .set("Cookie", viewerCookie);
    expect(res.status).to.equal(403);
    expect(res.body.error).to.equal("Forbidden");
  });

  it("returns workspace-scoped aggregate stats for managers", async () => {
    const res = await request(BASE)
      .get(statsPath(workspaceAId))
      .set("Cookie", managerCookie)
      .expect(200);

    expect(res.body).to.have.property("totalAssets", 3);
    expect(res.body).to.have.property("buckets");
    expect(res.body.buckets).to.include({
      expired: 1,
      expiring7: 1,
      healthy: 1,
    });
    expect(res.body).to.have.property("isComplete", true);
    expect(res.body).to.have.property("sources").that.is.an("array");

    const sourceKeys = res.body.sources.map((s) => s.key);
    expect(sourceKeys).to.include.members(["cert", "license", "key_secret"]);

    const names = (res.body.needsAttention || []).map((row) => row.name);
    expect(names).to.include("CC-Stats-A-Expired");
    expect(names).to.include("CC-Stats-A-Expiring7");
    expect(names).not.to.include("CC-Stats-A-Healthy");
    expect(names).not.to.include("CC-Stats-B-Secret-Leak-Probe");
  });

  it("does not expose tokens from other workspaces (cross-workspace leakage)", async () => {
    const resA = await request(BASE)
      .get(statsPath(workspaceAId))
      .set("Cookie", managerCookie)
      .expect(200);

    expect(resA.body.totalAssets).to.equal(3);
    const attentionIdsA = (resA.body.needsAttention || []).map((row) => row.id);
    expect(attentionIdsA).to.include(tokenAExpiredId);
    expect(attentionIdsA).not.to.include(tokenBSecretId);

    const resB = await request(BASE)
      .get(statsPath(workspaceBId))
      .set("Cookie", managerCookie);
    expect(resB.status).to.equal(403);
    expect(resB.body.error).to.match(/Forbidden/i);

    const ownerB = await request(BASE)
      .get(statsPath(workspaceBId))
      .set("Cookie", ownerCookie)
      .expect(200);
    expect(ownerB.body.totalAssets).to.equal(1);
    const attentionB = (ownerB.body.needsAttention || []).map((row) => row.name);
    expect(attentionB).to.include("CC-Stats-B-Secret-Leak-Probe");
    expect(attentionB).not.to.include("CC-Stats-A-Expired");
  });
});
