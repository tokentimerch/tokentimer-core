const crypto = require("crypto");
const { createRequire } = require("module");
const supertest = require("supertest");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const { createApiToken } = require("../../apps/api/services/certops/apiTokens");
const {
  createCertOpsApiTokenAuth,
} = require("../../apps/api/middleware/api-token-auth");
const {
  createCertOpsMachineTokenRateLimit,
} = require("../../apps/api/middleware/machine-token-rate-limit");

const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const express = apiRequire("express");

async function createWorkspacePair(label) {
  const ownerEmail = `${label}-${Date.now()}-${crypto.randomUUID()}@example.com`;
  const owner = await TestUtils.execQuery(
    `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
     VALUES ($1, $2, $3, $4, 'local', TRUE)
     RETURNING id`,
    [
      ownerEmail.toLowerCase(),
      ownerEmail,
      label,
      "not-used-in-machine-rate-limit-test",
    ],
  );
  const ownerId = owner.rows[0].id;
  const workspaceA = crypto.randomUUID();
  const workspaceB = crypto.randomUUID();

  await TestUtils.execQuery(
    `INSERT INTO workspaces (id, name, created_by, plan)
     VALUES ($1, $2, $3, 'oss'), ($4, $5, $3, 'oss')`,
    [
      workspaceA,
      `${label} A`,
      ownerId,
      workspaceB,
      `${label} B`,
    ],
  );

  return { ownerId, workspaceA, workspaceB };
}

async function cleanupWorkspacePair(ownerId, workspaceIds) {
  await TestUtils.execQuery(
    "DELETE FROM api_tokens WHERE workspace_id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [
    workspaceIds,
  ]);
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

function buildRateLimitHarness({ max = 2, windowMs = 60_000 } = {}) {
  const app = express();
  app.use(express.json());

  app.post(
    "/api/v1/workspaces/:id/certops/machine-rate-limit-test",
    createCertOpsApiTokenAuth({
      scopes: ["certops:events:write"],
      workspaceIdParam: "id",
    }),
    createCertOpsMachineTokenRateLimit({ max, windowMs }),
    (req, res) =>
      res.status(200).json({
        ok: true,
        apiToken: req.apiToken,
        hasUser: !!req.user,
        isAdmin: req.isAdmin === true,
        authenticated: req.authenticated === true,
      }),
  );

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    return res.status(500).json({
      error: "Internal test harness error",
      code: err?.code || "INTERNAL_ERROR",
    });
  });

  return app;
}

function expectNoRawToken(responseBody, rawToken) {
  expect(JSON.stringify(responseBody)).to.not.include(rawToken);
  expect(JSON.stringify(responseBody)).to.not.include(`Bearer ${rawToken}`);
  expect(JSON.stringify(responseBody)).to.not.include("token_hash");
}

describe("CertOps machine-token rate limiter", function () {
  this.timeout(60000);

  before(async () => {
    await runMigrations();
  });

  it("allows valid machine tokens under limit and blocks the same token over limit", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-machine-rate-limit-basic",
    );

    try {
      const created = await createApiToken({
        workspaceId: workspaceA,
        name: "Executor",
        scopes: ["certops:events:write"],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdBy: ownerId,
      });
      const app = buildRateLimitHarness({ max: 2 });
      const route = `/api/v1/workspaces/${workspaceA}/certops/machine-rate-limit-test`;

      const first = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${created.plaintextToken}`)
        .send({});
      const second = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${created.plaintextToken}`)
        .send({});
      const third = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${created.plaintextToken}`)
        .send({});

      expect(first.status).to.equal(200);
      expect(second.status).to.equal(200);
      expect(third.status).to.equal(429);
      expect(third.body.code).to.equal("CERTOPS_MACHINE_RATE_LIMITED");
      expect(third.headers["retry-after"]).to.match(/^[1-9][0-9]*$/);
      expectNoRawToken(third.body, created.plaintextToken);
      expect(first.body.hasUser).to.equal(false);
      expect(first.body.isAdmin).to.equal(false);
      expect(first.body.authenticated).to.equal(false);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("keeps different tokens and workspaces in separate limiter buckets", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-machine-rate-limit-isolation",
    );

    try {
      const tokenA1 = await createApiToken({
        workspaceId: workspaceA,
        name: "Executor A1",
        scopes: ["certops:events:write"],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdBy: ownerId,
      });
      const tokenA2 = await createApiToken({
        workspaceId: workspaceA,
        name: "Executor A2",
        scopes: ["certops:events:write"],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdBy: ownerId,
      });
      const tokenB = await createApiToken({
        workspaceId: workspaceB,
        name: "Executor B",
        scopes: ["certops:events:write"],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdBy: ownerId,
      });
      const app = buildRateLimitHarness({ max: 1 });
      const routeA = `/api/v1/workspaces/${workspaceA}/certops/machine-rate-limit-test`;
      const routeB = `/api/v1/workspaces/${workspaceB}/certops/machine-rate-limit-test`;

      const firstA1 = await supertest(app)
        .post(routeA)
        .set("Authorization", `Bearer ${tokenA1.plaintextToken}`)
        .send({});
      const firstA2 = await supertest(app)
        .post(routeA)
        .set("Authorization", `Bearer ${tokenA2.plaintextToken}`)
        .send({});
      const firstB = await supertest(app)
        .post(routeB)
        .set("Authorization", `Bearer ${tokenB.plaintextToken}`)
        .send({});
      const secondA1 = await supertest(app)
        .post(routeA)
        .set("Authorization", `Bearer ${tokenA1.plaintextToken}`)
        .send({});

      expect(firstA1.status).to.equal(200);
      expect(firstA2.status).to.equal(200);
      expect(firstB.status).to.equal(200);
      expect(secondA1.status).to.equal(429);
      expectNoRawToken(secondA1.body, tokenA1.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });
});
