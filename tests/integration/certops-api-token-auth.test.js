const crypto = require("crypto");
const { createRequire } = require("module");
const supertest = require("supertest");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  createApiToken,
  revokeApiToken,
} = require("../../apps/api/services/certops/apiTokens");
const {
  createCertOpsApiTokenAuth,
} = require("../../apps/api/middleware/api-token-auth");

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
      "not-used-in-api-token-auth-test",
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
  await TestUtils.execQuery("DELETE FROM api_tokens WHERE workspace_id = ANY($1::uuid[])", [
    workspaceIds,
  ]);
  await TestUtils.execQuery("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [
    workspaceIds,
  ]);
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

function buildAuthHarness(requiredScopes = ["certops:executor:events"]) {
  const app = express();
  app.use(express.json());

  app.post(
    "/api/v1/workspaces/:id/certops/machine-auth-test",
    createCertOpsApiTokenAuth({ scopes: requiredScopes }),
    (req, res) =>
      res.status(200).json({
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
}

describe("CertOps API token auth middleware", function () {
  this.timeout(60000);

  before(async () => {
    await runMigrations();
  });

  it("authenticates a valid scoped token without attaching session/admin identity", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-api-token-auth-success",
    );

    try {
      const created = await createApiToken({
        workspaceId: workspaceA,
        name: "Executor",
        scopes: ["certops:executor:events", "certops:jobs:read"],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdBy: ownerId,
      });

      const response = await supertest(buildAuthHarness())
        .post(`/api/v1/workspaces/${workspaceA}/certops/machine-auth-test`)
        .set("Authorization", `Bearer ${created.plaintextToken}`)
        .send({ workspaceId: workspaceB });

      expect(response.status).to.equal(200);
      expect(response.body.apiToken).to.include({
        id: created.token.id,
        workspaceId: workspaceA,
        tokenPrefix: created.token.tokenPrefix,
        name: "Executor",
        createdBy: ownerId,
      });
      expect(response.body.apiToken.scopes).to.include(
        "certops:executor:events",
      );
      expect(response.body.apiToken.token_hash).to.equal(undefined);
      expect(response.body.apiToken.plaintextToken).to.equal(undefined);
      expect(response.body.hasUser).to.equal(false);
      expect(response.body.isAdmin).to.equal(false);
      expect(response.body.authenticated).to.equal(false);
      expectNoRawToken(response.body, created.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects missing, non-Bearer, and malformed tokens with generic 401", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-api-token-auth-invalid",
    );

    try {
      for (const authorization of [
        null,
        "Basic abc123",
        "Bearer ttx__bad",
      ]) {
        const request = supertest(buildAuthHarness()).post(
          `/api/v1/workspaces/${workspaceA}/certops/machine-auth-test`,
        );
        if (authorization) request.set("Authorization", authorization);

        const response = await request.send({});
        expect(response.status).to.equal(401);
        expect(response.body.code).to.equal("CERTOPS_API_TOKEN_UNAUTHORIZED");
        expect(JSON.stringify(response.body)).to.not.include("ttx__bad");
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects wrong-workspace, revoked, expired, and missing-scope tokens", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-api-token-auth-failures",
    );

    try {
      const validForA = await createApiToken({
        workspaceId: workspaceA,
        name: "Workspace A",
        scopes: ["certops:executor:events"],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdBy: ownerId,
      });

      const wrongWorkspace = await supertest(buildAuthHarness())
        .post(`/api/v1/workspaces/${workspaceB}/certops/machine-auth-test`)
        .set("Authorization", `Bearer ${validForA.plaintextToken}`)
        .send({});
      expect(wrongWorkspace.status).to.equal(401);
      expectNoRawToken(wrongWorkspace.body, validForA.plaintextToken);

      await revokeApiToken({
        workspaceId: workspaceA,
        tokenId: validForA.token.id,
        revokedBy: ownerId,
      });
      const revoked = await supertest(buildAuthHarness())
        .post(`/api/v1/workspaces/${workspaceA}/certops/machine-auth-test`)
        .set("Authorization", `Bearer ${validForA.plaintextToken}`)
        .send({});
      expect(revoked.status).to.equal(401);

      const expired = await createApiToken({
        workspaceId: workspaceA,
        name: "Expired",
        scopes: ["certops:executor:events"],
        expiresAt: new Date(Date.now() - 60 * 1000),
        createdBy: ownerId,
      });
      const expiredResponse = await supertest(buildAuthHarness())
        .post(`/api/v1/workspaces/${workspaceA}/certops/machine-auth-test`)
        .set("Authorization", `Bearer ${expired.plaintextToken}`)
        .send({});
      expect(expiredResponse.status).to.equal(401);

      const jobsOnly = await createApiToken({
        workspaceId: workspaceA,
        name: "Jobs only",
        scopes: ["certops:jobs:read"],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdBy: ownerId,
      });
      const missingScope = await supertest(buildAuthHarness())
        .post(`/api/v1/workspaces/${workspaceA}/certops/machine-auth-test`)
        .set("Authorization", `Bearer ${jobsOnly.plaintextToken}`)
        .send({});
      expect(missingScope.status).to.equal(403);
      expect(missingScope.body.code).to.equal("CERTOPS_API_TOKEN_SCOPE_DENIED");
      expectNoRawToken(missingScope.body, jobsOnly.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });
});
