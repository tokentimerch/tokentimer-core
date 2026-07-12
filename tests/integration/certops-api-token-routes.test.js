const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, request, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  createApiToken,
  validateApiToken,
} = require("../../apps/api/services/certops/apiTokens");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

async function primaryWorkspaceId(session) {
  const response = await request(BASE)
    .get("/api/v1/workspaces?limit=50&offset=0")
    .set("Cookie", session.cookie)
    .expect(200);
  return response.body.items[0].id;
}

function walkKeys(value, visit) {
  if (Array.isArray(value)) {
    for (const item of value) walkKeys(item, visit);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    visit(key);
    walkKeys(item, visit);
  }
}

function expectNoPrivateKeyFields(value) {
  const forbiddenFragments = [
    "privatekey",
    "privatekeypem",
    "encryptedprivatekey",
    "keymaterial",
    "pfxblob",
    "jksblob",
    "tlskey",
    "caprivatekey",
    "keystorepassword",
    "privatekeypassword",
    "keypassword",
    "password",
    "secret",
    "credential",
    "tokensecret",
    "apisecret",
    "rawsecret",
    "rawprivatekey",
    "rawkey",
    "pemprivatekey",
  ];

  walkKeys(value, (key) => {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    for (const fragment of forbiddenFragments) {
      expect(
        normalized.includes(fragment),
        `${key} looks like private-key or credential custody`,
      ).to.equal(false);
    }
  });
}

function expectNoTokenLeak(value, rawTokens = []) {
  const serialized = JSON.stringify(value);
  expect(serialized).to.not.include("Authorization");
  expect(serialized).to.not.include("Bearer ");
  expect(serialized).to.not.include("token_hash");
  expect(serialized).to.not.include("tokenHash");
  expect(serialized).to.not.include("rawToken");
  expect(serialized).to.not.include("raw token");
  expect(serialized).to.not.include("PRIVATE KEY");
  for (const rawToken of rawTokens.filter(Boolean)) {
    expect(serialized).to.not.include(rawToken);
  }
  expectNoPrivateKeyFields(value);
}

function expectMetadataOnlyToken(token) {
  expect(token).to.include.keys([
    "id",
    "workspaceId",
    "name",
    "tokenPrefix",
    "scopes",
    "status",
    "createdAt",
  ]);
  expect(token.tokenPrefix).to.match(/^ttx_[^_]+$/);
  expect(token).to.not.have.property("token_hash");
  expect(token).to.not.have.property("tokenHash");
  expect(token).to.not.have.property("plaintextToken");
}

async function createWorkspaceFixture() {
  const ownerUser = await TestUtils.createVerifiedTestUser();
  const ownerSession = await TestUtils.loginTestUser(
    ownerUser.email,
    "SecureTest123!@#",
  );
  const workspaceId = await primaryWorkspaceId(ownerSession);

  const managerUser = await TestUtils.createVerifiedTestUser();
  const managerSession = await TestUtils.loginTestUser(
    managerUser.email,
    "SecureTest123!@#",
  );
  await TestUtils.execQuery(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
     VALUES ($1, $2, 'workspace_manager', $3)
     ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
    [managerUser.id, workspaceId, ownerUser.id],
  );

  const viewerUser = await TestUtils.createVerifiedTestUser();
  const viewerSession = await TestUtils.loginTestUser(
    viewerUser.email,
    "SecureTest123!@#",
  );
  await TestUtils.execQuery(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
     VALUES ($1, $2, 'viewer', $3)
     ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
    [viewerUser.id, workspaceId, ownerUser.id],
  );

  const outsiderUser = await TestUtils.createVerifiedTestUser();
  const outsiderSession = await TestUtils.loginTestUser(
    outsiderUser.email,
    "SecureTest123!@#",
  );
  const outsiderWorkspaceId = await primaryWorkspaceId(outsiderSession);

  return {
    managerSession,
    managerUser,
    outsiderSession,
    outsiderUser,
    outsiderWorkspaceId,
    ownerSession,
    ownerUser,
    viewerSession,
    viewerUser,
    workspaceId,
  };
}

async function cleanupWorkspaceFixture(fixture) {
  if (!fixture) return;
  const workspaceIds = [
    fixture.workspaceId,
    fixture.outsiderWorkspaceId,
  ].filter(Boolean);
  if (workspaceIds.length > 0) {
    await TestUtils.execQuery(
      "DELETE FROM api_tokens WHERE workspace_id = ANY($1::uuid[])",
      [workspaceIds],
    );
    await TestUtils.execQuery(
      "DELETE FROM workspaces WHERE id = ANY($1::uuid[])",
      [workspaceIds],
    );
  }

  for (const [user, session] of [
    [fixture.ownerUser, fixture.ownerSession],
    [fixture.managerUser, fixture.managerSession],
    [fixture.viewerUser, fixture.viewerSession],
    [fixture.outsiderUser, fixture.outsiderSession],
  ]) {
    if (user?.email && session?.cookie) {
      await TestUtils.cleanupTestUser(user.email, session.cookie);
    }
  }
}

describe("CertOps API token management routes", function () {
  this.timeout(60000);

  let fixture;

  before(async () => {
    await runMigrations();
    fixture = await createWorkspaceFixture();
  });

  after(async () => {
    await cleanupWorkspaceFixture(fixture);
  });

  it("requires authentication and workspace membership", async () => {
    const unauthenticated = await request(BASE).get(
      `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`,
    );
    expect(unauthenticated.status).to.be.oneOf([401, 403]);
    expect(unauthenticated.status).to.not.equal(500);
    expectNoTokenLeak(unauthenticated.body);

    const forbidden = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.outsiderSession.cookie);
    expect(forbidden.status).to.equal(403);
    expectNoTokenLeak(forbidden.body);
  });

  it("lists metadata for the requested workspace only", async () => {
    const created = await createApiToken({
      workspaceId: fixture.workspaceId,
      name: "Workspace route list",
      scopes: ["certops:executor:events", "certops:jobs:read"],
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      createdBy: fixture.ownerUser.id,
    });
    const otherWorkspaceToken = await createApiToken({
      workspaceId: fixture.outsiderWorkspaceId,
      name: "Other workspace",
      scopes: ["certops:executor:events"],
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      createdBy: fixture.outsiderUser.id,
    });

    const response = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);

    const ids = response.body.items.map((token) => token.id);
    expect(ids).to.include(created.token.id);
    expect(ids).to.not.include(otherWorkspaceToken.token.id);
    for (const item of response.body.items) {
      expectMetadataOnlyToken(item);
    }
    expectNoTokenLeak(response.body, [
      created.plaintextToken,
      otherWorkspaceToken.plaintextToken,
    ]);
  });

  it("creates a scoped API token for managers and returns plaintext only once", async () => {
    const viewerDenied = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.viewerSession.cookie)
      .send({
        name: "Viewer denied",
        scopes: ["certops:executor:events"],
      });
    expect(viewerDenied.status).to.equal(403);
    expectNoTokenLeak(viewerDenied.body);

    const invalidScope = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        name: "Invalid scope",
        scopes: ["certops:everything"],
      });
    expect(invalidScope.status).to.equal(400);
    expect(invalidScope.body.code).to.equal("CERTOPS_API_TOKEN_SCOPE_INVALID");
    expectNoTokenLeak(invalidScope.body);

    const response = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        name: "Executor route token",
        scopes: ["certops:executor:events", "certops:jobs:read"],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      })
      .expect(201);

    expect(response.body.plaintextToken).to.match(/^ttx_[^_]+_[^_]+$/);
    expectMetadataOnlyToken(response.body.token);
    expect(response.body.token.workspaceId).to.equal(fixture.workspaceId);
    expect(response.body.token.createdByUserId).to.equal(fixture.managerUser.id);
    expect(response.body.token.tokenPrefix).to.equal(
      response.body.plaintextToken.split("_").slice(0, 2).join("_"),
    );
    expect(JSON.stringify(response.body.token)).to.not.include(
      response.body.plaintextToken,
    );
    expectNoTokenLeak(response.body.token, [response.body.plaintextToken]);

    const persisted = await TestUtils.execQuery(
      "SELECT token_prefix, token_hash FROM api_tokens WHERE id = $1",
      [response.body.token.id],
    );
    expect(persisted.rows[0].token_prefix).to.equal(
      response.body.token.tokenPrefix,
    );
    expect(JSON.stringify(persisted.rows[0])).to.not.include(
      response.body.plaintextToken,
    );

    const listAfterCreate = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.managerSession.cookie)
      .expect(200);
    expect(JSON.stringify(listAfterCreate.body)).to.not.include(
      response.body.plaintextToken,
    );
    expectNoTokenLeak(listAfterCreate.body, [response.body.plaintextToken]);
  });

  it("revokes tokens within the workspace without returning plaintext or hashes", async () => {
    const created = await createApiToken({
      workspaceId: fixture.workspaceId,
      name: "Route revoke",
      scopes: ["certops:executor:events"],
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      createdBy: fixture.ownerUser.id,
    });

    const viewerDenied = await request(BASE)
      .post(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/${created.token.id}/revoke`,
      )
      .set("Cookie", fixture.viewerSession.cookie)
      .send({});
    expect(viewerDenied.status).to.equal(403);
    expectNoTokenLeak(viewerDenied.body, [created.plaintextToken]);

    const crossWorkspace = await request(BASE)
      .post(
        `/api/v1/workspaces/${fixture.outsiderWorkspaceId}/certops/tokens/${created.token.id}/revoke`,
      )
      .set("Cookie", fixture.outsiderSession.cookie)
      .send({});
    expect(crossWorkspace.status).to.equal(404);
    expect(crossWorkspace.body.code).to.equal("CERTOPS_API_TOKEN_NOT_FOUND");
    expectNoTokenLeak(crossWorkspace.body, [created.plaintextToken]);

    const malformed = await request(BASE)
      .post(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/not-a-uuid/revoke`,
      )
      .set("Cookie", fixture.managerSession.cookie)
      .send({});
    expect(malformed.status).to.equal(400);
    expect(malformed.status).to.not.equal(500);
    expect(malformed.body.code).to.equal("CERTOPS_API_TOKEN_INVALID");
    expectNoTokenLeak(malformed.body, ["not-a-uuid"]);

    const response = await request(BASE)
      .post(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/${created.token.id}/revoke`,
      )
      .set("Cookie", fixture.managerSession.cookie)
      .send({})
      .expect(200);

    expect(response.body.token.status).to.equal("revoked");
    expect(response.body.token.revokedByUserId).to.equal(fixture.managerUser.id);
    expectMetadataOnlyToken(response.body.token);
    expectNoTokenLeak(response.body, [created.plaintextToken]);

    const afterRevoke = await validateApiToken({
      workspaceId: fixture.workspaceId,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:executor:events"],
    });
    expect(afterRevoke.valid).to.equal(false);

    const idempotent = await request(BASE)
      .post(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/${created.token.id}/revoke`,
      )
      .set("Cookie", fixture.managerSession.cookie)
      .send({})
      .expect(200);
    expect(idempotent.body.token.status).to.equal("revoked");
    expectNoTokenLeak(idempotent.body, [created.plaintextToken]);
  });

  it("rejects private-key material before token creation or revoke handlers run", async () => {
    const createRejected = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        name: "bad",
        scopes: ["certops:executor:events"],
        note: "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----",
      });
    expect(createRejected.status).to.equal(422);
    expect(createRejected.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    expectNoTokenLeak(createRejected.body);

    const created = await createApiToken({
      workspaceId: fixture.workspaceId,
      name: "Reject revoke body",
      scopes: ["certops:executor:events"],
      createdBy: fixture.ownerUser.id,
    });

    const revokeRejected = await request(BASE)
      .post(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/${created.token.id}/revoke`,
      )
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        note: "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----",
      });
    expect(revokeRejected.status).to.equal(422);
    expect(revokeRejected.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    expectNoTokenLeak(revokeRejected.body, [created.plaintextToken]);

    const stillValid = await validateApiToken({
      workspaceId: fixture.workspaceId,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:executor:events"],
    });
    expect(stillValid.valid).to.equal(true);
  });
});
