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

async function tokenAuditEvents(workspaceId, action, tokenId) {
  const result = await TestUtils.execQuery(
    `SELECT actor_user_id,
            subject_user_id,
            target_type,
            target_id,
            workspace_id,
            metadata
       FROM audit_events
      WHERE workspace_id = $1
        AND action = $2
        AND metadata->>'api_token_id' = $3
      ORDER BY id ASC`,
    [workspaceId, action, tokenId],
  );
  return result.rows;
}

async function tokenAuditCount(workspaceId, action) {
  const result = await TestUtils.execQuery(
    `SELECT COUNT(*)::int AS count
       FROM audit_events
      WHERE workspace_id = $1
        AND action = $2`,
    [workspaceId, action],
  );
  return result.rows[0].count;
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
      "DELETE FROM audit_events WHERE workspace_id = ANY($1::uuid[])",
      [workspaceIds],
    );
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
      scopes: ["certops:events:write", "certops:jobs:read"],
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      createdBy: fixture.ownerUser.id,
    });
    const otherWorkspaceToken = await createApiToken({
      workspaceId: fixture.outsiderWorkspaceId,
      name: "Other workspace",
      scopes: ["certops:events:write"],
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
    const auditsBefore = await tokenAuditCount(
      fixture.workspaceId,
      "CERTOPS_API_TOKEN_CREATED",
    );
    const viewerDenied = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.viewerSession.cookie)
      .send({
        name: "Viewer denied",
        scopes: ["certops:events:write"],
      });
    expect(viewerDenied.status).to.equal(403);
    expectNoTokenLeak(viewerDenied.body);
    expect(
      await tokenAuditCount(fixture.workspaceId, "CERTOPS_API_TOKEN_CREATED"),
    ).to.equal(auditsBefore);

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
    expect(
      await tokenAuditCount(fixture.workspaceId, "CERTOPS_API_TOKEN_CREATED"),
    ).to.equal(auditsBefore);

    const response = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        name: "Executor route token",
        scopes: ["certops:events:write", "certops:jobs:read"],
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

    const createAudits = await tokenAuditEvents(
      fixture.workspaceId,
      "CERTOPS_API_TOKEN_CREATED",
      response.body.token.id,
    );
    expect(createAudits).to.have.length(1);
    expect(createAudits[0]).to.include({
      actor_user_id: fixture.managerUser.id,
      subject_user_id: fixture.managerUser.id,
      target_type: "certops_api_token",
      target_id: null,
      workspace_id: fixture.workspaceId,
    });
    expect(createAudits[0].metadata).to.deep.include({
      api_token_id: response.body.token.id,
      token_prefix: response.body.token.tokenPrefix,
      name: response.body.token.name,
      scopes: response.body.token.scopes,
      status: response.body.token.status,
    });
    expectNoTokenLeak(createAudits[0].metadata, [response.body.plaintextToken]);

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
    expect(
      await tokenAuditEvents(
        fixture.workspaceId,
        "CERTOPS_API_TOKEN_CREATED",
        response.body.token.id,
      ),
    ).to.have.length(1);
  });

  it("revokes tokens within the workspace without returning plaintext or hashes", async () => {
    const created = await createApiToken({
      workspaceId: fixture.workspaceId,
      name: "Route revoke",
      scopes: ["certops:events:write"],
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      createdBy: fixture.ownerUser.id,
    });
    const revokeAuditsBefore = await tokenAuditEvents(
      fixture.workspaceId,
      "CERTOPS_API_TOKEN_REVOKED",
      created.token.id,
    );
    expect(revokeAuditsBefore).to.have.length(0);

    const viewerDenied = await request(BASE)
      .post(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/${created.token.id}/revoke`,
      )
      .set("Cookie", fixture.viewerSession.cookie)
      .send({});
    expect(viewerDenied.status).to.equal(403);
    expectNoTokenLeak(viewerDenied.body, [created.plaintextToken]);
    expect(
      await tokenAuditEvents(
        fixture.workspaceId,
        "CERTOPS_API_TOKEN_REVOKED",
        created.token.id,
      ),
    ).to.have.length(0);

    const crossWorkspace = await request(BASE)
      .post(
        `/api/v1/workspaces/${fixture.outsiderWorkspaceId}/certops/tokens/${created.token.id}/revoke`,
      )
      .set("Cookie", fixture.outsiderSession.cookie)
      .send({});
    expect(crossWorkspace.status).to.equal(404);
    expect(crossWorkspace.body.code).to.equal("CERTOPS_API_TOKEN_NOT_FOUND");
    expectNoTokenLeak(crossWorkspace.body, [created.plaintextToken]);
    expect(
      await tokenAuditEvents(
        fixture.workspaceId,
        "CERTOPS_API_TOKEN_REVOKED",
        created.token.id,
      ),
    ).to.have.length(0);

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
    expect(
      await tokenAuditEvents(
        fixture.workspaceId,
        "CERTOPS_API_TOKEN_REVOKED",
        created.token.id,
      ),
    ).to.have.length(0);

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

    const revokeAudits = await tokenAuditEvents(
      fixture.workspaceId,
      "CERTOPS_API_TOKEN_REVOKED",
      created.token.id,
    );
    expect(revokeAudits).to.have.length(1);
    expect(revokeAudits[0]).to.include({
      actor_user_id: fixture.managerUser.id,
      subject_user_id: fixture.managerUser.id,
      target_type: "certops_api_token",
      target_id: null,
      workspace_id: fixture.workspaceId,
    });
    expect(revokeAudits[0].metadata).to.deep.include({
      api_token_id: created.token.id,
      token_prefix: created.token.tokenPrefix,
      name: created.token.name,
      scopes: created.token.scopes,
      status: "revoked",
    });
    expectNoTokenLeak(revokeAudits[0].metadata, [created.plaintextToken]);

    const afterRevoke = await validateApiToken({
      workspaceId: fixture.workspaceId,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:events:write"],
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
    expect(
      await tokenAuditEvents(
        fixture.workspaceId,
        "CERTOPS_API_TOKEN_REVOKED",
        created.token.id,
      ),
    ).to.have.length(1);
  });

  it("rejects raw CertOps tokens in names without exposing them or overblocking prefixes", async () => {
    const tokenA = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        name: "Token A",
        scopes: ["certops:events:write"],
      })
      .expect(201);
    const tokensBefore = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS count FROM api_tokens WHERE workspace_id = $1",
      [fixture.workspaceId],
    );

    for (const name of [
      tokenA.body.plaintextToken,
      `production-${tokenA.body.plaintextToken}`,
      `credential=${tokenA.body.plaintextToken}`,
      "credential=not-a-token",
      "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
      `token_hash=${"a".repeat(64)}`,
    ]) {
      const rejected = await request(BASE)
        .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
        .set("Cookie", fixture.managerSession.cookie)
        .send({ name, scopes: ["certops:events:write"] });
      expect(rejected.status).to.equal(400);
      expect(rejected.body.code).to.equal("CERTOPS_API_TOKEN_NAME_INVALID");
      expectNoTokenLeak(rejected.body, [tokenA.body.plaintextToken]);
    }

    const tokensAfterRejectedNames = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS count FROM api_tokens WHERE workspace_id = $1",
      [fixture.workspaceId],
    );
    expect(tokensAfterRejectedNames.rows[0].count).to.equal(
      tokensBefore.rows[0].count,
    );

    const prefixOnly = tokenA.body.token.tokenPrefix;
    const prefixAccepted = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({ name: prefixOnly, scopes: ["certops:events:write"] })
      .expect(201);
    expect(prefixAccepted.body.token.name).to.equal(prefixOnly);
    expectNoTokenLeak(prefixAccepted.body.token, [tokenA.body.plaintextToken]);

    const viewerList = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);
    expectNoTokenLeak(viewerList.body, [tokenA.body.plaintextToken]);
  });

  it("requires a real session manager or admin for token mutations", async () => {
    const workerKey = process.env.WORKER_API_KEY || process.env.SESSION_SECRET;
    expect(workerKey).to.be.a("string").and.not.equal("");
    const createAuditsBefore = await tokenAuditCount(
      fixture.workspaceId,
      "CERTOPS_API_TOKEN_CREATED",
    );

    const workerCreate = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Authorization", `Bearer ${workerKey}`)
      .send({
        name: "Worker denied",
        scopes: ["certops:events:write"],
      });
    expect(workerCreate.status).to.equal(401);
    expectNoTokenLeak(workerCreate.body);
    expect(
      await tokenAuditCount(fixture.workspaceId, "CERTOPS_API_TOKEN_CREATED"),
    ).to.equal(createAuditsBefore);

    const adminCreated = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.ownerSession.cookie)
      .send({
        name: "Owner admin token",
        scopes: ["certops:events:write"],
      })
      .expect(201);
    expect(adminCreated.body.token.createdByUserId).to.equal(
      fixture.ownerUser.id,
    );

    const workerRevoked = await request(BASE)
      .post(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/${adminCreated.body.token.id}/revoke`,
      )
      .set("Authorization", `Bearer ${workerKey}`)
      .send({});
    expect(workerRevoked.status).to.equal(401);
    expectNoTokenLeak(workerRevoked.body, [adminCreated.body.plaintextToken]);

    const persisted = await TestUtils.execQuery(
      "SELECT status FROM api_tokens WHERE id = $1",
      [adminCreated.body.token.id],
    );
    expect(persisted.rows[0].status).to.equal("active");
    expect(
      await tokenAuditEvents(
        fixture.workspaceId,
        "CERTOPS_API_TOKEN_REVOKED",
        adminCreated.body.token.id,
      ),
    ).to.have.length(0);
  });

  it("writes one revoke audit for concurrent idempotent revocation", async () => {
    const created = await createApiToken({
      workspaceId: fixture.workspaceId,
      name: "Concurrent revoke",
      scopes: ["certops:events:write"],
      createdBy: fixture.ownerUser.id,
    });
    const url = `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/${created.token.id}/revoke`;
    const responses = await Promise.all([
      request(BASE).post(url).set("Cookie", fixture.managerSession.cookie).send({}),
      request(BASE).post(url).set("Cookie", fixture.ownerSession.cookie).send({}),
    ]);

    for (const response of responses) {
      expect(response.status).to.equal(200);
      expect(response.body.token.status).to.equal("revoked");
      expectNoTokenLeak(response.body, [created.plaintextToken]);
    }
    expect(
      await tokenAuditEvents(
        fixture.workspaceId,
        "CERTOPS_API_TOKEN_REVOKED",
        created.token.id,
      ),
    ).to.have.length(1);
  });

  it("rolls back token mutations when the corresponding audit write fails", async () => {
    await TestUtils.execQuery(`
      CREATE OR REPLACE FUNCTION fail_certops_api_token_audit_for_test()
      RETURNS trigger AS $$
      BEGIN
        IF NEW.action IN ('CERTOPS_API_TOKEN_CREATED', 'CERTOPS_API_TOKEN_REVOKED') THEN
          RAISE EXCEPTION 'forced CertOps API token audit failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `);
    await TestUtils.execQuery(`
      CREATE TRIGGER fail_certops_api_token_audit_for_test_trigger
      BEFORE INSERT ON audit_events
      FOR EACH ROW
      EXECUTE FUNCTION fail_certops_api_token_audit_for_test();
    `);

    try {
      const failedCreate = await request(BASE)
        .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
        .set("Cookie", fixture.managerSession.cookie)
        .send({
          name: "Audit failure create",
          scopes: ["certops:events:write"],
        });
      expect(failedCreate.status).to.equal(500);
      expectNoTokenLeak(failedCreate.body);
      const createdRows = await TestUtils.execQuery(
        "SELECT id FROM api_tokens WHERE workspace_id = $1 AND name = $2",
        [fixture.workspaceId, "Audit failure create"],
      );
      expect(createdRows.rows).to.have.length(0);

      const created = await createApiToken({
        workspaceId: fixture.workspaceId,
        name: "Audit failure revoke",
        scopes: ["certops:events:write"],
        createdBy: fixture.ownerUser.id,
      });
      const failedRevoke = await request(BASE)
        .post(
          `/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/${created.token.id}/revoke`,
        )
        .set("Cookie", fixture.managerSession.cookie)
        .send({});
      expect(failedRevoke.status).to.equal(500);
      expectNoTokenLeak(failedRevoke.body, [created.plaintextToken]);
      const revokedRow = await TestUtils.execQuery(
        "SELECT status FROM api_tokens WHERE id = $1",
        [created.token.id],
      );
      expect(revokedRow.rows[0].status).to.equal("active");
      expect(
        await tokenAuditEvents(
          fixture.workspaceId,
          "CERTOPS_API_TOKEN_REVOKED",
          created.token.id,
        ),
      ).to.have.length(0);
    } finally {
      await TestUtils.execQuery(
        "DROP TRIGGER IF EXISTS fail_certops_api_token_audit_for_test_trigger ON audit_events",
      );
      await TestUtils.execQuery(
        "DROP FUNCTION IF EXISTS fail_certops_api_token_audit_for_test()",
      );
    }
  });

  it("rejects private-key material before token creation or revoke handlers run", async () => {
    const createRejected = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        name: "bad",
        scopes: ["certops:events:write"],
        note: "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----",
      });
    expect(createRejected.status).to.equal(422);
    expect(createRejected.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    expectNoTokenLeak(createRejected.body);

    const created = await createApiToken({
      workspaceId: fixture.workspaceId,
      name: "Reject revoke body",
      scopes: ["certops:events:write"],
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
      requiredScopes: ["certops:events:write"],
    });
    expect(stillValid.valid).to.equal(true);
  });
});
