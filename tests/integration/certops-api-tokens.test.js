const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations, migrations } = requireMigrateModule();
const {
  CERTOPS_API_TOKEN_SCOPE_INVALID,
  CERTOPS_API_TOKEN_SCOPE_DENIED,
  createApiToken,
  getApiTokenById,
  listApiTokens,
  revokeApiToken,
  validateApiToken,
  _test,
} = require("../../apps/api/services/certops/apiTokens");

const API_TOKENS_MIGRATION = migrations.find(
  (migration) => migration.name === "certops_api_tokens_schema",
);

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
      "not-used-in-api-token-test",
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
  await TestUtils.execQuery("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [
    workspaceIds,
  ]);
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

function assertNoPlaintext(value, plaintextToken) {
  expect(JSON.stringify(value)).to.not.include(plaintextToken);
}

function parseTokenShape(rawToken) {
  const match = /^ttx_([a-f0-9]{16})_([a-f0-9]{64})$/.exec(rawToken);
  expect(match, `expected ttx_<id>_<secret> token, got ${rawToken}`).to.not.equal(
    null,
  );
  return { idPart: match[1], secretPart: match[2] };
}

describe("CertOps API tokens", function () {
  this.timeout(60000);

  before(async () => {
    await runMigrations();
    await TestUtils.execQuery(API_TOKENS_MIGRATION.sql);
  });

  it("creates the api_tokens table with safe lookup columns and indexes", async () => {
    const columns = await TestUtils.execQuery(
      `SELECT column_name
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'api_tokens'
        ORDER BY ordinal_position`,
    );

    expect(columns.rows.map((row) => row.column_name)).to.include.members([
      "id",
      "workspace_id",
      "name",
      "token_prefix",
      "token_hash",
      "scopes",
      "status",
      "expires_at",
      "last_used_at",
      "revoked_at",
      "revoked_by",
      "created_by",
      "created_at",
      "updated_at",
    ]);

    const forbiddenFragments = [
      "private",
      "key_material",
      "pfx",
      "jks",
      "password",
      "credential",
      "secret",
    ];
    for (const row of columns.rows) {
      const hit = forbiddenFragments.find((fragment) =>
        row.column_name.includes(fragment),
      );
      expect(hit, `${row.column_name} looks like custody`).to.equal(undefined);
    }

    const indexes = await TestUtils.execQuery(
      `SELECT indexname
         FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = 'api_tokens'`,
    );
    expect(indexes.rows.map((row) => row.indexname)).to.include.members([
      "uq_api_tokens_token_prefix",
      "uq_api_tokens_token_hash",
      "idx_api_tokens_workspace",
      "idx_api_tokens_workspace_status",
      "idx_api_tokens_status_expires",
    ]);
  });

  it("supports create, list, validate, and revoke without persisting raw tokens", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-api-token-flow",
    );

    try {
      const created = await createApiToken({
        workspaceId: workspaceA,
        name: "Executor",
        scopes: ["certops:events:write", "certops:jobs:read"],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdBy: ownerId,
      });

      const { idPart, secretPart } = parseTokenShape(created.plaintextToken);
      expect(created.plaintextToken.length).to.equal(_test.RAW_TOKEN_LENGTH);
      expect(idPart).to.not.equal("");
      expect(secretPart).to.not.equal("");
      expect(created.plaintextToken).to.not.match(/^ttx__/);
      expect(created.token.workspaceId).to.equal(workspaceA);
      expect(created.token.tokenHash).to.equal(undefined);

      const persisted = await TestUtils.execQuery(
        `SELECT token_prefix, token_hash
           FROM api_tokens
          WHERE id = $1`,
        [created.token.id],
      );
      expect(persisted.rows[0].token_prefix).to.equal(`ttx_${idPart}`);
      expect(persisted.rows[0].token_prefix).to.not.equal("ttx__");
      expect(persisted.rows[0].token_hash).to.equal(
        _test.sha256Hex(created.plaintextToken),
      );
      expect(persisted.rows[0].token_hash).to.not.equal(
        _test.sha256Hex(secretPart),
      );
      expect(JSON.stringify(persisted.rows[0])).to.not.include(
        created.plaintextToken,
      );

      const listA = await listApiTokens({ workspaceId: workspaceA });
      const listB = await listApiTokens({ workspaceId: workspaceB });
      expect(listA.map((token) => token.id)).to.include(created.token.id);
      expect(listB.map((token) => token.id)).to.not.include(created.token.id);
      assertNoPlaintext(listA, created.plaintextToken);

      const getWrongWorkspace = await getApiTokenById({
        workspaceId: workspaceB,
        tokenId: created.token.id,
      });
      expect(getWrongWorkspace).to.equal(null);

      const valid = await validateApiToken({
        workspaceId: workspaceA,
        rawToken: created.plaintextToken,
        requiredScopes: ["certops:events:write"],
      });
      expect(valid.valid).to.equal(true);
      expect(valid.token.id).to.equal(created.token.id);
      expect(valid.token.lastUsedAt).to.be.a("string");

      const wrongWorkspace = await validateApiToken({
        workspaceId: workspaceB,
        rawToken: created.plaintextToken,
        requiredScopes: ["certops:events:write"],
      });
      expect(wrongWorkspace.valid).to.equal(false);

      const revoked = await revokeApiToken({
        workspaceId: workspaceA,
        tokenId: created.token.id,
        revokedBy: ownerId,
      });
      expect(revoked.status).to.equal("revoked");
      assertNoPlaintext(revoked, created.plaintextToken);

      const afterRevoke = await validateApiToken({
        workspaceId: workspaceA,
        rawToken: created.plaintextToken,
        requiredScopes: ["certops:events:write"],
      });
      expect(afterRevoke.valid).to.equal(false);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects expired tokens and invalid scopes", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-api-token-expiry",
    );

    try {
      let invalidScopeError;
      try {
        await createApiToken({
          workspaceId: workspaceA,
          name: "Invalid",
          scopes: ["certops:everything"],
          createdBy: ownerId,
        });
      } catch (error) {
        invalidScopeError = error;
      }
      expect(invalidScopeError?.code).to.equal(
        CERTOPS_API_TOKEN_SCOPE_INVALID,
      );

      const created = await createApiToken({
        workspaceId: workspaceA,
        name: "Expired",
        scopes: ["certops:events:write"],
        expiresAt: new Date(Date.now() - 60 * 1000),
        createdBy: ownerId,
      });

      const expired = await validateApiToken({
        workspaceId: workspaceA,
        rawToken: created.plaintextToken,
        requiredScopes: ["certops:events:write"],
      });
      expect(expired.valid).to.equal(false);
      expect(created.token.status).to.equal("expired");

      const expiredMetadata = await getApiTokenById({
        workspaceId: workspaceA,
        tokenId: created.token.id,
      });
      expect(expiredMetadata.status).to.equal("expired");

      const persisted = await TestUtils.execQuery(
        `SELECT token_hash, last_used_at
           FROM api_tokens
          WHERE id = $1`,
        [created.token.id],
      );
      expect(persisted.rows[0].token_hash).to.equal(
        _test.sha256Hex(created.plaintextToken),
      );
      expect(persisted.rows[0].last_used_at).to.equal(null);
      expect(JSON.stringify(persisted.rows[0])).to.not.include(
        created.plaintextToken,
      );
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("allows certops:read for job reads but not write scopes", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-api-token-read-scope",
    );

    try {
      const created = await createApiToken({
        workspaceId: workspaceA,
        name: "Read-only observer",
        scopes: ["certops:read"],
        createdBy: ownerId,
      });

      const jobsRead = await validateApiToken({
        workspaceId: workspaceA,
        rawToken: created.plaintextToken,
        requiredScopes: ["certops:jobs:read"],
      });
      expect(jobsRead.valid).to.equal(true);

      for (const requiredScope of [
        "certops:events:write",
        "certops:evidence:write",
      ]) {
        const result = await validateApiToken({
          workspaceId: workspaceA,
          rawToken: created.plaintextToken,
          requiredScopes: [requiredScope],
        });
        expect(result.valid).to.equal(false);
        expect(result.code).to.equal(CERTOPS_API_TOKEN_SCOPE_DENIED);
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });
});
