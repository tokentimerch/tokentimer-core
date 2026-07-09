"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_API_TOKEN_MALFORMED,
  CERTOPS_API_TOKEN_SCOPE_DENIED,
  CERTOPS_API_TOKEN_SCOPE_INVALID,
  PRIVATE_KEY_MATERIAL_REJECTED,
  TOKEN_PREFIX,
  createApiToken,
  getApiTokenById,
  listApiTokens,
  revokeApiToken,
  validateApiToken,
  _test,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/apiTokens.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const WORKSPACE_B = "22222222-2222-4222-8222-222222222222";

function date(offsetMs) {
  return new Date(Date.now() + offsetMs);
}

function createMemoryClient() {
  const rows = [];
  let nextId = 1;

  return {
    rows,
    async query(sql, params = []) {
      const normalizedSql = sql.replace(/\s+/g, " ");

      if (normalizedSql.includes("INSERT INTO api_tokens")) {
        const row = {
          id: `api-token-${nextId++}`,
          workspace_id: params[0],
          name: params[1],
          token_prefix: params[2],
          token_hash: params[3],
          scopes: params[4],
          status: "active",
          expires_at: params[5],
          last_used_at: null,
          revoked_at: null,
          revoked_by: null,
          created_by: params[6],
          created_at: new Date("2026-06-30T00:00:00.000Z"),
          updated_at: new Date("2026-06-30T00:00:00.000Z"),
        };
        rows.push(row);
        return { rows: [row] };
      }

      if (normalizedSql.includes("WHERE token_prefix = $1")) {
        return { rows: rows.filter((row) => row.token_prefix === params[0]) };
      }

      if (
        normalizedSql.includes("WHERE workspace_id = $1") &&
        normalizedSql.includes("AND id = $2") &&
        normalizedSql.includes("SELECT")
      ) {
        return {
          rows: rows.filter(
            (row) => row.workspace_id === params[0] && row.id === params[1],
          ),
        };
      }

      if (
        normalizedSql.includes("WHERE workspace_id = $1") &&
        normalizedSql.includes("ORDER BY created_at DESC")
      ) {
        return {
          rows: rows.filter((row) => row.workspace_id === params[0]),
        };
      }

      if (normalizedSql.includes("SET status = 'revoked'")) {
        const row = rows.find(
          (item) => item.workspace_id === params[0] && item.id === params[1],
        );
        if (!row) return { rows: [] };
        row.status = "revoked";
        row.revoked_at = row.revoked_at || new Date("2026-06-30T00:01:00.000Z");
        row.revoked_by = row.revoked_by || params[2] || null;
        row.updated_at = new Date("2026-06-30T00:01:00.000Z");
        return { rows: [row] };
      }

      if (normalizedSql.includes("SET last_used_at = NOW()")) {
        const row = rows.find((item) => item.id === params[0]);
        if (!row) return { rows: [] };
        row.last_used_at = new Date("2026-06-30T00:02:00.000Z");
        row.updated_at = new Date("2026-06-30T00:02:00.000Z");
        return { rows: [row] };
      }

      throw new Error(`Unexpected query: ${normalizedSql}`);
    },
  };
}

function assertNoPlaintextToken(value, plaintextToken) {
  assert.equal(
    JSON.stringify(value).includes(plaintextToken),
    false,
    "service output must not include plaintext token",
  );
}

function parseTokenShape(rawToken) {
  const match = /^ttx_([^_]+)_([^_]+)$/.exec(rawToken);
  assert.ok(match, `expected ttx_<id>_<secret> token, got ${rawToken}`);
  return { idPart: match[1], secretPart: match[2] };
}

function collectKeys(value, keys = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, keys);
    return keys;
  }
  if (!value || typeof value !== "object") return keys;
  for (const [key, item] of Object.entries(value)) {
    keys.push(key);
    collectKeys(item, keys);
  }
  return keys;
}

function assertNoCustodyKeys(value) {
  const forbidden = [
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

  for (const key of collectKeys(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    const hit = forbidden.find((fragment) => normalized.includes(fragment));
    assert.equal(hit, undefined, `${key} looks like a custody field`);
  }
}

describe("CertOps API token service", () => {
  it("creates ttx_<id>_<secret> tokens and stores only prefix plus sha256 hash", async () => {
    const client = createMemoryClient();
    const created = await createApiToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Executor",
      scopes: ["certops:events:write"],
      expiresAt: date(60_000),
      createdBy: 123,
    });
    const { idPart, secretPart } = parseTokenShape(created.plaintextToken);

    assert.equal(TOKEN_PREFIX, "ttx_");
    assert.notEqual(idPart, "");
    assert.notEqual(secretPart, "");
    assert.equal(created.plaintextToken.startsWith("ttx__"), false);
    assert.equal(created.token.tokenPrefix, client.rows[0].token_prefix);
    assert.equal(client.rows[0].token_prefix, `ttx_${idPart}`);
    assert.notEqual(client.rows[0].token_prefix, "ttx__");
    assert.equal(
      client.rows[0].token_hash,
      _test.sha256Hex(created.plaintextToken),
    );
    assert.notEqual(client.rows[0].token_hash, created.plaintextToken);
    assert.equal(JSON.stringify(client.rows[0]).includes(created.plaintextToken), false);
    assert.equal(created.token.tokenHash, undefined);
  });

  it("rejects invalid scopes at creation time", async () => {
    for (const scope of ["certops:admin", "certops:executor:events"]) {
      await assert.rejects(
        () =>
          createApiToken({
            client: createMemoryClient(),
            workspaceId: WORKSPACE_A,
            name: "Bad scope",
            scopes: [scope],
          }),
        (error) => error?.code === CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }
  });

  it("rejects private key material in persisted token metadata", async () => {
    await assert.rejects(
      () =>
        createApiToken({
          client: createMemoryClient(),
          workspaceId: WORKSPACE_A,
          name: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
          scopes: ["certops:events:write"],
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("validates required scopes and updates last_used_at only on success", async () => {
    const client = createMemoryClient();
    const created = await createApiToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Executor",
      scopes: ["certops:events:write", "certops:jobs:read"],
    });

    const failed = await validateApiToken({
      client,
      workspaceId: WORKSPACE_A,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:evidence:write"],
    });
    assert.equal(failed.valid, false);
    assert.equal(failed.code, CERTOPS_API_TOKEN_SCOPE_DENIED);
    assert.equal(client.rows[0].last_used_at, null);

    const validated = await validateApiToken({
      client,
      workspaceId: WORKSPACE_A,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:events:write"],
    });
    assert.equal(validated.valid, true);
    assert.equal(validated.token.id, created.token.id);
    assert.match(validated.token.lastUsedAt, /^2026-06-30T00:02:00/);
  });

  it("allows certops:read to satisfy read scopes without granting writes", async () => {
    const client = createMemoryClient();
    const created = await createApiToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Read only",
      scopes: ["certops:read"],
    });

    const read = await validateApiToken({
      client,
      workspaceId: WORKSPACE_A,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:jobs:read"],
    });
    assert.equal(read.valid, true);

    const write = await validateApiToken({
      client,
      workspaceId: WORKSPACE_A,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:events:write"],
    });
    assert.equal(write.valid, false);
    assert.equal(write.code, CERTOPS_API_TOKEN_SCOPE_DENIED);
  });

  it("rejects malformed tokens and wrong prefixes", async () => {
    const client = createMemoryClient();

    for (const rawToken of [
      "",
      "not-a-token",
      "abc__12345678901234567890",
      "ttx__secret",
      "ttx_id_",
      "ttx__",
      "ttx_secret",
      "ttx_id",
    ]) {
      const result = await validateApiToken({
        client,
        workspaceId: WORKSPACE_A,
        rawToken,
        requiredScopes: [],
      });
      assert.equal(result.valid, false);
      assert.equal(result.code, CERTOPS_API_TOKEN_MALFORMED);
    }
  });

  it("rejects revoked tokens", async () => {
    const client = createMemoryClient();
    const created = await createApiToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Executor",
      scopes: ["certops:events:write"],
    });

    await revokeApiToken({
      client,
      workspaceId: WORKSPACE_A,
      tokenId: created.token.id,
      revokedBy: 321,
    });

    const result = await validateApiToken({
      client,
      workspaceId: WORKSPACE_A,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:events:write"],
    });
    assert.equal(result.valid, false);
  });

  it("rejects expired tokens", async () => {
    const client = createMemoryClient();
    const created = await createApiToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Expired",
      scopes: ["certops:events:write"],
      expiresAt: date(-60_000),
    });

    const result = await validateApiToken({
      client,
      workspaceId: WORKSPACE_A,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:events:write"],
    });
    assert.equal(result.valid, false);
    assert.equal(client.rows[0].last_used_at, null);
  });

  it("enforces workspace binding", async () => {
    const client = createMemoryClient();
    const created = await createApiToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Workspace A",
      scopes: ["certops:events:write"],
    });

    const result = await validateApiToken({
      client,
      workspaceId: WORKSPACE_B,
      rawToken: created.plaintextToken,
      requiredScopes: ["certops:events:write"],
    });
    assert.equal(result.valid, false);
    assert.equal(client.rows[0].last_used_at, null);
  });

  it("does not return plaintext tokens from list, get, or revoke", async () => {
    const client = createMemoryClient();
    const created = await createApiToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Executor",
      scopes: ["certops:events:write"],
    });

    const list = await listApiTokens({ client, workspaceId: WORKSPACE_A });
    const got = await getApiTokenById({
      client,
      workspaceId: WORKSPACE_A,
      tokenId: created.token.id,
    });
    const revoked = await revokeApiToken({
      client,
      workspaceId: WORKSPACE_A,
      tokenId: created.token.id,
      revokedBy: 1,
    });

    assertNoPlaintextToken(list, created.plaintextToken);
    assertNoPlaintextToken(got, created.plaintextToken);
    assertNoPlaintextToken(revoked, created.plaintextToken);
    assert.equal(list[0].tokenHash, undefined);
    assert.equal(got.tokenHash, undefined);
    assert.equal(revoked.tokenHash, undefined);
  });

  it("does not expose private-key-looking fields", async () => {
    const client = createMemoryClient();
    const created = await createApiToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Safe metadata",
      scopes: ["certops:events:write"],
    });
    const listed = await listApiTokens({ client, workspaceId: WORKSPACE_A });

    assertNoCustodyKeys(created.token);
    assertNoCustodyKeys(listed);
  });

  it("uses constant-time sha256 hash comparison helpers", () => {
    const hash = _test.sha256Hex("token-value");

    assert.equal(_test.safeCompareSha256Hex(hash, hash), true);
    assert.equal(_test.safeCompareSha256Hex(hash, _test.sha256Hex("other")), false);
    assert.equal(_test.safeCompareSha256Hex(hash, "not-a-sha256"), false);
  });
});
