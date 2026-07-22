"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRED,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_MALFORMED,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_USED,
  CERTOPS_AGENT_CREDENTIAL_INVALID,
  CERTOPS_AGENT_CREDENTIAL_MALFORMED,
  PRIVATE_KEY_MATERIAL_REJECTED,
  consumeBootstrapToken,
  createBootstrapToken,
  generateAgentCredential,
  listBootstrapTokens,
  revokeBootstrapToken,
  validateAgentCredential,
  validateBootstrapToken,
  _test,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentCredentials.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";

function date(offsetMs) {
  return new Date(Date.now() + offsetMs);
}

function createMemoryClient() {
  const bootstrapRows = [];
  const agentRows = [];
  let nextId = 1;

  const client = {
    bootstrapRows,
    agentRows,
    queries: [],
    beforeConsume: null,
    async query(sql, params = []) {
      const normalizedSql = sql.replace(/\s+/g, " ");
      client.queries.push({ sql: normalizedSql, params });

      if (normalizedSql.includes("INSERT INTO certops_agent_bootstrap_tokens")) {
        const row = {
          id: `boot-${nextId++}`,
          workspace_id: params[0],
          name: params[1],
          token_prefix: params[2],
          token_hash: params[3],
          status: "active",
          expires_at: params[4],
          used_at: null,
          used_by_agent_id: null,
          revoked_at: null,
          revoked_by: null,
          created_by: params[5],
          created_at: new Date("2026-07-01T00:00:00.000Z"),
          updated_at: new Date("2026-07-01T00:00:00.000Z"),
        };
        bootstrapRows.push(row);
        return { rows: [row] };
      }

      if (
        normalizedSql.includes("FROM certops_agent_bootstrap_tokens") &&
        normalizedSql.includes("WHERE token_prefix = $1")
      ) {
        return {
          rows: bootstrapRows.filter((row) => row.token_prefix === params[0]),
        };
      }

      if (
        normalizedSql.includes("FROM certops_agent_bootstrap_tokens") &&
        normalizedSql.includes("WHERE workspace_id = $1") &&
        normalizedSql.includes("AND id = $2")
      ) {
        return {
          rows: bootstrapRows.filter(
            (row) => row.workspace_id === params[0] && row.id === params[1],
          ),
        };
      }

      if (
        normalizedSql.includes("FROM certops_agent_bootstrap_tokens") &&
        normalizedSql.includes("ORDER BY created_at DESC")
      ) {
        return {
          rows: bootstrapRows.filter((row) => row.workspace_id === params[0]),
        };
      }

      if (normalizedSql.includes("SET status = 'revoked'")) {
        const row = bootstrapRows.find(
          (item) => item.workspace_id === params[0] && item.id === params[1],
        );
        if (!row || row.status !== "active") return { rows: [] };
        row.status = "revoked";
        row.revoked_at = new Date("2026-07-01T00:01:00.000Z");
        row.revoked_by = params[2] || null;
        row.updated_at = new Date("2026-07-01T00:01:00.000Z");
        return { rows: [row] };
      }

      if (normalizedSql.includes("SET status = 'used'")) {
        const row = bootstrapRows.find((item) => item.id === params[0]);
        client.beforeConsume?.(row, params);
        const expired =
          row?.expires_at &&
          new Date(row.expires_at).getTime() <= Date.now();
        if (!row || row.status !== "active" || expired) return { rows: [] };
        row.status = "used";
        row.used_at = new Date("2026-07-01T00:02:00.000Z");
        row.used_by_agent_id = params[1];
        row.updated_at = new Date("2026-07-01T00:02:00.000Z");
        return { rows: [row] };
      }

      if (
        normalizedSql.includes("FROM certops_agents") &&
        normalizedSql.includes("WHERE credential_prefix = $1")
      ) {
        return {
          rows: agentRows.filter((row) => row.credential_prefix === params[0]),
        };
      }

      throw new Error(`Unexpected query: ${normalizedSql}`);
    },
  };
  return client;
}

function insertAgentRow(client, credential, overrides = {}) {
  const row = {
    id: `agent-row-${client.agentRows.length + 1}`,
    workspace_id: WORKSPACE_A,
    agent_id: "agent-01",
    name: "Edge agent",
    credential_prefix: credential.credentialPrefix,
    credential_hash: credential.credentialHash,
    status: "active",
    protocol_version: "1.0.0",
    agent_version: "0.1.0",
    pinned_signing_key_id: null,
    last_seen_at: null,
    retired_at: null,
    ...overrides,
  };
  client.agentRows.push(row);
  return row;
}

describe("CertOps agent bootstrap tokens", () => {
  it("creates ttboot_<id>_<secret> tokens and stores only prefix plus sha256 hash", async () => {
    const client = createMemoryClient();
    const created = await createBootstrapToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Rack 12 bootstrap",
      expiresAt: date(60_000),
      createdBy: 7,
    });

    const match = _test.RAW_BOOTSTRAP_TOKEN_PATTERN.exec(created.plaintextToken);
    assert.ok(match, `expected ttboot token, got ${created.plaintextToken}`);
    assert.equal(created.plaintextToken.length, _test.RAW_BOOTSTRAP_TOKEN_LENGTH);
    assert.equal(created.token.tokenPrefix, `ttboot_${match[1]}`);
    assert.equal(
      client.bootstrapRows[0].token_hash,
      _test.sha256Hex(created.plaintextToken),
    );
    assert.notEqual(client.bootstrapRows[0].token_hash, created.plaintextToken);
    assert.equal(
      JSON.stringify(created.token).includes(created.plaintextToken),
      false,
    );
    assert.equal(created.token.tokenHash, undefined);
    assert.equal(created.token.token_hash, undefined);
  });

  it("round-trips parse of a generated bootstrap token", () => {
    const raw = `ttboot_${"ab".repeat(8)}_${"cd".repeat(32)}`;
    const parsed = _test.parseRawBootstrapToken(raw);
    assert.equal(parsed.tokenPrefix, `ttboot_${"ab".repeat(8)}`);
    assert.equal(parsed.rawToken, raw);
  });

  it("requires a future expiry no more than 30 days out", async () => {
    for (const expiresAt of [
      undefined,
      null,
      "",
      "not-a-date",
      date(-60_000),
      new Date(),
      date(_test.MAX_BOOTSTRAP_TOKEN_TTL_MS + 60_000),
    ]) {
      await assert.rejects(
        () =>
          createBootstrapToken({
            client: createMemoryClient(),
            workspaceId: WORKSPACE_A,
            name: "Expiry check",
            expiresAt,
          }),
        (error) =>
          error?.code === CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID,
      );
    }

    await createBootstrapToken({
      client: createMemoryClient(),
      workspaceId: WORKSPACE_A,
      name: "Expiry ok",
      expiresAt: date(_test.MAX_BOOTSTRAP_TOKEN_TTL_MS - 60_000),
    });
  });

  it("rejects invalid and credential-looking names", async () => {
    const credentialLike = `ttboot_${"0".repeat(16)}_${"a".repeat(64)}`;
    for (const name of [
      undefined,
      "",
      "   ",
      "x".repeat(129),
      credentialLike,
      `deploy ${credentialLike}`,
      `ttagent_${"0".repeat(16)}_${"a".repeat(64)}`,
      `token_hash=${"a".repeat(64)}`,
      "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    ]) {
      await assert.rejects(
        () =>
          createBootstrapToken({
            client: createMemoryClient(),
            workspaceId: WORKSPACE_A,
            name,
            expiresAt: date(60_000),
          }),
        (error) => error?.code === CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID,
      );
    }
  });

  it("rejects private key material in names", async () => {
    await assert.rejects(
      () =>
        createBootstrapToken({
          client: createMemoryClient(),
          workspaceId: WORKSPACE_A,
          name: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
          expiresAt: date(60_000),
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("validates only active unexpired tokens with timing-safe comparison", async () => {
    const client = createMemoryClient();
    const created = await createBootstrapToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Valid token",
      expiresAt: date(60_000),
    });

    const valid = await validateBootstrapToken({
      client,
      rawToken: created.plaintextToken,
    });
    assert.equal(valid.valid, true);
    assert.equal(valid.bootstrapToken.id, created.token.id);
    assert.equal(valid.bootstrapToken.token_hash, undefined);

    const wrongSecret = `${created.plaintextToken.slice(0, -4)}beef`;
    const badHash = await validateBootstrapToken({
      client,
      rawToken: wrongSecret,
    });
    assert.equal(badHash.valid, false);
    assert.equal(badHash.code, CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID);
  });

  it("rejects malformed bootstrap tokens before any lookup", async () => {
    const client = createMemoryClient();
    for (const rawToken of [
      "",
      null,
      "ttboot_short",
      `ttx_${"0".repeat(16)}_${"a".repeat(64)}`,
      `ttboot_${"0".repeat(16)}_${"a".repeat(63)}`,
      `ttboot_${"0".repeat(16)}_${"a".repeat(64)} `,
      `TTBOOT_${"0".repeat(16)}_${"a".repeat(64)}`,
    ]) {
      const result = await validateBootstrapToken({ client, rawToken });
      assert.equal(result.valid, false);
      assert.equal(result.code, CERTOPS_AGENT_BOOTSTRAP_TOKEN_MALFORMED);
    }
    assert.equal(client.queries.length, 0);
  });

  it("maps used, revoked, and expired statuses to distinct service codes", async () => {
    const client = createMemoryClient();
    const created = await createBootstrapToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Status mapping",
      expiresAt: date(60_000),
    });
    const row = client.bootstrapRows[0];

    row.status = "used";
    const used = await validateBootstrapToken({
      client,
      rawToken: created.plaintextToken,
    });
    assert.equal(used.valid, false);
    assert.equal(used.code, CERTOPS_AGENT_BOOTSTRAP_TOKEN_USED);

    row.status = "revoked";
    const revoked = await validateBootstrapToken({
      client,
      rawToken: created.plaintextToken,
    });
    assert.equal(revoked.valid, false);
    assert.equal(revoked.code, CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED);

    row.status = "expired";
    const markedExpired = await validateBootstrapToken({
      client,
      rawToken: created.plaintextToken,
    });
    assert.equal(markedExpired.valid, false);
    assert.equal(markedExpired.code, CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRED);

    row.status = "active";
    row.expires_at = date(-60_000);
    const expiredByTime = await validateBootstrapToken({
      client,
      rawToken: created.plaintextToken,
    });
    assert.equal(expiredByTime.valid, false);
    assert.equal(expiredByTime.code, CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRED);
  });

  it("consumes a token once and returns null when the race is lost", async () => {
    const client = createMemoryClient();
    const created = await createBootstrapToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Single use",
      expiresAt: date(60_000),
    });

    const consumed = await consumeBootstrapToken({
      client,
      tokenId: created.token.id,
      agentRowId: "agent-row-1",
    });
    assert.equal(consumed.status, "used");
    assert.equal(consumed.usedByAgentId, "agent-row-1");

    const again = await consumeBootstrapToken({
      client,
      tokenId: created.token.id,
      agentRowId: "agent-row-2",
    });
    assert.equal(again, null);
  });

  it("returns null when the token is revoked or expires between validation and consumption", async () => {
    const client = createMemoryClient();
    const created = await createBootstrapToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Race",
      expiresAt: date(60_000),
    });
    client.beforeConsume = (row) => {
      row.status = "revoked";
    };

    const lost = await consumeBootstrapToken({
      client,
      tokenId: created.token.id,
      agentRowId: "agent-row-1",
    });
    assert.equal(lost, null);
  });

  it("lists and revokes tokens without exposing hashes", async () => {
    const client = createMemoryClient();
    const created = await createBootstrapToken({
      client,
      workspaceId: WORKSPACE_A,
      name: "Listable",
      expiresAt: date(60_000),
    });

    const listed = await listBootstrapTokens({ client, workspaceId: WORKSPACE_A });
    assert.equal(listed.length, 1);
    assert.equal(listed[0].tokenHash, undefined);
    assert.equal(
      JSON.stringify(listed).includes(created.plaintextToken),
      false,
    );

    const revoked = await revokeBootstrapToken({
      client,
      workspaceId: WORKSPACE_A,
      tokenId: created.token.id,
      revokedBy: 42,
    });
    assert.equal(revoked.status, "revoked");
    assert.equal(revoked.revokedBy, 42);
    assert.equal(revoked.tokenHash, undefined);

    const result = await validateBootstrapToken({
      client,
      rawToken: created.plaintextToken,
    });
    assert.equal(result.valid, false);
    assert.equal(result.code, CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED);
  });
});

describe("CertOps agent credentials", () => {
  it("generates ttagent_<id>_<secret> credentials with prefix and sha256 hash only", () => {
    const generated = generateAgentCredential();

    const match = _test.RAW_AGENT_CREDENTIAL_PATTERN.exec(
      generated.plaintextCredential,
    );
    assert.ok(match, `expected ttagent credential, got shape mismatch`);
    assert.equal(
      generated.plaintextCredential.length,
      _test.RAW_AGENT_CREDENTIAL_LENGTH,
    );
    assert.equal(generated.credentialPrefix, `ttagent_${match[1]}`);
    assert.match(generated.credentialPrefix, /^ttagent_[a-f0-9]{16}$/);
    assert.equal(
      generated.credentialHash,
      _test.sha256Hex(generated.plaintextCredential),
    );
    assert.notEqual(generated.credentialHash, generated.plaintextCredential);
    assert.equal(generated.credentialHash.includes("ttagent_"), false);
  });

  it("round-trips parse of a generated agent credential", () => {
    const generated = generateAgentCredential();
    const parsed = _test.parseRawAgentCredential(generated.plaintextCredential);
    assert.equal(parsed.credentialPrefix, generated.credentialPrefix);
    assert.equal(parsed.rawCredential, generated.plaintextCredential);
  });

  it("validates an active agent credential and returns safe metadata only", async () => {
    const client = createMemoryClient();
    const generated = generateAgentCredential();
    insertAgentRow(client, generated, {
      last_seen_at: new Date("2026-07-20T00:00:00.000Z"),
      pinned_signing_key_id: "signing-key-1",
    });

    const result = await validateAgentCredential({
      client,
      rawCredential: generated.plaintextCredential,
    });

    assert.equal(result.valid, true);
    assert.deepEqual(result.agent, {
      id: "agent-row-1",
      workspaceId: WORKSPACE_A,
      agentId: "agent-01",
      name: "Edge agent",
      status: "active",
      protocolVersion: "1.0.0",
      agentVersion: "0.1.0",
      pinnedSigningKeyId: "signing-key-1",
      lastSeenAt: "2026-07-20T00:00:00.000Z",
      retiredAt: null,
    });
    assert.equal(result.agent.credential_hash, undefined);
    assert.equal(result.agent.credentialHash, undefined);
    assert.equal(
      JSON.stringify(result).includes(generated.plaintextCredential),
      false,
    );
    assert.equal(
      JSON.stringify(result).includes(generated.credentialHash),
      false,
    );
  });

  it("rejects malformed agent credentials before any lookup", async () => {
    const client = createMemoryClient();
    for (const rawCredential of [
      "",
      null,
      "ttagent_short",
      `ttboot_${"0".repeat(16)}_${"a".repeat(64)}`,
      `ttagent_${"0".repeat(16)}_${"a".repeat(63)}`,
      ` ttagent_${"0".repeat(16)}_${"a".repeat(64)}`,
      `TTAGENT_${"0".repeat(16)}_${"a".repeat(64)}`,
    ]) {
      const result = await validateAgentCredential({ client, rawCredential });
      assert.equal(result.valid, false);
      assert.equal(result.code, CERTOPS_AGENT_CREDENTIAL_MALFORMED);
    }
    assert.equal(client.queries.length, 0);
  });

  it("rejects unknown prefixes and wrong secrets with the same generic code", async () => {
    const client = createMemoryClient();
    const generated = generateAgentCredential();
    insertAgentRow(client, generated);

    const unknown = await validateAgentCredential({
      client,
      rawCredential: `ttagent_${"f".repeat(16)}_${"a".repeat(64)}`,
    });
    assert.equal(unknown.valid, false);
    assert.equal(unknown.code, CERTOPS_AGENT_CREDENTIAL_INVALID);

    const wrongSecret = await validateAgentCredential({
      client,
      rawCredential: `${generated.plaintextCredential.slice(0, -4)}beef`,
    });
    assert.equal(wrongSecret.valid, false);
    assert.equal(wrongSecret.code, CERTOPS_AGENT_CREDENTIAL_INVALID);
  });

  it("still authenticates retired agents and surfaces status for the 410 route rule", async () => {
    const client = createMemoryClient();
    const generated = generateAgentCredential();
    insertAgentRow(client, generated, {
      status: "retired",
      retired_at: new Date("2026-07-10T00:00:00.000Z"),
    });

    const result = await validateAgentCredential({
      client,
      rawCredential: generated.plaintextCredential,
    });
    assert.equal(result.valid, true);
    assert.equal(result.agent.status, "retired");
    assert.equal(result.agent.retiredAt, "2026-07-10T00:00:00.000Z");
  });

  it("uses constant-time sha256 hash comparison helpers", () => {
    const hash = _test.sha256Hex("credential-value");

    assert.equal(_test.safeCompareSha256Hex(hash, hash), true);
    assert.equal(
      _test.safeCompareSha256Hex(hash, _test.sha256Hex("other")),
      false,
    );
    assert.equal(_test.safeCompareSha256Hex(hash, "not-a-sha256"), false);
    assert.equal(_test.safeCompareSha256Hex("not-a-sha256", hash), false);
    assert.equal(_test.safeCompareSha256Hex("", ""), false);
  });
});
