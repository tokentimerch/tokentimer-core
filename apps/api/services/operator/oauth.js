"use strict";

const crypto = require("node:crypto");
const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const { hasAtLeastRole } = require("../rbac");
const connections = require("./connections");
const {
  sha256Hex,
  safeCompareSha256Hex,
} = require("../credentials/primitives");
const { remoteConfig, OAUTH_SCOPE } = require("./remoteConfig");
const protocol = require("./oauthProtocol");
const { ACCESS, REFRESH, CODE, READ_SCOPES, UUID, oauthError } = protocol;

const ACCESS_SECONDS = 900;
const REFRESH_SECONDS = 90 * 86400;
const MAX_STORED_TOKENS = 20000;
const CODE_SECONDS = 120;
const REQUEST_SECONDS = 600;

async function transaction(callback) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await callback(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function audit(client, userId, action, connection, extra = {}) {
  return writeAudit({
    client,
    actorUserId: userId,
    subjectUserId: connection.userId,
    action,
    targetType: "operator_connection",
    targetId: null,
    workspaceId: connection.workspaceId,
    metadata: { connection_id: connection.id, transport: "oauth", ...extra },
  });
}

async function cleanup(client = pool) {
  await client.query(
    "DELETE FROM operator_oauth_authorizations WHERE id IN (SELECT id FROM operator_oauth_authorizations WHERE expires_at < NOW() - INTERVAL '1 day' LIMIT 1000)",
  );
  await client.query(
    "DELETE FROM operator_oauth_tokens WHERE lookup_prefix IN (SELECT lookup_prefix FROM operator_oauth_tokens WHERE kind='access' AND expires_at < NOW() - INTERVAL '1 day' LIMIT 1000)",
  );
  await client.query(
    "DELETE FROM operator_oauth_grants WHERE id IN (SELECT id FROM operator_oauth_grants WHERE expires_at < NOW() - INTERVAL '1 day' OR revoked_at < NOW() - INTERVAL '1 day' LIMIT 1000)",
  );
  await client.query(`DELETE FROM operator_oauth_clients c WHERE c.expires_at < NOW()
    AND NOT EXISTS (SELECT 1 FROM operator_oauth_grants g WHERE g.client_id=c.client_id)
    AND NOT EXISTS (SELECT 1 FROM operator_oauth_authorizations a WHERE a.client_id=c.client_id)`);
}

async function saveClient(clientId, metadata, source) {
  return transaction(async (client) => {
    // Public registration is bounded even when requests arrive concurrently.
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtextextended('operator-oauth-clients', 0))",
    );
    await cleanup(client);
    const existing = await client.query(
      "SELECT client_id FROM operator_oauth_clients WHERE client_id=$1",
      [clientId],
    );
    const count = await client.query(
      "SELECT COUNT(*)::int AS count FROM operator_oauth_clients",
    );
    if (!existing.rows.length && count.rows[0].count >= 10000) {
      const evicted =
        await client.query(`DELETE FROM operator_oauth_clients c WHERE client_id IN (
        SELECT old.client_id FROM operator_oauth_clients old WHERE old.created_at < NOW()-INTERVAL '10 minutes'
        AND NOT EXISTS(SELECT 1 FROM operator_oauth_grants g WHERE g.client_id=old.client_id)
        AND NOT EXISTS(SELECT 1 FROM operator_oauth_authorizations a WHERE a.client_id=old.client_id)
        ORDER BY old.updated_at LIMIT 1) RETURNING client_id`);
      if (!evicted.rowCount) throw oauthError("temporarily_unavailable", 503);
    }
    await client.query(
      `INSERT INTO operator_oauth_clients(client_id,metadata,source,expires_at)
      VALUES($1,$2::jsonb,$3,NOW()+INTERVAL '1 day')
      ON CONFLICT(client_id) DO UPDATE SET metadata=EXCLUDED.metadata,updated_at=NOW(),expires_at=EXCLUDED.expires_at`,
      [clientId, JSON.stringify(metadata), source],
    );
    return { clientId, ...metadata };
  });
}

async function registerClient(input) {
  return saveClient(
    "ttmc_" + crypto.randomUUID(),
    protocol.clientMetadata(input),
    "registration",
  );
}

async function findClient(clientId) {
  protocol.string(clientId);
  const found = await pool.query(
    "SELECT metadata FROM operator_oauth_clients WHERE client_id=$1 AND source='registration'",
    [clientId],
  );
  if (!found.rows[0]) throw oauthError("invalid_client");
  return { clientId, ...found.rows[0].metadata };
}

async function beginAuthorization(input, config = remoteConfig()) {
  if (!config) throw oauthError("temporarily_unavailable", 404);
  const registered = await findClient(input.client_id);
  const intent = protocol.validateAuthorize(input, registered, config);
  const id = crypto.randomUUID(),
    browserNonce = crypto.randomBytes(32).toString("hex");
  await transaction(async (client) => {
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtextextended('operator-oauth-authorizations', 0))",
    );
    await cleanup(client);
    const pending = await client.query(
      "SELECT COUNT(*)::int AS count FROM operator_oauth_authorizations WHERE expires_at>NOW() AND decision='pending'",
    );
    if (pending.rows[0].count >= 10000)
      throw oauthError("temporarily_unavailable", 503);
    await client.query(
      `INSERT INTO operator_oauth_authorizations
    (id,client_id,resource,redirect_uri,state,code_challenge,browser_nonce_hash,client_metadata,expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,NOW()+INTERVAL '${REQUEST_SECONDS} seconds')`,
      [
        id,
        registered.clientId,
        config.resource,
        intent.redirectUri,
        intent.state,
        intent.challenge,
        sha256Hex(browserNonce),
        JSON.stringify(registered),
      ],
    );
  });
  return { id, browserNonce, expiresIn: REQUEST_SECONDS };
}

async function consentRecord(
  client,
  { requestId, browserNonce, userId, sessionId },
  config,
  lock = false,
) {
  if (
    !UUID.test(String(requestId || "")) ||
    typeof browserNonce !== "string" ||
    !/^[a-f0-9]{64}$/.test(browserNonce) ||
    !Number.isInteger(userId) ||
    typeof sessionId !== "string" ||
    !sessionId
  )
    throw oauthError("invalid_request");
  const found = await client.query(
    `SELECT a.*,a.client_metadata AS metadata FROM operator_oauth_authorizations a
    WHERE a.id=$1${lock ? " FOR UPDATE OF a" : ""}`,
    [requestId],
  );
  const row = found.rows[0];
  if (
    !row ||
    row.resource !== config.resource ||
    row.decision !== "pending" ||
    new Date(row.expires_at) <= new Date() ||
    !safeCompareSha256Hex(sha256Hex(browserNonce), row.browser_nonce_hash)
  )
    throw oauthError("invalid_request");
  if (
    row.consent_user_id !== null &&
    (row.consent_user_id !== userId ||
      !safeCompareSha256Hex(sha256Hex(sessionId), row.consent_session_hash))
  )
    throw oauthError("access_denied", 403);
  return row;
}

async function getConsentDetails(input, config = remoteConfig()) {
  return transaction(async (client) => {
    const row = await consentRecord(client, input, config, true);
    await client.query(
      "UPDATE operator_oauth_authorizations SET consent_user_id=$2,consent_session_hash=$3 WHERE id=$1",
      [row.id, input.userId, sha256Hex(input.sessionId)],
    );
    const found = await client.query(
      `SELECT w.id,w.name FROM workspaces w WHERE w.created_by=$1
      OR EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.workspace_id=w.id AND m.user_id=$1) ORDER BY w.name,w.id LIMIT 1000`,
      [input.userId],
    );
    const workspaces = [];
    for (const workspace of found.rows) {
      const role = await connections.resolveCurrentWorkspaceRole(client, {
        userId: input.userId,
        workspaceId: workspace.id,
      });
      if (hasAtLeastRole(role, "viewer"))
        workspaces.push({
          id: workspace.id,
          name: workspace.name,
          canRequestRenewals: hasAtLeastRole(role, "workspace_manager"),
        });
    }
    return {
      requestId: row.id,
      clientName: row.metadata.client_name,
      clientId: row.client_id,
      redirectOrigin: new URL(row.redirect_uri).origin,
      identityVerified: row.client_id.startsWith("https://"),
      expiresAt: new Date(row.expires_at).toISOString(),
      workspaces,
    };
  });
}

async function decideAuthorization(
  input,
  { config = remoteConfig(), admitWorkspace = async () => {} } = {},
) {
  return transaction(async (client) => {
    const row = await consentRecord(client, input, config, true);
    // The displayed account/session must still be the one making the decision.
    if (
      row.consent_user_id !== input.userId ||
      !safeCompareSha256Hex(
        sha256Hex(input.sessionId),
        row.consent_session_hash,
      )
    )
      throw oauthError("access_denied", 403);
    if (input.decision === "deny") {
      await client.query(
        "UPDATE operator_oauth_authorizations SET decision='denied' WHERE id=$1",
        [row.id],
      );
      return {
        redirectUrl: protocol.callbackUrl(row, config, {
          error: "access_denied",
        }),
      };
    }
    if (
      input.decision !== "approve" ||
      !UUID.test(String(input.workspaceId || "")) ||
      (input.noExpiry !== undefined && typeof input.noExpiry !== "boolean") ||
      (input.noExpiry === true
        ? input.lifetimeDays !== undefined && input.lifetimeDays !== null
        : ![1, 7, 30, 90, 180, 365].includes(input.lifetimeDays)) ||
      typeof input.renewals !== "boolean" ||
      (input.inventoryImport !== undefined && typeof input.inventoryImport !== "boolean") ||
      (input.inventoryUpdate !== undefined && typeof input.inventoryUpdate !== "boolean") ||
      (input.contactCreate !== undefined && typeof input.contactCreate !== "boolean") ||
      (input.webhookCreate !== undefined && typeof input.webhookCreate !== "boolean") ||
      (input.groupCreate !== undefined && typeof input.groupCreate !== "boolean") ||
      (input.memberInvite !== undefined && typeof input.memberInvite !== "boolean") ||
      (input.issuance !== undefined && typeof input.issuance !== "boolean") ||
      typeof input.agentHealth !== "boolean"
    )
      throw oauthError("invalid_request");
    const role = await connections.resolveCurrentWorkspaceRole(client, {
      userId: input.userId,
      workspaceId: input.workspaceId,
      lock: true,
    });
    if (
      !hasAtLeastRole(role, "viewer") ||
      ((input.renewals || input.agentHealth || input.inventoryImport || input.inventoryUpdate || input.contactCreate || input.webhookCreate || input.groupCreate || input.memberInvite || input.issuance) &&
        !hasAtLeastRole(role, "workspace_manager"))
    )
      throw oauthError("access_denied", 403);
    await admitWorkspace({
      client,
      workspaceId: input.workspaceId,
      userId: input.userId,
    });
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
      [`operator-oauth:${input.workspaceId}:${input.userId}`],
    );
    const count = await client.query(
      `SELECT COUNT(*)::int AS count FROM operator_oauth_grants g JOIN operator_connections c ON c.id=g.connection_id
      WHERE c.workspace_id=$1 AND c.user_id=$2 AND c.status='active' AND (c.expires_at IS NULL OR c.expires_at>NOW()) AND g.revoked_at IS NULL`,
      [input.workspaceId, input.userId],
    );
    if (count.rows[0].count >= 100) throw oauthError("connection_limit", 409);
    const scopes = [...READ_SCOPES];
    if (input.agentHealth || input.renewals || input.issuance) scopes.push("mcp:agents:read");
    if (input.renewals) scopes.push("mcp:renew:request", "mcp:requests:read");
    if (input.inventoryImport) scopes.push("mcp:inventory:import");
    if (input.inventoryUpdate) scopes.push("mcp:inventory:update");
    if (input.contactCreate) scopes.push("mcp:contacts:create");
    if (input.webhookCreate) scopes.push("mcp:webhooks:create");
    if (input.groupCreate) scopes.push("mcp:groups:create");
    if (input.memberInvite) scopes.push("mcp:members:invite");
    if (input.issuance) scopes.push("mcp:issue:request");
    // Match the transaction clock used by the database lifetime constraint.
    const now = (await client.query("SELECT NOW() AS now")).rows[0].now;
    const created = await connections.createConnection({
      client,
      workspaceId: input.workspaceId,
      userId: input.userId,
      createdBy: input.userId,
      name: row.metadata.client_name,
      scopes,
      roleCeiling:
        input.renewals || input.agentHealth || input.inventoryImport || input.inventoryUpdate || input.contactCreate || input.webhookCreate || input.groupCreate || input.memberInvite || input.issuance ? "workspace_manager" : "viewer",
      expiresAt: input.noExpiry === true ? undefined : new Date(now.getTime() + input.lifetimeDays * 86400000),
      noExpiry: input.noExpiry,
      now,
    });
    // The unused local credential is discarded, never returned or persisted in plaintext.
    const connection = created.connection;
    await client.query(
      "INSERT INTO operator_oauth_grants(id,connection_id,client_id,resource,expires_at,refresh_allowed) VALUES($1,$2,$3,$4,$5,$6)",
      [
        crypto.randomUUID(),
        connection.id,
        row.client_id,
        config.resource,
        connection.expiresAt,
        row.metadata.grant_types.includes("refresh_token"),
      ],
    );
    const code = CODE.generate();
    await client.query(
      `UPDATE operator_oauth_authorizations SET decision='approved',connection_id=$2,code_hash=$3,code_expires_at=NOW()+INTERVAL '${CODE_SECONDS} seconds' WHERE id=$1`,
      [row.id, connection.id, sha256Hex(code)],
    );
    await audit(
      client,
      input.userId,
      "OPERATOR_CONNECTION_CREATED",
      connection,
      { scopes, client_id: row.client_id },
    );
    return { redirectUrl: protocol.callbackUrl(row, config, { code }) };
  });
}

async function issueTokens(client, grant) {
  // Keep every usable refresh hash for replay detection. Expired credentials
  // cannot authorize anything, so discard them after a day instead of ending
  // otherwise valid long-lived grants when a lifetime counter fills up.
  await client.query("DELETE FROM operator_oauth_tokens WHERE grant_id=$1 AND expires_at<NOW()-INTERVAL '1 day'", [grant.id]);
  const stored = await client.query("SELECT COUNT(*)::int AS count FROM operator_oauth_tokens WHERE grant_id=$1", [grant.id]);
  if (stored.rows[0].count + (grant.refresh_allowed ? 2 : 1) > MAX_STORED_TOKENS)
    throw oauthError("temporarily_unavailable", 429);
  const expiresIn = Math.min(
    ACCESS_SECONDS,
    grant.expires_at
      ? Math.floor((new Date(grant.expires_at).getTime() - Date.now()) / 1000)
      : ACCESS_SECONDS,
  );
  if (expiresIn <= 0) return { error: "invalid_grant" };
  const access = ACCESS.generate(),
    refresh = REFRESH.generate();
  const credentials = [
    ["access", access, ACCESS, new Date(Date.now() + expiresIn * 1000)],
  ];
  if (grant.refresh_allowed)
    credentials.push(["refresh", refresh, REFRESH, new Date(Math.min(
      grant.expires_at ? new Date(grant.expires_at).getTime() : Infinity,
      Date.now() + REFRESH_SECONDS * 1000,
    ))]);
  for (const [kind, raw, family, expiry] of credentials) {
    await client.query(
      "INSERT INTO operator_oauth_tokens(lookup_prefix,credential_hash,grant_id,kind,expires_at) VALUES($1,$2,$3,$4,$5)",
      [family.parse(raw).lookupPrefix, sha256Hex(raw), grant.id, kind, expiry],
    );
  }
  await client.query(
    "UPDATE operator_oauth_grants SET generation_count=CASE WHEN generation_count<2147483647 THEN generation_count+1 ELSE generation_count END WHERE id=$1",
    [grant.id],
  );
  return {
    access_token: access,
    token_type: "Bearer",
    expires_in: expiresIn,
    ...(grant.refresh_allowed ? { refresh_token: refresh } : {}),
    scope: OAUTH_SCOPE,
  };
}

async function lockedGrant(client, connectionId) {
  // Match the connection -> request/job lock order used by approval and revocation.
  await client.query(
    "SELECT id FROM operator_connections WHERE id=$1 FOR UPDATE",
    [connectionId],
  );
  const authority = await connections.authenticateConnectionId({
    client,
    connectionId,
  });
  if (!authority.valid) return null;
  const found = await client.query(
    "SELECT * FROM operator_oauth_grants WHERE connection_id=$1 FOR UPDATE",
    [connectionId],
  );
  const grant = found.rows[0];
  if (!grant || grant.revoked_at || (grant.expires_at && new Date(grant.expires_at) <= new Date()))
    return null;
  return { grant, connection: authority.connection };
}

async function revokeGrant(client, grant, connection, reason) {
  await client.query(
    "UPDATE operator_oauth_grants SET revoked_at=COALESCE(revoked_at,NOW()) WHERE id=$1",
    [grant.id],
  );
  const result = await connections.revokeConnection({
    client,
    workspaceId: connection.workspaceId,
    connectionId: connection.id,
    revokedBy: connection.userId,
  });
  if (result.revokedNow)
    await audit(
      client,
      connection.userId,
      "OPERATOR_CONNECTION_REVOKED",
      connection,
      { reason },
    );
}

async function exchangeCode(input, config) {
  if (!CODE.parse(input.code) || !input.client_id || !input.redirect_uri)
    throw oauthError("invalid_grant");
  return transaction(async (client) => {
    const found = await client.query(
      "SELECT * FROM operator_oauth_authorizations WHERE code_hash=$1",
      [sha256Hex(input.code)],
    );
    const row = found.rows[0];
    if (
      !row ||
      row.client_id !== input.client_id ||
      row.resource !== config.resource ||
      row.redirect_uri !== input.redirect_uri ||
      !protocol.validVerifier(input.code_verifier, row.code_challenge)
    )
      return { error: "invalid_grant" };
    const active = await lockedGrant(client, row.connection_id);
    if (!active) return { error: "invalid_grant" };
    const locked = (
      await client.query(
        "SELECT code_used_at,code_expires_at FROM operator_oauth_authorizations WHERE id=$1 FOR UPDATE",
        [row.id],
      )
    ).rows[0];
    if (locked.code_used_at) {
      await revokeGrant(
        client,
        active.grant,
        active.connection,
        "authorization_code_reuse",
      );
      return { error: "invalid_grant" };
    }
    if (new Date(locked.code_expires_at) <= new Date())
      return { error: "invalid_grant" };
    await client.query(
      "UPDATE operator_oauth_authorizations SET code_used_at=NOW() WHERE id=$1",
      [row.id],
    );
    return issueTokens(client, active.grant);
  });
}

async function exchangeRefresh(input, config) {
  const parsed = REFRESH.parse(input.refresh_token);
  if (!parsed || !input.client_id) throw oauthError("invalid_grant");
  return transaction(async (client) => {
    const found = await client.query(
      `SELECT t.*,g.connection_id,g.client_id,g.resource FROM operator_oauth_tokens t
      JOIN operator_oauth_grants g ON g.id=t.grant_id WHERE t.lookup_prefix=$1 AND t.kind='refresh'`,
      [parsed.lookupPrefix],
    );
    const row = found.rows[0];
    if (
      !row ||
      !safeCompareSha256Hex(
        sha256Hex(input.refresh_token),
        row.credential_hash,
      ) ||
      row.client_id !== input.client_id ||
      row.resource !== config.resource
    )
      return { error: "invalid_grant" };
    const active = await lockedGrant(client, row.connection_id);
    if (!active) return { error: "invalid_grant" };
    const locked = (
      await client.query(
        "SELECT used_at,expires_at FROM operator_oauth_tokens WHERE lookup_prefix=$1 FOR UPDATE",
        [parsed.lookupPrefix],
      )
    ).rows[0];
    if (locked.used_at) {
      await revokeGrant(
        client,
        active.grant,
        active.connection,
        "refresh_token_reuse",
      );
      return { error: "invalid_grant" };
    }
    if (new Date(locked.expires_at) <= new Date())
      return { error: "invalid_grant" };
    await client.query(
      "UPDATE operator_oauth_tokens SET used_at=NOW() WHERE lookup_prefix=$1",
      [parsed.lookupPrefix],
    );
    return issueTokens(client, active.grant);
  });
}

async function exchangeToken(input, config = remoteConfig()) {
  if (!config) throw oauthError("temporarily_unavailable", 404);
  protocol.requireResource(input.resource, config);
  protocol.requestedScope(input.scope);
  const result =
    input.grant_type === "authorization_code"
      ? await exchangeCode(input, config)
      : input.grant_type === "refresh_token"
        ? await exchangeRefresh(input, config)
        : { error: "unsupported_grant_type" };
  if (result.error) throw oauthError(result.error);
  return result;
}

async function authenticateAccess({
  client = pool,
  rawCredential,
  now = new Date(),
  config = remoteConfig(),
}) {
  const parsed = ACCESS.parse(rawCredential);
  if (!parsed || !config) return { valid: false };
  const found = await client.query(
    `SELECT t.credential_hash,t.expires_at,g.resource,g.client_id,g.revoked_at,g.expires_at AS grant_expires_at,g.connection_id
    FROM operator_oauth_tokens t JOIN operator_oauth_grants g ON g.id=t.grant_id
    WHERE t.lookup_prefix=$1 AND t.kind='access'`,
    [parsed.lookupPrefix],
  );
  const row = found.rows[0];
  if (
    !row ||
    !safeCompareSha256Hex(sha256Hex(rawCredential), row.credential_hash) ||
    row.resource !== config.resource ||
    row.revoked_at ||
    new Date(row.expires_at) <= now ||
    (row.grant_expires_at && new Date(row.grant_expires_at) <= now)
  )
    return { valid: false };
  const result = await connections.authenticateConnectionId({
    client,
    connectionId: row.connection_id,
    now,
  });
  if (!result.valid) return result;
  return {
    ...result,
    oauth: {
      clientId: row.client_id,
      resource: row.resource,
      expiresAt: new Date(row.expires_at).getTime() / 1000,
    },
  };
}

async function revokeToken(input, config = remoteConfig()) {
  const family = ACCESS.parse(input.token)
    ? ACCESS
    : REFRESH.parse(input.token)
      ? REFRESH
      : null;
  if (!family || !config || typeof input.client_id !== "string") return;
  await transaction(async (client) => {
    const found = await client.query(
      `SELECT t.credential_hash,g.connection_id,g.client_id,g.resource FROM operator_oauth_tokens t JOIN operator_oauth_grants g ON g.id=t.grant_id WHERE t.lookup_prefix=$1`,
      [family.parse(input.token).lookupPrefix],
    );
    const row = found.rows[0];
    if (
      !row ||
      row.client_id !== input.client_id ||
      row.resource !== config.resource ||
      !safeCompareSha256Hex(sha256Hex(input.token), row.credential_hash)
    )
      return;
    const active = await lockedGrant(client, row.connection_id);
    if (active)
      await revokeGrant(
        client,
        active.grant,
        active.connection,
        "oauth_client_revocation",
      );
  });
}

module.exports = {
  ACCESS_SECONDS,
  REFRESH_SECONDS,
  REQUEST_SECONDS,
  registerClient,
  findClient,
  beginAuthorization,
  getConsentDetails,
  decideAuthorization,
  exchangeToken,
  authenticateAccess,
  revokeToken,
  cleanup,
};
