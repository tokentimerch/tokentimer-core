"use strict";

// Real PostgreSQL and HTTP with fixture sessions. Browser qualification uses
// the normal edition sign-in pages separately; no test session route ships.
const { before, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const apiRequire = createRequire(require.resolve("../../apps/api/index.js"));
const express = apiRequire("express");
const cookieParser = apiRequire("cookie-parser");
const session = apiRequire("express-session");
const { doubleCsrf } = apiRequire("csrf-csrf");
const request = require("supertest");
const { pool } = require("../../apps/api/db/database");
const oauth = require("../../apps/api/services/operator/oauth");
const connections = require("../../apps/api/services/operator/connections");
const { MCP_PATH, OAUTH_PATH, remoteConfig } = require("../../apps/api/services/operator/remoteConfig");
const { createMcpRemoteRouter, remoteCors, remoteBodyParser } = require("../../apps/api/routes/mcpRemote");
const { guardOperatorCredentials } = require("../../apps/api/middleware/operator-connection-auth");
const { createCsrfExemptMiddleware, isOperatorBearerCsrfExemptRequest } = require("../../apps/api/middleware/csrf-exempt");
const { sha256Hex } = require("../../apps/api/services/credentials/primitives");
const mcpRequire = createRequire(require.resolve("../../packages/mcp/package.json"));
const { Client, StreamableHTTPClientTransport } = mcpRequire("@modelcontextprotocol/client");

let server, origin, manager, viewer, owner, workspaceId;
const ids = [];
async function user(name) {
  const found = await pool.query("INSERT INTO users(email,display_name,auth_method,password_hash,email_verified) VALUES($1,$2,'local','fixture-only',TRUE) RETURNING id", [`oauth-${crypto.randomUUID()}@example.test`, name]);
  return found.rows[0].id;
}
function appFixture() {
  const app = express();
  app.use(remoteCors); app.use(remoteBodyParser); app.use(express.json()); app.use(cookieParser());
  app.use(session({ secret: "isolated-oauth-http-fixture-session", resave: false, saveUninitialized: false, cookie: { secure: false, httpOnly: true, sameSite: "lax" } }));
  app.use(async (req, _res, next) => {
    if (req.session.userId) req.user = (await pool.query("SELECT id,email,auth_method,email_verified FROM users WHERE id=$1", [req.session.userId])).rows[0];
    req.isAuthenticated = () => Boolean(req.user);
    next();
  });
  app.post("/test/sign-in", (req, res) => {
    const id = req.body.userId;
    if (![owner, manager, viewer].includes(id)) return res.sendStatus(400);
    req.session.regenerate(() => { req.session.userId = id; req.session.save(() => res.sendStatus(204)); });
  });
  const csrf = doubleCsrf({ getSecret: () => "isolated-oauth-http-fixture-csrf", cookieName: "test-oauth-csrf", cookieOptions: { secure: false, sameSite: "lax", httpOnly: true, path: "/" }, getTokenFromRequest: (req) => req.headers["x-csrf-token"] });
  app.get("/api/csrf-token", (req, res) => res.json({ csrfToken: csrf.generateToken(req, res) }));
  app.use("/api", createCsrfExemptMiddleware(csrf.doubleCsrfProtection, { allowPath: isOperatorBearerCsrfExemptRequest }));
  app.use("/api", guardOperatorCredentials);
  app.use(createMcpRemoteRouter());
  app.use(require("../../apps/api/routes/operator"));
  app.get("/api/session", (_req, res) => res.json({ ok: true }));
  app.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.code === "EBADCSRFTOKEN" ? "csrf_required" : "fixture_error" }));
  return app;
}

async function authorize({ registeredClient = null, userId = manager, renewals = false, agentHealth = false, inventoryUpdate = false, contactCreate = false, webhookCreate = false, groupCreate = false, memberInvite = false, issuance = false, lifetimeDays = 30, noExpiry = false, decide = true } = {}) {
  const registered = registeredClient || await oauth.registerClient({ client_name: "HTTP qualification client", redirect_uris: ["http://127.0.0.1:4567/callback"], grant_types: ["authorization_code", "refresh_token"] });
  ids.push(registered.clientId);
  const verifier = crypto.randomBytes(32).toString("base64url"), challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const browser = request.agent(server);
  const started = await browser.get(OAUTH_PATH + "/authorize").query({ client_id: registered.clientId, redirect_uri: registered.redirect_uris[0], response_type: "code", code_challenge_method: "S256", code_challenge: challenge, scope: "mcp:connect", state: "client-state", resource: origin + MCP_PATH });
  assert.equal(started.status, 303);
  const requestId = new URL(started.headers.location).searchParams.get("request");
  await browser.post("/test/sign-in").send({ userId }).expect(204);
  const details = await browser.get(OAUTH_PATH + "/requests/" + requestId).expect(200);
  const csrf = await browser.get("/api/csrf-token").expect(200);
  const result = { registered, browser, requestId, verifier, details: details.body, csrf: csrf.body.csrfToken };
  if (decide) {
    const decided = await browser.post(`${OAUTH_PATH}/requests/${requestId}/decision`).set("X-CSRF-Token", result.csrf).send({ decision: "approve", workspaceId, lifetimeDays: noExpiry ? null : lifetimeDays, noExpiry, renewals, agentHealth, inventoryUpdate, contactCreate, webhookCreate, groupCreate, memberInvite, issuance }).expect(200);
    result.callback = new URL(decided.body.redirectUrl);
    result.code = result.callback.searchParams.get("code");
  }
  return result;
}
async function tokenFor(flow, patch = {}) {
  return request(server).post(OAUTH_PATH + "/token").type("form").send({ grant_type: "authorization_code", code: flow.code, code_verifier: flow.verifier, client_id: flow.registered.clientId, redirect_uri: flow.registered.redirect_uris[0], resource: origin + MCP_PATH, ...patch });
}
const refresh = (flow, token, patch = {}) => request(server).post(OAUTH_PATH + "/token").type("form").send({ grant_type: "refresh_token", refresh_token: token, client_id: flow.registered.clientId, resource: origin + MCP_PATH, ...patch });

describe("remote MCP OAuth on PostgreSQL", { concurrency: false }, () => {
  it("exposes issuance only with explicit consent over HTTP", async () => {
    const previousWrites = process.env.MCP_OPERATOR_WRITES_ENABLED;
    process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
    let client;
    try {
      const read = await authorize(), flow = await authorize({ issuance: true });
      const scopes = async (f) => (await pool.query("SELECT c.scopes FROM operator_connections c JOIN operator_oauth_authorizations a ON a.connection_id=c.id WHERE a.id=$1", [f.requestId])).rows[0].scopes;
      assert.ok(!(await scopes(read)).includes("mcp:issue:request"));
      assert.ok((await scopes(flow)).includes("mcp:issue:request"));
      assert.ok(!(await scopes(flow)).includes("mcp:renew:request"));
      const token = await tokenFor(flow);
      client = new Client({ name: "issuance-qualification", version: "1.0.0" });
      await client.connect(new StreamableHTTPClientTransport(new URL(origin + MCP_PATH), { requestInit: { headers: { Authorization: `Bearer ${token.body.access_token}` } } }));
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      assert.ok(names.includes("tt_preview_issuance")); assert.ok(names.includes("tt_request_issuance"));
      assert.ok(!names.includes("tt_request_renew"));
      const agent = (await pool.query("INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status) VALUES($1,$2,'HTTP issuer','0.18.0','1.0.0',$3,$4,'active') RETURNING id",
        [workspaceId, crypto.randomUUID(), "ttagent_" + crypto.randomBytes(8).toString("hex"), crypto.randomBytes(32).toString("hex")])).rows[0];
      await pool.query("UPDATE workspaces SET operator_issuance_enabled=TRUE WHERE id=$1", [workspaceId]);
      const issuance = { agentId: agent.id, commonName: "example.test", sans: ["example.test"], commandRef: "certbot",
        caEndpoint: "https://ca.example.test/directory", dnsZone: "example.test", dnsProvider: "cloudflare", certPath: "/etc/ssl/certs/http-e2e.pem" };
      const preview = await client.callTool({ name: "tt_preview_issuance", arguments: { issuance } });
      assert.notEqual(preview.isError, true, JSON.stringify(preview));
      assert.ok(!JSON.stringify(preview).includes(issuance.certPath));
    } finally {
      await pool.query("UPDATE workspaces SET operator_issuance_enabled=FALSE WHERE id=$1", [workspaceId]);
      if (previousWrites === undefined) delete process.env.MCP_OPERATOR_WRITES_ENABLED; else process.env.MCP_OPERATOR_WRITES_ENABLED = previousWrites;
      if (client) await client.close();
    }
  });
  it("invites an email as viewer through a specifically authorized MCP client", async () => {
    const emailService = require("../../apps/api/services/emailService");
    const oldSend = emailService.sendEmail, oldTemplate = emailService.generateEmailTemplate;
    let sends = 0;
    emailService.sendEmail = async () => { sends++; return { success: true }; };
    emailService.generateEmailTemplate = async () => ({ html: "synthetic", text: "synthetic", useEmbeddedLogo: false });
    const previousWrites = process.env.MCP_OPERATOR_WRITES_ENABLED;
    process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
    let client;
    try {
      const read = await authorize(), flow = await authorize({ memberInvite: true });
      const scopes = async (f) => (await pool.query("SELECT c.scopes FROM operator_connections c JOIN operator_oauth_authorizations a ON a.connection_id=c.id WHERE a.id=$1", [f.requestId])).rows[0].scopes;
      assert.ok(!(await scopes(read)).includes("mcp:members:invite"));
      assert.ok((await scopes(flow)).includes("mcp:members:invite"));
      const token = await tokenFor(flow);
      client = new Client({ name: "invite-qualification", version: "1.0.0" });
      await client.connect(new StreamableHTTPClientTransport(new URL(origin + MCP_PATH), { requestInit: { headers: { Authorization: `Bearer ${token.body.access_token}` } } }));
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      assert.ok(names.includes("tt_preview_member_invite")); assert.ok(names.includes("tt_invite_member"));
      assert.ok(!names.includes("tt_create_contact"));
      const email = "mcp-invite-" + crypto.randomUUID() + "@example.test";
      const preview = await client.callTool({ name: "tt_preview_member_invite", arguments: { invite: { email } } });
      assert.notEqual(preview.isError, true, JSON.stringify(preview));
      assert.equal(preview.structuredContent.effect.role, "viewer");
      const body = { planId: preview.structuredContent.planId, planHash: preview.structuredContent.planHash, requestId: crypto.randomUUID() };
      const result = await client.callTool({ name: "tt_invite_member", arguments: body });
      assert.notEqual(result.isError, true, JSON.stringify(result));
      assert.equal(result.structuredContent.emailStatus, "sent");
      assert.ok(!JSON.stringify(result).includes("token"));
      const replay = await client.callTool({ name: "tt_invite_member", arguments: body });
      assert.equal(replay.structuredContent.replayed, true); assert.equal(sends, 1);
    } finally {
      if (previousWrites === undefined) delete process.env.MCP_OPERATOR_WRITES_ENABLED;
      else process.env.MCP_OPERATOR_WRITES_ENABLED = previousWrites;
      emailService.sendEmail = oldSend; emailService.generateEmailTemplate = oldTemplate;
      if (client) await client.close();
    }
  });
  it("creates a reviewed contact group through a specifically authorized MCP client", async () => {
    const read = await authorize(), flow = await authorize({ groupCreate: true });
    const scopes = async (f) => (await pool.query("SELECT c.scopes FROM operator_connections c JOIN operator_oauth_authorizations a ON a.connection_id=c.id WHERE a.id=$1", [f.requestId])).rows[0].scopes;
    assert.ok(!(await scopes(read)).includes("mcp:groups:create"));
    assert.ok((await scopes(flow)).includes("mcp:groups:create"));
    const token = await tokenFor(flow), client = new Client({ name: "group-qualification", version: "1.0.0" });
    const previousWrites = process.env.MCP_OPERATOR_WRITES_ENABLED;
    const originalSettings = await pool.query("SELECT contact_groups FROM workspace_settings WHERE workspace_id=$1", [workspaceId]);
    let contactId;
    process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
    try {
      contactId = (await pool.query("INSERT INTO workspace_contacts(workspace_id,first_name,last_name,details,created_by) VALUES($1,'MCP','Group',$2::jsonb,$3) RETURNING id", [workspaceId, JSON.stringify({ email: "group@example.test" }), manager])).rows[0].id;
      await client.connect(new StreamableHTTPClientTransport(new URL(origin + MCP_PATH), { requestInit: { headers: { Authorization: `Bearer ${token.body.access_token}` } } }));
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      assert.ok(names.includes("tt_list_group_sources")); assert.ok(names.includes("tt_create_contact_group"));
      assert.ok(!names.includes("tt_create_contact"));
      const sources = await client.callTool({ name: "tt_list_group_sources", arguments: {} });
      assert.notEqual(sources.isError, true, JSON.stringify(sources));
      assert.ok(sources.structuredContent.items.some((item) => item.id === contactId));
      assert.ok(!JSON.stringify(sources).includes("group@example.test"));
      const preview = await client.callTool({ name: "tt_preview_contact_group", arguments: { group: { name: "MCP group", emailContactIds: [contactId], weeklyDigest: { email: true } } } });
      assert.notEqual(preview.isError, true, JSON.stringify(preview));
      const created = await client.callTool({ name: "tt_create_contact_group", arguments: { planId: preview.structuredContent.planId, planHash: preview.structuredContent.planHash, requestId: crypto.randomUUID() } });
      assert.notEqual(created.isError, true, JSON.stringify(created));
      assert.equal(created.structuredContent.state, "succeeded");
    } finally {
      if (previousWrites === undefined) delete process.env.MCP_OPERATOR_WRITES_ENABLED;
      else process.env.MCP_OPERATOR_WRITES_ENABLED = previousWrites;
      if (originalSettings.rowCount) await pool.query("UPDATE workspace_settings SET contact_groups=$2::jsonb WHERE workspace_id=$1", [workspaceId, originalSettings.rows[0].contact_groups === null ? null : JSON.stringify(originalSettings.rows[0].contact_groups)]);
      else await pool.query("DELETE FROM workspace_settings WHERE workspace_id=$1", [workspaceId]);
      if (contactId) await pool.query("DELETE FROM workspace_contacts WHERE id=$1", [contactId]);
      await client.close();
    }
  });
  it("offers and executes webhook creation only after explicit consent", async () => {
    const read = await authorize(), flow = await authorize({ webhookCreate: true });
    const scopes = async (f) => (await pool.query("SELECT c.scopes FROM operator_connections c JOIN operator_oauth_authorizations a ON a.connection_id=c.id WHERE a.id=$1", [f.requestId])).rows[0].scopes;
    assert.ok(!(await scopes(read)).includes("mcp:webhooks:create"));
    assert.ok((await scopes(flow)).includes("mcp:webhooks:create"));
    const token = await tokenFor(flow), client = new Client({ name: "webhook-qualification", version: "1.0.0" });
    const originalSettings = await pool.query("SELECT webhook_urls FROM workspace_settings WHERE workspace_id=$1", [workspaceId]);
    const previousWrites = process.env.MCP_OPERATOR_WRITES_ENABLED;
    process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(origin + MCP_PATH), { requestInit: { headers: { Authorization: `Bearer ${token.body.access_token}` } } }));
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      assert.ok(names.includes("tt_preview_webhook_create"));
      assert.ok(names.includes("tt_create_webhook"));
      assert.ok(!names.includes("tt_create_contact"));
      const url = "https://events.pagerduty.com/v2/enqueue", routingKey = "synthetic-routing-" + crypto.randomUUID();
      const preview = await client.callTool({ name: "tt_preview_webhook_create", arguments: { webhook: { name: "Example", url, kind: "pagerduty", routingKey } } });
      assert.notEqual(preview.isError, true, JSON.stringify(preview));
      assert.ok(!JSON.stringify(preview).includes(url));
      assert.ok(!JSON.stringify(preview).includes(routingKey));
      const created = await client.callTool({ name: "tt_create_webhook", arguments: { planId: preview.structuredContent.planId, planHash: preview.structuredContent.planHash, requestId: crypto.randomUUID(), url, routingKey } });
      assert.notEqual(created.isError, true, JSON.stringify(created));
      assert.ok(!JSON.stringify(created).includes(url));
      assert.ok(!JSON.stringify(created).includes(routingKey));
    } finally {
      if (previousWrites === undefined) delete process.env.MCP_OPERATOR_WRITES_ENABLED;
      else process.env.MCP_OPERATOR_WRITES_ENABLED = previousWrites;
      if (originalSettings.rowCount) await pool.query("UPDATE workspace_settings SET webhook_urls=$2::jsonb WHERE workspace_id=$1", [workspaceId, originalSettings.rows[0].webhook_urls === null ? null : JSON.stringify(originalSettings.rows[0].webhook_urls)]);
      else await pool.query("DELETE FROM workspace_settings WHERE workspace_id=$1", [workspaceId]);
      await client.close();
    }
  });
  it("offers contact creation only with explicit consent", async () => {
    const read = await authorize(), flow = await authorize({ contactCreate: true });
    const scopes = async (f) => (await pool.query("SELECT c.scopes FROM operator_connections c JOIN operator_oauth_authorizations a ON a.connection_id=c.id WHERE a.id=$1", [f.requestId])).rows[0].scopes;
    assert.ok(!(await scopes(read)).includes("mcp:contacts:create"));
    assert.ok((await scopes(flow)).includes("mcp:contacts:create"));
    const token = await tokenFor(flow), client = new Client({ name: "contact-qualification", version: "1.0.0" });
    const previousWrites = process.env.MCP_OPERATOR_WRITES_ENABLED;
    const verificationKeys = ["TT_DEPLOYMENT", "RECIPIENT_VERIFICATION_MODE", "RECIPIENT_VERIFICATION_CLOUD_SHADOW", "RECIPIENT_FINGERPRINT_SECRET"];
    const savedVerification = Object.fromEntries(verificationKeys.map((key) => [key, process.env[key]]));
    process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
    process.env.TT_DEPLOYMENT = "cloud";
    process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
    process.env.RECIPIENT_FINGERPRINT_SECRET = "synthetic-mcp-oauth-verification-secret";
    delete process.env.RECIPIENT_VERIFICATION_CLOUD_SHADOW;
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(origin + MCP_PATH), { requestInit: { headers: { Authorization: `Bearer ${token.body.access_token}` } } }));
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      assert.ok(names.includes("tt_preview_contact_create"));
      assert.ok(names.includes("tt_create_contact"));
      assert.ok(!names.includes("tt_import_inventory"));
      const preview = await client.callTool({ name: "tt_preview_contact_create", arguments: { contact: { firstName: "MCP", lastName: "Test", email: "mcp@example.test" } } });
      assert.notEqual(preview.isError, true, JSON.stringify(preview));
      const submitted = await client.callTool({ name: "tt_create_contact", arguments: { planId: preview.structuredContent.planId, planHash: preview.structuredContent.planHash, requestId: crypto.randomUUID() } });
      assert.notEqual(submitted.isError, true, JSON.stringify(submitted));
      assert.equal(submitted.structuredContent.state, "succeeded");
      assert.deepEqual(submitted.structuredContent.verification, { mode: "enforce", status: "available", email: "confirmation_required", whatsapp: null, invitationSentByCreation: false });
    } finally {
      if (previousWrites === undefined) delete process.env.MCP_OPERATOR_WRITES_ENABLED;
      else process.env.MCP_OPERATOR_WRITES_ENABLED = previousWrites;
      for (const key of verificationKeys) {
        if (savedVerification[key] === undefined) delete process.env[key];
        else process.env[key] = savedVerification[key];
      }
      await client.close();
    }
  });
  it("grants inventory updates only after explicit manager consent", async () => {
    const readOnly = await authorize();
    const explicit = await authorize({ inventoryUpdate: true });
    const scopes = async (flow) => (await pool.query("SELECT c.scopes FROM operator_connections c JOIN operator_oauth_authorizations a ON a.connection_id=c.id WHERE a.id=$1", [flow.requestId])).rows[0].scopes;
    assert.ok(!(await scopes(readOnly)).includes("mcp:inventory:update"));
    assert.ok((await scopes(explicit)).includes("mcp:inventory:update"));
  });
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_mcp_test$/, "Use only a disposable *_mcp_test database");
    assert.equal((await pool.query("SELECT current_database() AS db")).rows[0].db, process.env.DB_NAME);
    owner = await user("OAuth owner"); manager = await user("OAuth manager"); viewer = await user("OAuth viewer"); workspaceId = crypto.randomUUID();
    await pool.query("INSERT INTO workspaces(id,name,created_by) VALUES($1,'OAuth test workspace',$2)", [workspaceId, owner]);
    await pool.query("INSERT INTO workspace_memberships(user_id,workspace_id,role) VALUES($1,$2,'workspace_manager'),($3,$2,'viewer')", [manager, workspaceId, viewer]);
    process.env.MCP_OPERATOR_INTERFACE_ENABLED = "true"; process.env.MCP_OPERATOR_REMOTE_ENABLED = "true"; process.env.CERTOPS_ENABLED = "true";
    server = appFixture().listen(0, "127.0.0.1");
    await new Promise((resolve) => server.once("listening", resolve));
    origin = `http://127.0.0.1:${server.address().port}`;
    process.env.MCP_PUBLIC_URL = origin + MCP_PATH; process.env.APP_URL = origin; process.env.API_URL = origin;
  });
  after(async () => {
    try {
      const created = await connections.listConnections({ workspaceId });
      for (const connection of created) await connections.revokeConnection({ workspaceId, connectionId: connection.id, revokedBy: owner });
      // Keep immutable audit subjects and their fixtures in this disposable DB.
    } finally {
      await new Promise((resolve) => server.close(resolve));
      await pool.end();
    }
  });

  it("challenges an unauthenticated MCP POST and advertises OAuth discovery", async () => {
    const challenged = await request(server).post(MCP_PATH).send({ jsonrpc: "2.0", id: 1, method: "initialize" }).expect(401);
    assert.match(challenged.headers["www-authenticate"], /resource_metadata=/);
    const metadata = await request(server).get("/.well-known/oauth-protected-resource" + MCP_PATH).expect(200);
    assert.equal(metadata.body.resource, origin + MCP_PATH);
    const as = await request(server).get("/.well-known/oauth-authorization-server").expect(200);
    assert.deepEqual(as.body.code_challenge_methods_supported, ["S256"]);
    assert.equal(as.body.authorization_response_iss_parameter_supported, true);
    assert.equal(as.body.client_id_metadata_document_supported, false);
  });

  it("completes dynamic registration, consent, token exchange and refresh over HTTP", async () => {
    const registration = await request(server).post(OAUTH_PATH + "/register").send({ client_name: "Dynamic HTTP client", redirect_uris: ["http://127.0.0.1:4567/callback"], grant_types: ["authorization_code", "refresh_token"] }).expect(201);
    const flow = await authorize({ registeredClient: { ...registration.body, clientId: registration.body.client_id } });
    const issued = await tokenFor(flow);
    assert.equal(issued.status, 200);
    assert.equal(issued.body.scope, "mcp:connect");
    assert.equal((await oauth.authenticateAccess({ rawCredential: issued.body.access_token })).valid, true);
    const rotated = await refresh(flow, issued.body.refresh_token).expect(200);
    assert.notEqual(rotated.body.refresh_token, issued.body.refresh_token);
  });

  it("preserves access and refresh for an existing URL-client grant while refusing new authorization", async () => {
    const flow = await authorize();
    const issued = await tokenFor(flow);
    assert.equal(issued.status, 200);
    const clientId = `https://legacy.example.test/${crypto.randomUUID()}.json`;
    await pool.query("INSERT INTO operator_oauth_clients(client_id,metadata,source,expires_at) VALUES($1,$2::jsonb,'metadata',NOW()+INTERVAL '1 day')", [clientId, JSON.stringify({ redirect_uris: flow.registered.redirect_uris })]);
    await pool.query("UPDATE operator_oauth_grants SET client_id=$1 WHERE client_id=$2", [clientId, flow.registered.clientId]);
    assert.equal((await oauth.authenticateAccess({ rawCredential: issued.body.access_token })).valid, true);
    const rotated = await refresh(flow, issued.body.refresh_token, { client_id: clientId }).expect(200);
    assert.equal((await oauth.authenticateAccess({ rawCredential: rotated.body.access_token })).valid, true);
    await assert.rejects(oauth.findClient(clientId), (err) => err.oauthCode === "invalid_client");
  });

  it("rejects URL client IDs even when metadata was previously cached", async () => {
    const clientId = `https://metadata.example.test/${crypto.randomUUID()}.json`;
    await pool.query("INSERT INTO operator_oauth_clients(client_id,metadata,source,expires_at) VALUES($1,$2::jsonb,'metadata',NOW()+INTERVAL '1 day') ON CONFLICT(client_id) DO UPDATE SET source='metadata', metadata=EXCLUDED.metadata", [clientId, JSON.stringify({ redirect_uris: ["https://metadata.example.test/callback"] })]);
    try {
      await assert.rejects(oauth.findClient(clientId), (err) => err.oauthCode === "invalid_client");
    } finally {
      await pool.query("DELETE FROM operator_oauth_clients WHERE client_id=$1", [clientId]);
    }
  });

  it("bounds unfinished browser authorizations before they can evict sign-in cookies", async () => {
    const registered = await oauth.registerClient({ redirect_uris: ["http://127.0.0.1:4567/callback"] });
    const browser = request.agent(server);
    const params = { client_id: registered.clientId, redirect_uri: registered.redirect_uris[0], response_type: "code", code_challenge_method: "S256", code_challenge: crypto.randomBytes(32).toString("base64url"), resource: origin + MCP_PATH };
    for (let index = 0; index < 8; index++) await browser.get(OAUTH_PATH + "/authorize").query(params).expect(303);
    const refused = await browser.get(OAUTH_PATH + "/authorize").query(params).expect(429);
    assert.equal(refused.body.error, "temporarily_unavailable");
    assert.equal(refused.headers["set-cookie"], undefined);
    assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM operator_oauth_authorizations WHERE client_id=$1", [registered.clientId])).rows[0].count, 8);
  });

  it("survives session regeneration and stores only code/token/nonce hashes", async () => {
    const flow = await authorize();
    assert.equal(flow.callback.searchParams.get("state"), "client-state");
    assert.equal(flow.callback.searchParams.get("iss"), origin);
    const result = await tokenFor(flow); assert.equal(result.status, 200);
    assert.equal(result.body.scope, "mcp:connect"); assert.equal(result.body.expires_in, 900);
    const row = (await pool.query("SELECT * FROM operator_oauth_authorizations WHERE id=$1", [flow.requestId])).rows[0];
    assert.equal(row.code_hash, sha256Hex(flow.code));
    const stored = JSON.stringify((await pool.query("SELECT * FROM operator_oauth_tokens WHERE grant_id=(SELECT id FROM operator_oauth_grants WHERE connection_id=$1)", [row.connection_id])).rows);
    for (const raw of [flow.code, result.body.access_token, result.body.refresh_token]) assert.equal(stored.includes(raw), false);
    const authenticated = await oauth.authenticateAccess({ rawCredential: result.body.access_token });
    assert.equal(authenticated.valid, true); assert.equal(authenticated.connection.workspaceId, workspaceId); assert.equal(authenticated.authority.effectiveRole, "viewer");
    assert.equal(authenticated.authority.scopes.includes("mcp:renew:request"), false);
  });

  it("supports one-year consent at the database cap", async () => {
    const flow = await authorize({ lifetimeDays: 365 });
    const result = await tokenFor(flow);
    assert.equal(result.status, 200);
    assert.equal(result.body.expires_in, 900);
    const authenticated = await oauth.authenticateAccess({ rawCredential: result.body.access_token });
    const remaining = Date.parse(authenticated.connection.expiresAt) - Date.now();
    assert.ok(remaining > 364.9 * 86400000 && remaining <= 365 * 86400000);
  });

  it("keeps non-expiring consent behind short-lived access and bounded rotating refresh tokens", async () => {
    const flow = await authorize({ noExpiry: true });
    const result = await tokenFor(flow);
    assert.equal(result.status, 200);
    assert.equal(result.body.expires_in, 900);
    const authenticated = await oauth.authenticateAccess({ rawCredential: result.body.access_token });
    assert.equal(authenticated.valid, true);
    assert.equal(authenticated.connection.expiresAt, null);
    assert.equal((await oauth.authenticateAccess({ rawCredential: result.body.access_token, now: new Date(Date.now() + 901000) })).valid, false);
    const stored = (await pool.query("SELECT t.expires_at,g.expires_at AS grant_expires_at FROM operator_oauth_tokens t JOIN operator_oauth_grants g ON g.id=t.grant_id WHERE t.credential_hash=$1", [sha256Hex(result.body.refresh_token)])).rows[0];
    assert.equal(stored.grant_expires_at, null);
    const refreshLifetime = new Date(stored.expires_at).getTime() - Date.now();
    assert.ok(refreshLifetime > 89.9 * 86400000 && refreshLifetime <= oauth.REFRESH_SECONDS * 1000);
    const rotated = await refresh(flow, result.body.refresh_token).expect(200);
    assert.notEqual(rotated.body.refresh_token, result.body.refresh_token);
    await refresh(flow, result.body.refresh_token).expect(400);
    assert.equal((await oauth.authenticateAccess({ rawCredential: rotated.body.access_token })).valid, false);
  });

  it("keeps long-lived authorization usable after the old generation ceiling and integer saturation", async () => {
    const flow = await authorize({ noExpiry: true });
    const grantId = (await pool.query("SELECT id FROM operator_oauth_grants WHERE connection_id=(SELECT connection_id FROM operator_oauth_authorizations WHERE id=$1)", [flow.requestId])).rows[0].id;
    await pool.query("UPDATE operator_oauth_grants SET generation_count=10000 WHERE id=$1", [grantId]);
    const issued = await tokenFor(flow);
    assert.equal(issued.status, 200);
    assert.equal((await pool.query("SELECT generation_count FROM operator_oauth_grants WHERE id=$1", [grantId])).rows[0].generation_count, 10001);
    await pool.query("UPDATE operator_oauth_grants SET generation_count=2147483647 WHERE id=$1", [grantId]);
    await refresh(flow, issued.body.refresh_token).expect(200);
    assert.equal((await pool.query("SELECT generation_count FROM operator_oauth_grants WHERE id=$1", [grantId])).rows[0].generation_count, 2147483647);
  });

  it("bounds retained token rows without spending the usable refresh token when storage is full", async () => {
    const flow = await authorize({ noExpiry: true });
    const issued = await tokenFor(flow);
    assert.equal(issued.status, 200);
    const grantId = (await pool.query("SELECT id FROM operator_oauth_grants WHERE connection_id=(SELECT connection_id FROM operator_oauth_authorizations WHERE id=$1)", [flow.requestId])).rows[0].id;
    await pool.query(`INSERT INTO operator_oauth_tokens(lookup_prefix,credential_hash,grant_id,kind,expires_at)
      SELECT 'budget:'||$1::text||':'||n,md5($1::text)||md5(n::text),$1::uuid,'refresh',NOW()+INTERVAL '90 days' FROM generate_series(1,20000) AS n`, [grantId]);
    await refresh(flow, issued.body.refresh_token).expect(429);
    const unchanged = (await pool.query("SELECT used_at FROM operator_oauth_tokens WHERE credential_hash=$1", [sha256Hex(issued.body.refresh_token)])).rows[0];
    assert.equal(unchanged.used_at, null);
    await pool.query("UPDATE operator_oauth_tokens SET expires_at=NOW()-INTERVAL '2 days' WHERE grant_id=$1 AND lookup_prefix LIKE 'budget:%'", [grantId]);
    await refresh(flow, issued.body.refresh_token).expect(200);
    assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM operator_oauth_tokens WHERE grant_id=$1 AND lookup_prefix LIKE 'budget:%'", [grantId])).rows[0].count, 0);
  });

  it("counts non-expiring connections toward the per-user connection limit", async () => {
    const flow = await authorize({ decide: false });
    const name = 'non-expiring-quota-' + crypto.randomUUID();
    try {
      await pool.query(`WITH created AS (
        INSERT INTO operator_connections(workspace_id,user_id,name,scopes,role_ceiling,credential_prefix,credential_hash,expires_at)
        SELECT $1,$2,$3,ARRAY['mcp:identity:read'],'viewer','ttopc_'||substr(replace(gen_random_uuid()::text,'-',''),1,16),replace(gen_random_uuid()::text,'-','')||replace(gen_random_uuid()::text,'-',''),NULL FROM generate_series(1,100) RETURNING id
      ) INSERT INTO operator_oauth_grants(id,connection_id,client_id,resource,expires_at)
        SELECT gen_random_uuid(),id,$4,$5,NULL FROM created`, [workspaceId, manager, name, flow.registered.clientId, origin + MCP_PATH]);
      const response = await flow.browser.post(`${OAUTH_PATH}/requests/${flow.requestId}/decision`).set('X-CSRF-Token', flow.csrf).send({ decision: 'approve', workspaceId, noExpiry: true, lifetimeDays: null, renewals: false, agentHealth: false }).expect(409);
      assert.equal(response.body.error, 'connection_limit');
    } finally {
      await pool.query('DELETE FROM operator_connections WHERE workspace_id=$1 AND name=$2', [workspaceId, name]);
    }
  });

  it("serves the actual HTTP MCP SDK with workspace-bound read-only tools", async () => {
    const flow = await authorize(); const result = await tokenFor(flow);
    assert.equal(result.status, 200);
    const client = new Client({ name: "tokentimer-http-qualification", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(origin + MCP_PATH), { requestInit: { headers: { Authorization: `Bearer ${result.body.access_token}` } } });
    try {
      await client.connect(transport);
      const catalog = await client.listTools();
      assert.equal(catalog.tools.length, 11);
      assert.equal(catalog.tools.some((tool) => tool.name === "tt_get_agent_health"), false);
      assert.equal(catalog.tools.some((tool) => tool.name === "tt_request_renew"), false);
      const identity = await client.callTool({ name: "tt_whoami", arguments: {} });
      assert.notEqual(identity.isError, true, "The real SDK tool call must pass schema and API guards");
      assert.equal(identity.structuredContent.workspace.id, workspaceId);
      const certificates = await client.callTool({ name: "tt_list_certificates", arguments: {} });
      assert.notEqual(certificates.isError, true);
    } finally { await client.close(); }
  });

  it("offers updates but not imports or renewal to an update-only remote client", async () => {
    const flow = await authorize({ inventoryUpdate: true });
    const result = await tokenFor(flow);
    assert.equal(result.status, 200);
    const client = new Client({ name: "update-only-qualification", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(origin + MCP_PATH), { requestInit: { headers: { Authorization: `Bearer ${result.body.access_token}` } } });
    try {
      await client.connect(transport);
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      assert.ok(names.includes("tt_preview_inventory_update"));
      assert.ok(names.includes("tt_update_inventory"));
      assert.ok(!names.includes("tt_import_inventory"));
      assert.ok(!names.includes("tt_request_renew"));
    } finally { await client.close(); }
  });

  it("requires browser nonce, session identity and CSRF for consent", async () => {
    const flow = await authorize({ decide: false });
    const other = request.agent(server); await other.post("/test/sign-in").send({ userId: manager }).expect(204);
    await other.get(`${OAUTH_PATH}/requests/${flow.requestId}`).expect(400);
    await flow.browser.post(`${OAUTH_PATH}/requests/${flow.requestId}/decision`).send({ decision: "deny" }).expect(403);
    await flow.browser.post("/test/sign-in").send({ userId: owner }).expect(204);
    const csrf = await flow.browser.get("/api/csrf-token");
    await flow.browser.post(`${OAUTH_PATH}/requests/${flow.requestId}/decision`).set("X-CSRF-Token", csrf.body.csrfToken).send({ decision: "deny" }).expect(403);
  });

  it("completes SDK discovery, public registration, consent, PKCE and automatic refresh", async () => {
    let information, tokens, verifier, authorizationUrl, discovery;
    const provider = {
      redirectUrl: "http://127.0.0.1:4789/callback",
      clientMetadata: { client_name: "SDK sign-in qualification", redirect_uris: ["http://127.0.0.1:4789/callback"], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" },
      state: () => "sdk-qualification-state",
      clientInformation: () => information,
      saveClientInformation: value => { information = value; },
      tokens: () => tokens,
      saveTokens: value => { tokens = value; },
      redirectToAuthorization: value => { authorizationUrl = value; },
      saveCodeVerifier: value => { verifier = value; },
      codeVerifier: () => verifier,
      saveDiscoveryState: value => { discovery = value; },
      discoveryState: () => discovery,
    };
    const endpoint = new URL(origin + MCP_PATH);
    const initial = new Client({ name: "sdk-sign-in", version: "1.0.0" });
    const firstTransport = new StreamableHTTPClientTransport(endpoint, { authProvider: provider });
    await assert.rejects(initial.connect(firstTransport), error => error.name === "UnauthorizedError");
    assert.ok(information.client_id);
    assert.equal(authorizationUrl.origin, origin);
    assert.equal(authorizationUrl.searchParams.get("resource"), endpoint.href);
    assert.equal(authorizationUrl.searchParams.get("code_challenge_method"), "S256");
    const browser = request.agent(server);
    const started = await browser.get(authorizationUrl.pathname + authorizationUrl.search).expect(303);
    const requestId = new URL(started.headers.location).searchParams.get("request");
    await browser.post("/test/sign-in").send({ userId: manager }).expect(204);
    await browser.get(OAUTH_PATH + "/requests/" + requestId).expect(200);
    const csrf = await browser.get("/api/csrf-token");
    const consent = await browser.post(`${OAUTH_PATH}/requests/${requestId}/decision`).set("X-CSRF-Token", csrf.body.csrfToken).send({ decision: "approve", workspaceId, lifetimeDays: 1, renewals: false, agentHealth: false }).expect(200);
    const callback = new URL(consent.body.redirectUrl);
    assert.equal(callback.searchParams.get("state"), "sdk-qualification-state");
    const foreignIssuer = new URLSearchParams(callback.searchParams);
    foreignIssuer.set("iss", "https://other-issuer.example.test");
    await assert.rejects(firstTransport.finishAuth(foreignIssuer), error => /issuer/i.test(error.message));
    await firstTransport.finishAuth(callback.searchParams);
    await initial.close();
    assert.ok(tokens.refresh_token);
    const firstAccess = tokens.access_token, firstRefresh = tokens.refresh_token;
    const client = new Client({ name: "sdk-connected", version: "1.0.0" });
    try {
      await client.connect(new StreamableHTTPClientTransport(endpoint, { authProvider: provider }));
      assert.equal((await client.listTools()).tools.length, 11);
      // A real 401 forces the SDK to redeem the saved refresh token and retry.
      await pool.query("UPDATE operator_oauth_tokens SET expires_at=NOW()-INTERVAL '1 second' WHERE credential_hash=$1", [sha256Hex(firstAccess)]);
      const identity = await client.callTool({ name: "tt_whoami", arguments: {} });
      assert.notEqual(identity.isError, true);
      assert.equal(identity.structuredContent.workspace.id, workspaceId);
      assert.notEqual(tokens.access_token, firstAccess);
      assert.notEqual(tokens.refresh_token, firstRefresh);
      assert.equal((await pool.query("SELECT used_at IS NOT NULL AS used FROM operator_oauth_tokens WHERE credential_hash=$1", [sha256Hex(firstRefresh)])).rows[0].used, true);
    } finally { await client.close(); }
  });

  it("negotiates the legacy Streamable HTTP protocol used by existing MCP clients", async () => {
    const flow = await authorize(); const result = await tokenFor(flow);
    const response = await request(server).post(MCP_PATH).auth(result.body.access_token, { type: "bearer" }).set("Accept", "application/json, text/event-stream").send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "legacy-qualification", version: "1.0.0" } } }).expect(200);
    const payload = response.body?.result ? response.body : JSON.parse(response.text.split(/\r?\n/).find(line => line.startsWith("data: ")).slice(6));
    assert.equal(payload.result.protocolVersion, "2025-06-18");
  });

  it("serializes concurrent refresh attempts and revokes the replayed family", async () => {
    const flow = await authorize(); const first = await tokenFor(flow);
    const attempts = await Promise.all([refresh(flow, first.body.refresh_token), refresh(flow, first.body.refresh_token)]);
    assert.deepEqual(attempts.map(item => item.status).sort(), [200, 400]);
    assert.equal((await oauth.authenticateAccess({ rawCredential: attempts.find(item => item.status === 200).body.access_token })).valid, false);
  });

  it("returns a denial without creating a connection", async () => {
    const flow = await authorize({ decide: false });
    const response = await flow.browser.post(`${OAUTH_PATH}/requests/${flow.requestId}/decision`).set("X-CSRF-Token", flow.csrf).send({ decision: "deny" }).expect(200);
    const callback = new URL(response.body.redirectUrl); assert.equal(callback.searchParams.get("error"), "access_denied"); assert.equal(callback.searchParams.has("code"), false);
    assert.equal((await pool.query("SELECT connection_id FROM operator_oauth_authorizations WHERE id=$1", [flow.requestId])).rows[0].connection_id, null);
  });

  it("rejects wrong client, redirect, verifier and resource without spending the code", async () => {
    const flow = await authorize();
    for (const patch of [{ client_id: "other-client" }, { redirect_uri: "https://evil.example.test/cb" }, { code_verifier: "x".repeat(43) }, { resource: "https://other.example.test/mcp" }]) assert.equal((await tokenFor(flow, patch)).status, 400);
    assert.equal((await tokenFor(flow)).status, 200);
  });

  it("revokes issued authority on matching authorization-code reuse", async () => {
    const flow = await authorize(); const first = await tokenFor(flow); assert.equal(first.status, 200);
    assert.equal((await tokenFor(flow)).status, 400);
    assert.equal((await oauth.authenticateAccess({ rawCredential: first.body.access_token })).valid, false);
  });

  it("rotates refresh tokens, refuses cross-client use and revokes a replayed family", async () => {
    const flow = await authorize(); const first = await tokenFor(flow);
    assert.equal((await refresh(flow, first.body.refresh_token, { client_id: "other-client" })).status, 400);
    const second = await refresh(flow, first.body.refresh_token); assert.equal(second.status, 200);
    assert.equal((await refresh(flow, first.body.refresh_token)).status, 400);
    assert.equal((await oauth.authenticateAccess({ rawCredential: second.body.access_token })).valid, false);
    assert.equal((await refresh(flow, second.body.refresh_token)).status, 400);
  });

  it("allows client revocation without a session and keeps unknown-token responses uniform", async () => {
    const flow = await authorize(); const result = await tokenFor(flow);
    await request(server).post(OAUTH_PATH + "/revoke").type("form").send({ client_id: "other-client", token: result.body.refresh_token }).expect(200);
    assert.equal((await oauth.authenticateAccess({ rawCredential: result.body.access_token })).valid, true);
    await request(server).post(OAUTH_PATH + "/revoke").type("form").send({ client_id: flow.registered.clientId, token: result.body.refresh_token }).expect(200);
    assert.equal((await oauth.authenticateAccess({ rawCredential: result.body.access_token })).valid, false);
    await request(server).post(OAUTH_PATH + "/revoke").type("form").send({ client_id: flow.registered.clientId, token: "unknown" }).expect(200);
  });

  it("invalidates OAuth authority when the owner rotates the connection credential", async () => {
    const flow = await authorize(); const issued = await tokenFor(flow);
    const auth = await oauth.authenticateAccess({ rawCredential: issued.body.access_token });
    const rotated = await connections.rotateCredential({ workspaceId, connectionId: auth.connection.id });
    assert.ok(rotated.plaintextCredential);
    assert.equal((await oauth.authenticateAccess({ rawCredential: issued.body.access_token })).valid, false);
    assert.equal((await refresh(flow, issued.body.refresh_token)).status, 400);
    assert.equal((await connections.authenticateCredential({ rawCredential: rotated.plaintextCredential })).valid, true);
  });

  it("does not expand a read-only connection after promotion or token refresh", async () => {
    const flow = await authorize(); const first = await tokenFor(flow);
    try {
      await pool.query("UPDATE workspace_memberships SET role='admin' WHERE user_id=$1 AND workspace_id=$2", [manager, workspaceId]);
      const second = await refresh(flow, first.body.refresh_token); assert.equal(second.status, 200);
      const auth = await oauth.authenticateAccess({ rawCredential: second.body.access_token });
      assert.equal(auth.authority.effectiveRole, "viewer"); assert.equal(auth.authority.scopes.includes("mcp:renew:request"), false);
    } finally { await pool.query("UPDATE workspace_memberships SET role='workspace_manager' WHERE user_id=$1 AND workspace_id=$2", [manager, workspaceId]); }
  });

  it("refuses viewer renewal consent and cross-workspace grants", async () => {
    const flow = await authorize({ userId: viewer, decide: false });
    const body = { decision: "approve", workspaceId, lifetimeDays: 30, renewals: true, agentHealth: true };
    await flow.browser.post(`${OAUTH_PATH}/requests/${flow.requestId}/decision`).set("X-CSRF-Token", flow.csrf).send(body).expect(403);
    await flow.browser.post(`${OAUTH_PATH}/requests/${flow.requestId}/decision`).set("X-CSRF-Token", flow.csrf).send({ ...body, workspaceId: crypto.randomUUID(), renewals: false, agentHealth: false }).expect(403);
  });

  it("applies demotion and membership removal to existing tokens", async () => {
    const flow = await authorize({ renewals: true }); const result = await tokenFor(flow);
    assert.equal((await oauth.authenticateAccess({ rawCredential: result.body.access_token })).authority.scopes.includes("mcp:renew:request"), true);
    await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE user_id=$1 AND workspace_id=$2", [manager, workspaceId]);
    assert.equal((await oauth.authenticateAccess({ rawCredential: result.body.access_token })).authority.scopes.includes("mcp:renew:request"), false);
    await pool.query("DELETE FROM workspace_memberships WHERE user_id=$1 AND workspace_id=$2", [manager, workspaceId]);
    assert.equal((await oauth.authenticateAccess({ rawCredential: result.body.access_token })).valid, false);
    await pool.query("INSERT INTO workspace_memberships(user_id,workspace_id,role) VALUES($1,$2,'workspace_manager')", [manager, workspaceId]);
  });

  it("refuses expired and foreign-audience access, mixed cookies and general API reuse", async () => {
    const flow = await authorize(); const result = await tokenFor(flow); const token = result.body.access_token;
    await request(server).get("/api/session").auth(token, { type: "bearer" }).expect(403);
    await flow.browser.get(MCP_PATH).auth(token, { type: "bearer" }).expect(401);
    assert.equal((await oauth.authenticateAccess({ rawCredential: token, config: { ...remoteConfig(), resource: "https://other.example.test/mcp" } })).valid, false);
    await pool.query("UPDATE operator_oauth_tokens SET expires_at=NOW()-INTERVAL '1 second' WHERE credential_hash=$1", [sha256Hex(token)]);
    assert.equal((await oauth.authenticateAccess({ rawCredential: token })).valid, false);
  });

  it("rejects Host/Origin rebinding without trusting forwarding headers", async () => {
    await request(server).post(MCP_PATH).set("Host", "evil.example.test").set("X-Forwarded-Host", new URL(origin).host).send({}).expect(403);
    await request(server).post(MCP_PATH).set("Origin", "https://evil.example.test").send({}).expect(403);
  });

  it("isolates allowed MCP browser origins from session consent and caps public bodies", async () => {
    process.env.MCP_ALLOWED_ORIGINS = "https://browser-client.example.test";
    try {
      const metadata = await request(server).get("/.well-known/oauth-authorization-server").set("Origin", "https://browser-client.example.test").expect(200);
      assert.equal(metadata.headers["access-control-allow-origin"], "https://browser-client.example.test");
      assert.equal(metadata.headers["access-control-allow-credentials"], undefined);
      await request(server).get(OAUTH_PATH + "/requests/" + crypto.randomUUID()).set("Origin", "https://browser-client.example.test").expect(403);
      await request(server).post(OAUTH_PATH + "/register").send({ client_name: "x".repeat(17000) }).expect(413);
    } finally { delete process.env.MCP_ALLOWED_ORIGINS; }
  });

  it("keeps local adapter authority independent when remote access is disabled", async () => {
    const flow = await authorize(); const result = await tokenFor(flow);
    const local = await connections.createConnection({ userId: manager, workspaceId, name: "Local adapter", scopes: ["mcp:identity:read"], roleCeiling: "viewer" });
    try {
      process.env.MCP_OPERATOR_REMOTE_ENABLED = "false";
      await request(server).post(MCP_PATH).send({}).expect(404);
      assert.equal((await connections.authenticateCredential({ rawCredential: result.body.access_token })).valid, false);
      assert.equal((await connections.authenticateCredential({ rawCredential: local.plaintextCredential })).valid, true);
    } finally { process.env.MCP_OPERATOR_REMOTE_ENABLED = "true"; }
  });
});
