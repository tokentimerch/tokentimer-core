"use strict";

const { before, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const express = require("../../apps/api/node_modules/express");
const request = require("supertest");
const { pool } = require("../../apps/api/db/database");
const Token = require("../../apps/api/db/models/Token");
const connections = require("../../apps/api/services/operator/connections");
const { guardOperatorCredentials } = require("../../apps/api/middleware/operator-connection-auth");
const { loadTools } = require("../../packages/mcp/src/tools");

if (!/_mcp_test$/.test(process.env.DB_NAME || "")) throw new Error("A disposable _mcp_test database is required");
const run = crypto.randomUUID().replace(/-/g, ""), tools = new Map(loadTools({ includeWrites: true }).map((tool) => [tool.name, tool]));
let app, owner, manager, viewer, workspace, otherWorkspace, managerCredential, viewerCredential, base, otherToken;
let originalSend, originalTemplate;
const flags = ["MCP_OPERATOR_INTERFACE_ENABLED", "MCP_OPERATOR_WRITES_ENABLED"], original = Object.fromEntries(flags.map((key) => [key, process.env[key]]));
const metadata = (name, patch = {}) => ({ name, type: "api_key", category: "key_secret", expiresAt: "2027-12-01", location: "gitlab:manual/" + name, ...patch });
const post = (route, body, credential = managerCredential) => request(app).post("/api/v1/operator/" + route).set("Authorization", "Bearer " + credential).send(body);
const get = (route, credential = viewerCredential) => request(app).get("/api/v1/operator/" + route).set("Authorization", "Bearer " + credential);
async function user(name) {
  return (await pool.query("INSERT INTO users(email,display_name,auth_method,password_hash,email_verified)VALUES($1,$2,'local','x',TRUE)RETURNING id", [name + run + "@example.test", name])).rows[0].id;
}
async function credential(userId, scopes = ["mcp:tokens:read", "mcp:inventory:import"]) {
  return (await connections.createConnection({ workspaceId: workspace, userId, name: "inventory-" + crypto.randomUUID(), scopes, roleCeiling: userId === viewer ? "viewer" : "workspace_manager" })).plaintextCredential;
}
async function seed(name, patch = {}, workspaceId = workspace) {
  return Token.create({ userId: owner, workspaceId, created_by: owner, name, type: "api_key", category: "key_secret", expiration: "2027-12-01", location: "gitlab:manual/" + name, ...patch });
}
async function preview(records, credential_) {
  const response = await post("inventory/preview", { records }, credential_);
  assert.equal(response.status, 200, JSON.stringify(response.body));
  assert.equal(tools.get("tt_preview_inventory_import").validateOutput(response.body), true);
  return response.body;
}
const submit = (plan, requestId = crypto.randomUUID(), credential_) => post("inventory/import", { planId: plan.planId, planHash: plan.planHash, requestId }, credential_);
before(async () => {
  for (const key of flags) process.env[key] = "true";
  owner = await user("owner"); manager = await user("manager"); viewer = await user("viewer");
  workspace = crypto.randomUUID(); otherWorkspace = crypto.randomUUID();
  for (const id of [workspace, otherWorkspace]) await pool.query("INSERT INTO workspaces(id,name,created_by,operator_writes_enabled,certops_require_approval_always)VALUES($1,$2,$3,FALSE,TRUE)", [id, "inventory-" + run, owner]);
  for (const [id, role] of [[owner, "admin"], [manager, "workspace_manager"], [viewer, "viewer"]]) await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role)VALUES($1,$2,$3)", [workspace, id, role]);
  managerCredential = await credential(manager); viewerCredential = await credential(viewer, ["mcp:tokens:read"]);
  base = await seed("deploy-a", { location: "gitlab:projects/1/deploy_tokens/2", source_provider: "gitlab", source_kind: "gitlab-deploy-token", notes: "INVENTORY_PRIVATE_NOTES", source_object_id: "INVENTORY_PRIVATE_OBJECT" });
  await seed("deploy-b", { location: "gitlab:projects/1/deploy_tokens/3" });
  await seed("github", { location: "github:repos/team/project", source_provider: "github" });
  await seed("literal", { location: "gitlab:literal%_name" });
  otherToken = await seed("other-workspace", {}, otherWorkspace);
  const emailService = require("../../apps/api/services/emailService");
  originalSend = emailService.sendEmail; originalTemplate = emailService.generateEmailTemplate;
  emailService.sendEmail = async () => ({ success: true });
  emailService.generateEmailTemplate = async () => ({ html: "synthetic", text: "synthetic", useEmbeddedLogo: false });
  app = express(); app.use(express.json({ limit: "256kb" })); app.use("/api", guardOperatorCredentials);
  app.use((req, _res, next) => { if (req.path === `/api/v1/workspaces/${workspace}/members` && req.get("X-Fixture-Member-Actor") === run) { req.user = { id: manager, email: "manager" + run + "@example.test" }; req.isAuthenticated = () => true; } next(); });
  app.use(require("../../apps/api/routes/operator")); app.use(require("../../apps/api/routes/workspaces"));
});
after(async () => {
  const emailService = require("../../apps/api/services/emailService");
  emailService.sendEmail = originalSend; emailService.generateEmailTemplate = originalTemplate;
  for (const key of flags) if (original[key] === undefined) delete process.env[key]; else process.env[key] = original[key];
  if (workspace) await pool.query("DELETE FROM workspaces WHERE id=ANY($1::uuid[])", [[workspace, otherWorkspace]]);
  // Keep synthetic actors referenced by the immutable audit ledger; the
  // disposable database is removed by its owning qualification/CI runner.
  await pool.end();
});
describe("operator token inventory on PostgreSQL", () => {
  it("invites an email as viewer, sends at most one synthetic notification, and safely retries", async () => {
    const emailService = require("../../apps/api/services/emailService");
    const originalSend = emailService.sendEmail, originalTemplate = emailService.generateEmailTemplate;
    let sends = 0, link = "";
    emailService.sendEmail = async () => { sends++; return { success: true }; };
    emailService.generateEmailTemplate = async (options) => { link = options.buttonUrl; return { html: "synthetic", text: "synthetic", useEmbeddedLogo: false }; };
    try {
      const raw = await credential(manager, ["mcp:members:invite"]), email = "invite-" + crypto.randomUUID() + "@example.test";
      assert.equal((await post("members/preview", { invite: { email } }, viewerCredential)).status, 403);
      const preview = await post("members/preview", { invite: { email } }, raw);
      assert.equal(preview.status, 200, JSON.stringify(preview.body));
      assert.equal(tools.get("tt_preview_member_invite").validateOutput(preview.body), true);
      assert.equal(preview.body.effect.mode, "invite_new_user"); assert.equal(preview.body.effect.role, "viewer");
      const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
      const created = await post("members/invite", body, raw);
      assert.equal(created.status, 200, JSON.stringify(created.body));
      assert.equal(tools.get("tt_invite_member").validateOutput(created.body), true);
      assert.equal(created.body.emailStatus, "sent"); assert.ok(!JSON.stringify(created.body).includes("token"));
      assert.equal(new URL(link).searchParams.has("token"), true);
      const row = (await pool.query("SELECT role FROM workspace_invitations WHERE workspace_id=$1 AND email=$2", [workspace, email])).rows[0];
      assert.equal(row.role, "viewer");
      assert.equal((await post("members/invite", body, raw)).body.replayed, true);
      assert.equal(sends, 1);
    } finally {
      emailService.sendEmail = originalSend; emailService.generateEmailTemplate = originalTemplate;
    }
  });
  it("rejects an invitation when its preview expires or authority is withdrawn", async () => {
    const raw = await credential(manager, ["mcp:members:invite"]);
    const preview = await post("members/preview", { invite: { email: "expired-" + crypto.randomUUID() + "@example.test" } }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
    try {
      await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
      assert.equal((await post("members/invite", body, raw)).status, 403);
    } finally {
      await pool.query("UPDATE workspace_memberships SET role='workspace_manager' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
    }
    await pool.query("UPDATE operator_inventory_plans SET created_at=NOW()-INTERVAL '2 minutes',expires_at=NOW()-INTERVAL '1 second' WHERE id=$1", [preview.body.planId]);
    assert.equal((await post("members/invite", body, raw)).body.code, "OPERATOR_PLAN_EXPIRED");
    const fresh = await post("members/preview", { invite: { email: "revoked-" + crypto.randomUUID() + "@example.test" } }, raw);
    assert.equal(fresh.status, 200, JSON.stringify(fresh.body));
    const auth = await connections.authenticateCredential({ rawCredential: raw });
    await connections.revokeConnection({ workspaceId: workspace, connectionId: auth.connection.id, revokedBy: manager });
    assert.equal((await post("members/invite", { planId: fresh.body.planId, planHash: fresh.body.planHash, requestId: crypto.randomUUID() }, raw)).status, 401);
  });
  it("adds an existing user only as viewer and honors the manual-invite switch", async () => {
    const emailService = require("../../apps/api/services/emailService");
    const originalSend = emailService.sendEmail, originalTemplate = emailService.generateEmailTemplate, oldDisabled = process.env.DISABLE_MANUAL_INVITES;
    emailService.sendEmail = async () => ({ success: true });
    emailService.generateEmailTemplate = async () => ({ html: "synthetic", text: "synthetic", useEmbeddedLogo: false });
    try {
      const target = await user("existing-invite"), email = "existing-invite" + run + "@example.test";
      const raw = await credential(manager, ["mcp:members:invite"]);
      const preview = await post("members/preview", { invite: { email } }, raw);
      assert.equal(preview.status, 200, JSON.stringify(preview.body));
      assert.equal(preview.body.effect.mode, "add_existing_user");
      process.env.DISABLE_MANUAL_INVITES = "true";
      const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
      assert.equal((await post("members/invite", body, raw)).body.code, "MANUAL_INVITES_DISABLED");
      delete process.env.DISABLE_MANUAL_INVITES;
      const created = await post("members/invite", body, raw);
      assert.equal(created.status, 200, JSON.stringify(created.body));
      assert.equal((await pool.query("SELECT role FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2", [workspace, target])).rows[0].role, "viewer");
      assert.equal((await post("members/preview", { invite: { email } }, raw)).body.code, "OPERATOR_INTENT_STALE");
      assert.equal((await post("members/preview", { invite: { email, role: "admin" } }, raw)).status, 400);
    } finally {
      emailService.sendEmail = originalSend; emailService.generateEmailTemplate = originalTemplate;
      if (oldDisabled === undefined) delete process.env.DISABLE_MANUAL_INVITES; else process.env.DISABLE_MANUAL_INVITES = oldDisabled;
    }
  });
  it("shares the last member slot between an ordinary invitation and an MCP invitation", async () => {
    const limits = require("../../apps/api/services/planLimits").MEMBER_LIMITS;
    const plan = String((await pool.query("SELECT plan FROM workspaces WHERE id=$1", [workspace])).rows[0].plan || "oss").toLowerCase();
    const originalLimit = limits[plan], control = await pool.connect();
    const ordinaryEmail = "ordinary-" + crypto.randomUUID() + "@example.test", assistantEmail = "assistant-" + crypto.randomUUID() + "@example.test";
    let ordinary, assistant;
    try {
      const counts = (await pool.query(`SELECT
        (SELECT COUNT(DISTINCT wm.user_id)::int FROM workspaces w JOIN workspace_memberships wm ON wm.workspace_id=w.id WHERE w.created_by=$1) AS members,
        (SELECT COUNT(DISTINCT LOWER(wi.email))::int FROM workspaces w JOIN workspace_invitations wi ON wi.workspace_id=w.id WHERE w.created_by=$1 AND wi.accepted_at IS NULL) AS pending`, [owner])).rows[0];
      limits[plan] = counts.members + counts.pending + 1;
      const raw = await credential(manager, ["mcp:members:invite"]);
      const preview = await post("members/preview", { invite: { email: assistantEmail } }, raw);
      assert.equal(preview.status, 200, JSON.stringify(preview.body));
      await control.query("BEGIN");
      const controlPid = (await control.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      await control.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [JSON.stringify(["operator-member-admission", String(owner)])]);
      ordinary = request(app).post(`/api/v1/workspaces/${workspace}/members`).set("X-Fixture-Member-Actor", run).send({ email: ordinaryEmail, role: "viewer" }).then((response) => response);
      assistant = post("members/invite", { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() }, raw).then((response) => response);
      let blocked = 0;
      for (let n = 0; n < 100 && blocked < 2; n++) {
        blocked = (await pool.query("SELECT COUNT(*)::int AS count FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))", [controlPid])).rows[0].count;
        if (blocked < 2) await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.equal(blocked, 2, "both invitation paths wait on the same organization admission lock");
      await control.query("COMMIT");
      const responses = await Promise.all([ordinary, assistant]);
      assert.ok((responses[0].status === 201 && responses[1].status === 402) || (responses[0].status === 409 && responses[1].status === 200), JSON.stringify(responses.map((response) => ({ status: response.status, body: response.body }))));
      assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM workspace_invitations WHERE workspace_id=$1 AND email=ANY($2::text[])", [workspace, [ordinaryEmail, assistantEmail]])).rows[0].count, 1);
    } finally {
      await control.query("ROLLBACK").catch(() => {}); control.release();
      if (ordinary) await ordinary; if (assistant) await assistant;
      if (originalLimit === undefined) delete limits[plan]; else limits[plan] = originalLimit;
      await pool.query("DELETE FROM workspace_invitations WHERE workspace_id=$1 AND email=ANY($2::text[])", [workspace, [ordinaryEmail, assistantEmail]]);
    }
  });
  it("locks an existing invitee before the workspace on both invitation paths", async () => {
    const raw = await credential(manager, ["mcp:members:invite"]);
    for (const mode of ["assistant", "ordinary"]) {
      const target = await user("order-" + mode), email = "order-" + mode + run + "@example.test";
      const preview = mode === "assistant" ? await post("members/preview", { invite: { email } }, raw) : null;
      if (preview) assert.equal(preview.status, 200, JSON.stringify(preview.body));
      const control = await pool.connect(); let pending;
      try {
        await control.query("BEGIN"); await control.query("SET LOCAL lock_timeout='1500ms'");
        const controlPid = (await control.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
        await control.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [target]);
        pending = mode === "assistant"
          ? post("members/invite", { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() }, raw).then((response) => response)
          : request(app).post(`/api/v1/workspaces/${workspace}/members`).set("X-Fixture-Member-Actor", run).send({ email, role: "viewer" }).then((response) => response);
        let waiting = false;
        for (let n = 0; n < 100 && !waiting; n++) {
          waiting = (await pool.query("SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query ILIKE '%FROM users%KEY SHARE%'", [controlPid])).rowCount > 0;
          if (!waiting) await new Promise((resolve) => setTimeout(resolve, 20));
        }
        assert.equal(waiting, true, mode + " waits on the user row");
        await control.query("SELECT id FROM workspaces WHERE id=$1 FOR UPDATE", [workspace]);
        await control.query("COMMIT");
        assert.equal((await pending).status, mode === "assistant" ? 200 : 201);
      } finally {
        await control.query("ROLLBACK").catch(() => {}); control.release();
        if (pending) await pending;
        await pool.query("DELETE FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2", [workspace, target]);
      }
    }
  });
  it("previews and creates a contact group with recipients, webhooks and weekly digests", async () => {
    const raw = await credential(manager, ["mcp:groups:create"]);
    const contact = (await pool.query("INSERT INTO workspace_contacts(workspace_id,first_name,last_name,phone_e164,details,created_by) VALUES($1,'Ada','Group',$2,$3::jsonb,$4) RETURNING id", [workspace, "+491" + String(crypto.randomInt(100000000, 999999999)), JSON.stringify({ email: "group@example.test" }), manager])).rows[0];
    const webhookName = "Group webhook " + crypto.randomUUID();
    await pool.query("INSERT INTO workspace_settings(workspace_id,webhook_urls) VALUES($1,$2::jsonb) ON CONFLICT(workspace_id) DO UPDATE SET webhook_urls=COALESCE(workspace_settings.webhook_urls,'[]'::jsonb)||EXCLUDED.webhook_urls", [workspace, JSON.stringify([{ name: webhookName, url: "https://example.test/private-webhook" }])]);
    const sources = await get("groups/sources?limit=50", raw);
    assert.equal(sources.status, 200, JSON.stringify(sources.body));
    assert.equal(tools.get("tt_list_group_sources").validateOutput(sources.body), true);
    assert.ok(sources.body.items.some((item) => item.id === contact.id && item.hasEmail && item.hasWhatsapp));
    assert.ok(sources.body.items.some((item) => item.kind === "webhook" && item.name.value === webhookName));
    assert.ok(!JSON.stringify(sources.body).includes("group@example.test"));
    assert.ok(!JSON.stringify(sources.body).includes("private-webhook"));
    const group = { name: "Ops " + crypto.randomUUID(), emailContactIds: [contact.id], whatsappContactIds: [contact.id], webhookNames: [webhookName], weeklyDigest: { email: true, whatsapp: true, webhooks: true } };
    assert.equal((await post("groups/preview", { group }, viewerCredential)).status, 403);
    const preview = await post("groups/preview", { group }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    assert.equal(tools.get("tt_preview_contact_group").validateOutput(preview.body), true);
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
    const result = await post("groups/create", body, raw);
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(tools.get("tt_create_contact_group").validateOutput(result.body), true);
    assert.equal((await post("groups/create", body, raw)).body.replayed, true);
    const saved = (await pool.query("SELECT contact_groups FROM workspace_settings WHERE workspace_id=$1", [workspace])).rows[0].contact_groups.find((item) => item.id === result.body.groupId);
    assert.deepEqual(saved.email_contact_ids, [contact.id]); assert.deepEqual(saved.whatsapp_contact_ids, [contact.id]);
    assert.deepEqual(saved.webhook_names, [webhookName]);
    assert.equal(saved.weekly_digest_email, true); assert.equal(saved.weekly_digest_whatsapp, true); assert.equal(saved.weekly_digest_webhooks, true);
  });
  it("refuses foreign or changed contacts in a group preview", async () => {
    const raw = await credential(manager, ["mcp:groups:create"]);
    const foreign = (await pool.query("INSERT INTO workspace_contacts(workspace_id,first_name,last_name,details,created_by) VALUES($1,'Foreign','User',$2::jsonb,$3) RETURNING id", [otherWorkspace, JSON.stringify({ email: "foreign@example.test" }), owner])).rows[0];
    const foreignResponse = await post("groups/preview", { group: { name: "Foreign", emailContactIds: [foreign.id] } }, raw);
    assert.equal(foreignResponse.body.code, "OPERATOR_INTENT_STALE");
    const local = (await pool.query("INSERT INTO workspace_contacts(workspace_id,first_name,last_name,details,created_by) VALUES($1,'Local','User',$2::jsonb,$3) RETURNING id", [workspace, JSON.stringify({ email: "local@example.test" }), manager])).rows[0];
    const preview = await post("groups/preview", { group: { name: "Changed " + crypto.randomUUID(), emailContactIds: [local.id] } }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    await pool.query("UPDATE workspace_contacts SET first_name='Changed',updated_at=NOW() WHERE id=$1", [local.id]);
    const created = await post("groups/create", { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() }, raw);
    assert.equal(created.body.code, "OPERATOR_INTENT_STALE");
  });
  it("rejects group creation after its connection is downgraded or revoked", async () => {
    const raw = await credential(manager, ["mcp:groups:create"]);
    const contact = (await pool.query("INSERT INTO workspace_contacts(workspace_id,first_name,last_name,details,created_by) VALUES($1,'Role','Test',$2::jsonb,$3) RETURNING id", [workspace, JSON.stringify({ email: "role@example.test" }), manager])).rows[0];
    const preview = await post("groups/preview", { group: { name: "Role " + crypto.randomUUID(), emailContactIds: [contact.id] } }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
    try {
      await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
      assert.equal((await post("groups/create", body, raw)).status, 403);
    } finally {
      await pool.query("UPDATE workspace_memberships SET role='workspace_manager' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
    }
    const auth = await connections.authenticateCredential({ rawCredential: raw });
    await connections.revokeConnection({ workspaceId: workspace, connectionId: auth.connection.id, revokedBy: manager });
    assert.equal((await post("groups/create", body, raw)).status, 401);
  });
  it("previews and creates a webhook without storing its URL in the plan", async () => {
    const raw = await credential(manager, ["mcp:webhooks:create"]);
    const webhook = { name: "Webhook " + crypto.randomUUID(), url: "https://example.test/synthetic-private-path-" + crypto.randomUUID(), kind: "generic" };
    assert.equal((await post("webhooks/preview", { webhook }, viewerCredential)).status, 403);
    const preview = await post("webhooks/preview", { webhook }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    assert.equal(tools.get("tt_preview_webhook_create").validateOutput(preview.body), true);
    assert.ok(!JSON.stringify(preview.body).includes(webhook.url));
    const plan = (await pool.query("SELECT decisions::text AS decisions FROM operator_inventory_plans WHERE id=$1", [preview.body.planId])).rows[0];
    assert.ok(!plan.decisions.includes(webhook.url));
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID(), url: webhook.url };
    assert.equal((await post("webhooks/create", { ...body, url: "https://example.test/other" }, raw)).body.code, "OPERATOR_PLAN_MISMATCH");
    const created = await post("webhooks/create", body, raw);
    assert.equal(created.status, 200, JSON.stringify(created.body));
    assert.equal(tools.get("tt_create_webhook").validateOutput(created.body), true);
    assert.ok(!JSON.stringify(created.body).includes(webhook.url));
    assert.equal((await post("webhooks/create", body, raw)).body.replayed, true);
    const saved = (await pool.query("SELECT webhook_urls FROM workspace_settings WHERE workspace_id=$1", [workspace])).rows[0].webhook_urls.find((entry) => entry.name === webhook.name);
    assert.equal(saved.url, webhook.url); assert.equal(saved.verified, false);
  });
  it("rejects a webhook preview when settings or connection authority change", async () => {
    const raw = await credential(manager, ["mcp:webhooks:create"]);
    const webhook = { name: "Stale " + crypto.randomUUID(), url: "https://example.test/opaque", kind: "generic" };
    const preview = await post("webhooks/preview", { webhook }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID(), url: webhook.url };
    await pool.query("INSERT INTO workspace_settings(workspace_id,webhook_urls) VALUES($1,$2::jsonb) ON CONFLICT(workspace_id) DO UPDATE SET webhook_urls=COALESCE(workspace_settings.webhook_urls,'[]'::jsonb)||EXCLUDED.webhook_urls", [workspace, JSON.stringify([{ name: "Other", url: "https://example.test" }])]);
    assert.equal((await post("webhooks/create", body, raw)).body.code, "OPERATOR_INTENT_STALE");
    const auth = await connections.authenticateCredential({ rawCredential: raw });
    await connections.revokeConnection({ workspaceId: workspace, connectionId: auth.connection.id, revokedBy: manager });
    assert.equal((await post("webhooks/create", body, raw)).status, 401);
  });
  it("creates only the reviewed contact with its separate permission and safe retry", async () => {
    const raw = await credential(manager, ["mcp:contacts:create"]);
    const contact = { firstName: "Ada", lastName: "Example", email: "ADA@example.test", phoneE164: "+491" + String(crypto.randomInt(100000000, 999999999)) };
    assert.equal((await post("contacts/preview", { contact }, viewerCredential)).status, 403);
    const preview = await post("contacts/preview", { contact }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    assert.equal(tools.get("tt_preview_contact_create").validateOutput(preview.body), true);
    assert.equal(preview.body.effect.email.value, "ada@example.test");
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
    const created = await post("contacts/create", body, raw);
    assert.equal(created.status, 200, JSON.stringify(created.body));
    assert.equal(tools.get("tt_create_contact").validateOutput(created.body), true);
    const row = (await pool.query("SELECT first_name,last_name,phone_e164,details FROM workspace_contacts WHERE workspace_id=$1 AND id=$2", [workspace, created.body.contactId])).rows[0];
    assert.equal(row.first_name, "Ada"); assert.equal(row.phone_e164, contact.phoneE164); assert.equal(row.details.email, "ada@example.test");
    assert.equal((await post("contacts/create", body, raw)).body.replayed, true);
    assert.equal((await post("contacts/preview", { contact }, raw)).body.code, "OPERATOR_INTENT_STALE");
  });
  it("rejects expired, foreign, and revoked contact creation previews", async () => {
    const raw = await credential(manager, ["mcp:contacts:create"]), other = await credential(manager, ["mcp:contacts:create"]);
    const preview = await post("contacts/preview", { contact: { firstName: "Ada", lastName: "Example", email: "ada@example.test" } }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
    assert.equal((await post("contacts/create", body, other)).status, 404);
    assert.equal((await post("contacts/create", { ...body, planHash: "0".repeat(64) }, raw)).body.code, "OPERATOR_PLAN_MISMATCH");
    try {
      await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
      assert.equal((await post("contacts/create", body, raw)).status, 403);
    } finally {
      await pool.query("UPDATE workspace_memberships SET role='workspace_manager' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
    }
    await pool.query("UPDATE operator_inventory_plans SET created_at=NOW()-INTERVAL '16 minutes',expires_at=NOW()-INTERVAL '1 minute' WHERE id=$1", [body.planId]);
    assert.equal((await post("contacts/create", body, raw)).body.code, "OPERATOR_PLAN_EXPIRED");
    const auth = await connections.authenticateCredential({ rawCredential: raw });
    await connections.revokeConnection({ workspaceId: workspace, connectionId: auth.connection.id, revokedBy: manager });
    assert.equal((await post("contacts/create", body, raw)).status, 401);
  });
  it("returns only same-workspace records with the same type and category as context", async () => {
    const target = await seed("similar-seed-" + crypto.randomUUID());
    const match = await seed("similar-match-" + crypto.randomUUID());
    const foreign = await seed("similar-foreign-" + crypto.randomUUID(), {}, otherWorkspace);
    const first = await get("tokens/" + target.id + "/similar?limit=1");
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(tools.get("tt_list_similar_tokens").validateOutput(first.body), true);
    const records = [...first.body.items];
    let next = first.body.completeness.nextCursor;
    while (next) {
      const page = await get("tokens/" + target.id + "/similar?limit=1&cursor=" + encodeURIComponent(next));
      assert.equal(page.status, 200);
      records.push(...page.body.items);
      next = page.body.completeness.nextCursor;
    }
    assert.ok(records.some((row) => row.id === match.id));
    assert.ok(!records.some((row) => row.id === target.id || row.id === foreign.id));
    assert.equal((await get("tokens/" + foreign.id + "/similar")).status, 404);
    assert.equal((await get("tokens/" + target.id + "/similar?workspaceId=" + otherWorkspace)).status, 400);
  });
  it("lists only this workspace's sections with pagination", async () => {
    const unique = crypto.randomUUID();
    await seed("section-one-" + unique, { section: ["a-" + unique, "b-" + unique] });
    await seed("section-foreign-" + unique, { section: ["foreign-" + unique] }, otherWorkspace);
    const first = await get("sections?limit=1");
    assert.equal(first.status, 200); assert.equal(tools.get("tt_list_sections").validateOutput(first.body), true);
    const all = [...first.body.items]; let next = first.body.completeness.nextCursor;
    while (next) { const page = await get("sections?limit=1&cursor=" + encodeURIComponent(next)); assert.equal(page.status, 200); all.push(...page.body.items); next = page.body.completeness.nextCursor; }
    assert.ok(all.some((item) => item.value === "a-" + unique));
    assert.ok(all.some((item) => item.value === "b-" + unique));
    assert.ok(!all.some((item) => item.value === "foreign-" + unique));
    assert.equal((await get("sections?workspaceId=" + otherWorkspace)).status, 400);
  });
  it("requires a distinct update scope, reviews exact changes, and safely retries", async () => {
    const item = await seed("update-" + crypto.randomUUID(), { used_by: "before" });
    const updateCredential = await credential(manager, ["mcp:tokens:read", "mcp:inventory:update"]);
    assert.equal((await post("inventory/update/preview", { tokenId: item.id, changes: { usedBy: "after" } })).status, 403);
    assert.equal((await post("inventory/update/preview", { tokenId: item.id, changes: { usedBy: "after" } }, viewerCredential)).status, 403);
    const preview = await post("inventory/update/preview", { tokenId: item.id, changes: { usedBy: "after" } }, updateCredential);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    assert.equal(tools.get("tt_preview_inventory_update").validateOutput(preview.body), true);
    assert.equal(preview.body.effect.fields[0].before.value, "before");
    assert.equal(preview.body.effect.fields[0].after.value, "after");
    const requestId = crypto.randomUUID(), body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId };
    const result = await post("inventory/update", body, updateCredential);
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(tools.get("tt_update_inventory").validateOutput(result.body), true);
    assert.equal((await get("tokens/" + item.id)).body.record.usedBy.value, "after");
    const replay = await post("inventory/update", body, updateCredential);
    assert.equal(replay.status, 200); assert.equal(replay.body.replayed, true);
  });
  it("rejects stale, foreign, and provider-managed update previews", async () => {
    const certLike = await seed("cert-type-" + crypto.randomUUID());
    await pool.query("UPDATE tokens SET type='ssl_cert' WHERE id=$1", [certLike.id]);
    const certCredential = await credential(manager, ["mcp:tokens:read", "mcp:inventory:update"]);
    assert.equal((await post("inventory/update/preview", { tokenId: certLike.id, changes: { usedBy: "new" } }, certCredential)).status, 409);
    const sourced = await seed("source-kind-" + crypto.randomUUID(), { source_kind: "synthetic-kind" });
    assert.equal((await post("inventory/update/preview", { tokenId: sourced.id, changes: { usedBy: "new" } }, certCredential)).status, 409);
    const item = await seed("stale-update-" + crypto.randomUUID(), { used_by: "before" });
    const updateCredential = await credential(manager, ["mcp:tokens:read", "mcp:inventory:update"]);
    assert.equal((await post("inventory/update/preview", { tokenId: otherToken.id, changes: { usedBy: "new" } }, updateCredential)).status, 404);
    assert.equal((await post("inventory/update/preview", { tokenId: base.id, changes: { usedBy: "new" } }, updateCredential)).status, 409);
    const preview = await post("inventory/update/preview", { tokenId: item.id, changes: { usedBy: "new" } }, updateCredential);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    await pool.query("UPDATE tokens SET used_by='someone else',updated_at=NOW() WHERE id=$1", [item.id]);
    const result = await post("inventory/update", { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() }, updateCredential);
    assert.equal(result.status, 409); assert.equal(result.body.code, "OPERATOR_INTENT_STALE");
  });
  it("does not expand existing imports into updates and rejects a duplicate identity", async () => {
    const item = await seed("duplicate-update-" + crypto.randomUUID());
    const other = await seed("duplicate-target-" + crypto.randomUUID());
    const updateCredential = await credential(manager, ["mcp:tokens:read", "mcp:inventory:update"]);
    const refused = await post("inventory/update/preview", { tokenId: item.id, changes: { name: other.name, location: other.location } }, updateCredential);
    assert.equal(refused.status, 409); assert.equal(refused.body.code, "OPERATOR_INTENT_STALE");
    const existing = await post("inventory/update/preview", { tokenId: item.id, changes: { usedBy: "new" } }, managerCredential);
    assert.equal(existing.status, 403);
  });
  it("does not accept or replay an update preview through the import endpoint", async () => {
    const item = await seed("separate-actions-" + crypto.randomUUID());
    const both = await credential(manager, ["mcp:tokens:read", "mcp:inventory:import", "mcp:inventory:update"]);
    const preview = await post("inventory/update/preview", { tokenId: item.id, changes: { usedBy: "after" } }, both);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
    assert.equal((await post("inventory/import", body, both)).body.code, "OPERATOR_PLAN_MISMATCH");
    assert.equal((await post("inventory/update", body, both)).status, 200);
    assert.equal((await post("inventory/import", body, both)).body.code, "OPERATOR_IDEMPOTENCY_CONFLICT");
  });
  it("rechecks role, instance write switch, and revocation before an update", async () => {
    const item = await seed("update-authority-" + crypto.randomUUID(), { used_by: "before" });
    const raw = await credential(manager, ["mcp:tokens:read", "mcp:inventory:update"]);
    const preview = await post("inventory/update/preview", { tokenId: item.id, changes: { usedBy: "after" } }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
    try {
      await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
      assert.equal((await post("inventory/update", body, raw)).status, 403);
      await pool.query("UPDATE workspace_memberships SET role='workspace_manager' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
      process.env.MCP_OPERATOR_WRITES_ENABLED = "false";
      assert.equal((await post("inventory/update", body, raw)).body.code, "OPERATOR_WRITES_DISABLED");
      process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
      const auth = await connections.authenticateCredential({ rawCredential: raw });
      await connections.revokeConnection({ workspaceId: workspace, connectionId: auth.connection.id, revokedBy: manager });
      assert.equal((await post("inventory/update", body, raw)).status, 401);
      assert.equal((await pool.query("SELECT used_by FROM tokens WHERE id=$1", [item.id])).rows[0].used_by, "before");
    } finally {
      process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
      await pool.query("UPDATE workspace_memberships SET role='workspace_manager' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
    }
  });
  it("rejects altered, expired, or foreign update plans without changing inventory", async () => {
    const item = await seed("update-plan-" + crypto.randomUUID(), { used_by: "before" });
    const raw = await credential(manager, ["mcp:tokens:read", "mcp:inventory:update"]);
    const other = await credential(manager, ["mcp:tokens:read", "mcp:inventory:update"]);
    const preview = await post("inventory/update/preview", { tokenId: item.id, changes: { usedBy: "after" } }, raw);
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    const body = { planId: preview.body.planId, planHash: preview.body.planHash, requestId: crypto.randomUUID() };
    assert.equal((await post("inventory/update", body, other)).status, 404);
    assert.equal((await post("inventory/update", { ...body, planHash: "0".repeat(64) }, raw)).body.code, "OPERATOR_PLAN_MISMATCH");
    await pool.query("UPDATE operator_inventory_plans SET created_at=NOW()-INTERVAL '16 minutes',expires_at=NOW()-INTERVAL '1 minute' WHERE id=$1", [body.planId]);
    assert.equal((await post("inventory/update", body, raw)).body.code, "OPERATOR_PLAN_EXPIRED");
    assert.equal((await pool.query("SELECT used_by FROM tokens WHERE id=$1", [item.id])).rows[0].used_by, "before");
  });
  it("filters GitLab deploy metadata and follows complete pagination without secret fields", async () => {
    const first = await get("tokens?provider=gitlab&sourceKind=gitlab-deploy-token&limit=1");
    assert.equal(first.status, 200); assert.equal(first.body.items.length, 1); assert.equal(first.body.completeness.total, 2);
    const second = await get("tokens?provider=gitlab&sourceKind=gitlab-deploy-token&limit=1&cursor=" + first.body.completeness.nextCursor);
    assert.equal(second.body.items.length, 1); assert.notEqual(second.body.items[0].id, first.body.items[0].id); assert.equal(second.body.completeness.nextCursor, null);
    assert.equal(tools.get("tt_list_tokens").validateOutput(first.body), true);
    assert.ok(!JSON.stringify([first.body, second.body]).includes("INVENTORY_PRIVATE"));
    assert.equal((await get("tokens?locationContains=" + encodeURIComponent("%_"))).body.items.length, 1);
    const detail = await get("tokens/" + base.id); assert.equal(detail.status, 200); assert.equal(detail.body.record.name.untrusted, true);
    assert.equal((await get("tokens/" + otherToken.id)).status, 404);
    assert.equal((await get("tokens/9999999999")).status, 404);
    assert.equal((await get("tokens?workspaceId=" + otherWorkspace)).status, 400);
  });
  it("does not expand an existing certificate-only grant or let viewers import", async () => {
    const old = await credential(viewer, ["mcp:certs:read"]);
    assert.equal((await get("tokens", old)).status, 403);
    assert.equal((await post("inventory/preview", { records: [metadata("viewer-denied")] }, viewerCredential)).status, 403);
  });
  it("cannot infer masked location paths or URL credentials through filters and counts", async () => {
    await seed("file-location", { location: "/etc/hidden-inventory-path/credential" });
    await seed("url-location", { location: "https://hidden-user:hidden-password@inventory.example.test/item?api_key=hidden-value#hidden-fragment" });
    for (const value of ["/etc/hidden", "hidden-user", "hidden-password", "hidden-value", "hidden-fragment"]) {
      for (const filter of ["locationContains", "query"]) {
        const response = await get("tokens?" + filter + "=" + encodeURIComponent(value));
        assert.equal(response.status, 200); assert.equal(response.body.completeness.total, 0); assert.deepEqual(response.body.items, []);
      }
    }
    const visible = await get("tokens?locationContains=inventory.example.test");
    assert.equal(visible.body.completeness.total, 1); assert.equal(visible.body.items[0].location.value, "https://inventory.example.test/item");
    for (const [index, location] of ["https:alice:synthetic-secret@inventory.example.test/path", "https:\\alice:synthetic-secret@inventory.example.test/path", "https:/\\alice:synthetic-secret@inventory.example.test/path"].entries()) {
      const malformed = await seed("malformed-url-" + index, { location });
      assert.equal((await get("tokens/" + malformed.id)).body.record.location.value, "(invalid URL location)");
      assert.equal((await get("tokens?locationContains=synthetic-secret")).body.completeness.total, 0);
      assert.equal((await post("inventory/preview", { records: [metadata("reject-url-" + index, { location })] })).status, 422);
    }
    for (const [index, padding] of ["x".repeat(300), "😀".repeat(300)].entries()) {
      const long = await seed("long-location-" + index, { location: "gitlab:" + padding + "/hidden-location-suffix" });
      const detail = await get("tokens/" + long.id); assert.equal(detail.body.record.location.truncated, true);
      assert.equal((await get("tokens?locationContains=hidden-location-suffix")).body.completeness.total, 0);
    }
  });
  it("filters the same provider and source kind it displays, honoring stored provenance", async () => {
    await seed("provenance-priority", { location: "gitlab:projects/1/deploy_tokens/7", source_provider: "aws" });
    await seed("kind-priority", { location: "gitlab:projects/1/deploy_tokens/8", source_provider: "gitlab", source_kind: "gitlab-personal-token" });
    await seed("filesystem-provider", { location: "C:\\private\\inventory", source_provider: "aws" });
    for (const query of ["provider=gitlab&query=provenance-priority", "sourceKind=gitlab-deploy-token&query=kind-priority", "provider=c&query=filesystem-provider"]) assert.equal((await get("tokens?" + query)).body.completeness.total, 0);
    assert.equal((await get("tokens?provider=aws&query=provenance-priority")).body.items[0].provider, "aws");
    assert.equal((await get("tokens?sourceKind=gitlab-personal-token&query=kind-priority")).body.items[0].sourceKind, "gitlab-personal-token");
  });
  it("imports only the exact preview, keeps existing metadata, and retries once", async () => {
    const records = [metadata("deploy-a", { location: base.location, expiresAt: "2028-01-01" }), metadata("new-one"), metadata("new-two")];
    const plan = await preview(records); assert.equal(plan.effect.creates, 2); assert.equal(plan.effect.keeps, 1); assert.equal(plan.effect.updatesExisting, false);
    const requestId = crypto.randomUUID(), response = await submit(plan, requestId);
    assert.equal(response.status, 200, JSON.stringify(response.body)); assert.equal(response.body.createdIds.length, 2); assert.deepEqual(response.body.keptIds, [base.id]);
    assert.equal(tools.get("tt_import_inventory").validateOutput(response.body), true);
    assert.equal((await pool.query("SELECT expiration::text FROM tokens WHERE id=$1", [base.id])).rows[0].expiration, "2027-12-01");
    const retry = await submit(plan, requestId); assert.equal(retry.status, 200); assert.equal(retry.body.replayed, true); assert.deepEqual(retry.body.createdIds, response.body.createdIds);
    assert.equal((await submit(plan)).status, 409);
    assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1", [workspace])).rows[0].count, 0);
    assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM audit_events WHERE workspace_id=$1 AND action='TOKEN_CREATED'", [workspace])).rows[0].count, 2);
  });
  it("keeps imported calendar expiry and no-expiry reads and filters stable across process time zones", async () => {
    const records = [metadata("calendar-expiry"), metadata("calendar-no-expiry", { expiresAt: null })];
    const plan = await preview(records);
    assert.deepEqual(plan.effect.items.map((item) => item.expiresAt), ["2027-12-01", null]);
    const imported = await submit(plan);
    assert.equal(imported.status, 200, JSON.stringify(imported.body));
    const stored = await pool.query("SELECT id,expiration::text FROM tokens WHERE id=ANY($1::int[]) ORDER BY id", [imported.body.createdIds]);
    assert.deepEqual(stored.rows.map((row) => row.expiration), ["2027-12-01", "2099-12-31"]);
    const child = String.raw`
      const assert = require("node:assert/strict"), input = JSON.parse(require("node:fs").readFileSync(0,"utf8"));
      const express = require("node:module").createRequire(require.resolve("./apps/api/index.js"))("express"), request = require("supertest");
      const { pool } = require("./apps/api/db/database");
      const { guardOperatorCredentials } = require("./apps/api/middleware/operator-connection-auth");
      const { projectToken } = require("./apps/api/services/operator/tokenInventory");
      const app = express(); app.use(express.json()); app.use("/api",guardOperatorCredentials); app.use(require("./apps/api/routes/operator"));
      const get = (path) => request(app).get("/api/v1/operator/" + path).set("Authorization","Bearer " + input.credential);
      (async () => {
        for (const [id,expected] of input.ids.map((id,index) => [id,index === 0 ? "2027-12-01" : null])) {
          const detail = await get("tokens/" + id); assert.equal(detail.status,200); assert.equal(detail.body.record.expiresAt,expected);
        }
        const list = await get("tokens?query=calendar-"); assert.equal(list.status,200); assert.equal(list.body.completeness.total,2);
        assert.deepEqual(list.body.items.map((item) => item.expiresAt),["2027-12-01",null]);
        for (const [cutoff,count] of [["2027-12-01",0],["2027-12-02",1],["2100-01-01",1]]) {
          const filtered = await get("tokens?query=calendar-&expiresBefore=" + cutoff);
          assert.equal(filtered.status,200); assert.equal(filtered.body.completeness.total,count); assert.equal(filtered.body.items.length,count);
          if (count) assert.equal(filtered.body.items[0].expiresAt,"2027-12-01");
        }
        const record = {id:1,name:"local-calendar",type:"api_key",category:"key_secret"};
        assert.equal(projectToken({...record,expiration:new Date(2027,11,1)}).expiresAt,"2027-12-01");
        assert.equal(projectToken({...record,expiration:new Date(2099,11,31)}).expiresAt,null);
      })().catch((error) => { console.error(error); process.exitCode=1; }).finally(() => pool.end());
    `;
    for (const TZ of ["Europe/Berlin", "UTC", "America/Los_Angeles"]) {
      const result = spawnSync(process.execPath, ["-e", child], { cwd: process.cwd(), env: { ...process.env, TZ }, input: JSON.stringify({ ids: imported.body.createdIds, credential: viewerCredential }), encoding: "utf8", timeout: 30000 });
      assert.equal(result.error, undefined, TZ);
      assert.equal(result.status, 0, TZ + ": " + result.stderr + result.stdout);
    }
    assert.deepEqual((await pool.query("SELECT expiration::text FROM tokens WHERE id=ANY($1::int[]) ORDER BY id", [imported.body.createdIds])).rows.map((row) => row.expiration), ["2027-12-01", "2099-12-31"]);
  });
  it("serializes concurrent retries and rejects request-id reuse with a different plan", async () => {
    const plan = await preview([metadata("concurrent")]), id = crypto.randomUUID();
    const responses = await Promise.all([submit(plan, id), submit(plan, id)]);
    assert.deepEqual(responses.map((response) => response.status), [200, 200]); assert.equal(responses.filter((response) => response.body.replayed).length, 1);
    const next = await preview([metadata("different-plan")]); assert.equal((await submit(next, id)).body.code, "OPERATOR_IDEMPOTENCY_CONFLICT");
  });
  it("refuses stale, tampered, expired and foreign previews before writing", async () => {
    const plan = await preview([metadata("stale"), metadata("not-created")]); await seed("stale");
    assert.equal((await submit(plan)).body.code, "OPERATOR_INTENT_STALE");
    assert.equal((await pool.query("SELECT id FROM tokens WHERE workspace_id=$1 AND name='not-created'", [workspace])).rowCount, 0);
    const otherCredential = await credential(manager); assert.equal((await submit(plan, crypto.randomUUID(), otherCredential)).status, 404);
    for (const patch of [{ planId: [plan.planId] }, { planHash: [plan.planHash] }, { requestId: [crypto.randomUUID()] }]) assert.equal((await post("inventory/import", { planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID(), ...patch })).status, 400);
    assert.equal((await submit({ ...plan, planHash: "a".repeat(64) })).body.code, "OPERATOR_PLAN_MISMATCH");
    const expired = await preview([metadata("expired-plan")]);
    await pool.query("UPDATE operator_inventory_plans SET created_at=NOW()-INTERVAL '20 minutes',expires_at=NOW()-INTERVAL '5 minutes' WHERE id=$1", [expired.planId]);
    assert.equal((await submit(expired)).body.code, "OPERATOR_PLAN_EXPIRED");
  });
  it("rejects secrets, arbitrary fields and malformed metadata without retaining a preview", async () => {
    const count = async () => (await pool.query("SELECT COUNT(*)::int AS count FROM operator_inventory_plans WHERE workspace_id=$1", [workspace])).rows[0].count;
    const before = await count();
    for (const patch of [{ password: "secret" }, { description: "password=secret" }, { location: "https://user:pass@example.test" }, { expiresAt: "2027-02-30" }, { source_provider: "gitlab" }]) assert.ok([400, 422].includes((await post("inventory/preview", { records: [metadata("invalid", patch)] })).status));
    assert.equal(await count(), before);
  });
  it("rechecks role, revocation and the instance write switch at import", async () => {
    const raw = await credential(manager), plan = await preview([metadata("role-denied")], raw);
    await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
    assert.equal((await submit(plan, crypto.randomUUID(), raw)).status, 403);
    await pool.query("UPDATE workspace_memberships SET role='workspace_manager' WHERE workspace_id=$1 AND user_id=$2", [workspace, manager]);
    process.env.MCP_OPERATOR_WRITES_ENABLED = "false"; assert.equal((await submit(plan, crypto.randomUUID(), raw)).body.code, "OPERATOR_WRITES_DISABLED"); process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
    const auth = await connections.authenticateCredential({ rawCredential: raw }); await connections.revokeConnection({ workspaceId: workspace, connectionId: auth.connection.id, revokedBy: manager });
    assert.equal((await submit(plan, crypto.randomUUID(), raw)).status, 401);
  });
  it("keeps implicit-owner import admission behind billing's user-before-workspace lock order", async () => {
    await pool.query("DELETE FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2", [workspace, owner]);
    const raw = await credential(owner), plan = await preview([metadata("implicit-owner")], raw), billing = await pool.connect();
    let pending;
    try {
      await billing.query("BEGIN"); await billing.query("SET LOCAL lock_timeout='1500ms'");
      const billingPid = (await billing.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      await billing.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [owner]);
      pending = submit(plan, crypto.randomUUID(), raw).then((response) => response);
      let waiting = false;
      for (let n = 0; n < 50 && !waiting; n++) {
        waiting = (await pool.query("SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>$1 AND $1=ANY(pg_blocking_pids(pid)) AND query ILIKE '%FROM users%KEY SHARE%'", [billingPid])).rowCount > 0;
        if (!waiting) await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.equal(waiting, true, "import waits for the billing-held user before holding workspace authority");
      await billing.query("SELECT id FROM workspaces WHERE id=$1 FOR UPDATE", [workspace]);
      await billing.query("COMMIT"); assert.equal((await pending).status, 200);
    } finally {
      await billing.query("ROLLBACK").catch(() => {}); billing.release(); if (pending) await pending;
      await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role)VALUES($1,$2,'admin')ON CONFLICT DO NOTHING", [workspace, owner]);
    }
  });
});
