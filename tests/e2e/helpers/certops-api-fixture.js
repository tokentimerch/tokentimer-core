/**
 * Create isolated authenticated users/workspaces in a real disposable API/PostgreSQL stack.
 * Supporting API suites use public requests plus narrowly scoped prerequisite rows
 * and database oracles. cleanup() removes only fixture-owned identities; callers must
 * retain finally cleanup and must explicitly authorize the disposable stack. */
"use strict";
const crypto = require("node:crypto");
const path = require("node:path");
const { createRequire } = require("node:module");
const apiRequire = createRequire(path.resolve(__dirname, "../../../apps/api/package.json"));
async function cleanupApiFixture({ pool, workspaceId, userId, onCleanupFailure }) {
  const failures = [];
  let ownedWorkspaceIds = [workspaceId];
  const report = kind => { try { onCleanupFailure?.(kind); } catch { /* Preserve cleanup failures. */ } };
  try {
    // A login can create another personal workspace owned by this fixture user.
    if (userId) {
      try { ownedWorkspaceIds = [...new Set([workspaceId, ...(await pool.query("SELECT id FROM workspaces WHERE created_by=$1", [userId])).rows.map((row) => row.id)])]; }
      catch (error) { failures.push(error); report("workspace-discovery"); }
    }
    try { await pool.query("DELETE FROM audit_events WHERE workspace_id=ANY($1::uuid[]) OR actor_user_id=$2 OR subject_user_id=$2", [ownedWorkspaceIds, userId || null]); }
    catch (error) { failures.push(error); report("audit-delete"); }
    for (const id of ownedWorkspaceIds) {
      try { await pool.query("DELETE FROM workspaces WHERE id=$1", [id]); }
      catch (error) { failures.push(error); report("workspace-delete"); }
    }
    if (userId) {
      try { await pool.query("DELETE FROM users WHERE id=$1", [userId]); }
      catch (error) { failures.push(error); report("user-delete"); }
    }
    if (failures.length) throw new AggregateError(failures, "Run-owned API fixture cleanup failed");
  } finally {
    try { await pool.end(); } catch (error) { report("pool-close"); throw error; }
  }
}
async function createApiFixture(baseUrl, { onCleanupFailure } = {}) {
  if (process.env.CERTOPS_CSR_DISPOSABLE_STACK !== "1") throw new Error("Disposable API stack authorization required");
  const { Pool } = apiRequire("pg");
  const pool = new Pool({ host: process.env.DB_HOST || "localhost", port: Number(process.env.DB_PORT || 5432), user: process.env.DB_USER || "tokentimer", password: process.env.DB_PASSWORD || "password", database: process.env.DB_NAME || "tokentimer", connectionTimeoutMillis: 5000 });
  const workspaceId = crypto.randomUUID();
  let userId;
  const cookies = new Map();
  let csrfToken;
  async function request(route, method = "GET", body, extraHeaders = {}) {
    const response = await fetch(new URL(route, baseUrl), { method, signal: AbortSignal.timeout(30000), headers: { ...extraHeaders, "content-type": "application/json", cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join("; "), ...(csrfToken ? { "x-csrf-token": csrfToken } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    for (const value of response.headers.getSetCookie()) { const pair = value.split(";", 1)[0]; const i = pair.indexOf("="); cookies.set(pair.slice(0, i), pair.slice(i + 1)); }
    return { status: response.status, body: response.status === 204 ? null : await response.json() };
  }
  async function cleanup() {
    return cleanupApiFixture({ pool, workspaceId, userId, onCleanupFailure });
  }
  try {
    await pool.query("SELECT 1 FROM certificate_instances LIMIT 1");
    const email = `inventory-${crypto.randomUUID()}@example.test`;
    const password = crypto.randomBytes(24).toString("hex");
    userId = (await pool.query("INSERT INTO users(email,display_name,password_hash,email_verified) VALUES ($1,'Certificate API fixture',$2,true) RETURNING id", [email, await apiRequire("bcryptjs").hash(password, 10)])).rows[0].id;
    await pool.query("INSERT INTO workspaces(id,name,created_by) VALUES ($1,'Certificate API fixture',$2)", [workspaceId, userId]);
    await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'admin')", [workspaceId, userId]);
    csrfToken = (await request("/api/csrf-token")).body.csrfToken;
    if ((await request("/auth/login", "POST", { email, password })).status !== 200) throw new Error("Fixture real login failed");
    csrfToken = (await request("/api/csrf-token")).body.csrfToken;
    // Ephemeral fixture credentials remain in memory for real browser login;
    // callers must never include these values in reports or artifacts.
    return { workspaceId, userId, email, password, pool, request, cleanup };
  } catch (error) { try { await cleanup(); } catch (cleanupError) { throw new AggregateError([error, cleanupError], "API fixture setup and cleanup failed"); } throw error; }
}
module.exports = { createApiFixture, cleanupApiFixture };
