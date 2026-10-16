"use strict";
/** Draft genuine login/CSRF client for same-VM protected TTL finalization.
 * Session/CSRF/credentials stay in memory and never enter reports or argv. */
const assert = require("node:assert/strict"), credential = require("./certops-adcs-ttl24h-resume-credential");
function validateRoute(workspaceId, route, method) {
  assert.match(workspaceId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/); assert.ok(typeof route === "string" && route.length <= 512 && /^\/[a-zA-Z0-9/_-]+$/.test(route)); assert.ok(["GET", "POST"].includes(method));
  if (route === "/api/csrf-token") assert.equal(method, "GET"); else if (route === "/auth/login") assert.equal(method, "POST"); else assert.ok(route.startsWith(`/api/v1/workspaces/${workspaceId}/certops/`), "Only original workspace public CertOps routes allowed"); return true;
}
async function readBoundedJson(response) {
  assert.ok(response.body && typeof response.body.getReader === "function", "Public TTL API response body missing"); const reader = response.body.getReader(), chunks = []; let total = 0;
  try {
    for (;;) { const next = await reader.read(); if (next.done) break; assert.ok(next.value instanceof Uint8Array, "Public TTL API response bytes invalid"); total += next.value.byteLength; if (total > 262144) { try { await reader.cancel(); } catch {} throw new Error("Public TTL API response exceeds bounded read"); } chunks.push(Buffer.from(next.value)); }
    try { return JSON.parse(Buffer.concat(chunks, total).toString("utf8")); } catch { throw new Error("Public TTL API returned an invalid response"); }
  } finally { reader.releaseLock(); }
}
async function createClient({ config, lease }) {
  assert.equal(config.baseUrl, "https://10.64.0.6/"); const value = credential.unprotect({ lease, receipt: config.credentialReceipt }); assert.equal(value.workspaceId, config.workspaceId); const cookies = new Map(); let csrf;
  async function request(route, method = "GET", body) {
    validateRoute(config.workspaceId, route, method); const response = await fetch(new URL(route, config.baseUrl), { method, redirect: "error", signal: AbortSignal.timeout(30000), headers: { "content-type": "application/json", cookie: [...cookies].map(([key, token]) => `${key}=${token}`).join("; "), ...(csrf ? { "x-csrf-token": csrf } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    for (const entry of response.headers.getSetCookie()) { assert.ok(entry.length <= 8192, "Bounded private session cookie required"); const pair = entry.split(";", 1)[0], at = pair.indexOf("="); assert.ok(at > 0); cookies.set(pair.slice(0, at), pair.slice(at + 1)); assert.ok(cookies.size <= 16); }
    const result = response.status === 204 ? null : await readBoundedJson(response); return { status: response.status, body: result };
  }
  try {
    const first = await request("/api/csrf-token"); assert.equal(first.status, 200); assert.ok(typeof first.body?.csrfToken === "string" && first.body.csrfToken.length > 0 && first.body.csrfToken.length <= 4096); csrf = first.body.csrfToken;
    const login = await request("/auth/login", "POST", { email: value.email, password: value.password }); assert.ok(login.status === 200, "Original fixture public login refused");
    const fresh = await request("/api/csrf-token"); assert.equal(fresh.status, 200); assert.ok(typeof fresh.body?.csrfToken === "string" && fresh.body.csrfToken.length > 0 && fresh.body.csrfToken.length <= 4096); csrf = fresh.body.csrfToken;
  } finally { value.email = null; value.password = null; }
  return { request, close() { cookies.clear(); csrf = undefined; } };
}
module.exports = { validateRoute, readBoundedJson, createClient };
