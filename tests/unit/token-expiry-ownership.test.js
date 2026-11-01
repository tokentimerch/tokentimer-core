"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const express = require("../../apps/api/node_modules/express");
const request = require("supertest");

const api = path.resolve(__dirname, "../../apps/api");
const workspaceId = "11111111-1111-4111-8111-111111111111";
const originalExpiration = "2090-01-01";
const observedExpiration = "2091-02-02";

function loadModule(file, stubs) {
  const loaded = new Module(file, module);
  loaded.filename = file;
  loaded.paths = Module._nodeModulePaths(path.dirname(file));
  loaded.require = function (name) {
    return Object.hasOwn(stubs, name)
      ? stubs[name]
      : Module.prototype.require.call(this, name);
  };
  loaded._compile(fs.readFileSync(file, "utf8"), file);
  return loaded.exports;
}

// Exercise the real HTTP handlers and Token model. Only their database
// transport and unrelated middleware/services are fixtures; SQL is recorded,
// not claimed as PostgreSQL integration evidence.
function fixture({ owner = "provider", afterRead, member = true, frozen = false } = {}) {
  const calls = [];
  const token = {
    id: 7, user_id: 42, workspace_id: workspaceId,
    name: "Certificate", location: "Fixture", type: "tls_cert", category: "cert",
    expiration: originalExpiration, source_provider: owner === "provider" ? "vault" : null,
    source_observed_at: "2089-01-01T00:00:00Z", auto_sync_managed: true,
  };
  let reads = 0;
  let inTransaction = false;
  const rows = (values) => ({ rows: values, rowCount: values.length });
  const db = {
    release() {},
    async query(sql, values = []) {
      const text = String(sql).replace(/\s+/g, " ").trim();
      calls.push({ text, values });
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) {
        inTransaction = text === "BEGIN";
        return rows([]);
      }
      if (text.includes("FROM workspace_memberships"))
        return rows(member ? [{ role: "admin" }] : []);
      if (text.includes("SELECT is_frozen FROM workspaces")) return rows([{ is_frozen: frozen }]);
      if (text.includes("FROM token_contact_groups")) return rows([]);
      if (text.startsWith("SELECT") && text.includes("FROM managed_certificates"))
        return rows(["managed", "monitor"].includes(owner) ? [{}] : []);
      if (text.startsWith("SELECT") && text.includes("FROM domain_monitors"))
        return rows(owner === "monitor" ? [{}] : []);
      if (text.startsWith("SELECT") && /FROM tokens(?: t)? WHERE/.test(text)) {
        const snapshot = { ...token };
        if (!inTransaction && reads++ === 0) afterRead?.(token);
        return rows([snapshot]);
      }
      if (text.startsWith("UPDATE tokens")) {
        for (const match of text.matchAll(/\b(name|expiration|notes|auto_sync_managed) = \$(\d+)/g))
          token[match[1]] = values[Number(match[2]) - 1];
        return rows([{ ...token }]);
      }
      throw new Error(`Unexpected fixture query: ${text}`);
    },
  };
  const pool = { query: db.query, connect: async () => db };
  const logger = { info() {}, warn() {}, error() {}, debug() {} };
  const Token = loadModule(path.join(api, "db/models/Token.js"), {
    "../database": { pool }, "../../utils/logger.js": { logger },
  });
  const next = (_req, _res, done) => done();
  const router = loadModule(path.join(api, "routes/tokens.js"), {
    "../db/database": { pool }, "../db/models/Token": Token,
    "../utils/logger": { logger }, "../services/audit": { writeAudit: async () => {} },
    "../utils/sanitize": { sanitizeForLogging: (value) => value },
    "../middleware/auth": { requireAuth: next },
    "../middleware/rateLimit": { getTestApiLimiter: () => next },
    "../middleware/validation": { validateToken: next, handleValidationErrors: next },
    "../services/rbac": { requireNotViewer: next },
    "../services/alertEligibility": {
      enrichTokenWithAlertState: async (value) => value,
      enrichTokenWithAlertStateBestEffort: async (value) => value,
      enrichTokensWithAlertState: async (value) => value,
    },
    "../services/alertLifecycle": { fetchAlertLifecycle: async () => [] },
  });
  const app = express();
  app.use(express.json());
  app.use((req, _res, done) => { req.user = { id: 42 }; done(); });
  app.use(router);
  return {
    token, calls, Token,
    send(method, expiration = originalExpiration) {
      const body = { name: "Certificate", location: "Fixture", notes: "Metadata edit", expiresAt: expiration };
      return method === "PUT"
        ? request(app).put("/api/tokens/7").send(body)
        : request(app).post("/api/tokens").send({
          ...body, type: "tls_cert", category: "cert", workspace_id: workspaceId,
          confirm_duplicate: true,
        });
    },
  };
}

for (const method of ["PUT", "POST"]) {
  for (const owner of ["provider", "managed", "monitor"]) {
    test(`${method}: metadata preserves a concurrent ${owner} expiry observation`, async () => {
      const f = fixture({ owner, afterRead(token) {
        token.expiration = observedExpiration;
        token.source_observed_at = "2089-02-02T00:00:00Z";
      } });
      const response = await f.send(method);
      assert.equal(response.status, 200, JSON.stringify(response.body));
      assert.equal(f.token.expiration, observedExpiration);
      assert.equal(response.body.expiresAt, observedExpiration);
      assert.equal(f.token.source_observed_at, "2089-02-02T00:00:00Z");
      assert.equal(f.token.notes, "Metadata edit");
      assert.ok(f.calls.filter((call) => call.text.startsWith("UPDATE tokens"))
        .every((call) => !/\bexpiration =/.test(call.text)));
    });

    test(`${method}: refuses an explicit ${owner}-owned expiry edit`, async () => {
      const f = fixture({ owner });
      const response = await f.send(method, observedExpiration);
      assert.equal(response.status, 409, JSON.stringify(response.body));
      assert.equal(response.body.code, "VERIFIED_CERTIFICATE_EXPIRY_REQUIRED");
      assert.equal(f.token.expiration, originalExpiration);
      assert.ok(!f.calls.some((call) => call.text.startsWith("UPDATE tokens")));
    });
  }

  test(`${method}: current source ownership fences an edit admitted from an older snapshot`, async () => {
    const f = fixture({ owner: "manual", afterRead(token) { token.source_provider = "vault"; } });
    const response = await f.send(method, observedExpiration);
    assert.equal(response.status, 409, JSON.stringify(response.body));
    assert.equal(response.body.code, "VERIFIED_CERTIFICATE_EXPIRY_REQUIRED");
    assert.ok(f.calls.some((call) => /FROM tokens.*FOR UPDATE/.test(call.text)));
    assert.equal(f.token.expiration, originalExpiration);
  });

  test(`${method}: an ordinary manual expiry remains editable`, async () => {
    const f = fixture({ owner: "manual" });
    const response = await f.send(method, observedExpiration);
    assert.equal(response.status, 200, JSON.stringify(response.body));
    assert.equal(f.token.expiration, observedExpiration);
  });

  test(`${method}: workspace authorization still refuses nonmembers before writes`, async () => {
    const f = fixture({ member: false });
    assert.equal((await f.send(method)).status, 403);
    assert.ok(!f.calls.some((call) => call.text.startsWith("UPDATE tokens")));
  });
}

test("trusted provider model writes can still advance owned expiration", async () => {
  const f = fixture();
  await f.Token.update(7, { expiration: observedExpiration });
  assert.equal(f.token.expiration, observedExpiration);
});
