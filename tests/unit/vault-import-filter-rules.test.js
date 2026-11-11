"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const { it } = require("node:test");
const root = path.resolve(__dirname, "../..");

function fixture() {
  const calls = { writes: [], pairs: [] };
  const routes = new Map();
  const noop = () => {};
  const middleware = () => noop;
  const mocks = {
    express: { Router: () => ({
      use() {}, get() {}, post(url, ...handlers) { routes.set(url, handlers.at(-1)); },
    }) },
    "../utils/logger": { logger: { info() {}, warn() {}, error() {} } },
    "../services/importFilterRules": require(path.join(root, "apps/api/services/importFilterRules")),
    "../services/importCleanup": { validateCleanupRequest: () => null },
    "../src/shared/contactGroups": { interpretContactGroupWrite: () => ({ action: "omit" }) },
    "../services/scanBinding": {
      async bindImportItemsToScan({ pairs }) {
        calls.pairs.push(pairs);
        return { resolveForItem: () => null };
      },
    },
    "../services/autoSyncProvenance": {
      resolveAutoSyncImportContext: async () => null,
      recordAutoSyncImportErrors: async () => {},
      async upsertImportedToken({ payload }) {
        calls.writes.push(payload);
        return { created: true, token: { id: calls.writes.length, ...payload } };
      },
    },
    "../services/audit": { writeAudit: async () => {} },
  };
  const unused = new Proxy({}, { get: () => middleware });
  const filename = path.join(root, "apps/api/routes/integrations.js");
  const mod = new Module(filename);
  mod.filename = filename;
  mod.paths = Module._nodeModulePaths(path.dirname(filename));
  mod.require = id => Object.hasOwn(mocks, id) ? mocks[id] : unused;
  mod._compile(fs.readFileSync(filename, "utf8"), filename);
  return { handler: routes.get("/api/v1/integrations/vault/import"), calls };
}

async function request(handler, filterRules) {
  const res = {
    statusCode: 200, set() {},
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
  await handler({
    authz: { workspaceRole: "admin" }, workspace: { id: "workspace" }, user: { id: 1 },
    body: {
      items: [
        { name: "keep", location: "vault:secret/keep", source: "vault-kv" },
        { name: "excluded", location: "vault:secret/excluded", source: "vault-kv" },
      ],
      filterRules,
    },
  }, res);
  return res;
}

it("Vault import filters items before scan binding and persistence", async () => {
  const { handler, calls } = fixture();
  const res = await request(handler, [{ action: "exclude", field: "name", matchType: "exact", value: "excluded" }]);
  assert.equal(res.statusCode, 201, JSON.stringify(res.body));
  assert.deepEqual(calls.writes.map(item => item.name), ["keep"]);
  assert.equal(calls.pairs[0].length, 1);
  assert.equal(calls.pairs[0][0].sourceObjectId, "secret/keep");
  assert.equal(res.body.filtered_out_count, 1);
});

it("Vault import rejects invalid rules without binding or writing items", async () => {
  const { handler, calls } = fixture();
  const res = await request(handler, [{ action: "include", field: "name", matchType: "regex", value: "[" }]);
  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /regular expression/i);
  assert.deepEqual(calls.writes, []);
  assert.deepEqual(calls.pairs, []);
});

it("Vault imports without rules retain their original scope", async () => {
  const { handler, calls } = fixture();
  const res = await request(handler);
  assert.equal(res.statusCode, 201, JSON.stringify(res.body));
  assert.equal(calls.writes.length, 2);
  assert.equal(res.body.filtered_out_count, 0);
});
