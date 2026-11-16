"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const { it } = require("node:test");

const root = path.resolve(__dirname, "../..");
const core = root;
const logger = { info() {}, warn() {}, error() {} };

function load(file, mocks) {
  const filename = path.join(root, file);
  const mod = new Module(filename);
  mod.filename = filename;
  mod.paths = Module._nodeModulePaths(path.dirname(filename));
  mod.require = (id) => Object.hasOwn(mocks, id)
    ? mocks[id] : Module._load(id, mod, false);
  mod._compile(fs.readFileSync(filename, "utf8"), filename);
  return mod.exports;
}

function fixture({ complete = true } = {}) {
  const noop = () => {};
  const middleware = () => noop;
  const routes = new Map();
  const router = {
    use() {},
    post(url, ...handlers) { routes.set(url, handlers.at(-1)); },
    get() {},
  };
  const calls = { auth: [], scan: [], persisted: [] };
  const { validateManagedIdentityMode } = load("apps/api/services/azureADIntegration.js", {
    "../utils/logger": { logger },
  });
  const item = {
    name: "Managed certificate",
    location: "azure-ad:managedIdentities/app/certificates/key",
    servicePrincipalType: "ManagedIdentity",
    sourceKind: "azure-ad-sp-certificate",
    sourceObjectId: "app:key",
  };
  const mocks = {
    express: { Router: () => router },
    "../utils/logger": { logger },
    "../middleware/rateLimit": { getApiLimiter: middleware },
    "../middleware/auth": { requireAuth: noop },
    "../services/rbac": {
      loadWorkspace: noop, requireWorkspaceMembership: noop,
      requireWorkspaceManager: noop, requireIntegrationQuota: noop,
    },
    "../../../src/license/middleware.js": {
      requireIntegrationEntitlement: middleware, requireEntitledProviders: middleware,
    },
    "../services/azureADIntegration": {
      validateManagedIdentityMode,
      async scanAzureAD(body) {
        calls.scan.push(body);
        return {
          tenantId: "tenant", items: [item],
          summary: [
            { type: "applications", sourceKind: "azure-ad-secret", complete },
            { type: "service_principals", sourceKind: item.sourceKind, complete },
          ],
        };
      },
    },
    "../services/entraIdentity": {
      legacyManagedIdentityLocation: noop,
    },
    "../services/azureClientCredentials": {
      GRAPH_SCOPE: "https://graph.microsoft.com/.default",
      async resolveAzureScanAuth(body) {
        calls.auth.push(body);
        return { token: "graph", tenantId: "tenant" };
      },
      scrubAzureSecretsFromBody: noop,
    },
    "../services/importFilterRules": require(path.join(core, "apps/api/services/importFilterRules")),
    "../services/integrationScans": {
      async persistScan(body) {
        calls.persisted.push(body);
        return { scanId: "scan" };
      },
    },
    "../services/audit": { writeAudit: async () => {} },
  };
  const unused = new Proxy({}, { get: () => middleware });
  load("apps/api/routes/integrations.js", new Proxy(mocks, {
    getOwnPropertyDescriptor: () => ({ configurable: true, enumerable: true }),
    get: (target, key) => Object.hasOwn(target, key) ? target[key] : unused,
  }));
  return { handler: routes.get("/api/v1/integrations/azure-ad/scan"), calls };
}

async function request(handler, body, isWorkerCall = false) {
  const response = {
    statusCode: 200,
    set() {},
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
  };
  await handler({ body, isWorkerCall, workspace: { id: "workspace" } }, response);
  return response;
}

for (const mode of [undefined, "all", "exclude", "only"]) {
  it(`Core Entra route forwards ${mode ?? "default"} selection and classification`, async () => {
    const { handler, calls } = fixture();
    const response = await request(handler, { token: "graph", managedIdentityMode: mode });
    assert.equal(response.statusCode, 200);
    assert.equal(calls.auth.length, 1);
    assert.equal(calls.scan[0].managedIdentityMode, mode);
    assert.deepEqual(calls.persisted[0].items[0].dimensions, {
      servicePrincipalType: "ManagedIdentity",
    });
    assert.equal(response.body.scan_id, "scan");
  });
}

it("Core Entra route rejects invalid selection before credential exchange", async () => {
  const { handler, calls } = fixture();
  const response = await request(handler, { managedIdentityMode: "invalid" });
  assert.equal(response.statusCode, 400);
  assert.match(response.body.error, /managedIdentityMode/);
  assert.equal(calls.auth.length, 0);
  assert.equal(calls.scan.length, 0);
});

it("Core Entra route applies saved location filters before persisting the scan", async () => {
  const { handler, calls } = fixture();
  const response = await request(handler, {
    managedIdentityMode: "only",
    filterRules: [{
      action: "exclude", field: "location", matchType: "exact",
      value: "azure-ad:servicePrincipals/app/certificates/key",
    }],
  });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body.items, []);
  assert.deepEqual(calls.persisted[0].items, []);
});

for (const mode of [undefined, "all", "only", "exclude"]) {
  for (const worker of ["manual", "legacy-worker", "fenced-worker"]) {
    it(`Core ${worker} cleanup safely scopes ${mode ?? "default"} identity selection`, async () => {
      const { handler, calls } = fixture();
      const body = { token: "graph", managedIdentityMode: mode };
      if (worker === "fenced-worker") body.auto_sync_run = { run_id: "run" };
      await request(handler, body, worker !== "manual");
      const scopes = calls.persisted[0].subScopes;
      assert.equal(scopes[0].complete, true);
      const narrowed = mode === "only" || mode === "exclude";
      assert.equal(scopes[1].complete, !narrowed || worker === "fenced-worker");
      if (narrowed && worker !== "fenced-worker")
        assert.equal(scopes[1].reason, "managed_identity_filter");
    });
  }
  it(`Core partial ${mode ?? "default"} scans never authorize cleanup`, async () => {
    const { handler, calls } = fixture({ complete: false });
    await request(handler, { token: "graph", managedIdentityMode: mode, auto_sync_run: { run_id: "run" } }, true);
    assert.ok(calls.persisted[0].subScopes.every(scope => !scope.complete));
  });
}
