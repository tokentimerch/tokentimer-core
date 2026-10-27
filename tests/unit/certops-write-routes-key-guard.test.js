"use strict";

// Zero-custody guard (#248): every state-changing CertOps route must reject
// private key material before any handler or service sees the request body.
// The middleware itself is covered in reject-key-material.test.js; this file
// proves it is actually wired on every write route, including the
// distribution (Vault KV v2 fan-out) routes, so a newly added route cannot
// silently skip it.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

process.env.NODE_ENV = process.env.NODE_ENV || "test";

const router = require(path.resolve(__dirname, "../../apps/api/routes/certops.js"));

// Mutating routes that carry no request body, so there is nothing to scan.
const BODYLESS_ALLOWLIST = new Set([
  "delete /api/v1/workspaces/:id/certops/certificates/:certId/profile",
]);

function mutatingRoutes() {
  const routes = [];
  for (const layer of router.stack) {
    if (!layer.route) continue;
    for (const method of Object.keys(layer.route.methods)) {
      if (method === "get" || method === "head" || method === "options") continue;
      routes.push({
        key: `${method} ${layer.route.path}`,
        path: layer.route.path,
        handlers: layer.route.stack.map((entry) => entry.name),
      });
    }
  }
  return routes;
}

describe("CertOps write routes reject private key material", () => {
  const routes = mutatingRoutes();

  it("discovers the write routes", () => {
    assert.ok(routes.length >= 30, `expected the CertOps write surface, got ${routes.length}`);
  });

  it("guards every mutating route with a body", () => {
    const unguarded = routes
      .filter((route) => !BODYLESS_ALLOWLIST.has(route.key))
      .filter((route) => !route.handlers.includes("rejectKeyMaterial"))
      .map((route) => route.key);
    assert.deepEqual(unguarded, []);
  });

  it("runs the key-material guard before authorization side effects and the handler", () => {
    for (const route of routes) {
      const guardIndex = route.handlers.indexOf("rejectKeyMaterial");
      if (guardIndex === -1) continue;
      assert.ok(
        guardIndex < route.handlers.length - 1,
        `${route.key} must not use rejectKeyMaterial as its final handler`,
      );
      // Only the rate limiter may run first; the guard must precede the handler chain.
      assert.ok(guardIndex <= 2, `${route.key} runs rejectKeyMaterial too late (${guardIndex})`);
    }
  });

  it("covers every distribution write route", () => {
    const distribution = routes.filter((route) => route.path.includes("/distribution-"));
    const keys = distribution.map((route) => route.key).sort();
    assert.deepEqual(keys, [
      "post /api/v1/workspaces/:id/certops/distribution-groups/:groupId/consumers/:bindingId/emergency",
      "post /api/v1/workspaces/:id/certops/distribution-groups/:groupId/rollouts",
      "post /api/v1/workspaces/:id/certops/distribution-groups/:groupId/rollouts/:rolloutId/state",
      "post /api/v1/workspaces/:id/certops/distribution-jobs/:jobId/retry",
      "put /api/v1/workspaces/:id/certops/distribution-groups/:groupId/consumers/:bindingId",
      "put /api/v1/workspaces/:id/certops/distribution-groups/:groupId/consumers/:bindingId/activation-policy",
      "put /api/v1/workspaces/:id/certops/distribution-groups/:groupId/policy",
    ]);
    for (const route of distribution) {
      assert.ok(route.handlers.includes("rejectKeyMaterial"), `${route.key} must reject key material`);
    }
  });

  it("does not leave an unreviewed bodyless exception", () => {
    for (const key of BODYLESS_ALLOWLIST) {
      assert.ok(
        routes.some((route) => route.key === key && !route.handlers.includes("rejectKeyMaterial")),
        `${key} no longer exists or is now guarded; remove it from the allowlist`,
      );
    }
  });
});
