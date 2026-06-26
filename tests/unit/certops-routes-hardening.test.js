"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const routesSource = fs.readFileSync(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
  "utf8",
);

function routeBlock(method, routePath) {
  const start = routesSource.indexOf(`router.${method}(\n  "${routePath}"`);
  assert.notEqual(start, -1, `${method.toUpperCase()} ${routePath} not found`);

  const nextRoute = routesSource.indexOf("\nrouter.", start + 1);
  const end =
    nextRoute === -1
      ? routesSource.indexOf("\nmodule.exports", start)
      : nextRoute;
  assert.notEqual(
    end,
    -1,
    `${method.toUpperCase()} ${routePath} block end not found`,
  );
  return routesSource.slice(start, end);
}

describe("CertOps M1 route hardening", () => {
  it("implements only the frozen M1 workspace inventory routes", () => {
    const routeMatches = Array.from(
      routesSource.matchAll(/router\.(get|post)\(\n\s+"([^"]+)"/g),
    ).map((match) => `${match[1].toUpperCase()} ${match[2]}`);

    assert.deepEqual(routeMatches.sort(), [
      "GET /api/v1/workspaces/:id/certops/certificates",
      "GET /api/v1/workspaces/:id/certops/certificates/:certId",
      "POST /api/v1/workspaces/:id/certops/certificates",
      "POST /api/v1/workspaces/:id/certops/imports",
    ].sort());

    assert.equal(routesSource.includes("/api/v1/certops/executor"), false);
    assert.equal(routesSource.includes("/api/v1/certops/agent"), false);
  });

  it("gates every inventory route with certops.enabled", () => {
    for (const [method, routePath] of [
      ["get", "/api/v1/workspaces/:id/certops/certificates"],
      ["post", "/api/v1/workspaces/:id/certops/certificates"],
      ["get", "/api/v1/workspaces/:id/certops/certificates/:certId"],
      ["post", "/api/v1/workspaces/:id/certops/imports"],
    ]) {
      assert.match(routeBlock(method, routePath), /requireCertOpsEnabled/);
    }
  });

  it("runs private-key rejection before feature gating on write routes", () => {
    for (const routePath of [
      "/api/v1/workspaces/:id/certops/certificates",
      "/api/v1/workspaces/:id/certops/imports",
    ]) {
      const block = routeBlock("post", routePath);
      assert.ok(
        block.indexOf("rejectKeyMaterial") <
          block.indexOf("requireCertOpsEnabled"),
        `${routePath} must reject private key material before the rollout gate`,
      );
      assert.ok(
        block.indexOf("requireCertOpsEnabled") <
          block.indexOf("requireCertOpsWriteRole"),
        `${routePath} must check the rollout gate before write authorization`,
      );
    }
  });
});
