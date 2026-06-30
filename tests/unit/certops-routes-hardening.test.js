"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const routesSource = fs.readFileSync(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
  "utf8",
);
const routeCompatContract = require("../../packages/contracts/api/certops-route-compat.contract.json");
const openApiSource = fs.readFileSync(
  path.resolve(__dirname, "../../packages/contracts/openapi/openapi.yaml"),
  "utf8",
);

function parseOpenApiPathMethods(source) {
  const paths = new Map();
  let inPaths = false;
  let currentPath = null;

  for (const line of source.split(/\r?\n/)) {
    if (line === "paths:") {
      inPaths = true;
      continue;
    }

    if (inPaths && /^[A-Za-z][^:]*:\s*$/.test(line)) break;

    const pathMatch = line.match(/^  (\/[^:]+):\s*$/);
    if (pathMatch) {
      currentPath = pathMatch[1];
      paths.set(currentPath, new Set());
      continue;
    }

    const methodMatch = line.match(
      /^    (get|post|put|patch|delete|options|head|trace):\s*$/,
    );
    if (currentPath && methodMatch) {
      paths.get(currentPath).add(methodMatch[1].toUpperCase());
    }
  }

  return paths;
}

const openApiPathMethods = parseOpenApiPathMethods(openApiSource);

function assertOpenApiRoute(routePath, method) {
  const methods = openApiPathMethods.get(routePath);
  assert.ok(methods, `${routePath} missing from OpenAPI paths`);
  assert.ok(
    methods.has(method.toUpperCase()),
    `${method.toUpperCase()} ${routePath} missing from OpenAPI paths`,
  );
}

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
      "GET /api/v1/workspaces/:id/certops/certificates/:certId/instances",
      "POST /api/v1/workspaces/:id/certops/certificates",
      "POST /api/v1/workspaces/:id/certops/certificates/:certId/retire",
      "POST /api/v1/workspaces/:id/certops/imports",
    ].sort());

    assert.equal(routesSource.includes("/api/v1/certops/executor"), false);
    assert.equal(routesSource.includes("/api/v1/certops/agent"), false);
  });

  it("gates every inventory route with certops.enabled", () => {
    for (const [method, routePath] of [
      ["get", "/api/v1/workspaces/:id/certops/certificates"],
      ["post", "/api/v1/workspaces/:id/certops/certificates"],
      [
        "get",
        "/api/v1/workspaces/:id/certops/certificates/:certId/instances",
      ],
      [
        "post",
        "/api/v1/workspaces/:id/certops/certificates/:certId/retire",
      ],
      ["get", "/api/v1/workspaces/:id/certops/certificates/:certId"],
      ["post", "/api/v1/workspaces/:id/certops/imports"],
    ]) {
      assert.match(routeBlock(method, routePath), /requireCertOpsEnabled/);
    }
  });

  it("declares specific certificate child routes before generic certificate detail", () => {
    const instancesIndex = routesSource.indexOf(
      '"/api/v1/workspaces/:id/certops/certificates/:certId/instances"',
    );
    const retireIndex = routesSource.indexOf(
      '"/api/v1/workspaces/:id/certops/certificates/:certId/retire"',
    );
    const detailIndex = routesSource.indexOf(
      '"/api/v1/workspaces/:id/certops/certificates/:certId"',
    );

    assert.notEqual(instancesIndex, -1);
    assert.notEqual(retireIndex, -1);
    assert.notEqual(detailIndex, -1);
    assert.ok(
      instancesIndex < detailIndex,
      "instance history route must be declared before generic certificate detail",
    );
    assert.ok(
      retireIndex < detailIndex,
      "retire route must be declared before generic certificate detail",
    );
  });

  it("runs private-key rejection before feature gating on write routes", () => {
    for (const routePath of [
      "/api/v1/workspaces/:id/certops/certificates",
      "/api/v1/workspaces/:id/certops/certificates/:certId/retire",
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

  it("keeps the route-compat contract and OpenAPI path skeletons aligned", () => {
    const { namespacePolicy, routeAuth, guarantees } = routeCompatContract;
    const stableRoutes = guarantees.stableRoutes;
    const stableRouteByPath = new Map(
      stableRoutes.map((route) => [route.path, route]),
    );

    for (const route of stableRoutes) {
      assertOpenApiRoute(route.path, route.method);

      if (route.path.startsWith("/api/v1/workspaces/")) {
        assert.ok(
          route.path.startsWith(namespacePolicy.workspaceScoped.prefix),
          `${route.path} is outside the workspace CertOps namespace`,
        );
      }

      if (route.path.startsWith("/api/v1/certops/executor")) {
        assert.ok(
          route.path.startsWith(namespacePolicy.executor.prefix),
          `${route.path} is outside the executor CertOps namespace`,
        );
      }

      if (route.path.startsWith("/api/v1/certops/agent")) {
        assert.ok(
          route.path.startsWith(namespacePolicy.agent.prefix),
          `${route.path} is outside the agent CertOps namespace`,
        );
      }
    }

    for (const [routePath, authScheme] of Object.entries(routeAuth)) {
      const route = stableRouteByPath.get(routePath);
      assert.ok(route, `${routePath} routeAuth entry is not a stable route`);
      assertOpenApiRoute(routePath, route.method);
      assert.ok(
        openApiSource.includes(`${authScheme}:`),
        `${authScheme} missing from OpenAPI security schemes or route security`,
      );
    }

    assertOpenApiRoute(
      "/api/v1/workspaces/{id}/certops/certificates/{certId}/instances",
      "GET",
    );
    assertOpenApiRoute(
      "/api/v1/workspaces/{id}/certops/certificates/{certId}/retire",
      "POST",
    );
  });
});
