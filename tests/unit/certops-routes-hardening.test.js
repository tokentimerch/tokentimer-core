"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const routesSource = fs.readFileSync(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
  "utf8",
);
const executorRoutesSource = fs.readFileSync(
  path.resolve(__dirname, "../../apps/api/routes/certops-executor.js"),
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

function executorRouteBlock(routePath) {
  const start = executorRoutesSource.indexOf(`"${routePath}"`);
  assert.notEqual(start, -1, `POST ${routePath} not found`);

  const nextRoute = executorRoutesSource.indexOf(
    "\n  certOpsExecutorRouter.post(",
    start + 1,
  );
  const end =
    nextRoute === -1
      ? executorRoutesSource.indexOf("\n  return certOpsExecutorRouter", start)
      : nextRoute;
  assert.notEqual(end, -1, `POST ${routePath} block end not found`);
  return executorRoutesSource.slice(start, end);
}

describe("CertOps route hardening", () => {
  it("implements only the frozen workspace inventory and M2 read routes", () => {
    const routeMatches = Array.from(
      routesSource.matchAll(/router\.(get|post)\(\n\s+"([^"]+)"/g),
    ).map((match) => `${match[1].toUpperCase()} ${match[2]}`);

    assert.deepEqual(routeMatches.sort(), [
      "GET /api/v1/workspaces/:id/certops/certificates",
      "GET /api/v1/workspaces/:id/certops/certificates/:certId",
      "GET /api/v1/workspaces/:id/certops/certificates/:certId/instances",
      "GET /api/v1/workspaces/:id/certops/jobs",
      "GET /api/v1/workspaces/:id/certops/jobs/:jobId",
      "GET /api/v1/workspaces/:id/certops/jobs/:jobId/evidence",
      "GET /api/v1/workspaces/:id/certops/jobs/:jobId/log",
      "GET /api/v1/workspaces/:id/certops/tokens",
      "POST /api/v1/workspaces/:id/certops/certificates",
      "POST /api/v1/workspaces/:id/certops/certificates/:certId/retire",
      "POST /api/v1/workspaces/:id/certops/imports",
      "POST /api/v1/workspaces/:id/certops/jobs",
      "POST /api/v1/workspaces/:id/certops/tokens",
      "POST /api/v1/workspaces/:id/certops/tokens/:tokenId/revoke",
    ].sort());

    assert.equal(routesSource.includes("/api/v1/certops/executor"), false);
    assert.equal(routesSource.includes("/api/v1/certops/agent"), false);
  });

  it("gates every workspace CertOps route with certops.enabled", () => {
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
      ["get", "/api/v1/workspaces/:id/certops/jobs"],
      ["post", "/api/v1/workspaces/:id/certops/jobs"],
      ["get", "/api/v1/workspaces/:id/certops/jobs/:jobId/log"],
      ["get", "/api/v1/workspaces/:id/certops/jobs/:jobId/evidence"],
      ["get", "/api/v1/workspaces/:id/certops/jobs/:jobId"],
      ["get", "/api/v1/workspaces/:id/certops/tokens"],
      ["post", "/api/v1/workspaces/:id/certops/tokens"],
      ["post", "/api/v1/workspaces/:id/certops/tokens/:tokenId/revoke"],
    ]) {
      assert.match(routeBlock(method, routePath), /requireCertOpsEnabled/);
    }
  });

  it("requires manager role for CertOps API token metadata enumeration", () => {
    // Token metadata enumeration (names, prefixes, scopes, status) must be
    // manager-only, matching token create/revoke, so viewers cannot enumerate
    // machine tokens by calling the API directly.
    const block = routeBlock("get", "/api/v1/workspaces/:id/certops/tokens");
    assert.ok(
      block.indexOf("requireCertOpsEnabled") <
        block.indexOf("requireCertOpsWriteRole"),
      "GET /certops/tokens must check the rollout gate before manager authorization",
    );
  });

  it("declares specific child routes before generic detail routes", () => {
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

    const logIndex = routesSource.indexOf(
      '"/api/v1/workspaces/:id/certops/jobs/:jobId/log"',
    );
    const evidenceIndex = routesSource.indexOf(
      '"/api/v1/workspaces/:id/certops/jobs/:jobId/evidence"',
    );
    const jobDetailIndex = routesSource.indexOf(
      '"/api/v1/workspaces/:id/certops/jobs/:jobId"',
    );
    assert.notEqual(logIndex, -1);
    assert.notEqual(evidenceIndex, -1);
    assert.notEqual(jobDetailIndex, -1);
    assert.ok(
      logIndex < jobDetailIndex,
      "job log route must be declared before generic job detail",
    );
    assert.ok(
      evidenceIndex < jobDetailIndex,
      "job evidence route must be declared before generic job detail",
    );
  });

  it("runs private-key rejection before feature gating on write routes", () => {
    for (const routePath of [
      "/api/v1/workspaces/:id/certops/certificates",
      "/api/v1/workspaces/:id/certops/certificates/:certId/retire",
      "/api/v1/workspaces/:id/certops/imports",
      "/api/v1/workspaces/:id/certops/jobs",
      "/api/v1/workspaces/:id/certops/tokens",
      "/api/v1/workspaces/:id/certops/tokens/:tokenId/revoke",
    ]) {
      const block = routeBlock("post", routePath);
      assert.ok(
        block.indexOf("rejectKeyMaterial") <
          block.indexOf("requireCertOpsEnabled"),
        `${routePath} must reject private key material before the rollout gate`,
      );
      const authorizationMiddleware = routePath.includes("/certops/tokens")
        ? "requireCertOpsTokenManager"
        : "requireCertOpsWriteRole";
      assert.ok(
        block.indexOf("requireCertOpsEnabled") <
          block.indexOf(authorizationMiddleware),
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
    assertOpenApiRoute("/api/v1/workspaces/{id}/certops/jobs", "GET");
    assertOpenApiRoute("/api/v1/workspaces/{id}/certops/jobs/{jobId}", "GET");
    assertOpenApiRoute(
      "/api/v1/workspaces/{id}/certops/jobs/{jobId}/log",
      "GET",
    );
    assertOpenApiRoute(
      "/api/v1/workspaces/{id}/certops/jobs/{jobId}/evidence",
      "GET",
    );
    assertOpenApiRoute("/api/v1/workspaces/{id}/certops/tokens", "GET");
    assertOpenApiRoute("/api/v1/workspaces/{id}/certops/tokens", "POST");
    assertOpenApiRoute(
      "/api/v1/workspaces/{id}/certops/tokens/{tokenId}/revoke",
      "POST",
    );
    assertOpenApiRoute("/api/v1/certops/executor/events", "POST");
    assertOpenApiRoute("/api/v1/certops/jobs/{jobId}/events", "POST");
    assertOpenApiRoute("/api/v1/certops/jobs/{jobId}/evidence", "POST");
  });

  it("keeps machine-token executor writes in the executor router", () => {
    const aggregateBlock = executorRouteBlock(
      "/api/v1/certops/executor/events",
    );
    const perJobEventsBlock = executorRouteBlock(
      "/api/v1/certops/jobs/:jobId/events",
    );
    const perJobEvidenceBlock = executorRouteBlock(
      "/api/v1/certops/jobs/:jobId/evidence",
    );

    assert.match(aggregateBlock, /authMiddleware/);
    assert.match(aggregateBlock, /rateLimitMiddleware/);
    assert.match(perJobEventsBlock, /perJobEventAuthMiddleware/);
    assert.match(perJobEventsBlock, /rateLimitMiddleware/);
    assert.match(perJobEventsBlock, /mode: "event"/);
    assert.match(perJobEvidenceBlock, /perJobEvidenceAuthMiddleware/);
    assert.match(perJobEvidenceBlock, /rateLimitMiddleware/);
    assert.match(perJobEvidenceBlock, /mode: "evidence"/);
    assert.match(executorRoutesSource, /allowTokenWorkspace: true/);
    assert.match(executorRoutesSource, /certops:events:write/);
    assert.match(executorRoutesSource, /certops:evidence:write/);

    assert.equal(routesSource.includes("/api/v1/certops/jobs/:jobId"), false);
  });
});
