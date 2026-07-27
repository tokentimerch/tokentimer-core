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
const apiIndexSource = fs.readFileSync(
  path.resolve(__dirname, "../../apps/api/index.js"),
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

function openApiOperationBlock(documentedPath, method) {
  const pathStart = openApiSource.indexOf(`\n  ${documentedPath}:\n`);
  assert.notEqual(pathStart, -1, `${documentedPath} missing from OpenAPI paths`);
  const nextPath = openApiSource.indexOf("\n  /", pathStart + 1);
  const pathBlock = openApiSource.slice(
    pathStart,
    nextPath === -1 ? undefined : nextPath,
  );

  const methodStart = pathBlock.indexOf(`\n    ${method}:\n`);
  assert.notEqual(
    methodStart,
    -1,
    `${method.toUpperCase()} ${documentedPath} missing from OpenAPI`,
  );
  const nextMethod = pathBlock.slice(methodStart + 1).search(/\n {4}[a-z]+:\n/);
  return nextMethod === -1
    ? pathBlock.slice(methodStart)
    : pathBlock.slice(methodStart, methodStart + 1 + nextMethod);
}

function openApiSchemaBlock(schemaName) {
  const start = openApiSource.indexOf(`\n    ${schemaName}:\n`);
  assert.notEqual(start, -1, `${schemaName} missing from OpenAPI schemas`);
  const next = openApiSource.slice(start + 1).search(/\n {4}[A-Za-z]/);
  return next === -1
    ? openApiSource.slice(start)
    : openApiSource.slice(start, start + 1 + next);
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
  it("allows the provisioning idempotency header through split-host CORS", () => {
    assert.match(
      apiIndexSource,
      /allowedHeaders:\s*\[[\s\S]*?"Idempotency-Key"[\s\S]*?\]/,
    );
  });

  it("implements only the frozen workspace, executor, and controller routes", () => {
    // patch/delete are matched too: the point of this guard is that no new
    // workspace CertOps route appears without being reviewed here, and a
    // method-limited regex would let a mutating PATCH land unnoticed.
    const routeMatches = Array.from(
      routesSource.matchAll(/router\.(get|post|put|patch|delete)\(\n\s+"([^"]+)"/g),
    ).map((match) => `${match[1].toUpperCase()} ${match[2]}`);

    assert.deepEqual(routeMatches.sort(), [
      "DELETE /api/v1/workspaces/:id/certops/certificates/:certId/profile",
      "GET /api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
      "GET /api/v1/workspaces/:id/certops/agents",
      "GET /api/v1/workspaces/:id/certops/certificates",
      "GET /api/v1/workspaces/:id/certops/certificates/:certId",
      "GET /api/v1/workspaces/:id/certops/certificates/:certId/instances",
      "GET /api/v1/workspaces/:id/certops/instances",
      "GET /api/v1/workspaces/:id/certops/jobs",
      "GET /api/v1/workspaces/:id/certops/jobs/:jobId",
      "GET /api/v1/workspaces/:id/certops/jobs/:jobId/evidence",
      "GET /api/v1/workspaces/:id/certops/jobs/:jobId/log",
      "GET /api/v1/workspaces/:id/certops/profiles",
      "GET /api/v1/workspaces/:id/certops/profiles/:profileId",
      "GET /api/v1/workspaces/:id/certops/renewals/upcoming",
      "GET /api/v1/workspaces/:id/certops/tokens",
      "GET /api/v1/workspaces/:id/certops/settings",
      "GET /api/v1/workspaces/:id/certops/targets",
      "PATCH /api/v1/workspaces/:id/certops/profiles/:profileId",
      "POST /api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
      "POST /api/v1/workspaces/:id/certops/agent-bootstrap-tokens/:tokenId/revoke",
      "POST /api/v1/workspaces/:id/certops/agents/:agentId/retire",
      "POST /api/v1/workspaces/:id/certops/certificates",
      "POST /api/v1/workspaces/:id/certops/certificates/:certId/renewal-setup",
      "POST /api/v1/workspaces/:id/certops/certificates/:certId/retire",
      "POST /api/v1/workspaces/:id/certops/imports",
      "POST /api/v1/workspaces/:id/certops/jobs",
      "POST /api/v1/workspaces/:id/certops/jobs/:jobId/approve",
      "POST /api/v1/workspaces/:id/certops/jobs/:jobId/reject",
      "POST /api/v1/workspaces/:id/certops/jobs/bulk-renew",
      "POST /api/v1/workspaces/:id/certops/provision-intents",
      "POST /api/v1/workspaces/:id/certops/renewal-setup-intents/:outboxId/retry",
      "POST /api/v1/workspaces/:id/certops/tokens",
      "POST /api/v1/workspaces/:id/certops/tokens/:tokenId/revoke",
      "PUT /api/v1/workspaces/:id/certops/settings",
    ].sort());

    assert.equal(routesSource.includes("/api/v1/certops/executor"), false);
    assert.equal(routesSource.includes("/api/v1/certops/agent"), false);
  });

  it("gates renewal-profile reads on at least workspace_manager", () => {
    // A profile body carries deployment topology: certPath, keyPath,
    // reloadService, deployment owner/group, ACME command refs, CA account refs
    // and the DNS zone. That is host reconnaissance, not expiry metadata, so it
    // sits with the agent and machine-token routes rather than the certificates
    // inventory. This was originally shipped ungated, which let a viewer read
    // every host path in the workspace; the dashboard already gated /certops/*
    // at manager, so the API was the weaker of the two.
    for (const routePath of [
      "/api/v1/workspaces/:id/certops/profiles",
      "/api/v1/workspaces/:id/certops/profiles/:profileId",
      "/api/v1/workspaces/:id/certops/renewals/upcoming",
    ]) {
      const block = routeBlock("get", routePath);
      assert.match(
        block,
        /requireCertOpsWriteRole/,
        `${routePath} must not be readable below workspace_manager`,
      );
      assert.ok(
        block.indexOf("requireCertOpsEnabled") <
          block.indexOf("requireCertOpsWriteRole"),
        `${routePath} must check the rollout gate before manager authorization`,
      );
    }
  });

  it("gates renewal-profile editing on admin role and a human session", () => {
    // A profile edit changes what a host-privileged agent executes at the next
    // renewal, so it needs a strictly stronger gate than ordinary CertOps job
    // creation (workspace_manager) and must never be reachable by an internal
    // worker credential.
    const block = routeBlock(
      "patch",
      "/api/v1/workspaces/:id/certops/profiles/:profileId",
    );
    assert.match(block, /authorize\("certops\.renewal_profile\.manage"\)/);
    assert.match(block, /requireCertOpsSessionUser/);
    assert.ok(
      block.indexOf("rejectKeyMaterial") <
        block.indexOf("requireCertOpsSessionUser"),
      "profile PATCH must reject key material before session-user denial",
    );
    assert.ok(
      block.indexOf("requireCertOpsSessionUser") <
        block.indexOf('authorize("certops.renewal_profile.manage")'),
      "profile PATCH must require a human session before role authorization",
    );
    assert.ok(
      block.indexOf("requireCertOpsEnabled") <
        block.indexOf('authorize("certops.renewal_profile.manage")'),
      "profile PATCH must check the rollout gate before authorization",
    );
  });

  it("maps the renewal-profile permission to admin in shared RBAC", () => {
    const rbacSource = fs.readFileSync(
      path.resolve(__dirname, "../../apps/api/services/rbac.js"),
      "utf8",
    );
    assert.match(
      rbacSource,
      /"certops\.renewal_profile\.manage":\s*"admin"/,
      "renewal-profile editing must be admin-gated; can() denies unknown actions, so a missing entry would 403 instead of silently allowing, but an accidental downgrade to workspace_manager would not",
    );
  });

  it("declares the upcoming-renewals route before the generic profile detail route", () => {
    // /profiles/:profileId would otherwise swallow nothing here, but
    // /renewals/upcoming shares no prefix with it; the ordering that matters is
    // profiles list before profiles detail, asserted via index comparison.
    const listIndex = routesSource.indexOf(
      '"/api/v1/workspaces/:id/certops/profiles"',
    );
    const detailIndex = routesSource.indexOf(
      '"/api/v1/workspaces/:id/certops/profiles/:profileId"',
    );
    assert.notEqual(listIndex, -1);
    assert.notEqual(detailIndex, -1);
    assert.ok(
      listIndex < detailIndex,
      "profiles list route must be declared before generic profile detail",
    );
  });

  it("gates operational workspace CertOps routes with certops.enabled", () => {
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
      ["get", "/api/v1/workspaces/:id/certops/instances"],
      ["get", "/api/v1/workspaces/:id/certops/targets"],
      ["post", "/api/v1/workspaces/:id/certops/imports"],
      ["get", "/api/v1/workspaces/:id/certops/jobs"],
      ["post", "/api/v1/workspaces/:id/certops/jobs"],
      ["post", "/api/v1/workspaces/:id/certops/jobs/bulk-renew"],
      ["post", "/api/v1/workspaces/:id/certops/provision-intents"],
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

  it("keeps workspace kill-switch settings available while rollout is disabled", () => {
    for (const [method, routePath] of [
      ["get", "/api/v1/workspaces/:id/certops/settings"],
      ["put", "/api/v1/workspaces/:id/certops/settings"],
    ]) {
      assert.doesNotMatch(routeBlock(method, routePath), /requireCertOpsEnabled/);
    }
  });

  it("requires a human session user for both workspace kill-switch settings routes", () => {
    for (const [method, routePath] of [
      ["get", "/api/v1/workspaces/:id/certops/settings"],
      ["put", "/api/v1/workspaces/:id/certops/settings"],
    ]) {
      assert.match(
        routeBlock(method, routePath),
        /requireCertOpsSessionUser/,
        `${method.toUpperCase()} settings must reject internal worker credentials`,
      );
    }

    const putBlock = routeBlock("put", "/api/v1/workspaces/:id/certops/settings");
    assert.ok(
      putBlock.indexOf("rejectKeyMaterial") <
        putBlock.indexOf("requireCertOpsSessionUser"),
      "settings PUT must reject key material before session-user denial",
    );
    assert.ok(
      putBlock.indexOf("requireCertOpsSessionUser") <
        putBlock.indexOf('authorize("certops.kill_switch.manage")'),
      "settings PUT must require a human session before role authorization",
    );
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

  it("reads limit and offset on every paginated CertOps list route", () => {
    for (const routePath of [
      "/api/v1/workspaces/:id/certops/certificates",
      "/api/v1/workspaces/:id/certops/agents",
      "/api/v1/workspaces/:id/certops/tokens",
      "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
    ]) {
      const block = routeBlock("get", routePath);
      assert.match(
        block,
        /limit: req\.query\.limit/,
        `GET ${routePath} must forward limit`,
      );
      assert.match(
        block,
        /offset: req\.query\.offset/,
        `GET ${routePath} must forward offset`,
      );
    }

    // The jobs list reads its query through a shared options builder.
    assert.match(
      routesSource,
      /function jobListOptionsFromRequest\(req\)[\s\S]*?limit: req\.query\.limit[\s\S]*?offset: req\.query\.offset/,
    );
  });

  it("documents the unbounded lists with a limit that has no default", () => {
    // The runtime default for these three is still unlimited because none of
    // them has a paging control yet. A spec promising default: 50 would make a
    // conforming client page a list that returns everything.
    for (const documentedPath of [
      "/api/v1/workspaces/{id}/certops/agents",
      "/api/v1/workspaces/{id}/certops/tokens",
      "/api/v1/workspaces/{id}/certops/agent-bootstrap-tokens",
    ]) {
      const block = openApiOperationBlock(documentedPath, "get");
      assert.ok(
        block.includes(
          '$ref: "#/components/parameters/certOpsUnboundedListLimitParam"',
        ),
        `GET ${documentedPath} must document limit without a default`,
      );
      assert.equal(
        block.includes(
          '$ref: "#/components/parameters/certOpsReadLimitParam"',
        ),
        false,
        `GET ${documentedPath} must not claim the 50-row default`,
      );
    }

    const unboundedParam = openApiSource.slice(
      openApiSource.indexOf("    certOpsUnboundedListLimitParam:"),
    );
    const paramBlock = unboundedParam.slice(
      0,
      unboundedParam.indexOf("\n    certOpsCertificate"),
    );
    assert.equal(paramBlock.includes("default:"), false);
    assert.ok(paramBlock.includes("maximum: 100"));
  });

  it("documents the clamped CertOps read lists with the shared 50/100 parameters", () => {
    for (const documentedPath of [
      "/api/v1/workspaces/{id}/certops/certificates",
      "/api/v1/workspaces/{id}/certops/jobs",
      "/api/v1/workspaces/{id}/certops/profiles",
      "/api/v1/workspaces/{id}/certops/renewals/upcoming",
    ]) {
      const block = openApiOperationBlock(documentedPath, "get");
      assert.ok(
        block.includes(
          '$ref: "#/components/parameters/certOpsReadLimitParam"',
        ),
        `GET ${documentedPath} must document the real limit clamp`,
      );
      assert.ok(
        block.includes(
          '$ref: "#/components/parameters/certOpsReadOffsetParam"',
        ),
        `GET ${documentedPath} must document the real offset default`,
      );
    }
  });

  it("documents the certificate filters the list route applies in SQL", () => {
    const block = openApiOperationBlock(
      "/api/v1/workspaces/{id}/certops/certificates",
      "get",
    );
    for (const parameterName of [
      "certOpsCertificateStatusFilterParam",
      "certOpsCertificateSourceFilterParam",
      "certOpsCertificateNoRenewalProfileParam",
      "certOpsCertificateRenewalDisabledParam",
      "certOpsCertificateKeyNotAgentDeployableParam",
    ]) {
      assert.ok(
        block.includes(`$ref: "#/components/parameters/${parameterName}"`),
        `certificates list must document ${parameterName}`,
      );
      assert.ok(
        openApiSource.includes(`    ${parameterName}:`),
        `${parameterName} must be defined under components.parameters`,
      );
    }

    assert.ok(
      block.includes('"400":'),
      "an out-of-constraint filter value must be documented as a 400",
    );

    const routeBlockSource = routeBlock(
      "get",
      "/api/v1/workspaces/:id/certops/certificates",
    );
    for (const queryField of [
      "status: req.query.status",
      "source: req.query.source",
      "noRenewalProfile: req.query.noRenewalProfile",
      "renewalDisabled: req.query.renewalDisabled",
      "keyNotAgentDeployable: req.query.keyNotAgentDeployable",
    ]) {
      assert.ok(
        routeBlockSource.includes(queryField),
        `certificates list route must forward ${queryField}`,
      );
    }
  });

  it("returns a real total in every paginated CertOps list schema", () => {
    for (const schemaName of [
      "CertOpsManagedCertificateListResponse",
      "CertOpsJobListResponse",
      "CertOpsWorkspaceAgentListResponse",
      "CertOpsApiTokenListResponse",
      "CertOpsAgentBootstrapTokenListResponse",
    ]) {
      const block = openApiSchemaBlock(schemaName);
      assert.match(
        block,
        /pagination:\s*\n\s*\$ref: "#\/components\/schemas\/CertOps(Unbounded)?ListPagination"/,
        `${schemaName} must use a pagination schema carrying total`,
      );
    }

    for (const paginationSchema of [
      "CertOpsListPagination",
      "CertOpsUnboundedListPagination",
    ]) {
      const block = openApiSchemaBlock(paginationSchema);
      assert.match(block, /required: \[limit, offset, total\]/);
    }

    // The renewal routes keep their flat fields for shipped clients and gain
    // the nested object every other CertOps list returns.
    for (const schemaName of [
      "CertOpsRenewalProfileList",
      "CertOpsUpcomingRenewalList",
    ]) {
      const block = openApiSchemaBlock(schemaName);
      assert.match(block, /required: \[items, total, limit, offset, pagination\]/);
      assert.ok(
        block.includes('$ref: "#/components/schemas/CertOpsListPagination"'),
      );
    }

    // hasMore would be a second source of truth able to disagree with total,
    // so no CertOps list envelope carries one.
    for (const schemaName of [
      "CertOpsManagedCertificateListResponse",
      "CertOpsJobListResponse",
      "CertOpsWorkspaceAgentListResponse",
      "CertOpsApiTokenListResponse",
      "CertOpsAgentBootstrapTokenListResponse",
      "CertOpsRenewalProfileList",
      "CertOpsUpcomingRenewalList",
      "CertOpsListPagination",
      "CertOpsUnboundedListPagination",
    ]) {
      assert.equal(
        openApiSchemaBlock(schemaName).includes("hasMore"),
        false,
        `${schemaName} must not carry hasMore alongside total`,
      );
    }
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

  it("runs private-key rejection before rollout gating and authorization on write routes", () => {
    for (const [method, routePath] of [
      ["post", "/api/v1/workspaces/:id/certops/certificates"],
      ["post", "/api/v1/workspaces/:id/certops/certificates/:certId/retire"],
      ["post", "/api/v1/workspaces/:id/certops/imports"],
      ["put", "/api/v1/workspaces/:id/certops/settings"],
      ["post", "/api/v1/workspaces/:id/certops/jobs"],
      ["post", "/api/v1/workspaces/:id/certops/jobs/bulk-renew"],
      ["post", "/api/v1/workspaces/:id/certops/tokens"],
      ["post", "/api/v1/workspaces/:id/certops/tokens/:tokenId/revoke"],
    ]) {
      const block = routeBlock(method, routePath);
      const authorizationMiddleware = routePath.endsWith("/certops/settings")
        ? 'authorize("certops.kill_switch.manage")'
        : routePath.includes("/certops/tokens")
          ? "requireCertOpsTokenManager"
          : "requireCertOpsWriteRole";
      assert.ok(
        block.indexOf("rejectKeyMaterial") < block.indexOf(authorizationMiddleware),
        `${routePath} must reject private key material before write authorization`,
      );
      if (routePath.endsWith("/certops/settings")) {
        assert.ok(
          block.indexOf("rejectKeyMaterial") <
            block.indexOf("requireCertOpsSessionUser"),
          `${routePath} must reject private key material before session-user denial`,
        );
      }
      if (!routePath.endsWith("/certops/settings")) {
        assert.ok(
          block.indexOf("rejectKeyMaterial") <
            block.indexOf("requireCertOpsEnabled"),
          `${routePath} must reject private key material before the rollout gate`,
        );
        assert.ok(
          block.indexOf("requireCertOpsEnabled") <
            block.indexOf(authorizationMiddleware),
          `${routePath} must check the rollout gate before write authorization`,
        );
      }
    }
  });

  it("applies the workspace pause gate only to manual CertOps job creation", () => {
    const createBlock = routeBlock(
      "post",
      "/api/v1/workspaces/:id/certops/jobs",
    );
    assert.match(createBlock, /requireWorkspaceCertOpsActive/);
    assert.match(createBlock, /createManualCertificateJob/);
    assert.doesNotMatch(createBlock, /createCertificateJob/);
    assert.ok(
      createBlock.indexOf("requireCertOpsWriteRole") <
        createBlock.indexOf("requireWorkspaceCertOpsActive"),
      "role authorization must run before the pause gate",
    );

    const bulkRenewBlock = routeBlock(
      "post",
      "/api/v1/workspaces/:id/certops/jobs/bulk-renew",
    );
    assert.match(bulkRenewBlock, /requireWorkspaceCertOpsActive/);
    assert.match(bulkRenewBlock, /bulkRenewCertificatesHandler/);
    assert.ok(
      bulkRenewBlock.indexOf("requireCertOpsWriteRole") <
        bulkRenewBlock.indexOf("requireWorkspaceCertOpsActive"),
      "bulk renew role authorization must run before the pause gate",
    );

    for (const [method, routePath] of [
      ["get", "/api/v1/workspaces/:id/certops/jobs"],
      ["get", "/api/v1/workspaces/:id/certops/jobs/:jobId"],
      ["get", "/api/v1/workspaces/:id/certops/jobs/:jobId/evidence"],
      ["get", "/api/v1/workspaces/:id/certops/jobs/:jobId/log"],
    ]) {
      assert.doesNotMatch(
        routeBlock(method, routePath),
        /requireWorkspaceCertOpsActive/,
        `${routePath} is a passive read and must remain available while paused`,
      );
    }
  });

  it("keeps workspace existence policy generic in shared RBAC", () => {
    const rbacSource = fs.readFileSync(
      path.resolve(__dirname, "../../apps/api/services/rbac.js"),
      "utf8",
    );
    const indexSource = fs.readFileSync(
      path.resolve(__dirname, "../../apps/api/index.js"),
      "utf8",
    );
    const markerIndex = indexSource.indexOf(
      '"/api/v1/workspaces/:id/certops/settings"',
    );
    const workspaceMembershipIndex = indexSource.indexOf(
      '"/api/v1/workspaces/:id",',
    );

    assert.match(rbacSource, /workspaceAccessPolicy\?\.hideExistence/);
    assert.doesNotMatch(rbacSource, /certops\/settings/i);
    assert.ok(markerIndex !== -1 && markerIndex < workspaceMembershipIndex);
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
    assertOpenApiRoute("/api/v1/certops/executor/observations", "POST");
    assertOpenApiRoute("/api/v1/certops/executor/provisioning-commands/next", "POST");
    assertOpenApiRoute(
      "/api/v1/certops/executor/provisioning-commands/{jobId}/authorize-mutation",
      "POST",
    );
    assertOpenApiRoute("/api/v1/workspaces/{id}/certops/provision-intents", "POST");
    assertOpenApiRoute("/api/v1/certops/jobs/{jobId}/events", "POST");
    assertOpenApiRoute("/api/v1/certops/jobs/{jobId}/evidence", "POST");
  });

  it("keeps machine-token executor writes in the executor router", () => {
    const observationBlock = executorRouteBlock(
      "/api/v1/certops/executor/observations",
    );
    const provisioningBlock = executorRouteBlock(
      "/api/v1/certops/executor/provisioning-commands/next",
    );
    const provisioningAuthorizationBlock = executorRouteBlock(
      "/api/v1/certops/executor/provisioning-commands/:jobId/authorize-mutation",
    );
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
    assert.match(observationBlock, /controllerObservationAuthMiddleware/);
    assert.match(observationBlock, /rejectControllerObservationPrivateMaterial/);
    assert.match(observationBlock, /controllerObservationGateMiddleware/);
    assert.match(observationBlock, /requireControllerObservationScope/);
    assert.match(provisioningBlock, /controllerProvisioningAuthMiddleware/);
    assert.match(provisioningBlock, /rejectControllerProvisioningPrivateMaterial/);
    assert.match(provisioningBlock, /requireControllerProvisioningScope/);
    assert.match(provisioningAuthorizationBlock, /controllerProvisioningAuthMiddleware/);
    assert.match(provisioningAuthorizationBlock, /rejectControllerProvisioningPrivateMaterial/);
    assert.match(provisioningAuthorizationBlock, /certOpsEnabledMiddleware/);
    assert.match(provisioningAuthorizationBlock, /controllerProvisioningGateMiddleware/);
    assert.match(provisioningAuthorizationBlock, /requireControllerProvisioningScope/);
    assert.match(
      provisioningAuthorizationBlock,
      /controllerProvisioningMutationAuthorizationHandler/,
    );
    for (const [before, after] of [
      ["controllerProvisioningAuthMiddleware", "rejectControllerProvisioningPrivateMaterial"],
      ["rejectControllerProvisioningPrivateMaterial", "certOpsEnabledMiddleware"],
      ["certOpsEnabledMiddleware", "controllerProvisioningGateMiddleware"],
      ["controllerProvisioningGateMiddleware", "requireControllerProvisioningScope"],
      ["requireControllerProvisioningScope", "controllerProvisioningMutationAuthorizationHandler"],
    ]) {
      assert.ok(
        provisioningAuthorizationBlock.indexOf(before) <
          provisioningAuthorizationBlock.indexOf(after),
        `${before} must precede ${after}`,
      );
    }
    assert.match(executorRoutesSource, /CONTROLLER_OBSERVATION_SCOPE = OBSERVATION_WRITE_SCOPE/);

    assert.equal(routesSource.includes("/api/v1/certops/jobs/:jobId"), false);
  });

  it("keeps controller observations passive and key-rejection-first", () => {
    const block = executorRouteBlock("/api/v1/certops/executor/observations");
    assert.ok(
      block.indexOf("controllerObservationAuthMiddleware") <
        block.indexOf("rejectControllerObservationPrivateMaterial"),
    );
    assert.ok(
      block.indexOf("rejectControllerObservationPrivateMaterial") <
        block.indexOf("certOpsEnabledMiddleware"),
    );
    assert.ok(
      block.indexOf("certOpsEnabledMiddleware") <
        block.indexOf("controllerObservationGateMiddleware"),
    );
    assert.ok(
      block.indexOf("controllerObservationGateMiddleware") <
        block.indexOf("requireControllerObservationScope"),
    );
    assert.doesNotMatch(block, /requireWorkspaceCertOpsActive/);
  });
});
