"use strict";

// Route-level proof that operator connection credentials can reach only the
// operator namespace (ADR-0015 section 3). The inventory test loads every real
// router, so a route added later is covered without anyone remembering to list
// it.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const express = require("../../apps/api/node_modules/express");
const request = require("supertest");

const auth = require(
  path.resolve(__dirname, "../../apps/api/middleware/operator-connection-auth.js"),
);
const csrfExempt = require(
  path.resolve(__dirname, "../../apps/api/middleware/csrf-exempt.js"),
);

const ID = "0123456789abcdef";
const OPERATOR = `ttopc_${ID}_${"a".repeat(64)}`;
const EXECUTOR = `ttx_${ID}_${"b".repeat(64)}`;

function mockRes() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

function req({ url = "/api/v1/operator/whoami", authorization, headers = {}, ...rest } = {}) {
  const lower = { ...headers };
  if (authorization !== undefined) lower.authorization = authorization;
  return {
    originalUrl: url,
    url,
    headers: lower,
    get(name) {
      return lower[name.toLowerCase()];
    },
    ...rest,
  };
}

function run(middleware, request_) {
  const res = mockRes();
  const state = { nextCalled: false, nextError: null };
  return Promise.resolve(
    middleware(request_, res, (error) => {
      state.nextCalled = !error;
      state.nextError = error || null;
    }),
  ).then(() => ({ res, ...state }));
}

describe("guardOperatorCredentials", () => {
  it("lets every non-operator request through untouched", async () => {
    for (const authorization of [undefined, "", "Basic abc", `Bearer ${EXECUTOR}`, "Bearer plain-token"]) {
      const out = await run(
        auth.guardOperatorCredentials,
        req({ url: "/api/v1/workspaces/abc/certops/jobs", authorization }),
      );
      assert.equal(out.nextCalled, true, String(authorization));
      assert.equal(out.res.statusCode, null);
    }
  });

  it("refuses an operator credential on any route outside the operator namespace", async () => {
    for (const url of [
      "/api/v1/workspaces/abc/certops/jobs",
      "/api/v1/workspaces/abc/certops/jobs/approve",
      "/api/csrf-token",
      "/auth/login",
      "/api/v1/operator",
      "/api/v1/operatorx/whoami",
      "/api/v2/operator/whoami",
    ]) {
      const out = await run(auth.guardOperatorCredentials, req({ url, authorization: `Bearer ${OPERATOR}` }));
      assert.equal(out.nextCalled, false, url);
      assert.equal(out.res.statusCode, 403, url);
      assert.equal(out.res.body.code, auth.OPERATOR_ROUTE_FORBIDDEN, url);
    }
  });

  it("refuses a malformed operator-prefixed credential outside the namespace too", async () => {
    const out = await run(
      auth.guardOperatorCredentials,
      req({ url: "/api/v1/workspaces/abc", authorization: "Bearer ttopc_garbage" }),
    );
    assert.equal(out.res.statusCode, 403);
  });

  it("accepts the bearer scheme in any letter case", async () => {
    const out = await run(
      auth.guardOperatorCredentials,
      req({ url: "/api/v1/workspaces/abc", authorization: `bEaReR ${OPERATOR}` }),
    );
    assert.equal(out.res.statusCode, 403);
  });

  it("allows the operator namespace and nothing disguised as it", async () => {
    const ok = await run(
      auth.guardOperatorCredentials,
      req({ url: "/api/v1/operator/whoami", authorization: `Bearer ${OPERATOR}` }),
    );
    assert.equal(ok.nextCalled, true);

    for (const url of [
      "/api/v1/operator/../workspaces/abc/certops/jobs",
      "/api/v1/operator/%2e%2e/workspaces/abc",
      "/api/v1/operator//whoami",
      "/api/v1/operator/.",
      "/api/v1/operator/",
      "/api/v1/operator/whoami/../../workspaces",
    ]) {
      const out = await run(auth.guardOperatorCredentials, req({ url, authorization: `Bearer ${OPERATOR}` }));
      assert.equal(out.res.statusCode, 403, url);
    }
  });

  it("ignores a query string that mentions the operator namespace", async () => {
    const out = await run(
      auth.guardOperatorCredentials,
      req({
        url: "/api/v1/workspaces/abc?next=/api/v1/operator/whoami",
        authorization: `Bearer ${OPERATOR}`,
      }),
    );
    assert.equal(out.res.statusCode, 403);
  });
});

describe("guardOperatorCredentials and enrollment grants", () => {
  const GRANT = `ttopg_${ID}_${"c".repeat(64)}`;
  const REDEEM = "/api/v1/operator/enroll/redeem";
  const grantReq = (overrides = {}) => req({ url: REDEEM, authorization: `Bearer ${GRANT}`, method: "POST", ...overrides });

  it("lets a grant through at exactly POST on the redeem route", async () => {
    const out = await run(auth.guardOperatorCredentials, grantReq());
    assert.equal(out.nextCalled, true);
    assert.equal(out.res.statusCode, null);
  });

  it("refuses a grant on every other method, even at the redeem route", async () => {
    for (const method of ["GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", undefined]) {
      const out = await run(auth.guardOperatorCredentials, grantReq({ method }));
      assert.equal(out.nextCalled, false, String(method));
      assert.equal(out.res.statusCode, 403, String(method));
      assert.equal(out.res.body.code, auth.OPERATOR_ROUTE_FORBIDDEN);
    }
  });

  it("refuses a grant on every other path, including near misses and traversal", async () => {
    for (const url of [
      "/api/v1/operator/whoami",
      "/api/v1/operator/enroll",
      "/api/v1/operator/enroll/redeem/",
      "/api/v1/operator/enroll/redeem/extra",
      "/api/v1/operator/enroll/Redeem",
      "/api/v1/operator/enroll/redeem?x=/api/v1/operator/whoami",
      "/api/v1/operator/enroll/../whoami",
      "/api/v1/operator/enroll/%72edeem",
      "/api/v1/workspaces/abc/operator/enrollments",
      "/api/v1/workspaces/abc/certops/jobs",
      "/auth/login",
      "//api/v1/operator/enroll/redeem",
    ]) {
      const out = await run(auth.guardOperatorCredentials, grantReq({ url }));
      const expectedThrough = url.split("?")[0] === REDEEM;
      assert.equal(out.nextCalled, expectedThrough, url);
      if (!expectedThrough) assert.equal(out.res.statusCode, 403, url);
    }
  });

  it("treats a malformed grant like a grant: it still cannot travel", async () => {
    for (const bearer of ["ttopg_", "ttopg_short", `ttopg_${ID}_`, "ttopg_" + "z".repeat(90)]) {
      const out = await run(auth.guardOperatorCredentials, req({ url: "/api/v1/operator/whoami", authorization: `Bearer ${bearer}` }));
      assert.equal(out.nextCalled, false, bearer);
      assert.equal(out.res.statusCode, 403, bearer);
    }
  });

  it("is not fooled by the grant prefix in other casings of the header", async () => {
    const out = await run(
      auth.guardOperatorCredentials,
      req({ url: "/api/v1/operator/whoami", authorization: `bEaReR ${GRANT}`, method: "POST" }),
    );
    assert.equal(out.nextCalled, false);
    assert.equal(out.res.statusCode, 403);
  });

  it("exposes the family checks as exact prefix tests", () => {
    assert.equal(auth.looksLikeEnrollmentGrant(GRANT), true);
    assert.equal(auth.looksLikeEnrollmentGrant(OPERATOR), false);
    assert.equal(auth.looksLikeEnrollmentGrant(EXECUTOR), false);
    assert.equal(auth.looksLikeOperatorCredential(GRANT), false, "a grant is not a connection credential");
    assert.equal(auth.looksLikeEnrollmentGrant(null), false);
  });

  it("never lets a grant authenticate a connection route", async () => {
    const guard = auth.requireOperatorConnection({
      scope: "mcp:identity:read",
      authenticateCredential: async () => {
        throw new Error("a grant must never reach authentication");
      },
    });
    const out = await run(guard, req({ authorization: `Bearer ${GRANT}` }));
    assert.equal(out.res.statusCode, 401);
    assert.equal(out.nextCalled, false);
  });
});

describe("requireOperatorConnection", () => {
  const validResult = (overrides = {}) => ({
    valid: true,
    connection: {
      id: "550e8400-e29b-41d4-a716-446655440001",
      userId: 4,
      workspaceId: "550e8400-e29b-41d4-a716-446655440000",
      expiresAt: "2026-11-18T12:00:00.000Z",
    },
    authority: {
      currentRole: "admin",
      ceiling: "workspace_manager",
      effectiveRole: "workspace_manager",
      scopes: ["mcp:identity:read", "mcp:certs:read"],
    },
    ...overrides,
  });

  function guard({ result = validResult(), scope = "mcp:identity:read", minRole, touched = [] } = {}) {
    return auth.requireOperatorConnection({
      scope,
      minRole,
      authenticateCredential: async () => result,
      recordUse: async ({ connectionId }) => touched.push(connectionId),
    });
  }

  it("requires a scope at construction", () => {
    assert.throws(() => auth.requireOperatorConnection({}), /scope/);
    assert.throws(() => auth.requireOperatorConnection({ scope: "certops:read" }), /scope/);
  });

  it("rejects a missing, foreign-family or malformed bearer with 401", async () => {
    for (const authorization of [undefined, "Basic abc", `Bearer ${EXECUTOR}`, "Bearer", "Bearer a b"]) {
      const out = await run(guard(), req({ authorization }));
      assert.equal(out.nextCalled, false, String(authorization));
      assert.equal(out.res.statusCode, 401, String(authorization));
      assert.equal(out.res.body.code, auth.OPERATOR_UNAUTHORIZED);
    }
  });

  it("rejects an unknown, revoked or expired credential with the same 401", async () => {
    const out = await run(guard({ result: { valid: false } }), req({ authorization: `Bearer ${OPERATOR}` }));
    assert.equal(out.res.statusCode, 401);
    assert.equal(out.res.body.code, auth.OPERATOR_UNAUTHORIZED);
  });

  it("rejects a bearer that arrives with any session identity, cookie or worker flag", async () => {
    const variants = [
      { user: { id: 1 } },
      { session: { userId: 1 } },
      { session: { passport: { user: 1 } } },
      { isWorkerCall: true },
      { isAuthenticated: () => true },
      { headers: { cookie: "x-csrf-token=abc" } },
    ];
    for (const extra of variants) {
      const out = await run(guard(), req({ authorization: `Bearer ${OPERATOR}`, ...extra }));
      assert.equal(out.nextCalled, false, JSON.stringify(Object.keys(extra)));
      assert.equal(out.res.statusCode, 401);
      assert.equal(out.res.body.code, auth.OPERATOR_SESSION_FORBIDDEN);
    }
  });

  it("denies a scope the live authority no longer includes", async () => {
    const out = await run(guard({ scope: "mcp:agents:read" }), req({ authorization: `Bearer ${OPERATOR}` }));
    assert.equal(out.nextCalled, false);
    assert.equal(out.res.statusCode, 403);
    assert.equal(out.res.body.code, auth.OPERATOR_SCOPE_DENIED);
  });

  it("enforces an extra minimum role on top of the scope", async () => {
    const out = await run(
      guard({ minRole: "admin" }),
      req({ authorization: `Bearer ${OPERATOR}` }),
    );
    assert.equal(out.res.statusCode, 403);
  });

  it("binds a frozen principal and never an Express user, worker or session", async () => {
    const touched = [];
    const request_ = req({ authorization: `Bearer ${OPERATOR}` });
    const out = await run(guard({ touched }), request_);
    assert.equal(out.nextCalled, true);
    assert.equal(request_.user, undefined);
    assert.equal(request_.isWorkerCall, undefined);
    assert.equal(request_.session, undefined);
    assert.equal(request_.operator.role, "workspace_manager");
    assert.equal(request_.operator.currentRole, "admin");
    assert.equal(request_.operator.roleCeiling, "workspace_manager");
    assert.ok(Object.isFrozen(request_.operator));
    assert.ok(Object.isFrozen(request_.operator.scopes));
    assert.deepEqual(touched, ["550e8400-e29b-41d4-a716-446655440001"]);
  });

  it("passes an unexpected authenticator failure to next() without leaking it", async () => {
    const failing = auth.requireOperatorConnection({
      scope: "mcp:identity:read",
      authenticateCredential: async () => {
        throw new Error("connection pool exhausted");
      },
    });
    const out = await run(failing, req({ authorization: `Bearer ${OPERATOR}` }));
    assert.equal(out.nextCalled, false);
    assert.equal(out.nextError.message, "connection pool exhausted");
    assert.equal(out.res.statusCode, null);
  });
});

describe("CSRF exemption for operator bearer requests", () => {
  const exempt = csrfExempt.isOperatorBearerCsrfExemptRequest;
  const bearer = { authorization: `Bearer ${OPERATOR}` };

  it("applies to an operator bearer with no cookies on the operator namespace", () => {
    assert.equal(exempt("/v1/operator/whoami", { headers: bearer }), true);
    assert.equal(exempt("/api/v1/operator/whoami", { headers: bearer }), true);
  });

  it("never applies once a cookie is present, so a session cannot ride it", () => {
    assert.equal(exempt("/v1/operator/whoami", { headers: { ...bearer, cookie: "sid=1" } }), false);
    assert.equal(exempt("/v1/operator/whoami", { headers: bearer, cookies: { sid: "1" } }), false);
  });

  it("never applies to other credentials, other paths or disguised paths", () => {
    assert.equal(exempt("/v1/operator/whoami", { headers: { authorization: `Bearer ${EXECUTOR}` } }), false);
    assert.equal(exempt("/v1/operator/whoami", { headers: {} }), false);
    assert.equal(exempt("/v1/operator/whoami", null), false);
    for (const p of [
      "/v1/workspaces/abc/operator/connections",
      "/v1/operator/../workspaces/abc",
      "/v1/operator//whoami",
      "/v1/operator/",
      "/v1/operatorx/whoami",
    ]) {
      assert.equal(exempt(p, { headers: bearer }), false, p);
    }
  });
});

describe("route inventory", () => {
  const routesDir = path.resolve(__dirname, "../../apps/api/routes");
  const routeFiles = fs.readdirSync(routesDir).filter((name) => name.endsWith(".js"));

  function handlerNames(layer) {
    return (layer.route?.stack || []).map((entry) => entry.handle?.name || "");
  }

  function collect() {
    const found = [];
    for (const file of routeFiles) {
      const router = require(path.join(routesDir, file));
      const stack = router?.stack;
      if (!Array.isArray(stack)) continue;
      for (const layer of stack) {
        if (!layer.route) continue;
        for (const method of Object.keys(layer.route.methods)) {
          found.push({
            file,
            method: method.toUpperCase(),
            path: String(layer.route.path),
            handlers: handlerNames(layer),
          });
        }
      }
    }
    return found;
  }

  const routes = collect();

  it("finds a realistic number of routes, so an empty scan cannot pass silently", () => {
    assert.ok(routes.length > 150, `only ${routes.length} routes found`);
    assert.ok(routes.some((r) => r.path.startsWith("/api/v1/operator/")));
  });

  it("opts a route in to operator credentials only inside the operator namespace", () => {
    const optedIn = routes.filter((r) => r.handlers.includes("operatorConnectionGuard"));
    assert.ok(optedIn.length > 0);
    for (const route of optedIn) {
      assert.ok(
        route.path.startsWith("/api/v1/operator/"),
        `${route.method} ${route.path} (${route.file}) accepts operator credentials outside the namespace`,
      );
    }
  });

  // Redeeming an enrollment grant is the one route in the namespace that takes
  // no connection credential: it takes the grant, once. It is named here so
  // that any other unguarded route, or any other write, still fails.
  const REDEEM = "POST /api/v1/operator/enroll/redeem";
  const isRedeem = (route) => `${route.method} ${route.path}` === REDEEM;

  it("gates every operator-namespace route behind the rollout flag and the connection guard", () => {
    const inside = routes.filter((r) => r.path.startsWith("/api/v1/operator/") && !isRedeem(r));
    assert.ok(inside.length > 0);
    for (const route of inside) {
      assert.ok(route.handlers.includes("requireOperatorInterfaceEnabled"), `${route.path} lacks the rollout gate`);
      assert.ok(route.handlers.includes("operatorConnectionGuard"), `${route.path} lacks the connection guard`);
      // whoami is the one route that must answer when CertOps is off, because it
      // is how an assistant learns that.
      if (route.path === "/api/v1/operator/whoami") continue;
      assert.ok(route.handlers.includes("requireCertOpsEnabled"), `${route.path} lacks the CertOps gate`);
    }
  });

  // The only writes an assistant can make. Anything added to this list is a new
  // way for a model to change state, so it must be added here deliberately.
  const ALLOWED_WRITES = [
    "POST /api/v1/operator/enroll/redeem",
    "POST /api/v1/operator/renewals/preview",
    "POST /api/v1/operator/renewals/requests",
    "POST /api/v1/operator/requests/:requestRecordId/cancel",
  ].sort();

  it("limits operator writes to a reviewed list, each rate limited and refusing key material", () => {
    const writes = routes.filter((r) => r.path.startsWith("/api/v1/operator/") && r.method !== "GET");
    assert.deepEqual(writes.map((r) => `${r.method} ${r.path}`).sort(), ALLOWED_WRITES);
    for (const route of writes.filter((r) => !isRedeem(r))) {
      assert.ok(route.handlers.includes("rejectKeyMaterial"), `${route.path} must refuse key material`);
      assert.ok(route.handlers.includes("operatorConnectionGuard"), `${route.path} must take a connection credential`);
      assert.ok(!route.handlers.includes("requireSessionUser"), `${route.path} is not a session route`);
    }
  });

  it("keeps every operator write behind a single write scope", () => {
    const source = fs.readFileSync(path.join(routesDir, "operator.js"), "utf8");
    const writeScopes = new Set([...source.matchAll(/operatorWrite\("([^"]+)"\)/g)].map((m) => m[1]));
    assert.deepEqual([...writeScopes], ["mcp:renew:request"], "writes use only the narrow renew scope");
  });

  it("allows exactly one unguarded write in the namespace: redeeming a grant, gated and rate limited", () => {
    const unguarded = routes.filter(
      (r) => r.path.startsWith("/api/v1/operator/") && r.method !== "GET" && !r.handlers.includes("operatorConnectionGuard"),
    );
    assert.deepEqual(unguarded.map((r) => `${r.method} ${r.path}`), [REDEEM]);
    const [redeem] = unguarded;
    assert.ok(redeem.handlers.includes("requireOperatorInterfaceEnabled"), "redeem lacks the rollout gate");
    assert.ok(!redeem.handlers.includes("operatorConnectionGuard"), "redeem must not take a connection credential");
    assert.ok(!redeem.handlers.includes("requireSessionUser"), "redeem is not a session route");
    // The limiter is an anonymous function, so check it by identity: the
    // very instance the middleware module hands out must be on the route.
    const { getOperatorEnrollmentLimiter } = require(path.resolve(__dirname, "../../apps/api/middleware/rateLimit.js"));
    const operatorRouter = require(path.join(routesDir, "operator.js"));
    const layer = operatorRouter.stack.find(
      (l) => l.route && l.route.path === "/api/v1/operator/enroll/redeem" && l.route.methods.post,
    );
    assert.ok(layer, "redeem route layer not found");
    assert.ok(
      layer.route.stack.some((entry) => entry.handle === getOperatorEnrollmentLimiter()),
      "redeem must carry the enrollment rate limiter",
    );
    assert.equal(layer.route.stack[0].handle, getOperatorEnrollmentLimiter(), "the limiter must run before anything else");
  });

  it("makes every connection-management route session-only and flag-gated", () => {
    const management = routes.filter((r) => /\/operator\/(connections|enrollments)/.test(r.path));
    assert.ok(management.length >= 7, `only ${management.length} management routes found`);
    for (const route of management) {
      assert.ok(route.path.startsWith("/api/v1/workspaces/:id/"), route.path);
      assert.ok(route.handlers.includes("requireSessionUser"), `${route.path} must require a session user`);
      assert.ok(route.handlers.includes("requireOperatorInterfaceEnabled"), `${route.path} lacks the rollout gate`);
      assert.ok(!route.handlers.includes("operatorConnectionGuard"), `${route.path} must not accept a connection`);
    }
  });

  it("keeps the contract catalog honest about which operator routes exist", () => {
    const catalog = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../packages/contracts/mcp/mcp-tool-catalog.json"), "utf8"),
    );
    const live = new Set(routes.map((r) => `${r.method} ${r.path}`));
    const mvp = catalog.tools.filter((tool) => tool.contractStatus === "mvp");
    assert.ok(mvp.length > 0);
    for (const tool of mvp) {
      assert.match(tool.route, /^GET \/api\/v1\/operator\//, `${tool.name} must live in the operator namespace`);
      assert.ok(["implemented", "planned"].includes(tool.routeStatus), `${tool.name}: ${tool.routeStatus}`);
      if (tool.routeStatus === "implemented") {
        assert.ok(live.has(tool.route), `${tool.name} is marked implemented but ${tool.route} is not registered`);
      } else {
        assert.ok(!live.has(tool.route), `${tool.name} is marked planned but ${tool.route} already exists`);
      }
    }
  });

  it("refuses an operator credential on every real route outside the namespace", async () => {
    const app = express();
    app.use("/api", auth.guardOperatorCredentials);
    app.use("/auth", auth.guardOperatorCredentials);
    for (const file of routeFiles) app.use(require(path.join(routesDir, file)));

    const outside = routes.filter((r) => !r.path.startsWith("/api/v1/operator/"));
    assert.ok(outside.length > 150);
    const bodies = new Set();
    for (const route of outside) {
      if (!route.path.startsWith("/api") && !route.path.startsWith("/auth")) continue;
      const concrete = route.path.replace(/:[A-Za-z0-9_]+\??/g, "x");
      const response = await request(app)
        [route.method.toLowerCase()](concrete)
        .set("Authorization", `Bearer ${OPERATOR}`)
        .send({});
      assert.equal(response.status, 403, `${route.method} ${route.path} -> ${response.status}`);
      bodies.add(response.body.code);
    }
    assert.deepEqual([...bodies], [auth.OPERATOR_ROUTE_FORBIDDEN]);
  });

  it("refuses an enrollment grant on every real route except redeeming it", async () => {
    const GRANT = `ttopg_${ID}_${"c".repeat(64)}`;
    const app = express();
    app.use("/api", auth.guardOperatorCredentials);
    app.use("/auth", auth.guardOperatorCredentials);
    for (const file of routeFiles) app.use(require(path.join(routesDir, file)));

    const others = routes.filter((r) => !isRedeem(r));
    assert.ok(others.length > 150);
    const codes = new Set();
    for (const route of others) {
      if (!route.path.startsWith("/api") && !route.path.startsWith("/auth")) continue;
      const concrete = route.path.replace(/:[A-Za-z0-9_]+\??/g, "x");
      const response = await request(app)
        [route.method.toLowerCase()](concrete)
        .set("Authorization", `Bearer ${GRANT}`)
        .send({});
      assert.equal(response.status, 403, `${route.method} ${route.path} -> ${response.status}`);
      codes.add(response.body.code);
    }
    assert.deepEqual([...codes], [auth.OPERATOR_ROUTE_FORBIDDEN]);
  });

  it("mounts the early guard before any other authentication in the app entrypoint", () => {
    const source = fs.readFileSync(path.resolve(__dirname, "../../apps/api/index.js"), "utf8");
    const guardApi = source.indexOf('app.use("/api", guardOperatorCredentials)');
    const guardAuth = source.indexOf('app.use("/auth", guardOperatorCredentials)');
    const firstRouter = source.indexOf('app.use(require("./routes/');
    const workspaceStack = source.indexOf('"/api/v1/workspaces/:id",\n  requireAuth');
    assert.ok(guardApi > 0 && guardAuth > 0, "guard must be mounted on /api and /auth");
    assert.ok(guardApi < firstRouter, "guard must precede every router");
    assert.ok(guardApi < workspaceStack, "guard must precede the workspace authentication stack");
  });
});
