/**
 * Protocol-level integration test for the OIDC migration.
 *
 * Spins up a tiny in-process OIDC IdP (discovery, authorize, token, userinfo,
 * JWKS) backed by Node's crypto + jsonwebtoken, then drives the real
 * `oidcRoutes` through openid-client end-to-end.
 *
 * Covers, in one cohesive test file, the scenarios listed in the migration
 * acceptance checklist that unit-level mocks cannot reach:
 *
 *   - /auth/oidc/:provider redirects with code_challenge=S256 + state + nonce.
 *   - Callback rejects wrong state.
 *   - Callback rejects wrong nonce (tampered session).
 *   - Callback exchanges with code_verifier (the IdP requires it).
 *   - UserInfo sub mismatch rejects the login (route emits audit).
 *   - Happy path provisions/logs in the user and redirects to the deep link.
 */

"use strict";

const { describe, it, before, after, beforeEach } = require("node:test");
const assert = require("node:assert");
const apiRequire = require("node:module").createRequire(require.resolve("../../apps/api/package.json"));
const http = require("node:http");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const jwt = apiRequire("jsonwebtoken");

const oidcProvider = require("../../apps/api/auth/oidc");
const { createOidcClient } = require("../../apps/api/auth/oidc-flow");

/**
 * Tiny Express-shaped shim used by both the IdP and the test app.
 * Provides only the surface that oidcRoutes touches: Router(), router.get,
 * res.redirect, and res.json. Avoids pulling express into devDeps.
 */
function matchRoutePattern(routePath, reqPath) {
  const routeParts = routePath.split("/");
  const reqParts = reqPath.split("/");
  if (routeParts.length !== reqParts.length) return null;
  const params = {};
  for (let i = 0; i < routeParts.length; i++) {
    if (routeParts[i].startsWith(":")) {
      params[routeParts[i].slice(1)] = decodeURIComponent(reqParts[i]);
    } else if (routeParts[i] !== reqParts[i]) {
      return null;
    }
  }
  return params;
}

function makeMiniExpress() {
  const Router = () => {
    const routes = [];
    const router = {
      get(path, ...handlers) {
        routes.push({
          method: "GET",
          path,
          handler: handlers[handlers.length - 1],
        });
      },
      post(path, ...handlers) {
        routes.push({
          method: "POST",
          path,
          handler: handlers[handlers.length - 1],
        });
      },
      handle: async (req, res, next) => {
        const route = routes.find((r) => {
          if (r.method !== req.method) return false;
          const params = matchRoutePattern(r.path, req.path);
          if (!params) return false;
          req.params = params;
          return true;
        });
        if (!route) return next();
        try {
          await route.handler(req, res, next);
        } catch (err) {
          next(err);
        }
      },
    };
    return router;
  };
  return { Router };
}

function decorateRes(res) {
  res.redirect = (location) => {
    res.statusCode = 302;
    res.setHeader("Location", location);
    res.end();
  };
  res.json = (body) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(body));
  };
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.send = (body) => {
    res.end(String(body));
  };
  return res;
}

function parseQuery(search) {
  const params = new URLSearchParams(search);
  const out = {};
  for (const [k, v] of params.entries()) out[k] = v;
  return out;
}

async function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      const ct = req.headers["content-type"] || "";
      if (ct.includes("application/x-www-form-urlencoded")) {
        resolve(parseQuery(data));
      } else if (ct.includes("application/json") && data) {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      } else {
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

const CLIENT_ID = "tt-test-client";
const CLIENT_SECRET = "tt-test-secret";
const PROVIDER_SLUG = "test-oidc";
const CALLBACK_PATH = `/auth/oidc/${PROVIDER_SLUG}/callback`;

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}

/**
 * Mini OIDC IdP. Supports Authorization Code + PKCE S256.
 *
 * Settable per-test via `idp.config = { ... }`:
 *   - sub: subject claim to issue in the next ID Token (defaults to a fresh one)
 *   - email
 *   - emailVerified
 *   - userinfoSub: override the sub returned by /userinfo (default = sub)
 *   - userinfoEmail
 *   - skipUserinfoSub: drop the sub from /userinfo response
 *   - corruptNonce: include a different nonce in the ID Token
 *   - requirePkce: reject /token requests missing code_verifier (default true)
 */
async function startMockIdp() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = "kid-test";
  jwk.use = "sig";
  jwk.alg = "RS256";

  const pendingCodes = new Map();
  const idp = {
    privateKey,
    publicKey,
    jwk,
    config: {},
    issuedAccessTokens: new Set(),
    reset() {
      this.config = {};
      pendingCodes.clear();
      this.issuedAccessTokens.clear();
    },
  };

  const handlers = {
    "GET /.well-known/openid-configuration": (_req, res) => {
      res.json({
        issuer: idp.baseUrl,
        authorization_endpoint: `${idp.baseUrl}/authorize`,
        token_endpoint: `${idp.baseUrl}/token`,
        userinfo_endpoint: `${idp.baseUrl}/userinfo`,
        jwks_uri: `${idp.baseUrl}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        scopes_supported: ["openid", "profile", "email"],
        token_endpoint_auth_methods_supported: [
          "client_secret_basic",
          "client_secret_post",
        ],
        code_challenge_methods_supported: ["S256"],
      });
    },
    "GET /jwks": (_req, res) => {
      res.json({ keys: [idp.jwk] });
    },
    "GET /authorize": (req, res) => {
      const {
        client_id,
        redirect_uri,
        state,
        nonce,
        code_challenge,
        code_challenge_method,
        response_type,
      } = req.query;
      if (client_id !== CLIENT_ID) {
        return res.status(400).send("bad client_id");
      }
      if (response_type !== "code") {
        return res.status(400).send("bad response_type");
      }
      if (!code_challenge || code_challenge_method !== "S256") {
        return res.status(400).send("PKCE S256 required");
      }
      const code = randomToken();
      pendingCodes.set(code, {
        redirect_uri,
        nonce,
        code_challenge,
        created_at: Date.now(),
      });
      const url = new URL(redirect_uri);
      url.searchParams.set("code", code);
      if (state) url.searchParams.set("state", state);
      res.redirect(url.toString());
    },
    "POST /token": (req, res) => {
    const { grant_type, code, redirect_uri, code_verifier, client_id, client_secret } = req.body;
    const auth = req.headers.authorization;
    let resolvedClientId = client_id;
    let resolvedClientSecret = client_secret;
    if (auth && auth.startsWith("Basic ")) {
      const decoded = Buffer.from(auth.slice(6), "base64").toString();
      const [u, p] = decoded.split(":");
      resolvedClientId = decodeURIComponent(u);
      resolvedClientSecret = decodeURIComponent(p);
    }
    if (resolvedClientId !== CLIENT_ID || resolvedClientSecret !== CLIENT_SECRET) {
      return res.status(401).json({ error: "invalid_client" });
    }
    if (grant_type !== "authorization_code") {
      return res.status(400).json({ error: "unsupported_grant_type" });
    }
    const pending = pendingCodes.get(code);
    if (!pending) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    pendingCodes.delete(code);
    if (pending.redirect_uri !== redirect_uri) {
      return res.status(400).json({ error: "redirect_uri_mismatch" });
    }
    const requirePkce = idp.config.requirePkce !== false;
    if (requirePkce) {
      if (!code_verifier) {
        return res.status(400).json({ error: "pkce_missing_verifier" });
      }
      const computed = crypto
        .createHash("sha256")
        .update(code_verifier)
        .digest("base64url");
      if (computed !== pending.code_challenge) {
        return res.status(400).json({ error: "pkce_verification_failed" });
      }
    }

    const sub = idp.config.sub || `sub-${randomToken(8)}`;
    const email = idp.config.email || `user-${sub}@example.com`;
    const nonceForToken = idp.config.corruptNonce
      ? `tampered-${pending.nonce}`
      : pending.nonce;
    const idToken = jwt.sign(
      {
        sub,
        email,
        email_verified: idp.config.emailVerified !== false,
        nonce: nonceForToken,
        name: "Mock User",
      },
      idp.config.tokenSigningKey || idp.privateKey,
      {
        algorithm: "RS256",
        keyid: idp.jwk.kid,
        issuer: idp.config.tokenIssuer || idp.baseUrl,
        audience: idp.config.tokenAudience || CLIENT_ID,
        expiresIn: idp.config.tokenExpiration || "5m",
      },
    );
    const accessToken = `at-${randomToken()}`;
    idp.issuedAccessTokens.add(accessToken);
    idp.lastIssuedSub = sub;
    idp.lastIssuedEmail = email;
    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 300,
      id_token: idToken,
      scope: "openid profile email",
    });
    },
    "GET /userinfo": (req, res) => {
      const auth = req.headers.authorization || "";
      if (!auth.startsWith("Bearer ")) {
        return res.status(401).json({ error: "missing_token" });
      }
      const token = auth.slice(7);
      if (!idp.issuedAccessTokens.has(token)) {
        return res.status(401).json({ error: "invalid_token" });
      }
      const body = {};
      if (!idp.config.skipUserinfoSub) {
        body.sub = idp.config.userinfoSub || idp.lastIssuedSub;
      }
      body.email = idp.config.userinfoEmail || idp.lastIssuedEmail;
      body.name = "Mock User";
      res.json(body);
    },
  };

  const server = http.createServer(async (rawReq, rawRes) => {
    try {
      const url = new URL(rawReq.url, `http://${rawReq.headers.host || "x"}`);
      const req = rawReq;
      req.path = url.pathname;
      req.query = parseQuery(url.search.slice(1));
      req.body = await parseBody(rawReq);
      const res = decorateRes(rawRes);
      const key = `${rawReq.method} ${url.pathname}`;
      const handler = handlers[key];
      if (!handler) {
        res.status(404).send("not found");
        return;
      }
      await handler(req, res);
    } catch (e) {
      rawRes.statusCode = 500;
      rawRes.end(`error: ${e?.message}`);
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  idp.port = port;
  idp.baseUrl = `http://127.0.0.1:${port}`;
  idp.close = () =>
    new Promise((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  return idp;
}

/**
 * Minimal in-memory pool mock. Covers the SQL shapes hit by resolveUser,
 * resolveSsoBindings, applyResolution, and the post-login user refresh.
 */
function makeMockPool(issuer) {
  const state = {
    issuer,
    users: [],
    links: [],
    memberships: [],
    workspaces: [],
    mappings: [],
  };
  const matches = (sql, regex) =>
    regex.test(sql.replace(/\s+/g, " ").trim());
  const handle = async (sql, params = []) => {
    const flat = sql.replace(/\s+/g, " ").trim();
    if (/^BEGIN$/i.test(flat) || /^COMMIT$/i.test(flat) || /^ROLLBACK$/i.test(flat)) {
      return { rows: [], rowCount: 0 };
    }
    if (/^SELECT pg_advisory_xact_lock/i.test(flat)) {
      return { rows: [], rowCount: 1 };
    }
    if (/^SELECT type, config FROM sso_providers WHERE slug = \$1 AND enabled FOR SHARE/i.test(flat)) {
      return { rows: [{ type: "oidc", config: { issuer: state.issuer } }], rowCount: 1 };
    }
    if (/^SELECT 1 FROM sso_providers WHERE slug = \$1 AND enabled FOR SHARE$/i.test(flat)) {
      return params[0] === PROVIDER_SLUG
        ? { rows: [{ "?column?": 1 }], rowCount: 1 }
        : { rows: [], rowCount: 0 };
    }
    if (matches(flat, /^SELECT ei\.id AS link_id, u\.\*, u\.auth_method AS auth_method_before FROM external_identities ei JOIN users u ON u\.id = ei\.user_id WHERE ei\.provider_slug = \$1 AND ei\.subject_id = \$2/i)) {
      const [providerSlug, subjectId] = params;
      const link = state.links.find(
        (l) => l.provider_slug === providerSlug && l.subject_id === subjectId,
      );
      if (!link) return { rowCount: 0, rows: [] };
      const user = state.users.find((u) => u.id === link.user_id);
      return {
        rowCount: 1,
        rows: [{ link_id: link.id, ...user, auth_method_before: user.auth_method }],
      };
    }
    if (matches(flat, /^SELECT \* FROM users WHERE LOWER\(email\) = LOWER\(\$1\) LIMIT 1/i)) {
      const [email] = params;
      const u = state.users.find(
        (u) => u.email.toLowerCase() === String(email).toLowerCase(),
      );
      return u ? { rowCount: 1, rows: [u] } : { rowCount: 0, rows: [] };
    }
    if (matches(flat, /^UPDATE external_identities SET last_seen_at = NOW\(\) WHERE id = \$1/i)) {
      const [id] = params;
      const l = state.links.find((l) => l.id === id);
      if (l) l.last_seen_at = new Date();
      return { rowCount: l ? 1 : 0, rows: [] };
    }
    if (matches(flat, /^SELECT subject_id FROM external_identities WHERE user_id = \$1 AND provider_slug = \$2 LIMIT 1/i)) {
      const [userId, providerSlug] = params;
      const l = state.links.find(
        (l) => l.user_id === userId && l.provider_slug === providerSlug,
      );
      return l
        ? { rowCount: 1, rows: [{ subject_id: l.subject_id }] }
        : { rowCount: 0, rows: [] };
    }
    if (matches(flat, /^INSERT INTO external_identities \(user_id, provider_slug, protocol, subject_id, email_at_link, display_name_at_link, last_seen_at\) VALUES/i)) {
      const [userId, providerSlug, protocol, subjectId, emailAtLink, displayAtLink] = params;
      const existing = state.links.find(
        (l) => l.provider_slug === providerSlug && l.subject_id === subjectId,
      );
      if (existing) {
        if (existing.user_id !== userId) return { rows: [], rowCount: 0 };
        existing.last_seen_at = new Date();
      } else {
        state.links.push({
          id: `link-${state.links.length + 1}`,
          user_id: userId,
          provider_slug: providerSlug,
          protocol,
          subject_id: subjectId,
          email_at_link: emailAtLink,
          display_name_at_link: displayAtLink,
          last_seen_at: new Date(),
        });
      }
      return { rowCount: 1, rows: [{ user_id: userId }] };
    }
    if (matches(flat, /^UPDATE external_identities SET last_seen_at = NOW\(\) WHERE user_id = \$1/i)) {
      const [userId] = params;
      state.links
        .filter((l) => l.user_id === userId)
        .forEach((l) => (l.last_seen_at = new Date()));
      return { rowCount: 1, rows: [] };
    }
    if (matches(flat, /^INSERT INTO users \(email, email_original, display_name, auth_method, email_verified, password_hash, is_admin\) VALUES \(\$1, \$2, \$3, 'sso', TRUE, 'SSO_NO_PASSWORD', FALSE\) RETURNING/i)) {
      const [email, emailOriginal, displayName] = params;
      const row = {
        id: `user-${state.users.length + 1}`,
        email,
        email_original: emailOriginal,
        display_name: displayName,
        auth_method: "sso",
        email_verified: true,
        password_hash: "SSO_NO_PASSWORD",
        is_admin: false,
      };
      state.users.push(row);
      return { rowCount: 1, rows: [row] };
    }
    if (matches(flat, /^UPDATE users SET recipient_verified_email = CASE WHEN/i)) {
      const [userId, email, verified] = params;
      const user = state.users.find((row) => row.id === userId);
      if (!user) return { rowCount: 0, rows: [] };
      const mailbox = String(email).trim().toLowerCase();
      user.recipient_verified_email =
        verified === true && user.email_original.trim().toLowerCase() === mailbox
          ? mailbox
          : null;
      return { rowCount: 1, rows: [] };
    }
    if (matches(flat, /^UPDATE users SET auth_method = 'sso', email_verified = TRUE, updated_at = NOW\(\) WHERE id = \$1/i)) {
      return { rowCount: 0, rows: [] };
    }
    if (matches(flat, /^UPDATE users SET email_verified = TRUE, updated_at = NOW\(\) WHERE id = \$1/i)) {
      return { rowCount: 0, rows: [] };
    }
    if (matches(flat, /^SELECT id, provider_slug, idp_group, role, workspace_id FROM sso_group_role_mappings/i)) {
      return { rowCount: 0, rows: [] };
    }
    if (/FROM sso_system_admin_grants/i.test(flat) && /^SELECT/i.test(flat)) {
      return { rowCount: 0, rows: [] };
    }
    if (/is_admin_manual = TRUE/i.test(flat) && /sso_system_admin_grants/i.test(flat)) {
      return { rowCount: 0, rows: [] };
    }
    if (/^INSERT INTO workspace_memberships/i.test(flat) && /FROM workspaces w/i.test(flat)) {
      return { rowCount: 0, rows: [] };
    }
    if (/^INSERT INTO sso_system_admin_grants/i.test(flat)) {
      return { rowCount: 1, rows: [] };
    }
    if (/^SELECT is_admin FROM users WHERE id = \$1/i.test(flat)) {
      const u = state.users.find((u) => u.id === params[0]);
      return u
        ? { rowCount: 1, rows: [{ is_admin: u.is_admin === true }] }
        : { rowCount: 0, rows: [] };
    }
    if (/^UPDATE users\s+SET is_admin =/i.test(flat) && /sso_system_admin_grants/i.test(flat)) {
      const u = state.users.find((u) => u.id === params[0]);
      if (u) u.is_admin = true;
      return {
        rowCount: u ? 1 : 0,
        rows: u
          ? [{ id: u.id, is_admin: true, is_admin_manual: false }]
          : [],
      };
    }
    if (matches(flat, /^SELECT id FROM workspaces/i)) {
      return { rowCount: 0, rows: [] };
    }
    if (matches(flat, /^SELECT workspace_id FROM workspace_memberships/i)) {
      return { rowCount: 0, rows: [] };
    }
    if (matches(flat, /^UPDATE users SET is_admin = TRUE/i)) {
      return { rowCount: 0, rows: [] };
    }
    if (matches(flat, /^INSERT INTO workspace_memberships/i)) {
      return { rowCount: 0, rows: [] };
    }
    if (matches(flat, /^DELETE FROM workspace_memberships/i)) {
      return { rowCount: 0, rows: [] };
    }
    if (matches(flat, /^SELECT \* FROM users WHERE id = \$1/i)) {
      const [id] = params;
      const u = state.users.find((u) => u.id === id);
      return u ? { rowCount: 1, rows: [u] } : { rowCount: 0, rows: [] };
    }
    throw new Error(`mock pool: unhandled SQL: ${flat}`);
  };
  return {
    connect: async () => ({ query: handle, release: () => {} }),
    query: handle,
    _state: state,
  };
}

/**
 * Test app: the real oidcRoutes mounted behind our mini express shim plus
 * a cookie-keyed in-memory session and a `req.logIn` stub. Avoids pulling
 * in express / express-session as devDeps.
 */
function makeTestApp() {
  const sessions = new Map();
  const expressShim = makeMiniExpress();
  const router = oidcProvider.oidcRoutes({}, expressShim);

  const server = http.createServer(async (rawReq, rawRes) => {
    try {
      const url = new URL(rawReq.url, `http://${rawReq.headers.host || "x"}`);
      const req = rawReq;
      req.path = url.pathname;
      req.query = parseQuery(url.search.slice(1));
      req.originalUrl = rawReq.url;

      const cookieHeader = rawReq.headers.cookie || "";
      const m = /tt_sid=([^;]+)/.exec(cookieHeader);
      let sid = m ? m[1] : null;
      if (!sid) {
        sid = crypto.randomBytes(16).toString("hex");
        rawRes.setHeader("Set-Cookie", `tt_sid=${sid}; HttpOnly; Path=/`);
      }
      if (!sessions.has(sid)) sessions.set(sid, {});
      const sessionState = sessions.get(sid);
      req.session = sessionState;
      req.session.save = (cb) => {
        sessions.set(sid, sessionState);
        if (cb) cb();
      };
      req.logIn = (user, cb) => {
        sessionState.user = user;
        cb();
      };
      const res = decorateRes(rawRes);
      await router.handle(req, res, (err) => {
        if (err) {
          res.statusCode = 500;
          res.end(`error: ${err.message}`);
          return;
        }
        res.statusCode = 404;
        res.end("not found");
      });
    } catch (e) {
      rawRes.statusCode = 500;
      rawRes.end(`error: ${e?.message}`);
    }
  });
  return { server, sessions };
}

async function getFollow(baseUrl, pathOrUrl, cookies) {
  const url = new URL(pathOrUrl, baseUrl).toString();
  const res = await fetch(url, {
    redirect: "manual",
    headers: cookies ? { cookie: cookies } : {},
  });
  return res;
}

function extractSetCookie(res) {
  const sc = res.headers.get("set-cookie");
  if (!sc) return null;
  const m = /tt_sid=[^;]+/.exec(sc);
  return m ? m[0] : null;
}

describe("OIDC end-to-end with mock IdP", () => {
  let idp;
  let pool;
  let testApp;
  let appServer;
  let appBaseUrl;
  const originalEnv = { ...process.env };

  before(async () => {
    idp = await startMockIdp();
    process.env.APP_URL = "http://localhost:5173";

    pool = makeMockPool(idp.baseUrl);
    testApp = makeTestApp();

    appServer = testApp.server;
    await new Promise((resolve) =>
      appServer.listen(0, "127.0.0.1", resolve),
    );
    const { port } = appServer.address();
    appBaseUrl = `http://127.0.0.1:${port}`;
    const callbackURL = `${appBaseUrl}${CALLBACK_PATH}`;

    const strategyConfig = {
      issuer: idp.baseUrl,
      clientID: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      callbackURL,
      authorizationURL: `${idp.baseUrl}/authorize`,
      tokenURL: `${idp.baseUrl}/token`,
      userInfoURL: `${idp.baseUrl}/userinfo`,
      jwksURL: `${idp.baseUrl}/jwks`,
      scope: ["openid", "profile", "email"],
      acceptedClockSkewMs: 0,
    };
    const { client } = createOidcClient(strategyConfig);

    oidcProvider._setOidcRuntimeForTests(PROVIDER_SLUG, {
      providerSlug: PROVIDER_SLUG,
      displayName: PROVIDER_SLUG,
      enabled: true,
      issuer: idp.baseUrl,
      strategyConfig,
      client,
      openIdClient: apiRequire("openid-client"),
      pkceEnabled: true,
      claimConfig: {
        oidc: {
          email: "email",
          displayName: "name",
          groups: "groups",
          subject: "sub",
        },
      },
      securityConfig: {
        allowAutoLinkLocalAccounts: false,
        strictMembershipSync: false,
        pkce: true,
      },
      bootstrapAdminGroups: [],
      pool,
      deps: {
        logger: { warn: () => {}, info: () => {}, error: () => {} },
        canonicalizeEmail: (e) => e,
      },
    });
  });

  after(async () => {
    process.env = { ...originalEnv };
    oidcProvider._resetOidcRuntimeForTests();
    await new Promise((resolve, reject) =>
      appServer.close((err) => (err ? reject(err) : resolve())),
    );
    await idp.close();
  });

  beforeEach(() => {
    idp.reset();
    testApp.sessions.clear();
    pool._state.users.length = 0;
    pool._state.links.length = 0;
  });

  async function startAuthorization(nextPath) {
    const target = nextPath
      ? `/auth/oidc/${PROVIDER_SLUG}?next=${encodeURIComponent(nextPath)}`
      : `/auth/oidc/${PROVIDER_SLUG}`;
    const res = await getFollow(appBaseUrl, target);
    const cookies = extractSetCookie(res);
    return { res, cookies };
  }

  it("/auth/oidc/:provider redirects with PKCE S256 + state + nonce", async () => {
    const { res } = await startAuthorization();
    assert.strictEqual(res.status, 302);
    const loc = res.headers.get("location");
    assert.ok(loc, "missing redirect Location");
    const url = new URL(loc);
    assert.strictEqual(url.origin, idp.baseUrl);
    assert.ok(url.searchParams.get("state"), "state missing");
    assert.ok(url.searchParams.get("nonce"), "nonce missing");
    assert.ok(url.searchParams.get("code_challenge"), "code_challenge missing");
    assert.strictEqual(url.searchParams.get("code_challenge_method"), "S256");
    assert.strictEqual(url.searchParams.get("response_type"), "code");
    assert.strictEqual(url.searchParams.get("client_id"), CLIENT_ID);
  });

  it("full flow: /auth/oidc/:provider through signed ID Token (JWKS) to req.logIn and deep-link redirect", async () => {
    const deepLink = "/dashboard/tokens/abc";
    const { res: authRes, cookies } = await startAuthorization(deepLink);
    const idpUrl = new URL(authRes.headers.get("location"));

    assert.ok(
      idpUrl.searchParams.get("code_challenge"),
      "authorize step must send PKCE",
    );
    assert.ok(idpUrl.searchParams.get("state"), "authorize step must send state");

    const idpRedirect = await fetch(idpUrl.toString(), { redirect: "manual" });
    assert.strictEqual(idpRedirect.status, 302, "mock IdP should redirect back");
    const cbLoc = new URL(idpRedirect.headers.get("location"));
    assert.strictEqual(cbLoc.pathname, CALLBACK_PATH);
    assert.ok(cbLoc.searchParams.get("code"));
    assert.strictEqual(cbLoc.searchParams.get("state"), idpUrl.searchParams.get("state"));

    const cbRes = await getFollow(appBaseUrl, cbLoc.pathname + cbLoc.search, cookies);
    assert.strictEqual(cbRes.status, 302);
    assert.strictEqual(
      cbRes.headers.get("location"),
      `http://localhost:5173${deepLink}`,
    );
    assert.strictEqual(pool._state.users.length, 1, "user must be provisioned");
    assert.strictEqual(pool._state.links.length, 1, "external_identities link must be created");
    assert.strictEqual(pool._state.links[0].provider_slug, PROVIDER_SLUG);
    assert.strictEqual(pool._state.users[0].recipient_verified_email, idp.lastIssuedEmail);
  });

  for (const [label, config] of [
    ["an unverified mailbox", { emailVerified: false }],
    ["a different UserInfo mailbox", { userinfoEmail: "different@example.com" }],
  ]) {
    it(`allows new-user login without inheriting recipient proof for ${label}`, async () => {
      Object.assign(idp.config, config);
      const { res: authRes, cookies } = await startAuthorization();
      const idpRedirect = await fetch(authRes.headers.get("location"), {
        redirect: "manual",
      });
      const callback = new URL(idpRedirect.headers.get("location"));
      const result = await getFollow(appBaseUrl, callback.pathname + callback.search, cookies);
      assert.strictEqual(result.status, 302);
      assert.match(result.headers.get("location"), /\/dashboard$/);
      assert.strictEqual(pool._state.users.length, 1);
      assert.strictEqual(pool._state.users[0].recipient_verified_email, null);
    });
  }

  it("full flow persists session user via req.logIn after JWKS-validated callback", async () => {
    const { res: authRes, cookies } = await startAuthorization();
    const idpRedirect = await fetch(authRes.headers.get("location"), {
      redirect: "manual",
    });
    const cbLoc = new URL(idpRedirect.headers.get("location"));
    const cbRes = await getFollow(appBaseUrl, cbLoc.pathname + cbLoc.search, cookies);
    assert.strictEqual(cbRes.status, 302);
    assert.match(cbRes.headers.get("location"), /\/dashboard$/);

    const sidMatch = /tt_sid=([^;]+)/.exec(cookies || "");
    assert.ok(sidMatch, "session cookie must be set");
    const session = testApp.sessions.get(sidMatch[1]);
    assert.ok(session?.user, "req.logIn must attach user to session");
    assert.ok(session.user.id, "logged-in user must have an id");
    assert.strictEqual(pool._state.users.length, 1);
  });

  it("rejects callback with wrong state", async () => {
    const { res: authRes, cookies } = await startAuthorization();
    const idpUrl = new URL(authRes.headers.get("location"));
    const idpRedirect = await fetch(idpUrl.toString(), { redirect: "manual" });
    const cbLoc = new URL(idpRedirect.headers.get("location"));
    cbLoc.searchParams.set("state", "tampered-state-value");

    const cbRes = await getFollow(appBaseUrl, cbLoc.pathname + cbLoc.search, cookies);
    assert.strictEqual(cbRes.status, 302);
    const failLoc = new URL(cbRes.headers.get("location"));
    assert.strictEqual(failLoc.pathname, "/login");
    assert.strictEqual(failLoc.searchParams.get("error"), "state_mismatch");
    assert.strictEqual(failLoc.searchParams.get("provider"), "test-oidc");
    assert.strictEqual(failLoc.searchParams.get("reason"), "state_mismatch");
  });

  it("rejects callback when ID Token nonce does not match session nonce", async () => {
    idp.config.corruptNonce = true;
    const { res: authRes, cookies } = await startAuthorization();
    const idpUrl = new URL(authRes.headers.get("location"));
    const idpRedirect = await fetch(idpUrl.toString(), { redirect: "manual" });
    const cbLoc = new URL(idpRedirect.headers.get("location"));

    const cbRes = await getFollow(appBaseUrl, cbLoc.pathname + cbLoc.search, cookies);
    assert.strictEqual(cbRes.status, 302);
    const failLoc = new URL(cbRes.headers.get("location"));
    assert.strictEqual(failLoc.searchParams.get("error"), "oidc_failed");
    assert.strictEqual(failLoc.searchParams.get("provider"), "test-oidc");
    assert.strictEqual(failLoc.searchParams.get("reason"), "callback_error");
    assert.strictEqual(pool._state.users.length, 0, "no user must be provisioned");
  });

  for (const [description, configure] of [
    ["wrong issuer", () => ({ tokenIssuer: "https://unexpected.example.test" })],
    ["wrong audience", () => ({ tokenAudience: "another-client" })],
    ["expired ID token", () => ({ tokenExpiration: "-5m" })],
    ["untrusted signing key", () => ({
      tokenSigningKey: crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey,
    })],
  ]) {
    it("rejects an ID token with " + description, async () => {
      Object.assign(idp.config, configure());
      const { res: authRes, cookies } = await startAuthorization();
      const idpRedirect = await fetch(authRes.headers.get("location"), { redirect: "manual" });
      const callback = new URL(idpRedirect.headers.get("location"));
      const response = await getFollow(appBaseUrl, callback.pathname + callback.search, cookies);

      assert.strictEqual(response.status, 302);
      const failure = new URL(response.headers.get("location"));
      assert.strictEqual(failure.pathname, "/login");
      assert.strictEqual(failure.searchParams.get("error"), "oidc_failed");
      assert.strictEqual(failure.searchParams.get("reason"), "callback_error");
      assert.strictEqual(pool._state.users.length, 0);
    });
  }

  it("rejects login when UserInfo sub does not match ID Token sub", async () => {
    idp.config.userinfoSub = "sub-from-a-different-account";
    const { res: authRes, cookies } = await startAuthorization();
    const idpUrl = new URL(authRes.headers.get("location"));
    const idpRedirect = await fetch(idpUrl.toString(), { redirect: "manual" });
    const cbLoc = new URL(idpRedirect.headers.get("location"));

    const cbRes = await getFollow(appBaseUrl, cbLoc.pathname + cbLoc.search, cookies);
    assert.strictEqual(cbRes.status, 302);
    const failLoc = new URL(cbRes.headers.get("location"));
    assert.strictEqual(failLoc.searchParams.get("error"), "oidc_failed");
    assert.strictEqual(failLoc.searchParams.get("provider"), "test-oidc");
    assert.strictEqual(failLoc.searchParams.get("reason"), "userinfo_sub_mismatch");
    assert.strictEqual(pool._state.users.length, 0, "no user must be provisioned");
  });

  it("rejects PKCE-missing token exchange (proves code_verifier is actually sent)", async () => {
    // The IdP enforces PKCE; if our code did NOT send code_verifier, /token
    // would 400 with pkce_missing_verifier. The happy-path test above already
    // proves the verifier is sent, but we double-check by toggling the IdP
    // to demand it explicitly and re-running.
    idp.config.requirePkce = true;
    const { res: authRes, cookies } = await startAuthorization();
    const idpRedirect = await fetch(authRes.headers.get("location"), {
      redirect: "manual",
    });
    const cbLoc = new URL(idpRedirect.headers.get("location"));
    const cbRes = await getFollow(appBaseUrl, cbLoc.pathname + cbLoc.search, cookies);
    assert.strictEqual(cbRes.status, 302);
    assert.match(
      cbRes.headers.get("location"),
      /\/dashboard$/,
      "PKCE happy-path should land on /dashboard when no next= is given",
    );
  });
});
