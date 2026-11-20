/**
 * Route-level tests for oidcRoutes (callback handler wiring).
 */

"use strict";

const { describe, it, before, after, beforeEach } = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const crypto = require("node:crypto");

const oidcProvider = require("../../apps/api/auth/oidc");

const PROVIDER_SLUG = "route-test";

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
      handle: async (req, res, next) => {
        const route = routes.find((r) => {
          if (r.method !== req.method) return false;
          const params = matchRoutePattern(r.path, req.path);
          if (!params) return false;
          req.params = params;
          return true;
        });
        if (!route) return next();
        await route.handler(req, res, next);
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
  return res;
}

function parseQuery(search) {
  const params = new URLSearchParams(search);
  const out = {};
  for (const [k, v] of params.entries()) out[k] = v;
  return out;
}

function makeSessionApp(router) {
  const sessions = new Map();
  const server = http.createServer(async (rawReq, rawRes) => {
    const url = new URL(rawReq.url, `http://${rawReq.headers.host || "x"}`);
    const req = rawReq;
    req.path = url.pathname;
    req.query = parseQuery(url.search.slice(1));
    req.originalUrl = rawReq.url;

    const m = /tt_sid=([^;]+)/.exec(rawReq.headers.cookie || "");
    let sid = m ? m[1] : crypto.randomBytes(16).toString("hex");
    if (!m) rawRes.setHeader("Set-Cookie", `tt_sid=${sid}; HttpOnly; Path=/`);
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
    await router.handle(req, res, () => {
      res.statusCode = 404;
      res.end("not found");
    });
  });
  return { server, sessions, sidForCookie: (sid) => `tt_sid=${sid}` };
}

/** Minimal pool for a single new-user OIDC login. */
function makeMinimalPool() {
  const state = { users: [], links: [], hasMembership: false };
  const handle = async (sql, params = []) => {
    const flat = sql.replace(/\s+/g, " ").trim();
    if (/^BEGIN$|^COMMIT$|^ROLLBACK$/i.test(flat)) {
      return { rows: [], rowCount: 0 };
    }
    if (/^SELECT pg_advisory_xact_lock/i.test(flat)) {
      return { rows: [], rowCount: 1 };
    }
    if (/^SELECT type, config FROM sso_providers WHERE slug = \$1 AND enabled FOR SHARE/i.test(flat)) {
      return { rows: [{ type: "oidc", config: { issuer: "https://idp.test" } }], rowCount: 1 };
    }
    if (/^UPDATE users SET recipient_verified_email/i.test(flat)) {
      const user = state.users.find((u) => u.id === params[0]);
      if (user) {
        user.recipient_verified_email = params[2] === true &&
          user.email_original.trim().toLowerCase() === params[1].trim().toLowerCase()
          ? params[1].trim().toLowerCase() : null;
      }
      return { rows: [], rowCount: user ? 1 : 0 };
    }
    if (/external_identities ei JOIN users u/i.test(flat) && /subject_id = \$2/i.test(flat)) {
      const link = state.links.find((row) => row.provider === params[0] && row.subject === params[1]);
      const user = link && state.users.find((row) => row.id === link.userId);
      return user
        ? { rows: [{ ...user, link_id: link.id, auth_method_before: user.auth_method }], rowCount: 1 }
        : { rows: [], rowCount: 0 };
    }
    if (/FROM users WHERE LOWER\(email\)/i.test(flat)) {
      const user = state.users.find((row) => row.email.toLowerCase() === params[0].toLowerCase());
      return user ? { rows: [user], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (/^SELECT subject_id FROM external_identities|^SELECT 1 FROM external_identities|^UPDATE external_identities/i.test(flat)) {
      return { rows: [], rowCount: 0 };
    }
    if (/INSERT INTO users/i.test(flat)) {
      const [email, emailOriginal, displayName] = params;
      const row = {
        id: "user-1",
        email,
        email_original: emailOriginal,
        display_name: displayName,
        auth_method: "sso",
        email_verified: true,
        is_admin: false,
      };
      state.users.push(row);
      return { rowCount: 1, rows: [row] };
    }
    if (/INSERT INTO external_identities/i.test(flat)) {
      const [userId, provider, , subject] = params;
      state.links.push({ id: state.links.length + 1, userId, provider, subject });
      return { rowCount: 1, rows: [{ user_id: userId }] };
    }
    if (/^UPDATE users SET auth_method =/i.test(flat)) {
      const user = state.users.find((row) => row.id === params[0]);
      if (!user || (user.auth_method === "local" && flat.includes("AND auth_method <> 'local'"))) {
        return { rows: [], rowCount: 0 };
      }
      user.auth_method = "sso";
      user.email_verified = true;
      return { rows: [], rowCount: 1 };
    }
    if (/sso_group_role_mappings/i.test(flat)) {
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
    if (/FROM workspaces/i.test(flat)) {
      return { rowCount: 0, rows: [] };
    }
    if (/^SELECT 1 FROM workspace_memberships WHERE user_id/i.test(flat)) {
      return state.hasMembership ? { rowCount: 1, rows: [{}] } : { rowCount: 0, rows: [] };
    }
    if (/workspace_memberships/i.test(flat) && /SELECT/i.test(flat)) {
      return { rowCount: 0, rows: [] };
    }
    if (/UPDATE users SET is_admin/i.test(flat)) {
      return { rowCount: 0, rows: [] };
    }
    if (/INSERT INTO workspace_memberships/i.test(flat)) {
      return { rowCount: 0, rows: [] };
    }
    if (/SELECT \* FROM users WHERE id = \$1/i.test(flat)) {
      const u = state.users.find((u) => u.id === params[0]);
      return u ? { rowCount: 1, rows: [u] } : { rowCount: 0, rows: [] };
    }
    throw new Error(`minimal pool: unhandled SQL: ${flat}`);
  };
  return {
    connect: async () => ({ query: handle, release: () => {} }),
    query: handle,
    _state: state,
  };
}

describe("OIDC callback route", () => {
  const originalEnv = { ...process.env };
  let server;
  let baseUrl;
  let sessions;
  let pool;
  let userinfoCalls;
  let idClaims;
  let userinfoClaims;
  const callbackAudit = [];
  const provisioned = [];

  before(async () => {
    process.env.APP_URL = "http://localhost:5173";

    pool = makeMinimalPool();
    await oidcProvider.setupOidcStrategy({}, pool, null, {
      loadProviders: async () => [], writeAudit: async (event) => callbackAudit.push(event),
      logger: { info() {}, warn() {}, error() {} },
    });
    userinfoCalls = [];

    const tokenSet = {
      access_token: "access-1",
      claims: () => idClaims,
    };

    const client = {
      callback: async () => tokenSet,
      userinfo: async (arg) => {
        userinfoCalls.push(arg);
        return userinfoClaims;
      },
    };

    const expressShim = makeMiniExpress();
    const router = oidcProvider.oidcRoutes({}, expressShim);
    const app = makeSessionApp(router);
    sessions = app.sessions;
    server = app.server;
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;

    oidcProvider._setOidcRuntimeForTests(PROVIDER_SLUG, {
      providerSlug: PROVIDER_SLUG,
      displayName: PROVIDER_SLUG,
      enabled: true,
      issuer: "https://idp.test",
      strategyConfig: {
        issuer: "https://idp.test",
        userInfoURL: "https://idp.test/userinfo",
        callbackURL: `${baseUrl}/auth/oidc/${PROVIDER_SLUG}/callback`,
      },
      client,
      openIdClient: null,
      pkceEnabled: true,
      claimConfig: {
        oidc: {
          email: ["emails[0].value", "email"],
          displayName: ["displayName", "name"],
          groups: ["groups"],
          subject: ["id", "sub"],
        },
      },
      securityConfig: {
        allowAutoLinkLocalAccounts: true,
        strictMembershipSync: false,
        pkce: true,
      },
      bootstrapAdminGroups: [],
      pool,
      deps: {
        canonicalizeEmail: (e) => String(e || "").trim().toLowerCase(),
        logger: { warn: () => {} },
        writeAudit: null,
        ensureInitialWorkspaceForUser: (...args) => provisioned.push(args),
      },
    });
  });

  after(async () => {
    process.env = { ...originalEnv };
    oidcProvider._resetOidcRuntimeForTests();
    await new Promise((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  });

  beforeEach(() => {
    callbackAudit.length = 0;
    userinfoCalls.length = 0;
    provisioned.length = 0;
    pool._state.users.length = 0;
    pool._state.links.length = 0;
    pool._state.hasMembership = false;
    sessions.clear();
    idClaims = { sub: "route-sub-1", email: "route-user@example.com", email_verified: true };
    userinfoClaims = { sub: "route-sub-1", email: "route-user@example.com" };
  });

  it("calls client.userinfo with the access_token string, not the TokenSet", async () => {
    const sid = crypto.randomBytes(8).toString("hex");
    sessions.set(sid, {
      oidcAuth: {
        "state-ok": {
          providerSlug: PROVIDER_SLUG,
          state: "state-ok",
          nonce: "nonce-ok",
          codeVerifier: "verifier-ok",
          next: null,
        },
      },
    });

    const res = await fetch(
      `${baseUrl}/auth/oidc/${PROVIDER_SLUG}/callback?code=abc&state=state-ok`,
      {
        redirect: "manual",
        headers: { cookie: `tt_sid=${sid}` },
      },
    );

    assert.strictEqual(res.status, 302);
    assert.strictEqual(userinfoCalls.length, 1);
    assert.strictEqual(userinfoCalls[0], "access-1");
    assert.notStrictEqual(typeof userinfoCalls[0], "object");
    const loggedIn = sessions.get(sid);
    assert.ok(loggedIn?.user, "req.logIn should persist the user on the session");
    assert.strictEqual(loggedIn.user.email, "route-user@example.com");
    assert.strictEqual(pool._state.users[0].recipient_verified_email, "route-user@example.com");
  });

  it("records only the callback pathname and failure reason for a missing transaction", async () => {
    const path = `/auth/oidc/${PROVIDER_SLUG}/callback`;
    const response = await fetch(`${baseUrl}${path}?state=test-state&code=test-code`, {
      redirect: "manual",
    });
    assert.equal(response.status, 302);
    const event = callbackAudit.find((item) => item.action === "LOGIN_FAILED");
    assert.deepEqual(event.metadata, {
      method: "oidc", provider_slug: PROVIDER_SLUG, protocol: "oidc",
      reason: "state_mismatch", path,
    });
  });

  const otherEmail = "different@example.com";
  const cases = [
    { name: "absent verification", id: {}, ui: {}, proof: false },
    { name: "false verification", id: { email_verified: false }, ui: {}, proof: false },
    { name: "true verification", id: { email_verified: true }, ui: {}, proof: true },
    { name: "ID proof for a different UserInfo mailbox", id: { email_verified: true },
      ui: { email: otherEmail }, proof: false },
    { name: "UserInfo proof without a UserInfo mailbox", id: {},
      ui: { email: undefined, email_verified: true }, proof: false },
    { name: "UserInfo proof for the selected mailbox", id: {},
      ui: { email: otherEmail, email_verified: true }, proof: true },
    { name: "UserInfo false overrides ID true", id: { email_verified: true },
      ui: { email_verified: false }, proof: false },
    { name: "same-mailbox case and whitespace", id: { email_verified: true },
      ui: { email: " ROUTE-USER@EXAMPLE.COM " }, proof: true },
    { name: "custom email mapping cannot borrow standard email proof", id: { email_verified: true },
      ui: { mailbox: otherEmail }, emailPath: "mailbox,email", proof: false },
    { name: "ID custom mailbox cannot borrow UserInfo proof", id: { mailbox: otherEmail },
      ui: { email_verified: true }, emailPath: "mailbox,email", proof: false },
  ];
  for (const scenario of cases) {
    it(`persists recipient proof at the callback boundary: ${scenario.name}`, async () => {
      idClaims = { sub: "route-sub-1", email: "route-user@example.com", ...scenario.id };
      userinfoClaims = { sub: "route-sub-1", email: "route-user@example.com", ...scenario.ui };
      if (userinfoClaims.email === undefined) delete userinfoClaims.email;
      const runtime = oidcProvider.getOidcRuntime(PROVIDER_SLUG);
      const oldEmailPath = runtime.claimConfig.oidc.email;
      runtime.claimConfig.oidc.email = scenario.emailPath || "email,emails.0.value";
      try {
        const sid = crypto.randomBytes(8).toString("hex");
        sessions.set(sid, {
          oidcAuth: { "state-proof": { providerSlug: PROVIDER_SLUG, state: "state-proof",
            nonce: "nonce-proof", codeVerifier: "verifier-proof" } },
        });
        const res = await fetch(
          `${baseUrl}/auth/oidc/${PROVIDER_SLUG}/callback?code=abc&state=state-proof`,
          { redirect: "manual", headers: { cookie: `tt_sid=${sid}` } },
        );
        assert.strictEqual(res.status, 302);
        assert.ok(sessions.get(sid)?.user, "login policy must remain unchanged");
        const user = pool._state.users[0];
        assert.strictEqual(user.recipient_verified_email,
          scenario.proof ? user.email_original.trim().toLowerCase() : null);
      } finally {
        runtime.claimConfig.oidc.email = oldEmailPath;
      }
    });
  }

  for (const { name, id, ui, proof, emailPath } of cases) {
    it(`requires proof to link a local account: ${name}`, async () => {
      idClaims = { sub: "route-sub-1", email: "route-user@example.com", ...id };
      userinfoClaims = { sub: idClaims.sub, email: "route-user@example.com", ...ui };
      if (userinfoClaims.email === undefined) delete userinfoClaims.email;
      const runtime = oidcProvider.getOidcRuntime(PROVIDER_SLUG);
      const previousEmailPath = runtime.claimConfig.oidc.email;
      runtime.claimConfig.oidc.email = emailPath || "email";
      const selectedEmail =
        (ui.mailbox || id.mailbox || userinfoClaims.email || idClaims.email).trim().toLowerCase();
      const local = {
        id: "local-1", email: selectedEmail, email_original: selectedEmail,
        display_name: "Member", auth_method: "local", email_verified: true,
        password_hash: "local-hash", is_admin: false,
      };
      pool._state.users.push(local);
      try {
        const signIn = async () => {
          const sid = crypto.randomBytes(8).toString("hex");
          sessions.set(sid, {
            oidcAuth: { "state-link": { providerSlug: PROVIDER_SLUG, state: "state-link",
              nonce: "nonce-link", codeVerifier: "verifier-link" } },
          });
          const res = await fetch(
            `${baseUrl}/auth/oidc/${PROVIDER_SLUG}/callback?code=abc&state=state-link`,
            { redirect: "manual", headers: { cookie: `tt_sid=${sid}` } },
          );
          assert.strictEqual(res.status, 302);
          return { session: sessions.get(sid), location: new URL(res.headers.get("location")) };
        };
        const { session, location } = await signIn();
        assert.strictEqual(pool._state.users.length, 1);
        assert.strictEqual(pool._state.links.length, proof ? 1 : 0);
        if (proof) {
          assert.strictEqual(session.user.id, local.id);
          assert.strictEqual(session.sso.protocol, "oidc");
          assert.strictEqual(session.user.auth_method, "local");
          assert.strictEqual((await signIn()).session.user.auth_method, "local");
          assert.strictEqual(local.password_hash, "local-hash");
          assert.deepStrictEqual(provisioned.map((args) => args[3]), [
            { sso: true, verifiedEmail: selectedEmail },
            { sso: true, verifiedEmail: selectedEmail },
          ]);
        } else {
          assert.strictEqual(location.searchParams.get("reason"), "email_not_verified_for_link");
          assert.strictEqual(session.user, undefined);
          assert.deepStrictEqual(provisioned, []);
        }
      } finally {
        runtime.claimConfig.oidc.email = previousEmailPath;
      }
    });
  }

  for (const verifiedEmail of [false, true]) {
    it(`strict OIDC admission can redeem only an invitation for a verified mailbox (proof=${verifiedEmail})`, async () => {
      idClaims.email_verified = verifiedEmail;
      const runtime = oidcProvider.getOidcRuntime(PROVIDER_SLUG);
      const originalEnsure = runtime.deps.ensureInitialWorkspaceForUser;
      runtime.securityConfig.strictMembershipSync = true;
      runtime.deps.ensureInitialWorkspaceForUser = async (...args) => {
        const options = args[3];
        provisioned.push(options);
        if (options.invitationsOnly && options.verifiedEmail === idClaims.email) {
          pool._state.hasMembership = true;
        }
      };
      try {
        const sid = crypto.randomBytes(8).toString("hex");
        sessions.set(sid, {
          oidcAuth: { "state-strict": { providerSlug: PROVIDER_SLUG, state: "state-strict",
            nonce: "nonce", codeVerifier: "verifier" } },
        });
        const res = await fetch(
          `${baseUrl}/auth/oidc/${PROVIDER_SLUG}/callback?code=abc&state=state-strict`,
          { redirect: "manual", headers: { cookie: `tt_sid=${sid}` } },
        );
        const location = new URL(res.headers.get("location"));
        if (verifiedEmail) {
          assert.equal(location.pathname, "/dashboard");
          assert.ok(sessions.get(sid).user);
          assert.deepEqual(provisioned, [
            { sso: true, verifiedEmail: idClaims.email, invitationsOnly: true },
            { sso: true, verifiedEmail: idClaims.email },
          ]);
        } else {
          assert.equal(location.searchParams.get("reason"), "no_group_mapping_matched");
          assert.equal(sessions.get(sid).user, undefined);
          assert.deepEqual(provisioned, []);
        }
      } finally {
        runtime.securityConfig.strictMembershipSync = false;
        runtime.deps.ensureInitialWorkspaceForUser = originalEnsure;
      }
    });
  }
});
