"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { randomBytes, randomUUID } = require("node:crypto");
const { execFileSync, spawn } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const http = require("node:http");
const { startLocalHttpsServer, TEST_HTTPS_CERT } = require("../integration/helpers/local-https-server.js");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");
const { createRequire } = require("node:module");

const root = path.resolve(__dirname, "../..");
const requireApi = createRequire(path.join(root, "apps/api/package.json"));
const kcImage = "quay.io/keycloak/keycloak:26.8.1";
const docker = (...args) =>
  execFileSync("docker", args, { encoding: "utf8", windowsHide: true }).trim();
const secret = () => randomBytes(24).toString("hex");
const password = () => "Tt9!" + secret();

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) =>
    server.once("error", reject).listen(0, "127.0.0.1", resolve),
  );
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

// Chromium sees a real HTTPS relying party on localhost and a separate IdP site on
// 127.0.0.1. The two proxies share only their public hostname and test certificate.
function startTlsProxy(upstreamPort, observe) {
  return startLocalHttpsServer({
    advertisedHost: "localhost",
    handler(req, res) {
      observe?.(req);
      const upstream = http.request({
        host: "127.0.0.1", port: upstreamPort, path: req.url, method: req.method,
        headers: { ...req.headers, "x-forwarded-proto": "https" },
      }, (response) => {
        res.writeHead(response.statusCode, response.headers);
        response.pipe(res);
      });
      upstream.on("error", () => {
        if (res.headersSent) return res.destroy();
        res.writeHead(502);
        res.end();
      });
      req.pipe(upstream);
    },
  });
}

// Validate the unchanged signed response from the disposable IdP against a
// standalone verifier. The browser journey exercises Core's live correlation.
async function verifySamlRejections(response, config, callbackUrl) {
  const { SAML } = requireApi("@node-saml/passport-saml");
  assert.ok(response, "Keycloak SAML response was observed");
  const options = {
    callbackUrl,
    issuer: config.issuer,
    audience: config.issuer,
    idpCert: config.cert,
    validateInResponseTo: "never",
  };
  const validate = (settings) =>
    new SAML({ ...options, ...settings }).validatePostResponseAsync({
      SAMLResponse: response,
    });

  assert.ok((await validate({})).profile, "the synthetic fixture is valid");
  await assert.rejects(validate({ idpCert: TEST_HTTPS_CERT }), /invalid (?:document )?signature/i);
  await assert.rejects(validate({ audience: "different-test-service" }), /audience/i);
  // The verifier may discard expired subject confirmation before checking conditions.
  await assert.rejects(
    validate({ maxAssertionAgeMs: 1 }),
    /expired|no valid subject confirmation/i,
  );
  await assert.rejects(validate({ validateInResponseTo: "always" }), /inresponseto.*not valid/i);
}

async function ready(url, child) {
  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    if (child && child.exitCode !== null)
      throw new Error("Service exited with code " + child.exitCode);
    try {
      if ((await fetch(url, { signal: AbortSignal.timeout(2000) })).ok) return;
    } catch {
      /* The service is starting. */
    }
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error("Service did not become ready at " + url);
}

function realm(api, app, oidcSecret, userPassword) {
  return {
    realm: "tt-test",
    enabled: true,
    sslRequired: "external",
    groups: [{ name: "qa-viewers" }],
    clients: [
      {
        clientId: "core-oidc",
        protocol: "openid-connect",
        publicClient: false,
        secret: oidcSecret,
        standardFlowEnabled: true,
        directAccessGrantsEnabled: false,
        redirectUris: [api + "/auth/oidc/oidc/callback"],
        attributes: {
          "pkce.code.challenge.method": "S256",
          "post.logout.redirect.uris": app + "/login",
        },
        protocolMappers: [{
          name: "OIDC groups",
          protocol: "openid-connect",
          protocolMapper: "oidc-group-membership-mapper",
          config: {
            "full.path": "false",
            "claim.name": "groups",
            "id.token.claim": "true",
            "userinfo.token.claim": "true",
          },
        }],
      },
      {
        clientId: api + "/saml",
        protocol: "saml",
        enabled: true,
        redirectUris: [api + "/auth/saml/saml/callback"],
        attributes: {
          "saml.client.signature": "false",
          "saml.assertion.signature": "true",
          "saml.server.signature": "true",
          "saml.force.post.binding": "true",
          saml_name_id_format: "email",
          saml_force_name_id_format: "true",
          saml_assertion_consumer_url_post: api + "/auth/saml/saml/callback",
        },
        protocolMappers: [{
          name: "SAML groups",
          protocol: "saml",
          protocolMapper: "saml-group-membership-mapper",
          config: {
            "full.path": "false",
            "attribute.name": "groups",
            "attribute.nameformat": "Basic",
            "single": "true",
          },
        }],
      },
    ],
    users: ["oidc", "saml", "oidc-unmapped", "saml-unmapped"].map((type) => ({
      username: type + "-user",
      email: type + "@example.test",
      emailVerified: true,
      firstName: "Test",
      lastName: type,
      enabled: true,
      groups: type.endsWith("-unmapped") ? [] : ["/qa-viewers"],
      credentials: [
        { type: "password", value: userPassword, temporary: false },
      ],
    })),
  };
}

async function write(request, api, app, method, route, data, status) {
  const csrf = await request.get(api + "/api/csrf-token");
  assert.equal(csrf.status(), 200);
  const response = await request.fetch(api + route, {
    method,
    data,
    headers: { "x-csrf-token": (await csrf.json()).csrfToken, Origin: app },
  });
  if (response.status() !== status) {
    const error = await response.json().catch(() => ({}));
    assert.fail(
      method +
        " " +
        route +
        " returned " +
        response.status() +
        ": " +
        (error.error || error.code || ""),
    );
  }
}

async function createMapping(page, provider) {
  await page.getByRole("button", { name: "Add mapping", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Identity provider").selectOption(provider);
  await dialog.getByLabel("IdP group name").fill("qa-viewers");
  await dialog.getByLabel("TokenTimer role to grant").selectOption("viewer");
  await dialog.getByRole("button", { name: "Create mapping", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
}

async function verifySamlLogoutWithConcurrentRead({
  context, api, pgPort, pgPassword, userId, logout,
}) {
  const { Client } = requireApi("pg");
  const db = new Client({
    host: "127.0.0.1",
    port: Number(pgPort),
    user: "postgres",
    password: pgPassword,
    database: "tt_sso_test",
  });
  const countSessions = async () => {
    const { rows } = await db.query(
      "SELECT count(*)::int AS count FROM session WHERE sess #>> '{passport,user}' = $1",
      [String(userId)],
    );
    return rows[0].count;
  };

  await db.connect();
  try {
    const { rows: memberships } = await db.query(
      "SELECT workspace_id FROM workspace_memberships WHERE user_id = $1 AND source_provider_slug = 'saml'",
      [userId],
    );
    assert.equal(memberships.length, 1);
    assert.equal(await countSessions(), 1);
    const { rows: [{ pid }] } = await db.query("SELECT pg_backend_pid() AS pid");
    await db.query("BEGIN");
    let read;
    try {
      // Block a real authenticated read once it reaches PostgreSQL, after its
      // session has been loaded. Logout itself does not read the workspaces table.
      await db.query("LOCK TABLE workspaces IN ACCESS EXCLUSIVE MODE");
      read = context.request.get(
        api + "/api/v1/workspaces/" + memberships[0].workspace_id + "/alert-settings",
      );
      read.catch(() => {});
      const deadline = Date.now() + 10000;
      let waiting = false;
      do {
        // The lock transaction can cache a snapshot taken before the read connected.
        await db.query("SELECT pg_stat_clear_snapshot()");
        const { rows } = await db.query(
          "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))) AS waiting",
          [pid],
        );
        waiting = rows[0].waiting;
        if (!waiting) await new Promise((resolve) => setTimeout(resolve, 50));
      } while (!waiting && Date.now() < deadline);
      assert.equal(waiting, true, "The authenticated read must be in flight before logout");

      await logout();
      assert.equal(await countSessions(), 0, "Logout must delete the authenticated session");
    } finally {
      await db.query("ROLLBACK");
      if (read) assert.equal((await read).status(), 200);
    }
    assert.equal(await countSessions(), 0, "A concurrent read must not restore the logged-out session");
  } finally {
    await db.end();
  }
}

test(
  "Core signs in and out with Keycloak OIDC and SAML while both providers are active",
  {
    skip: process.env.TT_KEYCLOAK_E2E !== "1",
    timeout: 300000,
  },
  async (t) => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "tt-core-sso-"));
    const owned = [],
      children = [];
    let browser, apiProxy, appProxy;
    let samlPost;
    t.after(async () => {
      try {
        await browser?.close();
        await Promise.all([apiProxy?.close(), appProxy?.close()]);
      } finally {
        for (const child of children.reverse()) {
          if (child.exitCode === null && child.signalCode === null) {
            await new Promise((resolve) => {
              child.once("exit", resolve);
              child.kill();
            });
          }
        }
        try {
          for (const name of owned.reverse()) docker("rm", "-fv", name);
        } finally {
          fs.rmSync(scratch, { recursive: true, force: true });
        }
      }
    });
    const id = randomUUID().slice(0, 8);
    function create(role, args) {
      const name = "tt-sso-" + id + "-" + role;
      docker("create", "--name", name, ...args);
      owned.push(name);
      return name;
    }
    const apiPort = await freePort(),
      appPort = await freePort(),
      kcPort = await freePort();
    apiProxy = await startTlsProxy(apiPort, (req) => {
      if (req.method === "POST" && req.url === "/auth/saml/saml/callback") {
        samlPost = {
          site: req.headers["sec-fetch-site"],
          hasBrowserCookie: /(?:^|;\s*)__Host-tt-saml-browser=/.test(req.headers.cookie || ""),
        };
      }
    });
    appProxy = await startTlsProxy(appPort);
    const api = apiProxy.url, app = appProxy.url;
    const issuer = "http://127.0.0.1:" + kcPort + "/realms/tt-test";
    const pgPassword = password(),
      adminPassword = password(),
      userPassword = password(),
      clientSecret = secret();
    const pg = create("pg", [
      "-p",
      "127.0.0.1::5432",
      "-e",
      "POSTGRES_DB=tt_sso_test",
      "-e",
      "POSTGRES_PASSWORD=" + pgPassword,
      "postgres:16-alpine",
    ]);
    docker("start", pg);
    const pgPort = docker("port", pg, "5432/tcp").split(":").pop();
    const realmPath = path.join(scratch, "tt-test-realm.json");
    fs.writeFileSync(
      realmPath,
      JSON.stringify(realm(api, app, clientSecret, userPassword)),
    );
    const kc = create("keycloak", [
      "-p",
      "127.0.0.1:" + kcPort + ":8080",
      "--mount",
      "type=bind,src=" +
        realmPath +
        ",dst=/opt/keycloak/data/import/tt-test-realm.json,readonly",
      kcImage,
      "start-dev",
      "--import-realm",
    ]);
    docker("start", kc);
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([k]) =>
        /^(path|systemroot|userprofile|home|temp|tmp|comspec|pathext)$/i.test(
          k,
        ),
      ),
    );
    function serve(entry, args, options) {
      const child = spawn(process.execPath, [entry, ...args], {
        cwd: scratch,
        windowsHide: true,
        stdio: ["ignore", "ignore", "inherit"],
        ...options,
      });
      children.push(child);
      return child;
    }
    const core = serve(path.join(root, "apps/api/index.js"), [], {
      env: {
        ...env,
        NODE_ENV: "development",
        HOST: "127.0.0.1",
        PORT: String(apiPort),
        API_URL: api,
        APP_URL: app,
        PUBLIC_BASE_URL: api,
        TRUST_PROXY_HOPS: "1",
        DB_HOST: "127.0.0.1",
        DB_PORT: pgPort,
        DB_USER: "postgres",
        DB_PASSWORD: pgPassword,
        DB_NAME: "tt_sso_test",
        ADMIN_EMAIL: "admin@example.test",
        ADMIN_PASSWORD: adminPassword,
        SESSION_SECRET: secret(),
        SSO_POST_LOGOUT_REDIRECT: "true",
        SSO_SECRETS_KEYRING: JSON.stringify({
          primary: "test",
          keys: { test: randomBytes(32).toString("base64") },
        }),
      },
    });
    const dashboard = path.join(root, "apps/dashboard");
    const ui = serve(
      path.join(dashboard, "node_modules/vite/bin/vite.js"),
      ["--host", "127.0.0.1", "--port", String(appPort), "--strictPort"],
      {
        cwd: dashboard,
        env: { ...env, VITE_API_URL: api },
      },
    );
    await Promise.all([
      ready("http://127.0.0.1:" + apiPort + "/health", core),
      ready(issuer + "/.well-known/openid-configuration"),
      ready("http://127.0.0.1:" + appPort, ui),
    ]);
    browser = await chromium.launch();
    // The checked-in loopback certificate is trusted only by these test contexts.
    const localContext = () => browser.newContext({ ignoreHTTPSErrors: true });
    const admin = await localContext();
    await write(
      admin.request,
      api,
      app,
      "POST",
      "/auth/login",
      { email: "admin@example.test", password: adminPassword },
      200,
    );
    const adminPath = "/api/admin/sso/providers";
    const mappingPath = "/api/admin/sso/group-mappings";
    const adminPage = await admin.newPage();
    adminPage.setDefaultTimeout(15000);
    await adminPage.goto(app + "/onboarding");
    await adminPage.getByText("Set up single sign-on for my team", { exact: true }).click();
    await adminPage.getByRole("button", { name: "Continue", exact: true }).click();
    await adminPage.getByText("Choose protocol", { exact: true }).waitFor();
    const next = adminPage.getByRole("button", { name: "Continue", exact: true });
    await next.click();
    await next.click();
    await adminPage.getByLabel("Display name").fill("Keycloak OIDC");
    await adminPage.getByPlaceholder("entra-prod").fill("oidc");
    await adminPage.getByLabel("Issuer URL").fill(issuer);
    await adminPage.getByLabel("Client ID").fill("core-oidc");
    await adminPage.getByLabel("Client secret").fill(clientSecret);
    await next.click();
    await next.click();
    const [connectivity] = await Promise.all([
      adminPage.waitForResponse((response) =>
        new URL(response.url()).pathname === adminPath + "/oidc/test" &&
        response.request().method() === "POST"),
      adminPage.getByRole("button", { name: "Save and run test" }).click(),
    ]);
    assert.equal(connectivity.status(), 200);
    assert.equal((await connectivity.json()).ok, true, "OIDC connectivity test");
    await adminPage.getByRole("button", { name: "Enable provider", exact: true }).click();
    await adminPage.getByText("OIDC, sign-in ready", { exact: true }).waitFor();
    await next.click();
    await adminPage.getByRole("heading", { name: "Map groups to roles", exact: true }).waitFor();
    await createMapping(adminPage, "oidc");
    t.diagnostic("The setup guide configured, tested, enabled and mapped Keycloak OIDC");

    await adminPage.goto(app + "/sso-providers/oidc");
    await adminPage.getByRole("button", { name: "Show advanced options" }).click();
    await adminPage.getByLabel("Sample payload").fill(JSON.stringify({ groups: ["qa-viewers"] }));
    const [simulation] = await Promise.all([
      adminPage.waitForResponse((response) =>
        new URL(response.url()).pathname === mappingPath + "/simulate"),
      adminPage.getByRole("button", { name: "Simulate", exact: true }).click(),
    ]);
    assert.equal(simulation.status(), 200);
    const simulated = await simulation.json();
    assert.deepEqual(simulated.grants.map(({ role }) => role), ["viewer"]);
    await adminPage.getByRole("cell", { name: "Viewer", exact: true }).waitFor();

    const openSystemSso = async () => {
      await adminPage.goto(app + "/system-settings");
      await adminPage.getByRole("button", { name: /Single Sign-On \(SSO\)/i }).click();
    };
    await openSystemSso();
    await adminPage.getByText("Installation-wide SSO policy", { exact: true }).waitFor();
    assert.equal(await adminPage.getByLabel("Strict membership sync", { exact: true }).isChecked(), true);
    const policy = await (await admin.request.get(api + "/api/admin/system-settings")).json();
    assert.equal(policy.sso.strict_membership_sync.value, null, "no operator override is saved");
    const waiting = await localContext();
    const waitingPage = await waiting.newPage();
    await waitingPage.goto(app + "/login");
    await waitingPage.getByRole("link", { name: "Sign in with Keycloak OIDC", exact: true }).waitFor();
    assert.equal(await waitingPage.getByRole("link", { name: "Sign in with Keycloak SAML", exact: true }).count(), 0);

    await adminPage.goto(app + "/sso-providers/new");
    await adminPage.getByRole("combobox", { name: "Protocol", exact: true }).selectOption("saml");
    await next.click();
    await adminPage.getByRole("combobox", { name: "Template", exact: true }).selectOption("keycloak");
    await next.click();
    await adminPage.getByLabel("Display name").fill("Keycloak SAML");
    await adminPage.getByPlaceholder("entra-prod").fill("saml");
    const descriptor = await fetch(issuer + "/protocol/saml/descriptor");
    assert.equal(descriptor.status, 200);
    await adminPage.getByLabel("Or paste metadata XML").fill(await descriptor.text());
    await next.click();
    await next.click();
    await adminPage.getByRole("button", { name: "Save and run test" }).click();
    await adminPage.getByRole("button", { name: "Enable provider", exact: true }).click();
    await adminPage.waitForURL(url => url.pathname === "/system-settings" &&
      url.searchParams.get("provider") === "saml");
    await createMapping(adminPage, "saml");

    const saml = await (await admin.request.get(api + adminPath + "/saml")).json();
    assert.equal(saml.enabled, true);
    const enabledProtocols = Object.entries((await (
      await admin.request.get(api + "/api/auth/features")
    ).json()).providers);
    assert.deepEqual(enabledProtocols.map(([type, providers]) => [type, providers.length, providers[0]?.signInReady]),
      [["oidc", 1, true], ["saml", 1, true]]);

    await waitingPage.evaluate(() => window.dispatchEvent(new Event("pageshow")));
    await waitingPage.getByRole("link", { name: "Sign in with Keycloak SAML", exact: true }).waitFor();
    await waitingPage.getByRole("link", { name: "Sign in with Keycloak OIDC", exact: true }).waitFor();
    await waiting.close();
    t.diagnostic("Keycloak SAML was enabled from the standalone wizard and appeared beside OIDC on an existing login page");

    for (const type of ["oidc", "saml"]) {
      const displayName = "Keycloak " + type.toUpperCase();
      const context = await localContext();
      const page = await context.newPage();
      const navigations = [];
      let samlResponse;
      page.on("request", (req) => {
        if (!req.isNavigationRequest()) return;
        const url = new URL(req.url());
        navigations.push(url.origin + url.pathname);
        if (type === "saml" && req.method() === "POST" &&
            url.origin === api && url.pathname === "/auth/saml/saml/callback") {
          samlResponse = req.postDataJSON()?.SAMLResponse;
        }
      });
      const features = await (
        await context.request.get(api + "/api/auth/features")
      ).json();
      assert.ok(
        features.providers[type].some((p) => p.slug === type && p.signInReady),
        type + " sign-in readiness",
      );
      if (type === "saml") {
        const metadata = await context.request.get(
          api + "/auth/saml/saml/metadata",
        );
        assert.equal(metadata.status(), 200);
        assert.match(await metadata.text(), /AssertionConsumerService/);
      }
      await page.goto(app + "/login?next=%2Fworkspaces");
      await page.getByRole("link", { name: "Sign in with Keycloak OIDC", exact: true }).waitFor();
      await page.getByRole("link", { name: "Sign in with Keycloak SAML", exact: true }).waitFor();
      await page
        .getByRole("link", { name: "Sign in with " + displayName, exact: true })
        .click();
      try {
        await page
          .locator("#username")
          .fill(type + "-user", { timeout: 15000 });
      } catch (error) {
        t.diagnostic("Browser navigation: " + navigations.join(" -> "));
        const current = new URL(page.url());
        t.diagnostic(
          "Login landed at " +
            current.origin +
            current.pathname +
            ", error=" +
            (current.searchParams.get("error") || "") +
            ", page=" +
            (await page.title()) +
            ", heading=" +
            (await page.locator("h1").allTextContents()).join(" "),
        );
        throw error;
      }
      if (type === "saml") {
        const cookies = await context.cookies(api);
        const correlation = cookies.find((cookie) => cookie.name === "__Host-tt-saml-browser");
        assert.ok(correlation?.httpOnly && correlation.secure);
        assert.equal(correlation.sameSite, "None");
      }
      await page.locator("#password").fill(userPassword);
      await page.locator("#kc-login").click();
      await page.waitForURL((url) => url.origin === app && url.pathname === "/workspaces");
      const session = await (
        await context.request.get(api + "/api/session")
      ).json();
      assert.equal(
        session.loggedIn,
        true,
        type +
          " callback did not create a Core session at " +
          page.url().split("?")[0],
      );
      if (type === "saml") {
        assert.deepEqual(samlPost, { site: "cross-site", hasBrowserCookie: true });
        t.diagnostic("Chromium sent the host-only Secure SameSite=None cookie on Keycloak's cross-site HTTPS POST");
        await verifySamlRejections(samlResponse, saml.config, api + "/auth/saml/saml/callback");
        t.diagnostic("The signed SAML fixture was rejected for an untrusted signer, incorrect audience, expiry, and missing request context");
      }
      assert.equal(session.user.email, type + "@example.test");
      assert.equal(session.user.isAdmin, false);
      assert.equal((await context.request.get(api + mappingPath)).status(), 403);
      const membership = docker(
        "exec", pg, "psql", "-U", "postgres", "-d", "tt_sso_test", "-At", "-c",
        "SELECT m.role || ':' || m.source || ':' || m.source_provider_slug " +
          "FROM workspace_memberships m JOIN users u ON u.id = m.user_id " +
          "WHERE u.email = '" + type + "@example.test'",
      );
      assert.equal(membership, "viewer:sso:" + type);
      const logout = () => page.getByRole("menuitem", { name: "Sign Out", exact: true }).click();
      await page.locator('button[data-tour="user-menu"]').click();
      if (type === "oidc") {
        await Promise.all([
          page.waitForRequest(request => {
            const url = new URL(request.url());
            return url.origin === new URL(issuer).origin &&
              url.pathname === "/realms/tt-test/protocol/openid-connect/logout";
          }),
          logout(),
        ]);
        await page.waitForURL(app + "/login");
        await page.getByRole("link", { name: "Sign in with " + displayName, exact: true }).click();
        await page.locator("#username").waitFor();
      } else {
        await verifySamlLogoutWithConcurrentRead({
          context,
          api,
          pgPort,
          pgPassword,
          userId: session.user.id,
          logout: async () => {
            const [response] = await Promise.all([
              page.waitForResponse((result) =>
                new URL(result.url()).pathname === "/api/logout" &&
                result.request().method() === "POST"),
              logout(),
            ]);
            assert.equal(response.status(), 200);
            await page.waitForURL(app + "/login");
          },
        });
        await page.getByRole("link", { name: "Sign in with " + displayName, exact: true }).waitFor();
      }
      assert.equal(
        (await (await context.request.get(api + "/api/session")).json())
          .loggedIn,
        false,
      );
      await context.close();
      t.diagnostic(
        type.toUpperCase() +
          " administrator setup, browser sign-in, Core session and logout passed",
      );
    }
    for (const type of ["oidc", "saml"]) {
      const context = await localContext();
      try {
        const page = await context.newPage();
        await page.goto(app + "/login");
        await page.getByRole("link", { name: "Sign in with Keycloak " + type.toUpperCase(), exact: true }).click();
        await page.locator("#username").fill(type + "-unmapped-user");
        await page.locator("#password").fill(userPassword);
        await page.locator("#kc-login").click();
        await page.waitForURL(url => url.origin === app && url.pathname === "/login" && url.searchParams.has("error"));
        const session = await (await context.request.get(api + "/api/session")).json();
        assert.equal(session.loggedIn, false);
        const denied = docker(
          "exec", pg, "psql", "-U", "postgres", "-d", "tt_sso_test", "-At", "-c",
          "SELECT EXISTS (SELECT 1 FROM audit_events WHERE action = 'LOGIN_FAILED' " +
            "AND metadata->>'reason' = 'no_group_mapping_matched' AND metadata->>'method' = '" + type + "')",
        );
        assert.equal(denied, "t", type + " denies an unmapped account under the default policy");
        const membership = docker(
          "exec", pg, "psql", "-U", "postgres", "-d", "tt_sso_test", "-At", "-c",
          "SELECT COUNT(*) FROM workspace_memberships m JOIN users u ON u.id = m.user_id " +
            "WHERE u.email = '" + type + "-unmapped@example.test'",
        );
        assert.equal(membership, "0", type + " must not create a Default workspace membership");
      } finally {
        await context.close();
      }
    }
    t.diagnostic("The default policy denied fresh unmapped OIDC and SAML users");

    docker("stop", kc);
    const recovery = await localContext();
    await write(
      recovery.request,
      api,
      app,
      "POST",
      "/auth/login",
      {
        email: "admin@example.test",
        password: adminPassword,
      },
      200,
    );
    const recovered = await (
      await recovery.request.get(api + "/api/session")
    ).json();
    assert.equal(recovered.user.isAdmin, true);
    await write(
      recovery.request,
      api,
      app,
      "PUT",
      adminPath + "/saml",
      { enabled: false },
      200,
    );
    const features = await (
      await recovery.request.get(api + "/api/auth/features")
    ).json();
    assert.deepEqual(features.providers.saml, []);
    assert.deepEqual(features.providers.oidc.map(p => p.slug), ["oidc"]);
    await recovery.close();
    t.diagnostic(
      "Local admin signed in with Keycloak offline and disabled SAML without disabling OIDC",
    );
  },
);
