"use strict";

const assert = require("node:assert/strict");
const { once } = require("node:events");
const http = require("node:http");
const https = require("node:https");
const { test } = require("node:test");
const {
  assertOutboundUrl,
  isAllowedHost,
  OUTBOUND_POLICY_DENIED,
} = require("../../packages/config/src/network.cjs");
const { postWebhook } = require("../../packages/webhook-safety");
const { checkIntegrationAddress } = require("../../apps/api/utils/integrationAddressGuard");
const { vaultHttpRequest } = require("../../apps/api/services/vaultAuth");

function setPolicy(t, { offline = "false", allowlist = "" } = {}) {
  const names = ["OFFLINE_MODE", "OUTBOUND_ALLOWLIST", "INTEGRATION_ALLOW_PRIVATE_IPS", "WEBHOOK_ALLOW_PRIVATE_IPS"];
  const previous = new Map(names.map((name) => [name, process.env[name]]));
  t.after(() => {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });
  process.env.OFFLINE_MODE = offline;
  process.env.OUTBOUND_ALLOWLIST = allowlist;
}

test("unconfigured connections are allowed and offline mode with an empty list denies them", (t) => {
  setPolicy(t);
  assert.equal(isAllowedHost("api.example"), true);
  process.env.OFFLINE_MODE = "true";
  assert.equal(isAllowedHost("api.example"), false);
  assert.throws(() => assertOutboundUrl("https://api.example/token?secret=example"), {
    code: OUTBOUND_POLICY_DENIED,
    message: "Destination is blocked by the outbound policy",
  });
});

test("a nonempty allowlist applies in online mode and rejects unrelated or malformed hosts", (t) => {
  setPolicy(t, { allowlist: "*.Corp.Example.,192.0.2.0/24,2001:db8::/32,999.0.0.0/0,203.0.113.0/24x" });
  for (const host of ["corp.example", "A.CORP.EXAMPLE.", "192.0.2.4", "[2001:db8:0::5]"]) {
    assert.equal(isAllowedHost(host), true, host);
  }
  for (const host of ["badcorp.example", "corp.example.other", "192.0.3.1", "203.0.113.5", "2001:db9::1", "https://corp.example"]) {
    assert.equal(isAllowedHost(host), false, host);
  }
});

test("zone-qualified IPv6 entries do not match or block other allowlist entries", (t) => {
  setPolicy(t, { allowlist: "fe80::1%eth0,fe80::%eth0/64,vault.example,2001:db8::/32" });
  assert.equal(isAllowedHost("vault.example"), true);
  assert.equal(isAllowedHost("[2001:db8::1]"), true);
  assert.equal(isAllowedHost("[fe80::1]"), false);
  assert.equal(isAllowedHost("fe80::1%eth0"), false);
});

test("endpoint monitor listing reports scheduled TLS and manual HTTP policy separately", async (t) => {
  setPolicy(t, { allowlist: "endpoint.example" });
  const agentOptions = https.globalAgent.options;
  const originalProxyEnv = Object.getOwnPropertyDescriptor(agentOptions, "proxyEnv");
  t.after(() => {
    if (originalProxyEnv) Object.defineProperty(agentOptions, "proxyEnv", originalProxyEnv);
    else delete agentOptions.proxyEnv;
  });
  agentOptions.proxyEnv = { HTTPS_PROXY: "http://proxy.example" };

  const { pool } = require("../../apps/api/db/database");
  const router = require("../../apps/api/routes/admin");
  const route = router.stack.find(({ route }) => route?.path === "/api/v1/workspaces/:id/domains" && route.methods.get).route;
  t.mock.method(pool, "query", async (_sql, params) => {
    assert.deepEqual(params, ["workspace-id"]);
    return { rows: [
      { url: "https://endpoint.example", health_check_enabled: false },
      { url: "https://endpoint.example", health_check_enabled: true },
      { url: "https://other.example", health_check_enabled: false },
    ] };
  });
  let data;
  await route.stack.at(-1).handle({ workspace: { id: "workspace-id" } }, {
    json(body) { data = body; },
  });
  assert.deepEqual(data.items.map((row) => [row.outbound_policy_blocked, row.outbound_manual_check_blocked]), [
    [false, true],
    [true, true],
    [true, true],
  ]);
});

test("bulk import reports policy skips and preserves the response when checks are allowed", async (t) => {
  setPolicy(t, { offline: "true" });
  const { pool } = require("../../apps/api/db/database");
  const router = require("../../apps/api/routes/admin");
  const route = router.stack.find(({ route }) => route?.path === "/api/v1/workspaces/:id/domain-checker/import").route;
  const token = { id: 1, name: "server.example.com", expiration: "2030-01-01" };
  t.mock.method(pool, "connect", async () => ({
    query: async (sql) => ({ rows: sql.includes("INSERT INTO tokens") ? [token] : [] }),
    release() {},
  }));
  const query = t.mock.method(pool, "query", async (sql) => ({
    rows: sql.includes("INSERT INTO domain_monitors") ? [{ id: 1, token_id: token.id }] : [],
  }));
  const monitorInserts = () => query.mock.calls.filter(({ arguments: [sql] }) =>
    sql.includes("INSERT INTO domain_monitors"),
  ).length;
  async function importCertificate() {
    let status;
    let data;
    await route.stack.at(-1).handle({
      workspace: { id: 1 },
      user: { id: 1 },
      body: {
        domain: "example.com",
        certificates: [{ domains: [token.name], expiration: token.expiration }],
        monitorOptions: { enabled: true },
      },
    }, {
      status(code) { status = code; return this; },
      json(body) { data = body; },
    });
    assert.equal(status, 201);
    assert.equal(data.imported[0].tokenId, token.id);
    return data.monitors;
  }

  assert.deepEqual(await importCertificate(), { created: 0, existing: 0, blocked: 1 });
  assert.equal(monitorInserts(), 0);

  process.env.OUTBOUND_ALLOWLIST = token.name;
  assert.deepEqual(await importCertificate(), { created: 1, existing: 0 });
  assert.equal(monitorInserts(), 1);
});

test("API integration validation denies before resolution even when private addresses are enabled", async (t) => {
  setPolicy(t, { offline: "true", allowlist: "vault.corp.example" });
  process.env.INTEGRATION_ALLOW_PRIVATE_IPS = "true";
  const lookup = () => assert.fail("Blocked host reached the resolver");
  const denied = await checkIntegrationAddress(new URL("https://other.example"), { lookup });
  assert.equal(denied.allowed, false);
  assert.equal(denied.code, OUTBOUND_POLICY_DENIED);
  assert.deepEqual(await checkIntegrationAddress(new URL("https://vault.corp.example"), { lookup }), { allowed: true });
});

test("the production webhook test rejects HTTP before sending", async (t) => {
  const router = require("../../apps/api/routes/alerts");
  const route = router.stack.find(({ route }) => route?.path === "/api/test-webhook").route;
  const previous = process.env.NODE_ENV;
  t.after(() => {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  });
  process.env.NODE_ENV = "production";

  let status;
  let result;
  await route.stack.at(-1).handle({
    user: { id: -789 },
    body: { url: "http://webhook.example.invalid", kind: "generic" },
  }, {
    status(code) { status = code; return this; },
    json(body) { result = body; },
  });
  assert.equal(status, 400);
  assert.equal(result.code, "WEBHOOK_INVALID_URL");
});

test("webhook transport and Vault fetch share the policy before network I/O", async (t) => {
  setPolicy(t, { offline: "true", allowlist: "other.example" });
  process.env.WEBHOOK_ALLOW_PRIVATE_IPS = "true";
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests += 1;
    request.resume();
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end('{"ok":true}');
  });
  server.listen(0, "127.0.0.1");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await once(server, "listening");
  const address = "http://127.0.0.1:" + server.address().port;
  const webhook = () => postWebhook(address + "/hook", { proxyMode: "never" });
  const vault = () => vaultHttpRequest({ address, path: "/v1/secret" });
  await assert.rejects(webhook, { code: OUTBOUND_POLICY_DENIED });
  await assert.rejects(vault, { code: OUTBOUND_POLICY_DENIED });
  assert.equal(requests, 0);

  process.env.OUTBOUND_ALLOWLIST = "127.0.0.0/8";
  assert.equal((await webhook()).status, 200);
  assert.deepEqual(await vault(), { ok: true });
  assert.equal(requests, 2);
});

test("webhook delivery requires its configured proxy host to be allowed", async (t) => {
  setPolicy(t, { allowlist: "hooks.example" });
  const priorProxy = process.env.HTTP_PROXY;
  const priorNoProxy = process.env.NO_PROXY;
  t.after(() => {
    if (priorProxy === undefined) delete process.env.HTTP_PROXY;
    else process.env.HTTP_PROXY = priorProxy;
    if (priorNoProxy === undefined) delete process.env.NO_PROXY;
    else process.env.NO_PROXY = priorNoProxy;
  });
  process.env.HTTP_PROXY = "http://proxy.example:8080";
  process.env.NO_PROXY = "excluded.example";
  await assert.rejects(
    () => postWebhook("http://hooks.example", {
      lookupAll: () => assert.fail("Blocked proxy reached destination resolution"),
    }),
    { code: OUTBOUND_POLICY_DENIED },
  );
});

test("GitHub integration honors the outbound proxy policy and no-proxy host or CIDR", async (t) => {
  setPolicy(t, { allowlist: "127.0.0.1" });
  for (const name of ["HTTP_PROXY", "NO_PROXY", "NODE_ENV"]) {
    const value = process.env[name];
    t.after(() => {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    });
  }
  process.env.HTTP_PROXY = "http://localhost:9";
  process.env.NO_PROXY = "elsewhere.example";
  process.env.NODE_ENV = "test";
  const { githubRequest } = require("../../apps/api/services/githubIntegration")._test;
  let hits = 0;
  const server = http.createServer((_request, response) => {
    hits += 1;
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end('{"login":"fixture"}');
  });
  server.listen(0, "127.0.0.1");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await once(server, "listening");
  const request = () => githubRequest({
    baseUrl: "http://127.0.0.1:" + server.address().port,
    path: "/user",
    token: "fixture",
  });
  await assert.rejects(request, { code: OUTBOUND_POLICY_DENIED });
  assert.equal(hits, 0);
  process.env.NO_PROXY = "127.0.0.1";
  assert.deepEqual(await request(), { login: "fixture" });
  assert.equal(hits, 1);
  process.env.NO_PROXY = "127.0.0.0/8";
  assert.deepEqual(await request(), { login: "fixture" });
  assert.equal(hits, 2);

  process.env.NO_PROXY = "127.0.0.0/08";
  await assert.rejects(request, { code: OUTBOUND_POLICY_DENIED });
  assert.equal(hits, 2);
});

test("an unapproved environment SMTP relay leaves an approved DB relay usable", async (t) => {
  setPolicy(t, { allowlist: "127.0.0.1" });
  for (const name of ["SMTP_HOST", "NODE_ENV"]) {
    const value = process.env[name];
    t.after(() => {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    });
  }
  process.env.SMTP_HOST = "smtp.blocked.example";
  const { createServer } = require("node:net");
  let messages = 0;
  const server = createServer((socket) => {
    let buffer = "";
    let collecting = false;
    socket.setEncoding("utf8");
    socket.setTimeout(3_000, () => socket.destroy());
    socket.write("220 fixture ESMTP\r\n");
    socket.on("data", (data) => {
      buffer += data;
      let newline;
      while ((newline = buffer.indexOf("\r\n")) !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 2);
        if (collecting) {
          if (line === ".") {
            collecting = false;
            messages += 1;
            socket.write("250 accepted\r\n");
          }
        } else if (/^QUIT$/i.test(line)) {
          socket.end("221 bye\r\n");
        } else if (/^DATA$/i.test(line)) {
          collecting = true;
          socket.write("354 start mail input\r\n");
        } else {
          socket.write("250 fixture\r\n");
        }
      }
    });
  });
  server.listen(0, "127.0.0.1");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await once(server, "listening");
  const { sendEmailNotification } = await import("../../apps/worker/src/notify/email.js");
  const { pool } = await import("../../apps/worker/src/db.js");
  t.mock.method(pool, "query", async () => ({
    rows: [{
      smtp_host: "127.0.0.1",
      smtp_port: server.address().port,
      smtp_secure: "false",
      smtp_require_tls: "false",
      smtp_from_email: "ops@example.invalid",
    }],
  }));
  process.env.NODE_ENV = "development";
  const attempts = [];
  const result = await sendEmailNotification({
    to: "recipient@example.invalid",
    subject: "Test message",
    text: "Fixture",
    onBeforeAttempt: ({ attempt }) => attempts.push(attempt),
  });
  assert.deepEqual(result, { success: true });
  assert.deepEqual(attempts, ["db-smtp", "db-smtp-send"]);
  assert.equal(messages, 1);
});

test("native fetch checks an HTTP proxy used for HTTPS and mixed wildcard exclusions", () => {
  const { spawnSync } = require("node:child_process");
  const modulePath = require.resolve("../../packages/config/src/network.cjs");
  const code = [
    'const assert = require("node:assert/strict");',
    'const { assertOutboundUrl } = require(process.argv[1]);',
    'const [major, minor] = process.versions.node.split(".").map(Number);',
    'const check = () => assertOutboundUrl("https://ca.example", { proxyMode: "fetch" });',
    'if (major >= 24 || (major === 22 && minor >= 21)) {',
    '  assert.throws(check, { code: "OUTBOUND_POLICY_DENIED" });',
    '} else {',
    '  assert.doesNotThrow(check);',
    '}',
  ].join("\n");
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(?:http_proxy|https_proxy|no_proxy|all_proxy|node_use_env_proxy|node_options)$/i.test(key)) delete env[key];
  }
  const result = spawnSync(process.execPath, ["-e", code, modulePath], {
    env: { ...env, HTTP_PROXY: "http://proxy.example", NO_PROXY: "*,other.example", NODE_USE_ENV_PROXY: "1", OUTBOUND_ALLOWLIST: "ca.example" },
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});

test("policy denials stay distinct from provider credential or empty scan outcomes", async (t) => {
  setPolicy(t, { offline: "true" });
  for (const name of ["AWS_ENDPOINT_URL", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"]) {
    const value = process.env[name];
    t.after(() => {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    });
  }
  // These tests never need a provider endpoint. Redirect accidental calls to
  // a closed loopback socket so even a guard regression stays local.
  process.env.AWS_ENDPOINT_URL = "http://127.0.0.1:9";
  process.env.HTTP_PROXY = "http://127.0.0.1:9";
  process.env.HTTPS_PROXY = "http://127.0.0.1:9";
  process.env.NO_PROXY = "unused.example";
  const { detectAWSRegions } = require("../../apps/api/services/awsIntegration");
  const { scanAzureAD } = require("../../apps/api/services/azureADIntegration");
  const { scanGCP } = require("../../apps/api/services/gcpIntegration");
  const denied = { code: OUTBOUND_POLICY_DENIED };
  await assert.rejects(detectAWSRegions({ accessKeyId: "fixture", secretAccessKey: "fixture" }), denied);
  await assert.rejects(scanAzureAD({ token: "fixture" }), denied);
  await assert.rejects(scanGCP({ projectId: "fixture", accessToken: "fixture", include: { secrets: true } }), denied);
});
