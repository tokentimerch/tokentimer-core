"use strict";

const assert = require("node:assert/strict");
const { once } = require("node:events");
const http = require("node:http");
const https = require("node:https");
const { createRequire } = require("node:module");
const path = require("node:path");
const { test } = require("node:test");
const { rootCertificates } = require("node:tls");
const { validateAcmeIssuerDirectory } = require("../../apps/api/services/certops/issuerValidation");
const { createPinnedGet } = require("../../packages/webhook-safety");
const { createHttpsTarget } = require("../../scripts/proxy-smoke/fixtures");

const workspaceId = "2ca59d06-4cae-4f89-bf6f-16388f48f49a";
const issuerId = "89503dcc-431b-4a9c-ab0d-d7bb589ef695";
const caEndpoint = "https://ca.example/directory";
const directory = {
  newNonce: "https://ca.example/nonce",
  newAccount: "https://ca.example/account",
  newOrder: "https://ca.example/order",
  revokeCert: "https://ca.example/revoke",
  meta: { externalAccountRequired: true, opaque: "never returned" },
};

function input(t, { rows = [{ kind: "acme" }], request, endpoint = caEndpoint } = {}) {
  const previous = [process.env.OFFLINE_MODE, process.env.OUTBOUND_ALLOWLIST];
  delete process.env.OFFLINE_MODE;
  delete process.env.OUTBOUND_ALLOWLIST;
  t.after(() => {
    for (const [index, name] of ["OFFLINE_MODE", "OUTBOUND_ALLOWLIST"].entries()) {
      if (previous[index] == null) delete process.env[name];
      else process.env[name] = previous[index];
    }
  });
  return {
    workspaceId, issuerId, caEndpoint: endpoint,
    client: {
      async query(sql, args) {
        assert.match(sql, /workspace_id = \$1 AND id = \$2/);
        assert.deepEqual(args, [workspaceId, issuerId]);
        return { rows };
      },
    },
    request: request || (() => assert.fail("Unexpected outbound request")),
  };
}

test("ACME directory validation returns only the advertised capability flags", async t => {
  let calls = 0;
  const result = await validateAcmeIssuerDirectory(input(t, {
    async request(url, options) {
      assert.equal(url, caEndpoint);
      assert.deepEqual(options, { headers: { Accept: "application/json" }, timeoutMs: 5_000 });
      calls += 1;
      return { status: 200, bodyText: JSON.stringify(directory) };
    },
  }));
  assert.equal(calls, 1);
  assert.deepEqual(result, { issuerId, kind: "acme", revocationAdvertised: true, externalAccountRequired: true });
});

test("ACME validation stops for an unknown issuer or an AD CS issuer", async t => {
  const args = input(t, { rows: [] });
  await assert.rejects(validateAcmeIssuerDirectory(args), { code: "CERTOPS_ISSUER_NOT_FOUND" });
  args.client.query = async () => ({ rows: [{ kind: "adcs" }] });
  await assert.rejects(validateAcmeIssuerDirectory(args), { code: "CERTOPS_ISSUER_KIND_INVALID" });
});

test("ACME validation refuses invalid URLs and outbound policy denial", async t => {
  const args = input(t);
  for (const endpoint of ["http://ca.example/directory", "https://user:password@ca.example/directory",
    "https://ca.example/directory?token=secret", "https://ca.example/directory#fragment",
    "https://ca.example/directory?", "https://ca.example/directory#", "https://ca.example/" + "x".repeat(512)]) {
    await assert.rejects(validateAcmeIssuerDirectory({ ...args, caEndpoint: endpoint }), {
      code: "CERTOPS_ISSUER_DIRECTORY_URL_INVALID",
    });
  }
  process.env.OUTBOUND_ALLOWLIST = "other.example";
  await assert.rejects(validateAcmeIssuerDirectory(args), { code: "OUTBOUND_POLICY_DENIED" });
});

test("ACME validation returns stable failures and suppresses upstream data", async t => {
  const args = input(t);
  for (const bodyText of ["<html>secret</html>", JSON.stringify({ ...directory, newOrder: "http://ca.example/order" })]) {
    const request = async () => ({ status: 200, bodyText });
    await assert.rejects(validateAcmeIssuerDirectory({ ...args, request }), {
      code: "CERTOPS_ISSUER_DIRECTORY_INVALID",
    });
  }
  const timeout = async () => { throw Object.assign(new Error("upstream secret"), { code: "WEBHOOK_TIMEOUT" }); };
  await assert.rejects(validateAcmeIssuerDirectory({ ...args, request: timeout }), {
    code: "CERTOPS_ISSUER_DIRECTORY_TIMEOUT",
    message: "The ACME directory did not respond within five seconds.",
  });
  const request = async () => { throw new Error("upstream secret"); };
  await assert.rejects(validateAcmeIssuerDirectory({ ...args, request }), {
    code: "CERTOPS_ISSUER_DIRECTORY_UNREACHABLE",
    message: "The API could not connect directly to the ACME directory. Check DNS, connectivity and CA trust.",
  });
});

test("pinned read sends a bodyless GET and rejects redirects and oversize responses", async t => {
  input(t);
  const received = [];
  const server = http.createServer((req, res) => {
    received.push([req.method, req.url, req.headers["content-length"]]);
    if (req.url === "/redirect") res.writeHead(302, { Location: "/unintended" }).end();
    else if (req.url === "/oversize") res.end(Buffer.alloc(70 * 1024));
    else res.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(createPinnedGet(() => true)(base), { code: "WEBHOOK_PRIVATE_IP_BLOCKED" });
  const get = createPinnedGet(() => false);
  assert.deepEqual(await get(base + "/directory"), { status: 200, bodyText: "{}" });
  await assert.rejects(get(base + "/redirect"), { code: "WEBHOOK_REDIRECT_REFUSED" });
  await assert.rejects(get(base + "/oversize"), { code: "WEBHOOK_UNREACHABLE" });
  assert.deepEqual(received, [
    ["GET", "/directory", undefined],
    ["GET", "/redirect", undefined],
    ["GET", "/oversize", undefined],
  ]);
});

test("the mounted API route restricts access and validates a real local TLS directory", async t => {
  input(t);
  const previous = {
    CERTOPS_ENABLED: process.env.CERTOPS_ENABLED,
    INTEGRATION_ALLOW_PRIVATE_IPS: process.env.INTEGRATION_ALLOW_PRIVATE_IPS,
  };
  t.after(() => {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });
  process.env.CERTOPS_ENABLED = "true";
  process.env.INTEGRATION_ALLOW_PRIVATE_IPS = "true";

  const ca = createHttpsTarget();
  t.after(ca.close);
  const caPort = await ca.listen();
  const observed = [];
  ca.server.removeAllListeners("request");
  ca.server.on("request", (req, res) => {
    observed.push([req.method, req.url, req.socket.servername]);
    res.end(JSON.stringify(directory));
  });
  const request = https.request;
  t.mock.method(https, "request", (options, callback) => {
    assert.equal(options.rejectUnauthorized, true);
    return request({ ...options, ca: [...rootCertificates, ca.certPem] }, callback);
  });

  const requireApi = createRequire(path.resolve(__dirname, "../../apps/api/package.json"));
  const express = requireApi("express");
  const { pool } = require("../../apps/api/db/database");
  const lookup = t.mock.method(pool, "query", async (sql, values) => {
    assert.match(sql, /FROM certificate_issuers/);
    assert.deepEqual(values, [workspaceId, issuerId]);
    return { rows: [{ kind: "acme" }] };
  });
  const router = require("../../apps/api/routes/certops-enrollments");
  const app = express();
  app.use(express.json(), (req, _res, next) => {
    req.workspace = { id: workspaceId };
    req.authz = {
      workspaceRole: req.headers["x-test-role"] === "viewer" ? "workspace_viewer" : "workspace_manager",
    };
    req.user = { id: "fixture-user" };
    req.isWorkerCall = req.headers["x-test-role"] === "worker";
    next();
  }, router);
  const server = http.createServer(app);
  t.after(() => new Promise(resolve => server.close(resolve)));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");

  const endpoint = `http://127.0.0.1:${server.address().port}/api/v1/workspaces/${workspaceId}/certops/issuers/${issuerId}/validate`;
  const check = role => fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-test-role": role },
    body: JSON.stringify({ caEndpoint: `https://localhost:${caPort}/directory` }),
  });
  for (const role of ["viewer", "worker"]) {
    const denied = await check(role);
    assert.equal(denied.status, 403);
    await denied.text();
  }
  assert.equal(lookup.mock.callCount(), 0);
  assert.deepEqual(observed, []);

  const allowed = await check("manager");
  assert.equal(allowed.status, 200);
  assert.deepEqual(await allowed.json(), {
    validation: { issuerId, kind: "acme", revocationAdvertised: true, externalAccountRequired: true },
  });
  assert.equal(lookup.mock.callCount(), 1);
  assert.deepEqual(observed, [["GET", "/directory", "localhost"]]);
});
