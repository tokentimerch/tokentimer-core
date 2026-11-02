"use strict";

process.env.NODE_ENV = "test";
delete process.env.ENABLE_METRICS;
delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

test("webhook failures are classified from status and error code", async () => {
  const { _test } = await import("../../apps/worker/src/delivery-worker.js");
  const { postJson } = await import("../../apps/worker/src/notify/webhooks.js");
  const terminal = _test.webhookEndpointTerminal;

  for (const status of [200, 201, 204]) {
    assert.equal(terminal({ success: true, status }), false, String(status));
  }
  for (const status of [400, 401, 403, 404]) {
    assert.equal(terminal({ success: false, status, error: `HTTP ${status}` }), true, String(status));
  }
  for (const status of [408, 409, 429, 500, 502, 503, 504]) {
    assert.equal(terminal({ success: false, status, error: `HTTP ${status}` }), false, String(status));
  }
  for (const code of ["ETIMEDOUT", "ESOCKETTIMEDOUT", "WEBHOOK_TIMEOUT", "WEBHOOK_UNREACHABLE", "WEBHOOK_DNS_UNRESOLVED", "ECONNRESET", "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "EHOSTUNREACH", "ENETUNREACH", "UND_ERR_CONNECT_TIMEOUT", "ECONNABORTED", "WEBHOOK_NETWORK"]) {
    assert.equal(terminal({ success: false, code, error: code }), false, code);
  }
  assert.equal(terminal({ success: false, code: "WEBHOOK_INVALID_URL", error: "Invalid webhook URL" }), true);
  assert.equal(terminal({ success: false, code: "WEBHOOK_INVALID_SCHEME", error: "Invalid webhook URL scheme" }), true);
  assert.equal(terminal({ success: false, status: 302, code: "WEBHOOK_REDIRECT_REFUSED", error: "redirect refused" }), true);
  assert.equal(terminal({ success: false, code: "WEBHOOK_HOST_NOT_ALLOWED", error: "Webhook host not allowed for provider" }), true);
  assert.equal(terminal({ success: false, code: "WEBHOOK_PRIVATE_IP_BLOCKED", error: "Resolved to private/reserved IP" }), true);
  assert.equal(terminal({ success: false, status: 200, code: "WEBHOOK_PROVIDER_REJECTED", error: "PagerDuty responded HTTP 200" }), true);
  assert.equal(terminal({ success: false, status: 503, code: "WEBHOOK_PROVIDER_REJECTED", error: "PagerDuty responded HTTP 503" }), false);
  assert.equal(terminal({ success: false, error: "connect ECONNREFUSED 127.0.0.1:80" }), false);
  assert.equal(terminal({ success: false, status: 503, error: "http://127.0.0.1/__permanent__" }), false);

  const statuses = [200, 201, 204, 400, 401, 403, 404, 408, 409, 429, 500, 502, 503, 504];
  const server = http.createServer((req, res) => {
    const status = Number(req.url.slice(1));
    res.writeHead(status, { "content-type": "text/plain" });
    res.end("body");
  });
  const port = await listen(server);
  try {
    for (const status of statuses) {
      const result = await postJson(`http://127.0.0.1:${port}/${status}`, { ping: true }, "generic");
      assert.equal(result.status, status);
      assert.equal(result.success, status >= 200 && status < 300);
      assert.equal(terminal(result), status >= 400 && status < 500 && ![408, 409, 429].includes(status));
    }
    const invalid = await postJson("not a url", {}, "generic");
    assert.equal(invalid.code, "WEBHOOK_INVALID_URL");
    assert.equal(terminal(invalid), true);
    const ftp = await postJson("ftp://example.com/hook", {}, "generic");
    assert.equal(ftp.code, "WEBHOOK_INVALID_URL");
    assert.equal(terminal(ftp), true);
    const deniedHost = await postJson("http://127.0.0.1/hook", {}, "pagerduty");
    assert.equal(deniedHost.code, "WEBHOOK_HOST_NOT_ALLOWED");
    assert.equal(terminal(deniedHost), true);
    const refused = await postJson("http://127.0.0.1:1/hook", {}, "generic");
    assert.equal(refused.code, "WEBHOOK_UNREACHABLE");
    assert.equal(terminal(refused), false);
    const missing = await postJson("http://this-name-should-not-exist.invalid/hook", {}, "generic");
    assert.ok(["ENOTFOUND", "EAI_AGAIN", "WEBHOOK_TIMEOUT", "WEBHOOK_DNS_UNRESOLVED", "WEBHOOK_UNREACHABLE"].includes(missing.code), missing.code);
    assert.equal(terminal(missing), false);

    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    const blocked = await postJson("http://127.0.0.1:9/hook", {}, "generic");
    assert.equal(blocked.code, "WEBHOOK_PRIVATE_IP_BLOCKED");
    assert.equal(terminal(blocked), true);
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

    const hanging = http.createServer(() => {});
    const hangPort = await listen(hanging);
    try {
      const timedOut = await postJson(`http://127.0.0.1:${hangPort}/slow`, {}, "generic");
      assert.equal(timedOut.code, "WEBHOOK_TIMEOUT");
      assert.equal(terminal(timedOut), false);
    } finally {
      await close(hanging);
    }
  } finally {
    await close(server);
  }
});

test.after(async () => {
  try {
    const db = await import("../../apps/worker/src/db.js");
    await db.pool.end();
  } catch {
    // Import creates the pool; ending it lets the test process exit.
  }
});
