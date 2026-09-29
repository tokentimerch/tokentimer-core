"use strict";

const { it } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

it("returns a safe error for HTTP failure, refusal, and timeout", async () => {
  const previous = Object.fromEntries(
    [
      "NODE_ENV",
      "WEBHOOK_ALLOW_PRIVATE_IPS",
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "NO_PROXY",
    ].map((key) => [key, process.env[key]]),
  );
  Object.assign(process.env, {
    NODE_ENV: "development",
    WEBHOOK_ALLOW_PRIVATE_IPS: "true",
    HTTP_PROXY: "",
    HTTPS_PROXY: "",
    NO_PROXY: "127.0.0.1,localhost",
  });
  const server = http.createServer((request, response) => {
    if (request.url === "/timeout") return;
    response.writeHead(503, { "Content-Type": "application/json" });
    response.end('{"error":"provider failed","secret":"do-not-expose"}');
  });
  try {
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    const { postJson } =
      await import("../../apps/worker/src/notify/webhooks.js");
    const { buildOperationalIncidentEmail } =
      await import("../../apps/worker/src/notify/email.js");
    const failed = await postJson(
      `http://127.0.0.1:${port}/fail`,
      {},
      "generic",
    );
    assert.deepEqual(failed, {
      success: false,
      status: 503,
      error: "HTTP 503",
    });
    const message = `webhooks: generic: ${failed.error}`;
    const email = buildOperationalIncidentEmail({
      category: "delivery",
      title: "Delivery blocked: Test token",
      message,
    });
    for (const visible of [message, email.html, email.text]) {
      assert.match(visible, /generic: HTTP 503/);
      assert.doesNotMatch(visible, /undefined|null|do-not-expose/i);
    }

    const timedOut = await postJson(
      `http://127.0.0.1:${port}/timeout`,
      {},
      "generic",
    );
    assert.equal(timedOut.success, false);
    assert.match(timedOut.error, /timed? out|timeout/i);
    assert.doesNotMatch(timedOut.error, /undefined|null/i);

    await new Promise((resolve) => server.close(resolve));
    const refused = await postJson(
      `http://127.0.0.1:${port}/fail`,
      {},
      "generic",
    );
    assert.equal(refused.success, false);
    assert.match(refused.error, /refused|unreachable/i);
    assert.doesNotMatch(refused.error, /undefined|null/i);
  } finally {
    server.closeAllConnections();
    if (server.listening) await new Promise((resolve) => server.close(resolve));
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

it("keeps PagerDuty response bodies out of failed delivery results", async () => {
  const keys = [
    "NODE_ENV",
    "WEBHOOK_ALLOW_PRIVATE_IPS",
    "WEBHOOK_EXTRA_PROVIDER_HOSTS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
  ];
  const previous = Object.fromEntries(
    keys.map((key) => [key, process.env[key]]),
  );
  Object.assign(process.env, {
    NODE_ENV: "development",
    WEBHOOK_ALLOW_PRIVATE_IPS: "true",
    WEBHOOK_EXTRA_PROVIDER_HOSTS: "127.0.0.1",
    HTTP_PROXY: "",
    HTTPS_PROXY: "",
    NO_PROXY: "127.0.0.1,localhost",
  });
  const secret = "provider-response-secret";
  const server = http.createServer((request, response) => {
    if (request.url === "/success") {
      response.setHeader("Content-Type", "application/json");
      response.writeHead(200);
      response.end('{"status":"success"}');
    } else if (request.url === "/plain") {
      response.setHeader("Content-Type", "text/plain");
      response.writeHead(503);
      response.end(secret);
    } else {
      response.setHeader("Content-Type", "application/json");
      response.writeHead(503);
      response.end(JSON.stringify({ status: "error", detail: secret }));
    }
  });
  try {
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { postJson } =
      await import("../../apps/worker/src/notify/webhooks.js");
    const base = `http://127.0.0.1:${server.address().port}`;
    const failed = await postJson(`${base}/failure`, {}, "pagerduty");
    assert.deepEqual(failed, {
      success: false,
      status: 503,
      error: "PagerDuty responded HTTP 503",
    });
    assert.doesNotMatch(JSON.stringify(failed), /provider-response-secret/);
    const plainFailed = await postJson(`${base}/plain`, {}, "pagerduty");
    assert.deepEqual(plainFailed, failed);
    assert.deepEqual(await postJson(`${base}/success`, {}, "pagerduty"), {
      success: true,
      status: 200,
    });
  } finally {
    if (server.listening) await new Promise((resolve) => server.close(resolve));
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
