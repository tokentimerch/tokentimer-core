"use strict";
// Scope checks only; passing these never runs a browser/CA or qualifies a host.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  runner = require("./certops-acme-browser-lifecycle");
test("native browser lifecycle scope remains explicit trusted manual Ubuntu certbot/noEAB", () => {
  const env = {
      CERTOPS_PROTOCOL_DISPOSABLE_STACK: "1",
      CERTOPS_REAL_ACME_CLIENT: "certbot",
      CERTOPS_REAL_ACME_EAB: "none",
      CERTOPS_NATIVE_ACME_LIFECYCLE: "1",
      GITHUB_ACTIONS: "true",
      GITHUB_REF: "refs/heads/main",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_SHA: "a".repeat(40),
    },
    release = 'ID=ubuntu\nVERSION_ID="24.04"\n';
  assert.equal(runner.checkScope(env, "linux", release, false), true);
  for (const change of [
    { CERTOPS_REAL_ACME_CLIENT: "acme.sh" },
    { CERTOPS_REAL_ACME_EAB: "required" },
    { GITHUB_REF: "refs/heads/untrusted" },
    { GITHUB_EVENT_NAME: "push" },
    { CERTOPS_NATIVE_ACME_LIFECYCLE: "0" },
  ])
    assert.throws(() =>
      runner.checkScope({ ...env, ...change }, "linux", release, false),
    );
  assert.throws(() => runner.checkScope(env, "linux", release, true));
  assert.throws(() => runner.checkScope(env, "win32", release, false));
});

test("shared preview cleanup closes its retained HTTP server and keepalive connections", async () => {
  const http = require("node:http"), server = http.createServer((req, res) => res.end("owned"));
  const agent = new http.Agent({keepAlive: true});
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    await new Promise((resolve, reject) => {
      http.get({host: "127.0.0.1", port: server.address().port, agent}, response => {
        response.resume(); response.once("end", resolve); response.once("error", reject);
      }).once("error", reject);
    });
    await runner.closePreview(server);
    assert.equal(server.listening, false);
  } finally {
    agent.destroy();
    if (server.listening) await new Promise(resolve => server.close(resolve));
  }
});

test("shared preview cleanup propagates close failure and still closes connections", async () => {
  let connectionsClosed = false;
  await assert.rejects(runner.closePreview({
    once() {}, listening: true,
    close(callback) { callback(new Error("owned close refused")); },
    closeAllConnections() { connectionsClosed = true; },
  }), /Owned dashboard close failed/);
  assert.equal(connectionsClosed, true);
});
