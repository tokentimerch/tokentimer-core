"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const https = require("node:https");
const { startLocalHttpsServer } = require("../integration/helpers/local-https-server");

function readFixture(url) {
  return new Promise((resolve, reject) => {
    // The fixture deliberately serves a self-signed, test-only certificate.
    const req = https.get(url, { rejectUnauthorized: false, agent: false }, (res) => {
      const certificate = res.socket.getPeerCertificate();
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body, certificate }));
      res.on("error", reject);
    });
    req.on("error", reject);
  });
}

test("native HTTPS fixture stays on loopback and supports certificate rotation", async (t) => {
  const fixture = await startLocalHttpsServer();
  t.after(() => fixture.close());
  assert.equal(fixture.server.address().address, "127.0.0.1");
  assert.equal(new URL(fixture.url).hostname, "127.0.0.1");
  const first = await readFixture(fixture.url);
  assert.equal(first.status, 200);
  assert.equal(first.body, "ok");
  assert.ok(first.certificate.valid_to);
  fixture.rotateCertificate();
  const rotated = await readFixture(fixture.url);
  assert.ok(rotated.certificate.valid_to);
  assert.notEqual(rotated.certificate.fingerprint256, first.certificate.fingerprint256);
});

test("Docker callers can advertise a host alias independently of the listen address", async (t) => {
  const fixture = await startLocalHttpsServer({
    listenHost: "0.0.0.0",
    advertisedHost: "host.docker.internal",
  });
  t.after(() => fixture.close());
  const { port, address } = fixture.server.address();
  assert.equal(address, "0.0.0.0");
  assert.equal(fixture.url, `https://host.docker.internal:${port}`);
  const response = await readFixture(`https://127.0.0.1:${port}`);
  assert.equal(response.status, 200);
  assert.ok(response.certificate.valid_to);
});
