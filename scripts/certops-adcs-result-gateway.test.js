"use strict";
// In-memory software TLS and loopback transport only. No Windows service,
// certificate store, native CA, signed job or result acceptance is qualified.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");
const subject = require("../tests/e2e/helpers/certops-adcs-result-gateway");
test("gateway accepts the exact provisioned AD CS API origin", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../infra/certops-adcs/run-windows-tests.ps1"),
    "utf8",
  );
  const match = /\$env:CERTOPS_ADCS_API_URL='([^']+)'/.exec(source);
  assert.ok(match, "Actual guest API origin must be declared");
  const identity = subject.upstreamIdentity(match[1], softwareTls().cert);
  assert.ok(identity);
  assert.throws(() =>
    subject.upstreamIdentity("https://10.64.0.5", softwareTls().cert),
  );
});
function der(tag, ...parts) {
  const bytes = Buffer.concat(
    parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p))),
  );
  let length = Buffer.from([bytes.length]);
  if (bytes.length >= 128) {
    let hex = bytes.length.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const encoded = Buffer.from(hex, "hex");
    length = Buffer.concat([Buffer.from([128 + encoded.length]), encoded]);
  }
  return Buffer.concat([Buffer.from([tag]), length, bytes]);
}
const seq = (...parts) => der(0x30, ...parts);
function softwareTls() {
  const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const algorithm = Buffer.from("300d06092a864886f70d01010b0500", "hex");
  const name = seq(
    der(
      0x31,
      seq(
        Buffer.from("0603550403", "hex"),
        der(0x0c, Buffer.from("PUBLIC loopback software fixture")),
      ),
    ),
  );
  const time = (ms) =>
    der(
      0x18,
      Buffer.from(
        new Date(ms)
          .toISOString()
          .replace(/[-:]/g, "")
          .replace("T", "")
          .replace(/\.\d{3}Z$/, "Z"),
      ),
    );
  const tbs = seq(
    Buffer.from("a003020102020101", "hex"),
    algorithm,
    name,
    seq(time(Date.now() - 86400000), time(Date.now() + 86400000)),
    name,
    keys.publicKey.export({ format: "der", type: "spki" }),
    der(
      0xa3,
      seq(
        seq(
          Buffer.from("0603551d130101ff", "hex"),
          der(0x04, seq(Buffer.from("0101ff", "hex"))),
        ),
        seq(
          Buffer.from("0603551d11", "hex"),
          der(0x04, seq(der(0x87, Buffer.from([127, 0, 0, 1])))),
        ),
      ),
    ),
  );
  const cert = seq(
    tbs,
    algorithm,
    der(0x03, Buffer.from([0]), crypto.sign("sha256", tbs, keys.privateKey)),
  );
  return {
    key: keys.privateKey.export({ type: "pkcs8", format: "pem" }),
    cert: Buffer.from(new crypto.X509Certificate(cert).toString()),
  };
}
const tlsFixture = softwareTls();
const jobId = "11111111-1111-4111-8111-111111111111",
  claimId = "22222222-2222-4222-8222-222222222222";
async function upstream() {
  const received = [],
    sockets = new Set();
  const server = https.createServer(tlsFixture, (request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      received.push({ path: request.url, bytes: Buffer.concat(chunks) });
      response
        .writeHead(200, { "content-type": "application/json" })
        .end('{"softwareTransport":true}');
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `https://127.0.0.1:${server.address().port}/`,
    received,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}
test("only explicit owned HTTPS origins and a currently valid public server certificate are admitted", () => {
  subject.upstreamIdentity("https://10.64.0.6:3443/", tlsFixture.cert);
  for (const url of [
    "http://10.64.0.6:3443/",
    "https://example.test/",
    "https://10.64.0.6/other",
    "https://user:password@10.64.0.6/",
    "https://10.64.0.6/?x=1",
    "https://10.64.0.6/#x",
  ])
    assert.throws(() => subject.upstreamIdentity(url, tlsFixture.cert));
});
test("claim admission is held before ownership; evidence is forwarded while only the exact original result receives503", async () => {
  const remote = await upstream();
  let registered, gateway;
  const post = (path, bytes) =>
    fetch(gateway.agentUrl + path, {
      method: "POST",
      body: bytes,
      headers: { "content-type": "application/json" },
      signal: AbortSignal.timeout(5000),
    });
  try {
    gateway = await subject.startOwnedResultGateway({
      upstreamUrl: remote.url,
      upstreamCertificate: tlsFixture.cert,
      onCreated: (r) => {
        registered = r;
        assert.equal(r.hasLiveResource(), true);
      },
    });
    assert.equal(registered, gateway);
    assert.equal(
      (await post("/api/v1/certops/agent/jobs/claim", "{}")).status,
      503,
    );
    assert.equal(remote.received.length, 0);
    gateway.selectJob(jobId);
    assert.equal(
      (await post("/api/v1/certops/agent/jobs/claim", "{}")).status,
      200,
    );
    const original = Buffer.from(
      JSON.stringify({
        messageType: "result",
        body: { jobId, claimId },
        signature: "PUBLIC software bytes",
      }) + "\n",
    );
    assert.equal(
      (await post("/api/v1/certops/agent/jobs/results", original)).status,
      503,
    );
    assert.throws(() =>
      gateway.bindClaim("33333333-3333-4333-8333-333333333333"),
    );
    gateway.bindClaim(claimId);
    const evidence = Buffer.from(
      JSON.stringify({ messageType: "evidence", body: { jobId, claimId } }),
    );
    assert.equal(
      (await post("/api/v1/certops/agent/jobs/results", evidence)).status,
      200,
    );
    assert.ok(remote.received.at(-1).bytes.equals(evidence));
    gateway.restoreDelivery();
    assert.equal(
      (await post("/api/v1/certops/agent/jobs/results", original)).status,
      200,
    );
    assert.ok(remote.received.at(-1).bytes.equals(original));
    assert.deepEqual(gateway.observation(), {
      refusedResults: 1,
      forwardedResults: 1,
      mismatchedResults: 0,
      deliveryRestored: true,
      gatewayHealthy: true,
    });
    assert.equal(
      (await post("/api/v1/workspaces/foreign/certops/jobs", "{}")).status,
      404,
    );
    assert.equal(
      (await post("/api/v1/certops/agent/heartbeat?other=1", "{}")).status,
      404,
    );
  } finally {
    if (gateway) await gateway.close();
    await remote.close();
  }
  assert.equal(registered.hasLiveResource(), false);
});
test("an untrusted TLS endpoint never receives the original agent body", async () => {
  const remote = await upstream(),
    wrong = softwareTls();
  let gateway;
  try {
    gateway = await subject.startOwnedResultGateway({
      upstreamUrl: remote.url,
      upstreamCertificate: wrong.cert,
      onCreated: () => {},
    });
    const response = await fetch(
      gateway.agentUrl + "/api/v1/certops/agent/heartbeat",
      {
        method: "POST",
        body: '{"PUBLIC":"not forwarded"}',
        signal: AbortSignal.timeout(5000),
      },
    );
    assert.equal(response.status, 502);
    assert.equal(remote.received.length, 0);
  } finally {
    if (gateway) await gateway.close();
    await remote.close();
  }
});
