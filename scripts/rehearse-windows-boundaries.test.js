"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const https = require("node:https");
const path = require("node:path");
const { parseArgs, assertOwnedState, assertArchivePaths, assertOwnedObservation, inspectTls } = require("./rehearse-windows-boundaries");

test("Windows boundary smoke requires independently supplied archive and source identities", () => {
  const args = ["--archive", "candidate.tgz", "--archive-sha256", "a".repeat(64), "--source-sha", "b".repeat(40), "--out", "receipt.json"];
  assert.equal(parseArgs(args)["archive-sha256"], "a".repeat(64));
  assert.throws(() => parseArgs(args.slice(0, 2)), /Missing/);
  assert.throws(() => parseArgs([...args, "--archive", "other.tgz"]));
  const invalid = [...args]; invalid[3] = "not-a-checksum";
  assert.throws(() => parseArgs(invalid));
});

test("native cleanup identity cannot escape its unique site, pool, store or directory", () => {
  const owner = "tt-core-delta-" + "a".repeat(24);
  const directory = path.resolve(owner + "-random");
  const state = { owner, directory, site: owner, pool: owner, store: "TokenTimerSmoke" + "a".repeat(24), port: 54321, certificates: [] };
  assertOwnedState(state, directory);
  for (const [key, value] of [["site", "Default Web Site"], ["pool", "DefaultAppPool"], ["store", "Root"], ["directory", path.dirname(directory)], ["port", 443], ["owner", "tt-core-delta-wrong"]]) {
    assert.throws(() => assertOwnedState({ ...state, [key]: value }, directory));
  }
  assert.throws(() => assertOwnedState({ ...state, certificates: [{ kind: "foreign" }] }, directory));
});

test("archive extraction refuses traversal, links and nonpackage paths", () => {
  assertArchivePaths(["package/bin/agent.js"], ["-rwxr-xr-x entry"]);
  for (const name of ["../outside", "package/../../outside", "package/..\\outside", "other/file", "package/control\nfile"]) {
    assert.throws(() => assertArchivePaths([name], ["-rw-r--r-- entry"]));
  }
  for (const mode of ["lrwxrwxrwx link", "hrw-r--r-- hardlink"]) assert.throws(() => assertArchivePaths(["package/bin/agent.js"], [mode]));
});

test("a store query only passes for the exact SAN-only public certificate observation", () => {
  const expected = { fingerprint: "a".repeat(64), store: "TokenTimerSmoke" + "a".repeat(24), san: "nginx.wildcard.test" };
  const observation = { fingerprintSha256: expected.fingerprint, storeName: expected.store, subject: null, keyPresent: false, subjectAltNames: [expected.san] };
  assertOwnedObservation(observation, expected);
  for (const replacement of [{ subject: "" }, { keyPresent: true }, { fingerprintSha256: "b".repeat(64) }, { storeName: "My" }, { subjectAltNames: [] }]) assert.throws(() => assertOwnedObservation({ ...observation, ...replacement }, expected));
  assert.throws(() => assertOwnedObservation(undefined, expected));
});

// Real loopback TLS with ephemeral, self-signed server-auth leaf certificates.
// No OpenSSL executable, trust-store modification or fixed expiry date is needed.
function der(tag, ...parts) {
  const bytes = Buffer.concat(parts);
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
function selfSignedServer(servername) {
  const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const algorithm = Buffer.from("300d06092a864886f70d01010b0500", "hex");
  const name = seq(der(0x31, seq(Buffer.from("0603550403", "hex"), der(0x0c, Buffer.from(servername)))));
  const time = (milliseconds) => der(0x18, Buffer.from(new Date(milliseconds).toISOString().replace(/[-:]/g, "").replace("T", "").replace(/\.\d{3}Z$/, "Z")));
  const tbs = seq(
    Buffer.from("a003020102020101", "hex"), algorithm, name,
    seq(time(Date.now() - 3600000), time(Date.now() + 86400000)), name,
    keys.publicKey.export({ format: "der", type: "spki" }),
    der(0xa3, seq(
      seq(Buffer.from("0603551d130101ff", "hex"), der(0x04, seq())),
      seq(Buffer.from("0603551d0f0101ff", "hex"), der(0x04, der(0x03, Buffer.from([5, 0xa0])))),
      seq(Buffer.from("0603551d25", "hex"), der(0x04, seq(Buffer.from("06082b06010505070301", "hex")))),
      seq(Buffer.from("0603551d11", "hex"), der(0x04, seq(der(0x82, Buffer.from(servername))))),
    )),
  );
  const certificate = new crypto.X509Certificate(seq(tbs, algorithm, der(0x03, Buffer.from([0]), crypto.sign("sha256", tbs, keys.privateKey))));
  assert.equal(certificate.ca, false, "The fixture must be a server leaf, not a CA");
  return { key: keys.privateKey.export({ type: "pkcs8", format: "pem" }), cert: certificate.toString(), fingerprint: crypto.createHash("sha256").update(certificate.raw).digest("hex") };
}

const owner = "tt-core-delta-" + "a".repeat(24);
const servername = owner + ".invalid";
const fixture = selfSignedServer(servername);
const unrelatedFixture = selfSignedServer(servername);

async function ownedServer(t, body = owner) {
  const requests = [], sockets = new Set();
  const server = https.createServer(fixture, (request, response) => {
    requests.push({ path: request.url, servername: request.socket.servername });
    response.writeHead(200, { "content-type": "text/plain" }).end(body);
  });
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });
  return { port: server.address().port, requests };
}

function probeOptions(port, overrides = {}) {
  return { port, certificatePem: fixture.cert, expectedFingerprint: fixture.fingerprint, servername, owner, ...overrides };
}

test("IIS TLS probe verifies its explicit self-signed leaf and hostname over real TLS", async (t) => {
  const remote = await ownedServer(t);
  const result = await inspectTls(probeOptions(remote.port));
  assert.deepEqual(result, { peerFingerprintSha256: fixture.fingerprint, ownedIisContent: true, fixtureCertificateVerified: true, verifiedServername: servername });
  assert.deepEqual(remote.requests, [{ path: "/index.html", servername }]);
});

test("IIS TLS probe rejects an untrusted certificate before sending HTTP", async (t) => {
  const remote = await ownedServer(t);
  await assert.rejects(inspectTls(probeOptions(remote.port, { certificatePem: unrelatedFixture.cert })), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" });
  assert.deepEqual(remote.requests, []);
});

test("IIS TLS probe rejects a trusted certificate for the wrong hostname before HTTP", async (t) => {
  const remote = await ownedServer(t);
  await assert.rejects(inspectTls(probeOptions(remote.port, { servername: "other.invalid" })), { code: "ERR_TLS_CERT_ALTNAME_INVALID" });
  assert.deepEqual(remote.requests, []);
});

test("IIS TLS probe retains its exact certificate pin after TLS verification", async (t) => {
  const remote = await ownedServer(t);
  await assert.rejects(inspectTls(probeOptions(remote.port, { expectedFingerprint: unrelatedFixture.fingerprint })), /TLS served a different certificate/);
  assert.equal(remote.requests.length, 1);
});

test("IIS TLS probe rejects content belonging to another site", async (t) => {
  const remote = await ownedServer(t, "foreign site");
  await assert.rejects(inspectTls(probeOptions(remote.port)), /TLS served unexpected site content/);
  assert.equal(remote.requests.length, 1);
});
