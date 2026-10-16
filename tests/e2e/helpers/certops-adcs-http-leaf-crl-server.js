"use strict";
/* Disposable member-only HTTP endpoint. The only response bytes admitted here
 * are a genuine signed base CRL from the pinned original CA. Retained server
 * and socket objects own teardown; a lost receipt never releases ownership.
 * This module does not fabricate native chain verdicts or qualify enrollment.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const {
  applyRestrictivePermissions,
} = require("../../../packages/agent/src/platform");
const { ownedBytes } = require("./certops-adcs-http-intermediate-crl");
const { verifyCrl } = require("./certops-adcs-http-leaf-crl-der");
const active = new Map();
const HOST = "10.64.0.6";
const ROUTE = "/TTQualificationRoot.crl";
const digest = (bytes) =>
  crypto.createHash("sha256").update(bytes).digest("hex");
function acceptsRequest(request, boundPort) {
  return (
    request.method === "GET" &&
    request.url === ROUTE &&
    request.headers.host === `${HOST}:${boundPort}` &&
    request.headers["transfer-encoding"] === undefined &&
    (request.headers["content-length"] === undefined ||
      request.headers["content-length"] === "0")
  );
}

function assertCleanupSafe(workDir) {
  assert.equal(
    active.has(path.resolve(workDir)),
    false,
    "Unresolved HTTP leaf CRL listener ownership",
  );
  assert.equal(
    fs.existsSync(path.join(workDir, "http-leaf-crl-owner.json")),
    false,
    "Preserve HTTP leaf CRL ownership receipt",
  );
}

function decodePublic(value, maximum) {
  assert.equal(typeof value, "string");
  assert.ok(value.length >= 4 && value.length <= Math.ceil(maximum / 3) * 4);
  assert.match(
    value,
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
  );
  const bytes = Buffer.from(value, "base64");
  assert.ok(bytes.length >= 100 && bytes.length <= maximum);
  assert.equal(bytes.toString("base64"), value);
  return bytes;
}

function verifyPublication(value, expected, action) {
  const fields = [
    "scope",
    "action",
    "runId",
    "token",
    "caThumbprint",
    "httpUrl",
    "originalSha256",
    "appliedSha256",
    "caReady",
    "publicationRestored",
  ];
  if (action === "Apply") fields.push("crlBase64", "caCertificateBase64");
  assert.ok(action === "Apply" || action === "Restore");
  assert.deepEqual(Object.keys(value).sort(), fields.sort());
  assert.equal(value.scope, "owned-enterprise-ca-http-leaf-publication");
  for (const key of ["runId", "token", "caThumbprint", "httpUrl"])
    assert.equal(value[key], expected[key], "Publication ownership mismatch");
  assert.equal(value.action, action);
  assert.equal(value.caReady, true);
  assert.equal(value.publicationRestored, action === "Restore");
  for (const key of ["originalSha256", "appliedSha256"])
    assert.match(value[key], /^[a-f0-9]{64}$/);
  assert.notEqual(value.originalSha256, value.appliedSha256);
  if (action === "Restore") {
    assert.equal(value.originalSha256, expected.originalSha256);
    assert.equal(value.appliedSha256, expected.appliedSha256);
    return value;
  }
  const ca = decodePublic(value.caCertificateBase64, 1048576);
  assert.ok(ca.equals(expected.caBytes), "Original CA certificate changed");
  const crl = decodePublic(value.crlBase64, 1048576);
  return {
    publication: value,
    crl,
    crlProof: verifyCrl(crl, ca, expected.caKeySha256),
  };
}

async function createOwnedListener({ workDir, run, registerOwnership }) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.match(run, /^[a-f0-9]{10}$/);
  assert.equal(typeof registerOwnership, "function");
  assertCleanupSafe(workDir);
  const canonical = fs.realpathSync(workDir);
  assert.equal(canonical, path.resolve(workDir));
  const root = fs.lstatSync(canonical, { bigint: true });
  assert.ok(root.isDirectory() && !root.isSymbolicLink() && root.ino > 0n);
  const token = crypto.randomUUID();
  const guard = path.join(canonical, "http-leaf-crl-owner.json");
  const bytes = Buffer.from(JSON.stringify({ schemaVersion: 1, run, token }));
  // Sticky ownership precedes receipt creation and every socket/native action.
  const state = { closed: false, completed: false };
  active.set(canonical, state);
  fs.writeFileSync(guard, bytes, { flag: "wx", mode: 0o600 });
  applyRestrictivePermissions(guard, { kind: "file" });
  const receipt = ownedBytes(guard, 4096);
  const sockets = new Set();
  let crl = null,
    unavailable = false,
    boundPort = null,
    listenerError = false;
  const counts = { served: 0, unavailable: 0, refused: 0 };
  const server = http.createServer((request, response) => {
    response.setHeader("Connection", "close");
    response.setHeader("Cache-Control", "no-store");
    if (!acceptsRequest(request, boundPort)) {
      counts.refused++;
      response.writeHead(404).end();
    } else if (!crl || unavailable) {
      counts.unavailable++;
      response.writeHead(503, { "Content-Length": "0" }).end();
    } else {
      counts.served++;
      response
        .writeHead(200, {
          "Content-Type": "application/pkix-crl",
          "Content-Length": String(crl.length),
        })
        .end(crl);
    }
  });
  server.maxHeadersCount = 32;
  server.headersTimeout = 5000;
  server.requestTimeout = 5000;
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.setTimeout(5000, () => socket.destroy());
    socket.once("close", () => sockets.delete(socket));
  });
  server.on("error", () => {
    listenerError = true;
  });
  const resource = {
    token,
    hasOwnershipReceipt: () => !state.completed,
    hasLiveChild: () => !state.closed,
    assertCleanupSafe: () => assertCleanupSafe(canonical),
    setVerifiedCrl(crlBytes, caBytes, pin) {
      assert.equal(crl, null);
      verifyCrl(crlBytes, caBytes, pin);
      crl = Buffer.from(crlBytes);
    },
    setUnavailable(value) {
      assert.equal(typeof value, "boolean");
      assert.ok(crl && !state.closed && !listenerError);
      unavailable = value;
    },
    observations: () => ({ ...counts }),
    async close() {
      if (state.closed) return;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("Owned HTTP CRL listener did not close")),
          10000,
        );
        server.close((error) => {
          clearTimeout(timer);
          if (error) reject(new Error("Owned HTTP CRL listener close failed"));
          else resolve();
        });
        for (const socket of sockets) socket.destroy();
      });
      assert.equal(server.listening, false);
      assert.equal(sockets.size, 0);
      state.closed = true;
    },
    complete() {
      assert.equal(state.closed, true);
      assert.equal(listenerError, false);
      const currentRoot = fs.lstatSync(canonical, { bigint: true });
      assert.ok(
        currentRoot.isDirectory() &&
          !currentRoot.isSymbolicLink() &&
          currentRoot.dev === root.dev &&
          currentRoot.ino === root.ino,
      );
      const current = ownedBytes(guard, 4096);
      assert.ok(
        current.identity === receipt.identity && current.bytes.equals(bytes),
      );
      fs.unlinkSync(guard);
      state.completed = true;
      active.delete(canonical);
    },
  };
  registerOwnership(resource);
  await new Promise((resolve, reject) => {
    server.once("error", () =>
      reject(new Error("Owned member CRL endpoint could not bind")),
    );
    server.listen({ host: HOST, port: 0, exclusive: true }, resolve);
  });
  boundPort = server.address().port;
  assert.ok(
    Number.isInteger(boundPort) && boundPort >= 1024 && boundPort <= 65535,
  );
  resource.httpPort = boundPort;
  resource.httpUrl = `http://${HOST}:${boundPort}${ROUTE}`;
  resource.crlDigest = () => {
    assert.ok(crl);
    return digest(crl);
  };
  return resource;
}

module.exports = {
  assertCleanupSafe,
  decodePublic,
  verifyPublication,
  createOwnedListener,
  acceptsRequest,
};
