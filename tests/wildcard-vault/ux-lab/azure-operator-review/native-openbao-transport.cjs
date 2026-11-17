"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHash, X509Certificate } = require("node:crypto");
const { request } = require("node:https");

const HOST = "127.0.0.1";
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const AUTH = new Set(["/v1/auth/approle/login", "/v1/auth/token/renew-self", "/v1/auth/token/revoke-self"]);

function endpoint(address) {
  assert.match(address || "", /^https:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/);
  const selected = new URL(address);
  assert.ok(Number(selected.port) >= 1024 && Number(selected.port) <= 65535);
  return selected;
}

function loadEndpointCa(file, expectedSha256) {
  assert.ok(path.isAbsolute(file));
  assert.match(expectedSha256, /^[0-9a-f]{64}$/);
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.size > 0 && stat.size < 8192, "owned transport certificate required");
  const pem = fs.readFileSync(file, "utf8");
  assert.equal(createHash("sha256").update(pem).digest("hex"), expectedSha256);
  assert.match(pem, /^-----BEGIN CERTIFICATE-----[\r\n]+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----[\r\n]*$/);
  const certificate = new X509Certificate(pem);
  assert.equal(certificate.checkIP(HOST), HOST);
  assert.ok(certificate.verify(certificate.publicKey) &&
    Date.parse(certificate.validFrom) < Date.now() && Date.now() < Date.parse(certificate.validTo),
  "expected an unexpired, independently pinned loopback TLS certificate");
  return pem;
}

function pin({ workspaceId, groupId, materialVersionId, providerVersion }) {
  for (const id of [workspaceId, groupId, materialVersionId]) assert.match(id, UUID);
  assert.match(String(providerVersion), /^[1-9][0-9]{0,9}$/);
  return `/v1/secret/data/tokentimer/${workspaceId}/${groupId}/bundles/${materialVersionId}?version=${providerVersion}`;
}

function createNativeOpenBaoTransport(forward) {
  assert.equal(typeof forward, "function");
  let target;
  const statuses = { exactRead200: 0, renew200: 0 };
  return {
    arm(scope) {
      assert.equal(target, undefined, "provider route already bound to a version");
      target = pin(scope);
    },
    forward(req, res) {
      if (!target || !(req.method === "GET" && req.url === target || req.method === "POST" && AUTH.has(req.url))) {
        res.writeHead(403).end();
        return;
      }
      const observed = req.method === "GET" ? "exactRead200" : req.url === "/v1/auth/token/renew-self" ? "renew200" : null;
      if (observed) res.once("finish", () => { if (res.statusCode === 200) statuses[observed]++; });
      forward(req, res);
    },
    facts: () => ({ ...statuses }),
  };
}

// The separate native role's credential stays local. This client has no
// redirects, alternate CA roots, hostname overrides or plaintext fallback.
function requestPinned({ address, ca, method = "GET", target, token, body }) {
  const origin = endpoint(address);
  assert.ok(typeof target === "string" && target.startsWith("/") && !target.startsWith("//"));
  const url = new URL(target, origin);
  assert.equal(url.origin, origin.origin);
  return new Promise((resolve, reject) => {
    const bytes = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = request(url, {
      method, ca, rejectUnauthorized: true,
      headers: {
        ...(bytes ? { "Content-Type": "application/json", "Content-Length": bytes.length } : {}),
        ...(token ? { "X-Vault-Token": token } : {}),
      },
    }, response => {
      let size = 0;
      const chunks = [];
      response.on("error", () => reject(new Error("pinned HTTPS response failed")));
      response.on("data", chunk => {
        size += chunk.length;
        if (size > 1048576) req.destroy(new Error("pinned HTTPS response exceeds bound"));
        else chunks.push(chunk);
      });
      response.on("end", () => {
        try { resolve({ status: response.statusCode, data: size ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : null }); }
        catch { reject(new Error("invalid pinned HTTPS response")); }
      });
    });
    req.setTimeout(10000, () => req.destroy(new Error("pinned HTTPS request timed out")));
    req.on("error", () => reject(new Error("pinned HTTPS transport failed")));
    req.end(bytes);
  });
}

module.exports = { endpoint, loadEndpointCa, pin, createNativeOpenBaoTransport, requestPinned };
