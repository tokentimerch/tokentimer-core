"use strict";
const assert = require("node:assert/strict");
const { createHash, X509Certificate } = require("node:crypto");
const tls = require("node:tls");

const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
function certificateFacts(certificates, root) {
  assert.ok(certificates.length > 0 && certificates.length <= 8);
  assert.ok(root.ca && root.checkIssued(root) && root.verify(root.publicKey), "run CA root must be self-signed");
  const suppliedRoot = certificates.at(-1).fingerprint256 === root.fingerprint256;
  const chain = suppliedRoot ? certificates : [...certificates, root];
  assert.ok(chain.length >= 2 && !chain[0].ca, "leaf certificate required");
  assert.equal(new Set(chain.map(item => item.fingerprint256)).size, chain.length, "duplicate certificate in chain");
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i], child = chain[i - 1];
    assert.ok(parent.ca && child.checkIssued(parent) && child.verify(parent.publicKey), "certificate chain does not lead to the run CA");
  }
  const issuerChain = createHash("sha256");
  for (const issuer of chain.slice(1)) issuerChain.update(issuer.raw);
  return {
    leafSha256: createHash("sha256").update(chain[0].raw).digest("hex"),
    chainSha256: issuerChain.digest("hex"),
  };
}

function publishedFacts(pem, ca) {
  assert.equal(typeof pem, "string");
  assert.ok(pem.length <= 128 * 1024 && !pem.replaceAll(PEM_CERTIFICATE, "").trim(), "public certificates only");
  return certificateFacts((pem.match(PEM_CERTIFICATE) || []).map(text => new X509Certificate(text)), new X509Certificate(ca));
}

function servedFacts({ port, servername, ca }) {
  assert.ok(Number.isSafeInteger(port) && port >= 1024 && port <= 65535);
  assert.equal(servername, "nginx.wildcard.test");
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: "127.0.0.1", port, servername, ca, rejectUnauthorized: true });
    socket.once("error", reject);
    socket.setTimeout(5000, () => socket.destroy(new Error("Served TLS proof timed out")));
    socket.once("secureConnect", () => {
      try {
        assert.equal(socket.authorized, true);
        const certificates = [], seen = new Set();
        for (let cert = socket.getPeerCertificate(true); cert?.raw && !seen.has(cert.fingerprint256); cert = cert.issuerCertificate) {
          assert.ok(certificates.length < 8, "served chain exceeds qualification bound");
          seen.add(cert.fingerprint256);
          certificates.push(new X509Certificate(cert.raw));
        }
        resolve({ ...certificateFacts(certificates, new X509Certificate(ca)), verifiedChain: true });
      } catch (error) { reject(error); }
      finally { socket.destroy(); }
    });
  });
}

module.exports = { publishedFacts, servedFacts };
