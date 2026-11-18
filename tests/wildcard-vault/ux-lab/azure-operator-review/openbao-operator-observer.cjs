"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHash, X509Certificate } = require("node:crypto");

const Id = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const sha256 = value => createHash("sha256").update(value).digest("hex");
function pin(workspaceId, groupId, materialVersionId) {
  for (const id of [workspaceId, groupId, materialVersionId]) assert.match(id, Id);
  return `/v1/secret/data/tokentimer/${workspaceId}/${groupId}/bundles/${materialVersionId}`;
}

function chainProof(leaf, chain, root) {
  assert.ok(root.ca && chain.length > 0 && chain.length <= 8);
  assert.equal(chain.at(-1).fingerprint256, root.fingerprint256);
  let child = leaf;
  for (const issuer of chain) {
    assert.ok(issuer.ca && child.checkIssued(issuer) && child.verify(issuer.publicKey));
    child = issuer;
  }
  return { leafSha256: sha256(leaf.raw), chainSha256: sha256(Buffer.concat(chain.map(certificate => certificate.raw))) };
}

function issuedCertificate(leaf, chain, issuer) {
  const certificates = chain.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  assert.ok(certificates, "ACME response did not supply an issuer chain");
  return chainProof(new X509Certificate(leaf), certificates.map(pem => new X509Certificate(pem)), new X509Certificate(issuer));
}

function servedCertificate(peer, issuer) {
  const chain = [];
  const seen = new Set([peer.fingerprint256]);
  for (let certificate = peer.issuerCertificate; certificate && !seen.has(certificate.fingerprint256); certificate = certificate.issuerCertificate) {
    assert.ok(chain.length < 8 && certificate.raw);
    seen.add(certificate.fingerprint256);
    chain.push(new X509Certificate(certificate.raw));
  }
  return chainProof(new X509Certificate(peer.raw), chain, new X509Certificate(issuer));
}

function observe({ root, packageRoot }) {
  let target;
  let version;
  let writeAttempts = 0;
  let committedWrites = 0;
  let exactReads = 0;
  let latestReads = 0;
  const writeStatuses = [];
  const signed = new Map();
  const counts = () => ({ writeAttempts, committedWrites, exactReads, latestReads, version, writeStatuses: [...writeStatuses] });
  return {
    arm({ workspaceId, groupId, materialVersionId }) {
      assert.equal(target, undefined, "operator observation already armed");
      target = pin(workspaceId, groupId, materialVersionId);
    },
    beforeProvider({ method, url }) {
      if (!target || url.split("?")[0] !== target) return;
      if (method === "POST" || method === "PUT") writeAttempts++;
      if (method === "GET" && !/^\?version=[1-9][0-9]{0,9}$/.test(url.slice(target.length))) latestReads++;
    },
    afterProvider({ method, url }, status) {
      if (!target || url.split("?")[0] !== target) return;
      if (method === "POST" || method === "PUT") {
        assert.ok(writeStatuses.length < 128);
        writeStatuses.push(status);
        if (status === 200) committedWrites++;
      }
      if (status !== 200) return;
      const pin = method === "GET" && /^\?version=([1-9][0-9]{0,9})$/.exec(url.slice(target.length));
      if (pin) {
        if (version !== undefined) assert.equal(pin[1], version);
        version = pin[1];
        exactReads++;
      }
    },
    claim(envelope, payload) {
      if (!target) return;
      const directory = ["issuer", "nginx", "haproxy"].map(name => path.join(root, name))
        .find(directory => {
          const file = path.join(directory, "config.json");
          return fs.existsSync(file) && JSON.parse(fs.readFileSync(file, "utf8")).agentId === payload.agentId;
        });
      if (!directory) return;
      const { verifyJobEnvelope } = require(path.join(packageRoot(), "src/signing"));
      const { readSigningKeyPin } = require(path.join(packageRoot(), "src/config"));
      const { publicKeyPem, signingKeyId } = readSigningKeyPin(directory);
      const verdict = verifyJobEnvelope({ claimed: envelope, publicKeyPem, pinnedSigningKeyId: signingKeyId });
      assert.ok(verdict.allowed && verdict.job.agentId === payload.agentId, "operator dispatch failed independent signature verification");
      assert.match(verdict.job.jobId, Id);
      signed.set(verdict.job.jobId, sha256(signingKeyId));
    },
    counts,
    proof(jobIds) {
      assert.ok(target && Array.isArray(jobIds) && jobIds.length >= 2 && new Set(jobIds).size === jobIds.length);
      const keys = jobIds.map(id => { assert.match(id, Id); return signed.get(id); });
      assert.ok(keys[0] && keys.every(key => key === keys[0]), "selected jobs need genuine signed dispatches under the pinned key");
      return { ...counts(),
        signed: jobIds.length, verified: jobIds.length, signerKeyIdSha256: keys[0] };
    },
  };
}

module.exports = { Id, sha256, pin, issuedCertificate, servedCertificate, observe };
