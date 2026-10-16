"use strict";
/** Bounded public worker proof reader and cross-journey continuity verifier.
 * The later reuse branch starts from the exact leaf/key/profile left by the
 * real default-cron rotations. Offline fixtures never establish native work. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-acme-background-renewals");
const SCOPES = [
  "real-agent-acme-filesystem",
  "real-agent-acme-eab-filesystem",
  "real-agent-acmesh-filesystem",
  "real-agent-acmesh-eab-filesystem",
  "real-agent-alpine-acmesh",
];
const MAIN =
  "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence";
const FIELD = "nativeAcmeBackgroundRenewals";
function verifyForScope(proof, reuse, scope) {
  assert.ok(SCOPES.includes(scope));
  helper.verifyProof(proof);
  require("../tests/e2e/helpers/certops-acme-key-reuse").verifyProof(reuse);
  assert.equal(proof.client, scope.includes("acmesh") ? "acme.sh" : "certbot");
  assert.equal(reuse.client, proof.client);
  assert.equal(proof.fingerprints[2], reuse.fingerprints[0]);
  assert.equal(proof.spkiFingerprints[2], reuse.spkiFingerprint);
  assert.equal(
    proof.sourceProfileId.toLowerCase(),
    reuse.sourceProfileId.toLowerCase(),
  );
  assert.equal(
    new Set([...proof.jobIds, ...reuse.jobIds].map((id) => id.toLowerCase()))
      .size,
    4,
  );
  return true;
}
function readProof(scope, name, root = path.resolve(__dirname, "..")) {
  if (!SCOPES.includes(scope) || name !== MAIN) return undefined;
  const client = scope.includes("acmesh") ? "acme.sh" : "certbot",
    file = path.join(
      root,
      "qualification-results",
      `acme-background-${client === "certbot" ? "certbot" : "acmesh"}.json`,
    ),
    st = fs.lstatSync(file);
  assert.ok(
    st.isFile() && !st.isSymbolicLink() && st.size > 0 && st.size <= 32768,
  );
  const proof = JSON.parse(fs.readFileSync(file, "utf8"));
  helper.verifyProof(proof);
  assert.equal(proof.client, client);
  return proof;
}
module.exports = { SCOPES, MAIN, FIELD, readProof, verifyForScope };
