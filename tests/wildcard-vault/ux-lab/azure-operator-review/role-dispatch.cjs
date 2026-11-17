"use strict";
// Routing only: send must authenticate the selected private endpoint. No network
// operation is performed here and this does not implement a role-side control API.
const assert = require("node:assert/strict");
const ROLE = Object.freeze({ issuer: "issuer", nginx: "consumer", haproxy: "consumer" });
const COMMON = new Set(["configure", "enroll", "start", "stop", "facts", "prepare-signed-dry-run", "package-proof", "rotate-material-token", "revoke-material-token"]);
const ISSUER = new Set(["fault", "clear-fault", "scanner-requests"]);
const CONSUMER = new Set(["enable-discovery", "fail-reload", "repair-reload", "reconcile-binding", "tls-proof", "replace-local-material", "hold-reload", "release-reload", "transport-fault"]);
function authorizeRole(body, expectedRole) {
  assert.ok(body && typeof body === "object" && !Array.isArray(body));
  const name = body.name || "issuer", role = ROLE[name];
  assert.ok(role, "unsupported role or unisolated extra issuer");
  if (expectedRole) assert.equal(role, expectedRole, "action targets the wrong isolated role");
  assert.ok(COMMON.has(body.action) || (role === "issuer" ? ISSUER : CONSUMER).has(body.action), "unsupported action for role");
  return role;
}
async function dispatch(body, send) {
  const role = authorizeRole(body);
  assert.equal(typeof send, "function", "authenticated endpoint transport required");
  if (body.action === "package-proof") {
    assert.equal(role,"issuer","aggregate package proof starts at issuer");
    const issuer=await send("issuer",{action:"package-proof",name:"issuer"});
    const consumer=await send("consumer",{action:"package-proof",name:"nginx"});
    assert.equal(issuer.role,"issuer"); assert.equal(consumer.role,"consumer");
    assert.equal(issuer.candidateSha,consumer.candidateSha); assert.equal(issuer.packageSha256,consumer.packageSha256);
    assert.equal(issuer.packageFilesUnmodified,true); assert.equal(consumer.packageFilesUnmodified,true);
    return {candidateSha:issuer.candidateSha,packageSha256:issuer.packageSha256,packageFilesUnmodified:true,
      roleProofs:[issuer,consumer],releaseQualification:"not-established"};
  }
  return send(role, body);
}
module.exports = { dispatch, authorizeRole };
