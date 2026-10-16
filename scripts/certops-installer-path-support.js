"use strict";
/** Supporting native Windows copy/activation controls on temporary public files.
 * This wrapper requires actual command success and closed bounded proof; it
 * never invokes installer top-level or qualifies a service/certificate host. */
const assert = require("node:assert/strict"), path = require("node:path"), { spawnSync } = require("node:child_process");
const fields = ["outsideBytesAndIdentityPreserved", "predecessorBytesAndIdentityPreserved", "noDestinationMutationBeforeSourceRefusal", "excludedSourceJunctionsNotFollowedOrCopied", "ownedTemporaryFixtureRemoved"];
function verifyProof(proof) {
  assert.deepEqual(Object.keys(proof).sort(), [...fields, "scope", "positivePathShapes", "copyJunctionRefusals", "activationJunctionRefusals", "serviceOrCertificateExecutionQualified"].sort());
  assert.equal(proof.scope, "actual-production-copy-activation-temporary-filesystem"); assert.equal(proof.positivePathShapes, 3); assert.equal(proof.copyJunctionRefusals, 6); assert.equal(proof.activationJunctionRefusals, 4); assert.equal(proof.serviceOrCertificateExecutionQualified, false);
  for (const field of fields) assert.equal(proof[field], true, field); return true;
}
function main() {
  assert.equal(process.platform, "win32"); const env = { ...process.env }; for (const name of Object.keys(env)) if (name.toLowerCase() === "psmodulepath") delete env[name];
  const result = spawnSync(path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe"), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path.join(__dirname, "certops-installer-paths.test.ps1")], { env, encoding: "utf8", windowsHide: true, timeout: 60000, maxBuffer: 16384 });
  assert.ifError(result.error); assert.equal(result.status, 0, "Native temporary installer-path control failed"); const proof = JSON.parse(result.stdout.trim()); verifyProof(proof); console.log(JSON.stringify(proof));
}
if (require.main === module) { try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; } }
module.exports = { main, fields, verifyProof };
