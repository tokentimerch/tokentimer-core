"use strict";
/** Supporting contracts only: these checks never issue or mutate certificates. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-adcs-issued-san-boundary");
const root = path.resolve(__dirname, "..");
function proof() { return { scope: helper.SCOPE, requestId: "17", enrollmentId: "11111111-1111-1111-1111-111111111111", continuationJobId: "22222222-2222-2222-2222-222222222222", errorCode: "ADCS_CERTIFICATE_INVALID", ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) }; }
test("native scenario follows actual invalid-terminal custody semantics", () => {
  const { shouldCleanupAbandonedCngKey } = require("../packages/agent/src/adcs-windows-iis");
  const input = { submitStarted: true, containerCreated: true, preparedJournalCommitted: true, issuanceOutcome: "rejected_invalid" };
  assert.equal(shouldCleanupAbandonedCngKey({ ...input, journalState: "rejected_invalid" }), true);
  for (const journalState of ["installed", "validation_deferred", "pending_issuance", "submission_uncertain"]) assert.equal(shouldCleanupAbandonedCngKey({ ...input, journalState }), false, journalState);
});
test("wrong-SAN evidence requires every actual native fact and bounded public identities", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) { const missing = proof(); delete missing[key]; assert.throws(() => helper.verifyProof(missing)); }
  for (const flag of helper.FLAGS) for (const value of [false, 1, "true", null]) assert.throws(() => helper.verifyProof({ ...proof(), [flag]: value }));
  for (const patch of [{ requestId: "0" }, { requestId: "4294967296" }, { requestId: 17 }, { errorCode: "ADCS_CA_KEY_CHANGED" }, { rawPrivateKey: "sentinel" }]) assert.throws(() => helper.verifyProof({ ...proof(), ...patch }));
});
test("native SAN mutator ownership checks precede its sole exact extension operation", () => {
  const source = fs.readFileSync(path.join(root, "infra/certops-adcs/issued-san-fault.ps1"), "utf8");
  const mutation = source.indexOf("-setextension"); assert.ok(mutation > 0);
  for (const guard of ["Foreign request run", "Foreign CA host", "Foreign or non-pending request/template", "Owned pending public CSR DER mismatch", "Refusing existing public SAN file"]) assert.ok(source.indexOf(guard) > 0 && source.indexOf(guard) < mutation, guard);
  for (const guard of ["Identity(f,false)!=fileId", "Identity(g,false)!=guardId", "Identity(parent,true)!=parentId", "Digest(file)!=hash", "DeleteHandle(file);DeleteHandle(guard)", "Preserve replaced public SAN deletion candidate"]) assert.ok(source.includes(guard), guard);
  assert.doesNotMatch(source, /Remove-Item/);
  assert.equal((source.match(/-setextension/g) || []).length, 1); assert.match(source, /'2\.5\.29\.17' 0/); assert.match(source, /wrongsan\.example\.test/);
  assert.doesNotMatch(source, /-setattributes|-setreg|-resubmit|-deny|-revoke|SkipSignatureValidation|ExportPolicy|ExportPkcs/i);
});
test("source keeps public dispatch, exact matching positive and terminal cleanup before proof", () => {
  const source = fs.readFileSync(path.join(root, "tests/e2e/helpers/certops-adcs-issued-san-boundary.js"), "utf8");
  assert.ok(source.indexOf("registerOwnedUnacceptedEnrollment({ certificateId, domain })") < source.indexOf('fixture.request(`${api}/enrollments`'));
  for (const guard of ["matches.length, 1", 'previousJournal.journal.templateOid', 'rejected.last_error_code, "ADCS_CERTIFICATE_INVALID"', 'after.journal.state, "rejected_invalid"', 'Exact invalid terminal key must be absent', 'observe().subjectRequestCount, initial.subjectRequestCount', 'terminal.disposition, 21']) assert.ok(source.includes(guard), guard);
  assert.ok(source.indexOf("if (primary && cleanup)") < source.indexOf("gate.report.nativeIssuedSanBoundary"));
  for (const file of helper.REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, file)), true, file);
});
