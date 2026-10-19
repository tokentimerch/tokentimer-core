"use strict";
/** Pure bounded proof and native-source ordering checks; no CA/native action. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const h = require("../tests/e2e/helpers/certops-adcs-issued-revocation");
function proof() { return { scope: h.SCOPE, requestId: "17", enrollmentId: "11111111-1111-1111-1111-111111111111", continuationJobId: "22222222-2222-2222-2222-222222222222", errorCode: "ADCS_CERTIFICATE_INVALID", schedulerDefaultClockQualified: false, ...Object.fromEntries(h.FLAGS.map(flag => [flag, true])) }; }
test("revocation before accept proof requires actual valid and revoked chain controls", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) { const value = proof(); delete value[key]; assert.throws(() => h.verifyProof(value)); }
  for (const flag of h.FLAGS) for (const value of [false, 1, "true", null]) assert.throws(() => h.verifyProof({ ...proof(), [flag]: value }));
  for (const patch of [{ scope: "native-X509Chain-online-CRL" }, { requestId: "4294967296" }, { requestId: 17 }, { schedulerDefaultClockQualified: true }, { errorCode: "ADCS_CA_KEY_CHANGED" }, { privateJournal: "sentinel" }]) assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
});
test("actual CA revocation and positive chain precede production continuation without substituted material", () => {
  const source = fs.readFileSync(path.resolve(__dirname, "../tests/e2e/helpers/certops-adcs-issued-revocation.js"), "utf8");
  const positive = source.indexOf("const valid = chain()"), revoke = source.indexOf('"-Action", "revoke"', positive), observed = source.indexOf("value.revoked === true", revoke), continuation = source.indexOf("scheduleDueEnrollments", observed);
  assert.ok(positive > 0 && revoke > positive && observed > revoke && continuation > observed);
  assert.ok(source.indexOf("await assertPendingIdentity();", observed) < continuation);
  for (const token of ['jobs.length, 1', 'jobs[0].status, "awaiting_issuer"', 'new Date(current.next_poll_at).getTime() > Date.now()', 'isDeepStrictEqual(untouched.journal, original.journal)', 'untouched.artifacts.leafPem, null']) assert.ok(source.includes(token), token);
  for (const token of ["valid.valid, true", "valid.unknown, false", "matches.length, 1", "after.artifacts.leafPem", "fingerprint256, leaf.fingerprint256", "/certificate is revoked/i", 'rejected.last_error_code, "ADCS_CERTIFICATE_INVALID"', "observe().subjectRequestCount, initial.subjectRequestCount", "isDeepStrictEqual(custody("]) assert.ok(source.includes(token), token);
  assert.ok(source.indexOf("registerOwnedUnacceptedEnrollment({ certificateId, domain })") < source.indexOf('fixture.request(`${api}/enrollments`'));
  assert.doesNotMatch(source, /-setreg|-urlcache|chainValidateImpl|SkipSignatureValidation|writeEnrollmentJournal|UPDATE certificate_/);
  assert.ok(source.indexOf("if (primary && cleanup)") < source.indexOf("gate.report.nativeIssuedRevocation"));
  for (const file of h.REQUIRED_SOURCES) assert.ok(fs.statSync(path.resolve(__dirname, "..", file)).isFile(), file);
  assert.equal(new Set(h.REQUIRED_SOURCES).size, h.REQUIRED_SOURCES.length);
});
test("independent chain oracle is public DER in memory with mandatory online Revoked distinction", () => {
  const script = h.nativeChainScript({ raw: Buffer.from("public-der-ast-only") });
  for (const token of ["X509RevocationMode]::Online", "X509RevocationFlag]::ExcludeRoot", "X509ChainStatusFlags]::Revoked", "RevocationStatusUnknown", "OfflineRevocation", "$chain.Dispose();$c.Dispose()"]) assert.ok(script.includes(token), token);
  assert.doesNotMatch(script, /Cert:\\|Import-|Export-|certutil|certreq|Set-Item|WriteAll|File\]/);
});
