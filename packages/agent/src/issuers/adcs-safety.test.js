/**
 * Regression coverage: requested key constraints fail before trusting an otherwise safe template.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { evaluateEnrollmentSafety, createEnrollmentSafetyGuard, SAFETY_REUSE_MS } = require("./adcs-safety");
const { computeSpkiSha256Hex } = require("./adcs-enrollment");
const caBytes = fs.readFileSync(path.resolve(__dirname, "../../reference/adcs-cmc/testdata/ca.cer"));
const pin = computeSpkiSha256Hex(caBytes);
const snapshot = { kind: "adcs", transport: "dcom", caConfig: "ca.example.com\\Example CA", template: "SafeWeb",
  caKeySha256: pin, authorizedDnsNames: ["app.example.com"], keyAlgorithm: "rsa", keySize: 2048 };
function facts() { return { caConfig: snapshot.caConfig, template: snapshot.template,
  templateCheck: { verdict: "safe", reasons: [], schemaVersion: 2, minimalKeySize: 2048,
    asymmetricAlgorithm: null, enrolleeSuppliesSubject: true, templateOid: "1.3.6.1.4.1.311.21.8.2" },
  caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
  caCertificates: [{ keySha256: pin, certificateB64: caBytes.toString("base64") }] }; }
test("requested key constraints fail before trusting an otherwise safe template", () => {
  for (const [schemaVersion, asymmetricAlgorithm, minimalKeySize, requested] of [
    [2, null, 4096, snapshot], [2, null, 256, { ...snapshot, keyAlgorithm: "ecdsa", keySize: 256 }],
    [3, "ECDSA_P256", 256, snapshot], [4, "ECDSA_P256", 256, { ...snapshot, keyAlgorithm: "ecdsa", keySize: 384 }],
  ]) {
    const preflightResult = facts(); Object.assign(preflightResult.templateCheck, { schemaVersion, asymmetricAlgorithm, minimalKeySize });
    assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot: requested }).errorCode, "ADCS_TEMPLATE_UNSAFE");
  }
  const preflightResult = facts(); Object.assign(preflightResult.templateCheck, { schemaVersion: 4, asymmetricAlgorithm: "ECDSA_P256", minimalKeySize: 256 });
  assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot: { ...snapshot, keyAlgorithm: "ecdsa", keySize: 256 } }).ok, true);
});
test("unknown required attributes and foreign pair or CA pin never qualify", () => {
  for (const attribute of ["schemaVersion", "minimalKeySize", "enrolleeSuppliesSubject", "templateOid"]) {
    const preflightResult = facts(); preflightResult.templateCheck[attribute] = null;
    assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot }).errorCode, "ADCS_TEMPLATE_UNSAFE");
  }
  const foreign = facts(); foreign.template = "OtherTemplate";
  assert.equal(evaluateEnrollmentSafety({ preflightResult: foreign, snapshot }).ok, false);
  assert.equal(evaluateEnrollmentSafety({ preflightResult: facts(), snapshot: { ...snapshot, caKeySha256: "ab".repeat(32) } }).errorCode, "ADCS_CA_KEY_UNPINNED");
});
test("only explicit local unreadable-flag attestation is permitted", () => {
  const preflightResult = facts();
  preflightResult.caCheck = { verdict: "unsafe", reasons: ["encrypted_requests_not_enforced"], operatorAttested: true };
  assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot, operatorAttested: true }).errorCode, "ADCS_CA_CONFIG_UNSAFE");
  preflightResult.caCheck = { verdict: "unreadable", reasons: ["flags_unreadable"], operatorAttested: true };
  assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot }).ok, false);
  assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot, operatorAttested: true }).ok, true);
  preflightResult.caCheck.reasons = ["subject_alt_name_attribute_enabled", "flags_unreadable"];
  assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot, operatorAttested: true }).ok, false);
  preflightResult.caCheck.reasons = ["ca_unreachable"];
  assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot, operatorAttested: true }).ok, false);
});
test("exact local rule is mandatory before any probe or cache mutation", async () => {
  const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-safety-no-rule-"));
  try {
    let calls = 0;
    const executionContext = { adcsEnrollmentRules: [], adcsPreflightImpl() { calls += 1; return { preflightResult: facts() }; } };
    const result = await createEnrollmentSafetyGuard()({ snapshot, executionContext, stateDir });
    assert.equal(result.errorCode, "ADCS_CA_CONFIG_UNSAFE"); assert.equal(calls, 0); assert.deepEqual(fs.readdirSync(stateDir), []);
  } finally { await fsp.rm(stateDir, { recursive: true, force: true }); }
});
test("bounded same-attempt reuse rechecks snapshot constraints, new entries refresh and stale reads expire", async () => {
  const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-safety-cache-"));
  try {
    let clock = 1000000, calls = 0;
    const executionContext = { adcsEnrollmentRules: [{ caConfig: snapshot.caConfig, template: snapshot.template, dnsScopes:["example.com"],keyAlgorithms:["rsa","ecdsa"] }],
      adcsPreflightImpl() { calls += 1; return { preflightResult: facts() }; } };
    const check = createEnrollmentSafetyGuard({ now: () => clock });
    assert.equal((await check({ snapshot, executionContext, stateDir })).ok, true);
    const cacheFile = path.join(stateDir, "adcs-ca", `${pin}.cer`); const mtime = fs.statSync(cacheFile).mtimeMs;
    assert.equal((await check({ snapshot, executionContext, stateDir, forceRefresh: false })).ok, true);
    assert.equal(calls, 1); assert.equal(fs.statSync(cacheFile).mtimeMs, mtime, "reuse must not extend public pin-file freshness");
    const badKey = { ...snapshot, keyAlgorithm: "ecdsa", keySize: 256 };
    assert.equal((await check({ snapshot: badKey, executionContext, stateDir, forceRefresh: false })).errorCode, "ADCS_TEMPLATE_UNSAFE");
    assert.equal(calls, 1);
    assert.equal((await check({ snapshot, executionContext, stateDir })).ok, true); assert.equal(calls, 2);
    clock += SAFETY_REUSE_MS + 1;
    assert.equal((await check({ snapshot, executionContext, stateDir, forceRefresh: false })).ok, true); assert.equal(calls, 3);
    clock -= SAFETY_REUSE_MS * 2;
    assert.equal((await check({ snapshot, executionContext, stateDir, forceRefresh: false })).ok, true); assert.equal(calls, 4);
  } finally { await fsp.rm(stateDir, { recursive: true, force: true }); }
});
test("a matching declared CA hash cannot conceal invalid public certificate bytes", async () => {
  const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-safety-bad-ca-"));
  try {
    const preflightResult = facts(); preflightResult.caCertificates[0].certificateB64 = Buffer.from("not an X509 certificate").toString("base64");
    const executionContext = { adcsEnrollmentRules: [{ caConfig: snapshot.caConfig, template: snapshot.template, dnsScopes:["example.com"],keyAlgorithms:["rsa","ecdsa"] }],
      adcsPreflightImpl: () => ({ preflightResult }) };
    assert.equal((await createEnrollmentSafetyGuard()({ snapshot, executionContext, stateDir })).errorCode, "ADCS_CA_KEY_UNPINNED");
  } finally { await fsp.rm(stateDir, { recursive: true, force: true }); }
});
