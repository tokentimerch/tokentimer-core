/**
 * Regression coverage: new enrollment refuses unsafe ${unsafe} before keygen intent, CNG or CA submit.
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
const crypto = require("node:crypto");
const { createAdcsWindowsIisExecutors } = require("./adcs-windows-iis");
const { computeSpkiSha256Hex, keygenIntentPath, writeKeygenIntent, writeCsrArtifact, writeIssuedCertificateArtifacts, writeEnrollmentJournal, readEnrollmentJournal } = require("./issuers/adcs-enrollment");
const { buildEnrollmentContainerName, recordIssuedContainer, markIssuedContainerAccepted } = require("./windows-cert-store");
const caPath = path.resolve(__dirname, "../reference/adcs-cmc/testdata/ca.cer");
const caBytes = fs.readFileSync(caPath);
const snapshot = { kind: "adcs", transport: "dcom", caConfig: "ca.example.com\\Example CA", template: "SafeWeb",
  caKeySha256: computeSpkiSha256Hex(caBytes), authorizedDnsNames: ["app.example.com"], keyAlgorithm: "rsa", keySize: 2048 };
const templateOid = "1.3.6.1.4.1.311.21.8.2";
function facts(unsafe) { return { caConfig: snapshot.caConfig, template: snapshot.template,
  templateCheck: { verdict: "safe", reasons: [], schemaVersion: 2, minimalKeySize: unsafe === "template" ? 4096 : 2048,
    asymmetricAlgorithm: null, enrolleeSuppliesSubject: true, templateOid },
  caCheck: { verdict: unsafe === "ca" ? "unsafe" : "safe", reasons: unsafe === "ca" ? ["encrypted_requests_not_enforced"] : [], operatorAttested: false },
  caCertificates: [{ keySha256: snapshot.caKeySha256, certificateB64: caBytes.toString("base64") }] }; }
function factory(stateDir) { return createAdcsWindowsIisExecutors({ resolveAgentStateDir: () => stateDir,
  renewJobLeaseOrAbort: async () => ({ ok: true }), reportIssuanceEvidence: async () => {}, reportStepEvidence: async () => {},
  runWindowsIisDeployTail: async () => { throw new Error("must not deploy refused material"); },
  finalizeWindowsIisDeployBookkeeping: async () => {}, emitInfo() {}, emitLog() {}, recordWindowsCngContainer() {}, isValidCertificateId: () => true }); }
function jobFor(enrollmentId) {
  const bytes = Buffer.from(JSON.stringify(snapshot));
  return { certificateId: crypto.randomUUID(), keyMode: "os-store-managed", issuerKind: "adcs",
    target: { type: "windows-iis", reference: "app.example.com", store: "My", binding: { site: "Unit Site", port: 443 } },
    enrollment: { enrollmentId, attempt: 1, snapshotB64: bytes.toString("base64"), snapshotSha256: crypto.createHash("sha256").update(bytes).digest("hex") } };
}
for (const unsafe of ["template", "ca"]) test(`new enrollment refuses unsafe ${unsafe} before keygen intent, CNG or CA submit`, async () => {
  const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-native-safety-unit-"));
  try {
    const helper = path.join(stateDir, "unit-helper-never-executed.exe"); fs.writeFileSync(helper, "not executed");
    const enrollmentId = crypto.randomUUID(); const job = jobFor(enrollmentId); let nativeCalls = 0;
    const result = await factory(stateDir).executeWindowsIisAdcsRenewJob({ job, jobId: "safety-unit", client: {}, log: {},
      executionContext: { execution: { keysDir: path.join(stateDir, "keys") }, adcsHelperPath: helper, adcsCaCertPath: caPath,
        adcsEnrollmentRules: [{ caConfig: snapshot.caConfig, template: snapshot.template, dnsScopes:["example.com"],keyAlgorithms:["rsa","ecdsa"],operatorAttested: true }],
        adcsPreflightImpl: () => ({ preflightResult: facts(unsafe) }),
        windowsExecFileImpl() { nativeCalls += 1; throw new Error("no private effect or submit permitted"); } } });
    assert.equal(result.status, "rejected"); assert.equal(result.enrollmentResult.state, "refused");
    assert.equal(result.enrollmentResult.errorCode, unsafe === "template" ? "ADCS_TEMPLATE_UNSAFE" : "ADCS_CA_CONFIG_UNSAFE");
    assert.equal(nativeCalls, 0); assert.equal(fs.existsSync(keygenIntentPath(stateDir, enrollmentId)), false);
    assert.equal(readEnrollmentJournal(stateDir, enrollmentId).kind, "not_found");
  } finally { await fsp.rm(stateDir, { recursive: true, force: true }); }
});
for (const phase of ["prepared", "keygen_intent", "keygen_intent-operator", "prepared-accepted", "renew-prepared", "renew-foreign-job"]) test(`${phase} retry refuses newly unsafe facts without deleting protected keys`, async () => {
  const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-prepared-safety-unit-"));
  try {
    const helper = path.join(stateDir, "unit-helper-never-executed.exe"); fs.writeFileSync(helper, "not executed");
    const enrollmentId = crypto.randomUUID(); const job = jobFor(enrollmentId);
    const containerName = buildEnrollmentContainerName(enrollmentId);
    if (phase.startsWith("keygen_intent")) {
      await writeKeygenIntent({ stateDir, enrollmentId, containerName, attempt: 1,
        snapshotSha256: job.enrollment.snapshotSha256, jobId: "safety-unit" });
    } else {
      const { csrSha256 } = await writeCsrArtifact({ stateDir, enrollmentId, csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nUNIT-ONLY\n-----END CERTIFICATE REQUEST-----\n" });
      await writeEnrollmentJournal(stateDir, enrollmentId, { state: "prepared", attempt: 1, containerName,
      snapshotSha256: job.enrollment.snapshotSha256, jobId: "safety-unit", csrSha256, csrSpkiSha256: "ab".repeat(32),
      templateOid, caConfig: snapshot.caConfig, template: snapshot.template });
    }
    if (phase === "prepared-accepted") {
      recordIssuedContainer({ stateDir, containerName, jobId: "prior-unit-job", certificateId: job.certificateId });
      assert.equal(markIssuedContainerAccepted({ stateDir, containerName, acceptedThumbprint: "AA".repeat(20), store: "My" }),true);
    }
    const calls = [];
    if (phase === "keygen_intent-operator") job.metadata=[{name:"adcs.recoveryFromJobId",value:crypto.randomUUID()}];
    const executors=factory(stateDir);
    const handler=phase.startsWith("renew-") ? executors.executeWindowsIisAdcsRenewJob : executors.executeWindowsIisContinueEnrollmentJob;
    const result = await handler({ job, jobId: phase === "renew-foreign-job" ? "different-unit-job" : "safety-unit", client: {}, log: {},
      executionContext: { execution: { keysDir: path.join(stateDir, "keys") }, adcsHelperPath: helper, adcsCaCertPath: caPath, windowsKeySurvivorHelperPath: __filename,
        adcsEnrollmentRules: [{ caConfig: snapshot.caConfig, template: snapshot.template, dnsScopes:["example.com"],keyAlgorithms:["rsa","ecdsa"] }], adcsPreflightImpl: () => ({ preflightResult: facts("template") }),
        windowsExecFileImpl(file, args, _opts, callback) {
          calls.push(args);
          // Deletion is permitted only after the actual adapter accepts a
          // complete, unshared machine-store inventory. No native helper runs.
          if (args[0] === "--key-survivors") {
            assert.equal(file, __filename);
            assert.deepEqual(args, ["--key-survivors", "--container", containerName]);
            callback(null, JSON.stringify({ complete: true, shared: false, storesScanned: 3, certificatesScanned: 0, matches: 0 }), "");
          } else callback(null, "", "");
          return { kill() {}, once() {}, pid: 1 };
        } } });
    if (phase === "renew-foreign-job") {
      assert.equal(result.status,"blocked");assert.match(result.errorMessage,/use continue-enrollment/);
      assert.equal(readEnrollmentJournal(stateDir,enrollmentId).journal.state,"prepared");assert.equal(calls.length,0);return;
    }
    if (phase === "keygen_intent-operator") {
      assert.equal(result.status,"blocked");assert.match(result.errorMessage,/ADCS_RECOVERY_CSR_REQUIRED/);
      assert.equal(readEnrollmentJournal(stateDir,enrollmentId).journal.state,"keygen_intent");assert.equal(calls.length,0);return;
    }
    if (phase === "prepared-accepted") {
      assert.equal(result.status,"failed"); assert.match(result.errorMessage,/already accepted key/);
      assert.equal(readEnrollmentJournal(stateDir,enrollmentId).journal.state,"prepared");
      assert.equal(calls.length,0); return;
    }
    assert.equal(result.enrollmentResult.state, "refused"); assert.equal(result.enrollmentResult.errorCode, "ADCS_TEMPLATE_UNSAFE");
    const refused = readEnrollmentJournal(stateDir, enrollmentId);
    assert.equal(refused.kind, "valid"); assert.equal(refused.journal.state, "refused");
    if (phase === "keygen_intent") {
      assert.equal(refused.journal.preSubmitPhase, "keygen_intent");
      assert.equal(refused.journal.csrSpkiSha256, undefined); assert.equal(refused.journal.templateOid, undefined);
    }
    assert.equal(calls.length, 2);
    assert.deepEqual(calls[0], ["--key-survivors", "--container", containerName]);
    assert.deepEqual(calls[1], ["-csp", "Microsoft Software Key Storage Provider", "-delkey", containerName]);
  } finally { await fsp.rm(stateDir, { recursive: true, force: true }); }
});

for(const boundary of ["missing-constraints","dns-scope","key-algorithm","extra-san","target-sni","cross-product"])test(`whole local enrollment policy refuses ${boundary} before helper resolution, keygen or CA contact`,async()=>{
  const stateDir=await fsp.mkdtemp(path.join(os.tmpdir(),"adcs-local-rule-unit-"));
  try{
    const enrollmentId=crypto.randomUUID(),job=jobFor(enrollmentId);let nativeCalls=0;
    const allowed={caConfig:snapshot.caConfig,template:snapshot.template,dnsScopes:["example.com"],keyAlgorithms:["rsa"]};let rules=[allowed];
    if(boundary==="missing-constraints")rules=[{caConfig:snapshot.caConfig,template:snapshot.template}];
    if(boundary==="dns-scope")rules=[{...allowed,dnsScopes:["other.test"]}];
    if(boundary==="key-algorithm")rules=[{...allowed,keyAlgorithms:["ecdsa"]}];
    if(boundary==="target-sni")job.target.binding.sniHost="outside.test";
    if(boundary==="cross-product")rules=[{...allowed,dnsScopes:["other.test"]},{...allowed,keyAlgorithms:["ecdsa"]}];
    if(boundary==="extra-san"){const bytes=Buffer.from(JSON.stringify({...snapshot,authorizedDnsNames:["app.example.com","outside.test"]}));job.enrollment.snapshotB64=bytes.toString("base64");job.enrollment.snapshotSha256=crypto.createHash("sha256").update(bytes).digest("hex");}
    const result=await factory(stateDir).executeWindowsIisAdcsRenewJob({job,jobId:"whole-rule-unit",client:{},log:{},executionContext:{execution:{keysDir:path.join(stateDir,"keys")},adcsEnrollmentRules:rules,adcsPreflightImpl(){nativeCalls++;throw new Error("No CA contact permitted");},windowsExecFileImpl(){nativeCalls++;throw new Error("No native key mutation permitted");}}});
    assert.equal(result.status,"rejected");assert.equal(result.rejectionReason,"issuer_not_allowlisted");assert.equal(result.enrollmentResult.state,"refused");assert.equal(nativeCalls,0);assert.equal(fs.existsSync(keygenIntentPath(stateDir,enrollmentId)),false);
  }finally{await fsp.rm(stateDir,{recursive:true,force:true});}
});

for (const reference of ["production-iis-01", "iis://production/site-1"]) test('deployment reference is not a DNS identity: '+reference, async () => {
  const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-target-reference-"));
  try {
    const helper = path.join(stateDir, "fixture.exe"); fs.writeFileSync(helper, "fixture");
    const job = jobFor(crypto.randomUUID()); job.target.reference = reference;
    const result = await factory(stateDir).executeWindowsIisAdcsRenewJob({ job, jobId: "reference-unit", client: {}, log: {}, executionContext: {
      execution: { keysDir: path.join(stateDir, "keys") }, adcsHelperPath: helper, adcsCaCertPath: caPath,
      adcsEnrollmentRules: [{ caConfig: snapshot.caConfig, template: snapshot.template, dnsScopes: ["example.com"], keyAlgorithms: ["rsa"] }],
      adcsPreflightImpl: () => ({ preflightResult: facts("template") }),
      windowsExecFileImpl() { assert.fail("unsafe fixture must stop before key generation"); },
    }});
    assert.equal(result.enrollmentResult.errorCode, "ADCS_TEMPLATE_UNSAFE", "reference must pass local rule and reach template safety");
  } finally { await fsp.rm(stateDir, { recursive: true, force: true }); }
});
for (const state of ["pending", "pending_issuance", "submission_uncertain", "issued", "validation_deferred"]) test('removed local rule preserves submitted key in '+state, async () => {
  const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-submitted-policy-"));
  try {
    const helper = path.join(stateDir, "fixture.exe"); fs.writeFileSync(helper, "fixture");
    const enrollmentId = crypto.randomUUID(), job = jobFor(enrollmentId), containerName = buildEnrollmentContainerName(enrollmentId);
    const { csrSha256 } = await writeCsrArtifact({ stateDir, enrollmentId, csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nUNIT-ONLY\n-----END CERTIFICATE REQUEST-----\n" });
    const leafPem = fs.readFileSync(path.join(__dirname, "verify/fixtures/leaf.crt.pem"), "utf8");
    const base = { attempt: 1, containerName, snapshotSha256: job.enrollment.snapshotSha256, jobId: "preserve-unit", csrSha256, csrSpkiSha256: computeSpkiSha256Hex(leafPem), templateOid, caConfig: snapshot.caConfig, template: snapshot.template };
    await writeEnrollmentJournal(stateDir, enrollmentId, { ...base, state: "prepared" });
    await writeEnrollmentJournal(stateDir, enrollmentId, { ...base, state: "submitting" });
    if (["issued", "validation_deferred"].includes(state)) {
      const { leafSha256 } = await writeIssuedCertificateArtifacts({ stateDir, enrollmentId, leafPem });
      await writeEnrollmentJournal(stateDir, enrollmentId, { ...base, state: "issued", leafSha256, requestId: 17 });
      if (state === "validation_deferred") await writeEnrollmentJournal(stateDir, enrollmentId, { ...base, state, leafSha256, requestId: 17, validationDeadlineAt: new Date(Date.now()+600000).toISOString() });
    } else await writeEnrollmentJournal(stateDir, enrollmentId, { ...base, state, requestId: 17 });
    let retrieved = 0, validated = 0, reconciled = 0;
    const result = await factory(stateDir).executeWindowsIisContinueEnrollmentJob({ job, jobId: "preserve-unit", client: {}, log: {}, executionContext: {
      execution: { keysDir: path.join(stateDir, "keys") }, adcsHelperPath: helper, adcsCaCertPath: caPath, adcsEnrollmentRules: [],
      adcsPreflightImpl() { assert.fail("submitted recovery must not repeat admission checks"); },
      adcsTryReconcileUncertainSubmissionImpl: async () => { reconciled++; return { status: "unresolved", probed: 0, nextSearchFrom: 17 }; },
      adcsRunDecision6ValidationImpl: async () => { validated++; return { ok: false, retryable: true, errorCode: "ADCS_REVOCATION_UNKNOWN", error: "fixture unavailable" }; },
      adcsExecFileImpl: async (_, args) => { retrieved++; assert.ok(args.includes("-retrieve")); fs.writeFileSync(args.at(-1), "response fixture"); return { stdout: "", stderr: "" }; },
      adcsDecodeCmcImpl: async () => ({ ok: true, result: { disposition: "pending", requestId: 17 } }),
      windowsExecFileImpl() { assert.fail("policy change must not delete or replace a submitted key"); },
    }});
    assert.equal(retrieved, ["pending", "pending_issuance"].includes(state) ? 1 : 0);
    assert.equal(validated, ["issued", "validation_deferred"].includes(state) ? 1 : 0);
    assert.equal(reconciled, state === "submission_uncertain" ? 1 : 0);
    assert.notEqual(result.enrollmentResult?.state, "refused");
    assert.notEqual(readEnrollmentJournal(stateDir, enrollmentId).journal.state, "refused");
    assert.equal(readEnrollmentJournal(stateDir, enrollmentId).journal.containerName, containerName);
  } finally { await fsp.rm(stateDir, { recursive: true, force: true }); }
});
