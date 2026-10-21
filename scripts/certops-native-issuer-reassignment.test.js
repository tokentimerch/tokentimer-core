"use strict";
/**
 * Qualification notes: native issuer reassignment
 *
 * Confirm two different CA keys/configs with four real preflight/confirm/post-confirm dispatches,
 * reservePrimaryPreflights(4). Declare domain(run),10 lowercase hex, before service, register
 * My/domain/certificateId receipt before POST/IDs before waits. Install origin short template;
 * public profile update changes only issuerId,one CERTOPS_RENEWAL_PROFILE_UPDATED audit. Manual
 * renew 409 CERTOPS_ADCS_RENEWAL_NOT_MANUAL creates no job. Actual SQL-NOW sweep uses stored 6-day
 * expiry/30-day window, freezes destination config/key, leaf verifies destination not origin, same
 * IIS/HTTP.sys/TLS cutover with predecessor/key preserved. Gate is
 * native-adcs-issuer-reassignment/real-host. Without forest:
 *   node tests/e2e/helpers/certops-native-issuer-reassignment.js
 * writes failed qualification-results/native-issuer-reassignment.json, cleanup failed, nativeCell
 * pending, exit 1; lab markers alone cannot invoke qualifier. Even completed host proof keeps
 * nativeCell pending until catalog registration; API cases alone do not qualify. Parent retains
 * unresolved ownership/lab; reverse migration/rollback/second cycle/timer not covered.
 *
 * Shared setup, evidence and cleanup policy: docs/certops/e2e-qualification.md.
 */
// Pure proof refusals and the closed manual report. These checks do not
// qualify native CA, CNG, or IIS observations.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createRequire } = require("node:module");
const { verifyReport } = require("./certops-qualification-report");
const {
  verifyProof, verifyNativeProof, assessLab, dispatch, buildClosedReport, qualifyNativeIssuerReassignment,
  FLAGS, SCOPE, REQUIRED_SOURCES, REQUIRED_SCENARIOS, domain,
} = require("../tests/e2e/helpers/certops-native-issuer-reassignment");

const root = path.resolve(__dirname, "..");
const uuid = (digit) => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
function proof() {
  return {
    scope: SCOPE,
    renewalProtocol: "production-scheduler-sweep-after-public-issuer-switch",
    schedulerInvocation: "qualification-invoked-production-default-sweep",
    workerIntervalQualified: false,
    nativeCell: "pending",
    originIssuerId: uuid("1"),
    destinationIssuerId: uuid("2"),
    originCaKeySha256: "a".repeat(64),
    destinationCaKeySha256: "b".repeat(64),
    profileId: uuid("3"),
    certificateId: uuid("4"),
    requestIds: ["17", "18"],
    fingerprints: ["c".repeat(64), "d".repeat(64)],
    spkiFingerprints: ["e".repeat(64), "f".repeat(64)],
    enrollmentIds: [uuid("5"), uuid("6")],
    jobIds: [uuid("7"), uuid("8")],
    containerNames: [
      "tokentimer-enr-55555555-5555-5555-5555-555555555555",
      "tokentimer-enr-66666666-6666-6666-6666-666666666666",
    ],
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
}
const labEnv = {
  CERTOPS_ADCS_DISPOSABLE_LAB: "1",
  CERTOPS_ADCS_API_URL: "https://10.64.0.6",
  CERTOPS_ADCS_ORIGIN_CA_CONFIG: "ca-a.lab.certops.test\\Origin",
  CERTOPS_ADCS_DESTINATION_CA_CONFIG: "ca-b.lab.certops.test\\Destination",
};

test("native issuer reassignment proof stays pending and refuses a synthetic or same-CA result", () => {
  assert.equal(verifyProof(proof()), true);
  for (const flag of FLAGS) for (const value of [false, undefined, "true", 1]) {
    const bad = proof();
    bad[flag] = value;
    assert.throws(() => verifyProof(bad), flag);
  }
  for (const [field, value] of [
    ["scope", "api-only-issuer-switch"],
    ["renewalProtocol", "manual-renew-job"],
    ["schedulerInvocation", "direct-createEnrollment"],
    ["workerIntervalQualified", true],
    ["nativeCell", "qualified"],
    ["originCaKeySha256", proof().destinationCaKeySha256],
    ["destinationIssuerId", proof().originIssuerId],
  ]) {
    const bad = proof();
    bad[field] = value;
    assert.throws(() => verifyProof(bad), field);
  }
  const extra = proof();
  extra.qualified = true;
  assert.throws(() => verifyProof(extra));
});

test("CA-local request IDs may coincide while global custody identities stay distinct", () => {
  const sameNumericId = proof();
  sameNumericId.requestIds = ["17", "17"];
  assert.equal(verifyProof(sameNumericId), true);
  for (const field of ["fingerprints", "spkiFingerprints", "enrollmentIds", "jobIds", "containerNames"]) {
    for (const value of [[proof()[field][0], proof()[field][0]], [proof()[field][0]], [], [null, proof()[field][1]]]) {
      const bad = proof();
      bad[field] = value;
      assert.throws(() => verifyProof(bad));
    }
  }
  for (const id of ["0", "4294967296", 17, "0017", "-1"]) {
    const bad = proof();
    bad.requestIds[0] = id;
    assert.throws(() => verifyProof(bad));
  }
});
test("native qualification requires exact observations on two independent CA databases", () => {
  const candidate = proof();
  candidate.nativeCell = "qualified";
  candidate.requestIds = ["17", "17"];
  assert.throws(() => verifyNativeProof(candidate));
  candidate.nativeRequests = [
    "tt-ca.lab.certops.test\\TTQualificationRoot",
    "tt-ca-switch.lab.certops.test\\TTQualificationDestination",
  ].map((caConfig, i) => ({ caConfig, caKeySha256: i === 0 ? candidate.originCaKeySha256 : candidate.destinationCaKeySha256,
    requestId: candidate.requestIds[i], disposition: 20, subjectRequestCount: 1, fingerprintSha256: candidate.fingerprints[i] }));
  assert.equal(verifyNativeProof(candidate), true);
  assert.throws(() => verifyProof(candidate));
  assert.throws(() => verifyNativeProof(proof()));
  for (const patch of [
    { caConfig: candidate.nativeRequests[0].caConfig }, { caKeySha256: candidate.originCaKeySha256 },
    { requestId: "18" }, { disposition: 9 }, { subjectRequestCount: 2 },
    { fingerprintSha256: candidate.fingerprints[0] },
  ]) {
    const invalid = structuredClone(candidate);
    Object.assign(invalid.nativeRequests[1], patch);
    assert.throws(() => verifyNativeProof(invalid));
  }
  for (const field of Object.keys(candidate.nativeRequests[0])) {
    const invalid = structuredClone(candidate);
    delete invalid.nativeRequests[0][field];
    assert.throws(() => verifyNativeProof(invalid));
  }
});
test("issuer-switch cleanup registry refuses capacity and foreign certificate namespaces", () => {
  const helper = require("../tests/e2e/helpers/certops-adcs-webhosting-renewal");
  const receipts = [];
  const receipt = helper.registerIssuerSwitchStoreCertificate(receipts, {
    domain: "certops-adcs-0123456789-issuer-switch.example.test", certificateId: uuid("1"),
  });
  assert.deepEqual(helper.issuerSwitchCleanupPlan(receipt, [], () => null), []);
  assert.throws(() => helper.capacityCleanupPlan(receipt, [], () => null));
  assert.throws(() => helper.issuerSwitchCleanupPlan({ ...receipt, domain: "certops-adcs-0123456789-capacity0.example.test" }, [], () => null));
  assert.throws(() => helper.registerIssuerSwitchStoreCertificate(receipts, { domain: receipt.domain, certificateId: uuid("2") }));
});

test("the owned subject is exact and critical sources are present", () => {
  const run = "0123456789";
  assert.equal(domain(run), "certops-adcs-0123456789-issuer-switch.example.test");
  for (const bad of ["", "0123456789'", "../outside", "ABCDEF0123"]) assert.throws(() => domain(bad));
  for (const file of REQUIRED_SOURCES) assert.equal(fs.existsSync(path.join(root, file)), true, file);
  assert.deepEqual([...REQUIRED_SCENARIOS], [
    "adcs-real-issuer-reassignment-confirmed-switch",
    "adcs-real-issuer-reassignment-renewal-migrates",
    "adcs-real-issuer-reassignment-cleanup",
  ]);
});

test("lab assessment fail closed unless two distinct disposable CA configs are present", () => {
  assert.equal(assessLab(labEnv, "win32").ok, true);
  assert.equal(assessLab({ ...labEnv, CERTOPS_ADCS_DISPOSABLE_LAB: "0" }, "win32").ok, false);
  assert.equal(assessLab(labEnv, "linux").ok, false);
  assert.equal(assessLab({ ...labEnv, CERTOPS_ADCS_API_URL: "http://10.64.0.6" }, "win32").ok, false);
  assert.equal(assessLab({ ...labEnv, CERTOPS_ADCS_DESTINATION_CA_CONFIG: labEnv.CERTOPS_ADCS_ORIGIN_CA_CONFIG }, "win32").ok, false);
  assert.equal(assessLab({}, "win32").ok, false);
});

test("a missing forest never reaches the fixture and cannot satisfy the strict verifier", async () => {
  const previous = process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
  delete process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
  let touched = false;
  const context = new Proxy({}, { get() { touched = true; throw new Error("fixture touched"); } });
  try {
    await assert.rejects(() => qualifyNativeIssuerReassignment(context), /Disposable AD CS forest is required/);
    assert.equal(touched, false);
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
    else process.env.CERTOPS_ADCS_DISPOSABLE_LAB = previous;
  }
  const closed = buildClosedReport("Disposable AD CS forest is required");
  const errors = verifyReport(closed, undefined, { expectedSha: null });
  assert.equal(closed.status, "failed");
  assert.equal(closed.nativeCell, "pending");
  assert.equal(closed.cleanup.status, "failed");
  assert.ok(errors.includes("Report is not a completed strict qualification"));
  assert.equal(errors.includes("Suite has no committed mandatory scenario specification"), false);
  const forged = {
    ...closed,
    status: "passed",
    nativeCell: "qualified",
    cleanup: { status: "passed" },
    missingScenarios: [],
    missingCapabilities: [],
    scenarios: REQUIRED_SCENARIOS.map((id) => ({ id, status: "passed", evidenceLevel: "real-host", startedAt: closed.startedAt, finishedAt: closed.finishedAt })),
    capabilities: Object.fromEntries(["windows", "elevated", "domain", "api", "qualifiedBuild"].map((name) => [name, { available: true }])),
  };
  const forgedErrors = verifyReport(forged, undefined, { expectedSha: null });
  assert.equal(forgedErrors.includes("Suite has no committed mandatory scenario specification"), false);
  assert.throws(() => verifyProof({ ...proof(), nativeCell: "qualified" }));
  assert.equal(forged.nativeIssuerReassignment, undefined);
});

test("dispatch writes a failed report for both a missing forest and lab markers", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "issuer-reassignment-"));
  try {
    const missing = path.join(directory, "missing.json");
    assert.equal(dispatch({ env: {}, platform: "win32", reportPath: missing, qualify() { throw new Error("must not run"); } }), 1);
    const missingReport = JSON.parse(fs.readFileSync(missing, "utf8"));
    assert.equal(missingReport.status, "failed");
    assert.equal(missingReport.nativeCell, "pending");
    assert.ok(verifyReport(missingReport, undefined, { expectedSha: null }).includes("Report is not a completed strict qualification"));
    const marked = path.join(directory, "marked.json");
    let called = false;
    assert.equal(dispatch({
      env: labEnv,
      platform: "win32",
      reportPath: marked,
      qualify() { called = true; },
    }), 1);
    assert.equal(called, false);
    const markedReport = JSON.parse(fs.readFileSync(marked, "utf8"));
    assert.equal(markedReport.status, "failed");
    assert.equal(markedReport.nativeCell, "pending");
    assert.match(markedReport.cleanup.summary, /do not execute native issuer reassignment/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the domain-only workflow is manual, protected and destroys its optional fourth VM", () => {
  const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
  const name = "certops-native-issuer-reassignment.yml";
  const file = path.join(root, ".github/workflows", name);
  const text = fs.readFileSync(file, "utf8").replace(/\r\n/g, "\n");
  assert.equal(text.includes("pull_request"), false);
  assert.equal(text.includes("\npush:"), false);
  assert.match(text, /IssuerReassignment 1/);
  assert.match(text, /CERTOPS_ADCS_LAB_ENABLED/);
  assert.match(text, /environment: certops-adcs-lab/);
  assert.match(text, /if: always\(\)\s+shell: pwsh\s+run: \.\/infra\/certops-adcs\/remove-owned-lab\.ps1/);
  assert.equal(text.includes("azure/login"), false);
  const workflow = yaml.load(text);
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.equal(workflow.permissions.contents, "read");
  const errors = require("./certops-workflow-security").validateWorkflow(workflow, name);
  assert.deepEqual(errors, []);
});
test("real benign loopback TLS probes close before success, refusal and parent cleanup", async () => {
  const { spawnSync } = require("node:child_process");
  const tls = require("node:tls");
  const { createOwnedTlsProbes } = require("../tests/e2e/helpers/certops-native-issuer-reassignment");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "issuer-switch-public-tls-"));
  const key = path.join(directory, "key.pem"), cert = path.join(directory, "cert.pem");
  const sockets = new Set();
  let server;
  const probes = createOwnedTlsProbes({timeoutMs:3000});
  try {
    // Benign software test certificate only; no OS store, CNG or agent custody.
    const generated = spawnSync(process.env.OPENSSL_BIN || "openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"], {encoding:"utf8"});
    assert.ifError(generated.error); assert.equal(generated.status, 0, "OpenSSL test prerequisite failed");
    server = tls.createServer({key:fs.readFileSync(key),cert:fs.readFileSync(cert)});
    server.on("tlsClientError", () => {});
    server.on("connection", socket => {sockets.add(socket);socket.once("close",()=>sockets.delete(socket));});
    await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
    const options = {host:"127.0.0.1",port:server.address().port,servername:"localhost",ca:fs.readFileSync(cert),rejectUnauthorized:true};
    const subject = await probes.observe(options, socket => {assert.equal(socket.authorized,true);return socket.getPeerCertificate().subject.CN;});
    assert.equal(subject,"localhost"); assert.equal(probes.isDrained(),true);
    await assert.rejects(probes.observe({...options,servername:"foreign.example.test"},()=>true));
    assert.equal(probes.isDrained(),true);
    await assert.rejects(probes.observe(options,()=>{throw new Error("Observed refusal");}),/Observed refusal/);
    assert.equal(probes.isDrained(),true);
    const pending = assert.rejects(probes.observe(options,()=>true),/closed before observation|reset|hang up|disconnected/i);
    await probes.drain(); await pending;
    assert.equal(probes.isDrained(),true);
  } finally {
    await probes.drain();
    for(const socket of sockets)socket.destroy();
    if(server)await new Promise(resolve=>server.close(resolve));
    fs.rmSync(directory,{recursive:true,force:true});
  }
});
