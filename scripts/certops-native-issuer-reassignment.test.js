"use strict";
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
  verifyProof, assessLab, dispatch, buildClosedReport, qualifyNativeIssuerReassignment,
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

test("origin and destination requests, leaves, enrollments, jobs, and containers must be distinct", () => {
  for (const field of ["requestIds", "fingerprints", "spkiFingerprints", "enrollmentIds", "jobIds", "containerNames"]) {
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

test("the manual workflow is dispatch-only, read-only, and outside Azure provisioning", () => {
  const yaml = createRequire(require.resolve(path.join(root, "node_modules/mocha/package.json")))("js-yaml");
  const name = "certops-native-issuer-reassignment.yml";
  const file = path.join(root, ".github/workflows", name);
  const text = fs.readFileSync(file, "utf8");
  assert.equal(text.includes("\r"), false);
  assert.equal(text.includes("pull_request"), false);
  assert.equal(text.includes("\npush:"), false);
  assert.equal(text.includes("AZURE_"), false);
  assert.equal(text.includes("provision-lab"), false);
  assert.equal(text.includes("azure/login"), false);
  const workflow = yaml.load(text);
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.equal(workflow.permissions.contents, "read");
  const errors = require("./certops-workflow-security").validateWorkflow(workflow, name);
  assert.deepEqual(errors, []);
});
