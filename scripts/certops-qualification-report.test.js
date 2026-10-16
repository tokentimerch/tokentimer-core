/**
 * Regression coverage: committed catalog contains valid independent scenario specifications.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { verifyReport } = require("./certops-qualification-report");
const { validateCatalog } = require("./certops-qualification-catalog");
test("committed catalog contains valid independent scenario specifications", () => {
  assert.deepEqual(validateCatalog(require("../docs/certops/e2e-scenario-catalog.json")), []);
});
test("catalog rejects duplicate identities and unsupported implementation claims", () => {
  const row = { id: "fixture.case", outcome: "Checks behavior", status: "implemented", evidenceLevel: "unassigned", requiredEnvironments: [], implementation: null };
  assert.ok(validateCatalog({ schemaVersion: 1, scenarios: [row, row] }).length >= 3);
});
test("verifier rejects false success, duplicate IDs and missing capability evidence", () => {
  const report = { schemaVersion: 1, suite: "fixture", status: "passed", strict: true, finishedAt: "now", requiredCapabilities: ["native"], scenarios: [{ id: "case", status: "passed" }, { id: "case", status: "passed" }] };
  assert.ok(verifyReport(report).some((error) => error.includes("duplicate")));
  assert.ok(verifyReport(report).some((error) => error.includes("capability")));
});
test("committed mandatory IDs cannot be removed from a success report", () => {
  const report = { schemaVersion: 1, suite: "windows-host", candidateSha: "a".repeat(40), evidenceLevel: "real-host", strict: true, status: "passed", finishedAt: new Date().toISOString(), scenarios: [{ id: "unrelated", status: "passed", startedAt: "now", finishedAt: "now" }], requiredScenarios: [] };
  assert.equal(verifyReport(report).filter((error) => error.includes("Missing required scenario")).length, require("../docs/certops/qualification-suites.json").suites["windows-host"].length);
});
test("malformed reports return failure instead of crashing", () => {
  for (const report of [null, [], {}, { scenarios: {} }, { scenarios: [null] }]) assert.ok(verifyReport(report).length);
});

test("uncommitted scenario identifiers and capability text cannot enter verifier diagnostics", () => {
  const sentinel = "private-untrusted-report-sentinel";
  const errors = verifyReport({ suite: "windows-host", scenarios: [{ id: sentinel, status: "failed" }], requiredScenarios: [sentinel], requiredCapabilities: [sentinel] });
  assert.ok(errors.some(error => error.includes("Unrecognized scenario")));
  assert.ok(!errors.join("\n").includes(sentinel));
  assert.deepEqual(verifyReport({ scenarios: Array(4097).fill({}) }), ["Report execution metadata exceeds bounds"]);
});
test("partial mappings declare the remaining coverage explicitly", () => {
  const row = { id: "fixture.partial", outcome: "Behavior", status: "partial", evidenceLevel: "real-host", requiredEnvironments: ["windows"], implementation: "host.test.js" };
  assert.ok(validateCatalog({ schemaVersion: 1, scenarios: [row] }).some((error) => error.includes("remaining coverage")));
  row.remainingCoverage = "Additional algorithms and service identity";
  assert.deepEqual(validateCatalog({ schemaVersion: 1, scenarios: [row] }), []);
});
test("candidate commit must agree with the qualification environment", () => {
  const previous = process.env.GITHUB_SHA;
  try {
    process.env.GITHUB_SHA = "b".repeat(40);
    assert.ok(verifyReport({ candidateSha: "a".repeat(40) }).some((error) => error.includes("differs")));
  } finally { if (previous === undefined) delete process.env.GITHUB_SHA; else process.env.GITHUB_SHA = previous; }
});
test("report cannot suppress externally required capabilities", () => {
  const errors = verifyReport({ suite: "windows-host", requiredCapabilities: [], scenarios: [] });
  assert.ok(errors.some((error) => error === "Missing capability evidence: elevated"));
  assert.ok(errors.some((error) => error === "Missing capability evidence: iis"));
});
test("CLI rejects absent arguments and malformed report files", () => {
  const { spawnSync } = require("node:child_process");
  const path = require("node:path");
  const command = path.join(__dirname, "certops-qualification-report.js");
  const empty = spawnSync(process.execPath, [command], { encoding: "utf8" });
  assert.equal(empty.status, 1); assert.match(empty.stderr, /Usage:/);
  const invalid = spawnSync(process.execPath, [command, path.join(__dirname, "certops-qualification-report.js")], { encoding: "utf8" });
  assert.equal(invalid.status, 1);
});
test("unit helper evidence cannot be promoted to native certificate proof", () => {
  const errors = verifyReport({ suite: "windows-host", scenarios: [{ id: "windows-adcs-chain-go", evidenceLevel: "real-host" }] });
  assert.ok(errors.some((error) => error.includes("differs from specification")));
});
test("committed suites require unique scenarios and exhaustive evidence classifications", () => {
  const { validateSuites } = require("./certops-qualification-suites");
  assert.deepEqual(validateSuites(require("../docs/certops/qualification-suites.json")), []);
  const invalid = { schemaVersion: 1, suites: { fixture: ["native", "native"] } };
  assert.ok(validateSuites(invalid).length);
  assert.ok(validateSuites({ schemaVersion: 1, suites: { fixture: ["native"] } }).length >= 2);
});

test("a complete execution report cannot pass with missing committed classifications", () => {
  const metadata = require("../docs/certops/qualification-suites.json");
  const suite = "terminal-renewal-admission-api", candidateSha = "a".repeat(40), time = new Date().toISOString();
  const report = { schemaVersion: 1, suite, candidateSha, evidenceLevel: metadata.suiteEvidenceLevels[suite], strict: true, status: "passed", startedAt: time, finishedAt: time,
    requiredScenarios: metadata.suites[suite], missingScenarios: [], requiredCapabilities: metadata.requiredCapabilities[suite], missingCapabilities: [],
    capabilities: Object.fromEntries(metadata.requiredCapabilities[suite].map(name => [name, { available: true }])),
    scenarios: metadata.suites[suite].map(id => ({ id, status: "passed", evidenceLevel: metadata.scenarioEvidenceLevels[suite][id], startedAt: time, finishedAt: time })),
  };
  assert.deepEqual(verifyReport(report, undefined, { expectedSha: candidateSha }), []);
  const id = metadata.suites[suite][0], level = metadata.scenarioEvidenceLevels[suite][id];
  try {
    delete metadata.scenarioEvidenceLevels[suite][id];
    assert.deepEqual(verifyReport(report, undefined, { expectedSha: candidateSha }), ["Invalid committed qualification suite contract"]);
  } finally { metadata.scenarioEvidenceLevels[suite][id] = level; }
  assert.deepEqual(verifyReport(report, undefined, { expectedSha: candidateSha }), []);
});

test("API runner binds reports to the current selected source file", () => {
  const { verifySource } = require("./certops-api-qualification");
  const fs = require("node:fs");
  const path = require("node:path");
  const crypto = require("node:crypto");
  const file = "certops-csr-lifecycle-e2e.test.js";
  const source = "tests/e2e/" + file;
  const sha256 = crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "..", source))).digest("hex");
  assert.equal(verifySource({ fixtureSource: { file: source, sha256 } }, file), true);
  assert.equal(verifySource({ fixtureSource: { file: source, sha256: "0".repeat(64) } }, file), false);
  assert.equal(verifySource({ fixtureSource: { file: "another-source.js", sha256 } }, file), false);
  assert.equal(verifySource({}, file), false);
});
