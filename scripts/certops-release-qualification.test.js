"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { verifyMatrix, validateMatrix } = require("./certops-release-qualification");
const { catalogCoverage, validateQualificationSummary } = require("./certops-release-qualification");
const contract = require("../docs/certops/qualification-suites.json");
const root = path.resolve(__dirname, "..");
const candidateSha = "a".repeat(40);
const source = "tests/e2e/certops-job-decisions-e2e.test.js";
const environment = { osFamily: "linux" };
test("a complete mandatory matrix cannot promote incomplete feature specifications", () => {
  const catalog = { schemaVersion: 1, scenarios: [{ id: "fixture.not-yet-covered", outcome: "Still requires native qualification", status: "planned", evidenceLevel: "unassigned", requiredEnvironments: [], implementation: null }] };
  const coverage = catalogCoverage(catalog);
  assert.equal(coverage.total, 1); assert.equal(coverage.planned, 1); assert.equal(coverage.implementationStatus, "incomplete");
  const summary = { qualificationScope: "committed-mandatory-matrix", allFeaturesQualified: false, catalogCoverage: coverage };
  assert.deepEqual(validateQualificationSummary(summary, catalog), []);
  assert.ok(validateQualificationSummary({ ...summary, allFeaturesQualified: true }, catalog).length);
  assert.ok(validateQualificationSummary({ ...summary, qualificationScope: "all-features" }, catalog).length);
  assert.ok(validateQualificationSummary({ ...summary, catalogCoverage: { ...coverage, implementationStatus: "all-specifications-implemented" } }, catalog).length);
});
const specification = { schemaVersion: 1, slots: [{ id: "fixture", kind: "host", suite: "job-decisions-api", source, environment }] };
function artifact() {
  const suite = "job-decisions-api";
  const now = new Date().toISOString();
  const report = { schemaVersion: 1, suite, candidateSha, startedAt: now, finishedAt: now, status: "passed", strict: true, evidenceLevel: "integration", requiredCapabilities: contract.requiredCapabilities[suite], capabilities: { api: { available: true }, postgres: { available: true } }, requiredScenarios: contract.suites[suite], missingCapabilities: [], missingScenarios: [], scenarios: contract.suites[suite].map((id) => ({ id, status: "passed", evidenceLevel: "integration", startedAt: now, finishedAt: now })), qualificationEnvironment: { ...environment, measurement: "native" }, artifactQualification: "workflow-checkout-source", fixtureSource: { file: source, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, source))).digest("hex") } };
  return { kind: "host", suite, environment: report.qualificationEnvironment, report };
}
test("release matrix accepts complete source-bound evidence, rejects missing and repeated environments", () => {
  const options = { candidateSha, specification };
  assert.deepEqual(verifyMatrix([artifact()], options), []);
  assert.ok(verifyMatrix([], options).length);
  assert.ok(verifyMatrix([artifact(), artifact()], options).length);
  assert.ok(verifyMatrix([artifact()], { specification }).length);
});

test("native ADCS cohort dispatch budgets cannot be omitted duplicated or exceeded", () => {
  const suite = "enterprise-adcs-real", file = "tests/e2e/certops-adcs-real-e2e.test.js";
  const value = artifact(); value.suite = suite; Object.assign(value.report, {
    suite, evidenceLevel: "real-host", requiredCapabilities: contract.requiredCapabilities[suite],
    capabilities: Object.fromEntries(contract.requiredCapabilities[suite].map(name => [name, { available: true }])),
    requiredScenarios: contract.suites[suite], scenarios: contract.suites[suite].map(id => ({ ...value.report.scenarios[0], id, evidenceLevel: "real-host" })),
    fixtureSource: { file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") },
    primaryNativePreflightDispatchCount: 18,
    nativePreflightCohorts: [{ workspaceId: "a".repeat(36), agentId: "b".repeat(36), dispatchCount: 18, dispatchLimit: 18, nativeIdentity: "LocalSystem", runtime: "candidate-cli" }],
    nativeTemplateMutations: contract.suites[suite].filter(id => id.startsWith("adcs-real-mutated-template-")).map(id => ({ caseId: id.slice("adcs-real-mutated-template-".length, -"-native-refused".length), template: "TTQualificationRSAShort", preflightVerdict: "unsafe", originalConfirmedIssuerReused: true, actualSignedJobRefused: true, noCaRequestAllocated: true, noKeyGenerated: true, outgoingTrustedTlsPreserved: true })),
  });
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [{ id: "cohort", kind: "host", suite, source: file, environment }] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const mutate of [item => { delete item.report.nativePreflightCohorts; }, item => { item.report.primaryNativePreflightDispatchCount = 19; }, item => { item.report.nativePreflightCohorts[0].dispatchCount = 19; }, item => { item.report.nativePreflightCohorts.push(item.report.nativePreflightCohorts[0]); }, item => { item.report.nativePreflightCohorts[0].runtime = "mock"; }]) {
    const invalid = structuredClone(value); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
  for (const mutate of [item => { item.report.nativeTemplateMutations.pop(); }, item => { item.report.nativeTemplateMutations[0].noKeyGenerated = false; }, item => { item.report.nativeTemplateMutations[0].preflightVerdict = "safe"; }]) {
    const invalid = structuredClone(value); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
});
test("release matrix rejects mislabeled hosts, stale source, local evidence, skips and candidate mismatch", () => {
  const options = { candidateSha, specification };
  for (const mutate of [
    (value) => { value.report.candidateSha = "b".repeat(40); },
    (value) => { value.report.fixtureSource.sha256 = "0".repeat(64); },
    (value) => { value.report.qualificationEnvironment.osFamily = "windows"; },
    (value) => { value.report.qualificationEnvironment.measurement = "selected-input"; },
    (value) => { value.report.artifactQualification = "local-worktree-source-baseline-sha-only"; },
    (value) => { value.report.qualificationStatus = "not-qualified"; },
    (value) => { value.report.scenarios[0].status = "skipped"; },
    (value) => { value.report.requiredCapabilities = []; value.report.capabilities = {}; },
  ]) { const value = artifact(); mutate(value); assert.ok(verifyMatrix([value], options).length); }
});
test("release matrix refuses duplicate specifications and malformed artifact collections", () => {
  assert.ok(verifyMatrix(null, { candidateSha, specification }).length);
  assert.ok(verifyMatrix([artifact()], { candidateSha, specification: { ...specification, slots: [specification.slots[0], specification.slots[0]] } }).length);
  assert.ok(verifyMatrix([], { candidateSha, specification: { schemaVersion: 1, slots: [] } }).length);
});
test("supporting helper sources require unique current fingerprints", () => {
  const files = ["tests/e2e/helpers/certops-windows-reregistration.js", "tests/e2e/helpers/certops-windows-capability-refresh.js"];
  const specificationWithHelpers = { ...specification, slots: [{ ...specification.slots[0], requiredSources: files }] };
  const value = artifact();
  value.report.fixtureSources = files.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  assert.deepEqual(verifyMatrix([value], { candidateSha, specification: specificationWithHelpers }), []);
  for (const mutate of [
    report => { delete report.fixtureSources; },
    report => { report.fixtureSources.pop(); },
    report => { report.fixtureSources[0].sha256 = "0".repeat(64); },
    report => { report.fixtureSources.push(report.fixtureSources[0]); },
  ]) {
    const copy = structuredClone(value); mutate(copy.report);
    assert.ok(verifyMatrix([copy], { candidateSha, specification: specificationWithHelpers }).length);
  }
  assert.ok(validateMatrix({ ...specification, slots: [{ ...specification.slots[0], requiredSources: ["../outside.js"] }] }).some(error => error.includes("supporting source")));
});
test("committed release matrix covers all mandatory suites and rejects escaped sources", () => {
  assert.deepEqual(validateMatrix(), []);
  assert.ok(validateMatrix({ schemaVersion: 1, slots: [{ ...specification.slots[0], source: "../outside.js" }] }).some((error) => error.includes("inside")));
  assert.ok(validateMatrix({ schemaVersion: 1, slots: [] }).length);
  assert.ok(verifyMatrix([], { candidateSha, specification: { schemaVersion: 1, slots: [null, { id: "invalid" }] } }).length);
});
test("migration slot requires historical schema and transition evidence beyond generic scenario success", () => {
  const value = artifact();
  const suite = "core-api-migration-upgrade", source = "scripts/certops-migration-upgrade.js";
  value.suite = suite; value.report.suite = suite; value.report.evidenceLevel = "e2e";
  value.report.requiredCapabilities = contract.requiredCapabilities[suite];
  value.report.capabilities = Object.fromEntries(contract.requiredCapabilities[suite].map(name => [name, { available: true }]));
  value.report.requiredScenarios = contract.suites[suite];
  value.report.scenarios = contract.suites[suite].map(id => ({ id, status: "passed", evidenceLevel: "e2e", startedAt: value.report.startedAt, finishedAt: value.report.finishedAt }));
  value.report.fixtureSource = { file: source, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, source))).digest("hex") };
  const specification = { schemaVersion: 1, slots: [{ id: suite, kind: "host", suite, source, environment }] };
  assert.ok(verifyMatrix([value], { candidateSha, specification }).length);
  value.report.sourceProvenance = "historical-source-build-to-candidate-source";
  value.report.sourceIdentity = {
    baseline: { sha: require("./certops-migration-upgrade").BASELINE, version: "0.17.3", lockfileSha256: "b".repeat(64) },
    candidate: { sha: candidateSha, version: require("../package.json").version, lockfileSha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "pnpm-lock.yaml"))).digest("hex") },
  };
  value.report.databaseRuntime = { imageId: "sha256:" + "c".repeat(64), serverVersion: "16.6" };
  value.report.baselineSchema = { tables: 1, columns: 2, migrations: [{ version: 1, name: "core_schema" }] };
  value.report.candidateSchema = { tables: 2, columns: 4, migrations: [{ version: 1, name: "core_schema" }, { version: 2, name: "additional_schema" }] };
  value.report.actualTlsObservedPromotion = true; value.report.repeatMigrationSchemaUnchanged = true;
  assert.deepEqual(verifyMatrix([value], { candidateSha, specification }), []);
  value.report.sourceIdentity.candidate.lockfileSha256 = "0".repeat(64);
  assert.ok(verifyMatrix([value], { candidateSha, specification }).some(error => error.includes("package identity")));
});
test("stack matrix validates exact mandatory journey names and refuses skipped or foreign-scope events", () => {
  const event = { ...artifact().report, type: "test:pass", name: "fixture mandatory journey", file: path.join(root, source), scope: "fixture-stack", skip: false, todo: false };
  const slot = { id: "stack-fixture", kind: "stack", suite: event.scope, source, environment, requiredTests: [event.name] };
  const specification = { schemaVersion: 1, slots: [slot] };
  const stack = { kind: "stack", suite: event.scope, environment: event.qualificationEnvironment, events: [event] };
  assert.deepEqual(verifyMatrix([stack], { candidateSha, specification }), []);
  for (const mutation of [{ skip: true }, { scope: "foreign-scope" }, { name: "unrequired journey" }, { type: "test:fail" }]) {
    assert.ok(verifyMatrix([{ ...stack, events: [{ ...event, ...mutation }] }], { candidateSha, specification }).length);
  }
});
test("database matrix requires every committed case and source digest without promoting supporting evidence", () => {
  const definition = require("../tests/integration/certops-qualification-groups.json").adcs;
  const suite = "adcs-database-integration";
  const sources = definition.files.map((file) => ({ file: `tests/integration/${file}`, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "tests/integration", file))).digest("hex") }));
  const report = { scope: suite, candidateSha, evidenceLevel: "integration", qualificationEnvironment: { ...environment, measurement: "native" }, artifactQualification: "workflow-checkout-source", fixtureSources: sources, tests: definition.requiredTests.map((test) => ({ ...test, status: "pass" })) };
  const specification = { schemaVersion: 1, slots: [{ id: "database-fixture", kind: "database", suite, source: sources[0].file, requiredGroup: "adcs", environment }] };
  const artifact = { kind: "database", suite, environment: report.qualificationEnvironment, report };
  assert.deepEqual(verifyMatrix([artifact], { candidateSha, specification }), []);
  for (const mutate of [
    (value) => { value.tests[0].status = "pending"; },
    (value) => { value.tests.pop(); },
    (value) => { value.fixtureSources[0].sha256 = "0".repeat(64); },
    (value) => { value.fixtureSources.push(value.fixtureSources[0]); },
    (value) => { value.evidenceLevel = "real-host"; },
  ]) { const copy = JSON.parse(JSON.stringify(report)); mutate(copy); assert.ok(verifyMatrix([{ ...artifact, report: copy }], { candidateSha, specification }).length); }
});
