/** Offline admission checks for renewal public-key metadata qualification.
 * Require the disposable API runner and current production-source evidence;
 * synthetic reports here never establish native key custody or CA execution. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { suites, verifySource } = require("./certops-api-qualification");
const { verifyMatrix } = require("./certops-release-qualification");
const inventory = require("../docs/certops/qualification-suites.json");
const matrix = require("../docs/certops/qualification-suites.json");
const root = path.resolve(__dirname, ".."), suite = "renewal-key-facts-api";
const source = "tests/e2e/certops-renewal-key-facts-e2e.test.js";
const hash = file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") });

test("renewal key facts run in the disposable API lane with exact mandatory names and source dependencies", () => {
  assert.deepEqual(suites.filter(row => row[0] === suite), [[suite, path.basename(source), "CERTOPS_RENEWAL_KEY_FACTS_REPORT"]]);
  assert.equal(inventory.suites[suite].length, 7);
  assert.equal(inventory.suiteEvidenceLevels[suite], "integration");
  assert.deepEqual(inventory.requiredCapabilities[suite], ["api", "postgres", "openssl"]);
  const slots = matrix.slots.filter(slot => slot.suite === suite);
  assert.equal(slots.length, 1);
  assert.deepEqual(slots[0].environment, { osFamily: "linux" });
  assert.equal(slots[0].requiredSources.length, 6);
  assert.ok(slots[0].requiredSources.includes("apps/api/services/certops/agentDispatch.js"));
  const workflow = fs.readFileSync(path.join(root, ".github/workflows/certops-qualification.yml"), "utf8");
  assert.match(workflow, /node scripts\/certops-api-qualification\.js/);
  assert.match(workflow, /path: qualification-results\//);
  assert.equal(verifySource({ fixtureSource: hash(source) }, path.basename(source)), true);
  assert.equal(verifySource({ fixtureSource: { file: source, sha256: "0".repeat(64) } }, path.basename(source)), false);
});

test("renewal key-fact evidence refuses missing execution, skips and stale production fingerprints", () => {
  const slot = matrix.slots.find(row => row.suite === suite), now = new Date().toISOString(), candidateSha = "a".repeat(40);
  const report = { schemaVersion: 1, suite, candidateSha, startedAt: now, finishedAt: now, status: "passed", strict: true,
    evidenceLevel: "integration", requiredCapabilities: inventory.requiredCapabilities[suite],
    capabilities: Object.fromEntries(inventory.requiredCapabilities[suite].map(name => [name, { available: true }])),
    requiredScenarios: inventory.suites[suite], missingCapabilities: [], missingScenarios: [],
    scenarios: inventory.suites[suite].map(id => ({ id, status: "passed", evidenceLevel: "integration", startedAt: now, finishedAt: now })),
    fixtureSource: hash(source), fixtureSources: slot.requiredSources.map(hash),
    qualificationEnvironment: { osFamily: "linux", measurement: "native" }, artifactQualification: "workflow-checkout-source" };
  const artifact = { kind: "host", suite, environment: report.qualificationEnvironment, report };
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
  assert.deepEqual(verifyMatrix([artifact], options), []);
  for (const mutate of [value => value.report.scenarios.pop(), value => { value.report.scenarios[0].status = "skipped"; },
    value => { value.report.fixtureSources.find(row => row.file.endsWith("agentDispatch.js")).sha256 = "0".repeat(64); },
    value => { delete value.report.fixtureSources; }]) {
    const invalid = structuredClone(artifact); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
});
