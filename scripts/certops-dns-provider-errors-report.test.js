"use strict";
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { validateInventory, verifyDnsErrors } = require("./certops-dns-provider-errors-report");
const inventory = require("../docs/certops/dns-provider-errors.json"), contract = require("../docs/certops/qualification-suites.json");
const root = path.resolve(__dirname, "..");
test("new unsupported test declarations cannot silently escape the mandatory inventory", () => {
  const { contractNames } = require("./certops-dns-provider-errors-report");
  assert.deepEqual(contractNames('test("named", () => {});'), ["named"]);
  for (const source of ["test('new single quoted', () => {});", "test(name, () => {});", 'test("same", () => {});test("same", () => {});']) assert.throws(() => contractNames(source));
});
function fixture() {
  const now = new Date().toISOString(), suite = "dns-provider-errors", definitions = [...inventory.providers, ...inventory.sharedContracts];
  const source = file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") });
  return { schemaVersion: 1, suite, candidateSha: process.env.GITHUB_SHA || "a".repeat(40), startedAt: now, finishedAt: now, status: "passed", strict: true, evidenceLevel: "integration", requiredCapabilities: contract.requiredCapabilities[suite], capabilities: Object.fromEntries(contract.requiredCapabilities[suite].map(name => [name, { available: true }])), requiredScenarios: inventory.requiredScenarios, missingCapabilities: [], missingScenarios: [], scenarios: inventory.requiredScenarios.map(id => ({ id, status: "passed", evidenceLevel: contract.scenarioEvidenceLevels[suite][id], startedAt: now, finishedAt: now })), fixtureSource: source("scripts/certops-dns-provider-errors.js"), fixtureSources: definitions.map(definition => source(definition.file)), dnsAdapterCases: definitions.flatMap(definition => definition.requiredTests.map(name => ({ file: definition.file, name, status: "passed" }))) };
}
test("all production providers and current contract names require committed inventory", () => {
  assert.equal(validateInventory().providers, 11);
  const missing = structuredClone(inventory); missing.providers.pop(); assert.throws(() => validateInventory(missing));
  const changed = structuredClone(inventory); changed.providers[0].requiredTests.pop(); assert.throws(() => validateInventory(changed));
});
test("adapter evidence refuses omitted duplicate skipped stale or relabeled cases", () => {
  assert.equal(verifyDnsErrors(fixture()), true);
  for (const mutate of [report => { report.dnsAdapterCases.pop(); }, report => { report.dnsAdapterCases[0].status = "skipped"; }, report => { report.dnsAdapterCases[1] = report.dnsAdapterCases[0]; }, report => { report.fixtureSources[0].sha256 = "0".repeat(64); }, report => { report.scenarios[0].evidenceLevel = "real-host"; }]) {
    const report = fixture(); mutate(report); assert.throws(() => verifyDnsErrors(report), /evidence incomplete/);
  }
});
