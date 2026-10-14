"use strict";
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { validateInventory, verifyDnsErrors } = require("./certops-dns-provider-errors-report");
const inventory = require("../docs/certops/dns-provider-errors.json"), contract = require("../docs/certops/qualification-suites.json");
const root = path.resolve(__dirname, "..");
test("OAuth fixture endpoints require exact HTTPS origin and token path", () => {
  const { isOAuthFixtureEndpoint } = require("./certops-dns-provider-errors");
  const credential = { tenantId: "fixture-tenant" };
  assert.equal(isOAuthFixtureEndpoint("https://oauth2.googleapis.com/token", "google-cloud-dns", credential), true);
  assert.equal(isOAuthFixtureEndpoint("https://login.microsoftonline.com/fixture-tenant/oauth2/v2.0/token", "azure-dns", credential), true);
  for (const endpoint of ["https://oauth2.googleapis.com.evil.test/token", "https://evil-oauth2.googleapis.com/token", "https://evil.test/oauth2.googleapis.com/token", "https://oauth2.googleapis.com@evil.test/token", "http://oauth2.googleapis.com/token", "https://oauth2.googleapis.com:444/token", "https://oauth2.googleapis.com/token?redirect=fixture", "https://oauth2.googleapis.com/token#fragment", "not a URL"]) assert.equal(isOAuthFixtureEndpoint(endpoint, "google-cloud-dns", credential), false);
  assert.equal(isOAuthFixtureEndpoint("https://login.microsoftonline.com/wrong-tenant/oauth2/v2.0/token", "azure-dns", credential), false);
  assert.equal(isOAuthFixtureEndpoint("https://evil.test/fixture-tenant/oauth2/v2.0/token", "azure-dns", credential), false);
});
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
