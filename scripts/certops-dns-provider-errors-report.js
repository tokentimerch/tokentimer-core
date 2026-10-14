"use strict";
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), assert = require("node:assert/strict");
const inventory = require("../docs/certops/dns-provider-errors.json");
const { listSupportedDnsProviders } = require("../packages/agent/src/dns");
const { verifyReport } = require("./certops-qualification-report");
const root = path.resolve(__dirname, "..");
function contractNames(source) {
  const names = [...source.matchAll(/\btest\(\s*"((?:[^"\\]|\\.)*)"/g)].map(match => JSON.parse(`"${match[1]}"`));
  assert.equal(names.length, [...source.matchAll(/\btest\s*\(/g)].length, "Unsupported dynamic or alternate test declaration requires inventory review");
  assert.equal(new Set(names).size, names.length, "Contract names must be unique within a source file");
  return names;
}
function validateInventory(value = inventory) {
  assert.equal(value.schemaVersion, 1);
  assert.deepEqual(value.providers.map(item => item.provider).sort(), listSupportedDnsProviders().filter(item => item !== "pebble-challtestsrv").sort());
  assert.equal(new Set(value.providers.map(item => item.provider)).size, value.providers.length);
  assert.ok(value.requiredScenarios.length > value.providers.length); assert.equal(new Set(value.requiredScenarios).size, value.requiredScenarios.length);
  for (const provider of [...value.providers, ...value.sharedContracts]) {
    assert.equal(provider.file, provider.provider ? `packages/agent/src/dns/providers/${provider.provider}.test.js` : "packages/agent/src/dns/dns.test.js");
    assert.ok(provider.requiredTests.length > 0);
    const source = fs.readFileSync(path.join(root, provider.file), "utf8");
    const names = contractNames(source);
    assert.deepEqual(provider.requiredTests, names, "New or changed adapter contracts require inventory review");
  }
  return { providers: value.providers.length, adapterCases: [...value.providers, ...value.sharedContracts].reduce((count, provider) => count + provider.requiredTests.length, 0), scenarios: value.requiredScenarios.length };
}
function verifyDnsErrors(report) {
  try {
  validateInventory(); assert.equal(report.suite, "dns-provider-errors"); assert.deepEqual(verifyReport(report), []);
  const definitions = [...inventory.providers, ...inventory.sharedContracts];
  const digest = file => crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex");
  assert.equal(report.fixtureSource?.file, "scripts/certops-dns-provider-errors.js"); assert.equal(report.fixtureSource.sha256, digest(report.fixtureSource.file));
  assert.ok(Array.isArray(report.fixtureSources)); assert.equal(report.fixtureSources.length, definitions.length);
  for (const definition of definitions) { const rows = report.fixtureSources.filter(row => row.file === definition.file); assert.equal(rows.length, 1); assert.equal(rows[0].sha256, digest(definition.file)); }
  const expected = [...inventory.providers, ...inventory.sharedContracts].flatMap(provider => provider.requiredTests.map(name => `${provider.file}\0${name}`));
  assert.ok(Array.isArray(report.dnsAdapterCases)); assert.equal(report.dnsAdapterCases.length, expected.length);
  const actual = [];
  for (const row of report.dnsAdapterCases) { assert.equal(row.status, "passed"); actual.push(`${row.file}\0${row.name}`); }
  assert.equal(new Set(actual).size, actual.length); assert.deepEqual(actual.sort(), expected.sort());
  return true;
  } catch { throw new Error("Mandatory DNS adapter source and execution evidence incomplete"); }
}
if (require.main === module) {
  try {
    if (process.argv[2] === "--check-inventory") console.log(JSON.stringify(validateInventory()));
    else { assert.equal(process.argv.length, 3); verifyDnsErrors(JSON.parse(fs.readFileSync(process.argv[2], "utf8"))); console.log("DNS adapter mandatory errors and contract execution verified"); }
  } catch { console.error("DNS provider error inventory or execution evidence incomplete"); process.exitCode = 1; }
}
module.exports = { validateInventory, verifyDnsErrors, contractNames };
