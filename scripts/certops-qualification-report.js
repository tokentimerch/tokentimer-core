"use strict";
/**
 * Verifies named HostGate reports against committed suite requirements.
 * Used by qualification workflows and CLI callers after execution; rejects absent, skipped or
 * failed cases. Verification inspects evidence and does not itself execute certificate operations.
 */
const fs = require("node:fs");

function verifyReport(report, expectedScenarios, { expectedSha = process.env.GITHUB_SHA } = {}) {
  if (!report || typeof report !== "object" || Array.isArray(report)) return ["Invalid report object"];
  // Direct CLI verification must fail too when a newly registered suite omits
  // required classifications; a separate CI metadata check is not sufficient.
  const metadata = require("../docs/certops/qualification-suites.json");
  if (require("./certops-qualification-suites").validateSuites(metadata).length) return ["Invalid committed qualification suite contract"];
  expectedScenarios ??= require("../docs/certops/qualification-suites.json").suites[report.suite];
  const errors = [];
  if (report.suite === "distribution-agent-lab") {
    try { require("./certops-distribution-report").verifyScope(report); }
    catch { errors.push("Distribution supporting evidence scope or source identity invalid"); }
  }
  const knownScenario = id => Array.isArray(expectedScenarios) && expectedScenarios.includes(id) ? id : "[unrecognized]";
  const knownCapabilities = require("../docs/certops/qualification-suites.json").requiredCapabilities?.[report.suite] || [];
  const knownCapability = name => knownCapabilities.includes(name) ? name : "[unrecognized]";
  if ([report.scenarios, report.requiredScenarios, report.requiredCapabilities].some(value => Array.isArray(value) && value.length > 4096)) return ["Report execution metadata exceeds bounds"];
  if (report.cleanup !== undefined && report.cleanup?.status !== "passed") errors.push("Host cleanup did not pass");
  const validTime = (value) => typeof value === "string" && Number.isFinite(Date.parse(value));
  if (!validTime(report.startedAt) || !validTime(report.finishedAt) || Date.parse(report.finishedAt) < Date.parse(report.startedAt)) errors.push("Invalid report execution interval");
  if (!Array.isArray(report.requiredCapabilities) || !Array.isArray(report.requiredScenarios) || !Array.isArray(report.missingCapabilities) || !Array.isArray(report.missingScenarios)) errors.push("Missing or malformed required execution metadata");
  if (typeof report.candidateSha !== "string" || !/^[a-f0-9]{40}$/i.test(report.candidateSha)) errors.push("Missing candidate commit identity");
  if (expectedSha && report.candidateSha !== expectedSha) errors.push("Report candidate differs from requested commit");
  const expectedSuiteLevel = require("../docs/certops/qualification-suites.json").suiteEvidenceLevels?.[report.suite];
  if (expectedSuiteLevel ? report.evidenceLevel !== expectedSuiteLevel : !["real-host", "e2e"].includes(report.evidenceLevel)) errors.push("Unsupported qualification evidence level");
  if (!Array.isArray(expectedScenarios) || !expectedScenarios.length) errors.push("Suite has no committed mandatory scenario specification");
  if (report.schemaVersion !== 1 || !report.suite || report.status !== "passed" || report.strict !== true || !report.finishedAt) errors.push("Report is not a completed strict qualification");
  if (!Array.isArray(report.scenarios) || !report.scenarios.length) errors.push("No scenarios executed");
  const ids = new Set();
  for (const scenario of Array.isArray(report.scenarios) ? report.scenarios : []) {
    if (!scenario || typeof scenario !== "object") { errors.push("Invalid scenario object"); continue; }
    if (!scenario.id || ids.has(scenario.id)) errors.push("Missing or duplicate scenario ID");
    ids.add(scenario.id);
    if (!Array.isArray(expectedScenarios) || !expectedScenarios.includes(scenario.id)) errors.push("Unrecognized scenario requires committed specification");
    const expectedLevel = require("../docs/certops/qualification-suites.json").scenarioEvidenceLevels?.[report.suite]?.[scenario.id];
    if (expectedLevel && scenario.evidenceLevel !== expectedLevel) errors.push(`Scenario evidence classification differs from specification: ${knownScenario(scenario.id)}`);
    if (!["unit", "integration", "real-host", "e2e"].includes(scenario.evidenceLevel)) errors.push(`Missing scenario evidence classification: ${knownScenario(scenario.id)}`);
    if (!validTime(scenario.startedAt) || !validTime(scenario.finishedAt) || Date.parse(scenario.finishedAt) < Date.parse(scenario.startedAt)) errors.push(`Invalid scenario execution interval: ${knownScenario(scenario.id)}`);
    if (scenario.status !== "passed" || !scenario.startedAt || !scenario.finishedAt) errors.push(`Scenario did not complete: ${knownScenario(scenario.id)}`);
  }
  if (report.missingCapabilities?.length || report.missingScenarios?.length) errors.push("Required execution evidence missing");
  const expectedCapabilities = require("../docs/certops/qualification-suites.json").requiredCapabilities?.[report.suite] || [];
  for (const name of [...(Array.isArray(report.requiredCapabilities) ? report.requiredCapabilities : []), ...expectedCapabilities]) {
    if (report.capabilities?.[name]?.available !== true) errors.push(`Missing capability evidence: ${knownCapability(name)}`);
  }
  for (const id of [...(Array.isArray(report.requiredScenarios) ? report.requiredScenarios : []), ...(Array.isArray(expectedScenarios) ? expectedScenarios : [])]) {
    if (!Array.isArray(report.scenarios) || !report.scenarios.some((scenario) => scenario?.id === id && scenario.status === "passed")) errors.push(`Missing required scenario: ${knownScenario(id)}`);
  }
  return errors;
}
if (require.main === module) {
  const files = process.argv.slice(2);
  if (!files.length) { console.error("Usage: node scripts/certops-qualification-report.js <report.json> [...]"); process.exitCode = 1; }
  for (const file of files) {
    try {
      const errors = verifyReport(JSON.parse(fs.readFileSync(file, "utf8")));
      if (errors.length) { console.error(`${file}: ${errors.join("; ")}`); process.exitCode = 1; }
      else console.log(`${file}: qualification passed`);
    } catch (error) { console.error(`${file}: ${error.message}`); process.exitCode = 1; }
  }
}
module.exports = { verifyReport };
