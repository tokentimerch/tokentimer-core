"use strict";
/**
 * Verifies the report of one diagnostic AD CS qualification shard. A shard never satisfies the release gate
 * (that is certops-qualification-report.js on the "all" run); this check only proves the shard itself ran every
 * scenario it owns to completion, so a green shard job cannot hide an unexecuted journey.
 */
const fs = require("node:fs");
const { SHARD_NAMES, createShard } = require("../tests/e2e/helpers/certops-adcs-shards");

function verifyShardReport(report, expectedShard) {
  if (!report || typeof report !== "object" || Array.isArray(report)) return ["Invalid report object"];
  const errors = [];
  if (!SHARD_NAMES.includes(expectedShard) || expectedShard === "all") return ["Unknown diagnostic shard"];
  if (report.shard?.name !== expectedShard) errors.push("Report belongs to a different shard");
  if (report.experimental !== true || report.qualificationStatus !== "not-qualified") errors.push("Shard report must stay unqualified diagnostic evidence");
  if (report.status !== "passed" || report.failureBudgetExhausted !== undefined) errors.push("Shard did not pass");
  if (report.cleanup?.status !== "passed") errors.push("Host cleanup did not pass");
  if (!Array.isArray(report.scenarios) || !report.scenarios.length) errors.push("No scenarios executed");
  if (Array.isArray(report.missingScenarios) && report.missingScenarios.length) errors.push(`Unexecuted scenarios: ${report.missingScenarios.length}`);
  const owner = createShard(expectedShard);
  const passed = new Set();
  for (const scenario of Array.isArray(report.scenarios) ? report.scenarios : []) {
    if (scenario?.status === "passed") passed.add(scenario.id);
    else errors.push(`Scenario did not complete: ${String(scenario?.id).slice(0, 120)}`);
  }
  const required = Array.isArray(report.requiredScenarios) ? report.requiredScenarios : [];
  if (!required.length) errors.push("Shard reported no required scenarios");
  for (const id of required) {
    if (!owner.owns(id)) errors.push(`Scenario outside the shard: ${String(id).slice(0, 120)}`);
    if (!passed.has(id)) errors.push(`Missing required scenario: ${String(id).slice(0, 120)}`);
  }
  return errors;
}

if (require.main === module) {
  const [file, shard] = process.argv.slice(2);
  const errors = verifyShardReport(JSON.parse(fs.readFileSync(file, "utf8")), shard);
  if (errors.length) {
    for (const error of errors) console.error(error);
    process.exit(1);
  }
  console.log(`Diagnostic shard ${shard} completed every owned scenario`);
}
module.exports = { verifyShardReport };
