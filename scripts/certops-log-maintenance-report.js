"use strict";
/** Strict bounded evidence for the separate actual-elapsed log maintenance lane.
 * This verifies observed facts, not a simulated clock or a day of retention.
 * Generic named cases, candidate identity and current helper source hashes also apply. */
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
function verifyFacts(facts) {
  assert.equal(facts.defaultGraceMs, 300000);
  assert.ok(Number.isFinite(facts.observedMonotonicMs) && facts.observedMonotonicMs >= 300000 && facts.observedMonotonicMs <= 420000);
  for (const field of ["actualDatabaseExpired", "originalJobSucceeded", "lateUploadRefused", "tombstoneRetained", "onlySelectedWorkerSweeps"]) assert.equal(facts[field], true);
  assert.equal(facts.timestampsRewritten, false); assert.equal(facts.abandonedStreams, 1);
  assert.equal(facts.purgedLines, 2); assert.equal(facts.repeatedPurgeDeleted, 0); assert.equal(facts.retentionDays, 0);
  assert.equal(facts.scope, "actual-default-five-minute-grace-and-supported-retention-zero"); return true;
}
function verify(report, root = path.resolve(__dirname, ".."), expectedSha = process.env.GITHUB_SHA) {
  assert.equal(report.suite, "agent-log-maintenance-worker");
  assert.deepEqual(require("./certops-qualification-report").verifyReport(report, undefined, { expectedSha }), []);
  const required = ["tests/e2e/certops-log-maintenance-e2e.test.js", "tests/e2e/helpers/certops-log-maintenance-worker.mjs", "apps/worker/src/certops-worker.js", "apps/api/services/certops/agentJobLogs.js"];
  for (const file of required) assert.ok([report.fixtureSource, ...(report.fixtureSources || [])].some(source => source?.file === file && source.sha256 === crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex")), "Current maintenance source binding missing");
  return verifyFacts(report.maintenance);
}
if (require.main === module) { try { verify(JSON.parse(fs.readFileSync(process.argv[2], "utf8"))); console.log("Actual log maintenance evidence verified"); } catch { console.error("Actual log maintenance qualification evidence invalid"); process.exitCode = 1; } }
module.exports = { verifyFacts, verify };
