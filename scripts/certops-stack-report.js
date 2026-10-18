"use strict";
/**
 * Checks JSONL execution events against the exact committed protocol or native journey inventory.
 * Invoked by workflow report verification and the release aggregator; skipped, duplicate and
 * foreign-scope events fail. A protocol-only fixture cannot prove optional native certificate work.
 */
const fs = require("node:fs");
const manifest = {requiredTests:[],scope:""};
function verify(text, required = manifest.requiredTests, sourceFile = "certops-agent-e2e.test.js", scope = manifest.scope, expectedSha = process.env.GITHUB_SHA) {
  const events = text.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  if (!required.length || new Set(required).size !== required.length) throw new Error("Invalid mandatory test inventory");
  for (const name of required) {
    const matches = events.filter((event) => event.name === name);
    if (matches.length !== 1 || matches[0].type !== "test:pass" || matches[0].skip || matches[0].todo) throw new Error(`Required protocol test did not execute successfully: ${name}`);
  }
  if (events.some((event) => event.type !== "test:pass" || event.skip || event.todo)) throw new Error("Protocol suite contains failed, skipped or todo tests");
  if (events.some((event) => require("node:path").basename(event.file || "") !== sourceFile || event.scope !== scope || (expectedSha && event.candidateSha !== expectedSha))) throw new Error("Report source or candidate identity mismatch");
  return { scope, executed: required.length };
}
if (require.main === module) {
  try { console.log(JSON.stringify(verify(fs.readFileSync(process.argv[2], "utf8")))); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { verify };
