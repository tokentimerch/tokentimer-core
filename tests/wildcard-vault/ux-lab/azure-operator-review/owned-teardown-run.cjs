"use strict";
// A destructive operation: explicit invocation only, after owner review.
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const { cleanup } = require("./owned-teardown.cjs"), { createDockerTransport } = require("./docker-transport.cjs");
async function main(argv = process.argv.slice(2)) {
  assert.equal(argv.length, 2, "usage: node owned-teardown-run.cjs --execute <owned-run.json>");
  assert.equal(argv[0], "--execute", "explicit execution required");
  const receipt = JSON.parse(fs.readFileSync(path.resolve(argv[1]), "utf8"));
  assert.match(receipt.project || "", /^tt-wildcard-ux-qual-[a-z0-9-]+$/);
  assert.match(receipt.producerRunId || "", /^[1-9][0-9]{0,15}$/);
  assert.match(receipt.candidateSha || "", /^[a-f0-9]{40}$/);
  assert.match(receipt.archiveSha256 || "", /^[a-f0-9]{64}$/);
  return { ...await cleanup({ project: receipt.project, transport: createDockerTransport({project:receipt.project}) }),
    candidateSha: receipt.candidateSha, archiveSha256: receipt.archiveSha256,
    producerRunId: receipt.producerRunId, provenance: "caller-declared-not-authenticated" };
}
if (require.main === module) main().then(result => process.stdout.write(JSON.stringify(result) + "\n"))
  .catch(() => { process.stderr.write("Owned teardown refused or incomplete\n"); process.exitCode = 1; });
module.exports = { main };
