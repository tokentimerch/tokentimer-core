"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),{validateObservedEvidence,CONTRACT_SOURCE_COMMIT}=require("./final-evidence-bridge.cjs");
test("trusted checkout contract rejects incomplete evidence and caller-supplied validators",()=>{
  assert.equal(CONTRACT_SOURCE_COMMIT,"5ac8b05578a0d48c917dc1cc4ffeb1c0eed5e19a");
  assert.throws(()=>validateObservedEvidence({profile:"azure-operator-http-real-ca",report:{},context:{},contract:{PROFILES:{},verify:()=>true}}));
  assert.throws(()=>validateObservedEvidence({profile:"unknown",report:{},context:{}}),/profile/);
});

const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const {runOperatorQualification} = require("./final-evidence-bridge.cjs");
const {CAPABILITIES} = require("../../../../scripts/certops-azure-keyvault-package.cjs");
const {report: supportReport} = require("../../../../scripts/test-support/final-package-evidence.cjs");

function qualification(t) {
  const profile = "openbao-operator-http-real-ca", sourceSha = "a".repeat(40), runId = "123";
  const files = { "bin/tokentimer-agent.js": "b".repeat(64) };
  const packageIdentity = { artifactId: "567", runId: "456", candidateSha: "c".repeat(40),
    packageSha256: "d".repeat(64), packageVersion: "0.20.0", capabilities: CAPABILITIES };
  const fixture = supportReport(profile, sourceSha, runId, packageIdentity, files);
  const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-operator-evidence-"));
  t.after(() => fs.rmSync(outputDirectory, { recursive: true, force: true }));
  const file = path.join(outputDirectory, "openbao-operator-final-package.json");
  const order = [];
  const options = { profile, context: { sourceSha, runId, packageIdentity, files, requireNative: true }, outputDirectory,
    async observe() {
      assert.equal(fs.existsSync(file), false);
      order.push("observe");
      return { packageArtifact: packageIdentity, scenarios: fixture.scenarios.slice(0, -1), facts: fixture.facts, nativeService: fixture.nativeService };
    },
    async teardown() {
      assert.equal(fs.existsSync(file), false);
      order.push("teardown");
      return { sourceSha, runId, packageArtifact: packageIdentity, cleanup: fixture.cleanup };
    } };
  return { options, file, order, fixture };
}
test("publishes one closed profile only after successful same-run teardown", async t => {
  const { options, file, order, fixture } = qualification(t);
  assert.deepEqual(await runOperatorQualification(options), fixture);
  assert.deepEqual(order, ["observe", "teardown"]);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), fixture);
  await assert.rejects(runOperatorQualification(options), /reuse/);
});
test("runs teardown on scenario failure and never emits on mismatched or failed cleanup", async t => {
  const { options, file, order } = qualification(t);
  await assert.rejects(runOperatorQualification({ ...options, observe: async () => { throw new Error("scenario failed"); } }), /scenario failed/);
  assert.deepEqual(order, ["teardown"]);
  await assert.rejects(runOperatorQualification({ ...options, teardown: async () => ({ ...await options.teardown(), runId: "56" }) }));
  await assert.rejects(runOperatorQualification({ ...options, teardown: async () => {
    const closed = await options.teardown();
    return { ...closed, cleanup: { ...closed.cleanup, credentials: "pending" } };
  } }));
  assert.equal(fs.existsSync(file), false);
});
