"use strict";
/** Actual producer inventory/release verifier, synthetic observations only. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { createRequire } = require("node:module"),
  { verifyMatrix } = require("./certops-release-qualification");
const root = path.resolve(__dirname, ".."),
  matrix = require("../docs/certops/qualification-suites.json"),
  contract = require("../docs/certops/qualification-suites.json"),
  slot = matrix.slots.find((s) => s.suite === "native-signing-rotation"),
  candidateSha = "a".repeat(40);
const digest = (file) => ({
  file,
  sha256: crypto
    .createHash("sha256")
    .update(fs.readFileSync(path.join(root, file)))
    .digest("hex"),
});
function artifact() {
  const now = new Date().toISOString(),
    caps = contract.requiredCapabilities[slot.suite];
  const report = {
    schemaVersion: 1,
    suite: slot.suite,
    candidateSha,
    startedAt: now,
    finishedAt: now,
    status: "passed",
    strict: true,
    evidenceLevel: contract.suiteEvidenceLevels[slot.suite],
    requiredCapabilities: caps,
    capabilities: Object.fromEntries(
      caps.map((name) => [name, { available: true }]),
    ),
    requiredScenarios: contract.suites[slot.suite],
    missingCapabilities: [],
    missingScenarios: [],
    scenarios: contract.suites[slot.suite].map((id) => ({
      id,
      status: "passed",
      evidenceLevel: contract.scenarioEvidenceLevels[slot.suite][id],
      startedAt: now,
      finishedAt: now,
    })),
    qualificationEnvironment: { ...slot.environment, measurement: "native" },
    artifactQualification: "workflow-checkout-source",
    fixtureSource: digest(slot.source),
    fixtureSources: slot.requiredSources.map(digest),
  };
  return {
    kind: "host",
    suite: slot.suite,
    environment: report.qualificationEnvironment,
    report,
  };
}
const errors = (value) =>
  verifyMatrix([value], {
    candidateSha,
    specification: { schemaVersion: 1, slots: [slot] },
  });
test("actual native rotation producer binds exactly its reviewed retained ownership sources", () => {
  const filename = path.join(root, slot.source),
    source = fs.readFileSync(filename, "utf8"),
    start = source.indexOf("const requiredSources ="),
    end = source.indexOf("gate.report.fixtureSources", start);
  assert.ok(start >= 0 && end > start);
  const sources = new Function(
    "require",
    source.slice(start, end) + ";return requiredSources;",
  )(createRequire(filename));
  assert.deepEqual(sources, slot.requiredSources);
});
test("native rotation release refuses omitted or stale retained ownership implementation", () => {
  assert.deepEqual(errors(artifact()), []);
  for (const file of slot.requiredSources) {
    const changed = artifact();
    changed.report.fixtureSources.find((row) => row.file === file).sha256 =
      "f".repeat(64);
    assert.ok(errors(changed).length, file);
    const omitted = artifact();
    omitted.report.fixtureSources = omitted.report.fixtureSources.filter(
      (row) => row.file !== file,
    );
    assert.ok(errors(omitted).length, file);
  }
});
