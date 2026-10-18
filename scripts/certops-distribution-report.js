"use strict";
// Lab evidence can qualify its functional scope, never a released native agent.
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const {
  SUITE,
  PHASES,
} = require("../tests/wildcard-vault/ux-lab/qualification.cjs");
function verifyScope(report, root = path.resolve(__dirname, "..")) {
  assert.equal(report.suite, SUITE);
  assert.equal(
    report.experimental,
    true,
    "Source-mounted capability-enabled artifact must remain experimental",
  );
  assert.equal(report.qualificationStatus, "not-qualified");
  assert.ok(["source-mounted-enrolled-agent-lab", "packaged-enrolled-agent-lab"].includes(report.qualificationScope));
  if (report.qualificationScope === "packaged-enrolled-agent-lab") {
    const proof = report.packageAcceptance;
    assert.equal(proof?.candidateSha, report.candidateSha);
    assert.match(proof.packageSha256, /^[a-f0-9]{64}$/);
    assert.equal(proof.buildMode, "qualification-only-not-release");
    for (const field of ["packageFilesUnmodified", "vaultTlsVerified", "separateRolesAndSinks", "rolePermissionsChecked", "roleIsolationChecked"]) assert.equal(proof[field], true);
    assert.equal(proof.authentication, "vault-agent-approle");
    assert.equal(proof.supervision, "documented-node-process");
    assert.equal(proof.agentAccountUid, 10001);
    assert.equal(proof.vaultAgentUid, 10001);
    assert.equal(proof.systemdQualified, false);
    assert.equal(proof.publishedReleaseQualified, false);
    assert.ok(Number.isInteger(proof.credentialRotationCount) && proof.credentialRotationCount > 0);
  }
  assert.equal(report.allFeaturesQualified, false);
  assert.equal(report.databaseInjection, false);
  assert.ok(
    ["ordinary", "san", "wildcard"].includes(
      report.qualificationEnvironment?.certificateMode,
    ),
  );
  const source = "tests/wildcard-vault/ux-lab/journey.cjs";
  assert.equal(report.fixtureSource?.file, source);
  assert.equal(
    report.fixtureSource.sha256,
    crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(root, source)))
      .digest("hex"),
  );
  const required =
    require("../docs/certops/qualification-suites.json").slots.find(
      (s) => s.suite === SUITE,
    ).requiredSources;
  for (const file of required) {
    const rows = report.fixtureSources?.filter((r) => r.file === file);
    assert.equal(rows?.length, 1);
    assert.equal(
      rows[0].sha256,
      crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.join(root, file)))
        .digest("hex"),
    );
  }
  assert.deepEqual(
    report.requiredScenarios,
    PHASES.map((p) => "distribution-" + p),
  );
  return true;
}
function verify(report, expectedSha) {
  assert.deepEqual(
    require("./certops-qualification-report").verifyReport(report, undefined, {
      expectedSha,
    }),
    [],
  );
  verifyScope(report);
  return {
    scope: report.qualificationScope,
    status: "passed",
    nativeQualification: "not-qualified",
  };
}
// The generic verifier calls verifyScope back while this CLI is executing.
// Publish exports first so a direct invocation has the same contract as import.
module.exports = { verify, verifyScope };
if (require.main === module) {
  try {
    console.log(
      JSON.stringify(
        verify(
          JSON.parse(fs.readFileSync(process.argv[2], "utf8")),
          process.env.GITHUB_SHA,
        ),
      ),
    );
  } catch {
    console.error(
      "Distribution evidence is incomplete, stale or incorrectly classified",
    );
    process.exitCode = 1;
  }
}
