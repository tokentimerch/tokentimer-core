"use strict";
// Completeness of capability-enabled source-tree functional tests only. This
// aggregate cannot qualify a shipped native distribution capability.
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const ROOT = path.resolve(__dirname, ".."),
  SCOPE = "distribution-functional-support",
  MODES = ["ordinary", "san", "wildcard"],
  POSTGRES = ["postgres", "pr329-review", "transfer"];
const digest = (bytes) =>
  crypto.createHash("sha256").update(bytes).digest("hex");
function sourceFiles(kind, root = ROOT) {
  assert.ok(["postgres", "vault"].includes(kind));
  const shared = [
    "scripts/certops-distribution-functional-summary.js",
    ".github/workflows/certops-distribution-qualification.yml",
  ];
  const material = fs
    .readdirSync(path.join(root, "packages/agent/src/material-store"))
    .filter((name) => name.endsWith(".js"))
    .map((name) => "packages/agent/src/material-store/" + name);
  if (kind === "vault")
    return [
      ...new Set([
        ...shared,
        "scripts/certops-distribution-vault.js",
        "tests/wildcard-vault/Dockerfile.fixture",
        ...material,
      ]),
    ].sort();
  const services = fs
    .readdirSync(path.join(root, "apps/api/services/certops"))
    .filter(
      (name) => /^(distribution|material)/.test(name) && name.endsWith(".js"),
    )
    .map((name) => "apps/api/services/certops/" + name);
  return [
    ...new Set([
      ...shared,
      "scripts/certops-distribution-postgres.js",
      "tests/wildcard-vault/qualification-database.cjs",
      ...POSTGRES.map((name) => "tests/wildcard-vault/" + name + ".test.cjs"),
      ...services,
      ...material,
    ]),
  ].sort();
}
function sourceInventory(kind, root = ROOT) {
  return sourceFiles(kind, root).map((file) => ({
    file,
    sha256: digest(fs.readFileSync(path.join(root, file))),
  }));
}
function read(file) {
  const stat = fs.lstatSync(file);
  assert.ok(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.size > 0 &&
      stat.size <= 32 * 1024 * 1024,
    "Bounded public evidence file required",
  );
  return fs.readFileSync(file, "utf8");
}
function walk(directory) {
  const result = [];
  function visit(current, depth) {
    assert.ok(depth <= 8);
    for (const row of fs.readdirSync(current, { withFileTypes: true })) {
      assert.equal(row.isSymbolicLink(), false);
      const file = path.join(current, row.name);
      if (row.isDirectory()) visit(file, depth + 1);
      else if (row.isFile()) result.push(file);
      assert.ok(result.length <= 4096);
    }
  }
  visit(directory, 0);
  return result;
}
function verifySupportSummary(summary, kind, candidateSha, root = ROOT) {
  assert.equal(summary.schemaVersion, 1);
  assert.equal(summary.scope, SCOPE);
  assert.equal(summary.kind, kind);
  assert.equal(summary.candidateSha, candidateSha);
  assert.equal(summary.status, "passed");
  assert.equal(summary.cleanup, "passed");
  assert.equal(summary.evidenceLevel, "integration");
  assert.equal(summary.nativeAgentQualified, false);
  assert.equal(summary.qualificationStatus, "not-qualified");
  assert.ok(
    Number.isFinite(Date.parse(summary.startedAt)) &&
      Number.isFinite(Date.parse(summary.finishedAt)) &&
      Date.parse(summary.finishedAt) >= Date.parse(summary.startedAt),
  );
  assert.deepEqual(summary.fixtureSources, sourceInventory(kind, root));
  const names =
    kind === "postgres"
      ? POSTGRES.map((name) => ({
          suite: "distribution-postgres-" + name,
          status: "passed",
          report: name + ".jsonl",
        }))
      : [
          {
            suite: "distribution-vault-adapter",
            status: "passed",
            report: "adapter.jsonl",
          },
        ];
  assert.deepEqual(summary.tests, names);
  return names;
}
function verifyEvents(file, slot, candidateSha, root = ROOT) {
  const text = read(file);
  require("./certops-stack-report").verify(
    text,
    slot.requiredTests,
    path.basename(slot.source),
    slot.suite,
    candidateSha,
  );
  const rows = text
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const expected = digest(fs.readFileSync(path.join(root, slot.source)));
  for (const row of rows) {
    assert.equal(row.artifactQualification, "workflow-checkout-source");
    assert.equal(row.fixtureSource?.file, slot.source);
    assert.equal(row.fixtureSource?.sha256, expected);
  }
  return slot.requiredTests.length;
}
function verifyPrivacy(report, file, mode, candidateSha) {
  const bytes = read(file),
    value = JSON.parse(bytes);
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "candidateSha",
      "certificateMode",
      "project",
      "status",
      "coreDatabaseAndLogsScanned",
      "customerAgentLogsScanned",
      "privateNeedlesExported",
      "dnsCredentialQualification",
      "privateKeys",
      "credentials",
      "historicalVaultCredentialsChecked",
      "historicalVaultVersionsChecked",
    ].sort(),
  );
  assert.equal(report.privacyEvidence?.file, "privacy.json");
  assert.equal(report.privacyEvidence?.sha256, digest(bytes));
  assert.equal(value.candidateSha, candidateSha);
  assert.equal(value.certificateMode, mode);
  assert.equal(value.project, report.supportingRunId);
  assert.match(value.project || "", /^tt-wildcard-ux-ci-[a-z0-9-]+$/);
  assert.equal(value.status, "passed");
  for (const flag of ["coreDatabaseAndLogsScanned", "customerAgentLogsScanned"])
    assert.equal(value[flag], true);
  assert.equal(value.privateNeedlesExported, false);
  assert.equal(value.dnsCredentialQualification, false);
  for (const [name, min] of [
    ["privateKeys", 3],
    ["credentials", 3],
    ["historicalVaultCredentialsChecked", 4],
    ["historicalVaultVersionsChecked", 2],
  ])
    assert.ok(Number.isSafeInteger(value[name]) && value[name] >= min);
}
function verify(directory, candidateSha, root = ROOT) {
  assert.match(candidateSha || "", /^[a-f0-9]{40}$/);
  const files = walk(directory),
    matrix = JSON.parse(
      fs.readFileSync(
        path.join(root, "docs/certops/qualification-suites.json"),
        "utf8",
      ),
    ),
    cohorts = [];
  for (const kind of ["postgres", "vault"]) {
    const matches = files
      .filter((file) => path.basename(file) === "summary.json")
      .map((file) => ({ file, value: JSON.parse(read(file)) }))
      .filter((row) => row.value.kind === kind);
    assert.equal(
      matches.length,
      1,
      `Exactly one ${kind} supporting summary required`,
    );
    const summary = matches[0];
    for (const test of verifySupportSummary(
      summary.value,
      kind,
      candidateSha,
      root,
    )) {
      const slot = matrix.slots.find((row) => row.id === test.suite);
      assert.ok(slot);
      const count = verifyEvents(
        path.join(path.dirname(summary.file), test.report),
        slot,
        candidateSha,
        root,
      );
      cohorts.push({ id: test.suite, status: "passed", executed: count });
    }
  }
  const labFiles = files.filter(
      (file) => path.basename(file) === "qualification.json",
    ),
    labs = labFiles.map((file) => ({ file, value: JSON.parse(read(file)) }));
  assert.equal(labs.length, 3, "All three certificate modes must execute");
  for (const mode of MODES) {
    const rows = labs.filter(
      (row) => row.value.qualificationEnvironment?.certificateMode === mode,
    );
    assert.equal(rows.length, 1, `Exactly one ${mode} lab result required`);
    const { file, value } = rows[0];
    require("./certops-distribution-report").verify(value, candidateSha);
    verifyPrivacy(
      value,
      path.join(path.dirname(file), "privacy.json"),
      mode,
      candidateSha,
    );
    cohorts.push({
      id: "distribution-agent-" + mode,
      status: "passed",
      executed: value.requiredScenarios.length,
    });
  }
  return {
    schemaVersion: 1,
    scope: SCOPE,
    status: "passed",
    candidateSha,
    nativeAgentQualified: false,
    qualificationStatus: "not-qualified",
    experimental: true,
    allFeaturesQualified: false,
    cohorts,
    fixtureSource: {
      file: "scripts/certops-distribution-functional-summary.js",
      sha256: digest(fs.readFileSync(__filename)),
    },
  };
}
module.exports = {
  SCOPE,
  MODES,
  POSTGRES,
  sourceFiles,
  sourceInventory,
  verifySupportSummary,
  verifyEvents,
  verifyPrivacy,
  verify,
};
function runCli(args, env = process.env) {
  const output =
    args[1] || "qualification-results/distribution-functional-summary.json";
  let report;
  try {
    assert.equal(env.DISTRIBUTION_POSTGRES_RESULT, "success");
    assert.equal(env.DISTRIBUTION_AGENT_LAB_RESULT, "success");
    report = verify(args[0], env.GITHUB_SHA);
  } catch {
    report = {
      schemaVersion: 1,
      scope: SCOPE,
      status: "failed",
      candidateSha: /^[a-f0-9]{40}$/.test(env.GITHUB_SHA || "")
        ? env.GITHUB_SHA
        : null,
      nativeAgentQualified: false,
      qualificationStatus: "not-qualified",
      experimental: true,
      allFeaturesQualified: false,
      reason:
        "Mandatory current-candidate cohorts or owned cleanup did not complete",
    };
  }
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
  return report;
}
module.exports.runCli = runCli;
if (require.main === module) {
  try {
    const report = runCli(process.argv.slice(2));
    console.log(
      JSON.stringify({
        status: report.status,
        scope: report.scope,
        nativeAgentQualified: false,
        cohorts: report.cohorts?.length || 0,
      }),
    );
    if (report.status !== "passed") process.exitCode = 1;
  } catch {
    console.error("Unable to write bounded distribution functional verdict");
    process.exitCode = 1;
  }
}
