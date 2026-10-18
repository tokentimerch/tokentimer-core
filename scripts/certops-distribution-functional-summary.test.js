"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  crypto = require("node:crypto");
const summary = require("./certops-distribution-functional-summary"),
  {
    createGate,
    PHASES,
  } = require("../tests/wildcard-vault/ux-lab/qualification.cjs"),
  matrix = require("../docs/certops/qualification-suites.json"),
  candidate = "a".repeat(40);
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex"),
  write = (file, value) => fs.writeFileSync(file, JSON.stringify(value));
function fixture(t) {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "distribution-functional-"),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const now = new Date().toISOString();
  for (const kind of ["postgres", "vault"]) {
    const dir = path.join(root, kind);
    fs.mkdirSync(dir);
    const tests =
      kind === "postgres"
        ? summary.POSTGRES.map((n) => ({
            suite: "distribution-postgres-" + n,
            status: "passed",
            report: n + ".jsonl",
          }))
        : [
            {
              suite: "distribution-vault-adapter",
              status: "passed",
              report: "adapter.jsonl",
            },
          ];
    write(path.join(dir, "summary.json"), {
      schemaVersion: 1,
      scope: summary.SCOPE,
      kind,
      candidateSha: candidate,
      status: "passed",
      cleanup: "passed",
      evidenceLevel: "integration",
      nativeAgentQualified: false,
      qualificationStatus: "not-qualified",
      startedAt: now,
      finishedAt: now,
      fixtureSources: summary.sourceInventory(kind),
      tests,
    });
    for (const row of tests) {
      const slot = matrix.slots.find((s) => s.id === row.suite);
      fs.writeFileSync(
        path.join(dir, row.report),
        slot.requiredTests
          .map((name) =>
            JSON.stringify({
              name,
              type: "test:pass",
              file: slot.source,
              scope: slot.suite,
              candidateSha: candidate,
              artifactQualification: "workflow-checkout-source",
              fixtureSource: {
                file: slot.source,
                sha256: hash(
                  fs.readFileSync(path.join(__dirname, "..", slot.source)),
                ),
              },
            }),
          )
          .join("\n"),
      );
    }
  }
  for (const mode of summary.MODES) {
    const dir = path.join(root, mode);
    fs.mkdirSync(dir);
    const report = createGate({
      root: dir,
      candidateSha: candidate,
      mode,
    }).report;
    Object.assign(report, {
      startedAt: now,
      status: "passed",
      finishedAt: now,
      missingCapabilities: [],
      missingScenarios: [],
      requiredScenarios: PHASES.map((p) => "distribution-" + p),
      supportingRunId: "tt-wildcard-ux-ci-123-1-" + mode,
    });
    report.capabilities = Object.fromEntries(
      report.requiredCapabilities.map((name) => [name, { available: true }]),
    );
    report.scenarios = report.requiredScenarios.map((id) => ({
      id,
      status: "passed",
      evidenceLevel: "e2e",
      startedAt: now,
      finishedAt: now,
    }));
    write(path.join(dir, "privacy.json"), {
      candidateSha: candidate,
      certificateMode: mode,
      project: report.supportingRunId,
      status: "passed",
      coreDatabaseAndLogsScanned: true,
      customerAgentLogsScanned: true,
      privateNeedlesExported: false,
      dnsCredentialQualification: false,
      privateKeys: 3,
      credentials: 3,
      historicalVaultCredentialsChecked: 4,
      historicalVaultVersionsChecked: 2,
    });
    report.privacyEvidence = {
      file: "privacy.json",
      sha256: hash(fs.readFileSync(path.join(dir, "privacy.json"))),
    };
    write(path.join(dir, "qualification.json"), report);
  }
  return root;
}
function mutate(root, file, fn) {
  const p = path.join(root, file),
    v = JSON.parse(fs.readFileSync(p));
  fn(v);
  write(p, v);
}
test("all seven current candidate cohorts retain supporting classification", (t) => {
  const root = fixture(t),
    result = summary.verify(root, candidate);
  assert.equal(result.cohorts.length, 7);
  assert.equal(result.nativeAgentQualified, false);
  assert.equal(result.qualificationStatus, "not-qualified");
  assert.equal(result.allFeaturesQualified, false);
});
test("missing cohorts, failed cleanup, stale source and skipped real Vault tests fail closed", (t) => {
  for (const change of [
    (r) => fs.unlinkSync(path.join(r, "vault/summary.json")),
    (r) => mutate(r, "postgres/summary.json", (s) => (s.cleanup = "failed")),
    (r) =>
      mutate(
        r,
        "vault/summary.json",
        (s) => (s.fixtureSources[0].sha256 = "0".repeat(64)),
      ),
    (r) =>
      mutate(r, "vault/summary.json", (s) => (s.nativeAgentQualified = true)),
    (r) => {
      const p = path.join(r, "vault/adapter.jsonl"),
        rows = fs.readFileSync(p, "utf8").split("\n").map(JSON.parse);
      rows[0].skip = true;
      fs.writeFileSync(p, rows.map(JSON.stringify).join("\n"));
    },
    (r) =>
      fs.copyFileSync(
        path.join(r, "san/qualification.json"),
        path.join(r, "ordinary/qualification.json"),
      ),
  ]) {
    const root = fixture(t);
    change(root);
    assert.throws(() => summary.verify(root, candidate));
  }
});
test("privacy evidence cannot be substituted, broadened or taken from another candidate", (t) => {
  for (const change of [
    (s) => (s.candidateSha = "b".repeat(40)),
    (s) => (s.certificateMode = "san"),
    (s) => (s.privateNeedlesExported = true),
    (s) => (s.credentials = 0),
    (s) => (s.secret = "unexpected"),
  ]) {
    const root = fixture(t);
    mutate(root, "ordinary/privacy.json", change);
    mutate(
      root,
      "ordinary/qualification.json",
      (s) =>
        (s.privacyEvidence.sha256 = hash(
          fs.readFileSync(path.join(root, "ordinary/privacy.json")),
        )),
    );
    assert.throws(() => summary.verify(root, candidate));
  }
  const root = fixture(t);
  mutate(root, "ordinary/privacy.json", (s) => (s.credentials = 4));
  assert.throws(() => summary.verify(root, candidate));
});
test("workflow keeps trusted main execution and requires aggregate even after cohort failure", () => {
  const text = fs.readFileSync(
    path.join(
      __dirname,
      "../.github/workflows/certops-distribution-qualification.yml",
    ),
    "utf8",
  );
  assert.match(text, /needs: \[postgres, agent-lab\]/);
  assert.match(text, /always\(\) && github.ref == 'refs\/heads\/main'/);
  assert.match(
    text,
    /Real isolated Vault adapter and ACL regressions\r?\n\s+if: \$\{\{ !cancelled\(\) \}\}/,
  );
  assert.doesNotMatch(text, /pull_request|azure|secrets\./i);
  for (const broad of [
    "apps/api/**",
    "apps/worker/**",
    "apps/dashboard/**",
    "packages/**",
    "docs/certops/**",
  ])
    assert.ok(!text.includes("'" + broad + "'"));
});

test("failed, cancelled or missing upstream cleanup yields a bounded failed verdict", (t) => {
  const root = fixture(t),
    output = path.join(root, "verdict.json"),
    env = {
      GITHUB_SHA: candidate,
      DISTRIBUTION_POSTGRES_RESULT: "success",
      DISTRIBUTION_AGENT_LAB_RESULT: "success",
    };
  assert.equal(summary.runCli([root, output], env).status, "passed");
  for (const key of [
    "DISTRIBUTION_POSTGRES_RESULT",
    "DISTRIBUTION_AGENT_LAB_RESULT",
  ])
    for (const value of ["failure", "cancelled", "skipped", undefined]) {
      const result = summary.runCli([root, output], { ...env, [key]: value });
      assert.equal(result.status, "failed");
      assert.equal(result.nativeAgentQualified, false);
      assert.equal(JSON.parse(fs.readFileSync(output)).status, "failed");
    }
  assert.equal(
    summary.runCli([path.join(root, "missing"), output], env).status,
    "failed",
  );
});
