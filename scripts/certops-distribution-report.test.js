"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { verify } = require("./certops-distribution-report");
const {
  createGate,
  PHASES,
} = require("../tests/wildcard-vault/ux-lab/qualification.cjs");
function fixture(t) {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-distribution-report-"),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const report = createGate({
    root,
    candidateSha: "a".repeat(40),
    mode: "san",
  }).report;
  const now = new Date().toISOString();
  Object.assign(report, {
    status: "passed",
    finishedAt: now,
    missingCapabilities: [],
    missingScenarios: [],
    requiredScenarios: PHASES.map((p) => "distribution-" + p),
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
  return report;
}
test("complete supporting report remains explicitly unqualified for native release", (t) => {
  const r = fixture(t);
  assert.deepEqual(verify(r, "a".repeat(40)), {
    scope: "source-mounted-enrolled-agent-lab",
    status: "passed",
    nativeQualification: "not-qualified",
  });
  const slot =
    require("../docs/certops/qualification-suites.json").slots.find(
      (s) => s.suite === r.suite,
    );
  r.qualificationEnvironment = {
    ...r.qualificationEnvironment,
    ...slot.environment,
  };
  const errors = require("./certops-release-qualification").verifyMatrix(
    [
      {
        kind: "host",
        suite: r.suite,
        environment: slot.environment,
        report: r,
      },
    ],
    {
      candidateSha: r.candidateSha,
      specification: { schemaVersion: 1, slots: [slot] },
    },
  );
  assert.ok(errors.some((e) => /Experimental evidence/.test(e)));
});
test("missing, skipped, duplicated or stale distribution evidence never succeeds", (t) => {
  const base = fixture(t);
  for (const mutate of [
    (r) => r.scenarios.pop(),
    (r) => (r.scenarios[0].status = "skipped"),
    (r) => r.scenarios.push(r.scenarios[0]),
    (r) => (r.fixtureSources[0].sha256 = "0".repeat(64)),
    (r) => (r.fixtureSource.sha256 = "0".repeat(64)),
    (r) => (r.candidateSha = "b".repeat(40)),
    (r) => (r.capabilities["fresh-owned-lab"].available = false),
  ]) {
    const r = structuredClone(base);
    mutate(r);
    assert.throws(() => verify(r, "a".repeat(40)));
  }
});
test("removing experimental scope or claiming native execution cannot promote a lab result", (t) => {
  const base = fixture(t);
  for (const mutate of [
    (r) => delete r.experimental,
    (r) => (r.experimental = false),
    (r) => (r.qualificationStatus = "qualified"),
    (r) => (r.allFeaturesQualified = true),
    (r) => (r.databaseInjection = true),
    (r) => (r.evidenceLevel = "real-host"),
    (r) => (r.qualificationEnvironment.certificateMode = "other"),
  ]) {
    const r = structuredClone(base);
    mutate(r);
    assert.throws(() => verify(r, "a".repeat(40)));
  }
});
test("direct report CLI accepts complete supporting scope without a circular import", (t) => {
  const report = fixture(t);
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-distribution-cli-"),
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, "report.json");
  fs.writeFileSync(file, JSON.stringify(report));
  const result = require("node:child_process").spawnSync(
    process.execPath,
    [path.join(__dirname, "certops-distribution-report.js"), file],
    {
      encoding: "utf8",
      timeout: 10000,
      env: { ...process.env, GITHUB_SHA: report.candidateSha },
    },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.equal(JSON.parse(result.stdout).nativeQualification, "not-qualified");
});
test("database fixtures and all three certificate cohorts remain mandatory", () => {
  assert.deepEqual(require("./certops-distribution-inventory").validate(), []);
});

test("privacy refuses missing, duplicated or unsafe historical inventory before accessing a lab", () => {
  const { audit } = require("./certops-distribution-privacy");
  const id = crypto.randomUUID();
  for (const versions of [[], [id], [id, id], [id, "../../other-customer"], [id, "-".repeat(36)]])
    assert.throws(() => audit("tt-wildcard-ux-qual-fence-test", "unused.json", versions));
  assert.throws(() => audit("shared-production", "unused.json", [id, crypto.randomUUID()]));
});
test("qualification database opt-in refuses arbitrary names and missing ports", () => {
  const saved = { ...process.env };
  try {
    process.env.TT_CERTOPS_DISTRIBUTION_DISPOSABLE = "1";
    process.env.DB_NAME = "production";
    assert.throws(() =>
      require("../tests/wildcard-vault/qualification-database.cjs")(
        "wildcard_candidate",
        "57470",
      ),
    );
    process.env.DB_NAME =
      "wildcard_candidate_qualification_" +
      crypto.randomBytes(16).toString("hex");
    delete process.env.TT_CERTOPS_DISTRIBUTION_DB_PORT;
    assert.throws(() =>
      require("../tests/wildcard-vault/qualification-database.cjs")(
        "wildcard_candidate",
        "57470",
      ),
    );
  } finally {
    for (const key of Object.keys(process.env))
      if (!Object.hasOwn(saved, key)) delete process.env[key];
    Object.assign(process.env, saved);
  }
});
