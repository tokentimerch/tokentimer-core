"use strict";
// Policy selection and source guards only: no workflow, cloud or native action.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  yaml = require("node:module").createRequire(
    require.resolve("mocha/package.json"),
  )("js-yaml");
const subject = require("./certops-qualification-profiles"),
  azure = require("./certops-azure-scope-policy");
const matrix = require("../docs/certops/qualification-suites.json");
test("native AD CS collection requires every runnable cohort and exposes deferred contracts", () => {
  const selected = subject.selectProfile(matrix, "adcs-native");
  assert.deepEqual(new Set(selected.specification.slots.map(slot => slot.suite)), new Set(subject.ADCS_NATIVE));
  for (const slot of matrix.slots) {
    assert.equal(selected.selectedSlotIds.includes(slot.id), subject.ADCS_NATIVE.includes(slot.suite));
  }
  const diagnostics = ["adcs-install-interruption", "adcs-lost-submit", "adcs-cmc-renewal", "adcs-safety-variants", "adcs-crash-experiments"];
  for (const suite of diagnostics) {
    const slots = matrix.slots.filter(row => row.suite === suite);
    assert.ok(matrix.deferredSlots.some(row => row.suite === suite));
    assert.ok(slots.every(row => selected.omittedSlotIds.includes(row.id)));
  }
  const summary = subject.summaryFields(selected, true);
  assert.equal(summary.fullMatrixQualified, false);
  assert.equal(summary.qualificationScope, "declared-profile");
});
const {
  verifyMatrix,
  validateQualificationSummary,
  catalogCoverage,
} = require("./certops-release-qualification");
test("core profiles expose all deferred environments and cannot qualify the full feature set", () => {
  const { verifyMatrix, validateQualificationSummary, catalogCoverage } = require("./certops-release-qualification");
  const full = subject.selectProfile(matrix);
  assert.deepEqual(new Set(full.omittedSlotIds), new Set(matrix.deferredSlots.map(slot => slot.id)));
  assert.equal(full.selectedSlotIds.length, matrix.slots.length);
  assert.equal(subject.summaryFields(full, true).fullMatrixQualified, false);
  assert.throws(() => subject.selectProfile(matrix, "extended-adcs"));
  for (const profile of ["full", "standard-hosted", "adcs", "adcs-native"]) {
    const selected = subject.selectProfile(matrix, profile);
    assert.ok(verifyMatrix([], { candidateSha: "a".repeat(40), specification: selected.specification }).length);
    const summary = { schemaVersion: 1, status: "passed", mandatoryEnvironments: selected.selectedSlotIds.length, allFeaturesQualified: false, catalogCoverage: catalogCoverage(), ...subject.summaryFields(selected, true) };
    assert.deepEqual(validateQualificationSummary(summary), []);
    for (const patch of [{ omittedSlotIds: [] }, { fullMatrixQualified: true }, { allFeaturesQualified: true }]) assert.ok(validateQualificationSummary({ ...summary, ...patch }).length);
  }
});
test("unknown empty and newly unclassified domain profiles fail closed", () => {
  for (const name of ["", null, "hosted", "full ", "FULL"])
    assert.throws(() => subject.selectProfile(matrix, name));
  assert.throws(() => subject.selectProfile({ slots: [] }, "full"));
  assert.throws(() =>
    subject.selectProfile({ slots: [matrix.slots[0], matrix.slots[0]] }),
  );
  assert.throws(() =>
    subject.selectProfile({ slots: [matrix.slots[0]] }, "adcs"),
  );
  const caps =
    require("../docs/certops/qualification-suites.json").requiredCapabilities;
  caps["new-domain-fixture"] = ["domain"];
  try {
    assert.throws(() =>
      subject.selectProfile(
        { slots: [{ id: "new", suite: "new-domain-fixture" }] },
        "standard-hosted",
      ),
    );
  } finally {
    delete caps["new-domain-fixture"];
  }
  assert.deepEqual(
    subject.parseArguments([
      "--profile",
      "standard-hosted",
      "candidate",
      "report",
    ]),
    { profile: "standard-hosted", rest: ["candidate", "report"] },
  );
  for (const args of [["--profile"], ["--profile", ""], ["--unknown"]])
    assert.throws(() => subject.parseArguments(args));
});
function workflows() {
  return Object.fromEntries(
    fs
      .readdirSync(path.resolve(__dirname, "../.github/workflows"))
      .filter((name) => name.startsWith("certops-") && name.endsWith(".yml"))
      .map((name) => [
        name,
        yaml.load(
          fs.readFileSync(
            path.resolve(__dirname, "../.github/workflows", name),
            "utf8",
          ),
        ),
      ]),
  );
}
test("all reviewed Azure workflows opt in and only manual workflows can provision", () => {
  const files = workflows();
  assert.equal(azure.PROVISION.length + azure.LIFECYCLE.length, 2);
  assert.ok(azure.PROVISION.includes("certops-enterprise-adcs-qualification.yml"));
  for (const [name, workflow] of Object.entries(files))
    assert.deepEqual(azure.validate(name, workflow), [], name);
  for (const name of azure.PROVISION) {
    const original = files[name];
    assert.deepEqual(Object.keys(original.on), ["workflow_dispatch"]);
    for (const trigger of ["push", "schedule", "workflow_run"]) {
      const bad = structuredClone(original);
      bad.on[trigger] = {};
      assert.ok(azure.validate(name, bad).length);
    }
    const bad = structuredClone(original);
    Object.values(bad.jobs)[0].if = "github.ref == 'refs/heads/main'";
    assert.ok(azure.validate(name, bad).length);
  }
  for (const name of azure.LIFECYCLE) {
    const original = files[name];
    assert.ok(
      Object.values(original.jobs).every(
        (job) => job.if === azure.LIFECYCLE_IF,
      ),
    );
    const bad = structuredClone(original);
    Object.values(bad.jobs)[0].steps.push({
      run: "./infra/certops-adcs/provision-lab.ps1",
    });
    assert.ok(azure.validate(name, bad).length);
  }
  for (const step of [
    { uses: "azure/login@pinned" },
    { run: "az group create --name hidden" },
    { run: "az deployment group create --name hidden" },
    { run: "az login --identity" },
  ])
    assert.ok(
      azure.validate("certops-unreviewed.yml", {
        on: { push: {} },
        jobs: { hidden: { steps: [step] } },
      }).length,
    );
  assert.ok(
    azure.validate("certops-unreviewed.yml", {
      env: { AZURE_CLIENT_ID: "fixture" },
      jobs: {},
    }).length,
  );
});

test("actual scoped CLI rejects unknown profile and absent evidence", () => {
  const { spawnSync } = require("node:child_process");
  for (const args of [
    ["--profile", "unknown", "a".repeat(40), "missing.json"],
    ["--profile", "standard-hosted", "a".repeat(40)],
  ]) {
    const result = spawnSync(
      process.execPath,
      [path.join(__dirname, "certops-release-qualification.js"), ...args],
      { encoding: "utf8", timeout: 30000 },
    );
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
  }
});
