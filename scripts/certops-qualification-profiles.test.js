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
const matrix = require("./certops-qualification-manifest");
test("native AD CS collection requires every runnable cohort and exposes deferred contracts", () => {
  const selected = subject.selectProfile(matrix, "adcs-native");
  assert.deepEqual(new Set(selected.specification.slots.map(slot => slot.suite)), new Set(subject.ADCS_NATIVE));
  for (const slot of matrix.slots) {
    assert.equal(selected.selectedSlotIds.includes(slot.id), subject.ADCS_NATIVE.includes(slot.suite));
  }
  const diagnostics = require("./_registration/adcs-coverage.json").suites
    .map(row => row.id).filter(id => !subject.ADCS_NATIVE.includes(id));
  for (const suite of diagnostics) {
    const slots = matrix.slots.filter(row => row.suite === suite);
    assert.ok(slots.length);
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
test("profiles partition the complete matrix without hiding missing or blocked hosted cells", () => {
  assert.deepEqual(matrix.qualificationProfiles, subject.PROFILES);
  const full = subject.selectProfile(matrix),
    hosted = subject.selectProfile(matrix, "standard-hosted"),
    domain = subject.selectProfile(matrix, "adcs"),
    extended = subject.selectProfile(matrix, "extended-adcs"),
    cleanup = subject.selectProfile(matrix, "vault-cleanup"),
    openbao = subject.selectProfile(matrix, "openbao-cleanup"),
    staging = subject.selectProfile(matrix, "linux-staging"),
    openbaoStaging = subject.selectProfile(matrix, "openbao-staging");
  assert.deepEqual(cleanup.selectedSlotIds, ["linux-vault-cleanup-restart"]);
  assert.deepEqual(openbao.selectedSlotIds, ["linux-openbao-cleanup-restart"]);
  assert.deepEqual(staging.selectedSlotIds, ["linux-staging-restart"]);
  assert.deepEqual(openbaoStaging.selectedSlotIds, ["linux-openbao-staging-restart"]);
  assert.deepEqual(full.omittedSlotIds, [...cleanup.selectedSlotIds, ...openbao.selectedSlotIds, ...staging.selectedSlotIds, ...openbaoStaging.selectedSlotIds]);
  assert.equal(full.selectedSlotIds.length, matrix.slots.length - full.omittedSlotIds.length);
  assert.deepEqual(
    new Set([
      ...hosted.selectedSlotIds,
      ...domain.selectedSlotIds,
      ...extended.selectedSlotIds,
    ]),
    new Set(full.selectedSlotIds),
  );
  assert.equal(
    hosted.selectedSlotIds.length +
      domain.selectedSlotIds.length +
      extended.selectedSlotIds.length,
    full.selectedSlotIds.length,
  );
  for (const slot of hosted.specification.slots)
    assert.equal(subject.classify(slot), "hosted");
  for (const slot of matrix.slots.filter((slot) =>
    /dns-provider|arm64/.test(slot.id),
  ))
    assert.ok(hosted.selectedSlotIds.includes(slot.id));
  for (const profile of Object.keys(subject.PROFILES)) {
    const selection = subject.selectProfile(matrix, profile);
    assert.ok(
      verifyMatrix([], {
        candidateSha: "a".repeat(40),
        specification: selection.specification,
      }).length >= selection.selectedSlotIds.length,
    );
    const summary = {
      schemaVersion: 1,
      status: "passed",
      mandatoryEnvironments: selection.selectedSlotIds.length,
      allFeaturesQualified: false,
      catalogCoverage: catalogCoverage(),
      ...subject.summaryFields(selection, true),
    };
    assert.deepEqual(validateQualificationSummary(summary), []);
    for (const patch of [
      { selectedSlotIds: [] },
      { omittedSlotIds: [] },
      { fullMatrixQualified: profile !== "full" },
      { qualificationScope: "all-features" },
    ]) {
      assert.ok(validateQualificationSummary({ ...summary, ...patch }).length);
    }
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
    require("./certops-qualification-manifest").requiredCapabilities;
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
  assert.equal(azure.PROVISION.length + azure.LIFECYCLE.length, 21);
  assert.ok(azure.PROVISION.includes(azure.STORE_PREPARE));
  assert.ok(azure.PROVISION.includes("certops-azure-imds-qualification.yml"));
  assert.ok(azure.PROVISION.includes(azure.OPERATOR));
  assert.ok(azure.PROVISION.includes("certops-native-issuer-reassignment.yml"));
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
    Object.values(bad.jobs).find(job => job.environment).if = "github.ref == 'refs/heads/main'";
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
  const keyvault = files["certops-azure-keyvault-janitor.yml"];
  for (const mutate of [
    (workflow) => { workflow.on.push = {}; },
    (workflow) => { workflow.jobs.cleanup.if = "always()"; },
    (workflow) => { workflow.jobs.cleanup.environment = "certops-adcs-cleanup"; },
    (workflow) => { workflow.jobs.cleanup.steps[0].with.ref = "main"; },
    (workflow) => { workflow.jobs.cleanup.steps[3].run = "az group create --name hidden"; },
  ]) {
    const bad = structuredClone(keyvault);
    mutate(bad);
    assert.ok(azure.validate("certops-azure-keyvault-janitor.yml", bad).length);
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

test("the Azure operator workflow rejects any change to its protected run, credential, cleanup and evidence boundaries", () => {
  const name = azure.OPERATOR;
  const original = workflows()[name];
  const { validateWorkflow } = require("./certops-workflow-security");
  assert.deepEqual(azure.validate(name, original), []);
  assert.deepEqual(validateWorkflow(original, name), []);
  assert.ok(azure.validate("certops-foreign-operator.yml", original).length);
  const job = workflow => workflow.jobs["azure-operator"];
  const changeStep = (predicate, update) => workflow => update(job(workflow).steps.find(predicate));
  const step = (id, update) => changeStep(item => item.id === id, update);
  const upload = update => changeStep(item => item.uses?.startsWith("actions/upload-artifact@"), update);
  const env = "TT_AZURE_OPERATOR_ISSUER_KEY_PEM";
  const changes = [
    ["workflow token", w => { w.permissions.actions = "write"; }],
    ["live opt-in", w => { job(w).if = "github.ref == 'refs/heads/main'"; }],
    ["exact trusted main", w => { job(w).if += " || true"; }],
    ["protected environment", w => { job(w).environment = "certops-azure-keyvault-cleanup"; }],
    ["job token", w => { job(w).permissions.contents = "write"; }],
    ["bounded runtime", w => { job(w)["timeout-minutes"] = 120; }],
    ["non-cancelling queue", w => { w.concurrency["cancel-in-progress"] = true; }],
    ["manual dispatch only", w => { w.on.schedule = [{ cron: "1 * * * *" }]; }],
    ["exact archive inputs", w => { w.on.workflow_dispatch.inputs.package_sha256.required = false; }],
    ["approved region", w => { w.on.workflow_dispatch.inputs.location.options.push("other"); }],
    ["immutable checkout", w => { job(w).steps[0].with.ref = "feature"; }],
    ["approval before credentials", w => { job(w).steps.splice(3, 1); }],
    ["producer shell", changeStep(item => item.run?.includes("azure-keyvault-operator.cjs stage"),
      item => { item.run += "echo unreviewed\n"; })],
    ["job credential scope", w => { job(w).env[env] = job(w).steps[6].env[env]; }],
    ["step credential scope", step("azure-login", item => { item.env = { [env]: "${{ secrets.CERTOPS_AZURE_OPERATOR_ISSUER_KEY_PEM }}" }; })],
    ["separate credentials", step("operator-journey", item => { item.env[env] = item.env.TT_AZURE_OPERATOR_CONSUMER_KEY_PEM; })],
    ["exact privileged command", step("operator-journey", item => { item.run += "env\n"; })],
    ["fresh cleanup authentication", step("cleanup-login", item => { item.run = "echo skipped"; })],
    ["cleanup also after failure", step("operator-cleanup", item => { item.if = "success()"; })],
    ["cleanup failure cannot be hidden", step("operator-cleanup", item => { item["continue-on-error"] = true; })],
    ["cleanup cannot be removed", w => { job(w).steps.splice(8, 1); }],
    ["bounded report copy", changeStep(item => item.run?.includes("131072"), item => {
      item.run = item.run.replace("131072", "1048576");
    })],
    ["successful independent cleanup before upload", upload(item => {
      item.if = "success() && steps.operator-journey.outcome == 'success'";
    })],
    ["single closed report path", upload(item => { item.with.path = "${{ runner.temp }}/**"; })],
    ["immutable upload action", upload(item => { item.uses = "actions/upload-artifact@v4"; })],
    ["mandatory report", upload(item => { item.with["if-no-files-found"] = "warn"; })],
  ];
  for (const [description, mutate] of changes) {
    const changed = structuredClone(original);
    mutate(changed);
    assert.ok(azure.validate(name, changed).length, description);
    assert.ok(validateWorkflow(changed, name).length, description);
  }
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
