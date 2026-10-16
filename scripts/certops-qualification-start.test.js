"use strict";
// Validate the read-only recommendation against actual committed workflows.
// The child below prints JSON only: no workflow or native fixture is launched.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  { spawnSync } = require("node:child_process"),
  helper = require("./certops-qualification-start");
test("first qualification plan uses actual hosted manual workflows without Azure provisioning", () => {
  assert.equal(helper.validatePlan(), true);
  const plan = helper.buildPlan("a".repeat(40));
  assert.equal(plan.executionStatus, "not-run");
  assert.equal(plan.dispatchesWorkflows, false);
  assert.equal(plan.configuresRemoteResources, false);
  assert.equal(plan.azureLabCredentialsRequired, false);
  assert.equal(plan.collection.profile, "standard-hosted");
  assert.match(plan.collection.warning, /live DNS-provider/);
  assert.match(plan.collection.warning, /blocked published-package/);
  assert.deepEqual(
    plan.phases[0].runs.map((r) => r.inputs),
    [{ lane: "tooling" }],
  );
  for (const phase of plan.phases)
    for (const run of phase.runs) {
      assert.match(
        run.command,
        /^gh workflow run certops-[a-z0-9-]+\.yml --repo tokentimerch\/tokentimer-core --ref main/,
      );
      assert.doesNotMatch(
        run.workflow,
        /adcs|retention24h|retention-cadence|ttl24h|dns-provider-qualification/,
      );
    }
});
test("plan refuses unsafe candidates and unsupported execution switches without dispatch", () => {
  for (const candidate of [
    "main",
    "a".repeat(39),
    "a".repeat(40) + "; commands",
    "A".repeat(40),
  ])
    assert.throws(() => helper.buildPlan(candidate));
  const script = path.join(__dirname, "certops-qualification-start.js"),
    result = spawnSync(
      process.execPath,
      [script, "--candidate", "b".repeat(40), "--json"],
      { encoding: "utf8", timeout: 10000 },
    );
  assert.equal(result.status, 0, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.equal(plan.candidateSha, "b".repeat(40));
  assert.equal(plan.dispatchesWorkflows, false);
  const wrong = spawnSync(process.execPath, [script, "--dispatch"], {
    encoding: "utf8",
    timeout: 10000,
  });
  assert.notEqual(wrong.status, 0);
  assert.match(wrong.stderr, /no dispatch option/);
});
test("collection workflow preserves full default and passes explicit closed profile safely", () => {
  const source = fs.readFileSync(
    path.join(
      __dirname,
      "../.github/workflows/certops-release-qualification.yml",
    ),
    "utf8",
  );
  assert.match(
    source,
    /profile:\s+description:[^\n]+\s+type: choice\s+default: full\s+options: \[full, standard-hosted, adcs, extended-adcs\]/,
  );
  assert.ok(
    source.includes("CERTOPS_QUALIFICATION_PROFILE: ${{ inputs.profile }}"),
  );
  assert.ok(
    source.includes(
      'python3 scripts/certops-release-collector.py --profile "$CERTOPS_QUALIFICATION_PROFILE"',
    ),
  );
  assert.doesNotMatch(source, /azure\/(?:login|cli)@|provision-lab\.ps1/);
});
test("profile inventory derives exact selected and omitted IDs without a qualified verdict", () => {
  const matrix = require("../docs/certops/release-qualification-matrix.json"),
    h = require("./certops-qualification-profiles"),
    inventory = helper.profileInventory();
  assert.equal(inventory.executionStatus, "not-run");
  for (const row of inventory.profiles) {
    const selection = h.selectProfile(matrix, row.profile);
    assert.deepEqual(row.selectedSlotIds, selection.selectedSlotIds);
    assert.deepEqual(row.omittedSlotIds, selection.omittedSlotIds);
    assert.equal(row.selectedCount + row.omittedCount, matrix.slots.length);
    assert.equal(Object.hasOwn(row, "fullMatrixQualified"), false);
  }
});
