"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const suites = require("../docs/certops/qualification-suites.json");
const { SHARD_NAMES, createShard, phaseOf } = require("../tests/e2e/helpers/certops-adcs-shards");
const { verifyShardReport } = require("./certops-adcs-shard-report");

const REQUIRED = suites.suites["enterprise-adcs-real"];
const SHARDS = SHARD_NAMES.filter((name) => name !== "all");

test("every mandatory native scenario is owned by exactly one diagnostic shard", () => {
  for (const id of REQUIRED) {
    assert.ok(phaseOf(id), `unassigned scenario ${id}`);
    const owners = SHARDS.filter((name) => createShard(name).owns(id));
    const shared = ["setup", "cleanup"].includes(phaseOf(id));
    assert.equal(owners.length, shared ? SHARDS.length : 1, `${id} owned by ${owners.join(",") || "nobody"}`);
  }
});

test("the union of the shards equals the full release scenario list", () => {
  const union = new Set(SHARDS.flatMap((name) => createShard(name).select(REQUIRED)));
  assert.deepEqual([...union].sort(), [...REQUIRED].sort());
});

test("the release mode is never filtered", () => {
  assert.equal(createShard("all").select(REQUIRED), REQUIRED);
  assert.equal(createShard(undefined).name, "all");
  assert.throws(() => createShard("bogus"), /Unknown AD CS qualification shard/);
});

function report(shard) {
  const required = createShard(shard).select(REQUIRED);
  return {
    status: "passed",
    experimental: true,
    qualificationStatus: "not-qualified",
    shard: { name: shard },
    cleanup: { status: "passed" },
    missingScenarios: [],
    requiredScenarios: required,
    scenarios: required.map((id) => ({ id, status: "passed" })),
  };
}

test("a complete shard report is accepted and cannot be qualified evidence", () => {
  for (const name of SHARDS) assert.deepEqual(verifyShardReport(report(name), name), []);
  const promoted = report("renewals");
  promoted.qualificationStatus = "qualified";
  assert.ok(verifyShardReport(promoted, "renewals").length);
});

test("an unexecuted, failed or foreign scenario fails the shard", () => {
  const missing = report("issuance");
  missing.scenarios.pop();
  assert.ok(verifyShardReport(missing, "issuance").some((e) => /Missing required scenario/.test(e)));
  const failed = report("issuance");
  failed.scenarios[0].status = "failed";
  assert.ok(verifyShardReport(failed, "issuance").length);
  assert.ok(verifyShardReport(report("renewals"), "issuance").some((e) => /different shard/.test(e)));
  const foreign = report("renewals");
  foreign.requiredScenarios.push(createShard("issuance").select(REQUIRED).find((id) => !createShard("renewals").owns(id)));
  assert.ok(verifyShardReport(foreign, "renewals").some((e) => /outside the shard/.test(e)));
  assert.ok(verifyShardReport(report("renewals"), "all").length);
});

test("the workflow matrix keeps release evidence serial and shards parallel with valid group names", () => {
  const { plan } = require("./certops-adcs-shard-plan");
  assert.deepEqual(plan({ attempt: "2" }), [{ shard: "all", suffix: "2", artifactSuffix: "" }]);
  const parallel = plan({ shard: "parallel", attempt: "2" });
  assert.equal(parallel.length, SHARDS.length);
  assert.equal(new Set(parallel.map((item) => item.suffix)).size, SHARDS.length);
  for (const item of parallel) assert.match(`tt-certops-123-${item.suffix}`, /^tt-certops-[0-9]+-[0-9]+$/);
  assert.equal(plan({ shard: "renewals" }).length, 1);
  assert.throws(() => plan({ shard: "renewals", scope: "operator-acceptance" }), /plain comprehensive/);
  assert.throws(() => plan({ shard: "parallel", fault: "issued" }), /plain comprehensive/);
  assert.throws(() => plan({ shard: "bogus" }), /Unknown shard/);
});
