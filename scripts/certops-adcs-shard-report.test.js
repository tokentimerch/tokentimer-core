"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const suites = require("./certops-qualification-manifest");
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

test("diagnostic reports use the complete canonical inventory while full runs keep their own requirements", () => {
  const incomplete = REQUIRED.filter((id) => id !== "adcs-real-localized-iis-repeat-deployment-idempotent");
  const shard = createShard("issuance");
  const required = shard.selectReportRequirements(incomplete, REQUIRED);
  assert.ok(required.includes("adcs-real-localized-iis-repeat-deployment-idempotent"));
  assert.deepEqual(required, shard.select(REQUIRED));
  assert.equal(createShard("all").selectReportRequirements(incomplete, REQUIRED), incomplete);
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
    scenarios: [...required, ...(createShard(shard).runs("core") ? [] : ["adcs-real-rsa2048-issued-cng-iis"])].map((id) => ({ id, status: "passed" })),
  };
}

test("a complete shard report is accepted and cannot be qualified evidence", () => {
  for (const name of SHARDS) assert.deepEqual(verifyShardReport(report(name), name), []);
  const promoted = report("renewals");
  promoted.qualificationStatus = "qualified";
  assert.ok(verifyShardReport(promoted, "renewals").length);
});

test("non-core shards accept only their passed shared RSA setup scenario", () => {
  const bootstrap = "adcs-real-rsa2048-issued-cng-iis";
  const evidence = report("templates-and-uncertain");
  assert.deepEqual(verifyShardReport(evidence, "templates-and-uncertain"), []);
  const absent = structuredClone(evidence); absent.scenarios = absent.scenarios.filter(item => item.id !== bootstrap);
  assert.ok(verifyShardReport(absent, "templates-and-uncertain").length);
  const failed = structuredClone(evidence); failed.scenarios.at(-1).status = "failed";
  assert.ok(verifyShardReport(failed, "templates-and-uncertain").length);
  const duplicate = structuredClone(evidence); duplicate.scenarios.push(duplicate.scenarios.at(-1));
  assert.ok(verifyShardReport(duplicate, "templates-and-uncertain").length);
  const foreign = structuredClone(evidence); foreign.scenarios.push({ id: "adcs-real-rsa3072-issued-cng-iis", status: "passed" });
  assert.ok(verifyShardReport(foreign, "templates-and-uncertain").length);
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

test("a shard cannot hide a missing native scenario by narrowing its own requirement list", () => {
  const narrowed = report("issuance");
  narrowed.requiredScenarios = narrowed.requiredScenarios.slice(0, -1);
  narrowed.scenarios.pop();
  assert.ok(verifyShardReport(narrowed, "issuance").length);
  const duplicate = report("renewals");
  duplicate.scenarios.push(duplicate.scenarios[0]);
  assert.ok(verifyShardReport(duplicate, "renewals").length);
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

test("the 15 minute lease fixtures are split so no shard holds more than two (60 minute run-command window)", () => {
  const { phaseOf, createShard } = require("../tests/e2e/helpers/certops-adcs-shards");
  const waits = { "adcs-real-uncertain-zero-request-acknowledged-recovery": "uncertain", "adcs-real-uncertain-single-candidate-auto-installs": "recovery", "adcs-real-uncertain-operator-created-ambiguity-refuses-attachment": "recovery" };
  for (const [id, phase] of Object.entries(waits)) assert.equal(phaseOf(id), phase, id);
  for (const id of ["adcs-real-uncertain-public-explicit-request-recovers", "adcs-real-uncertain-unused-operator-request-revoked", "adcs-real-public-reconcile-foreign-spki-refused", "adcs-real-browser-owned-requestid-reconcile"]) assert.equal(phaseOf(id), "recovery", id);
  assert.equal(phaseOf("adcs-real-browser-uncertain-abandon-confirmation"), "uncertain");
  const recovery = createShard("uncertain-recovery");
  assert.equal(recovery.runs("recovery"), true);
  assert.equal(recovery.runs("uncertain"), false);
  assert.equal(createShard("templates-and-uncertain").runs("recovery"), false);
  assert.equal(createShard("all").runs("recovery"), true);
});
