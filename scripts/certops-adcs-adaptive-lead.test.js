"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { qualifyAdaptiveLead } = require("../tests/e2e/helpers/certops-adcs-adaptive-lead");

function setup({ inherited = null, early = [], after = [{ workspace_id: "workspace", id: "source" }], patched = 30, env = {} } = {}) {
  const operations = [];
  const fixture = { workspaceId: "workspace", pool: {}, async request(route, method = "GET", body) {
    operations.push({ route, method, body });
    return { status: 200, body: { renewBeforeDays: method === "GET" ? inherited : patched } };
  } };
  let calls = 0;
  const scheduler = { DEFAULT_RENEWAL_THRESHOLD_DAYS: 30, RENEWAL_JOB_TERMINAL_STATUSES: ["succeeded"], async findCertificatesDueForRenewal(options) {
    assert.equal(options.db, fixture.pool); assert.equal(options.adaptive, true); assert.equal(options.thresholdDays, 30);
    return calls++ === 0 ? early : after;
  } };
  return { args: { fixture, api: "/api", scheduler, source: { id: "source" }, profileId: "profile", env }, operations };
}

test("adaptive AD CS qualification compares the same source before and after an explicit override", async () => {
  const { args, operations } = setup({ early: [{ workspace_id: "other", id: "source" }] });
  await qualifyAdaptiveLead(args);
  assert.deepEqual(operations.map(value => value.method), ["GET", "PATCH"]);
  assert.deepEqual(operations[1].body, { renewBeforeDays: 30 });
});

test("adaptive AD CS qualification fails closed on wrong inheritance or selection", async () => {
  for (const options of [
    { inherited: 30 },
    { env: { CERTOPS_RENEWAL_THRESHOLD_DAYS: "4" } },
    { early: [{ workspace_id: "workspace", id: "source" }] },
    { patched: null },
    { after: [] },
  ]) await assert.rejects(() => qualifyAdaptiveLead(setup(options).args));
});
