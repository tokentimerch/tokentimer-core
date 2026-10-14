"use strict";
/** Regression for malformed native scenario calls that ordinary syntax checks accept. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { validateScenarioCalls, validateHarnessSources } = require("./certops-harness-source");
const { readOnlyQueries, explainNativeQueries } = require("./certops-harness-source");
test("native scenario registration refuses multiple IDs substituted for its callback", () => {
  for (const source of ['gate.scenario("discovery", "repeat", "rollback", async () => {});', 'gate.scenario("discovery", "other");', 'gate.scenario("discovery", {});', 'gate.scenario("discovery");']) assert.ok(validateScenarioCalls(source).length);
});
test("native scenario registration accepts executable callbacks and cleanup references", () => {
  for (const source of ['gate.scenario("discovery", async () => {}, { oracle: "actual host" });', 'gate.scenario(ids[0], cleanup);', 'gate.scenario(`case-${kind}`, run.bind(null, kind));']) assert.deepEqual(validateScenarioCalls(source), []);
});
test("the committed native harness source has valid scenario calls", () => assert.deepEqual(validateHarnessSources(), []));
test("schema inventory extracts actual literal read queries and excludes mutations or interpolated SQL", () => {
  const queries = readOnlyQueries('pool.query("SELECT state, operator_request_id AS request_id FROM certificate_enrollments WHERE id=$1", [id]); pool.query(`SELECT count(*) FROM certificate_jobs`); pool.query("DELETE FROM certificate_enrollments"); pool.query(`SELECT ${column} FROM ${table}`);');
  assert.equal(queries.length, 2);
  assert.match(queries[0].sql, /operator_request_id AS request_id/);
  assert.throws(() => readOnlyQueries("const = invalid"));
});
test("native SQL schema probing refuses an unauthorized database before connecting", async () => {
  const previous = process.env.CERTOPS_CSR_DISPOSABLE_STACK;
  delete process.env.CERTOPS_CSR_DISPOSABLE_STACK;
  try { await assert.rejects(explainNativeQueries(), /Explicit disposable schema-check stack/); }
  finally { if (previous === undefined) delete process.env.CERTOPS_CSR_DISPOSABLE_STACK; else process.env.CERTOPS_CSR_DISPOSABLE_STACK = previous; }
});
