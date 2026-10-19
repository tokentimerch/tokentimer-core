/**
 * Regression coverage: AD CS fixture inventory cannot omit a prohibited standalone or mixed EKU.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const cases = require("../../infra/certops-adcs/safety-cases.json");
const { validate } = require("../../scripts/certops-adcs-safety-inventory");
test("AD CS fixture inventory cannot omit a prohibited standalone or mixed EKU", () => {
  assert.equal(validate().template, 14);
  for (const item of cases.templateCases.filter(item => item.reason === "eku_not_server_auth_only")) {
    const missing = structuredClone(cases); missing.templateCases = missing.templateCases.filter(row => row.id !== item.id);
    assert.throws(() => validate(missing));
  }
});
test("AD CS fixture inventory cannot relabel schema boundaries or omit unsafe CA combinations", () => {
  const mislabeled = structuredClone(cases); mislabeled.keyConstraintCases.find(item => item.id === "ec-curve-on-schema-three").schema = 4;
  assert.throws(() => validate(mislabeled));
  for (const item of cases.caFlagCases) { const missing = structuredClone(cases); missing.caFlagCases = missing.caFlagCases.filter(row => row.id !== item.id); assert.throws(() => validate(missing)); }
});
