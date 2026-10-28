"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { REQUIRED_SCENARIOS } = require("../e2e/helpers/certops-adcs-browser-admin-boundary");
const catalog = require("../../.github/maintainers/certops/qualification-suites.json");

test("AD CS role-boundary qualification retains the catalogued real-host scenarios", () => {
  for (const scenario of REQUIRED_SCENARIOS) {
    for (const suite of ["enterprise-adcs-real", "enterprise-adcs-hierarchy-real"]) {
      assert.equal(
        catalog.scenarioEvidenceLevels[suite][scenario],
        "real-host",
        `${scenario} must retain its ${suite} catalog mapping`,
      );
    }
  }
});
