/**
 * Regression coverage: public documentation refuses private checkout paths and repository URLs.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { scanText } = require("./ci-guards/leak-scan.cjs");
function findings(file, text) {
  const rows = [];
  scanText(file, text, rows);
  return rows.filter(row => row.describe.includes("private downstream repository"));
}
test("public documentation refuses private checkout paths and repository URLs", () => {
  for (const edition of ["cloud", "enterprise"]) {
    const repository = ["tokentimer", edition].join("-");
    for (const text of ["`" + repository + "`", repository + "/scripts/private.js", "https://github.com/example/" + repository + "/blob/main/file.js"]) {
      assert.equal(findings("docs/certops/qualification/guide.md", text).length, 1);
      assert.equal(findings("docs/certops/e2e-scenario-catalog.json", JSON.stringify({ implementation: text })).length, 1);
    }
  }
});
test("public product terminology assets and executable runtime labels remain valid", () => {
  assert.deepEqual(findings("README.md", "TokenTimer Cloud and TokenTimer Enterprise; docs/assets/tokentimer-cloud-cta.svg"), []);
  assert.deepEqual(findings("apps/api/config/runtime-labels.js", 'service: "tokentimer-cloud"'), []);
  assert.equal(findings("docs/new-guide.md", ["TOK", "123"].join("-")).length, 0);
  const violations = [];
  scanText("docs/new-guide.md", ["TOK", "123"].join("-"), violations);
  assert.ok(violations.some(row => row.describe.includes("issue-tracker")));
});
