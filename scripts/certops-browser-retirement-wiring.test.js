"use strict";
/** Protect the manual browser retirement lane's mandatory execution/evidence
 * wiring. These offline checks cannot substitute for actual Chromium/API/TLS
 * scenarios and must never select costly native hosts for frontend-only changes. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const yaml = require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
const fixture = require("./certops-browser-retirement");
const root = path.resolve(__dirname, "..");
const workflow = yaml.load(fs.readFileSync(path.join(root, ".github/workflows/certops-browser-qualification.yml"), "utf8"));
function validateWiring(value) {
  assert.deepEqual(Object.keys(value.on), ["workflow_dispatch"]);
  const job = value.jobs.browser;
  assert.equal(job.if, "github.ref == 'refs/heads/main'");
  const step = job.steps.find(item => item.name === "Retired certificate visibility and factual observed details");
  assert.ok(step); assert.equal(step.if, undefined); assert.notEqual(step["continue-on-error"], true);
  assert.equal(step.env.CERTOPS_BROWSER_RETIREMENT_REPORT, "qualification-results/browser-retirement.json");
  assert.match(step.run, /^node scripts\/certops-browser-retirement\.js\r?\nnode scripts\/certops-qualification-report\.js qualification-results\/browser-retirement\.json\s*$/);
  const upload = job.steps.find(item => item.uses?.startsWith("actions/upload-artifact@"));
  assert.equal(upload.if, "always()"); assert.equal(upload.with["if-no-files-found"], "error");
  assert.ok(upload.with.path.split(/\r?\n/).includes("qualification-results/browser-retirement.json"));
}
test("manual browser retirement executes and independently verifies its exact uploaded report", () => {
  validateWiring(workflow);
  for (const mutate of [value => { value.jobs.browser.steps.find(step => step.env?.CERTOPS_BROWSER_RETIREMENT_REPORT).run = "node scripts/certops-browser-retirement.js"; }, value => { value.jobs.browser.steps.find(step => step.env?.CERTOPS_BROWSER_RETIREMENT_REPORT)["continue-on-error"] = true; }, value => { value.jobs.browser.steps.find(step => step.uses?.startsWith("actions/upload-artifact@")).with.path = "qualification-results/browser.json"; }]) {
    const invalid = structuredClone(workflow); mutate(invalid); assert.throws(() => validateWiring(invalid));
  }
});
test("all retirement scenarios and current supporting sources remain mandatory in one actual host slot", () => {
  const inventory = require("../docs/certops/qualification-suites.json"), matrix = require("../docs/certops/release-qualification-matrix.json");
  assert.deepEqual(inventory.suites["browser-retirement-visibility"], fixture.scenarios);
  assert.deepEqual(inventory.requiredCapabilities["browser-retirement-visibility"], ["browser", "api", "postgres", "openssl"]);
  for (const id of fixture.scenarios) assert.equal(inventory.scenarioEvidenceLevels["browser-retirement-visibility"][id], "e2e");
  const slots = matrix.slots.filter(slot => slot.suite === "browser-retirement-visibility"); assert.equal(slots.length, 1);
  assert.deepEqual(slots[0].requiredSources, fixture.requiredSources); assert.equal(slots[0].environment.distributionVersion, "24.04");
  const { selectFiles } = require("./certops-ci-selection");
  for (const file of ["scripts/certops-browser-retirement.js", "apps/dashboard/src/pages/certops/CertOpsCertificates.jsx", "apps/dashboard/src/components/certops/CertificateDetailsModal.jsx"]) assert.deepEqual(selectFiles([file]), { tooling: true, windows: false, stack: false, reason: "changed-files" });
});
