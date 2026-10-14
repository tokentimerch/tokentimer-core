"use strict";
/** Offline wiring checks for real browser audit qualification: mandatory names,
 * source evidence and a verified artifact cannot silently disappear. The shared
 * audit page selects cheap tooling; authenticated Chromium remains manual. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const yaml = require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
const producer = require("./certops-browser-audit");
const read = file => yaml.load(fs.readFileSync(path.resolve(__dirname, "..", file), "utf8"));
function validate(workflow) {
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  const job = workflow.jobs.browser; assert.equal(job.if, "github.ref == 'refs/heads/main'");
  const step = job.steps.find(item => item.env?.CERTOPS_BROWSER_AUDIT_REPORT);
  assert.ok(step); assert.equal(step.if, undefined); assert.notEqual(step["continue-on-error"], true);
  assert.equal(step.env.CERTOPS_BROWSER_AUDIT_REPORT, "qualification-results/browser-audit.json");
  assert.match(step.run, /^node scripts\/certops-browser-audit\.js\r?\nnode scripts\/certops-qualification-report\.js qualification-results\/browser-audit\.json\s*$/);
  const upload = job.steps.find(item => item.uses?.startsWith("actions/upload-artifact@"));
  assert.equal(upload.if, "always()"); assert.equal(upload.with["if-no-files-found"], "error");
  assert.ok(upload.with.path.split(/\r?\n/).includes("qualification-results/browser-audit.json"));
}
test("browser audit is mandatory manual execution with independent verification and exact artifact", () => {
  const workflow = read(".github/workflows/certops-browser-qualification.yml"); validate(workflow);
  for (const mutate of [value => { value.jobs.browser.steps.find(step => step.env?.CERTOPS_BROWSER_AUDIT_REPORT).run = "node scripts/certops-browser-audit.js"; }, value => { value.jobs.browser.steps.find(step => step.env?.CERTOPS_BROWSER_AUDIT_REPORT).env.CERTOPS_BROWSER_AUDIT_REPORT = "qualification-results/browser.json"; }, value => { value.jobs.browser.steps.find(step => step.uses?.startsWith("actions/upload-artifact@")).with.path = "qualification-results/browser.json"; }]) {
    const invalid = structuredClone(workflow); mutate(invalid); assert.throws(() => validate(invalid));
  }
});
test("audit producer names and all source dependencies bind one native Ubuntu slot without auto browser launch", () => {
  const suite = "browser-certificate-audit", inventory = require("../docs/certops/qualification-suites.json"), matrix = require("../docs/certops/release-qualification-matrix.json");
  assert.deepEqual(inventory.suites[suite], producer.scenarios);
  assert.deepEqual(inventory.requiredCapabilities[suite], ["browser", "api", "postgres", "openssl"]);
  for (const id of producer.scenarios) assert.equal(inventory.scenarioEvidenceLevels[suite][id], "e2e");
  const slots = matrix.slots.filter(slot => slot.suite === suite); assert.equal(slots.length, 1);
  assert.deepEqual(slots[0].requiredSources, producer.requiredSources); assert.equal(slots[0].environment.distributionVersion, "24.04");
  const push = read(".github/workflows/certops-qualification.yml"); assert.ok(push.on.push.paths.includes("apps/dashboard/src/pages/Audit.jsx")); assert.equal(push.on.push.paths.includes("apps/dashboard/**"), false);
  const { selectFiles } = require("./certops-ci-selection");
  for (const file of ["apps/dashboard/src/pages/Audit.jsx", "scripts/certops-browser-audit.js"]) assert.deepEqual(selectFiles([file]), { tooling: true, windows: false, stack: false, reason: "changed-files" });
});
