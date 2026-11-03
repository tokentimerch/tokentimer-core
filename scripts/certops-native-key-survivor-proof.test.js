"use strict";
/** Supporting report/prerequisite regressions; never execute native key operations. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { FIELDS, REQUIRED_SOURCES, verifyProof } = require("./certops-native-key-survivor-proof");
const root = path.resolve(__dirname, "..");
test("cross-store proof refuses missing, coerced and unbounded native facts", () => {
  const proof = Object.fromEntries(FIELDS.map(field => [field, true]));
  assert.equal(verifyProof(proof), true);
  for (const field of FIELDS) {
    for (const invalid of [false, null, 1, "true"]) assert.throws(() => verifyProof({ ...proof, [field]: invalid }));
    const missing = { ...proof }; delete missing[field]; assert.throws(() => verifyProof(missing));
  }
  assert.throws(() => verifyProof({ ...proof, rawInventory: "must not escape" }));
  assert.throws(() => verifyProof(undefined));
  const slots = require("./certops-qualification-manifest").slots.filter(slot => slot.suite === "windows-host");
  assert.equal(slots.length, 2);
  for (const slot of slots) for (const file of REQUIRED_SOURCES) assert.ok(slot.requiredSources.includes(file), file);
});
test("clean Windows host lanes build the current metadata helper before any host cleanup case", () => {
  const yaml = require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
  for (const file of ["certops-qualification.yml"]) {
    const steps = yaml.load(fs.readFileSync(path.join(root, ".github/workflows", file), "utf8")).jobs.windows.steps;
    const setup = steps.findIndex(step => step.uses === "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff");
    const build = steps.findIndex(step => step.run === "node packages/agent/scripts/build-windows-chain-helper.js");
    const host = steps.findIndex(step => typeof step.run === "string" && step.run.split(/\r?\n/).some(line => line.trim() === "node --test packages/agent/scripts/host/windows-host.test.js"));
    assert.ok(setup >= 0 && setup < build && build < host, file);
    assert.equal(steps[setup].with["go-version-file"], "packages/agent/windows-service-host/go.mod", file);
  }
});

test("unsupported historical ARM64 full-host dispatch fails before checkout or native mutation", () => {
 const source=fs.readFileSync(path.join(root,".github/workflows/certops-windows-arm64-host.yml"),"utf8");
 assert.match(source,/permissions: \{\}/);assert.match(source,/runs-on: ubuntu-latest/);assert.match(source,/exit 1/);
 for(const workflow of ["certops-windows-arm64-cng.yml","certops-windows-arm64-scm.yml"])assert.ok(source.includes(workflow));
 assert.doesNotMatch(source,/uses:|if:|windows-host\.test\.js|CERTOPS_HOST_TESTS|upload-artifact/);
});
