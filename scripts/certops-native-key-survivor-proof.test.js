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
  const slots = require("../docs/certops/release-qualification-matrix.json").slots.filter(slot => slot.suite === "windows-host");
  assert.equal(slots.length, 2);
  for (const slot of slots) for (const file of REQUIRED_SOURCES) assert.ok(slot.requiredSources.includes(file), file);
});
test("clean Windows host lanes build the current metadata helper before any host cleanup case", () => {
  for (const file of ["certops-qualification.yml", "certops-windows-arm64-host.yml"]) {
    let source = fs.readFileSync(path.join(root, ".github/workflows", file), "utf8").replace(/\r\n/g, "\n");
    if (file === "certops-qualification.yml") source = source.split("  windows:\n")[1].split("  agent-stack:")[0];
    const setup = source.indexOf("actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff");
    const build = source.indexOf("run: node packages/agent/scripts/build-windows-chain-helper.js");
    const host = source.indexOf("run: node --test packages/agent/scripts/host/windows-host.test.js");
    assert.ok(setup >= 0 && setup < build && build < host, file);
    assert.ok(source.includes("go-version-file: packages/agent/windows-service-host/go.mod"), file);
  }
});
