"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const contract = require("../tests/e2e/helpers/certops-issuer-adoption-capacity");

const ROOT = path.resolve(__dirname, "..");

function registration() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "_registration", "cross-coverage.json"), "utf8"));
}

test("registration does not qualify the native issuer cell", () => {
  const body = registration();
  assert.equal(body.status, "partial");
  assert.equal(body.promotesCatalogRows, false);
  const suite = body.suites.find((item) => item.id === contract.SUITE);
  assert.equal(suite.status, "partial");
  assert.equal(suite.evidenceLevel, "integration");
  assert.equal(suite.qualified, false);
  assert.deepEqual(suite.scenarios, [...contract.SCENARIOS]);
  assert.deepEqual(suite.catalogIds, [...contract.CATALOG_IDS]);
  assert.equal(suite.separateSuite, "native-adcs-issuer-reassignment");
});

test("capacity exhaustion and foreign adoption leave nativeCell pending", () => {
  const state = contract.createState(["issuer-owned"]);
  for (let index = 0; index < contract.CAPACITY; index += 1) {
    contract.reserve(state, `subject-${index}`);
  }
  assert.equal(state.reservations.length, contract.CAPACITY);
  assert.throws(() => contract.reserve(state, "subject-extra"), { code: "CAPACITY_EXHAUSTED" });
  assert.equal(state.reservations.length, contract.CAPACITY);
  assert.equal(state.nativeCell, "pending");
  assert.equal(state.nativeCellQualified, false);
  assert.throws(() => contract.adopt(state, "issuer-foreign"), { code: "FOREIGN_ISSUER" });
  assert.equal(state.adopted, null);
  contract.adopt(state, "issuer-owned");
  assert.equal(state.adopted, "issuer-owned");
  assert.equal(state.nativeCell, "pending");
  assert.equal(state.nativeCellQualified, false);
  state.nativeCell = "qualified";
  assert.throws(() => contract.seal(state), { code: "NATIVE_CELL_PENDING" });
  contract.verifyProof(contract.localProof());
});

test("missing forest fails closed and does not mark the cell qualified", () => {
  const reportPath = path.join(os.tmpdir(), `issuer-adoption-${crypto.randomUUID()}.json`);
  const report = contract.run({ env: {}, reportPath, write: true });
  assert.equal(report.status, "failed");
  assert.equal(report.nativeCell, "pending");
  assert.equal(report.nativeCellQualified, false);
  assert.equal(report.qualified, false);
  assert.equal(report.hostCapabilityAbsentIsPass, false);
  assert.equal(report.separateSuite, "native-adcs-issuer-reassignment");
  const spawned = spawnSync(process.execPath, ["scripts/certops-issuer-adoption-capacity.js"], {
    cwd: ROOT,
    env: { ...process.env, [contract.REPORT_ENV]: reportPath },
    encoding: "utf8",
  });
  assert.equal(spawned.status, 1);
  const written = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  assert.equal(written.nativeCell, "pending");
  fs.rmSync(reportPath, { force: true });
});
