"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const contract = require("../tests/e2e/helpers/certops-dns-interruption");

const ROOT = path.resolve(__dirname, "..");

function registration() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "_registration", "cross-coverage.json"), "utf8"));
}

function records() {
  return [
    { name: "_acme.owned.example", value: "token-owned", owner: "owned" },
    { name: "_acme.owned.example", value: "token-foreign", owner: "foreign" },
    { name: "_acme.other.example", value: "token-other", owner: "foreign" },
  ];
}

test("registration keeps DNS real-host work pending", () => {
  const body = registration();
  assert.equal(body.status, "partial");
  assert.equal(body.promotesCatalogRows, false);
  const suite = body.suites.find((item) => item.id === contract.SUITE);
  assert.equal(suite.status, "pending");
  assert.equal(suite.evidenceLevel, "real-host");
  assert.equal(suite.proofEvidenceLevel, "script");
  assert.equal(suite.qualified, false);
  assert.deepEqual(suite.scenarios, [...contract.SCENARIOS]);
  assert.deepEqual(suite.catalogIds, [...contract.CATALOG_IDS]);
});

test("cancellation and interrupted cleanup touch only the owned record", () => {
  const owned = {
    name: "_acme.owned.example",
    value: "token-owned",
    owner: "owned",
    action: "delete-txt",
  };
  const cancelled = contract.cancelOwned(records(), owned);
  assert.equal(cancelled.removed, 1);
  assert.equal(cancelled.propagationClaimed, false);
  assert.equal(cancelled.liveDnsQualified, false);
  assert.deepEqual(cancelled.remaining.map((row) => row.value), ["token-foreign", "token-other"]);
  const interrupted = contract.interruptedCleanup(records(), owned);
  assert.equal(interrupted.removedOwned, true);
  assert.equal(interrupted.deletedUnrelated, 0);
  assert.equal(interrupted.propagationClaimed, false);
  assert.equal(interrupted.liveDnsQualified, false);
  assert.deepEqual(interrupted.remaining.map((row) => row.owner), ["foreign", "foreign"]);
  assert.throws(() => contract.refuseBlanketReset("netsh http reset"), { code: "BLANKET_NETSH_RESET" });
  assert.throws(() => contract.cancelOwned(records(), { ...owned, action: "*" }), { code: "BLANKET_CLEANUP" });
  const absent = contract.assessLive(null);
  assert.equal(absent.liveDnsQualified, false);
  assert.equal(absent.propagationClaimed, false);
  assert.match(absent.reason, /no provider probe/);
  assert.equal(contract.assessLive({ provider: true }).liveDnsQualified, false);
  assert.equal(contract.assessLive({ provider: true }).propagationClaimed, false);
  contract.verifyProof(contract.localProof());
});

test("missing provider probe fails closed", () => {
  const reportPath = path.join(os.tmpdir(), `dns-interruption-${crypto.randomUUID()}.json`);
  const report = contract.run({ env: {}, probe: null, reportPath, write: true });
  assert.equal(report.status, "failed");
  assert.equal(report.suiteStatus, "pending");
  assert.equal(report.evidenceLevel, "real-host");
  assert.equal(report.liveDnsQualified, false);
  assert.equal(report.propagationClaimed, false);
  assert.equal(report.qualified, false);
  assert.equal(report.hostCapabilityAbsentIsPass, false);
  assert.match(report.reason, /no provider probe/);
  const spawned = spawnSync(process.execPath, ["scripts/certops-dns-interruption.js"], {
    cwd: ROOT,
    env: { ...process.env, [contract.REPORT_ENV]: reportPath },
    encoding: "utf8",
  });
  assert.equal(spawned.status, 1);
  fs.rmSync(reportPath, { force: true });
});
