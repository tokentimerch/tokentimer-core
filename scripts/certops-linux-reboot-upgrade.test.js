"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const contract = require("../tests/e2e/helpers/certops-linux-reboot-upgrade");

const ROOT = path.resolve(__dirname, "..");

function registration() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "_registration", "cross-coverage.json"), "utf8"));
}

test("registration does not claim a reboot", () => {
  const body = registration();
  assert.equal(body.status, "partial");
  assert.equal(body.promotesCatalogRows, false);
  const suite = body.suites.find((item) => item.id === contract.SUITE);
  assert.equal(suite.status, "partial");
  assert.equal(suite.evidenceLevel, "integration");
  assert.equal(suite.proofEvidenceLevel, "host-integration");
  assert.equal(suite.qualified, false);
  assert.deepEqual(suite.scenarios, [...contract.SCENARIOS]);
  assert.deepEqual(suite.catalogIds, [...contract.CATALOG_IDS]);
});

test("upgrade rollback restores the unit and a missing systemd host fails closed", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "linux-unit-"));
  try {
    const keyPath = path.join(root, "in-use.key");
    fs.writeFileSync(keyPath, "do-not-delete");
    const previous = Buffer.from("[Service]\nExecStart=/usr/bin/node agent.js\n");
    const next = Buffer.from("[Service]\nExecStart=/usr/bin/node agent-next.js\n");
    assert.throws(() => contract.applyUpgrade({
      root,
      previous,
      next,
      host: { systemd: false },
      keyPath,
    }), { code: "SYSTEMD_ABSENT" });
    assert.equal(fs.existsSync(path.join(root, "tokentimer-agent.service")), false);
    assert.equal(fs.readFileSync(keyPath, "utf8"), "do-not-delete");
    const upgraded = contract.applyUpgrade({
      root,
      previous,
      next,
      host: { systemd: true },
      keyPath,
    });
    assert.ok(fs.readFileSync(upgraded.unitPath).equals(previous));
    assert.equal(upgraded.realRebootQualified, false);
    assert.equal(upgraded.rebootClaimed, false);
    assert.equal(fs.readFileSync(keyPath, "utf8"), "do-not-delete");
    assert.throws(() => contract.recordReboot(true), { code: "REBOOT_NOT_CLAIMED" });
    const quiet = contract.recordReboot(false);
    assert.equal(quiet.realRebootQualified, false);
    assert.equal(quiet.rebootClaimed, false);
    contract.verifyProof(contract.localProof());
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("missing systemd lab fails closed", () => {
  const reportPath = path.join(os.tmpdir(), `linux-reboot-${crypto.randomUUID()}.json`);
  const report = contract.run({
    env: {},
    probe: { systemd: false, platform: "none" },
    reportPath,
    write: true,
  });
  assert.equal(report.status, "failed");
  assert.equal(report.realRebootQualified, false);
  assert.equal(report.rebootClaimed, false);
  assert.equal(report.hostCapabilityAbsentIsPass, false);
  assert.equal(report.qualified, false);
  assert.match(report.reason, /systemd|lab absent/);
  const spawned = spawnSync(process.execPath, ["scripts/certops-linux-reboot-upgrade.js"], {
    cwd: ROOT,
    env: { ...process.env, [contract.REPORT_ENV]: reportPath },
    encoding: "utf8",
  });
  assert.equal(spawned.status, 1);
  fs.rmSync(reportPath, { force: true });
});
